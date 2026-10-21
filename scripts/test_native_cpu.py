"""CPU evidence contract tests; execution belongs to the Actions test job."""

import importlib.util
import json
from pathlib import Path
import signal
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("native_acceptance_cpu", Path(__file__).with_name("native-acceptance.py"))
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)


class CPUContractTests(unittest.TestCase):
    def test_formal_samples_remove_inherited_diagnostic_flags(self):
        inherited = {"TXNODE_NATIVE_AB_CPU_PROFILE": "old.pprof",
                     "TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS": "1"}
        with patch.dict(BENCH.os.environ, inherited):
            environment = BENCH.sample_environment("nonce")
        self.assertNotIn("TXNODE_NATIVE_AB_CPU_PROFILE", environment)
        self.assertNotIn("TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS", environment)
        self.assertEqual(environment["TXNODE_NATIVE_AB_CPU_NONCE"], "nonce")

    def test_persistence_observer_requires_explicit_profiled_diagnostic(self):
        with patch.dict(BENCH.os.environ, {"TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS": "1"}):
            environment = BENCH.sample_environment("nonce", Path("cpu.pprof"))
            self.assertNotIn("TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS", environment)
            environment = BENCH.sample_environment("nonce", Path("cpu.pprof"), True)
        self.assertEqual(environment["TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS"], "1")
        self.assertEqual(environment["TXNODE_NATIVE_AB_CPU_PROFILE"], "cpu.pprof")
        with self.assertRaises(ValueError):
            BENCH.sample_environment("nonce", persistence_diagnostics=True)

    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.state = Path(self.directory.name)
        self.nonce = "a" * 64

    def proof(self, **changes):
        result = {"schema": "txnode-process-cpu-snapshot/v1", "method": BENCH.CPU_METHOD,
                  "clock_id": 2, "pid": 1234, "sequence": 1, "nonce": self.nonce,
                  "cpu_nanos": 500, "resolution_nanos": 1,
                  "monotonic_before_nanos": 120, "monotonic_after_nanos": 140}
        result.update(changes)
        return result

    def snapshot(self, proof=None, *, number=1, write=True, dead=False, unsupported=False):
        state = self.state
        owner = self

        class Process:
            pid = 1234

            def send_signal(self, received):
                owner.assertEqual(received, signal.SIGUSR2)
                if unsupported:
                    raise OSError("unsupported signal or CPU clock")
                if write:
                    target = state / ("cpu-%d.json" % number)
                    temporary = target.with_suffix(".tmp")
                    temporary.write_text(json.dumps(proof), encoding="utf-8")
                    temporary.replace(target)

            def poll(self):
                return 2 if dead else None

        with patch.object(BENCH.time, "monotonic_ns", side_effect=[100, 200]), \
                patch.object(BENCH.time, "monotonic", side_effect=[0, 6]), \
                patch.object(BENCH, "process_resources", side_effect=AssertionError("CPU fallback forbidden")):
            return BENCH.cpu_snapshot(Process(), self.state, number, self.nonce)

    def test_valid_atomic_snapshot_retains_raw_clock_and_round_trip(self):
        result = self.snapshot(self.proof())
        self.assertEqual(result["cpu_nanos"], 500)
        self.assertEqual(result["round_trip_nanos"], 100)
        self.assertEqual(result["requested_monotonic_nanos"], 100)
        self.assertEqual(result["received_monotonic_nanos"], 200)

    def test_snapshot_rejects_wrong_identity_and_method(self):
        for field, value in (("schema", "old"), ("method", "proc-stat-clk-tck-v1"),
                             ("clock_id", 3), ("pid", 1235), ("nonce", "other"), ("sequence", 2)):
            with self.subTest(field=field), self.assertRaises(ValueError):
                self.snapshot(self.proof(**{field: value}))
            (self.state / "cpu-1.json").unlink(missing_ok=True)

    def test_snapshot_rejects_boolean_integer_and_missing_fields(self):
        fields = ("clock_id", "pid", "sequence", "cpu_nanos", "resolution_nanos",
                  "monotonic_before_nanos", "monotonic_after_nanos")
        for field in fields:
            for value in (True, None, "1"):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.snapshot(self.proof(**{field: value}))
                (self.state / "cpu-1.json").unlink(missing_ok=True)

    def test_snapshot_rejects_nonpositive_cpu_or_resolution(self):
        for field in ("cpu_nanos", "resolution_nanos"):
            for value in (0, -1):
                with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                    self.snapshot(self.proof(**{field: value}))
                (self.state / "cpu-1.json").unlink(missing_ok=True)

    def test_snapshot_rejects_out_of_request_bounds_and_reversed_read(self):
        for before, after in ((99, 140), (120, 201), (150, 140)):
            with self.subTest(before=before, after=after), self.assertRaises(ValueError):
                self.snapshot(self.proof(monotonic_before_nanos=before, monotonic_after_nanos=after))
            (self.state / "cpu-1.json").unlink(missing_ok=True)

    def test_duplicate_file_is_not_reused(self):
        (self.state / "cpu-1.json").write_text("{}", encoding="utf-8")
        with self.assertRaises(ValueError):
            self.snapshot(self.proof())

    def test_unsupported_clock_timeout_and_dead_server_never_fall_back(self):
        with self.assertRaises(OSError):
            self.snapshot(write=False, unsupported=True)
        with self.assertRaises(RuntimeError):
            self.snapshot(write=False)
        with self.assertRaises(RuntimeError):
            self.snapshot(write=False, dead=True)

    def pair(self):
        return self.proof(), self.proof(sequence=2, cpu_nanos=750,
                                       monotonic_before_nanos=300, monotonic_after_nanos=320)

    def test_valid_pair_uses_process_cpu_delta(self):
        start, end = self.pair()
        result = BENCH.cpu_measurement(start, end, 1073741824)
        self.assertEqual(result["delta_nanos"], 250)
        self.assertEqual(result["cpu_seconds_per_gib"], 250 / 1_000_000_000)
        self.assertEqual(result["monotonic_inner_elapsed_nanos"], 160)

    def test_pair_rejects_resolution_identity_and_sequence_changes(self):
        for field, value in (("resolution_nanos", 2), ("nonce", "other"), ("pid", 1235), ("sequence", 1)):
            start, end = self.pair()
            end[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                BENCH.cpu_measurement(start, end, 1024)
        start, end = self.pair()
        with self.assertRaises(ValueError):
            BENCH.cpu_measurement(end, start, 1024)

    def test_pair_rejects_nonpositive_cpu_delta_elapsed_and_business_bytes(self):
        for field, value in (("cpu_nanos", 500), ("cpu_nanos", 499),
                             ("cpu_nanos", 0), ("cpu_nanos", True),
                             ("resolution_nanos", 0), ("monotonic_before_nanos", 140)):
            start, end = self.pair()
            end[field] = value
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
                BENCH.cpu_measurement(start, end, 1024)
        for size in (0, -1, True):
            start, end = self.pair()
            with self.subTest(size=size), self.assertRaises(ValueError):
                BENCH.cpu_measurement(start, end, size)


class PersistenceDiagnosticContractTests(unittest.TestCase):
    def test_unprofiled_observer_requires_explicit_independent_mode(self):
        inherited = {"TXNODE_NATIVE_AB_CPU_PROFILE": "old.pprof", "TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS": "1"}
        with patch.dict(BENCH.os.environ, inherited):
            off = BENCH.sample_environment("nonce", persistence_diagnostics_only=True)
            on = BENCH.sample_environment("nonce", persistence_diagnostics=True, persistence_diagnostics_only=True)
        self.assertNotIn("TXNODE_NATIVE_AB_CPU_PROFILE", off)
        self.assertNotIn("TXNODE_NATIVE_AB_CPU_PROFILE", on)
        self.assertNotIn("TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS", off)
        self.assertEqual(on["TXNODE_NATIVE_AB_EVENT_DIAGNOSTICS"], "1")
        with self.assertRaises(ValueError):
            BENCH.sample_environment("nonce", persistence_diagnostics=True)
        with self.assertRaises(ValueError):
            BENCH.sample_environment("nonce", Path("cpu.pprof"), persistence_diagnostics_only=True)

    def test_five_groups_cover_all_cells_and_reverse_execution_order(self):
        plan = BENCH.persistence_plan(5)
        self.assertEqual(len(plan), 20)
        for group in range(1, 6):
            cells = [(side, enabled) for number, side, enabled in plan if number == group]
            self.assertEqual(set(cells), {("legacy", False), ("legacy", True), ("candidate", False), ("candidate", True)})
        first = [(side, enabled) for group, side, enabled in plan if group == 1]
        second = [(side, enabled) for group, side, enabled in plan if group == 2]
        self.assertEqual(first, list(reversed(second)))

    def report(self):
        return {"schema": "txnode-native-persistence-diagnostics/v1", "status": "persistence-diagnostics-only",
                "accepted": False, "samples": [], "comparisons": [],
                "persistence_samples": [
                    {"group": group, "side": side, "observer_enabled": enabled, "acceptance_sample": False,
                     "mode": "events", "workload": "download",
                     "cpu_profile_enabled": False,
                     "sample": {"status": "incomplete", "persistence_diagnostics": enabled},
                     "event_observation": {"observer_evidence_present": enabled}}
                    for group, side, enabled in BENCH.persistence_plan(5)]}

    def test_collected_accounting_failures_never_become_acceptance(self):
        report = self.report()
        self.assertTrue(BENCH.persistence_collection_complete(report, 5))
        self.assertIs(report["accepted"], False)
        self.assertEqual(report["samples"], [])
        self.assertEqual(report["comparisons"], [])
        for field, value in (("accepted", True), ("samples", [{}]), ("comparisons", [{}]),
                             ("schema", "txnode-native-performance/v2")):
            changed = self.report()
            changed[field] = value
            with self.subTest(field=field):
                self.assertFalse(BENCH.persistence_collection_complete(changed, 5))

    def test_collection_requires_unique_cases_and_matching_observer_evidence(self):
        for field, value in (("cpu_profile_enabled", True), ("acceptance_sample", True),
                             ("collection_error", "snapshot missing")):
            report = self.report()
            report["persistence_samples"][0][field] = value
            with self.subTest(field=field):
                self.assertFalse(BENCH.persistence_collection_complete(report, 5))
        report = self.report()
        report["persistence_samples"][-1] = report["persistence_samples"][0]
        self.assertFalse(BENCH.persistence_collection_complete(report, 5))
        report = self.report()
        report["persistence_samples"][0]["event_observation"]["observer_evidence_present"] = True
        self.assertFalse(BENCH.persistence_collection_complete(report, 5))

    def test_pairs_exclude_failed_accounting_from_ratios(self):
        report = self.report()
        pairs = BENCH.persistence_pairs(report["persistence_samples"], 5)
        self.assertTrue(all(not item["paired_metrics_available"] for item in pairs))
        self.assertTrue(all("observer_on_over_off_cpu" not in item for item in pairs))
        for item in report["persistence_samples"]:
            item["sample"].update(status="measured", mib_per_second=20 if item["observer_enabled"] else 10,
                                  cpu_seconds_per_gib=3 if item["observer_enabled"] else 2)
        pairs = BENCH.persistence_pairs(report["persistence_samples"], 5)
        self.assertTrue(all(item["observer_on_over_off_throughput"] == 2 for item in pairs))
        self.assertTrue(all(item["observer_on_over_off_cpu"] == 1.5 for item in pairs))


if __name__ == "__main__":
    unittest.main()
