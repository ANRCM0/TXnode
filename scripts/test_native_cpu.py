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


if __name__ == "__main__":
    unittest.main()
