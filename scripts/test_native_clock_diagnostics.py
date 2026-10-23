"""Evidence policy tests for disposable clock diagnostic builds; run in Actions."""

import copy
import importlib.util
from pathlib import Path
import unittest


SPEC = importlib.util.spec_from_file_location("native_clock_diagnostics", Path(__file__).with_name("native-clock-diagnostics.py"))
DIAGNOSTIC = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DIAGNOSTIC)


class ClockCapturePolicyTests(unittest.TestCase):
    def capture(self):
        return {"schema": DIAGNOSTIC.SCHEMA, "observed": True, "sequence": "1", "direction": "download",
                "bytes": "1", "requested": "1", "deadline_elapsed_nanos": "90000000000",
                "grant_issued_seconds": "1", "grant_expires_seconds": "90",
                "started": {"wall_nanos": "1999999900", "elapsed_nanos": "100"},
                "completed": {"wall_nanos": "2000000000", "elapsed_nanos": "200"},
                "last": {"wall_nanos": "2000000001", "elapsed_nanos": "199"},
                "retired": False, "wall_forward": True, "elapsed_forward": True,
                "global_order_allowed": False, "before_deadline": True, "inside_grant": True, "eligible": False}

    def test_no_rejection_observed_requires_exact_armed_envelope(self):
        armed = {"schema": DIAGNOSTIC.SCHEMA, "observed": False}
        self.assertEqual(DIAGNOSTIC.validate_capture(armed), {"observed": False, "rejecting_guards": []})
        for changes in ({"observed": 0}, {"observed": "false"}, {"credential": "private"}, {"eligible": True}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DIAGNOSTIC.validate_capture(dict(armed, **changes))

    def test_exact_last_stamp_reconstructs_the_global_order_rejection(self):
        result = DIAGNOSTIC.validate_capture(self.capture())
        self.assertEqual(result["rejecting_guards"], ["global_order_allowed"])
        self.assertEqual(result["last_wall_delta_nanos"], -1)
        self.assertEqual(result["last_elapsed_delta_nanos"], 1)

    def test_unreviewed_fields_types_operation_and_eligibility_are_rejected(self):
        for changes in ({"token": "private"}, {"eligible": True}, {"retired": 0}, {"sequence": True},
                        {"bytes": "2"}, {"bytes": "-1"}, {"requested": "-1"}, {"direction": "raw text"},
                        {"grant_issued_seconds": 1.0}, {"deadline_elapsed_nanos": "1e30"},
                        {"requested": str(1 << 63)}, {"bytes": "-0"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DIAGNOSTIC.validate_capture(dict(self.capture(), **changes))

    def test_reported_guards_must_agree_with_each_exact_clock(self):
        for stamp, field, number in (("last", "elapsed_nanos", "201"), ("last", "wall_nanos", "1999999999"),
                                     ("started", "elapsed_nanos", "201"), ("started", "wall_nanos", "2000000001")):
            value = self.capture()
            value[stamp][field] = number
            with self.subTest(stamp=stamp, field=field), self.assertRaises(ValueError):
                DIAGNOSTIC.validate_capture(value)
        for changes in ({"global_order_allowed": True}, {"before_deadline": False}, {"inside_grant": False}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                DIAGNOSTIC.validate_capture(dict(self.capture(), **changes))

    def test_other_actual_guards_are_distinct_from_global_clock_order(self):
        value = self.capture()
        value["last"]["wall_nanos"] = value["completed"]["wall_nanos"]
        value["global_order_allowed"] = True
        with self.assertRaises(ValueError):
            DIAGNOSTIC.validate_capture(value)
        expired = copy.deepcopy(value)
        expired.update(deadline_elapsed_nanos="200", before_deadline=False)
        self.assertEqual(DIAGNOSTIC.validate_capture(expired)["rejecting_guards"], ["before_deadline"])
        withdrawn = dict(value, retired=True)
        self.assertEqual(DIAGNOSTIC.validate_capture(withdrawn)["rejecting_guards"], ["retired"])


class ClockBuildPolicyTests(unittest.TestCase):
    def test_instrumentation_only_adds_one_cold_hook_before_last_stamp_update(self):
        for side, sha in (("legacy", DIAGNOSTIC.BENCH.BASELINE), ("legacy_serialized", DIAGNOSTIC.BENCH.BASELINE), ("candidate", "HEAD")):
            source = DIAGNOSTIC.BENCH.command(["git", "show", sha + ":internal/usageinterval/native.go"]) + "\n"
            instrumented = DIAGNOSTIC.instrument(source, side)
            self.assertEqual(instrumented.count(DIAGNOSTIC.HOOK), 1)
            restored = instrumented.replace(DIAGNOSTIC.HOOK, "")
            if side == "legacy_serialized":
                restored = restored.replace(DIAGNOSTIC.SERIALIZED_CLOCK, DIAGNOSTIC.LEGACY_CLOCK)
                predicate = source.split("\t\te.Eligible = ", 1)[1].split(DIAGNOSTIC.ANCHOR, 1)[0]
                self.assertIn("\t\te.Eligible = " + predicate + DIAGNOSTIC.HOOK, instrumented)
            self.assertEqual(restored, source)
            self.assertIn(DIAGNOSTIC.HOOK + DIAGNOSTIC.ANCHOR, instrumented)
            for changed in (source.replace(DIAGNOSTIC.ANCHOR, ""), source + DIAGNOSTIC.ANCHOR, instrumented):
                with self.subTest(side=side), self.assertRaises(ValueError):
                    DIAGNOSTIC.instrument(changed, side)
        with self.assertRaises(ValueError):
            DIAGNOSTIC.instrument(source, "legacy")

    def test_five_three_way_groups_are_bounded_and_counterbalanced(self):
        plan = DIAGNOSTIC.plan()
        self.assertEqual(len(plan), 15)
        for group in range(1, 6):
            sides = [side for number, side in plan if number == group]
            self.assertEqual(set(sides), {"legacy", "legacy_serialized", "candidate"})
            self.assertEqual(len(sides), 3)
        old_before_modified = [next(i for i, (_, side) in enumerate(plan[(g-1)*3:g*3]) if side == "legacy") <
                               next(i for i, (_, side) in enumerate(plan[(g-1)*3:g*3]) if side == "legacy_serialized")
                               for g in range(1, 6)]
        self.assertTrue(any(old_before_modified))
        self.assertFalse(all(old_before_modified))


if __name__ == "__main__":
    unittest.main()
