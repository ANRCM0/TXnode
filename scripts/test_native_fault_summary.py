"""Failure and missing-evidence cases must produce a rejecting fault summary."""

import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location("native_fault_summary", Path(__file__).with_name("native-fault-summary.py"))
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)


class FaultSummaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)

    def write(self, extra=(), missing=()):
        events = [{"Action": "pass", "Test": name} for name in sorted(SUMMARY.REQUIRED - set(missing))]
        (self.directory / "events.jsonl").write_text(
            "".join(json.dumps(event) + "\n" for event in events + list(extra)), encoding="utf-8")

    def test_requires_all_seven_tests_and_successful_command(self):
        self.write()
        self.assertTrue(SUMMARY.summarize(self.directory, "success")["accepted"])
        for outcome in ("failure", "cancelled", "skipped"):
            with self.subTest(outcome=outcome):
                result = SUMMARY.summarize(self.directory, outcome)
                self.assertFalse(result["accepted"])
                self.assertEqual(result["test_outcome"], outcome)
        self.write(missing={next(iter(SUMMARY.REQUIRED))})
        self.assertFalse(SUMMARY.summarize(self.directory, "success")["accepted"])

    def test_failed_or_skipped_tests_and_package_failures_remain_rejected(self):
        for event in ({"Action": "fail", "Test": "TestNativeLoadedSIGKILLRestartsWithOriginalUsagePeriod"},
                      {"Action": "skip", "Test": "unexpected-child"}, {"Action": "fail", "Package": "native"}):
            with self.subTest(event=event):
                self.write(extra=[event])
                result = SUMMARY.summarize(self.directory, "failure")
                self.assertFalse(result["accepted"])
                self.assertEqual(result["rejected"], [event])

    def test_missing_empty_and_truncated_logs_never_accept(self):
        result = SUMMARY.summarize(self.directory, "failure")
        self.assertFalse(result["accepted"])
        self.assertTrue(result["evidence_errors"])
        for text in ("", '{"Action":', '[]\n', '{"Action":"pass","Test":[]}\n'):
            with self.subTest(text=text):
                (self.directory / "events.jsonl").write_text(text, encoding="utf-8")
                self.assertFalse(SUMMARY.summarize(self.directory, "success")["accepted"])
        self.write()
        with (self.directory / "events.jsonl").open("a", encoding="utf-8") as output:
            output.write('{"Action":')
        result = SUMMARY.summarize(self.directory, "success")
        self.assertFalse(result["accepted"])
        self.assertTrue(result["evidence_errors"])

    def test_cli_writes_rejection_before_exiting_on_failed_go_command(self):
        self.write()
        with patch("sys.argv", ["native-fault-summary.py", str(self.directory), "--test-outcome", "failure"]):
            with self.assertRaises(SystemExit):
                SUMMARY.main()
        result = json.loads((self.directory / "summary.json").read_text(encoding="utf-8"))
        self.assertFalse(result["accepted"])
        self.assertEqual(result["test_outcome"], "failure")
