"""Policy regressions for the interop gate; execute in GitHub Actions."""

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

import interop_gate as gate


def manifest():
    return {"schema": "txnode-interop-cases/v1", "package": "example/txnode",
            "profiles": {"quick": {}, "full": {}},
            "clients": {"client": {"version": "1.0", "environment": "CLIENT", "sha256": "a" * 64}},
            "cases": [{"test": "TestInteropSupported", "client": "client", "profiles": ["quick", "full"],
                       "expected": "pass", "subtests": ["one", "two"]},
                      {"test": "TestInteropGap", "client": "client", "profiles": ["full"],
                       "expected": "known-gap", "gap": {"id": "GAP-1", "marker": "INTEROP_KNOWN_GAP:GAP-1",
                                                          "reason": "explicitly unaccepted"}}]}


def event(action, test=None, output=None):
    value = {"Action": action, "Package": "example/txnode"}
    if test:
        value["Test"] = test
    if output is not None:
        value["Output"] = output
    return value


def supported_events():
    name = "TestInteropSupported"
    return [event("run", name), event("run", name + "/one"), event("pass", name + "/one"),
            event("run", name + "/two"), event("pass", name + "/two"), event("pass", name)]


def full_events():
    return supported_events() + [event("run", "TestInteropGap"),
                                event("output", "TestInteropGap", "INTEROP_KNOWN_GAP:GAP-1 explicitly unaccepted\n"),
                                event("skip", "TestInteropGap"), event("pass")]


def result(events, profile="full", exit_code=0):
    return gate.summarize(manifest(), profile, [json.dumps(value) for value in events], exit_code)


class InteropResults(unittest.TestCase):
    def test_explicit_gap_is_retained_without_counting_as_pass(self):
        report = result(full_events())
        self.assertTrue(report["accepted"])
        self.assertEqual(report["status"], "accepted-with-gaps")
        self.assertEqual(report["counts"], {"passed_top_level": 1, "passed_subtests": 2, "known_gap": 1})

    def test_unavailable_client_combination_is_separate_from_known_gap_and_pass(self):
        value = manifest()
        value["cases"][1]["expected"] = "not-applicable"
        report = gate.summarize(value, "full", [json.dumps(item) for item in full_events()], 0)
        self.assertTrue(report["accepted"])
        self.assertEqual(report["counts"], {"passed_top_level": 1, "passed_subtests": 2, "not_applicable": 1})

    def test_required_client_missing_cannot_hide_behind_skip(self):
        events = [event("run", "TestInteropSupported"),
                  event("output", "TestInteropSupported", "CLIENT not set"),
                  event("skip", "TestInteropSupported"), event("pass")]
        self.assertFalse(result(events, "quick")["accepted"])

    def test_child_failure_or_skip_cannot_hide_behind_parent_pass(self):
        for action in ["fail", "skip"]:
            with self.subTest(action=action):
                events = supported_events() + [event("pass")]
                events[2]["Action"] = action
                self.assertFalse(result(events, "quick")["accepted"])

    def test_unknown_children_and_out_of_profile_cases_fail(self):
        for name in ["TestInteropSupported/unexpected", "TestInteropGap", "TestInteropNew"]:
            with self.subTest(test=name):
                events = supported_events() + [event("run", name), event("pass", name), event("pass")]
                self.assertFalse(result(events, "quick")["accepted"])

    def test_missing_or_duplicate_events_fail(self):
        base = supported_events() + [event("pass")]
        variants = [base[1:], base[:-1], base + [event("pass")],
                    base + [event("run", "TestInteropSupported")],
                    base + [event("pass", "TestInteropSupported/one")]]
        for events in variants:
            with self.subTest(events=events):
                self.assertFalse(result(events, "quick")["accepted"])

    def test_gap_marker_and_reason_are_both_required(self):
        for text in ["arbitrary connection error", "INTEROP_KNOWN_GAP:OTHER explicitly unaccepted",
                     "INTEROP_KNOWN_GAP:GAP-1 arbitrary connection error",
                     "INTEROP_KNOWN_GAP:GAP-1 explicitly unaccepted arbitrary connection error",
                     "INTEROP_KNOWN_GAP:GAP-1 explicitly unaccepted INTEROP_KNOWN_GAP:OTHER"]:
            with self.subTest(text=text):
                events = full_events()
                events[-3]["Output"] = text
                self.assertFalse(result(events)["accepted"])

    def test_recovered_gap_requires_manifest_to_be_tightened(self):
        events = full_events()
        events[-2]["Action"] = "pass"
        report = result(events)
        self.assertFalse(report["accepted"])
        self.assertTrue(any("tighten manifest" in value for value in report["errors"]))

    def test_failure_exit_or_package_failure_is_never_accepted(self):
        self.assertFalse(result(full_events(), exit_code=1)["accepted"])
        events = full_events()
        events[-1]["Action"] = "fail"
        self.assertFalse(result(events)["accepted"])

    def test_truncated_or_invalid_json_is_rejected(self):
        events = [json.dumps(value) for value in full_events()]
        for invalid in ["{", "[]", json.dumps({"Action": "run", "Test": []})]:
            with self.subTest(invalid=invalid):
                self.assertFalse(gate.summarize(manifest(), "full", events + [invalid], 0)["accepted"])

    def test_foreign_package_event_is_rejected(self):
        events = full_events()
        events[0]["Package"] = "other/package"
        self.assertFalse(result(events)["accepted"])

    def test_cached_package_is_not_fresh_acceptance(self):
        events = full_events()
        events.insert(-1, event("output", output="ok example/txnode (cached)\n"))
        self.assertFalse(result(events)["accepted"])


class InteropManifest(unittest.TestCase):
    def test_nested_subtests_are_explicit_paths_and_cannot_hide_failures(self):
        value = manifest()
        value["cases"][0]["subtests"] = ["one", "one/two"]
        gate.validate_manifest(value)
        names = ["TestInteropSupported", "TestInteropSupported/one", "TestInteropSupported/one/two"]
        events = [event("run", name) for name in names] + [event("pass", name) for name in reversed(names)] + [event("pass")]
        report = gate.summarize(value, "quick", [json.dumps(item) for item in events], 0)
        self.assertTrue(report["accepted"])
        events[3]["Action"] = "skip"
        self.assertFalse(gate.summarize(value, "quick", [json.dumps(item) for item in events], 0)["accepted"])
        for child in ["one//two", "/one", "one/", "one/../two", "one.*"]:
            with self.subTest(child=child), self.assertRaisesRegex(ValueError, "invalid subtest"):
                value["cases"][0]["subtests"] = [child]
                gate.validate_manifest(value)

    def test_new_source_case_must_be_explicitly_classified(self):
        value = manifest()
        with self.assertRaisesRegex(ValueError, "manifest/source mismatch"):
            gate.validate_manifest(value, [case["test"] for case in value["cases"]] + ["TestInteropNew"])

    def test_unknown_client_invalid_pin_and_duplicate_cases_fail(self):
        values = []
        value = manifest()
        value["cases"][0]["client"] = "unknown"
        values.append(value)
        value = manifest()
        value["clients"]["client"]["sha256"] = "short"
        values.append(value)
        value = manifest()
        value["cases"].append(copy.deepcopy(value["cases"][0]))
        values.append(value)
        for value in values:
            with self.subTest(value=value), self.assertRaises(ValueError):
                gate.validate_manifest(value)

    def test_quick_profile_cannot_budget_known_gap(self):
        value = manifest()
        value["cases"][1]["profiles"].append("quick")
        with self.assertRaisesRegex(ValueError, "invalid explicit gap"):
            gate.validate_manifest(value)

    def test_preflight_rejects_missing_binary_before_executing_go(self):
        proofs, errors = gate.client_proofs(manifest(), "quick", {})
        self.assertEqual(proofs["client"]["expected_version"], "1.0")
        self.assertTrue(any("missing or not executable" in value for value in errors))

    def test_preflight_rejects_wrong_binary_digest(self):
        with tempfile.TemporaryDirectory() as directory:
            binary = Path(directory) / "client"
            binary.write_bytes(b"wrong pinned binary")
            binary.chmod(0o700)
            with mock.patch.object(os, "access", return_value=True):
                _, errors = gate.client_proofs(manifest(), "quick", {"CLIENT": str(binary)})
            self.assertTrue(any("digest mismatch" in value for value in errors))


if __name__ == "__main__":
    unittest.main()
