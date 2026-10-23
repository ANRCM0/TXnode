#!/usr/bin/env python3
"""Retain a rejecting fault verdict even when go test fails before the gate."""

import argparse
import json
from pathlib import Path


REQUIRED = {
    "TestNativeActiveLoadLifecycleFaults",
    "TestNativeLoadRateCancellation",
    "TestNativeUpstreamDisconnectKeepsLoadedPeerFlows",
    "TestNativeAuthenticatedShortWriteKeepsActualTail",
    "TestNativeLoadedSIGKILLRestartsWithOriginalUsagePeriod",
    "TestNativeLoadedAuthorizationExpiryDuringBlockedReport",
    "TestNativeRelayLoadSlowDiskRetainsExclusiveOwnerAndOriginalEvidence",
}


def summarize(directory, outcome):
    events, errors = [], []
    try:
        with (directory / "events.jsonl").open(encoding="utf-8") as source:
            for number, line in enumerate(source, 1):
                try:
                    event = json.loads(line)
                    if not isinstance(event, dict) or not isinstance(event.get("Action"), str):
                        raise ValueError("invalid Go test event")
                    if "Test" in event and not isinstance(event["Test"], str):
                        raise ValueError("invalid Go test name")
                    events.append(event)
                except ValueError as error:
                    errors.append({"line": number, "error": str(error)})
    except (OSError, UnicodeError) as error:
        errors.append({"error": str(error)})
    passed = {event.get("Test") for event in events if event.get("Action") == "pass"}
    rejected = [event for event in events if event.get("Action") in ("skip", "fail")]
    return {
        "required": sorted(REQUIRED),
        "passed": sorted(REQUIRED & passed),
        "rejected": rejected,
        "test_outcome": outcome,
        "evidence_errors": errors,
        "accepted": outcome == "success" and REQUIRED <= passed and not rejected and not errors,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--test-outcome", required=True,
                        choices=("success", "failure", "cancelled", "skipped"))
    args = parser.parse_args()
    summary = summarize(args.directory, args.test_outcome)
    args.directory.mkdir(parents=True, exist_ok=True)
    (args.directory / "summary.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    if not summary["accepted"]:
        raise SystemExit("native loaded fault acceptance incomplete")


if __name__ == "__main__":
    main()
