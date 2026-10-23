#!/usr/bin/env python3
"""Bounded, instrumented completion-clock observations; never formal A/B evidence."""

import argparse
import difflib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parent.parent
SPEC = importlib.util.spec_from_file_location("native_clock_bench", ROOT / "scripts/native-acceptance.py")
BENCH = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(BENCH)
ANCHOR = "\t\tif at.Elapsed > c.last.Elapsed {\n"
HOOK = "\t\tif !e.Eligible {\n\t\t\tnativeClockDiagnosticRecord(c, e, c.last, at, now)\n\t\t}\n"
LEGACY_CLOCK = "\tnow := time.Now()\n\tat := stamp{now.UnixNano(), int64(now.Sub(c.origin))}\n\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n"
SERIALIZED_CLOCK = "\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n\tnow := time.Now()\n\tat := stamp{now.UnixNano(), int64(now.Sub(c.origin))}\n"
SCHEMA = "txnode-native-clock-rejection/v1"
BOOLS = {"retired", "wall_forward", "elapsed_forward", "global_order_allowed", "before_deadline", "inside_grant", "eligible"}
NUMBERS = {"sequence", "bytes", "requested", "deadline_elapsed_nanos", "grant_issued_seconds", "grant_expires_seconds"}


def instrument(source, side):
    if source.count(ANCHOR) != 1 or source.count("e.Eligible = ") != 1 or "nativeClockDiagnosticRecord" in source:
        raise ValueError("completion source does not match the reviewed single-decision shape")
    if side in ("legacy", "legacy_serialized"):
        expected = LEGACY_CLOCK
    elif side == "candidate":
        expected = "\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n\t// Serialize the wall/monotonic observation"
    else:
        raise ValueError("unknown diagnostic side")
    if source.count(expected) != 1:
        raise ValueError("unreviewed completion clock placement")
    if side == "legacy_serialized":
        source = source.replace(LEGACY_CLOCK, SERIALIZED_CLOCK)
    return source.replace(ANCHOR, HOOK + ANCHOR)


def decimal(value):
    if not isinstance(value, str) or not re.fullmatch(r"(?:0|-?[1-9][0-9]*)", value):
        raise ValueError("clock evidence requires exact decimal strings")
    number = int(value)
    if not -(1 << 63) <= number <= (1 << 64) - 1:
        raise ValueError("clock evidence integer outside reviewed bounds")
    return number


def validate_capture(value):
    if not isinstance(value, dict) or value.get("schema") != SCHEMA or type(value.get("observed")) is not bool:
        raise ValueError("invalid clock observation envelope")
    if not value["observed"]:
        if set(value) != {"schema", "observed"}:
            raise ValueError("unobserved capture includes unreviewed fields")
        return {"observed": False, "rejecting_guards": []}
    fields = {"schema", "observed", "direction", "started", "completed", "last"} | BOOLS | NUMBERS
    if set(value) != fields or value["direction"] not in ("upload", "download") or any(type(value[k]) is not bool for k in BOOLS):
        raise ValueError("unreviewed clock capture fields, direction or booleans")
    numbers = {k: decimal(value[k]) for k in NUMBERS}
    if numbers["sequence"] <= 0 or any(not -(1 << 63) <= v < (1 << 63) for k, v in numbers.items() if k != "sequence") or not 0 <= numbers["bytes"] <= numbers["requested"]:
        raise ValueError("invalid captured operation")
    stamps = {}
    for name in ("started", "completed", "last"):
        item = value[name]
        if not isinstance(item, dict) or set(item) != {"wall_nanos", "elapsed_nanos"}:
            raise ValueError("unreviewed clock stamp fields")
        stamps[name] = {k: decimal(v) for k, v in item.items()}
        if any(not -(1 << 63) <= v < (1 << 63) for v in stamps[name].values()):
            raise ValueError("captured stamp outside signed int64 bounds")
    start, end, last = (stamps[k] for k in ("started", "completed", "last"))
    guards = {
        "wall_forward": end["wall_nanos"] >= start["wall_nanos"],
        "elapsed_forward": end["elapsed_nanos"] >= start["elapsed_nanos"],
        "global_order_allowed": end["elapsed_nanos"] < last["elapsed_nanos"] or end["wall_nanos"] >= last["wall_nanos"],
        "before_deadline": end["elapsed_nanos"] < numbers["deadline_elapsed_nanos"],
        "inside_grant": numbers["grant_issued_seconds"] * 1_000_000_000 <= end["wall_nanos"] < numbers["grant_expires_seconds"] * 1_000_000_000,
    }
    if any(value[k] is not expected for k, expected in guards.items()) or value["eligible"] is not False:
        raise ValueError("captured guard values disagree with exact timestamps")
    rejecting = (["retired"] if value["retired"] else []) + [k for k, allowed in guards.items() if not allowed]
    if not rejecting:
        raise ValueError("capture does not prove any rejecting guard")
    return {"observed": True, "rejecting_guards": rejecting,
            "last_wall_delta_nanos": end["wall_nanos"] - last["wall_nanos"],
            "last_elapsed_delta_nanos": end["elapsed_nanos"] - last["elapsed_nanos"]}


def plan():
    result = []
    sides = ("legacy", "legacy_serialized", "candidate")
    for group in range(5):
        order = sides[group % 3:] + sides[:group % 3]
        if group % 2:
            order = tuple(reversed(order))
        result.extend((group + 1, side) for side in order)
    return result


def run(args):
    if os.environ.get("GITHUB_ACTIONS") != "true" or platform.system() != "Linux":
        raise RuntimeError("clock diagnostic execution belongs to Linux GitHub Actions")
    if not re.fullmatch("[0-9a-f]{40}", args.candidate):
        raise ValueError("candidate must be a full immutable SHA")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    clock_source = Path("/sys/devices/system/clocksource/clocksource0/current_clocksource")
    report = {"schema": "txnode-native-clock-diagnostics/v1", "accepted": False,
              "collection_complete": False, "baseline_source": BENCH.BASELINE, "candidate_source": args.candidate,
              "tool_revision": BENCH.command(["git", "rev-parse", "HEAD"]),
              "run_id": os.environ.get("GITHUB_RUN_ID"), "run_attempt": os.environ.get("GITHUB_RUN_ATTEMPT"),
              "tool_sha256": BENCH.digest(Path(__file__)), "go": BENCH.command(["go", "version"]),
              "machine": {"platform": platform.platform(), "cpu_count": os.cpu_count(),
                          "clock_source": clock_source.read_text().strip() if clock_source.exists() else "unavailable"},
              "scope": "instrumented disposable builds; legacy_serialized additionally moves only the old completion clock under its lock, preserving eligibility and persistence; first rejected completion only; no BeginIO observation, throughput comparison, S3 or historical-run causality claim",
              "settings": {"groups": 5, "seconds": 10, "warmup": 2, "concurrency": 4, "cpu_profiles": False},
              "builds": {}, "clock_samples": [], "samples": [], "comparisons": []}
    workspace = Path(tempfile.mkdtemp(prefix="txnode-native-clock-"))
    checkouts = []
    origin = None
    try:
        for side, sha in (("legacy", BENCH.BASELINE), ("legacy_serialized", BENCH.BASELINE), ("candidate", args.candidate)):
            checkout = workspace / side
            BENCH.command(["git", "worktree", "add", "--detach", str(checkout), sha])
            checkouts.append(checkout)
            build_dir = output / ("build-" + side)
            build_dir.mkdir()
            native = checkout / "internal/usageinterval/native.go"
            original = native.read_text()
            instrumented = instrument(original, side)
            metadata = {"source_revision": sha, "source_tree": BENCH.command(["git", "rev-parse", sha + "^{tree}"]),
                        "source_native_sha256": BENCH.digest(native), "instrumented": True,
                        "clock_placement": "before_collector_lock" if side == "legacy" else "inside_collector_lock",
                        "counterfactual_clock_serialization": side == "legacy_serialized"}
            overlay = build_dir / "source-overlay.patch"
            overlay.write_text("".join(difflib.unified_diff(original.splitlines(True), instrumented.splitlines(True),
                                                         fromfile="native.go", tofile="native.go+clock-diagnostic")))
            native.write_text(instrumented)
            helper = checkout / "internal/usageinterval/native_clock_diagnostic.go"
            shutil.copyfile(ROOT / "scripts/native-clock-diagnostic.go.tmpl", helper)
            harness = checkout / "cmd/native-ab"
            harness.mkdir()
            shutil.copyfile(ROOT / "scripts/native-acceptance-server.go.tmpl", harness / "main.go")
            factory_side = "legacy" if side == "legacy_serialized" else side
            shutil.copyfile(ROOT / ("scripts/native-acceptance-%s.go.tmpl" % factory_side), harness / "factory.go")
            shutil.copyfile(ROOT / "scripts/native-acceptance-bucket-diagnostic.go.tmpl", checkout / "internal/usagebucket/native_ab_diagnostic.go")
            metadata.update(instrumented_native_sha256=BENCH.digest(native), overlay_sha256=BENCH.digest(overlay),
                            helper_sha256=BENCH.digest(helper),
                            template_sha256={name: BENCH.digest(ROOT / "scripts" / name) for name in
                                             ("native-acceptance-server.go.tmpl", "native-acceptance-%s.go.tmpl" % factory_side,
                                              "native-acceptance-bucket-diagnostic.go.tmpl")},
                            module_lock_sha256={name: BENCH.digest(checkout / name) for name in ("go.mod", "go.sum")})
            report["builds"][side] = metadata
            (build_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
            prefetch = BENCH.prefetch_modules(checkout, output, side)
            metadata["prefetch"] = prefetch
            if prefetch["status"] != "complete" or any(BENCH.digest(checkout / name) != expected for name, expected in metadata["module_lock_sha256"].items()):
                raise RuntimeError("diagnostic module preparation failed or changed locks")
            binary = output / ("clock-server-" + side)
            BENCH.command(["go", "build", *BENCH.FLAGS, "-o", str(binary), "./cmd/native-ab"], checkout)
            metadata.update(harness_sha256=BENCH.digest(binary), status="built")
            (build_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n")
        origin = BENCH.Origin()
        sampling = argparse.Namespace(warmup=2, seconds=10, concurrency=4)
        for group, side in plan():
            state = output / ("clock-g%d-%s" % (group, side))
            previous = os.environ.get("TXNODE_NATIVE_CLOCK_DIAGNOSTIC_ROOT")
            try:
                os.environ["TXNODE_NATIVE_CLOCK_DIAGNOSTIC_ROOT"] = str(state)
                sample = BENCH.sample(output / ("clock-server-" + side), state, "usage_v2", "upload", sampling,
                                      origin, persistence_diagnostics_only=True)
            finally:
                if previous is None:
                    os.environ.pop("TXNODE_NATIVE_CLOCK_DIAGNOSTIC_ROOT", None)
                else:
                    os.environ["TXNODE_NATIVE_CLOCK_DIAGNOSTIC_ROOT"] = previous
            if "NATIVE_CLOCK_DIAGNOSTIC_WRITE_FAILED" in (state / "server.log").read_text():
                raise ValueError("rejected-completion observation could not be saved")
            capture = validate_capture(json.loads((state / "clock-rejection.json").read_text()))
            result = {"group": group, "side": side, "sample_status": sample["status"], "stage": sample.get("stage"),
                      "capture": capture, "state_directory": state.name}
            report["clock_samples"].append(result)
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
            print(json.dumps(result), flush=True)
        report["collection_complete"] = True
        return report
    finally:
        if origin is not None:
            origin.close()
        for checkout in reversed(checkouts):
            BENCH.command(["git", "worktree", "remove", "--force", str(checkout)])
        shutil.rmtree(workspace, ignore_errors=True)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        lines = ["# Independent completion clock diagnostics", "", "Accepted for S3: false.",
                 "Collection complete: " + str(report["collection_complete"]) + ".", "", report["scope"], ""]
        lines.extend("- g%d %s: %s; %s" % (item["group"], item["side"], item["sample_status"], item["capture"])
                     for item in report["clock_samples"])
        (output / "report.md").write_text("\n".join(lines) + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", required=True, type=Path)
    result = run(parser.parse_args())
    raise SystemExit(0 if result["collection_complete"] is True and result["accepted"] is False else 1)
