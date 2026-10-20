#!/usr/bin/env python3
"""Run pinned interop profiles and reject missing tests or unbudgeted skips."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
from collections import Counter, defaultdict


ROOT = Path(__file__).resolve().parents[1]
MANIFEST = ROOT / "scripts/interop-cases.v1.json"
TERMINAL = {"pass", "fail", "skip"}


def validate_manifest(manifest, discovered=None):
    if not isinstance(manifest, dict):
        raise ValueError("interop manifest must be an object")
    if manifest.get("schema") != "txnode-interop-cases/v1":
        raise ValueError("unsupported interop manifest schema")
    if (not isinstance(manifest.get("profiles"), dict) or not isinstance(manifest.get("clients"), dict)
            or not isinstance(manifest.get("cases"), list)):
        raise ValueError("manifest profiles/clients/cases have invalid types")
    if set(manifest.get("profiles", {})) != {"quick", "full"}:
        raise ValueError("manifest must declare quick and full profiles")
    names = set()
    gaps = set()
    for case in manifest.get("cases", []):
        if not isinstance(case, dict):
            raise ValueError("manifest case must be an object")
        name = case.get("test", "")
        if not re.fullmatch(r"TestInterop\w+", name) or name in names:
            raise ValueError("invalid or duplicate case: " + name)
        names.add(name)
        profiles = case.get("profiles", [])
        if (not isinstance(profiles, list) or not profiles or not all(isinstance(x, str) for x in profiles)
                or "full" not in profiles or not set(profiles) <= {"quick", "full"}):
            raise ValueError("invalid case profiles: " + name)
        if case.get("client") not in manifest.get("clients", {}):
            raise ValueError("unknown case client: " + name)
        if case.get("expected") not in {"pass", "known-gap", "not-applicable"}:
            raise ValueError("invalid expected result: " + name)
        children = case.get("subtests", [])
        if (not isinstance(children, list) or not all(isinstance(x, str) for x in children)
                or len(children) != len(set(children)) or any(not re.fullmatch(r"[\w-]+", x) for x in children)):
            raise ValueError("invalid subtest declaration: " + name)
        if case["expected"] != "pass":
            gap = case.get("gap", {})
            if not isinstance(gap, dict):
                raise ValueError("manifest gap must be an object: " + name)
            gap_id = gap.get("id", "")
            if (not re.fullmatch(r"[A-Z0-9-]+", gap_id) or gap_id in gaps
                    or gap.get("marker") != "INTEROP_KNOWN_GAP:" + gap_id
                    or not gap.get("reason") or children or "quick" in profiles):
                raise ValueError("invalid explicit gap: " + name)
            gaps.add(gap_id)
        elif "gap" in case:
            raise ValueError("passing case cannot keep a skip budget: " + name)
    if not names or not any("quick" in case["profiles"] for case in manifest["cases"]):
        raise ValueError("empty interop profile")
    if discovered is not None and names != set(discovered):
        raise ValueError("manifest/source mismatch; missing=%s stale=%s" %
                         (sorted(set(discovered) - names), sorted(names - set(discovered))))
    for name, client in manifest["clients"].items():
        if not isinstance(client, dict):
            raise ValueError("manifest client must be an object: " + name)
        if not client.get("environment") or not client.get("version"):
            raise ValueError("incomplete client pin: " + name)
        digest = client.get("sha256")
        if digest is not None and not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise ValueError("invalid client digest: " + name)
        if digest is None and not client.get("version_pattern"):
            raise ValueError("client needs binary pin or explicit system version: " + name)
        if digest is None:
            try:
                re.compile(client["version_pattern"])
            except re.error as error:
                raise ValueError("invalid system client version pattern: " + name) from error


def load_manifest(path=MANIFEST):
    with path.open(encoding="utf-8") as source:
        manifest = json.load(source)
    validate_manifest(manifest)
    if manifest.get("source") != "internal/kernel/txnode/interop_test.go":
        raise ValueError("manifest must reference the native interop source")
    source = "\n".join(path.read_text(encoding="utf-8")
                       for path in sorted((ROOT / manifest["source"]).parent.glob("*_test.go")))
    discovered = re.findall(r"^func\s+(TestInterop\w*)\s*\(\s*\w+\s+\*testing\.T\s*\)", source, re.MULTILINE)
    if len(discovered) != len(set(discovered)):
        raise ValueError("duplicate interop source case names")
    validate_manifest(manifest, discovered)
    return manifest


def selected_cases(manifest, profile):
    return [case for case in manifest["cases"] if profile in case["profiles"]]


def summarize(manifest, profile, lines, go_exit_code, metadata=None, initial_errors=None):
    cases = selected_cases(manifest, profile)
    expected = {case["test"]: case for case in cases}
    allowed = set(expected)
    for case in cases:
        allowed.update(case["test"] + "/" + child for child in case.get("subtests", []))
    errors = list(initial_errors or [])
    starts = Counter()
    endings = defaultdict(list)
    outputs = defaultdict(list)
    package_endings = []
    for number, line in enumerate(lines, 1):
        try:
            event = json.loads(line)
        except (ValueError, TypeError):
            errors.append("invalid go test JSON at line %d" % number)
            continue
        if not isinstance(event, dict):
            errors.append("non-object go test JSON at line %d" % number)
            continue
        package = event.get("Package")
        if package and package != manifest["package"]:
            errors.append("unexpected package: " + str(package))
            continue
        name, action = event.get("Test"), event.get("Action")
        if ((name is not None and not isinstance(name, str))
                or not isinstance(action, str) or not isinstance(event.get("Output", ""), str)):
            errors.append("invalid go test event fields at line %d" % number)
            continue
        if name:
            if name not in allowed:
                errors.append("unexpected test/subtest: " + name)
            if action == "run":
                starts[name] += 1
            elif action in TERMINAL:
                endings[name].append(action)
            elif action == "output":
                outputs[name].append(event.get("Output", ""))
        elif package and action in TERMINAL:
            package_endings.append(action)
        if (not name and action == "output"
                and re.search(r"^ok\s+\S+\s+\(cached\)", event.get("Output", ""), re.MULTILINE)):
            errors.append("cached go test result is not fresh interop evidence")
    if go_exit_code != 0:
        errors.append("go test exit status: %s" % go_exit_code)
    if package_endings != ["pass"]:
        errors.append("package did not complete exactly once with pass: " + repr(package_endings))

    results = []
    counts = Counter()
    for case in cases:
        name = case["test"]
        terminal = endings[name]
        actual = terminal[0] if len(terminal) == 1 else "missing-or-duplicate"
        if starts[name] != 1 or len(terminal) != 1:
            errors.append("case must start and finish exactly once: " + name)
        elif case["expected"] == "pass":
            if actual != "pass":
                errors.append("supported case did not pass: " + name + " (" + actual + ")")
            else:
                counts["passed_top_level"] += 1
            if any("INTEROP_KNOWN_GAP:" in output for output in outputs[name]):
                errors.append("supported case emitted a gap marker: " + name)
        else:
            gap = case["gap"]
            if actual == "pass":
                errors.append("gap unexpectedly passed; tighten manifest: " + name)
            elif actual != "skip":
                errors.append("declared gap did not explicitly skip: " + name)
            else:
                text = "".join(outputs[name])
                markers = re.findall(r"INTEROP_KNOWN_GAP:([A-Z0-9-]+)", text)
                reasons = re.findall(re.escape(gap["marker"]) + r" ([^\r\n]*)", text)
                if markers != [gap["id"]] or reasons != [gap["reason"]]:
                    errors.append("gap ID/reason mismatch: " + name)
                else:
                    counts[case["expected"].replace("-", "_")] += 1
        for child in case.get("subtests", []):
            child_name = name + "/" + child
            if starts[child_name] != 1 or endings[child_name] != ["pass"]:
                errors.append("required subtest did not pass exactly once: " + child_name)
            else:
                counts["passed_subtests"] += 1
        result = {"test": name, "client": case["client"], "expected": case["expected"], "actual": actual}
        if "gap" in case:
            result["gap"] = case["gap"]
        results.append(result)
    # A failing or skipped unknown child must not disappear behind its parent's result.
    for name in allowed - set(expected):
        if any("INTEROP_KNOWN_GAP:" in output for output in outputs[name]):
            errors.append("passing subtest emitted a gap marker: " + name)
    errors = sorted(set(errors))
    return {"schema": "txnode-interop-result/v1", "profile": profile,
            "status": "failure" if errors else "accepted-with-gaps" if any(case["expected"] != "pass" for case in cases) else "accepted",
            "accepted": not errors, "go_exit_code": go_exit_code, "counts": dict(counts),
            "metadata": metadata or {}, "cases": results, "errors": errors}


def digest(path):
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def client_proofs(manifest, profile, environment):
    proofs = {}
    errors = []
    required = sorted({case["client"] for case in selected_cases(manifest, profile)})
    for name in required:
        client = manifest["clients"][name]
        value = environment.get(client["environment"], client.get("default_path", ""))
        path = Path(value) if value else None
        proof = {"expected_version": client["version"], "environment": client["environment"], "path": value}
        proofs[name] = proof
        if path is None or not path.is_file() or not os.access(path, os.X_OK):
            errors.append("required client missing or not executable: " + name)
            continue
        try:
            actual = digest(path)
        except OSError as error:
            errors.append("cannot read client binary %s: %s" % (name, error))
            continue
        proof["sha256"] = actual
        if "sha256" in client:
            proof["expected_sha256"] = client["sha256"]
            if actual != client["sha256"]:
                errors.append("pinned client digest mismatch: " + name)
        else:
            try:
                version = subprocess.run([str(path), *client["version_arguments"]], check=True,
                                         capture_output=True, text=True, timeout=10).stdout
                proof["version_output"] = version
                proof["provenance"] = client["provenance"]
                if not re.search(client["version_pattern"], version):
                    errors.append("system client version mismatch: " + name)
                if name == "curl" and not re.search(r"^Features:.*\bHTTP2\b", version, re.MULTILINE):
                    errors.append("system curl lacks required HTTP2 capability")
            except (OSError, subprocess.SubprocessError) as error:
                errors.append("cannot read client version %s: %s" % (name, error))
    return proofs, errors


def command_output(command):
    try:
        return subprocess.run(command, cwd=ROOT, check=True, capture_output=True,
                              text=True, timeout=15).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unavailable"


def retain_result(output, result):
    output.mkdir(parents=True, exist_ok=True)
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    rows = ["## Interop %s: %s" % (result["profile"], result["status"]), "",
            "Source: `%s`" % result["metadata"].get("source_revision", "unknown"), "",
            "Known gaps and unavailable combinations are **not accepted capabilities**.", "",
            "| Test | Expected | Observed |", "| --- | --- | --- |"]
    rows.extend("| `%s` | %s | %s |" % (case["test"], case["expected"], case["actual"]) for case in result["cases"])
    if result["errors"]:
        rows.extend(["", "Errors:", ""] + ["- " + error for error in result["errors"]])
    markdown = "\n".join(rows) + "\n"
    (output / "summary.md").write_text(markdown, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as target:
            target.write(markdown)


def run_profile(manifest, profile, output):
    output.mkdir(parents=True, exist_ok=True)
    environment = dict(os.environ)
    environment["TXNODE_INTEROP_STRICT"] = "1"
    environment.pop("TXNODE_INTEROP_DIAGNOSTIC_GAPS", None)
    proofs, errors = client_proofs(manifest, profile, environment)
    revision = command_output(["git", "rev-parse", "HEAD"])
    metadata = {"source_revision": revision, "source_tree": command_output(["git", "rev-parse", "HEAD^{tree}"]),
                "requested_revision": environment.get("GITHUB_SHA", ""), "run_id": environment.get("GITHUB_RUN_ID", ""),
                "event": environment.get("GITHUB_EVENT_NAME", ""), "go_version": command_output(["go", "version"]),
                "manifest_sha256": digest(MANIFEST), "clients": proofs, "strict": True}
    if environment.get("GITHUB_SHA") and environment["GITHUB_SHA"] != revision:
        errors.append("checkout revision does not match requested GITHUB_SHA")
    expression = "^(" + "|".join(re.escape(case["test"]) for case in selected_cases(manifest, profile)) + ")$"
    command = ["go", "test", "./internal/kernel/txnode/", "-run", expression, "-count=1", "-json", "-timeout=900s"]
    metadata["command"] = command
    event_path, stderr_path = output / "events.jsonl", output / "stderr.log"
    exit_code = 2
    with event_path.open("wb") as events, stderr_path.open("wb") as stderr:
        if not errors:
            process = None
            try:
                process = subprocess.Popen(command, cwd=ROOT, env=environment, stdout=events, stderr=stderr,
                                           start_new_session=os.name == "posix")
                exit_code = process.wait(timeout=1200)
            except subprocess.TimeoutExpired:
                errors.append("interop runner wall-clock deadline exceeded")
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait()
                exit_code = 124
            except OSError as error:
                errors.append("cannot start interop: " + str(error))
    with event_path.open(encoding="utf-8", errors="replace") as events:
        result = summarize(manifest, profile, events, exit_code, metadata, errors)
    retain_result(output, result)
    print("Interop %s: %s; counts=%s" % (profile, result["status"], json.dumps(result["counts"], sort_keys=True)))
    for error in result["errors"]:
        print("interop gate: " + error, file=sys.stderr)
    return 0 if result["accepted"] else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", choices=["quick", "full"], required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    try:
        manifest = load_manifest()
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        result = {"schema": "txnode-interop-result/v1", "profile": args.profile, "status": "failure", "accepted": False,
                  "go_exit_code": None, "counts": {}, "metadata": {}, "cases": [], "errors": [str(error)]}
        retain_result(args.output, result)
        print("interop manifest: " + str(error), file=sys.stderr)
        return 1
    return run_profile(manifest, args.profile, args.output)


if __name__ == "__main__":
    sys.exit(main())
