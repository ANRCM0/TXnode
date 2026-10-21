#!/usr/bin/env python3
"""Actions-only, same-job native/legacy SOCKS relay measurement.

No performance claim is emitted for a failed sample, missing accounting
evidence, a noisy runner, or an unsupported measurement.
"""

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import secrets
import shutil
import signal
import socket
import statistics
import struct
import subprocess
import tempfile
import threading
import time


ROOT = Path(__file__).resolve().parent.parent
BASELINE = "a1ad2695e1143269168c36a274283de3342e91c7"
MODES = ("ordinary", "usage_v2", "events")
WORKLOADS = ("upload", "download", "short", "long")
FLAGS = ["-trimpath", "-ldflags=-s -w", "-tags", "with_quic with_utls with_wireguard with_acme with_clash_api"]
CPU_METHOD = "process-cputime-ns-v1"


def command(args, cwd=ROOT):
    return subprocess.check_output(args, cwd=cwd, text=True, stderr=subprocess.STDOUT).strip()


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def prefetch_modules(checkout, output, side):
    log_path = output / ("prefetch-%s.log" % side)
    evidence = {"status": "incomplete", "log": log_path.name, "attempts": []}
    with log_path.open("w") as log:
        for attempt in range(1, 4):
            result = subprocess.run(["go", "mod", "download"], cwd=checkout,
                                    text=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
            log.write("=== attempt %d ===\n" % attempt)
            log.write(result.stdout)
            log.write("\n=== exit %d ===\n" % result.returncode)
            log.flush()
            evidence["attempts"].append({"attempt": attempt, "status": "succeeded" if result.returncode == 0 else "failed",
                                         "exit_code": result.returncode, "log": log_path.name})
            if result.returncode == 0:
                evidence["status"] = "complete"
                break
            if attempt < 3:
                time.sleep(5)
    return evidence


def receive(conn, length):
    data = bytearray()
    while len(data) < length:
        chunk = conn.recv(length - len(data))
        if not chunk:
            raise EOFError("unexpected relay EOF")
        data.extend(chunk)
    return bytes(data)


class Origin:
    def __init__(self):
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(2048)
        self.port = self.listener.getsockname()[1]
        self.stopped = threading.Event()
        self.sockets = set()
        self.lock = threading.Lock()
        self.thread = threading.Thread(target=self.accept, daemon=True)
        self.thread.start()

    def accept(self):
        while not self.stopped.is_set():
            try:
                conn, _ = self.listener.accept()
            except OSError:
                return
            with self.lock:
                self.sockets.add(conn)
            threading.Thread(target=self.serve, args=(conn,), daemon=True).start()

    def serve(self, conn):
        try:
            conn.settimeout(15)
            while True:
                action, length = struct.unpack("!cI", receive(conn, 5))
                if length > 1048576:
                    raise ValueError("oversized benchmark request")
                if action == b"D":
                    conn.sendall(b"x" * length)
                elif action == b"U":
                    receive(conn, length)
                    conn.sendall(b"K")
                elif action == b"E":
                    conn.sendall(receive(conn, length))
                else:
                    raise ValueError("unknown benchmark request")
        except (OSError, EOFError, ValueError):
            pass
        finally:
            with self.lock:
                self.sockets.discard(conn)
            conn.close()

    def close(self):
        self.stopped.set()
        self.listener.close()
        with self.lock:
            for conn in self.sockets:
                conn.close()


def connect(port, origin):
    conn = socket.create_connection(("127.0.0.1", port), timeout=15)
    try:
        conn.sendall(b"\x05\x01\x02")
        if receive(conn, 2) != b"\x05\x02":
            raise ValueError("SOCKS method rejected")
        secret = b"native-ab-secret"
        conn.sendall(b"\x01" + bytes([len(secret)]) + secret + bytes([len(secret)]) + secret)
        if receive(conn, 2) != b"\x01\x00":
            raise ValueError("SOCKS authentication rejected")
        conn.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", origin))
        reply = receive(conn, 4)
        if reply[:3] != b"\x05\x00\x00":
            raise ValueError("SOCKS target rejected")
        if reply[3] == 1:
            receive(conn, 6)
        elif reply[3] == 4:
            receive(conn, 18)
        elif reply[3] == 3:
            receive(conn, receive(conn, 1)[0] + 2)
        else:
            raise ValueError("invalid SOCKS address")
        return conn
    except Exception:
        conn.close()
        raise


def transfer(port, origin, workload, duration, concurrency):
    deadline = time.monotonic() + duration
    def worker():
        conn = None
        count = 0
        latency = []
        transferred = 0
        # Bound latency memory without discarding the completed operation count.
        reservoir = 20000
        while time.monotonic() < deadline:
            started = time.monotonic()
            if conn is None:
                conn = connect(port, origin)
            size = 1024 if workload == "short" else 32768
            action = b"U" if workload == "upload" else b"D" if workload == "download" else b"E"
            try:
                conn.sendall(struct.pack("!cI", action, size))
                if action != b"D":
                    conn.sendall(b"x" * size)
                response = receive(conn, 1 if action == b"U" else size)
                if response != (b"K" if action == b"U" else b"x" * size):
                    raise ValueError("relay data mismatch")
                transferred += size if action in (b"U", b"D") else size * 2
                count += 1
                value = (time.monotonic() - started) * 1000
                if len(latency) < reservoir:
                    latency.append(value)
                elif count % max(1, count // reservoir) == 0:
                    latency[count % reservoir] = value
            finally:
                if workload == "short" and conn is not None:
                    conn.close()
                    conn = None
        if conn is not None:
            conn.close()
        return transferred, count, latency
    started = time.monotonic()
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        results = list(pool.map(lambda _: worker(), range(concurrency)))
    elapsed = time.monotonic() - started
    values = sorted(value for result in results for value in result[2])
    if not values:
        raise ValueError("no completed load")
    total = sum(result[0] for result in results)
    operations = sum(result[1] for result in results)
    size = 1024 if workload == "short" else 32768
    up = operations * (5 + (0 if workload == "download" else size))
    down = operations * (1 if workload == "upload" else size)
    return {"bytes": total, "operations": sum(result[1] for result in results),
            "wire_upload_bytes": up, "wire_download_bytes": down,
            "seconds": elapsed, "mib_per_second": total / elapsed / 1048576,
            "latency_ms": {str(p): values[min(len(values)-1, math.ceil(len(values)*p/100)-1)] for p in (50,95,99)},
            "latency_sample_count": len(values), "latency_method": "bounded deterministic sample per worker"}


def process_resources(pid):
    fields = Path("/proc/%d/stat" % pid).read_text().rsplit(")", 1)[1].split()
    ticks = os.sysconf("SC_CLK_TCK")
    # Fields after comm start at state (#3); utime/stime are #14/#15.
    cpu = (int(fields[11]) + int(fields[12])) / ticks
    pages = int(Path("/proc/%d/statm" % pid).read_text().split()[1])
    return cpu, pages * os.sysconf("SC_PAGE_SIZE")


def runtime_snapshot(process, state, number):
    process.send_signal(signal.SIGUSR1)
    path = state / ("runtime-%d.json" % number)
    deadline = time.monotonic() + 5
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("Node runtime allocation snapshot missing")
        time.sleep(0.01)
    return json.loads(path.read_text())


def cpu_snapshot(process, state, number, nonce):
    path = state / ("cpu-%d.json" % number)
    if path.exists():
        raise ValueError("process CPU snapshot already exists")
    requested = time.monotonic_ns()
    process.send_signal(signal.SIGUSR2)
    deadline = time.monotonic() + 5
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError("process CPU snapshot missing")
        time.sleep(0.001)
    received = time.monotonic_ns()
    proof = json.loads(path.read_text())
    if (proof.get("schema") != "txnode-process-cpu-snapshot/v1"
            or proof.get("method") != CPU_METHOD or proof.get("nonce") != nonce):
        raise ValueError("process CPU snapshot method or identity mismatch")
    for key in ("clock_id", "pid", "sequence", "cpu_nanos", "resolution_nanos",
                "monotonic_before_nanos", "monotonic_after_nanos"):
        if type(proof.get(key)) is not int:
            raise ValueError("process CPU snapshot integer field missing: " + key)
    if proof["clock_id"] != 2 or proof["pid"] != process.pid or proof["sequence"] != number:
        raise ValueError("process CPU snapshot clock, PID or sequence mismatch")
    if proof["cpu_nanos"] <= 0 or proof["resolution_nanos"] <= 0:
        raise ValueError("process CPU snapshot has nonpositive value or resolution")
    if not requested <= proof["monotonic_before_nanos"] <= proof["monotonic_after_nanos"] <= received:
        raise ValueError("process CPU snapshot escaped request/acknowledgement bounds")
    proof.update(requested_monotonic_nanos=requested, received_monotonic_nanos=received,
                 round_trip_nanos=received-requested)
    return proof


def cpu_measurement(start, end, business_bytes):
    if type(business_bytes) is not int or business_bytes <= 0:
        raise ValueError("process CPU measurement has invalid business bytes")
    for proof in (start, end):
        for key in ("cpu_nanos", "resolution_nanos", "monotonic_before_nanos", "monotonic_after_nanos"):
            if type(proof.get(key)) is not int or proof[key] <= 0:
                raise ValueError("process CPU measurement has invalid paired field: " + key)
    if (start["resolution_nanos"] != end["resolution_nanos"]
            or start["nonce"] != end["nonce"] or start["pid"] != end["pid"]
            or start["sequence"] != 1 or end["sequence"] != 2):
        raise ValueError("process CPU snapshot pair is inconsistent")
    delta = end["cpu_nanos"] - start["cpu_nanos"]
    elapsed = end["monotonic_before_nanos"] - start["monotonic_after_nanos"]
    if delta <= 0 or elapsed <= 0 or business_bytes <= 0:
        raise ValueError("process CPU measurement has nonpositive CPU, elapsed time or bytes")
    return {"method": CPU_METHOD, "start": start, "end": end,
            "delta_nanos": delta, "monotonic_inner_elapsed_nanos": elapsed,
            "resolution_nanos": start["resolution_nanos"],
            "cpu_seconds_per_gib": (delta / 1_000_000_000) / (business_bytes / 1073741824)}


def build_runtime_images(output, report):
    command(["docker", "pull", "--platform", "linux/amd64", "alpine:3.20"])
    base = json.loads(command(["docker", "image", "inspect", "alpine:3.20"]))[0]["RepoDigests"][0]
    recipe = ("FROM " + base + "\nRUN apk add --no-cache ca-certificates tzdata\n"
              "COPY tx-node /usr/local/bin/tx-node\nRUN mkdir -p /etc/txnode /etc/xboard-node\n"
              "WORKDIR /etc/txnode\nENTRYPOINT [\"tx-node\"]\nCMD [\"-c\", \"/etc/txnode/config.yml\"]\n")
    report["runtime_images"] = {"base": base, "scope": "identical immutable Alpine runtime recipe and prebuilt business binaries"}
    for side in ("legacy", "candidate"):
        context = output / ("runtime-image-" + side)
        context.mkdir()
        (context / "Dockerfile").write_text(recipe)
        target = context / "tx-node"
        shutil.copyfile(output / ("tx-node-" + side), target)
        target.chmod(0o755)
        tag = "txnode-native-ab:%s-%s" % (report["candidate"][:12], side)
        try:
            log = command(["docker", "build", "--platform", "linux/amd64", "-t", tag, str(context)])
            (context / "build.log").write_text(log)
            metadata = json.loads(command(["docker", "image", "inspect", tag]))[0]
            (context / "inspect.json").write_text(json.dumps(metadata, indent=2) + "\n")
            report["runtime_images"][side] = {"image_id": metadata["Id"], "uncompressed_bytes": metadata["Size"], "business_binary_sha256": digest(target)}
        finally:
            target.unlink()


def sample(binary, state, mode, workload, args, origin, cpu_profile=None):
    state.mkdir(parents=True)
    log = (state / "server.log").open("w")
    environment = os.environ.copy()
    nonce = secrets.token_hex(32)
    environment["TXNODE_NATIVE_AB_CPU_NONCE"] = nonce
    environment.pop("TXNODE_NATIVE_AB_CPU_PROFILE", None)
    if cpu_profile is not None:
        environment["TXNODE_NATIVE_AB_CPU_PROFILE"] = str(cpu_profile)
    process = subprocess.Popen([str(binary), "-mode", mode, "-state", str(state)], stdout=log, stderr=log, text=True, env=environment)
    measurements = {"mode": mode, "workload": workload, "status": "incomplete"}
    rss_samples = []
    stop = threading.Event()
    def monitor():
        while not stop.wait(0.05):
            try:
                rss_samples.append(process_resources(process.pid)[1])
            except (OSError, ValueError, IndexError):
                return
    watcher = None
    try:
        ready_deadline = time.monotonic() + 30
        port = None
        while time.monotonic() < ready_deadline:
            with (state / "server.log").open() as reader:
                lines = reader.readlines()
            for line in lines:
                if line.startswith("NATIVE_AB_READY "):
                    port = int(line.split()[1])
                    break
            if port is not None or process.poll() is not None:
                break
            time.sleep(0.05)
        if port is None:
            raise RuntimeError("server readiness missing; see server.log")
        measurements["stage"] = "warmup"
        warmup = transfer(port, origin.port, workload, args.warmup, args.concurrency)
        memory_start = runtime_snapshot(process, state, 1)
        proc_cpu_start, rss = process_resources(process.pid)
        rss_samples.append(rss)
        watcher = threading.Thread(target=monitor, daemon=True)
        watcher.start()
        measurements["stage"] = "measurement"
        cpu_start = cpu_snapshot(process, state, 1, nonce)
        transfer_started = time.monotonic_ns()
        measurements.update(transfer(port, origin.port, workload, args.seconds, args.concurrency))
        transfer_completed = time.monotonic_ns()
        cpu_end = cpu_snapshot(process, state, 2, nonce)
        proc_cpu_end, rss = process_resources(process.pid)
        memory_end = runtime_snapshot(process, state, 2)
        rss_samples.append(rss)
        cpu = cpu_measurement(cpu_start, cpu_end, measurements["bytes"])
        if not (cpu_start["monotonic_after_nanos"] <= transfer_started
                < transfer_completed <= cpu_end["monotonic_before_nanos"]):
            raise ValueError("process CPU window does not contain the completed transfer")
        cpu.update(transfer_started_monotonic_nanos=transfer_started,
                   transfer_completed_monotonic_nanos=transfer_completed)
        measurements["cpu_measurement"] = cpu
        measurements["cpu_method"] = CPU_METHOD
        measurements["cpu_seconds_per_gib"] = cpu["cpu_seconds_per_gib"]
        measurements["proc_cpu_secondary"] = {
            "method": "proc-stat-clk-tck-v1", "clock_ticks_per_second": os.sysconf("SC_CLK_TCK"),
            "start_seconds": proc_cpu_start, "end_seconds": proc_cpu_end,
            "delta_seconds": proc_cpu_end-proc_cpu_start,
            "window": "outside CPU request/acknowledgement; secondary diagnostic only"}
        measurements["rss_peak_bytes"] = max(rss_samples)
        measurements["allocated_bytes_per_business_byte"] = (memory_end["total_alloc_bytes"] - memory_start["total_alloc_bytes"]) / measurements["bytes"]
        measurements["allocations_per_business_byte"] = (memory_end["mallocs"] - memory_start["mallocs"]) / measurements["bytes"]
        measurements["stage"] = "shutdown-accounting"
        process.send_signal(signal.SIGTERM)
        if process.wait(timeout=30) != 0:
            raise RuntimeError("server shutdown/accounting failed; see server.log")
        proof = json.loads((state / "evidence.json").read_text())
        if proof.get("mode") != mode or not proof.get("stopped"):
            raise ValueError("accounting mode proof mismatch")
        if mode in ("usage_v2", "events"):
            prefix = "usage" if mode == "usage_v2" else "event"
            for direction in ("up", "down"):
                wire_key = "wire_%sload_bytes" % direction
                expected = warmup[wire_key] + measurements[wire_key]
                if proof.get("%s_raw_%s_bytes" % (prefix, direction)) != expected:
                    raise ValueError("%s durable %s bytes differ from actual client I/O" % (mode, direction))
        if mode == "events":
            if (proof.get("event_contract") != "physical-byte-observation-v1"
                    or proof.get("event_authorizes") is not False
                    or proof.get("event_tail_unknown") is not True
                    or proof.get("event_count", 0) <= 0):
                raise ValueError("local event projection contract incomplete")
            measurements["semantic_contract"] = "physical-byte-observation-v1"
        measurements["accounting_evidence"] = proof
        measurements["status"] = "measured"
        measurements["stage"] = "complete"
    except Exception as error:
        measurements["error"] = str(error)
        measurements["error_type"] = type(error).__name__
        measurements["server_exit_at_error"] = process.poll()
    finally:
        stop.set()
        if watcher is not None:
            watcher.join(timeout=1)
        if process.poll() is None:
            if cpu_profile is not None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=15)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            else:
                process.kill()
                process.wait()
        log.close()
    (state / "sample.json").write_text(json.dumps(measurements, indent=2) + "\n")
    return measurements


def diagnostics(output, report, args, origin):
    # Profiled samples are separate from all acceptance samples and ratios.
    cases = [("ordinary", "download"), ("events", "download")]
    if any(s["mode"] == "usage_v2" and s["workload"] == "short" and s["status"] != "measured" for s in report["samples"]):
        cases.append(("usage_v2", "short"))
    results = []
    report["diagnostics"] = results
    for mode, workload in cases:
        for side in ("legacy", "candidate"):
            state = output / ("diagnostic-%s-%s-%s" % (mode, workload, side))
            profile = state / "cpu.pprof"
            binary = output / ("server-" + side)
            result = {"side": side, "mode": mode, "workload": workload, "acceptance_sample": False,
                      "profile_scope": "startup, warmup, measurement, graceful shutdown", "binary_sha256": digest(binary)}
            try:
                result["sample"] = sample(binary, state, mode, workload, args, origin, cpu_profile=profile)
                result["profile_bytes"] = profile.stat().st_size
                result["profile_sha256"] = digest(profile)
                top = command(["go", "tool", "pprof", "-top", "-nodecount=40", str(binary), str(profile)])
                (state / "cpu-top.txt").write_text(top + "\n")
                print("diagnostic %s/%s/%s\n%s" % (side, mode, workload, top), flush=True)
            except Exception as error:
                result["diagnostic_error"] = str(error)
            results.append(result)
            (state / "metadata.json").write_text(json.dumps(result, indent=2) + "\n")
            (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")


def cv(values):
    mean = statistics.mean(values)
    return statistics.stdev(values) / mean if mean > 0 and len(values) > 1 else float("inf")


def compare(samples, groups):
    comparisons = []
    for mode in MODES:
        for workload in WORKLOADS:
            subset = [s for s in samples if s["mode"] == mode and s["workload"] == workload]
            sides = {side: [s for s in subset if s["side"] == side and s["status"] == "measured"] for side in ("legacy", "candidate")}
            entry = {"mode": mode, "workload": workload, "status": "incomplete"}
            if any(len(sides[side]) != groups for side in sides):
                entry["reason"] = "all five complete samples per side are required"
                comparisons.append(entry)
                continue
            if any(s.get("cpu_method") != CPU_METHOD or s.get("cpu_measurement", {}).get("method") != CPU_METHOD
                   for side in sides.values() for s in side):
                entry["reason"] = "every sample must use validated process CPU nanosecond snapshots"
                comparisons.append(entry)
                continue
            entry["cpu_method"] = CPU_METHOD
            if mode == "events" and any(s.get("semantic_contract") != "physical-byte-observation-v1" for side in sides.values() for s in side):
                entry.update(reason="every sample must prove the shared durable physical byte/unknown-tail/nonbilling contract")
                comparisons.append(entry)
                continue
            if mode == "events":
                entry["semantic_contract"] = "physical-byte-observation-v1"
            rates = {side: [s["mib_per_second"] for s in sides[side]] for side in sides}
            cpus = {side: [s["cpu_seconds_per_gib"] for s in sides[side]] for side in sides}
            entry["throughput_candidate_over_legacy"] = statistics.median(rates["candidate"]) / statistics.median(rates["legacy"])
            baseline_cpu = statistics.median(cpus["legacy"])
            if baseline_cpu <= 0:
                entry["reason"] = "CPU sample is below clock resolution"
            else:
                entry["cpu_candidate_over_legacy"] = statistics.median(cpus["candidate"]) / baseline_cpu
                noise = max(cv(values) for values in list(rates.values()) + list(cpus.values()))
                entry["max_coefficient_of_variation"] = noise
                if noise > 0.10:
                    entry.update(status="unresolved", reason="same runner sample noise exceeds fixed 10% budget")
                elif entry["throughput_candidate_over_legacy"] < 0.95 or entry["cpu_candidate_over_legacy"] > 1.05:
                    entry.update(status="investigate", reason="fixed 5% throughput/CPU investigation threshold exceeded")
                else:
                    entry["status"] = "within-initial-thresholds"
            comparisons.append(entry)
    return comparisons


def run(args):
    if os.environ.get("GITHUB_ACTIONS") != "true" or platform.system() != "Linux":
        raise RuntimeError("native performance execution is restricted to Linux GitHub Actions")
    if args.groups < 5 or args.seconds < 10 or args.warmup < 2 or args.concurrency < 1:
        raise ValueError("acceptance requires >=5 groups, >=10s samples, >=2s warmup and positive concurrency")
    if args.seconds + args.warmup > 60:
        raise ValueError("sample plus warmup must fit the explicit 90 second bounded authorization lease")
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    candidate = command(["git", "rev-parse", args.candidate + "^{commit}"])
    if len(candidate) != 40:
        raise ValueError("candidate must resolve to a commit")
    report = {"schema": "txnode-native-performance/v2", "cpu_method": CPU_METHOD,
              "baseline": BASELINE, "candidate": candidate,
              "candidate_tree": command(["git", "rev-parse", candidate + "^{tree}"]),
              "baseline_tree": command(["git", "rev-parse", BASELINE + "^{tree}"]),
              "tool_sha256": digest(Path(__file__)), "go": command(["go", "version"]),
              "template_sha256": {path.name: digest(path) for path in sorted((ROOT / "scripts").glob("native-acceptance-*.go.tmpl"))},
              "go_environment": command(["go", "env", "GOOS", "GOARCH", "GOTOOLCHAIN", "CGO_ENABLED"]),
              "machine": {"platform": platform.platform(), "cpu_count": os.cpu_count(),
                          "cpuinfo": Path("/proc/cpuinfo").read_text(), "meminfo": Path("/proc/meminfo").read_text()},
              "settings": {"groups": args.groups, "sample_seconds": args.seconds, "warmup_seconds": args.warmup,
                           "concurrency": args.concurrency, "buffer_bytes": 32768, "short_buffer_bytes": 1024,
                           "build_flags": FLAGS, "protocol": "SOCKS5 RFC1929 IPv4 loopback", "tls": "none on both sides",
                           "legacy_kernel": "sing-box", "loopback_route": "127.0.0.1/32 direct, identical structured rule on both sides",
                           "event_store_max_bytes": 1 << 30, "usage_lease_seconds": 90,
                           "throughput_floor": 0.95, "cpu_ceiling": 1.05, "noise_cv_ceiling": 0.10},
              "scope": "same runner SOCKS forwarding; ordinary/events/usage_v2 configured identically; local durability, no Core receipts",
              "not_measured": ["cross-region-network", "xray-legacy-kernel", "protocols-other-than-SOCKS", "internal-event-path-and-timestamp-equivalence"],
              "accepted": False, "builds": {}, "samples": [], "comparisons": [], "status": "incomplete"}
    workspace = Path(tempfile.mkdtemp(prefix="txnode-native-ab-"))
    checkouts = []
    origin = None
    try:
        for side, sha in (("legacy", BASELINE), ("candidate", candidate)):
            checkout = workspace / side
            command(["git", "worktree", "add", "--detach", str(checkout), sha])
            checkouts.append(checkout)
            harness = checkout / "cmd" / "native-ab"
            harness.mkdir()
            shutil.copyfile(ROOT / "scripts/native-acceptance-server.go.tmpl", harness / "main.go")
            shutil.copyfile(ROOT / ("scripts/native-acceptance-%s.go.tmpl" % side), harness / "factory.go")
            shutil.copyfile(ROOT / "scripts/native-acceptance-bucket-diagnostic.go.tmpl",
                            checkout / "internal/usagebucket/native_ab_diagnostic.go")
            binary = output / ("server-" + side)
            app = output / ("tx-node-" + side)
            module_locks = {name: digest(checkout / name) for name in ("go.mod", "go.sum")}
            prefetch = prefetch_modules(checkout, output, side)
            build = {"status": "incomplete", "sha": sha, "prefetch": prefetch,
                     "module_lock_sha256": module_locks}
            report["builds"][side] = build
            if any(digest(checkout / name) != expected for name, expected in module_locks.items()):
                build["error"] = "module prefetch changed checked-in module locks"
                continue
            if prefetch["status"] != "complete":
                build["error"] = "module prefetch failed after three attempts"
                continue
            try:
                command(["go", "build", *FLAGS, "-o", str(binary), "./cmd/native-ab"], checkout)
                command(["go", "build", *FLAGS, "-o", str(app), "./cmd/tx-node"], checkout)
                build.update(status="built", binary_sha256=digest(app), binary_bytes=app.stat().st_size,
                             harness_sha256=digest(binary), harness_bytes=binary.stat().st_size)
            except subprocess.CalledProcessError as error:
                build["error"] = error.output
        if any(report["builds"][side]["status"] != "built" for side in ("legacy", "candidate")):
            return report
        if args.diagnostics_only:
            origin = Origin()
            diagnostics(output, report, args, origin)
            report["status"] = "diagnostics-only"
            return report
        build_runtime_images(output, report)
        origin = Origin()
        for group in range(args.groups):
            order = ("legacy", "candidate") if group % 2 == 0 else ("candidate", "legacy")
            for mode in MODES:
                for workload in WORKLOADS:
                    for side in order:
                        state = output / ("g%d-%s-%s-%s" % (group+1, mode, workload, side))
                        result = sample(output / ("server-"+side), state, mode, workload, args, origin)
                        result.update(group=group+1, side=side)
                        report["samples"].append(result)
                        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
                        print("group=%d mode=%s workload=%s side=%s status=%s" % (group+1, mode, workload, side, result["status"]), flush=True)
        report["comparisons"] = compare(report["samples"], args.groups)
        report["status"] = "measured-with-limitations" if all(s["status"] == "measured" for s in report["samples"]) else "incomplete"
        report["accepted"] = report["status"] == "measured-with-limitations" and len(report["comparisons"]) == len(MODES)*len(WORKLOADS) and all(item["status"] == "within-initial-thresholds" for item in report["comparisons"])
        diagnostics(output, report, args, origin)
        return report
    finally:
        if origin is not None:
            origin.close()
        for checkout in reversed(checkouts):
            # These are fresh, private disposable Actions checkouts. No user's
            # checkout or state path is passed to this cleanup.
            command(["git", "worktree", "remove", "--force", str(checkout)])
        shutil.rmtree(workspace, ignore_errors=True)
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        lines = ["# Native / legacy performance", "", "Candidate: `%s`; baseline: `%s`." % (candidate, BASELINE), "", "Status: **%s**. Scoped A/B accepted: **%s**." % (report["status"], report["accepted"]), "", "| Mode | Workload | Status | Candidate / legacy throughput | Candidate / legacy CPU |", "|---|---|---|---:|---:|"]
        lines[6:6] = ["CPU method: `%s`; schema: `%s`. /proc CLK_TCK is secondary only." % (CPU_METHOD, report["schema"]), ""]
        for item in report["comparisons"]:
            lines.append("| %s | %s | %s | %.4f | %.4f |" % (item["mode"], item["workload"], item["status"], item.get("throughput_candidate_over_legacy", 0), item.get("cpu_candidate_over_legacy", 0)))
        if report.get("diagnostics"):
            lines.extend(["", "Separate CPU profile diagnostics (excluded from acceptance samples and ratios):"])
            for item in report["diagnostics"]:
                lines.append("- %s/%s/%s: %s; profile bytes=%d; error=%s" % (
                    item["side"], item["mode"], item["workload"], item.get("sample", {}).get("status", "incomplete"),
                    item.get("profile_bytes", 0), item.get("diagnostic_error", item.get("sample", {}).get("error", "none"))))
        lines.extend(["", "Not measured: " + ", ".join(report["not_measured"]) + ".", "", "Loopback evidence does not establish production or cross-region performance."])
        (output / "report.md").write_text("\n".join(lines) + "\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--candidate", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--groups", type=int, default=5)
    parser.add_argument("--seconds", type=int, default=10)
    parser.add_argument("--warmup", type=int, default=2)
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--diagnostics-only", action="store_true", help="separate two-side CPU profiles; never satisfies the performance gate")
    args = parser.parse_args()
    report = run(args)
    if args.diagnostics_only:
        expected = {(mode, "download", side) for mode in ("ordinary", "events") for side in ("legacy", "candidate")}
        observed = {(item["mode"], item["workload"], item["side"]) for item in report.get("diagnostics", [])}
        complete = report["status"] == "diagnostics-only" and len(report.get("diagnostics", [])) == 4 and observed == expected and all(
            item.get("profile_bytes", 0) > 0 and not item.get("diagnostic_error") and item.get("sample", {}).get("status") == "measured"
            for item in report["diagnostics"])
        return 0 if complete else 1
    # Semantic-equivalence gaps and unsupported measurements are explicit, and
    # an incomplete or noisy measurement never satisfies a performance gate.
    return 0 if report["accepted"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
