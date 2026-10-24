#!/usr/bin/env python3
"""Actions-only collector repair proof and four traced samples from frozen binaries."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import time
from types import SimpleNamespace

FIRST_REPORT_SHA256 = '7af59ce203b043e734aeaaf27ef6d5d65e308835ca483ca5d5a13cd04c7c12fa'


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def progress(path, previous):
    deadline = time.monotonic() + 2
    while time.monotonic() < deadline:
        try:
            value = int(path.read_text())
            if value > previous:
                return value
        except (FileNotFoundError, ValueError):
            pass
        time.sleep(.01)
    raise RuntimeError('tracee progress deadline')


def probe(control, state, interruptible):
    state.mkdir()
    marker = state / 'progress.txt'
    code = ('import pathlib,sys,time\np=pathlib.Path(sys.argv[1])\n'
            'for i in range(10000):\n p.write_text(str(i)); time.sleep(.02)\n')
    process = subprocess.Popen([sys.executable, '-c', code, str(marker)])
    window = control.TraceWindow(process, state, interruptible)
    try:
        progress(marker, -1)
        window.start()
        before = progress(marker, 0)
        try:
            window.stop()
        except ValueError as error:
            window.result['collection_error'] = type(error).__name__
        after = progress(marker, before)
        window.result.update(progress_before_detach=before, progress_after_detach=after,
                             continued_after_detach=process.poll() is None and after > before)
        if interruptible == 1:
            valid = (window.result['complete'] is False and window.result['sigint_caught'] is False
                     and window.result['collection_error'] == 'ValueError'
                     and (state / 'syscalls.txt').stat().st_size == 0)
        else:
            valid = window.result['complete'] is True and window.result['sigint_caught'] is True
        valid = valid and window.result['continued_after_detach'] and window.result['detached']
        control.write(state / 'probe.json', dict(window.result, expected_result_observed=valid))
        if not valid:
            raise RuntimeError('collector control proof failed')
        return dict(window.result, expected_result_observed=valid)
    finally:
        try:
            window.stop()
        finally:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--first-directory', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('diagnostic execution belongs to Linux Actions')
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError('fresh diagnostic output required')
    output.mkdir(parents=True)
    root = Path(__file__).resolve().parent.parent
    control = load_module('long_cpu_control', root / 'scripts/native-long-cpu-investigation.py')
    bench = load_module('long_cpu_original_bench', root / 'scripts/native-acceptance.py')
    first = args.first_directory.resolve() / 'native-long-cpu'
    raw = (first / 'report.json').read_bytes()
    if hashlib.sha256(raw).hexdigest() != FIRST_REPORT_SHA256:
        raise RuntimeError('first investigation report changed')
    original = json.loads(raw)
    first_plan = json.loads((first / 'plan.json').read_text())
    if (original['candidate'] != control.CANDIDATE or original['accepted'] is not False
            or original['baseline'] != 'a1ad2695e1143269168c36a274283de3342e91c7'
            or len(original['reproduction_samples']) != 20
            or not all(s['status'] == 'measured' for s in original['reproduction_samples'])):
        raise RuntimeError('first investigation scope changed')
    for path, expected in first_plan['source_sha256'].items():
        if (hashlib.sha256((root / path).read_bytes()).hexdigest() != expected
                or (root / path).read_bytes() != subprocess.check_output(
                    ['git', 'show', control.CANDIDATE + ':' + path], cwd=root)):
            raise RuntimeError('original measurement source changed')
    for side in ('legacy', 'candidate'):
        for name, field in [('server-', 'harness_sha256'), ('tx-node-', 'binary_sha256')]:
            binary = first / (name + side)
            if hashlib.sha256(binary.read_bytes()).hexdigest() != original['builds'][side][field]:
                raise RuntimeError('frozen binary digest mismatch')
            binary.chmod(0o700)
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    plan = {'schema': 'txnode-long-syscall-supplement/v1', 'candidate': control.CANDIDATE,
            'baseline': original['baseline'], 'workflow_source': subprocess.check_output(
                ['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
            'reference_run': 40059251852, 'reference_artifact': 12547191583,
            'reference_report_sha256': FIRST_REPORT_SHA256, 'builds': original['builds'],
            'original_affinity': allowed, 'driver_affinity': sorted(os.sched_getaffinity(0)),
            'settings': {'warmup': 2, 'seconds': 10, 'concurrency': 4},
            'source_sha256': first_plan['source_sha256'],
            'collector_sha256': {p: hashlib.sha256((root / p).read_bytes()).hexdigest()
                                 for p in ('scripts/native-long-cpu-investigation.py',
                                           'scripts/native-long-syscall-supplement.py')},
            'scope': 'Four instrumented syscall summaries only; no new untraced comparison, build or acceptance.',
            'full_S3_accepted': False}
    control.write(output / 'plan.json', plan)
    report = {'schema': plan['schema'], 'accepted': False, 'full_S3_accepted': False,
              'reference_report_sha256': FIRST_REPORT_SHA256, 'probe': [], 'syscall_samples': []}
    for interruptible in (1, 2):
        report['probe'].append(probe(control, output / ('probe-I%d' % interruptible), interruptible))
        control.write(output / 'report.json', report)
    origin = bench.Origin()
    settings = SimpleNamespace(warmup=2, seconds=10, concurrency=4)
    original_snapshot = bench.cpu_snapshot
    try:
        for mode in control.CASES:
            for side in ('legacy', 'candidate'):
                state = output / ('syscalls-%s-%s' % (mode, side))
                active = []
                def traced_snapshot(process, snapshot_state, number, nonce):
                    if number == 1:
                        window = control.TraceWindow(process, snapshot_state)
                        active.append(window)
                        window.start()
                    value = original_snapshot(process, snapshot_state, number, nonce)
                    if number == 2:
                        try:
                            active[-1].stop()
                        except Exception as error:
                            active[-1].result['collection_error'] = type(error).__name__
                    return value
                bench.cpu_snapshot = traced_snapshot
                item = {'mode': mode, 'side': side, 'workload': 'long', 'acceptance_sample': False}
                try:
                    item['sample'] = bench.sample(first / ('server-' + side), state, mode, 'long', settings, origin)
                finally:
                    bench.cpu_snapshot = original_snapshot
                    for window in active:
                        try:
                            window.stop()
                        except Exception as error:
                            window.result['collection_error'] = type(error).__name__
                        item['syscall_window'] = window.result
                    control.write(state / 'trace-metadata.json', item.get('syscall_window', {'complete': False}))
                report['syscall_samples'].append(item)
                control.write(output / 'report.json', report)
                print('traced mode=%s side=%s status=%s complete=%s' % (
                    mode, side, item['sample']['status'], item['syscall_window']['complete']), flush=True)
    finally:
        bench.cpu_snapshot = original_snapshot
        origin.close()
    report['collection_complete'] = (len(report['syscall_samples']) == 4 and all(
        s['sample']['status'] == 'measured' and s['syscall_window']['complete'] is True
        for s in report['syscall_samples']))
    control.write(output / 'report.json', report)
    if not report['collection_complete']:
        raise SystemExit('syscall supplement incomplete')


if __name__ == '__main__':
    main()
