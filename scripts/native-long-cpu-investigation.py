#!/usr/bin/env python3
"""Finite Actions-only reproduction and bounded syscall counts; never S3 acceptance."""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import platform
import re
import shutil
import signal
import subprocess
import time
from types import SimpleNamespace


CANDIDATE = '90508592b4c0b433eb9a71f367694a981aa958e1'
CASES = ('ordinary', 'events')


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def proc_field(pid, name):
    for line in Path('/proc/%d/status' % pid).read_text().splitlines():
        if line.startswith(name + ':'):
            return line.split(':', 1)[1].strip()
    raise ValueError('missing process identity field')


def descendant(pid, ancestor):
    for _ in range(12):
        if pid == ancestor:
            return True
        if pid <= 1:
            return False
        pid = int(proc_field(pid, 'PPid'))
    return False


def syscall_summary(path):
    rows, total = [], None
    for line in path.read_text().splitlines():
        fields = line.split()
        if not fields or not re.fullmatch(r'\d+\.\d+', fields[0]):
            continue
        if len(fields) not in (5, 6):
            raise ValueError('unexpected syscall summary columns')
        item = {'name': fields[-1], 'percent': float(fields[0]), 'system_seconds': float(fields[1]),
                'usecs_per_call': int(fields[2]), 'calls': int(fields[3]),
                'errors': int(fields[4]) if len(fields) == 6 else 0}
        if item['name'] == 'total':
            total = item
        else:
            rows.append(item)
    if not rows or total is None or sum(item['calls'] for item in rows) != total['calls']:
        raise ValueError('syscall summary is not complete')
    if sum(item['errors'] for item in rows) != total['errors']:
        raise ValueError('syscall summary error total mismatch')
    return {'rows': rows, 'total': total}


class TraceWindow:
    def __init__(self, process, state):
        self.process, self.state = process, state
        self.handle = None
        self.tracer_pid = None
        self.log = None
        self.result = {'scope': 'attach before first CPU request; detach after second CPU acknowledgement',
                       'summary_only': True, 'complete': False}

    def start(self):
        self.log = (self.state / 'trace-attach.log').open('wb')
        command = ['sudo', '-n', 'strace', '-f', '-c', '-I', '1', '-o',
                   str(self.state / 'syscalls.txt'), '-p', str(self.process.pid)]
        self.handle = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=self.log,
                                       start_new_session=True)
        deadline = time.monotonic() + 5
        while True:
            tracer = int(proc_field(self.process.pid, 'TracerPid'))
            if tracer:
                if proc_field(tracer, 'Name') != 'strace' or not descendant(tracer, self.handle.pid):
                    raise RuntimeError('unexpected tracer identity')
                self.tracer_pid = tracer
                self.result.update(tracee_pid=self.process.pid, tracer_pid=tracer,
                                   attached_monotonic_nanos=time.monotonic_ns())
                return
            if self.handle.poll() is not None:
                raise RuntimeError('tracer exited before attachment')
            if time.monotonic() >= deadline:
                raise RuntimeError('tracer attachment deadline')
            time.sleep(.01)

    def stop(self):
        if self.handle is None:
            return
        if self.handle.poll() is None:
            tracer = self.tracer_pid or int(proc_field(self.process.pid, 'TracerPid'))
            if tracer:
                if proc_field(tracer, 'Name') != 'strace' or not descendant(tracer, self.handle.pid):
                    raise RuntimeError('tracer identity changed before detach')
                subprocess.run(['sudo', '-n', 'kill', '-INT', str(tracer)], check=True,
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, timeout=5)
            else:
                self.handle.terminate()
        self.result['tracer_exit_code'] = self.handle.wait(timeout=10)
        self.log.close()
        self.log = None
        alive = self.process.poll() is None
        detached = alive and int(proc_field(self.process.pid, 'TracerPid')) == 0
        self.result.update(detached_monotonic_nanos=time.monotonic_ns(),
                           tracee_alive_after_detach=alive, detached=detached)
        self.handle = None
        if not detached:
            raise RuntimeError('tracee did not continue after detach')
        if self.result['tracer_exit_code'] not in (0, -signal.SIGINT, 128 + signal.SIGINT):
            raise RuntimeError('unexpected tracer exit status')
        summary = syscall_summary(self.state / 'syscalls.txt')
        self.result.update(summary=summary, complete=True)
        write(self.state / 'syscall-window.json', self.result)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference-directory', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('diagnostic execution belongs to Linux Actions')
    output = args.output.resolve()
    if output.exists():
        raise RuntimeError('fresh diagnostic output required')
    output.mkdir(parents=True)
    reference_path = args.reference_directory / 'performance/report.json'
    reference = json.loads(reference_path.read_text())
    envelope = json.loads((args.reference_directory / 'result.json').read_text())
    reference_driver = json.loads((args.reference_directory / 'driver.json').read_text())
    if (reference['candidate'] != CANDIDATE or reference['baseline'] != 'a1ad2695e1143269168c36a274283de3342e91c7'
            or envelope['report_sha256'] != hashlib.sha256(reference_path.read_bytes()).hexdigest()
            or reference_driver['affinity'] != [0] or reference['accepted'] is not False):
        raise RuntimeError('original single CPU reference does not match')
    for key, value in [('groups', 5), ('sample_seconds', 10), ('warmup_seconds', 2), ('concurrency', 4)]:
        if reference['settings'][key] != value:
            raise RuntimeError('reference workload settings changed')
    allowed = sorted(os.sched_getaffinity(0))
    os.sched_setaffinity(0, {allowed[0]})
    root = Path(__file__).resolve().parent.parent
    paths = ['scripts/native-acceptance.py'] + [str(p.relative_to(root))
             for p in sorted((root / 'scripts').glob('native-acceptance-*.go.tmpl'))]
    def git(*parts):
        return subprocess.check_output(['git', *parts], cwd=root)
    for path in paths:
        if (root / path).read_bytes() != git('show', CANDIDATE + ':' + path):
            raise RuntimeError('original measurement source changed')
    plan = {'schema': 'txnode-long-cpu-plan/v1', 'candidate': CANDIDATE,
            'baseline': 'a1ad2695e1143269168c36a274283de3342e91c7',
            'workflow_source': git('rev-parse', 'HEAD').decode().strip(),
            'reference_run': 40041704618, 'reference_artifact': 12540691528,
            'reference_report_sha256': envelope['report_sha256'],
            'reference_go': reference['go'], 'reference_builds': reference['builds'],
            'original_affinity': allowed, 'driver_affinity': sorted(os.sched_getaffinity(0)),
            'source_sha256': {p: hashlib.sha256((root / p).read_bytes()).hexdigest() for p in paths},
            'settings': {'groups': 5, 'warmup': 2, 'seconds': 10, 'concurrency': 4,
                         'modes': list(CASES), 'workload': 'long'},
            'untraced_samples': 20, 'traced_samples': 4, 'full_S3_accepted': False,
            'strace_version': subprocess.check_output(['strace', '-V'], text=True).splitlines()[0],
            'strace_sha256': hashlib.sha256(Path(shutil.which('strace')).read_bytes()).hexdigest(),
            'scope': 'Two observed single-CPU long cases only. Other modes/workloads, images, soak and faults are not executed. '
                     'Trace CPU and timing are instrumented diagnostics, not threshold comparisons.'}
    write(output / 'plan.json', plan)
    spec = importlib.util.spec_from_file_location('long_cpu_original_bench', root / 'scripts/native-acceptance.py')
    bench = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(bench)
    original_snapshot = bench.cpu_snapshot
    settings = SimpleNamespace(candidate=CANDIDATE, output=output, groups=5, seconds=10,
                               warmup=2, concurrency=4, diagnostics_only=True, persistence_diagnostics_only=False)

    def investigate(directory, report, arguments, origin):
        report['settings']['persistence_diagnostics'] = 'disabled'
        report['settings']['cpu_profiles'] = False
        report['diagnostics'] = []
        report['reproduction_samples'], report['syscall_samples'] = [], []
        for group in range(1, 6):
            sides = ('legacy', 'candidate') if group % 2 else ('candidate', 'legacy')
            for mode in CASES:
                for side in sides:
                    state = directory / ('repeat-g%d-%s-%s' % (group, mode, side))
                    result = bench.sample(directory / ('server-' + side), state, mode, 'long', arguments, origin)
                    result.update(group=group, side=side)
                    report['reproduction_samples'].append(result)
                    write(directory / 'report.json', report)
                    print('untraced group=%d mode=%s side=%s status=%s' % (group, mode, side, result['status']), flush=True)
        comparisons = bench.compare(report['reproduction_samples'], 5)
        report['reproduction_comparisons'] = [c for c in comparisons if c['mode'] in CASES and c['workload'] == 'long']
        for mode in CASES:
            for side in ('legacy', 'candidate'):
                state = directory / ('syscalls-%s-%s' % (mode, side))
                active = []
                def traced_snapshot(process, snapshot_state, number, nonce):
                    if number == 1:
                        window = TraceWindow(process, snapshot_state)
                        active.append(window)
                        window.start()
                    value = original_snapshot(process, snapshot_state, number, nonce)
                    if number == 2:
                        active[-1].stop()
                    return value
                bench.cpu_snapshot = traced_snapshot
                item = {'mode': mode, 'workload': 'long', 'side': side, 'acceptance_sample': False}
                try:
                    item['sample'] = bench.sample(directory / ('server-' + side), state, mode, 'long', arguments, origin)
                finally:
                    bench.cpu_snapshot = original_snapshot
                    for window in active:
                        try:
                            window.stop()
                        except Exception as error:
                            window.result['collection_error'] = type(error).__name__
                        item['syscall_window'] = window.result
                    write(state / 'trace-metadata.json', item.get('syscall_window', {'complete': False}))
                report['syscall_samples'].append(item)
                write(directory / 'report.json', report)
                print('traced mode=%s side=%s status=%s' % (mode, side, item['sample']['status']), flush=True)

    bench.diagnostics = investigate
    report = bench.run(settings)
    report['binary_hashes_match_reference'] = {
        side: {field: report['builds'][side].get(field) == reference['builds'][side][field]
               for field in ('binary_sha256', 'harness_sha256')}
        for side in ('legacy', 'candidate')}
    report.update(schema='txnode-native-long-cpu-investigation/v1', accepted=False, full_S3_accepted=False,
                  scope=plan['scope'], plan_sha256=hashlib.sha256((output / 'plan.json').read_bytes()).hexdigest())
    repeated, traced = report.get('reproduction_samples', []), report.get('syscall_samples', [])
    complete = (len(repeated) == 20 and len(traced) == 4
                and all(s['status'] == 'measured' for s in repeated)
                and all(s.get('sample', {}).get('status') == 'measured'
                        and s.get('syscall_window', {}).get('complete') is True for s in traced))
    report.update(collection_complete=complete, status='collected' if complete else 'incomplete')
    write(output / 'report.json', report)
    lines = ['# Single CPU long-workload investigation', '', 'Collection complete: `%s`; full S3 accepted: `false`.' % complete,
             '', 'Untraced comparisons use only the two diagnostic cases, not a full acceptance matrix.', '',
             '```json', json.dumps(report.get('reproduction_comparisons', []), indent=2), '```', '',
             'Traced syscall counts include the CPU request/acknowledgement envelope; their timing and CPU ratios are not acceptance data.']
    (output / 'report.md').write_text('\n'.join(lines) + '\n', encoding='utf-8')
    print(json.dumps({'collection_complete': complete, 'comparisons': report.get('reproduction_comparisons', []),
                      'full_S3_accepted': False}), flush=True)
    if not complete:
        raise SystemExit('long CPU diagnostic collection incomplete')


if __name__ == '__main__':
    main()
