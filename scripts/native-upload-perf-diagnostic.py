"""Finite software CPU stacks on the exact ordinary/upload reference binaries."""
import argparse
import collections
import importlib.util
import json
import os
from pathlib import Path
import platform
import select
import subprocess
import sys
from types import SimpleNamespace


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def line(process):
    if not select.select([process.stdout], [], [], 5)[0]:
        raise RuntimeError('controlled fixture response missing')
    return json.loads(process.stdout.readline())


def control_probe(output, perf):
    state = output / 'control-probe'
    state.mkdir()
    fixture = '''import json,os,sys,time
print(json.dumps({'ready':os.getpid()}),flush=True)
for request in sys.stdin:
 if request.strip()=='run':
  start=time.process_time_ns();end=time.monotonic()+2;value=1
  while time.monotonic()<end:value=(value*13+7)%10000019
  print(json.dumps({'cpu_nanos':time.process_time_ns()-start}),flush=True)
 elif request.strip()=='ping':print(json.dumps({'alive':True}),flush=True)
 elif request.strip()=='exit':break
'''
    with (state / 'fixture.stderr').open('wb') as err:
        process = subprocess.Popen([sys.executable, '-u', '-c', fixture], stdin=subprocess.PIPE,
                                   stdout=subprocess.PIPE, stderr=err, text=True)
        window = perf.PerfWindow(process, state)
        result = {'complete': False, 'minimum_samples': 1000}
        try:
            if line(process) != {'ready': process.pid}:
                raise ValueError('controlled fixture identity changed')
            window.start()
            process.stdin.write('run\n')
            process.stdin.flush()
            result['work'] = line(process)
            window.stop()
            process.stdin.write('ping\n')
            process.stdin.flush()
            if line(process) != {'alive': True} or window.result.get('samples', 0) < 1000:
                raise ValueError('controlled fixture continuation or CPU sample budget failed')
            result.update(complete=True, window=window.result)
            process.stdin.write('exit\n')
            process.stdin.flush()
            if process.wait(timeout=5) != 0:
                raise RuntimeError('controlled fixture did not exit cleanly')
        finally:
            if not window.finished:
                try:
                    window.stop()
                except Exception as error:
                    result['collection_error'] = type(error).__name__
            if process.poll() is None:
                process.terminate()
                process.wait(timeout=5)
            process.stdin.close()
            process.stdout.close()
            result['window'] = window.result
            perf.write(state / 'result.json', result)
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux' or os.cpu_count() != 4:
        raise RuntimeError('sampling belongs to four-CPU Linux Actions')
    if args.output.exists() or args.reference.exists():
        raise RuntimeError('fresh diagnostic directories required')
    root = Path(__file__).resolve().parent.parent
    reader = module('frozen_original_reader', root / 'scripts/native-cpu-latency-follow-up.py')
    perf = module('bounded_software_perf', root / 'scripts/native-perf-window.py')
    reference = reader.download_reference(args.reference)
    if (reference['candidate'] != reader.CANDIDATE or reference['accepted'] is not False
            or reference['baseline'] != '4904a193d4564cf67af55728da0b338ff3b1268f'
            or reference['go'] != 'go version go1.26.0 linux/amd64'):
        raise ValueError('original reference identity changed')
    paths = ['scripts/native-acceptance.py'] + [str(p.relative_to(root))
             for p in sorted((root / 'scripts').glob('native-acceptance-*.go.tmpl'))]
    sources = {}
    for path in paths:
        if (root / path).read_bytes() != subprocess.check_output(['git', 'show', reader.CANDIDATE + ':' + path], cwd=root):
            raise ValueError('original measurement or harness source changed')
        sources[path] = perf.sha(root / path)
    binaries = {}
    for side in ('legacy', 'candidate'):
        for prefix, field in [('server-', 'harness_sha256'), ('tx-node-', 'binary_sha256')]:
            path = args.reference / (prefix + side)
            if perf.sha(path) != reference['builds'][side][field]:
                raise ValueError('frozen binary digest changed')
            path.chmod(0o755)
            binaries[path.name] = perf.sha(path)
    if perf.sha(perf.PERF) != perf.PERF_SHA:
        raise ValueError('perf differs from the capability probe')
    args.output.mkdir(parents=True)
    plan = {'schema': 'txnode-native-upload-perf-plan/v1', 'candidate': reader.CANDIDATE,
            'baseline_identity': reference['baseline_identity'],
            'workflow_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'reference_run': 40121606962, 'reference_artifact': reader.REFERENCE_ARTIFACT,
            'reference_zip_sha256': reader.REFERENCE_ZIP, 'reference_report_sha256': reader.REFERENCE_REPORT,
            'capability_run': 40128772350, 'decoded_reference_run': 40129327238,
            'binary_sha256': binaries, 'source_sha256': sources, 'perf_sha256': perf.PERF_SHA,
            'cpu_count': os.cpu_count(), 'affinity_unchanged': sorted(os.sched_getaffinity(0)),
            'gomaxprocs': os.environ.get('GOMAXPROCS'), 'minimum_inner_samples_per_side': 1000,
            'settings': {'groups': 3, 'warmup': 2, 'seconds': 55, 'concurrency': 4,
                         'mode': 'ordinary', 'workload': 'upload', 'frequency': 997, 'event': 'cpu-clock',
                         'clock': 'CLOCK_MONOTONIC', 'stack_bytes': 16384, 'max_record_bytes': 128 << 20},
            'scope': 'controlled synthetic CPU fixture then six separate instrumented upload samples; '
                     'inner CPU snapshot windows only, no acceptance ratio or full S3 claim',
            'accepted': False, 'full_S3_accepted': False}
    perf.write(args.output / 'plan.json', plan)
    report = {'schema': 'txnode-native-upload-perf/v1', 'candidate': reader.CANDIDATE,
              'baseline_identity': reference['baseline_identity'], 'plan_sha256': perf.sha(args.output / 'plan.json'),
              'samples': [], 'collection_complete': False, 'accepted': False, 'full_S3_accepted': False}
    origin = bench = None
    try:
        report['control_probe'] = control_probe(args.output, perf)
        perf.write(args.output / 'report.json', report)
        if not report['control_probe']['complete']:
            raise RuntimeError('controlled perf probe failed before Node load')
        bench = module('original_upload_benchmark', root / 'scripts/native-acceptance.py')
        original = bench.cpu_snapshot
        settings = SimpleNamespace(candidate=reader.CANDIDATE, output=args.output, groups=3, seconds=55,
                                   warmup=2, concurrency=4, diagnostics_only=True, persistence_diagnostics_only=False)
        origin = bench.Origin()
        for group in range(1, 4):
            for side in (('legacy', 'candidate') if group % 2 else ('candidate', 'legacy')):
                state = args.output / ('sample-g%d-%s' % (group, side))
                windows = []

                def snapshot(process, directory, number, nonce):
                    if number == 1:
                        window = perf.PerfWindow(process, directory)
                        windows.append(window)
                        window.start()
                    value = original(process, directory, number, nonce)
                    if number == 2:
                        try:
                            windows[-1].stop()
                        except Exception as error:
                            windows[-1].result['collection_error'] = type(error).__name__
                    return value

                bench.cpu_snapshot = snapshot
                try:
                    sample = bench.sample(args.reference / ('server-' + side), state, 'ordinary', 'upload',
                                          settings, origin)
                finally:
                    bench.cpu_snapshot = original
                    for window in windows:
                        if not window.finished:
                            try:
                                window.stop()
                            except Exception as error:
                                window.result['collection_error'] = type(error).__name__
                item = {'group': group, 'side': side, 'sample': sample, 'acceptance_sample': False,
                        'perf_window': windows[0].result if len(windows) == 1 else {'complete': False}}
                if sample['status'] == 'measured' and item['perf_window']['complete']:
                    controls = item['perf_window']['controls']
                    proof = sample['cpu_measurement']
                    if ([c['command'] for c in controls] != ['enable', 'disable', 'stop']
                            or controls[0]['ack_ns'] >= proof['start']['requested_monotonic_nanos']
                            or proof['end']['received_monotonic_nanos'] >= controls[1]['sent_ns']):
                        raise ValueError('perf controls do not surround original CPU requests')
                    captured = perf.parse_samples(state / 'perf-script.txt', proof['start']['pid'])
                    inner = [s for s in captured if proof['start']['monotonic_after_nanos'] <= s['time_ns']
                             <= proof['end']['monotonic_before_nanos']]
                    flat, cumulative = collections.Counter(), collections.Counter()
                    for point in inner:
                        flat[point['frames'][0]['symbol']] += point['period_ns']
                        for name in {frame['symbol'] for frame in point['frames']}:
                            cumulative[name] += point['period_ns']
                    item['inner'] = {'samples': len(inner), 'period_ns': sum(s['period_ns'] for s in inner),
                                     'tids': sorted({s['tid'] for s in inner}),
                                     'flat': dict(flat.most_common()), 'cumulative': dict(cumulative.most_common())}
                report['samples'].append(item)
                perf.write(args.output / 'report.json', report)
                print('group=%d side=%s measured=%s perf_complete=%s inner_samples=%s' %
                      (group, side, sample['status'], item['perf_window']['complete'],
                       item.get('inner', {}).get('samples', 0)), flush=True)
    finally:
        if origin is not None:
            origin.close()
        assert all(perf.sha(args.reference / name) == expected for name, expected in binaries.items())
        counts = {side: sum(item.get('inner', {}).get('samples', 0) for item in report['samples']
                            if item['side'] == side) for side in ('legacy', 'candidate')}
        report.update(inner_samples_per_side=counts, collection_complete=(
            report.get('control_probe', {}).get('complete') is True and len(report['samples']) == 6
            and all(item['sample']['status'] == 'measured' and item['perf_window']['complete']
                    and item.get('inner', {}).get('samples', 0) > 0 for item in report['samples'])
            and all(n >= plan['minimum_inner_samples_per_side'] for n in counts.values())))
        perf.write(args.output / 'report.json', report)
    if not report['collection_complete']:
        raise SystemExit('bounded software CPU stack collection incomplete')


if __name__ == '__main__':
    main()
