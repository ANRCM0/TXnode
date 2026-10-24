"""Finite Actions reproduction on frozen binaries; never formal S3 acceptance."""
import argparse
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import platform
import subprocess
from types import SimpleNamespace
import urllib.error
import urllib.request
import zipfile


CANDIDATE = '8cfddde002bea6d9fb3c96b4d4941188c0c332ea'
REFERENCE_ARTIFACT = 12572342452
REFERENCE_ZIP = 'ba37981a33d5d0cd8c83f61b9879f205f9b9471494c199c8143506d2ad09df4c'
REFERENCE_REPORT = 'a5780c319fa4594985cef0bfc0fcb418fcd851e64df51b27e6676d151b9d28bb'
CASES = (('ordinary', 'upload'), ('ordinary', 'long'), ('usage_v2', 'download'))


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def download_reference(directory):
    token = os.environ.pop('GH_TOKEN')
    endpoint = 'https://api.github.com/repos/ANRCM0/TXnode/actions/artifacts/%d/zip' % REFERENCE_ARTIFACT
    request = urllib.request.Request(endpoint, headers={'Authorization': 'Bearer ' + token})
    try:
        urllib.request.build_opener(NoRedirect()).open(request, timeout=30)
        raise RuntimeError('artifact endpoint did not redirect')
    except urllib.error.HTTPError as error:
        if error.code != 302:
            raise RuntimeError('reference artifact API refused the request') from None
        url = error.headers['Location']
    del request, token
    try:
        with urllib.request.urlopen(url, timeout=60) as response:
            data = response.read()
    except Exception:
        raise RuntimeError('reference artifact transport failed') from None
    if hashlib.sha256(data).hexdigest() != REFERENCE_ZIP:
        raise ValueError('reference ZIP digest mismatch')
    directory.mkdir(parents=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        for name in ('report.json', 'server-legacy', 'server-candidate', 'tx-node-legacy', 'tx-node-candidate'):
            (directory / name).write_bytes(archive.read(name))
    report_path = directory / 'report.json'
    if hashlib.sha256(report_path.read_bytes()).hexdigest() != REFERENCE_REPORT:
        raise ValueError('reference report digest mismatch')
    return json.loads(report_path.read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('workloads belong to Linux Actions')
    if os.cpu_count() != 4:
        raise RuntimeError('the reference requires a four-CPU hosted runner')
    output = args.output.resolve()
    if output.exists() or args.reference.exists():
        raise RuntimeError('fresh private diagnostic directories required')
    output.mkdir(parents=True)
    root = Path(__file__).resolve().parent.parent
    reference = download_reference(args.reference)
    if (reference['candidate'] != CANDIDATE
            or reference['baseline'] != '4904a193d4564cf67af55728da0b338ff3b1268f'
            or reference['go'] != 'go version go1.26.0 linux/amd64'
            or reference['accepted'] is not False or len(reference['samples']) != 120):
        raise ValueError('frozen reference identity mismatch')
    for key, value in [('groups', 5), ('sample_seconds', 10), ('warmup_seconds', 2), ('concurrency', 4)]:
        if reference['settings'][key] != value:
            raise ValueError('reference sampling settings mismatch')
    paths = ['scripts/native-acceptance.py', 'scripts/native_baselines.py', 'scripts/native_latency.py']
    paths += [str(p.relative_to(root)) for p in sorted((root / 'scripts').glob('native-acceptance-*.go.tmpl'))]
    source_hashes = {}
    for path in paths:
        data = (root / path).read_bytes()
        if data != subprocess.check_output(['git', 'show', CANDIDATE + ':' + path], cwd=root):
            raise ValueError('reference measurement source changed')
        source_hashes[path] = hashlib.sha256(data).hexdigest()
    binary_hashes = {}
    for side in ('legacy', 'candidate'):
        for prefix, key in [('server-', 'harness_sha256'), ('tx-node-', 'binary_sha256')]:
            path = args.reference / (prefix + side)
            value = hashlib.sha256(path.read_bytes()).hexdigest()
            if value != reference['builds'][side][key]:
                raise ValueError('frozen binary digest mismatch')
            path.chmod(0o755)
            binary_hashes[path.name] = value
    plan = {'schema': 'txnode-native-cpu-latency-follow-up-plan/v1',
            'candidate': CANDIDATE, 'baseline_identity': reference['baseline_identity'],
            'workflow_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], cwd=root, text=True).strip(),
            'reference_run': 40121606962, 'reference_artifact': REFERENCE_ARTIFACT,
            'reference_zip_sha256': REFERENCE_ZIP, 'reference_report_sha256': REFERENCE_REPORT,
            'source_sha256': source_hashes, 'binary_sha256': binary_hashes,
            'cpu_count': os.cpu_count(), 'affinity_unchanged': sorted(os.sched_getaffinity(0)),
            'gomaxprocs': os.environ.get('GOMAXPROCS'),
            'settings': {'groups': 5, 'warmup': 2, 'seconds': 10, 'concurrency': 4,
                         'cases': [list(case) for case in CASES]},
            'untraced_samples': 30, 'traced_samples': 4,
            'scope': 'frozen-binary diagnostic reproduction of three reported cells; '
                     'trace counts include CPU request/ack envelope and trace timing is not acceptance data',
            'accepted': False, 'full_S3_accepted': False}
    write(output / 'plan.json', plan)
    bench = load_module('frozen_reference_bench', root / 'scripts/native-acceptance.py')
    latency = load_module('frozen_reference_latency', root / 'scripts/native_latency.py')
    trace = load_module('bounded_reference_trace', root / 'scripts/native-reproduction-trace.py')
    settings = SimpleNamespace(seconds=10, warmup=2, concurrency=4,
                               diagnostics_only=False, persistence_diagnostics_only=False)
    report = {'schema': 'txnode-native-cpu-latency-follow-up/v1', 'candidate': CANDIDATE,
              'baseline_identity': reference['baseline_identity'], 'plan_sha256': hashlib.sha256((output / 'plan.json').read_bytes()).hexdigest(),
              'reproduction_samples': [], 'syscall_samples': [], 'accepted': False,
              'full_S3_accepted': False, 'status': 'incomplete', 'collection_complete': False}
    original_snapshot = bench.cpu_snapshot
    origin = bench.Origin()
    try:
        for group in range(1, 6):
            sides = ('legacy', 'candidate') if group % 2 else ('candidate', 'legacy')
            for mode, workload in CASES:
                for side in sides:
                    state = output / ('repeat-g%d-%s-%s-%s' % (group, mode, workload, side))
                    sample = bench.sample(args.reference / ('server-' + side), state, mode, workload, settings, origin)
                    sample.update(group=group, side=side)
                    report['reproduction_samples'].append(sample)
                    write(output / 'report.json', report)
                    print('repeat group=%d mode=%s workload=%s side=%s status=%s' %
                          (group, mode, workload, side, sample['status']), flush=True)
        report['cpu_comparisons'] = [c for c in bench.compare(report['reproduction_samples'], 5)
                                     if (c['mode'], c['workload']) in CASES]
        report['latency_comparisons'] = [c for c in latency.comparisons(report['reproduction_samples'])
                                         if (c['mode'], c['workload']) in CASES]
        for mode, workload in CASES[:2]:
            for side in ('legacy', 'candidate'):
                state = output / ('trace-%s-%s-%s' % (mode, workload, side))
                windows = []

                def snapshot(process, directory, number, nonce):
                    if number == 1:
                        window = trace.TraceWindow(process, directory, interruptible=2)
                        windows.append(window)
                        window.start()
                    value = original_snapshot(process, directory, number, nonce)
                    if number == 2:
                        try:
                            windows[-1].stop()
                        except Exception as error:
                            windows[-1].result['collection_error'] = type(error).__name__
                    return value

                item = {'mode': mode, 'workload': workload, 'side': side, 'acceptance_sample': False}
                bench.cpu_snapshot = snapshot
                try:
                    item['sample'] = bench.sample(args.reference / ('server-' + side), state, mode, workload, settings, origin)
                finally:
                    bench.cpu_snapshot = original_snapshot
                    for window in windows:
                        try:
                            window.stop()
                        except Exception as error:
                            window.result['collection_error'] = type(error).__name__
                        item['syscall_window'] = window.result
                    write(state / 'trace-metadata.json', item.get('syscall_window', {'complete': False}))
                report['syscall_samples'].append(item)
                write(output / 'report.json', report)
    finally:
        bench.cpu_snapshot = original_snapshot
        origin.close()
        for name, expected in binary_hashes.items():
            if hashlib.sha256((args.reference / name).read_bytes()).hexdigest() != expected:
                raise ValueError('frozen binary changed during reproduction')
        repeated, traced = report['reproduction_samples'], report['syscall_samples']
        complete = (len(repeated) == 30 and len(traced) == 4
                    and all(s['status'] == 'measured' for s in repeated)
                    and all(s.get('sample', {}).get('status') == 'measured'
                            and s.get('syscall_window', {}).get('complete') is True for s in traced))
        report.update(collection_complete=complete, status='collected' if complete else 'incomplete')
        write(output / 'report.json', report)
    print(json.dumps({'collection_complete': report['collection_complete'],
                      'cpu_comparisons': report.get('cpu_comparisons'),
                      'latency_comparisons': report.get('latency_comparisons'),
                      'full_S3_accepted': False}), flush=True)
    if not report['collection_complete']:
        raise SystemExit('bounded reproduction collection incomplete')


if __name__ == '__main__':
    main()
