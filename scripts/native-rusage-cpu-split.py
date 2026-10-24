"""Independent Actions CPU split with symmetric diagnostic-only harness reads."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import statistics
import subprocess
import tempfile
from types import SimpleNamespace

import importlib.util


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def instrument(original):
    replacements = [
        ('func writeCPUSnapshot(root, nonce string, sequence int) {\n',
         'func writeCPUSnapshot(root, nonce string, sequence int) {\n'
         '\tvar usageBefore, usageAfter unix.Rusage\n'
         '\tif err := unix.Getrusage(unix.RUSAGE_SELF, &usageBefore); err != nil {\n'
         '\t\tpanic(err)\n\t}\n'),
        ('\tif err := unix.ClockGetres(unix.CLOCK_PROCESS_CPUTIME_ID, &resolution); err != nil {\n',
         '\tif err := unix.Getrusage(unix.RUSAGE_SELF, &usageAfter); err != nil {\n'
         '\t\tpanic(err)\n\t}\n'
         '\tif err := unix.ClockGetres(unix.CLOCK_PROCESS_CPUTIME_ID, &resolution); err != nil {\n'),
        ('\t\t"monotonic_before_nanos": before.Nano(), "monotonic_after_nanos": after.Nano(),\n',
         '\t\t"monotonic_before_nanos": before.Nano(), "monotonic_after_nanos": after.Nano(),\n'
         '\t\t"rusage_schema": "self-user-system-outer-v1",\n'
         '\t\t"rusage_before": map[string]int64{\n'
         '\t\t\t"user_nanos": usageBefore.Utime.Sec*1e9 + usageBefore.Utime.Usec*1e3,\n'
         '\t\t\t"system_nanos": usageBefore.Stime.Sec*1e9 + usageBefore.Stime.Usec*1e3},\n'
         '\t\t"rusage_after": map[string]int64{\n'
         '\t\t\t"user_nanos": usageAfter.Utime.Sec*1e9 + usageAfter.Utime.Usec*1e3,\n'
         '\t\t\t"system_nanos": usageAfter.Stime.Sec*1e9 + usageAfter.Stime.Usec*1e3},\n')]
    transformed = original
    for before, after in replacements:
        if transformed.count(before) != 1:
            raise ValueError('original CPU snapshot anchor changed')
        transformed = transformed.replace(before, after, 1)
    restored = transformed
    for before, after in reversed(replacements):
        restored = restored.replace(after, before, 1)
    if restored != original:
        raise ValueError('diagnostic harness changed outside the two reads and fields')
    return transformed


def split(state, sample):
    snapshots = [json.loads((state / ('cpu-%d.json' % index)).read_text()) for index in (1, 2)]
    start, end = snapshots
    for index, snapshot in enumerate(snapshots, 1):
        if (snapshot.get('rusage_schema') != 'self-user-system-outer-v1'
                or snapshot['sequence'] != index or snapshot['pid'] != start['pid']
                or snapshot['nonce'] != start['nonce']):
            raise ValueError('rusage snapshot identity changed')
        for field in ('user_nanos', 'system_nanos'):
            before, after = snapshot['rusage_before'][field], snapshot['rusage_after'][field]
            if not isinstance(before, int) or before < 0 or after < before or before % 1000 or after % 1000:
                raise ValueError('rusage counter units or monotonicity invalid')
    bounds = {}
    for field in ('user_nanos', 'system_nanos'):
        low = end['rusage_before'][field] - start['rusage_after'][field]
        high = end['rusage_after'][field] - start['rusage_before'][field]
        if low < 0 or high < low:
            raise ValueError('rusage component delta invalid')
        bounds[field] = {'inner': low, 'outer': high, 'midpoint': (low + high) / 2,
                         'inner_seconds_per_gib': low / 1e9 / (sample['bytes'] / 1073741824),
                         'outer_seconds_per_gib': high / 1e9 / (sample['bytes'] / 1073741824)}
    low = sum(value['inner'] for value in bounds.values())
    high = sum(value['outer'] for value in bounds.values())
    original = end['cpu_nanos'] - start['cpu_nanos']
    if not low - 2000 <= original <= high + 2000:
        raise ValueError('rusage total does not enclose original process CPU delta within 2us rounding')
    uncertainty = (high - low + 4000) / original
    if uncertainty > 0.005:
        raise ValueError('rusage boundary uncertainty exceeds the declared 0.5 percent ceiling')
    return {'components': bounds, 'original_process_cpu_nanos': original,
            'total_inner_nanos': low, 'total_outer_nanos': high,
            'boundary_uncertainty_ratio': uncertainty, 'rounding_allowance_nanos': 2000,
            'acceptance_sample': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    if (os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux'
            or os.cpu_count() != 4 or os.environ.get('CGO_ENABLED') != '0'):
        raise RuntimeError('the probe requires four-CPU Linux Actions with CGO=0')
    root = Path(__file__).resolve().parent.parent
    base = load('frozen_split_reference', root / 'scripts/native-cpu-latency-follow-up.py')
    bench = load('frozen_split_bench', root / 'scripts/native-acceptance.py')
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=False)
    reference = base.download_reference(args.reference)
    if (reference['candidate'] != base.CANDIDATE or reference['accepted'] is not False
            or reference['baseline'] != '4904a193d4564cf67af55728da0b338ff3b1268f'
            or bench.command(['go', 'version']) != reference['go']
            or reference['go'] != 'go version go1.26.0 linux/amd64'):
        raise ValueError('frozen production source or compiler identity differs')
    baseline = bench.native_baselines.verify('legacy-clock-serialized-v1')
    paths = ['scripts/native-acceptance.py', 'scripts/native_baselines.py']
    paths += [str(path.relative_to(root)) for path in sorted((root / 'scripts').glob('native-acceptance-*.go.tmpl'))]
    source_hashes = {}
    for path in paths:
        data = (root / path).read_bytes()
        if data != subprocess.check_output(['git', 'show', base.CANDIDATE + ':' + path], cwd=root):
            raise ValueError('original measurement source differs')
        source_hashes[path] = hashlib.sha256(data).hexdigest()
    for side in ('legacy', 'candidate'):
        for prefix, key in [('server-', 'harness_sha256'), ('tx-node-', 'binary_sha256')]:
            if digest(args.reference / (prefix + side)) != reference['builds'][side][key]:
                raise ValueError('frozen reference binary digest differs')
    original = (root / 'scripts/native-acceptance-server.go.tmpl').read_text()
    transformed = instrument(original)
    (output / 'diagnostic-server.go.txt').write_text(transformed)
    plan = {'schema': 'txnode-rusage-split-plan/v1', 'candidate': base.CANDIDATE,
            'candidate_tree': reference['candidate_tree'], 'baseline_identity': baseline,
            'tool_source': bench.command(['git', 'rev-parse', 'HEAD']),
            'reference_run': 40121606962, 'reference_artifact': base.REFERENCE_ARTIFACT,
            'reference_zip_sha256': base.REFERENCE_ZIP, 'reference_report_sha256': base.REFERENCE_REPORT,
            'original_source_sha256': source_hashes, 'go': reference['go'], 'build_flags': bench.FLAGS,
            'diagnostic_template_sha256': digest(output / 'diagnostic-server.go.txt'),
            'groups': 5, 'seconds': 55, 'warmup': 2, 'concurrency': 4,
            'mode': 'ordinary', 'workload': 'upload', 'samples': 10,
            'cpu_count': os.cpu_count(), 'affinity': sorted(os.sched_getaffinity(0)),
            'gomaxprocs': os.environ.get('GOMAXPROCS'), 'cpu_profiles': False,
            'maximum_boundary_uncertainty_ratio': 0.005, 'rounding_allowance_nanos': 2000,
            'scope': 'symmetric RUSAGE_SELF reads around the original CPU clock; diagnostic harnesses are rebuilt; '
                     'production app binary digests must equal the frozen originals; no formal S3 verdict',
            'accepted': False, 'full_S3_accepted': False}
    write(output / 'plan.json', plan)
    report = {'schema': 'txnode-rusage-split/v1', 'plan_sha256': digest(output / 'plan.json'),
              'builds': {}, 'samples': [], 'collection_complete': False,
              'accepted': False, 'full_S3_accepted': False}
    workspace = Path(tempfile.mkdtemp(prefix='txnode-rusage-checkouts-')).resolve()
    checkouts, origin = [], None
    try:
        for side, revision in [('legacy', baseline['commit']), ('candidate', base.CANDIDATE)]:
            checkout = workspace / side
            bench.command(['git', 'worktree', 'add', '--detach', str(checkout), revision])
            checkouts.append(checkout)
            if bench.command(['git', 'status', '--porcelain'], checkout):
                raise ValueError('production checkout is not pristine before harness injection')
            harness = checkout / 'cmd/native-ab'
            harness.mkdir()
            (harness / 'main.go').write_text(transformed)
            shutil.copyfile(root / ('scripts/native-acceptance-%s.go.tmpl' % side), harness / 'factory.go')
            shutil.copyfile(root / 'scripts/native-acceptance-bucket-diagnostic.go.tmpl',
                            checkout / 'internal/usagebucket/native_ab_diagnostic.go')
            locks = {name: digest(checkout / name) for name in ('go.mod', 'go.sum')}
            if locks != reference['builds'][side]['module_lock_sha256']:
                raise ValueError('frozen production module locks differ')
            prefetch = bench.prefetch_modules(checkout, output, side)
            if prefetch['status'] != 'complete':
                raise ValueError('module prefetch incomplete')
            binary, app = output / ('server-' + side), output / ('tx-node-' + side)
            bench.command(['go', 'build', *bench.FLAGS, '-o', str(binary), './cmd/native-ab'], checkout)
            bench.command(['go', 'build', *bench.FLAGS, '-o', str(app), './cmd/tx-node'], checkout)
            if digest(app) != reference['builds'][side]['binary_sha256']:
                raise ValueError('production app binary differs from frozen original')
            if locks != {name: digest(checkout / name) for name in locks}:
                raise ValueError('build changed production module locks')
            bench.command(['git', 'diff', '--exit-code'], checkout)
            report['builds'][side] = {'source': revision, 'source_tree': bench.command(['git', 'rev-parse', 'HEAD^{tree}'], checkout),
                                      'production_app_sha256': digest(app), 'matches_original_app': True,
                                      'diagnostic_harness_sha256': digest(binary), 'module_lock_sha256': locks,
                                      'prefetch': prefetch}
            write(output / 'report.json', report)
        origin = bench.Origin()
        settings = SimpleNamespace(seconds=55, warmup=2, concurrency=4)
        for group in range(1, 6):
            for side in (('legacy', 'candidate') if group % 2 else ('candidate', 'legacy')):
                state = output / ('split-g%d-%s' % (group, side))
                sample = bench.sample(output / ('server-' + side), state, 'ordinary', 'upload', settings, origin)
                item = {'group': group, 'side': side, 'state': state.name, 'sample': sample}
                if sample['status'] == 'measured':
                    try:
                        item['cpu_split'] = split(state, sample)
                    except Exception as error:
                        item['split_error'] = str(error)
                report['samples'].append(item)
                write(output / 'report.json', report)
                print('group=%d side=%s accounting=%s split=%s' %
                      (group, side, sample['status'], 'complete' if 'cpu_split' in item else 'incomplete'), flush=True)
        report['collection_complete'] = len(report['samples']) == 10 and all('cpu_split' in item for item in report['samples'])
        if report['collection_complete']:
            comparisons = {}
            for field in ('user_nanos', 'system_nanos'):
                sides = {}
                for side in ('legacy', 'candidate'):
                    values = [item['cpu_split']['components'][field]['midpoint'] / 1e9 /
                              (item['sample']['bytes'] / 1073741824) for item in report['samples'] if item['side'] == side]
                    sides[side] = {'values_seconds_per_gib': values, 'median': statistics.median(values),
                                   'cv': statistics.pstdev(values) / statistics.mean(values)}
                comparisons[field] = {'sides': sides, 'candidate_over_legacy_median': sides['candidate']['median'] / sides['legacy']['median']}
            report['diagnostic_component_comparisons'] = comparisons
    except Exception as error:
        report['collection_error'] = str(error)
        raise
    finally:
        if origin is not None:
            origin.close()
        for checkout in reversed(checkouts):
            if checkout.parent.resolve() != workspace:
                raise ValueError('private checkout cleanup escaped its temporary workspace')
            bench.command(['git', 'worktree', 'remove', '--force', str(checkout)])
        shutil.rmtree(workspace)
        write(output / 'report.json', report)
    return 0 if report['collection_complete'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
