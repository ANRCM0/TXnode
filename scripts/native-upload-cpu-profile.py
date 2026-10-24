"""Bounded ordinary/upload CPU profiles on the exact rejected-run binaries."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
from types import SimpleNamespace

import importlib.util


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


def write(path, value):
    path.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--reference', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux' or os.cpu_count() != 4:
        raise RuntimeError('profiles belong to the four-CPU Linux Actions environment')
    if args.output.exists() or args.reference.exists():
        raise RuntimeError('fresh diagnostic directories required')
    root = Path(__file__).resolve().parent.parent
    driver = module('frozen_reference_reader', root / 'scripts/native-cpu-latency-follow-up.py')
    reference = driver.download_reference(args.reference)
    if (reference['candidate'] != driver.CANDIDATE or reference['accepted'] is not False
            or reference['baseline'] != '4904a193d4564cf67af55728da0b338ff3b1268f'
            or reference['go'] != 'go version go1.26.0 linux/amd64'):
        raise ValueError('frozen reference source identity changed')
    if subprocess.check_output(['go', 'version'], text=True).strip() != reference['go']:
        raise ValueError('profile decoder toolchain differs from the frozen build')
    paths = ['scripts/native-acceptance.py'] + [str(p.relative_to(root))
             for p in sorted((root / 'scripts').glob('native-acceptance-*.go.tmpl'))]
    sources = {}
    for path in paths:
        if (root / path).read_bytes() != subprocess.check_output(['git', 'show', driver.CANDIDATE + ':' + path], cwd=root):
            raise ValueError('original sample or harness source changed')
        sources[path] = sha(root / path)
    binaries = {}
    for side in ('legacy', 'candidate'):
        for prefix, field in [('server-', 'harness_sha256'), ('tx-node-', 'binary_sha256')]:
            path = args.reference / (prefix + side)
            if sha(path) != reference['builds'][side][field]:
                raise ValueError('frozen binary identity changed')
            path.chmod(0o755)
            binaries[path.name] = sha(path)
    args.output.mkdir(parents=True)
    plan = {'schema': 'txnode-upload-cpu-profile-plan/v1', 'candidate': driver.CANDIDATE,
            'baseline_identity': reference['baseline_identity'],
            'workflow_source': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
            'reference_run': 40121606962, 'reference_artifact': driver.REFERENCE_ARTIFACT,
            'reference_report_sha256': driver.REFERENCE_REPORT, 'reference_zip_sha256': driver.REFERENCE_ZIP,
            'binary_sha256': binaries, 'source_sha256': sources,
            'cpu_count': os.cpu_count(), 'affinity_unchanged': sorted(os.sched_getaffinity(0)),
            'gomaxprocs': os.environ.get('GOMAXPROCS'), 'go': reference['go'],
            'settings': {'groups': 3, 'warmup': 2, 'seconds': 55, 'concurrency': 4,
                         'mode': 'ordinary', 'workload': 'upload'},
            'scope': 'instrumented startup/warmup/55-second measurement/shutdown profiles; '
                     'six finite samples, no acceptance ratio, threshold, full matrix, soak or loaded fault claim',
            'accepted': False, 'full_S3_accepted': False}
    write(args.output / 'plan.json', plan)
    report = {'schema': 'txnode-upload-cpu-profile/v1', 'candidate': driver.CANDIDATE,
              'baseline_identity': reference['baseline_identity'], 'plan_sha256': sha(args.output / 'plan.json'),
              'samples': [], 'collection_complete': False, 'accepted': False, 'full_S3_accepted': False}
    bench = module('original_upload_sample', root / 'scripts/native-acceptance.py')
    settings = SimpleNamespace(candidate=driver.CANDIDATE, output=args.output, groups=3, seconds=55,
                               warmup=2, concurrency=4, diagnostics_only=True, persistence_diagnostics_only=False)
    origin = bench.Origin()
    try:
        for group in range(1, 4):
            for side in (('legacy', 'candidate') if group % 2 else ('candidate', 'legacy')):
                state = args.output / ('profile-g%d-%s' % (group, side))
                profile = state / 'cpu.pprof'
                value = bench.sample(args.reference / ('server-' + side), state, 'ordinary', 'upload',
                                     settings, origin, cpu_profile=profile)
                entry = {'group': group, 'side': side, 'sample': value, 'acceptance_sample': False}
                if value['status'] == 'measured' and profile.exists() and profile.stat().st_size > 0:
                    for name, flags in [('cpu-top.txt', ['-top', '-nodecount=40']),
                                        ('cpu-raw.txt', ['-raw'])]:
                        result = subprocess.check_output(['go', 'tool', 'pprof', *flags,
                                                          str(args.reference / ('server-' + side)), str(profile)],
                                                         text=True, stderr=subprocess.STDOUT, timeout=30)
                        (state / name).write_text(result, encoding='utf-8')
                    entry.update(profile_sha256=sha(profile), raw_sha256=sha(state / 'cpu-raw.txt'),
                                 top_sha256=sha(state / 'cpu-top.txt'))
                report['samples'].append(entry)
                write(args.output / 'report.json', report)
                print('profile group=%d side=%s status=%s' % (group, side, value['status']), flush=True)
    finally:
        origin.close()
        assert all(sha(args.reference / name) == expected for name, expected in binaries.items())
        report['collection_complete'] = (len(report['samples']) == 6 and all(
            item['sample']['status'] == 'measured' and 'profile_sha256' in item for item in report['samples']))
        write(args.output / 'report.json', report)
    if not report['collection_complete']:
        raise SystemExit('finite upload CPU profile collection incomplete')


if __name__ == '__main__':
    main()
