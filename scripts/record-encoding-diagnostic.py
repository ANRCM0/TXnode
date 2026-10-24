"""Actions-only primitive diagnostics; not a relay or S3 acceptance result."""
import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import statistics
import subprocess


ROOT_TESTS = {'TestJournalRecordPreparationKeepsCanonicalBytes',
              'TestJournalRecordPreparationRejectsInvalidEvidence',
              'TestStorePreparedRecordPreservesCanonicalRecovery'}
SOURCE_FILES = ['go.mod', 'go.sum', 'internal/usagebucket/store.go',
                'internal/usagebucket/store_schema.go', 'internal/usagebucket/store_encoding.go',
                'internal/usagebucket/store_encoding_test.go',
                'internal/usagebucket/store_encoding_linux_test.go']
BENCH = re.compile(r'^BenchmarkJournalRecordPreparation/(1|128)_events/(reference|reuse)-(\d+)\s+'
                   r'(\d+)\s+([0-9.]+)\s+ns/op\s+([0-9.]+)\s+MB/s\s+(\d+)\s+B/op\s+(\d+)\s+allocs/op$')


def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def command(args, cwd):
    return subprocess.check_output(args, cwd=cwd, text=True).strip()


def execute(args, source, output, name, environment):
    with (output / (name + '.stdout')).open('w') as stdout, (output / (name + '.stderr')).open('w') as stderr:
        status = subprocess.run(args, cwd=source, env=environment, stdout=stdout, stderr=stderr, timeout=360).returncode
    if status != 0:
        raise RuntimeError('%s failed with exit %d' % (name, status))
    return (output / (name + '.stdout')).read_text()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--source', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.environ.get('GITHUB_ACTIONS') != 'true' or platform.system() != 'Linux':
        raise RuntimeError('record encoding execution is restricted to Linux GitHub Actions')
    if re.fullmatch('[0-9a-f]{40}', args.candidate) is None:
        raise ValueError('immutable candidate required')
    source, output = args.source.resolve(), args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    assert command(['git', 'rev-parse', 'HEAD'], source) == args.candidate
    assert command(['git', 'status', '--porcelain'], source) == ''
    assert command(['go', 'version'], source) == 'go version go1.26.0 linux/amd64'
    plan = {'schema': 'txnode-record-encoding-diagnostic/v1', 'candidate': args.candidate,
            'candidate_tree': command(['git', 'rev-parse', 'HEAD^{tree}'], source),
            'tool_source': os.environ['GITHUB_SHA'], 'driver_sha256': sha(Path(__file__)),
            'source_sha256': {name: sha(source / name) for name in SOURCE_FILES},
            'go': command(['go', 'version'], source),
            'settings': {'groups': 5, 'events': [1, 128], 'benchtime': '300ms',
                         'alternating_pipeline_order': True, 'benchmark_race': False,
                         'tests_race': True, 'noise_cv_ceiling': 0.10},
            'inherited_environment': {name: os.environ.get(name) for name in ('GOMAXPROCS', 'GOFLAGS', 'GOEXPERIMENT', 'GODEBUG')},
            'scope': 'same-candidate Go benchmark wall ns/op and allocations; no I/O workload, process CPU/GiB or S3 gate'}
    (output / 'plan.json').write_text(json.dumps(plan, indent=2) + '\n')
    report = {**plan, 'accepted': False, 'full_S3_accepted': False,
              'collection_complete': False, 'benchmarks': [], 'comparisons': []}
    try:
        environment = os.environ.copy()
        environment['CGO_ENABLED'] = '1'
        expression = '^(' + '|'.join(sorted(ROOT_TESTS)) + ')$'
        raw = execute(['go', 'test', '-race', '-json', '-count=1', '-run', expression,
                       '-timeout=5m', './internal/usagebucket'], source, output, 'record-tests', environment)
        tests = [json.loads(line) for line in raw.splitlines()]
        assert not any(item['Action'] in ('fail', 'skip') for item in tests)
        passed = [item['Test'] for item in tests if item['Action'] == 'pass' and 'Test' in item]
        roots = [name for name in passed if '/' not in name]
        assert len(roots) == len(ROOT_TESTS) and set(roots) == ROOT_TESTS
        assert any(item['Action'] == 'pass' and 'Test' not in item for item in tests)
        report['tests'] = {'root_passes': roots, 'subtest_passes': len(passed) - len(roots),
                           'events_sha256': sha(output / 'record-tests.stdout')}
        environment['CGO_ENABLED'] = '0'
        for group in range(1, 6):
            order = ('reference', 'reuse') if group % 2 else ('reuse', 'reference')
            for pipeline in order:
                name = 'g%d-%s' % (group, pipeline)
                expression = '^BenchmarkJournalRecordPreparation$/^(1|128)_events$/^' + pipeline + '$'
                raw = execute(['go', 'test', '-run', '^$', '-bench', expression, '-benchmem',
                               '-benchtime=300ms', '-count=1', './internal/usagebucket'], source, output, name, environment)
                rows = []
                for line in raw.splitlines():
                    match = BENCH.fullmatch(line)
                    if match is None:
                        continue
                    events, actual, gomaxprocs, iterations, nanos, megabytes, allocated, allocations = match.groups()
                    assert actual == pipeline
                    row = {'group': group, 'pipeline': actual, 'events': int(events),
                           'gomaxprocs': int(gomaxprocs), 'iterations': int(iterations),
                           'nanos_per_op': float(nanos), 'encoded_megabytes_per_second': float(megabytes),
                           'allocated_bytes_per_op': int(allocated), 'allocations_per_op': int(allocations),
                           'stdout_sha256': sha(output / (name + '.stdout'))}
                    assert all(math.isfinite(row[k]) and row[k] > 0 for k in
                               ('nanos_per_op', 'encoded_megabytes_per_second', 'iterations', 'gomaxprocs'))
                    rows.append(row)
                assert len(rows) == 2 and {row['events'] for row in rows} == {1, 128}
                report['benchmarks'].extend(rows)
                (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        assert len(report['benchmarks']) == 20
        for events in (1, 128):
            sides = {side: [r for r in report['benchmarks'] if r['pipeline'] == side and r['events'] == events]
                     for side in ('reference', 'reuse')}
            assert all(len(rows) == 5 and {r['group'] for r in rows} == set(range(1, 6)) for rows in sides.values())
            medians = {side: statistics.median(r['nanos_per_op'] for r in rows) for side, rows in sides.items()}
            cv = max(statistics.pstdev(r['nanos_per_op'] for r in rows) / statistics.mean(r['nanos_per_op'] for r in rows)
                     for rows in sides.values())
            report['comparisons'].append({'events': events, 'median_nanos_per_op': medians,
                'reuse_over_reference': medians['reuse'] / medians['reference'], 'max_population_cv': cv,
                'status': 'unresolved-noise' if cv > 0.10 else 'observed',
                'median_allocated_bytes_per_op': {s: statistics.median(r['allocated_bytes_per_op'] for r in rows) for s, rows in sides.items()},
                'median_allocations_per_op': {s: statistics.median(r['allocations_per_op'] for r in rows) for s, rows in sides.items()}})
        assert command(['git', 'status', '--porcelain'], source) == ''
        assert plan['source_sha256'] == {name: sha(source / name) for name in SOURCE_FILES}
        report['collection_complete'] = True
    except Exception as error:
        report['error'] = type(error).__name__ + ': ' + str(error)
        raise
    finally:
        (output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps({'tests': report['tests'], 'comparisons': report['comparisons'],
                      'collection_complete': report['collection_complete'], 'full_S3_accepted': False}), flush=True)


if __name__ == '__main__':
    main()
