"""Prospectively declared latency budgets for the original native A/B workload."""
import argparse
import copy
from datetime import datetime, timezone
import hashlib
import itertools
import json
import math
from pathlib import Path
import re
import statistics
import subprocess

import native_baselines


OBSERVATIONS = 'observations-only'
PROFILE = 'percentiles-5pct-v1'
POLICY = {'schema': 'txnode-native-latency-policy/v1', 'profile': PROFILE,
          'percentiles': ['50', '95', '99'], 'groups': 5,
          'candidate_over_legacy_ceiling': 1.05, 'population_cv_ceiling': 0.10,
          'aggregation': 'ratio of side medians across five groups',
          'sampling': 'bounded deterministic sample per worker'}
MODES = ('ordinary', 'usage_v2', 'events')
WORKLOADS = ('upload', 'download', 'short', 'long')
ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError, ZeroDivisionError, OverflowError)


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':'),
                                    allow_nan=False).encode()).hexdigest()


def identity(candidate, baseline_profile, workflow_run, tool_revision, root=native_baselines.ROOT):
    if (not isinstance(candidate, str) or not re.fullmatch('[0-9a-f]{40}', candidate)
            or tool_revision != candidate or not re.fullmatch('[1-9][0-9]*', str(workflow_run))):
        raise ValueError('prospective latency needs the workflow commit and a specific run')
    def git(*args):
        try:
            return subprocess.check_output(['git', *args], cwd=root)
        except subprocess.SubprocessError as error:
            raise ValueError('committed latency source could not be verified') from error

    head = git('rev-parse', 'HEAD').decode().strip()
    if head != candidate:
        raise ValueError('prospective latency tool and candidate must be the same immutable source')
    hashes = {}
    for name in ('native-acceptance.py', 'native_latency.py'):
        path = 'scripts/' + name
        data = (root / path).read_bytes()
        if data != git('show', candidate + ':' + path):
            raise ValueError('latency and measurement tools must match their committed source bytes')
        hashes[name] = hashlib.sha256(data).hexdigest()
    return {'candidate': candidate,
            'candidate_tree': git('rev-parse', 'HEAD^{tree}').decode().strip(),
            'baseline_identity': native_baselines.identity(baseline_profile),
            'workflow_run': str(workflow_run), 'tool_revision': tool_revision,
            'measurement_tool_sha256': hashes['native-acceptance.py'],
            'latency_tool_sha256': hashes['native_latency.py']}


def plan(expected):
    return {'schema': 'txnode-native-latency-plan/v1', 'identity': copy.deepcopy(expected),
            'policy': copy.deepcopy(POLICY), 'policy_sha256': digest(POLICY),
            'created_at_utc': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')}


def validate_plan(value, expected):
    if (not isinstance(value, dict) or set(value) != {'schema', 'identity', 'policy', 'policy_sha256', 'created_at_utc'}
            or value['schema'] != 'txnode-native-latency-plan/v1'
            or value['identity'] != expected or value['policy'] != POLICY or value['policy_sha256'] != digest(POLICY)):
        raise ValueError('latency plan identity or immutable budget mismatch')
    stamp = value['created_at_utc']
    if not isinstance(stamp, str) or not stamp.endswith('Z'):
        raise ValueError('latency plan needs a UTC creation time')
    if datetime.fromisoformat(stamp.replace('Z', '+00:00')) > datetime.now(timezone.utc):
        raise ValueError('latency plan creation time is in the future')
    return True


def valid_sample(sample):
    if (sample['status'] != 'measured' or sample['persistence_diagnostics'] is not False
            or sample['latency_method'] != POLICY['sampling']
            or type(sample['operations']) is not int or sample['operations'] <= 0
            or type(sample['latency_sample_count']) is not int
            or not 0 < sample['latency_sample_count'] <= min(sample['operations'], 80000)
            or set(sample['latency_ms']) != set(POLICY['percentiles'])):
        return False
    values = [sample['latency_ms'][p] for p in POLICY['percentiles']]
    return (all(type(v) in (int, float) and math.isfinite(v) and v > 0 for v in values)
            and values == sorted(values))


def comparisons(samples):
    result = []
    for mode, workload in itertools.product(MODES, WORKLOADS):
        row = {'mode': mode, 'workload': workload, 'status': 'incomplete', 'percentiles': []}
        try:
            sides = {side: [s for s in samples if s['mode'] == mode and s['workload'] == workload and s['side'] == side]
                     for side in ('legacy', 'candidate')}
            if any(len(rows) != 5 or {s['group'] for s in rows} != set(range(1, 6))
                   or not all(valid_sample(s) for s in rows) for rows in sides.values()):
                raise ValueError('five valid fresh latency windows are required on each side')
            for percentile in POLICY['percentiles']:
                values = {side: [s['latency_ms'][percentile] for s in rows] for side, rows in sides.items()}
                medians = {side: statistics.median(v) for side, v in values.items()}
                ratio = medians['candidate'] / medians['legacy']
                noise = max(statistics.pstdev(v) / statistics.mean(v) for v in values.values())
                status = ('unresolved' if noise > POLICY['population_cv_ceiling'] else
                          'investigate' if ratio > POLICY['candidate_over_legacy_ceiling'] else
                          'within-initial-thresholds')
                row['percentiles'].append({'percentile': percentile, 'median_ms': medians,
                                           'candidate_over_legacy': ratio, 'max_population_cv': noise,
                                           'status': status})
            statuses = {p['status'] for p in row['percentiles']}
            row['status'] = ('unresolved' if 'unresolved' in statuses else
                             'investigate' if 'investigate' in statuses else 'within-initial-thresholds')
        except ERRORS as error:
            row['error'] = type(error).__name__
        result.append(row)
    return result


def summarize(report, declared, expected):
    checks = dict.fromkeys(('plan_identity', 'report_identity', 'complete_latency_windows', 'latency_comparisons'), False)
    errors = {}

    def check(name, operation):
        try:
            return operation()
        except ERRORS as error:
            errors[name] = {'error': type(error).__name__}
            return None

    checks['plan_identity'] = check('plan_identity', lambda: validate_plan(declared, expected)) is True

    def report_identity():
        fixed = {'groups': 5, 'sample_seconds': 10, 'warmup_seconds': 2, 'concurrency': 4,
                 'buffer_bytes': 32768, 'short_buffer_bytes': 1024, 'throughput_floor': 0.95,
                 'cpu_ceiling': 1.05, 'noise_cv_ceiling': 0.10, 'event_store_max_bytes': 1 << 30,
                 'usage_lease_seconds': 90, 'persistence_diagnostics': 'disabled'}
        baseline = expected['baseline_identity']
        return (report['schema'] == 'txnode-native-performance/v2'
                and report['cpu_method'] == 'process-cputime-ns-v1'
                and report['candidate'] == expected['candidate'] and report['candidate_tree'] == expected['candidate_tree']
                and report['tool_sha256'] == expected['measurement_tool_sha256']
                and report['builds']['candidate']['status'] == 'built'
                and report['builds']['candidate']['sha'] == expected['candidate']
                and report['go'] == 'go version go1.26.0 linux/amd64'
                and report['go_environment'].splitlines() == ['linux', 'amd64', 'local', '0']
                and native_baselines.matches_report(report, baseline['profile'])
                and all(type(report['settings'][k]) is type(v) and report['settings'][k] == v for k, v in fixed.items()))

    checks['report_identity'] = check('report_identity', report_identity) is True

    def windows():
        samples = report['samples']
        cells = set(itertools.product(range(1, 6), MODES, WORKLOADS, ('legacy', 'candidate')))
        return (len(samples) == 120 and all(type(s['group']) is int and valid_sample(s) for s in samples)
                and {(s['group'], s['mode'], s['workload'], s['side']) for s in samples} == cells)

    checks['complete_latency_windows'] = check('complete_latency_windows', windows) is True
    compared = check('latency_comparisons', lambda: comparisons(report['samples'])) or []
    checks['latency_comparisons'] = len(compared) == 12 and all(c['status'] == 'within-initial-thresholds' for c in compared)
    return {'schema': 'txnode-native-latency-acceptance/v1', 'identity': copy.deepcopy(expected),
            'policy': copy.deepcopy(POLICY), 'policy_sha256': digest(POLICY),
            'plan_sha256': check('plan_hash', lambda: digest(declared)),
            'report_sha256': check('report_hash', lambda: digest(report)),
            'checks': checks, 'errors': errors, 'comparisons': compared,
            'accepted': all(checks.values()) and not errors,
            'scope': 'fixed Actions SOCKS A/B latency percentiles; prospective plan, bounded client samples, no production SLO'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=('plan', 'validate-plan', 'summarize'))
    parser.add_argument('--profile', choices=(PROFILE,), required=True)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--baseline-profile', choices=native_baselines.PROFILES, required=True)
    parser.add_argument('--workflow-run', required=True)
    parser.add_argument('--tool-revision', required=True)
    parser.add_argument('--plan', type=Path)
    parser.add_argument('--report', type=Path)
    parser.add_argument('--output', type=Path)
    parser.add_argument('--step-summary', type=Path)
    args = parser.parse_args()
    expected = identity(args.candidate, args.baseline_profile, args.workflow_run, args.tool_revision)
    if args.operation == 'plan':
        if args.output is None:
            parser.error('plan needs --output')
        value = plan(expected)
    elif args.operation == 'validate-plan':
        validate_plan(json.loads(args.plan.read_text(encoding='utf-8')), expected)
        return
    else:
        if args.output is None:
            parser.error('summarize needs --output')
        failures = {}

        def load(path, name):
            try:
                return json.loads(path.read_text(encoding='utf-8'))
            except ERRORS as error:
                failures[name] = {'error': type(error).__name__}
                return None

        value = summarize(load(args.report, 'report_input'), load(args.plan, 'plan_input'), expected)
        value['errors'].update(failures)
        value['accepted'] = value['accepted'] and not failures
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(value, indent=2, allow_nan=False)
    args.output.write_text(encoded + '\n', encoding='utf-8')
    if args.step_summary:
        with args.step_summary.open('a', encoding='utf-8') as output:
            output.write('## Prospective latency budget\n\n```json\n' + encoded + '\n```\n')
    if args.operation == 'summarize' and not value['accepted']:
        raise SystemExit('Latency evidence incomplete, noisy, or outside its prospectively declared budget')


if __name__ == '__main__':
    main()
