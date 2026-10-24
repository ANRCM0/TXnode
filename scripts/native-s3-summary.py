#!/usr/bin/env python3
"""Retain every independent S3 check when another evidence scope is incomplete."""
import argparse
import json
import math
from pathlib import Path
import re

import native_baselines
import native_latency


def valid_cpu(sample):
    cpu = sample['cpu_measurement']
    start, end = cpu['start'], cpu['end']
    method = 'process-cputime-ns-v1'
    fields = ('clock_id', 'pid', 'sequence', 'cpu_nanos', 'resolution_nanos',
              'monotonic_before_nanos', 'monotonic_after_nanos',
              'requested_monotonic_nanos', 'received_monotonic_nanos', 'round_trip_nanos')
    if sample['status'] != 'measured' or sample['cpu_method'] != method or cpu['method'] != method:
        return False
    if type(sample['bytes']) is not int or sample['bytes'] <= 0:
        return False
    if any(type(cpu[field]) is not int for field in ('delta_nanos', 'resolution_nanos', 'monotonic_inner_elapsed_nanos', 'transfer_started_monotonic_nanos', 'transfer_completed_monotonic_nanos')):
        return False
    if any(type(value) not in (int, float) or not math.isfinite(value) or value <= 0 for value in (sample['cpu_seconds_per_gib'], cpu['cpu_seconds_per_gib'])):
        return False
    for number, snapshot in enumerate((start, end), 1):
        if snapshot['schema'] != 'txnode-process-cpu-snapshot/v1' or snapshot['method'] != method:
            return False
        if any(type(snapshot[field]) is not int for field in fields):
            return False
        if snapshot['clock_id'] != 2 or snapshot['pid'] <= 0 or snapshot['sequence'] != number or snapshot['cpu_nanos'] <= 0 or snapshot['resolution_nanos'] <= 0:
            return False
        if not snapshot['requested_monotonic_nanos'] <= snapshot['monotonic_before_nanos'] <= snapshot['monotonic_after_nanos'] <= snapshot['received_monotonic_nanos']:
            return False
        if snapshot['round_trip_nanos'] != snapshot['received_monotonic_nanos'] - snapshot['requested_monotonic_nanos']:
            return False
    nonce = start['nonce']
    if not isinstance(nonce, str) or len(nonce) != 64 or any(c not in '0123456789abcdef' for c in nonce) or nonce != end['nonce'] or start['pid'] != end['pid']:
        return False
    delta = end['cpu_nanos'] - start['cpu_nanos']
    elapsed = end['monotonic_before_nanos'] - start['monotonic_after_nanos']
    if delta <= 0 or elapsed <= 0 or cpu['delta_nanos'] != delta or cpu['monotonic_inner_elapsed_nanos'] != elapsed:
        return False
    if cpu['resolution_nanos'] != start['resolution_nanos'] or start['resolution_nanos'] != end['resolution_nanos']:
        return False
    if not start['monotonic_after_nanos'] <= cpu['transfer_started_monotonic_nanos'] < cpu['transfer_completed_monotonic_nanos'] <= end['monotonic_before_nanos']:
        return False
    expected = delta / 1_000_000_000 / (sample['bytes'] / 1073741824)
    return math.isfinite(expected) and expected > 0 and sample['cpu_seconds_per_gib'] == cpu['cpu_seconds_per_gib'] and math.isclose(sample['cpu_seconds_per_gib'], expected, rel_tol=1e-12)


CHECKS = ('same_candidate', 'baseline_identity', 'sustained_loaded_lifecycle', 'loaded_faults',
          'equivalent_ab', 'process_cpu_windows', 'image_sizes', 'allocation_windows')
EVIDENCE_ERRORS = (OSError, ValueError, KeyError, TypeError, AttributeError,
                   ZeroDivisionError, OverflowError)
SCOPE = ('fixed Linux Actions loopback profile: 30 minute staged TCP/UDP/mux, '
         'load-bearing TLS lifecycle, separate loaded faults, same-runner legacy '
         'sing-box versus native SOCKS A/B; no production or physical multi-host claim')


def summarize(root, candidate, outcomes, baseline_profile=native_baselines.DEFAULT_PROFILE,
              latency_profile=native_latency.OBSERVATIONS, workflow_run='', tool_revision=''):
    baseline = native_baselines.identity(baseline_profile)
    checks = {name: outcomes.get(name) == 'success' for name in ('SOAK', 'FAULTS', 'PERFORMANCE')}
    checks.update(dict.fromkeys(CHECKS, False))
    strict_latency = latency_profile != native_latency.OBSERVATIONS
    if strict_latency:
        checks.update(dict.fromkeys(('latency_evidence', 'latency_windows', 'latency_comparisons'), False))
    errors = {}

    def record(name, operation):
        try:
            return operation()
        except EVIDENCE_ERRORS as error:
            detail = {'error': type(error).__name__}
            if isinstance(error, KeyError):
                detail['field'] = error.args[0]
            errors[name] = detail
            return None

    if isinstance(candidate, str) and re.fullmatch('[0-9a-f]{40}', candidate):
        def read(kind, name):
            label = native_baselines.artifact_label(baseline_profile) if kind == 'performance' else ''
            return json.loads((root / ('native-' + kind + '-' + label + candidate) / name).read_text(encoding='utf-8'))

        soak = record('soak_evidence', lambda: read('soak', 'soak-summary.json'))
        faults = record('faults_evidence', lambda: read('faults', 'summary.json'))
        performance = record('performance_evidence', lambda: read('performance', 'report.json'))

        def baseline_tests():
            directory = root / ('native-baseline-tests-' + native_baselines.artifact_label(baseline_profile) + candidate)
            return (outcomes.get('BASELINE_TESTS') == 'success'
                    and (directory / 'commit.txt').read_text(encoding='utf-8').strip() == baseline['commit']
                    and (directory / 'tree.txt').read_text(encoding='utf-8').strip() == baseline['tree']
                    and (directory / 'candidate.txt').read_text(encoding='utf-8').strip() == candidate)

        predicates = {
            'same_candidate': lambda: performance['candidate'] == candidate and all(
                (root / ('native-' + kind + '-' + candidate) / 'commit.txt').read_text(encoding='utf-8').strip() == candidate
                for kind in ('soak', 'faults')),
            'baseline_identity': lambda: native_baselines.matches_report(performance, baseline_profile),
            'sustained_loaded_lifecycle': lambda: soak['accepted'] and soak['elapsed_seconds'] >= 1800 and len(soak['phases']) == 4 and all(
                p['lifecycle_cycles'] >= 8 and p['load_bearing_generations_recovered'] == p['lifecycle_cycles'] + 1
                and p['expected_retired_disconnects'] == p['lifecycle_cycles'] * p['load_bearing_tls_workers']
                for p in soak['phases']),
            'loaded_faults': lambda: faults['accepted'],
            'equivalent_ab': lambda: performance['accepted'] and len(performance['comparisons']) == 12,
            'process_cpu_windows': lambda: performance['schema'] == 'txnode-native-performance/v2'
                and performance['cpu_method'] == 'process-cputime-ns-v1'
                and len(performance['samples']) >= 120 and all(valid_cpu(sample) for sample in performance['samples']),
            'image_sizes': lambda: all(performance['runtime_images'][side]['uncompressed_bytes'] > 0 for side in ('legacy', 'candidate')),
            'allocation_windows': lambda: len(performance['samples']) >= 120 and all(
                s.get('allocated_bytes_per_business_byte', -1) >= 0 and s.get('allocations_per_business_byte', -1) >= 0
                for s in performance['samples']),
        }
        if baseline_profile == native_baselines.ERRATA_PROFILE:
            predicates['errata_baseline_tests'] = baseline_tests
        # A missing CPU field must not prevent independent image/allocation checks.
        for name in predicates:
            checks[name] = record(name, predicates[name]) is True
        if strict_latency:
            def latency_evidence():
                if latency_profile != native_latency.PROFILE:
                    raise ValueError('unknown prospective latency profile')
                expected = native_latency.identity(candidate, baseline_profile, workflow_run, tool_revision)
                declared = json.loads((root / ('native-source-' + candidate) / 'latency-plan.json').read_text(encoding='utf-8'))
                copied = read('performance', 'latency-plan.json')
                archived = read('performance', 'latency-acceptance.json')
                derived = native_latency.summarize(performance, declared, expected)
                if copied != declared or archived != derived:
                    raise ValueError('latency archive must match its pre-load plan and original report')
                return derived

            latency = record('latency_evidence', latency_evidence)
            if latency is not None:
                checks['latency_evidence'] = latency['checks']['plan_identity'] and latency['checks']['report_identity']
                checks['latency_windows'] = latency['checks']['complete_latency_windows']
                checks['latency_comparisons'] = latency['checks']['latency_comparisons']
    else:
        errors['candidate'] = {'error': 'immutable_candidate_required'}
    checks['evidence_complete'] = not errors
    if errors:
        checks['evidence_error'] = ', '.join(errors)
    result = {'schema': 'txnode-s3-acceptance/v3' if strict_latency else 'txnode-s3-acceptance/v2',
              'candidate': candidate, 'baseline_identity': baseline, 'checks': checks,
              'evidence_errors': errors, 'full_S3_accepted': all(value is True for value in checks.values()),
              'scope': SCOPE}
    if strict_latency:
        result.update(latency_profile=latency_profile, latency_policy_sha256=native_latency.digest(native_latency.POLICY))
        result['scope'] += '; prospectively declared p50/p95/p99 regression budget, no production SLO'
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--candidate', required=True)
    parser.add_argument('--baseline-profile', choices=native_baselines.PROFILES, default=native_baselines.DEFAULT_PROFILE)
    parser.add_argument('--latency-profile', choices=(native_latency.OBSERVATIONS, native_latency.PROFILE), default=native_latency.OBSERVATIONS)
    parser.add_argument('--workflow-run', default='')
    parser.add_argument('--tool-revision', default='')
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--soak-job', required=True)
    parser.add_argument('--faults-job', required=True)
    parser.add_argument('--performance-job', required=True)
    parser.add_argument('--baseline-test-job', default='skipped')
    parser.add_argument('--step-summary', type=Path)
    args = parser.parse_args()
    result = summarize(args.evidence, args.candidate,
                       {'SOAK': args.soak_job, 'FAULTS': args.faults_job, 'PERFORMANCE': args.performance_job,
                        'BASELINE_TESTS': args.baseline_test_job},
                       args.baseline_profile, args.latency_profile, args.workflow_run, args.tool_revision)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    encoded = json.dumps(result, indent=2)
    args.output.write_text(encoded + '\n', encoding='utf-8')
    if args.step_summary is not None:
        with args.step_summary.open('a', encoding='utf-8') as summary:
            summary.write('## Exact source S3 evidence\n\nCandidate: `' + args.candidate
                          + '`\n\n```json\n' + encoded + '\n```\n')
    if not result['full_S3_accepted']:
        raise SystemExit('S3 evidence incomplete, noisy, or outside fixed performance thresholds')


if __name__ == '__main__':
    main()
