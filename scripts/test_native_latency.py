import copy
from datetime import datetime, timedelta, timezone
import itertools
import json
from pathlib import Path
import sys
import subprocess
import tempfile
import unittest
from unittest import mock

import native_baselines
import native_latency as latency


def expected_identity():
    return {'candidate': '1' * 40, 'candidate_tree': '2' * 40,
            'baseline_identity': native_baselines.identity(native_baselines.ERRATA_PROFILE),
            'workflow_run': '17', 'tool_revision': '1' * 40,
            'measurement_tool_sha256': '3' * 64, 'latency_tool_sha256': '4' * 64}


def complete_report():
    identity = expected_identity()
    baseline = identity['baseline_identity']
    return {'schema': 'txnode-native-performance/v2', 'cpu_method': 'process-cputime-ns-v1',
            'candidate': identity['candidate'], 'candidate_tree': identity['candidate_tree'],
            'baseline': baseline['commit'], 'baseline_tree': baseline['tree'], 'baseline_identity': baseline,
            'builds': {'legacy': {'sha': baseline['commit'], 'status': 'built'},
                       'candidate': {'sha': identity['candidate'], 'status': 'built'}},
            'tool_sha256': identity['measurement_tool_sha256'], 'go': 'go version go1.26.0 linux/amd64',
            'go_environment': 'linux\namd64\nlocal\n0',
            'settings': {'groups': 5, 'sample_seconds': 10, 'warmup_seconds': 2, 'concurrency': 4,
                         'buffer_bytes': 32768, 'short_buffer_bytes': 1024, 'throughput_floor': 0.95,
                         'cpu_ceiling': 1.05, 'noise_cv_ceiling': 0.10, 'event_store_max_bytes': 1 << 30,
                         'usage_lease_seconds': 90, 'persistence_diagnostics': 'disabled'},
            'samples': [{'group': group, 'mode': mode, 'workload': workload, 'side': side,
                         'status': 'measured', 'persistence_diagnostics': False, 'operations': 100000,
                         'latency_sample_count': 80000, 'latency_method': 'bounded deterministic sample per worker',
                         'latency_ms': {'50': 1.0, '95': 2.0, '99': 3.0}}
                        for group, mode, workload, side in itertools.product(range(1, 6), latency.MODES,
                                                                          latency.WORKLOADS, ('legacy', 'candidate'))]}


class ProspectiveLatencyTests(unittest.TestCase):
    def setUp(self):
        self.expected = expected_identity()
        self.plan = latency.plan(self.expected)
        self.report = complete_report()

    def summarize(self):
        return latency.summarize(self.report, self.plan, self.expected)

    def test_complete_five_group_matrix_and_exact_ceiling_are_accepted(self):
        for sample in self.report['samples']:
            if sample['side'] == 'candidate':
                sample['latency_ms']['50'] = 1.05
        result = self.summarize()
        self.assertTrue(result['accepted'])
        self.assertEqual(len(result['comparisons']), 12)
        self.assertEqual(sum(len(c['percentiles']) for c in result['comparisons']), 36)
        self.assertTrue(all(v is True for v in result['checks'].values()))
        self.assertEqual(result['errors'], {})

    def test_stable_percentile_regression_cannot_hide_in_other_percentiles(self):
        for sample in self.report['samples']:
            if (sample['mode'], sample['workload'], sample['side']) == ('events', 'download', 'candidate'):
                sample['latency_ms']['99'] = 3.18
        result = self.summarize()
        row = next(c for c in result['comparisons'] if (c['mode'], c['workload']) == ('events', 'download'))
        self.assertFalse(result['accepted'])
        self.assertEqual(row['status'], 'investigate')
        self.assertEqual(row['percentiles'][2]['candidate_over_legacy'], 1.06)
        self.assertEqual(row['percentiles'][2]['max_population_cv'], 0)

    def test_noisy_windows_remain_unresolved_even_when_the_medians_match(self):
        for sample in self.report['samples']:
            if (sample['mode'], sample['workload']) == ('ordinary', 'long'):
                sample['latency_ms']['99'] = 10.0
                if sample['side'] == 'candidate' and sample['group'] in (2, 4):
                    sample['latency_ms']['95'] = 3.0
        row = next(c for c in self.summarize()['comparisons'] if (c['mode'], c['workload']) == ('ordinary', 'long'))
        self.assertEqual(row['status'], 'unresolved')
        self.assertEqual(row['percentiles'][1]['candidate_over_legacy'], 1.0)
        self.assertGreater(row['percentiles'][1]['max_population_cv'], 0.10)
        self.assertFalse(self.summarize()['accepted'])

    def test_missing_duplicate_or_failed_sample_never_becomes_a_complete_matrix(self):
        original = copy.deepcopy(self.report)
        for mutation in (lambda rows: rows.pop(), lambda rows: rows.__setitem__(0, copy.deepcopy(rows[1])),
                         lambda rows: rows[0].update(status='incomplete'), lambda rows: rows[0].update(group=True)):
            with self.subTest(mutation=mutation):
                self.report = copy.deepcopy(original)
                mutation(self.report['samples'])
                result = self.summarize()
                self.assertFalse(result['accepted'])
                self.assertFalse(result['checks']['complete_latency_windows'])
                self.assertEqual(len(result['comparisons']), 12)

    def test_invalid_latency_numbers_order_method_or_sample_counts_are_rejected(self):
        original = copy.deepcopy(self.report['samples'][0])
        mutations = [lambda s: s['latency_ms'].update({'50': True}),
                     lambda s: s['latency_ms'].update({'95': float('nan')}),
                     lambda s: s['latency_ms'].update({'99': float('inf')}),
                     lambda s: s['latency_ms'].update({'50': 0}),
                     lambda s: s['latency_ms'].update({'50': 4}),
                     lambda s: s['latency_ms'].pop('99'),
                     lambda s: s.update(latency_method='all operations'),
                     lambda s: s.update(latency_sample_count=True),
                     lambda s: s.update(latency_sample_count=100001),
                     lambda s: s.update(latency_sample_count=80001),
                     lambda s: s.update(persistence_diagnostics=True)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.report['samples'][0] = copy.deepcopy(original)
                mutation(self.report['samples'][0])
                self.assertFalse(self.summarize()['accepted'])
                self.assertFalse(self.summarize()['checks']['complete_latency_windows'])

    def test_plan_cannot_exchange_run_source_tool_baseline_or_budget(self):
        original = copy.deepcopy(self.plan)
        mutations = [lambda p: p['identity'].update(workflow_run='18'),
                     lambda p: p['identity'].update(candidate='5' * 40),
                     lambda p: p['identity'].update(candidate_tree='6' * 40),
                     lambda p: p['identity'].update(tool_revision='7' * 40),
                     lambda p: p['identity'].update(measurement_tool_sha256='8' * 64),
                     lambda p: p['identity'].update(latency_tool_sha256='9' * 64),
                     lambda p: p['identity'].update(baseline_identity=native_baselines.identity()),
                     lambda p: p['policy'].update(candidate_over_legacy_ceiling=1.10),
                     lambda p: p['policy'].update(population_cv_ceiling=0.20),
                     lambda p: p.update(policy_sha256='0' * 64),
                     lambda p: p.update(created_at_utc='2026-10-25'),
                     lambda p: p.update(created_at_utc=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat().replace('+00:00', 'Z')),
                     lambda p: p.update(unregistered_budget=True)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.plan = copy.deepcopy(original)
                mutation(self.plan)
                result = self.summarize()
                self.assertFalse(result['accepted'])
                self.assertFalse(result['checks']['plan_identity'])

    def test_other_toolchain_sampling_or_candidate_build_is_not_comparable(self):
        original = copy.deepcopy(self.report)
        mutations = [lambda r: r.update(candidate='9' * 40), lambda r: r.update(candidate_tree='8' * 40),
                     lambda r: r.update(tool_sha256='7' * 64), lambda r: r.update(go='go version go1.26.3 linux/amd64'),
                     lambda r: r.update(go_environment='linux\namd64\nauto\n1'),
                     lambda r: r['settings'].update(groups=True), lambda r: r['settings'].update(sample_seconds=55),
                     lambda r: r['settings'].update(event_store_max_bytes=1 << 31),
                     lambda r: r['builds']['candidate'].update(sha='6' * 40),
                     lambda r: r['builds']['legacy'].update(sha=native_baselines.ORIGINAL)]
        for mutation in mutations:
            with self.subTest(mutation=mutation):
                self.report = copy.deepcopy(original)
                mutation(self.report)
                self.assertFalse(self.summarize()['accepted'])
                self.assertFalse(self.summarize()['checks']['report_identity'])

    def test_missing_evidence_still_reports_all_independent_checks(self):
        for report, declared in ((None, self.plan), (self.report, None), ({}, {})):
            with self.subTest(report=report is None, declared=declared is None):
                result = latency.summarize(report, declared, self.expected)
                self.assertFalse(result['accepted'])
                self.assertEqual(set(result['checks']), {'plan_identity', 'report_identity', 'complete_latency_windows', 'latency_comparisons'})
                self.assertTrue(all(type(v) is bool for v in result['checks'].values()))
                json.dumps(result, allow_nan=False)

    def test_cli_retains_input_failure_before_nonzero_exit(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            argv = ['native_latency.py', 'summarize', '--profile', latency.PROFILE,
                    '--candidate', self.expected['candidate'], '--baseline-profile', native_baselines.ERRATA_PROFILE,
                    '--workflow-run', '17', '--tool-revision', self.expected['tool_revision'],
                    '--plan', str(root / 'missing-plan'), '--report', str(root / 'missing-report'),
                    '--output', str(root / 'result.json')]
            with mock.patch.object(sys, 'argv', argv), mock.patch.object(latency, 'identity', return_value=self.expected):
                with self.assertRaises(SystemExit):
                    latency.main()
            result = json.loads((root / 'result.json').read_text())
            self.assertFalse(result['accepted'])
            self.assertEqual(result['errors']['report_input']['error'], 'FileNotFoundError')
            self.assertEqual(result['errors']['plan_input']['error'], 'FileNotFoundError')

    def test_source_identity_rejects_another_head_or_unreadable_commit_before_load(self):
        arguments = (self.expected['candidate'], native_baselines.ERRATA_PROFILE, '17', self.expected['tool_revision'])
        with mock.patch.object(latency.subprocess, 'check_output', return_value=('9' * 40).encode()):
            with self.assertRaises(ValueError):
                latency.identity(*arguments)
        with mock.patch.object(latency.subprocess, 'check_output', side_effect=subprocess.CalledProcessError(1, 'git')):
            with self.assertRaises(ValueError):
                latency.identity(*arguments)
        for run, tool in (('0', arguments[3]), ('017', arguments[3]), ('17', '9' * 40)):
            with self.subTest(run=run, tool=tool), mock.patch.object(latency.subprocess, 'check_output') as git:
                with self.assertRaises(ValueError):
                    latency.identity(arguments[0], arguments[1], run, tool)
                git.assert_not_called()


if __name__ == '__main__':
    unittest.main()
