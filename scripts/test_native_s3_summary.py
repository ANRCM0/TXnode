"""Incomplete S3 scopes must remain rejecting and independently observable."""
import copy
import importlib.util
import itertools
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


SPEC = importlib.util.spec_from_file_location('native_s3_summary', Path(__file__).with_name('native-s3-summary.py'))
SUMMARY = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(SUMMARY)
CANDIDATE = 'a' * 40
SUCCESS = dict.fromkeys(('SOAK', 'FAULTS', 'PERFORMANCE'), 'success')


def sample(number):
    start = {'schema': 'txnode-process-cpu-snapshot/v1', 'method': 'process-cputime-ns-v1',
             'clock_id': 2, 'pid': 1234, 'sequence': 1, 'nonce': '%064x' % number,
             'cpu_nanos': 1_000_000_000, 'resolution_nanos': 1,
             'requested_monotonic_nanos': 10_000_000_000, 'monotonic_before_nanos': 10_001_000_000,
             'monotonic_after_nanos': 10_002_000_000, 'received_monotonic_nanos': 10_003_000_000,
             'round_trip_nanos': 3_000_000}
    end = dict(start, sequence=2, cpu_nanos=2_000_000_000,
               requested_monotonic_nanos=12_000_000_000, monotonic_before_nanos=12_001_000_000,
               monotonic_after_nanos=12_002_000_000, received_monotonic_nanos=12_003_000_000)
    cpu = {'method': 'process-cputime-ns-v1', 'start': start, 'end': end, 'delta_nanos': 1_000_000_000,
           'resolution_nanos': 1, 'monotonic_inner_elapsed_nanos': 1_999_000_000,
           'transfer_started_monotonic_nanos': 10_003_000_000,
           'transfer_completed_monotonic_nanos': 12_000_000_000, 'cpu_seconds_per_gib': 1.0}
    return {'status': 'measured', 'bytes': 1_073_741_824, 'cpu_method': 'process-cputime-ns-v1',
            'cpu_measurement': cpu, 'cpu_seconds_per_gib': 1.0,
            'allocated_bytes_per_business_byte': 0.5, 'allocations_per_business_byte': 0.1}


class S3SummaryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.profile = SUMMARY.native_baselines.DEFAULT_PROFILE
        self.baseline = SUMMARY.native_baselines.identity(self.profile)
        self.soak = {'accepted': True, 'elapsed_seconds': 1801,
                     'phases': [{'lifecycle_cycles': 8, 'load_bearing_generations_recovered': 9,
                                 'load_bearing_tls_workers': 12, 'expected_retired_disconnects': 96}
                                for _ in range(4)]}
        self.faults = {'accepted': True}
        self.performance = {'candidate': CANDIDATE, 'accepted': True,
                            'baseline': self.baseline['commit'], 'baseline_tree': self.baseline['tree'],
                            'builds': {'legacy': {'sha': self.baseline['commit'], 'status': 'built'}},
                            'schema': 'txnode-native-performance/v2', 'cpu_method': 'process-cputime-ns-v1',
                            'comparisons': [{'status': 'within-initial-thresholds'} for _ in range(12)],
                            'runtime_images': {side: {'uncompressed_bytes': 1000} for side in ('legacy', 'candidate')}}
        samples = []
        cells = itertools.product(range(1, 6), ('ordinary', 'usage_v2', 'events'),
                                  ('upload', 'download', 'short', 'long'), ('legacy', 'candidate'))
        for number, (group, mode, workload, side) in enumerate(cells, 1):
            samples.append(dict(sample(number), group=group, mode=mode, workload=workload, side=side))
        self.performance['samples'] = samples

    def write(self):
        for kind, name, document in [('soak', 'soak-summary.json', self.soak),
                                      ('faults', 'summary.json', self.faults),
                                      ('performance', 'report.json', self.performance)]:
            label = SUMMARY.native_baselines.artifact_label(self.profile) if kind == 'performance' else ''
            directory = self.root / ('native-' + kind + '-' + label + CANDIDATE)
            directory.mkdir(exist_ok=True)
            (directory / name).write_text(json.dumps(document), encoding='utf-8')
            (directory / 'commit.txt').write_text(CANDIDATE, encoding='utf-8')

    def summarize(self, outcomes=SUCCESS):
        self.write()
        return SUMMARY.summarize(self.root, CANDIDATE, outcomes, self.profile)

    def test_errata_requires_its_own_identity_and_exact_baseline_test_evidence(self):
        self.profile = SUMMARY.native_baselines.ERRATA_PROFILE
        self.baseline = SUMMARY.native_baselines.identity(self.profile)
        self.performance.update(baseline=self.baseline['commit'], baseline_tree=self.baseline['tree'],
                                baseline_identity=self.baseline)
        self.performance['builds']['legacy']['sha'] = self.baseline['commit']
        directory = self.root / ('native-baseline-tests-' + SUMMARY.native_baselines.artifact_label(self.profile) + CANDIDATE)
        directory.mkdir()
        for name, value in [('commit.txt', self.baseline['commit']), ('tree.txt', self.baseline['tree']),
                            ('candidate.txt', CANDIDATE)]:
            (directory / name).write_text(value, encoding='utf-8')
        success = dict(SUCCESS, BASELINE_TESTS='success')
        result = self.summarize(success)
        self.assertTrue(result['full_S3_accepted'])
        self.assertEqual(result['baseline_identity'], self.baseline)
        for outcome in ('skipped', 'failure', ''):
            with self.subTest(outcome=outcome):
                self.assertFalse(self.summarize(dict(success, BASELINE_TESTS=outcome))['checks']['errata_baseline_tests'])
        for name in ('commit.txt', 'tree.txt', 'candidate.txt'):
            original = (directory / name).read_text(encoding='utf-8')
            (directory / name).write_text('b' * 40, encoding='utf-8')
            self.assertFalse(self.summarize(success)['checks']['errata_baseline_tests'])
            (directory / name).write_text(original, encoding='utf-8')
        del self.performance['baseline_identity']
        self.assertFalse(self.summarize(success)['checks']['baseline_identity'])
        self.performance['baseline_identity'] = self.baseline
        self.performance['builds']['legacy']['sha'] = SUMMARY.native_baselines.ORIGINAL
        self.assertFalse(self.summarize(success)['checks']['baseline_identity'])
        self.performance['builds']['legacy']['sha'] = self.baseline['commit']
        self.performance['baseline'] = SUMMARY.native_baselines.ORIGINAL
        self.assertFalse(self.summarize(success)['checks']['baseline_identity'])

    def test_mismatched_original_baseline_cannot_satisfy_the_default_gate(self):
        self.performance['baseline'] = SUMMARY.native_baselines.ERRATA
        result = self.summarize()
        self.assertFalse(result['full_S3_accepted'])
        self.assertFalse(result['checks']['baseline_identity'])
        self.assertTrue(result['checks']['image_sizes'])

    def test_complete_valid_scopes_and_successful_jobs_are_required(self):
        result = self.summarize()
        self.assertTrue(result['full_S3_accepted'])
        self.assertTrue(all(value is True for value in result['checks'].values()))
        self.assertEqual(result['evidence_errors'], {})
        for outcome in ('failure', 'cancelled', 'skipped', ''):
            with self.subTest(outcome=outcome):
                result = self.summarize(dict(SUCCESS, PERFORMANCE=outcome))
                self.assertFalse(result['full_S3_accepted'])
                self.assertFalse(result['checks']['PERFORMANCE'])
                self.assertTrue(result['checks']['image_sizes'])

    def test_missing_cpu_on_failed_sample_does_not_hide_image_or_allocation_checks(self):
        self.performance['accepted'] = False
        self.performance['samples'][0] = {'status': 'incomplete', 'side': 'legacy'}
        result = self.summarize(dict(SUCCESS, PERFORMANCE='failure'))
        self.assertFalse(result['full_S3_accepted'])
        self.assertFalse(result['checks']['process_cpu_windows'])
        self.assertFalse(result['checks']['allocation_windows'])
        self.assertTrue(result['checks']['image_sizes'])
        self.assertFalse(result['checks']['evidence_complete'])
        self.assertEqual(result['evidence_errors']['process_cpu_windows'],
                         {'error': 'KeyError', 'field': 'cpu_measurement'})
        self.assertTrue(set(SUMMARY.CHECKS) <= set(result['checks']))

    def test_missing_images_do_not_hide_valid_cpu_and_allocations(self):
        del self.performance['runtime_images']
        result = self.summarize()
        self.assertFalse(result['full_S3_accepted'])
        self.assertFalse(result['checks']['image_sizes'])
        self.assertTrue(result['checks']['process_cpu_windows'])
        self.assertTrue(result['checks']['allocation_windows'])
        self.assertEqual(result['evidence_errors']['image_sizes']['field'], 'runtime_images')

    def test_missing_and_malformed_inputs_still_report_every_scope(self):
        for contents in (None, '{', 'null', '[]'):
            with self.subTest(contents=contents):
                self.write()
                path = self.root / ('native-soak-' + CANDIDATE) / 'soak-summary.json'
                if contents is None:
                    path.unlink()
                else:
                    path.write_text(contents, encoding='utf-8')
                result = SUMMARY.summarize(self.root, CANDIDATE, SUCCESS)
                self.assertFalse(result['full_S3_accepted'])
                self.assertFalse(result['checks']['sustained_loaded_lifecycle'])
                self.assertTrue(result['checks']['loaded_faults'])
                self.assertTrue(result['checks']['process_cpu_windows'])
                self.assertTrue(result['checks']['image_sizes'])
                self.assertTrue(result['checks']['allocation_windows'])
                self.assertTrue(set(SUMMARY.CHECKS) <= set(result['checks']))

    def test_source_mismatch_and_invalid_windows_remain_rejected(self):
        self.write()
        (self.root / ('native-faults-' + CANDIDATE) / 'commit.txt').write_text('b' * 40, encoding='utf-8')
        self.assertFalse(SUMMARY.summarize(self.root, CANDIDATE, SUCCESS)['checks']['same_candidate'])
        original = copy.deepcopy(self.performance['samples'][0])
        for field, value in (('delta_nanos', 0), ('cpu_seconds_per_gib', float('nan')),
                             ('transfer_started_monotonic_nanos', True)):
            with self.subTest(field=field):
                self.performance['samples'][0] = copy.deepcopy(original)
                self.performance['samples'][0]['cpu_measurement'][field] = value
                result = self.summarize()
                self.assertFalse(result['full_S3_accepted'])
                self.assertFalse(result['checks']['process_cpu_windows'])
                self.assertTrue(result['checks']['image_sizes'])

    def test_invalid_candidate_is_rejecting_without_reading_evidence_paths(self):
        for candidate in ('', '../outside', 'main'):
            with self.subTest(candidate=candidate):
                result = SUMMARY.summarize(self.root, candidate, SUCCESS)
                self.assertFalse(result['full_S3_accepted'])
                self.assertFalse(result['checks']['same_candidate'])
                self.assertEqual(result['evidence_errors']['candidate']['error'], 'immutable_candidate_required')

    def test_cli_writes_full_rejection_before_its_nonzero_exit(self):
        self.performance['samples'][0].pop('cpu_measurement')
        self.write()
        output, markdown = self.root / 'result.json', self.root / 'summary.md'
        arguments = ['native-s3-summary.py', '--candidate', CANDIDATE, '--evidence', str(self.root),
                     '--output', str(output), '--soak-job', 'success', '--faults-job', 'success',
                     '--performance-job', 'failure', '--step-summary', str(markdown)]
        with patch('sys.argv', arguments), self.assertRaises(SystemExit):
            SUMMARY.main()
        result = json.loads(output.read_text(encoding='utf-8'))
        self.assertFalse(result['full_S3_accepted'])
        self.assertFalse(result['checks']['process_cpu_windows'])
        self.assertTrue(result['checks']['image_sizes'])
        self.assertTrue(result['checks']['allocation_windows'])
        self.assertIn('Exact source S3 evidence', markdown.read_text(encoding='utf-8'))

    def enable_latency(self):
        self.expected = {'candidate': CANDIDATE, 'candidate_tree': 'b' * 40, 'baseline_identity': self.baseline,
                         'workflow_run': '17', 'tool_revision': CANDIDATE,
                         'measurement_tool_sha256': 'c' * 64, 'latency_tool_sha256': 'd' * 64}
        self.performance.update(candidate_tree=self.expected['candidate_tree'], baseline_identity=self.baseline,
                                tool_sha256=self.expected['measurement_tool_sha256'],
                                go='go version go1.26.0 linux/amd64', go_environment='linux\namd64\nlocal\n0',
                                settings={'groups': 5, 'sample_seconds': 10, 'warmup_seconds': 2, 'concurrency': 4,
                                          'buffer_bytes': 32768, 'short_buffer_bytes': 1024,
                                          'throughput_floor': 0.95, 'cpu_ceiling': 1.05, 'noise_cv_ceiling': 0.10,
                                          'event_store_max_bytes': 1 << 30, 'usage_lease_seconds': 90,
                                          'persistence_diagnostics': 'disabled'})
        self.performance['builds']['candidate'] = {'sha': CANDIDATE, 'status': 'built'}
        for item in self.performance['samples']:
            item.update(persistence_diagnostics=False, operations=100000, latency_sample_count=80000,
                        latency_method='bounded deterministic sample per worker',
                        latency_ms={'50': 1.0, '95': 2.0, '99': 3.0})
        self.declared = SUMMARY.native_latency.plan(self.expected)

    def write_latency(self):
        self.write()
        self.source_plan = self.root / ('native-source-' + CANDIDATE) / 'latency-plan.json'
        self.source_plan.parent.mkdir(exist_ok=True)
        self.source_plan.write_text(json.dumps(self.declared), encoding='utf-8')
        directory = self.root / ('native-performance-' + SUMMARY.native_baselines.artifact_label(self.profile) + CANDIDATE)
        self.copied_plan = directory / 'latency-plan.json'
        self.copied_plan.write_text(json.dumps(self.declared), encoding='utf-8')
        self.latency_archive = directory / 'latency-acceptance.json'
        value = SUMMARY.native_latency.summarize(self.performance, self.declared, self.expected)
        self.latency_archive.write_text(json.dumps(value), encoding='utf-8')

    def strict_summary(self):
        with patch.object(SUMMARY.native_latency, 'identity', return_value=self.expected):
            return SUMMARY.summarize(self.root, CANDIDATE, SUCCESS, self.profile,
                                     SUMMARY.native_latency.PROFILE, '17', CANDIDATE)

    def test_prospective_latency_is_an_explicit_v3_scope_and_does_not_rewrite_v2(self):
        self.enable_latency()
        self.write_latency()
        result = self.strict_summary()
        self.assertTrue(result['full_S3_accepted'])
        self.assertEqual(result['schema'], 'txnode-s3-acceptance/v3')
        self.assertEqual(result['latency_profile'], 'percentiles-5pct-v1')
        self.assertTrue(all(result['checks'][name] for name in ('latency_evidence', 'latency_windows', 'latency_comparisons')))
        prior = SUMMARY.summarize(self.root, CANDIDATE, SUCCESS, self.profile)
        self.assertTrue(prior['full_S3_accepted'])
        self.assertEqual(prior['schema'], 'txnode-s3-acceptance/v2')
        self.assertNotIn('latency_profile', prior)

    def test_stable_latency_failure_cannot_be_waived_by_successful_cpu_and_jobs(self):
        self.enable_latency()
        for item in self.performance['samples']:
            if (item['mode'], item['workload'], item['side']) == ('events', 'download', 'candidate'):
                item['latency_ms']['99'] = 3.18
        self.write_latency()
        result = self.strict_summary()
        self.assertFalse(result['full_S3_accepted'])
        self.assertTrue(result['checks']['latency_evidence'])
        self.assertTrue(result['checks']['latency_windows'])
        self.assertFalse(result['checks']['latency_comparisons'])
        self.assertTrue(all(result['checks'][name] for name in ('PERFORMANCE', 'equivalent_ab', 'process_cpu_windows', 'image_sizes')))

    def test_missing_or_forged_latency_archive_does_not_hide_original_checks(self):
        self.enable_latency()
        for change in ('remove', 'accepted', 'budget', 'run'):
            with self.subTest(change=change):
                self.write_latency()
                if change == 'remove':
                    self.latency_archive.unlink()
                elif change == 'accepted':
                    value = json.loads(self.latency_archive.read_text())
                    value['accepted'] = False
                    self.latency_archive.write_text(json.dumps(value), encoding='utf-8')
                else:
                    value = json.loads(self.copied_plan.read_text())
                    if change == 'budget':
                        value['policy']['candidate_over_legacy_ceiling'] = 1.10
                    else:
                        value['identity']['workflow_run'] = '18'
                    self.copied_plan.write_text(json.dumps(value), encoding='utf-8')
                result = self.strict_summary()
                self.assertFalse(result['full_S3_accepted'])
                self.assertFalse(result['checks']['latency_evidence'])
                self.assertIn('latency_evidence', result['evidence_errors'])
                self.assertTrue(all(result['checks'][name] for name in ('process_cpu_windows', 'allocation_windows', 'image_sizes')))

    def test_strict_invalid_candidate_never_reads_a_latency_plan_outside_evidence(self):
        with patch.object(SUMMARY.native_latency, 'identity', side_effect=AssertionError('must not read invalid source')):
            result = SUMMARY.summarize(self.root, '../outside', SUCCESS, self.profile,
                                       SUMMARY.native_latency.PROFILE, '17', CANDIDATE)
        self.assertFalse(result['full_S3_accepted'])
        self.assertEqual(result['evidence_errors']['candidate']['error'], 'immutable_candidate_required')
        self.assertFalse(result['checks']['latency_evidence'])


if __name__ == '__main__':
    unittest.main()
