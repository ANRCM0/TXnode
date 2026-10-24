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
        self.soak = {'accepted': True, 'elapsed_seconds': 1801,
                     'phases': [{'lifecycle_cycles': 8, 'load_bearing_generations_recovered': 9,
                                 'load_bearing_tls_workers': 12, 'expected_retired_disconnects': 96}
                                for _ in range(4)]}
        self.faults = {'accepted': True}
        self.performance = {'candidate': CANDIDATE, 'accepted': True,
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
            directory = self.root / ('native-' + kind + '-' + CANDIDATE)
            directory.mkdir(exist_ok=True)
            (directory / name).write_text(json.dumps(document), encoding='utf-8')
            (directory / 'commit.txt').write_text(CANDIDATE, encoding='utf-8')

    def summarize(self, outcomes=SUCCESS):
        self.write()
        return SUMMARY.summarize(self.root, CANDIDATE, outcomes)

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


if __name__ == '__main__':
    unittest.main()
