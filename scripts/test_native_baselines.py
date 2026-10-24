"""Clock errata must remain an explicit, exact two-line legacy source change."""
import copy
import subprocess
import unittest
from unittest.mock import patch

import native_baselines as BASELINES


class BaselineIdentityTests(unittest.TestCase):
    def test_both_immutable_commits_match_their_complete_trees(self):
        for profile in BASELINES.PROFILES:
            with self.subTest(profile=profile):
                self.assertEqual(BASELINES.verify(profile), BASELINES.identity(profile))
        self.assertEqual(BASELINES.identity()['commit'], BASELINES.ORIGINAL)
        self.assertEqual(BASELINES.artifact_label(), '')
        self.assertEqual(BASELINES.artifact_label(BASELINES.ERRATA_PROFILE), BASELINES.ERRATA_PROFILE + '-')
        with self.assertRaises(ValueError):
            BASELINES.verify('main')

    def test_other_files_guards_or_parent_changes_cannot_be_errata(self):
        original_call = subprocess.check_output

        def wrong_result(target, replacement):
            def git(args, **kwargs):
                return replacement if args[1:] == target else original_call(args, **kwargs)
            return git

        cases = [
            (['rev-parse', BASELINES.ERRATA + '^{tree}'], b'0' * 40),
            (['rev-list', '--parents', '-n', '1', BASELINES.ERRATA],
             (BASELINES.ERRATA + ' ' + '0' * 40).encode()),
            (['diff', '--name-only', '--no-renames', BASELINES.ORIGINAL, BASELINES.ERRATA],
             (BASELINES.NATIVE_PATH + '\ninternal/usagebucket/store.go\n').encode()),
            (['show', BASELINES.ERRATA + ':' + BASELINES.NATIVE_PATH],
             original_call(['git', 'show', BASELINES.ERRATA + ':' + BASELINES.NATIVE_PATH], cwd=BASELINES.ROOT)
             .replace(b'now.Before(c.deadline)', b'true', 1)),
        ]
        for target, replacement in cases:
            with self.subTest(target=target), patch.object(BASELINES.subprocess, 'check_output',
                                                          side_effect=wrong_result(target, replacement)):
                with self.assertRaises(ValueError):
                    BASELINES.verify(BASELINES.ERRATA_PROFILE)

    def test_reports_cannot_exchange_or_omit_errata_identity(self):
        for profile in BASELINES.PROFILES:
            expected = BASELINES.identity(profile)
            report = {'baseline': expected['commit'], 'baseline_tree': expected['tree'], 'baseline_identity': expected,
                      'builds': {'legacy': {'sha': expected['commit'], 'status': 'built'}}}
            self.assertTrue(BASELINES.matches_report(report, profile))
            other = next(name for name in BASELINES.PROFILES if name != profile)
            self.assertFalse(BASELINES.matches_report(report, other))
            del report['baseline_identity']
            self.assertEqual(BASELINES.matches_report(report, profile), profile == BASELINES.DEFAULT_PROFILE)
        expected = BASELINES.identity(BASELINES.ERRATA_PROFILE)
        changed = copy.deepcopy(expected)
        changed['errata']['patch_sha256'] = '0' * 64
        self.assertFalse(BASELINES.matches_report({'baseline': expected['commit'], 'baseline_tree': expected['tree'],
                                                   'baseline_identity': changed,
                                                   'builds': {'legacy': {'sha': expected['commit'], 'status': 'built'}}},
                                                  BASELINES.ERRATA_PROFILE))
        self.assertEqual(BASELINES.identity(BASELINES.ERRATA_PROFILE), expected)


if __name__ == '__main__':
    unittest.main()
