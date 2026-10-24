"""Immutable, separately named legacy inputs for native performance evidence."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parent.parent
DEFAULT_PROFILE = 'original-a1ad269-v1'
ERRATA_PROFILE = 'legacy-clock-serialized-v1'
NATIVE_PATH = 'internal/usageinterval/native.go'
ORIGINAL = 'a1ad2695e1143269168c36a274283de3342e91c7'
ERRATA = '4904a193d4564cf67af55728da0b338ff3b1268f'
ORIGINAL_NATIVE_SHA256 = 'ba7110cc4f045c55e882a6fb9b634f6e1aaa772b3f14dab8903099fd8a795d1a'
ERRATA_NATIVE_SHA256 = '3654cede9a105d1ca5c6f2bfcd819b91b4f29e373e9d93fe34ddbccaa58d6b14'
PROFILES = {
    DEFAULT_PROFILE: {'profile': DEFAULT_PROFILE, 'commit': ORIGINAL,
                      'tree': 'd070c68744b27641c3c769b1952d1c2c83ffd74b',
                      'original_commit': ORIGINAL, 'errata': None},
    ERRATA_PROFILE: {'profile': ERRATA_PROFILE, 'commit': ERRATA,
                     'tree': 'edfe6051a97952aba014bf874927bca8bc0b550d',
                     'original_commit': ORIGINAL,
                     'errata': {'file': NATIVE_PATH,
                                'original_sha256': ORIGINAL_NATIVE_SHA256,
                                'corrected_sha256': ERRATA_NATIVE_SHA256,
                                'patch_sha256': 'cf241d75a71ca6d07ac2f1f1651a2aaf0e2ead452c652d915ca12b9df2fe3135'}},
}


def identity(profile=DEFAULT_PROFILE):
    if profile not in PROFILES:
        raise ValueError('unknown immutable baseline profile')
    return copy.deepcopy(PROFILES[profile])


def artifact_label(profile=DEFAULT_PROFILE):
    identity(profile)
    return '' if profile == DEFAULT_PROFILE else profile + '-'


def matches_report(report, profile=DEFAULT_PROFILE):
    expected = identity(profile)
    if report['baseline'] != expected['commit'] or report['baseline_tree'] != expected['tree']:
        return False
    built = report['builds']['legacy']
    if built['sha'] != expected['commit'] or built['status'] != 'built':
        return False
    # Archived original reports predate named profiles; they still identify the
    # exact original source. Errata evidence always needs its explicit identity.
    recorded = report.get('baseline_identity')
    return ((profile == DEFAULT_PROFILE and recorded is None)
            or recorded == expected)


def verify(profile=DEFAULT_PROFILE, root=ROOT):
    expected = identity(profile)

    def git(*args):
        return subprocess.check_output(['git', *args], cwd=root)

    for revision, tree in ((expected['commit'], expected['tree']),
                           (ORIGINAL, PROFILES[DEFAULT_PROFILE]['tree'])):
        if git('rev-parse', revision + '^{tree}').decode().strip() != tree:
            raise ValueError('immutable baseline tree mismatch')
    original = git('show', ORIGINAL + ':' + NATIVE_PATH)
    if hashlib.sha256(original).hexdigest() != ORIGINAL_NATIVE_SHA256:
        raise ValueError('original baseline collector mismatch')
    if profile == ERRATA_PROFILE:
        if git('rev-list', '--parents', '-n', '1', ERRATA).decode().split() != [ERRATA, ORIGINAL]:
            raise ValueError('errata must be one child of the original baseline')
        if git('diff', '--name-only', '--no-renames', ORIGINAL, ERRATA).decode().splitlines() != [NATIVE_PATH]:
            raise ValueError('errata changed another source file')
        before = (b'\tnow := time.Now()\n'
                  b'\tat := stamp{now.UnixNano(), int64(now.Sub(c.origin))}\n'
                  b'\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n')
        after = (b'\tc.mu.Lock()\n\tdefer c.mu.Unlock()\n'
                 b'\tnow := time.Now()\n'
                 b'\tat := stamp{now.UnixNano(), int64(now.Sub(c.origin))}\n')
        corrected = git('show', ERRATA + ':' + NATIVE_PATH)
        if original.count(before) != 1 or corrected != original.replace(before, after, 1):
            raise ValueError('errata must only move the CompleteIO clock observation into its existing lock')
        if hashlib.sha256(corrected).hexdigest() != ERRATA_NATIVE_SHA256:
            raise ValueError('corrected baseline collector mismatch')
        diff = git('diff', '--no-ext-diff', '--no-textconv', '--no-color', '--no-renames', '--full-index',
                   '--unified=3', ORIGINAL, ERRATA, '--', NATIVE_PATH)
        if hashlib.sha256(diff).hexdigest() != expected['errata']['patch_sha256']:
            raise ValueError('errata patch mismatch')
    return expected


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile', choices=PROFILES, default=DEFAULT_PROFILE)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    result = verify(args.profile)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result))


if __name__ == '__main__':
    main()
