#!/usr/bin/env python3
"""Select this Node checkout for a fixed Core's CI-only native fixture."""
import json
from pathlib import Path
import subprocess


ROOT = Path(__file__).resolve().parents[1]
CORE = ROOT / '.compat/core'


def git(root, *arguments):
    return subprocess.check_output(['git', '-C', str(root), *arguments], text=True).strip()


def main():
    baseline = json.loads((ROOT / 'compatibility/core.v1.json').read_text(encoding='utf-8'))
    core_head = git(CORE, 'rev-parse', 'HEAD')
    if core_head != baseline['revision']:
        raise ValueError('Core checkout differs from the supported immutable baseline')
    if CORE.resolve() != ROOT / '.compat/core':
        raise ValueError('Core fixture escaped the task-owned compatibility directory')
    node_head = git(ROOT, 'rev-parse', 'HEAD')
    native_test = ROOT / 'internal/service/native_c2_interop_test.go'
    if not native_test.is_file() or 'func TestNativeC2RuntimeEndToEnd(' not in native_test.read_text(encoding='utf-8'):
        raise ValueError('The required native C2 runtime test is missing')
    # The baseline may still contain the historical bundled module. Keep it for
    # diagnostics and point only its integration path at this candidate checkout.
    reference = CORE / 'node'
    if reference.exists() or reference.is_symlink():
        reference.rename(CORE / '.bundled-node-reference')
    reference.symlink_to(ROOT, target_is_directory=True)
    evidence = {
        'schema': 'txnode-core-compatibility-sources/v1',
        'core_repository': baseline['repository'],
        'core_revision': core_head,
        'core_tree': git(CORE, 'rev-parse', 'HEAD^{tree}'),
        'node_repository': 'ANRCM0/txnode',
        'node_revision': node_head,
        'node_tree': git(ROOT, 'rev-parse', 'HEAD^{tree}'),
        'node_kernel': 'txnode',
        'native_c2_test': 'TestNativeC2RuntimeEndToEnd',
        'fixture': 'Pinned Core application source with candidate Node integration path',
    }
    target = ROOT / 'artifacts/core-compatibility-sources.json'
    target.parent.mkdir(exist_ok=True)
    target.write_text(json.dumps(evidence, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(evidence))


if __name__ == '__main__':
    main()
