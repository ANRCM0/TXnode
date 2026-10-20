#!/usr/bin/env python3
"""Fail closed on missing pinned Core admission contracts; no runtime claim."""
from pathlib import Path
import json
import re
import subprocess
import sys


def git(core, *args):
    return subprocess.check_output(['git', '-C', str(core), *args], text=True,
                                   stderr=subprocess.DEVNULL).strip()


def inspect(api, baseline):
    core = Path(api).resolve().parent
    gaps = []
    result = {'schema': 'txnode-core-machine-preflight/v1', 'kind': 'static_contract',
              'runtime_verified': False, 'core_revision': baseline['revision'], 'gaps': gaps}
    try:
        actual = git(core, 'rev-parse', 'HEAD')
        result['actual_core_revision'] = actual
        if baseline['repository'] != 'ANRCM0/TXBoard' or actual != baseline['revision']:
            gaps.append({'code': 'CORE_PIN_MISMATCH'})
        if git(core, 'diff', 'HEAD', '--', 'api'):
            gaps.append({'code': 'CORE_SOURCE_MODIFIED'})
        if git(core, 'ls-files', '--others', '--exclude-standard', '--', 'api/app', 'api/routes'):
            gaps.append({'code': 'CORE_SOURCE_UNTRACKED'})
        source_path = 'api/app/Domains/Installation/NativeRuntimeAdmission.php'
        source = git(core, 'show', baseline['revision'] + ':' + source_path)
        # Parse only the literal closed inventory; unfamiliar syntax fails closed.
        commands = re.search(r'public const COMMANDS\s*=\s*\[(.*?)\];', source, re.S)
        http = re.search(r'private const HTTP\s*=\s*\[(.*?)\n    \];', source, re.S)
        if commands is None or http is None:
            gaps.append({'code': 'CORE_ADMISSION_INVENTORY_UNPARSEABLE'})
        else:
            if 'ws-server' not in re.findall(r"'([^']*)'", commands.group(1)):
                gaps.append({'code': 'CORE_WS_COMMAND_NOT_ADMITTED', 'command': 'ws-server'})
            inventory = {}
            for method, patterns in re.findall(
                    r"'([A-Z]+)'\s*=>\s*\[(.*?)(?=\n        '[A-Z]+'\s*=>|\Z)",
                    http.group(1), re.S):
                inventory[method] = re.findall(r"'([^']*)'", patterns)
            required = [('GET', 'txapi/admin/native_machine_admin/network-nodes'),
                        ('PUT', 'txapi/admin/native_machine_admin/network-nodes/1'),
                        ('PATCH', 'txapi/admin/native_machine_admin/network-nodes/1'),
                        ('POST', 'txapi/admin/native_machine_admin/network-machines/1/token/rotate')]
            for method, path in required:
                if not any(re.fullmatch(pattern, path) for pattern in inventory.get(method, [])):
                    gaps.append({'code': 'CORE_HTTP_NOT_ADMITTED', 'method': method, 'path': path})
        result['inventory_source'] = source_path
    except (OSError, subprocess.SubprocessError, re.error):
        gaps.append({'code': 'CORE_STATIC_INSPECTION_FAILED'})
    result['status'] = 'blocked' if gaps else 'necessary_contracts_present'
    return result


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: preflight.py API CORE_BASELINE_JSON')
    report = inspect(Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()))
    print(json.dumps(report, sort_keys=True, indent=2))
    raise SystemExit(1 if report['gaps'] else 0)
