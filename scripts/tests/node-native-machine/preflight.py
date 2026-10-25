#!/usr/bin/env python3
"""Fail closed on missing pinned Core admission contracts; no runtime claim."""
from pathlib import Path
import json
import re
import subprocess
import sys

# These are the existing compiled admin owners, not the retired raw PUT routes.
REQUIRED_OPERATIONS = {
    'network.nodes.configuration.get': ('NetworkNodeAdminController', 'configuration', 'network.nodes.manage', 'read'),
    'network.nodes.configuration.replace': ('NetworkNodeAdminController', 'replaceConfigured', 'network.nodes.manage', 'workflow'),
    'network.nodes.patch': ('NetworkNodeAdminController', 'patch', 'network.nodes.manage', 'workflow'),
    'network.machines.token.rotate': ('NetworkMachineAdminController', 'nativeRotateToken', 'network.machines.manage', 'workflow'),
    'network.machines.credentials.get': ('NetworkMachineAdminController', 'nativeCredentials', 'network.machines.manage', 'read'),
}
CONTRACT_SOURCES = {
    'operations': 'api/resources/contracts/core-operations.v1.json',
    'bindings': 'api/resources/contracts/admin-bindings.v1.json',
    'surface': 'api/resources/contracts/browser-surfaces.v1.json',
}


def git(core, *args):
    return subprocess.check_output(['git', '-C', str(core), *args], text=True,
                                   stderr=subprocess.DEVNULL).strip()


def inspect(api, baseline):
    core = Path(api).resolve().parent
    gaps = []
    result = {'schema': 'txnode-core-machine-preflight/v1', 'kind': 'static_contract',
              'runtime_verified': False, 'core_revision': baseline['revision'],
              'required_contracts': [], 'gaps': gaps}
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
        result['inventory_blob'] = git(core, 'rev-parse', baseline['revision'] + ':' + source_path)
        # Parse only the literal closed inventory; unfamiliar syntax fails closed.
        commands = re.search(r'public const COMMANDS\s*=\s*\[(.*?)\];', source, re.S)
        http = re.search(r'private const HTTP\s*=\s*\[(.*?)\n    \];', source, re.S)
        if commands is None or http is None:
            gaps.append({'code': 'CORE_ADMISSION_INVENTORY_UNPARSEABLE'})
        else:
            admitted = 'ws-server' in re.findall(r"'([^']*)'", commands.group(1))
            result['required_contracts'].append({'kind': 'command', 'command': 'ws-server',
                                                 'admitted': admitted})
            if not admitted:
                gaps.append({'code': 'CORE_WS_COMMAND_NOT_ADMITTED', 'command': 'ws-server'})
            inventory = {}
            for method, patterns in re.findall(
                    r"'([A-Z]+)'\s*=>\s*\[(.*?)(?=\n        '[A-Z]+'\s*=>|\Z)",
                    http.group(1), re.S):
                inventory[method] = re.findall(r"'([^']*)'", patterns)
            documents = {}
            result['contract_sources'] = {}
            for name, path in CONTRACT_SOURCES.items():
                documents[name] = json.loads(git(core, 'show', baseline['revision'] + ':' + path))
                result['contract_sources'][name] = {'path': path, 'blob': git(
                    core, 'rev-parse', baseline['revision'] + ':' + path)}
            required_operations = dict(REQUIRED_OPERATIONS)
            if 'node-connections/v1' in baseline.get('protocols', []):
                required_operations.update({
                    'network.nodes.connections.list.request': ('NativeNodeConnectionsController', 'listConnections', 'network.nodes.read', 'workflow'),
                    'network.nodes.connections.close': ('NativeNodeConnectionsController', 'closeConnection', 'network.nodes.manage', 'workflow'),
                    'network.nodes.connections.result.get': ('NativeNodeConnectionsController', 'result', 'network.nodes.read', 'read'),
                })
            for operation, (controller, handler, permission, mode) in required_operations.items():
                path = 'gateway/v1/core/admin/operations/' + operation
                admitted = any(re.fullmatch(pattern, path) for pattern in inventory.get('POST', []))
                spec = documents['operations'].get('operations', {}).get(operation, {})
                binding = documents['bindings'].get('bindings', {}).get(operation, {})
                bound = (spec.get('actor') == 'admin' and 'admin' in spec.get('domains', [])
                         and spec.get('permission') == permission and spec.get('idempotency') == mode
                         and binding.get('controller') == controller and binding.get('method') == handler
                         and operation in documents['surface'].get('admin', []))
                result['required_contracts'].append({'kind': 'admin_operation', 'operation': operation,
                                                     'admitted': admitted, 'owner_bound': bound})
                if not admitted:
                    gaps.append({'code': 'CORE_HTTP_NOT_ADMITTED', 'method': 'POST', 'path': path})
                if not bound:
                    gaps.append({'code': 'CORE_ADMIN_CONTRACT_MISMATCH', 'operation': operation})
        result['inventory_source'] = source_path
    except (OSError, subprocess.SubprocessError, re.error, ValueError, TypeError, AttributeError):
        gaps.append({'code': 'CORE_STATIC_INSPECTION_FAILED'})
    result['status'] = 'blocked' if gaps else 'necessary_contracts_present'
    return result


if __name__ == '__main__':
    if len(sys.argv) != 3:
        raise SystemExit('usage: preflight.py API CORE_BASELINE_JSON')
    report = inspect(Path(sys.argv[1]), json.loads(Path(sys.argv[2]).read_text()))
    print(json.dumps(report, sort_keys=True, indent=2))
    raise SystemExit(1 if report['gaps'] else 0)
