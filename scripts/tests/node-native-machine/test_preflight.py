"""Static inventory regressions; execute in Actions, never runtime acceptance."""
import json
import unittest
from unittest.mock import patch

import preflight


REVISION = 'd2e70b8c3896b8d9808595886cb544d133f179ee'
BASELINE = {'repository': 'ANRCM0/TXBoard', 'revision': REVISION}
SOURCE_PATH = 'api/app/Domains/Installation/NativeRuntimeAdmission.php'


def inventory(admit=False):
    commands = "'core:native-work', 'ws-server'" if admit else "'core:native-work'"
    return ("public const COMMANDS = [" + commands + "];\n"
            "private const HTTP = [\n"
            "        'POST' => ['gateway/v1/core/(?:user|admin)/operations/[a-z][a-z0-9.-]{1,100}'],\n"
            "    ];")


def contracts():
    operations, bindings = {}, {}
    for operation, (controller, handler, permission, mode) in preflight.REQUIRED_OPERATIONS.items():
        operations[operation] = {'actor': 'admin', 'domains': ['admin'],
                                 'permission': permission, 'idempotency': mode}
        bindings[operation] = {'controller': controller, 'method': handler}
    return {'operations': {'operations': operations}, 'bindings': {'bindings': bindings},
            'surface': {'admin': list(operations)}}


class MachinePreflightTest(unittest.TestCase):
    def inspect(self, source, head=REVISION, dirty='', untracked='', documents=None):
        documents = contracts() if documents is None else documents
        def git(_core, *args):
            if args == ('rev-parse', 'HEAD'):
                return head
            if args == ('diff', 'HEAD', '--', 'api'):
                return dirty
            if args == ('ls-files', '--others', '--exclude-standard', '--', 'api/app', 'api/routes'):
                return untracked
            if args == ('show', REVISION + ':' + SOURCE_PATH):
                return source
            if args == ('rev-parse', REVISION + ':' + SOURCE_PATH):
                return '1' * 40
            for name, path in preflight.CONTRACT_SOURCES.items():
                if args == ('show', REVISION + ':' + path):
                    return json.dumps(documents[name])
                if args == ('rev-parse', REVISION + ':' + path):
                    return '3' * 40
            raise AssertionError('Unexpected source read: ' + repr(args))
        with patch.object(preflight, 'git', side_effect=git):
            return preflight.inspect('/exclusive/core/api', BASELINE)

    def test_current_core_contracts_close_four_old_routes_but_not_ws_command(self):
        result = self.inspect(inventory())
        self.assertEqual(result['status'], 'blocked')
        self.assertEqual(result['gaps'], [{'code': 'CORE_WS_COMMAND_NOT_ADMITTED', 'command': 'ws-server'}])
        self.assertEqual(len(result['required_contracts']), 6)
        self.assertTrue(all(item['admitted'] and item['owner_bound']
                            for item in result['required_contracts'][1:]))
        self.assertEqual(result['inventory_blob'], '1' * 40)
        self.assertEqual(set(result['contract_sources']), set(preflight.CONTRACT_SOURCES))
        self.assertFalse(result['runtime_verified'])

    def test_inventory_presence_is_necessary_not_runtime_acceptance(self):
        result = self.inspect(inventory(True))
        self.assertEqual(result['gaps'], [])
        self.assertEqual(result['status'], 'necessary_contracts_present')
        self.assertEqual(len(result['required_contracts']), 6)
        self.assertTrue(all(item['admitted'] for item in result['required_contracts']))
        self.assertFalse(result['runtime_verified'])

    def test_admission_is_method_specific_and_matches_whole_path(self):
        for source in [inventory(True).replace("'POST' => [", "'GET' => ["),
                       inventory(True).replace("/operations/", "/retired-operations/")]:
            result = self.inspect(source)
            self.assertEqual([gap['code'] for gap in result['gaps']], ['CORE_HTTP_NOT_ADMITTED'] * 5)

    def test_missing_binding_permission_or_browser_surface_fails_closed(self):
        operation = 'network.nodes.configuration.replace'
        for kind in ['binding', 'permission', 'surface']:
            documents = contracts()
            if kind == 'binding':
                documents['bindings']['bindings'][operation]['method'] = 'replace'
            elif kind == 'permission':
                documents['operations']['operations'][operation]['permission'] = None
            else:
                documents['surface']['admin'].remove(operation)
            result = self.inspect(inventory(True), documents=documents)
            self.assertIn({'code': 'CORE_ADMIN_CONTRACT_MISMATCH', 'operation': operation}, result['gaps'])

    def test_drifted_core_head_or_source_never_passes_inventory(self):
        for arguments, code in [({'head': '2' * 40}, 'CORE_PIN_MISMATCH'),
                                ({'dirty': 'modified'}, 'CORE_SOURCE_MODIFIED'),
                                ({'untracked': 'api/app/extra.php'}, 'CORE_SOURCE_UNTRACKED')]:
            with self.subTest(code=code):
                result = self.inspect(inventory(True), **arguments)
                self.assertEqual(result['status'], 'blocked')
                self.assertIn({'code': code}, result['gaps'])

    def test_unknown_inventory_shape_fails_closed(self):
        result = self.inspect('public const COMMANDS = [];')
        self.assertEqual(result['status'], 'blocked')
        self.assertIn({'code': 'CORE_ADMISSION_INVENTORY_UNPARSEABLE'}, result['gaps'])
        self.assertEqual(result['required_contracts'], [])


if __name__ == '__main__':
    unittest.main()
