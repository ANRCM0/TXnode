"""Linux PHP fixture concurrency regression; run in the Actions Machine job."""
import http.client
import json
import os
from pathlib import Path
import shutil
import signal
import socket
import subprocess
import tempfile
import threading
import time
import unittest

from php_server import core_http_command, core_http_environment


class CoreHTTPFixtureTest(unittest.TestCase):
    def test_busy_request_does_not_block_an_independent_request(self):
        php = shutil.which('php84') or shutil.which('php')
        self.assertIsNotNone(php, 'Machine fixture requires PHP')
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'router.php').write_text('''<?php
if ($_SERVER['REQUEST_URI'] === '/cache') {
    $status = function_exists('opcache_get_status') ? opcache_get_status(false) : false;
    header('Content-Type: application/json');
    echo json_encode(['enabled' => is_array($status) && $status['opcache_enabled'],
                      'cached' => function_exists('opcache_is_script_cached') && opcache_is_script_cached(__FILE__)]);
    exit;
}
if ($_SERVER['REQUEST_URI'] === '/held') {
    touch(__DIR__ . '/entered');
    $deadline = microtime(true) + 10;
    while (!file_exists(__DIR__ . '/release')) {
        if (microtime(true) > $deadline) { http_response_code(504); exit; }
        usleep(10000);
    }
}
header('Content-Length: 7');
echo 'fixture';
''', encoding='utf-8')
            with socket.socket() as listener:
                listener.bind(('127.0.0.1', 0))
                port = listener.getsockname()[1]
            process = subprocess.Popen(
                core_http_command(php, port, 'router.php'), cwd=root,
                env=core_http_environment(os.environ), start_new_session=True,
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            held_result = []

            def request(path, timeout=2):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=timeout)
                try:
                    connection.request('GET', path)
                    response = connection.getresponse()
                    return response.status, response.read()
                finally:
                    connection.close()

            def hold_request():
                try:
                    held_result.append(request('/held', timeout=8))
                except OSError:
                    held_result.append('transport_failure')

            worker = None
            try:
                deadline = time.monotonic() + 10
                while True:
                    self.assertIsNone(process.poll(), 'PHP fixture exited before readiness')
                    try:
                        self.assertEqual(request('/ready'), (200, b'fixture'))
                        break
                    except OSError:
                        if time.monotonic() >= deadline:
                            self.fail('PHP fixture readiness deadline')
                        time.sleep(.01)
                status, cache = request('/cache')
                self.assertEqual(status, 200)
                self.assertEqual(json.loads(cache), {'enabled': True, 'cached': True})
                worker = threading.Thread(target=hold_request, daemon=True)
                worker.start()
                deadline = time.monotonic() + 2
                while not (root / 'entered').is_file():
                    if time.monotonic() >= deadline:
                        self.fail('PHP did not enter the held request')
                    time.sleep(.01)
                self.assertEqual(request('/independent'), (200, b'fixture'))
                self.assertTrue(worker.is_alive(), 'held request ended before the independent response')
            finally:
                (root / 'release').touch()
                if worker is not None:
                    worker.join(timeout=3)
                try:
                    os.killpg(process.pid, signal.SIGTERM)
                except ProcessLookupError:
                    pass
                process.wait(timeout=5)
            self.assertEqual(held_result, [(200, b'fixture')])


if __name__ == '__main__':
    unittest.main()
