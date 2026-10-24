"""Trusted facade connection isolation; execute network tests only in Actions."""
import http.client
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
import socket
import ssl
import subprocess
import tempfile
import threading
import unittest
from unittest.mock import patch

from tls_proxy import NativeTLSProxy


class NativeTLSProxyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        self.cert, key = root / 'server.pem', root / 'server.key'
        subprocess.run(
            ['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
             '-keyout', str(key), '-out', str(self.cert), '-subj', '/CN=localhost',
             '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1'],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header('Content-Length', '7')
                self.end_headers()
                self.wfile.write(b'trusted')

            def log_message(self, *args):
                pass

        backend = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        worker = threading.Thread(target=backend.serve_forever, daemon=True)
        worker.start()

        def close_backend():
            backend.shutdown()
            backend.server_close()
            worker.join(timeout=2)
        self.addCleanup(close_backend)
        self.proxy = NativeTLSProxy(0, backend.server_address[1], 0, self.cert, key, root / 'events.jsonl')
        self.proxy.start()
        self.addCleanup(self.proxy.close)

    def request(self, context=None):
        if context is None:
            context = ssl.create_default_context(cafile=str(self.cert))
        connection = http.client.HTTPSConnection(
            '127.0.0.1', self.proxy.server.server_address[1], timeout=2, context=context)
        try:
            connection.request('GET', '/fixture')
            response = connection.getresponse()
            return response.status, response.read()
        finally:
            connection.close()

    def test_pending_handshake_does_not_block_other_trusted_requests(self):
        entered = threading.Event()
        handshake = ssl.SSLSocket.do_handshake

        def observed(connection, *args, **kwargs):
            if connection.server_side:
                entered.set()
            return handshake(connection, *args, **kwargs)

        with patch.object(ssl.SSLSocket, 'do_handshake', observed):
            stalled = socket.create_connection(self.proxy.server.server_address, timeout=2)
            try:
                self.assertTrue(entered.wait(timeout=2), 'server did not enter the first handshake')
                self.assertEqual(self.request(), (200, b'trusted'))
            finally:
                stalled.close()
        self.assertEqual([event['status'] for event in self.proxy.event_snapshot() if event['kind'] == 'http'], [200])

    def test_untrusted_certificate_is_rejected_before_http_forwarding(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request(ssl.create_default_context())
        self.assertFalse(any(event['kind'] == 'http' for event in self.proxy.event_snapshot()))
        self.assertEqual(self.request(), (200, b'trusted'))


if __name__ == '__main__':
    unittest.main()
