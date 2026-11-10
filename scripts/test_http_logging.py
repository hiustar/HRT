#!/usr/bin/env python3
"""Exercise actual HTTP access logs without touching a real deployment database."""

from contextlib import redirect_stderr, redirect_stdout
import http.client
import io
import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import traceback
import unittest

sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
temp_dir = tempfile.TemporaryDirectory(prefix='hrt-http-logging-')
os.environ['PERSIST_DIR'] = temp_dir.name
import server  # noqa: E402


class LoggingHandler(server.HRTServerHandler):
    def do_GET(self):
        if self.path.startswith('/missing'):
            self.send_error(404)
            return
        if self.path.startswith('/exception'):
            try:
                raise RuntimeError('real error remains visible')
            except RuntimeError:
                traceback.print_exc()
            code = 500
        else:
            code = int(self.path.split('/')[1].split('?')[0])
        self.send_response(code)
        self.end_headers()


class HTTPLoggingTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.httpd = server.ThreadingServer(('127.0.0.1', 0), LoggingHandler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()
        cls.thread.join(timeout=5)
        temp_dir.cleanup()

    def request_logs(self, path):
        stdout, stderr = io.StringIO(), io.StringIO()
        with redirect_stdout(stdout), redirect_stderr(stderr):
            conn = http.client.HTTPConnection('127.0.0.1', self.httpd.server_address[1], timeout=5)
            try:
                conn.request('GET', path)
                response = conn.getresponse()
                response.read()
                code = response.status
            finally:
                conn.close()
        return code, stdout.getvalue(), stderr.getvalue()

    def test_status_codes_use_expected_levels_and_streams(self):
        for code, level in ((200, 'info'), (302, 'info'), (400, 'warning'),
                            (401, 'warning'), (429, 'warning'), (500, 'error'), (503, 'error')):
            with self.subTest(code=code):
                actual, stdout, stderr = self.request_logs(f'/{code}?token=private')
                self.assertEqual(actual, code)
                output = stderr if level == 'error' else stdout
                self.assertEqual(stdout if level == 'error' else stderr, '')
                self.assertEqual(len(output.splitlines()), 1)
                entry = json.loads(output)
                self.assertEqual(entry['status'], level)
                self.assertEqual(entry['http'], {'method': 'GET', 'url': f'/{code}', 'status_code': code})
                self.assertEqual(entry['network']['client']['ip'], '127.0.0.1')
                self.assertNotIn('private', output)

    def test_send_error_produces_one_warning(self):
        code, stdout, stderr = self.request_logs('/missing?token=private')
        self.assertEqual(code, 404)
        self.assertEqual(stderr, '')
        self.assertEqual(len(stdout.splitlines()), 1)
        self.assertEqual(json.loads(stdout)['status'], 'warning')
        self.assertNotIn('private', stdout)

    def test_real_exception_traceback_is_kept_on_stderr(self):
        code, stdout, stderr = self.request_logs('/exception')
        self.assertEqual(code, 500)
        self.assertEqual(stdout, '')
        self.assertIn('RuntimeError: real error remains visible', stderr)
        self.assertEqual(json.loads(stderr.splitlines()[-1])['status'], 'error')

    def test_untrusted_control_characters_cannot_add_log_lines(self):
        handler = object.__new__(LoggingHandler)
        handler.client_address = ('127.0.0.1', 1234)
        handler.command = 'GET'
        handler.path = '/unsafe\x1b[31m\nFAKE?token=private'
        output = io.StringIO()
        with redirect_stdout(output):
            handler.log_request(200)
        self.assertEqual(len(output.getvalue().splitlines()), 1)
        self.assertEqual(json.loads(output.getvalue())['http']['url'], '/unsafe\x1b[31m\nFAKE')
        self.assertNotIn('private', output.getvalue())


if __name__ == '__main__':
    unittest.main()
