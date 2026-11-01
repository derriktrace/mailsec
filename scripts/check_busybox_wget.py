"""Execute the rebuilt applet against loopback only; no external URL is fetched."""
import json
import os
import socket
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def check(binary):
    environment = {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'HOME': '/tmp'}

    def wget(url):
        return subprocess.run([binary, 'wget', '-Y', 'off', '-T', '2', '-q', '-O', '-', url],
                              env=environment, capture_output=True, timeout=5)

    rejected = 0
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        listener.setblocking(False)
        base = f'http://127.0.0.1:{listener.getsockname()[1]}'
        for value in [*range(1, 33), 127]:
            character = chr(value)
            for url in (base + '/before' + character + 'after',
                        base + '/?before=' + character + 'after',
                        base + '/#before' + character + 'after'):
                result = wget(url)
                assert result.returncode != 0, f'Unsafe byte {value} accepted'
                assert b'invalid control character or space in URL' in result.stderr, result.stderr
                try:
                    connection, _ = listener.accept()
                except BlockingIOError:
                    pass
                else:
                    connection.close()
                    raise AssertionError('Rejected URL caused an outbound connection')
                rejected += 1
        # NUL cannot occur in an operating-system argv element at all.
        try:
            wget(base + '/before\0after')
        except ValueError:
            pass
        else:
            raise AssertionError('Operating system accepted embedded NUL argv')

    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            if self.path in ('/invalid-relative', '/invalid-absolute'):
                target = '/invalid path'
                if self.path == '/invalid-absolute':
                    target = f'http://127.0.0.1:{self.server.server_port}' + target
                self.send_response(302)
                self.send_header('Location', target)
                self.end_headers()
                return
            if self.path in ('/redirect', '/relative'):
                target = '/final%20path?answer=42'
                if self.path == '/redirect':
                    target = f'http://127.0.0.1:{self.server.server_port}' + target
                self.send_response(302)
                self.send_header('Location', target)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header('Content-Length', '2')
            self.end_headers()
            self.wfile.write(b'ok')

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        base = f'http://127.0.0.1:{server.server_port}'
        for path in ('/normal', '/safe%20path%0D%0A%7F?value=a%20b', '/redirect', '/relative'):
            result = wget(base + path)
            assert result.returncode == 0 and result.stdout == b'ok', result.stderr
        assert requests == ['/normal', '/safe%20path%0D%0A%7F?value=a%20b',
                            '/redirect', '/final%20path?answer=42', '/relative', '/final%20path?answer=42']
        for path in ('/invalid-relative', '/invalid-absolute'):
            before = len(requests)
            result = wget(base + path)
            assert result.returncode != 0 and b'invalid control character or space in URL' in result.stderr
            assert requests[before:] == [path], 'An invalid redirect caused a follow-up request'
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
    return {'unsafe_initial_urls_rejected_before_connect': rejected,
            'nul_rejected_by_argv': True, 'normal_percent_encoded_and_redirect_requests': 6,
            'unsafe_absolute_and_relative_redirects_rejected_before_followup': 2}


if __name__ == '__main__':
    print(json.dumps(check(os.path.abspath(sys.argv[1])), sort_keys=True))
