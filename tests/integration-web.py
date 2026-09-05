#!/usr/bin/env python3
"""Linux/macOS HTTP + Unix IPC bridge checks; no Tailscale or network peers required."""
import contextlib
import http.client
import json
import pathlib
import signal
import socket
import socketserver
import subprocess
import sys
import tempfile
import threading
import time

BIN = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/meshmsg').resolve())


class Daemon(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path):
        self.requests = []
        self.clients = set()
        self.subscribers = set()
        self.lock = threading.Lock()
        super().__init__(str(path), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def broadcast(self, value):
        encoded = json.dumps(value).encode() + b'\n'
        with self.lock:
            subscribers = list(self.subscribers)
        for client in subscribers:
            try:
                client.sendall(encoded)
            except OSError:
                with self.lock:
                    self.subscribers.discard(client)

    def close(self):
        self.shutdown()
        with self.lock:
            for client in self.clients:
                with contextlib.suppress(OSError):
                    client.shutdown(socket.SHUT_RDWR)
        self.server_close()
        pathlib.Path(self.server_address).unlink(missing_ok=True)
        self.thread.join()


class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        with self.server.lock:
            self.server.clients.add(self.request)
        try:
            value = json.loads(self.rfile.readline())
            self.server.requests.append(value)

            def emit(value):
                self.wfile.write(json.dumps(value).encode() + b'\n')
                self.wfile.flush()

            if value['command'] == 'status':
                emit({'type': 'status', 'running': True, 'peer': 'fake-peer', 'neighbors': 1,
                      'endpoint_online': True, 'topic_joined': True, 'socket': 'private-path', 'invite': 'private-token'})
            elif value['command'] == 'send':
                if value['body'] == 'lost-reply':
                    return  # Ambiguous: command reached daemon, reply did not.
                if value['body'] == 'reject':
                    emit({'type': 'error', 'message': 'scripted rejection'})
                else:
                    queued = {'type': 'queued', 'from': 'fake-peer', 'body': value['body'],
                              'timestamp_ms': 1700000000000, 'delivery_acknowledged': False}
                    self.server.broadcast(queued)
                    emit(queued)
            elif value['command'] == 'subscribe':
                emit({'type': 'connected', 'peer': 'fake-peer'})
                emit({'type': 'attachment_offer', 'token': 'private-token'})
                emit({'type': 'message', 'from': 'other-peer', 'body': '<img src=x onerror=alert(1)>\ndata: injected', 'timestamp_ms': 1})
                emit({'type': 'lagged', 'dropped': 3})
                with self.server.lock:
                    self.server.subscribers.add(self.request)
                self.rfile.read(1)  # Remain subscribed until web disconnects.
            else:
                raise AssertionError(f'web leaked command: {value}')
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with self.server.lock:
                self.server.subscribers.discard(self.request)
                self.server.clients.discard(self.request)


def main():
    with tempfile.TemporaryDirectory(prefix='meshmsg-web-test-') as root:
        root = pathlib.Path(root)
        with socket.socket() as reservation:
            reservation.bind(('127.0.0.1', 0))
            port = reservation.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        public = 'https://test.example.ts.net'
        daemon = Daemon(root / 'daemon.sock')
        with (root / 'web.log').open('w+') as log:
            web = subprocess.Popen([BIN, '--state-dir', str(root), 'web', '--listen', f'127.0.0.1:{port}', '--origin', public], stdout=log, stderr=log)
            streams = []

            def request(method='POST', path='/api/request', value=None, headers=None, raw=None):
                body = raw if raw is not None else json.dumps(value or {'command': 'status'})
                actual_headers = {'Origin': origin, 'Content-Type': 'application/json'} if headers is None else headers
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                conn.request(method, path, body if method == 'POST' else None, actual_headers)
                response = conn.getresponse()
                data = response.read()
                result = response.status, dict(response.getheaders()), data
                conn.close()
                return result

            def api(value):
                code, _, data = request(value=value)
                return code, json.loads(data)

            def open_feed():
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                conn.request('GET', '/api/events')
                response = conn.getresponse()
                streams.append((response, conn))
                return response

            def next_event(response):
                while True:
                    line = response.readline()
                    assert line, 'SSE closed unexpectedly'
                    if line.startswith(b'data: '):
                        return json.loads(line[6:])

            try:
                deadline = time.monotonic() + 15
                while True:
                    assert web.poll() is None, 'web exited before startup'
                    try:
                        code, _, _ = request('GET', '/')
                        assert code == 200
                        break
                    except ConnectionRefusedError:
                        assert time.monotonic() < deadline, 'web startup timeout'
                        time.sleep(.05)

                code, headers, html = request('GET', '/')
                assert code == 200 and b'Broadcast' in html
                assert "script-src 'self'" in headers['content-security-policy']
                assert 'unsafe-inline' not in headers['content-security-policy']
                assert headers['cache-control'] == 'no-store'
                assert 'access-control-allow-origin' not in headers
                for path in ['/app.js', '/app.css']:
                    assert request('GET', path)[0] == 200
                for path in ['/config.json', '/../config.json', '/api/request?command=stop']:
                    assert request('GET', path)[0] == 404
                assert request('OPTIONS', '/api/request')[0] == 404
                code, status = api({'command': 'status'})
                assert code == 200 and status['peer'] == 'fake-peer'
                assert 'socket' not in status and 'invite' not in status
                assert request(headers={'Host': 'test.example.ts.net', 'Origin': public, 'Content-Type': 'application/json'})[0] == 200

                before = len(daemon.requests)
                for headers in [
                    {'Content-Type': 'application/json'},
                    {'Content-Type': 'application/json', 'Origin': 'null'},
                    {'Content-Type': 'application/json', 'Origin': 'https://evil.example'},
                    {'Content-Type': 'application/json', 'Origin': public},
                    {'Host': 'evil.example', 'Origin': origin, 'Content-Type': 'application/json', 'X-Forwarded-Host': f'127.0.0.1:{port}'},
                ]:
                    assert request(headers=headers)[0] == 403
                assert request(headers={'Origin': origin, 'Content-Type': 'text/plain'})[0] == 415
                assert request(headers={'Origin': origin, 'Content-Type': 'application/json', 'Content-Encoding': 'gzip'})[0] == 415
                for command in ['stop', 'subscribe', 'share', 'offers', 'download', 'bench_send', 'init', 'join', 'topic']:
                    assert api({'command': command})[0] == 400
                for value in [{'command': 'status', 'path': '/etc/passwd'}, {'command': 'send', 'body': ''}, {'command': 'send', 'body': '二' * 1366}, {'command': 'send', 'body': 'x', 'extra': True}]:
                    assert api(value)[0] == 400
                assert request(raw='{bad json')[0] == 400
                assert request(raw='x' * 30000)[0] == 413
                assert len(daemon.requests) == before, 'rejected HTTP request reached IPC'

                assert api({'command': 'send', 'body': 'hello\n<script>test</script>'}) == (200, {'type': 'queued', 'delivery_acknowledged': False})
                assert api({'command': 'send', 'body': 'too-fast'})[0] == 429
                time.sleep(1.05)
                assert api({'command': 'send', 'body': 'reject'})[1]['outcome'] == 'not_sent'
                time.sleep(1.05)
                assert api({'command': 'send', 'body': 'lost-reply'})[1]['outcome'] == 'unknown'
                time.sleep(1.05)
                assert sum(r.get('body') == 'lost-reply' for r in daemon.requests) == 1, 'send retried'

                feed = open_feed()
                other_tab = open_feed()
                for response in [feed, other_tab]:
                    assert response.status == 200
                    assert next_event(response)['type'] == 'connected'
                    value = next_event(response)
                    assert value['type'] == 'message' and '\ndata: injected' in value['body']
                    assert next_event(response)['type'] == 'lagged'

                time.sleep(1.05)
                synced = 'sent-from-another-web-tab'
                assert api({'command': 'send', 'body': synced}) == (200, {'type': 'queued', 'delivery_acknowledged': False})
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value == {'type': 'queued', 'from': 'fake-peer', 'body': synced,
                                     'timestamp_ms': 1700000000000, 'delivery_acknowledged': False}

                with socket.socket(socket.AF_UNIX) as local_cli:
                    local_cli.connect(str(root / 'daemon.sock'))
                    local_cli.sendall(b'{"command":"send","body":"sent-from-cli"}\n')
                    assert json.loads(local_cli.recv(4096))['type'] == 'queued'
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value['type'] == 'queued' and value['body'] == 'sent-from-cli'

                chat_body = 'sent-from-chat-input'
                chat = subprocess.run(
                    [BIN, '--state-dir', str(root), '--json', 'chat'], input=chat_body + '\n',
                    text=True, capture_output=True, timeout=15, check=False)
                assert chat.returncode == 0, chat.stderr
                assert any(request == {'command': 'send', 'body': chat_body} for request in daemon.requests)
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value == {'type': 'queued', 'from': 'fake-peer', 'body': chat_body,
                                     'timestamp_ms': 1700000000000, 'delivery_acknowledged': False}

                for _ in range(14):
                    response = open_feed()
                    assert response.status == 200
                    assert next_event(response)['type'] == 'connected'
                assert open_feed().status == 503, 'SSE concurrency was not bounded'
                for response, conn in streams:
                    response.close()
                    conn.close()
                streams.clear()
                deadline = time.monotonic() + 5
                while daemon.clients and time.monotonic() < deadline:
                    time.sleep(.05)
                assert not daemon.clients, 'closed HTTP feeds retained IPC clients'

                # A body that never completes must not hold a request indefinitely.
                with socket.create_connection(('127.0.0.1', port), timeout=10) as slow:
                    slow.sendall(f'POST /api/request HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{{'.encode())
                    assert b'408' in slow.recv(8192)

                daemon.close()
                assert api({'command': 'status'})[0] == 503
                offline = open_feed()
                assert next_event(offline)['type'] == 'offline'
                offline.close()
                daemon = Daemon(root / 'daemon.sock')
                assert api({'command': 'status'})[0] == 200
                restarted = open_feed()
                assert next_event(restarted)['type'] == 'connected'
                restarted.close()

                web.send_signal(signal.SIGINT)
                assert web.wait(timeout=5) == 0
                # Web shutdown must leave the separate daemon endpoint usable.
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(root / 'daemon.sock'))
                    client.sendall(b'{"command":"status"}\n')
                    assert json.loads(client.recv(4096))['running'] is True
                print('PASS: HTTP security/allowlist/assets, UTF-8/body bounds/timeouts, throttle, queued/rejected/unknown outcomes, local CLI/chat/web sends synchronized to simultaneous SSE feeds, SSE filtering/framing/capacity/cleanup, offline/restart, independent web shutdown')
            finally:
                for response, conn in streams:
                    response.close()
                    conn.close()
                if web.poll() is None:
                    web.terminate()
                    web.wait(timeout=5)
                daemon.close()
                if sys.exc_info()[0]:
                    log.seek(0)
                    print(log.read(), file=sys.stderr)


if __name__ == '__main__':
    if not hasattr(socket, 'AF_UNIX') or sys.platform == 'win32':
        raise SystemExit('This fake-daemon harness requires Unix sockets; Windows named-pipe runtime coverage is separate.')
    main()
