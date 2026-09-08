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
import urllib.parse

BIN = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/meshmsg').resolve())
SELF_KEY = '7c9f3405d1e6ca4df5947f98bbe1301227ca6b82973940ed2d04b71ffa54b25c'
REMOTE_KEY = '6356c835326c19e98e8b0874f03de7d90f2d7d261a00e2eeb608781bb4784718'
EVENT_KEY = '971dafe5454792b588f162818f11df9c2accd649774f19a5c67360a91bacf6de'


def malicious_peers_snapshot():
    return {
        'type': 'peers_snapshot', 'schema_version': 2, 'generated_at_ms': 1000,
        'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 0,
        'self': {
            'public_key': SELF_KEY, 'alias': 'local-node', 'online': True,
            'endpoint': 'private-self-endpoint', 'socket': 'private-socket',
            'body': 'private-self-body',
        },
        'peers': [{
            'public_key': REMOTE_KEY, 'alias': 'remote-node', 'online': True,
            'last_seen_ms': 900, 'expires_at_ms': 150900,
            'endpoint': 'private-remote-endpoint', 'addresses': ['10.0.0.1:1'],
            'relay': 'private-relay', 'invite': 'private-invite',
            'body': 'private-remote-body',
        }],
        'socket': 'private-top-level-socket', 'invite': 'private-top-level-invite',
    }


def canonical_broadcast_event(value):
    if value.get('type') in {'message', 'queued', 'attachment_offer', 'attachment_shared'}:
        value.setdefault('schema_version', 2)
        value.setdefault('message_id', '0123456789abcdef0123456789abcdef')
    return value


class Daemon(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path):
        self.requests = []
        self.web_download_attempts = {}
        self.web_download_capability = True
        self.clients = set()
        self.subscribers = set()
        self.lock = threading.Lock()
        super().__init__(str(path), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def broadcast(self, value):
        encoded = json.dumps(canonical_broadcast_event(value)).encode() + b'\n'
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
                self.wfile.write(json.dumps(canonical_broadcast_event(value)).encode() + b'\n')
                self.wfile.flush()

            if value['command'] == 'status':
                emit({'type': 'status', 'running': True, 'peer': SELF_KEY, 'neighbors': 1,
                      'endpoint_online': True, 'topic_joined': True,
                      'ipc_capabilities': ['peer_directory_v2', 'web_share_v1'],
                      'max_attachment_bytes': 1024 * 1024,
                      'socket': 'private-path', 'invite': 'private-token'})
            elif value['command'] == 'peers':
                emit(malicious_peers_snapshot())
            elif value['command'] == 'web_download':
                offer = value['offer']
                self.server.web_download_attempts[offer] = self.server.web_download_attempts.get(offer, 0) + 1
                if offer == 'retry-token' and self.server.web_download_attempts[offer] == 1:
                    emit({'type': 'error', 'code': 'download_busy', 'message': 'scripted busy'})
                    return
                output = pathlib.Path(value['output'])
                if offer == 'late-token':
                    def late_export():
                        time.sleep(.3)
                        output.parent.mkdir(parents=True, exist_ok=True)
                        output.write_bytes(b'late daemon export\n')
                    threading.Thread(target=late_export, daemon=True).start()
                    return  # Accepted, but IPC reply is lost before completion.

                assert output.parent.parent.name == 'web-downloads-v2'
                assert output.name.endswith('.blob') and '..' not in output.name
                output.write_bytes(b'browser attachment payload\n')
                if offer == 'missing-schema-token':
                    emit({'type': 'download_complete'})
                elif offer == 'wrong-schema-token':
                    emit({'type': 'download_complete', 'schema_version': 2})
                elif offer == 'malformed-schema-token':
                    emit({'type': 'download_complete', 'schema_version': '1'})
                else:
                    emit({'type': 'download_complete', 'schema_version': 1,
                          'name': '<incoming>.txt', 'kind': 'file', 'size': output.stat().st_size})
            elif value['command'] == 'share':
                path = pathlib.Path(value['path'])
                assert path.parent.parent.parent == pathlib.Path(self.server.server_address).parent / 'web-uploads-v1'
                payload = path.read_bytes()
                shared = {'type': 'attachment_shared', 'schema_version': 2, 'from': 'fake-peer',
                          'timestamp_ms': 1700000000001, 'name': path.name, 'kind': 'file',
                          'size': len(payload), 'offer': 'private-offer', 'ticket': 'private-ticket',
                          'delivery_acknowledged': False}
                if path.name == 'post-broadcast-failure.txt':
                    self.server.broadcast(shared)
                    emit({'type': 'error', 'code': 'share_failed',
                          'message': 'broadcast result was ambiguous'})
                elif path.name == 'mismatched-success.txt':
                    shared['name'] = 'wrong-name.txt'
                    emit(shared)
                else:
                    self.server.broadcast(shared)
                    emit(shared)
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
                capabilities = ['web_download_v1'] if self.server.web_download_capability else []
                emit({'type': 'connected', 'peer': SELF_KEY,
                      'ipc_capabilities': capabilities})
                emit(malicious_peers_snapshot())
                emit({'type': 'attachment_offer', 'from': 'other-peer', 'timestamp_ms': 2,
                      'name': '<incoming>.txt', 'kind': 'file', 'size': 1536,
                      'offer_id': 'private-id', 'offer': 'private-token',
                      'ticket': 'private-ticket', 'path': 'private-path', 'output': 'private-output'})
                emit({'type': 'message', 'from': 'other-peer', 'body': '<img src=x onerror=alert(1)>\ndata: injected', 'timestamp_ms': 1})
                emit({'type': 'lagged', 'dropped': 3})
                emit({'type': 'private_message', 'from': 'other-peer', 'body': 'private-message-body'})
                emit({'type': 'private_accepted', 'to': 'other-peer', 'body': 'private-accepted-body'})
                emit({
                    'type': 'peer_discovered', 'schema_version': 2,
                    'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 1,
                    'peer': {
                        'public_key': EVENT_KEY, 'alias': 'event-node', 'online': True,
                        'last_seen_ms': 950, 'expires_at_ms': 150950,
                        'endpoint': 'private-event-endpoint', 'relay': 'private-event-relay',
                        'body': 'private-event-body',
                    },
                    'socket': 'private-event-socket', 'body': 'private-top-event-body',
                })
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
                assert code == 200 and b'Broadcast' in html and b'href="/settings"' in html
                assert b'Local daemon' not in html
                assert "script-src 'self'" in headers['content-security-policy']
                assert 'unsafe-inline' not in headers['content-security-policy']
                assert headers['cache-control'] == 'no-store'
                assert 'access-control-allow-origin' not in headers
                code, settings_headers, settings_html = request('GET', '/settings')
                assert code == 200 and b'MESHMSG STATUS' in settings_html and b'href="/"' in settings_html
                assert settings_headers['content-security-policy'] == headers['content-security-policy']
                assert all(private not in settings_html.lower() for private in [b'state dir', b'invite', b'offer', b'token', b'ticket'])
                for path in ['/app.js', '/app.css', '/settings.js']:
                    assert request('GET', path)[0] == 200
                for path in ['/config.json', '/../config.json', '/api/request?command=stop']:
                    assert request('GET', path)[0] == 404
                assert request('OPTIONS', '/api/request')[0] == 404
                assert request('POST', '/api/attachment', raw=b'file', headers={
                    'Origin': origin, 'Content-Type': 'text/plain',
                    'X-Meshmsg-File-Name': 'file.txt'})[0] == 415
                daemon.web_download_capability = False
                legacy_feed = open_feed()
                legacy_connected = next_event(legacy_feed)
                assert legacy_connected['type'] == 'connected' and legacy_connected['download_supported'] is False
                assert next_event(legacy_feed)['type'] == 'peers_snapshot'
                legacy_attachment = next_event(legacy_feed)
                assert legacy_attachment['type'] == 'attachment_offer' and 'download_id' not in legacy_attachment
                legacy_feed.close()
                streams.pop()[1].close()
                daemon.web_download_capability = True

                code, status = api({'command': 'status'})
                assert code == 200 and status['peer'] == SELF_KEY
                assert all(key not in status for key in ['socket', 'invite', 'ipc_capabilities'])
                code, peers = api({'command': 'peers'})
                assert code == 200 and peers == {
                    'type': 'peers_snapshot', 'schema_version': 2, 'generated_at_ms': 1000,
                    'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 0,
                    'self': {'public_key': SELF_KEY, 'alias': 'local-node', 'online': True},
                    'peers': [{
                        'public_key': REMOTE_KEY, 'alias': 'remote-node', 'online': True,
                        'last_seen_ms': 900, 'expires_at_ms': 150900,
                    }],
                }
                encoded_peers = json.dumps(peers)
                assert all(secret not in encoded_peers for secret in ['endpoint', 'socket', 'address', 'relay', 'invite', 'private-', 'body'])
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
                incoming_download_ids = []
                for response in [feed, other_tab]:
                    assert response.status == 200
                    assert next_event(response)['type'] == 'connected'
                    assert next_event(response) == {
                        'type': 'peers_snapshot', 'schema_version': 2, 'generated_at_ms': 1000,
                        'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 0,
                        'self': {'public_key': SELF_KEY, 'alias': 'local-node', 'online': True},
                        'peers': [{
                            'public_key': REMOTE_KEY, 'alias': 'remote-node', 'online': True,
                            'last_seen_ms': 900, 'expires_at_ms': 150900,
                        }],
                    }
                    attachment = next_event(response)
                    download_id = attachment.pop('download_id')
                    assert len(download_id) == 32 and all(c in '0123456789abcdef' for c in download_id)
                    incoming_download_ids.append(download_id)
                    assert attachment == {
                        'type': 'attachment_offer', 'schema_version': 2,
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'direction': 'incoming', 'from': 'other-peer',
                        'timestamp_ms': 2, 'name': '<incoming>.txt', 'kind': 'file', 'size': 1536}
                    assert 'private-token' not in json.dumps(attachment)
                    value = next_event(response)
                    assert value['type'] == 'message' and '\ndata: injected' in value['body']
                    assert next_event(response)['type'] == 'lagged'
                    # The two private events are dropped; this must be the next frame.
                    assert next_event(response) == {
                        'type': 'peer_discovered', 'schema_version': 2,
                        'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 1,
                        'peer': {
                            'public_key': EVENT_KEY, 'alias': 'event-node', 'online': True,
                            'last_seen_ms': 950, 'expires_at_ms': 150950,
                        },
                    }
                deadline = time.monotonic() + 5
                while True:
                    with daemon.lock:
                        if len(daemon.subscribers) == 2:
                            break
                    assert time.monotonic() < deadline, 'fake daemon subscriptions were not active'
                    time.sleep(.01)

                upload_name = 'browser résumé.txt'
                upload_payload = b'attachment sent from browser\n'
                code, _, upload_response = request(
                    'POST', '/api/attachment', raw=upload_payload,
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': urllib.parse.quote(upload_name, safe="~()*!.'-")})
                assert code == 200
                assert json.loads(upload_response) == {
                    'type': 'attachment_shared', 'name': upload_name,
                    'size': len(upload_payload), 'delivery_acknowledged': False}
                for response in [feed, other_tab]:
                    assert next_event(response) == {
                        'type': 'attachment_shared', 'schema_version': 2,
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'direction': 'outgoing', 'from': 'fake-peer',
                        'timestamp_ms': 1700000000001, 'name': upload_name,
                        'kind': 'file', 'size': len(upload_payload)}
                upload_request = next(value for value in daemon.requests if value.get('command') == 'share')
                upload_path = pathlib.Path(upload_request['path'])
                assert not upload_path.exists(), 'completed upload staging file was retained'
                assert upload_path.name == upload_name
                assert request(
                    'POST', '/api/attachment', raw=b'x',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': '../escape'})[0] == 400
                assert request(
                    'POST', '/api/attachment', raw=b'x' * (1024 * 1024 + 1),
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'large.bin'})[0] == 413

                code, _, ambiguous_body = request(
                    'POST', '/api/attachment', raw=b'ambiguous publication\n',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'post-broadcast-failure.txt'})
                ambiguous = json.loads(ambiguous_body)
                assert code == 502 and ambiguous['outcome'] == 'unknown'
                assert 'before retrying' in ambiguous['message']
                for response in [feed, other_tab]:
                    observed = next_event(response)
                    assert observed['type'] == 'attachment_shared'
                    assert observed['name'] == 'post-broadcast-failure.txt'
                ambiguous_request = next(
                    value for value in daemon.requests
                    if pathlib.Path(value.get('path', '')).name == 'post-broadcast-failure.txt')
                assert not pathlib.Path(ambiguous_request['path']).exists()

                code, _, mismatch_body = request(
                    'POST', '/api/attachment', raw=b'metadata mismatch\n',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'mismatched-success.txt'})
                mismatch = json.loads(mismatch_body)
                assert code == 502 and mismatch['outcome'] == 'unknown'
                mismatch_request = next(
                    value for value in daemon.requests
                    if pathlib.Path(value.get('path', '')).name == 'mismatched-success.txt')
                assert not pathlib.Path(mismatch_request['path']).exists()

                code, started = api({'command': 'download', 'id': incoming_download_ids[0]})
                assert code == 202 and started['type'] == 'download_started'
                assert started['poll_timeout_ms'] == 71 * 60 * 1000
                deadline = time.monotonic() + 5
                while True:
                    code, download = api({'command': 'download_status', 'id': started['id']})
                    if download.get('type') == 'download_ready':
                        break
                    assert code == 200 and download['type'] == 'download_pending'
                    assert time.monotonic() < deadline, 'web download did not become ready'
                    time.sleep(.01)
                interrupted = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                interrupted.request('GET', download['url'])
                interrupted_response = interrupted.getresponse()
                assert interrupted_response.status == 200
                assert interrupted_response.read(5) == b'brows'
                interrupted.close()
                code, download_headers, payload = request('GET', download['url'])
                assert code == 200 and payload == b'browser attachment payload\n'
                assert download_headers['cache-control'] == 'no-store'
                assert download_headers['content-type'] == 'application/octet-stream'
                assert download_headers['content-length'] == str(len(payload))
                disposition = download_headers['content-disposition']
                assert 'attachment;' in disposition and 'filename*=UTF-8' in disposition
                assert '%3Cincoming%3E.txt' in disposition and '\r' not in disposition and '\n' not in disposition
                retry_code, _, retry_payload = request('GET', download['url'])
                assert retry_code == 200 and retry_payload == payload, 'ready download was not retryable'
                range_code, range_headers, range_payload = request(
                    'GET', download['url'], headers={'Range': 'bytes=8-17'})
                assert range_code == 206 and range_payload == payload[8:18]
                assert range_headers['content-range'] == f'bytes 8-17/{len(payload)}'
                assert range_headers['accept-ranges'] == 'bytes'
                web_download = next(value for value in daemon.requests if value['command'] == 'web_download')
                assert set(web_download) == {'command', 'offer', 'output'}
                assert web_download['offer'] == 'private-token'
                output_path = pathlib.Path(web_download['output'])
                assert output_path.parent.parent == root / 'web-downloads-v2'
                assert output_path.exists(), 'retryable ready file was removed after serving'

                retry_offer = {'type': 'attachment_offer', 'from': 'retry-peer', 'timestamp_ms': 5,
                               'name': 'retry.txt', 'kind': 'file', 'size': 27,
                               'offer_id': 'retry-id', 'offer': 'retry-token', 'ticket': 'private-ticket'}
                daemon.broadcast(retry_offer)
                retry_ids = []
                for response in [feed, other_tab]:
                    retry_ids.append(next_event(response)['download_id'])
                code, first_retry = api({'command': 'download', 'id': retry_ids[0]})
                assert code == 202
                deadline = time.monotonic() + 5
                while True:
                    code, failed = api({'command': 'download_status', 'id': first_retry['id']})
                    if code == 422:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                code, second_retry = api({'command': 'download', 'id': retry_ids[0]})
                assert code == 202, 'definitely-not-started failure consumed the offer handle'
                deadline = time.monotonic() + 5
                while True:
                    code, retried = api({'command': 'download_status', 'id': second_retry['id']})
                    if retried.get('type') == 'download_ready':
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                assert request('GET', retried['url'])[2] == b'browser attachment payload\n'

                for schema_offer in ['missing-schema-token', 'wrong-schema-token', 'malformed-schema-token']:
                    daemon.broadcast({'type': 'attachment_offer', 'from': schema_offer,
                                      'timestamp_ms': 6, 'name': 'schema.txt', 'kind': 'file',
                                      'size': 27, 'offer_id': 'schema-id', 'offer': schema_offer,
                                      'ticket': 'private-ticket'})
                    schema_ids = [next_event(response)['download_id'] for response in [feed, other_tab]]
                    code, schema_started = api({'command': 'download', 'id': schema_ids[0]})
                    assert code == 202
                    deadline = time.monotonic() + 5
                    while True:
                        code, schema_status = api({'command': 'download_status', 'id': schema_started['id']})
                        if code == 422:
                            break
                        assert time.monotonic() < deadline
                        time.sleep(.01)
                    schema_request = next(value for value in reversed(daemon.requests)
                                          if value.get('command') == 'web_download'
                                          and value.get('offer') == schema_offer)
                    assert not pathlib.Path(schema_request['output']).exists(), 'invalid IPC success exposed a file'

                shared = {'type': 'attachment_shared', 'from': 'fake-peer', 'timestamp_ms': 3,
                          'name': 'shared-directory.tar', 'kind': 'directory_tar_v1', 'size': 4096,
                          'offer_id': 'private-id', 'offer': 'private-token',
                          'ticket': 'private-ticket', 'path': 'private-path', 'output': 'private-output',
                          'delivery_acknowledged': True}
                daemon.broadcast(shared)
                for response in [feed, other_tab]:
                    assert next_event(response) == {
                        'type': 'attachment_shared', 'schema_version': 2,
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'direction': 'outgoing', 'from': 'fake-peer',
                        'timestamp_ms': 3, 'name': 'shared-directory.tar',
                        'kind': 'directory_tar_v1', 'size': 4096}

                incoming = {'type': 'attachment_offer', 'from': 'another-peer', 'timestamp_ms': 4,
                            'name': 'incoming-directory.tar', 'kind': 'directory_tar_v1', 'size': 8192,
                            'offer_id': 'private-id', 'offer': 'private-token', 'ticket': 'private-ticket'}
                daemon.broadcast(incoming)
                for response in [feed, other_tab]:
                    directory = next_event(response)
                    directory_id = directory.pop('download_id')
                    assert len(directory_id) == 32
                    assert directory == {
                        'type': 'attachment_offer', 'schema_version': 2,
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'direction': 'incoming', 'from': 'another-peer',
                        'timestamp_ms': 4, 'name': 'incoming-directory.tar',
                        'kind': 'directory_tar_v1', 'size': 8192}

                time.sleep(1.05)
                synced = 'sent-from-another-web-tab'
                assert api({'command': 'send', 'body': synced}) == (200, {'type': 'queued', 'delivery_acknowledged': False})
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value == {
                        'type': 'queued', 'schema_version': 2,
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'from': 'fake-peer', 'body': synced,
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
                    assert value == {
                        'type': 'queued', 'schema_version': 2,
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'from': 'fake-peer', 'body': chat_body,
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

                late_feed = open_feed()
                assert next_event(late_feed)['type'] == 'connected'
                assert next_event(late_feed)['type'] == 'peers_snapshot'
                daemon.broadcast({'type': 'attachment_offer', 'from': 'late-peer', 'timestamp_ms': 9,
                                  'name': 'late.txt', 'kind': 'file', 'size': 19,
                                  'offer_id': 'late-id', 'offer': 'late-token', 'ticket': 'private-ticket'})
                while True:
                    late_event = next_event(late_feed)
                    if late_event.get('from') == 'late-peer':
                        late_id = late_event['download_id']
                        break
                code, late_started = api({'command': 'download', 'id': late_id})
                assert code == 202
                deadline = time.monotonic() + 5
                while True:
                    matches = [value for value in daemon.requests
                               if value.get('command') == 'web_download' and value.get('offer') == 'late-token']
                    if matches:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                late_output = pathlib.Path(matches[0]['output'])
                late_feed.close()
                web.send_signal(signal.SIGINT)
                assert web.wait(timeout=5) == 0
                time.sleep(.5)
                assert late_output.read_bytes() == b'late daemon export\n', 'web shutdown raced late daemon export'
                web = subprocess.Popen([BIN, '--state-dir', str(root), 'web', '--listen', f'127.0.0.1:{port}', '--origin', public], stdout=log, stderr=log)
                deadline = time.monotonic() + 15
                while True:
                    assert web.poll() is None, 'web restart failed after late export'
                    try:
                        if api({'command': 'status'})[0] == 200:
                            break
                    except ConnectionRefusedError:
                        pass
                    assert time.monotonic() < deadline
                    time.sleep(.05)
                assert late_output.exists(), 'new web process removed a possibly active prior root'
                web.send_signal(signal.SIGINT)
                assert web.wait(timeout=5) == 0
                # Web shutdown must leave the separate daemon endpoint usable.
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(root / 'daemon.sock'))
                    client.sendall(b'{"command":"status"}\n')
                    assert json.loads(client.recv(4096))['running'] is True
                print('PASS: HTTP security/allowlist/assets, bounded browser attachment uploads and negotiated opaque retryable/ranged downloads with safe staging/headers, UTF-8/body bounds/timeouts, throttle, queued/rejected/unknown outcomes, local CLI/chat/web sends, reconstructed peer snapshots/lifecycle without endpoints or private bodies, safe attachment metadata synchronized to simultaneous SSE feeds, SSE framing/capacity/cleanup, offline/restart, independent web shutdown')
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
