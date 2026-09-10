#!/usr/bin/env python3
"""Linux/macOS HTTP + Unix IPC bridge checks; no Tailscale or network peers required."""
import contextlib
import hashlib
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
    # Despite the historical helper name this is now the exact strict DTO;
    # separate malformed-reply cases verify fail-closed handling.
    return {
        'type': 'peers_snapshot', 'schema_version': 2, 'generated_at_ms': 1000,
        'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 0,
        'self': {'public_key': SELF_KEY, 'alias': 'local-node', 'online': True},
        'peers': [{
            'public_key': REMOTE_KEY, 'alias': 'remote-node', 'online': True,
            'last_seen_ms': 900, 'expires_at_ms': 150900,
        }],
    }


def canonical_broadcast_event(value):
    if value.get('type') in {'message', 'queued', 'attachment_offer', 'attachment_shared'}:
        value.setdefault('schema_version', 3 if value.get('type') in {'queued', 'attachment_shared'} else 2)
        value.setdefault('message_id', '0123456789abcdef0123456789abcdef')
        if value.get('type') in {'queued', 'attachment_shared'}:
            value.setdefault('operation_id', value['message_id'])
        if value.get('type') in {'attachment_offer', 'attachment_shared'}:
            value['offer_id'] = value['message_id']
        if value.get('type') == 'attachment_shared':
            value.setdefault('source_digest', '0' * 64)
    return value


class Daemon(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path):
        self.requests = []
        self.operations = {}
        self.share_operations = {}
        self.idempotency_capability = True
        self.web_download_attempts = {}
        self.web_download_capability = True
        self.malformed_handshake = False
        self.clients = set()
        self.subscribers = {}
        self.lock = threading.Lock()
        super().__init__(str(path), Handler)
        self.thread = threading.Thread(target=self.serve_forever, daemon=True)
        self.thread.start()

    def broadcast(self, value):
        with self.lock:
            subscribers = list(self.subscribers.items())
        for client, request_id in subscribers:
            try:
                event = canonical_broadcast_event(dict(value))
                event.setdefault('schema_version', 1)
                event['request_id'] = request_id
                client.sendall(json.dumps(event).encode() + b'\n')
            except OSError:
                with self.lock:
                    self.subscribers.pop(client, None)

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
            envelope = json.loads(self.rfile.readline())
            assert set(envelope) == {'schema_version', 'request_id', 'request'}
            assert envelope['schema_version'] == 1
            request_id = envelope['request_id']
            value = envelope['request']
            self.server.requests.append(value)


            assert len(request_id) == 32 and request_id == request_id.lower()

            def emit(value):
                omit_schema = value.pop('_omit_schema', False)
                value = canonical_broadcast_event(value)
                if not omit_schema:
                    value.setdefault('schema_version', 1)
                value['request_id'] = request_id
                self.wfile.write(json.dumps(value).encode() + b'\n')
                self.wfile.flush()

            if value['command'] == 'status':
                capabilities = ['peer_directory_v2', 'web_share_v1']
                if self.server.idempotency_capability:
                    capabilities.append('idempotent_mutations_v1')
                capabilities.append('typed_contracts_v1')
                emit({'type': 'status', 'running': True, 'peer': SELF_KEY,
                      'topic': '00' * 32, 'advertises_self': False, 'has_invite': True,
                      'bootstrap_peer_count': 1, 'self_advertised': False, 'neighbors': 1,
                      'endpoint_online': True, 'topic_joined': True, 'alias': 'local-node',
                      'alias_enabled': True, 'captured_hostname': 'local-node',
                      'custom_alias': None, 'advertised_aliases': 1,
                      'ipc_capabilities': capabilities,
                      'operation_cache_capacity': 1024, 'operation_cache_ttl_ms': 600000,
                      'operation_cache_persistent': False, 'direct_replay_available': True,
                      'direct_replay_error': None, 'direct_replay_capacity': 8192,
                      'direct_replay_per_sender_capacity': 512, 'direct_replay_queue_capacity': 64,
                      'direct_replay_global_rate_per_second': 128,
                      'direct_replay_global_rate_burst': 256,
                      'direct_replay_sender_rate_per_second': 8,
                      'direct_replay_sender_rate_burst': 16,
                      'max_attachment_bytes': 1024 * 1024,
                      'attachment_storage': {'tagged_bytes': 0, 'tagged_blobs': 0, 'tags': 0,
                          'tag_capacity': 8192, 'quota_bytes': 1024 * 1024,
                          'available_bytes': 1024 * 1024, 'min_free_bytes': 0,
                          'pressure': False, 'over_quota': False, 'below_min_free': False,
                          'sampled_at_ms': 1},
                      'attachment_retention_secs': 0})
            elif value['command'] == 'peers':
                emit(malicious_peers_snapshot())
            elif value['command'] == 'web_download':
                offer = value['offer']
                self.server.web_download_attempts[offer] = self.server.web_download_attempts.get(offer, 0) + 1
                if offer == 'retry-token' and self.server.web_download_attempts[offer] == 1:
                    emit({'type': 'error', 'schema_version': 1,
                          'code': 'attachment_storage_busy',
                          'message': 'Local capacity is currently unavailable.',
                          'outcome': 'not_started', 'retryable': True})
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
                    emit({'type': 'download_complete', '_omit_schema': True})
                elif offer == 'wrong-schema-token':
                    emit({'type': 'download_complete', 'schema_version': 2})
                elif offer == 'malformed-schema-token':
                    emit({'type': 'download_complete', 'schema_version': '1'})
                else:
                    names = {
                        'private-token': '<incoming>.txt',
                        'retry-token': 'retry.txt',
                        'late-token': 'late.txt',
                    }
                    emit({'type': 'download_complete', 'schema_version': 1,
                          'offer_id': '0123456789abcdef0123456789abcdef',
                          'name': names.get(offer, 'schema.txt'), 'kind': 'file',
                          'size': output.stat().st_size, 'from': REMOTE_KEY,
                          'output': str(output), 'installed': True, 'pinned': True,
                          'destination_synced': True, 'cleanup_complete': True,
                          'warnings': []})
            elif value['command'] == 'share':
                path = pathlib.Path(value['path'])
                assert path.parent.parent.parent == pathlib.Path(self.server.server_address).parent / 'web-uploads-v1'
                payload = path.read_bytes()
                operation_id = value['operation_id']
                source_digest = value['source_digest']
                fingerprint = (path.name, len(payload), source_digest)
                previous = self.server.share_operations.get(operation_id)
                if previous:
                    if previous[0] != fingerprint:
                        emit({'type': 'error', 'schema_version': 1,
                              'code': 'operation_id_conflict', 'operation_id': operation_id,
                              'message': 'The operation ID is bound to different input.',
                              'outcome': 'not_started', 'retryable': False})
                    else:
                        emit(previous[1])
                    return
                shared = {'type': 'attachment_shared', 'schema_version': 3,
                          'operation_id': operation_id, 'message_id': operation_id,
                          'offer_id': operation_id, 'source_digest': source_digest,
                          'from': SELF_KEY,
                          'timestamp_ms': 1700000000001, 'name': path.name, 'kind': 'file',
                          'size': len(payload), 'offer': 'private-offer', 'ticket': 'private-ticket',
                          'delivery_acknowledged': False}
                if path.name == 'post-broadcast-failure.txt':
                    outcome = {'type': 'error', 'schema_version': 1,
                               'code': 'share_failed', 'operation_id': operation_id,
                               'message': 'Attachment sharing failed.',
                               'outcome': 'unknown', 'retryable': True}
                    self.server.share_operations[operation_id] = (fingerprint, outcome)
                    self.server.broadcast(shared)
                    emit(outcome)
                elif path.name == 'mismatched-success.txt':
                    shared['name'] = 'wrong-name.txt'
                    self.server.share_operations[operation_id] = (fingerprint, shared)
                    emit(shared)
                else:
                    self.server.share_operations[operation_id] = (fingerprint, shared)
                    self.server.broadcast(shared)
                    emit(shared)
            elif value['command'] == 'send':
                operation_id = value['operation_id']
                if operation_id in self.server.operations:
                    previous_body, previous_outcome = self.server.operations[operation_id]
                    if previous_body != value['body']:
                        emit({'type': 'error', 'schema_version': 1,
                              'code': 'operation_id_conflict', 'operation_id': operation_id,
                              'message': 'The operation ID is bound to different input.',
                              'outcome': 'not_started', 'retryable': False})
                    else:
                        emit(previous_outcome)
                    return
                if value['body'] == 'reject':
                    outcome = {'type': 'error', 'schema_version': 1, 'code': 'send_failed',
                               'operation_id': operation_id, 'message': 'Message submission failed.',
                               'outcome': 'unknown', 'retryable': True}
                else:
                    outcome = {'type': 'queued', 'schema_version': 3,
                               'operation_id': operation_id, 'message_id': operation_id,
                               'from': SELF_KEY, 'body': value['body'],
                               'timestamp_ms': 1700000000000, 'delivery_acknowledged': False}
                    self.server.broadcast(outcome)
                self.server.operations[operation_id] = (value['body'], outcome)
                if value['body'] == 'lost-reply':
                    return  # The terminal outcome is cached but this reply is lost.
                emit(outcome)
            elif value['command'] == 'subscribe':
                capabilities = ['web_download_v1'] if self.server.web_download_capability else []
                emit({'type': 'connected', 'peer': SELF_KEY,
                      'endpoint_online': not self.server.malformed_handshake,
                      'topic_joined': True, 'alias': 'local-node',
                      'ipc_capabilities': capabilities})
                emit(malicious_peers_snapshot())
                emit({'type': 'attachment_offer', 'from': REMOTE_KEY, 'timestamp_ms': 2,
                      'name': '<incoming>.txt', 'kind': 'file', 'size': 1536,
                      'offer_id': '0123456789abcdef0123456789abcdef',
                      'message_id': '0123456789abcdef0123456789abcdef',
                      'offer': 'private-token', 'ticket': 'private-ticket'})
                emit({'type': 'message', 'from': REMOTE_KEY,
                      'message_id': '1123456789abcdef0123456789abcdef',
                      'body': '<img src=x onerror=alert(1)>\ndata: injected', 'timestamp_ms': 1})
                emit({'type': 'lagged', 'source': 'local', 'dropped': 3,
                      'message': 'local listener missed 3 events'})
                emit({
                    'type': 'peer_discovered', 'schema_version': 2,
                    'directory_epoch': 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', 'directory_revision': 1,
                    'peer': {
                        'public_key': EVENT_KEY, 'alias': 'event-node', 'online': True,
                        'last_seen_ms': 950, 'expires_at_ms': 150950,
                    },
                })
                with self.server.lock:
                    self.server.subscribers[self.request] = request_id
                self.rfile.read(1)  # Remain subscribed until web disconnects.
            else:
                raise AssertionError(f'web leaked command: {value}')
        except (BrokenPipeError, ConnectionResetError):
            pass
        finally:
            with self.server.lock:
                self.server.subscribers.pop(self.request, None)
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

            request_counter = 0

            def request(method='POST', path='/api/request', value=None, headers=None, raw=None):
                nonlocal request_counter
                request_counter += 1
                request_id = f'{request_counter:032x}'
                command = dict(value or {'command': 'status'})
                payload = {'schema_version': 1, 'request_id': request_id, 'request': command}
                body = raw if raw is not None else json.dumps(payload)
                actual_headers = {'Origin': origin, 'Content-Type': 'application/json'} if headers is None else dict(headers)
                if method == 'POST' and raw is None:
                    actual_headers.setdefault('X-Meshmsg-Request-Id', request_id)
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                conn.request(method, path, body if method == 'POST' else None, actual_headers)
                response = conn.getresponse()
                data = response.read()
                result = response.status, dict(response.getheaders()), data
                conn.close()
                return result

            def response_json(data):
                decoded = json.loads(data)
                request_id = decoded.pop('request_id')
                assert len(request_id) == 32 and request_id == request_id.lower()
                return decoded

            def api(value):
                code, headers, data = request(value=value)
                decoded = json.loads(data)
                request_id = decoded.pop('request_id')
                assert len(request_id) == 32 and request_id == headers['x-meshmsg-request-id']
                assert isinstance(decoded.get('schema_version'), int)
                return code, decoded

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
                        value = json.loads(line[6:])
                        request_id = value.pop('request_id')
                        assert len(request_id) == 32 and request_id == request_id.lower()
                        assert isinstance(value.get('schema_version'), int)
                        return value

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
                    'X-Meshmsg-File-Name': 'file.txt',
                    'X-Meshmsg-Operation-Id': '20000000000000000000000000000000'})[0] == 415
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

                # A structurally valid handshake that cannot represent a public
                # connected state must become one correlated sanitized error,
                # not panic the bridge or claim connection success.
                daemon.malformed_handshake = True
                malformed_feed = open_feed()
                malformed = next_event(malformed_feed)
                assert malformed == {
                    'type': 'error', 'schema_version': 1,
                    'code': 'invalid_daemon_response',
                    'message': 'The daemon returned an invalid response.',
                    'outcome': 'unknown', 'retryable': True}
                assert malformed_feed.readline() == b'\n'
                assert malformed_feed.readline() == b'', 'invalid handshake feed stayed open'
                malformed_feed.close()
                streams.pop()[1].close()
                daemon.malformed_handshake = False

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
                strict_id = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'
                strict_body = json.dumps({
                    'schema_version': 1, 'request_id': strict_id,
                    'request': {'command': 'status'},
                })
                base_headers = {'Origin': origin, 'Content-Type': 'application/json'}
                assert request(raw=strict_body, headers=base_headers)[0] == 400
                malformed_headers = dict(base_headers, **{'X-Meshmsg-Request-Id': 'BAD'})
                assert request(raw=strict_body, headers=malformed_headers)[0] == 400
                mismatch_headers = dict(base_headers, **{
                    'X-Meshmsg-Request-Id': 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'})
                assert request(raw=strict_body, headers=mismatch_headers)[0] == 400
                duplicate = socket.create_connection(('127.0.0.1', port), timeout=5)
                duplicate.sendall((
                    'POST /api/request HTTP/1.1\r\n'
                    f'Host: 127.0.0.1:{port}\r\n'
                    f'Origin: {origin}\r\n'
                    'Content-Type: application/json\r\n'
                    f'Content-Length: {len(strict_body.encode())}\r\n'
                    f'X-Meshmsg-Request-Id: {strict_id}\r\n'
                    'X-Meshmsg-Request-Id: bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb\r\n'
                    'Connection: close\r\n\r\n' + strict_body
                ).encode())
                duplicate_response = duplicate.recv(4096)
                duplicate.close()
                assert duplicate_response.startswith(b'HTTP/1.1 400')
                for command in ['stop', 'subscribe', 'share', 'offers', 'download', 'bench_send', 'init', 'join', 'topic']:
                    assert api({'command': command})[0] == 400
                for value in [{'command': 'status', 'path': '/etc/passwd'}, {'command': 'send', 'operation_id': '00000000000000000000000000000003', 'body': 'x', 'extra': True}]:
                    assert api(value)[0] == 400
                for operation_id, body in [
                    ('00000000000000000000000000000001', ''),
                    ('00000000000000000000000000000002', '二' * 1301),
                ]:
                    code, rejected = api({
                        'command': 'send', 'operation_id': operation_id, 'body': body})
                    assert code == 422
                    assert rejected == {
                        'type': 'error', 'schema_version': 1,
                        'code': 'invalid_message', 'operation_id': operation_id,
                        'message': 'The message is invalid.',
                        'outcome': 'not_started', 'retryable': False}
                raw_headers = dict(base_headers, **{'X-Meshmsg-Request-Id': strict_id})
                assert request(raw='{bad json', headers=raw_headers)[0] == 400
                assert request(raw='x' * 30000, headers=raw_headers)[0] == 413
                assert len(daemon.requests) == before, 'rejected HTTP request reached IPC'
                reused_http_id = '00000000000000000000000000000001'
                assert api({
                    'command': 'send', 'operation_id': reused_http_id,
                    'body': 'valid-after-http-empty-rejection'}) == (
                        200, {'type': 'queued', 'schema_version': 3,
                              'operation_id': reused_http_id,
                              'message_id': reused_http_id,
                              'delivery_acknowledged': False})

                daemon.idempotency_capability = False
                sends_before = sum(r.get('command') == 'send' for r in daemon.requests)
                code, unsupported = api({
                    'command': 'send',
                    'operation_id': '10000000000000000000000000000000',
                    'body': 'must-not-submit'})
                assert code == 422 and unsupported == {
                    'type': 'error', 'schema_version': 1,
                    'code': 'idempotency_unsupported',
                    'operation_id': '10000000000000000000000000000000',
                    'message': 'Retry-safe mutations are unsupported by the daemon.',
                    'outcome': 'not_started', 'retryable': False}
                assert sum(r.get('command') == 'send' for r in daemon.requests) == sends_before
                daemon.idempotency_capability = True
                time.sleep(1.05)

                assert api({'command': 'send', 'operation_id': '10000000000000000000000000000001', 'body': 'hello\n<script>test</script>'}) == (200, {'type': 'queued', 'schema_version': 3, 'operation_id': '10000000000000000000000000000001', 'message_id': '10000000000000000000000000000001', 'delivery_acknowledged': False})
                assert api({'command': 'send', 'operation_id': '10000000000000000000000000000002', 'body': 'too-fast'})[0] == 429
                time.sleep(1.05)
                assert api({'command': 'send', 'operation_id': '10000000000000000000000000000003', 'body': 'reject'}) == (502, {
                    'type': 'error', 'schema_version': 1, 'code': 'send_failed',
                    'operation_id': '10000000000000000000000000000003',
                    'message': 'Message submission failed.', 'outcome': 'unknown', 'retryable': True})
                time.sleep(1.05)
                assert api({'command': 'send', 'operation_id': '10000000000000000000000000000004', 'body': 'lost-reply'})[1]['outcome'] == 'unknown'
                time.sleep(1.05)
                assert api({'command': 'send', 'operation_id': '10000000000000000000000000000004', 'body': 'lost-reply'})[1]['operation_id'] == '10000000000000000000000000000004'
                time.sleep(1.05)
                assert sum(r.get('body') == 'lost-reply' for r in daemon.requests) == 2, 'retry did not reuse HTTP operation ID'

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
                        'direction': 'incoming', 'from': REMOTE_KEY,
                        'timestamp_ms': 2, 'name': '<incoming>.txt', 'kind': 'file', 'size': 1536}
                    assert 'private-token' not in json.dumps(attachment)
                    value = next_event(response)
                    assert value['type'] == 'message' and '\ndata: injected' in value['body']
                    assert next_event(response)['type'] == 'lagged'
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
                upload_operation_id = '20000000000000000000000000000001'
                upload_digest = hashlib.sha256(
                    b'meshmsg-share-source-v1\0file\0' + upload_payload).hexdigest()
                code, _, upload_response = request(
                    'POST', '/api/attachment', raw=upload_payload,
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': urllib.parse.quote(upload_name, safe="~()*!.'-"),
                             'X-Meshmsg-Operation-Id': upload_operation_id})
                assert code == 200
                assert response_json(upload_response) == {
                    'type': 'attachment_shared', 'schema_version': 3,
                    'operation_id': upload_operation_id,
                    'message_id': upload_operation_id, 'offer_id': upload_operation_id,
                    'source_digest': upload_digest,
                    'name': upload_name, 'size': len(upload_payload),
                    'delivery_acknowledged': False}
                for response in [feed, other_tab]:
                    assert next_event(response) == {
                        'type': 'attachment_shared', 'schema_version': 3,
                        'operation_id': '20000000000000000000000000000001',
                        'message_id': '20000000000000000000000000000001',
                        'direction': 'outgoing', 'from': SELF_KEY,
                        'timestamp_ms': 1700000000001, 'name': upload_name,
                        'kind': 'file', 'size': len(upload_payload)}
                upload_request = next(value for value in daemon.requests if value.get('command') == 'share')
                upload_path = pathlib.Path(upload_request['path'])
                assert not upload_path.exists(), 'completed upload staging file was retained'
                assert upload_path.name == upload_name

                retry_headers = {
                    'Origin': origin, 'Content-Type': 'application/octet-stream',
                    'X-Meshmsg-File-Name': urllib.parse.quote(upload_name, safe="~()*!.'-"),
                    'X-Meshmsg-Operation-Id': upload_operation_id}
                code, _, retry_body = request(
                    'POST', '/api/attachment', raw=upload_payload, headers=retry_headers)
                assert code == 200 and response_json(retry_body)['operation_id'] == upload_operation_id
                retry_request = [value for value in daemon.requests
                                 if value.get('command') == 'share'][-1]
                assert retry_request['path'] == str(upload_path)
                share_request_count = len([value for value in daemon.requests
                                           if value.get('command') == 'share'])
                code, _, conflict_body = request(
                    'POST', '/api/attachment', raw=b'x' * len(upload_payload), headers=retry_headers)
                conflict = response_json(conflict_body)
                assert code == 409 and conflict['code'] == 'operation_id_conflict'
                assert conflict['operation_id'] == upload_operation_id
                assert len([value for value in daemon.requests
                            if value.get('command') == 'share']) == share_request_count

                assert request(
                    'POST', '/api/attachment', raw=b'x',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': '../escape',
                             'X-Meshmsg-Operation-Id': '20000000000000000000000000000002'})[0] == 400
                assert request(
                    'POST', '/api/attachment', raw=b'x' * (1024 * 1024 + 1),
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'large.bin',
                             'X-Meshmsg-Operation-Id': '20000000000000000000000000000003'})[0] == 413

                code, _, ambiguous_body = request(
                    'POST', '/api/attachment', raw=b'ambiguous publication\n',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'post-broadcast-failure.txt',
                             'X-Meshmsg-Operation-Id': '20000000000000000000000000000004'})
                ambiguous = response_json(ambiguous_body)
                assert code == 502 and ambiguous == {
                    'type': 'error', 'schema_version': 1, 'code': 'share_failed',
                    'operation_id': '20000000000000000000000000000004',
                    'message': 'Attachment sharing failed.',
                    'outcome': 'unknown', 'retryable': True}
                assert b'/srv/meshmsg' not in ambiguous_body and b'internal route diagnostic' not in ambiguous_body
                for response in [feed, other_tab]:
                    observed = next_event(response)
                    assert observed['type'] == 'attachment_shared'
                    assert observed['name'] == 'post-broadcast-failure.txt'
                ambiguous_request = next(
                    value for value in daemon.requests
                    if pathlib.Path(value.get('path', '')).name == 'post-broadcast-failure.txt')
                assert not pathlib.Path(ambiguous_request['path']).exists()
                code, _, cached_ambiguous_body = request(
                    'POST', '/api/attachment', raw=b'ambiguous publication\n',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'post-broadcast-failure.txt',
                             'X-Meshmsg-Operation-Id': '20000000000000000000000000000004'})
                assert code == 502 and response_json(cached_ambiguous_body) == ambiguous

                forced_conflict_id = '20000000000000000000000000000006'
                daemon.share_operations[forced_conflict_id] = (
                    ('different.txt', 17, '0' * 64), {'unused': True})
                code, _, conflict_body = request(
                    'POST', '/api/attachment', raw=b'authoritative conflict',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'conflict.txt',
                             'X-Meshmsg-Operation-Id': forced_conflict_id})
                assert code == 422 and response_json(conflict_body) == {
                    'type': 'error', 'schema_version': 1,
                    'code': 'operation_id_conflict',
                    'operation_id': forced_conflict_id,
                    'message': 'The operation ID is bound to different input.',
                    'outcome': 'not_started', 'retryable': False}

                code, _, mismatch_body = request(
                    'POST', '/api/attachment', raw=b'metadata mismatch\n',
                    headers={'Origin': origin, 'Content-Type': 'application/octet-stream',
                             'X-Meshmsg-File-Name': 'mismatched-success.txt',
                             'X-Meshmsg-Operation-Id': '20000000000000000000000000000005'})
                mismatch = response_json(mismatch_body)
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

                retry_offer = {'type': 'attachment_offer', 'from': REMOTE_KEY, 'timestamp_ms': 5,
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
                assert failed['code'] == 'attachment_storage_busy'
                assert failed['outcome'] == 'not_started' and failed['retryable'] is True
                assert failed['message'] == 'Local capacity is currently unavailable.'
                assert '/home/alice' not in json.dumps(failed) and 'database diagnostic' not in json.dumps(failed)
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
                    daemon.broadcast({'type': 'attachment_offer', 'from': REMOTE_KEY,
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

                shared = {'type': 'attachment_shared', 'from': SELF_KEY, 'timestamp_ms': 3,
                          'name': 'shared-directory.tar', 'kind': 'directory_tar_v1', 'size': 4096,
                          'offer_id': 'private-id', 'offer': 'private-token',
                          'ticket': 'private-ticket', 'delivery_acknowledged': False}
                daemon.broadcast(shared)
                for response in [feed, other_tab]:
                    assert next_event(response) == {
                        'type': 'attachment_shared', 'schema_version': 3,
                        'operation_id': '0123456789abcdef0123456789abcdef',
                        'message_id': '0123456789abcdef0123456789abcdef',
                        'direction': 'outgoing', 'from': SELF_KEY,
                        'timestamp_ms': 3, 'name': 'shared-directory.tar',
                        'kind': 'directory_tar_v1', 'size': 4096}

                incoming = {'type': 'attachment_offer', 'from': REMOTE_KEY, 'timestamp_ms': 4,
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
                        'direction': 'incoming', 'from': REMOTE_KEY,
                        'timestamp_ms': 4, 'name': 'incoming-directory.tar',
                        'kind': 'directory_tar_v1', 'size': 8192}

                daemon.broadcast({
                    'type': 'error', 'schema_version': 1,
                    'code': 'internal_contract_error',
                    'message': 'An internal contract error occurred.',
                    'retryable': False, 'outcome': 'unknown',
                    'suppressed_since_last': 2})
                for response in [feed, other_tab]:
                    observed = next_event(response)
                    assert observed == {
                        'type': 'error', 'schema_version': 1,
                        'code': 'internal_contract_error',
                        'message': 'An internal contract error occurred.',
                        'retryable': False, 'outcome': 'unknown',
                        'suppressed_since_last': 2}

                time.sleep(1.05)
                synced = 'sent-from-another-web-tab'
                assert api({'command': 'send', 'operation_id': '10000000000000000000000000000005', 'body': synced})[0] == 200
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value == {
                        'type': 'queued', 'schema_version': 3,
                        'operation_id': '10000000000000000000000000000005',
                        'message_id': '10000000000000000000000000000005',
                        'from': SELF_KEY, 'body': synced,
                        'timestamp_ms': 1700000000000, 'delivery_acknowledged': False}

                with socket.socket(socket.AF_UNIX) as local_cli:
                    local_cli.connect(str(root / 'daemon.sock'))
                    local_cli.sendall(b'{"schema_version":1,"request_id":"77777777777777777777777777777777","request":{"command":"send","operation_id":"10000000000000000000000000000006","body":"sent-from-cli"}}\n')
                    assert json.loads(local_cli.recv(4096))['type'] == 'queued'
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value['type'] == 'queued' and value['body'] == 'sent-from-cli'

                chat_body = 'sent-from-chat-input'
                sends_before_chat = len([
                    request for request in daemon.requests if request.get('command') == 'send'])
                chat = subprocess.run(
                    [BIN, '--state-dir', str(root), '--json', 'chat'],
                    input='\n\n' + chat_body + '\n\n',
                    text=True, capture_output=True, timeout=15, check=False)
                assert chat.returncode == 0, chat.stderr
                chat_sends = [
                    request for request in daemon.requests if request.get('command') == 'send'][sends_before_chat:]
                assert len(chat_sends) == 1 and chat_sends[0].get('body') == chat_body
                assert len(chat_sends[0].get('operation_id', '')) == 32
                for response in [feed, other_tab]:
                    value = next_event(response)
                    assert value['type'] == 'queued' and value['schema_version'] == 3
                    assert value['operation_id'] == value['message_id']
                    assert value['from'] == SELF_KEY and value['body'] == chat_body
                    assert value['timestamp_ms'] == 1700000000000
                    assert value['delivery_acknowledged'] is False
                    assert value == {
                        'type': 'queued', 'schema_version': 3,
                        'operation_id': value['operation_id'],
                        'message_id': value['operation_id'],
                        'from': SELF_KEY, 'body': chat_body,
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
                    slow.sendall(f'POST /api/request HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nOrigin: {origin}\r\nContent-Type: application/json\r\nX-Meshmsg-Request-Id: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\r\nContent-Length: 100\r\n\r\n{{'.encode())
                    assert b'408' in slow.recv(8192)

                daemon.close()
                assert api({'command': 'status'})[0] == 503
                offline = open_feed()
                offline_event = next_event(offline)
                assert offline_event['type'] == 'error' and offline_event['code'] == 'daemon_offline'
                assert offline_event['retryable'] is True and offline_event['outcome'] == 'unknown'
                offline.close()
                daemon = Daemon(root / 'daemon.sock')
                assert api({'command': 'status'})[0] == 200
                restarted = open_feed()
                assert next_event(restarted)['type'] == 'connected'
                restarted.close()

                late_feed = open_feed()
                assert next_event(late_feed)['type'] == 'connected'
                assert next_event(late_feed)['type'] == 'peers_snapshot'
                daemon.broadcast({'type': 'attachment_offer', 'from': REMOTE_KEY, 'timestamp_ms': 9,
                                  'name': 'late.txt', 'kind': 'file', 'size': 19,
                                  'offer_id': 'late-id', 'offer': 'late-token', 'ticket': 'private-ticket'})
                while True:
                    late_event = next_event(late_feed)
                    if late_event.get('name') == 'late.txt':
                        assert late_event.get('from') == REMOTE_KEY
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
                    client.sendall(b'{"schema_version":1,"request_id":"66666666666666666666666666666666","request":{"command":"status"}}\n')
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
