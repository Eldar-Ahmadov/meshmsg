#!/usr/bin/env python3
"""Linux/macOS HTTP + Unix IPC bridge checks; no Tailscale or network peers required."""
import contextlib
import hashlib
import http.client
import json
import os
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
            value.setdefault('offer_id', value['message_id'])
        if value.get('type') == 'attachment_shared':
            value.setdefault('source_digest', '0' * 64)
    return value


class Daemon(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True

    def __init__(self, path, signer_state):
        self.signer_state = pathlib.Path(signer_state)
        self.fixture_root = pathlib.Path(path).parent / 'signed-offer-fixtures'
        self.fixture_root.mkdir(exist_ok=True)
        self.offer_labels = {}
        self.offer_events = {}
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
        initial_path = self.fixture_root / 'incoming.txt'
        initial_path.write_bytes(b'browser attachment payload\n')
        self.initial_offer = self.signed_event(
            initial_path, '0123456789abcdef0123456789abcdef', incoming=True,
            label='private-token')

    def signed_event(self, path, operation_id, *, incoming=False, label=None):
        path = pathlib.Path(path)
        directory = path.is_dir()
        name = f'{path.name}.tar' if directory else path.name
        size = sum(item.stat().st_size for item in path.rglob('*') if item.is_file()) if directory else path.stat().st_size
        environment = dict(os.environ, MESHMSG_TEST_FIXTURE_SIGNER='1')
        completed = subprocess.run(
            [BIN, '--state-dir', str(self.signer_state), '--json',
             'test-sign-attachment-fixture', '--operation-id', operation_id,
             '--name', name, '--size', str(size),
             '--kind', 'directory_tar_v1' if directory else 'file'],
            env=environment, text=True, capture_output=True, check=True, timeout=10)
        value = json.loads(completed.stdout)
        value.update({
            'type': 'attachment_shared', 'schema_version': 3,
            'operation_id': value['message_id'], 'source_digest': '0' * 64,
            'delivery_acknowledged': False,
        })
        if label is not None:
            self.offer_labels[value['offer']] = label
        self.offer_events[value['offer']] = dict(value)
        if incoming:
            value['type'] = 'attachment_offer'
            value['schema_version'] = 2
            for field in ['operation_id', 'source_digest', 'delivery_acknowledged']:
                value.pop(field, None)
        return value

    def fixture_offer(self, name, operation_id, *, size=27, kind='file', label=None):
        path = self.fixture_root / name
        if kind == 'directory_tar_v1':
            path.mkdir(exist_ok=True)
            (path / 'payload.txt').write_bytes(b'x' * size)
        else:
            path.write_bytes(b'x' * size)
        return self.signed_event(path, operation_id, incoming=True, label=label)

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
                capabilities = ['peer_directory_v2', 'web_share_v1',
                                'idempotent_attachment_operations_v1']
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
                label = self.server.offer_labels.get(offer, offer)
                self.server.web_download_attempts[label] = self.server.web_download_attempts.get(label, 0) + 1
                if label == 'retry-token' and self.server.web_download_attempts[label] == 1:
                    emit({'type': 'error', 'schema_version': 1,
                          'code': 'attachment_storage_busy',
                          'operation_id': value['operation_id'],
                          'message': 'Local capacity is currently unavailable.',
                          'outcome': 'not_started', 'retryable': True})
                    return
                output = pathlib.Path(value['output'])
                if (label == 'late-token'
                        and self.server.web_download_attempts[label] == 1):
                    def late_export():
                        time.sleep(.3)
                        output.parent.mkdir(parents=True, exist_ok=True)
                        output.write_bytes(b'browser attachment payload\n')
                    threading.Thread(target=late_export, daemon=True).start()
                    return  # Accepted, but IPC reply is lost before completion.

                assert output.parent.parent.name == 'web-downloads-v2'
                assert output.name.endswith('.blob') and '..' not in output.name
                output.write_bytes(b'browser attachment payload\n')
                if label == 'missing-schema-token':
                    emit({'type': 'download_complete', '_omit_schema': True})
                elif label == 'wrong-schema-token':
                    emit({'type': 'download_complete', 'schema_version': 1})
                elif label == 'malformed-schema-token':
                    emit({'type': 'download_complete', 'schema_version': '2'})
                else:
                    signed = self.server.offer_events[offer]
                    token_bytes = offer.encode()
                    token_digest = hashlib.sha256(
                        b'meshmsg-download-token-v1\0'
                        + len(token_bytes).to_bytes(8, 'little') + token_bytes).hexdigest()
                    emit({'type': 'download_complete', 'schema_version': 2,
                          'operation_id': value['operation_id'],
                          'token_digest': token_digest,
                          'offer_id': signed['offer_id'],
                          'name': signed['name'], 'kind': signed['kind'],
                          'size': output.stat().st_size, 'from': signed['from'],
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
                shared = self.server.signed_event(path, operation_id)
                shared['source_digest'] = source_digest
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
                capabilities = (
                    ['web_download_v1', 'idempotent_attachment_operations_v1']
                    if self.server.web_download_capability else []
                )
                emit({'type': 'connected', 'peer': SELF_KEY,
                      'endpoint_online': not self.server.malformed_handshake,
                      'topic_joined': True, 'alias': 'local-node',
                      'ipc_capabilities': capabilities})
                emit(malicious_peers_snapshot())
                emit(dict(self.server.initial_offer))
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
        signer_state = root / 'offer-signer'
        subprocess.run(
            [BIN, 'init', '--state-dir', str(signer_state), '--json', '--no-default-alias'],
            check=True, capture_output=True, text=True)
        signer_config = json.loads((signer_state / 'config.json').read_text())
        (root / 'config.json').write_text(json.dumps({
            'advertise_self': True, 'topic': signer_config['topic'], 'invite': None}))
        daemon = Daemon(root / 'daemon.sock', signer_state)
        signed_provider = daemon.initial_offer['from']
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
                        'direction': 'incoming', 'from': signed_provider,
                        'timestamp_ms': daemon.initial_offer['timestamp_ms'],
                        'name': 'incoming.txt', 'kind': 'file', 'size': 27}
                    assert daemon.initial_offer['offer'] not in json.dumps(attachment)
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

                malformed_offer = dict(daemon.initial_offer)
                malformed_offer['offer_id'] = malformed_offer['offer_id'].upper()
                daemon.broadcast(malformed_offer)
                for response in [feed, other_tab]:
                    diagnostic = next_event(response)
                    assert diagnostic == {
                        'type': 'error', 'schema_version': 1,
                        'code': 'internal_contract_error',
                        'message': 'An internal contract error occurred.',
                        'outcome': 'unknown', 'retryable': False,
                        'suppressed_since_last': 0}
                    assert 'download_id' not in diagnostic
                daemon.broadcast({'type': 'message', 'from': REMOTE_KEY,
                                  'message_id': '4123456789abcdef0123456789abcdef',
                                  'body': 'feed survived malformed attachment',
                                  'timestamp_ms': int(time.time() * 1000)})
                for response in [feed, other_tab]:
                    continued = next_event(response)
                    assert continued['type'] == 'message'
                    assert continued['body'] == 'feed survived malformed attachment'

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
                        'direction': 'outgoing', 'from': signed_provider,
                        'timestamp_ms': daemon.share_operations[upload_operation_id][1]['timestamp_ms'], 'name': upload_name,
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
                assert pathlib.Path(mismatch_request['path']).exists(), \
                    'unknown malformed share outcome was not retained for race-safe cleanup'

                download_operation = '40000000000000000000000000000001'
                start_barrier = threading.Barrier(3)
                concurrent_starts = []
                def concurrent_start():
                    start_barrier.wait()
                    concurrent_starts.append(api({
                        'command': 'download', 'id': incoming_download_ids[0],
                        'operation_id': download_operation}))
                start_threads = [threading.Thread(target=concurrent_start) for _ in range(2)]
                for thread in start_threads:
                    thread.start()
                start_barrier.wait()
                for thread in start_threads:
                    thread.join()
                assert len(concurrent_starts) == 2
                assert all(code == 202 and value['type'] == 'download_started'
                           for code, value in concurrent_starts)
                assert concurrent_starts[0][1]['id'] == concurrent_starts[1][1]['id']
                code, started = concurrent_starts[0]
                assert (started['operation_id'] == started['id'] == download_operation
                        and started['poll_timeout_ms'] == 71 * 60 * 1000)
                deadline = time.monotonic() + 5
                while True:
                    code, download = api({'command': 'download_status', 'id': started['id']})
                    if download.get('type') == 'download_ready':
                        break
                    assert (code == 200 and download['type'] == 'download_pending'
                            and download['operation_id'] == download['id'] == download_operation)
                    assert time.monotonic() < deadline, 'web download did not become ready'
                    time.sleep(.01)
                assert (download['operation_id'] == download['id'] == download_operation
                        and download['url'] == f'/api/download/{download_operation}')
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
                assert 'incoming.txt' in disposition and '\r' not in disposition and '\n' not in disposition
                retry_code, _, retry_payload = request('GET', download['url'])
                assert retry_code == 200 and retry_payload == payload, 'ready download was not retryable'
                range_code, range_headers, range_payload = request(
                    'GET', download['url'], headers={'Range': 'bytes=8-17'})
                assert range_code == 206 and range_payload == payload[8:18]
                assert range_headers['content-range'] == f'bytes 8-17/{len(payload)}'
                assert range_headers['accept-ranges'] == 'bytes'
                web_download = next(value for value in daemon.requests if value['command'] == 'web_download')
                assert set(web_download) == {'command', 'operation_id', 'offer', 'output'}
                assert web_download['operation_id'] == download_operation
                assert daemon.offer_labels[web_download['offer']] == 'private-token'
                output_path = pathlib.Path(web_download['output'])
                assert output_path.parent.parent == root / 'web-downloads-v2'
                assert output_path.exists(), 'retryable ready file was removed after serving'
                duplicate_code, duplicate_started = api({
                    'command': 'download', 'id': incoming_download_ids[0],
                    'operation_id': download_operation})
                assert duplicate_code == 202 and duplicate_started['id'] == started['id']
                assert daemon.web_download_attempts['private-token'] == 1, \
                    'duplicate browser start repeated daemon export work'

                retry_offer = daemon.fixture_offer(
                    'retry.txt', '30000000000000000000000000000001',
                    label='retry-token')
                daemon.broadcast(retry_offer)
                retry_ids = []
                for response in [feed, other_tab]:
                    retry_ids.append(next_event(response)['download_id'])
                conflict_code, conflict = api({
                    'command': 'download', 'id': retry_ids[0],
                    'operation_id': download_operation})
                assert conflict_code == 409 and conflict['code'] == 'operation_id_conflict'
                assert conflict['operation_id'] == download_operation
                assert daemon.web_download_attempts.get('retry-token', 0) == 0
                retry_operation = '40000000000000000000000000000002'
                code, first_retry = api({'command': 'download', 'id': retry_ids[0],
                                         'operation_id': retry_operation})
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
                code, cached_retry = api({'command': 'download', 'id': retry_ids[0],
                                          'operation_id': retry_operation})
                assert code == 202 and cached_retry['id'] == first_retry['id']
                code, cached_failure = api({'command': 'download_status', 'id': cached_retry['id']})
                assert code == 422 and cached_failure == failed
                assert daemon.web_download_attempts['retry-token'] == 1, 'cached failure repeated daemon work'
                second_operation = '40000000000000000000000000000003'
                code, second_retry = api({'command': 'download', 'id': retry_ids[0],
                                          'operation_id': second_operation})
                assert code == 202, 'new operation could not retry a definitely-not-started failure'
                deadline = time.monotonic() + 5
                while True:
                    code, retried = api({'command': 'download_status', 'id': second_retry['id']})
                    if retried.get('type') == 'download_ready':
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                assert request('GET', retried['url'])[2] == b'browser attachment payload\n'

                for schema_index, schema_offer in enumerate(
                        ['missing-schema-token', 'wrong-schema-token', 'malformed-schema-token'], 2):
                    daemon.broadcast(daemon.fixture_offer(
                        f'schema-{schema_index}.txt', f'{0x30000000000000000000000000000000 + schema_index:032x}',
                        label=schema_offer))
                    schema_ids = [next_event(response)['download_id'] for response in [feed, other_tab]]
                    code, schema_started = api({
                        'command': 'download', 'id': schema_ids[0],
                        'operation_id': f'{0x40000000000000000000000000000010 + schema_index:032x}'})
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
                                          and daemon.offer_labels.get(value.get('offer')) == schema_offer)
                    assert pathlib.Path(schema_request['output']).exists(), \
                        'unknown malformed reply did not quarantine possible late output'
                    assert code == 422 and schema_status['outcome'] == 'unknown'

                shared_path = daemon.fixture_root / 'shared-directory'
                shared_path.mkdir(exist_ok=True)
                (shared_path / 'payload.txt').write_bytes(b'x' * 4096)
                shared = daemon.signed_event(
                    shared_path, '30000000000000000000000000000005')
                daemon.broadcast(shared)
                for response in [feed, other_tab]:
                    assert next_event(response) == {
                        'type': 'attachment_shared', 'schema_version': 3,
                        'operation_id': shared['operation_id'],
                        'message_id': shared['message_id'],
                        'direction': 'outgoing', 'from': signed_provider,
                        'timestamp_ms': shared['timestamp_ms'], 'name': shared['name'],
                        'kind': 'directory_tar_v1', 'size': shared['size']}

                incoming = daemon.fixture_offer(
                    'incoming-directory', '30000000000000000000000000000006',
                    size=8192, kind='directory_tar_v1')
                daemon.broadcast(incoming)
                for response in [feed, other_tab]:
                    directory = next_event(response)
                    directory_id = directory.pop('download_id')
                    assert len(directory_id) == 32
                    assert directory == {
                        'type': 'attachment_offer', 'schema_version': 2,
                        'message_id': incoming['message_id'],
                        'direction': 'incoming', 'from': signed_provider,
                        'timestamp_ms': incoming['timestamp_ms'], 'name': incoming['name'],
                        'kind': 'directory_tar_v1', 'size': incoming['size']}

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
                daemon = Daemon(root / 'daemon.sock', signer_state)
                assert api({'command': 'status'})[0] == 200
                restarted = open_feed()
                assert next_event(restarted)['type'] == 'connected'
                restarted.close()

                # Replace the stopped daemon's complete state/topic while the
                # web process survives. A new subscription must bind the new
                # topic, reject an old-topic token, and admit both directions.
                old_topic_offer = daemon.fixture_offer(
                    'old-topic.txt', '30000000000000000000000000000008')
                daemon.close()
                replacement_state = root / 'replacement-signer'
                subprocess.run(
                    [BIN, 'init', '--state-dir', str(replacement_state), '--json',
                     '--no-default-alias'], check=True, capture_output=True, text=True)
                replacement_config = json.loads(
                    (replacement_state / 'config.json').read_text())
                assert replacement_config['topic'] != signer_config['topic']
                (root / 'config.json').write_text(json.dumps(replacement_config))
                daemon = Daemon(root / 'daemon.sock', replacement_state)
                signed_provider = daemon.initial_offer['from']
                assert web.poll() is None, 'web process did not survive topic replacement'
                replacement_feed = open_feed()
                assert next_event(replacement_feed)['type'] == 'connected'
                assert next_event(replacement_feed)['type'] == 'peers_snapshot'
                for expected_type in ['attachment_offer', 'message', 'lagged', 'peer_discovered']:
                    assert next_event(replacement_feed)['type'] == expected_type
                daemon.broadcast(old_topic_offer)
                rejected = next_event(replacement_feed)
                assert rejected['type'] == 'error', rejected
                assert rejected['code'] == 'internal_contract_error'
                new_topic_offer = daemon.fixture_offer(
                    'new-topic.txt', '30000000000000000000000000000009')
                daemon.broadcast(new_topic_offer)
                accepted = next_event(replacement_feed)
                assert accepted['type'] == 'attachment_offer'
                assert accepted['message_id'] == new_topic_offer['message_id']
                assert accepted['from'] == signed_provider
                replacement_upload_id = '3000000000000000000000000000000a'
                replacement_payload = b'new topic browser share\n'
                code, _, replacement_response = request(
                    'POST', '/api/attachment', raw=replacement_payload,
                    headers={
                        'Origin': origin, 'Content-Type': 'application/octet-stream',
                        'X-Meshmsg-File-Name': 'new-topic-share.txt',
                        'X-Meshmsg-Operation-Id': replacement_upload_id,
                    })
                assert code == 200
                shared_response = response_json(replacement_response)
                assert shared_response['operation_id'] == replacement_upload_id
                assert shared_response['message_id'] == replacement_upload_id
                shared_event = next_event(replacement_feed)
                assert shared_event['type'] == 'attachment_shared'
                assert shared_event['operation_id'] == replacement_upload_id
                assert shared_event['message_id'] == replacement_upload_id
                assert shared_event['from'] == signed_provider
                replacement_feed.close()

                late_feed = open_feed()
                assert next_event(late_feed)['type'] == 'connected'
                assert next_event(late_feed)['type'] == 'peers_snapshot'
                late_offer = daemon.fixture_offer(
                    'late.txt', '30000000000000000000000000000007',
                    size=27, label='late-token')
                daemon.broadcast(late_offer)
                while True:
                    late_event = next_event(late_feed)
                    if late_event.get('name') == 'late.txt':
                        assert late_event.get('from') == signed_provider
                        late_id = late_event['download_id']
                        break
                code, late_started = api({
                    'command': 'download', 'id': late_id,
                    'operation_id': '40000000000000000000000000000020'})
                assert code == 202
                deadline = time.monotonic() + 5
                while True:
                    matches = [value for value in daemon.requests
                               if value.get('command') == 'web_download'
                               and daemon.offer_labels.get(value.get('offer')) == 'late-token']
                    if matches:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                late_output = pathlib.Path(matches[0]['output'])
                deadline = time.monotonic() + 5
                while True:
                    status_code, late_status = api({
                        'command': 'download_status', 'id': late_started['id']})
                    if status_code == 422:
                        break
                    assert time.monotonic() < deadline
                    time.sleep(.01)
                assert late_status['outcome'] == 'unknown'
                time.sleep(.5)
                code, reconciled_start = api({
                    'command': 'download', 'id': late_id,
                    'operation_id': '40000000000000000000000000000020'})
                assert code == 202 and reconciled_start['id'] == late_started['id']
                deadline = time.monotonic() + 5
                while True:
                    status_code, reconciled = api({
                        'command': 'download_status', 'id': reconciled_start['id']})
                    if reconciled.get('type') == 'download_ready':
                        break
                    assert status_code == 200 and time.monotonic() < deadline
                    time.sleep(.01)
                assert daemon.web_download_attempts['late-token'] == 2
                assert request('GET', reconciled['url'])[2] == b'browser attachment payload\n'
                late_feed.close()
                web.send_signal(signal.SIGINT)
                assert web.wait(timeout=5) == 0
                assert late_output.read_bytes() == b'browser attachment payload\n', 'web shutdown raced reconciled export'
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
                print('PASS: isolated offline signed fixtures, HTTP security/allowlist/assets, bounded browser attachment uploads and negotiated opaque retryable/ranged downloads with safe staging/headers, UTF-8/body bounds/timeouts, throttle, queued/rejected/unknown outcomes, local CLI/chat/web sends, reconstructed peer snapshots/lifecycle without endpoints or private bodies, safe attachment metadata synchronized to simultaneous SSE feeds, SSE framing/capacity/cleanup, live web-process daemon topic replacement with old-topic rejection and correlated new-topic offer/share delivery, offline/restart, independent web shutdown')
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
