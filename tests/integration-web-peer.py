#!/usr/bin/env python3
"""Real two-peer web receipt check. Requires working Iroh networking; no Tailscale changes."""
import contextlib
import hashlib
import http.client
import io
import json
import pathlib
import signal
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.parse

BIN = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else 'target/debug/meshmsg').resolve())


def main():
    with tempfile.TemporaryDirectory(prefix='meshmsg-web-peers-') as root:
        root = pathlib.Path(root)
        processes = []
        logs = []
        feeds = []

        def cli(peer, *args):
            return json.loads(subprocess.check_output([BIN, '--state-dir', str(root / peer), '--json', *args], stderr=subprocess.PIPE, timeout=15))

        def spawn(peer, *args):
            log = (root / f'{peer}-{args[0]}-{len(processes)}.log').open('w+')
            logs.append(log)
            process = subprocess.Popen([BIN, '--state-dir', str(root / peer), '--json', *args], stdout=log, stderr=log)
            processes.append(process)
            return process, log

        def wait_for(check, description, seconds=80):
            deadline = time.monotonic() + seconds
            while time.monotonic() < deadline:
                try:
                    if check():
                        return
                except (subprocess.CalledProcessError, ConnectionRefusedError, json.JSONDecodeError):
                    pass
                time.sleep(.2)
            raise AssertionError(f'timeout: {description}')

        def running(peer):
            return cli(peer, 'status')['running']

        try:
            cli('one', 'init')
            first, _ = spawn('one', 'daemon')
            wait_for(lambda: running('one'), 'first daemon startup')
            invite = cli('one', 'invite')['token']
            token_file = root / 'invite.txt'
            token_file.write_text(invite)
            cli('two', 'join', '--token-file', str(token_file))
            spawn('two', 'daemon')
            wait_for(lambda: running('two'), 'second daemon startup')
            wait_for(lambda: cli('one', 'status')['neighbors'] >= 1 and cli('two', 'status')['neighbors'] >= 1, 'peer neighbors')
            one_peer = cli('one', 'status')['peer']
            two_peer = cli('two', 'status')['peer']
            _, peer_log = spawn('two', 'listen')
            wait_for(lambda: '"type":"connected"' in pathlib.Path(peer_log.name).read_text(), 'second peer listener', 10)
            with socket.socket() as reservation:
                reservation.bind(('127.0.0.1', 0))
                port = reservation.getsockname()[1]
            origin = f'http://127.0.0.1:{port}'
            web, _ = spawn('one', 'web', '--listen', f'127.0.0.1:{port}')

            def post(value):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=15)
                conn.request('POST', '/api/request', json.dumps(value), {'Origin': origin, 'Content-Type': 'application/json'})
                response = conn.getresponse()
                result = response.status, json.loads(response.read())
                conn.close()
                return result

            operation_counter = 0
            def operation_id():
                nonlocal operation_counter
                operation_counter += 1
                return f'{operation_counter:032x}'

            def upload(name, payload, op_id=None):
                op_id = op_id or operation_id()
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
                conn.request('POST', '/api/attachment', payload, {
                    'Origin': origin, 'Content-Type': 'application/octet-stream',
                    'X-Meshmsg-File-Name': urllib.parse.quote(name, safe="~()*!.'-"),
                    'X-Meshmsg-Operation-Id': op_id})
                response = conn.getresponse()
                result = response.status, json.loads(response.read())
                conn.close()
                return result, op_id

            def submit_without_reply(value):
                with socket.socket(socket.AF_UNIX) as client:
                    client.connect(str(root / 'one' / 'daemon.sock'))
                    client.sendall(json.dumps(value).encode() + b'\n')

            def get(path):
                conn = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
                conn.request('GET', path)
                response = conn.getresponse()
                result = response.status, dict(response.getheaders()), response.read()
                conn.close()
                return result

            def browser_download(offer_id):
                code, started = post({'command': 'download', 'id': offer_id})
                assert code == 202 and started['type'] == 'download_started'
                deadline = time.monotonic() + 30
                while True:
                    code, status = post({'command': 'download_status', 'id': started['id']})
                    if status.get('type') == 'download_ready':
                        break
                    assert code == 200 and status['type'] == 'download_pending'
                    assert time.monotonic() < deadline, 'browser attachment download timeout'
                    time.sleep(.1)
                code, headers, body = get(status['url'])
                assert code == 200 and headers['cache-control'] == 'no-store'
                return headers, body

            wait_for(lambda: post({'command': 'status'})[0] == 200, 'web ready', 15)

            def assert_peer_snapshot(value):
                assert set(value) == {
                    'type', 'schema_version', 'generated_at_ms', 'directory_epoch',
                    'directory_revision', 'self', 'peers'
                }
                assert value['type'] == 'peers_snapshot' and value['schema_version'] == 2
                assert len(value['directory_epoch']) == 32
                assert isinstance(value['directory_revision'], int)
                assert set(value['self']) == {'public_key', 'alias', 'online'}
                assert value['self']['public_key'] == one_peer and value['self']['online'] is True
                assert [peer['public_key'] for peer in value['peers']] == [two_peer]
                assert set(value['peers'][0]) == {
                    'public_key', 'alias', 'online', 'last_seen_ms', 'expires_at_ms'}
                assert value['peers'][0]['online'] is True
                encoded = json.dumps(value)
                assert all(private not in encoded for private in [
                    'endpoint', 'address', 'relay', 'socket', 'invite', 'ticket', 'token', 'body'])

            wait_for(
                lambda: post({'command': 'peers'})[0] == 200
                and len(post({'command': 'peers'})[1].get('peers', [])) == 1,
                'web peer snapshot', 30,
            )
            code, web_snapshot = post({'command': 'peers'})
            assert code == 200
            assert_peer_snapshot(web_snapshot)
            for _ in range(2):
                connection = http.client.HTTPConnection('127.0.0.1', port, timeout=30)
                connection.request('GET', '/api/events')
                feed = connection.getresponse()
                assert feed.status == 200
                feeds.append((feed, connection))

            def event(feed):
                while True:
                    line = feed.readline()
                    assert line, 'SSE ended'
                    if line.startswith(b'data: '):
                        return json.loads(line[6:])

            for feed, _ in feeds:
                assert event(feed)['type'] == 'connected'
                assert_peer_snapshot(event(feed))
            marker = f'web-peer-receipt-{time.time_ns()}'
            send_operation_id = operation_id()
            code, queued = post({'command': 'send', 'operation_id': send_operation_id, 'body': marker})
            assert code == 200 and queued == {
                'type': 'queued', 'schema_version': 3,
                'operation_id': send_operation_id, 'message_id': send_operation_id,
                'delivery_acknowledged': False}
            canonical = None
            for feed, _ in feeds:
                local = event(feed)
                assert local['type'] == 'queued' and local['body'] == marker
                assert local['delivery_acknowledged'] is False and isinstance(local['timestamp_ms'], int)
                if canonical is None:
                    canonical = local
                else:
                    assert local == canonical
            wait_for(lambda: marker in pathlib.Path(peer_log.name).read_text(), 'web broadcast received on distinct peer', 30)
            received = [json.loads(line) for line in pathlib.Path(peer_log.name).read_text().splitlines() if marker in line]
            remote = next(value for value in received if value['type'] == 'message' and value['body'] == marker)
            assert canonical['schema_version'] == 3 and remote['schema_version'] == 2
            assert canonical['operation_id'] == canonical['message_id'] == remote['message_id']
            assert remote['from'] == canonical['from']
            assert remote['timestamp_ms'] == canonical['timestamp_ms']

            # Lose the local IPC response, then recover the real daemon's cached
            # terminal success through HTTP without another wire delivery.
            lost_operation_id = operation_id()
            lost_body = marker + '-lost-ipc-reply'
            submit_without_reply({
                'command': 'send', 'operation_id': lost_operation_id,
                'body': lost_body})
            wait_for(lambda: lost_body in pathlib.Path(peer_log.name).read_text(),
                     'lost-response broadcast', 30)
            time.sleep(1.05)
            code, recovered = post({
                'command': 'send', 'operation_id': lost_operation_id,
                'body': lost_body})
            assert code == 200 and recovered['operation_id'] == lost_operation_id
            time.sleep(1)
            assert pathlib.Path(peer_log.name).read_text().count(lost_body) == 1
            for feed, _ in feeds:
                local = event(feed)
                assert local['type'] == 'queued' and local['body'] == lost_body

            local_cli = marker + '-local-cli'
            assert cli('one', 'send', local_cli)['type'] == 'queued'
            for feed, _ in feeds:
                local = event(feed)
                assert local['type'] == 'queued' and local['body'] == local_cli

            attachment_name = 'web-attachment.txt'
            attachment_payload = b'real web attachment upload\n'
            (code, shared_reply), share_operation_id = upload(attachment_name, attachment_payload)
            share_digest = hashlib.sha256(
                b'meshmsg-share-source-v1\0file\0' + attachment_payload).hexdigest()
            assert code == 200 and shared_reply == {
                'type': 'attachment_shared', 'schema_version': 3,
                'operation_id': share_operation_id,
                'message_id': share_operation_id, 'offer_id': share_operation_id,
                'source_digest': share_digest, 'name': attachment_name,
                'size': len(attachment_payload), 'delivery_acknowledged': False}
            safe_shared = None
            for feed, _ in feeds:
                local = event(feed)
                assert set(local) == {'type', 'schema_version', 'operation_id', 'message_id', 'direction', 'from', 'timestamp_ms', 'name', 'kind', 'size'}
                assert local['type'] == 'attachment_shared' and local['schema_version'] == 3
                assert local['operation_id'] == local['message_id'] == share_operation_id
                assert local['direction'] == 'outgoing'
                assert local['name'] == attachment_name and local['kind'] == 'file'
                assert local['size'] == len(attachment_payload) and isinstance(local['timestamp_ms'], int)
                if safe_shared is None:
                    safe_shared = local
                else:
                    assert local == safe_shared
            wait_for(lambda: '"type":"attachment_offer"' in pathlib.Path(peer_log.name).read_text()
                     and attachment_name in pathlib.Path(peer_log.name).read_text(),
                     'attachment offer received on distinct peer', 30)
            remote_offer = next(
                value for value in map(json.loads, pathlib.Path(peer_log.name).read_text().splitlines())
                if value.get('type') == 'attachment_offer' and value.get('name') == attachment_name)
            offer_file = root / 'web-upload.offer'
            offer_file.write_text(remote_offer['offer'])
            received_upload = root / 'received-web-upload.txt'
            downloaded = cli('two', 'download', '--offer-file', str(offer_file), '--output', str(received_upload))
            assert downloaded['type'] == 'download_complete'
            assert received_upload.read_bytes() == attachment_payload

            # A real daemon conflict (not the bridge's local fingerprint check)
            # must cross IPC and HTTP without being rewritten as unknown.
            conflict_path = root / 'http-conflict.txt'
            conflict_payload = b'real daemon attachment conflict\n'
            conflict_path.write_bytes(conflict_payload)
            conflict_operation_id = operation_id()
            shared_cli = cli(
                'one', 'share', '--operation-id', conflict_operation_id,
                str(conflict_path))
            assert shared_cli['operation_id'] == conflict_operation_id
            for feed, _ in feeds:
                local = event(feed)
                assert local['type'] == 'attachment_shared'
                assert local['operation_id'] == conflict_operation_id
            (code, conflict), _ = upload(
                conflict_path.name, conflict_payload, conflict_operation_id)
            assert code == 422 and conflict == {
                'type': 'error', 'schema_version': 1,
                'code': 'operation_id_conflict',
                'operation_id': conflict_operation_id,
                'message': 'operation ID was already used with different inputs',
                'outcome': 'not_started', 'retryable': False}
            (retry_code, retry_conflict), _ = upload(
                conflict_path.name, conflict_payload, conflict_operation_id)
            assert retry_code == code and retry_conflict == conflict

            reverse_attachment_path = root / 'reverse-attachment.txt'
            reverse_attachment_path.write_text('reverse real attachment metadata\n')
            reverse_shared = cli('two', 'share', str(reverse_attachment_path))
            safe_offer = None
            for feed, _ in feeds:
                while True:
                    incoming = event(feed)
                    if incoming['type'] == 'attachment_offer' and incoming['name'] == 'reverse-attachment.txt':
                        break
                offer_id = incoming.pop('download_id')
                assert len(offer_id) == 32
                assert set(incoming) == {'type', 'schema_version', 'message_id', 'direction', 'from', 'timestamp_ms', 'name', 'kind', 'size'}
                assert incoming == {
                    'type': 'attachment_offer', 'schema_version': 2,
                    'message_id': reverse_shared['message_id'],
                    'direction': 'incoming', 'from': reverse_shared['from'],
                    'timestamp_ms': reverse_shared['timestamp_ms'], 'name': 'reverse-attachment.txt',
                    'kind': 'file', 'size': reverse_attachment_path.stat().st_size}
                if safe_offer is None:
                    safe_offer = incoming
                    file_offer_id = offer_id
                else:
                    assert incoming == safe_offer
            headers, body = browser_download(file_offer_id)
            assert body == reverse_attachment_path.read_bytes()
            assert 'reverse-attachment.txt' in headers['content-disposition']
            pinned = cli('one', 'offers')['blobs']
            assert any(item['direction'] == 'incoming' and item['name'] == 'reverse-attachment.txt'
                       for item in pinned), 'web preparation did not retain its documented inbound blob pin'

            directory_path = root / 'reverse-directory'
            directory_path.mkdir()
            (directory_path / 'inside.txt').write_text('browser directory payload\n')
            cli('two', 'share', str(directory_path))
            directory_offer_id = None
            for feed, _ in feeds:
                while True:
                    incoming = event(feed)
                    if incoming['type'] == 'attachment_offer' and incoming['name'] == 'reverse-directory.tar':
                        break
                current_id = incoming.pop('download_id')
                directory_offer_id = directory_offer_id or current_id
                assert incoming['kind'] == 'directory_tar_v1'
            headers, archive = browser_download(directory_offer_id)
            assert 'reverse-directory.tar' in headers['content-disposition']
            with tarfile.open(fileobj=io.BytesIO(archive), mode='r:') as downloaded:
                assert downloaded.extractfile('inside.txt').read() == b'browser directory payload\n'

            reverse = marker + '-reverse'
            assert cli('two', 'send', reverse)['type'] == 'queued'
            for feed, _ in feeds:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    value = event(feed)
                    if value['type'] == 'message' and value['body'] == reverse:
                        break
                else:
                    raise AssertionError('second peer message missing from web SSE')
            for feed, connection in feeds:
                feed.close()
                connection.close()
            feeds.clear()

            cli('one', 'stop')
            first.wait(timeout=15)
            assert post({'command': 'status'})[0] == 503
            spawn('one', 'daemon')
            wait_for(lambda: running('one'), 'first daemon restart')
            assert post({'command': 'status'})[0] == 200
            web.send_signal(signal.SIGINT)
            assert web.wait(timeout=5) == 0
            assert running('one') and running('two')
            print('PASS: real sanitized peer snapshot reached HTTP and both SSE handshakes without routes; web messages and a real browser attachment upload reached the distinct peer and both feeds as canonical events; safe metadata and verified browser file/directory-tar downloads passed; reverse peer send, daemon offline/restart, and independent web shutdown passed')
        except BaseException:
            for log in logs:
                log.flush()
                print(f'--- {pathlib.Path(log.name).name} ---', file=sys.stderr)
                print(pathlib.Path(log.name).read_text()[-4000:], file=sys.stderr)
            raise
        finally:
            for feed, connection in feeds:
                feed.close()
                connection.close()
            for peer in ['one', 'two']:
                with contextlib.suppress(Exception):
                    cli(peer, 'stop')
            for process in processes:
                if process.poll() is None:
                    process.terminate()
                with contextlib.suppress(subprocess.TimeoutExpired):
                    process.wait(timeout=5)
                if process.poll() is None:
                    process.kill()
                    process.wait()
            for log in logs:
                log.close()


if __name__ == '__main__':
    main()
