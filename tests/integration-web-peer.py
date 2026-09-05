#!/usr/bin/env python3
"""Real two-peer web receipt check. Requires working Iroh networking; no Tailscale changes."""
import contextlib
import http.client
import json
import pathlib
import signal
import socket
import subprocess
import sys
import tempfile
import time

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

            wait_for(lambda: post({'command': 'status'})[0] == 200, 'web ready', 15)
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
            marker = f'web-peer-receipt-{time.time_ns()}'
            code, queued = post({'command': 'send', 'body': marker})
            assert code == 200 and queued == {'type': 'queued', 'delivery_acknowledged': False}
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
            assert remote['from'] == canonical['from']
            assert remote['timestamp_ms'] == canonical['timestamp_ms']

            local_cli = marker + '-local-cli'
            assert cli('one', 'send', local_cli)['type'] == 'queued'
            for feed, _ in feeds:
                local = event(feed)
                assert local['type'] == 'queued' and local['body'] == local_cli

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
            print('PASS: real web and local CLI sends reached both simultaneous SSE feeds as canonical queued events; web POST sender/timestamp matched receipt on a distinct peer; reverse peer send reached both feeds; daemon offline/restart handled; stopping web leaves both daemons running')
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
