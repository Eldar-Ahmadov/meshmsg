#!/usr/bin/env python3
"""Streaming CLI contract against owner-local fake IPC, without Iroh networking."""
import contextlib
import json
import os
import pathlib
import queue
import re
import signal
import socket
import subprocess
import sys
import tempfile
import threading

if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
    raise SystemExit("send-stream fake-daemon regression requires Unix sockets")

BINARY = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg").resolve())
PEER = "3" * 64
ID = re.compile(r"^[0-9a-f]{32}$")


def accepted(frame, _connection):
    request = frame["request"]
    common = {"operation_id": request["operation_id"],
              "message_id": request["operation_id"], "timestamp_ms": 1}
    if request["command"] == "private_send":
        assert request["to"] == PEER
        return {**common, "type": "private_accepted", "to": PEER,
                "body_bytes": len(request["body"].encode()),
                "acceptance_acknowledged": True, "duplicate_accepted": False,
                "durable": False, "read": False}
    assert request["command"] == "send"
    return {**common, "type": "queued", "from": PEER,
            "body": request["body"], "delivery_acknowledged": False}


@contextlib.contextmanager
def daemon(handler=accepted):
    with tempfile.TemporaryDirectory(prefix="meshmsg-send-stream-") as temporary:
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(pathlib.Path(temporary) / "daemon.sock"))
        listener.listen(8)
        listener.settimeout(0.1)
        stopped = threading.Event()
        requests, errors = [], []

        def serve():
            try:
                while not stopped.is_set():
                    try:
                        connection, _ = listener.accept()
                    except socket.timeout:
                        continue
                    with connection:
                        connection.settimeout(5)
                        with connection.makefile("rb") as source:
                            frame = json.loads(source.readline())
                        assert frame["protocol_version"] == 4
                        assert ID.fullmatch(frame["request_id"])
                        assert ID.fullmatch(frame["request"]["operation_id"])
                        requests.append(frame)
                        reply = handler(frame, connection)
                        if reply is not None:
                            reply = {**reply, "protocol_version": 4,
                                     "request_id": frame["request_id"]}
                            connection.sendall(json.dumps(reply).encode() + b"\n")
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        try:
            yield temporary, requests
        finally:
            stopped.set()
            thread.join(6)
            listener.close()
            assert not thread.is_alive(), "fake daemon did not stop"
            if errors:
                raise errors[0]


class Client:
    def __init__(self, state, private=False):
        args = [BINARY, "--state-dir", state, "--json", "send-stream"]
        if private:
            args += ["--to", PEER]
        self.process = subprocess.Popen(args, stdin=subprocess.PIPE,
                                        stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.lines = []
        self.output = queue.Queue()

        def read_output():
            for line in self.process.stdout:
                self.lines.append(line)
                self.output.put(line)

        self.reader = threading.Thread(target=read_output, daemon=True)
        self.reader.start()

    def send(self, data):
        self.process.stdin.write(data)
        self.process.stdin.flush()

    def next(self):
        return json.loads(self.output.get(timeout=5))

    def finish(self, expected=0, close_input=True):
        if close_input:
            self.process.stdin.close()
        assert self.process.wait(timeout=5) == expected
        self.reader.join(1)
        assert not self.reader.is_alive()
        assert self.process.stderr.read() == b""
        return [json.loads(line) for line in self.lines]

    def __enter__(self):
        return self

    def __exit__(self, *_):
        if self.process.poll() is None:
            self.process.kill()
        self.process.wait(timeout=5)
        self.reader.join(1)
        for stream in (self.process.stdin, self.process.stdout, self.process.stderr):
            if not stream.closed:
                stream.close()


# A result arrives before stdin closes, preserving order, whitespace and Unicode.
# The last unterminated record is sent on EOF; blank lines generate no requests.
for private in [False, True]:
    with daemon() as (state, requests), Client(state, private) as client:
        client.send("\n\r\n first 界\u2028line \r\n".encode())
        first = client.next()
        assert first["type"] == ("private_accepted" if private else "queued")
        assert client.process.poll() is None
        client.send(b"second\n")
        second = client.next()
        assert first["operation_id"] != second["operation_id"]
        client.send(b"last\r")
        frames = client.finish()
        assert len(frames) == 3
        assert [r["request"]["body"] for r in requests] == [" first 界\u2028line ", "second", "last\r"]
        assert len({r["request"]["operation_id"] for r in requests}) == 3
        assert len({r["request_id"] for r in requests}) == 3

# Empty input succeeds even without a daemon; no mutation is attempted.
with tempfile.TemporaryDirectory() as state, Client(state) as client:
    client.send(b"\n\r\n")
    assert client.finish() == []

# Exact private/broadcast bounds, UTF-8 byte counting, over-limit and invalid
# records. A failure leaves earlier results intact and prevents later sends.
for private, maximum in [(False, 65358), (True, 65358)]:
    for ending in [b"", b"\n", b"\r\n"]:
        with daemon() as (state, requests), Client(state, private) as client:
            client.send(b"x" * maximum + ending)
            frames = client.finish()
            assert len(frames) == len(requests) == 1
            assert len(requests[0]["request"]["body"].encode()) == maximum
    for bad in [b"x" * (maximum + 1), b"\xff", ("界" * (maximum // 3 + 1)).encode()]:
        with daemon() as (state, requests), Client(state, private) as client:
            client.send(b"before\n")
            client.next()
            client.send(bad + b"\nafter\n")
            frames = client.finish(expected=1)
            assert len(frames) == 2 and len(requests) == 1
            assert frames[-1]["code"] == "invalid_message"
            assert frames[-1]["outcome"] == "not_started"
            assert ID.fullmatch(frames[-1]["operation_id"])

# An oversized record fails without waiting for a delimiter or closing stdin.
for private, maximum in [(False, 65358), (True, 65358)]:
    with tempfile.TemporaryDirectory() as state, Client(state, private) as client:
        client.send(b"x" * (maximum + 2))
        error = client.next()
        assert error["code"] == "invalid_message" and error["outcome"] == "not_started"
        assert len(client.finish(expected=1, close_input=False)) == 1

# Terminal and ambiguous daemon failures preserve exact operation/request IDs.
# Neither retries nor private-to-broadcast fallback are allowed.
for code, outcome in [("private_recipient_busy", "not_started"),
                      ("private_delivery_unknown", "unknown")]:
    def reject(frame, _connection):
        return {"type": "error", "code": code, "outcome": outcome,
                "operation_id": frame["request"]["operation_id"]}

    with daemon(reject) as (state, requests), Client(state, True) as client:
        client.send(b"one\ntwo\n")
        frames = client.finish(expected=1)
        assert len(frames) == len(requests) == 1
        assert frames[0]["code"] == code and frames[0]["outcome"] == outcome
        assert frames[0]["operation_id"] == requests[0]["request"]["operation_id"]
        assert frames[0]["request_id"] == requests[0]["request_id"]

# Lost or malformed replies report unknown, retaining the mutation identity.
for reply in [None, {"type": "bogus"}]:
    with daemon(lambda *_: reply) as (state, requests), Client(state, True) as client:
        client.send(b"one\ntwo\n")
        frames = client.finish(expected=1)
        assert len(frames) == len(requests) == 1
        assert frames[0]["code"] == "private_send_failed"
        assert frames[0]["outcome"] == "unknown"
        assert frames[0]["operation_id"] == requests[0]["request"]["operation_id"]

# Ctrl-C exits with stdin still open (including an incomplete next line).
with daemon() as (state, requests), Client(state) as client:
    client.send(b"first\n")
    client.next()
    client.send(b"incomplete")
    client.process.send_signal(signal.SIGINT)
    assert len(client.finish(close_input=False)) == 1
    assert len(requests) == 1

# Interrupting an outstanding request is explicitly ambiguous, never success.
received = threading.Event()


def stalled_reply(_frame, connection):
    received.set()
    assert connection.recv(1) == b""  # Client closes IPC on interruption.
    return None


with daemon(stalled_reply) as (state, requests), Client(state, True) as client:
    client.send(b"first\nsecond\n")
    assert received.wait(5)
    client.process.send_signal(signal.SIGINT)
    frames = client.finish(expected=1, close_input=False)
    assert len(frames) == len(requests) == 1
    assert frames[0]["outcome"] == "unknown"
    assert frames[0]["operation_id"] == requests[0]["request"]["operation_id"]

print("send-stream integration passed")
