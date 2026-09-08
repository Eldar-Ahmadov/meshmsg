#!/usr/bin/env python3
"""Real CLI failure behavior against a local fake daemon (Unix sockets only)."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading

if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
    raise SystemExit("fake-daemon CLI regression requires Unix sockets (run in Linux CI)")

binary = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg").resolve())


def run_case(command, response, check):
    with tempfile.TemporaryDirectory(prefix="meshmsg-cli-errors-") as temporary:
        state = pathlib.Path(temporary)
        path = state / "daemon.sock"
        ready = threading.Event()
        stopped = threading.Event()
        failure = []
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        child = None

        def daemon():
            try:
                listener.bind(str(path))
                listener.listen(1)
                listener.settimeout(0.2)
                ready.set()
                while not stopped.is_set():
                    try:
                        connection, _ = listener.accept()
                        break
                    except socket.timeout:
                        continue
                else:
                    return
                with connection:
                    request = connection.makefile("rb").readline()
                    assert json.loads(request)["command"] == command[0]
                    connection.sendall(json.dumps(response).encode() + b"\n")
            except OSError as error:
                if not stopped.is_set():
                    failure.append(error)
            except BaseException as error:  # propagate thread assertions
                failure.append(error)
            finally:
                ready.set()

        # Last-resort daemonization means a broken fake listener can never pin the test
        # process; normal teardown below still closes and joins it deterministically.
        thread = threading.Thread(target=daemon, daemon=True)
        thread.start()
        try:
            assert ready.wait(5), "fake daemon did not start"
            if failure:
                raise failure[0]
            child = subprocess.Popen(
                [binary, "--state-dir", str(state), *command],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            try:
                stdout, stderr = child.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                child.kill()
                stdout, stderr = child.communicate(timeout=5)
                raise AssertionError((command, "CLI timed out", stdout, stderr))
            assert child.returncode != 0, (command, child.returncode, stdout, stderr)
            assert stdout == "", (command, stdout)
            assert "response-body-secret" not in stderr, stderr
            check(stderr)
        finally:
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)
            stopped.set()
            listener.close()  # closes an accepted socket or interrupts the timeout loop
            thread.join(2)
            assert not thread.is_alive(), "fake daemon did not finish"
            if failure:
                raise failure[0]


def contains(text):
    return lambda stderr: (_ for _ in ()).throw(AssertionError(stderr)) if text not in stderr else None


run_case(
    ["send", "hello"],
    {"type": "accepted_instead", "body": "response-body-secret"},
    contains('expected queued, observed "accepted_instead"'),
)
run_case(
    ["send", "hello"],
    {"type": {"nested": "malformed"}, "body": "response-body-secret"},
    contains("expected queued, observed object"),
)
run_case(
    ["send", "hello"],
    {"type": "left\u009bright", "body": "response-body-secret"},
    lambda stderr: (
        contains('expected queued, observed "left\\u009bright"')(stderr),
        (_ for _ in ()).throw(AssertionError(stderr)) if "\u009b" in stderr else None,
    ),
)
run_case(
    ["status"],
    {
        "type": "error",
        "message": "status useful\n\x1b[31m" + "x" * 1000,
        "body": "response-body-secret",
    },
    lambda stderr: (
        contains('daemon rejected request: "status useful\\n\\u001b[31m')(stderr),
        contains("…")(stderr),
        (_ for _ in ()).throw(AssertionError(stderr)) if "\x1b" in stderr or len(stderr) > 400 else None,
    ),
)
run_case(
    ["stop"],
    {"type": "error", "message": "shutdown denied", "body": "response-body-secret"},
    contains('daemon rejected request: "shutdown denied"'),
)
run_case(
    ["offers"],
    {"type": "offers", "body": "response-body-secret"},
    contains("unsupported offers response version (expected 1, observed missing)"),
)
run_case(
    ["offers"],
    {"type": "offers", "schema_version": "one", "body": "response-body-secret"},
    contains('unsupported offers response version (expected 1, observed "one")'),
)
with tempfile.NamedTemporaryFile() as shared:
    run_case(
        ["share", shared.name],
        {"type": "attachment_shared", "schema_version": 1, "body": "response-body-secret"},
        contains("unsupported attachment_shared response version (expected 2, observed 1)"),
    )

# peers/private-send require capability handshakes and chat is interactive; their
# discriminator/schema combinations use the same validate_response helper covered by
# Rust unit tests. These real-CLI cases cover representative direct mutation paths.
print("fake-daemon CLI error checks passed")
