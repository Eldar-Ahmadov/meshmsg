#!/usr/bin/env python3
"""Machine-readable CLI failures and malformed daemon replies (Unix sockets)."""
import json
import os
import pathlib
import socket
import subprocess
import sys
import tempfile
import threading

if os.name == "nt" or not hasattr(socket, "AF_UNIX"):
    raise SystemExit("fake-daemon CLI regression requires Unix sockets")

BINARY = str(pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg").resolve())
REQUEST_ID = "1" * 32


def run_case(command, response):
    with tempfile.TemporaryDirectory(prefix="meshmsg-cli-errors-") as temporary:
        state = pathlib.Path(temporary)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(state / "daemon.sock"))
        listener.listen(1)
        failure = []

        def daemon():
            try:
                connection, _ = listener.accept()
                with connection:
                    request = json.loads(connection.makefile("rb").readline())
                    assert request["schema_version"] == 1
                    assert len(request["request_id"]) == 32
                    assert "command" in request["request"]
                    reply = dict(response)
                    if reply.pop("_correlate", True):
                        reply.setdefault("schema_version", 1)
                        reply["request_id"] = request["request_id"]
                    connection.sendall(json.dumps(reply).encode() + b"\n")
            except BaseException as error:
                failure.append(error)

        thread = threading.Thread(target=daemon, daemon=True)
        thread.start()
        child = subprocess.run(
            [BINARY, "--json", "--state-dir", str(state), *command],
            text=True, capture_output=True, timeout=10,
        )
        listener.close()
        thread.join(2)
        if failure:
            raise failure[0]
        assert child.returncode == 1, (command, child.returncode, child.stdout, child.stderr)
        assert child.stderr == "", (command, child.stderr)
        lines = child.stdout.splitlines()
        assert len(lines) == 1, (command, child.stdout)
        error = json.loads(lines[0])
        assert error["type"] == "error" and error["schema_version"] == 1
        assert error["code"] == "command_failed"
        assert error["outcome"] == "not_started" and error["retryable"] is False
        assert len(error["request_id"]) == 32
        assert "response-body-secret" not in child.stdout


# Wrong discriminators/types/versions, malformed errors, correlation failures,
# and duplicate fields all fail closed and become one stable CLI error record.
run_case(["status"], {"type": "accepted_instead", "body": "response-body-secret"})
run_case(["status"], {"type": {"nested": "malformed"}, "body": "response-body-secret"})
run_case(["status"], {"type": "status", "schema_version": 2, "body": "response-body-secret"})
run_case(["status"], {"type": "error", "message": "response-body-secret"})
run_case(["status"], {"type": "status", "request_id": "2" * 32, "_correlate": False})

# Genuine global JSON parse errors remain machine-readable, but a positional
# literal after `--` must not switch the process-wide error stream contract.
parse_error = subprocess.run(
    [BINARY, "--json", "definitely-not-a-command"],
    text=True, capture_output=True, timeout=10,
)
assert parse_error.returncode == 1 and parse_error.stderr == ""
assert json.loads(parse_error.stdout)["code"] == "command_failed"
with tempfile.TemporaryDirectory(prefix="meshmsg-cli-literal-json-") as temporary:
    literal = subprocess.run(
        [BINARY, "--state-dir", temporary, "send", "--", "--json"],
        text=True, capture_output=True, timeout=10,
    )
    assert literal.returncode == 1 and literal.stdout == ""
    assert "error:" in literal.stderr and not literal.stderr.lstrip().startswith("{")

# Offline is stable, retryable, and also uses stdout only in JSON mode.
with tempfile.TemporaryDirectory(prefix="meshmsg-cli-offline-") as temporary:
    child = subprocess.run(
        [BINARY, "--json", "--state-dir", temporary, "status"],
        text=True, capture_output=True, timeout=10,
    )
    assert child.returncode == 1 and child.stderr == ""
    error = json.loads(child.stdout)
    assert error["code"] == "daemon_offline"
    assert error["retryable"] is True and error["outcome"] == "not_started"

print("PASS: CLI JSON failures are one bounded versioned stdout record")
