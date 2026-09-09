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


def run_case(command, response, expected_code="command_failed",
             expected_outcome="not_started", expected_retryable=False):
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
                    reply = dict(response(request) if callable(response) else response)
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
        assert error["code"] == expected_code
        assert error["outcome"] == expected_outcome
        assert error["retryable"] is expected_retryable
        assert len(error["request_id"]) == 32
        assert "response-body-secret" not in child.stdout


# Wrong discriminators/types/versions, malformed errors, correlation failures,
# and duplicate fields all fail closed and become one stable CLI error record.
run_case(["status"], {"type": "accepted_instead", "body": "response-body-secret"})
run_case(["status"], {"type": {"nested": "malformed"}, "body": "response-body-secret"})
run_case(["status"], {"type": "status", "schema_version": 2, "body": "response-body-secret"})
run_case(["status"], {"type": "error", "message": "response-body-secret"})
run_case(["status"], {"type": "status", "request_id": "2" * 32, "_correlate": False})

# Correlated, fully valid completions must echo the exact submitted OS-string
# representation, not merely a Path-equivalent spelling.
def mismatched_download(transform):
    def response(request):
        requested = request["request"]["output"]
        assert pathlib.Path(requested).is_absolute()
        different = transform(requested)
        assert different != requested
        return {
            "type": "download_complete",
            "offer_id": "2" * 32,
            "kind": "file",
            "name": "safe.txt",
            "size": 0,
            "from": "3" * 64,
            "output": different,
            "installed": True,
            "pinned": True,
            "destination_synced": True,
            "cleanup_complete": True,
            "warnings": [],
        }
    return response


def dot_component(path):
    parent, name = path.rsplit("/", 1)
    return parent + "/./" + name


def parent_component(path):
    parent, name = path.rsplit("/", 1)
    return parent + "/unused/../" + name


for transform in [
    lambda path: path + ".different",
    lambda path: "/" + path,
    dot_component,
    parent_component,
    lambda path: path + "/",
]:
    run_case(
        ["download", "fake-offer", "--output", "requested.bin"],
        mismatched_download(transform),
    )

# The stable listing-capacity error crosses a strict correlated fake IPC reply
# and remains actionable in CLI JSON mode.
run_case(
    ["offers"],
    {"type": "error", "code": "offers_busy",
     "message": "Attachment listing is currently busy.",
     "outcome": "not_started", "retryable": True},
    expected_code="offers_busy", expected_retryable=True,
)

# Benchmark summaries are streamed contracts. Incoherent daemon summaries must
# be rejected, replaced by a safe disconnected summary, and end with failure;
# coherent deadline/sending-failure summaries retain their documented exits.
def run_benchmark_case(changes, expected_exit, expected_reason):
    with tempfile.TemporaryDirectory(prefix="meshmsg-cli-benchmark-") as temporary:
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
                    request_id = request["request_id"]
                    config = request["request"]["config"]
                    assert request["request"]["command"] == "bench_send"
                    common = {
                        "schema_version": 1, "request_id": request_id,
                        "run_id": config["run_id"], "rate": config["rate"],
                        "duration_secs": config["duration_secs"],
                        "payload_bytes": config["payload_bytes"], "planned": 1,
                    }
                    started = dict(common, type="bench_send_started",
                                   delivery_acknowledged=False)
                    summary = dict(
                        common, type="bench_send_summary", attempted=1,
                        queued=1, failed=0, schedule_missed=0,
                        queued_body_bytes=128, queued_envelope_bytes=256,
                        elapsed_ms=1000, achieved_messages_per_second=1.0,
                        achieved_body_bytes_per_second=128.0,
                        delivery_acknowledged=False,
                        completion_reason="deadline", first_error=None,
                    )
                    summary.update(changes)
                    connection.sendall(json.dumps(started).encode() + b"\n")
                    connection.sendall(json.dumps(summary).encode() + b"\n")
            except BaseException as error:
                failure.append(error)

        thread = threading.Thread(target=daemon, daemon=True)
        thread.start()
        child = subprocess.run(
            [BINARY, "--json", "--state-dir", str(state), "bench-send",
             "--run-id", "4" * 32, "--rate", "1", "--duration-secs", "1",
             "--payload-bytes", "128"],
            text=True, capture_output=True, timeout=10,
        )
        listener.close()
        thread.join(2)
        if failure:
            raise failure[0]
        assert child.returncode == expected_exit, (changes, child.stdout, child.stderr)
        assert child.stderr == "", (changes, child.stderr)
        values = [json.loads(line) for line in child.stdout.splitlines()]
        assert values[0]["type"] == "bench_send_started"
        summaries = [value for value in values if value["type"] == "bench_send_summary"]
        assert len(summaries) == 1 and summaries[0]["completion_reason"] == expected_reason
        if expected_exit == 1:
            assert values[-1]["type"] == "error" and values[-1]["code"] == "command_failed"
        else:
            assert values[-1]["type"] == "bench_send_summary"
        assert "/home/alice/private" not in child.stdout
        assert "forged-record" not in child.stdout


for incoherent in [
    {"completion_reason": "send_failed", "first_error": "Message submission failed."},
    {"completion_reason": "send_failed", "queued": 0, "failed": 1,
     "queued_body_bytes": 0, "first_error": None},
    {"completion_reason": "deadline", "queued": 0, "failed": 1,
     "queued_body_bytes": 0,
     "first_error": "/home/alice/private/bench.log\tforged-record"},
    {"completion_reason": "deadline", "queued": 0, "failed": 0,
     "queued_body_bytes": 0, "first_error": None},
]:
    run_benchmark_case(incoherent, 1, "daemon_stopped")

run_benchmark_case({}, 0, "deadline")
run_benchmark_case(
    {"completion_reason": "send_failed", "queued": 0, "failed": 1,
     "queued_body_bytes": 0, "first_error": "Message submission failed."},
    1, "send_failed",
)

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
