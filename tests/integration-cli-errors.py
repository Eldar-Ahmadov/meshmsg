#!/usr/bin/env python3
"""Machine-readable CLI failures and malformed daemon replies (Unix sockets)."""
import json
import os
import pathlib
import signal
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
             expected_outcome="not_started", expected_retryable=False,
             expected_fields=None, absent_fields=()):
    with tempfile.TemporaryDirectory(prefix="meshmsg-cli-errors-") as temporary:
        state = pathlib.Path(temporary)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(state / "daemon.sock"))
        listener.listen(1)
        failure = []

        def daemon():
            try:
                negotiated = command[0] == "download" or (
                    command[0] == "offers" and len(command) > 1
                    and command[1] in ("remove", "prune"))
                request_count = 2 if negotiated else 1
                for _ in range(request_count):
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
        for key, expected in (expected_fields or {}).items():
            assert error.get(key) == expected, (key, error)
        for key in absent_fields:
            assert key not in error, (key, error)
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
def download_status():
    return {
        "type": "status", "running": True, "peer": "3" * 64, "topic": "4" * 64,
        "advertises_self": False, "has_invite": True, "bootstrap_peer_count": 1,
        "self_advertised": False, "neighbors": 1, "endpoint_online": True,
        "topic_joined": True, "alias": None, "alias_enabled": False,
        "captured_hostname": None, "custom_alias": None, "advertised_aliases": 0,
        "ipc_capabilities": ["idempotent_attachment_operations_v1", "attachment_lifecycle_v3"],
        "operation_cache_capacity": 1024, "operation_cache_ttl_ms": 600000,
        "operation_cache_persistent": False, "direct_replay_available": True,
        "direct_replay_error": None, "direct_replay_capacity": 8192,
        "direct_replay_per_sender_capacity": 512, "direct_replay_queue_capacity": 64,
        "direct_replay_global_rate_per_second": 128, "direct_replay_global_rate_burst": 256,
        "direct_replay_sender_rate_per_second": 8, "direct_replay_sender_rate_burst": 16,
        "max_attachment_bytes": 1024,
        "attachment_storage": {"tagged_bytes": 0, "tagged_blobs": 0, "tags": 0,
            "tag_capacity": 8192, "quota_bytes": 1024, "available_bytes": 1024,
            "min_free_bytes": 0, "pressure": False, "over_quota": False,
            "below_min_free": False, "sampled_at_ms": 1},
        "attachment_retention_secs": 0,
    }


def mismatched_download(transform):
    def response(request):
        if request["request"]["command"] == "status":
            return download_status()
        requested = request["request"]["output"]
        assert pathlib.Path(requested).is_absolute()
        different = transform(requested)
        assert different != requested
        return {
            "type": "download_complete", "schema_version": 2,
            "operation_id": request["request"]["operation_id"],
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

def lifecycle_error(code, outcome, retryable, include_offer=False, partial=False):
    def response(request):
        if request["request"]["command"] == "status":
            return download_status()
        operation_id = request["request"]["operation_id"]
        value = {
            "type": "error", "schema_version": 1, "code": code,
            "message": {
                "operation_id_conflict": "The operation ID is bound to different input.",
                "operation_capacity": "Local capacity is currently unavailable.",
                "attachment_removal_partial": "Attachment removal completed only partially.",
            }[code],
            "operation_id": operation_id, "outcome": outcome, "retryable": retryable,
        }
        if include_offer:
            value["offer_id"] = request["request"]["offer_id"]
        if partial:
            value.update(selected_tags=2, removed_tags=1, quota_bytes_released=4,
                         maximum=512, dry_run=False)
            if request["request"]["command"] == "offers_prune":
                value.update(
                    direction=request["request"]["direction"],
                    older_than_secs=request["request"]["older_than_secs"],
                    cutoff_ms=1,
                    maximum=request["request"]["max_delete"],
                )
        return value
    return response


# Generic operation conflicts/capacity are valid without offer_id, while an
# offer-specific partial removal remains exactly operation/offer/count bound.
for code in ["operation_id_conflict", "operation_capacity"]:
    run_case(
        ["offers", "remove", "--operation-id", "a" * 32, "b" * 32],
        lifecycle_error(code, "not_started", code == "operation_capacity"),
        expected_code=code,
        expected_retryable=code == "operation_capacity",
        expected_fields={"operation_id": "a" * 32},
        absent_fields=("offer_id",),
    )
run_case(
    ["offers", "remove", "--operation-id", "c" * 32, "d" * 32],
    lifecycle_error("attachment_removal_partial", "partial", True,
                    include_offer=True, partial=True),
    expected_code="attachment_removal_partial", expected_outcome="partial",
    expected_retryable=True,
    expected_fields={"operation_id": "c" * 32, "offer_id": "d" * 32,
                     "selected_tags": 2, "removed_tags": 1,
                     "quota_bytes_released": 4},
)
run_case(
    ["offers", "prune", "--operation-id", "e" * 32,
     "--older-than-secs", "1", "--direction", "outgoing", "--max-delete", "2"],
    lifecycle_error("attachment_removal_partial", "partial", True, partial=True),
    expected_code="attachment_removal_partial", expected_outcome="partial",
    expected_retryable=True,
    expected_fields={"operation_id": "e" * 32, "direction": "outgoing",
                     "older_than_secs": 1, "maximum": 2, "dry_run": False,
                     "selected_tags": 2, "removed_tags": 1,
                     "quota_bytes_released": 4},
    absent_fields=("offer_id", "provider"),
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
def run_benchmark_case(changes, expected_exit, expected_reason,
                       expected_code=None, expected_outcome=None):
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
                                   schema_version=2, delivery_acknowledged=False)
                    summary = dict(
                        common, type="bench_send_summary", schema_version=2, attempted=1,
                        queued=1, failed=0, incomplete=0, schedule_missed=0,
                        queued_body_bytes=128, queued_envelope_bytes=256,
                        elapsed_ms=1000, achieved_messages_per_second=1.0,
                        achieved_body_bytes_per_second=128.0,
                        delivery_acknowledged=False, accounting_complete=True,
                        completion_reason="deadline", first_error=None,
                    )
                    connection.sendall(json.dumps(started).encode() + b"\n")
                    if changes.get("_disconnect"):
                        return
                    if "_error" in changes:
                        terminal_error = dict(changes["_error"], schema_version=1,
                                              type="error")
                        correlation = terminal_error.pop("_correlation", "matching")
                        if correlation == "matching":
                            terminal_error["request_id"] = request_id
                        elif correlation == "mismatched":
                            terminal_error["request_id"] = "f" * 32
                        elif correlation != "missing":
                            raise AssertionError(correlation)
                        connection.sendall(json.dumps(terminal_error).encode() + b"\n")
                        return
                    summary.update(changes)
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
        assert len(summaries) == 1 and summaries[0]["completion_reason"] == expected_reason, (changes, values)
        benchmark_request_id = values[0]["request_id"]
        assert all(value["request_id"] == benchmark_request_id for value in values), (changes, values)
        if expected_exit == 1:
            errors = [value for value in values if value["type"] == "error"]
            assert len(errors) == 1 and values[-1] == errors[0], (changes, values)
            assert values[-1]["code"] == expected_code, (changes, values)
            assert values[-1]["outcome"] == expected_outcome, (changes, values)
        else:
            assert values[-1]["type"] == "bench_send_summary"
        assert "/home/alice/private" not in child.stdout
        assert "forged-record" not in child.stdout


for incoherent in [
    {"completion_reason": "send_failed", "first_error": "Message submission failed."},
    {"completion_reason": "send_failed", "queued": 0, "failed": 1,
     "incomplete": 0, "queued_body_bytes": 0, "queued_envelope_bytes": 0,
     "achieved_messages_per_second": 0.0,
     "achieved_body_bytes_per_second": 0.0, "first_error": None},
    {"completion_reason": "deadline", "queued": 0, "failed": 1,
     "incomplete": 0, "queued_body_bytes": 0, "queued_envelope_bytes": 0,
     "achieved_messages_per_second": 0.0,
     "achieved_body_bytes_per_second": 0.0,
     "first_error": "/home/alice/private/bench.log\tforged-record"},
    {"completion_reason": "deadline", "queued": 0, "failed": 0,
     "incomplete": 0, "queued_body_bytes": 0, "queued_envelope_bytes": 0,
     "achieved_messages_per_second": 0.0,
     "achieved_body_bytes_per_second": 0.0, "first_error": None},
    {"queued_body_bytes": 0},
    {"queued_envelope_bytes": 0},
    {"queued_envelope_bytes": 128},
    {"queued_envelope_bytes": 4097},
    {"achieved_messages_per_second": -1.0},
    {"achieved_body_bytes_per_second": -1.0},
    {"achieved_messages_per_second": 2.0},
    {"achieved_body_bytes_per_second": 127.0},
    {"rate": 0},
    {"rate": 2**32 - 1},
    {"elapsed_ms": 2**64 - 1},
    {"schedule_missed": 1},
    {"schedule_missed": 2**64 - 1},
    {"attempted": 2**64 - 1, "queued": 2**64 - 1,
     "queued_body_bytes": 2**64 - 1, "queued_envelope_bytes": 2**64 - 1},
    {"planned": 2},
    {"duration_secs": 2, "planned": 2, "attempted": 1,
     "schedule_missed": 1, "elapsed_ms": 2000,
     "achieved_messages_per_second": 0.5,
     "achieved_body_bytes_per_second": 64.0},
    {"run_id": "5" * 32},
    {"incomplete": 1},
    {"accounting_complete": False},
]:
    run_benchmark_case(
        incoherent, 1, "daemon_stopped", "invalid_daemon_response", "partial"
    )

run_benchmark_case({}, 0, "deadline")
run_benchmark_case(
    {"_disconnect": True}, 1, "daemon_stopped", "daemon_disconnected", "partial"
)
run_benchmark_case(
    {"_error": {"code": "command_timeout",
                "message": "The request timed out; reconcile before retrying.",
                "outcome": "not_started", "retryable": True}},
    1, "daemon_stopped", "invalid_daemon_response", "partial",
)
for valid_outcome in ["partial", "unknown"]:
    run_benchmark_case(
        {"_error": {"code": "command_timeout",
                    "message": "The request timed out; reconcile before retrying.",
                    "outcome": valid_outcome, "retryable": True}},
        1, "daemon_stopped", "command_timeout", valid_outcome,
    )
for code, message, outcome, correlation in [
    ("ipc_capacity", "Local capacity is currently unavailable.",
     "partial", "missing"),
    ("initial_frame_timeout", "The initial local request timed out.",
     "unknown", "missing"),
    ("command_timeout", "The request timed out; reconcile before retrying.",
     "partial", "missing"),
    ("ipc_capacity", "Local capacity is currently unavailable.",
     "unknown", "mismatched"),
    ("initial_frame_timeout", "The initial local request timed out.",
     "partial", "mismatched"),
    ("command_timeout", "The request timed out; reconcile before retrying.",
     "unknown", "mismatched"),
]:
    run_benchmark_case(
        {"_error": {"code": code, "message": message, "outcome": outcome,
                    "retryable": True, "_correlation": correlation}},
        1, "daemon_stopped", "invalid_daemon_response", "partial",
    )
run_benchmark_case(
    {"completion_reason": "interrupted", "queued": 0, "failed": 0,
     "incomplete": 1, "queued_body_bytes": 0, "queued_envelope_bytes": 0,
     "achieved_messages_per_second": 0.0,
     "achieved_body_bytes_per_second": 0.0},
    1, "daemon_stopped", "invalid_daemon_response", "partial",
)
run_benchmark_case(
    {"completion_reason": "send_failed", "queued": 0, "failed": 1,
     "incomplete": 0, "queued_body_bytes": 0, "queued_envelope_bytes": 0,
     "achieved_messages_per_second": 0.0,
     "achieved_body_bytes_per_second": 0.0,
     "first_error": "Message submission failed."},
    1, "send_failed", "send_failed", "partial",
)

# Only a cancellation initiated by this client may yield an interrupted summary.
with tempfile.TemporaryDirectory(prefix="meshmsg-cli-benchmark-cancel-") as temporary:
    state = pathlib.Path(temporary)
    listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    listener.bind(str(state / "daemon.sock"))
    listener.listen(1)
    failure = []

    def cancellation_daemon():
        try:
            connection, _ = listener.accept()
            with connection:
                request = json.loads(connection.makefile("rb").readline())
                request_id = request["request_id"]
                config = request["request"]["config"]
                common = {
                    "schema_version": 2, "request_id": request_id,
                    "run_id": config["run_id"], "rate": 1,
                    "duration_secs": 1, "payload_bytes": 128, "planned": 1,
                }
                connection.sendall(json.dumps(dict(
                    common, type="bench_send_started",
                    delivery_acknowledged=False,
                )).encode() + b"\n")
                assert connection.recv(1) == b"\n"
                connection.sendall(json.dumps(dict(
                    common, type="bench_send_summary", attempted=1, queued=0,
                    failed=0, incomplete=1, schedule_missed=0,
                    queued_body_bytes=0, queued_envelope_bytes=0, elapsed_ms=100,
                    achieved_messages_per_second=0.0,
                    achieved_body_bytes_per_second=0.0,
                    delivery_acknowledged=False, accounting_complete=True,
                    completion_reason="interrupted",
                    first_error=None,
                )).encode() + b"\n")
        except BaseException as error:
            failure.append(error)

    thread = threading.Thread(target=cancellation_daemon, daemon=True)
    thread.start()
    child = subprocess.Popen(
        [BINARY, "--json", "--state-dir", str(state), "bench-send",
         "--run-id", "4" * 32, "--rate", "1", "--duration-secs", "1",
         "--payload-bytes", "128"],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    started_line = child.stdout.readline()
    child.send_signal(signal.SIGINT)
    remaining_stdout, stderr = child.communicate(timeout=10)
    listener.close()
    thread.join(2)
    if failure:
        raise failure[0]
    values = [json.loads(line) for line in (started_line + remaining_stdout).splitlines()]
    assert child.returncode == 0 and stderr == "", (values, stderr)
    assert [value["type"] for value in values] == [
        "bench_send_started", "bench_send_summary"
    ]
    assert values[-1]["completion_reason"] == "interrupted"
    assert len({value["request_id"] for value in values}) == 1

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
