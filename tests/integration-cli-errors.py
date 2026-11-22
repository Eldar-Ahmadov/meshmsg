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
             expected_outcome="not_started", expected_fields=None, absent_fields=()):
    with tempfile.TemporaryDirectory(prefix="meshmsg-cli-errors-") as temporary:
        state = pathlib.Path(temporary)
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(state / "daemon.sock"))
        listener.listen(1)
        failure = []

        def daemon():
            try:
                # Every command, including download and prune, makes exactly
                # one request: the CLI never probes status first.
                connection, _ = listener.accept()
                with connection:
                    request = json.loads(connection.makefile("rb").readline())
                    assert request["protocol_version"] == 5
                    assert len(request["request_id"]) == 32
                    assert request["request"]["command"] != "status" or command == ["status"]
                    reply = dict(response(request) if callable(response) else response)
                    if reply.pop("_correlate", True):
                        reply["request_id"] = request["request_id"]
                    reply.setdefault("protocol_version", 5)
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
        assert error["protocol_version"] == 5 and error["type"] == "error"
        assert error["code"] == expected_code
        assert error["outcome"] == expected_outcome
        assert "schema_version" not in error
        assert "message" not in error and "retryable" not in error
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

# The CLI trusts its daemon's payload, but a completion must still be the strict
# current typed shape, belong to the download family, and carry the request's
# operation ID.
def download_reply(**changes):
    def response(request):
        submitted = request["request"]
        assert submitted["command"] == "download"
        assert set(submitted) == {"command", "operation_id", "offer", "output"}
        assert submitted["offer"] == "fake-offer"
        assert pathlib.Path(submitted["output"]).is_absolute()
        reply = {
            "type": "download_complete",
            "operation_id": submitted["operation_id"],
            "offer_id": "2" * 32,
            "kind": "file",
            "name": "safe.txt",
            "size": 0,
            "from": "3" * 64,
            "output": submitted["output"],
            "destination_synced": True,
            "cleanup_complete": True,
            "warnings": [],
        }
        reply.update(changes)
        return reply
    return response


for changes in [
    {"operation_id": "f" * 32},
    # Fields removed in protocol v5 are unknown and fail closed.
    {"installed": True, "pinned": True},
    {"mode": "install"},
    {"token_digest": "4" * 64},
    {"output": "relative.bin"},
]:
    run_case(
        ["download", "--operation-id", "a" * 32, "fake-offer", "--output", "requested.bin"],
        download_reply(**changes),
    )

run_case(
    ["download", "--operation-id", "a" * 32, "fake-offer", "--output", "requested.bin"],
    {"type": "stopping"},
)

# A prune without an explicit age submits a null age for the daemon to resolve.
def default_age_prune(request):
    submitted = request["request"]
    assert submitted["command"] == "offers_prune"
    assert submitted["older_than_secs"] is None
    return {
        "type": "error", "code": "attachment_storage_busy",
        "operation_id": submitted["operation_id"], "outcome": "not_started",
    }


run_case(
    ["offers", "prune", "--operation-id", "9" * 32, "--dry-run"],
    default_age_prune,
    expected_code="attachment_storage_busy",
    expected_fields={"operation_id": "9" * 32},
)

def lifecycle_error(code, outcome, include_offer=False, partial=False):
    def response(request):
        operation_id = request["request"]["operation_id"]
        # Retry guidance and display text are derived for human output, not IPC or JSON.
        assert include_offer in (True, False) and partial in (True, False)
        return {
            "type": "error", "code": code,
            "operation_id": operation_id, "outcome": outcome,
        }
    return response


# Generic operation conflicts/capacity are valid without offer_id, while an
# offer-specific partial removal remains exactly operation/offer/count bound.
for code in ["operation_id_conflict", "operation_capacity"]:
    run_case(
        ["offers", "remove", "--operation-id", "a" * 32, "b" * 32],
        lifecycle_error(code, "not_started"),
        expected_code=code,
        expected_fields={"operation_id": "a" * 32},
        absent_fields=("offer_id",),
    )
run_case(
    ["offers", "remove", "--operation-id", "c" * 32, "d" * 32],
    lifecycle_error("attachment_removal_partial", "partial",
                    include_offer=True, partial=True),
    expected_code="attachment_removal_partial", expected_outcome="partial",
    expected_fields={"operation_id": "c" * 32},
    absent_fields=("offer_id", "selected_tags", "removed_tags", "quota_bytes_released"),
)
run_case(
    ["offers", "prune", "--operation-id", "e" * 32,
     "--older-than-secs", "1", "--direction", "outgoing", "--max-delete", "2"],
    lifecycle_error("attachment_removal_partial", "partial", partial=True),
    expected_code="attachment_removal_partial", expected_outcome="partial",
    expected_fields={"operation_id": "e" * 32},
    absent_fields=("offer_id", "provider", "direction", "older_than_secs",
                   "maximum", "dry_run", "selected_tags", "removed_tags",
                   "quota_bytes_released"),
)

# The stable listing-capacity error crosses a strict correlated fake IPC reply
# and remains actionable in CLI JSON mode.
run_case(
    ["offers"],
    {"type": "error", "code": "offers_busy", "outcome": "not_started"},
    expected_code="offers_busy",
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

# Offline is stable and also uses stdout only in JSON mode.
with tempfile.TemporaryDirectory(prefix="meshmsg-cli-offline-") as temporary:
    child = subprocess.run(
        [BINARY, "--json", "--state-dir", temporary, "status"],
        text=True, capture_output=True, timeout=10,
    )
    assert child.returncode == 1 and child.stderr == ""
    error = json.loads(child.stdout)
    assert error["protocol_version"] == 5 and len(error["request_id"]) == 32
    assert error["code"] == "daemon_offline" and error["outcome"] == "not_started"
    assert "message" not in error and "retryable" not in error

print("PASS: CLI JSON failures are one canonical protocol-v5 stdout frame")
