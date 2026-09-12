#!/usr/bin/env python3
"""Exact v0.1.19/current diagnostic-status compatibility in both directions."""
import hashlib
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.request

current = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg").resolve()
root = pathlib.Path(tempfile.mkdtemp(prefix="meshmsg-diagnostic-compat-"))
release = "0.1.19"
archive_name = f"meshmsg-v{release}-x86_64-unknown-linux-gnu.tar.gz"
archive = root / archive_name
release_url = f"https://github.com/Eldar-Ahmadov/meshmsg/releases/download/v{release}/{archive_name}"
release_sha256 = "137b7d0314aea7496bc6f49a3a248ce6e85a7fb95e815e7de0d818c77ad1f849"
old = root / "old" / "meshmsg"
daemons = []

V2_FIELDS = {
    "type", "schema_version", "request_id", "records_accepted", "records_dropped",
    "records_retained", "stdout_queue_occupancy", "stdout_queue_capacity",
    "stdout_queue_high_watermark", "diagnostic_queue_occupancy",
    "diagnostic_queue_capacity", "diagnostic_queue_high_watermark", "records_sampled",
    "records_suppressed", "queue_drops", "contention_drops", "records_written",
    "write_failures", "writer_panics", "writer_records_lost", "writer_healthy",
    "writer_terminal", "process_panics",
}
V3_FIELDS = V2_FIELDS | {"admission_rejections"}


def run(binary, state, *args, env=None, timeout=20):
    return subprocess.run(
        [str(binary), "--state-dir", str(state), *args], env=env,
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )


def raw_request(state, command):
    request_id = "1" * 32
    request = {"command": command}
    frame = json.dumps({
        "schema_version": 1, "request_id": request_id, "request": request,
    }).encode() + b"\n"
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.settimeout(5)
    client.connect(str(state / "daemon.sock"))
    client.sendall(frame)
    response = b""
    while not response.endswith(b"\n"):
        part = client.recv(65536)
        assert part
        response += part
    client.close()
    return json.loads(response)


def status(binary, state):
    result = run(binary, state, "--json", "status")
    assert result.returncode == 0, (result.stdout, result.stderr)
    return json.loads(result.stdout)


def wait_ready(binary, state):
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        try:
            if status(binary, state).get("running") is True:
                return
        except (AssertionError, OSError, json.JSONDecodeError, subprocess.TimeoutExpired):
            pass
        time.sleep(0.1)
    raise AssertionError(f"daemon did not become ready: {state}")


def start(binary, state, env=None):
    initialized = run(binary, state, "init", "--no-default-alias")
    assert initialized.returncode == 0, initialized.stderr
    process = subprocess.Popen(
        [str(binary), "--state-dir", str(state), "--json", "daemon"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    daemons.append((binary, state, process))
    wait_ready(binary, state)


def assert_schema(value, version, fields):
    assert value["type"] == "diagnostic_status"
    assert value["schema_version"] == version
    assert set(value) == fields, (set(value) - fields, fields - set(value))
    assert value["records_dropped"] == (
        value["queue_drops"] + value["contention_drops"] + value["writer_records_lost"]
    )


try:
    with urllib.request.urlopen(release_url, timeout=180) as response, archive.open("wb") as output:
        shutil.copyfileobj(response, output)
    assert hashlib.sha256(archive.read_bytes()).hexdigest() == release_sha256
    old.parent.mkdir()
    with tarfile.open(archive, "r:gz") as bundle:
        member = bundle.getmember(f"meshmsg-v{release}-x86_64-unknown-linux-gnu/meshmsg")
        member.name = "meshmsg"
        bundle.extract(member, old.parent, filter="data")
    old.chmod(0o755)
    assert subprocess.check_output([str(old), "--version"], text=True).strip() == "meshmsg 0.1.19"

    old_state = root / "old-state"
    start(old, old_state)
    old_status = status(current, old_state)
    assert "diagnostic_status_v2" in old_status["ipc_capabilities"]
    assert "diagnostic_status_v3" not in old_status["ipc_capabilities"]
    fallback = run(current, old_state, "--json", "diagnostics")
    assert fallback.returncode == 0, (fallback.stdout, fallback.stderr)
    assert fallback.stderr == b""
    assert_schema(json.loads(fallback.stdout), 2, V2_FIELDS)

    current_state = root / "current-state"
    env = os.environ.copy()
    env["MESHMSG_TEST_REJECT_DAEMON_ERROR"] = "1"
    start(current, current_state, env)
    current_status = status(old, current_state)
    assert "diagnostic_status_v2" in current_status["ipc_capabilities"]
    assert "diagnostic_status_v3" in current_status["ipc_capabilities"]

    # A v0.1.19 protocol client continues to issue `diagnostics` and receives its
    # exact strict v2 response, with no v3 field collision.
    assert_schema(raw_request(current_state, "diagnostics"), 2, V2_FIELDS)

    # A current client prefers the separately negotiated v3 command and observes
    # the pre-queue rejection without changing aggregate drop accounting.
    preferred = run(current, current_state, "--json", "diagnostics")
    assert preferred.returncode == 0, (preferred.stdout, preferred.stderr)
    assert preferred.stderr == b""
    v3 = json.loads(preferred.stdout)
    assert_schema(v3, 3, V3_FIELDS)
    assert v3["admission_rejections"] >= 1

finally:
    for binary, state, process in reversed(daemons):
        if process.poll() is None:
            try:
                run(binary, state, "stop", timeout=5)
            except Exception:
                process.kill()
        try:
            process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
    shutil.rmtree(root, ignore_errors=True)

print("PASS: v0.1.19/current diagnostic status v2 compatibility and negotiated v3 telemetry")
