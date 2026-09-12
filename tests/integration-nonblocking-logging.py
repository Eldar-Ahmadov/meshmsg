#!/usr/bin/env python3
"""Real daemon/IPC responsiveness with permanently blocked stdout and stderr."""
import json
import os
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import time

binary = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg").resolve()
root = pathlib.Path(tempfile.mkdtemp(prefix="meshmsg-output-integration-"))


def cli(state, *args, timeout=10):
    return subprocess.run(
        [str(binary), "--state-dir", str(state), *args],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=timeout, check=False,
    )


def wait_status(state):
    deadline = time.monotonic() + 40
    while time.monotonic() < deadline:
        result = cli(state, "--json", "status", timeout=5)
        if result.returncode == 0:
            value = json.loads(result.stdout)
            if value.get("running") is True:
                return
        time.sleep(0.1)
    raise AssertionError("daemon did not become IPC-ready")


def diagnostics(state):
    request_id = "1" * 32
    frame = json.dumps({
        "schema_version": 1,
        "request_id": request_id,
        "request": {"command": "diagnostics"},
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


def run_once(index, signal_shutdown=False, panic_stdout=False):
    state = root / f"state-{index}"
    initialized = cli(state, "init", "--no-default-alias")
    assert initialized.returncode == 0, initialized.stderr
    env = os.environ.copy()
    env.update({
        "MESHMSG_TEST_BLOCK_STDERR": "1",
        "MESHMSG_TEST_EMIT_DIAGNOSTIC": "1",
    })
    if panic_stdout:
        env.update({
            "MESHMSG_TEST_PANIC_DAEMON_STDOUT": "1",
            "MESHMSG_TEST_OUTPUT_BURST": "1",
        })
    else:
        env["MESHMSG_TEST_BLOCK_DAEMON_STDOUT"] = "1"
    daemon = subprocess.Popen(
        [str(binary), "--state-dir", str(state), "daemon"],
        env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        wait_status(state)
        for _ in range(3):
            status = cli(state, "--json", "status")
            assert status.returncode == 0 and json.loads(status.stdout)["running"] is True
            health = diagnostics(state)
            assert health["type"] == "diagnostic_status"
            assert health["schema_version"] == 2
            assert health["stdout_queue_occupancy"] <= health["stdout_queue_capacity"]
            assert health["diagnostic_queue_occupancy"] <= health["diagnostic_queue_capacity"]
            assert health["records_suppressed"] >= 0
            if panic_stdout:
                if health["writer_terminal"]:
                    assert health["writer_healthy"] is False
                    assert health["writer_panics"] == 1
                    assert health["writer_records_lost"] >= 1
                    assert health["stdout_queue_occupancy"] == 0
                    assert health["diagnostic_queue_occupancy"] == 1
            else:
                assert health["writer_healthy"] is True
        if panic_stdout:
            deadline = time.monotonic() + 2
            while not health["writer_terminal"] and time.monotonic() < deadline:
                time.sleep(0.02)
                health = diagnostics(state)
            assert health["writer_terminal"] is True
            assert health["writer_records_lost"] >= 1
            assert health["stdout_queue_occupancy"] == 0
            assert health["diagnostic_queue_occupancy"] == 1
        started = time.monotonic()
        if signal_shutdown:
            daemon.terminate()
        else:
            stopped = cli(state, "--json", "stop")
            assert stopped.returncode == 0, (stopped.stdout, stopped.stderr)
        daemon.wait(timeout=5)
        assert time.monotonic() - started < 5
        assert daemon.returncode == 0, daemon.returncode
        # Both worker threads were blocked permanently. Process exit must not wait
        # for them and no competing panic/final-error owner may write stderr.
        assert daemon.stderr.read() == b""
    finally:
        if daemon.poll() is None:
            daemon.kill()
            daemon.wait()


def post_start_terminal(index, panic, json_mode, blocked=False):
    state = root / f"terminal-{index}"
    initialized = cli(state, "init", "--no-default-alias")
    assert initialized.returncode == 0, initialized.stderr
    ready = root / f"terminal-{index}.ready"
    env = os.environ.copy()
    env["MESHMSG_TEST_POST_START_READY_FILE"] = str(ready)
    env[
        "MESHMSG_TEST_DAEMON_PANIC_AFTER_OUTPUT"
        if panic else "MESHMSG_TEST_DAEMON_ERROR_AFTER_OUTPUT"
    ] = "1"
    if blocked:
        env["MESHMSG_TEST_BLOCK_DAEMON_STDOUT"] = "1"
    command = [str(binary), "--state-dir", str(state)]
    if json_mode:
        command.append("--json")
    command.append("daemon")
    daemon = subprocess.Popen(
        command,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT if not json_mode else subprocess.PIPE,
    )
    deadline = time.monotonic() + 40
    while not ready.exists() and daemon.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    assert ready.exists(), "daemon did not reach post-start injection"
    injected = time.monotonic()
    stdout, stderr = daemon.communicate(timeout=4)
    assert time.monotonic() - injected < 2
    assert daemon.returncode == 1
    assert not (state / "daemon.sock").exists(), "endpoint guard did not clean up"
    if blocked:
        assert stdout == b"" and stderr == b""
        return
    if json_mode:
        assert stderr == b"", stderr
        values = [json.loads(line) for line in stdout.splitlines()]
        assert [value["type"] for value in values] == [
            "daemon_started", "logging_test_marker", "error"
        ], values
        expected_code = "internal_contract_error" if panic else "command_failed"
        assert values[-1]["code"] == expected_code
        expected_message = (
            "An internal contract error occurred." if panic else "The command failed."
        )
        assert values[-1]["message"] == expected_message
    else:
        text = stdout.decode()
        started = text.index("daemon running as")
        marker = text.index('"type":"logging_test_marker"')
        terminal = text.index("error: internal process panic" if panic else "error:")
        assert started < marker < terminal, text


try:
    # Repetition covers command shutdown and graceful signal-triggered shutdown.
    run_once(1, False)
    run_once(2, True)
    run_once(3, False, True)
    # True post-start Result failure and unwind paths prove marker-before-terminal
    # ordering. A blocked unwind proves the RAII deadline and output suppression.
    post_start_terminal(4, False, True)
    post_start_terminal(5, True, True)
    post_start_terminal(6, True, False)
    post_start_terminal(7, True, True, blocked=True)
finally:
    shutil.rmtree(root, ignore_errors=True)

print("PASS: real daemon status/diagnostics/shutdown survive blocked stdout+stderr")
