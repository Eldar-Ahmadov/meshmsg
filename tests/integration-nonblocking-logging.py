#!/usr/bin/env python3
"""Daemon stays responsive and shuts down when process output is never consumed."""
import json
import pathlib
import shutil
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
        if result.returncode == 0 and json.loads(result.stdout).get("running") is True:
            return
        time.sleep(0.1)
    raise AssertionError("daemon did not become IPC-ready")


def run_once(index, signal_shutdown):
    state = root / f"state-{index}"
    initialized = cli(state, "init", "--no-default-alias")
    assert initialized.returncode == 0, initialized.stderr
    # Keep both pipes unread until exit. Daemon events must use listen, so stdout
    # cannot fill; stderr receives only the single bounded startup line.
    daemon = subprocess.Popen(
        [str(binary), "--state-dir", str(state), "--json", "daemon"],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        wait_status(state)
        for _ in range(8):
            status = cli(state, "--json", "status")
            assert status.returncode == 0 and json.loads(status.stdout)["running"] is True
        started = time.monotonic()
        if signal_shutdown:
            daemon.terminate()
        else:
            stopped = cli(state, "--json", "stop")
            assert stopped.returncode == 0, (stopped.stdout, stopped.stderr)
        stdout, stderr = daemon.communicate(timeout=5)
        assert time.monotonic() - started < 5
        assert daemon.returncode == 0, daemon.returncode
        assert stdout == b"", stdout
        assert stderr.startswith(b"daemon running as "), stderr
        assert len(stderr.splitlines()) == 1, stderr
        assert not (state / "daemon.sock").exists(), "endpoint guard did not clean up"
    finally:
        if daemon.poll() is None:
            daemon.kill()
            daemon.wait()


try:
    run_once(1, False)
    run_once(2, True)
finally:
    shutil.rmtree(root, ignore_errors=True)

print("PASS: daemon emits no stdout events and IPC/signal shutdown remains nonblocking")
