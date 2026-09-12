#!/usr/bin/env python3
"""One-shot output contracts and daemon startup/fatal stream routing."""
import json
import os
import subprocess
import sys
import tempfile
import time

binary = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg")
base = os.environ.copy()


def run(args, changes=None, timeout=4, cwd=None):
    env = base.copy()
    env.update(changes or {})
    started = time.monotonic()
    child = subprocess.run(
        [binary, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False, cwd=cwd,
    )
    assert time.monotonic() - started < timeout
    return child


# One-shot JSON failures remain one normal stdout result with empty stderr.
json_error = run(["--json", "definitely-not-a-command"])
assert json_error.returncode == 1 and json_error.stderr == b""
value = json.loads(json_error.stdout)
assert value["type"] == "error" and len(json_error.stdout.splitlines()) == 1

# A global option value equal to a subcommand is not daemon mode. The parsed
# status command retains the one-shot JSON stdout contract.
with tempfile.TemporaryDirectory(prefix="meshmsg-argument-collision-") as directory:
    collision = run(["--state-dir", "daemon", "--json", "status"], cwd=directory)
assert collision.returncode == 1 and collision.stderr == b""
assert json.loads(collision.stdout)["type"] == "error"
assert len(collision.stdout.splitlines()) == 1

# Human one-shot failures use normal stderr.
human_error = run(["definitely-not-a-command"])
assert human_error.returncode == 1 and human_error.stdout == b""
assert human_error.stderr.startswith(b"error: ")

# Legacy output-hardening injectors have no effect after subsystem removal.
legacy = run(
    ["--json", "status"],
    {"MESHMSG_TEST_BLOCK_STDERR": "1", "MESHMSG_TEST_DIAGNOSTIC_STARTUP_FAIL": "1"},
)
assert legacy.returncode == 1 and legacy.stderr == b""
assert json.loads(legacy.stdout)["type"] == "error"

# A parsed daemon's fatal output is stderr even with --json; stdout is never an
# event/error stream.
with tempfile.TemporaryDirectory(prefix="meshmsg-daemon-fatal-") as directory:
    fatal = run(["--state-dir", "missing", "--json", "daemon"], cwd=directory)
assert fatal.returncode == 1 and fatal.stdout == b""
assert fatal.stderr.startswith(b"error: ")

print("PASS: one-shot output is normal and daemon fatal output is stderr-only")
