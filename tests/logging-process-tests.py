#!/usr/bin/env python3
"""Process-level panic, stderr ownership, and startup-failure logging checks."""
import json
import os
import subprocess
import sys
import time

binary = sys.argv[1] if len(sys.argv) > 1 else "target/debug/meshmsg"
base = os.environ.copy()


def run(args, changes, timeout=4):
    env = base.copy()
    env.update(changes)
    started = time.monotonic()
    child = subprocess.run(
        [binary, *args], env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=timeout, check=False,
    )
    assert time.monotonic() - started < timeout
    return child


# The panic hook is deliberately I/O-free, including in JSON mode.
panic = run(["--json", "status"], {"MESHMSG_TEST_PROCESS_PANIC": "1"})
assert panic.returncode == 1
assert panic.stderr == b"", panic.stderr
panic_error = json.loads(panic.stdout)
assert panic_error["type"] == "error" and panic_error["code"] == "internal_contract_error"
assert panic_error["message"] == "An internal contract error occurred."
assert panic_error["outcome"] == "unknown" and panic_error["retryable"] is False

human_panic = run(["status"], {"MESHMSG_TEST_PROCESS_PANIC": "1"})
assert human_panic.returncode == 1 and human_panic.stdout == b""
assert human_panic.stderr == b"error: internal process panic\n"

json_blocked = run(
    ["--json", "definitely-not-a-command"], {"MESHMSG_TEST_BLOCK_STDERR": "1"}
)
assert json_blocked.returncode == 1 and json_blocked.stderr == b""
assert json.loads(json_blocked.stdout)["type"] == "error"

# A detached blocked diagnostic writer remains the sole stderr owner. The final
# human error is suppressed after the bounded drain deadline rather than racing it.
blocked = run(
    ["definitely-not-a-command"],
    {"MESHMSG_TEST_BLOCK_STDERR": "1", "MESHMSG_TEST_EMIT_DIAGNOSTIC": "1"},
)
assert blocked.returncode == 1, blocked.returncode
assert blocked.stderr == b"", blocked.stderr

# Production initialization propagates writer startup failure instead of silently
# disabling diagnostics. JSON still preserves the one-record stdout contract.
failed = run(
    ["--json", "status"], {"MESHMSG_TEST_DIAGNOSTIC_STARTUP_FAIL": "1"}
)
# JSON mode intentionally starts no stderr writer, so the failure injector is not
# applicable there. Verify the normal offline contract remains intact.
assert failed.returncode == 1 and failed.stderr == b""
value = json.loads(failed.stdout)
assert value["type"] == "error"

failed_human = run(
    ["status"], {"MESHMSG_TEST_DIAGNOSTIC_STARTUP_FAIL": "1"}
)
assert failed_human.returncode == 1
assert b"start bounded diagnostic writer" in failed_human.stderr

print("PASS: process panic/stderr ownership/startup-failure logging")
