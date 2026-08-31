#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-integration.XXXXXX")
declare -A PIDS=()

cleanup() {
  set +e
  for node in "${!PIDS[@]}"; do
    "$BIN" --state-dir "$ROOT/$node" stop >/dev/null 2>&1
  done
  sleep 0.2
  for pid in "${PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for pid in "${PIDS[@]}"; do wait "$pid" >/dev/null 2>&1; done
  if [[ ${KEEP_MESHMSG_TEST_STATE:-0} != 1 ]]; then rm -rf "$ROOT"; else echo "kept test state: $ROOT"; fi
}
trap cleanup EXIT INT TERM

fail() { echo "integration failure: $* (artifacts: $ROOT)" >&2; exit 1; }
wait_for() {
  local seconds=$1 description=$2; shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timeout waiting for $description"
    sleep 0.2
  done
}
status_ok() { "$BIN" --state-dir "$ROOT/$1" --json status | grep -q '"running":true'; }
status_joined() {
  "$BIN" --state-dir "$ROOT/$1" --json status | python3 -c \
    'import json,sys; value=json.load(sys.stdin); assert value["topic_joined"] and value["neighbors"] >= 1'
}
start_node() {
  local node=$1
  RUST_LOG=meshmsg=trace timeout 1100 "$BIN" --state-dir "$ROOT/$node" --json daemon >"$ROOT/$node.daemon.log" 2>"$ROOT/$node.daemon.err" &
  PIDS[$node]=$!
  # Daemon startup permits 45 seconds for topic join followed by 30 seconds
  # for endpoint-online discovery; the harness must not reject a valid startup.
  wait_for 80 "$node daemon" status_ok "$node"
}
stop_node() {
  local node=$1
  "$BIN" --state-dir "$ROOT/$node" --json stop | grep -q '"type":"stopping"'
  wait "${PIDS[$node]}" || true
  unset 'PIDS[$node]'
}
invite() { "$BIN" --state-dir "$ROOT/$1" --json seed invite | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
wait_log() { wait_for "$1" "$3 in $2" grep -Fq "$3" "$2"; }

# Form a three-seed swarm.
"$BIN" --state-dir "$ROOT/s1" seed init >/dev/null
start_node s1
I1=$(invite s1)
"$BIN" --state-dir "$ROOT/s2" seed join "$I1" >/dev/null
start_node s2
I2=$(invite s2)
"$BIN" --state-dir "$ROOT/s3" seed join "$I2" >/dev/null
start_node s3
I3=$(invite s3)
for secret in "$I1" "$I2" "$I3"; do
  if grep -Fq "$secret" "$ROOT"/*.daemon.log "$ROOT"/*.daemon.err; then
    fail "daemon startup leaked an invite capability"
  fi
done
if grep -Fq '"invite":' "$ROOT"/*.daemon.log "$ROOT"/*.daemon.err; then
  fail "daemon startup output included an invite field"
fi

# Two resident member daemons and owner-only IPC listeners.
"$BIN" --state-dir "$ROOT/c1" join "$I3" >/dev/null
"$BIN" --state-dir "$ROOT/c2" join "$I3" >/dev/null
start_node c1
start_node c2
# The initial bootstrap neighbor consumed by subscribe_and_join remains visible
# in live status rather than waiting for a later NeighborUp event.
wait_for 10 "c1 joined status" status_joined c1
wait_for 10 "c2 joined status" status_joined c2
# Seed-only commands reject member state before touching daemon ownership.
if "$BIN" --state-dir "$ROOT/c1" seed invite >"$ROOT/member-seed-invite.out" 2>"$ROOT/member-seed-invite.err"; then
  fail "member state produced a seed invite"
fi
grep -q 'requires Seed state' "$ROOT/member-seed-invite.err" || fail "seed invite role rejection was not actionable"
if timeout 5 "$BIN" --state-dir "$ROOT/c1" seed run >"$ROOT/member-seed-run.out" 2>"$ROOT/member-seed-run.err"; then
  fail "member state started through seed run"
fi
grep -q 'requires Seed state' "$ROOT/member-seed-run.err" || fail "seed run role rejection was not actionable"
timeout 180 "$BIN" --state-dir "$ROOT/c1" --json listen >"$ROOT/c1.listen.log" 2>"$ROOT/c1.listen.err" & L1=$!
timeout 180 "$BIN" --state-dir "$ROOT/c2" --json listen >"$ROOT/c2.listen.log" 2>"$ROOT/c2.listen.err" & L2=$!
wait_log 10 "$ROOT/c1.listen.log" '"type":"connected"'
wait_log 10 "$ROOT/c2.listen.log" '"type":"connected"'

M1="integration-c1-$(date +%s%N)"
M2="integration-c2-$(date +%s%N)"
"$BIN" --state-dir "$ROOT/c1" --json send "$M1" | grep -q '"type":"queued"'
"$BIN" --state-dir "$ROOT/c2" --json send "$M2" | grep -q '"type":"queued"'
wait_log 30 "$ROOT/c2.listen.log" "\"body\":\"$M1\""
wait_log 30 "$ROOT/c1.listen.log" "\"body\":\"$M2\""
for seed in s1 s2 s3; do
  wait_for 30 "two suppressed messages at $seed" bash -c "test \$(grep -c '\"body_suppressed\":true' '$ROOT/$seed.daemon.log') -ge 2"
done
for node in s1 s2 s3 c1 c2; do
  for output in "$ROOT/$node.daemon.log" "$ROOT/$node.daemon.err"; do
    ! grep -Fq "$M1" "$output" || fail "$node daemon leaked message body to $output"
    ! grep -Fq "$M2" "$output" || fail "$node daemon leaked message body to $output"
  done
  "$BIN" --state-dir "$ROOT/$node" --json doctor | grep -q '"ok":true'
done

# A duplicate daemon must fail promptly while the original remains healthy.
if timeout 5 "$BIN" --state-dir "$ROOT/c1" daemon >"$ROOT/duplicate.out" 2>"$ROOT/duplicate.err"; then
  fail "duplicate daemon unexpectedly started"
fi
grep -Eq 'state is in use|already running' "$ROOT/duplicate.err" || fail "duplicate rejection was not actionable"
status_ok c1 || fail "duplicate attempt disturbed original daemon"

# Oversized application envelopes are rejected and are never reported queued.
OVERSIZED=$(python3 -c 'print("x" * 5000)')
if "$BIN" --state-dir "$ROOT/c1" --json send "$OVERSIZED" >"$ROOT/oversized.out" 2>"$ROOT/oversized.err"; then
  fail "oversized message unexpectedly succeeded"
fi
! grep -q '"type":"queued"' "$ROOT/oversized.out" || fail "oversized message was reported queued"
grep -q 'maximum is 4096 bytes' "$ROOT/oversized.err" || fail "oversized rejection was not actionable"

# Stale socket recovery and member daemon restart.
stop_node c1
kill "$L1" >/dev/null 2>&1 || true; wait "$L1" >/dev/null 2>&1 || true
echo stale >"$ROOT/c1/daemon.sock"
start_node c1
status_ok c1 || fail "member did not recover from stale socket"
timeout 180 "$BIN" --state-dir "$ROOT/c1" --json listen >"$ROOT/c1-restarted.listen.log" 2>/dev/null & L1=$!
wait_log 10 "$ROOT/c1-restarted.listen.log" '"type":"connected"'

# Stop one listed seed, restart a member, and verify failover through remaining seeds.
stop_node s1
stop_node c2
kill "$L2" >/dev/null 2>&1 || true; wait "$L2" >/dev/null 2>&1 || true
start_node c2
M3="integration-failover-$(date +%s%N)"
"$BIN" --state-dir "$ROOT/c2" --json send "$M3" | grep -q '"type":"queued"'
wait_log 30 "$ROOT/c1-restarted.listen.log" "\"body\":\"$M3\""

# Restart seeds using persisted state/endpoints; seed role and invite remain valid.
start_node s1
stop_node s3
start_node s3
"$BIN" --state-dir "$ROOT/s3" --json doctor | grep -q '"role":"seed"'
invite s3 >/dev/null

# Re-check both output streams after restart and failover traffic as well.
for node in s1 s2 s3 c1 c2; do
  for output in "$ROOT/$node.daemon.log" "$ROOT/$node.daemon.err"; do
    ! grep -Fq "$M3" "$output" || fail "$node daemon leaked failover message body to $output"
    ! grep -Fq '"invite":' "$output" || fail "$node daemon leaked an invite field to $output"
  done
done

kill "$L1" >/dev/null 2>&1 || true; wait "$L1" >/dev/null 2>&1 || true
echo "PASS: 3 seeds + 2 clients, privacy logs, restart/failover, IPC safety, and limits"
