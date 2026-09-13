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
status_not_joined() {
  "$BIN" --state-dir "$ROOT/$1" --json status | python3 -c \
    'import json,sys; value=json.load(sys.stdin); assert not value["topic_joined"] and value["neighbors"] == 0'
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
invite() { "$BIN" --state-dir "$ROOT/$1" --json invite | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])'; }
wait_log() { wait_for "$1" "$3 in $2" grep -Fq "$3" "$2"; }

# Form a five-peer swarm with three endpoint-advertising peers.
S1_INIT=$("$BIN" --state-dir "$ROOT/s1" --json init)
S1_PEER=$(python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["advertises_self"] and not value["has_invite"]; print(value["peer"])' <<<"$S1_INIT")
if "$BIN" --state-dir "$ROOT/s1" invite >"$ROOT/fresh-invite.out" 2>"$ROOT/fresh-invite.err"; then
  fail "fresh init exported an invite before daemon startup"
fi
grep -q 'run `meshmsg daemon` first' "$ROOT/fresh-invite.err" || fail "fresh invite error was not actionable"
start_node s1
I1=$(invite s1)
printf '%s' "$I1" >"$ROOT/s2.invite"
"$BIN" --state-dir "$ROOT/s2" join --advertise-self --token-file "$ROOT/s2.invite" >/dev/null
start_node s2
I2=$(invite s2)
"$BIN" --state-dir "$ROOT/s3" join --advertise-self "$I2" >/dev/null
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

# Add two non-advertising peers and owner-only IPC listeners.
printf '%s\n' "$I3" | "$BIN" --state-dir "$ROOT/c1" join --token-stdin >/dev/null
"$BIN" --state-dir "$ROOT/c2" join "$I3" >/dev/null
start_node c1
start_node c2
# The initial bootstrap neighbor consumed by subscribe_and_join remains visible
# in live status rather than waiting for a later NeighborUp event.
wait_for 10 "c1 joined status" status_joined c1
wait_for 10 "c2 joined status" status_joined c2
# Every peer can export its stored invite, while default join does not advertise itself.
C1_INVITE=$(invite c1)
[[ "$C1_INVITE" == "$I3" ]] || fail "non-advertising peer did not export its stored invite"
"$BIN" --state-dir "$ROOT/c1" --json doctor | python3 -c 'import json,sys; value=json.load(sys.stdin); assert not value["advertises_self"] and value["has_invite"] and not value["self_advertised"]'
timeout 180 "$BIN" --state-dir "$ROOT/c1" --json listen >"$ROOT/c1.listen.log" 2>"$ROOT/c1.listen.err" & L1=$!
timeout 180 "$BIN" --state-dir "$ROOT/c2" --json listen >"$ROOT/c2.listen.log" 2>"$ROOT/c2.listen.err" & L2=$!
wait_log 10 "$ROOT/c1.listen.log" '"type":"connected"'
wait_log 10 "$ROOT/c2.listen.log" '"type":"connected"'

M1="integration-c1-$(date +%s%N)"
M2="integration-c2-$(date +%s%N)"
printf '%s' "$M1" >"$ROOT/message.txt"
Q1=$("$BIN" --state-dir "$ROOT/c1" --json send --message-file "$ROOT/message.txt")
Q2=$(printf '%s' "$M2" | "$BIN" --state-dir "$ROOT/c2" --json send --message-stdin)
python3 -c 'import json,sys; v=json.loads(sys.argv[1]); assert v["type"] == "queued" and v["protocol_version"] == 3 and len(v["request_id"]) == 32 and v["operation_id"] == v["message_id"] and len(v["message_id"]) == 32' "$Q1"
python3 -c 'import json,sys; v=json.loads(sys.argv[1]); assert v["type"] == "queued" and v["protocol_version"] == 3 and len(v["request_id"]) == 32 and v["operation_id"] == v["message_id"] and len(v["message_id"]) == 32' "$Q2"
wait_log 30 "$ROOT/c2.listen.log" "\"body\":\"$M1\""
wait_log 30 "$ROOT/c1.listen.log" "\"body\":\"$M2\""
python3 - "$Q1" "$Q2" "$ROOT/c2.listen.log" "$ROOT/c1.listen.log" <<'PY'
import json, pathlib, sys
for queued_text, log_path in [(sys.argv[1], sys.argv[3]), (sys.argv[2], sys.argv[4])]:
    queued = json.loads(queued_text)
    received = next(v for v in map(json.loads, pathlib.Path(log_path).read_text().splitlines())
                    if v.get("type") == "message" and v.get("message_id") == queued["message_id"])
    assert received["protocol_version"] == 3 and len(received["request_id"]) == 32
    assert received["from"] == queued["from"]
    assert received["timestamp_ms"] == queued["timestamp_ms"]
    assert received["body"] == queued["body"]
PY

python3 - "$ROOT/s1/config.json" "$ROOT/s2/config.json" "$ROOT/s3/config.json" "$ROOT/c1/config.json" "$ROOT/c2/config.json" <<'PY'
import json, pathlib, sys
for index, name in enumerate(sys.argv[1:]):
    state = json.loads(pathlib.Path(name).read_text())
    assert set(state) == {"schema_version", "advertise_self", "topic", "invite", "identity"}
    assert state["schema_version"] == 1
    assert state["advertise_self"] is (index < 3)
PY
for node in s1 s2 s3 c1 c2; do
  test ! -s "$ROOT/$node.daemon.log" || fail "$node daemon mirrored events to stdout"
  for output in "$ROOT/$node.daemon.log" "$ROOT/$node.daemon.err"; do
    ! grep -Fq "$M1" "$output" || fail "$node daemon leaked message body to $output"
    ! grep -Fq "$M2" "$output" || fail "$node daemon leaked message body to $output"
  done
  "$BIN" --state-dir "$ROOT/$node" --json doctor | grep -q '"ok":true'
done
S1_DOCTOR_PEER=$("$BIN" --state-dir "$ROOT/s1" --json doctor | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer"])')
[[ "$S1_DOCTOR_PEER" == "$S1_PEER" ]] || fail "doctor peer differs from committed initialization peer"

# Doctor must reject a valid but incorrect expected public key.
cp "$ROOT/s1/config.json" "$ROOT/s1/config.json.saved"
python3 - "$ROOT/s1/config.json" "$ROOT/s2/config.json" <<'PY'
import json, pathlib, sys
left, right = map(pathlib.Path, sys.argv[1:])
state = json.loads(left.read_text())
state["identity"]["public_key"] = json.loads(right.read_text())["identity"]["public_key"]
left.write_text(json.dumps(state))
PY
if "$BIN" --state-dir "$ROOT/s1" doctor >"$ROOT/mismatch.out" 2>"$ROOT/mismatch.err"; then
  fail "doctor accepted an expected-public-key mismatch"
fi
grep -q 'does not match' "$ROOT/mismatch.err" || fail "doctor mismatch error was not actionable"
mv "$ROOT/s1/config.json.saved" "$ROOT/s1/config.json"

# A duplicate daemon must fail promptly while the original remains healthy.
if timeout 5 "$BIN" --state-dir "$ROOT/c1" daemon >"$ROOT/duplicate.out" 2>"$ROOT/duplicate.err"; then
  fail "duplicate daemon unexpectedly started"
fi
grep -Eq 'state is in use|already running' "$ROOT/duplicate.err" || fail "duplicate rejection was not actionable"
status_ok c1 || fail "duplicate attempt disturbed original daemon"

# Exercise the exact V3 body boundary through real process, IPC, Gossip, and
# subscription framing. File/stdin/positional/chat all accept the same maximum.
python3 - "$ROOT/max-message.txt" "$ROOT/oversized-message.txt" <<'PY'
import pathlib, sys
pathlib.Path(sys.argv[1]).write_bytes(b"x" * 65358)
pathlib.Path(sys.argv[2]).write_bytes(b"x" * 65359)
PY
QMAX_FILE=$("$BIN" --state-dir "$ROOT/c1" --json send --message-file "$ROOT/max-message.txt")
QMAX_STDIN=$("$BIN" --state-dir "$ROOT/c1" --json send --message-stdin <"$ROOT/max-message.txt")
MAX_POSITIONAL=$(cat "$ROOT/max-message.txt")
QMAX_POSITIONAL=$("$BIN" --state-dir "$ROOT/c1" --json send "$MAX_POSITIONAL")
printf '%s\n' "$MAX_POSITIONAL" | timeout 30 "$BIN" --state-dir "$ROOT/c1" --json chat >"$ROOT/max-chat.out" 2>"$ROOT/max-chat.err" || fail "chat rejected the exact broadcast maximum"
for queued in "$QMAX_FILE" "$QMAX_STDIN" "$QMAX_POSITIONAL"; do
  python3 -c 'import json,sys; v=json.loads(sys.argv[1]); assert v["protocol_version"] == 3 and v["type"] == "queued" and len(v["body"].encode()) == 65358' "$queued" || fail "maximum broadcast response was invalid"
done
MAX_ID=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["message_id"])' "$QMAX_FILE")
wait_for 30 "maximum broadcast subscription event" python3 -c 'import json,sys; assert any(v.get("message_id") == sys.argv[2] and len(v.get("body", "").encode()) == 65358 for v in map(json.loads, open(sys.argv[1])))' "$ROOT/c2.listen.log" "$MAX_ID"
test ! -s "$ROOT/max-chat.err" || fail "exact maximum chat wrote an error"

# 65,359-byte inputs fail before IPC admission for every non-chat source; chat's
# bounded line reader also rejects without allocating past limit plus two.
OVERSIZED=$(cat "$ROOT/oversized-message.txt")
for source in positional file stdin; do
  case "$source" in
    positional) command=("$BIN" --state-dir "$ROOT/c1" --json send "$OVERSIZED") ;;
    file) command=("$BIN" --state-dir "$ROOT/c1" --json send --message-file "$ROOT/oversized-message.txt") ;;
    stdin) command=("$BIN" --state-dir "$ROOT/c1" --json send --message-stdin) ;;
  esac
  if [[ $source == stdin ]]; then
    "${command[@]}" <"$ROOT/oversized-message.txt" >"$ROOT/oversized-$source.out" 2>"$ROOT/oversized-$source.err" && fail "oversized $source message unexpectedly succeeded"
  else
    "${command[@]}" >"$ROOT/oversized-$source.out" 2>"$ROOT/oversized-$source.err" && fail "oversized $source message unexpectedly succeeded"
  fi
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "invalid_message" and v["outcome"] == "not_started" and len(v["operation_id"]) == 32' "$ROOT/oversized-$source.out" || fail "oversized $source rejection had the wrong stable contract"
  test ! -s "$ROOT/oversized-$source.err" || fail "oversized $source JSON failure wrote to stderr"
done
if printf '%s\n' "$OVERSIZED" | timeout 30 "$BIN" --state-dir "$ROOT/c1" --json chat >"$ROOT/oversized-chat.out" 2>"$ROOT/oversized-chat.err"; then
  fail "oversized chat message unexpectedly succeeded"
fi
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["type"] == "error" and v["protocol_version"] == 3' "$ROOT/oversized-chat.out" || fail "oversized chat rejection was not machine-readable"
test ! -s "$ROOT/oversized-chat.err" || fail "oversized chat JSON failure wrote to stderr"

# Stale socket recovery and peer daemon restart.
stop_node c1
kill "$L1" >/dev/null 2>&1 || true; wait "$L1" >/dev/null 2>&1 || true
echo stale >"$ROOT/c1/daemon.sock"
start_node c1
status_ok c1 || fail "peer did not recover from stale socket"
timeout 180 "$BIN" --state-dir "$ROOT/c1" --json listen >"$ROOT/c1-restarted.listen.log" 2>/dev/null & L1=$!
wait_log 10 "$ROOT/c1-restarted.listen.log" '"type":"connected"'

# Stop one listed bootstrap peer, restart another peer, and verify failover.
stop_node s1
stop_node c2
kill "$L2" >/dev/null 2>&1 || true; wait "$L2" >/dev/null 2>&1 || true
start_node c2
M3="integration-failover-$(date +%s%N)"
"$BIN" --state-dir "$ROOT/c2" --json send "$M3" | grep -q '"type":"queued"'
wait_log 30 "$ROOT/c1-restarted.listen.log" "\"body\":\"$M3\""

# Restart advertising peers using persisted state/endpoints; refreshed invites remain valid.
start_node s1
stop_node s3
start_node s3
"$BIN" --state-dir "$ROOT/s3" --json doctor | python3 -c 'import json,sys; value=json.load(sys.stdin); assert value["advertises_self"] and value["self_advertised"]'
invite s3 >/dev/null

# Isolate a running peer, restore one configured bootstrap peer, and verify the
# isolated daemon rejoins without being restarted itself.
stop_node s1
stop_node s2
stop_node s3
stop_node c2
wait_for 30 "c1 to lose all gossip neighbors" status_not_joined c1
start_node s1
wait_for 30 "c1 to rejoin after connectivity restoration" status_joined c1
M4="integration-rejoin-$(date +%s%N)"
"$BIN" --state-dir "$ROOT/s1" --json send "$M4" | grep -q '"type":"queued"'
wait_log 30 "$ROOT/c1-restarted.listen.log" "\"body\":\"$M4\""

# Re-check both output streams after restart, failover, and rejoin traffic.
for node in s1 s2 s3 c1 c2; do
  test ! -s "$ROOT/$node.daemon.log" || fail "$node daemon mirrored events to stdout"
  for output in "$ROOT/$node.daemon.log" "$ROOT/$node.daemon.err"; do
    ! grep -Fq "$M3" "$output" || fail "$node daemon leaked failover message body to $output"
    ! grep -Fq "$M4" "$output" || fail "$node daemon leaked rejoin message body to $output"
    ! grep -Fq '"invite":' "$output" || fail "$node daemon leaked an invite field to $output"
  done
done

kill "$L1" >/dev/null 2>&1 || true; wait "$L1" >/dev/null 2>&1 || true
echo "PASS: 5 equal peers, V3 65,358-byte positional/file/stdin/chat boundary and subscription delivery, listen-only events/no daemon stdout, selective endpoint advertising, restart/failover/rejoin, IPC safety, and limits"
