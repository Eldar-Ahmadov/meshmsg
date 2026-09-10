#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-direct-integration.XXXXXX")
declare -A PIDS=()
declare -a LISTENER_PIDS=()
LISTENER_PID=
WEB_PID=
SSE_PID=

cleanup() {
  set +e
  [[ -n "$SSE_PID" ]] && kill "$SSE_PID" >/dev/null 2>&1
  [[ -n "$WEB_PID" ]] && kill "$WEB_PID" >/dev/null 2>&1
  for pid in "${LISTENER_PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for node in "${!PIDS[@]}"; do
    "$BIN" --state-dir "$ROOT/$node" stop >/dev/null 2>&1
  done
  for pid in "${PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for pid in "${LISTENER_PIDS[@]}"; do wait "$pid" >/dev/null 2>&1; done
  for pid in "${PIDS[@]}"; do wait "$pid" >/dev/null 2>&1; done
  if [[ ${KEEP_MESHMSG_TEST_STATE:-0} != 1 ]]; then
    rm -rf "$ROOT"
  else
    echo "kept test state: $ROOT"
  fi
}
trap cleanup EXIT INT TERM

fail() { echo "direct-message integration failure: $* (artifacts: $ROOT)" >&2; exit 1; }
wait_for() {
  local seconds=$1 description=$2; shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timeout waiting for $description"
    sleep 0.2
  done
}
status_ok() { "$BIN" --state-dir "$ROOT/$1" --json status | grep -q '"running":true'; }
status_aliases() {
  "$BIN" --state-dir "$ROOT/$1" --json status | python3 -c \
    'import json,sys; value=json.load(sys.stdin); assert value["advertised_aliases"] >= int(sys.argv[1])' "$2"
}
start_node() {
  local node=$1
  RUST_LOG=meshmsg=trace timeout 400 "$BIN" --state-dir "$ROOT/$node" --json daemon \
    >"$ROOT/$node.daemon.log" 2>"$ROOT/$node.daemon.err" &
  PIDS[$node]=$!
  wait_for 80 "$node daemon" status_ok "$node"
}
stop_node() {
  local node=$1
  "$BIN" --state-dir "$ROOT/$node" --json stop | grep -q '"type":"stopping"'
  wait "${PIDS[$node]}" || true
  unset 'PIDS[$node]'
}
start_listener() {
  local node=$1 output=$2
  timeout 300 "$BIN" --state-dir "$ROOT/$node" --json listen >"$output" 2>"$output.err" &
  LISTENER_PID=$!
  LISTENER_PIDS+=("$LISTENER_PID")
}
json_invite() {
  "$BIN" --state-dir "$ROOT/$1" --json invite | python3 -c \
    'import json,sys; print(json.load(sys.stdin)["token"])'
}

# Hostname defaults are captured once in persistent state. Override, clear,
# explicit opt-out, and recapture are all offline state operations.
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json init >"$ROOT/alias-init.json"
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias show >"$ROOT/alias-default.json"
python3 - "$ROOT/alias-default.json" <<'PY'
import json, pathlib, socket, sys
shown = json.loads(pathlib.Path(sys.argv[1]).read_text())
request_id = shown.pop("request_id")
assert len(request_id) == 32
hostname = socket.gethostname().split('.', 1)[0].lower()
assert shown == {
    "schema_version": 1,
    "type": "alias", "enabled": True, "hostname": hostname,
    "custom": None, "alias": hostname,
}
PY
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias set Mixed-Node >"$ROOT/alias-set.json"
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["alias"] == v["custom"] == "mixed-node" and v["enabled"]' \
  <"$ROOT/alias-set.json" || fail "custom alias was not normalized and enabled"
if "$BIN" --state-dir "$ROOT/alias-lifecycle" alias set invalid_name >"$ROOT/invalid-alias.out" 2>"$ROOT/invalid-alias.err"; then
  fail "invalid alias was accepted"
fi
grep -q 'letters, digits, and hyphens' "$ROOT/invalid-alias.err" || fail "invalid alias error was not actionable"
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias show | python3 -c \
  'import json,sys; assert json.load(sys.stdin)["alias"] == "mixed-node"' \
  || fail "failed alias update mutated persistent state"
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias clear | python3 -c \
  'import json,sys; v=json.load(sys.stdin); assert not v["enabled"] and v["custom"] is None and v["alias"] is None' \
  || fail "alias clear did not persist the privacy opt-out"
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias disable | python3 -c \
  'import json,sys; v=json.load(sys.stdin); assert not v["enabled"] and v["alias"] is None' \
  || fail "alias disable synonym did not remain opted out"
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias reset-hostname | python3 -c \
  'import json,sys; v=json.load(sys.stdin); assert v["enabled"] and v["alias"] == v["hostname"] and v["custom"] is None' \
  || fail "hostname reset did not recapture and enable the default alias"
OLD_ALIAS_PEER=$(python3 -c 'import json,sys; print(json.load(sys.stdin)["peer"])' <"$ROOT/alias-init.json")
FORCED=$({ "$BIN" --state-dir "$ROOT/alias-lifecycle" --json init --force --no-default-alias; })
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["peer"] != sys.argv[1] and not v["alias_enabled"] and v["alias"] is None' "$OLD_ALIAS_PEER" \
  <<<"$FORCED" || fail "forced opt-out retained the previous identity or enabled alias"
"$BIN" --state-dir "$ROOT/alias-lifecycle" --json alias show | python3 -c \
  'import json,sys; v=json.load(sys.stdin); assert not v["enabled"] and v["hostname"] is None and v["alias"] is None' \
  || fail "forced replacement retained stale alias state"
"$BIN" --state-dir "$ROOT/no-alias" --json init --no-default-alias >/dev/null
"$BIN" --state-dir "$ROOT/no-alias" --json alias show | python3 -c \
  'import json,sys; v=json.load(sys.stdin); r=v.pop("request_id"); assert len(r) == 32 and v == {"type":"alias","schema_version":1,"enabled":False,"hostname":None,"custom":None,"alias":None}' \
  || fail "init --no-default-alias did not persist explicit opt-out"
cp "$ROOT/no-alias/alias.json" "$ROOT/no-alias/alias.json.saved"
cp "$ROOT/alias-lifecycle/alias.json" "$ROOT/no-alias/alias.json"
if "$BIN" --state-dir "$ROOT/no-alias" doctor >"$ROOT/mismatched-alias.out" 2>"$ROOT/mismatched-alias.err"; then
  fail "doctor accepted alias state bound to a different identity"
fi
grep -q 'does not match the selected identity' "$ROOT/mismatched-alias.err" \
  || fail "alias identity mismatch did not fail closed with an actionable error"
mv "$ROOT/no-alias/alias.json.saved" "$ROOT/no-alias/alias.json"

# Form three local processes. The recipient starts with a unique alias while a
# third online topic peer proves private traffic is not broadcast.
"$BIN" --state-dir "$ROOT/sender" init --no-default-alias >/dev/null
"$BIN" --state-dir "$ROOT/sender" alias set sender-node >/dev/null
start_node sender
INVITE=$(json_invite sender)
"$BIN" --state-dir "$ROOT/join-default" join "$INVITE" >/dev/null
"$BIN" --state-dir "$ROOT/join-default" --json alias show | python3 -c \
  'import json,socket,sys; v=json.load(sys.stdin); h=socket.gethostname().split(".",1)[0].lower(); assert v["enabled"] and v["hostname"] == h and v["alias"] == h' \
  || fail "join did not persist the captured hostname default"
"$BIN" --state-dir "$ROOT/receiver" join --no-default-alias "$INVITE" >/dev/null
"$BIN" --state-dir "$ROOT/receiver" alias set target-node >/dev/null
"$BIN" --state-dir "$ROOT/spy" join --no-default-alias "$INVITE" >/dev/null
"$BIN" --state-dir "$ROOT/spy" alias set collision-node >/dev/null
start_node receiver
start_node spy
wait_for 40 "two signed aliases at sender" status_aliases sender 2

# Alias state cannot race a running daemon's captured configuration.
if "$BIN" --state-dir "$ROOT/sender" alias set racing-update >"$ROOT/locked-alias.out" 2>"$ROOT/locked-alias.err"; then
  fail "alias changed while daemon held the state lock"
fi
grep -q 'state is in use' "$ROOT/locked-alias.err" || fail "running-daemon alias rejection was not actionable"

start_listener sender "$ROOT/sender.listen.log"; SENDER_LISTEN=$LISTENER_PID
start_listener receiver "$ROOT/receiver.listen.log"; RECEIVER_LISTEN=$LISTENER_PID
start_listener spy "$ROOT/spy.listen.log"; SPY_LISTEN=$LISTENER_PID
wait_for 10 "sender listener" grep -Fq '"type":"connected"' "$ROOT/sender.listen.log"
wait_for 10 "receiver listener" grep -Fq '"type":"connected"' "$ROOT/receiver.listen.log"
wait_for 10 "spy listener" grep -Fq '"type":"connected"' "$ROOT/spy.listen.log"
wait_for 40 "sender presence at receiver" status_aliases receiver 2

SENDER_STATUS=$("$BIN" --state-dir "$ROOT/sender" --json status)
SENDER_PEER=$(python3 -c \
  'import json,sys; v=json.load(sys.stdin); assert "private_send_v2" in v["ipc_capabilities"]; print(v["peer"])' \
  <<<"$SENDER_STATUS") || fail "current daemon did not advertise safe private-send IPC"

# Private positional/file/stdin inputs retain their independent 4096-byte
# contract, while broadcasts are covered by the v0.1.18 boundary scenario.
for size in 3900 3901 4096 4097; do
  python3 -c 'import pathlib,sys; pathlib.Path(sys.argv[1]).write_text("p" * int(sys.argv[2]))' \
    "$ROOT/private-$size.txt" "$size"
done
assert_private_result() {
  local path=$1 size=$2 form=$3
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["type"] == "private_accepted" and v["body_bytes"] == int(sys.argv[2])' \
    "$path" "$size" || fail "$form private $size-byte input was not accepted"
}
for size in 3900 3901 4096; do
  body=$(python3 -c 'print("p" * int(__import__("sys").argv[1]), end="")' "$size")
  "$BIN" --state-dir "$ROOT/sender" --json send --to target-node "$body" >"$ROOT/private-positional-$size.out"
  assert_private_result "$ROOT/private-positional-$size.out" "$size" positional
  "$BIN" --state-dir "$ROOT/sender" --json send --to target-node --message-file "$ROOT/private-$size.txt" >"$ROOT/private-file-$size.out"
  assert_private_result "$ROOT/private-file-$size.out" "$size" file
  printf '%s' "$body" | "$BIN" --state-dir "$ROOT/sender" --json send --to target-node --message-stdin >"$ROOT/private-stdin-$size.out"
  assert_private_result "$ROOT/private-stdin-$size.out" "$size" stdin
done
for form in positional file stdin; do
  output="$ROOT/private-$form-4097.out"
  case "$form" in
    positional) body=$(python3 -c 'print("p" * 4097, end="")'); command=("$BIN" --state-dir "$ROOT/sender" --json send --to target-node "$body") ;;
    file) command=("$BIN" --state-dir "$ROOT/sender" --json send --to target-node --message-file "$ROOT/private-4097.txt") ;;
    stdin) command=("$BIN" --state-dir "$ROOT/sender" --json send --to target-node --message-stdin) ;;
  esac
  if [[ "$form" == stdin ]]; then
    if cat "$ROOT/private-4097.txt" | "${command[@]}" >"$output" 2>"$output.err"; then fail "stdin private 4097-byte input was accepted"; fi
  elif "${command[@]}" >"$output" 2>"$output.err"; then
    fail "$form private 4097-byte input was accepted"
  fi
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "invalid_message" and v["outcome"] == "not_started" and len(v["operation_id"]) == 32' \
    "$output" || fail "$form private oversized error was not canonical"
done

# The receiver learned the sender from its invite. Exercise that identity after
# dynamic presence has updated the same peer so route replacement cannot discard
# the separately pinned bootstrap route.
PINNED="private-pinned-bootstrap-$(date +%s%N)"
PINNED_RESULT=$("$BIN" --state-dir "$ROOT/receiver" --json send --to "$SENDER_PEER" "$PINNED")
python3 -c \
  'import json,sys; v=json.load(sys.stdin); assert v["type"] == "private_accepted" and v["to"] == sys.argv[1] and "body" not in v' \
  "$SENDER_PEER" <<<"$PINNED_RESULT" \
  || fail "invite-pinned private route was not authenticated and acknowledged"
wait_for 30 "invite-pinned private delivery" grep -Fq "\"body\":\"$PINNED\"" "$ROOT/sender.listen.log"
! grep -Fq "$PINNED" "$ROOT/spy.listen.log" || fail "invite-pinned private body reached a third peer"

# Attach the broadcast-only web bridge to the receiver before delivering a DM.
WEB_PORT=$(python3 - <<'PY'
import socket
s = socket.socket(); s.bind(('127.0.0.1', 0)); print(s.getsockname()[1]); s.close()
PY
)
timeout 300 "$BIN" --state-dir "$ROOT/receiver" web --listen "127.0.0.1:$WEB_PORT" \
  >"$ROOT/web.log" 2>"$ROOT/web.err" & WEB_PID=$!
wait_for 10 "web listener" curl -fsS "http://127.0.0.1:$WEB_PORT/"
timeout 60 curl --no-buffer --silent --show-error "http://127.0.0.1:$WEB_PORT/api/events" \
  >"$ROOT/web.sse" 2>"$ROOT/web.sse.err" & SSE_PID=$!
wait_for 10 "web SSE subscription" grep -Fq '"type":"connected"' "$ROOT/web.sse"

PRIVATE="private-alias-$(date +%s%N)"
PRIVATE_RESULT=$("$BIN" --state-dir "$ROOT/sender" --json send --to target-node "$PRIVATE")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "private_accepted" and v["schema_version"] == 3; assert v["operation_id"] == v["message_id"]; assert v["acceptance_acknowledged"] is True and v["duplicate_accepted"] is False and v["durable"] is False and v["read"] is False; assert v["body_bytes"] == int(sys.argv[1]) and "body" not in v; assert len(v["message_id"]) == 32' "${#PRIVATE}" \
  <<<"$PRIVATE_RESULT" || fail "private alias send did not return the bounded acceptance acknowledgement"
wait_for 30 "private alias delivery" grep -Fq "\"body\":\"$PRIVATE\"" "$ROOT/receiver.listen.log"
sleep 1
! grep -Fq "$PRIVATE" "$ROOT/sender.listen.log" || fail "sender subscription received its outgoing private body"
! grep -Fq "$PRIVATE" "$ROOT/spy.listen.log" || fail "third topic peer received private body"
! grep -Fq "$PRIVATE" "$ROOT/web.sse" || fail "web SSE exposed private body"

RECEIVER_PEER=$("$BIN" --state-dir "$ROOT/receiver" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer"])')
CANONICAL="private-key-$(date +%s%N)"
CANONICAL_RESULT=$("$BIN" --state-dir "$ROOT/sender" --json send --to "$RECEIVER_PEER" "$CANONICAL")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "private_accepted" and v["to"] == sys.argv[1] and "body" not in v' "$RECEIVER_PEER" \
  <<<"$CANONICAL_RESULT" || fail "canonical-key private send was not authenticated and acknowledged"
wait_for 30 "canonical-key private delivery" grep -Fq "\"body\":\"$CANONICAL\"" "$ROOT/receiver.listen.log"
! grep -Fq "$CANONICAL" "$ROOT/spy.listen.log" || fail "canonical-key private body reached a third peer"

# The no---to path remains the existing gossip broadcast with its old result.
BROADCAST="broadcast-control-$(date +%s%N)"
BROADCAST_RESULT=$("$BIN" --state-dir "$ROOT/sender" --json send "$BROADCAST")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "queued" and v["body"] == sys.argv[1] and v["delivery_acknowledged"] is False' "$BROADCAST" \
  <<<"$BROADCAST_RESULT" || fail "ordinary send no longer followed broadcast semantics"
wait_for 30 "receiver broadcast" grep -Fq "\"body\":\"$BROADCAST\"" "$ROOT/receiver.listen.log"
wait_for 30 "spy broadcast" grep -Fq "\"body\":\"$BROADCAST\"" "$ROOT/spy.listen.log"

# Change one signed claim so two distinct canonical identities advertise the
# same alias. The sender must forget the superseded claim and fail closed.
kill "$RECEIVER_LISTEN" >/dev/null 2>&1 || true
wait "$RECEIVER_LISTEN" >/dev/null 2>&1 || true
[[ -n "$SSE_PID" ]] && kill "$SSE_PID" >/dev/null 2>&1 || true
[[ -n "$SSE_PID" ]] && wait "$SSE_PID" >/dev/null 2>&1 || true
SSE_PID=
[[ -n "$WEB_PID" ]] && kill "$WEB_PID" >/dev/null 2>&1 || true
[[ -n "$WEB_PID" ]] && wait "$WEB_PID" >/dev/null 2>&1 || true
WEB_PID=
stop_node receiver
"$BIN" --state-dir "$ROOT/receiver" alias set collision-node >/dev/null
start_node receiver
start_listener receiver "$ROOT/receiver-restarted.listen.log"; RECEIVER_LISTEN=$LISTENER_PID
wait_for 10 "restarted receiver listener" grep -Fq '"type":"connected"' "$ROOT/receiver-restarted.listen.log"

target_absent() {
  if "$BIN" --state-dir "$ROOT/sender" send --to target-node alias-refresh-probe \
      >"$ROOT/old-alias.out" 2>"$ROOT/old-alias.err"; then
    return 1
  fi
  grep -q 'recipient_unresolved' "$ROOT/old-alias.err"
}
wait_for 45 "superseded signed alias to disappear" target_absent
COLLISION="collision-secret-$(date +%s%N)"
if "$BIN" --state-dir "$ROOT/sender" --json send --to collision-node "$COLLISION" \
    >"$ROOT/collision.out" 2>"$ROOT/collision.err"; then
  fail "colliding alias selected a recipient"
fi
grep -q '"code":"recipient_unresolved"' "$ROOT/collision.out" || fail "alias collision lacked a stable error code"
test ! -s "$ROOT/collision.err" || fail "JSON alias collision wrote to stderr"
sleep 2
! grep -Fq "$COLLISION" "$ROOT/receiver-restarted.listen.log" || fail "colliding alias delivered to one claimant"
! grep -Fq "$COLLISION" "$ROOT/spy.listen.log" || fail "colliding alias delivered to another claimant"

# Private contents may appear only in the explicit owner CLI subscription, not
# daemon diagnostics, sender responses, or the broadcast-only web process/feed.
for secret in "$PINNED" "$PRIVATE" "$CANONICAL" "$COLLISION"; do
  for output in "$ROOT"/*.daemon.log "$ROOT"/*.daemon.err "$ROOT"/web.log "$ROOT"/web.err "$ROOT"/web.sse "$ROOT"/collision.out "$ROOT"/collision.err; do
    [[ -e "$output" ]] || continue
    ! grep -Fq "$secret" "$output" || fail "private body leaked to $output"
  done
done
for node in sender receiver spy; do
  "$BIN" --state-dir "$ROOT/$node" --json doctor | python3 -c \
    'import json,sys; assert json.load(sys.stdin)["ok"] is True' \
    || fail "$node doctor did not validate alias state"
done

kill "$SENDER_LISTEN" "$RECEIVER_LISTEN" "$SPY_LISTEN" >/dev/null 2>&1 || true
wait "$SENDER_LISTEN" "$RECEIVER_LISTEN" "$SPY_LISTEN" >/dev/null 2>&1 || true
echo "PASS: persistent hostname aliases, opt-out/override/clear, signed unique resolution, collision fail-closed, positional/file/stdin private 3900/3901/4096/4097 boundaries, authenticated private acknowledgements, broadcast compatibility, and DM log/web privacy"
