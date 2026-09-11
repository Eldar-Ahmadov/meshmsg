#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-idempotency.XXXXXX")
declare -A PIDS=()
cleanup() {
  set +e
  for node in "${!PIDS[@]}"; do "$BIN" --state-dir "$ROOT/$node" stop >/dev/null 2>&1; done
  for pid in "${PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for pid in "${PIDS[@]}"; do wait "$pid" >/dev/null 2>&1; done
  rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM
fail() { echo "idempotency integration failure: $* (artifacts: $ROOT)" >&2; exit 1; }
wait_for() {
  local seconds=$1 description=$2; shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timeout waiting for $description"
    sleep 0.2
  done
}
status_ok() { "$BIN" --state-dir "$ROOT/$1" --json status | grep -q '"running":true'; }
knows_peer() { "$BIN" --state-dir "$ROOT/$1" --json status | python3 -c 'import json,sys; assert json.load(sys.stdin)["advertised_aliases"] >= 1'; }
start_node() {
  local node=$1
  timeout 300 "$BIN" --state-dir "$ROOT/$node" --json daemon >"$ROOT/$node.daemon.log" 2>"$ROOT/$node.daemon.err" &
  PIDS[$node]=$!
  wait_for 80 "$node daemon" status_ok "$node"
}
stop_node() {
  local node=$1
  "$BIN" --state-dir "$ROOT/$node" --json stop >/dev/null
  wait "${PIDS[$node]}" || true
  unset 'PIDS[$node]'
}
ipc() {
  python3 - "$ROOT/$1/daemon.sock" "$2" <<'PY'
import json,socket,sys
request=json.loads(sys.argv[2]); envelope={'schema_version':1,'request_id':'9'*32,'request':request}
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.sendall(json.dumps(envelope).encode()+b'\n')
data=b''
while not data.endswith(b'\n'):
    chunk=s.recv(65536)
    if not chunk: break
    data += chunk
print(data.decode().strip())
PY
}

"$BIN" --state-dir "$ROOT/sender" init >/dev/null
start_node sender
INVITE=$("$BIN" --state-dir "$ROOT/sender" --json invite | python3 -c 'import json,sys; print(json.load(sys.stdin)["token"])')
"$BIN" --state-dir "$ROOT/receiver" join "$INVITE" >/dev/null
start_node receiver
RECEIVER=$("$BIN" --state-dir "$ROOT/receiver" --json status | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer"])')
timeout 240 "$BIN" --state-dir "$ROOT/receiver" --json listen >"$ROOT/receiver.listen" 2>"$ROOT/receiver.listen.err" &
LISTENER=$!
wait_for 10 "receiver listener" grep -q '"type":"connected"' "$ROOT/receiver.listen"

# Empty text is rejected before daemon admission from the CLI, and the daemon
# independently rejects a crafted IPC request without reserving its operation ID.
EMPTY_ID=00000000000000000000000000000001
if "$BIN" --state-dir "$ROOT/sender" --json send --operation-id "$EMPTY_ID" '' >"$ROOT/empty-cli.out" 2>"$ROOT/empty-cli.err"; then
  fail "empty positional CLI send succeeded"
fi
[[ ! -s "$ROOT/empty-cli.err" ]] || fail "empty JSON CLI send wrote stderr"
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "invalid_message" and v["outcome"] == "not_started" and v["operation_id"] == sys.argv[2]' "$ROOT/empty-cli.out" "$EMPTY_ID" \
  || fail "empty CLI send did not preserve canonical error and operation ID"
: >"$ROOT/empty-message"
if "$BIN" --state-dir "$ROOT/sender" --json send --message-file "$ROOT/empty-message" >"$ROOT/empty-file.out" 2>"$ROOT/empty-file.err"; then
  fail "empty file CLI send succeeded"
fi
if printf '' | "$BIN" --state-dir "$ROOT/sender" --json send --message-stdin >"$ROOT/empty-stdin.out" 2>"$ROOT/empty-stdin.err"; then
  fail "empty stdin CLI send succeeded"
fi
for form in file stdin; do
  [[ ! -s "$ROOT/empty-$form.err" ]] || fail "empty $form JSON CLI send wrote stderr"
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "invalid_message" and v["outcome"] == "not_started" and len(v["operation_id"]) == 32' "$ROOT/empty-$form.out" \
    || fail "empty $form CLI send did not report canonical not_started with generated ID"
done
EMPTY_IPC=$(ipc sender "{\"command\":\"send\",\"operation_id\":\"$EMPTY_ID\",\"body\":\"\"}")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "invalid_message" and v["outcome"] == "not_started" and v["operation_id"] == sys.argv[1]' "$EMPTY_ID" <<<"$EMPTY_IPC" \
  || fail "daemon did not reject empty IPC send before admission"
sleep 1
! grep -Fq '"body":""' "$ROOT/receiver.listen" || fail "empty rejection reached the wire/feed"
REUSED=$("$BIN" --state-dir "$ROOT/sender" --json send --operation-id "$EMPTY_ID" operation-id-reused-after-empty)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "queued" and v["operation_id"] == sys.argv[1]' "$EMPTY_ID" <<<"$REUSED" \
  || fail "operation ID was consumed by empty rejection"
wait_for 30 "reused operation ID broadcast" grep -Fq '"body":"operation-id-reused-after-empty"' "$ROOT/receiver.listen"

# Submit then discard the response. Retrying with the caller's ID must return the
# cached outcome and must not broadcast a second envelope.
SEND_ID=11111111111111111111111111111111
python3 - "$ROOT/sender/daemon.sock" "$SEND_ID" <<'PY'
import json,socket,sys
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1])
request={'command':'send','operation_id':sys.argv[2],'body':'lost-response-message'}
s.sendall((json.dumps({'schema_version':1,'request_id':'8'*32,'request':request})+'\n').encode())
s.close()
PY
wait_for 30 "lost-response broadcast" grep -q '"body":"lost-response-message"' "$ROOT/receiver.listen"
RETRY=$("$BIN" --state-dir "$ROOT/sender" --json send --operation-id "$SEND_ID" lost-response-message)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["schema_version"] == 3 and v["operation_id"] == sys.argv[1] and v["message_id"] == sys.argv[1]' "$SEND_ID" <<<"$RETRY" \
  || fail "broadcast retry did not return its original operation outcome"
sleep 1
grep -c '"body":"lost-response-message"' "$ROOT/receiver.listen" | grep -qx 1 \
  || fail "broadcast retry repeated the wire side effect"
CONFLICT=$(ipc sender "{\"command\":\"send\",\"operation_id\":\"$SEND_ID\",\"body\":\"different\"}")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "operation_id_conflict" and v["operation_id"] == sys.argv[1]' "$SEND_ID" <<<"$CONFLICT" \
  || fail "operation ID input conflict was not rejected"

# Concurrent private retries join one in-flight operation. The private wire ID is
# exactly the operation ID and the receiver delivers once.
PRIVATE_ID=22222222222222222222222222222222
"$BIN" --state-dir "$ROOT/sender" --json send --operation-id "$PRIVATE_ID" --to "$RECEIVER" private-idempotent >"$ROOT/private.1" & P1=$!
"$BIN" --state-dir "$ROOT/sender" --json send --operation-id "$PRIVATE_ID" --to "$RECEIVER" private-idempotent >"$ROOT/private.2" & P2=$!
wait "$P1"; wait "$P2"
python3 - "$ROOT/private.1" "$ROOT/private.2" <<'PY' || fail "concurrent private duplicates returned different outcomes"
import json,sys
left=json.load(open(sys.argv[1])); right=json.load(open(sys.argv[2]))
left.pop('request_id'); right.pop('request_id'); assert left == right
PY
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["schema_version"] == 3 and v["operation_id"] == sys.argv[2] and v["message_id"] == sys.argv[2] and v["duplicate_accepted"] is False' "$ROOT/private.1" "$PRIVATE_ID" \
  || fail "private operation ID did not reach the wire response"
wait_for 30 "private delivery" grep -q '"body":"private-idempotent"' "$ROOT/receiver.listen"
sleep 1
grep -c '"body":"private-idempotent"' "$ROOT/receiver.listen" | grep -qx 1 \
  || fail "concurrent private duplicate was delivered twice"

# Concurrent shares produce one durable tag and one publication outcome.
printf 'idempotent attachment\n' >"$ROOT/source.txt"
SHARE_ID=33333333333333333333333333333333
"$BIN" --state-dir "$ROOT/sender" --json share --operation-id "$SHARE_ID" "$ROOT/source.txt" >"$ROOT/share.1" & P1=$!
"$BIN" --state-dir "$ROOT/sender" --json share --operation-id "$SHARE_ID" "$ROOT/source.txt" >"$ROOT/share.2" & P2=$!
wait "$P1"; wait "$P2"
python3 - "$ROOT/share.1" "$ROOT/share.2" <<'PY' || fail "concurrent share duplicates returned different outcomes"
import json,sys
left=json.load(open(sys.argv[1])); right=json.load(open(sys.argv[2]))
left.pop('request_id'); right.pop('request_id'); assert left == right
PY
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["schema_version"] == 3 and v["operation_id"] == sys.argv[2] and v["message_id"] == sys.argv[2] and v["offer_id"] == sys.argv[2]' "$ROOT/share.1" "$SHARE_ID" \
  || fail "share operation ID did not reach offer and wire IDs"
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; assert len([x for x in b if x["offer_id"] == sys.argv[1]]) == 1' "$SHARE_ID" \
  <<<"$("$BIN" --state-dir "$ROOT/sender" --json offers)" || fail "duplicate share created duplicate permanent tags"
REPLAY=$("$BIN" --state-dir "$ROOT/sender" --json share --operation-id "$SHARE_ID" "$ROOT/source.txt")
python3 - "$ROOT/share.1" "$REPLAY" <<'PY' || fail "exact-path share retry did not replay"
import json,sys
left=json.load(open(sys.argv[1])); right=json.loads(sys.argv[2])
left.pop('request_id'); right.pop('request_id'); assert left == right
PY
python3 - "$ROOT/source.txt" <<'PY'
import pathlib,sys
path = pathlib.Path(sys.argv[1])
path.write_bytes(b'X' * len(path.read_bytes()))
PY
if "$BIN" --state-dir "$ROOT/sender" --json share --operation-id "$SHARE_ID" "$ROOT/source.txt" >"$ROOT/share.changed" 2>"$ROOT/share.changed.err"; then
  fail "same-size changed attachment reused an operation ID"
fi
[[ ! -s "$ROOT/share.changed.err" ]] || fail "JSON conflict wrote to stderr"
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "operation_id_conflict" and v["outcome"] == "not_started"' "$ROOT/share.changed" || fail "changed attachment conflict was not reported"
printf 'idempotent attachment\n' >"$ROOT/source.txt"
if "$BIN" --state-dir "$ROOT/sender" --json share --operation-id "$SHARE_ID" "$ROOT/./source.txt" >"$ROOT/share.spelling" 2>"$ROOT/share.spelling.err"; then
  fail "equivalent but differently submitted absolute path reused an operation ID"
fi
[[ ! -s "$ROOT/share.spelling.err" ]] || fail "JSON path conflict wrote to stderr"
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "operation_id_conflict" and v["outcome"] == "not_started"' "$ROOT/share.spelling" || fail "submitted-path spelling conflict was not reported"

# Prune caches its original deterministic selection and terminal result. A lost
# response retry cannot select the next batch, and max-delete is operation-bound.
printf 'second attachment\n' >"$ROOT/source-2.txt"
printf 'third attachment\n' >"$ROOT/source-3.txt"
SECOND_ID=33333333333333333333333333333334
THIRD_ID=33333333333333333333333333333335
SECOND=$($BIN --state-dir "$ROOT/sender" --json share --operation-id "$SECOND_ID" "$ROOT/source-2.txt")
THIRD=$($BIN --state-dir "$ROOT/sender" --json share --operation-id "$THIRD_ID" "$ROOT/source-3.txt")
PRUNE_ID=55555555555555555555555555555555
PRUNE_REQUEST="{\"command\":\"offers_prune\",\"operation_id\":\"$PRUNE_ID\",\"older_than_secs\":0,\"direction\":\"outgoing\",\"dry_run\":false,\"max_delete\":1}"
ipc sender "$PRUNE_REQUEST" >/dev/null
PRUNE_RETRY=$($BIN --state-dir "$ROOT/sender" --json offers prune --operation-id "$PRUNE_ID" --older-than-secs 0 --direction outgoing --max-delete 1)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "offers_pruned" and v["schema_version"] == 2 and v["operation_id"] == sys.argv[1] and v["selected_tags"] == v["removed_tags"] == 1' "$PRUNE_ID" <<<"$PRUNE_RETRY" \
  || fail "lost-response prune did not replay its authoritative original result"
COUNT=$($BIN --state-dir "$ROOT/sender" --json offers | python3 -c 'import json,sys; print(len(json.load(sys.stdin)["blobs"]))')
[[ "$COUNT" == 2 ]] || fail "prune retry deleted the next eligible batch"
PRUNE_CONFLICT=$(ipc sender "{\"command\":\"offers_prune\",\"operation_id\":\"$PRUNE_ID\",\"older_than_secs\":0,\"direction\":\"outgoing\",\"dry_run\":false,\"max_delete\":2}")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "operation_id_conflict" and v["operation_id"] == sys.argv[1]' "$PRUNE_ID" <<<"$PRUNE_CONFLICT" \
  || fail "changed prune limit did not conflict"

# Remove replays the authoritative original count even though the end state is
# already absent, and selector changes conflict.
REMOVE_TARGET=$($BIN --state-dir "$ROOT/sender" --json offers | python3 -c 'import json,sys; print(json.load(sys.stdin)["blobs"][0]["offer_id"])')
REMOVE_ID=66666666666666666666666666666666
REMOVE1=$($BIN --state-dir "$ROOT/sender" --json offers remove --operation-id "$REMOVE_ID" "$REMOVE_TARGET")
REMOVE2=$($BIN --state-dir "$ROOT/sender" --json offers remove --operation-id "$REMOVE_ID" "$REMOVE_TARGET")
python3 -c 'import json,sys; a=json.loads(sys.argv[1]); b=json.loads(sys.argv[2]); a.pop("request_id"); b.pop("request_id"); assert a == b and a["operation_id"] == sys.argv[3] and a["removed_tags"] == 1' "$REMOVE1" "$REMOVE2" "$REMOVE_ID" \
  || fail "remove did not replay the original authoritative result"
if $BIN --state-dir "$ROOT/sender" --json offers remove --operation-id "$REMOVE_ID" \
    "$REMOVE_TARGET" --direction incoming >"$ROOT/remove-conflict.out" 2>"$ROOT/remove-conflict.err"; then
  fail "changed remove selector succeeded"
fi
[[ ! -s "$ROOT/remove-conflict.err" ]] || fail "CLI JSON selector conflict wrote stderr"
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "operation_id_conflict" and v["operation_id"] == sys.argv[1] and "offer_id" not in v' "$REMOVE_ID" <"$ROOT/remove-conflict.out" \
  || fail "CLI JSON changed-selector conflict was not preserved"

# A discarded download response is replayed without re-running export/install.
# The already-installed no-clobber destination therefore remains a success only
# while the operation cache can authoritatively replay it.
DOWNLOAD_OFFER=$(python3 -c 'import json,sys; print(json.loads(sys.argv[1])["offer"])' "$THIRD")
DOWNLOAD_ID=77777777777777777777777777777777
DOWNLOAD_OUT="$ROOT/downloaded.txt"
DOWNLOAD_FIRST=$(ipc sender "$(python3 -c 'import json,sys; print(json.dumps({"command":"download","operation_id":sys.argv[1],"offer":sys.argv[2],"output":sys.argv[3]}))' "$DOWNLOAD_ID" "$DOWNLOAD_OFFER" "$DOWNLOAD_OUT")")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "download_complete" and v["operation_id"] == sys.argv[1]' "$DOWNLOAD_ID" <<<"$DOWNLOAD_FIRST" \
  || fail "initial lost-response download did not complete"
[[ -f "$DOWNLOAD_OUT" ]] || fail "lost-response download did not install output"
set +e
DOWNLOAD_RETRY=$($BIN --state-dir "$ROOT/sender" --json download --operation-id "$DOWNLOAD_ID" --output "$DOWNLOAD_OUT" "$DOWNLOAD_OFFER" 2>"$ROOT/download-retry.err")
DOWNLOAD_STATUS=$?
set -e
if [[ $DOWNLOAD_STATUS != 0 ]]; then
  DEBUG_ERROR=$($BIN --state-dir "$ROOT/sender" download --operation-id "$DOWNLOAD_ID" --output "$DOWNLOAD_OUT" "$DOWNLOAD_OFFER" 2>&1 || true)
  fail "download retry failed: $DEBUG_ERROR $DOWNLOAD_RETRY"
fi
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "download_complete" and v["schema_version"] == 2 and v["operation_id"] == sys.argv[1] and v["output"] == sys.argv[2]' "$DOWNLOAD_ID" "$DOWNLOAD_OUT" <<<"$DOWNLOAD_RETRY" \
  || fail "download retry did not replay cached completion"
DOWNLOAD_CONFLICT=$(ipc sender "$(python3 -c 'import json,sys; print(json.dumps({"command":"download","operation_id":sys.argv[1],"offer":sys.argv[2],"output":sys.argv[3]}))' "$DOWNLOAD_ID" "$DOWNLOAD_OFFER" "$ROOT/changed-output.txt")")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "operation_id_conflict"' <<<"$DOWNLOAD_CONFLICT" \
  || fail "changed download output did not conflict"
[[ ! -e "$ROOT/changed-output.txt" ]] || fail "download conflict performed extra export/install work"

# Terminal failures are cached exactly and do not become a fresh attempt.
FAIL_ID=44444444444444444444444444444444
FAILED1=$(ipc sender "{\"command\":\"private_send\",\"operation_id\":\"$FAIL_ID\",\"to\":\"not-a-peer\",\"body\":\"failure\"}")
FAILED2=$(ipc sender "{\"command\":\"private_send\",\"operation_id\":\"$FAIL_ID\",\"to\":\"not-a-peer\",\"body\":\"failure\"}")
[[ "$FAILED1" == "$FAILED2" ]] || fail "terminal failure was not replayed exactly"
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "recipient_unresolved" and v["operation_id"] == sys.argv[1]' "$FAIL_ID" <<<"$FAILED1" \
  || fail "terminal failure omitted operation metadata"

# Restart semantics are explicit rather than pretending this volatile cache is durable.
stop_node sender
start_node sender
"$BIN" --state-dir "$ROOT/sender" --json status | python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["operation_cache_persistent"] is False and v["operation_cache_capacity"] == 1024 and v["operation_cache_ttl_ms"] == 600000; assert v["direct_replay_available"] is True and v["direct_replay_error"] is None; assert v["direct_replay_capacity"] == 8192 and v["direct_replay_per_sender_capacity"] == 512 and v["direct_replay_queue_capacity"] == 64' \
  || fail "status omitted operation/replay cache bounds"

# The sender cache was cleared by restart, so this retry reaches the recipient.
# Its durable replay WAL must acknowledge the same wire ID without redelivery.
wait_for 30 "receiver presence after sender restart" knows_peer sender
PRIVATE_RETRY=$("$BIN" --state-dir "$ROOT/sender" --json send --operation-id "$PRIVATE_ID" --to "$RECEIVER" private-idempotent)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["operation_id"] == v["message_id"] == sys.argv[1] and v["duplicate_accepted"] is True' "$PRIVATE_ID" \
  <<<"$PRIVATE_RETRY" || fail "post-restart private retry was not identified as a duplicate acceptance"
sleep 1
grep -c '"body":"private-idempotent"' "$ROOT/receiver.listen" | grep -qx 1 \
  || fail "recipient replay persistence redelivered after sender restart"

# Clear the sender's volatile outcome again, then change the body under the same
# wire ID. The recipient's persisted fingerprint must return a signed conflict.
stop_node sender
start_node sender
wait_for 30 "receiver presence before conflict retry" knows_peer sender
PRIVATE_CONFLICT=$(ipc sender "{\"command\":\"private_send\",\"operation_id\":\"$PRIVATE_ID\",\"to\":\"$RECEIVER\",\"body\":\"changed-private-body\"}")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["code"] == "private_message_conflict" and v["outcome"] == "not_started" and v["retryable"] is False' \
  <<<"$PRIVATE_CONFLICT" || fail "recipient did not reject changed content under a persisted private ID"
sleep 1
grep -c '"body":"private-idempotent"' "$ROOT/receiver.listen" | grep -qx 1 \
  || fail "private conflict altered original delivery count"
! grep -q '"body":"changed-private-body"' "$ROOT/receiver.listen" \
  || fail "private conflict delivered changed content"

kill "$LISTENER" >/dev/null 2>&1 || true
wait "$LISTENER" >/dev/null 2>&1 || true
echo "PASS: empty rejection; send/private/share joins and replay; prune selection stability and per-operation limit; authoritative remove replay; download response-loss replay/no-extra-install and changed-input conflicts; terminal failures; bounded-cache expiry/eviction/restart semantics; recipient WAL replay persistence"
