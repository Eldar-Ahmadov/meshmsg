#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-attachments.XXXXXX")
declare -A PIDS=()

cleanup() {
  set +e
  for node in "${!PIDS[@]}"; do
    "$BIN" --state-dir "$ROOT/$node" stop >/dev/null 2>&1
  done
  for pid in "${PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for pid in "${PIDS[@]}"; do wait "$pid" >/dev/null 2>&1; done
  if [[ ${KEEP_MESHMSG_TEST_STATE:-0} != 1 ]]; then
    rm -rf "$ROOT"
  else
    echo "kept test state: $ROOT"
  fi
}
trap cleanup EXIT INT TERM

fail() { echo "attachment integration failure: $* (artifacts: $ROOT)" >&2; exit 1; }
wait_for() {
  local seconds=$1 description=$2; shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timeout waiting for $description"
    sleep 0.2
  done
}
status_ok() { "$BIN" --state-dir "$ROOT/$1" --json status | grep -q '"running":true'; }
start_node() {
  local node=$1
  timeout 300 "$BIN" --state-dir "$ROOT/$node" --json daemon >"$ROOT/$node.daemon.log" 2>"$ROOT/$node.daemon.err" &
  PIDS[$node]=$!
  wait_for 80 "$node daemon" status_ok "$node"
}
stop_node() {
  local node=$1
  "$BIN" --state-dir "$ROOT/$node" --json stop | grep -q '"type":"stopping"'
  wait "${PIDS[$node]}" || true
  unset 'PIDS[$node]'
}
json_field() { python3 -c "import json,sys; print(json.load(sys.stdin)[$1])"; }

"$BIN" --state-dir "$ROOT/provider" init >/dev/null
start_node provider
INVITE=$("$BIN" --state-dir "$ROOT/provider" --json invite | json_field '"token"')
"$BIN" --state-dir "$ROOT/receiver" join "$INVITE" >/dev/null
start_node receiver

python3 -c 'import json,sys; assert json.load(sys.stdin) == {"type":"offers","schema_version":1,"blobs":[]}' \
  <<<"$("$BIN" --state-dir "$ROOT/provider" --json offers)" \
  || fail "fresh provider had pinned attachment blobs"
python3 -c 'import json,sys; assert json.load(sys.stdin) == {"type":"offers","schema_version":1,"blobs":[]}' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "fresh receiver had pinned attachment blobs"

# A received gossip offer is informational and never creates an output by itself.
timeout 180 "$BIN" --state-dir "$ROOT/receiver" --json listen >"$ROOT/receiver.listen.log" 2>"$ROOT/receiver.listen.err" &
LISTENER=$!
wait_for 10 "receiver listener" grep -Fq '"type":"connected"' "$ROOT/receiver.listen.log"
printf 'attachment integration payload\n' >"$ROOT/source.txt"
FILE_SHARE=$(cd "$ROOT" && "$BIN" --state-dir "$ROOT/provider" --json share source.txt)
FILE_OFFER=$(json_field '"offer"' <<<"$FILE_SHARE")
FILE_TICKET=$(json_field '"ticket"' <<<"$FILE_SHARE")
FILE_ID=$(json_field '"offer_id"' <<<"$FILE_SHARE")
FILE_TIMESTAMP=$(json_field '"timestamp_ms"' <<<"$FILE_SHARE")
FILE_MESSAGE_ID=$(json_field '"message_id"' <<<"$FILE_SHARE")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "attachment_shared" and v["schema_version"] == 3 and len(v["operation_id"]) == 32 and v["message_id"] == v["operation_id"] and isinstance(v["timestamp_ms"], int) and v["timestamp_ms"] > 0 and v["delivery_acknowledged"] is False' \
  <<<"$FILE_SHARE" || fail "shared attachment JSON omitted its canonical timestamp or existing fields"
python3 -c 'import json,sys; v=json.load(sys.stdin); assert len(v["blobs"]) == 1; b=v["blobs"][0]; assert b["direction"] == "outgoing" and b["offer_id"] == sys.argv[1] and b["name"] == "source.txt" and b["kind"] == "file" and b["status"] == "complete"' "$FILE_ID" \
  <<<"$("$BIN" --state-dir "$ROOT/provider" --json offers)" \
  || fail "provider offer listing did not include shared file"
python3 -c 'import json,sys; assert json.load(sys.stdin)["blobs"] == []' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "received but undownloaded offer was listed as pinned"
wait_for 30 "file offer" grep -Fq '"type":"attachment_offer"' "$ROOT/receiver.listen.log"
python3 -c 'import json,sys; events=[json.loads(line) for line in open(sys.argv[1])]; offer=next(v for v in events if v.get("type") == "attachment_offer" and v.get("offer_id") == sys.argv[2]); assert offer["schema_version"] == 2 and offer["message_id"] == sys.argv[4] and offer["timestamp_ms"] == int(sys.argv[3]) and offer["name"] == "source.txt" and offer["kind"] == "file"' \
  "$ROOT/receiver.listen.log" "$FILE_ID" "$FILE_TIMESTAMP" "$FILE_MESSAGE_ID" \
  || fail "local attachment_shared timestamp/metadata did not match the received offer"
[[ ! -e "$ROOT/receiver/source.txt" ]] || fail "receiver automatically exported an offered file"

RAW_DOWNLOAD=$(cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download "$FILE_TICKET" --output raw-ticket.txt)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "download_complete" and v["installed"] is True and v["pinned"] is True and v["destination_synced"] is True and v["cleanup_complete"] is True and v["warnings"] == []' \
  <<<"$RAW_DOWNLOAD" || fail "successful download omitted commit durability metadata"
cmp "$ROOT/source.txt" "$ROOT/raw-ticket.txt" || fail "raw-ticket download differs"
RAW_RETRY=$(cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download "$FILE_TICKET" --output raw-ticket-retry.txt)
python3 -c 'import json,sys; assert json.loads(sys.argv[1])["offer_id"] == json.loads(sys.argv[2])["offer_id"]' \
  "$RAW_DOWNLOAD" "$RAW_RETRY" || fail "raw-ticket retry changed its deterministic pin identity"
cmp "$ROOT/source.txt" "$ROOT/raw-ticket-retry.txt" || fail "raw-ticket retry download differs"
printf '%s\n' "$FILE_OFFER" >"$ROOT/signed-offer.txt"
(cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download --offer-file signed-offer.txt --output received-from-file.txt) \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source.txt" "$ROOT/received-from-file.txt" || fail "offer-file download differs"
printf '%s\n' "$FILE_OFFER" \
  | (cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download --offer-stdin --output received.txt) \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source.txt" "$ROOT/received.txt" || fail "signed-offer download differs"
if (cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" download "$FILE_OFFER" --output received.txt) >"$ROOT/clobber.out" 2>"$ROOT/clobber.err"; then
  fail "download overwrote an existing file"
fi
grep -q 'output already exists' "$ROOT/clobber.err" || fail "overwrite refusal was not actionable"
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; assert len(b) == 2 and {x["name"] for x in b} == {"raw-ticket.blob", "source.txt"} and all(x["direction"] == "incoming" and x["kind"] == "file" and x["status"] == "complete" for x in b)' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "receiver listing did not include downloaded blobs"

# Download success is acknowledged only after the inbound pins are durable.
# Restart immediately and verify recovery before performing another transfer.
kill "$LISTENER" >/dev/null 2>&1 || true
wait "$LISTENER" >/dev/null 2>&1 || true
stop_node receiver
printf stale >"$ROOT/receiver/.meshmsg-part-0123456789abcdef.blob"
printf keep >"$ROOT/receiver/.meshmsg-part-0123456789abcdef.download"
mkdir "$ROOT/receiver/.meshmsg-part-fedcba9876543210.tar"
start_node receiver
[[ ! -e "$ROOT/receiver/.meshmsg-part-0123456789abcdef.blob" ]] \
  || fail "startup did not remove validated stale share staging"
[[ -f "$ROOT/receiver/.meshmsg-part-0123456789abcdef.download" ]] \
  || fail "startup unsafely removed arbitrary download staging"
[[ -d "$ROOT/receiver/.meshmsg-part-fedcba9876543210.tar" ]] \
  || fail "startup unsafely removed a non-regular staging lookalike"
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; assert len(b) == 2 and all(x["direction"] == "incoming" and x["status"] == "complete" for x in b)' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "durable inbound pins did not recover after receiver restart"

# A directory snapshot remains available after the provider daemon restarts.
mkdir -p "$ROOT/source-dir/nested" "$ROOT/source-dir/empty"
printf alpha >"$ROOT/source-dir/a.txt"
printf beta >"$ROOT/source-dir/nested/b.txt"
DIR_SHARE=$("$BIN" --state-dir "$ROOT/provider" --json share "$ROOT/source-dir")
DIR_OFFER=$(json_field '"offer"' <<<"$DIR_SHARE")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert isinstance(v["timestamp_ms"], int) and v["timestamp_ms"] > 0 and v["kind"] == "directory_tar_v1" and v["message_id"] == v["operation_id"]' \
  <<<"$DIR_SHARE" || fail "shared directory JSON omitted its canonical timestamp or kind"
stop_node provider
start_node provider
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; assert len(b) == 2 and {(x["name"], x["kind"]) for x in b} == {("source.txt", "file"), ("source-dir.tar", "directory_tar_v1")} and all(x["direction"] == "outgoing" and x["status"] == "complete" for x in b)' \
  <<<"$("$BIN" --state-dir "$ROOT/provider" --json offers)" \
  || fail "provider offer listing did not survive restart"
"$BIN" --state-dir "$ROOT/receiver" --json download "$DIR_OFFER" --output "$ROOT/received-dir" \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source-dir/a.txt" "$ROOT/received-dir/a.txt" || fail "top-level archive file differs"
cmp "$ROOT/source-dir/nested/b.txt" "$ROOT/received-dir/nested/b.txt" || fail "nested archive file differs"
[[ -d "$ROOT/received-dir/empty" ]] || fail "empty directory was not preserved"
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; assert any(x["name"] == "source-dir.tar" and x["kind"] == "directory_tar_v1" for x in b)' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "receiver listing did not preserve downloaded directory name and kind"

# Lifecycle controls account shared content once and preserve other references.
STATUS=$($BIN --state-dir "$ROOT/provider" --json status)
python3 -c 'import json,sys; s=json.load(sys.stdin); a=s["attachment_storage"]; assert a["tagged_bytes"] > 0 and a["tagged_blobs"] == 2 and a["tags"] == 2 and isinstance(a["pressure"], bool) and s["attachment_retention_secs"] == 0' \
  <<<"$STATUS" || fail "status omitted attachment storage pressure metrics"
DUP_ID=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
DUP_SHARE=$($BIN --state-dir "$ROOT/provider" --json share --operation-id "$DUP_ID" "$ROOT/source.txt")
python3 -c 'import json,sys; assert json.load(sys.stdin)["offer_id"] == sys.argv[1]' "$DUP_ID" \
  <<<"$DUP_SHARE" || fail "duplicate share failed"
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; same=[x for x in b if x["name"] == "source.txt"]; assert len(same) == 2 and len({x["hash"] for x in same}) == 1' \
  <<<"$($BIN --state-dir "$ROOT/provider" --json offers)" || fail "deduplicated tags were not independently listed"
REMOVED=$($BIN --state-dir "$ROOT/provider" --json offers remove "$FILE_ID" --direction outgoing)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v == {"type":"offer_removed","schema_version":1,"dry_run":False,"selected_tags":1,"removed_tags":1,"released_bytes":0,"limited":False,"cutoff_ms":None}' \
  <<<"$REMOVED" || fail "removing one deduplicated reference released shared bytes"
DRY=$($BIN --state-dir "$ROOT/provider" --json offers prune --older-than-secs 0 --dry-run --max-delete 1)
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "offers_pruned" and v["dry_run"] is True and v["selected_tags"] == 1 and v["removed_tags"] == 0 and v["limited"] is True' \
  <<<"$DRY" || fail "bounded prune dry-run was not deterministic/non-mutating"

# A remote transfer remains protected after it has started while the provider
# removes its durable offer pin. Concurrent local share/download/lifecycle
# commands prove the storage gate returns a strict retryable busy outcome.
dd if=/dev/zero of="$ROOT/large.bin" bs=1M count=64 status=none
LARGE_SHARE=$($BIN --state-dir "$ROOT/provider" --json share "$ROOT/large.bin")
LARGE_OFFER=$(json_field '"offer"' <<<"$LARGE_SHARE")
LARGE_ID=$(json_field '"offer_id"' <<<"$LARGE_SHARE")
: >"$ROOT/concurrent.listen.log"
timeout 180 "$BIN" --state-dir "$ROOT/receiver" --json listen >"$ROOT/concurrent.listen.log" 2>"$ROOT/concurrent.listen.err" &
CONCURRENT_LISTENER=$!
wait_for 10 "concurrent listener" grep -Fq '"type":"connected"' "$ROOT/concurrent.listen.log"
"$BIN" --state-dir "$ROOT/receiver" --json download "$LARGE_OFFER" --output "$ROOT/large.received" >"$ROOT/large.download" 2>"$ROOT/large.download.err" &
LARGE_DOWNLOAD_PID=$!
wait_for 30 "remote download made verified progress" grep -Fq '"type":"download_progress"' "$ROOT/concurrent.listen.log"
"$BIN" --state-dir "$ROOT/receiver" --json share "$ROOT/source.txt" >"$ROOT/concurrent.share" 2>"$ROOT/concurrent.share.err" &
CONCURRENT_SHARE_PID=$!
if "$BIN" --state-dir "$ROOT/receiver" --json offers prune --older-than-secs 0 --dry-run >"$ROOT/concurrent.prune" 2>"$ROOT/concurrent.prune.err"; then
  fail "prune raced an active download instead of returning busy"
fi
grep -q attachment_storage_busy "$ROOT/concurrent.prune.err" || fail "concurrent prune lacked strict busy code"
if "$BIN" --state-dir "$ROOT/receiver" --json offers remove "$FILE_ID" >"$ROOT/concurrent.remove" 2>"$ROOT/concurrent.remove.err"; then
  fail "remove raced an active download instead of returning busy"
fi
grep -q attachment_storage_busy "$ROOT/concurrent.remove.err" || fail "concurrent remove lacked strict busy code"
"$BIN" --state-dir "$ROOT/provider" --json offers remove "$LARGE_ID" >/dev/null
wait "$LARGE_DOWNLOAD_PID" || fail "remote download did not survive provider pin removal"
wait "$CONCURRENT_SHARE_PID" || fail "share queued behind concurrent download failed"
cmp "$ROOT/large.bin" "$ROOT/large.received" || fail "remote download changed during provider removal"
kill "$CONCURRENT_LISTENER" >/dev/null 2>&1 || true
wait "$CONCURRENT_LISTENER" >/dev/null 2>&1 || true

# Download admission rejects quota and minimum-free-space pressure before
# installing output, using the same strict lifecycle errors as shares.
printf 12345 >"$ROOT/five.bin"
FIVE_SHARE=$($BIN --state-dir "$ROOT/provider" --json share "$ROOT/five.bin")
FIVE_OFFER=$(json_field '"offer"' <<<"$FIVE_SHARE")
"$BIN" --state-dir "$ROOT/quota-receiver" join "$INVITE" >/dev/null
timeout 300 "$BIN" --state-dir "$ROOT/quota-receiver" --json daemon \
  --max-attachment-storage-bytes 4 --min-attachment-free-bytes 0 --attachment-retention-secs 0 \
  >"$ROOT/quota-receiver.daemon.log" 2>"$ROOT/quota-receiver.daemon.err" &
PIDS[quota-receiver]=$!
wait_for 80 "quota receiver daemon" status_ok quota-receiver
if "$BIN" --state-dir "$ROOT/quota-receiver" --json download "$FIVE_OFFER" --output "$ROOT/quota-download" >"$ROOT/quota-download.out" 2>"$ROOT/quota-download.err"; then
  fail "download exceeded total attachment quota"
fi
grep -q attachment_quota_exceeded "$ROOT/quota-download.err" || fail "download quota failure lacked strict code"
[[ ! -e "$ROOT/quota-download" ]] || fail "quota failure installed a download"
stop_node quota-receiver
timeout 300 "$BIN" --state-dir "$ROOT/quota-receiver" --json daemon \
  --max-attachment-storage-bytes 100 --min-attachment-free-bytes 999999999999999 --attachment-retention-secs 0 \
  >"$ROOT/quota-receiver.daemon.log" 2>"$ROOT/quota-receiver.daemon.err" &
PIDS[quota-receiver]=$!
wait_for 80 "free-space receiver daemon" status_ok quota-receiver
if "$BIN" --state-dir "$ROOT/quota-receiver" --json download "$FIVE_OFFER" --output "$ROOT/free-download" >"$ROOT/free-download.out" 2>"$ROOT/free-download.err"; then
  fail "download ignored minimum free-space reserve"
fi
grep -q attachment_min_free_space "$ROOT/free-download.err" || fail "download free-space failure lacked strict code"
[[ ! -e "$ROOT/free-download" ]] || fail "free-space failure installed a download"

# A tiny isolated store proves quota exhaustion, remove recovery, persistence,
# and a configured free-space reserve failure through the real CLI/IPC daemon.
"$BIN" --state-dir "$ROOT/quota" init >/dev/null
timeout 300 "$BIN" --state-dir "$ROOT/quota" --json daemon \
  --max-attachment-storage-bytes 4 --min-attachment-free-bytes 0 --attachment-retention-secs 0 \
  >"$ROOT/quota.daemon.log" 2>"$ROOT/quota.daemon.err" &
PIDS[quota]=$!
wait_for 80 "quota daemon" status_ok quota
printf 1234 >"$ROOT/four.bin"
Q_ID=bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb
"$BIN" --state-dir "$ROOT/quota" --json share --operation-id "$Q_ID" "$ROOT/four.bin" >/dev/null
printf x >"$ROOT/one.bin"
if "$BIN" --state-dir "$ROOT/quota" --json share "$ROOT/one.bin" >"$ROOT/quota.out" 2>"$ROOT/quota.err"; then
  fail "unique blob exceeded total attachment quota"
fi
grep -q attachment_quota_exceeded "$ROOT/quota.err" || fail "quota failure lacked stable error"
"$BIN" --state-dir "$ROOT/quota" --json offers remove "$Q_ID" | grep -q '"released_bytes":4'
"$BIN" --state-dir "$ROOT/quota" --json share "$ROOT/one.bin" >/dev/null || fail "quota did not recover after removal"
stop_node quota
timeout 300 "$BIN" --state-dir "$ROOT/quota" --json daemon \
  --max-attachment-storage-bytes 4 --min-attachment-free-bytes 999999999999999 --attachment-retention-secs 0 \
  >"$ROOT/quota.daemon.log" 2>"$ROOT/quota.daemon.err" &
PIDS[quota]=$!
wait_for 80 "free-space daemon" status_ok quota
python3 -c 'import json,sys; a=json.load(sys.stdin)["attachment_storage"]; assert a["below_min_free"] is True and a["pressure"] is True and a["tagged_bytes"] == 1' \
  <<<"$($BIN --state-dir "$ROOT/quota" --json status)" || fail "free-space pressure/status was not persistent"
if "$BIN" --state-dir "$ROOT/quota" --json share "$ROOT/one.bin" >"$ROOT/free.out" 2>"$ROOT/free.err"; then
  fail "share ignored minimum free-space reserve"
fi
grep -q attachment_min_free_space "$ROOT/free.err" || fail "free-space failure lacked stable error"

echo "PASS: attachment transfer/transaction recovery, lifecycle remove/prune/dry-run, dedup accounting, share/download quota and free-space failures, concurrent lifecycle exclusion, active remote transfer safety, and restart persistence"
