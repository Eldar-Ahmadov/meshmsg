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
python3 -c 'import json,sys; v=json.load(sys.stdin); assert v["type"] == "attachment_shared" and isinstance(v["timestamp_ms"], int) and v["timestamp_ms"] > 0 and v["delivery_acknowledged"] is False' \
  <<<"$FILE_SHARE" || fail "shared attachment JSON omitted its canonical timestamp or existing fields"
python3 -c 'import json,sys; v=json.load(sys.stdin); assert len(v["blobs"]) == 1; b=v["blobs"][0]; assert b["direction"] == "outgoing" and b["offer_id"] == sys.argv[1] and b["name"] == "source.txt" and b["kind"] == "file" and b["status"] == "complete"' "$FILE_ID" \
  <<<"$("$BIN" --state-dir "$ROOT/provider" --json offers)" \
  || fail "provider offer listing did not include shared file"
python3 -c 'import json,sys; assert json.load(sys.stdin)["blobs"] == []' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "received but undownloaded offer was listed as pinned"
wait_for 30 "file offer" grep -Fq '"type":"attachment_offer"' "$ROOT/receiver.listen.log"
python3 -c 'import json,sys; events=[json.loads(line) for line in open(sys.argv[1])]; offer=next(v for v in events if v.get("type") == "attachment_offer" and v.get("offer_id") == sys.argv[2]); assert offer["timestamp_ms"] == int(sys.argv[3]) and offer["name"] == "source.txt" and offer["kind"] == "file"' \
  "$ROOT/receiver.listen.log" "$FILE_ID" "$FILE_TIMESTAMP" \
  || fail "local attachment_shared timestamp/metadata did not match the received offer"
[[ ! -e "$ROOT/receiver/source.txt" ]] || fail "receiver automatically exported an offered file"

(cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download "$FILE_TICKET" --output raw-ticket.txt) \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source.txt" "$ROOT/raw-ticket.txt" || fail "raw-ticket download differs"
printf '%s\n' "$FILE_OFFER" \
  | (cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download --offer-stdin --output received.txt) \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source.txt" "$ROOT/received.txt" || fail "signed-offer download differs"
if (cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" download "$FILE_OFFER" --output received.txt) >"$ROOT/clobber.out" 2>"$ROOT/clobber.err"; then
  fail "download overwrote an existing file"
fi
grep -q 'output already exists' "$ROOT/clobber.err" || fail "overwrite refusal was not actionable"
python3 -c 'import json,sys; b=json.load(sys.stdin)["blobs"]; assert len(b) == 2 and {x["name"] for x in b} == {"raw-ticket.txt", "source.txt"} and all(x["direction"] == "incoming" and x["kind"] == "file" and x["status"] == "complete" for x in b)' \
  <<<"$("$BIN" --state-dir "$ROOT/receiver" --json offers)" \
  || fail "receiver listing did not include downloaded blobs"

# A directory snapshot remains available after the provider daemon restarts.
mkdir -p "$ROOT/source-dir/nested" "$ROOT/source-dir/empty"
printf alpha >"$ROOT/source-dir/a.txt"
printf beta >"$ROOT/source-dir/nested/b.txt"
DIR_SHARE=$("$BIN" --state-dir "$ROOT/provider" --json share "$ROOT/source-dir")
DIR_OFFER=$(json_field '"offer"' <<<"$DIR_SHARE")
python3 -c 'import json,sys; v=json.load(sys.stdin); assert isinstance(v["timestamp_ms"], int) and v["timestamp_ms"] > 0 and v["kind"] == "directory_tar_v1"' \
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

kill "$LISTENER" >/dev/null 2>&1 || true
wait "$LISTENER" >/dev/null 2>&1 || true
echo "PASS: canonical shared/received offer timestamps and metadata, transfers, no-clobber, deterministic extraction, persistent pins, and best-effort blob listing"
