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

# A received gossip offer is informational and never creates an output by itself.
timeout 180 "$BIN" --state-dir "$ROOT/receiver" --json listen >"$ROOT/receiver.listen.log" 2>"$ROOT/receiver.listen.err" &
LISTENER=$!
wait_for 10 "receiver listener" grep -Fq '"type":"connected"' "$ROOT/receiver.listen.log"
printf 'attachment integration payload\n' >"$ROOT/source.txt"
FILE_SHARE=$(cd "$ROOT" && "$BIN" --state-dir "$ROOT/provider" --json share source.txt)
FILE_OFFER=$(json_field '"offer"' <<<"$FILE_SHARE")
FILE_TICKET=$(json_field '"ticket"' <<<"$FILE_SHARE")
wait_for 30 "file offer" grep -Fq '"type":"attachment_offer"' "$ROOT/receiver.listen.log"
[[ ! -e "$ROOT/receiver/source.txt" ]] || fail "receiver automatically exported an offered file"

(cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download "$FILE_TICKET" --output raw-ticket.txt) \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source.txt" "$ROOT/raw-ticket.txt" || fail "raw-ticket download differs"
(cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" --json download "$FILE_OFFER" --output received.txt) \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source.txt" "$ROOT/received.txt" || fail "signed-offer download differs"
if (cd "$ROOT" && "$BIN" --state-dir "$ROOT/receiver" download "$FILE_OFFER" --output received.txt) >"$ROOT/clobber.out" 2>"$ROOT/clobber.err"; then
  fail "download overwrote an existing file"
fi
grep -q 'output already exists' "$ROOT/clobber.err" || fail "overwrite refusal was not actionable"

# A directory snapshot remains available after the provider daemon restarts.
mkdir -p "$ROOT/source-dir/nested" "$ROOT/source-dir/empty"
printf alpha >"$ROOT/source-dir/a.txt"
printf beta >"$ROOT/source-dir/nested/b.txt"
DIR_SHARE=$("$BIN" --state-dir "$ROOT/provider" --json share "$ROOT/source-dir")
DIR_OFFER=$(json_field '"offer"' <<<"$DIR_SHARE")
stop_node provider
start_node provider
"$BIN" --state-dir "$ROOT/receiver" --json download "$DIR_OFFER" --output "$ROOT/received-dir" \
  | grep -q '"type":"download_complete"'
cmp "$ROOT/source-dir/a.txt" "$ROOT/received-dir/a.txt" || fail "top-level archive file differs"
cmp "$ROOT/source-dir/nested/b.txt" "$ROOT/received-dir/nested/b.txt" || fail "nested archive file differs"
[[ -d "$ROOT/received-dir/empty" ]] || fail "empty directory was not preserved"

kill "$LISTENER" >/dev/null 2>&1 || true
wait "$LISTENER" >/dev/null 2>&1 || true
echo "PASS: signed/raw manual file transfer, no-clobber, deterministic directory extraction, and provider-restart pinning"
