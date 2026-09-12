#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-v018-boundary.XXXXXX")
OLD="$ROOT/release/meshmsg"
PIDS=()
cleanup() {
  set +e
  "$OLD" --state-dir "$ROOT/old" stop >/dev/null 2>&1
  "$BIN" --state-dir "$ROOT/current" stop >/dev/null 2>&1
  for pid in "${PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for pid in "${PIDS[@]}"; do wait "$pid" >/dev/null 2>&1; done
  [[ ${KEEP_MESHMSG_TEST_STATE:-0} == 1 ]] || rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM
fail() { echo "v0.1.18 message-boundary failure: $* (artifacts: $ROOT)" >&2; exit 1; }
wait_for() {
  local seconds=$1 description=$2; shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timeout waiting for $description"
    sleep .2
  done
}
status_current() { "$BIN" --state-dir "$ROOT/current" --json status | grep -q '"running":true'; }
status_old() { "$OLD" --state-dir "$ROOT/old" --json status | grep -q '"running":true'; }

mkdir -p "$ROOT/release"
archive="$ROOT/v0.1.18.tar.gz"
curl --proto '=https' --tlsv1.2 -fsSL --retry 3 --retry-all-errors \
  https://github.com/Eldar-Ahmadov/meshmsg/releases/download/v0.1.18/meshmsg-v0.1.18-x86_64-unknown-linux-gnu.tar.gz \
  -o "$archive"
printf '%s  %s\n' c658dde5dccffc2fa145370f92b2df8de38f2fc860b2acec03a3aa9598060f57 "$archive" | sha256sum -c --status \
  || fail "published archive checksum mismatch"
tar -xzf "$archive" --strip-components=1 -C "$ROOT/release" meshmsg-v0.1.18-x86_64-unknown-linux-gnu/meshmsg
chmod +x "$OLD"

"$OLD" --state-dir "$ROOT/old" init --no-default-alias >/dev/null
timeout 300 "$OLD" --state-dir "$ROOT/old" daemon >"$ROOT/old.daemon" 2>&1 & PIDS+=("$!")
wait_for 80 "old daemon" status_old
invite=$("$OLD" --state-dir "$ROOT/old" invite)
"$BIN" --state-dir "$ROOT/current" join --no-default-alias "$invite" >/dev/null
timeout 300 "$BIN" --state-dir "$ROOT/current" daemon >"$ROOT/current.daemon" 2>&1 & PIDS+=("$!")
wait_for 80 "current daemon" status_current
wait_for 80 "mixed neighbors" bash -c '[[ $("$1" --state-dir "$2" --json status | python3 -c '\''import json,sys; print(json.load(sys.stdin)["neighbors"])'\'') -ge 1 ]]' _ "$BIN" "$ROOT/current"

# Retain only the released on-wire EnvelopeV2 promise. Each listener uses the
# client matching its daemon; cross-version local IPC compatibility is not a v2
# protocol promise.
timeout 240 "$BIN" --state-dir "$ROOT/current" --json listen >"$ROOT/current.listen" 2>"$ROOT/current.listen.err" & PIDS+=("$!")
timeout 240 "$OLD" --state-dir "$ROOT/old" --json listen >"$ROOT/old.listen" 2>"$ROOT/old.listen.err" & PIDS+=("$!")
wait_for 10 "current listener" grep -Fq '"type":"connected"' "$ROOT/current.listen"
wait_for 10 "released listener" grep -Fq '"type":"connected"' "$ROOT/old.listen"

# At contemporary Unix-millisecond timestamps the released producer's exact
# 4096-byte frame capacity is 3923. Focused Rust tests cover the absolute 3928
# maximum at one-byte timestamps and every relevant postcard metadata boundary.
python3 - "$ROOT/released-contemporary-max.txt" <<'PY'
import pathlib,sys
pathlib.Path(sys.argv[1]).write_text('R' * 3923)
PY
"$OLD" --state-dir "$ROOT/old" --json send --operation-id 18181818181818181818181818181818 --message-file "$ROOT/released-contemporary-max.txt" >"$ROOT/old-send.out"
wait_for 40 "released contemporary-max 3923-byte wire body at current peer" grep -Fq '"body":"RRRRRRRRRR' "$ROOT/current.listen"
python3 - "$ROOT/current.listen" <<'PY' || fail "current peer dropped released contemporary-max EnvelopeV2 body"
import json,sys
assert any(v.get('type') == 'message' and len(v.get('body','')) == 3923 for v in map(json.loads, open(sys.argv[1])))
PY

python3 - "$ROOT/current-valid.txt" <<'PY'
import pathlib,sys
pathlib.Path(sys.argv[1]).write_text('C' * 3900)
PY
"$BIN" --state-dir "$ROOT/current" --json send --operation-id 19191919191919191919191919191919 --message-file "$ROOT/current-valid.txt" >"$ROOT/current-daemon-send.out"
wait_for 40 "current-produced 3900-byte wire body at released peer" grep -Fq '"body":"CCCCCCCCCC' "$ROOT/old.listen"
python3 - "$ROOT/old.listen" <<'PY' || fail "released peer dropped current-produced canonical EnvelopeV2 body"
import json,sys
assert any(v.get('type') == 'message' and len(v.get('body','')) == 3900 for v in map(json.loads, open(sys.argv[1])))
PY
python3 -c 'open(__import__("sys").argv[1], "w").write("X" * 3901)' "$ROOT/current-oversized.txt"
if "$BIN" --state-dir "$ROOT/current" --json send --operation-id 20202020202020202020202020202020 \
  --message-file "$ROOT/current-oversized.txt" >"$ROOT/current-oversized.out" 2>"$ROOT/current-oversized.err"; then
  fail "current 3901-byte broadcast producer input was accepted"
fi
python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["code"] == "invalid_message" and v["outcome"] == "not_started" and v["operation_id"] == "20202020202020202020202020202020"' \
  "$ROOT/current-oversized.out" || fail "current 3901-byte broadcast rejection was not canonical"

kill "${PIDS[2]}" "${PIDS[3]}" >/dev/null 2>&1 || true
wait "${PIDS[2]}" "${PIDS[3]}" >/dev/null 2>&1 || true
PIDS=("${PIDS[0]}" "${PIDS[1]}")
echo "PASS: retained EnvelopeV2 wire promise works in both directions at released/current production boundaries; current 3901-byte production failed canonically"
