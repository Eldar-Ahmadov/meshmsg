#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-state-migration.XXXXXX")
PID=
cleanup() {
  set +e
  if [[ -n ${PID:-} ]]; then
    "$BIN" --state-dir "$ROOT/state" stop >/dev/null 2>&1
    kill "$PID" >/dev/null 2>&1
    wait "$PID" >/dev/null 2>&1
  fi
  rm -rf "$ROOT"
}
trap cleanup EXIT INT TERM

"$BIN" --state-dir "$ROOT/state" --json init >/dev/null
python3 - "$ROOT/state/config.json" <<'PY'
import json, pathlib, sys
path = pathlib.Path(sys.argv[1])
value = json.loads(path.read_text())
assert value.pop("schema_version") == 1
path.write_text(json.dumps(value, indent=2))
PY
cp "$ROOT/state/config.json" "$ROOT/legacy.expected"

# Read-only diagnosis accepts the released v0 shape but does not migrate it.
"$BIN" --state-dir "$ROOT/state" --json doctor | grep -q '"ok":true'
test ! -e "$ROOT/state/config.json.v0.bak"

start_and_stop() {
  "$BIN" --state-dir "$ROOT/state" --json daemon >"$ROOT/daemon.log" 2>"$ROOT/daemon.err" &
  PID=$!
  local end=$((SECONDS + 80))
  until "$BIN" --state-dir "$ROOT/state" --json status | grep -q '"running":true'; do
    (( SECONDS < end )) || { echo "state migration daemon did not start" >&2; exit 1; }
    sleep 0.2
  done
  "$BIN" --state-dir "$ROOT/state" --json stop | grep -q '"type":"stopping"'
  wait "$PID"
  PID=
}

start_and_stop
cmp "$ROOT/legacy.expected" "$ROOT/state/config.json.v0.bak"
python3 - "$ROOT/state/config.json" <<'PY'
import json, pathlib, sys
value = json.loads(pathlib.Path(sys.argv[1]).read_text())
assert value["schema_version"] == 1
assert set(value) == {"schema_version", "advertise_self", "topic", "invite", "identity"}
PY
if [[ $(uname -s) == Linux ]]; then
  [[ $(stat -c '%a' "$ROOT/state/config.json") == 600 ]]
  [[ $(stat -c '%a' "$ROOT/state/config.json.v0.bak") == 600 ]]
fi
peer_before=$("$BIN" --state-dir "$ROOT/state" --json doctor | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer"])')
backup_hash=$(sha256sum "$ROOT/state/config.json.v0.bak" | cut -d' ' -f1)
start_and_stop
python3 - "$ROOT/state/config.json" <<'PY'
import json, pathlib, sys
assert json.loads(pathlib.Path(sys.argv[1]).read_text())["schema_version"] == 1
PY
peer_after=$("$BIN" --state-dir "$ROOT/state" --json doctor | python3 -c 'import json,sys; print(json.load(sys.stdin)["peer"])')
[[ "$peer_after" == "$peer_before" ]]
[[ $(sha256sum "$ROOT/state/config.json.v0.bak" | cut -d' ' -f1) == "$backup_hash" ]]

echo "state migration integration: ok"
