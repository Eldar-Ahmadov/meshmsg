#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
ROOT=$(mktemp -d "${TMPDIR:-/tmp}/meshmsg-ipc-version-compat.XXXXXX")
DOWNLOAD_DIR="$ROOT/releases"
mkdir -p "$DOWNLOAD_DIR"

declare -A PIDS=()
declare -a LISTENER_PIDS=()

cleanup() {
  set +e
  for pid in "${LISTENER_PIDS[@]}"; do kill "$pid" >/dev/null 2>&1; done
  for key in "${!PIDS[@]}"; do
    local version=${key%%:*}
    local node=${key#*:}
    local old_bin="$DOWNLOAD_DIR/$version/meshmsg"
    [[ -x "$old_bin" ]] && "$old_bin" --state-dir "$ROOT/$version/$node" stop >/dev/null 2>&1
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

fail() { echo "IPC version compatibility failure: $* (artifacts: $ROOT)" >&2; exit 1; }
wait_for() {
  local seconds=$1 description=$2; shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    (( SECONDS < end )) || fail "timeout waiting for $description"
    sleep 0.2
  done
}

fetch_release() {
  local version=$1 checksum=$2
  local archive="meshmsg-v${version}-x86_64-unknown-linux-gnu.tar.gz"
  local url="https://github.com/Eldar-Ahmadov/meshmsg/releases/download/v${version}/${archive}"
  local target="$DOWNLOAD_DIR/$archive"
  curl --proto '=https' --tlsv1.2 --fail --location --silent --show-error \
    --connect-timeout 15 --max-time 180 --retry 3 --retry-all-errors \
    "$url" --output "$target"
  printf '%s  %s\n' "$checksum" "$target" | sha256sum --check --status \
    || fail "checksum mismatch for published v${version} archive"
  mkdir -p "$DOWNLOAD_DIR/$version"
  tar --extract --gzip --file "$target" --strip-components=1 \
    --directory "$DOWNLOAD_DIR/$version" \
    "meshmsg-v${version}-x86_64-unknown-linux-gnu/meshmsg"
  chmod 0755 "$DOWNLOAD_DIR/$version/meshmsg"
  [[ $("$DOWNLOAD_DIR/$version/meshmsg" --version) == "meshmsg $version" ]] \
    || fail "downloaded binary did not report v${version}"
}

status_ok() {
  local version=$1 node=$2
  "$DOWNLOAD_DIR/$version/meshmsg" --state-dir "$ROOT/$version/$node" --json status \
    | grep -q '"running":true'
}

status_has_alias() {
  local version=$1 node=$2
  "$DOWNLOAD_DIR/$version/meshmsg" --state-dir "$ROOT/$version/$node" --json status \
    | python3 -c 'import json,sys; assert json.load(sys.stdin)["advertised_aliases"] >= 1'
}

start_old_node() {
  local version=$1 node=$2
  local old_bin="$DOWNLOAD_DIR/$version/meshmsg"
  timeout 240 "$old_bin" --state-dir "$ROOT/$version/$node" --json daemon \
    >"$ROOT/$version/$node.daemon.log" 2>"$ROOT/$version/$node.daemon.err" &
  PIDS["$version:$node"]=$!
  wait_for 80 "v${version} $node daemon" status_ok "$version" "$node"
}

run_scenario() {
  local version=$1
  local old_bin="$DOWNLOAD_DIR/$version/meshmsg"
  local base="$ROOT/$version"
  mkdir -p "$base"

  if [[ $version == 0.1.11 ]]; then
    "$old_bin" --state-dir "$base/sender" init >/dev/null
  else
    "$old_bin" --state-dir "$base/sender" init --no-default-alias >/dev/null
  fi
  start_old_node "$version" sender
  local invite
  invite=$("$old_bin" --state-dir "$base/sender" invite)
  if [[ $version == 0.1.11 ]]; then
    "$old_bin" --state-dir "$base/spy" join "$invite" >/dev/null
  else
    "$old_bin" --state-dir "$base/spy" join --no-default-alias "$invite" >/dev/null
    "$old_bin" --state-dir "$base/spy" alias set intended-private-peer >/dev/null
  fi
  start_old_node "$version" spy
  if [[ $version == 0.1.12 ]]; then
    wait_for 40 "v0.1.12 legacy alias discovery" status_has_alias "$version" sender
  fi

  local listener="$base/spy.listen.log"
  timeout 180 "$old_bin" --state-dir "$base/spy" --json listen \
    >"$listener" 2>"$listener.err" &
  local listener_pid=$!
  LISTENER_PIDS+=("$listener_pid")
  wait_for 10 "v${version} spy listener" grep -Fq '"type":"connected"' "$listener"

  # Peer-directory clients capability-check before sending the new IPC command.
  # An old daemon must fail promptly and remain usable, never reinterpret the
  # request or expose its endpoint-bearing status as a peer snapshot.
  set +e
  timeout 10 "$BIN" --state-dir "$base/sender" --json peers \
    >"$base/peers.out" 2>"$base/peers.err"
  local peers_status=$?
  set -e
  [[ $peers_status -ne 0 ]] || fail "current peers unexpectedly succeeded against v${version} daemon"
  [[ $peers_status -ne 124 ]] || fail "current peers hung against v${version} daemon"
  [[ ! -s "$base/peers.err" ]] || fail "current JSON peers wrote diagnostics to stderr"
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["type"] == "error" and v["schema_version"] == 1 and v["outcome"] == "not_started"' "$base/peers.out" \
    || fail "current peers did not fail with the stable JSON contract"
  status_ok "$version" sender || fail "v${version} daemon stopped responding after rejected peers request"

  # A current client must negotiate before submitting private plaintext. The
  # v0.1.11 parser ignored `to` on command=send and broadcast the body; v0.1.12
  # also predates capability negotiation. Merely checking a reply is too late.
  local private="must-not-broadcast-v${version}-$(date +%s%N)"
  set +e
  timeout 10 "$BIN" --state-dir "$base/sender" --json send --to intended-private-peer "$private" \
    >"$base/private.out" 2>"$base/private.err"
  local private_status=$?
  set -e
  [[ $private_status -ne 0 ]] \
    || fail "current --to unexpectedly succeeded against v${version} daemon"
  [[ $private_status -ne 124 ]] \
    || fail "current --to negotiation hung against v${version} daemon"
  [[ ! -s "$base/private.err" ]] || fail "current JSON --to wrote diagnostics to stderr"
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["type"] == "error" and v["outcome"] == "not_started"' "$base/private.out" \
    || fail "current --to did not report a stable not-started JSON error"
  sleep 2
  ! grep -Fq "$private" "$listener" \
    || fail "current --to plaintext was broadcast by v${version} daemon"
  ! grep -Fq "$private" "$base/sender.daemon.log" \
    || fail "current --to plaintext reached v${version} daemon output"
  ! grep -Fq "$private" "$base/sender.daemon.err" \
    || fail "current --to plaintext reached v${version} daemon diagnostics"

  # All current mutations require retry-safe operation-ID negotiation, including
  # broadcast. The old wire command remains parseable, but a current client must
  # not submit it when the daemon lacks idempotent_mutations_v1.
  local broadcast="must-not-submit-broadcast-v${version}-$(date +%s%N)"
  set +e
  timeout 10 "$BIN" --state-dir "$base/sender" --json send "$broadcast" \
    >"$base/broadcast.out" 2>"$base/broadcast.err"
  local broadcast_status=$?
  set -e
  [[ $broadcast_status -ne 0 ]] \
    || fail "current broadcast unexpectedly succeeded against v${version} daemon"
  [[ $broadcast_status -ne 124 ]] \
    || fail "current broadcast negotiation hung against v${version} daemon"
  [[ ! -s "$base/broadcast.err" ]] || fail "current JSON broadcast wrote diagnostics to stderr"
  python3 -c 'import json,sys; v=json.load(open(sys.argv[1])); assert v["type"] == "error" and v["outcome"] == "not_started"' "$base/broadcast.out" \
    || fail "current broadcast did not report a stable not-started JSON error"
  sleep 2
  ! grep -Fq "$broadcast" "$listener" \
    || fail "current broadcast was submitted to a v${version} peer"
  ! grep -Fq "$broadcast" "$base/sender.daemon.log" \
    || fail "current broadcast reached v${version} daemon output"
  ! grep -Fq "$broadcast" "$base/sender.daemon.err" \
    || fail "current broadcast reached v${version} daemon diagnostics"
  status_ok "$version" sender \
    || fail "v${version} daemon stopped responding after rejected mutation negotiations"
}

# Published immutable archives are checksum-pinned so this downgrade regression
# exercises the exact permissive IPC parsers that shipped to users.
fetch_release 0.1.11 57e2ab1b5039936de533b11ab6378db1d1b0492cce1c57a3d75d55a3c45c13fd
fetch_release 0.1.12 016c350a22e4d6c7d5b1d75d1982fb158e32aa3fac807b1178cd92b9b9dffa65
run_scenario 0.1.11
run_scenario 0.1.12

echo "PASS: peer-directory and all current mutations fail closed without submission against published v0.1.11/v0.1.12 daemons lacking retry-safe operation IDs"
