#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET_DIR=${MESHMSG_LEAN_TARGET_DIR:-target/lean-verification}
DEFAULT_METADATA=$(mktemp)
ALL_METADATA=$(mktemp)
DEFAULT_PACKAGES=$(mktemp)
ALL_PACKAGES=$(mktemp)
cleanup() {
  rm -f "$DEFAULT_METADATA" "$ALL_METADATA" "$DEFAULT_PACKAGES" "$ALL_PACKAGES"
}
trap cleanup EXIT

cargo metadata --locked --format-version 1 --no-default-features >"$DEFAULT_METADATA"
cargo metadata --locked --format-version 1 --all-features >"$ALL_METADATA"

python3 - "$DEFAULT_METADATA" "$ALL_METADATA" <<'PY'
import json
import sys

optional = {"crossterm", "ratatui"}
expected_features = {"bench", "bench-tui", "default"}

def root_state(path):
    metadata = json.load(open(path, encoding="utf-8"))
    package = next(
        package for package in metadata["packages"]
        if package["name"] == "meshmsg" and package["source"] is None
    )
    node = next(node for node in metadata["resolve"]["nodes"] if node["id"] == package["id"])
    direct = {dependency["name"] for dependency in node["deps"]}
    bins = {
        target["name"]: set(target.get("required-features", []))
        for target in package["targets"] if "bin" in target["kind"]
    }
    return set(node["features"]), direct, bins

default_features, default_direct, bins = root_state(sys.argv[1])
all_features, all_direct, _ = root_state(sys.argv[2])
assert default_features == set(), default_features
assert not (default_direct & optional), default_direct & optional
assert all_features == expected_features, all_features
assert optional <= all_direct, optional - all_direct
assert bins == {
    "meshmsg": set(),
    "meshmsg-bench": {"bench"},
    "meshmsg-bench-tui": {"bench-tui"},
}, bins
print("default root features: none")
print("default direct optional dependencies: none")
print("optional benchmark binaries: required-features wiring verified")
PY

cargo tree --locked --no-default-features --edges normal --prefix none \
  | awk '{print $1}' | sort -u >"$DEFAULT_PACKAGES"
cargo tree --locked --all-features --edges normal --prefix none \
  | awk '{print $1}' | sort -u >"$ALL_PACKAGES"

for dependency in ratatui crossterm; do
  ! grep -qx "$dependency" "$DEFAULT_PACKAGES" || {
    echo "default dependency graph unexpectedly contains $dependency" >&2
    exit 1
  }
  grep -qx "$dependency" "$ALL_PACKAGES" || {
    echo "all-features dependency graph is missing $dependency" >&2
    exit 1
  }
done

# HTTP crates remain transitive because Iroh uses them for relay/discovery.
for dependency in hyper http-body http-body-util hyper-util; do
  if grep -qx "$dependency" "$DEFAULT_PACKAGES"; then
    echo "default transitive transport dependency retained by Iroh: $dependency"
  fi
done

echo "unique normal packages: default=$(wc -l <"$DEFAULT_PACKAGES") all-features=$(wc -l <"$ALL_PACKAGES")"

rm -rf "$TARGET_DIR"
cargo build --locked --release --no-default-features --bin meshmsg --target-dir "$TARGET_DIR"
BINARY="$TARGET_DIR/release/meshmsg"
for optional_binary in meshmsg-bench meshmsg-bench-tui; do
  test ! -e "$TARGET_DIR/release/$optional_binary" || {
    echo "default release unexpectedly built $optional_binary" >&2
    exit 1
  }
done
for optional_marker in \
  meshmsg-bench-tui \
  "Configure and monitor a meshmsg benchmark interactively"; do
  ! grep -aFq "$optional_marker" "$BINARY" || {
    echo "default release unexpectedly contains optional marker: $optional_marker" >&2
    exit 1
  }
done

echo "default artifact: optional benchmark/TUI markers absent"

if command -v file >/dev/null 2>&1; then
  file "$BINARY"
  file "$BINARY" | grep -q 'stripped' || {
    echo "default release binary is not stripped" >&2
    exit 1
  }
fi

bytes=$(wc -c <"$BINARY")
printf 'stripped default release: %s bytes (%s)\n' "$bytes" "$(du -h "$BINARY" | cut -f1)"
