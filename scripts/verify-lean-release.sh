#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

TARGET_DIR=${MESHMSG_LEAN_TARGET_DIR:-target/lean-verification}
METADATA=$(mktemp)
PACKAGES=$(mktemp)
cleanup() {
  rm -f "$METADATA" "$PACKAGES"
}
trap cleanup EXIT

cargo metadata --locked --format-version 1 --all-features >"$METADATA"

python3 - "$METADATA" <<'PY'
import json
import sys

metadata = json.load(open(sys.argv[1], encoding="utf-8"))
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
assert package["features"] == {}, package["features"]
assert node["features"] == [], node["features"]
assert not ({"crossterm", "ratatui"} & direct), direct
assert bins == {"meshmsg": set()}, bins
print("root features: none")
print("binary targets: meshmsg only")
PY

cargo tree --locked --all-features --edges normal --prefix none \
  | awk '{print $1}' | sort -u >"$PACKAGES"

for dependency in ratatui crossterm ratatui-core ratatui-crossterm ratatui-widgets; do
  ! grep -qx "$dependency" "$PACKAGES" || {
    echo "dependency graph unexpectedly contains $dependency" >&2
    exit 1
  }
  ! grep -Eq "^name = \"$dependency\"$" Cargo.lock || {
    echo "lockfile unexpectedly contains $dependency" >&2
    exit 1
  }
done

# HTTP crates remain transitive because Iroh uses them for relay/discovery.
for dependency in hyper http-body http-body-util hyper-util; do
  if grep -qx "$dependency" "$PACKAGES"; then
    echo "default transitive transport dependency retained by Iroh: $dependency"
  fi
done

echo "unique normal packages: $(wc -l <"$PACKAGES")"

rm -rf "$TARGET_DIR"
cargo build --locked --release --bin meshmsg --target-dir "$TARGET_DIR"
BINARY="$TARGET_DIR/release/meshmsg"

if command -v file >/dev/null 2>&1; then
  file "$BINARY"
  file "$BINARY" | grep -q 'stripped' || {
    echo "release binary is not stripped" >&2
    exit 1
  }
fi

bytes=$(wc -c <"$BINARY")
printf 'stripped release: %s bytes (%s)\n' "$bytes" "$(du -h "$BINARY" | cut -f1)"
