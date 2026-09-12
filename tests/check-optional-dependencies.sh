#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")/.."

contains_tui_dependencies() {
  grep -Eq '^(crossterm|ratatui) v'
}

assert_absent() {
  local label=$1
  shift
  local tree
  tree=$(cargo tree --locked --edges normal --prefix none "$@")
  if printf '%s\n' "$tree" | contains_tui_dependencies; then
    echo "$label dependency graph unexpectedly contains Ratatui/Crossterm" >&2
    return 1
  fi
}

assert_present() {
  local label=$1
  shift
  local tree dependency
  tree=$(cargo tree --locked --edges normal --prefix none "$@")
  for dependency in ratatui crossterm; do
    if ! grep -Eq "^${dependency} v" <<<"$tree"; then
      echo "$label dependency graph is missing $dependency" >&2
      return 1
    fi
  done
}

assert_absent default
assert_absent bench --features bench
assert_absent web --features web
assert_present bench-tui --features bench-tui
assert_present full --features full
