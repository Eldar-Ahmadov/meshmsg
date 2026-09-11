#!/usr/bin/env bash
set -euo pipefail

BIN=${1:-target/debug/meshmsg}
BIN=$(realpath "$BIN")
INVENTORY=tests/linux-integration-inventory.tsv

# Syntax/static checks live beside the parsed integration inventory so local and
# CI verification cannot silently acquire different command lists.
bash -n install.sh tests/*.sh scripts/*.sh
python3 -m py_compile tests/*.py
node --check src/web/app.js
node --check src/web/settings.js
node --check tests/web-ui.cjs

total_timeout=0
while IFS=$'\t' read -r seconds command arguments; do
  [[ $seconds =~ ^[1-9][0-9]*$ && -n $command && -n $arguments ]] || {
    echo "invalid Linux integration inventory record" >&2
    exit 1
  }
  total_timeout=$((total_timeout + seconds))
  read -r -a args <<<"$arguments"
  for index in "${!args[@]}"; do
    [[ ${args[$index]} == "{BIN}" ]] && args[$index]=$BIN
  done
  timeout "$seconds" "$command" "${args[@]}"
done <"$INVENTORY"

# Keep the workflow timeout reviewable when inventory entries change.
((total_timeout <= 6900)) || {
  echo "Linux integration timeout inventory exceeds the 115-minute command budget" >&2
  exit 1
}
