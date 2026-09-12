#!/usr/bin/env bash
set -euo pipefail

PHASE=${1:?usage: check-release-eligibility.sh admission|recheck TAG EXPECTED_SHA}
TAG=${2:?usage: check-release-eligibility.sh admission|recheck TAG EXPECTED_SHA}
EXPECTED_SHA=${3:?usage: check-release-eligibility.sh admission|recheck TAG EXPECTED_SHA}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
case "$PHASE" in admission|recheck) ;; *) echo "eligibility phase must be admission or recheck" >&2; exit 2 ;; esac

if [[ ! $TAG =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "release tag must have form vMAJOR.MINOR.PATCH: $TAG" >&2
  exit 1
fi
if [[ ! $EXPECTED_SHA =~ ^[0-9a-fA-F]{40}$ ]]; then
  echo "expected release SHA must be a full commit SHA" >&2
  exit 1
fi

# Resolve both refs afresh every time this script is called. No worktree file is
# trusted for eligibility: metadata is extracted from the resolved commit below.
git fetch --force --no-tags origin \
  "+refs/heads/main:refs/remotes/origin/main" \
  "+refs/tags/${TAG}:refs/tags/${TAG}"
expected_commit=$(git rev-parse "${EXPECTED_SHA}^{commit}")
tag_commit=$(git rev-parse "refs/tags/${TAG}^{commit}")
head_commit=$(git rev-parse "HEAD^{commit}")
test "$tag_commit" = "$expected_commit" || {
  echo "tag $TAG does not identify expected commit $expected_commit" >&2
  exit 1
}
test "$head_commit" = "$expected_commit" || {
  echo "checked-out HEAD $head_commit does not match release commit $expected_commit" >&2
  exit 1
}
git diff --quiet "$expected_commit" -- Cargo.toml Cargo.lock ".github/release-notes/${TAG}.md" || {
  echo "release metadata worktree differs from tagged commit $expected_commit" >&2
  exit 1
}
main_tip=$(git rev-parse "origin/main^{commit}")
if [[ $PHASE == admission ]]; then
  test "$expected_commit" = "$main_tip" || {
    echo "initial tag admission requires current origin/main tip $main_tip, got $expected_commit" >&2
    exit 1
  }
else
  first_parent_matches=$(git rev-list --first-parent origin/main | awk -v wanted="$expected_commit" '$0 == wanted { count++ } END { print count + 0 }')
  test "$first_parent_matches" -eq 1 || {
    echo "release commit $expected_commit is no longer on origin/main first-parent history" >&2
    exit 1
  }
fi

metadata=$(mktemp -d)
trap 'rm -rf "$metadata"' EXIT
mkdir -p "$metadata/.github/release-notes"
git show "$expected_commit:Cargo.toml" >"$metadata/Cargo.toml"
git show "$expected_commit:Cargo.lock" >"$metadata/Cargo.lock"
git show "$expected_commit:.github/release-notes/${TAG}.md" \
  >"$metadata/.github/release-notes/${TAG}.md" || {
    echo "tagged commit is missing release notes for $TAG" >&2
    exit 1
  }
python3 "$SCRIPT_DIR/validate-release-metadata.py" \
  --tag "$TAG" \
  --cargo "$metadata/Cargo.toml" \
  --lock "$metadata/Cargo.lock" \
  --notes "$metadata/.github/release-notes/${TAG}.md"
