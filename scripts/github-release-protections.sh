#!/usr/bin/env bash
set -euo pipefail

MODE=${1:---check}
REPOSITORY=${GITHUB_REPOSITORY:-Eldar-Ahmadov/meshmsg}
RELEASE_AUTHORITY=${MESHMSG_RELEASE_AUTHORITY:-${REPOSITORY%%/*}}
API_VERSION=2022-11-28
IMMUTABLE_NAME="meshmsg-immutable-v-tags"
CREATION_NAME="meshmsg-release-tag-authority"
SCRIPT_ROOT=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
export MISE_QUIET=1 GH_PROMPT_DISABLED=1

case "$MODE" in
  --check|--apply) ;;
  --ci-check) [[ -n ${GH_TOKEN:-} ]] || { echo "RELEASE_PROTECTION_AUDIT_TOKEN is unavailable" >&2; exit 1; } ;;
  *) echo "usage: $0 [--check|--ci-check|--apply]" >&2; exit 2 ;;
esac
for command in gh jq python3; do command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }; done
# Deliberately noninteractive: never starts login or widens a token.
gh auth status >/dev/null
api() { gh api -H "X-GitHub-Api-Version: $API_VERSION" "$@"; }

temp=$(mktemp -d)
trap 'rm -rf "$temp"' EXIT
ruleset_id() {
  local name=$1 ids count
  ids=$(api "repos/$REPOSITORY/rulesets" --paginate --jq ".[] | select(.name == \"$name\") | .id")
  count=$(printf '%s\n' "$ids" | awk 'NF { count++ } END { print count + 0 }')
  [[ $count -le 1 ]] || { echo "duplicate rulesets named $name" >&2; return 1; }
  printf '%s' "$ids"
}
write_ruleset() {
  local name=$1 payload=$2 id
  id=$(ruleset_id "$name")
  if [[ -n $id ]]; then
    api --method PUT "repos/$REPOSITORY/rulesets/$id" --input "$payload" >/dev/null
  else
    api --method POST "repos/$REPOSITORY/rulesets" --input "$payload" >/dev/null
  fi
}
authority_id=$(api "users/$RELEASE_AUTHORITY" --jq .id)
if [[ $MODE == --apply ]]; then
  jq -n --arg name "$IMMUTABLE_NAME" '{
    name:$name,target:"tag",enforcement:"active",bypass_actors:[],
    conditions:{ref_name:{include:["refs/tags/v*"],exclude:[]}},
    rules:[{type:"update",parameters:{update_allows_fetch_and_merge:false}},{type:"deletion"}]
  }' >"$temp/immutable-policy.json"
  jq -n --arg name "$CREATION_NAME" --argjson actor "$authority_id" '{
    name:$name,target:"tag",enforcement:"active",
    bypass_actors:[{actor_id:$actor,actor_type:"User",bypass_mode:"always"}],
    conditions:{ref_name:{include:["refs/tags/v*"],exclude:[]}},rules:[{type:"creation"}]
  }' >"$temp/creation-policy.json"
  write_ruleset "$IMMUTABLE_NAME" "$temp/immutable-policy.json"
  write_ruleset "$CREATION_NAME" "$temp/creation-policy.json"
fi

immutable_id=$(ruleset_id "$IMMUTABLE_NAME")
creation_id=$(ruleset_id "$CREATION_NAME")
[[ -n $immutable_id && -n $creation_id ]] || { echo "canonical tag rulesets are missing" >&2; exit 1; }
api "repos/$REPOSITORY/rulesets/$immutable_id" >"$temp/immutable.json"
api "repos/$REPOSITORY/rulesets/$creation_id" >"$temp/creation.json"
python3 "$SCRIPT_ROOT/tests/validate-github-protections.py" \
  --immutable "$temp/immutable.json" --creation "$temp/creation.json" \
  --authority-id "$authority_id"
printf 'GitHub release tag protections: canonical policy active (%s; authority %s)\n' \
  "$REPOSITORY" "$RELEASE_AUTHORITY"
