#!/usr/bin/env bash
set -euo pipefail

MODE=${1:---check}
REPOSITORY=${GITHUB_REPOSITORY:-Eldar-Ahmadov/meshmsg}
RELEASE_AUTHORITY=${MESHMSG_RELEASE_AUTHORITY:-${REPOSITORY%%/*}}
API_VERSION=2022-11-28
MAIN_CHECK="Required verification"
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
fetch_codeowners() {
  api -H "Accept: application/vnd.github.raw+json" \
    "repos/$REPOSITORY/contents/.github/CODEOWNERS?ref=main"
}

expected_codeowners="$SCRIPT_ROOT/.github/CODEOWNERS"
[[ -f $expected_codeowners ]] || { echo "local canonical CODEOWNERS is missing" >&2; exit 1; }
if ! fetch_codeowners >"$temp/remote-CODEOWNERS" 2>/dev/null || ! cmp -s "$expected_codeowners" "$temp/remote-CODEOWNERS"; then
  echo "protected origin/main does not contain the canonical .github/CODEOWNERS" >&2
  exit 1
fi

authority_id=$(api "users/$RELEASE_AUTHORITY" --jq .id)
api "repos/$REPOSITORY/collaborators?affiliation=direct&per_page=100" --paginate | jq -s 'add' >"$temp/collaborators.json"
python3 "$SCRIPT_ROOT/tests/validate-codeowners.py" \
  --codeowners "$expected_codeowners" --collaborators "$temp/collaborators.json" \
  --authority "$RELEASE_AUTHORITY" || {
    echo "refusing protection changes/audit success without applicable independent code ownership" >&2
    exit 1
  }
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
  jq -n --arg check "$MAIN_CHECK" '{
    required_status_checks:{strict:true,checks:[{context:$check,app_id:15368}]},
    enforce_admins:true,
    required_pull_request_reviews:{
      dismiss_stale_reviews:true,require_code_owner_reviews:true,
      required_approving_review_count:1,require_last_push_approval:true
    },
    restrictions:null,required_linear_history:false,allow_force_pushes:false,
    allow_deletions:false,block_creations:false,required_conversation_resolution:true,
    lock_branch:false,allow_fork_syncing:false
  }' >"$temp/main-policy.json"
  write_ruleset "$IMMUTABLE_NAME" "$temp/immutable-policy.json"
  write_ruleset "$CREATION_NAME" "$temp/creation-policy.json"
  api --method PUT "repos/$REPOSITORY/branches/main/protection" --input "$temp/main-policy.json" >/dev/null
fi

immutable_id=$(ruleset_id "$IMMUTABLE_NAME")
creation_id=$(ruleset_id "$CREATION_NAME")
[[ -n $immutable_id && -n $creation_id ]] || { echo "canonical tag rulesets are missing" >&2; exit 1; }
api "repos/$REPOSITORY/rulesets/$immutable_id" >"$temp/immutable.json"
api "repos/$REPOSITORY/rulesets/$creation_id" >"$temp/creation.json"
api "repos/$REPOSITORY/branches/main/protection" >"$temp/main.json"
python3 "$SCRIPT_ROOT/tests/validate-github-protections.py" \
  --immutable "$temp/immutable.json" --creation "$temp/creation.json" \
  --main "$temp/main.json" --authority-id "$authority_id"
printf 'GitHub release protections: complete canonical policy active (%s; authority %s; check %s)\n' \
  "$REPOSITORY" "$RELEASE_AUTHORITY" "$MAIN_CHECK"
