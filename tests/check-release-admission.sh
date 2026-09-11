#!/usr/bin/env bash
# Admit a first run only at main tip; admit a rerun only if an earlier attempt
# of this same immutable workflow run completed the initial admission job.
set -euo pipefail

TAG=${1:?usage: check-release-admission.sh TAG EXPECTED_SHA RUN_ID RUN_ATTEMPT}
EXPECTED_SHA=${2:?usage: check-release-admission.sh TAG EXPECTED_SHA RUN_ID RUN_ATTEMPT}
RUN_ID=${3:?usage: check-release-admission.sh TAG EXPECTED_SHA RUN_ID RUN_ATTEMPT}
RUN_ATTEMPT=${4:?usage: check-release-admission.sh TAG EXPECTED_SHA RUN_ID RUN_ATTEMPT}
SCRIPT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
[[ $RUN_ID =~ ^[1-9][0-9]*$ && $RUN_ATTEMPT =~ ^[1-9][0-9]*$ ]] || {
  echo "run ID and attempt must be positive integers" >&2; exit 2;
}
if [[ $RUN_ATTEMPT -eq 1 ]]; then
  exec "$SCRIPT_DIR/check-release-eligibility.sh" admission "$TAG" "$EXPECTED_SHA"
fi
: "${GH_TOKEN:?GitHub Actions token is required to prove prior release admission on rerun}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
export GH_PROMPT_DISABLED=1 MISE_QUIET=1
run=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$RUN_ID")
[[ $(jq -r .event <<<"$run") == push && $(jq -r .head_sha <<<"$run") == "$EXPECTED_SHA" ]] || {
  echo "rerun identity does not match the immutable release event" >&2; exit 1;
}
proved=false
for ((attempt = 1; attempt < RUN_ATTEMPT; attempt++)); do
  jobs=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$RUN_ID/attempts/$attempt/jobs?per_page=100")
  count=$(jq '[.jobs[] | select(.name == "Initial release admission" and .status == "completed" and .conclusion == "success")] | length' <<<"$jobs")
  [[ $count -le 1 ]] || { echo "ambiguous prior admission evidence in attempt $attempt" >&2; exit 1; }
  [[ $count -eq 1 ]] && proved=true
done
[[ $proved == true ]] || { echo "no successful prior initial admission exists for this workflow run" >&2; exit 1; }
exec "$SCRIPT_DIR/check-release-eligibility.sh" recheck "$TAG" "$EXPECTED_SHA"
