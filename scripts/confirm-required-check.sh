#!/usr/bin/env bash
set -euo pipefail

REPOSITORY=${1:-${GITHUB_REPOSITORY:-Eldar-Ahmadov/meshmsg}}
PR=${2:-}
[[ $PR =~ ^[1-9][0-9]*$ ]] || { echo "usage: $0 OWNER/REPO PR_NUMBER" >&2; exit 2; }
export GH_PROMPT_DISABLED=1 MISE_QUIET=1
for command in gh jq; do command -v "$command" >/dev/null || { echo "$command is required" >&2; exit 1; }; done
gh auth status >/dev/null
pull=$(gh api "repos/$REPOSITORY/pulls/$PR")
[[ $(jq -r .state <<<"$pull") == open && $(jq -r .base.ref <<<"$pull") == main ]] || {
  echo "probe PR must be open against main" >&2; exit 1;
}
sha=$(jq -r .head.sha <<<"$pull")
base_sha=$(jq -r .base.sha <<<"$pull")
main_sha=$(gh api "repos/$REPOSITORY/commits/main" --jq .sha)
[[ $base_sha == "$main_sha" ]] || { echo "probe PR base is not the current protected main tip" >&2; exit 1; }
commits=$(gh api "repos/$REPOSITORY/pulls/$PR/commits?per_page=100")
[[ $(jq 'length' <<<"$commits") -eq 1 && $(jq -r '.[0].parents | length' <<<"$commits") -eq 1 &&
   $(jq -r '.[0].parents[0].sha' <<<"$commits") == "$base_sha" ]] || {
  echo "probe PR must contain exactly one commit directly based on current main" >&2; exit 1;
}
mapfile -t files < <(gh api "repos/$REPOSITORY/pulls/$PR/files" --paginate --jq '.[] | [.filename,.status] | @tsv')
[[ ${#files[@]} -eq 1 && ${files[0]} == $'.github/required-check-probe.txt\tadded' ]] || {
  echo "probe PR must only add .github/required-check-probe.txt" >&2; exit 1;
}
checks=$(gh api "repos/$REPOSITORY/commits/$sha/check-runs?per_page=100")
named=$(jq '[.check_runs[] | select(.name == "Required verification" and .head_sha == "'"$sha"'")]' <<<"$checks")
[[ $(jq 'length' <<<"$named") -ge 1 && $(jq 'all(.[]; .app.id == 15368)' <<<"$named") == true &&
   $(jq '[.[] | select(.status == "completed" and .conclusion == "success")] | length' <<<"$named") -ge 1 ]] || {
  echo "a successful Required verification exclusively from GitHub Actions app 15368 was not observed for $sha" >&2
  exit 1
}
printf 'Required verification context confirmed for PR #%s at %s from GitHub Actions app 15368\n' "$PR" "$sha"
