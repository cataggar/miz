#!/usr/bin/env bash
set -euo pipefail
umask 077

output_dir=${1:?usage: check_repository_release_policy.sh OUTPUT_DIR RELEASE_TOOL REPOSITORY}
release_tool=${2:?release tool is required}
repository=${3:?repository is required}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_API_VERSION:=2026-03-10}"

[[ "$repository" == cataggar/miz ]]
[[ -x "$release_tool" ]]
mkdir -p -- "$output_dir"

api_headers=(
  -H 'Accept: application/vnd.github+json'
  -H "X-GitHub-Api-Version: $GH_API_VERSION"
)
immutable_response="$output_dir/immutable-releases.json"
rulesets_response="$output_dir/tag-ruleset-pages.json"

gh api --method GET "${api_headers[@]}" \
  "repos/$repository/immutable-releases" >"$immutable_response"
gh api --method GET --paginate --slurp "${api_headers[@]}" \
  "repos/$repository/rulesets?includes_parents=true&targets=tag&per_page=100" \
  >"$rulesets_response"

"$release_tool" check-release-policy \
  --repository "$repository" \
  --immutable-response "$immutable_response" \
  --rulesets-response "$rulesets_response"
