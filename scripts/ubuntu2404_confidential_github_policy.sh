#!/usr/bin/env bash
set -euo pipefail
umask 077

output_dir=${1:?usage: ubuntu2404_confidential_github_policy.sh OUTPUT_DIR}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_API_VERSION:?GH_API_VERSION is required}"
: "${EXPECTED_PUBLISHER_APP_ID:?EXPECTED_PUBLISHER_APP_ID is required}"
: "${PROVENANCE_RULESET_NAME:?PROVENANCE_RULESET_NAME is required}"
: "${PROVENANCE_TAG_PATTERN:?PROVENANCE_TAG_PATTERN is required}"

[[ "$EXPECTED_PUBLISHER_APP_ID" =~ ^[1-9][0-9]*$ ]]
test "$PROVENANCE_RULESET_NAME" = ubuntu2404-confidential-provenance-tags
test "$PROVENANCE_TAG_PATTERN" = \
  'refs/tags/miz-provenance/ubuntu2404-confidential-cvm/**'

mkdir -m 0700 -p "$output_dir"
api_headers=(
  -H 'Accept: application/vnd.github+json'
  -H "X-GitHub-Api-Version: $GH_API_VERSION"
)
ruleset_pages="$output_dir/tag-ruleset-pages.json"
rulesets="$output_dir/tag-rulesets.json"
ruleset="$output_dir/tag-ruleset.json"

gh api --paginate --slurp "${api_headers[@]}" \
  "repos/$GITHUB_REPOSITORY/rulesets?includes_parents=true&targets=tag&per_page=100" \
  >"$ruleset_pages"
jq -e \
  'type == "array" and all(.[]; type == "array")' \
  "$ruleset_pages" >/dev/null
jq '[.[][]]' "$ruleset_pages" >"$rulesets"
jq -e \
  --arg name "$PROVENANCE_RULESET_NAME" \
  'length == 1 and .[0].name == $name and
   (.[0].id | type == "number" and . > 0)' \
  "$rulesets" >/dev/null
ruleset_id=$(jq -er '.[0].id' "$rulesets")

gh api "${api_headers[@]}" \
  "repos/$GITHUB_REPOSITORY/rulesets/$ruleset_id?includes_parents=true" \
  >"$ruleset"
jq -e \
  --argjson ruleset_id "$ruleset_id" \
  --arg name "$PROVENANCE_RULESET_NAME" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg pattern "$PROVENANCE_TAG_PATTERN" \
  --argjson app_id "$EXPECTED_PUBLISHER_APP_ID" \
  '
  type == "object" and
  .id == $ruleset_id and
  .name == $name and
  .target == "tag" and
  .source_type == "Repository" and
  .source == $repository and
  .enforcement == "active" and
  .bypass_actors == [{
    actor_id: $app_id,
    actor_type: "Integration",
    bypass_mode: "always"
  }] and
  (.conditions | type == "object" and
    (keys | sort) == ["ref_name"] and
    (.ref_name | type == "object" and
      (keys | sort) == ["exclude", "include"] and
      .include == [$pattern] and
      .exclude == [])) and
  (.rules | type == "array" and length == 3 and
    ([.[].type] | sort) == ["creation", "deletion", "update"] and
    all(.[]; (keys | sort) == ["type"]))
  ' "$ruleset" >/dev/null || {
  echo "::error::The provenance tag ruleset is missing, inherited, ambiguous, inactive, or not exact"
  exit 1
}
