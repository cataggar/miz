#!/usr/bin/env bash
set -euo pipefail
umask 077

output_dir=${1:?usage: ubuntu2404_confidential_github_policy.sh OUTPUT_DIR}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GITHUB_REPOSITORY_OWNER:?GITHUB_REPOSITORY_OWNER is required}"
: "${GH_API_VERSION:?GH_API_VERSION is required}"
: "${EXPECTED_PUBLISHER_APP_ID:?EXPECTED_PUBLISHER_APP_ID is required}"
: "${PROVENANCE_RULESET_NAME:?PROVENANCE_RULESET_NAME is required}"
: "${PROVENANCE_TAG_PATTERN:?PROVENANCE_TAG_PATTERN is required}"

[[ "$EXPECTED_PUBLISHER_APP_ID" =~ ^[1-9][0-9]*$ ]]
test "$GITHUB_REPOSITORY" = "$GITHUB_REPOSITORY_OWNER/miz"
test "$GITHUB_REPOSITORY_OWNER" = cataggar
test "$PROVENANCE_RULESET_NAME" = ubuntu2404-confidential-provenance-tags
test "$PROVENANCE_TAG_PATTERN" = \
  'refs/tags/miz-provenance/ubuntu2404-confidential-cvm/*/*/*'

mkdir -m 0700 -p "$output_dir"
api_headers=(
  -H 'Accept: application/vnd.github+json'
  -H "X-GitHub-Api-Version: $GH_API_VERSION"
)
repository="$output_dir/repository.json"
collaborator_pages="$output_dir/collaborator-pages.json"
collaborators="$output_dir/collaborators.json"
installation_pages="$output_dir/installation-pages.json"
installations="$output_dir/installations.json"
workflow_permissions="$output_dir/workflow-permissions.json"
ruleset_pages="$output_dir/tag-ruleset-pages.json"
rulesets="$output_dir/tag-rulesets.json"
ruleset="$output_dir/tag-ruleset.json"

gh api "${api_headers[@]}" \
  "repos/$GITHUB_REPOSITORY" >"$repository"
jq -e \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg owner "$GITHUB_REPOSITORY_OWNER" \
  '
  type == "object" and
  .full_name == $repository and
  (.owner | type == "object" and
    .login == $owner and .type == "User") and
  ((.organization? // null) == null)
  ' "$repository" >/dev/null || {
  echo "::error::The repository must remain the expected personal repository"
  exit 1
}

gh api --paginate --slurp "${api_headers[@]}" \
  "repos/$GITHUB_REPOSITORY/collaborators?affiliation=all&per_page=100" \
  >"$collaborator_pages"
jq -e \
  'type == "array" and all(.[]; type == "array")' \
  "$collaborator_pages" >/dev/null
jq '[.[][]]' "$collaborator_pages" >"$collaborators"
jq -e \
  --arg owner "$GITHUB_REPOSITORY_OWNER" \
  '
  ($owner | ascii_downcase) as $owner_login |
  type == "array" and length >= 1 and
  all(.[];
    type == "object" and
    (.login | type == "string" and length > 0) and
    (.permissions | type == "object") and
    (.permissions.pull | type) == "boolean" and
    (.permissions.push | type) == "boolean" and
    (.permissions.maintain | type) == "boolean" and
    (.permissions.admin | type) == "boolean") and
  ([.[] | select((.login | ascii_downcase) == $owner_login)] | length) == 1 and
  ([.[] | select((.login | ascii_downcase) == $owner_login)][0] |
    .permissions.admin == true) and
  ([.[] |
    select(.permissions.push or .permissions.maintain or .permissions.admin) |
    (.login | ascii_downcase)] | unique) == [$owner_login]
  ' "$collaborators" >/dev/null || {
  echo "::error::Only the personal repository owner may have write access"
  exit 1
}

# This Administration API response must enumerate every App installation with
# its granted repository permissions. An unavailable or redacted route fails
# before any protected mutation.
gh api --paginate --slurp "${api_headers[@]}" \
  "repos/$GITHUB_REPOSITORY/installations?per_page=100" \
  >"$installation_pages"
jq -e \
  'type == "array" and all(.[]; type == "array")' \
  "$installation_pages" >/dev/null
jq '[.[][]]' "$installation_pages" >"$installations"
jq -e \
  --argjson app_id "$EXPECTED_PUBLISHER_APP_ID" \
  '
  type == "array" and length >= 1 and
  all(.[];
    type == "object" and
    (.app_id | type == "number" and . > 0) and
    (.permissions | type == "object") and
    ((.permissions.contents? // "none") |
      . == "none" or . == "read" or . == "write")) and
  ([.[].app_id] | length) == ([.[].app_id] | unique | length) and
  ([.[] | select(.app_id == $app_id)] | length) == 1 and
  ([.[] | select(.app_id == $app_id)][0] |
    .permissions.administration == "write" and
    .permissions.contents == "write" and
    .permissions.workflows == "write") and
  ([.[] | select(.permissions.contents? == "write") | .app_id]) == [$app_id]
  ' "$installations" >/dev/null || {
  echo "::error::The publishing App must be the only Contents-write installation"
  exit 1
}

gh api "${api_headers[@]}" \
  "repos/$GITHUB_REPOSITORY/actions/permissions/workflow" \
  >"$workflow_permissions"
jq -e \
  '
  type == "object" and
  .default_workflow_permissions == "read" and
  .can_approve_pull_request_reviews == false
  ' "$workflow_permissions" >/dev/null || {
  echo "::error::Default workflow permissions must be read-only without PR approval"
  exit 1
}

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
