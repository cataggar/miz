#!/usr/bin/env bash
set -euo pipefail
umask 077

release_id=${1:?usage: ubuntu2404_confidential_publish_release.sh RELEASE_ID REQUEST_JSON RESPONSE_JSON}
request_json=${2:?usage: ubuntu2404_confidential_publish_release.sh RELEASE_ID REQUEST_JSON RESPONSE_JSON}
response_json=${3:?usage: ubuntu2404_confidential_publish_release.sh RELEASE_ID REQUEST_JSON RESPONSE_JSON}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GH_API_VERSION:?GH_API_VERSION is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${PROVENANCE_RELEASE_TAG:?PROVENANCE_RELEASE_TAG is required}"
: "${PROVENANCE_RELEASE_TITLE:?PROVENANCE_RELEASE_TITLE is required}"
: "${TOOL_COMMIT:?TOOL_COMMIT is required}"
: "${EXPECTED_RELEASE_NOTES:?EXPECTED_RELEASE_NOTES is required}"

[[ "$release_id" =~ ^[1-9][0-9]*$ ]]
[[ "$TOOL_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$PROVENANCE_RELEASE_TAG" != *$'\n'* ]]
[[ "$PROVENANCE_RELEASE_TITLE" != *$'\n'* ]]
test "$request_json" != "$response_json"
mkdir -m 0700 -p "$(dirname "$request_json")" "$(dirname "$response_json")"

jq -n \
  --arg tag "$PROVENANCE_RELEASE_TAG" \
  --arg target "$TOOL_COMMIT" \
  --arg title "$PROVENANCE_RELEASE_TITLE" \
  --arg notes "$EXPECTED_RELEASE_NOTES" \
  '{
    tag_name: $tag,
    target_commitish: $target,
    name: $title,
    body: $notes,
    draft: false,
    prerelease: false,
    make_latest: "false"
  }' >"$request_json"

gh api --method PATCH \
  -H 'Accept: application/vnd.github+json' \
  -H "X-GitHub-Api-Version: $GH_API_VERSION" \
  --input "$request_json" \
  "repos/$GITHUB_REPOSITORY/releases/$release_id" >"$response_json"
