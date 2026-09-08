#!/usr/bin/env bash
set -euo pipefail
umask 077

command_name=${1:?usage: ubuntu2404_confidential_provenance_tag.sh COMMAND TAG COMMIT OUTPUT_DIR}
tag_name=${2:?tag name is required}
expected_commit=${3:?expected commit is required}
output_dir=${4:?output directory is required}
: "${GH_TOKEN:?GH_TOKEN is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
: "${GH_API_VERSION:?GH_API_VERSION is required}"

tag_pattern='^miz-provenance/ubuntu2404-confidential-cvm/v(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})/origin-[1-9][0-9]{0,19}-attempt-[1-9][0-9]{0,9}/tool-[0-9a-f]{40}$'
[[ "$tag_name" =~ $tag_pattern ]]
[[ "$expected_commit" =~ ^[0-9a-f]{40}$ ]]

mkdir -m 0700 -p "$output_dir"
api_headers=(
  -H 'Accept: application/vnd.github+json'
  -H "X-GitHub-Api-Version: $GH_API_VERSION"
)
full_ref="refs/tags/$tag_name"

case "$command_name" in
  classify)
    matching_refs="$output_dir/provenance-matching-refs.json"
    gh api "${api_headers[@]}" \
      "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$tag_name" \
      >"$matching_refs"
    exact_count=$(jq -er \
      --arg ref "$full_ref" \
      '[.[] | select(.ref == $ref)] | length' \
      "$matching_refs")
    if (( exact_count == 0 )); then
      printf '%s\n' absent
    elif (( exact_count == 1 )); then
      jq -e \
        --arg ref "$full_ref" \
        --arg commit "$expected_commit" \
        '([.[] | select(.ref == $ref)] | length) == 1 and
         ([.[] | select(.ref == $ref)][0] |
           .object.type == "commit" and .object.sha == $commit)' \
        "$matching_refs" >/dev/null || {
        echo "::error::The protected provenance tag is not the exact lightweight commit ref"
        exit 1
      }
      printf '%s\n' lightweight
    else
      echo "::error::The protected provenance tag is ambiguous"
      exit 1
    fi
    ;;
  require-absent)
    matching_refs="$output_dir/provenance-matching-refs.json"
    gh api "${api_headers[@]}" \
      "repos/$GITHUB_REPOSITORY/git/matching-refs/tags/$tag_name" \
      >"$matching_refs"
    jq -e \
      --arg ref "$full_ref" \
      'type == "array" and
       all(.[]; .ref | type == "string") and
       ([.[] | select(.ref == $ref)] | length) == 0' \
      "$matching_refs" >/dev/null || {
      echo "::error::The protected provenance tag already exists"
      exit 1
    }
    ;;
  require-lightweight)
    tag_ref="$output_dir/provenance-tag-ref.json"
    gh api "${api_headers[@]}" \
      "repos/$GITHUB_REPOSITORY/git/ref/tags/$tag_name" \
      >"$tag_ref"
    jq -e \
      --arg ref "$full_ref" \
      --arg commit "$expected_commit" \
      '.ref == $ref and
       .object.type == "commit" and
       .object.sha == $commit' \
      "$tag_ref" >/dev/null || {
      echo "::error::The published provenance tag is not the expected lightweight commit ref"
      exit 1
    }
    ;;
  *)
    echo "unknown command: $command_name" >&2
    exit 2
    ;;
esac
