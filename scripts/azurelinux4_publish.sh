#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${CANDIDATES_DIR:-} || -z ${AZURE_RESULTS_DIR:-} ||
      -z ${SOURCE_COMMIT:-} || -z ${RELEASE_TAG:-} ||
      -z ${RELEASE_TITLE:-} || -z ${REPOSITORY:-} ||
      -z ${STAGING_ROOT:-} || -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Required publication configuration is incomplete"
  exit 1
fi
for tool in gh sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required publication tool $tool is unavailable"
    exit 1
  }
done
release_tool=${AZURELINUX4_RELEASE:-zig-out/bin/azurelinux4_release}
[[ -x "$release_tool" ]] || {
  echo "::error::Azure Linux release tool is unavailable: $release_tool"
  exit 1
}
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$RELEASE_TAG" == AzureLinux-4.0-20260814 ]]
[[ "$REPOSITORY" == cataggar/miz ]]

mkdir -p "$STAGING_ROOT"
assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
refs_file="$STAGING_ROOT/tag-refs.json"
release_file="$STAGING_ROOT/release.json"
verify_dir="$STAGING_ROOT/remote"
rm -rf -- "$assets_dir" "$verify_dir"

"$release_tool" stage \
  --candidates "$CANDIDATES_DIR" \
  --azure-results "$AZURE_RESULTS_DIR" \
  --source-commit "$SOURCE_COMMIT" \
  --release-tag "$RELEASE_TAG" \
  --output "$assets_dir" \
  --notes "$notes_file"

"$release_tool" publish-expected \
  --manifest "$assets_dir/publish-manifest.json" >"$expected_file"
test "$(wc -l <"$expected_file")" -eq 4

release_mutated=false
publish_attempted=false
release_published=false
keep_draft_on_failure() {
  status=$?
  trap - EXIT INT TERM
  if [[ $status -ne 0 && "$release_mutated" == true ]]; then
    if [[ "$release_published" == true ]]; then
      echo "::error::Post-publication verification failed; quarantine and inspect immutable release $RELEASE_TAG without mutating it"
    elif [[ "$publish_attempted" == true ]]; then
      echo "::error::Publication outcome is unconfirmed; inspect $RELEASE_TAG without attempting release mutation"
    else
      echo "::warning::Publication failed; retaining resumable draft $RELEASE_TAG"
    fi
  fi
  exit "$status"
}
trap keep_draft_on_failure EXIT
trap 'exit 130' INT TERM

release_exists=false
if release_is_draft=$(
  gh release view "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --json isDraft \
    --jq .isDraft 2>/dev/null
); then
  release_exists=true
  if [[ "$release_is_draft" != true ]]; then
    echo "::error::Final release $RELEASE_TAG is immutable"
    exit 1
  fi
  existing_release_id=$(gh release view "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --json databaseId \
    --jq .databaseId)
  [[ "$existing_release_id" =~ ^[0-9]+$ ]]
  gh api "repos/$REPOSITORY/releases/$existing_release_id" >"$release_file"
  "$release_tool" check-release-metadata \
    --release "$release_file" \
    --notes "$notes_file" \
    --release-tag "$RELEASE_TAG" \
    --release-title "$RELEASE_TITLE" \
    --source-commit "$SOURCE_COMMIT"
fi

gh api "repos/$REPOSITORY/git/matching-refs/tags/$RELEASE_TAG" --paginate >"$refs_file"
readarray -t tag_object < <(
  "$release_tool" tag-ref --refs "$refs_file" --tag "$RELEASE_TAG"
)

if ((${#tag_object[@]} == 0)); then
  gh api --method POST "repos/$REPOSITORY/git/refs" \
    -f "ref=refs/tags/$RELEASE_TAG" \
    -f "sha=$SOURCE_COMMIT" >/dev/null
else
  object_type=${tag_object[0]}
  object_sha=${tag_object[1]}
  for _ in {1..8}; do
    [[ "$object_type" == tag ]] || break
    gh api "repos/$REPOSITORY/git/tags/$object_sha" >"$STAGING_ROOT/tag-object.json"
    readarray -t tag_object < <(
      "$release_tool" tag-object --document "$STAGING_ROOT/tag-object.json"
    )
    object_type=${tag_object[0]}
    object_sha=${tag_object[1]}
  done
  if [[ "$object_type" != commit || "$object_sha" != "$SOURCE_COMMIT" ]]; then
    echo "::error::Existing tag $RELEASE_TAG resolves to $object_type $object_sha, not accepted commit $SOURCE_COMMIT"
    exit 1
  fi
fi

if [[ "$release_exists" == true ]]; then
  gh release edit "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --draft \
    --latest=false \
    --title "$RELEASE_TITLE" \
    --notes-file "$notes_file" >/dev/null
else
  gh release create "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --target "$SOURCE_COMMIT" \
    --draft \
    --latest=false \
    --title "$RELEASE_TITLE" \
    --notes-file "$notes_file" >/dev/null
fi
release_mutated=true
release_id=${existing_release_id:-$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json databaseId \
  --jq .databaseId)}
[[ "$release_id" =~ ^[0-9]+$ ]]
release_api="repos/$REPOSITORY/releases/$release_id"
gh api "$release_api" >"$release_file"
"$release_tool" check-release-metadata \
  --release "$release_file" \
  --notes "$notes_file" \
  --release-tag "$RELEASE_TAG" \
  --release-title "$RELEASE_TITLE" \
  --source-commit "$SOURCE_COMMIT"

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
  gh release upload "$RELEASE_TAG" "$assets_dir/$asset_name" \
    --clobber \
    --repo "$REPOSITORY"
done <"$expected_file"

gh api "$release_api" >"$release_file"
"$release_tool" release-stale-assets \
  --release "$release_file" \
  --expected "$expected_file" >"$STAGING_ROOT/stale-asset-ids"
while read -r asset_id; do
  [[ "$asset_id" =~ ^[0-9]+$ ]]
  gh api --method DELETE "repos/$REPOSITORY/releases/assets/$asset_id"
done <"$STAGING_ROOT/stale-asset-ids"

gh api "$release_api" >"$release_file"
"$release_tool" check-release-assets \
  --release "$release_file" \
  --expected "$expected_file" \
  --state draft

mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir" \
  --clobber
"$release_tool" check-downloads \
  --directory "$verify_dir" \
  --expected "$expected_file"

gh api "$release_api" >"$release_file"
"$release_tool" check-release-assets \
  --release "$release_file" \
  --expected "$expected_file" \
  --state draft

publish_attempted=true
gh release edit "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --verify-tag \
  --draft=false \
  --latest=false \
  --title "$RELEASE_TITLE" \
  --notes-file "$notes_file" >/dev/null
release_published=true

gh api "$release_api" >"$release_file"
"$release_tool" check-release-assets \
  --release "$release_file" \
  --expected "$expected_file" \
  --state published

{
  echo "### Azure Linux 4 release published"
  echo
  echo "- Release: https://github.com/$REPOSITORY/releases/tag/$RELEASE_TAG"
  echo "- Source commit: \`$SOURCE_COMMIT\`"
  while IFS=$'\t' read -r asset_name expected_sha _; do
    echo "- \`$asset_name\`: \`$expected_sha\`"
  done <"$expected_file"
  echo
  echo "No checksum sidecar assets were published."
} >>"$GITHUB_STEP_SUMMARY"

release_mutated=false
publish_attempted=false
trap - EXIT INT TERM
