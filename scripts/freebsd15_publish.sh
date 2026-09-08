#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${SOURCE_COMMIT:-} || -z ${RELEASE_SET:-} ||
      -z ${RELEASE_TAG:-} || -z ${RELEASE_TITLE:-} ||
      -z ${REPOSITORY:-} || -z ${STAGING_ROOT:-} ||
      -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Required publication configuration is incomplete"
  exit 1
fi
if [[ "$RELEASE_SET" != "zfs" ]]; then
  echo "::error::Only the combined ZFS release set is publishable"
  exit 1
fi
if [[ -z ${RELEASE_DATE:-} || ! "$RELEASE_DATE" =~ ^[0-9]{8}$ ]]; then
  echo "::error::ZFS releases require an explicit reviewed RELEASE_DATE"
  exit 1
fi
for tool in gh sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required publication tool $tool is unavailable"
    exit 1
  }
done
release_tool=${MIZ_FREEBSD15_RELEASE_TOOL:-zig-out/bin/freebsd15_release}
[[ -x "$release_tool" ]] || {
  echo "::error::Required publication tool $release_tool is unavailable"
  exit 1
}
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$REPOSITORY" == cataggar/miz ]]

release_description=$("$release_tool" describe \
  --release-set "$RELEASE_SET" \
  --release-date "$RELEASE_DATE")
expected_tag=${release_description#*release_tag=}
expected_tag=${expected_tag%%$'\n'*}
expected_title=${release_description#*release_title=}
expected_title=${expected_title%%$'\n'*}
expected_asset_count=${release_description#*asset_count=}
expected_asset_count=${expected_asset_count%%$'\n'*}
[[ "$RELEASE_TAG" == "$expected_tag" ]]
[[ "$RELEASE_TITLE" == "$expected_title" ]]
[[ "$expected_asset_count" =~ ^[0-9]+$ ]]

assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
release_file="$STAGING_ROOT/release.json"
verify_dir="$STAGING_ROOT/remote"
manifest_file="$assets_dir/publish-manifest.json"
test -d "$assets_dir"
test -s "$notes_file"
test -s "$manifest_file"
rm -rf -- "$verify_dir"

"$release_tool" publish-expected \
  --manifest "$manifest_file" \
  --assets "$assets_dir" \
  --release-set "$RELEASE_SET" \
  --release-tag "$RELEASE_TAG" \
  --source-commit "$SOURCE_COMMIT" \
  --asset-count "$expected_asset_count" >"$expected_file"
test "$(wc -l <"$expected_file")" -eq "$expected_asset_count"

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
done <"$expected_file"

tag_created=false
release_created=false
publish_attempted=false
release_published=false
preserve_draft_on_failure() {
  status=$?
  trap - EXIT INT TERM
  if [[ $status -ne 0 ]]; then
    if $release_created; then
      if $release_published; then
        echo "::error::Post-publication verification failed; quarantine and inspect immutable release $RELEASE_TAG without mutating it"
      elif $publish_attempted; then
        echo "::error::Publication outcome is unconfirmed; inspect $RELEASE_TAG without attempting release mutation"
      else
        echo "::warning::Publication failed; retaining resumable draft $RELEASE_TAG"
      fi
    elif $tag_created; then
      gh api --method DELETE "repos/$REPOSITORY/git/refs/tags/$RELEASE_TAG" \
        >/dev/null 2>&1 || true
    fi
  fi
  exit "$status"
}
trap preserve_draft_on_failure EXIT
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
  release_id=$(gh release view "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --json databaseId \
    --jq .databaseId)
  [[ "$release_id" =~ ^[0-9]+$ ]]
  release_api="repos/$REPOSITORY/releases/$release_id"
  gh api "$release_api" >"$release_file"
  "$release_tool" verify-release-metadata \
    --release "$release_file" \
    --notes "$notes_file" \
    --release-tag "$RELEASE_TAG" \
    --release-title "$RELEASE_TITLE" \
    --source-commit "$SOURCE_COMMIT"
fi
tag_refs_file="$STAGING_ROOT/tag-refs.json"
gh api "repos/$REPOSITORY/git/matching-refs/tags/$RELEASE_TAG" \
  --paginate >"$tag_refs_file"
readarray -t tag_object < <(
  "$release_tool" tag-object --refs "$tag_refs_file" --tag "$RELEASE_TAG"
)

if ((${#tag_object[@]} != 0)); then
  tag_type=${tag_object[0]}
  tag_sha=${tag_object[1]}
  if [[ "$tag_type" != commit || "$tag_sha" != "$SOURCE_COMMIT" ]]; then
    echo "::error::Existing tag $RELEASE_TAG does not target $SOURCE_COMMIT"
    exit 1
  fi
else
  gh api --method POST "repos/$REPOSITORY/git/refs" \
    -f "ref=refs/tags/$RELEASE_TAG" \
    -f "sha=$SOURCE_COMMIT" >/dev/null
  tag_created=true
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
release_created=true

release_id=${release_id:-$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json databaseId \
  --jq .databaseId)}
[[ "$release_id" =~ ^[0-9]+$ ]]
release_api="repos/$REPOSITORY/releases/$release_id"
gh api "$release_api" >"$release_file"
"$release_tool" verify-release-metadata \
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
"$release_tool" verify-remote-release \
  --release "$release_file" \
  --expected "$expected_file"

mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir"
"$release_tool" verify-downloaded-release \
  --directory "$verify_dir" \
  --expected "$expected_file"

gh api "$release_api" >"$release_file"
"$release_tool" verify-remote-release \
  --release "$release_file" \
  --expected "$expected_file"

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
"$release_tool" verify-published-release \
  --release "$release_file" \
  --expected "$expected_file"

{
  echo "### FreeBSD 15.1 release published"
  echo
  echo "- Release: https://github.com/$REPOSITORY/releases/tag/$RELEASE_TAG"
  echo "- Release set: \`$RELEASE_SET\`"
  echo "- Source commit: \`$SOURCE_COMMIT\`"
  while IFS=$'\t' read -r asset_name expected_sha _; do
    echo "- \`$asset_name\`: \`$expected_sha\`"
  done <"$expected_file"
  echo
  echo "No checksum or package-manifest sidecar assets were published."
} >>"$GITHUB_STEP_SUMMARY"

release_created=false
tag_created=false
publish_attempted=false
trap - EXIT INT TERM
