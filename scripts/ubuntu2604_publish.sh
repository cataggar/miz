#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${CANDIDATES_DIR:-} || -z ${NATIVE_RESULTS_DIR:-} ||
      -z ${AZURE_RESULTS_DIR:-} ||
      -z ${SOURCE_COMMIT:-} || -z ${RELEASE_TAG:-} ||
      -z ${RELEASE_TITLE:-} || -z ${REPOSITORY:-} ||
      -z ${STAGING_ROOT:-} || -z ${GITHUB_STEP_SUMMARY:-} ||
      -z ${CANDIDATE_RUN_ID:-} ||
      -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} ]]; then
  echo "::error::Required publication configuration is incomplete"
  exit 1
fi
for tool in date gh sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required publication tool $tool is unavailable"
    exit 1
  }
done
# The release schema, the publication allowlist, and every remote-state check
# below live in one native tool, so publication never depends on an interpreter
# being present on the runner.
RELEASE_TOOL=${UBUNTU2604_RELEASE_TOOL:-zig-out/bin/ubuntu2604_release}
[[ -x "$RELEASE_TOOL" ]] || {
  echo "::error::Ubuntu release tooling is unavailable at $RELEASE_TOOL"
  exit 1
}
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$RELEASE_TAG" =~ ^Ubuntu-26\.04-[0-9]{8}$ ]]
[[ "$REPOSITORY" == cataggar/miz ]]

mkdir -p "$STAGING_ROOT"
assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
refs_file="$STAGING_ROOT/tag-refs.json"
release_file="$STAGING_ROOT/release.json"
verify_dir="$STAGING_ROOT/remote"
rm -rf -- "$assets_dir" "$verify_dir"

"$RELEASE_TOOL" stage \
  --candidates "$CANDIDATES_DIR" \
  --native-results "$NATIVE_RESULTS_DIR" \
  --azure-results "$AZURE_RESULTS_DIR" \
  --source-commit "$SOURCE_COMMIT" \
  --release-tag "$RELEASE_TAG" \
  --candidate-run-id "$CANDIDATE_RUN_ID" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output "$assets_dir" \
  --notes "$notes_file"

"$RELEASE_TOOL" publish-expected \
  --manifest "$assets_dir/publish-manifest.json" \
  --assets-dir "$assets_dir" \
  --release-tag "$RELEASE_TAG" \
  --source-commit "$SOURCE_COMMIT" >"$expected_file"
test "$(wc -l <"$expected_file")" -eq 4

release_mutated=false
keep_draft_on_failure() {
  status=$?
  trap - EXIT INT TERM
  if [[ $status -ne 0 && "$release_mutated" == true ]]; then
    echo "::warning::Publication failed; retaining $RELEASE_TAG as a draft"
    gh release edit "$RELEASE_TAG" --repo "$REPOSITORY" --draft >/dev/null 2>&1 || true
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
  if [[ "$release_is_draft" != true &&
        "$(date -u +%Y%m%d)" != "${RELEASE_TAG##*-}" ]]; then
    echo "::error::Final release $RELEASE_TAG is immutable after its tag date"
    exit 1
  fi
fi

gh api "repos/$REPOSITORY/git/matching-refs/tags/$RELEASE_TAG" --paginate >"$refs_file"
readarray -t tag_object < <(
  "$RELEASE_TOOL" github-tag-object --refs "$refs_file" --tag "$RELEASE_TAG"
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
      "$RELEASE_TOOL" github-tag-target --object "$STAGING_ROOT/tag-object.json"
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
    --draft \
    --latest=false \
    --title "$RELEASE_TITLE" \
    --notes-file "$notes_file" >/dev/null
fi
release_mutated=true
release_id=$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json databaseId \
  --jq .databaseId)
[[ "$release_id" =~ ^[0-9]+$ ]]
release_api="repos/$REPOSITORY/releases/$release_id"

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
  gh release upload "$RELEASE_TAG" "$assets_dir/$asset_name" \
    --clobber \
    --repo "$REPOSITORY"
done <"$expected_file"

gh api "$release_api" >"$release_file"
"$RELEASE_TOOL" github-stale-assets \
  --release "$release_file" \
  --expected "$expected_file" >"$STAGING_ROOT/stale-asset-ids"
while read -r asset_id; do
  [[ "$asset_id" =~ ^[0-9]+$ ]]
  gh api --method DELETE "repos/$REPOSITORY/releases/assets/$asset_id"
done <"$STAGING_ROOT/stale-asset-ids"

gh api "$release_api" >"$release_file"
"$RELEASE_TOOL" github-release-assets \
  --release "$release_file" \
  --expected "$expected_file" \
  --stage draft

mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir" \
  --clobber
"$RELEASE_TOOL" github-release-downloaded \
  --dir "$verify_dir" \
  --expected "$expected_file"

gh release edit "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --verify-tag \
  --draft=false \
  --latest=false \
  --title "$RELEASE_TITLE" \
  --notes-file "$notes_file" >/dev/null

gh api "$release_api" >"$release_file"
"$RELEASE_TOOL" github-release-assets \
  --release "$release_file" \
  --expected "$expected_file" \
  --stage final

{
  echo "### Ubuntu 26.04 release published"
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
trap - EXIT INT TERM
