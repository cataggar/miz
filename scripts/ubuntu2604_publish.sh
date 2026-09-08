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
for tool in gh git sha256sum; do
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
test "$(wc -l <"$expected_file")" -eq 8

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

policy_token=${RELEASE_POLICY_GH_TOKEN:-}
unset RELEASE_POLICY_GH_TOKEN
if [[ -z "$policy_token" ]]; then
  echo "::error::Protected repository release policy token is missing"
  exit 1
fi
check_repository_release_policy() {
  local label=$1
  GH_TOKEN="$policy_token" \
    scripts/release/check_repository_release_policy.sh \
    "$STAGING_ROOT/release-policy-$label" "$RELEASE_TOOL" "$REPOSITORY"
}
verify_exact_remote_tag() {
  local tag=$1
  local expected=$2
  local -a direct=()
  local -a peeled=()
  mapfile -t direct < <(
    git ls-remote origin "refs/tags/$tag" | awk '{print $1}'
  )
  mapfile -t peeled < <(
    git ls-remote origin "refs/tags/$tag^{}" | awk '{print $1}'
  )
  if ((${#direct[@]} != 1 || ${#peeled[@]} > 1)); then
    echo "::error::Tag $tag did not resolve from one exact remote ref"
    return 1
  fi
  if [[ "${peeled[0]:-${direct[0]}}" != "$expected" ]]; then
    echo "::error::Tag $tag does not peel to accepted commit $expected"
    return 1
  fi
}

check_repository_release_policy before-mutation

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
  "$RELEASE_TOOL" github-release-metadata \
    --release "$release_file" \
    --notes "$notes_file" \
    --release-tag "$RELEASE_TAG" \
    --release-title "$RELEASE_TITLE" \
    --source-commit "$SOURCE_COMMIT"
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
verify_exact_remote_tag "$RELEASE_TAG" "$SOURCE_COMMIT"

if [[ "$release_exists" != true ]]; then
  release_mutated=true
  gh release create "$RELEASE_TAG" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --target "$SOURCE_COMMIT" \
    --draft \
    --latest=false \
    --title "$RELEASE_TITLE" \
    --notes-file "$notes_file" >/dev/null
fi
release_id=${existing_release_id:-$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json databaseId \
  --jq .databaseId)}
[[ "$release_id" =~ ^[0-9]+$ ]]
release_api="repos/$REPOSITORY/releases/$release_id"
gh api "$release_api" >"$release_file"
"$RELEASE_TOOL" github-release-metadata \
  --release "$release_file" \
  --notes "$notes_file" \
  --release-tag "$RELEASE_TAG" \
  --release-title "$RELEASE_TITLE" \
  --source-commit "$SOURCE_COMMIT"

check_draft_assets() {
  local mode=$1
  local asset_name=${2:-}
  local -a args=(
    github-draft-assets
    --release "$release_file"
    --notes "$notes_file"
    --expected "$expected_file"
    --release-id "$release_id"
    --release-tag "$RELEASE_TAG"
    --release-title "$RELEASE_TITLE"
    --source-commit "$SOURCE_COMMIT"
    --mode "$mode"
  )
  if [[ -n "$asset_name" ]]; then
    args+=(--asset-name "$asset_name")
  fi
  gh api "$release_api" >"$release_file"
  "$RELEASE_TOOL" "${args[@]}"
}

repair_file="$STAGING_ROOT/repair-asset-ids"
while true; do
  check_draft_assets repair >"$repair_file"
  asset_id=
  read -r asset_id <"$repair_file" || true
  [[ -n "$asset_id" ]] || break
  [[ "$asset_id" =~ ^[1-9][0-9]*$ ]]
  release_mutated=true
  gh api --method DELETE "repos/$REPOSITORY/releases/assets/$asset_id"
done
check_draft_assets subset >/dev/null

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
  [[ "$asset_name" =~ ^[A-Za-z0-9._-]+$ ]]
  upload_status=$(check_draft_assets asset "$asset_name")
  if [[ "$upload_status" == keep ]]; then
    continue
  fi
  [[ "$upload_status" == upload ]]
  release_mutated=true
  gh api --method POST \
    -H 'Content-Type: application/octet-stream' \
    --input "$assets_dir/$asset_name" \
    "https://uploads.github.com/repos/$REPOSITORY/releases/$release_id/assets?name=$asset_name" \
    >/dev/null
  check_draft_assets subset >/dev/null
done <"$expected_file"

check_draft_assets exact >/dev/null

mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir"
"$RELEASE_TOOL" github-release-downloaded \
  --dir "$verify_dir" \
  --expected "$expected_file"

check_draft_assets exact >/dev/null

verify_exact_remote_tag "$RELEASE_TAG" "$SOURCE_COMMIT"
check_repository_release_policy before-publish
publish_attempted=true
gh api --method PATCH "$release_api" \
  -f "tag_name=$RELEASE_TAG" \
  -f "target_commitish=$SOURCE_COMMIT" \
  -f "name=$RELEASE_TITLE" \
  -F "body=@$notes_file" \
  -F "draft=false" \
  -F "prerelease=false" \
  -f "make_latest=false" >/dev/null
release_published=true

verify_exact_remote_tag "$RELEASE_TAG" "$SOURCE_COMMIT"
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
publish_attempted=false
trap - EXIT INT TERM
