#!/usr/bin/env bash
set -euo pipefail

required=(
  ASSETS_DIR ASSET_NAME CANDIDATE_DIR CANDIDATE_KEY CANDIDATE_RUN_ATTEMPT
  CANDIDATE_RUN_ID GH_TOKEN GITHUB_STEP_SUMMARY METADATA_NAME RELEASE_TITLE
  REISSUE_TAG REPOSITORY SOURCE_COMMIT SOURCE_RELEASE_TAG STAGING_ROOT
  TOOLING_COMMIT
)
for name in "${required[@]}"; do
  if [[ -z ${!name:-} ]]; then
    echo "::error::Required reissue configuration $name is absent"
    exit 1
  fi
done
for tool in awk gh jq sha256sum stat wc; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required reissue tool $tool is unavailable"
    exit 1
  }
done

RELEASE_TOOL=${UBUNTU2604_RELEASE_TOOL:-zig-out/bin/ubuntu2604_release}
[[ -x "$RELEASE_TOOL" ]] || {
  echo "::error::Ubuntu release tooling is unavailable at $RELEASE_TOOL"
  exit 1
}

asset_name=Ubuntu-26.04-aarch64.core.qcow2
expected_metadata_name=Ubuntu-26.04-aarch64.core.gallery.json
[[ "$REPOSITORY" == cataggar/miz ]]
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$TOOLING_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$SOURCE_RELEASE_TAG" =~ ^Ubuntu-26\.04-[0-9]{8}-armhost$ ]]
[[ "$REISSUE_TAG" == "$SOURCE_RELEASE_TAG-gallery" ]]
[[ "$REISSUE_TAG" != "$SOURCE_RELEASE_TAG" ]]
[[ "$CANDIDATE_KEY" == aarch64-core ]]
[[ "$CANDIDATE_RUN_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$CANDIDATE_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
[[ "$ASSET_NAME" == "$asset_name" ]]
[[ "$METADATA_NAME" == "$expected_metadata_name" ]]

manifest="$CANDIDATE_DIR/candidate.json"
asset="$ASSETS_DIR/$asset_name"
metadata="$ASSETS_DIR/$METADATA_NAME"
expected_file="$STAGING_ROOT/expected.tsv"
notes_file="$STAGING_ROOT/release-notes.md"
release_file="$STAGING_ROOT/release.json"
source_release_file="$STAGING_ROOT/source-release.json"
verify_dir="$STAGING_ROOT/remote"
mkdir -p -- "$STAGING_ROOT"
rm -rf -- "$verify_dir"

"$RELEASE_TOOL" verify-candidate \
  --manifest "$manifest" \
  --asset "$asset" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" \
  --run-id "$CANDIDATE_RUN_ID" \
  --run-attempt "$CANDIDATE_RUN_ATTEMPT" >/dev/null
"$RELEASE_TOOL" verify-gallery-metadata \
  --metadata "$metadata" \
  --manifest "$manifest" \
  --asset "$asset" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" >/dev/null

shopt -s nullglob dotglob
asset_entries=("$ASSETS_DIR"/*)
shopt -u nullglob dotglob
if ((${#asset_entries[@]} != 2)); then
  echo "::error::Reissue staging must contain exactly one image/metadata pair"
  exit 1
fi
for entry in "${asset_entries[@]}"; do
  [[ -f "$entry" ]]
  name=${entry##*/}
  [[ "$name" == "$asset_name" || "$name" == "$METADATA_NAME" ]]
done

asset_sha=$(sha256sum "$asset" | awk '{print $1}')
asset_bytes=$(stat --format='%s' "$asset")
metadata_sha=$(sha256sum "$metadata" | awk '{print $1}')
metadata_bytes=$(stat --format='%s' "$metadata")
printf '%s\t%s\t%s\n%s\t%s\t%s\n' \
  "$asset_name" "$asset_sha" "$asset_bytes" \
  "$METADATA_NAME" "$metadata_sha" "$metadata_bytes" >"$expected_file"
test "$(wc -l <"$expected_file")" -eq 2

gh release view "$SOURCE_RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json tagName,isDraft,isPrerelease,assets >"$source_release_file"
jq -e \
  --arg tag "$SOURCE_RELEASE_TAG" \
  --arg asset "$asset_name" \
  --arg digest "sha256:$asset_sha" \
  --argjson bytes "$asset_bytes" \
  '(.tagName == $tag) and
   (.isDraft == false) and
   (.isPrerelease == false) and
   (.assets | length == 1) and
   (.assets[0].name == $asset) and
   (.assets[0].state == "uploaded") and
   (.assets[0].size == $bytes) and
   (.assets[0].digest == $digest)' "$source_release_file" >/dev/null

certificate_sha=$(jq -er '.signing.uefi_db.certificate_sha256' "$metadata")
provenance_sha=$(jq -er '.provenance.digest' "$metadata")
cat >"$notes_file" <<EOF
## Highlights

- Explicit metadata-capable reissue of [$SOURCE_RELEASE_TAG](https://github.com/$REPOSITORY/releases/tag/$SOURCE_RELEASE_TAG); the source release remains unchanged.
- The QCOW2 is byte-for-byte identical to the source asset: \`$asset_sha\` ($asset_bytes bytes).
- \`$METADATA_NAME\` binds the image, source commit, candidate provenance, signed UKI, public UEFI \`db\` certificate, and \`TrustedLaunchSupported\` image-definition contract.

## Verification

- Source commit: \`$SOURCE_COMMIT\`
- Reissue tooling commit: \`$TOOLING_COMMIT\`
- Candidate workflow: run \`$CANDIDATE_RUN_ID\`, attempt \`$CANDIDATE_RUN_ATTEMPT\`
- Candidate provenance: \`$provenance_sha\`
- UEFI \`db\` certificate: \`$certificate_sha\`
- Gallery metadata: \`$metadata_sha\` ($metadata_bytes bytes)

The metadata does not include deployment-specific Azure resource IDs and does not claim Confidential VM support. Live Secure Boot and vTPM acceptance remains a separate requirement.

No checksum sidecar assets are published.
EOF

tag_present=false
tag_type=
tag_sha=
resolve_tag() {
  local tag=$1
  local label=$2
  local refs_file="$STAGING_ROOT/$label-tag-refs.json"
  local object_file="$STAGING_ROOT/$label-tag-object.json"
  local target_file="$STAGING_ROOT/$label-tag-target"
  local -a object=()

  tag_present=false
  tag_type=
  tag_sha=
  gh api "repos/$REPOSITORY/git/matching-refs/tags/$tag" \
    --paginate >"$refs_file"
  "$RELEASE_TOOL" github-tag-object \
    --refs "$refs_file" --tag "$tag" >"$target_file"
  readarray -t object <"$target_file"
  if ((${#object[@]} == 0)); then
    return
  fi
  if ((${#object[@]} != 2)); then
    echo "::error::Tag $tag did not resolve to one exact object"
    return 1
  fi
  tag_present=true
  tag_type=${object[0]}
  tag_sha=${object[1]}
  for _ in {1..8}; do
    [[ "$tag_type" == tag ]] || break
    gh api "repos/$REPOSITORY/git/tags/$tag_sha" >"$object_file"
    "$RELEASE_TOOL" github-tag-target \
      --object "$object_file" >"$target_file"
    readarray -t object <"$target_file"
    if ((${#object[@]} != 2)); then
      echo "::error::Annotated tag $tag did not resolve to one exact object"
      return 1
    fi
    tag_type=${object[0]}
    tag_sha=${object[1]}
  done
  [[ "$tag_type" == commit ]]
}

resolve_tag "$SOURCE_RELEASE_TAG" source
if [[ "$tag_present" != true || "$tag_sha" != "$SOURCE_COMMIT" ]]; then
  echo "::error::Source release tag does not resolve to the candidate source commit"
  exit 1
fi

release_exists=false
if release_is_draft=$(
  gh release view "$REISSUE_TAG" \
    --repo "$REPOSITORY" \
    --json isDraft \
    --jq .isDraft 2>/dev/null
); then
  release_exists=true
  if [[ "$release_is_draft" != true ]]; then
    echo "::error::Final reissue $REISSUE_TAG is immutable"
    exit 1
  fi
  existing_release_id=$(gh release view "$REISSUE_TAG" \
    --repo "$REPOSITORY" \
    --json databaseId \
    --jq .databaseId)
  [[ "$existing_release_id" =~ ^[1-9][0-9]*$ ]]
  gh api "repos/$REPOSITORY/releases/$existing_release_id" >"$release_file"
  "$RELEASE_TOOL" github-release-metadata \
    --release "$release_file" \
    --notes "$notes_file" \
    --release-tag "$REISSUE_TAG" \
    --release-title "$RELEASE_TITLE" \
    --source-commit "$TOOLING_COMMIT"
fi

tag_created=false
release_mutated=false
publish_attempted=false
release_published=false
preserve_draft_on_failure() {
  status=$?
  trap - EXIT INT TERM
  if [[ $status -ne 0 ]]; then
    if [[ "$release_published" == true ]]; then
      echo "::error::Post-publication verification failed; quarantine and inspect immutable reissue $REISSUE_TAG without mutating it"
    elif [[ "$publish_attempted" == true ]]; then
      echo "::error::Publication outcome is unconfirmed; inspect $REISSUE_TAG without attempting release mutation"
    elif [[ "$release_mutated" == true ]]; then
      echo "::warning::Reissue failed; retaining resumable draft $REISSUE_TAG"
    elif [[ "$tag_created" == true ]]; then
      gh api --method DELETE \
        "repos/$REPOSITORY/git/refs/tags/$REISSUE_TAG" >/dev/null 2>&1 || true
    fi
  fi
  exit "$status"
}
trap preserve_draft_on_failure EXIT
trap 'exit 130' INT TERM

resolve_tag "$REISSUE_TAG" reissue
if [[ "$tag_present" == true ]]; then
  if [[ "$tag_sha" != "$TOOLING_COMMIT" ]]; then
    echo "::error::Existing reissue tag does not resolve to the tooling commit"
    exit 1
  fi
else
  gh api --method POST "repos/$REPOSITORY/git/refs" \
    -f "ref=refs/tags/$REISSUE_TAG" \
    -f "sha=$TOOLING_COMMIT" >/dev/null
  tag_created=true
fi

if [[ "$release_exists" != true ]]; then
  release_mutated=true
  gh release create "$REISSUE_TAG" \
    --repo "$REPOSITORY" \
    --verify-tag \
    --target "$TOOLING_COMMIT" \
    --draft \
    --latest=false \
    --title "$RELEASE_TITLE" \
    --notes-file "$notes_file" >/dev/null
fi

release_id=${existing_release_id:-$(gh release view "$REISSUE_TAG" \
  --repo "$REPOSITORY" \
  --json databaseId \
  --jq .databaseId)}
[[ "$release_id" =~ ^[1-9][0-9]*$ ]]
release_api="repos/$REPOSITORY/releases/$release_id"
gh api "$release_api" >"$release_file"
"$RELEASE_TOOL" github-release-metadata \
  --release "$release_file" \
  --notes "$notes_file" \
  --release-tag "$REISSUE_TAG" \
  --release-title "$RELEASE_TITLE" \
  --source-commit "$TOOLING_COMMIT"

check_draft_assets() {
  local mode=$1
  local asset_name=${2:-}
  local -a args=(
    github-draft-assets
    --release "$release_file"
    --notes "$notes_file"
    --expected "$expected_file"
    --release-id "$release_id"
    --release-tag "$REISSUE_TAG"
    --release-title "$RELEASE_TITLE"
    --source-commit "$TOOLING_COMMIT"
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

while IFS=$'\t' read -r name expected_sha expected_bytes; do
  test "$(sha256sum "$ASSETS_DIR/$name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$ASSETS_DIR/$name")" = "$expected_bytes"
  [[ "$name" =~ ^[A-Za-z0-9._-]+$ ]]
  upload_status=$(check_draft_assets asset "$name")
  if [[ "$upload_status" == keep ]]; then
    continue
  fi
  [[ "$upload_status" == upload ]]
  release_mutated=true
  gh api --method POST \
    -H 'Content-Type: application/octet-stream' \
    --input "$ASSETS_DIR/$name" \
    "https://uploads.github.com/repos/$REPOSITORY/releases/$release_id/assets?name=$name" \
    >/dev/null
  check_draft_assets subset >/dev/null
done <"$expected_file"

check_draft_assets exact >/dev/null

mkdir "$verify_dir"
gh release download "$REISSUE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir"
"$RELEASE_TOOL" github-release-downloaded \
  --dir "$verify_dir" \
  --expected "$expected_file" \
  --key "$CANDIDATE_KEY"
"$RELEASE_TOOL" verify-candidate \
  --manifest "$manifest" \
  --asset "$verify_dir/$asset_name" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" \
  --run-id "$CANDIDATE_RUN_ID" \
  --run-attempt "$CANDIDATE_RUN_ATTEMPT" >/dev/null
"$RELEASE_TOOL" verify-gallery-metadata \
  --metadata "$verify_dir/$METADATA_NAME" \
  --manifest "$manifest" \
  --asset "$verify_dir/$asset_name" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" >/dev/null

check_draft_assets exact >/dev/null

gh release view "$SOURCE_RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json tagName,isDraft,isPrerelease,assets >"$source_release_file"
jq -e \
  --arg tag "$SOURCE_RELEASE_TAG" \
  --arg asset "$asset_name" \
  --arg digest "sha256:$asset_sha" \
  --argjson bytes "$asset_bytes" \
  '(.tagName == $tag) and
   (.isDraft == false) and
   (.isPrerelease == false) and
   (.assets | length == 1) and
   (.assets[0].name == $asset) and
   (.assets[0].state == "uploaded") and
   (.assets[0].size == $bytes) and
   (.assets[0].digest == $digest)' "$source_release_file" >/dev/null

check_draft_assets exact >/dev/null
publish_attempted=true
gh api --method PATCH "$release_api" \
  -f "tag_name=$REISSUE_TAG" \
  -f "target_commitish=$TOOLING_COMMIT" \
  -f "name=$RELEASE_TITLE" \
  -F "body=@$notes_file" \
  -F "draft=false" \
  -F "prerelease=false" \
  -f "make_latest=false" >/dev/null
release_published=true

gh api "$release_api" >"$release_file"
"$RELEASE_TOOL" github-release-assets \
  --release "$release_file" \
  --expected "$expected_file" \
  --stage final

{
  echo "### Ubuntu 26.04 gallery metadata reissue published"
  echo
  echo "- Source release: https://github.com/$REPOSITORY/releases/tag/$SOURCE_RELEASE_TAG"
  echo "- Reissue: https://github.com/$REPOSITORY/releases/tag/$REISSUE_TAG"
  echo "- Source commit: \`$SOURCE_COMMIT\`"
  echo "- Reissue tooling commit: \`$TOOLING_COMMIT\`"
  echo "- Image SHA-256: \`$asset_sha\`"
  echo "- Metadata SHA-256: \`$metadata_sha\`"
} >>"$GITHUB_STEP_SUMMARY"

release_mutated=false
publish_attempted=false
trap - EXIT INT TERM
