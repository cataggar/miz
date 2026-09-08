#!/usr/bin/env bash
set -Eeuo pipefail

if [[ -z ${CANDIDATE:-} || -z ${PROVENANCE:-} ||
      -z ${ACCEPTANCE_RESULT:-} || -z ${SOURCE_COMMIT:-} ||
      -z ${AZURE_LOCATION:-} || -z ${AZURE_VM_SIZE:-} ||
      -z ${RELEASE_TAG:-} || -z ${RELEASE_TITLE:-} ||
      -z ${REPOSITORY:-} || -z ${STAGING_ROOT:-} ||
      -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} ||
      -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Required Ubuntu 24.04 Confidential VM publication configuration is incomplete"
  exit 1
fi
for tool in gh sha256sum stat; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required publication tool $tool is unavailable"
    exit 1
  }
done
RELEASE_TOOL=${UBUNTU2404_CONFIDENTIAL_RELEASE_TOOL:-zig-out/bin/ubuntu2404_confidential_release}
[[ -x "$RELEASE_TOOL" ]] || {
  echo "::error::Ubuntu 24.04 Confidential VM release tool is unavailable: $RELEASE_TOOL"
  exit 1
}
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
[[ "$AZURE_LOCATION" == westeurope ]]
[[ "$AZURE_VM_SIZE" == Standard_DC2as_v5 ]]
[[ "$RELEASE_TAG" =~ ^Ubuntu-24\.04-confidential-[0-9]{8}$ ]]
[[ "$REPOSITORY" == cataggar/miz ]]

candidate_name=Ubuntu-24.04-x86_64.confidential.qcow2
provenance_name=$candidate_name.provenance.json
acceptance_name=Ubuntu-24.04-x86_64.confidential.azure-acceptance.json
[[ $(basename -- "$CANDIDATE") == "$candidate_name" ]]
[[ $(basename -- "$PROVENANCE") == "$provenance_name" ]]
[[ -f "$CANDIDATE" && -f "$PROVENANCE" && -f "$ACCEPTANCE_RESULT" ]]

readarray -t identity < <(
  "$RELEASE_TOOL" verify-acceptance \
    --result "$ACCEPTANCE_RESULT" \
    --provenance "$PROVENANCE" \
    --qcow "$CANDIDATE" \
    --source-commit "$SOURCE_COMMIT" \
    --location "$AZURE_LOCATION" \
    --vm-size "$AZURE_VM_SIZE" \
    --run-id "$GITHUB_RUN_ID" \
    --run-attempt "$GITHUB_RUN_ATTEMPT"
)
test "${#identity[@]}" -eq 3
qcow_sha256=${identity[0]}
qcow_size=${identity[1]}
virtual_size=${identity[2]}
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$qcow_size" =~ ^[1-9][0-9]*$ ]]
[[ "$virtual_size" =~ ^[1-9][0-9]*$ ]]

mkdir -p "$STAGING_ROOT"
assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
release_file="$STAGING_ROOT/release.json"
immutable_policy_file="$STAGING_ROOT/immutable-releases.json"
verify_dir="$STAGING_ROOT/remote"
rm -rf -- "$assets_dir" "$verify_dir"
mkdir "$assets_dir"
ln -- "$CANDIDATE" "$assets_dir/$candidate_name"
ln -- "$PROVENANCE" "$assets_dir/$provenance_name"
ln -- "$ACCEPTANCE_RESULT" "$assets_dir/$acceptance_name"

: >"$expected_file"
for asset_name in "$candidate_name" "$provenance_name" "$acceptance_name"; do
  asset="$assets_dir/$asset_name"
  digest=$(sha256sum "$asset" | awk '{print $1}')
  bytes=$(stat --format='%s' "$asset")
  [[ "$digest" =~ ^[0-9a-f]{64}$ ]]
  [[ "$bytes" =~ ^[1-9][0-9]*$ ]]
  printf '%s\t%s\t%s\n' "$asset_name" "$digest" "$bytes" >>"$expected_file"
done
test "$(wc -l <"$expected_file")" -eq 3
test "$(sha256sum "$assets_dir/$candidate_name" | awk '{print $1}')" = "$qcow_sha256"
test "$(stat --format='%s' "$assets_dir/$candidate_name")" = "$qcow_size"

cat >"$notes_file" <<EOF
Ubuntu 24.04 LTS x86_64 image accepted on Azure Confidential VM.

- Source commit: \`$SOURCE_COMMIT\`
- Candidate SHA-256: \`$qcow_sha256\`
- Virtual size: \`$virtual_size\` bytes
- Azure profile: \`$AZURE_LOCATION\` / \`$AZURE_VM_SIZE\`
- Security: AMD SEV-SNP, VMGuestStateOnly, Secure Boot, and vTPM
- Attestation: nonce-bound Microsoft Azure Attestation result verified against JWKS

The provenance and acceptance JSON assets bind the published QCOW2 to the
authenticated Canonical input, fixed-VHD conversion, gallery image version,
deployed VM identity, and attested guest security state.
EOF

direct_tag=$(git ls-remote origin "refs/tags/$RELEASE_TAG" | awk '{print $1}')
peeled_tag=$(git ls-remote origin "refs/tags/$RELEASE_TAG^{}" | awk '{print $1}')
tag_commit=${peeled_tag:-$direct_tag}
test "$tag_commit" = "$SOURCE_COMMIT"

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
  "$RELEASE_TOOL" check-release-metadata \
    --release "$release_file" \
    --notes "$notes_file" \
    --release-tag "$RELEASE_TAG" \
    --release-title "$RELEASE_TITLE" \
    --source-commit "$SOURCE_COMMIT"
fi

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
"$RELEASE_TOOL" check-release-metadata \
  --release "$release_file" \
  --notes "$notes_file" \
  --release-tag "$RELEASE_TAG" \
  --release-title "$RELEASE_TITLE" \
  --source-commit "$SOURCE_COMMIT"

check_release_assets() {
  local mode=$1
  local asset_name=${2:-}
  local -a args=(
    check-draft-assets
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
  check_release_assets repair >"$repair_file"
  asset_id=
  read -r asset_id <"$repair_file" || true
  [[ -n "$asset_id" ]] || break
  [[ "$asset_id" =~ ^[1-9][0-9]*$ ]]
  release_mutated=true
  gh api --method DELETE "repos/$REPOSITORY/releases/assets/$asset_id"
done
check_release_assets subset >/dev/null

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
  [[ "$asset_name" =~ ^[A-Za-z0-9._-]+$ ]]
  upload_status=$(check_release_assets asset "$asset_name")
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
  check_release_assets subset >/dev/null
done <"$expected_file"

check_release_assets exact >/dev/null
mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir"
while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$verify_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$verify_dir/$asset_name")" = "$expected_bytes"
done <"$expected_file"

check_release_assets exact >/dev/null
policy_token=${RELEASE_POLICY_GH_TOKEN:-}
unset RELEASE_POLICY_GH_TOKEN
if [[ -z "$policy_token" ]]; then
  echo "::error::Protected immutable-release policy token is missing"
  exit 1
fi
if ! GH_TOKEN="$policy_token" gh api --method GET \
    -H 'Accept: application/vnd.github+json' \
    -H 'X-GitHub-Api-Version: 2026-03-10' \
    "repos/$REPOSITORY/immutable-releases" >"$immutable_policy_file"; then
  unset policy_token
  echo "::error::Cannot read the protected immutable-release policy"
  exit 1
fi
unset policy_token
"$RELEASE_TOOL" check-immutable-releases \
  --response "$immutable_policy_file"
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
check_release_assets published >/dev/null

{
  echo "### Ubuntu 24.04 Confidential VM release published"
  echo
  echo "- Release: https://github.com/$REPOSITORY/releases/tag/$RELEASE_TAG"
  echo "- Source commit: \`$SOURCE_COMMIT\`"
  while IFS=$'\t' read -r asset_name expected_sha _; do
    echo "- \`$asset_name\`: \`$expected_sha\`"
  done <"$expected_file"
} >>"$GITHUB_STEP_SUMMARY"

release_mutated=false
publish_attempted=false
trap - EXIT INT TERM
