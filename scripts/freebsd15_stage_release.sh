#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${CANDIDATES_DIR:-} || -z ${SOURCE_COMMIT:-} ||
      -z ${RELEASE_SET:-} || -z ${RELEASE_TAG:-} || -z ${RELEASE_TITLE:-} ||
      -z ${STAGING_ROOT:-} || -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Required staging configuration is incomplete"
  exit 1
fi
if [[ -z ${AZURE_RESULTS_DIR:-} ]]; then
  echo "::error::$RELEASE_SET releases require AZURE_RESULTS_DIR"
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
for tool in sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required staging tool $tool is unavailable"
    exit 1
  }
done
release_tool=${MIZ_FREEBSD15_RELEASE_TOOL:-zig-out/bin/freebsd15_release}
[[ -x "$release_tool" ]] || {
  echo "::error::Required staging tool $release_tool is unavailable"
  exit 1
}
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]

release_description=$("$release_tool" describe \
  --release-set "$RELEASE_SET" \
  --release-date "$RELEASE_DATE")
expected_tag=${release_description#*release_tag=}
expected_tag=${expected_tag%%$'\n'*}
expected_title=${release_description#*release_title=}
expected_title=${expected_title%%$'\n'*}
expected_asset_count=${release_description#*asset_count=}
expected_asset_count=${expected_asset_count%%$'\n'*}
minimum_core_reduction=${release_description#*core_minimum_reduction_percent=}
minimum_core_reduction=${minimum_core_reduction%%$'\n'*}
[[ "$RELEASE_TAG" == "$expected_tag" ]]
[[ "$RELEASE_TITLE" == "$expected_title" ]]
[[ "$expected_asset_count" =~ ^[0-9]+$ ]]
[[ "$minimum_core_reduction" =~ ^[0-9]+$ ]]

rm -rf -- "$STAGING_ROOT"
mkdir -p "$STAGING_ROOT"
assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
comparison_file="$STAGING_ROOT/size-comparison.md"
evidence_dir="$STAGING_ROOT/evidence"

"$release_tool" stage \
  --release-set "$RELEASE_SET" \
  --candidates "$CANDIDATES_DIR" \
  --source-commit "$SOURCE_COMMIT" \
  --release-tag "$RELEASE_TAG" \
  --release-date "$RELEASE_DATE" \
  --azure-results "$AZURE_RESULTS_DIR" \
  --minimum-core-reduction-percent "$minimum_core_reduction" \
  --output "$assets_dir" \
  --notes "$notes_file"

"$release_tool" compare \
  --candidate "$assets_dir/publish-manifest.json" \
  --output "$comparison_file" >/dev/null

"$release_tool" stage-expected \
  --manifest "$assets_dir/publish-manifest.json" \
  --release-set "$RELEASE_SET" >"$expected_file"
test "$(wc -l <"$expected_file")" -eq "$expected_asset_count"

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
done <"$expected_file"

mkdir -p "$evidence_dir"
cp "$assets_dir/publish-manifest.json" "$evidence_dir/publish-manifest.json"
cp "$notes_file" "$evidence_dir/release-notes.md"
cp "$comparison_file" "$evidence_dir/size-comparison.md"

"$release_tool" stage-evidence \
  --release-set "$RELEASE_SET" \
  --manifest "$assets_dir/publish-manifest.json" \
  --azure-results "$AZURE_RESULTS_DIR" \
  --evidence "$evidence_dir"

{
  echo "### FreeBSD 15.1 release staged and verified"
  echo
  echo "- Release set: \`$RELEASE_SET\`"
  echo "- Proposed tag: \`$RELEASE_TAG\`"
  echo "- Source commit: \`$SOURCE_COMMIT\`"
  while IFS=$'\t' read -r asset_name expected_sha _; do
    echo "- \`$asset_name\`: \`$expected_sha\`"
  done <"$expected_file"
} >>"$GITHUB_STEP_SUMMARY"
