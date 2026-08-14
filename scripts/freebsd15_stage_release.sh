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
if [[ "$RELEASE_SET" == "ufs" ]]; then
  if [[ -z ${RELEASE_DATE:-} || ! "$RELEASE_DATE" =~ ^[0-9]{8}$ ]]; then
    echo "::error::UFS releases require an explicit reviewed RELEASE_DATE"
    exit 1
  fi
elif [[ -n ${RELEASE_DATE:-} ]]; then
  echo "::error::RELEASE_DATE is only applicable to UFS releases"
  exit 1
fi
for tool in python3 sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required staging tool $tool is unavailable"
    exit 1
  }
done
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]

describe_args=(--release-set "$RELEASE_SET")
stage_release_date_args=()
if [[ "$RELEASE_SET" == "ufs" ]]; then
  describe_args+=(--release-date "$RELEASE_DATE")
  stage_release_date_args=(--release-date "$RELEASE_DATE")
fi
release_description=$(python3 scripts/freebsd15_release.py describe \
  "${describe_args[@]}")
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

python3 scripts/freebsd15_release.py stage \
  --release-set "$RELEASE_SET" \
  --candidates "$CANDIDATES_DIR" \
  --source-commit "$SOURCE_COMMIT" \
  --release-tag "$RELEASE_TAG" \
  "${stage_release_date_args[@]}" \
  --azure-results "$AZURE_RESULTS_DIR" \
  --minimum-core-reduction-percent "$minimum_core_reduction" \
  --output "$assets_dir" \
  --notes "$notes_file"

if [[ "$RELEASE_SET" == "ufs" ]]; then
  python3 scripts/freebsd15_release.py compare \
    --candidate "$assets_dir/publish-manifest.json" \
    --output "$comparison_file" >/dev/null
fi

python3 - "$assets_dir/publish-manifest.json" >"$expected_file" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
for asset in document["assets"]:
    print(f"{asset['asset_name']}\t{asset['sha256']}\t{asset['bytes']}")
PY
test "$(wc -l <"$expected_file")" -eq "$expected_asset_count"

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
done <"$expected_file"

mkdir -p "$evidence_dir"
cp "$assets_dir/publish-manifest.json" "$evidence_dir/publish-manifest.json"
cp "$notes_file" "$evidence_dir/release-notes.md"
if [[ "$RELEASE_SET" == "ufs" ]]; then
  cp "$comparison_file" "$evidence_dir/size-comparison.md"
fi

python3 - \
  "$RELEASE_SET" \
  "$assets_dir/publish-manifest.json" \
  "${AZURE_RESULTS_DIR:-}" \
  "$evidence_dir" <<'PY'
import json
import shutil
import sys
from pathlib import Path

release_set, manifest_path, azure_root, evidence_root = sys.argv[1:]
manifest = json.loads(Path(manifest_path).read_text(encoding="utf-8"))
variants = {asset["variant"] for asset in manifest["assets"]}
evidence = Path(evidence_root)
expected = {"publish-manifest.json", "release-notes.md"}
if release_set == "ufs":
    expected.add("size-comparison.md")
source_documents = sorted(Path(azure_root).rglob("azure-result.json"))
copied = set()
for source in source_documents:
    document = json.loads(source.read_text(encoding="utf-8"))
    variant = document["variant"]
    if variant not in variants or variant in copied:
        raise SystemExit("unexpected or duplicate Azure evidence variant")
    relative = Path("azure-results") / variant / "azure-result.json"
    destination = evidence / relative
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(source, destination)
    copied.add(variant)
    expected.add(relative.as_posix())
if copied != variants:
    raise SystemExit("Azure evidence matrix is incomplete")

actual = {
    path.relative_to(evidence).as_posix()
    for path in evidence.rglob("*")
    if path.is_file()
}
if actual != expected:
    raise SystemExit(f"validation evidence allowlist mismatch: {actual!r}")
PY

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
