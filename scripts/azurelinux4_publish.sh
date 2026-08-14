#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${CANDIDATES_DIR:-} || -z ${AZURE_RESULTS_DIR:-} ||
      -z ${SOURCE_COMMIT:-} || -z ${RELEASE_TAG:-} ||
      -z ${RELEASE_TITLE:-} || -z ${REPOSITORY:-} ||
      -z ${STAGING_ROOT:-} || -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Required publication configuration is incomplete"
  exit 1
fi
for tool in gh python3 sha256sum; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required publication tool $tool is unavailable"
    exit 1
  }
done
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$RELEASE_TAG" == AzureLinux-4.0-20260814 ]]
[[ "$REPOSITORY" == cataggar/zvmi ]]

mkdir -p "$STAGING_ROOT"
assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
refs_file="$STAGING_ROOT/tag-refs.json"
release_file="$STAGING_ROOT/release.json"
verify_dir="$STAGING_ROOT/remote"
rm -rf -- "$assets_dir" "$verify_dir"

python3 scripts/azurelinux4_release.py stage \
  --candidates "$CANDIDATES_DIR" \
  --azure-results "$AZURE_RESULTS_DIR" \
  --source-commit "$SOURCE_COMMIT" \
  --release-tag "$RELEASE_TAG" \
  --output "$assets_dir" \
  --notes "$notes_file"

python3 - "$assets_dir/publish-manifest.json" >"$expected_file" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
for asset in document["assets"]:
    print(f"{asset['asset_name']}\t{asset['sha256']}\t{asset['bytes']}")
PY
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

gh api "repos/$REPOSITORY/git/matching-refs/tags/$RELEASE_TAG" --paginate >"$refs_file"
readarray -t tag_object < <(python3 - "$refs_file" "$RELEASE_TAG" <<'PY'
import json
import sys

expected = f"refs/tags/{sys.argv[2]}"
matches = [item for item in json.load(open(sys.argv[1], encoding="utf-8")) if item["ref"] == expected]
if len(matches) > 1:
    raise SystemExit("duplicate exact tag refs")
if matches:
    print(matches[0]["object"]["type"])
    print(matches[0]["object"]["sha"])
PY
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
    readarray -t tag_object < <(python3 - "$STAGING_ROOT/tag-object.json" <<'PY'
import json
import sys

obj = json.load(open(sys.argv[1], encoding="utf-8"))["object"]
print(obj["type"])
print(obj["sha"])
PY
)
    object_type=${tag_object[0]}
    object_sha=${tag_object[1]}
  done
  if [[ "$object_type" != commit || "$object_sha" != "$SOURCE_COMMIT" ]]; then
    echo "::error::Existing tag $RELEASE_TAG resolves to $object_type $object_sha, not accepted commit $SOURCE_COMMIT"
    exit 1
  fi
fi

if gh release view "$RELEASE_TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
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
python3 - "$release_file" "$expected_file" >"$STAGING_ROOT/stale-asset-ids" <<'PY'
import json
import sys

allowed = {line.split("\t", 1)[0] for line in open(sys.argv[2], encoding="utf-8")}
for asset in json.load(open(sys.argv[1], encoding="utf-8"))["assets"]:
    if asset["name"] not in allowed:
        print(asset["id"])
PY
while read -r asset_id; do
  [[ "$asset_id" =~ ^[0-9]+$ ]]
  gh api --method DELETE "repos/$REPOSITORY/releases/assets/$asset_id"
done <"$STAGING_ROOT/stale-asset-ids"

gh api "$release_api" >"$release_file"
python3 - "$release_file" "$expected_file" <<'PY'
import json
import sys

release = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {}
for line in open(sys.argv[2], encoding="utf-8"):
    name, digest, size = line.rstrip("\n").split("\t")
    expected[name] = (digest, int(size))
actual = {asset["name"]: asset["size"] for asset in release["assets"]}
if len(release["assets"]) != 4 or actual != {name: size for name, (_, size) in expected.items()}:
    raise SystemExit(f"remote release asset allowlist/size mismatch: {actual!r}")
if not release["draft"]:
    raise SystemExit("release stopped being a draft before verification")
PY

mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir" \
  --clobber
python3 - "$verify_dir" "$expected_file" <<'PY'
import hashlib
import sys
from pathlib import Path

root = Path(sys.argv[1])
expected = {}
for line in open(sys.argv[2], encoding="utf-8"):
    name, digest, size = line.rstrip("\n").split("\t")
    expected[name] = (digest, int(size))
actual = {path.name for path in root.iterdir() if path.is_file()}
if actual != set(expected):
    raise SystemExit(f"downloaded release allowlist mismatch: {actual!r}")
for name, (digest, size) in expected.items():
    path = root / name
    if path.stat().st_size != size:
        raise SystemExit(f"{name}: downloaded size mismatch")
    actual_digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            actual_digest.update(chunk)
    if actual_digest.hexdigest() != digest:
        raise SystemExit(f"{name}: downloaded digest mismatch")
PY

gh release edit "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --verify-tag \
  --draft=false \
  --latest=false \
  --title "$RELEASE_TITLE" \
  --notes-file "$notes_file" >/dev/null

gh api "$release_api" >"$release_file"
python3 - "$release_file" "$expected_file" <<'PY'
import json
import sys

release = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {line.split("\t", 1)[0] for line in open(sys.argv[2], encoding="utf-8")}
actual = {asset["name"] for asset in release["assets"]}
if release["draft"] or len(release["assets"]) != 4 or actual != expected:
    raise SystemExit("published release did not retain the exact final allowlist")
PY

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
trap - EXIT INT TERM
