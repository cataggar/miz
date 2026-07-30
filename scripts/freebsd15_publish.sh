#!/usr/bin/env bash
set -euo pipefail

if [[ -z ${CANDIDATES_DIR:-} || -z ${SOURCE_COMMIT:-} ||
      -z ${RELEASE_SET:-} || -z ${RELEASE_TAG:-} || -z ${RELEASE_TITLE:-} ||
      -z ${REPOSITORY:-} || -z ${STAGING_ROOT:-} ||
      -z ${GITHUB_STEP_SUMMARY:-} ]]; then
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
[[ "$REPOSITORY" == cataggar/zvmi ]]

# The release set is the single source of truth for the tag, the title, and
# how many assets may be published. Deriving all three from it keeps a
# dispatch that names the wrong tag from silently publishing the wrong images.
release_description=$(python3 scripts/freebsd15_release.py describe \
  --release-set "$RELEASE_SET")
expected_tag=${release_description#*release_tag=}
expected_tag=${expected_tag%%$'\n'*}
expected_title=${release_description#*release_title=}
expected_title=${expected_title%%$'\n'*}
expected_asset_count=${release_description#*asset_count=}
expected_asset_count=${expected_asset_count%%$'\n'*}
[[ "$RELEASE_TAG" == "$expected_tag" ]]
[[ "$RELEASE_TITLE" == "$expected_title" ]]
[[ "$expected_asset_count" =~ ^[0-9]+$ ]]

mkdir -p "$STAGING_ROOT"
assets_dir="$STAGING_ROOT/assets"
notes_file="$STAGING_ROOT/release-notes.md"
expected_file="$STAGING_ROOT/expected.tsv"
release_file="$STAGING_ROOT/release.json"
verify_dir="$STAGING_ROOT/remote"
rm -rf -- "$assets_dir" "$verify_dir"

python3 scripts/freebsd15_release.py stage \
  --release-set "$RELEASE_SET" \
  --candidates "$CANDIDATES_DIR" \
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
test "$(wc -l <"$expected_file")" -eq "$expected_asset_count"

tag_created=false
release_created=false
preserve_draft_on_failure() {
  status=$?
  trap - EXIT INT TERM
  if [[ $status -ne 0 ]]; then
    if $release_created; then
      echo "::warning::Publication failed; retaining $RELEASE_TAG as a draft"
      gh release edit "$RELEASE_TAG" --repo "$REPOSITORY" --draft >/dev/null 2>&1 || true
    elif $tag_created; then
      gh api --method DELETE "repos/$REPOSITORY/git/refs/tags/$RELEASE_TAG" \
        >/dev/null 2>&1 || true
    fi
  fi
  exit "$status"
}
trap preserve_draft_on_failure EXIT
trap 'exit 130' INT TERM

if gh release view "$RELEASE_TAG" --repo "$REPOSITORY" >/dev/null 2>&1; then
  echo "::error::Release $RELEASE_TAG already exists; refusing to replace it"
  exit 1
fi
tag_ref_file="$STAGING_ROOT/tag-ref.json"
tag_error_file="$STAGING_ROOT/tag-ref.error"
if gh api "repos/$REPOSITORY/git/ref/tags/$RELEASE_TAG" \
  >"$tag_ref_file" 2>"$tag_error_file"; then
  tag_sha=$(python3 - "$tag_ref_file" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
print(document["object"]["sha"])
PY
)
  if [[ "$tag_sha" != "$SOURCE_COMMIT" ]]; then
    echo "::error::Existing tag $RELEASE_TAG does not target $SOURCE_COMMIT"
    exit 1
  fi
elif python3 - "$tag_ref_file" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
raise SystemExit(document.get("status") != "404")
PY
then
  gh api --method POST "repos/$REPOSITORY/git/refs" \
    -f "ref=refs/tags/$RELEASE_TAG" \
    -f "sha=$SOURCE_COMMIT" >/dev/null
  tag_created=true
else
  cat "$tag_error_file" >&2
  echo "::error::Unable to inspect existing tag $RELEASE_TAG"
  exit 1
fi

gh release create "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --verify-tag \
  --draft \
  --latest=false \
  --title "$RELEASE_TITLE" \
  --notes-file "$notes_file" >/dev/null
release_created=true

while IFS=$'\t' read -r asset_name expected_sha expected_bytes; do
  test "$(sha256sum "$assets_dir/$asset_name" | awk '{print $1}')" = "$expected_sha"
  test "$(stat --format='%s' "$assets_dir/$asset_name")" = "$expected_bytes"
  gh release upload "$RELEASE_TAG" "$assets_dir/$asset_name" \
    --repo "$REPOSITORY"
done <"$expected_file"

release_id=$(gh release view "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --json databaseId \
  --jq .databaseId)
[[ "$release_id" =~ ^[0-9]+$ ]]
release_api="repos/$REPOSITORY/releases/$release_id"
gh api "$release_api" >"$release_file"
python3 - "$release_file" "$expected_file" <<'PY'
import json
import sys

release = json.load(open(sys.argv[1], encoding="utf-8"))
expected = {}
for line in open(sys.argv[2], encoding="utf-8"):
    name, digest, size = line.rstrip("\n").split("\t")
    expected[name] = (digest, int(size))
actual = {
    asset["name"]: (
        (asset.get("digest") or "").removeprefix("sha256:"),
        asset["size"],
    )
    for asset in release["assets"]
}
if actual != expected:
    raise SystemExit(f"remote release asset mismatch: {actual!r}")
if not release["draft"]:
    raise SystemExit("release stopped being a draft before verification")
PY

mkdir "$verify_dir"
gh release download "$RELEASE_TAG" \
  --repo "$REPOSITORY" \
  --dir "$verify_dir"
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
if release["draft"] or actual != expected:
    raise SystemExit("published release did not retain the exact final allowlist")
PY

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
  echo "No checksum sidecar assets were published."
} >>"$GITHUB_STEP_SUMMARY"

release_created=false
tag_created=false
trap - EXIT INT TERM
