#!/usr/bin/env bash
set -euo pipefail

# Fetch bounded workflow metadata only; the Zig resolver validates and selects
# the exact artifact IDs without downloading the candidate payloads.
if (( $# != 4 )); then
  echo "usage: ubuntu2604_resolve_artifacts.sh KIND RUN_ID SOURCE_COMMIT OUTPUT" >&2
  exit 2
fi

kind=$1
run_id=$2
source_commit=$3
output=$4

case "$kind" in
  candidate|native|azure) ;;
  *)
    echo "unsupported Ubuntu artifact kind: $kind" >&2
    exit 2
    ;;
esac
[[ "$run_id" =~ ^[1-9][0-9]*$ ]]
[[ "$source_commit" =~ ^[0-9a-f]{40}$ ]]
test -n "$output"
test -n "${GITHUB_REPOSITORY:-}"
test -n "${GH_TOKEN:-}"
test -x "${RELEASE_TOOL:-}"

temporary_directory="${output}.inputs"
rm -rf -- "$temporary_directory"
mkdir -p -- "$(dirname -- "$output")"
mkdir -p -- "$temporary_directory"
trap 'rm -rf -- "$temporary_directory"' EXIT

run=$(gh api "repos/$GITHUB_REPOSITORY/actions/runs/$run_id")
test "$(jq -r .repository.full_name <<<"$run")" = "$GITHUB_REPOSITORY"
test "$(jq -r .path <<<"$run")" = ".github/workflows/ubuntu2604-release.yml"
test "$(jq -r .event <<<"$run")" = workflow_dispatch
test "$(jq -r .head_branch <<<"$run")" = main
test "$(jq -r .head_sha <<<"$run")" = "$source_commit"
run_status=$(jq -r .status <<<"$run")
if [[ "$run_id" == "${GITHUB_RUN_ID:-}" ]]; then
  [[ "$run_status" == in_progress || "$run_status" == completed ]]
else
  test "$run_status" = completed
fi
max_attempt=$(jq -r .run_attempt <<<"$run")
[[ "$max_attempt" =~ ^[1-9][0-9]*$ ]]

for (( attempt = 1; attempt <= max_attempt; attempt++ )); do
  gh api --paginate \
    "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/attempts/$attempt/jobs?filter=all&per_page=100" |
    jq -s '[.[].jobs[]]' >"$temporary_directory/jobs-$attempt.json"
done
jq -s 'add' "$temporary_directory"/jobs-*.json \
  >"$temporary_directory/jobs.json"

gh api --paginate \
  "repos/$GITHUB_REPOSITORY/actions/runs/$run_id/artifacts?per_page=100" |
  jq -s '[.[].artifacts[]]' >"$temporary_directory/artifacts.json"

"$RELEASE_TOOL" resolve-artifacts \
  --jobs "$temporary_directory/jobs.json" \
  --artifacts "$temporary_directory/artifacts.json" \
  --kind "$kind" \
  --run-id "$run_id" \
  --source-commit "$source_commit" \
  --max-attempt "$max_attempt" \
  --output "$output"
