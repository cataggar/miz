#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temp_dir=$(mktemp -d)
trap 'rm -rf -- "$temp_dir"' EXIT
counter="$temp_dir/counter"
stub="$temp_dir/zig"

cat >"$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
count=0
if [[ -f "$ZIG_FETCH_TEST_COUNTER" ]]; then
  read -r count <"$ZIG_FETCH_TEST_COUNTER"
fi
count=$((count + 1))
printf '%s\n' "$count" >"$ZIG_FETCH_TEST_COUNTER"
case "$ZIG_FETCH_TEST_SCENARIO" in
  transient)
    if (( count < 3 )); then
      echo 'error: NameServerFailure' >&2
      exit 1
    fi
    ;;
  permanent)
    echo 'error: hash mismatch' >&2
    exit 7
    ;;
  *)
    exit 99
    ;;
esac
EOF
chmod +x "$stub"

export ZIG_FETCH_COMMAND="$stub"
export ZIG_FETCH_RETRY_DELAY_SECONDS=0
export ZIG_FETCH_TEST_COUNTER="$counter"

export ZIG_FETCH_TEST_SCENARIO=transient
bash "$root/scripts/zig_fetch_retry.sh" --global-cache-dir "$temp_dir/cache"
test "$(cat "$counter")" = 3

printf '0\n' >"$counter"
export ZIG_FETCH_TEST_SCENARIO=permanent
status=0
bash "$root/scripts/zig_fetch_retry.sh" \
  --global-cache-dir "$temp_dir/cache" || status=$?
test "$status" = 7
test "$(cat "$counter")" = 1
