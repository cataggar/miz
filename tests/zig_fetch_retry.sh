#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temp_dir="$root/.scratch/zig-fetch-test-$BASHPID"
mkdir -p -- "$root/.scratch"
mkdir -- "$temp_dir"
trap 'rm -rf -- "$temp_dir"' EXIT
counter="$temp_dir/counter"
stub="$temp_dir/zig"

cat >"$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = build
test "$2" = --fetch=all
test "$3" = --global-cache-dir
test "$4" = "$ZIG_GLOBAL_CACHE_DIR"
test "$ZIG_LOCAL_PKG_DIR" = "$ZIG_GLOBAL_CACHE_DIR/zig-pkg"
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
  exhausted)
    echo "error: bad HTTP response code: '503 Service Unavailable'" >&2
    exit 9
    ;;
  permanent)
    echo 'error: hash mismatch' >&2
    exit 7
    ;;
  missing)
    echo "error: bad HTTP response code: '404 Not Found'" >&2
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
export ZIG_FETCH_LOG_DIR="$temp_dir/logs"
export ZIG_GLOBAL_CACHE_DIR="$temp_dir/cache"
export ZIG_LOCAL_PKG_DIR="$ZIG_GLOBAL_CACHE_DIR/zig-pkg"

export ZIG_FETCH_TEST_SCENARIO=transient
bash "$root/scripts/zig_fetch_retry.sh" --global-cache-dir "$temp_dir/cache"
test "$(cat "$counter")" = 3

for scenario in permanent missing; do
  printf '0\n' >"$counter"
  export ZIG_FETCH_TEST_SCENARIO="$scenario"
  status=0
  bash "$root/scripts/zig_fetch_retry.sh" \
    --global-cache-dir "$temp_dir/cache" || status=$?
  test "$status" = 7
  test "$(cat "$counter")" = 1
done

printf '0\n' >"$counter"
export ZIG_FETCH_TEST_SCENARIO=exhausted
status=0
bash "$root/scripts/zig_fetch_retry.sh" \
  --global-cache-dir "$temp_dir/cache" || status=$?
test "$status" = 9
test "$(cat "$counter")" = 4
test -z "$(find "$ZIG_FETCH_LOG_DIR" -type f -print -quit)"
