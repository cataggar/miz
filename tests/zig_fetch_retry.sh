#!/usr/bin/env bash
set -euo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
temp_dir="$root/.scratch/zig-fetch-test-$BASHPID"
mkdir -p -- "$root/.scratch"
mkdir -- "$temp_dir"
trap 'rm -rf -- "$temp_dir"' EXIT
counter="$temp_dir/counter"
stub="$temp_dir/zig"
if ! real_zig=$(command -v zig); then
  echo "zig is required for the actual compiler regression" >&2
  exit 1
fi
real_version=$("$real_zig" version)
if [[ "$real_version" != 0.17.0 ]]; then
  echo "the actual compiler regression requires Zig 0.17.0, found $real_version" >&2
  exit 1
fi

cat >"$stub" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
test "$1" = build
test "$2" = --fetch=all
test "$#" = 2
test "$ZIG_GLOBAL_CACHE_DIR" = "$ZIG_FETCH_TEST_CACHE"
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
export ZIG_FETCH_TEST_CACHE="$ZIG_GLOBAL_CACHE_DIR"

export ZIG_FETCH_TEST_SCENARIO=transient
ZIG_GLOBAL_CACHE_DIR="$temp_dir/wrong-cache" \
  bash "$root/scripts/zig_fetch_retry.sh" --global-cache-dir "$temp_dir/cache"
test "$(cat "$counter")" = 3

printf '0\n' >"$counter"
export ZIG_FETCH_TEST_SCENARIO=transient
bash "$root/scripts/zig_fetch_retry.sh"
test "$(cat "$counter")" = 3

printf '0\n' >"$counter"
export ZIG_FETCH_TEST_SCENARIO=transient
bash "$root/scripts/zig_fetch_retry.sh" --global-cache-dir="$temp_dir/cache"
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

printf '0\n' >"$counter"
for option in --global-cache-dir --global-cache-dir=; do
  status=0
  bash "$root/scripts/zig_fetch_retry.sh" "$option" || status=$?
  test "$status" = 2
  test "$(cat "$counter")" = 0
done

export ZIG_FETCH_COMMAND="$real_zig"
export ZIG_GLOBAL_CACHE_DIR="$temp_dir/real-global-cache"
export ZIG_LOCAL_CACHE_DIR="$temp_dir/real-local-cache"
export ZIG_LOCAL_PKG_DIR="$temp_dir/real-packages"
graph="$root/qcow2/build.zig"
status=0
"$real_zig" build --build-file "$graph" --fetch=all \
  --global-cache-dir "$ZIG_GLOBAL_CACHE_DIR" -j2 --summary none \
  >"$temp_dir/removed-flag.log" 2>&1 || status=$?
test "$status" != 0
grep -F 'unrecognized argument: --global-cache-dir' "$temp_dir/removed-flag.log"

ZIG_GLOBAL_CACHE_DIR="$temp_dir/wrong-real-cache" \
  bash "$root/scripts/zig_fetch_retry.sh" \
    --global-cache-dir "$temp_dir/real-global-cache" \
    --build-file "$graph" -j2 --summary none
test -d "$temp_dir/real-global-cache"
test -n "$(find "$temp_dir/real-global-cache" -type f -print -quit)"
test ! -e "$temp_dir/wrong-real-cache"
bash "$root/scripts/zig_fetch_retry.sh" \
  --build-file "$graph" -j2 --summary none
test -z "$(find "$ZIG_FETCH_LOG_DIR" -type f -print -quit)"
echo "actual Zig 0.17.0 private-cache fetch regression passed"
