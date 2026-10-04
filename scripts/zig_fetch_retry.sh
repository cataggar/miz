#!/usr/bin/env bash
set -euo pipefail

readonly max_attempts=4
readonly retryable_errors="NameServerFailure|TemporaryNameServerFailure|ConnectionTimedOut|ConnectionResetByPeer|NetworkUnreachable|TlsConnectionTruncated|HttpConnectionClosing|UnexpectedEndOfStream|HTTP response code: '?(408|429|5[0-9][0-9])"
readonly zig_command=${ZIG_FETCH_COMMAND:-zig}
readonly delay_seconds=${ZIG_FETCH_RETRY_DELAY_SECONDS:-10}
readonly log_root=${ZIG_FETCH_LOG_DIR:-.scratch/zig-fetch}
build_args=()
while (( $# > 0 )); do
  case "$1" in
    --global-cache-dir)
      if (( $# < 2 )) || [[ -z "$2" || "$2" == -* ]]; then
        echo "::error::--global-cache-dir requires a directory" >&2
        exit 2
      fi
      export ZIG_GLOBAL_CACHE_DIR="$2"
      shift 2
      ;;
    --global-cache-dir=*)
      cache_dir=${1#*=}
      if [[ -z "$cache_dir" ]]; then
        echo "::error::--global-cache-dir requires a directory" >&2
        exit 2
      fi
      export ZIG_GLOBAL_CACHE_DIR="$cache_dir"
      shift
      ;;
    *)
      build_args+=("$1")
      shift
      ;;
  esac
done
mkdir -p -- "$log_root"
fetch_log="$log_root/fetch-$BASHPID.log"
(set -o noclobber; : >"$fetch_log")
trap 'rm -f -- "$fetch_log"' EXIT

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  : >"$fetch_log"
  set +e
  # Zig 0.17 keeps extracted packages locally, while the global cache holds
  # compressed archives. Include lazy packages before an offline build.
  "$zig_command" build --fetch=all "${build_args[@]}" 2>&1 | tee "$fetch_log"
  statuses=("${PIPESTATUS[@]}")
  set -e
  status=${statuses[0]}
  if (( status == 0 )); then
    exit 0
  fi

  if ! grep -Eq "$retryable_errors" "$fetch_log"; then
    echo "::error::zig build --fetch=all failed with a non-retryable error"
    exit "$status"
  fi
  if (( attempt == max_attempts )); then
    echo "::error::zig build --fetch=all exhausted $max_attempts attempts"
    exit "$status"
  fi

  delay=$((attempt * delay_seconds))
  echo "::warning::Transient dependency fetch failure on attempt $attempt/$max_attempts; retrying in ${delay}s"
  sleep "$delay"
done
