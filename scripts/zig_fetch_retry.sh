#!/usr/bin/env bash
set -euo pipefail

readonly max_attempts=4
readonly retryable_errors='NameServerFailure|TemporaryNameServerFailure|ConnectionTimedOut|ConnectionResetByPeer|NetworkUnreachable|TlsConnectionTruncated|HttpConnectionClosing|UnexpectedEndOfStream|HTTP response code: (408|429|5[0-9][0-9])'
readonly zig_command=${ZIG_FETCH_COMMAND:-zig}
readonly delay_seconds=${ZIG_FETCH_RETRY_DELAY_SECONDS:-10}
fetch_log=$(mktemp)
trap 'rm -f -- "$fetch_log"' EXIT

for ((attempt = 1; attempt <= max_attempts; attempt++)); do
  : >"$fetch_log"
  set +e
  "$zig_command" build --fetch "$@" 2>&1 | tee "$fetch_log"
  statuses=("${PIPESTATUS[@]}")
  set -e
  status=${statuses[0]}
  if (( status == 0 )); then
    exit 0
  fi

  if ! grep -Eq "$retryable_errors" "$fetch_log"; then
    echo "::error::zig build --fetch failed with a non-retryable error"
    exit "$status"
  fi
  if (( attempt == max_attempts )); then
    echo "::error::zig build --fetch exhausted $max_attempts attempts"
    exit "$status"
  fi

  delay=$((attempt * delay_seconds))
  echo "::warning::Transient dependency fetch failure on attempt $attempt/$max_attempts; retrying in ${delay}s"
  sleep "$delay"
done
