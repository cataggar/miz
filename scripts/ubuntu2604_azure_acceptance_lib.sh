#!/usr/bin/env bash

write_bearer_header() {
  local token=$1
  local output=$2
  (umask 077; printf 'Authorization: Bearer %s\n' "$token" >"$output")
}

ubuntu2604_expected_asset() {
  case "$1-$2" in
    x86_64-full) printf '%s\n' Ubuntu-26.04-x86_64.qcow2 ;;
    aarch64-full) printf '%s\n' Ubuntu-26.04-aarch64.qcow2 ;;
    x86_64-core) printf '%s\n' Ubuntu-26.04-x86_64.core.qcow2 ;;
    aarch64-core) printf '%s\n' Ubuntu-26.04-aarch64.core.qcow2 ;;
    *) return 1 ;;
  esac
}

ubuntu2604_validate_candidate_identity() {
  local key=$1
  local architecture=$2
  local flavor=$3
  local asset_name=$4
  local expected_asset

  [[ "$architecture" =~ ^(x86_64|aarch64)$ ]] || return 1
  [[ "$flavor" =~ ^(full|core)$ ]] || return 1
  [[ "$key" == "$architecture-$flavor" ]] || return 1
  expected_asset=$(ubuntu2604_expected_asset "$architecture" "$flavor") || return 1
  [[ "$asset_name" == "$expected_asset" ]]
}
