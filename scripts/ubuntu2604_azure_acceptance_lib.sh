#!/usr/bin/env bash

write_bearer_header() {
  local token=$1
  local output=$2
  (umask 077; printf 'Authorization: Bearer %s\n' "$token" >"$output")
}
