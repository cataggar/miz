#!/usr/bin/env bash
set -Eeuo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/azure_trusted_launch_lib.sh
source "$script_dir/azure_trusted_launch_lib.sh"
# shellcheck source=scripts/azure_confidential_vm_lib.sh
source "$script_dir/azure_confidential_vm_lib.sh"
# shellcheck source=scripts/ubuntu2404_confidential_guest_acceptance_lib.sh
source "$script_dir/ubuntu2404_confidential_guest_acceptance_lib.sh"

RELEASE_TOOL=${UBUNTU2404_CONFIDENTIAL_RELEASE_TOOL:-zig-out/bin/ubuntu2404_confidential_release}
ATTESTATION_ENDPOINT=${ATTESTATION_ENDPOINT:-https://sharedeus2.eus2.attest.azure.net}
EXPECTED_REPOSITORY=cataggar/miz
EXPECTED_REF=refs/heads/main
EXPECTED_ENVIRONMENT=ubuntu2404-confidential-capture
EXPECTED_PUBLICATION_LOCK=ubuntu2404-confidential-cvm-target-version
OWNER=ubuntu2404-confidential-capture
TARGET_PUBLISHER=miz
TARGET_OFFER=ubuntu2404
TARGET_SKU=confidential-x64

command_name=${1:-run}
if (( $# > 1 )) ||
    [[ "$command_name" != run && "$command_name" != prepare &&
      "$command_name" != publish && "$command_name" != cleanup ]]; then
  echo "usage: $0 prepare|publish|cleanup|run" >&2
  exit 2
fi

# Target publication is an upsert, not a create-only Azure operation. The
# protected workflow must use EXPECTED_PUBLICATION_LOCK as a stable,
# non-canceling concurrency group and pre-authenticate
# PUBLICATION_AZURE_CONFIG_DIR only as the exclusive
# PUBLICATION_PRINCIPAL_CLIENT_ID. That OIDC principal must have target
# parent/version read and version write, but no version delete or parent
# write/delete. The default Azure context should have only narrow scratch-RG
# rights plus target-version read for final validation. This script validates
# those protected-context identities; it cannot prove RBAC or defend against a
# malicious subscription Owner.

fail() {
  printf '::error::%s\n' "$*" >&2
  return 1
}

valid_gallery_version() {
  local value=$1 major minor patch
  [[ "$value" =~ ^(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})\.(0|[1-9][0-9]{0,9})$ ]] ||
    return 1
  IFS=. read -r major minor patch <<<"$value"
  (( 10#$major <= 2147483647 &&
      10#$minor <= 2147483647 &&
      10#$patch <= 2147483647 &&
      (10#$major != 0 || 10#$minor != 0 || 10#$patch != 0) ))
}

publication_az() {
  AZURE_CONFIG_DIR="$PUBLICATION_AZURE_CONFIG_DIR" az "$@"
}

private_directory_is_safe() {
  local path=$1 metadata owner mode extra
  [[ "$path" == /* && -d "$path" && ! -L "$path" ]] || return 1
  metadata=$(stat -c '%u %a' -- "$path") || return 1
  IFS=' ' read -r owner mode extra <<<"$metadata" || return 1
  [[ -z "$extra" && "$owner" == "$EUID" && "$mode" == 700 ]]
}

require_capture_account() {
  local subscription tenant principal_type principal_client_id
  subscription=$(az account show --query id --output tsv) || return
  tenant=$(az account show --query tenantId --output tsv) || return
  principal_type=$(az account show --query user.type --output tsv) || return
  principal_client_id=$(az account show --query user.name --output tsv) || return
  [[ "${subscription,,}" == "${AZURE_SUBSCRIPTION_ID,,}" &&
      "${tenant,,}" == "${AZURE_TENANT_ID,,}" &&
      "$principal_type" == servicePrincipal &&
      "${principal_client_id,,}" == "${CAPTURE_PRINCIPAL_CLIENT_ID,,}" ]] ||
    {
      fail "Azure login does not match the narrow capture principal, tenant, and subscription"
      return
    }
}

require_publication_account() {
  local subscription tenant principal_type principal_client_id
  subscription=$(publication_az account show --query id --output tsv) || return
  tenant=$(publication_az account show --query tenantId --output tsv) || return
  principal_type=$(publication_az account show --query user.type --output tsv) ||
    return
  principal_client_id=$(publication_az account show --query user.name --output tsv) ||
    return
  [[ "${subscription,,}" == "${AZURE_SUBSCRIPTION_ID,,}" &&
      "${tenant,,}" == "${AZURE_TENANT_ID,,}" &&
      "$principal_type" == servicePrincipal &&
      "${principal_client_id,,}" == "${PUBLICATION_PRINCIPAL_CLIENT_ID,,}" ]] ||
    {
      fail "Azure login does not match the exclusive publication principal, tenant, and subscription"
      return
    }
}

require_cleanup_identity() {
  if [[ -z ${STATE_FILE:-} || -z ${GITHUB_REPOSITORY:-} ||
      -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} ||
      -z ${SOURCE_COMMIT:-} || -z ${SOURCE_RELEASE_TAG:-} ||
      -z ${TOOL_COMMIT:-} ||
      -z ${AZURE_SUBSCRIPTION_ID:-} || -z ${AZURE_TENANT_ID:-} ||
      -z ${CAPTURE_PRINCIPAL_CLIENT_ID:-} || -z ${AZURE_CONFIG_DIR:-} ||
      -z ${TARGET_OWNER_TAG:-} || -z ${TARGET_RESOURCE_GROUP:-} ||
      -z ${TARGET_GALLERY:-} || -z ${TARGET_IMAGE_DEFINITION:-} ||
      -z ${TARGET_IMAGE_VERSION:-} ]]; then
    fail "Capture cleanup identity is incomplete"
    return 1
  fi
  if [[ "$GITHUB_REPOSITORY" != "$EXPECTED_REPOSITORY" ]]; then
    fail "Capture repository identity is invalid"
    return 1
  fi
  if [[ ! "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$ ||
      ! "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,9}$ ||
      ! "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ||
      ! "$TOOL_COMMIT" =~ ^[0-9a-f]{40}$ ]]; then
    fail "Capture cleanup identity is invalid"
    return 1
  fi
}

state_replace() {
  if (( $# < 1 )); then
    fail "Capture cleanup state transformation is missing"
    return 1
  fi
  local filter=$1 metadata next owner mode size extra
  if ! shift; then
    fail "Could not read the capture cleanup state transformation"
    return 1
  fi
  if [[ -z ${STATE_FILE:-} ]]; then
    fail "Capture cleanup state path is unavailable"
    return 1
  fi
  next="${STATE_FILE}.next"
  if ! rm -f -- "$next"; then
    fail "Could not clear the temporary capture cleanup state"
    return 1
  fi
  if ! state_file_is_safe "$STATE_FILE" ||
      ! state_matches_identity "$STATE_FILE"; then
    fail "Refusing to replace invalid capture cleanup state"
    return 1
  fi
  if ! (umask 077; jq -c "$@" "$filter" "$STATE_FILE" >"$next"); then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Could not transform capture cleanup state"
    return 1
  fi
  if [[ ! -f "$next" || -L "$next" ]]; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Temporary capture cleanup state is not a regular file"
    return 1
  fi
  if ! chmod 0600 "$next"; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Could not secure temporary capture cleanup state"
    return 1
  fi
  if ! metadata=$(stat -c '%u %a %s' -- "$next"); then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Could not inspect temporary capture cleanup state"
    return 1
  fi
  if ! IFS=' ' read -r owner mode size extra <<<"$metadata"; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Could not parse temporary capture cleanup state metadata"
    return 1
  fi
  if [[ -n "$extra" || "$owner" != "$EUID" || "$mode" != 600 ]]; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Temporary capture cleanup state permissions are unsafe"
    return 1
  fi
  if [[ ! "$size" =~ ^[1-9][0-9]*$ || "$size" -gt 16384 ]]; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Capture cleanup state is empty or exceeds its size limit"
    return 1
  fi
  if ! state_matches_identity "$next"; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Temporary capture cleanup state is invalid"
    return 1
  fi
  if ! mv -fT -- "$next" "$STATE_FILE"; then
    if ! rm -f -- "$next"; then
      fail "Could not remove failed temporary capture cleanup state"
    fi
    fail "Could not atomically replace capture cleanup state"
    return 1
  fi
}

state_file_is_safe() {
  local path=${1:-$STATE_FILE} metadata owner mode size extra
  [[ -f "$path" && ! -L "$path" ]] || return 1
  metadata=$(stat -c '%u %a %s' -- "$path") || return 1
  IFS=' ' read -r owner mode size extra <<<"$metadata" || return 1
  [[ -z "$extra" && "$owner" == "$EUID" && "$mode" == 600 &&
      "$size" =~ ^[1-9][0-9]*$ && "$size" -le 16384 ]]
}

state_matches_identity() {
  local path=${1:-$STATE_FILE}
  jq -e \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg run_id "$GITHUB_RUN_ID" \
    --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
    --arg source_commit "$SOURCE_COMMIT" \
    --arg source_release_tag "$SOURCE_RELEASE_TAG" \
    --arg tool_commit "$TOOL_COMMIT" \
    --arg publication_lock "$EXPECTED_PUBLICATION_LOCK" \
    --arg target_owner "$TARGET_OWNER_TAG" \
    --arg target_resource_group "$TARGET_RESOURCE_GROUP" \
    --arg target_gallery "$TARGET_GALLERY" \
    --arg target_image_definition "$TARGET_IMAGE_DEFINITION" \
    --arg target_image_version "$TARGET_IMAGE_VERSION" \
    '. as $state |
     keys == [
       "outstanding_write_access", "repository", "run_attempt", "run_id",
       "run_succeeded", "schema", "source_commit", "source_release_tag",
       "stage", "subscription_id", "target", "temporary_group_create",
       "temporary_resource_group",
       "temporary_resources", "tool_commit"
     ] and
     .schema == 4 and
     .repository == $repository and
     .run_id == $run_id and
     .run_attempt == $run_attempt and
     .source_commit == $source_commit and
     .source_release_tag == $source_release_tag and
     .tool_commit == $tool_commit and
     (
       .stage == "preparing" or
       .stage == "prepared" or
       .stage == "publishing" or
       .stage == "completed"
     ) and
     (.subscription_id | type == "string") and
     (.subscription_id | test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) and
     (.temporary_resource_group | type == "string") and
     (.temporary_resource_group | test("^miz-u2404-cvm-capture-[1-9][0-9]{0,19}-[1-9][0-9]{0,9}-[0-9a-f]{32}$")) and
     (
       .temporary_group_create == null or
       (
         (.temporary_group_create | type == "object") and
         (.temporary_group_create | keys == [
           "owner_tag", "repository", "resource_id", "resource_name",
           "run_attempt", "run_id", "source_commit", "status"
         ]) and
         (
           .temporary_group_create.status == "expected" or
           .temporary_group_create.status == "pending" or
           .temporary_group_create.status == "quarantined" or
           .temporary_group_create.status == "confirmed_created"
         ) and
         (.temporary_group_create.resource_id | ascii_downcase) ==
           ("/subscriptions/" + $state.subscription_id + "/resourceGroups/" +
            $state.temporary_resource_group | ascii_downcase) and
         .temporary_group_create.resource_name ==
           $state.temporary_resource_group and
         .temporary_group_create.owner_tag ==
           "ubuntu2404-confidential-capture" and
         .temporary_group_create.repository == $repository and
         .temporary_group_create.run_id == $run_id and
         .temporary_group_create.run_attempt == $run_attempt and
         .temporary_group_create.source_commit == $source_commit
       )
     ) and
     (.temporary_resources | type == "array") and
     (.temporary_resources | length <= 64) and
     (all(.temporary_resources[];
       (type == "object") and
       (keys == ["id", "name", "type"]) and
       (.id | type == "string") and
       (.id | length >= 1 and length <= 2048) and
       (.id | ascii_downcase | startswith(
         ("/subscriptions/" + $state.subscription_id + "/resourceGroups/" +
          $state.temporary_resource_group + "/providers/" | ascii_downcase)
       )) and
       (.name | type == "string") and
       (.name | length >= 1 and length <= 512) and
       (.type | type == "string") and
       (.type | test("^[A-Za-z][A-Za-z0-9.]+/[A-Za-z][A-Za-z0-9/]+$"))
     )) and
     ([.temporary_resources[].id | ascii_downcase] | unique | length) ==
       (.temporary_resources | length) and
     (.run_succeeded | type == "boolean") and
     (.target | type == "object") and
     (.target | keys == [
       "definition_id", "gallery", "image_definition", "owner_tag",
       "publication", "resource_group", "version_id"
     ]) and
     (.target.owner_tag | type == "string") and
     .target.owner_tag == $target_owner and
     (.target.owner_tag | test("^[A-Za-z0-9._:/-]{1,128}$")) and
     (.target.resource_group | type == "string") and
     .target.resource_group == $target_resource_group and
     (.target.resource_group | test("^[A-Za-z0-9._()-]{1,90}$")) and
     (.target.gallery | type == "string") and
     .target.gallery == $target_gallery and
     (.target.gallery | test("^[A-Za-z0-9_]{1,80}$")) and
     (.target.image_definition | type == "string") and
     .target.image_definition == $target_image_definition and
     (.target.image_definition | test("^[A-Za-z0-9._()-]{1,80}$")) and
     (.target.definition_id | ascii_downcase) ==
       ("/subscriptions/" + $state.subscription_id + "/resourceGroups/" +
        $state.target.resource_group +
        "/providers/Microsoft.Compute/galleries/" + $state.target.gallery +
        "/images/" + $state.target.image_definition | ascii_downcase) and
     (.target.version_id | ascii_downcase | startswith(
       ($state.target.definition_id + "/versions/" | ascii_downcase)
     )) and
     (.target.version_id | split("/") | last |
       test("^(0|[1-9][0-9]{0,9})\\.(0|[1-9][0-9]{0,9})\\.(0|[1-9][0-9]{0,9})$")) and
     (.target.version_id | split("/") | last) == $target_image_version and
     (.target.publication | type == "object") and
     (.target.publication | keys == [
       "lock_id", "principal_client_id", "status"
     ]) and
     .target.publication.lock_id == $publication_lock and
     (.target.publication.principal_client_id |
       test("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")) and
     (
       .target.publication.status == "not_dispatched" or
       .target.publication.status == "pending" or
       .target.publication.status == "quarantined" or
       .target.publication.status == "published"
     ) and
     (
       .outstanding_write_access == null or
       (
         (.outstanding_write_access | type == "object") and
         (.outstanding_write_access | keys == [
           "disk_id", "disk_name", "resource_group", "status"
         ]) and
         (.outstanding_write_access.status == "pending" or
          .outstanding_write_access.status == "active") and
         (.outstanding_write_access.disk_id | type == "string") and
         (.outstanding_write_access.disk_name | type == "string") and
         (.outstanding_write_access.resource_group | type == "string")
       )
     )' \
    "$path" >/dev/null
}

owned_tags_match() {
  local metadata=$1 owner=$2 repository=$3 run_id=$4 run_attempt=$5 source_commit=$6
  jq -e \
    --arg owner "$owner" \
    --arg repository "$repository" \
    --arg run_id "$run_id" \
    --arg run_attempt "$run_attempt" \
    --arg source_commit "$source_commit" \
    '.tags["miz-owner"] == $owner and
     .tags["miz-repository"] == $repository and
     .tags["miz-run-id"] == $run_id and
     .tags["miz-run-attempt"] == $run_attempt and
     .tags["miz-source-commit"] == $source_commit' \
    "$metadata" >/dev/null
}

exact_owned_tags_match() {
  local metadata=$1 owner=$2 repository=$3 run_id=$4 run_attempt=$5 source_commit=$6
  jq -e \
    --arg owner "$owner" \
    --arg repository "$repository" \
    --arg run_id "$run_id" \
    --arg run_attempt "$run_attempt" \
    --arg source_commit "$source_commit" \
    '.tags == {
      "miz-owner": $owner,
      "miz-repository": $repository,
      "miz-run-id": $run_id,
      "miz-run-attempt": $run_attempt,
      "miz-source-commit": $source_commit
    }' \
    "$metadata" >/dev/null
}

validate_temporary_group_identity() {
  local metadata=$1 expected_id=$2 expected_name=$3
  jq -e \
    --arg expected_id "$expected_id" \
    --arg name "$expected_name" \
    '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
     (.name | ascii_downcase) == ($name | ascii_downcase) and
     (.type | ascii_downcase) == "microsoft.resources/resourcegroups"' \
    "$metadata" >/dev/null
}

validate_target_definition_identity() {
  local metadata=$1 expected_id=$2 expected_name=$3
  jq -e \
    --arg expected_id "$expected_id" \
    --arg name "$expected_name" \
    '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
     .name == $name and
     (.type | ascii_downcase) == "microsoft.compute/galleries/images"' \
    "$metadata" >/dev/null
}

validate_created_resource_document() {
  local metadata=$1 expected_id=$2 expected_type=$3 expected_name=$4
  jq -e \
    --arg expected_id "$expected_id" \
    --arg expected_type "$expected_type" \
    --arg expected_name "$expected_name" \
    --arg location "$AZURE_LOCATION" \
    '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
     (.type | ascii_downcase) == ($expected_type | ascii_downcase) and
     .name == $expected_name and
     (.location | ascii_downcase) == ($location | ascii_downcase)' \
    "$metadata" >/dev/null &&
    owned_tags_match "$metadata" "$OWNER" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"
}

record_expected_resource() {
  local metadata=$1 expected_id=$2 expected_type=$3
  local document_name=$4 inventory_name=${5:-$4}
  validate_created_resource_document \
    "$metadata" "$expected_id" "$expected_type" "$document_name" ||
    {
      fail "Created temporary resource failed exact identity, location, or tag validation"
      return
    }
  state_replace \
    'if any(.temporary_resources[];
         (.id | ascii_downcase) == ($id | ascii_downcase))
     then error("duplicate temporary resource")
     else .temporary_resources += [{
       id: $id,
       type: $type,
       name: $name
     }] end' \
    --arg id "$expected_id" \
    --arg type "$expected_type" \
    --arg name "$inventory_name" ||
    fail "Could not append the exact temporary resource allowlist"
}

validate_write_access_identity() {
  local disk_id=$1 disk_group=$2 disk_name=$3 temporary_group subscription expected_id
  temporary_group=$(jq -er '.temporary_resource_group' "$STATE_FILE") || return
  subscription=$(jq -er '.subscription_id' "$STATE_FILE") || return
  [[ "$disk_group" == "$temporary_group" &&
      "$disk_name" == "miz-u2404-capture-upload-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}" ]] ||
    return 1
  expected_id="/subscriptions/$subscription/resourceGroups/$disk_group/providers/Microsoft.Compute/disks/$disk_name"
  [[ "${disk_id,,}" == "${expected_id,,}" ]]
}

revoke_outstanding_disk_write_access() {
  local status disk_id disk_group disk_name metadata stderr_file
  status=$(jq -r '.outstanding_write_access.status // "none"' "$STATE_FILE") ||
    return
  case "$status" in
    none) return 0 ;;
    pending|active) ;;
    *) fail "Capture cleanup state has an invalid disk write grant"; return ;;
  esac
  disk_id=$(jq -er '.outstanding_write_access.disk_id' "$STATE_FILE") || return
  disk_group=$(jq -er '.outstanding_write_access.resource_group' "$STATE_FILE") ||
    return
  disk_name=$(jq -er '.outstanding_write_access.disk_name' "$STATE_FILE") ||
    return
  validate_write_access_identity "$disk_id" "$disk_group" "$disk_name" || {
    fail "Refusing to revoke a disk write grant with invalid state identity"
    return
  }

  metadata="${STATE_FILE}.write-access-disk.json"
  stderr_file="${metadata}.stderr"
  if ! az disk show --ids "$disk_id" --output json >"$metadata" 2>"$stderr_file"; then
    if grep -Eq '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' "$stderr_file"; then
      rm -f -- "$metadata" "$stderr_file"
      state_replace '.outstanding_write_access = null'
      return
    fi
    fail "Could not inspect the disk with an outstanding write grant"
    return
  fi
  rm -f -- "$stderr_file"
  jq -e \
    --arg disk_id "$disk_id" \
    --arg disk_group "$disk_group" \
    --arg disk_name "$disk_name" \
    '(.id | ascii_downcase) == ($disk_id | ascii_downcase) and
     (.resourceGroup | ascii_downcase) == ($disk_group | ascii_downcase) and
     .name == $disk_name' \
    "$metadata" >/dev/null ||
    {
      fail "Refusing to revoke a disk write grant without exact disk identity"
      return
    }
  owned_tags_match "$metadata" "$OWNER" "$GITHUB_REPOSITORY" \
    "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT" ||
    {
      fail "Refusing to revoke a disk write grant without exact ownership tags"
      return
    }
  if ! az disk revoke-access --ids "$disk_id" --output none; then
    if az disk show --ids "$disk_id" --output none 2>"$stderr_file"; then
      fail "Failed to revoke the outstanding disk write grant"
      return
    fi
    if ! grep -Eq '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' \
        "$stderr_file"; then
      fail "Could not prove the disk disappeared after revoke failure"
      return
    fi
  fi
  rm -f -- "$metadata" "$stderr_file"
  state_replace '.outstanding_write_access = null'
}

delete_temporary_group() {
  local status publication_status run_succeeded group resource_id metadata stderr_file
  local inventory subscription_id
  status=$(jq -r '.temporary_group_create.status // "none"' "$STATE_FILE")
  case "$status" in
    none) return 0 ;;
    expected) return 0 ;;
    pending|quarantined)
      fail "Temporary resource-group creation is quarantined and requires manual review"
      return
      ;;
    confirmed_created) ;;
    *) fail "Capture cleanup state has an invalid temporary group create"; return ;;
  esac
  publication_status=$(jq -er '.target.publication.status' "$STATE_FILE") ||
    return
  if [[ "$publication_status" == pending ||
      "$publication_status" == quarantined ]]; then
    fail "Target publication is unresolved; retaining the temporary resource group for break-glass review"
    return
  fi
  run_succeeded=$(jq -r '.run_succeeded' "$STATE_FILE") || return
  if [[ "$run_succeeded" != true &&
      "$publication_status" != not_dispatched ]]; then
    fail "Capture failed after target publication dispatch; retaining the temporary resource group for break-glass review"
    return
  fi
  group=$(jq -er '.temporary_group_create.resource_name' "$STATE_FILE") || return
  resource_id=$(jq -er '.temporary_group_create.resource_id' "$STATE_FILE") ||
    return
  subscription_id=$(jq -er '.subscription_id' "$STATE_FILE") || return
  metadata="${STATE_FILE}.group.json"
  stderr_file="${metadata}.stderr"
  if ! az group show --name "$group" --output json >"$metadata" 2>"$stderr_file"; then
    if grep -Eq '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' \
        "$stderr_file"; then
      rm -f -- "$metadata" "$stderr_file"
      state_replace \
        '.temporary_group_create = null | .temporary_resources = []'
      return
    fi
    fail "Could not inspect temporary resource-group ownership"
    return
  fi
  rm -f -- "$stderr_file"
  validate_temporary_group_identity "$metadata" "$resource_id" "$group" ||
    {
      fail "Refusing to delete temporary resource group without exact resource identity"
      return
    }
  if ! exact_owned_tags_match "$metadata" "$OWNER" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"; then
    fail "Refusing to delete temporary resource group without exact ownership tags"
    return
  fi
  inventory="${STATE_FILE}.inventory.json"
  if ! az resource list \
      --resource-group "$group" \
      --output json >"$inventory"; then
    fail "Could not freshly inventory the temporary resource group"
    return
  fi
  [[ $(stat -c %s -- "$inventory") -le 1048576 ]] ||
    {
      fail "Temporary resource-group inventory exceeds its size limit"
      return
    }
  jq -e \
    --slurpfile state "$STATE_FILE" \
    --arg prefix "/subscriptions/$subscription_id/resourceGroups/$group/providers/" \
    --arg owner "$OWNER" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg run_id "$GITHUB_RUN_ID" \
    --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
    --arg source_commit "$SOURCE_COMMIT" \
    '
    type == "array" and length <= 64 and
    all(.[];
      (.id | type == "string") and
      (.id | ascii_downcase | startswith($prefix | ascii_downcase)) and
      (.type | type == "string") and
      (.name | type == "string") and
      .tags["miz-owner"] == $owner and
      .tags["miz-repository"] == $repository and
      .tags["miz-run-id"] == $run_id and
      .tags["miz-run-attempt"] == $run_attempt and
      .tags["miz-source-commit"] == $source_commit and
      (. as $live |
       any($state[0].temporary_resources[];
         (.id | ascii_downcase) == ($live.id | ascii_downcase) and
         (.type | ascii_downcase) == ($live.type | ascii_downcase) and
         .name == $live.name))
    )
    ' "$inventory" >/dev/null ||
    {
      fail "Temporary resource-group inventory contains an unknown, mismatched, or untagged resource"
      return
    }
  az group delete --name "$group" --yes ||
    {
      fail "Failed to delete exact-owned temporary resource group"
      return
    }
  state_replace \
    '.temporary_group_create = null | .temporary_resources = []'
}

cleanup_resources() {
  require_cleanup_identity || return
  [[ -e "$STATE_FILE" ]] || {
    fail "Capture cleanup state is unavailable"
    return
  }
  [[ -s "$STATE_FILE" ]] || {
    fail "Capture cleanup state is empty"
    return
  }
  command -v az >/dev/null || {
    fail "Azure CLI is unavailable during cleanup"
    return
  }
  command -v jq >/dev/null || {
    fail "jq is unavailable during cleanup"
    return
  }
  state_file_is_safe || {
    fail "Capture cleanup state is not a bounded owner-only regular file"
    return
  }
  state_matches_identity || {
    fail "Refusing cleanup because state identity does not match this run"
    return
  }
  local state_subscription
  require_capture_account ||
    {
      fail "Azure login is unavailable or invalid during cleanup"
      return
    }
  state_subscription=$(jq -er '.subscription_id' "$STATE_FILE") || return
  [[ "${AZURE_SUBSCRIPTION_ID,,}" == "${state_subscription,,}" ]] || {
    fail "Azure cleanup subscription does not match capture state"
    return
  }

  local cleanup_status=0
  revoke_outstanding_disk_write_access || cleanup_status=1
  delete_temporary_group || cleanup_status=1
  return "$cleanup_status"
}

if [[ "$command_name" == cleanup ]]; then
  cleanup_resources
  exit
fi

require_cleanup_identity
if [[ -z ${GITHUB_REF:-} || -z ${PROTECTED_ENVIRONMENT:-} ||
      -z ${CANDIDATE:-} || -z ${PROVENANCE:-} ||
      -z ${SOURCE_ACCEPTANCE:-} || -z ${SOURCE_RELEASE_TAG:-} ||
      -z ${SOURCE_LOCATION:-} ||
      -z ${SOURCE_VM_SIZE:-} || -z ${SOURCE_RUN_ID:-} ||
      -z ${SOURCE_RUN_ATTEMPT:-} || -z ${SOURCE_REPOSITORY:-} ||
      -z ${AZURE_SUBSCRIPTION_ID:-} || -z ${AZURE_TENANT_ID:-} ||
      -z ${AZURE_LOCATION:-} ||
      -z ${AZURE_VM_SIZE:-} || -z ${TARGET_RESOURCE_GROUP:-} ||
      -z ${TARGET_GALLERY:-} || -z ${TARGET_IMAGE_DEFINITION:-} ||
      -z ${TARGET_IMAGE_VERSION:-} || -z ${TARGET_LOCATION:-} ||
      -z ${TARGET_OWNER_TAG:-} || -z ${PUBLICATION_LOCK_ID:-} ||
      -z ${CAPTURE_PRINCIPAL_CLIENT_ID:-} ||
      -z ${PUBLICATION_PRINCIPAL_CLIENT_ID:-} ||
      -z ${AZURE_CONFIG_DIR:-} || -z ${RESULT_DIR:-} || -z ${MIZ:-} ]]; then
  fail "Confidential VM capture configuration is incomplete"
  exit 1
fi
if [[ "$command_name" == publish || "$command_name" == run ]] &&
    [[ -z ${PUBLICATION_AZURE_CONFIG_DIR:-} ]]; then
  fail "Protected publication Azure context is incomplete"
  exit 1
fi
[[ "$GITHUB_REF" == "$EXPECTED_REF" &&
    "$PROTECTED_ENVIRONMENT" == "$EXPECTED_ENVIRONMENT" &&
    "$SOURCE_REPOSITORY" == "$EXPECTED_REPOSITORY" ]] ||
  {
    fail "Protected capture workflow identity is invalid"
    exit 1
  }
[[ "$SOURCE_RUN_ID" =~ ^[1-9][0-9]{0,19}$ &&
    "$SOURCE_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,9}$ &&
    "$SOURCE_RELEASE_TAG" =~ ^Ubuntu-24\.04-confidential-[0-9]{8}$ &&
    "$AZURE_SUBSCRIPTION_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
    "$AZURE_TENANT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
    "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ &&
    "$SOURCE_LOCATION" =~ ^[a-z0-9-]+$ &&
    "$TARGET_LOCATION" =~ ^[a-z0-9-]+$ &&
    "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ &&
    "$SOURCE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ &&
    "$TARGET_RESOURCE_GROUP" =~ ^[A-Za-z0-9._()-]{1,90}$ &&
    "$TARGET_GALLERY" =~ ^[A-Za-z0-9_]{1,80}$ &&
    "$TARGET_IMAGE_DEFINITION" =~ ^[A-Za-z0-9._()-]{1,80}$ &&
    "$TARGET_OWNER_TAG" =~ ^[A-Za-z0-9._:/-]{1,128}$ &&
    "$CAPTURE_PRINCIPAL_CLIENT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
    "$PUBLICATION_PRINCIPAL_CLIENT_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
    "$ATTESTATION_ENDPOINT" =~ ^https://[a-z0-9.-]+\.attest\.azure\.net$ ]] ||
  {
    fail "Confidential VM capture configuration is invalid"
    exit 1
  }
  valid_gallery_version "$TARGET_IMAGE_VERSION" ||
    {
      fail "Target gallery version is not a canonical nonzero semantic version"
      exit 1
    }
[[ "$PUBLICATION_LOCK_ID" == "$EXPECTED_PUBLICATION_LOCK" ]] ||
  {
    fail "Protected publication lock identity is invalid"
    exit 1
  }
private_directory_is_safe "$AZURE_CONFIG_DIR" ||
  {
    fail "Protected capture Azure context is not a private absolute directory"
    exit 1
  }
if [[ "$command_name" == publish || "$command_name" == run ]]; then
  private_directory_is_safe "$PUBLICATION_AZURE_CONFIG_DIR" ||
    {
      fail "Protected publication Azure context is not a private absolute directory"
      exit 1
    }
  [[ "$PUBLICATION_AZURE_CONFIG_DIR" != "$AZURE_CONFIG_DIR" ]] ||
    {
      fail "Capture and publication Azure contexts must be distinct"
      exit 1
    }
fi
[[ "${CAPTURE_PRINCIPAL_CLIENT_ID,,}" != "${PUBLICATION_PRINCIPAL_CLIENT_ID,,}" ]] ||
  {
    fail "Capture and publication principals must be distinct"
    exit 1
  }
[[ "$SOURCE_LOCATION" == "$AZURE_LOCATION" &&
    "$TARGET_LOCATION" == "$AZURE_LOCATION" &&
    "$SOURCE_VM_SIZE" == "$AZURE_VM_SIZE" ]] ||
  {
    fail "Capture source, target, and validation region or SKU differ"
    exit 1
  }
[[ -f "$CANDIDATE" && -f "$PROVENANCE" && -f "$SOURCE_ACCEPTANCE" &&
    -x "$MIZ" && -x "$RELEASE_TOOL" ]] ||
  {
    fail "Capture input artifact or executable is unavailable"
    exit 1
  }

for tool in az azcopy curl jq openssl qemu-img scp sha256sum ssh ssh-keygen unzip; do
  command -v "$tool" >/dev/null || {
    fail "Required Confidential VM capture tool $tool is unavailable"
    exit 1
  }
done

require_capture_account

report_error() {
  local status=$1 line=$2
  trap - ERR
  printf '::error::Confidential VM capture failed at line %s\n' "$line" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO"' ERR

name_seed="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
upload_disk_name="miz-u2404-capture-upload-${name_seed}"
managed_image_name="miz-u2404-capture-image-${name_seed}"
staging_gallery="mizcvmcapture${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}"
staging_definition=mizu2404cvmsource
staging_version=1.0.0
source_vm_name="miz-cvm-source-${name_seed}"
source_os_disk_name="miz-cvm-source-os-${name_seed}"
source_data_disk_name="miz-cvm-source-data-${name_seed}"
capture_vm_name="miz-cvm-capture-${name_seed}"
capture_os_disk_name="miz-cvm-capture-os-${name_seed}"
snapshot_name="miz-cvm-snapshot-${name_seed}"
final_vm_name="miz-cvm-final-${name_seed}"
final_os_disk_name="miz-cvm-final-os-${name_seed}"
final_data_disk_name="miz-cvm-final-data-${name_seed}"
vnet_name="miz-cvm-vnet-${name_seed}"
subnet_name=miz-cvm-subnet
nsg_name="miz-cvm-nsg-${name_seed}"
source_public_ip_name="miz-cvm-source-pip-${name_seed}"
source_nic_name="miz-cvm-source-nic-${name_seed}"
capture_public_ip_name="miz-cvm-capture-pip-${name_seed}"
capture_nic_name="miz-cvm-capture-nic-${name_seed}"
final_public_ip_name="miz-cvm-final-pip-${name_seed}"
final_nic_name="miz-cvm-final-nic-${name_seed}"
admin_username=mizcapture

if [[ "$command_name" == publish ]]; then
  state_file_is_safe && state_matches_identity ||
    {
      fail "Publish requires valid owner-only capture recovery state"
      exit 1
    }
  resource_group=$(jq -er '.temporary_resource_group' "$STATE_FILE")
else
  mkdir -p "$RESULT_DIR" "$(dirname -- "$STATE_FILE")"
  chmod 0700 "$RESULT_DIR" "$(dirname -- "$STATE_FILE")"
  [[ ! -e "$STATE_FILE" ]] ||
    {
      fail "Refusing to overwrite existing capture state"
      exit 1
    }
  random_group_suffix=$(openssl rand -hex 16)
  [[ "$random_group_suffix" =~ ^[0-9a-f]{32}$ ]] ||
    fail "Could not generate a 128-bit temporary resource-group suffix"
  resource_group="miz-u2404-cvm-capture-${name_seed}-${random_group_suffix}"
fi

temporary_group_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group"
target_definition_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$TARGET_RESOURCE_GROUP/providers/Microsoft.Compute/galleries/$TARGET_GALLERY/images/$TARGET_IMAGE_DEFINITION"
target_version_id="$target_definition_id/versions/$TARGET_IMAGE_VERSION"
staging_definition_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Compute/galleries/$staging_gallery/images/$staging_definition"
staging_version_id="$staging_definition_id/versions/$staging_version"
snapshot_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Compute/snapshots/$snapshot_name"

if [[ "$command_name" != publish ]]; then
  jq -n \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg run_id "$GITHUB_RUN_ID" \
    --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
    --arg source_commit "$SOURCE_COMMIT" \
    --arg source_release_tag "$SOURCE_RELEASE_TAG" \
    --arg tool_commit "$TOOL_COMMIT" \
    --arg subscription_id "$AZURE_SUBSCRIPTION_ID" \
    --arg temporary_resource_group "$resource_group" \
    --arg target_owner "$TARGET_OWNER_TAG" \
    --arg target_resource_group "$TARGET_RESOURCE_GROUP" \
    --arg target_gallery "$TARGET_GALLERY" \
    --arg target_image_definition "$TARGET_IMAGE_DEFINITION" \
    --arg definition_id "$target_definition_id" \
    --arg version_id "$target_version_id" \
    --arg publication_lock "$PUBLICATION_LOCK_ID" \
    --arg publication_principal "$PUBLICATION_PRINCIPAL_CLIENT_ID" \
    --arg temporary_owner "$OWNER" \
    -c '{
      schema: 4,
      stage: "preparing",
      repository: $repository,
      run_id: $run_id,
      run_attempt: $run_attempt,
      source_commit: $source_commit,
      source_release_tag: $source_release_tag,
      tool_commit: $tool_commit,
      subscription_id: $subscription_id,
      temporary_resource_group: $temporary_resource_group,
      temporary_group_create: {
        status: "expected",
        resource_id: (
          "/subscriptions/" + $subscription_id + "/resourceGroups/" +
          $temporary_resource_group
        ),
        resource_name: $temporary_resource_group,
        owner_tag: $temporary_owner,
        repository: $repository,
        run_id: $run_id,
        run_attempt: $run_attempt,
        source_commit: $source_commit
      },
      temporary_resources: [],
      run_succeeded: false,
      outstanding_write_access: null,
      target: {
        owner_tag: $target_owner,
        resource_group: $target_resource_group,
        gallery: $target_gallery,
        image_definition: $target_image_definition,
        definition_id: $definition_id,
        version_id: $version_id,
        publication: {
          lock_id: $publication_lock,
          principal_client_id: $publication_principal,
          status: "not_dispatched"
        }
      }
    }' >"$STATE_FILE"
  [[ $(stat -c %s -- "$STATE_FILE") -le 16384 ]]
  chmod 0600 "$STATE_FILE"
fi

vhd="$RESULT_DIR/Ubuntu-24.04-x86_64.confidential.vhd"
vhd_info="$RESULT_DIR/vhd-info.json"
conversion="$RESULT_DIR/conversion.json"
sku_json="$RESULT_DIR/sku.json"
upload_disk_json="$RESULT_DIR/staging-managed-disk.json"
managed_image_json="$RESULT_DIR/staging-managed-image.json"
staging_definition_json="$RESULT_DIR/staging-definition.json"
staging_request="$RESULT_DIR/staging-gallery-request.json"
staging_response="$RESULT_DIR/staging-gallery-response.json"
staging_gallery_json="$RESULT_DIR/staging-gallery.json"
source_dir="$RESULT_DIR/source-validation"
capture_dir="$RESULT_DIR/capture"
final_dir="$RESULT_DIR/final-validation"
if [[ "$command_name" != publish ]]; then
  mkdir -p "$source_dir" "$capture_dir" "$final_dir"
  chmod 0700 "$source_dir" "$capture_dir" "$final_dir"
fi
private_key="$RESULT_DIR/id_ed25519"
known_hosts="$RESULT_DIR/known_hosts"
capture_result="$RESULT_DIR/capture-result.json"
prepare_evidence_manifest="$RESULT_DIR/prepare-evidence.sha256"
temporary_group_request="$RESULT_DIR/temporary-resource-group-request.json"
temporary_group_response="$RESULT_DIR/temporary-resource-group-response.json"
temporary_group_json="$RESULT_DIR/temporary-resource-group.json"
target_group_json="$RESULT_DIR/target-resource-group.json"
target_gallery_json="$RESULT_DIR/target-gallery.json"
target_definition_json="$RESULT_DIR/target-definition.json"
target_request="$RESULT_DIR/target-gallery-request.json"
target_response="$RESULT_DIR/target-gallery-response.json"
capture_vm_resource="$capture_dir/vm-resource.json"
capture_vm_instance="$capture_dir/vm-instance.json"
capture_disk_json="$capture_dir/os-disk.json"
snapshot_json="$capture_dir/snapshot.json"

exact_tags=(
  "miz-owner=$OWNER"
  "miz-repository=$GITHUB_REPOSITORY"
  "miz-run-id=$GITHUB_RUN_ID"
  "miz-run-attempt=$GITHUB_RUN_ATTEMPT"
  "miz-source-commit=$SOURCE_COMMIT"
)
UBUNTU2404_CONFIDENTIAL_GUEST_AZURE_TAGS=("${exact_tags[@]}")

tag_resource() {
  local resource_id=$1
  [[ "${resource_id,,}" == \
    "/subscriptions/${AZURE_SUBSCRIPTION_ID,,}/resourcegroups/${resource_group,,}/providers/"* ]] ||
    return 1
  az tag update \
    --operation Merge \
    --resource-id "$resource_id" \
    --tags "${exact_tags[@]}" \
    --output none
}

grant_disk_write_access() {
  local disk_id=$1 disk_group=$2 disk_name=$3 duration_seconds=$4
  local auth_header headers location request_dir response_body retry_after sas status token
  validate_write_access_identity "$disk_id" "$disk_group" "$disk_name" || {
    fail "Refusing to grant disk write access without exact run identity"
    return
  }
  state_replace \
    '.outstanding_write_access = {
      status: "pending",
      disk_id: $disk_id,
      resource_group: $disk_group,
      disk_name: $disk_name
    }' \
    --arg disk_id "$disk_id" \
    --arg disk_group "$disk_group" \
    --arg disk_name "$disk_name" ||
    {
      fail "Could not persist the pending disk write grant"
      return
    }
  request_dir="$RESULT_DIR/disk-access"
  rm -rf -- "$request_dir"
  mkdir -m 0700 "$request_dir"
  auth_header="$request_dir/auth-header"
  headers="$request_dir/headers"
  response_body="$request_dir/body"
  token=$(az account get-access-token \
    --resource https://management.azure.com/ \
    --query accessToken \
    --output tsv)
  [[ -n "$token" ]] || return 1
  (umask 077; printf 'Authorization: Bearer %s' "$token" >"$auth_header")
  token=
  status=$(curl \
    --silent --show-error --connect-timeout 30 --max-time 60 \
    --retry 3 --retry-max-time 120 \
    --dump-header "$headers" --output "$response_body" \
    --write-out '%{http_code}' --request POST \
    --header "@$auth_header" --header 'Content-Type: application/json' \
    --data "{\"access\":\"Write\",\"durationInSeconds\":$duration_seconds}" \
    "https://management.azure.com${disk_id}/beginGetAccess?api-version=2025-01-02")
  if [[ "$status" == 202 ]]; then
    location=$(awk -F: '
      tolower($1) == "location" {
        sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit
      }' "$headers")
    [[ "$location" == https://management.azure.com/* ]] || return 1
    for _ in {1..60}; do
      retry_after=$(awk -F: '
        tolower($1) == "retry-after" {
          sub(/^[^:]*:[[:space:]]*/, ""); sub(/\r$/, ""); print; exit
        }' "$headers")
      [[ "$retry_after" =~ ^[0-9]+$ ]] || retry_after=2
      (( retry_after >= 1 )) || retry_after=1
      (( retry_after <= 30 )) || retry_after=30
      sleep "$retry_after"
      status=$(curl \
        --silent --show-error --connect-timeout 30 --max-time 60 \
        --retry 3 --retry-max-time 120 \
        --dump-header "$headers" --output "$response_body" \
        --write-out '%{http_code}' --header "@$auth_header" "$location")
      [[ "$status" == 202 ]] || break
    done
  fi
  [[ "$status" == 200 ]] || return 1
  sas=$(jq -er '.accessSAS | strings | select(startswith("https://"))' "$response_body")
  if ! state_replace \
      '.outstanding_write_access.status = "active"'; then
    revoke_outstanding_disk_write_access ||
      fail "Failed to revoke a disk write grant after state promotion failed"
    return 1
  fi
  printf '%s\n' "$sas"
}

persist_temporary_group_create() {
  state_replace '.temporary_group_create.status = "pending"'
}

validate_temporary_group_document() {
  local metadata=$1
  validate_temporary_group_identity \
    "$metadata" "$temporary_group_id" "$resource_group" &&
    jq -e \
    --arg location "$AZURE_LOCATION" \
    '(.location | ascii_downcase) == ($location | ascii_downcase)' \
    "$metadata" >/dev/null &&
    exact_owned_tags_match "$metadata" "$OWNER" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"
}

validate_target_parents() {
  if ! publication_az group show --name "$TARGET_RESOURCE_GROUP" --output json \
      >"$target_group_json"; then
    fail "Pre-provisioned target resource group is missing or unavailable"
    return
  fi
  if ! publication_az sig show \
      --resource-group "$TARGET_RESOURCE_GROUP" \
      --gallery-name "$TARGET_GALLERY" \
      --output json >"$target_gallery_json"; then
    fail "Pre-provisioned target gallery is missing or unavailable"
    return
  fi
  if ! publication_az sig image-definition show \
      --ids "$target_definition_id" \
      --output json >"$target_definition_json"; then
    fail "Pre-provisioned target ConfidentialVM image definition is missing or unavailable"
    return
  fi
  jq -e \
    --arg expected_id "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$TARGET_RESOURCE_GROUP" \
    --arg name "$TARGET_RESOURCE_GROUP" \
    --arg location "$TARGET_LOCATION" \
    --arg owner "$TARGET_OWNER_TAG" \
    --arg repository "$GITHUB_REPOSITORY" \
    '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
     (.name | ascii_downcase) == ($name | ascii_downcase) and
     (.type | ascii_downcase) == "microsoft.resources/resourcegroups" and
     (.location | ascii_downcase) == ($location | ascii_downcase) and
     .tags["miz-owner"] == $owner and
     .tags["miz-repository"] == $repository' \
    "$target_group_json" >/dev/null ||
    {
      fail "Target resource group subscription, location, or durable ownership is invalid"
      return
    }
  jq -e \
    --arg expected_id "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$TARGET_RESOURCE_GROUP/providers/Microsoft.Compute/galleries/$TARGET_GALLERY" \
    --arg name "$TARGET_GALLERY" \
    --arg location "$TARGET_LOCATION" \
    --arg owner "$TARGET_OWNER_TAG" \
    --arg repository "$GITHUB_REPOSITORY" \
    '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
     .name == $name and
     (.type | ascii_downcase) == "microsoft.compute/galleries" and
     (.location | ascii_downcase) == ($location | ascii_downcase) and
     .tags["miz-owner"] == $owner and
     .tags["miz-repository"] == $repository' \
    "$target_gallery_json" >/dev/null ||
    {
      fail "Target gallery subscription, location, or durable ownership is invalid"
      return
    }
  validate_target_definition_identity \
    "$target_definition_json" "$target_definition_id" \
    "$TARGET_IMAGE_DEFINITION" ||
    {
      fail "Target image definition identity or name is invalid"
      return
    }
  jq -e \
    --arg location "$TARGET_LOCATION" \
    --arg owner "$TARGET_OWNER_TAG" \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg publisher "$TARGET_PUBLISHER" \
    --arg offer "$TARGET_OFFER" \
    --arg sku "$TARGET_SKU" \
    '(.location | ascii_downcase) == ($location | ascii_downcase) and
     .tags["miz-owner"] == $owner and
     .tags["miz-repository"] == $repository and
     .identifier == {
       publisher: $publisher,
       offer: $offer,
       sku: $sku
     } and
     .osType == "Linux" and
     .osState == "Generalized" and
     .hyperVGeneration == "V2" and
     .architecture == "x64" and
     .provisioningState == "Succeeded" and
     ([.features[]? | select(.name == "SecurityType")] == [{
       name: "SecurityType", value: "ConfidentialVM"
     }]) and
     ([paths as $path |
       select(($path[-1] | tostring | ascii_downcase) | contains("uefi"))] |
       length == 0)' \
    "$target_definition_json" >/dev/null ||
    {
      fail "Target image definition contract, durable ownership, or stock UEFI boundary is invalid"
      return
    }
  "$RELEASE_TOOL" check-capture-definition \
    --definition "$target_definition_json" \
    --subscription-id "$AZURE_SUBSCRIPTION_ID" \
    --location "$TARGET_LOCATION" \
    --snapshot-id "$snapshot_id" \
    --definition-id "$target_definition_id" \
    --version-id "$target_version_id" >/dev/null
}

require_target_version_absent() {
  local phase=$1 stderr_file
  stderr_file="$RESULT_DIR/target-version-${phase}.stderr"
  if publication_az sig image-version show \
      --ids "$target_version_id" --output json \
      >"$RESULT_DIR/target-version-${phase}.json" 2>"$stderr_file"; then
    rm -f -- "$stderr_file"
    fail "Target gallery version already exists; refusing update or overwrite"
    return
  fi
  if ! grep -Eq \
      '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' \
      "$stderr_file"; then
    fail "Could not prove the target gallery version is absent"
    return
  fi
  rm -f -- "$stderr_file"
}

require_target_version_absent_capture() {
  local phase=$1 stderr_file
  stderr_file="$RESULT_DIR/target-version-${phase}.stderr"
  if az sig image-version show \
      --ids "$target_version_id" --output json \
      >"$RESULT_DIR/target-version-${phase}.json" 2>"$stderr_file"; then
    rm -f -- "$stderr_file"
    fail "Target gallery version already exists; refusing update or overwrite"
    return
  fi
  if ! grep -Eq \
      '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' \
      "$stderr_file"; then
    fail "Capture principal could not prove the target gallery version is absent"
    return
  fi
  rm -f -- "$stderr_file"
}

quarantine_temporary_group_create() {
  state_replace '.temporary_group_create.status = "quarantined"' ||
    fail "Could not quarantine ambiguous temporary resource-group creation"
}

create_temporary_group() {
  persist_temporary_group_create ||
    {
      fail "Could not persist pending temporary resource-group creation"
      return
    }
  azure_confidential_vm_resource_group_create_args \
    "$temporary_group_id" "$temporary_group_request"
  if ! az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" \
      >"$temporary_group_response"; then
    quarantine_temporary_group_create
    fail "Temporary resource-group create failed ambiguously; manual review is required"
    return
  fi
  if ! validate_temporary_group_document "$temporary_group_response"; then
    quarantine_temporary_group_create
    fail "Temporary resource-group create response is invalid; manual review is required"
    return
  fi
  if ! az group show --name "$resource_group" --output json \
      >"$temporary_group_json"; then
    quarantine_temporary_group_create
    fail "Could not freshly inspect the created temporary resource group"
    return
  fi
  if ! validate_temporary_group_document "$temporary_group_json"; then
    quarantine_temporary_group_create
    fail "Created temporary resource group failed fresh ownership validation"
    return
  fi
  state_replace \
    '.temporary_group_create.status = "confirmed_created"' ||
    fail "Could not confirm temporary resource-group cleanup eligibility"
}

create_common_network() {
  local vnet_json="$RESULT_DIR/vnet.json" nsg_json="$RESULT_DIR/nsg.json"
  local vnet_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Network/virtualNetworks/$vnet_name"
  local nsg_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Network/networkSecurityGroups/$nsg_name"
  az network vnet create \
    --resource-group "$resource_group" \
    --name "$vnet_name" \
    --location "$AZURE_LOCATION" \
    --subnet-name "$subnet_name" \
    --tags "${exact_tags[@]}" \
    --output none
  az network vnet show \
    --resource-group "$resource_group" \
    --name "$vnet_name" \
    --output json >"$vnet_json"
  jq -e \
    --arg subnet "$subnet_name" \
    '[.subnets[]? | select(.name == $subnet)] | length == 1' \
    "$vnet_json" >/dev/null ||
    {
      fail "Created virtual network lacks the exact capture subnet"
      return
    }
  record_expected_resource \
    "$vnet_json" "$vnet_id" "Microsoft.Network/virtualNetworks" "$vnet_name"

  az network nsg create \
    --resource-group "$resource_group" \
    --name "$nsg_name" \
    --location "$AZURE_LOCATION" \
    --tags "${exact_tags[@]}" \
    --output none
  az network nsg show \
    --resource-group "$resource_group" \
    --name "$nsg_name" \
    --output json >"$nsg_json"
  record_expected_resource \
    "$nsg_json" "$nsg_id" "Microsoft.Network/networkSecurityGroups" "$nsg_name"
  az network nsg rule create \
    --resource-group "$resource_group" \
    --nsg-name "$nsg_name" \
    --name SSH \
    --priority 1000 \
    --direction Inbound \
    --access Allow \
    --protocol Tcp \
    --destination-port-ranges 22 \
    --output none
  az network nsg rule show \
    --resource-group "$resource_group" \
    --nsg-name "$nsg_name" \
    --name SSH \
    --query '{name:name,priority:priority,direction:direction,access:access,protocol:protocol,destinationPortRange:destinationPortRange}' \
    --output json >"$RESULT_DIR/nsg-ssh-rule.json"
  jq -e \
    '. == {
      name: "SSH",
      priority: 1000,
      direction: "Inbound",
      access: "Allow",
      protocol: "Tcp",
      destinationPortRange: "22"
    }' "$RESULT_DIR/nsg-ssh-rule.json" >/dev/null ||
    {
      fail "Created network security group lacks the exact SSH rule"
      return
    }
}

create_vm_network() {
  local public_ip_name=$1 nic_name=$2 prefix=$3
  local public_ip_json="$RESULT_DIR/${prefix}-public-ip.json"
  local nic_json="$RESULT_DIR/${prefix}-nic.json"
  local public_ip_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Network/publicIPAddresses/$public_ip_name"
  local nic_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Network/networkInterfaces/$nic_name"
  az network public-ip create \
    --resource-group "$resource_group" \
    --name "$public_ip_name" \
    --location "$AZURE_LOCATION" \
    --sku Standard \
    --allocation-method Static \
    --tags "${exact_tags[@]}" \
    --output none
  az network public-ip show \
    --resource-group "$resource_group" \
    --name "$public_ip_name" \
    --output json >"$public_ip_json"
  record_expected_resource \
    "$public_ip_json" "$public_ip_id" \
    "Microsoft.Network/publicIPAddresses" "$public_ip_name"
  az network nic create \
    --resource-group "$resource_group" \
    --name "$nic_name" \
    --location "$AZURE_LOCATION" \
    --vnet-name "$vnet_name" \
    --subnet "$subnet_name" \
    --network-security-group "$nsg_name" \
    --public-ip-address "$public_ip_name" \
    --tags "${exact_tags[@]}" \
    --output none
  az network nic show \
    --resource-group "$resource_group" \
    --name "$nic_name" \
    --output json >"$nic_json"
  jq -e \
    --arg subnet_id "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Network/virtualNetworks/$vnet_name/subnets/$subnet_name" \
    --arg nsg_id "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Network/networkSecurityGroups/$nsg_name" \
    --arg public_ip_id "$public_ip_id" \
    '(.networkSecurityGroup.id | ascii_downcase) ==
       ($nsg_id | ascii_downcase) and
     ([.ipConfigurations[]? |
       select(
         (.subnet.id | ascii_downcase) == ($subnet_id | ascii_downcase) and
         (.publicIPAddress.id | ascii_downcase) ==
           ($public_ip_id | ascii_downcase)
       )] | length == 1)' \
    "$nic_json" >/dev/null ||
    {
      fail "Created NIC does not bind the exact VNet, NSG, and public IP"
      return
    }
  record_expected_resource \
    "$nic_json" "$nic_id" "Microsoft.Network/networkInterfaces" "$nic_name"
  CREATED_NIC_ID=$nic_id
}

record_vm_and_os_disk() {
  local vm_json=$1 vm_name=$2 os_disk_name=$3 disk_json=$4
  local vm_id disk_id
  vm_id=$(jq -er '.id' "$vm_json")
  disk_id=$(jq -er '.storageProfile.osDisk.managedDisk.id' "$vm_json")
  [[ "$(jq -er '.storageProfile.osDisk.name' "$vm_json")" == "$os_disk_name" ]] ||
    {
      fail "Azure VM did not use the explicit OS disk name"
      return
    }
  record_expected_resource \
    "$vm_json" "$vm_id" "Microsoft.Compute/virtualMachines" "$vm_name"
  tag_resource "$disk_id"
  azure_confidential_vm_capture_disk_show_args "$disk_id"
  az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$disk_json"
  record_expected_resource \
    "$disk_json" "$disk_id" "Microsoft.Compute/disks" "$os_disk_name"
}

ubuntu2404_confidential_guest_record_created_data_disk() {
  local disk_group=$1 disk_name=$2 location=$3
  local disk_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$disk_group/providers/Microsoft.Compute/disks/$disk_name"
  local disk_json="$RESULT_DIR/${disk_name}.json"
  [[ "$disk_group" == "$resource_group" && "$location" == "$AZURE_LOCATION" ]] ||
    return 1
  az disk show --ids "$disk_id" --output json >"$disk_json"
  record_expected_resource \
    "$disk_json" "$disk_id" "Microsoft.Compute/disks" "$disk_name"
}

wait_gallery_version() {
  local response=$1 version_id=$2 provisioning replication states_file
  states_file="${response}.state"
  for _ in {1..180}; do
    if ! "$RELEASE_TOOL" capture-gallery-state \
        --response "$response" >"$states_file"; then
      fail "Could not validate the target gallery LRO response"
      return
    fi
    if ! readarray -t states <"$states_file" ||
        [[ ${#states[@]} -ne 2 ]]; then
      fail "Target gallery LRO state is malformed"
      return
    fi
    provisioning=${states[0]}
    replication=${states[1]}
    case "$provisioning" in
      Failed|Canceled)
        fail "Gallery image version entered $provisioning"
        return
        ;;
    esac
    case "$replication" in
      Failed|Canceled)
        fail "Gallery replication entered $replication"
        return
        ;;
    esac
    if jq -e '
        .properties.replicationStatus.summary[]?
        | select(.state == "Failed" or .state == "Canceled")
      ' "$response" >/dev/null; then
      fail "Gallery regional replication entered Failed or Canceled"
      return
    fi
    if [[ "$provisioning" == Succeeded && "$replication" == Completed ]]; then
      return
    fi
    sleep 10
    azure_confidential_vm_capture_gallery_version_get_args "$version_id"
    if ! publication_az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$response"; then
      fail "Target gallery LRO poll failed ambiguously; refusing to retry"
      return
    fi
  done
  fail "Gallery full replication did not complete before the deadline"
}

quarantine_target_publication() {
  state_replace '.target.publication.status = "quarantined"' ||
    fail "Could not persist target publication quarantine"
}

publish_target_version_once() {
  state_replace '.target.publication.status = "pending"' ||
    {
      fail "Could not persist pending target publication"
      return
    }
  azure_confidential_vm_capture_gallery_version_put_args \
    "$target_version_id" "$target_request"
  # Do not retry this upsert. A transport or LRO failure can leave a live
  # version even when the client cannot observe the final response.
  if ! publication_az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" \
      >"$target_response"; then
    quarantine_target_publication
    fail "Target version publication failed ambiguously; manual break-glass review is required"
    return
  fi
  if ! wait_gallery_version "$target_response" "$target_version_id"; then
    quarantine_target_publication
    fail "Target version publication did not reach a clear success; manual break-glass review is required"
    return
  fi
  if ! "$RELEASE_TOOL" check-capture-gallery \
      --request "$target_request" \
      --response "$target_response" \
      --subscription-id "$AZURE_SUBSCRIPTION_ID" \
      --location "$TARGET_LOCATION" \
      --snapshot-id "$snapshot_id" \
      --definition-id "$target_definition_id" \
      --version-id "$target_version_id"; then
    quarantine_target_publication
    fail "Published target version failed exact response validation"
    return
  fi
  # Provenance tags remain evidence to validate, not an atomic ownership or
  # cleanup boundary.
  if ! owned_tags_match "$target_response" "$OWNER" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"; then
    quarantine_target_publication
    fail "Target gallery version lost its exact run provenance tags"
    return
  fi
  state_replace '.target.publication.status = "published"' ||
    {
      fail "Could not persist successful target publication"
      return
    }
}

wait_source_gallery_version() {
  local response=$1 version_id=$2 state
  for _ in {1..120}; do
    state=$("$RELEASE_TOOL" gallery-state --response "$response")
    case "$state" in
      Succeeded) return ;;
      Failed|Canceled) fail "Staging gallery version entered $state"; return ;;
    esac
    sleep 10
    azure_trusted_launch_gallery_version_get_args "$version_id"
    az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$response"
  done
  fail "Staging gallery version did not provision before the deadline"
}

configure_vm_ssh() {
  local vm_name=$1
  local public_ip
  public_ip=$(az vm show \
    --resource-group "$resource_group" \
    --name "$vm_name" \
    --show-details \
    --query publicIps \
    --output tsv)
  [[ "$public_ip" =~ ^[0-9a-fA-F:.]+$ ]]
  rm -f -- "$known_hosts"
  ubuntu2404_confidential_guest_configure_ssh \
    "$private_key" "$known_hosts" "$admin_username" "$public_ip"
}

refresh_maa_metadata() {
  local openid=$1 jwks=$2 jwks_uri
  curl --fail --silent --show-error \
    --output "$openid" \
    "$ATTESTATION_ENDPOINT/.well-known/openid-configuration"
  jwks_uri=$(jq -er '.jwks_uri | select(type == "string")' "$openid")
  [[ "$jwks_uri" == "$ATTESTATION_ENDPOINT/certs" ]]
  curl --fail --silent --show-error --output "$jwks" "$jwks_uri"
}

collect_vm_contract() {
  local vm_name=$1 resource=$2 instance=$3
  azure_confidential_vm_capture_vm_resource_args "$resource_group" "$vm_name"
  az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$resource"
  azure_confidential_vm_vm_instance_security_args "$resource_group" "$vm_name"
  az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$instance"
}

collect_acceptance_vm_contract() {
  local vm_name=$1 resource=$2 instance=$3
  azure_confidential_vm_vm_resource_args "$resource_group" "$vm_name"
  az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$resource"
  azure_confidential_vm_vm_instance_security_args "$resource_group" "$vm_name"
  az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$instance"
}

run_capture_vm_check() {
  local vm_json=$1 vm_id=$2 disk_id=$3
  "$RELEASE_TOOL" check-capture-vm \
    --vm "$vm_json" \
    --source-acceptance "$SOURCE_ACCEPTANCE" \
    --provenance "$PROVENANCE" \
    --qcow "$CANDIDATE" \
    --source-commit "$SOURCE_COMMIT" \
    --vm-size "$SOURCE_VM_SIZE" \
    --run-id "$SOURCE_RUN_ID" \
    --run-attempt "$SOURCE_RUN_ATTEMPT" \
    --repository "$SOURCE_REPOSITORY" \
    --capture-run-id "$GITHUB_RUN_ID" \
    --capture-run-attempt "$GITHUB_RUN_ATTEMPT" \
    --scratch-resource-group "$resource_group" \
    --subscription-id "$AZURE_SUBSCRIPTION_ID" \
    --location "$AZURE_LOCATION" \
    --source-version-id "$staging_version_id" \
    --staging-disk "$upload_disk_json" \
    --staging-managed-image "$managed_image_json" \
    --staging-definition "$staging_definition_json" \
    --staging-gallery-request "$staging_request" \
    --staging-gallery-response "$staging_response" \
    --vm-id "$vm_id" \
    --disk-id "$disk_id"
}

prepared_file_is_safe() {
  local path=$1 metadata owner mode size extra
  [[ -f "$path" && ! -L "$path" ]] || return 1
  metadata=$(stat -c '%u %a %s' -- "$path") || return 1
  IFS=' ' read -r owner mode size extra <<<"$metadata" || return 1
  [[ -z "$extra" && "$owner" == "$EUID" &&
      "$mode" =~ ^[0-7]{3,4}$ && "$size" =~ ^[1-9][0-9]*$ ]] || return 1
  (( (8#$mode & 077) == 0 ))
}

require_prepared_state() {
  state_file_is_safe && state_matches_identity ||
    {
      fail "Prepared capture recovery state is invalid"
      return
    }
  jq -e '
    .stage == "prepared" and
    .run_succeeded == false and
    .outstanding_write_access == null and
    .temporary_group_create.status == "confirmed_created" and
    .target.publication.status == "not_dispatched"
  ' "$STATE_FILE" >/dev/null ||
    {
      fail "Capture recovery state is not exactly prepared"
      return
    }
  for directory in \
      "$(dirname -- "$STATE_FILE")" "$(dirname -- "$CANDIDATE")" \
      "$RESULT_DIR" "$source_dir" "$capture_dir" "$final_dir"; do
    private_directory_is_safe "$directory" ||
      {
        fail "Prepared capture evidence directory is not owner-only"
        return
      }
  done
  [[ -z $(find "$RESULT_DIR" -type l -print -quit) ]] ||
    {
      fail "Prepared capture evidence contains a symbolic link"
      return
    }
  local path
  for path in \
      "$CANDIDATE" "$PROVENANCE" "$SOURCE_ACCEPTANCE" \
      "$upload_disk_json" "$managed_image_json" "$staging_definition_json" \
      "$staging_request" "$staging_response" "$capture_vm_resource" \
      "$capture_vm_instance" "$capture_disk_json" "$snapshot_json" \
      "$target_request" "$private_key" "$private_key.pub" \
      "$prepare_evidence_manifest"; do
    prepared_file_is_safe "$path" ||
      {
        fail "Prepared capture evidence is missing, empty, linked, or not owner-only"
        return
      }
  done
  sha256sum --check --status "$prepare_evidence_manifest" ||
    {
      fail "Prepared capture evidence changed after the prepare transition"
      return
    }
}

persist_prepared_state() {
  chmod -R go-rwx -- "$RESULT_DIR"
  chmod go-rwx -- "$CANDIDATE" "$PROVENANCE" "$SOURCE_ACCEPTANCE"
  sha256sum \
    "$CANDIDATE" \
    "$PROVENANCE" \
    "$SOURCE_ACCEPTANCE" \
    "$upload_disk_json" \
    "$managed_image_json" \
    "$staging_definition_json" \
    "$staging_request" \
    "$staging_response" \
    "$capture_vm_resource" \
    "$capture_vm_instance" \
    "$capture_disk_json" \
    "$snapshot_json" \
    "$target_request" \
    "$private_key" \
    "$private_key.pub" >"$prepare_evidence_manifest"
  chmod 0600 "$prepare_evidence_manifest"
  state_replace '.stage = "prepared"' ||
    fail "Could not persist the exact prepared capture transition"
  require_prepared_state
  printf 'MIZ_CAPTURE_STAGE=prepared\n'
}

cleanup_on_exit() {
  local status=$? cleanup_status=0
  trap - EXIT INT TERM
  ubuntu2404_confidential_guest_cleanup_validation_files || cleanup_status=1
  rm -f -- "$vhd" "$private_key" "$private_key.pub" "$known_hosts"
  rm -rf -- "$RESULT_DIR/disk-access" \
    "$source_dir/attestation-client" "$final_dir/attestation-client"
  rm -f -- \
    "$source_dir/azguestattestation1.deb" "$source_dir/attestation-client.zip" \
    "$final_dir/azguestattestation1.deb" "$final_dir/attestation-client.zip"
  cleanup_resources || cleanup_status=1
  if (( cleanup_status != 0 && status == 0 )); then
    status=1
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

if [[ "$command_name" != publish ]]; then
  require_target_version_absent_capture prepare

# The random 128-bit suffix makes collision with an unrelated group
# cryptographically negligible. Resource Group PUT remains an ordinary upsert,
# so only an unambiguous response plus a fresh exact GET authorizes cleanup.
group_exists=$(az group exists --name "$resource_group" --output tsv)
case "$group_exists" in
  false) ;;
  true) fail "Refusing to reuse temporary resource group $resource_group"; exit 1 ;;
  *) fail "Azure returned an invalid resource-group existence result"; exit 1 ;;
esac
jq -n \
  --arg location "$AZURE_LOCATION" \
  --arg owner "$OWNER" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  '{
    location: $location,
    tags: {
      "miz-owner": $owner,
      "miz-repository": $repository,
      "miz-run-id": $run_id,
      "miz-run-attempt": $run_attempt,
      "miz-source-commit": $source_commit
    }
  }' >"$temporary_group_request"
create_temporary_group

accepted_identity_file="$RESULT_DIR/accepted-identity.txt"
"$RELEASE_TOOL" verify-acceptance \
  --result "$SOURCE_ACCEPTANCE" \
  --provenance "$PROVENANCE" \
  --qcow "$CANDIDATE" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$SOURCE_LOCATION" \
  --vm-size "$SOURCE_VM_SIZE" \
  --run-id "$SOURCE_RUN_ID" \
  --run-attempt "$SOURCE_RUN_ATTEMPT" >"$accepted_identity_file"
readarray -t accepted_identity <"$accepted_identity_file"
[[ ${#accepted_identity[@]} -eq 3 ]]
qcow_sha256=${accepted_identity[0]}
qcow_bytes=${accepted_identity[1]}
virtual_size=${accepted_identity[2]}
accepted_source_version_id=$(
  jq -er '.azure.gallery_image_version_id | select(type == "string")' \
    "$SOURCE_ACCEPTANCE"
)
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ &&
    "$qcow_bytes" =~ ^[1-9][0-9]*$ &&
    "$virtual_size" =~ ^[1-9][0-9]*$ &&
    "${accepted_source_version_id,,}" == "/subscriptions/${AZURE_SUBSCRIPTION_ID,,}/"* ]] ||
  fail "Accepted source identity is malformed or cross-subscription"

"$MIZ" azure derive \
  --input-sha256 "$qcow_sha256" \
  --expected-virtual-size "$virtual_size" \
  "$CANDIDATE" "$vhd"
qemu-img info -f vpc --output=json "$vhd" >"$vhd_info"
vhd_identity_file="$RESULT_DIR/vhd-identity.txt"
"$RELEASE_TOOL" verify-vhd \
  --provenance "$PROVENANCE" \
  --qcow "$CANDIDATE" \
  --vhd "$vhd" \
  --info "$vhd_info" \
  --output "$conversion" >"$vhd_identity_file"
readarray -t vhd_identity <"$vhd_identity_file"
[[ ${#vhd_identity[@]} -eq 3 ]]
vhd_current_size=${vhd_identity[0]}
vhd_bytes=${vhd_identity[1]}
vhd_sha256=${vhd_identity[2]}
[[ "$vhd_current_size" == "$virtual_size" &&
    "$vhd_bytes" =~ ^[1-9][0-9]*$ &&
    "$vhd_sha256" =~ ^[0-9a-f]{64}$ ]]
jq -e \
  --arg qcow_sha256 "$qcow_sha256" \
  --argjson qcow_size "$qcow_bytes" \
  --arg vhd_sha256 "$vhd_sha256" \
  --argjson vhd_size "$vhd_bytes" \
  --argjson virtual_size "$virtual_size" \
  '.artifact.qcow_sha256 == $qcow_sha256 and
   .artifact.qcow_size == $qcow_size and
   .artifact.vhd_sha256 == $vhd_sha256 and
   .artifact.vhd_size == $vhd_size and
   .artifact.virtual_size == $virtual_size' \
  "$SOURCE_ACCEPTANCE" >/dev/null ||
  fail "Re-derived VHD does not exactly match the released accepted artifact"
chmod 0444 "$vhd"

azure_confidential_vm_sku_list_args "$AZURE_LOCATION" "$AZURE_VM_SIZE"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$sku_json"
"$RELEASE_TOOL" check-sku --sku "$sku_json" --vm-size "$AZURE_VM_SIZE" >/dev/null

azure_trusted_launch_disk_create_args \
  "$resource_group" "$upload_disk_name" "$AZURE_LOCATION" "$vhd_bytes" x64
AZURE_TRUSTED_LAUNCH_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
azure_trusted_launch_disk_show_args "$resource_group" "$upload_disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$upload_disk_json"
upload_disk_id=$("$RELEASE_TOOL" check-managed-disk --disk "$upload_disk_json")
record_expected_resource \
  "$upload_disk_json" "$upload_disk_id" "Microsoft.Compute/disks" \
  "$upload_disk_name"
upload_sas=$(
  grant_disk_write_access \
    "$upload_disk_id" "$resource_group" "$upload_disk_name" 7200
)
[[ "$upload_sas" == https://* ]]
azcopy copy "$vhd" "$upload_sas" --blob-type PageBlob
upload_sas=
revoke_outstanding_disk_write_access
azure_trusted_launch_disk_show_args "$resource_group" "$upload_disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$upload_disk_json"
[[ "$("$RELEASE_TOOL" check-managed-disk --disk "$upload_disk_json")" == "$upload_disk_id" ]]

azure_confidential_vm_managed_image_create_args \
  "$resource_group" "$managed_image_name" "$AZURE_LOCATION" "$upload_disk_id"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_managed_image_show_args "$resource_group" "$managed_image_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$managed_image_json"
managed_image_id=$(
  "$RELEASE_TOOL" check-managed-image \
    --image "$managed_image_json" \
    --disk-id "$upload_disk_id"
)
record_expected_resource \
  "$managed_image_json" "$managed_image_id" "Microsoft.Compute/images" \
  "$managed_image_name"

azure_trusted_launch_gallery_create_args "$resource_group" "$staging_gallery" "$AZURE_LOCATION"
AZURE_TRUSTED_LAUNCH_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
az sig show \
  --resource-group "$resource_group" \
  --gallery-name "$staging_gallery" \
  --output json >"$staging_gallery_json"
record_expected_resource \
  "$staging_gallery_json" \
  "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Compute/galleries/$staging_gallery" \
  "Microsoft.Compute/galleries" "$staging_gallery"
azure_confidential_vm_image_definition_create_args \
  "$resource_group" "$staging_gallery" "$staging_definition" ubuntu2404 \
  confidential-source-x64 "$AZURE_LOCATION"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_image_definition_show_args \
  "$resource_group" "$staging_gallery" "$staging_definition"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$staging_definition_json"
[[ "$("$RELEASE_TOOL" check-image-definition --definition "$staging_definition_json")" == "$staging_definition_id" ]]
record_expected_resource \
  "$staging_definition_json" "$staging_definition_id" \
  "Microsoft.Compute/galleries/images" "$staging_definition" \
  "$staging_gallery/$staging_definition"

"$RELEASE_TOOL" gallery-request \
  --output "$staging_request" \
  --location "$AZURE_LOCATION" \
  --source-id "$managed_image_id"
source_acceptance_sha256=$(sha256sum "$SOURCE_ACCEPTANCE" | awk '{print $1}')
jq \
  --arg owner "$OWNER" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg qcow_sha256 "$qcow_sha256" \
  --arg vhd_sha256 "$vhd_sha256" \
  --arg source_acceptance_sha256 "$source_acceptance_sha256" \
  '.tags = {
    "miz-owner": $owner,
    "miz-repository": $repository,
    "miz-run-id": $run_id,
    "miz-run-attempt": $run_attempt,
    "miz-source-commit": $source_commit,
    "miz-qcow-sha256": $qcow_sha256,
    "miz-vhd-sha256": $vhd_sha256,
    "miz-source-acceptance-sha256": $source_acceptance_sha256
  }' "$staging_request" >"${staging_request}.tagged"
mv -f -- "${staging_request}.tagged" "$staging_request"
azure_trusted_launch_gallery_version_put_args "$staging_version_id" "$staging_request"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$staging_response"
wait_source_gallery_version "$staging_response" "$staging_version_id"
"$RELEASE_TOOL" check-gallery \
  --request "$staging_request" \
  --response "$staging_response" \
  --image-version-id "$staging_version_id" \
  --source-id "$managed_image_id"
jq -e \
  --arg owner "$OWNER" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg qcow_sha256 "$qcow_sha256" \
  --arg vhd_sha256 "$vhd_sha256" \
  --arg source_acceptance_sha256 "$source_acceptance_sha256" \
  '.tags["miz-owner"] == $owner and
   .tags["miz-repository"] == $repository and
   .tags["miz-run-id"] == $run_id and
   .tags["miz-run-attempt"] == $run_attempt and
   .tags["miz-source-commit"] == $source_commit and
   .tags["miz-qcow-sha256"] == $qcow_sha256 and
   .tags["miz-vhd-sha256"] == $vhd_sha256 and
   .tags["miz-source-acceptance-sha256"] == $source_acceptance_sha256' \
  "$staging_response" >/dev/null ||
  fail "Staging gallery version lost its exact artifact and ownership binding"
record_expected_resource \
  "$staging_response" "$staging_version_id" \
  "Microsoft.Compute/galleries/images/versions" "$staging_version" \
  "$staging_gallery/$staging_definition/$staging_version"

ssh-keygen -q -t ed25519 -N '' -f "$private_key"
create_common_network
create_vm_network "$source_public_ip_name" "$source_nic_name" source
source_nic_id=$CREATED_NIC_ID

source_vm_resource="$source_dir/vm-resource.json"
source_vm_instance="$source_dir/vm-instance.json"
source_guest_imds="$source_dir/guest-imds.json"
source_token="$source_dir/attestation.jwt"
source_openid="$source_dir/openid-configuration.json"
source_jwks="$source_dir/jwks.json"
azure_confidential_vm_vm_create_args \
  "$resource_group" "$source_vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$staging_version_id" "$admin_username" "$private_key.pub" true \
  "$source_nic_id" "$source_os_disk_name"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$source_dir/vm-create.json"
collect_vm_contract \
  "$source_vm_name" "$source_dir/vm-full-resource.json" \
  "$source_dir/vm-full-instance.json"
record_vm_and_os_disk \
  "$source_dir/vm-full-resource.json" "$source_vm_name" \
  "$source_os_disk_name" "$source_dir/os-disk.json"
collect_acceptance_vm_contract \
  "$source_vm_name" "$source_vm_resource" "$source_vm_instance"
source_vm_resource_id=$(jq -er '.id' "$source_vm_resource")
source_vm_unique_id=$(jq -er '.vmId' "$source_vm_resource")
source_checked_file="$source_dir/checked-identity.txt"
"$RELEASE_TOOL" check-vm \
  --resource "$source_vm_resource" \
  --instance "$source_vm_instance" \
  --image-version-id "$staging_version_id" >"$source_checked_file"
readarray -t source_checked <"$source_checked_file"
[[ ${#source_checked[@]} -eq 2 &&
    "${source_checked[0]}" == "$source_vm_resource_id" &&
    "${source_checked[1],,}" == "${source_vm_unique_id,,}" ]]
configure_vm_ssh "$source_vm_name"
source_nonce=$(openssl rand -hex 32)
ubuntu2404_confidential_guest_final_acceptance \
  "$virtual_size" "$source_vm_unique_id" "$source_guest_imds" \
  "$ATTESTATION_ENDPOINT" "$source_nonce" "$source_dir" \
  "$source_token" "$source_openid" "$source_jwks" \
  "$source_dir/attestation-client.stderr" \
  "$resource_group" "$source_vm_name" "$source_data_disk_name" "$AZURE_LOCATION"
[[ "${UBUNTU2404_CONFIDENTIAL_GUEST_VM_ID,,}" == "${source_vm_unique_id,,}" ]]
refresh_maa_metadata "$source_openid" "$source_jwks"
"$RELEASE_TOOL" verify-attestation \
  --token "$source_token" \
  --openid "$source_openid" \
  --jwks "$source_jwks" \
  --endpoint "$ATTESTATION_ENDPOINT" \
  --nonce "$source_nonce" \
  --vm-id "$source_vm_unique_id" \
  --now "$(date +%s)" >"$source_dir/attestation-verification.txt"
readarray -t source_attestation_identity \
  <"$source_dir/attestation-verification.txt"
[[ ${#source_attestation_identity[@]} -eq 3 &&
    "${source_attestation_identity[0]}" == "$ATTESTATION_ENDPOINT" &&
    "${source_attestation_identity[1]}" =~ ^[0-9a-f]{64}$ &&
    "${source_attestation_identity[2]}" =~ ^[0-9a-f]{64}$ ]]

capture_vm_resource="$capture_dir/vm-resource.json"
capture_vm_instance="$capture_dir/vm-instance.json"
capture_disk_json="$capture_dir/os-disk.json"
capture_guest_imds="$capture_dir/guest-imds.json"
create_vm_network "$capture_public_ip_name" "$capture_nic_name" capture
capture_nic_id=$CREATED_NIC_ID
azure_confidential_vm_vm_create_args \
  "$resource_group" "$capture_vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$staging_version_id" "$admin_username" "$private_key.pub" true \
  "$capture_nic_id" "$capture_os_disk_name"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$capture_dir/vm-create.json"
collect_vm_contract "$capture_vm_name" "$capture_vm_resource" "$capture_vm_instance"
record_vm_and_os_disk \
  "$capture_vm_resource" "$capture_vm_name" "$capture_os_disk_name" \
  "$capture_disk_json"
capture_vm_id=$(jq -er '.id' "$capture_vm_resource")
capture_vm_unique_id=$(jq -er '.vmId' "$capture_vm_resource")
capture_disk_id=$(jq -er '.storageProfile.osDisk.managedDisk.id' "$capture_vm_resource")
run_capture_vm_check "$capture_vm_resource" "$capture_vm_id" "$capture_disk_id" >/dev/null
azure_confidential_vm_capture_disk_show_args "$capture_disk_id"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$capture_disk_json"
[[ "$("$RELEASE_TOOL" check-capture-disk \
  --disk "$capture_disk_json" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --source-version-id "$staging_version_id" \
  --vm-id "$capture_vm_id" \
  --disk-id "$capture_disk_id")" == "$capture_disk_id" ]]

configure_vm_ssh "$capture_vm_name"
ubuntu2404_confidential_guest_pre_capture_check \
  "$virtual_size" "$capture_vm_unique_id" "$capture_guest_imds"

deprovision_and_schedule_shutdown() {
  local proof
  if ! proof=$(ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
      "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
      "sudo -n -- sh -c 'set -eu; waagent -deprovision+user -force >/dev/null; shutdown -h +1 >/dev/null; printf \"%s\\\\n\" MIZ_DEPROVISION_SHUTDOWN_SCHEDULED'"); then
    fail "Capture VM deprovision and shutdown scheduling failed"
    return
  fi
  [[ "$proof" == MIZ_DEPROVISION_SHUTDOWN_SCHEDULED ]] || {
    fail "Capture VM did not prove deprovision and shutdown scheduling succeeded"
    return
  }
}

deprovision_and_schedule_shutdown

shutdown_power_state=
for _ in {1..90}; do
  shutdown_power_state=$(az vm get-instance-view \
    --resource-group "$resource_group" \
    --name "$capture_vm_name" \
    --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" \
    --output tsv)
  if [[ "$shutdown_power_state" == PowerState/stopped ||
        "$shutdown_power_state" == PowerState/deallocated ]]; then
    break
  fi
  sleep 5
done
[[ "$shutdown_power_state" == PowerState/stopped ||
    "$shutdown_power_state" == PowerState/deallocated ]] ||
  fail "Azure did not report a stopped capture VM after guest shutdown"

azure_confidential_vm_deallocate_args "$resource_group" "$capture_vm_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
power_state=
for _ in {1..120}; do
  power_state=$(az vm get-instance-view \
    --resource-group "$resource_group" \
    --name "$capture_vm_name" \
    --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" \
    --output tsv)
  [[ "$power_state" == PowerState/deallocated ]] && break
  sleep 5
done
[[ "$power_state" == PowerState/deallocated ]] ||
  fail "Capture VM did not reach PowerState/deallocated"

azure_confidential_vm_generalize_args "$resource_group" "$capture_vm_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_capture_disk_show_args "$capture_disk_id"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$capture_disk_json"
[[ "$("$RELEASE_TOOL" check-capture-disk \
  --disk "$capture_disk_json" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --source-version-id "$staging_version_id" \
  --vm-id "$capture_vm_id" \
  --disk-id "$capture_disk_id")" == "$capture_disk_id" ]]

snapshot_json="$capture_dir/snapshot.json"
azure_confidential_vm_snapshot_create_args \
  "$resource_group" "$snapshot_name" "$AZURE_LOCATION" "$capture_disk_id"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_snapshot_show_args "$resource_group" "$snapshot_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$snapshot_json"
[[ "$("$RELEASE_TOOL" check-capture-snapshot \
  --snapshot "$snapshot_json" \
  --snapshot-id "$snapshot_id" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --source-version-id "$staging_version_id" \
  --vm-id "$capture_vm_id" \
  --disk-id "$capture_disk_id")" == "$snapshot_id" ]]
owned_tags_match "$snapshot_json" "$OWNER" "$GITHUB_REPOSITORY" \
  "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT" ||
  fail "Capture snapshot lost its exact run ownership tags"
record_expected_resource \
  "$snapshot_json" "$snapshot_id" "Microsoft.Compute/snapshots" "$snapshot_name"

"$RELEASE_TOOL" capture-gallery-request \
  --output "$target_request" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$TARGET_LOCATION" \
  --snapshot-id "$snapshot_id" \
  --definition-id "$target_definition_id" \
  --version-id "$target_version_id"
jq \
  --arg owner "$OWNER" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  '.tags = {
    "miz-owner": $owner,
    "miz-repository": $repository,
    "miz-run-id": $run_id,
    "miz-run-attempt": $run_attempt,
    "miz-source-commit": $source_commit
  }' "$target_request" >"${target_request}.tagged"
mv -f -- "${target_request}.tagged" "$target_request"

rm -f -- "$vhd" "$known_hosts"
rm -rf -- "$source_dir"
mkdir -m 0700 "$source_dir"
persist_prepared_state
if [[ "$command_name" == prepare ]]; then
  trap - EXIT INT TERM
  exit 0
fi
else
  require_prepared_state
fi

require_publication_account

accepted_identity_file="$RESULT_DIR/accepted-identity.txt"
"$RELEASE_TOOL" verify-acceptance \
  --result "$SOURCE_ACCEPTANCE" \
  --provenance "$PROVENANCE" \
  --qcow "$CANDIDATE" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$SOURCE_LOCATION" \
  --vm-size "$SOURCE_VM_SIZE" \
  --run-id "$SOURCE_RUN_ID" \
  --run-attempt "$SOURCE_RUN_ATTEMPT" >"$accepted_identity_file"
readarray -t accepted_identity <"$accepted_identity_file"
[[ ${#accepted_identity[@]} -eq 3 ]]
qcow_sha256=${accepted_identity[0]}
qcow_bytes=${accepted_identity[1]}
virtual_size=${accepted_identity[2]}
vhd_sha256=$(jq -er '.artifact.vhd_sha256' "$SOURCE_ACCEPTANCE")
vhd_bytes=$(jq -er '.artifact.vhd_size' "$SOURCE_ACCEPTANCE")
source_acceptance_sha256=$(sha256sum "$SOURCE_ACCEPTANCE" | awk '{print $1}')
upload_disk_id=$("$RELEASE_TOOL" check-managed-disk --disk "$upload_disk_json")
managed_image_id=$(
  "$RELEASE_TOOL" check-managed-image \
    --image "$managed_image_json" \
    --disk-id "$upload_disk_id"
)
[[ "$("$RELEASE_TOOL" check-image-definition \
  --definition "$staging_definition_json")" == "$staging_definition_id" ]]
"$RELEASE_TOOL" check-gallery \
  --request "$staging_request" \
  --response "$staging_response" \
  --image-version-id "$staging_version_id" \
  --source-id "$managed_image_id"
capture_vm_id=$(jq -er '.id' "$capture_vm_resource")
capture_disk_id=$(jq -er '.storageProfile.osDisk.managedDisk.id' "$capture_vm_resource")
run_capture_vm_check "$capture_vm_resource" "$capture_vm_id" "$capture_disk_id" \
  >/dev/null
azure_confidential_vm_capture_snapshot_show_args \
  "$resource_group" "$snapshot_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$snapshot_json"
[[ "$("$RELEASE_TOOL" check-capture-snapshot \
  --snapshot "$snapshot_json" \
  --snapshot-id "$snapshot_id" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --source-version-id "$staging_version_id" \
  --vm-id "$capture_vm_id" \
  --disk-id "$capture_disk_id")" == "$snapshot_id" ]]
owned_tags_match "$snapshot_json" "$OWNER" "$GITHUB_REPOSITORY" \
  "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT" ||
  fail "Prepared capture snapshot lost its exact run ownership tags"

expected_target_request="$RESULT_DIR/target-gallery-request.expected.json"
"$RELEASE_TOOL" capture-gallery-request \
  --output "$expected_target_request" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$TARGET_LOCATION" \
  --snapshot-id "$snapshot_id" \
  --definition-id "$target_definition_id" \
  --version-id "$target_version_id"
jq \
  --arg owner "$OWNER" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  '.tags = {
    "miz-owner": $owner,
    "miz-repository": $repository,
    "miz-run-id": $run_id,
    "miz-run-attempt": $run_attempt,
    "miz-source-commit": $source_commit
  }' "$expected_target_request" >"${expected_target_request}.tagged"
mv -f -- "${expected_target_request}.tagged" "$expected_target_request"
cmp -s "$expected_target_request" "$target_request" ||
  fail "Prepared target gallery request does not match protected target identity"
rm -f -- "$expected_target_request"

# Revalidate all durable parents and the exact version absence at the final
# mutation boundary. The remaining check-to-PUT race is controlled only by the
# stable workflow lock and exclusive least-privilege publisher principal.
validate_target_parents
require_target_version_absent pre-put
state_replace '.stage = "publishing"' ||
  fail "Could not persist the exact publishing transition"
printf 'MIZ_CAPTURE_STAGE=publishing\n'
publish_target_version_once

final_vm_resource="$final_dir/vm-resource.json"
final_vm_instance="$final_dir/vm-instance.json"
final_guest_imds="$final_dir/guest-imds.json"
final_token="$final_dir/attestation.jwt"
final_openid="$final_dir/openid-configuration.json"
final_jwks="$final_dir/jwks.json"
create_vm_network "$final_public_ip_name" "$final_nic_name" final
final_nic_id=$CREATED_NIC_ID
azure_confidential_vm_captured_vm_create_args \
  "$resource_group" "$final_vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$target_version_id" "$admin_username" "$private_key.pub" true \
  "$final_nic_id" "$final_os_disk_name"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$final_dir/vm-create.json"
collect_vm_contract "$final_vm_name" "$final_vm_resource" "$final_vm_instance"
record_vm_and_os_disk \
  "$final_vm_resource" "$final_vm_name" "$final_os_disk_name" \
  "$final_dir/os-disk.json"
final_vm_id=$(jq -er '.id' "$final_vm_resource")
final_vm_unique_id=$(jq -er '.vmId' "$final_vm_resource")
final_disk_id=$(jq -er '.storageProfile.osDisk.managedDisk.id' "$final_vm_resource")
"$RELEASE_TOOL" check-captured-vm \
  --vm "$final_vm_resource" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --version-id "$target_version_id" \
  --vm-id "$final_vm_id" \
  --disk-id "$final_disk_id" >/dev/null

configure_vm_ssh "$final_vm_name"
final_nonce=$(openssl rand -hex 32)
ubuntu2404_confidential_guest_final_acceptance \
  "$virtual_size" "$final_vm_unique_id" "$final_guest_imds" \
  "$ATTESTATION_ENDPOINT" "$final_nonce" "$final_dir" \
  "$final_token" "$final_openid" "$final_jwks" \
  "$final_dir/attestation-client.stderr" \
  "$resource_group" "$final_vm_name" "$final_data_disk_name" "$AZURE_LOCATION"
final_guest_vm_id=$UBUNTU2404_CONFIDENTIAL_GUEST_VM_ID

# Refresh every live Azure document and both public MAA documents at one
# evidence boundary. The result and verifier consume these exact revisions.
azure_trusted_launch_disk_show_args "$resource_group" "$upload_disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$upload_disk_json"
azure_confidential_vm_managed_image_show_args \
  "$resource_group" "$managed_image_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$managed_image_json"
azure_confidential_vm_image_definition_show_args \
  "$resource_group" "$staging_gallery" "$staging_definition"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$staging_definition_json"
azure_trusted_launch_gallery_version_get_args "$staging_version_id"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$staging_response"
collect_vm_contract "$capture_vm_name" "$capture_vm_resource" "$capture_vm_instance"
azure_confidential_vm_capture_disk_show_args "$capture_disk_id"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$capture_disk_json"
azure_confidential_vm_snapshot_show_args "$resource_group" "$snapshot_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$snapshot_json"
azure_confidential_vm_capture_image_definition_show_args \
  "$TARGET_RESOURCE_GROUP" "$TARGET_GALLERY" "$TARGET_IMAGE_DEFINITION"
publication_az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$target_definition_json"
azure_confidential_vm_capture_gallery_version_get_args "$target_version_id"
publication_az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$target_response"
collect_vm_contract "$final_vm_name" "$final_vm_resource" "$final_vm_instance"
refresh_maa_metadata "$final_openid" "$final_jwks"

[[ "$("$RELEASE_TOOL" check-managed-disk --disk "$upload_disk_json")" == "$upload_disk_id" ]]
[[ "$("$RELEASE_TOOL" check-managed-image \
  --image "$managed_image_json" \
  --disk-id "$upload_disk_id")" == "$managed_image_id" ]]
[[ "$("$RELEASE_TOOL" check-image-definition \
  --definition "$staging_definition_json")" == "$staging_definition_id" ]]
"$RELEASE_TOOL" check-gallery \
  --request "$staging_request" \
  --response "$staging_response" \
  --image-version-id "$staging_version_id" \
  --source-id "$managed_image_id"
jq -e \
  --arg owner "$OWNER" \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg qcow_sha256 "$qcow_sha256" \
  --arg vhd_sha256 "$vhd_sha256" \
  --arg source_acceptance_sha256 "$source_acceptance_sha256" \
  '.tags["miz-owner"] == $owner and
   .tags["miz-repository"] == $repository and
   .tags["miz-run-id"] == $run_id and
   .tags["miz-run-attempt"] == $run_attempt and
   .tags["miz-source-commit"] == $source_commit and
   .tags["miz-qcow-sha256"] == $qcow_sha256 and
   .tags["miz-vhd-sha256"] == $vhd_sha256 and
   .tags["miz-source-acceptance-sha256"] == $source_acceptance_sha256' \
  "$staging_response" >/dev/null ||
  fail "Fresh staging gallery version lost its exact artifact and ownership binding"
run_capture_vm_check "$capture_vm_resource" "$capture_vm_id" "$capture_disk_id" \
  >/dev/null
[[ "$("$RELEASE_TOOL" check-capture-disk \
  --disk "$capture_disk_json" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --source-version-id "$staging_version_id" \
  --vm-id "$capture_vm_id" \
  --disk-id "$capture_disk_id")" == "$capture_disk_id" ]]
[[ "$("$RELEASE_TOOL" check-capture-snapshot \
  --snapshot "$snapshot_json" \
  --snapshot-id "$snapshot_id" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --source-version-id "$staging_version_id" \
  --vm-id "$capture_vm_id" \
  --disk-id "$capture_disk_id")" == "$snapshot_id" ]]
owned_tags_match "$snapshot_json" "$OWNER" "$GITHUB_REPOSITORY" \
  "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT" ||
  fail "Fresh capture snapshot evidence lost its exact run ownership tags"
"$RELEASE_TOOL" check-capture-definition \
  --definition "$target_definition_json" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$TARGET_LOCATION" \
  --snapshot-id "$snapshot_id" \
  --definition-id "$target_definition_id" \
  --version-id "$target_version_id" >/dev/null
"$RELEASE_TOOL" check-capture-gallery \
  --request "$target_request" \
  --response "$target_response" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$TARGET_LOCATION" \
  --snapshot-id "$snapshot_id" \
  --definition-id "$target_definition_id" \
  --version-id "$target_version_id"
owned_tags_match "$target_response" "$OWNER" "$GITHUB_REPOSITORY" \
  "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT" ||
  fail "Fresh target gallery version evidence lost its exact run ownership tags"
"$RELEASE_TOOL" check-captured-vm \
  --vm "$final_vm_resource" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --version-id "$target_version_id" \
  --vm-id "$final_vm_id" \
  --disk-id "$final_disk_id" >/dev/null

scratch_inventory="$RESULT_DIR/scratch-resource-inventory.json"
state_matches_identity "$STATE_FILE" ||
  fail "Cannot create capture provenance from invalid scratch state"
jq -c \
  '{
    schema: 1,
    subscription_id: .subscription_id,
    scratch_resource_group: .temporary_resource_group,
    resources: (.temporary_resources | sort_by(.id | ascii_downcase))
  }' "$STATE_FILE" >"$scratch_inventory"
chmod 0600 "$scratch_inventory"

capture_evidence_manifest="$RESULT_DIR/capture-evidence.sha256"
sha256sum \
  "$scratch_inventory" \
  "$upload_disk_json" \
  "$managed_image_json" \
  "$staging_definition_json" \
  "$staging_response" \
  "$capture_vm_resource" \
  "$capture_vm_instance" \
  "$capture_disk_json" \
  "$snapshot_json" \
  "$target_definition_json" \
  "$target_response" \
  "$final_vm_resource" \
  "$final_vm_instance" \
  "$final_token" \
  "$final_openid" \
  "$final_jwks" >"$capture_evidence_manifest"
chmod 0600 "$capture_evidence_manifest"

verify_capture_evidence_revisions() {
  sha256sum --check --status "$capture_evidence_manifest" || {
    fail "Capture evidence changed after the final freshness boundary"
    return
  }
}

final_now=$(date +%s)
capture_common_args=(
  --source-acceptance "$SOURCE_ACCEPTANCE"
  --provenance "$PROVENANCE"
  --qcow "$CANDIDATE"
  --source-commit "$SOURCE_COMMIT"
  --source-release-tag "$SOURCE_RELEASE_TAG"
  --source-location "$SOURCE_LOCATION"
  --source-vm-size "$SOURCE_VM_SIZE"
  --source-run-id "$SOURCE_RUN_ID"
  --source-run-attempt "$SOURCE_RUN_ATTEMPT"
  --source-repository "$SOURCE_REPOSITORY"
  --source-version-id "$staging_version_id"
  --staging-disk "$upload_disk_json"
  --staging-managed-image "$managed_image_json"
  --staging-definition "$staging_definition_json"
  --staging-gallery-request "$staging_request"
  --staging-gallery-response "$staging_response"
  --subscription-id "$AZURE_SUBSCRIPTION_ID"
  --tool-commit "$TOOL_COMMIT"
  --location "$AZURE_LOCATION"
  --repository "$GITHUB_REPOSITORY"
  --run-id "$GITHUB_RUN_ID"
  --run-attempt "$GITHUB_RUN_ATTEMPT"
  --scratch-resource-group "$resource_group"
  --scratch-inventory "$scratch_inventory"
  --target-resource-group "$TARGET_RESOURCE_GROUP"
  --capture-vm-id "$capture_vm_id"
  --capture-disk-id "$capture_disk_id"
  --snapshot-id "$snapshot_id"
  --definition-id "$target_definition_id"
  --version-id "$target_version_id"
  --final-vm-id "$final_vm_id"
  --final-disk-id "$final_disk_id"
  --capture-vm "$capture_vm_resource"
  --capture-vm-instance "$capture_vm_instance"
  --capture-disk "$capture_disk_json"
  --snapshot "$snapshot_json"
  --definition "$target_definition_json"
  --gallery-request "$target_request"
  --gallery-response "$target_response"
  --final-vm "$final_vm_resource"
  --final-vm-instance "$final_vm_instance"
  --token "$final_token"
  --openid "$final_openid"
  --jwks "$final_jwks"
  --endpoint "$ATTESTATION_ENDPOINT"
  --nonce "$final_nonce"
  --now "$final_now"
)
verify_capture_evidence_revisions
"$RELEASE_TOOL" capture-result \
  "${capture_common_args[@]}" \
  --guest-vm-id "$final_guest_vm_id" \
  --output "$capture_result"
verify_capture_evidence_revisions
"$RELEASE_TOOL" verify-capture \
  "${capture_common_args[@]}" \
  --result "$capture_result"

jq -e \
  '[paths(scalars) as $path |
    {
      key: ($path[-1] | tostring | ascii_downcase),
      value: getpath($path)
    } |
    select(
      (.key == "token" or .key == "jwt" or .key == "nonce" or
       .key == "sas" or .key == "private_key") and
      (.value | type == "string")
    )
  ] | length == 0' \
  "$capture_result" >/dev/null ||
  fail "Durable capture result contains a raw secret field"

state_replace '.run_succeeded = true | .stage = "completed"'
printf 'MIZ_CAPTURE_STAGE=completed\n'
