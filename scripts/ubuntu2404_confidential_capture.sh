#!/usr/bin/env bash
set -Eeuo pipefail

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
OWNER=ubuntu2404-confidential-capture

command_name=${1:-run}
if (( $# > 1 )) || [[ "$command_name" != run && "$command_name" != cleanup ]]; then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi

fail() {
  printf '::error::%s\n' "$*" >&2
  return 1
}

require_cleanup_identity() {
  [[ -n ${STATE_FILE:-} && -n ${GITHUB_REPOSITORY:-} &&
      -n ${GITHUB_RUN_ID:-} && -n ${GITHUB_RUN_ATTEMPT:-} &&
      -n ${SOURCE_COMMIT:-} ]] ||
    fail "Capture cleanup identity is incomplete"
  [[ "$GITHUB_REPOSITORY" == "$EXPECTED_REPOSITORY" ]] ||
    fail "Capture repository identity is invalid"
  [[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]{0,19}$ &&
      "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]{0,9}$ &&
      "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]] ||
    fail "Capture cleanup identity is invalid"
}

state_replace() {
  local filter=$1
  shift
  local next="${STATE_FILE}.next"
  jq "$@" "$filter" "$STATE_FILE" >"$next"
  chmod 0600 "$next"
  mv -f -- "$next" "$STATE_FILE"
}

state_matches_identity() {
  jq -e \
    --arg repository "$GITHUB_REPOSITORY" \
    --arg run_id "$GITHUB_RUN_ID" \
    --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
    --arg source_commit "$SOURCE_COMMIT" \
    '.schema == 1 and
     .repository == $repository and
     .run_id == $run_id and
     .run_attempt == $run_attempt and
     .source_commit == $source_commit and
     (.temporary_resource_group | type == "string") and
     (.temporary_resource_group | test("^miz-u2404-cvm-capture-[1-9][0-9]{0,19}-[1-9][0-9]{0,9}$"))' \
    "$STATE_FILE" >/dev/null
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

delete_created_version() {
  local created version_id metadata
  created=$(jq -r '.target.version_created' "$STATE_FILE")
  [[ "$created" == true ]] || return 0
  version_id=$(jq -r '.target.version_id' "$STATE_FILE")
  [[ "$version_id" == /subscriptions/*/resourceGroups/*/providers/Microsoft.Compute/galleries/*/images/*/versions/* ]] ||
    return 1
  metadata="${STATE_FILE}.version.json"
  if ! az sig image-version show --ids "$version_id" --output json >"$metadata" 2>"${metadata}.stderr"; then
    if grep -Eq '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' "${metadata}.stderr"; then
      rm -f -- "$metadata" "${metadata}.stderr"
      return 0
    fi
    fail "Could not inspect the target gallery version during cleanup"
    return
  fi
  rm -f -- "${metadata}.stderr"
  if ! owned_tags_match "$metadata" "$OWNER" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"; then
    fail "Refusing to delete target version without exact run ownership tags"
    return
  fi
  az sig image-version delete --ids "$version_id" ||
    fail "Failed to delete exact-owned target gallery version"
}

delete_created_definition() {
  local created definition_id image_name gallery_name metadata owner_tag resource_group versions
  created=$(jq -r '.target.definition_created' "$STATE_FILE")
  [[ "$created" == true ]] || return 0
  definition_id=$(jq -r '.target.definition_id' "$STATE_FILE")
  resource_group=$(jq -r '.target.resource_group' "$STATE_FILE")
  gallery_name=$(jq -r '.target.gallery' "$STATE_FILE")
  image_name=$(jq -r '.target.image_definition' "$STATE_FILE")
  [[ "$definition_id" == /subscriptions/*/resourceGroups/*/providers/Microsoft.Compute/galleries/*/images/* ]] ||
    return 1
  [[ "$resource_group" =~ ^[A-Za-z0-9._()-]{1,90}$ &&
      "$gallery_name" =~ ^[A-Za-z0-9_]{1,80}$ &&
      "$image_name" =~ ^[A-Za-z0-9._()-]{1,80}$ ]] ||
    return 1
  metadata="${STATE_FILE}.definition.json"
  if ! az sig image-definition show --ids "$definition_id" --output json >"$metadata" 2>"${metadata}.stderr"; then
    if grep -Eq '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' "${metadata}.stderr"; then
      rm -f -- "$metadata" "${metadata}.stderr"
      return 0
    fi
    fail "Could not inspect the target image definition during cleanup"
    return
  fi
  rm -f -- "${metadata}.stderr"
  owner_tag=$(jq -r '.target.owner_tag' "$STATE_FILE")
  if ! owned_tags_match "$metadata" "$owner_tag" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"; then
    fail "Refusing to delete target definition without exact run ownership tags"
    return
  fi
  versions="${STATE_FILE}.definition-versions.json"
  az sig image-version list \
    --resource-group "$resource_group" \
    --gallery-name "$gallery_name" \
    --gallery-image-definition "$image_name" \
    --output json >"$versions" ||
    {
      fail "Could not prove that the target definition is empty"
      return
    }
  jq -e 'type == "array" and length == 0' "$versions" >/dev/null ||
    {
      fail "Refusing to delete a non-empty target image definition"
      return
    }
  az sig image-definition delete --ids "$definition_id" ||
    fail "Failed to delete exact-owned empty target image definition"
}

delete_temporary_group() {
  local created group exists metadata
  created=$(jq -r '.temporary_group_created' "$STATE_FILE")
  [[ "$created" == true ]] || return 0
  group=$(jq -r '.temporary_resource_group' "$STATE_FILE")
  exists=$(az group exists --name "$group" --output tsv) ||
    {
      fail "Could not determine whether the temporary resource group exists"
      return
    }
  case "$exists" in
    false) return 0 ;;
    true) ;;
    *) fail "Azure returned an invalid resource-group existence result"; return ;;
  esac
  metadata="${STATE_FILE}.group.json"
  az group show --name "$group" --output json >"$metadata" ||
    {
      fail "Could not inspect temporary resource-group ownership"
      return
    }
  if ! owned_tags_match "$metadata" "$OWNER" "$GITHUB_REPOSITORY" \
      "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$SOURCE_COMMIT"; then
    fail "Refusing to delete temporary resource group without exact ownership tags"
    return
  fi
  az group delete --name "$group" --yes ||
    fail "Failed to delete exact-owned temporary resource group"
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
  state_matches_identity || {
    fail "Refusing cleanup because state identity does not match this run"
    return
  }
  az account show --output none ||
    {
      fail "Azure login is unavailable during cleanup"
      return
    }

  local succeeded cleanup_status=0
  succeeded=$(jq -r '.run_succeeded' "$STATE_FILE")
  if [[ "$succeeded" != true ]]; then
    delete_created_version || cleanup_status=1
    delete_created_definition || cleanup_status=1
  fi
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
      -z ${SOURCE_ACCEPTANCE:-} || -z ${SOURCE_LOCATION:-} ||
      -z ${SOURCE_VM_SIZE:-} || -z ${SOURCE_RUN_ID:-} ||
      -z ${SOURCE_RUN_ATTEMPT:-} || -z ${SOURCE_REPOSITORY:-} ||
      -z ${AZURE_SUBSCRIPTION_ID:-} || -z ${AZURE_LOCATION:-} ||
      -z ${AZURE_VM_SIZE:-} || -z ${TARGET_RESOURCE_GROUP:-} ||
      -z ${TARGET_GALLERY:-} || -z ${TARGET_IMAGE_DEFINITION:-} ||
      -z ${TARGET_IMAGE_VERSION:-} || -z ${TARGET_LOCATION:-} ||
      -z ${TARGET_OWNER_TAG:-} || -z ${RESULT_DIR:-} || -z ${MIZ:-} ]]; then
  fail "Confidential VM capture configuration is incomplete"
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
    "$AZURE_SUBSCRIPTION_ID" =~ ^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$ &&
    "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ &&
    "$SOURCE_LOCATION" =~ ^[a-z0-9-]+$ &&
    "$TARGET_LOCATION" =~ ^[a-z0-9-]+$ &&
    "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ &&
    "$SOURCE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ &&
    "$TARGET_RESOURCE_GROUP" =~ ^[A-Za-z0-9._()-]{1,90}$ &&
    "$TARGET_GALLERY" =~ ^[A-Za-z0-9_]{1,80}$ &&
    "$TARGET_IMAGE_DEFINITION" =~ ^[A-Za-z0-9._()-]{1,80}$ &&
    "$TARGET_IMAGE_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ &&
    "$TARGET_OWNER_TAG" =~ ^[A-Za-z0-9._:/-]{1,128}$ &&
    "$ATTESTATION_ENDPOINT" =~ ^https://[a-z0-9.-]+\.attest\.azure\.net$ ]] ||
  {
    fail "Confidential VM capture configuration is invalid"
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

report_error() {
  local status=$1 line=$2
  trap - ERR
  printf '::error::Confidential VM capture failed at line %s\n' "$line" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO"' ERR

mkdir -p "$RESULT_DIR" "$(dirname -- "$STATE_FILE")"
chmod 0700 "$RESULT_DIR"
[[ ! -e "$STATE_FILE" ]] ||
  {
    fail "Refusing to overwrite existing capture state"
    exit 1
  }

name_seed="${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"
resource_group="miz-u2404-cvm-capture-${name_seed}"
upload_disk_name="miz-u2404-capture-upload-${name_seed}"
managed_image_name="miz-u2404-capture-image-${name_seed}"
staging_gallery="mizcvmcapture${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}"
staging_definition=mizu2404cvmsource
staging_version=1.0.0
source_vm_name="miz-cvm-source-${name_seed}"
source_data_disk_name="miz-cvm-source-data-${name_seed}"
capture_vm_name="miz-cvm-capture-${name_seed}"
snapshot_name="miz-cvm-snapshot-${name_seed}"
final_vm_name="miz-cvm-final-${name_seed}"
final_data_disk_name="miz-cvm-final-data-${name_seed}"
admin_username=mizcapture

target_definition_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$TARGET_RESOURCE_GROUP/providers/Microsoft.Compute/galleries/$TARGET_GALLERY/images/$TARGET_IMAGE_DEFINITION"
target_version_id="$target_definition_id/versions/$TARGET_IMAGE_VERSION"
staging_definition_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Compute/galleries/$staging_gallery/images/$staging_definition"
staging_version_id="$staging_definition_id/versions/$staging_version"

jq -n \
  --arg repository "$GITHUB_REPOSITORY" \
  --arg run_id "$GITHUB_RUN_ID" \
  --arg run_attempt "$GITHUB_RUN_ATTEMPT" \
  --arg source_commit "$SOURCE_COMMIT" \
  --arg temporary_resource_group "$resource_group" \
  --arg target_owner "$TARGET_OWNER_TAG" \
  --arg target_resource_group "$TARGET_RESOURCE_GROUP" \
  --arg target_gallery "$TARGET_GALLERY" \
  --arg target_image_definition "$TARGET_IMAGE_DEFINITION" \
  --arg definition_id "$target_definition_id" \
  --arg version_id "$target_version_id" \
  '{
    schema: 1,
    repository: $repository,
    run_id: $run_id,
    run_attempt: $run_attempt,
    source_commit: $source_commit,
    temporary_resource_group: $temporary_resource_group,
    temporary_group_created: false,
    run_succeeded: false,
    target: {
      owner_tag: $target_owner,
      resource_group: $target_resource_group,
      gallery: $target_gallery,
      image_definition: $target_image_definition,
      definition_id: $definition_id,
      version_id: $version_id,
      definition_created: false,
      version_created: false
    }
  }' >"$STATE_FILE"
chmod 0600 "$STATE_FILE"

vhd="$RESULT_DIR/Ubuntu-24.04-x86_64.confidential.vhd"
vhd_info="$RESULT_DIR/vhd-info.json"
conversion="$RESULT_DIR/conversion.json"
sku_json="$RESULT_DIR/sku.json"
upload_disk_json="$RESULT_DIR/staging-managed-disk.json"
managed_image_json="$RESULT_DIR/staging-managed-image.json"
staging_definition_json="$RESULT_DIR/staging-definition.json"
staging_request="$RESULT_DIR/staging-gallery-request.json"
staging_response="$RESULT_DIR/staging-gallery-response.json"
source_dir="$RESULT_DIR/source-validation"
capture_dir="$RESULT_DIR/capture"
final_dir="$RESULT_DIR/final-validation"
mkdir -p "$source_dir" "$capture_dir" "$final_dir"
private_key="$RESULT_DIR/id_ed25519"
known_hosts="$RESULT_DIR/known_hosts"
capture_result="$RESULT_DIR/capture-result.json"

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
  [[ "$resource_id" == /subscriptions/* ]] || return 1
  az tag update \
    --operation Merge \
    --resource-id "$resource_id" \
    --tags "${exact_tags[@]}" \
    --output none
}

tag_group_resources() {
  local resource_id
  while IFS= read -r resource_id; do
    [[ -n "$resource_id" ]] && tag_resource "$resource_id"
  done < <(
    az resource list \
      --resource-group "$resource_group" \
      --query '[].id' \
      --output tsv
  )
}

grant_disk_write_access() {
  local disk_id=$1 duration_seconds=$2
  local auth_header headers location request_dir response_body retry_after sas status token
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
  printf '%s\n' "$sas"
}

resource_absent() {
  local stderr_file=$1
  shift
  if "$@" >/dev/null 2>"$stderr_file"; then
    return 1
  fi
  grep -Eq '(^|[^0-9])404([^0-9]|$)|ResourceNotFound|was not found' "$stderr_file"
}

wait_gallery_version() {
  local response=$1 version_id=$2 provisioning replication
  for _ in {1..180}; do
    readarray -t states < <(
      "$RELEASE_TOOL" capture-gallery-state --response "$response"
    )
    [[ ${#states[@]} -eq 2 ]]
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
    az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$response"
  done
  fail "Gallery full replication did not complete before the deadline"
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

cleanup_on_exit() {
  local status=$?
  trap - EXIT INT TERM
  ubuntu2404_confidential_guest_cleanup_validation_files || status=1
  rm -f -- "$vhd" "$private_key" "$private_key.pub" "$known_hosts"
  rm -rf -- "$RESULT_DIR/disk-access" \
    "$source_dir/attestation-client" "$final_dir/attestation-client"
  rm -f -- \
    "$source_dir/azguestattestation1.deb" "$source_dir/attestation-client.zip" \
    "$final_dir/azguestattestation1.deb" "$final_dir/attestation-client.zip"
  cleanup_resources || status=1
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

account_subscription=$(az account show --query id --output tsv)
[[ "${account_subscription,,}" == "${AZURE_SUBSCRIPTION_ID,,}" ]] ||
  fail "Azure login subscription does not match the protected input"

group_exists=$(az group exists --name "$resource_group" --output tsv)
case "$group_exists" in
  false) ;;
  true) fail "Refusing to reuse temporary resource group $resource_group"; exit 1 ;;
  *) fail "Azure returned an invalid resource-group existence result"; exit 1 ;;
esac
state_replace '.temporary_group_created = true'
az group create \
  --name "$resource_group" \
  --location "$AZURE_LOCATION" \
  --tags "${exact_tags[@]}" \
  --output none

target_group_json="$RESULT_DIR/target-resource-group.json"
target_gallery_json="$RESULT_DIR/target-gallery.json"
az group show --name "$TARGET_RESOURCE_GROUP" --output json >"$target_group_json"
az sig show \
  --resource-group "$TARGET_RESOURCE_GROUP" \
  --gallery-name "$TARGET_GALLERY" \
  --output json >"$target_gallery_json"
jq -e \
  --arg subscription "$AZURE_SUBSCRIPTION_ID" \
  --arg expected_id "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$TARGET_RESOURCE_GROUP" \
  --arg location "$TARGET_LOCATION" \
  --arg owner "$TARGET_OWNER_TAG" \
  --arg repository "$GITHUB_REPOSITORY" \
  '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
   (.location | ascii_downcase) == ($location | ascii_downcase) and
   .tags["miz-owner"] == $owner and
   .tags["miz-repository"] == $repository' \
  "$target_group_json" >/dev/null ||
  fail "Target resource group subscription, location, or durable ownership is invalid"
jq -e \
  --arg subscription "$AZURE_SUBSCRIPTION_ID" \
  --arg expected_id "/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$TARGET_RESOURCE_GROUP/providers/Microsoft.Compute/galleries/$TARGET_GALLERY" \
  --arg location "$TARGET_LOCATION" \
  --arg owner "$TARGET_OWNER_TAG" \
  --arg repository "$GITHUB_REPOSITORY" \
  '(.id | ascii_downcase) == ($expected_id | ascii_downcase) and
   (.location | ascii_downcase) == ($location | ascii_downcase) and
   .tags["miz-owner"] == $owner and
   .tags["miz-repository"] == $repository' \
  "$target_gallery_json" >/dev/null ||
  fail "Target gallery subscription, location, or durable ownership is invalid"

version_absent_stderr="$RESULT_DIR/target-version-show.stderr"
if ! resource_absent "$version_absent_stderr" \
    az sig image-version show --ids "$target_version_id" --output json; then
  fail "Target gallery version already exists; refusing update or overwrite"
fi
rm -f -- "$version_absent_stderr"

readarray -t accepted_identity < <(
  "$RELEASE_TOOL" verify-acceptance \
    --result "$SOURCE_ACCEPTANCE" \
    --provenance "$PROVENANCE" \
    --qcow "$CANDIDATE" \
    --source-commit "$SOURCE_COMMIT" \
    --location "$SOURCE_LOCATION" \
    --vm-size "$SOURCE_VM_SIZE" \
    --run-id "$SOURCE_RUN_ID" \
    --run-attempt "$SOURCE_RUN_ATTEMPT"
)
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
readarray -t vhd_identity < <(
  "$RELEASE_TOOL" verify-vhd \
    --provenance "$PROVENANCE" \
    --qcow "$CANDIDATE" \
    --vhd "$vhd" \
    --info "$vhd_info" \
    --output "$conversion"
)
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
upload_sas=$(grant_disk_write_access "$upload_disk_id" 7200)
[[ "$upload_sas" == https://* ]]
azcopy copy "$vhd" "$upload_sas" --blob-type PageBlob
upload_sas=
azure_trusted_launch_disk_revoke_access_args "$resource_group" "$upload_disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
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

azure_trusted_launch_gallery_create_args "$resource_group" "$staging_gallery" "$AZURE_LOCATION"
AZURE_TRUSTED_LAUNCH_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
azure_confidential_vm_image_definition_create_args \
  "$resource_group" "$staging_gallery" "$staging_definition" ubuntu2404 \
  confidential-source-x64 "$AZURE_LOCATION"
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_image_definition_show_args \
  "$resource_group" "$staging_gallery" "$staging_definition"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$staging_definition_json"
[[ "$("$RELEASE_TOOL" check-image-definition --definition "$staging_definition_json")" == "$staging_definition_id" ]]

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

ssh-keygen -q -t ed25519 -N '' -f "$private_key"

source_vm_resource="$source_dir/vm-resource.json"
source_vm_instance="$source_dir/vm-instance.json"
source_guest_imds="$source_dir/guest-imds.json"
source_token="$source_dir/attestation.jwt"
source_openid="$source_dir/openid-configuration.json"
source_jwks="$source_dir/jwks.json"
azure_confidential_vm_vm_create_args \
  "$resource_group" "$source_vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$staging_version_id" "$admin_username" "$private_key.pub" true
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$source_dir/vm-create.json"
tag_group_resources
collect_acceptance_vm_contract \
  "$source_vm_name" "$source_vm_resource" "$source_vm_instance"
collect_vm_contract \
  "$source_vm_name" "$source_dir/vm-full-resource.json" \
  "$source_dir/vm-full-instance.json"
source_vm_resource_id=$(jq -er '.id' "$source_vm_resource")
source_vm_unique_id=$(jq -er '.vmId' "$source_vm_resource")
readarray -t source_checked < <(
  "$RELEASE_TOOL" check-vm \
    --resource "$source_vm_resource" \
    --instance "$source_vm_instance" \
    --image-version-id "$staging_version_id"
)
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
tag_group_resources

capture_vm_resource="$capture_dir/vm-resource.json"
capture_vm_instance="$capture_dir/vm-instance.json"
capture_disk_json="$capture_dir/os-disk.json"
capture_guest_imds="$capture_dir/guest-imds.json"
azure_confidential_vm_vm_create_args \
  "$resource_group" "$capture_vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$staging_version_id" "$admin_username" "$private_key.pub" true
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$capture_dir/vm-create.json"
tag_group_resources
collect_vm_contract "$capture_vm_name" "$capture_vm_resource" "$capture_vm_instance"
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

ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
  "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
  'sudo -n waagent -deprovision+user -force && sudo -n shutdown -h now' \
  >/dev/null 2>&1 || true
ssh_stopped=false
for _ in {1..90}; do
  if ! ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
      "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" true >/dev/null 2>&1; then
    ssh_stopped=true
    break
  fi
  sleep 5
done
[[ "$ssh_stopped" == true ]] || fail "Capture VM did not stop accepting SSH after shutdown"

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
  fail "Capture VM did not reach a stopped power state after guest shutdown"

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
snapshot_id="/subscriptions/$AZURE_SUBSCRIPTION_ID/resourceGroups/$resource_group/providers/Microsoft.Compute/snapshots/$snapshot_name"
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

target_definition_json="$RESULT_DIR/target-definition.json"
definition_absent_stderr="$RESULT_DIR/target-definition-show.stderr"
definition_was_created=false
if resource_absent "$definition_absent_stderr" \
    az sig image-definition show --ids "$target_definition_id" --output json; then
  state_replace '.target.definition_created = true'
  azure_confidential_vm_capture_image_definition_create_args \
    "$TARGET_RESOURCE_GROUP" "$TARGET_GALLERY" "$TARGET_IMAGE_DEFINITION" \
    ubuntu2404 confidential-x64 "$TARGET_LOCATION"
  AZURE_CONFIDENTIAL_VM_ARGS+=(
    --tags
    "miz-owner=$TARGET_OWNER_TAG"
    "miz-repository=$GITHUB_REPOSITORY"
    "miz-run-id=$GITHUB_RUN_ID"
    "miz-run-attempt=$GITHUB_RUN_ATTEMPT"
    "miz-source-commit=$SOURCE_COMMIT"
  )
  az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$target_definition_json"
  definition_was_created=true
else
  az sig image-definition show --ids "$target_definition_id" --output json \
    >"$target_definition_json"
  jq -e \
    --arg owner "$TARGET_OWNER_TAG" \
    --arg repository "$GITHUB_REPOSITORY" \
    '.tags["miz-owner"] == $owner and .tags["miz-repository"] == $repository' \
    "$target_definition_json" >/dev/null ||
    fail "Pre-existing target definition lacks durable ownership tags"
fi
rm -f -- "$definition_absent_stderr"
if [[ "$definition_was_created" == true ]]; then
  owned_tags_match "$target_definition_json" "$TARGET_OWNER_TAG" \
    "$GITHUB_REPOSITORY" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" \
    "$SOURCE_COMMIT" ||
    fail "Created target definition lost its exact ownership tags"
fi
"$RELEASE_TOOL" check-capture-definition \
  --definition "$target_definition_json" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$TARGET_LOCATION" \
  --snapshot-id "$snapshot_id" \
  --definition-id "$target_definition_id" \
  --version-id "$target_version_id" >/dev/null

state_replace '.target.version_created = true'

target_request="$RESULT_DIR/target-gallery-request.json"
target_response="$RESULT_DIR/target-gallery-response.json"
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
azure_confidential_vm_capture_gallery_version_put_args \
  "$target_version_id" "$target_request"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$target_response"
wait_gallery_version "$target_response" "$target_version_id"
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
  fail "Target gallery version lost its exact run ownership tags"

final_vm_resource="$final_dir/vm-resource.json"
final_vm_instance="$final_dir/vm-instance.json"
final_guest_imds="$final_dir/guest-imds.json"
final_token="$final_dir/attestation.jwt"
final_openid="$final_dir/openid-configuration.json"
final_jwks="$final_dir/jwks.json"
azure_confidential_vm_captured_vm_create_args \
  "$resource_group" "$final_vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$target_version_id" "$admin_username" "$private_key.pub" true
AZURE_CONFIDENTIAL_VM_ARGS+=(--tags "${exact_tags[@]}")
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$final_dir/vm-create.json"
tag_group_resources
collect_vm_contract "$final_vm_name" "$final_vm_resource" "$final_vm_instance"
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
tag_group_resources

# Refresh authenticated Azure resource evidence after reboot acceptance and use
# the just-fetched MAA OpenID/JWKS documents without exposing the JWT or nonce.
collect_vm_contract "$final_vm_name" "$final_vm_resource" "$final_vm_instance"
refresh_maa_metadata "$final_openid" "$final_jwks"
"$RELEASE_TOOL" check-captured-vm \
  --vm "$final_vm_resource" \
  --subscription-id "$AZURE_SUBSCRIPTION_ID" \
  --location "$AZURE_LOCATION" \
  --version-id "$target_version_id" \
  --vm-id "$final_vm_id" \
  --disk-id "$final_disk_id" >/dev/null

final_now=$(date +%s)
capture_common_args=(
  --source-acceptance "$SOURCE_ACCEPTANCE"
  --provenance "$PROVENANCE"
  --qcow "$CANDIDATE"
  --source-commit "$SOURCE_COMMIT"
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
  --location "$AZURE_LOCATION"
  --repository "$GITHUB_REPOSITORY"
  --run-id "$GITHUB_RUN_ID"
  --run-attempt "$GITHUB_RUN_ATTEMPT"
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
  --guest-vm-id "$final_guest_vm_id"
)
"$RELEASE_TOOL" capture-result \
  "${capture_common_args[@]}" \
  --output "$capture_result"
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

state_replace '.run_succeeded = true'
