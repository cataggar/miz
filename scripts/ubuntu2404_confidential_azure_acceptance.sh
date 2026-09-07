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

command_name=${1:-run}
if (( $# > 1 )); then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi
if [[ -z ${STATE_FILE:-} || -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} ]]; then
  echo "::error::Azure cleanup identity is incomplete"
  exit 1
fi
if ! [[ "$GITHUB_RUN_ID" =~ ^[1-9][0-9]*$ &&
        "$GITHUB_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]; then
  echo "::error::Azure cleanup identity is invalid"
  exit 1
fi

resource_group="miz-u2404-cvm-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}"

cleanup_group() {
  [[ -s "$STATE_FILE" ]] || return 0
  local recorded group_exists
  recorded=$(<"$STATE_FILE")
  [[ "$recorded" == "$resource_group" ]] || {
    echo "::error::Refusing cleanup of unexpected resource-group name"
    return 1
  }
  command -v az >/dev/null || {
    echo "::error::Azure CLI is unavailable during cleanup"
    return 1
  }
  group_exists=$(az group exists --name "$resource_group" --output tsv) || {
    echo "::error::Could not determine whether the temporary resource group exists"
    return 1
  }
  case "$group_exists" in
    false) return 0 ;;
    true) ;;
    *)
      echo "::error::Azure returned an invalid resource-group existence result"
      return 1
      ;;
  esac
  local ownership_text
  local -a ownership
  ownership_text=$(az group show \
    --name "$resource_group" \
    --query '[tags."miz-owner", tags."miz-run-id", tags."miz-run-attempt"]' \
    --output tsv) || return 1
  mapfile -t ownership <<<"$ownership_text"
  [[ ${#ownership[@]} -eq 3 &&
      ${ownership[0]} == ubuntu2404-confidential-acceptance &&
      ${ownership[1]} == "$GITHUB_RUN_ID" &&
      ${ownership[2]} == "$GITHUB_RUN_ATTEMPT" ]] || {
    echo "::error::Refusing cleanup of a resource group without exact ownership tags"
    return 1
  }
  az group delete --name "$resource_group" --yes
}

if [[ "$command_name" == cleanup ]]; then
  cleanup_group
  exit
fi
if [[ "$command_name" != run ]]; then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi

if [[ -z ${CANDIDATE:-} || -z ${PROVENANCE:-} || -z ${SOURCE_COMMIT:-} ||
      -z ${AZURE_LOCATION:-} || -z ${AZURE_VM_SIZE:-} ||
      -z ${RESULT_DIR:-} || -z ${MIZ:-} || -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Azure Confidential VM acceptance configuration is incomplete"
  exit 1
fi
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ ]]
[[ "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ ]]
[[ "$ATTESTATION_ENDPOINT" =~ ^https://[a-z0-9.-]+\.attest\.azure\.net$ ]]
[[ -f "$CANDIDATE" && -f "$PROVENANCE" ]]
[[ -x "$MIZ" && -x "$RELEASE_TOOL" ]]

report_error() {
  local status=$1 line=$2 command=$3
  trap - ERR
  printf '::error::Confidential VM acceptance failed at line %s: %s\n' \
    "$line" "$command" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

for tool in az azcopy curl jq openssl qemu-img scp sha256sum ssh ssh-keygen unzip; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required Confidential VM acceptance tool $tool is unavailable"
    exit 1
  }
done

grant_disk_write_access() {
  local disk_id=$1
  local duration_seconds=$2
  local attempt auth_header headers location request_dir response_body retry_after sas status token
  request_dir=$(mktemp -d "$RESULT_DIR/disk-access.XXXXXX")
  auth_header="$request_dir/auth-header"
  headers="$request_dir/headers"
  response_body="$request_dir/body"
  if ! token=$(az account get-access-token \
      --resource https://management.azure.com/ \
      --query accessToken \
      --output tsv)
  then
    echo "::error::Could not acquire an Azure management token" >&2
    rm -f "$auth_header" "$headers" "$response_body"
    rmdir "$request_dir"
    return 1
  fi
  if [[ -z "$token" ]]; then
    echo "::error::Azure returned an empty management token" >&2
    rm -f "$auth_header" "$headers" "$response_body"
    rmdir "$request_dir"
    return 1
  fi
  (umask 077; printf 'Authorization: Bearer %s\n' "$token" >"$auth_header")
  token=

  if ! status=$(curl \
      --silent \
      --show-error \
      --connect-timeout 30 \
      --max-time 60 \
      --retry 3 \
      --retry-max-time 120 \
      --dump-header "$headers" \
      --output "$response_body" \
      --write-out '%{http_code}' \
      --request POST \
      --header "@$auth_header" \
      --header 'Content-Type: application/json' \
      --data "{\"access\":\"Write\",\"durationInSeconds\":$duration_seconds}" \
      "https://management.azure.com${disk_id}/beginGetAccess?api-version=2025-01-02")
  then
    echo "::error::Azure disk access request failed" >&2
    rm -f "$auth_header" "$headers" "$response_body"
    rmdir "$request_dir"
    return 1
  fi
  if [[ "$status" == 202 ]]; then
    location=$(
      awk -F: '
        tolower($1) == "location" {
          sub(/^[^:]*:[[:space:]]*/, "")
          sub(/\r$/, "")
          print
          exit
        }
      ' "$headers"
    )
    if [[ "$location" != https://management.azure.com/* ]]; then
      echo "::error::Azure disk access response omitted a valid polling location" >&2
      rm -f "$auth_header" "$headers" "$response_body"
      rmdir "$request_dir"
      return 1
    fi
    for ((attempt = 1; attempt <= 60; attempt++)); do
      retry_after=$(
        awk -F: '
          tolower($1) == "retry-after" {
            sub(/^[^:]*:[[:space:]]*/, "")
            sub(/\r$/, "")
            print
            exit
          }
        ' "$headers"
      )
      if [[ ! "$retry_after" =~ ^[0-9]+$ || "$retry_after" -lt 1 ]]; then
        retry_after=2
      elif [[ "$retry_after" -gt 30 ]]; then
        retry_after=30
      fi
      sleep "$retry_after"
      if ! status=$(curl \
          --silent \
          --show-error \
          --connect-timeout 30 \
          --max-time 60 \
          --retry 3 \
          --retry-max-time 120 \
          --dump-header "$headers" \
          --output "$response_body" \
          --write-out '%{http_code}' \
          --header "@$auth_header" \
          "$location")
      then
        echo "::error::Azure disk access polling request failed" >&2
        rm -f "$auth_header" "$headers" "$response_body"
        rmdir "$request_dir"
        return 1
      fi
      [[ "$status" == 202 ]] || break
    done
  fi
  if [[ "$status" != 200 ]]; then
    echo "::error::Azure disk access polling ended with HTTP $status" >&2
    rm -f "$auth_header" "$headers" "$response_body"
    rmdir "$request_dir"
    return 1
  fi
  if ! sas=$(jq -er '
      .accessSAS
      | strings
      | select(startswith("https://"))
    ' "$response_body")
  then
    echo "::error::Azure disk access response omitted the SAS URL" >&2
    rm -f "$auth_header" "$headers" "$response_body"
    rmdir "$request_dir"
    return 1
  fi
  rm -f "$auth_header" "$headers" "$response_body"
  rmdir "$request_dir"
  printf '%s\n' "$sas"
}

mkdir -p "$RESULT_DIR" "$(dirname -- "$STATE_FILE")"
vhd="$RESULT_DIR/Ubuntu-24.04-x86_64.confidential.vhd"
vhd_info="$RESULT_DIR/vhd-info.json"
conversion="$RESULT_DIR/conversion.json"
sku_json="$RESULT_DIR/sku.json"
disk_json="$RESULT_DIR/managed-disk.json"
managed_image_json="$RESULT_DIR/managed-image.json"
definition_json="$RESULT_DIR/image-definition.json"
gallery_request="$RESULT_DIR/gallery-request.json"
gallery_response="$RESULT_DIR/gallery-response.json"
vm_resource="$RESULT_DIR/vm-resource.json"
vm_instance="$RESULT_DIR/vm-instance.json"
guest_imds="$RESULT_DIR/guest-imds.json"
attestation_token="$RESULT_DIR/attestation.jwt"
openid_json="$RESULT_DIR/openid-configuration.json"
jwks_json="$RESULT_DIR/jwks.json"
acceptance_result="$RESULT_DIR/azure-result.json"
failure_instance="$RESULT_DIR/failure-instance-view.json"
private_key="$RESULT_DIR/id_ed25519"

name_seed="${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}"
disk_name="miz-cvm-os-${name_seed}"
managed_image_name="miz-cvm-image-${name_seed}"
data_disk_name="miz-cvm-data-${name_seed}"
gallery_name="mizcvm${name_seed}"
image_name="mizu2404cvm"
vm_name="miz-cvm-${name_seed}"
admin_username=mizaccept

collect_failure_diagnostics() {
  if az vm show --resource-group "$resource_group" --name "$vm_name" \
      >/dev/null 2>&1; then
    az vm get-instance-view \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --output json >"$failure_instance" 2>/dev/null || true
  fi
}

cleanup_on_exit() {
  local status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 ]]; then collect_failure_diagnostics; fi
  ubuntu2404_confidential_guest_cleanup_validation_files || status=1
  rm -f "$vhd" "$private_key" "$private_key.pub"
  cleanup_group || status=1
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

group_exists=$(az group exists --name "$resource_group" --output tsv)
case "$group_exists" in
  false) ;;
  true)
    echo "::error::Refusing to reuse existing resource group $resource_group"
    exit 1
    ;;
  *)
    echo "::error::Azure returned an invalid resource-group existence result"
    exit 1
    ;;
esac
printf '%s\n' "$resource_group" >"$STATE_FILE"
az group create \
  --name "$resource_group" \
  --location "$AZURE_LOCATION" \
  --tags \
    miz-owner=ubuntu2404-confidential-acceptance \
    "miz-run-id=$GITHUB_RUN_ID" \
    "miz-run-attempt=$GITHUB_RUN_ATTEMPT" \
  --output none

readarray -t build_identity < <(
  "$RELEASE_TOOL" verify-build \
    --provenance "$PROVENANCE" \
    --qcow "$CANDIDATE"
)
test "${#build_identity[@]}" -eq 3
qcow_sha256=${build_identity[0]}
qcow_bytes=${build_identity[1]}
virtual_size=${build_identity[2]}
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$qcow_bytes" =~ ^[1-9][0-9]*$ ]]
[[ "$virtual_size" =~ ^[1-9][0-9]*$ ]]

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
test "${#vhd_identity[@]}" -eq 3
vhd_current_size=${vhd_identity[0]}
vhd_bytes=${vhd_identity[1]}
vhd_sha256=${vhd_identity[2]}
[[ "$vhd_current_size" == "$virtual_size" ]]
[[ "$vhd_bytes" =~ ^[1-9][0-9]*$ ]]
[[ "$vhd_sha256" =~ ^[0-9a-f]{64}$ ]]
chmod 0444 "$vhd"

azure_confidential_vm_sku_list_args "$AZURE_LOCATION" "$AZURE_VM_SIZE"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$sku_json"
has_temporary_storage=$(
  "$RELEASE_TOOL" check-sku \
    --sku "$sku_json" \
    --vm-size "$AZURE_VM_SIZE"
)
[[ "$has_temporary_storage" == true || "$has_temporary_storage" == false ]]

azure_trusted_launch_disk_create_args \
  "$resource_group" "$disk_name" "$AZURE_LOCATION" "$vhd_bytes" x64
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
azure_trusted_launch_disk_show_args "$resource_group" "$disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$disk_json"
disk_id=$("$RELEASE_TOOL" check-managed-disk --disk "$disk_json")
[[ "$disk_id" == /subscriptions/* ]]
upload_sas=$(grant_disk_write_access "$disk_id" 7200)
[[ "$upload_sas" == https://* ]]
azcopy copy "$vhd" "$upload_sas" --blob-type PageBlob
upload_sas=
azure_trusted_launch_disk_revoke_access_args "$resource_group" "$disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
azure_trusted_launch_disk_show_args "$resource_group" "$disk_name"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$disk_json"
uploaded_disk_id=$("$RELEASE_TOOL" check-managed-disk --disk "$disk_json")
[[ "$uploaded_disk_id" == "$disk_id" ]]

azure_confidential_vm_managed_image_create_args \
  "$resource_group" "$managed_image_name" "$AZURE_LOCATION" "$disk_id"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_managed_image_show_args \
  "$resource_group" "$managed_image_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$managed_image_json"
managed_image_id=$(
  "$RELEASE_TOOL" check-managed-image \
    --image "$managed_image_json" \
    --disk-id "$disk_id"
)
[[ "$managed_image_id" == /subscriptions/* ]]

azure_trusted_launch_gallery_create_args \
  "$resource_group" "$gallery_name" "$AZURE_LOCATION"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >/dev/null
azure_confidential_vm_image_definition_create_args \
  "$resource_group" "$gallery_name" "$image_name" ubuntu2404 \
  confidential-x64 "$AZURE_LOCATION"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >/dev/null
azure_confidential_vm_image_definition_show_args \
  "$resource_group" "$gallery_name" "$image_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$definition_json"
definition_id=$(
  "$RELEASE_TOOL" check-image-definition --definition "$definition_json"
)
[[ "$definition_id" == /subscriptions/* ]]
image_version_id="$definition_id/versions/1.0.0"
"$RELEASE_TOOL" gallery-request \
  --output "$gallery_request" \
  --location "$AZURE_LOCATION" \
  --source-id "$managed_image_id"
azure_trusted_launch_gallery_version_put_args \
  "$image_version_id" "$gallery_request"
az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$gallery_response"
provisioning_state=
for _ in {1..120}; do
  provisioning_state=$(
    "$RELEASE_TOOL" gallery-state --response "$gallery_response"
  )
  case "$provisioning_state" in
    Succeeded) break ;;
    Failed|Canceled)
      echo "::error::Gallery image version entered $provisioning_state"
      exit 1
      ;;
  esac
  sleep 10
  azure_trusted_launch_gallery_version_get_args "$image_version_id"
  az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}" >"$gallery_response"
done
test "$provisioning_state" = Succeeded
"$RELEASE_TOOL" check-gallery \
  --request "$gallery_request" \
  --response "$gallery_response" \
  --image-version-id "$image_version_id" \
  --source-id "$managed_image_id"

ssh-keygen -q -t ed25519 -N '' -f "$private_key"
azure_confidential_vm_vm_create_args \
  "$resource_group" "$vm_name" "$AZURE_LOCATION" "$AZURE_VM_SIZE" \
  "$image_version_id" "$admin_username" "$private_key.pub" true
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$RESULT_DIR/vm-create.json"
azure_confidential_vm_vm_resource_args "$resource_group" "$vm_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$vm_resource"
azure_confidential_vm_vm_instance_security_args "$resource_group" "$vm_name"
az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}" >"$vm_instance"
readarray -t vm_identity < <(
  "$RELEASE_TOOL" check-vm \
    --resource "$vm_resource" \
    --instance "$vm_instance" \
    --image-version-id "$image_version_id"
)
test "${#vm_identity[@]}" -eq 2
vm_resource_id=${vm_identity[0]}
azure_vm_id=${vm_identity[1]}
[[ "$vm_resource_id" == /subscriptions/* ]]
[[ "$azure_vm_id" =~ ^[0-9a-fA-F-]{36}$ ]]

public_ip=$(az vm show \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --show-details \
  --query publicIps \
  --output tsv)
[[ "$public_ip" =~ ^[0-9a-fA-F:.]+$ ]]
ubuntu2404_confidential_guest_configure_ssh \
  "$private_key" "$RESULT_DIR/known_hosts" "$admin_username" "$public_ip"
nonce=$(openssl rand -hex 32)
ubuntu2404_confidential_guest_final_acceptance \
  "$virtual_size" "$azure_vm_id" "$guest_imds" \
  "$ATTESTATION_ENDPOINT" "$nonce" "$RESULT_DIR" \
  "$attestation_token" "$openid_json" "$jwks_json" \
  "$RESULT_DIR/attestation-client.stderr" \
  "$resource_group" "$vm_name" "$data_disk_name" "$AZURE_LOCATION"
guest_vm_id=$UBUNTU2404_CONFIDENTIAL_GUEST_VM_ID

now=$(date +%s)
"$RELEASE_TOOL" acceptance-result \
  --provenance "$PROVENANCE" \
  --qcow "$CANDIDATE" \
  --conversion "$conversion" \
  --sku "$sku_json" \
  --vm-size "$AZURE_VM_SIZE" \
  --disk "$disk_json" \
  --managed-image "$managed_image_json" \
  --definition "$definition_json" \
  --gallery-request "$gallery_request" \
  --gallery-response "$gallery_response" \
  --image-version-id "$image_version_id" \
  --vm-resource "$vm_resource" \
  --vm-instance "$vm_instance" \
  --token "$attestation_token" \
  --openid "$openid_json" \
  --jwks "$jwks_json" \
  --endpoint "$ATTESTATION_ENDPOINT" \
  --nonce "$nonce" \
  --now "$now" \
  --guest-vm-id "$guest_vm_id" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$AZURE_LOCATION" \
  --resource-group "$resource_group" \
  --output "$acceptance_result"

{
  echo "### Ubuntu 24.04 Confidential VM acceptance"
  echo
  echo "- Candidate SHA-256: \`$qcow_sha256\`"
  echo "- Upload VHD SHA-256: \`$vhd_sha256\`"
  echo "- Azure: \`$AZURE_LOCATION\` / \`$AZURE_VM_SIZE\`"
  echo "- Gallery image: \`$image_version_id\`"
  echo "- TEE: AMD SEV-SNP / \`azure-compliant-cvm\`"
  echo "- Secure Boot: enabled and attested"
  echo "- vTPM: present and attested"
  echo "- Reboot and persistent data-disk checks: passed"
} >>"$GITHUB_STEP_SUMMARY"
