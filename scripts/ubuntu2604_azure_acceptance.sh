#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/ubuntu2604_azure_acceptance_lib.sh
source "$script_dir/ubuntu2604_azure_acceptance_lib.sh"

# Release-schema integration contract: `verify-candidate`, `verify-vhd`,
# `azure-result`, and every document check below are subcommands of one native
# tool. Keep schema validation there rather than duplicating it in this
# acceptance harness.
RELEASE_TOOL=${UBUNTU2604_RELEASE_TOOL:-zig-out/bin/ubuntu2604_release}

command_name=${1:-run}
if (( $# > 1 )); then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi
if [[ -z ${STATE_FILE:-} || -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} || -z ${CANDIDATE_KEY:-} ]]; then
  echo "::error::Azure cleanup identity is incomplete"
  exit 1
fi
if ! [[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ &&
        "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ &&
        "$CANDIDATE_KEY" =~ ^(x86_64|aarch64)-(full|core)$ ]]; then
  echo "::error::Azure cleanup identity is invalid"
  exit 1
fi

cleanup_group() {
  [[ -s "$STATE_FILE" ]] || return 0
  [[ -x "$RELEASE_TOOL" ]] || {
    echo "::error::Ubuntu release tooling is unavailable at $RELEASE_TOOL"
    return 1
  }
  command -v az >/dev/null || {
    echo "::error::Azure CLI is unavailable during cleanup"
    return 1
  }
  local resource_group metadata_file group_exists expected_resource_group suffix
  resource_group=$(<"$STATE_FILE")
  suffix=${CANDIDATE_KEY//_/-}
  expected_resource_group="miz-u2604-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
  [[ "$resource_group" == "$expected_resource_group" ]] || {
    echo "::error::Refusing cleanup of unexpected resource-group name"
    return 1
  }
  if ! group_exists=$(az group exists --name "$resource_group" --output tsv); then
    echo "::error::Could not determine whether the temporary resource group exists"
    return 1
  fi
  case "$group_exists" in
    false) return 0 ;;
    true) ;;
    *)
      echo "::error::Azure returned an invalid resource-group existence result"
      return 1
      ;;
  esac
  metadata_file="${STATE_FILE}.group.json"
  if ! az group show --name "$resource_group" --output json >"$metadata_file"; then
    echo "::error::Could not inspect temporary resource-group ownership"
    return 1
  fi
  if ! "$RELEASE_TOOL" azure-cleanup-tags \
      --metadata "$metadata_file" \
      --run-id "$GITHUB_RUN_ID" \
      --run-attempt "$GITHUB_RUN_ATTEMPT" \
      --candidate-key "$CANDIDATE_KEY"
  then
    return 1
  fi
  if ! az group delete --name "$resource_group" --yes; then
    echo "::error::Failed to delete owned temporary resource group"
    return 1
  fi
}

if [[ "$command_name" == cleanup ]]; then
  cleanup_group
  exit
fi
if [[ "$command_name" != run ]]; then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi

if [[ -z ${CANDIDATE_DIR:-} || -z ${SOURCE_COMMIT:-} ||
      -z ${CANDIDATE_RUN_ID:-} || -z ${CANDIDATE_RUN_ATTEMPT:-} ||
      -z ${ARCHITECTURE:-} ||
      -z ${FLAVOR:-} || -z ${ASSET_NAME:-} || -z ${AZURE_LOCATION:-} ||
      -z ${AZURE_VM_SIZE:-} || -z ${RESULT_DIR:-} || -z ${MIZ:-} ||
      -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Azure acceptance configuration is incomplete"
  exit 1
fi
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$CANDIDATE_RUN_ID" =~ ^[1-9][0-9]*$ ]]
[[ "$CANDIDATE_RUN_ATTEMPT" =~ ^[1-9][0-9]*$ ]]
if ! ubuntu2604_validate_candidate_identity \
    "$CANDIDATE_KEY" "$ARCHITECTURE" "$FLAVOR" "$ASSET_NAME"
then
  echo "::error::Ubuntu candidate identity is invalid"
  exit 1
fi
[[ "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ ]]
[[ "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ ]]
[[ -x "$MIZ" ]]
[[ -x "$RELEASE_TOOL" ]]
if [[ -z ${RUNTIME_CONTRACT_PROBE:-} ]]; then
  echo "::error::Azure acceptance requires a runtime contract probe binary"
  exit 1
fi
[[ -x "$RUNTIME_CONTRACT_PROBE" ]] || {
  echo "::error::Runtime contract probe binary is not executable"
  exit 1
}
if [[ "$FLAVOR" == core ]]; then
  if [[ -z ${BINDER_PROBE:-} ]]; then
    echo "::error::Core Azure acceptance requires a Binder device probe binary"
    exit 1
  fi
  [[ -x "$BINDER_PROBE" ]] || {
    echo "::error::Binder device probe binary is not executable"
    exit 1
  }
fi

report_error() {
  local status=$1 line=$2 command=$3
  trap - ERR
  printf '::error::Azure acceptance failed at line %s: %s\n' "$line" "$command" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

for tool in az azcopy base64 curl qemu-img sha256sum ssh ssh-keygen; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required Azure acceptance tool $tool is unavailable"
    exit 1
  }
done
azure_contract_list=$(
  "$RELEASE_TOOL" azure-contracts --flavor "$FLAVOR"
)
[[ -n "$azure_contract_list" ]]

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
    rm -rf "$request_dir"
    return 1
  fi
  if [[ -z "$token" ]]; then
    echo "::error::Azure returned an empty management token" >&2
    rm -rf "$request_dir"
    return 1
  fi
  write_bearer_header "$token" "$auth_header"
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
    rm -rf "$request_dir"
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
    if [[ "$location" != https://* ]]; then
      echo "::error::Azure disk access response omitted the polling location" >&2
      rm -rf "$request_dir"
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
        rm -rf "$request_dir"
        return 1
      fi
      [[ "$status" == 202 ]] || break
    done
  fi
  if [[ "$status" != 200 ]]; then
    echo "::error::Azure disk access polling ended with HTTP $status" >&2
    rm -rf "$request_dir"
    return 1
  fi
  if ! sas=$(
      "$RELEASE_TOOL" azure-disk-access --response "$response_body"
    )
  then
    echo "::error::Azure disk access response was not valid JSON" >&2
    rm -rf "$request_dir"
    return 1
  fi
  rm -rf "$request_dir"
  if [[ "$sas" != https://* ]]; then
    echo "::error::Azure disk access response omitted the SAS URL" >&2
    return 1
  fi
  printf '%s\n' "$sas"
}

mkdir -p "$RESULT_DIR"
manifest="$CANDIDATE_DIR/candidate.json"
asset="$CANDIDATE_DIR/$ASSET_NAME"
readarray -t candidate < <(
  "$RELEASE_TOOL" verify-candidate \
    --manifest "$manifest" \
    --asset "$asset" \
    --key "$CANDIDATE_KEY" \
    --source-commit "$SOURCE_COMMIT" \
    --run-id "$CANDIDATE_RUN_ID" \
    --run-attempt "$CANDIDATE_RUN_ATTEMPT"
)
test "${#candidate[@]}" -eq 3
qcow_sha256=${candidate[0]}
qcow_bytes=${candidate[1]}
virtual_size=${candidate[2]}
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$qcow_bytes" =~ ^[0-9]+$ ]]
[[ "$virtual_size" =~ ^[0-9]+$ ]]
# Canonical's sparse GPT keeps root in entry 1 and boot partitions in later
# slots, so root growth must be measured from its architecture-specific start.
case "$ARCHITECTURE" in
  x86_64) root_first_lba=2324480 ;;
  aarch64) root_first_lba=2099200 ;;
  *) echo "::error::Unsupported Ubuntu architecture: $ARCHITECTURE"; exit 1 ;;
esac
gpt_sector_size=512
gpt_partition_array_sectors=32
test "$((virtual_size % gpt_sector_size))" -eq 0
total_sectors=$((virtual_size / gpt_sector_size))
last_usable_lba=$((total_sectors - 2 - gpt_partition_array_sectors))
test "$root_first_lba" -le "$last_usable_lba"
original_root_size=$(((last_usable_lba - root_first_lba + 1) * gpt_sector_size))
minimum_grown_root_size=$((original_root_size + 1073741824))

suffix=${CANDIDATE_KEY//_/-}
resource_group="miz-u2604-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
short_arch=${ARCHITECTURE/x86_64/x64}
name_seed="${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}${short_arch}${FLAVOR}"
disk_name="miz-os-${name_seed}"
data_disk_name="miz-data-${name_seed}"
gallery_name="mizu2604${name_seed}"
image_name="mizu2604${short_arch}${FLAVOR}"
vm_name="miz-vm-${name_seed}"
vnet_name="miz-vnet-${name_seed}"
subnet_name="miz-subnet-${name_seed}"
public_ip_name="miz-ip-${name_seed}"
nsg_name="miz-nsg-${name_seed}"
nic_name="miz-nic-${name_seed}"
admin_username=miztest
vhd="$RESULT_DIR/${CANDIDATE_KEY}.vhd"
private_key="$RESULT_DIR/id_ed25519"
boot_log="$RESULT_DIR/boot.log"
boot_screenshot="$RESULT_DIR/boot-screenshot.png"
failure_diagnostics="$RESULT_DIR/failure-diagnostics.json"
failure_instance_view="$RESULT_DIR/failure-instance-view.json"
boot_diagnostics_errors="$RESULT_DIR/boot-diagnostics-errors.log"
boot_diagnostics_attempt_error="$RESULT_DIR/boot-diagnostics-attempt.stderr"
sku_json="$RESULT_DIR/sku.json"
certificate_der="$RESULT_DIR/signing-certificate.der"
uefi_request="$RESULT_DIR/gallery-version-request.json"
uefi_create_response="$RESULT_DIR/gallery-version-create-response.json"
uefi_response="$RESULT_DIR/gallery-version-response.json"
vm_security_json="$RESULT_DIR/vm-security.json"
instance_security_json="$RESULT_DIR/instance-security.json"
conversion_attestation="$RESULT_DIR/conversion-attestation.json"
vm_create_stderr="$RESULT_DIR/vm-create.stderr"
vm_request="$RESULT_DIR/vm-request.json"
mkdir -p "$(dirname -- "$STATE_FILE")"
rm -f -- "$STATE_FILE" "${STATE_FILE}.group.json" "$vhd" "$private_key" "$private_key.pub"
# Writes the canonical DER signing certificate next to the acceptance results
# and reports the digests this harness binds, all re-derived from the candidate
# manifest that was just verified.
readarray -t signing_identity < <(
  "$RELEASE_TOOL" candidate-signing-env \
    --manifest "$manifest" \
    --certificate "$certificate_der"
)
test "${#signing_identity[@]}" -eq 3
certificate_sha256=${signing_identity[1]}
fallback_uki_sha256=${signing_identity[2]}
[[ "$certificate_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$fallback_uki_sha256" =~ ^[0-9a-f]{64}$ ]]

download_boot_artifact() {
  local uri=$1
  local output=$2
  timeout 90s "$RELEASE_TOOL" azure-boot-artifact --uri "$uri" --output "$output"
}

record_boot_diagnostics_error() {
  local operation=$1
  local error_file=$2
  {
    printf '%s\n' "--- $operation ---"
    if [[ -s "$error_file" ]]; then
      # Azure diagnostic blob URIs carry SAS credentials. Preserve the API
      # error while ensuring a URI can never enter the uploaded artifact.
      sed -E 's#https://[^[:space:]]+#<redacted-url>#g' "$error_file" |
        head -c 16384 || true
      printf '\n'
    else
      printf '%s\n' '(command failed without stderr)'
    fi
  } >>"$boot_diagnostics_errors"
  rm -f -- "$error_file"
}

retrieve_managed_boot_log() {
  local output=$1
  local error_file=$2
  rm -f -- "$output" "$error_file"
  if ! timeout 90s az vm boot-diagnostics get-boot-log \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --output tsv >"$output" 2>"$error_file"; then
    rm -f -- "$output"
    return 1
  fi
  if [[ ! -s "$output" ]]; then
    printf '%s\n' 'Azure returned an empty managed boot log' >"$error_file"
    rm -f -- "$output"
    return 1
  fi
  if head -c 512 "$output" | grep -Eq '<Error>|<Code>BlobNotFound</Code>'; then
    mv -- "$output" "$error_file"
    return 1
  fi
  rm -f -- "$error_file"
}

collect_failure_diagnostics() {
  local instance_view_status=unavailable
  local boot_log_status=unavailable
  local boot_screenshot_status=unavailable
  local serial_console_uri=
  local console_screenshot_uri=
  : >"$boot_diagnostics_errors"
  rm -f -- "$boot_diagnostics_attempt_error"

  if timeout 60s az vm get-instance-view \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --query 'instanceView.{statuses:statuses[].{code:code,displayStatus:displayStatus,level:level,time:time},vmAgent:vmAgent.statuses[].{code:code,displayStatus:displayStatus,level:level,time:time}}' \
      --output json >"$failure_instance_view" 2>"$boot_diagnostics_attempt_error"; then
    instance_view_status=retrieved
    rm -f -- "$boot_diagnostics_attempt_error"
  else
    rm -f -- "$failure_instance_view"
    record_boot_diagnostics_error "instance view" "$boot_diagnostics_attempt_error"
  fi

  # Managed boot diagnostics can take up to ~2 minutes to populate after a
  # VM is created, so a single attempt right after a failure can legitimately
  # come back empty even though the data exists; retry briefly (see #660).
  local diagnostics_attempt=0
  while (( diagnostics_attempt < 4 )) && [[ "$boot_log_status" != retrieved ]]; do
    diagnostics_attempt=$((diagnostics_attempt + 1))
    if (( diagnostics_attempt > 1 )); then sleep 20; fi

    serial_console_uri=$(timeout 60s az vm get-instance-view \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --query instanceView.bootDiagnostics.serialConsoleLogBlobUri \
      --output tsv 2>"$boot_diagnostics_attempt_error") || {
      serial_console_uri=
      record_boot_diagnostics_error \
        "serial console URI attempt $diagnostics_attempt" \
        "$boot_diagnostics_attempt_error"
    }
    rm -f -- "$boot_diagnostics_attempt_error"
    if [[ "$serial_console_uri" == https://* ]]; then
      if download_boot_artifact \
          "$serial_console_uri" "$boot_log" 2>"$boot_diagnostics_attempt_error" &&
          [[ -s "$boot_log" ]]; then
        boot_log_status=retrieved
        rm -f -- "$boot_diagnostics_attempt_error"
      else
        rm -f -- "$boot_log"
        record_boot_diagnostics_error \
          "serial console download attempt $diagnostics_attempt" \
          "$boot_diagnostics_attempt_error"
      fi
    else
      printf '%s\n' \
        "--- serial console URI attempt $diagnostics_attempt ---" \
        '(instance view returned no serial-console URI)' \
        >>"$boot_diagnostics_errors"
    fi
    serial_console_uri=

    if [[ "$boot_log_status" != retrieved ]]; then
      if retrieve_managed_boot_log \
          "$boot_log" "$boot_diagnostics_attempt_error"; then
        boot_log_status=retrieved
      else
        record_boot_diagnostics_error \
          "direct boot log attempt $diagnostics_attempt" \
          "$boot_diagnostics_attempt_error"
      fi
    fi
  done

  console_screenshot_uri=$(timeout 60s az vm get-instance-view \
    --resource-group "$resource_group" \
    --name "$vm_name" \
    --query instanceView.bootDiagnostics.consoleScreenshotBlobUri \
    --output tsv 2>"$boot_diagnostics_attempt_error") || {
    console_screenshot_uri=
    record_boot_diagnostics_error \
      "console screenshot URI" \
      "$boot_diagnostics_attempt_error"
  }
  rm -f -- "$boot_diagnostics_attempt_error"
  if [[ "$console_screenshot_uri" == https://* ]]; then
    if download_boot_artifact \
        "$console_screenshot_uri" "$boot_screenshot" \
        2>"$boot_diagnostics_attempt_error"; then
      boot_screenshot_status=retrieved
      rm -f -- "$boot_diagnostics_attempt_error"
    else
      rm -f -- "$boot_screenshot"
      record_boot_diagnostics_error \
        "console screenshot download" \
        "$boot_diagnostics_attempt_error"
    fi
  else
    printf '%s\n' \
      '--- console screenshot URI ---' \
      '(instance view returned no console-screenshot URI)' \
      >>"$boot_diagnostics_errors"
  fi
  console_screenshot_uri=

  "$RELEASE_TOOL" azure-failure-diagnostics \
    --output "$failure_diagnostics" \
    --instance-view "$instance_view_status" \
    --serial-console-log "$boot_log_status" \
    --console-screenshot "$boot_screenshot_status"
}

cleanup_on_exit() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 ]] &&
      az vm show --resource-group "$resource_group" --name "$vm_name" >/dev/null 2>&1; then
    collect_failure_diagnostics
  fi
  rm -f -- "$vhd" "$private_key" "$private_key.pub"
  if ! cleanup_group; then
    status=1
  fi
  exit "$status"
}
trap cleanup_on_exit EXIT
trap 'exit 130' INT TERM

if ! group_exists=$(az group exists --name "$resource_group" --output tsv); then
  echo "::error::Could not check for a resource-group collision"
  exit 1
fi
case "$group_exists" in
  true)
    echo "::error::Collision-resistant resource group already exists: $resource_group"
    exit 1
    ;;
  false) ;;
  *)
    echo "::error::Azure returned an invalid resource-group existence result"
    exit 1
    ;;
esac
printf '%s\n' "$resource_group" >"$STATE_FILE"
if ! az group create \
  --name "$resource_group" \
  --location "$AZURE_LOCATION" \
  --tags \
    miz-owner=ubuntu2604-release \
    "miz-run-id=$GITHUB_RUN_ID" \
    "miz-run-attempt=$GITHUB_RUN_ATTEMPT" \
    "miz-candidate=$CANDIDATE_KEY" \
  --output json >/dev/null
then
  echo "::error::Failed to create the persisted temporary resource group"
  exit 1
fi

az vm list-skus \
  --location "$AZURE_LOCATION" \
  --resource-type virtualMachines \
  --size "$AZURE_VM_SIZE" \
  --all \
  --output json >"$sku_json"
expected_azure_architecture=x64
runtime_architecture=x86_64
azure_image_architecture=x64
if [[ "$ARCHITECTURE" == aarch64 ]]; then
  expected_azure_architecture=Arm64
  runtime_architecture=aarch64
  azure_image_architecture=Arm64
fi
readarray -t sku_storage < <(
  "$RELEASE_TOOL" azure-sku \
    --sku "$sku_json" \
    --vm-size "$AZURE_VM_SIZE" \
    --architecture "$expected_azure_architecture"
)
test "${#sku_storage[@]}" -eq 2
has_conventional_resource_disk=${sku_storage[0]}
has_local_temp_storage=${sku_storage[1]}
[[ "$has_conventional_resource_disk" == true ||
   "$has_conventional_resource_disk" == false ]]
[[ "$has_local_temp_storage" == true ||
   "$has_local_temp_storage" == false ]]

source_before=$(sha256sum "$asset" | awk '{print $1}')
test "$source_before" = "$qcow_sha256"
"$MIZ" azure derive \
  --input-sha256 "$qcow_sha256" \
  --expected-virtual-size "$virtual_size" \
  "$asset" \
  "$vhd"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"
qemu-img info -f vpc --output=json "$vhd" >"$RESULT_DIR/vhd-info.json"
readarray -t vhd_geometry < <(
  "$RELEASE_TOOL" verify-vhd \
    --info "$RESULT_DIR/vhd-info.json" \
    --vhd "$vhd"
)
test "${#vhd_geometry[@]}" -eq 2
vhd_current_size=${vhd_geometry[0]}
vhd_bytes=${vhd_geometry[1]}
expected_vhd_current_size=$(((virtual_size + 1048575) / 1048576 * 1048576))
test "$vhd_current_size" -eq "$expected_vhd_current_size"
test "$vhd_bytes" -eq "$((vhd_current_size + 512))"
vhd_sha256=$(sha256sum "$vhd" | awk '{print $1}')
[[ "$vhd_sha256" =~ ^[0-9a-f]{64}$ ]]
"$RELEASE_TOOL" azure-conversion-attestation \
  --output "$conversion_attestation" \
  --key "$CANDIDATE_KEY" \
  --asset-name "$ASSET_NAME" \
  --qcow-sha256 "$qcow_sha256" \
  --qcow-bytes "$qcow_bytes" \
  --virtual-size "$virtual_size" \
  --vhd-sha256 "$vhd_sha256" \
  --vhd-bytes "$vhd_bytes" \
  --vhd-current-size "$vhd_current_size" \
  --info "$RESULT_DIR/vhd-info.json"

az disk create \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --location "$AZURE_LOCATION" \
  --sku Standard_LRS \
  --upload-type Upload \
  --upload-size-bytes "$vhd_bytes" \
  --os-type Linux \
  --hyper-v-generation V2 \
  --architecture "$azure_image_architecture" \
  --output json >/dev/null
disk_id=$(az disk show \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --query id \
  --output tsv)
[[ "$disk_id" == /subscriptions/* ]]
upload_sas=$(grant_disk_write_access "$disk_id" 7200)
[[ "$upload_sas" == https://* ]]
echo "::add-mask::$upload_sas"
azcopy copy "$vhd" "$upload_sas" --blob-type PageBlob
az disk revoke-access \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --output json >/dev/null
upload_sas=

expanded_size_gib=$(((vhd_current_size + 1073741823) / 1073741824 + 2))
az disk update \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --size-gb "$expanded_size_gib" \
  --output json >/dev/null

az sig create \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --location "$AZURE_LOCATION" \
  --output json >/dev/null
az sig image-definition create \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_name" \
  --publisher miz \
  --offer ubuntu2604 \
  --sku "${short_arch}-${FLAVOR}" \
  --os-type Linux \
  --os-state Generalized \
  --hyper-v-generation V2 \
  --architecture "$azure_image_architecture" \
  --features SecurityType=TrustedLaunchSupported \
  --location "$AZURE_LOCATION" \
  --output json >/dev/null
image_definition_id=$(az sig image-definition show \
  --resource-group "$resource_group" \
  --gallery-name "$gallery_name" \
  --gallery-image-definition "$image_name" \
  --query id \
  --output tsv)
[[ "$image_definition_id" == /subscriptions/* ]]
image_version_id="$image_definition_id/versions/1.0.0"
"$RELEASE_TOOL" azure-gallery-request \
  --output "$uefi_request" \
  --location "$AZURE_LOCATION" \
  --disk-id "$disk_id" \
  --certificate "$certificate_der"
az rest \
  --method put \
  --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03" \
  --body "@$uefi_request" \
  --output json >"$uefi_response"
cp "$uefi_response" "$uefi_create_response"
"$RELEASE_TOOL" azure-gallery-accepted \
  --request "$uefi_request" \
  --response "$uefi_create_response"
for _ in {1..120}; do
  provisioning_state=$(
    "$RELEASE_TOOL" azure-gallery-state --response "$uefi_response"
  )
  case "$provisioning_state" in
    Succeeded) break ;;
    Failed|Canceled)
      echo "::error::Gallery image-version provisioning ended in $provisioning_state"
      exit 1
      ;;
  esac
  sleep 10
  az rest \
    --method get \
    --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03" \
    --output json >"$uefi_response"
done
test "$provisioning_state" = Succeeded
"$RELEASE_TOOL" azure-gallery-verify \
  --request "$uefi_request" \
  --response "$uefi_response" \
  --image-version-id "$image_version_id"
[[ "$image_version_id" == /subscriptions/* ]]

ssh-keygen -q -t ed25519 -N '' -C miz-azure-acceptance -f "$private_key"
# core ships azagent, a minimal guest agent that deliberately does not
# implement the VM extension/status-blob handshake real waagent uses (see
# azagent/main.zig, issue #112). Requesting --enable-agent true for core
# makes Azure's OS-provisioning wait on that handshake and it never arrives,
# so az vm create reliably fails with OSProvisioningTimedOut.
enable_agent=true
if [[ "$FLAVOR" == core ]]; then
  enable_agent=false
fi
vm_create_status=0
if [[ "$CANDIDATE_KEY" == x86_64-core ]]; then
  # Azure CLI cannot express managed boot diagnostics during `az vm create`
  # (Azure/azure-cli#30340). Build the network with the CLI, then deploy the VM
  # resource with diagnostics enabled in its initial ARM request so serial
  # output exists even when OS provisioning reaches a terminal failure.
  az network vnet create \
    --resource-group "$resource_group" \
    --name "$vnet_name" \
    --location "$AZURE_LOCATION" \
    --subnet-name "$subnet_name" \
    --output none
  az network public-ip create \
    --resource-group "$resource_group" \
    --name "$public_ip_name" \
    --location "$AZURE_LOCATION" \
    --sku Standard \
    --allocation-method Static \
    --output none
  az network nsg create \
    --resource-group "$resource_group" \
    --name "$nsg_name" \
    --location "$AZURE_LOCATION" \
    --output none
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
  az network nic create \
    --resource-group "$resource_group" \
    --name "$nic_name" \
    --location "$AZURE_LOCATION" \
    --vnet-name "$vnet_name" \
    --subnet "$subnet_name" \
    --network-security-group "$nsg_name" \
    --public-ip-address "$public_ip_name" \
    --output none
  nic_id=$(az network nic show \
    --resource-group "$resource_group" \
    --name "$nic_name" \
    --query id \
    --output tsv)
  [[ "$nic_id" == /subscriptions/*/resourceGroups/*/providers/Microsoft.Network/networkInterfaces/* ]]
  ssh_public_key=$(<"$private_key.pub")
  jq -n \
    --arg location "$AZURE_LOCATION" \
    --arg vm_name "$vm_name" \
    --arg vm_size "$AZURE_VM_SIZE" \
    --arg image_id "$image_version_id" \
    --arg admin_username "$admin_username" \
    --arg ssh_public_key "$ssh_public_key" \
    --arg nic_id "$nic_id" \
    --argjson enable_agent "$enable_agent" \
    '{
      location: $location,
      properties: {
        hardwareProfile: {vmSize: $vm_size},
        storageProfile: {
          imageReference: {id: $image_id},
          osDisk: {
            createOption: "FromImage",
            caching: "ReadWrite",
            deleteOption: "Delete"
          }
        },
        osProfile: {
          computerName: $vm_name,
          adminUsername: $admin_username,
          linuxConfiguration: {
            disablePasswordAuthentication: true,
            provisionVMAgent: $enable_agent,
            ssh: {publicKeys: [{
              path: ("/home/" + $admin_username + "/.ssh/authorized_keys"),
              keyData: $ssh_public_key
            }]}
          }
        },
        networkProfile: {networkInterfaces: [{
          id: $nic_id,
          properties: {primary: true, deleteOption: "Delete"}
        }]},
        securityProfile: {
          securityType: "TrustedLaunch",
          uefiSettings: {secureBootEnabled: true, vTpmEnabled: true}
        },
        diagnosticsProfile: {bootDiagnostics: {enabled: true}}
      }
    }' >"$vm_request"
  resource_group_id=$(az group show \
    --name "$resource_group" \
    --query id \
    --output tsv)
  vm_id="${resource_group_id}/providers/Microsoft.Compute/virtualMachines/${vm_name}"
  az rest \
    --method put \
    --uri "https://management.azure.com${vm_id}?api-version=2024-11-01" \
    --body "@$vm_request" \
    --output none 2>"$vm_create_stderr" || vm_create_status=$?
  if [[ "$vm_create_status" -eq 0 ]]; then
    diagnostics_enabled=
    for _ in {1..12}; do
      diagnostics_enabled=$(az vm show \
        --resource-group "$resource_group" \
        --name "$vm_name" \
        --query diagnosticsProfile.bootDiagnostics.enabled \
        --output tsv 2>/dev/null) || diagnostics_enabled=
      [[ "$diagnostics_enabled" == true ]] && break
      sleep 5
    done
    test "$diagnostics_enabled" = true

    vm_provisioning_state=
    for _ in {1..180}; do
      vm_provisioning_state=$(az vm show \
        --resource-group "$resource_group" \
        --name "$vm_name" \
        --query provisioningState \
        --output tsv 2>/dev/null) || vm_provisioning_state=
      case "$vm_provisioning_state" in
        Succeeded) break ;;
        Failed)
          printf '%s\n' \
            "::error::VM provisioning reached terminal state $vm_provisioning_state" \
            >"$vm_create_stderr"
          vm_create_status=1
          break
          ;;
      esac
      sleep 10
    done
    if [[ "$vm_provisioning_state" != Succeeded ]] &&
        [[ "$vm_create_status" -eq 0 ]]; then
      printf '%s\n' \
        "::error::VM provisioning did not succeed within 30 minutes (last state: ${vm_provisioning_state:-unavailable})" \
        >"$vm_create_stderr"
      vm_create_status=124
    fi
  fi
else
  az vm create \
    --resource-group "$resource_group" \
    --name "$vm_name" \
    --location "$AZURE_LOCATION" \
    --size "$AZURE_VM_SIZE" \
    --image "$image_version_id" \
    --admin-username "$admin_username" \
    --authentication-type ssh \
    --ssh-key-values "$private_key.pub" \
    --enable-agent "$enable_agent" \
    --enable-auto-update false \
    --security-type TrustedLaunch \
    --enable-secure-boot true \
    --enable-vtpm true \
    --public-ip-sku Standard \
    --nsg-rule SSH \
    --output json >/dev/null 2>"$vm_create_stderr" || vm_create_status=$?
fi
if [[ "$vm_create_status" -ne 0 ]]; then
  cat -- "$vm_create_stderr" >&2
  # Two real x86_64-core deployments remained failed throughout the former
  # 20-minute late-success poll (#660). Fail immediately so diagnostics and
  # targeted retry can start without adding a disproven recovery delay.
  exit "$vm_create_status"
fi
az vm show \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query securityProfile \
  --output json >"$vm_security_json"
az vm get-instance-view \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query securityProfile \
  --output json >"$instance_security_json"
"$RELEASE_TOOL" azure-vm-security \
  --vm "$vm_security_json" \
  --instance "$instance_security_json"
public_ip=$(az vm show \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --show-details \
  --query publicIps \
  --output tsv)
[[ "$public_ip" =~ ^[0-9a-fA-F:.]+$ ]]
test "$(az vm get-instance-view \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query "instanceView.statuses[?code=='ProvisioningState/succeeded'].code | [0]" \
  --output tsv)" = ProvisioningState/succeeded

ssh_options=(
  -i "$private_key"
  -o BatchMode=yes
  -o ConnectTimeout=5
  -o ConnectionAttempts=1
  -o IdentitiesOnly=yes
  -o KbdInteractiveAuthentication=no
  -o PasswordAuthentication=no
  -o NumberOfPasswordPrompts=0
  -o PreferredAuthentications=publickey
  -o StrictHostKeyChecking=no
  -o UserKnownHostsFile=/dev/null
)
ssh_target="$admin_username@$public_ip"

wait_for_ssh() {
  for _ in {1..180}; do
    if ssh "${ssh_options[@]}" "$ssh_target" true >/dev/null 2>&1; then
      return
    fi
    sleep 5
  done
  echo "::error::Timed out waiting for key-only SSH"
  return 1
}

reboot_and_reconnect() {
  local old_boot_id=$1
  ssh "${ssh_options[@]}" "$ssh_target" 'sudo -n /sbin/reboot' >/dev/null 2>&1 || true
  local boot_id
  for _ in {1..180}; do
    boot_id=$(ssh "${ssh_options[@]}" "$ssh_target" \
      'cat /proc/sys/kernel/random/boot_id' 2>/dev/null || true)
    if [[ -n "$boot_id" && "$boot_id" != "$old_boot_id" ]]; then
      return
    fi
    sleep 5
  done
  echo "::error::Guest did not reboot and reconnect with a new boot ID"
  return 1
}

read_core_sshd_pid() {
  ssh "${ssh_options[@]}" "$ssh_target" '/usr/bin/bash -s' <<'GUEST'
set -euo pipefail
for proc in /proc/[0-9]*; do
  test -r "$proc/status" || continue
  name= ppid=
  while read -r key value _; do
    case "$key" in
      Name:) name=$value ;;
      PPid:) ppid=$value ;;
    esac
  done <"$proc/status"
  test "$name" = sshd && test "$ppid" = 1 || continue
  case "$(tr '\000' ' ' <"$proc/cmdline")" in
    *"/usr/sbin/sshd -D -e"*) printf '%s\n' "${proc##*/}"; exit 0 ;;
  esac
done
exit 1
GUEST
}

wait_for_ssh
if ssh \
  -o BatchMode=yes \
  -o ConnectTimeout=5 \
  -o PreferredAuthentications=none \
  -o PubkeyAuthentication=no \
  -o PasswordAuthentication=no \
  -o KbdInteractiveAuthentication=no \
  -o StrictHostKeyChecking=no \
  -o UserKnownHostsFile=/dev/null \
  "$ssh_target" true >/dev/null 2>&1; then
  echo "::error::SSH unexpectedly accepted a connection without the generated key"
  exit 1
fi

ssh "${ssh_options[@]}" "$ssh_target" \
  "/usr/bin/bash -s -- '$vhd_current_size' '$minimum_grown_root_size' '$runtime_architecture' '$ARCHITECTURE'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
original_size=$1
minimum_grown_root_size=$2
runtime_arch=$3
release_arch=$4
test "$(id -un)" = miztest
test "$(uname -m)" = "$runtime_arch"
sshd_config=$(sudo -n /usr/sbin/sshd -T)
grep -Fxq 'passwordauthentication no' <<<"$sshd_config"
grep -Fxq 'kbdinteractiveauthentication no' <<<"$sshd_config"
case "$release_arch" in
  x86_64) grep -Fwq 'console=ttyS0,115200n8' /proc/cmdline ;;
  aarch64) grep -Fwq 'console=ttyAMA0,115200n8' /proc/cmdline ;;
esac
root_source=$(findmnt -n -o SOURCE /)
root_device=$(readlink -f "$root_source")
root_disk_name=$(lsblk -n -o PKNAME "$root_device")
test -n "$root_disk_name"
disk_size=$(sudo -n blockdev --getsize64 "/dev/$root_disk_name")
root_size=$(sudo -n blockdev --getsize64 "$root_device")
test "$disk_size" -gt "$original_size"
test "$root_size" -gt "$minimum_grown_root_size"
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
GUEST

uefi_report="$RESULT_DIR/uefi-variables.txt"
# Issue #677 step 6: the UEFI signature database is read by the static contract
# probe, not by mounting efivarfs in the shell. `mount` is util-linux, which the
# minimized core closure does not install, and retaining a package because
# acceptance used it is exactly what #677 forbids. The probe mounts efivarfs
# itself when nothing already has, on its own mountpoint, and unmounts only what
# it mounted.
runtime_contract_remote=/home/miztest/.miz-runtime-contract-probe
runtime_contract_sha256=$(sha256sum "$RUNTIME_CONTRACT_PROBE" | awk '{print $1}')
base64 -w0 "$RUNTIME_CONTRACT_PROBE" | ssh "${ssh_options[@]}" "$ssh_target" \
  "set -eu; rm -f -- '$runtime_contract_remote'; umask 077; base64 -d >'$runtime_contract_remote'; chmod 0700 '$runtime_contract_remote'"
runtime_contract_remote_sha256=$(
  ssh "${ssh_options[@]}" "$ssh_target" "sha256sum '$runtime_contract_remote'" |
    awk '{print $1}'
)
test "$runtime_contract_remote_sha256" = "$runtime_contract_sha256"

ssh "${ssh_options[@]}" "$ssh_target" \
  "sudo -n '$runtime_contract_remote' efivar db-d719b2cb-3d3a-4596-a3bc-dad00e67656f SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c; sudo -n '$runtime_contract_remote' requirement secure-boot kernel-lockdown; exit 0" \
  >"$uefi_report"
test -s "$uefi_report"
"$RELEASE_TOOL" azure-uefi-db \
  --report "$uefi_report" \
  --certificate-sha256 "$certificate_sha256"
"$RELEASE_TOOL" runtime-contract-requirement \
  --report "$uefi_report" \
  --id secure-boot,kernel-lockdown
ssh "${ssh_options[@]}" "$ssh_target" \
  "/usr/bin/bash -s -- '$FLAVOR'" <<'GUEST'
set -euo pipefail
flavor=$1
test -c /dev/tpm0
test -c /dev/tpmrm0
for module in hv_netvsc crc_itu_t udf isofs; do
  if ! test -d "/sys/module/$module"; then
    sudo -n /usr/sbin/modprobe "$module"
  fi
  test -d "/sys/module/$module"
done
dmesg_output=$(sudo -n /usr/bin/dmesg) || exit 1
if printf '%s\n' "$dmesg_output" | grep -Eiq 'module verification failed|Loading of unsigned module|Lockdown:.*unsigned'; then
  exit 1
fi
if [[ "$flavor" == core ]]; then
  module_info=$(/usr/sbin/modinfo binder_linux)
  module_filename=$(printf '%s\n' "$module_info" | awk -F': +' '/^filename:/{print $2; exit}')
  module_signer=$(printf '%s\n' "$module_info" | awk -F': +' '/^signer:/{print $2; exit}')
  module_sig_id=$(printf '%s\n' "$module_info" | awk -F': +' '/^sig_id:/{print $2; exit}')
  # Official in-tree module only: reject a DKMS/out-of-tree build path.
  case "$module_filename" in
    /lib/modules/*/kernel/*|/usr/lib/modules/*/kernel/*) ;;
    *) exit 1 ;;
  esac
  case "$module_filename" in
    */updates/dkms/*) exit 1 ;;
  esac
  test -n "$module_signer"
  test "$module_sig_id" = "PKCS#7"
  if printf '%s\n' "$module_info" | grep -iq anbox; then
    exit 1
  fi
  if command -v dkms >/dev/null 2>&1 && /usr/sbin/dkms status | grep -Eq '.'; then
    exit 1
  fi
  if grep -iq anbox /proc/modules; then
    exit 1
  fi
  # An untainted module is neither out-of-tree (O) nor unsigned (E), among
  # other kernel-integrity flags; the official signed driver carries none.
  module_taint=$(cat /sys/module/binder_linux/taint 2>/dev/null || true)
  test -z "$module_taint"
  if printf '%s\n' "$dmesg_output" |
      grep -Eiq 'anbox|binder_linux:.*(verification failed|taint)'; then
    exit 1
  fi
fi
GUEST

if [[ "$FLAVOR" == core ]]; then
  binder_probe_remote=/home/miztest/.miz-binder-probe
  binder_probe_sha256=$(sha256sum "$BINDER_PROBE" | awk '{print $1}')
  base64 -w0 "$BINDER_PROBE" | ssh "${ssh_options[@]}" "$ssh_target" \
    "set -eu; rm -f -- '$binder_probe_remote'; umask 077; base64 -d >'$binder_probe_remote'; chmod 0700 '$binder_probe_remote'"
  binder_probe_remote_sha256=$(
    ssh "${ssh_options[@]}" "$ssh_target" "sha256sum '$binder_probe_remote'" |
      awk '{print $1}'
  )
  test "$binder_probe_remote_sha256" = "$binder_probe_sha256"

  ssh "${ssh_options[@]}" "$ssh_target" \
    "/usr/bin/bash -s -- '$binder_probe_remote'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
probe=$1

# The binderfs mount type, every fixed device node, and the DMA heap are
# `runtime-contract` requirements, evaluated by the static contract probe with
# syscalls alone (issue #677 step 2). Re-checking them here with `findmnt` and
# `test -c` would make the image keep those utilities for a test's sake.
binderfs_mount=/dev/binderfs

# A real, driver-backed BINDER_VERSION ioctl on each fixed device, and a
# real BINDER_CTL_ADD dynamic allocation through binder-control.
sudo -n /usr/bin/chmod 0755 "$probe"
for device in binder hwbinder vndbinder; do
  sudo -n "$probe" version "$binderfs_mount/$device"
done
sudo -n "$probe" alloc "$binderfs_mount/binder-control" miz-acceptance-probe
sudo -n "$probe" version "$binderfs_mount/miz-acceptance-probe"
sudo -n /usr/bin/rm -f -- "$binderfs_mount/miz-acceptance-probe" "$probe"
GUEST

  # `runtime-contract`: the explicit allowlist issue #677 step 2 defines,
  # evaluated inside the guest by a static probe rather than by shell
  # utilities, and judged on the host by the release tool so a partial or
  # unparseable report can never read as agreement. The probe is already in
  # the guest: the UEFI variable read above uploaded and verified it.
  ssh "${ssh_options[@]}" "$ssh_target" \
    "sudo -n '$runtime_contract_remote' contract" \
    >"$RESULT_DIR/runtime-contract-report.txt"
  test -s "$RESULT_DIR/runtime-contract-report.txt"
  "$RELEASE_TOOL" runtime-contract-probe-verify \
    --report "$RESULT_DIR/runtime-contract-report.txt"
fi

ssh "${ssh_options[@]}" "$ssh_target" \
  "sudo -n /usr/bin/rm -f -- '$runtime_contract_remote'"

if [[ "$FLAVOR" == core ]]; then
  readarray -t core_identity < <(
    ssh "${ssh_options[@]}" "$ssh_target" \
      "/usr/bin/bash -s -- '$has_local_temp_storage'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
has_local_temp_storage=$1
sudo -n /usr/bin/test /proc/1/exe -ef /sbin/mizinit
test -x /usr/sbin/azagent
test -s /var/lib/azagent/provisioned
test "$(cat /var/lib/azagent/provisioned)" = "$(cat /etc/hostname)"
test ! -d /run/systemd/system
for binary in cloud-init waagent WALinuxAgent; do
  ! command -v "$binary" >/dev/null 2>&1
done
for path in \
  /usr/bin/cloud-init \
  /usr/sbin/cloud-init \
  /usr/bin/waagent \
  /usr/sbin/waagent \
  /usr/sbin/WALinuxAgent.py \
  /usr/sbin/WALinuxAgent \
  /etc/cloud \
  /usr/lib/python3/dist-packages/azurelinuxagent \
  /usr/lib/python3/dist-packages/cloudinit \
  /var/lib/cloud \
  /run/cloud-init \
  /var/lib/waagent \
  /var/log/waagent.log \
  /var/log/azure
do
  test ! -e "$path"
done
self=$$
for proc in /proc/[0-9]*; do
  test "${proc##*/}" = "$self" && continue
  test -r "$proc/cmdline" || continue
  cmdline=$(tr '\000' ' ' <"$proc/cmdline")
  case "$cmdline" in
    *cloud-init*|*waagent*|*WALinuxAgent*|*azurelinuxagent*) exit 1 ;;
  esac
  executable=$(readlink "$proc/exe" 2>/dev/null || true)
  test "$executable" != /usr/sbin/azagent
  case "$executable" in
    /usr/lib/systemd/systemd|/lib/systemd/systemd) exit 1 ;;
  esac
done
for status in /proc/[0-9]*/status; do
  test -r "$status" || continue
  ppid= state=
  while read -r key value _; do
    case "$key" in
      PPid:) ppid=$value ;;
      State:) state=$value ;;
    esac
  done <"$status"
  test "$ppid" != 1 || test "$state" != Z
done
grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*y[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.MountPoint[[:space:]]*=[[:space:]]*/d[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.EnableSwap[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*DataDisk.Mount[[:space:]]*=[[:space:]]*y[[:space:]]*$' /etc/waagent.conf
if mountpoint -q /d; then
  test "$has_local_temp_storage" = true
  mount_source=$(findmnt -n -o SOURCE --target /d)
  mount_source=$(readlink -f "$mount_source")
  mount_fstype=$(findmnt -n -o FSTYPE --target /d)
  root_source=$(findmnt -n -o SOURCE --target /)
  root_source=$(readlink -f "$root_source")
  test -b "$mount_source"
  [[ "$mount_source" == /dev/* ]]
  resource_disk=$(lsblk -n -o PKNAME "$mount_source")
  root_disk=$(lsblk -n -o PKNAME "$root_source")
  [[ -n "$resource_disk" ]] || resource_disk=${mount_source##*/}
  [[ -n "$root_disk" ]] || root_disk=${root_source##*/}
  [[ -n "$resource_disk" && "$resource_disk" != "$root_disk" ]]
  test -b "/dev/$resource_disk"
  test "$(lsblk -dn -o TYPE "/dev/$resource_disk")" = disk
  [[ "$mount_fstype" == ext4 || "$mount_fstype" == xfs ]]
  test -f /d/DATALOSS_WARNING_README.txt
  grep -Fq "temporary resource disk" /d/DATALOSS_WARNING_README.txt
  while read -r swap_path _; do
    test "$swap_path" = Filename && continue
    case "$swap_path" in
      /d|/d/*) exit 1 ;;
    esac
    swap_source=$(readlink -f "$swap_path" 2>/dev/null || true)
    test "$swap_source" != "$mount_source"
    if [[ "$swap_source" == /dev/* ]]; then
      swap_disk=$(lsblk -n -o PKNAME "$swap_source")
      [[ -n "$swap_disk" ]] || swap_disk=${swap_source##*/}
      test "$swap_disk" != "$resource_disk"
    fi
  done </proc/swaps
else
  test "$has_local_temp_storage" = false
fi
! mountpoint -q /mnt
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
test -s /home/miztest/.ssh/authorized_keys
machine_id=$(cat /etc/machine-id)
read -r _ host_key_fingerprint _ < <(
  /usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
)
read -r authorized_keys_sha256 _ < <(
  sha256sum /home/miztest/.ssh/authorized_keys
)
read -r sentinel_sha256 _ < <(
  sha256sum /var/lib/azagent/provisioned
)
printf '%s\n' \
  "$machine_id" \
  "$host_key_fingerprint" \
  "$authorized_keys_sha256" \
  "$sentinel_sha256"
GUEST
  )
  test "${#core_identity[@]}" -eq 4
  initial_machine_id=${core_identity[0]}
  initial_host_key_fingerprint=${core_identity[1]}
  initial_authorized_keys_sha256=${core_identity[2]}
  initial_sentinel_sha256=${core_identity[3]}
  [[ "$initial_machine_id" =~ ^[0-9a-f]{32}$ ]]
  [[ "$initial_host_key_fingerprint" == SHA256:* ]]
  [[ "$initial_authorized_keys_sha256" =~ ^[0-9a-f]{64}$ ]]
  [[ "$initial_sentinel_sha256" =~ ^[0-9a-f]{64}$ ]]

  initial_sshd_pid=$(read_core_sshd_pid)
  [[ "$initial_sshd_pid" =~ ^[0-9]+$ ]]
  ssh "${ssh_options[@]}" "$ssh_target" \
    "sudo -n /usr/bin/kill -KILL '$initial_sshd_pid'" >/dev/null 2>&1 || true
  wait_for_ssh
  restarted_sshd_pid=$(read_core_sshd_pid)
  [[ "$restarted_sshd_pid" =~ ^[0-9]+$ ]]
  test "$restarted_sshd_pid" != "$initial_sshd_pid"
  test "$(az vm extension list \
    --resource-group "$resource_group" \
    --vm-name "$vm_name" \
    --query 'length(@)' \
    --output tsv)" = 0
else
  ssh "${ssh_options[@]}" "$ssh_target" \
    "/usr/bin/bash -s -- '$has_conventional_resource_disk'" <<'GUEST'
set -euo pipefail
has_conventional_resource_disk=$1
check() {
  label=$1
  shift
  if "$@"; then
    printf 'PASS %s\n' "$label"
  else
    status=$?
    printf 'FAIL %s (exit %s)\n' "$label" "$status" >&2
    return "$status"
  fi
}
diagnose_unit() {
  unit=$1
  {
    printf '%s\n' "--- bounded diagnostics for $unit ---"
    systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,TimeoutStartUSec "$unit"
    sudo -n journalctl --no-pager --boot=0 --unit "$unit" --priority=info..emerg --lines=120 --output=short-monotonic
  } 2>&1 | head -c 49152 >&2 || true
  printf '\n' >&2
}
diagnose_failed_units() {
  printf '%s\n' "$failed_units" |
    awk 'NF { print $1 }' |
    head -n 8 |
    while IFS= read -r unit; do diagnose_unit "$unit"; done
}
check_service() {
  unit=$1
  check "service-active:$unit" systemctl is-active --quiet "$unit" || {
    diagnose_unit "$unit"
    return 1
  }
  check "service-enabled:$unit" systemctl is-enabled --quiet "$unit" || {
    diagnose_unit "$unit"
    return 1
  }
}
package_installed() {
  package=$1
  test "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null)" = installed
}
not_mountpoint() {
  ! mountpoint -q "$1"
}
validate_conventional_resource_disk() {
  local expected=$1
  local mount_source
  local mount_fstype
  local resource_disk
  local root_source
  local root_disk

  if [[ "$expected" == false ]]; then
    if mountpoint -q /mnt; then
      return 1
    fi
    return 0
  fi
  [[ "$expected" == true ]] || return 1

  mountpoint -q /mnt || return 1
  mount_source=$(findmnt -n -o SOURCE --target /mnt) || return 1
  mount_source=$(readlink -f "$mount_source") || return 1
  mount_fstype=$(findmnt -n -o FSTYPE --target /mnt) || return 1
  root_source=$(findmnt -n -o SOURCE --target /) || return 1
  root_source=$(readlink -f "$root_source") || return 1
  [[ "$mount_source" == /dev/* ]] || return 1
  resource_disk=$(lsblk -n -o PKNAME "$mount_source") || return 1
  root_disk=$(lsblk -n -o PKNAME "$root_source") || return 1
  [[ -n "$resource_disk" ]] || resource_disk=${mount_source##*/}
  [[ -n "$root_disk" ]] || root_disk=${root_source##*/}
  [[ -n "$resource_disk" && "$resource_disk" != "$root_disk" ]] || return 1
  [[ "$mount_fstype" == ext4 || "$mount_fstype" == xfs ]] || return 1
  while read -r swap_device _; do
    [[ "$swap_device" == Filename ]] && continue
    case "$swap_device" in
      /mnt|/mnt/*) return 1 ;;
    esac
  done </proc/swaps
}
check pid1-systemd sudo -n /usr/bin/test /proc/1/exe -ef /usr/lib/systemd/systemd
check mizinit-sbin-absent test ! -e /sbin/mizinit
check mizinit-usr-bin-absent test ! -e /usr/bin/mizinit
check os-release-readable test -r /etc/os-release
. /etc/os-release
check os-id-ubuntu test "$ID" = ubuntu
check os-version-26.04 test "$VERSION_ID" = 26.04
check cloud-init-wait cloud-init status --wait
for unit in cloud-init-local.service cloud-init-network.service cloud-config.service cloud-final.service walinuxagent.service ssh.service systemd-networkd.service networkd-dispatcher.service; do
  check_service "$unit"
done
check udisks2-installed package_installed udisks2
check udisks2-dbus-service test -r /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
check udisks2-dbus-name grep -Fxq 'Name=org.freedesktop.UDisks2' /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
check udisks2-systemd-activation grep -Fxq 'SystemdService=udisks2.service' /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
check udisks2-unit-loaded test "$(systemctl show --property=LoadState --value udisks2.service)" = loaded
check udisks2-graphical-eager-start-absent test ! -e /etc/systemd/system/graphical.target.wants/udisks2.service
netplan_network=$(find /run/systemd/network -maxdepth 1 -name '10-netplan-*.network' -print -quit)
check netplan-network-generated test -n "$netplan_network"
check network-online systemctl is-active --quiet network-online.target
check waagent-provisioning-agent grep -Eq '^[[:space:]]*Provisioning.Agent[[:space:]]*=[[:space:]]*auto[[:space:]]*$' /etc/waagent.conf
check waagent-resource-disk-format grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
check waagent-resource-disk-swap grep -Eq '^[[:space:]]*ResourceDisk.EnableSwap[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
check cloud-init-instance-state test -s /var/lib/cloud/instance/obj.pkl
check resource-disk-not-mounted not_mountpoint /d
check conventional-resource-disk-policy validate_conventional_resource_disk "$has_conventional_resource_disk" || {
  findmnt -n -o SOURCE,FSTYPE,OPTIONS --target /mnt >&2 || true
  lsblk -o NAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS >&2 || true
  exit 1
}
failed_units=$(systemctl --failed --no-legend --plain)
check no-failed-units test -z "$failed_units" || {
  printf '%s\n' "$failed_units" >&2
  diagnose_failed_units
  exit 1
}
GUEST
  # cloud-init reports its status as a JSON document. The guest emits the
  # document and the host decides, so the guest needs no JSON interpreter, and
  # a failed or malformed query fails this pipeline instead of being read as
  # "done".
  cloud_init_status=$(
    ssh "${ssh_options[@]}" "$ssh_target" "cloud-init status --format json" |
      "$RELEASE_TOOL" cloud-init-status
  )
  test "$cloud_init_status" = done
fi
if [[ "$FLAVOR" != core ]]; then
  # core's azagent never reports through the vmAgent status-blob channel
  # (see the --enable-agent false note above); this check only applies to
  # full's real waagent.
  test "$(az vm get-instance-view \
    --resource-group "$resource_group" \
    --name "$vm_name" \
    --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].code | [0]" \
    --output tsv)" = ProvisioningState/succeeded
fi

data_disk_size_gib=4
az disk create \
  --resource-group "$resource_group" \
  --name "$data_disk_name" \
  --location "$AZURE_LOCATION" \
  --size-gb "$data_disk_size_gib" \
  --sku Standard_LRS \
  --output json >/dev/null
az vm disk attach \
  --resource-group "$resource_group" \
  --vm-name "$vm_name" \
  --name "$data_disk_name" \
  --lun 0 \
  --output json >/dev/null
boot_id=$(ssh "${ssh_options[@]}" "$ssh_target" 'cat /proc/sys/kernel/random/boot_id')
reboot_and_reconnect "$boot_id"
if [[ "$FLAVOR" == core ]]; then
  readarray -t rebooted_identity < <(
    ssh "${ssh_options[@]}" "$ssh_target" '/usr/bin/bash -s' <<'GUEST'
set -euo pipefail
sudo -n /usr/bin/test /proc/1/exe -ef /sbin/mizinit
test -s /var/lib/azagent/provisioned
test "$(cat /var/lib/azagent/provisioned)" = "$(cat /etc/hostname)"
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
test -s /home/miztest/.ssh/authorized_keys
test ! -d /run/systemd/system
machine_id=$(cat /etc/machine-id)
read -r _ host_key_fingerprint _ < <(
  /usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
)
read -r authorized_keys_sha256 _ < <(
  sha256sum /home/miztest/.ssh/authorized_keys
)
read -r sentinel_sha256 _ < <(
  sha256sum /var/lib/azagent/provisioned
)
printf '%s\n' \
  "$machine_id" \
  "$host_key_fingerprint" \
  "$authorized_keys_sha256" \
  "$sentinel_sha256"
GUEST
  )
  test "${#rebooted_identity[@]}" -eq 4
  test "${rebooted_identity[0]}" = "$initial_machine_id"
  test "${rebooted_identity[1]}" = "$initial_host_key_fingerprint"
  test "${rebooted_identity[2]}" = "$initial_authorized_keys_sha256"
  test "${rebooted_identity[3]}" = "$initial_sentinel_sha256"
  rebooted_sshd_pid=$(read_core_sshd_pid)
  [[ "$rebooted_sshd_pid" =~ ^[0-9]+$ ]]
else
  ssh "${ssh_options[@]}" "$ssh_target" '/usr/bin/bash -s' <<'GUEST'
set -euo pipefail
diagnose_unit() {
  unit=$1
  {
    printf '%s\n' "--- bounded diagnostics for $unit ---"
    systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,TimeoutStartUSec "$unit"
    sudo -n journalctl --no-pager --boot=0 --unit "$unit" --priority=info..emerg --lines=120 --output=short-monotonic
  } 2>&1 | head -c 49152 >&2 || true
  printf '\n' >&2
}
diagnose_failed_units() {
  printf '%s\n' "$failed_units" |
    awk 'NF { print $1 }' |
    head -n 8 |
    while IFS= read -r unit; do diagnose_unit "$unit"; done
}
for unit in cloud-final.service walinuxagent.service ssh.service systemd-networkd.service networkd-dispatcher.service; do
  systemctl is-active --quiet "$unit" || {
    diagnose_unit "$unit"
    exit 1
  }
done
cloud-init status --long | grep -Eq '^status:[[:space:]]*done$'
failed_units=$(systemctl --failed --no-legend --plain)
test -z "$failed_units" || {
  printf '%s\n' "$failed_units" >&2
  diagnose_failed_units
  exit 1
}
GUEST
fi
if [[ "$FLAVOR" != core ]]; then
  # See the earlier vmAgent check: only full's real waagent reports through
  # this channel, so this is skipped for core.
  test "$(az vm get-instance-view \
    --resource-group "$resource_group" \
    --name "$vm_name" \
    --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].code | [0]" \
    --output tsv)" = ProvisioningState/succeeded
fi

expected_data_disk_size=$((data_disk_size_gib * 1073741824))
data_device=$(ssh "${ssh_options[@]}" "$ssh_target" \
  "/usr/bin/bash -s -- '$expected_data_disk_size' '$FLAVOR'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
expected_size=$1
flavor=$2
root_source=$(readlink -f "$(findmnt -n -o SOURCE /)")
root_disk=$(lsblk -n -o PKNAME "$root_source")
found=
for sysdev in /sys/class/block/sd* /sys/class/block/nvme*n*; do
  test -e "$sysdev" || continue
  name=${sysdev##*/}
  test "$name" != "$root_disk" || continue
  test ! -e "$sysdev/partition" || continue
  size=$(sudo -n blockdev --getsize64 "/dev/$name")
  [[ "$size" -eq "$expected_size" ]] || continue
  if [[ -n "$found" ]]; then
    echo "multiple unattached disks match the expected size" >&2
    exit 1
  fi
  found="/dev/$name"
done
if [[ -z "$found" ]]; then
  echo "no unattached disk matches the expected size $expected_size" >&2
  lsblk -b -o NAME,TYPE,SIZE,PKNAME,MOUNTPOINTS,MODEL >&2
  exit 1
fi
if lsblk -nr -o TYPE "$found" | tail -n +2 | grep -q '^part$'; then
  exit 1
fi
first_sector=$(sudo -n dd if="$found" bs=512 count=1 status=none | od -An -v -tx1 | tr -d ' \n')
test -n "$first_sector"
if [[ "$flavor" == core ]]; then
  test "${#first_sector}" -eq 1024
  test -z "${first_sector//0/}"
fi
if findmnt -rn -S "$found" >/dev/null; then
  exit 1
fi
printf '%s\n' "$found"
GUEST
)
[[ "$data_device" == /dev/* ]]

rm -f -- "$boot_log"
for _ in {1..6}; do
  if retrieve_managed_boot_log \
      "$boot_log" "$boot_diagnostics_attempt_error"; then
    break
  fi
  rm -f -- "$boot_diagnostics_attempt_error"
  sleep 5
done
if [[ -s "$boot_log" ]]; then
  if [[ "$FLAVOR" == core ]]; then
    grep -Fq '[mizinit] MIZINIT_PID1_READY supervisor loop active' "$boot_log"
    grep -Fq '[mizinit] azagent completed successfully' "$boot_log"
    ! grep -Eiq 'anbox|binder_linux:.*(verification failed|taint)' "$boot_log"
  fi
  if [[ "$ARCHITECTURE" == aarch64 ]]; then
    grep -Fq 'ttyAMA0' "$boot_log"
  fi
  ! grep -Eiq 'security violation|module verification failed|Loading of unsigned module' "$boot_log"
else
  echo "::warning::Azure managed boot diagnostics did not return a serial log"
fi

"$RELEASE_TOOL" azure-result \
  --manifest "$manifest" \
  --asset "$asset" \
  --vhd "$vhd" \
  --vhd-info "$RESULT_DIR/vhd-info.json" \
  --conversion-attestation "$conversion_attestation" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$AZURE_LOCATION" \
  --vm-size "$AZURE_VM_SIZE" \
  --resource-group "$resource_group" \
  --image-version-id "$image_version_id" \
  --uefi-request "$uefi_request" \
  --uefi-response "$uefi_response" \
  --contracts "$azure_contract_list" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output "$RESULT_DIR/azure-result.json"
"$RELEASE_TOOL" verify-azure-result \
  --manifest "$manifest" \
  --asset "$asset" \
  --result "$RESULT_DIR/azure-result.json" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" >/dev/null
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"

{
  echo "### Azure acceptance: $ASSET_NAME"
  echo
  echo "- QCOW2 SHA-256: \`$qcow_sha256\`"
  echo "- Temporary VHD: \`$vhd_sha256\`; current $vhd_current_size bytes;" \
    "file $vhd_bytes bytes (not retained or published)"
  echo "- UKI SHA-256: \`$fallback_uki_sha256\`"
  echo "- Signing certificate SHA-256: \`$certificate_sha256\`"
  echo "- Azure: \`$AZURE_LOCATION\` / \`$AZURE_VM_SIZE\`"
  echo "- Flavor: \`$FLAVOR\`"
  if [[ "$FLAVOR" == core ]]; then
    echo "- Binder device probe SHA-256: \`$binder_probe_sha256\`"
    echo "- Runtime contract probe SHA-256: \`$runtime_contract_sha256\`"
  fi
  echo "- Contracts: \`$azure_contract_list\`"
} >>"$GITHUB_STEP_SUMMARY"
