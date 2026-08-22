#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/ubuntu2604_azure_acceptance_lib.sh
source "$script_dir/ubuntu2604_azure_acceptance_lib.sh"

# Release-schema integration contract (implemented by the Ubuntu release
# tooling PR): `verify-candidate`, `verify-vhd`, and `azure-result` must expose
# the same arguments consumed below. Keep schema validation in that tool
# rather than duplicating it in this acceptance harness.
RELEASE_SCHEMA=${UBUNTU2604_RELEASE_SCHEMA:-scripts/ubuntu2604_release.py}

command_name=${1:-run}
if (( $# > 1 )); then
  echo "usage: $0 run|cleanup" >&2
  exit 2
fi
if [[ -z ${STATE_FILE:-} || -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} || -z ${CANDIDATE_KEY:-} ]]; then
  echo "::error::Azure cleanup identity is incomplete"
  exit 1
fi
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]]
[[ "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]
[[ "$CANDIDATE_KEY" =~ ^(x86_64|aarch64)-(full|core)$ ]]

cleanup_group() {
  [[ -s "$STATE_FILE" ]] || return 0
  command -v az >/dev/null || {
    echo "::error::Azure CLI is unavailable during cleanup"
    return 1
  }
  local resource_group metadata_file group_exists expected_resource_group suffix
  resource_group=$(<"$STATE_FILE")
  suffix=${CANDIDATE_KEY//_/-}
  expected_resource_group="vmiz-u2604-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
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
  if ! python3 - "$metadata_file" "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" "$CANDIDATE_KEY" <<'PY'
import hashlib
import json
import sys

tags = json.load(open(sys.argv[1], encoding="utf-8")).get("tags") or {}
expected = {
    "vmiz-owner": "ubuntu2604-release",
    "vmiz-run-id": sys.argv[2],
    "vmiz-run-attempt": sys.argv[3],
    "vmiz-candidate": sys.argv[4],
}
if tags != expected:
    raise SystemExit(f"refusing to delete resource group with non-exact ownership tags: {tags!r}")
PY
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

if [[ -z ${CANDIDATE_DIR:-} || -z ${SOURCE_COMMIT:-} || -z ${ARCHITECTURE:-} ||
      -z ${FLAVOR:-} || -z ${ASSET_NAME:-} || -z ${AZURE_LOCATION:-} ||
      -z ${AZURE_VM_SIZE:-} || -z ${RESULT_DIR:-} || -z ${VMIZ:-} ||
      -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Azure acceptance configuration is incomplete"
  exit 1
fi
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
if ! ubuntu2604_validate_candidate_identity \
    "$CANDIDATE_KEY" "$ARCHITECTURE" "$FLAVOR" "$ASSET_NAME"
then
  echo "::error::Ubuntu candidate identity is invalid"
  exit 1
fi
[[ "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ ]]
[[ "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ ]]
[[ -x "$VMIZ" ]]
[[ -r "$RELEASE_SCHEMA" ]]

report_error() {
  local status=$1 line=$2 command=$3
  trap - ERR
  printf '::error::Azure acceptance failed at line %s: %s\n' "$line" "$command" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

for tool in az azcopy curl python3 qemu-img sha256sum ssh ssh-keygen; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required Azure acceptance tool $tool is unavailable"
    exit 1
  }
done
azure_contract_list=$(
  python3 "$RELEASE_SCHEMA" azure-contracts --flavor "$FLAVOR"
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
      python3 - "$response_body" <<'PY'
import json
import sys

response = json.load(open(sys.argv[1], encoding="utf-8"))
print(response.get("accessSAS") or response.get("accessSas") or "")
PY
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
  python3 "$RELEASE_SCHEMA" verify-candidate \
    --manifest "$manifest" \
    --asset "$asset" \
    --key "$CANDIDATE_KEY" \
    --source-commit "$SOURCE_COMMIT"
)
test "${#candidate[@]}" -eq 3
qcow_sha256=${candidate[0]}
qcow_bytes=${candidate[1]}
virtual_size=${candidate[2]}
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$qcow_bytes" =~ ^[0-9]+$ ]]
[[ "$virtual_size" =~ ^[0-9]+$ ]]
readarray -t signing_identity < <(
  python3 - "$manifest" <<'PY'
import json
import sys

signing = json.load(open(sys.argv[1], encoding="utf-8"))["uki_signing"]
print(signing["certificate_sha256"])
print(signing["fallback_uki_sha256"])
print(signing["certificate_der_base64"])
PY
)
test "${#signing_identity[@]}" -eq 3
certificate_sha256=${signing_identity[0]}
fallback_uki_sha256=${signing_identity[1]}
certificate_der_base64=${signing_identity[2]}
[[ "$certificate_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$fallback_uki_sha256" =~ ^[0-9a-f]{64}$ ]]

suffix=${CANDIDATE_KEY//_/-}
resource_group="vmiz-u2604-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
short_arch=${ARCHITECTURE/x86_64/x64}
name_seed="${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}${short_arch}${FLAVOR}"
disk_name="vmiz-os-${name_seed}"
data_disk_name="vmiz-data-${name_seed}"
gallery_name="vmizu2604${name_seed}"
image_name="vmizu2604${short_arch}${FLAVOR}"
vm_name="vmiz-vm-${name_seed}"
admin_username=vmiztest
vhd="$RESULT_DIR/${CANDIDATE_KEY}.vhd"
private_key="$RESULT_DIR/id_ed25519"
boot_log="$RESULT_DIR/boot.log"
sku_json="$RESULT_DIR/sku.json"
certificate_der="$RESULT_DIR/signing-certificate.der"
uefi_request="$RESULT_DIR/gallery-version-request.json"
uefi_create_response="$RESULT_DIR/gallery-version-create-response.json"
uefi_response="$RESULT_DIR/gallery-version-response.json"
vm_security_json="$RESULT_DIR/vm-security.json"
instance_security_json="$RESULT_DIR/instance-security.json"
conversion_attestation="$RESULT_DIR/conversion-attestation.json"
mkdir -p "$(dirname -- "$STATE_FILE")"
rm -f -- "$STATE_FILE" "${STATE_FILE}.group.json" "$vhd" "$private_key" "$private_key.pub"
python3 - "$certificate_der" "$certificate_sha256" "$certificate_der_base64" <<'PY'
import base64
import hashlib
import sys

certificate = base64.b64decode(sys.argv[3], validate=True)
if not certificate or hashlib.sha256(certificate).hexdigest() != sys.argv[2]:
    raise SystemExit("candidate signing certificate binding is invalid")
open(sys.argv[1], "wb").write(certificate)
PY

cleanup_on_exit() {
  status=$?
  trap - EXIT INT TERM
  if [[ "$status" -ne 0 ]] &&
      az vm show --resource-group "$resource_group" --name "$vm_name" >/dev/null 2>&1; then
    az vm boot-diagnostics get-boot-log \
      --resource-group "$resource_group" \
      --name "$vm_name" >"$boot_log" 2>/dev/null || rm -f "$boot_log"
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
    vmiz-owner=ubuntu2604-release \
    "vmiz-run-id=$GITHUB_RUN_ID" \
    "vmiz-run-attempt=$GITHUB_RUN_ATTEMPT" \
    "vmiz-candidate=$CANDIDATE_KEY" \
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
has_resource_disk=$(
  python3 - "$sku_json" "$AZURE_VM_SIZE" "$expected_azure_architecture" <<'PY'
import json
import sys

matches = [item for item in json.load(open(sys.argv[1], encoding="utf-8")) if item["name"] == sys.argv[2]]
if len(matches) != 1:
    raise SystemExit("configured Azure VM SKU is absent or ambiguous in the configured location")
sku = matches[0]
location_restrictions = [
    restriction
    for restriction in sku.get("restrictions", [])
    if restriction.get("type") == "Location"
]
if location_restrictions:
    raise SystemExit(f"configured Azure VM SKU is location-restricted: {location_restrictions!r}")
capabilities = {item["name"]: item["value"] for item in sku.get("capabilities", [])}
if capabilities.get("CpuArchitectureType") != sys.argv[3]:
    raise SystemExit(f"SKU architecture mismatch: {capabilities.get('CpuArchitectureType')!r}")
if "V2" not in capabilities.get("HyperVGenerations", "").split(","):
    raise SystemExit("configured Azure VM SKU does not support Gen2")
if capabilities.get("TrustedLaunchDisabled") == "True":
    raise SystemExit("configured Azure VM SKU does not support Trusted Launch")
has_resource_disk = int(capabilities.get("MaxResourceVolumeMB", "0")) > 0
if sys.argv[3] == "x64" and not has_resource_disk:
    raise SystemExit("configured Azure VM SKU has no temporary resource disk")
print("true" if has_resource_disk else "false")
PY
)
[[ "$has_resource_disk" == true || "$has_resource_disk" == false ]]

source_before=$(sha256sum "$asset" | awk '{print $1}')
test "$source_before" = "$qcow_sha256"
"$VMIZ" azure derive \
  --input-sha256 "$qcow_sha256" \
  --expected-virtual-size "$virtual_size" \
  "$asset" \
  "$vhd"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"
qemu-img info -f vpc --output=json "$vhd" >"$RESULT_DIR/vhd-info.json"
readarray -t vhd_geometry < <(
  python3 "$RELEASE_SCHEMA" verify-vhd \
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
python3 - \
  "$conversion_attestation" \
  "$CANDIDATE_KEY" \
  "$ASSET_NAME" \
  "$qcow_sha256" \
  "$qcow_bytes" \
  "$virtual_size" \
  "$vhd_sha256" \
  "$vhd_bytes" \
  "$vhd_current_size" \
  "$RESULT_DIR/vhd-info.json" <<'PY'
import hashlib
import json
import sys

(
    output,
    key,
    asset_name,
    qcow_sha256,
    qcow_bytes,
    virtual_size,
    vhd_sha256,
    vhd_bytes,
    vhd_current_size,
    info_path,
) = sys.argv[1:]
info = json.load(open(info_path, encoding="utf-8"))
qemu_virtual_size = info.get("virtual-size")
if type(qemu_virtual_size) is not int:
    raise SystemExit("qemu-img omitted the derived VHD virtual size")
qemu_info_sha256 = hashlib.sha256(open(info_path, "rb").read()).hexdigest()
document = {
    "schema": 1,
    "type": "vmiz-azure-vhd-conversion",
    "key": key,
    "status": "success",
    "tool": "vmiz",
    "operation": "azure derive",
    "source": {
        "asset_name": asset_name,
        "sha256_before": qcow_sha256,
        "sha256_after": qcow_sha256,
        "bytes": int(qcow_bytes),
        "virtual_size": int(virtual_size),
    },
    "parameters": {
        "input_sha256": qcow_sha256,
        "expected_virtual_size": int(virtual_size),
        "output_format": "vpc-fixed",
        "vhd_alignment_bytes": 1024 * 1024,
        "vhd_footer_bytes": 512,
    },
    "result": {
        "sha256": vhd_sha256,
        "bytes": int(vhd_bytes),
        "current_size": int(vhd_current_size),
        "qemu_virtual_size": qemu_virtual_size,
        "qemu_info_sha256": qemu_info_sha256,
    },
}
open(output, "w", encoding="utf-8").write(
    json.dumps(document, indent=2, sort_keys=True) + "\n"
)
PY

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
  --publisher vmiz \
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
python3 - "$uefi_request" "$AZURE_LOCATION" "$disk_id" "$certificate_der" <<'PY'
import base64
import json
import sys

output, location, disk_id, certificate_path = sys.argv[1:]
certificate = base64.b64encode(open(certificate_path, "rb").read()).decode("ascii")
payload = {
    "location": location,
    "properties": {
        "publishingProfile": {
            "replicationMode": "Shallow",
            "targetRegions": [
                {
                    "name": location,
                    "regionalReplicaCount": 1,
                    "storageAccountType": "Standard_LRS",
                }
            ],
        },
        "storageProfile": {"osDiskImage": {"source": {"id": disk_id}}},
        "securityProfile": {
            "uefiSettings": {
                "signatureTemplateNames": [
                    "MicrosoftUefiCertificateAuthorityTemplate"
                ],
                "additionalSignatures": {
                    "db": [{"type": "x509", "value": [certificate]}]
                },
            }
        },
    },
}
open(output, "w", encoding="utf-8").write(
    json.dumps(payload, indent=2, sort_keys=True) + "\n"
)
PY
az rest \
  --method put \
  --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03" \
  --body "@$uefi_request" \
  --output json >"$uefi_response"
cp "$uefi_response" "$uefi_create_response"
python3 - "$uefi_request" "$uefi_create_response" <<'PY'
import json
import sys

request = json.load(open(sys.argv[1], encoding="utf-8"))
response = json.load(open(sys.argv[2], encoding="utf-8"))
expected = request["properties"]["securityProfile"]["uefiSettings"]
actual = response.get("properties", {}).get("securityProfile", {}).get("uefiSettings")
if actual != expected:
    raise SystemExit("Azure did not accept the exact custom UEFI settings")
PY
for _ in {1..120}; do
  provisioning_state=$(python3 - "$uefi_response" <<'PY'
import json
import sys
print(json.load(open(sys.argv[1], encoding="utf-8")).get("properties", {}).get("provisioningState", ""))
PY
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
python3 - "$uefi_request" "$uefi_response" "$image_version_id" <<'PY'
import json
import sys

request = json.load(open(sys.argv[1], encoding="utf-8"))
response = json.load(open(sys.argv[2], encoding="utf-8"))
if response.get("id", "").lower() != sys.argv[3].lower():
    raise SystemExit("Azure returned a different gallery image-version identity")
expected = request["properties"]["securityProfile"]["uefiSettings"]
actual = response.get("properties", {}).get("securityProfile", {}).get("uefiSettings")
if actual is not None and actual != expected:
    raise SystemExit("Azure returned different custom UEFI settings after provisioning")
if actual is None:
    print("Azure omitted custom UEFI settings from the final GET; boot validation remains authoritative")
state = response.get("properties", {}).get("provisioningState")
if state != "Succeeded":
    raise SystemExit(f"gallery image-version provisioning did not succeed: {state!r}")
PY
[[ "$image_version_id" == /subscriptions/* ]]

ssh-keygen -q -t ed25519 -N '' -C vmiz-azure-acceptance -f "$private_key"
az vm create \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --location "$AZURE_LOCATION" \
  --size "$AZURE_VM_SIZE" \
  --image "$image_version_id" \
  --admin-username "$admin_username" \
  --authentication-type ssh \
  --ssh-key-values "$private_key.pub" \
  --enable-agent true \
  --enable-auto-update false \
  --security-type TrustedLaunch \
  --enable-secure-boot true \
  --enable-vtpm true \
  --public-ip-sku Standard \
  --nsg-rule SSH \
  --boot-diagnostics-storage "" \
  --output json >/dev/null
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
python3 - "$vm_security_json" "$instance_security_json" <<'PY'
import json
import sys

for path in sys.argv[1:]:
    profile = json.load(open(path, encoding="utf-8"))
    if profile.get("securityType") != "TrustedLaunch":
        raise SystemExit(f"{path}: VM is not Trusted Launch")
    settings = profile.get("uefiSettings") or {}
    if settings.get("secureBootEnabled") is not True:
        raise SystemExit(f"{path}: Secure Boot is not enabled")
    if settings.get("vTpmEnabled") is not True:
        raise SystemExit(f"{path}: vTPM is not enabled")
PY
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
  "/usr/bin/bash -s -- '$vhd_current_size' '$runtime_architecture' '$ARCHITECTURE'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
original_size=$1
runtime_arch=$2
release_arch=$3
test "$(id -un)" = vmiztest
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
test "$root_size" -gt $((original_size + 1073741824))
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
GUEST

uefi_db="$RESULT_DIR/uefi-db.bin"
ssh "${ssh_options[@]}" "$ssh_target" \
  "sudo -n /usr/bin/cat /sys/firmware/efi/efivars/db-*" >"$uefi_db"
python3 - "$uefi_db" "$certificate_sha256" <<'PY'
import hashlib
import struct
import sys

data = open(sys.argv[1], "rb").read()
expected = sys.argv[2]
efi_cert_x509_guid = bytes.fromhex("a159c0a5e494a74a87b5ab155c2bf072")
offset = 4
found = False
while offset < len(data):
    if len(data) - offset < 28:
        raise SystemExit("truncated EFI signature list")
    list_size, header_size, signature_size = struct.unpack_from("<III", data, offset + 16)
    is_x509 = data[offset : offset + 16] == efi_cert_x509_guid
    if list_size < 28 or signature_size <= 16:
        raise SystemExit("invalid EFI signature list")
    end = offset + list_size
    signatures = offset + 28 + header_size
    if end > len(data) or signatures > end or (end - signatures) % signature_size:
        raise SystemExit("invalid EFI signature-list bounds")
    while signatures < end:
        certificate = data[signatures + 16 : signatures + signature_size]
        found |= is_x509 and hashlib.sha256(certificate).hexdigest() == expected
        signatures += signature_size
    offset = end
if not found:
    raise SystemExit("release signing certificate is absent from UEFI db")
PY
ssh "${ssh_options[@]}" "$ssh_target" \
  "/usr/bin/bash -s -- '$FLAVOR'" <<'GUEST'
set -euo pipefail
flavor=$1
secure_boot=$(od -An -t u1 -j 4 -N 1 /sys/firmware/efi/efivars/SecureBoot-* | tr -d ' ')
test "$secure_boot" = 1
if ! test -r /sys/kernel/security/lockdown; then
  sudo -n /usr/bin/mount -t securityfs securityfs /sys/kernel/security
fi
grep -Eq '\[(integrity|confidentiality)\]' /sys/kernel/security/lockdown
test -c /dev/tpm0
test -c /dev/tpmrm0
for module in hv_netvsc crc_itu_t udf isofs; do
  if ! test -d "/sys/module/$module" && [[ "$flavor" == full ]]; then
    sudo -n /usr/sbin/modprobe "$module"
  fi
  test -d "/sys/module/$module"
done
dmesg_output=$(sudo -n /usr/bin/dmesg) || exit 1
if printf '%s\n' "$dmesg_output" | grep -Eiq 'module verification failed|Loading of unsigned module|Lockdown:.*unsigned'; then
  exit 1
fi
GUEST

if [[ "$FLAVOR" == core ]]; then
  readarray -t core_identity < <(
    ssh "${ssh_options[@]}" "$ssh_target" \
      "/usr/bin/bash -s -- '$has_resource_disk'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
has_resource_disk=$1
sudo -n /usr/bin/test /proc/1/exe -ef /sbin/vmizinit
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
  /usr/sbin/WALinuxAgent \
  /usr/lib/python3/dist-packages/azurelinuxagent \
  /var/lib/cloud \
  /run/cloud-init \
  /var/lib/waagent \
  /var/log/waagent.log \
  /var/log/azure
do
  test ! -e "$path"
done
for proc in /proc/[0-9]*; do
  test -r "$proc/cmdline" || continue
  cmdline=$(tr '\000' ' ' <"$proc/cmdline")
  case "$cmdline" in
    *cloud-init*|*waagent*|*WALinuxAgent*|*azurelinuxagent*) exit 1 ;;
  esac
  executable=$(readlink "$proc/exe" 2>/dev/null || true)
  case "$executable" in
    /usr/lib/systemd/systemd|/lib/systemd/systemd) exit 1 ;;
  esac
done
grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*y[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.MountPoint[[:space:]]*=[[:space:]]*/d[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.EnableSwap[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*DataDisk.Mount[[:space:]]*=[[:space:]]*y[[:space:]]*$' /etc/waagent.conf
if mountpoint -q /d; then
  test "$has_resource_disk" = true
  findmnt -n -o FSTYPE /d | grep -Eq '^(ext4|xfs)$'
  test -f /d/DATALOSS_WARNING_README.txt
  while read -r swap_path _; do
    test "$swap_path" = Filename && continue
    case "$swap_path" in
      /d|/d/*) exit 1 ;;
    esac
  done </proc/swaps
else
  test "$has_resource_disk" = false
fi
! mountpoint -q /mnt
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
test -s /home/vmiztest/.ssh/authorized_keys
machine_id=$(cat /etc/machine-id)
read -r _ host_key_fingerprint _ < <(
  /usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
)
read -r authorized_keys_sha256 _ < <(
  sha256sum /home/vmiztest/.ssh/authorized_keys
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
  ssh "${ssh_options[@]}" "$ssh_target" '/usr/bin/bash -s' <<'GUEST'
set -euo pipefail
sudo -n /usr/bin/test /proc/1/exe -ef /usr/lib/systemd/systemd
test ! -e /sbin/vmizinit
test ! -e /usr/bin/vmizinit
test "$( . /etc/os-release; printf '%s' "$ID")" = ubuntu
test "$( . /etc/os-release; printf '%s' "$VERSION_ID")" = 26.04
for unit in cloud-init-local.service cloud-init.service cloud-config.service cloud-final.service walinuxagent.service ssh.service systemd-networkd.service; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done
cloud-init status --wait
cloud-init status --long | grep -Eq '^status:[[:space:]]*done$'
test -n "$(find /run/systemd/network -maxdepth 1 -name '10-netplan-*.network' -print -quit)"
networkctl is-online --quiet
grep -Eq '^[[:space:]]*Provisioning.Agent[[:space:]]*=[[:space:]]*auto[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.EnableSwap[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
! mountpoint -q /d
! mountpoint -q /mnt
test "$(systemctl --failed --no-legend --plain | wc -l)" -eq 0
GUEST
fi
test "$(az vm get-instance-view \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].code | [0]" \
  --output tsv)" = ProvisioningState/succeeded

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
sudo -n /usr/bin/test /proc/1/exe -ef /sbin/vmizinit
test -s /var/lib/azagent/provisioned
test "$(cat /var/lib/azagent/provisioned)" = "$(cat /etc/hostname)"
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
test -s /home/vmiztest/.ssh/authorized_keys
test ! -d /run/systemd/system
machine_id=$(cat /etc/machine-id)
read -r _ host_key_fingerprint _ < <(
  /usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256
)
read -r authorized_keys_sha256 _ < <(
  sha256sum /home/vmiztest/.ssh/authorized_keys
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
for unit in cloud-final.service walinuxagent.service ssh.service systemd-networkd.service; do
  systemctl is-active --quiet "$unit"
done
cloud-init status --long | grep -Eq '^status:[[:space:]]*done$'
test "$(systemctl --failed --no-legend --plain | wc -l)" -eq 0
GUEST
fi
test "$(az vm get-instance-view \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --query "instanceView.vmAgent.statuses[?code=='ProvisioningState/succeeded'].code | [0]" \
  --output tsv)" = ProvisioningState/succeeded

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
first_sector=$(sudo -n dd if="$found" bs=512 count=1 status=none | od -An -tx1 | tr -d ' \n')
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
  if az vm boot-diagnostics get-boot-log \
    --resource-group "$resource_group" \
    --name "$vm_name" >"$boot_log" 2>/dev/null && [[ -s "$boot_log" ]]; then
    break
  fi
  sleep 5
done
if [[ -s "$boot_log" ]]; then
  if [[ "$FLAVOR" == core ]]; then
    grep -Fq '[vmizinit] VMIZINIT_PID1_READY supervisor loop active' "$boot_log"
    grep -Fq '[vmizinit] azagent completed successfully' "$boot_log"
  fi
  if [[ "$ARCHITECTURE" == aarch64 ]]; then
    grep -Fq 'ttyAMA0' "$boot_log"
  fi
  ! grep -Eiq 'security violation|module verification failed|Loading of unsigned module' "$boot_log"
else
  echo "::warning::Azure managed boot diagnostics did not return a serial log"
fi

python3 "$RELEASE_SCHEMA" azure-result \
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
python3 "$RELEASE_SCHEMA" verify-azure-result \
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
  echo "- Contracts: \`$azure_contract_list\`"
} >>"$GITHUB_STEP_SUMMARY"
