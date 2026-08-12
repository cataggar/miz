#!/usr/bin/env bash
# FreeBSD 15 Azure acceptance harness — UFS and ZFS variants (aarch64 / x86_64).
# Validates a candidate QCOW2 by deriving a fixed VHD, uploading to Azure,
# booting a Gen2 VM, and exercising shared and filesystem-specific contracts.
set -Eeuo pipefail

command_name=${1:-run}
if [[ -z ${STATE_FILE:-} || -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} || -z ${CANDIDATE_KEY:-} ]]; then
  echo "::error::Azure cleanup identity is incomplete"
  exit 1
fi
[[ "$GITHUB_RUN_ID" =~ ^[0-9]+$ ]]
[[ "$GITHUB_RUN_ATTEMPT" =~ ^[0-9]+$ ]]
[[ "$CANDIDATE_KEY" =~ ^(x86_64|aarch64)-(ufs-(full|core)|zfs-full)$ ]]

cleanup_group() {
  [[ -s "$STATE_FILE" ]] || return 0
  command -v az >/dev/null || {
    echo "::error::Azure CLI is unavailable during cleanup"
    return 1
  }
  local resource_group metadata_file group_exists expected_resource_group suffix
  resource_group=$(<"$STATE_FILE")
  suffix=${CANDIDATE_KEY//_/-}
  expected_resource_group="zvmi-fb15-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
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
import json
import sys

tags = json.load(open(sys.argv[1], encoding="utf-8")).get("tags") or {}
expected = {
    "zvmi-owner": "freebsd15-release",
    "zvmi-run-id": sys.argv[2],
    "zvmi-run-attempt": sys.argv[3],
    "zvmi-candidate": sys.argv[4],
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

# --- Run mode: full acceptance ---
if [[ -z ${CANDIDATE_DIR:-} || -z ${SOURCE_COMMIT:-} || -z ${ARCHITECTURE:-} ||
      -z ${FILESYSTEM:-} || -z ${FLAVOR:-} || -z ${ASSET_NAME:-} ||
      -z ${AZURE_LOCATION:-} || -z ${AZURE_VM_SIZE:-} || -z ${RESULT_DIR:-} ||
      -z ${ZVMI:-} || -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Azure acceptance configuration is incomplete"
  exit 1
fi
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$ARCHITECTURE" =~ ^(x86_64|aarch64)$ ]]
case "$FILESYSTEM-$FLAVOR" in
  ufs-full|ufs-core|zfs-full) ;;
  *)
    echo "::error::Unsupported FreeBSD Azure acceptance profile: $FILESYSTEM-$FLAVOR"
    exit 1
    ;;
esac
[[ "$CANDIDATE_KEY" == "$ARCHITECTURE-$FILESYSTEM-$FLAVOR" ]]
[[ "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ ]]
[[ "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ ]]
[[ -x "$ZVMI" ]]

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
  (umask 077; printf 'Authorization: Bearer %s' "$token" >"$auth_header")
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

validate_candidate_binding() {
  python3 - "$manifest" "$asset" "$CANDIDATE_KEY" "$SOURCE_COMMIT" \
    "$ARCHITECTURE" "$FILESYSTEM" "$FLAVOR" "$ASSET_NAME" \
    "$GITHUB_RUN_ID" "$GITHUB_RUN_ATTEMPT" scripts/freebsd15_release.py <<'PY'
import importlib.util
import sys
from pathlib import Path

(
    manifest_path,
    asset_path,
    key,
    source_commit,
    architecture,
    filesystem,
    flavor,
    asset_name,
    run_id,
    run_attempt,
    helper_path,
) = sys.argv[1:]

helper = Path(helper_path).resolve(strict=True)
spec = importlib.util.spec_from_file_location("freebsd15_release", helper)
if spec is None or spec.loader is None:
    raise SystemExit("could not load canonical candidate validator")
release = importlib.util.module_from_spec(spec)
spec.loader.exec_module(release)

doc, canonical_asset = release.validate_candidate(
    Path(manifest_path).resolve(strict=True),
    source_commit,
)
requested_asset = Path(asset_path).resolve(strict=True)
if requested_asset != canonical_asset.resolve():
    raise SystemExit("candidate asset path does not match manifest")
if requested_asset.name != asset_name or doc.get("asset_name") != asset_name:
    raise SystemExit("candidate asset name mismatch")
if doc.get("variant") != key:
    raise SystemExit(f"candidate variant mismatch: expected {key}")
if doc.get("architecture") != architecture:
    raise SystemExit("candidate architecture mismatch")
if doc.get("filesystem") != filesystem:
    raise SystemExit("candidate filesystem mismatch")
if doc.get("flavor") != flavor:
    raise SystemExit("candidate flavor mismatch")
if (filesystem, flavor) not in {
    ("ufs", "full"),
    ("ufs", "core"),
    ("zfs", "full"),
}:
    raise SystemExit("unsupported candidate filesystem/flavor combination")
if not isinstance(doc.get("compressed_size"), int) or doc["compressed_size"] <= 0:
    raise SystemExit("candidate compressed size is missing or invalid")
if not isinstance(doc.get("allocated_size"), int) or doc["allocated_size"] <= 0:
    raise SystemExit("candidate allocated size is missing or invalid")
if not isinstance(doc.get("virtual_size"), int) or doc["virtual_size"] <= 0:
    raise SystemExit("candidate virtual size is missing or invalid")
source = doc.get("source")
if not isinstance(source, dict):
    raise SystemExit("candidate source metadata is missing")
if not isinstance(source.get("bytes"), int) or source["bytes"] <= 0:
    raise SystemExit("candidate source size is missing or invalid")
packages = doc.get("packages")
if not isinstance(packages, dict):
    raise SystemExit("candidate package manifest is missing")
if not isinstance(packages.get("installed_bytes"), int) or packages["installed_bytes"] <= 0:
    raise SystemExit("candidate package installed size is missing or invalid")
package_manifest_path = Path(f"{requested_asset}.packages.txt").resolve(strict=True)
installed_packages = release.parse_package_manifest(package_manifest_path)
release.verify_package_manifest(flavor, installed_packages)
if [package["name"] for package in installed_packages] != packages.get("names"):
    raise SystemExit("candidate package manifest content does not match")
if len(installed_packages) != packages.get("count"):
    raise SystemExit("candidate package manifest count does not match")
if sum(package["installed_bytes"] for package in installed_packages) != packages["installed_bytes"]:
    raise SystemExit("candidate package manifest installed size does not match")
validation = doc.get("validation")
if not isinstance(validation, dict):
    raise SystemExit("candidate validation metadata is missing")
for field in ("qemu_version", "runner", "run_id", "run_attempt"):
    value = validation.get(field)
    if not isinstance(value, str) or not value.strip():
        raise SystemExit(f"candidate validation metadata is missing {field}")
if validation["runner"] != release.VARIANTS[key]["runner"]:
    raise SystemExit("candidate validation runner does not match profile")
if validation["run_id"] != run_id or validation["run_attempt"] != run_attempt:
    raise SystemExit("candidate validation workflow identity mismatch")
print(doc["asset_sha256"])
print(doc["compressed_size"])
print(doc["allocated_size"])
print(doc["virtual_size"])
print(doc["architecture"])
PY
}

# Canonically validate every candidate field before creating Azure resources.
readarray -t candidate < <(
  validate_candidate_binding
)
test "${#candidate[@]}" -eq 5
qcow_sha256=${candidate[0]}
qcow_bytes=${candidate[1]}
qcow_allocated_size=${candidate[2]}
virtual_size=${candidate[3]}
candidate_architecture=${candidate[4]}
[[ "$qcow_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$qcow_bytes" =~ ^[0-9]+$ ]]
[[ "$qcow_allocated_size" =~ ^[0-9]+$ ]]
[[ "$virtual_size" =~ ^[0-9]+$ ]]
[[ "$candidate_architecture" == "$ARCHITECTURE" ]]

suffix=${CANDIDATE_KEY//_/-}
resource_group="zvmi-fb15-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
short_arch=${ARCHITECTURE/x86_64/x64}
short_arch=${short_arch/aarch64/arm64}
name_seed="${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}${short_arch}"
disk_name="zvmi-os-${name_seed}"
vm_name="zvmi-vm-${name_seed}"
admin_username=zvmitest
vhd="$RESULT_DIR/${CANDIDATE_KEY}.vhd"
private_key="$RESULT_DIR/id_ed25519"
boot_log="$RESULT_DIR/boot.log"
sku_json="$RESULT_DIR/sku.json"
mkdir -p "$(dirname -- "$STATE_FILE")"
rm -f -- "$STATE_FILE" "${STATE_FILE}.group.json" "$vhd" "$private_key" "$private_key.pub"

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

# Derive the fixed VHD
source_before=$(sha256sum "$asset" | awk '{print $1}')
test "$source_before" = "$qcow_sha256"
"$ZVMI" azure derive \
  --input-sha256 "$qcow_sha256" \
  --expected-virtual-size "$virtual_size" \
  "$asset" \
  "$vhd"
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"

# Structural VHD inspection
qemu-img info -f vpc --output=json "$vhd" >"$RESULT_DIR/vhd-info.json"
readarray -t vhd_geometry < <(
  python3 - "$RESULT_DIR/vhd-info.json" "$vhd" <<'PY'
import json
import os
import struct
import sys

info = json.load(open(sys.argv[1], encoding="utf-8"))
vhd_path = sys.argv[2]
vhd_size = os.path.getsize(vhd_path)
virtual_size = info["virtual-size"]
# Fixed VHD: file size == virtual size + 512 byte footer
if vhd_size != virtual_size + 512:
    raise SystemExit(f"VHD is not a fixed-size image: file={vhd_size} virtual={virtual_size}")
# Validate footer magic
with open(vhd_path, "rb") as f:
    f.seek(virtual_size)
    footer = f.read(512)
if footer[:8] != b"conectix":
    raise SystemExit("VHD footer magic is missing")
# Disk type field at offset 60: must be 2 (Fixed)
disk_type = struct.unpack(">I", footer[60:64])[0]
if disk_type != 2:
    raise SystemExit(f"VHD disk type is {disk_type}, expected 2 (Fixed)")
# Virtual size must be 1 MiB aligned for Azure
if virtual_size % (1024 * 1024) != 0:
    raise SystemExit(f"VHD virtual size {virtual_size} is not 1 MiB aligned")
print(virtual_size)
print(vhd_size)
PY
)
test "${#vhd_geometry[@]}" -eq 2
vhd_virtual_size=${vhd_geometry[0]}
vhd_bytes=${vhd_geometry[1]}
expected_vhd_virtual_size=$(((virtual_size + 1048575) / 1048576 * 1048576))
test "$vhd_virtual_size" -eq "$expected_vhd_virtual_size"
vhd_sha256=$(sha256sum "$vhd" | awk '{print $1}')
[[ "$vhd_sha256" =~ ^[0-9a-f]{64}$ ]]

# Confirm QCOW2 digest did not change after derivation
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"

# Azure resource setup
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
    zvmi-owner=freebsd15-release \
    "zvmi-run-id=$GITHUB_RUN_ID" \
    "zvmi-run-attempt=$GITHUB_RUN_ATTEMPT" \
    "zvmi-candidate=$CANDIDATE_KEY" \
  --output json >/dev/null
then
  echo "::error::Failed to create the persisted temporary resource group"
  exit 1
fi

# Validate VM SKU
az vm list-skus \
  --location "$AZURE_LOCATION" \
  --resource-type virtualMachines \
  --size "$AZURE_VM_SIZE" \
  --all \
  --output json >"$sku_json"
expected_azure_architecture=x64
runtime_architecture=amd64
azure_image_architecture=x64
if [[ "$ARCHITECTURE" == aarch64 ]]; then
  expected_azure_architecture=Arm64
  runtime_architecture=arm64
  azure_image_architecture=Arm64
fi
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
PY

# Upload VHD to managed disk
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

# Expand the OS disk to exercise root partition/pool growth
expanded_size_gib=$(((virtual_size + 1073741823) / 1073741824 + 2))
az disk update \
  --resource-group "$resource_group" \
  --name "$disk_name" \
  --size-gb "$expanded_size_gib" \
  --output json >/dev/null

# Create VM with key-only SSH
ssh-keygen -q -t ed25519 -N '' -C zvmi-azure-acceptance -f "$private_key"
az vm create \
  --resource-group "$resource_group" \
  --name "$vm_name" \
  --location "$AZURE_LOCATION" \
  --size "$AZURE_VM_SIZE" \
  --attach-os-disk "$disk_name" \
  --os-type Linux \
  --admin-username "$admin_username" \
  --authentication-type ssh \
  --ssh-key-values "$private_key.pub" \
  --enable-agent false \
  --security-type Standard \
  --public-ip-sku Standard \
  --nsg-rule SSH \
  --boot-diagnostics-storage "" \
  --output json >/dev/null
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
  --query "instanceView.statuses[?code=='PowerState/running'].code | [0]" \
  --output tsv)" = PowerState/running

ssh_options=(
  -i "$private_key"
  -o BatchMode=yes
  -o ConnectTimeout=10
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
  ssh "${ssh_options[@]}" "$ssh_target" 'sudo shutdown -r now' >/dev/null 2>&1 || true
  sleep 15
  for _ in {1..180}; do
    if ssh "${ssh_options[@]}" "$ssh_target" true >/dev/null 2>&1; then
      return
    fi
    sleep 5
  done
  echo "::error::Guest did not reboot and reconnect"
  return 1
}

wait_for_poweroff() {
  local power_state
  for _ in {1..60}; do
    power_state=$(az vm get-instance-view \
      --resource-group "$resource_group" \
      --name "$vm_name" \
      --query "instanceView.statuses[?starts_with(code, 'PowerState/')].code | [0]" \
      --output tsv)
    case "$power_state" in
      PowerState/stopped|PowerState/deallocated) return ;;
    esac
    sleep 5
  done
  echo "::error::Guest did not complete a clean shutdown"
  return 1
}

require_serial_console_log() {
  local attempt saw_nonempty=false
  rm -f -- "$boot_log"
  for attempt in {1..6}; do
    if az vm boot-diagnostics get-boot-log \
      --resource-group "$resource_group" \
      --name "$vm_name" >"$boot_log" 2>/dev/null
    then
      if [[ -s "$boot_log" ]]; then
        saw_nonempty=true
        if grep -iq 'FreeBSD' "$boot_log"; then
          return
        fi
      fi
    fi
    if [[ "$attempt" -lt 6 ]]; then
      sleep 5
    fi
  done
  if $saw_nonempty; then
    echo "::error::Azure serial log is missing expected FreeBSD output" >&2
  else
    echo "::error::Azure managed boot diagnostics did not return a nonempty" \
      "serial log after 6 attempts" \
      >&2
  fi
  return 1
}

# --- CONTRACT: matching-architecture-gen2 ---
# (Gen2 enforced by disk hyper-v-generation V2)

# --- CONTRACT: key-only-ssh ---
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

# Capture pre-reboot identity markers
pre_reboot_hostkey=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'cat /etc/ssh/ssh_host_ed25519_key.pub')
pre_reboot_hostuuid=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'sudo sysctl -n kern.hostuuid')
pre_reboot_storage_identity=
if [[ "$FILESYSTEM" == zfs ]]; then
  pre_reboot_storage_identity=$(ssh "${ssh_options[@]}" "$ssh_target" \
    'zpool get -Hp -o value guid zroot')
fi

# --- SHARED CONTRACTS: agent-ready, hn0-dhcp, root-growth, gpt-healthy ---
# --- FILESYSTEM CONTRACTS: ufs-root / zfs-root and their growth/health state ---
ssh "${ssh_options[@]}" "$ssh_target" \
  "/bin/sh -s -- '$virtual_size' '$runtime_architecture' '$FILESYSTEM'" <<'GUEST'
set -eu
original_size=$1
runtime_arch=$2
expected_filesystem=$3

# Validate runtime architecture
hw_machine=$(sysctl -n hw.machine_arch)
test "$hw_machine" = "$runtime_arch"

# key-only-ssh: verify sshd configuration
sshd_config=$(sudo sshd -T 2>/dev/null)
printf '%s\n' "$sshd_config" | grep -iq '^passwordauthentication no'
printf '%s\n' "$sshd_config" | grep -iq '^kbdinteractiveauthentication no'

# No default freebsd account, root is locked
! id freebsd >/dev/null 2>&1
root_pw=$(sudo awk -F: '$1=="root"{print $2}' /etc/master.passwd)
case "$root_pw" in
  '*LOCKED*'|'*'|'!*'|'!') ;;
  *) echo "root account is not locked: $root_pw" >&2; exit 1 ;;
esac

# agent-ready: Azure Agent (waagent or azure-agent) is running
if ! pgrep -f 'python.*waagent' >/dev/null 2>&1 && \
   ! service azure_agent status >/dev/null 2>&1 && \
   ! pgrep azure-agent >/dev/null 2>&1; then
  echo "Azure Agent is not running" >&2
  exit 1
fi

# hn0-dhcp: network interface has an address via DHCP
if ifconfig hn0 >/dev/null 2>&1; then
  ifconfig hn0 | grep -q 'inet '
elif ifconfig eth0 >/dev/null 2>&1; then
  ifconfig eth0 | grep -q 'inet '
else
  # Any Hyper-V NIC
  nic=$(ifconfig -l | tr ' ' '\n' | grep -E '^(hn|storvsc)' | head -1)
  test -n "$nic"
  ifconfig "$nic" | grep -q 'inet '
fi

root_device=$(mount -p | awk '$2 == "/" { print $1 }')
rootfs=$(mount -p | awk '$2 == "/" { print $3 }')
test -n "$root_device"
test "$rootfs" = "$expected_filesystem"

case "$expected_filesystem" in
  ufs)
    # ufs-root and UFS growth: both the partition provider and filesystem must
    # have expanded beyond the exact candidate's original virtual size.
    grep -Eq '^[^#]+[[:space:]]+/[[:space:]]+ufs[[:space:]]' /etc/fstab
    root_provider=$(basename "$(realpath "$root_device")")
    disk=$(printf '%s\n' "$root_provider" | sed -E 's/p[0-9]+$//')
    test "$disk" != "$root_provider"
    root_partition_size=$(diskinfo "$root_device" | awk '{ print $3 }')
    root_filesystem_kib=$(df -k / | awk 'END { print $2 }')
    test "$root_partition_size" -gt "$original_size"
    test "$root_filesystem_kib" -gt "$((original_size / 1024))"
    ;;
  zfs)
    # zfs-root, pool health, autoexpand, growth, and absence of swap zvols.
    root_pool=${root_device%%/*}
    test "$root_pool" = zroot
    test "$(zpool status -x "$root_pool")" = "pool '$root_pool' is healthy"
    test "$(zpool get -H -o value autoexpand "$root_pool")" = on
    pool_size=$(zpool list -Hp -o size "$root_pool")
    test "$pool_size" -gt "$original_size"
    disk=$(zpool status -LP "$root_pool" |
      awk '/\/dev\// { sub("^/dev/", "", $1); sub("p[0-9]+$", "", $1); print $1; exit }')
    test -z "$(zfs list -H -o name,org.freebsd:swap -t volume |
      awk '$2 == "on" { print $1 }')"
    ;;
  *)
    echo "unsupported root filesystem: $expected_filesystem" >&2
    exit 1
    ;;
esac

# gpt-healthy: the OS disk has a recovered GPT and every provider is healthy.
test -n "$disk"
! gpart show "$disk" | grep -q CORRUPT
test "$(gpart status -s "$disk" | awk '{ print $2 }' | sort -u)" = OK

# no-os-disk-swap: positively identify every swap as resource-disk-backed.
require_resource_disk_provider() {
  provider=$1
  resource_disk=$(printf '%s\n' "$provider" | sed -E 's/(p|s)[0-9]+$//')
  if [ "$resource_disk" = "$provider" ] || [ "$resource_disk" = "$disk" ]; then
    echo "swap is not backed by a resource-disk partition: $provider" >&2
    return 1
  fi
  diskinfo "/dev/$resource_disk" >/dev/null
}

swapinfo -k | awk 'NR > 1 { print $1 }' | while IFS= read -r swap_device; do
  test -n "$swap_device" || continue
  swap_provider=$(basename "$(realpath "$swap_device")")
  case "$swap_provider" in
    md[0-9]*)
      md_unit=${swap_provider#md}
      md_backing=$(mdconfig -lv -u "$md_unit" |
        awk -F '	' '$2 == "vnode" { print $4; exit }')
      if [ -z "$md_backing" ] || [ ! -f "$md_backing" ]; then
        echo "swap md provider is not a resolvable vnode: $swap_device" >&2
        exit 1
      fi
      md_backing_mount=$(df -k "$md_backing" | awk 'END { print $6 }')
      md_backing_device=$(df -k "$md_backing" | awk 'END { print $1 }')
      if [ "$md_backing_mount" = / ] || [ "${md_backing_device#/dev/}" = "$md_backing_device" ]; then
        echo "swap vnode is backed by the OS/root filesystem: $md_backing" >&2
        exit 1
      fi
      md_backing_provider=$(basename "$(realpath "$md_backing_device")")
      require_resource_disk_provider "$md_backing_provider"
      ;;
    *p[0-9]*|*s[0-9]*)
      require_resource_disk_provider "$swap_provider"
      ;;
    *)
      echo "swap provider is not positively identified as resource-disk-backed: $swap_device" >&2
      exit 1
      ;;
  esac
done
GUEST

# --- CONTRACT: serial-console ---
require_serial_console_log

# --- CONTRACT: reboot-reconnect ---
reboot_and_reconnect

# --- CONTRACT: instance-identity ---
post_reboot_hostkey=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'cat /etc/ssh/ssh_host_ed25519_key.pub')
post_reboot_hostuuid=$(ssh "${ssh_options[@]}" "$ssh_target" \
  'sudo sysctl -n kern.hostuuid')
test "$pre_reboot_hostkey" = "$post_reboot_hostkey"
test "$pre_reboot_hostuuid" = "$post_reboot_hostuuid"

if [[ "$FILESYSTEM" == zfs ]]; then
  post_reboot_storage_identity=$(ssh "${ssh_options[@]}" "$ssh_target" \
    'zpool get -Hp -o value guid zroot')
  test "$pre_reboot_storage_identity" = "$post_reboot_storage_identity"
  ssh "${ssh_options[@]}" "$ssh_target" \
    'test "$(zpool status -x zroot)" = "pool '\''zroot'\'' is healthy"; test "$(zpool get -H -o value autoexpand zroot)" = on'
else
  ssh "${ssh_options[@]}" "$ssh_target" \
    'test "$(mount -p | awk '\''$2 == "/" { print $3 }'\'')" = ufs'
fi

# Clean shutdown
ssh "${ssh_options[@]}" "$ssh_target" 'sudo shutdown -p now' >/dev/null 2>&1 || true
wait_for_poweroff

# --- Generate result ---
azure_accepted_sha256=$(sha256sum "$asset" | awk '{print $1}')
test "$azure_accepted_sha256" = "$qcow_sha256"
readarray -t result_candidate < <(
  validate_candidate_binding
)
test "${#result_candidate[@]}" -eq 5
test "${result_candidate[0]}" = "$qcow_sha256"
test "${result_candidate[1]}" = "$qcow_bytes"
test "${result_candidate[2]}" = "$qcow_allocated_size"
test "${result_candidate[3]}" = "$virtual_size"
test "${result_candidate[4]}" = "$candidate_architecture"

shared_contracts_before_storage="matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp,serial-console"
shared_contracts_after_storage="root-growth,gpt-healthy,reboot-reconnect,instance-identity"
case "$FILESYSTEM" in
  zfs)
    # Keep the established ZFS/full result contract byte-for-byte stable.
    filesystem_contracts="zfs-root,zpool-healthy"
    ;;
  ufs)
    filesystem_contracts="ufs-root,ufs-root-partition-growth,ufs-root-filesystem-growth,no-os-disk-swap"
    ;;
esac
contracts="$shared_contracts_before_storage,$filesystem_contracts,$shared_contracts_after_storage"

python3 scripts/freebsd15_release.py azure-result \
  --manifest "$manifest" \
  --asset "$asset" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$AZURE_LOCATION" \
  --vm-size "$AZURE_VM_SIZE" \
  --resource-group "$resource_group" \
  --vhd-sha256 "$vhd_sha256" \
  --vhd-bytes "$vhd_bytes" \
  --contracts "$contracts" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output "$RESULT_DIR/azure-result.json"

# Final source-digest assertion
test "$(sha256sum "$asset" | awk '{print $1}')" = "$qcow_sha256"

{
  echo "### Azure acceptance: $ASSET_NAME"
  echo
  echo "- QCOW2 SHA-256: \`$qcow_sha256\`"
  echo "- Derived VHD SHA-256: \`$vhd_sha256\` (not retained or published)"
  echo "- Azure: \`$AZURE_LOCATION\` / \`$AZURE_VM_SIZE\`"
  echo "- Contracts: $contracts"
  echo "- Status: success"
} >>"$GITHUB_STEP_SUMMARY"
