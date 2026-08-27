#!/usr/bin/env bash
set -Eeuo pipefail

command_name=${1:-run}
if [[ -z ${STATE_FILE:-} || -z ${GITHUB_RUN_ID:-} || -z ${GITHUB_RUN_ATTEMPT:-} || -z ${CANDIDATE_KEY:-} ]]; then
  echo "::error::Azure cleanup identity is incomplete"
  exit 1
fi
release_tool=${AZURELINUX4_RELEASE:-zig-out/bin/azurelinux4_release}
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
  expected_resource_group="miz-al4-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
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
  if [[ ! -x "$release_tool" ]]; then
    echo "::error::Azure Linux release tool is unavailable during cleanup"
    return 1
  fi
  if ! "$release_tool" check-group-tags \
      --metadata "$metadata_file" \
      --run-id "$GITHUB_RUN_ID" \
      --run-attempt "$GITHUB_RUN_ATTEMPT" \
      --key "$CANDIDATE_KEY"
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
      -z ${AZURE_VM_SIZE:-} || -z ${RESULT_DIR:-} || -z ${MIZ:-} ||
      -z ${GITHUB_STEP_SUMMARY:-} ]]; then
  echo "::error::Azure acceptance configuration is incomplete"
  exit 1
fi
[[ "$SOURCE_COMMIT" =~ ^[0-9a-f]{40}$ ]]
[[ "$ARCHITECTURE" =~ ^(x86_64|aarch64)$ ]]
[[ "$FLAVOR" =~ ^(full|core)$ ]]
[[ "$CANDIDATE_KEY" == "$ARCHITECTURE-$FLAVOR" ]]
[[ "$AZURE_LOCATION" =~ ^[a-z0-9-]+$ ]]
[[ "$AZURE_VM_SIZE" =~ ^Standard_[A-Za-z0-9_]+$ ]]
[[ -x "$MIZ" ]]

report_error() {
  local status=$1 line=$2 command=$3
  trap - ERR
  printf '::error::Azure acceptance failed at line %s: %s\n' "$line" "$command" >&2
  exit "$status"
}
trap 'report_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

for tool in az azcopy curl qemu-img sha256sum ssh ssh-keygen; do
  command -v "$tool" >/dev/null || {
    echo "::error::Required Azure acceptance tool $tool is unavailable"
    exit 1
  }
done
[[ -x "$release_tool" ]] || {
  echo "::error::Azure Linux release tool is unavailable: $release_tool"
  exit 1
}

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
  if ! sas=$("$release_tool" disk-access-sas --response "$response_body")
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
  "$release_tool" verify-candidate \
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

suffix=${CANDIDATE_KEY//_/-}
resource_group="miz-al4-${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}-${suffix}"
short_arch=${ARCHITECTURE/x86_64/x64}
name_seed="${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}${short_arch}${FLAVOR}"
disk_name="miz-os-${name_seed}"
data_disk_name="miz-data-${name_seed}"
gallery_name="mizal4${name_seed}"
image_name="mizal4${short_arch}${FLAVOR}"
vm_name="miz-vm-${name_seed}"
admin_username=miztest
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
mkdir -p "$(dirname -- "$STATE_FILE")"
rm -f -- "$STATE_FILE" "${STATE_FILE}.group.json" "$vhd" "$private_key" "$private_key.pub"
readarray -t signing_identity < <(
  "$release_tool" signing-identity \
    --manifest "$manifest" \
    --certificate-der "$certificate_der"
)
test "${#signing_identity[@]}" -eq 2
certificate_sha256=${signing_identity[0]}
fallback_uki_sha256=${signing_identity[1]}
[[ "$certificate_sha256" =~ ^[0-9a-f]{64}$ ]]
[[ "$fallback_uki_sha256" =~ ^[0-9a-f]{64}$ ]]
test -s "$certificate_der"

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
    miz-owner=azurelinux4-release \
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
has_resource_disk=$(
  "$release_tool" check-vm-sku \
    --skus "$sku_json" \
    --vm-size "$AZURE_VM_SIZE" \
    --architecture "$expected_azure_architecture"
)
[[ "$has_resource_disk" == true || "$has_resource_disk" == false ]]

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
  "$release_tool" verify-vhd \
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
  --offer azurelinux4 \
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
"$release_tool" gallery-request \
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
"$release_tool" check-gallery-accepted \
  --request "$uefi_request" \
  --response "$uefi_create_response"
for _ in {1..120}; do
  provisioning_state=$("$release_tool" gallery-state --response "$uefi_response")
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
"$release_tool" check-gallery-final \
  --request "$uefi_request" \
  --response "$uefi_response" \
  --image-version-id "$image_version_id"
[[ "$image_version_id" == /subscriptions/* ]]

ssh-keygen -q -t ed25519 -N '' -C miz-azure-acceptance -f "$private_key"
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
"$release_tool" check-vm-security \
  --profile "$vm_security_json" \
  --profile "$instance_security_json"
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
test "$root_size" -gt $((original_size + 1073741824))
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key.pub
GUEST

uefi_db="$RESULT_DIR/uefi-db.bin"
ssh "${ssh_options[@]}" "$ssh_target" \
  "sudo -n /usr/bin/cat /sys/firmware/efi/efivars/db-*" >"$uefi_db"
"$release_tool" check-uefi-db \
  --db "$uefi_db" \
  --certificate-sha256 "$certificate_sha256"
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
sudo -n /usr/bin/test /proc/1/exe -ef /sbin/mizinit
test -f /var/lib/azagent/provisioned
master=
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
    *"/usr/sbin/sshd -D -e"*) master=${proc##*/}; break ;;
  esac
done
test -n "$master"
if mountpoint -q /d; then
  mountpoint -q /d
  test "$(findmnt -n -o FSTYPE /d)" = ext4
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
GUEST
else
  ssh "${ssh_options[@]}" "$ssh_target" '/usr/bin/bash -s' <<'GUEST'
set -euo pipefail
sudo -n /usr/bin/test /proc/1/exe -ef /usr/lib/systemd/systemd
test ! -e /sbin/mizinit
test ! -e /usr/bin/mizinit
for unit in cloud-final.service waagent.service sshd.service systemd-networkd.service; do
  systemctl is-active --quiet "$unit"
  systemctl is-enabled --quiet "$unit"
done
cloud-init status --wait
grep -Eq '^[[:space:]]*Provisioning.Agent[[:space:]]*=[[:space:]]*auto[[:space:]]*$' /etc/waagent.conf
grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
! mountpoint -q /d
GUEST
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

expected_data_disk_size=$((data_disk_size_gib * 1073741824))
data_device=$(ssh "${ssh_options[@]}" "$ssh_target" \
  "/usr/bin/bash -s -- '$expected_data_disk_size'" <<'GUEST'
set -Eeuo pipefail
guest_error() {
  status=$1
  trap - ERR
  printf 'guest acceptance failed at line %s: %s\n' "$2" "$3" >&2
  exit "$status"
}
trap 'guest_error "$?" "$LINENO" "$BASH_COMMAND"' ERR
expected_size=$1
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
    grep -Fq '[mizinit] MIZINIT_PID1_READY supervisor loop active' "$boot_log"
    grep -Fq '[mizinit] azagent completed successfully' "$boot_log"
  fi
  if [[ "$ARCHITECTURE" == aarch64 ]]; then
    grep -Fq 'ttyAMA0' "$boot_log"
  fi
  ! grep -Eiq 'security violation|module verification failed|Loading of unsigned module' "$boot_log"
else
  echo "::warning::Azure managed boot diagnostics did not return a serial log"
fi

"$release_tool" azure-result \
  --manifest "$manifest" \
  --asset "$asset" \
  --vhd "$vhd" \
  --vhd-current-size "$vhd_current_size" \
  --key "$CANDIDATE_KEY" \
  --source-commit "$SOURCE_COMMIT" \
  --location "$AZURE_LOCATION" \
  --vm-size "$AZURE_VM_SIZE" \
  --resource-group "$resource_group" \
  --image-version-id "$image_version_id" \
  --uefi-request "$uefi_request" \
  --uefi-response "$uefi_response" \
  --run-id "$GITHUB_RUN_ID" \
  --run-attempt "$GITHUB_RUN_ATTEMPT" \
  --output "$RESULT_DIR/azure-result.json"
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
  echo "- Contracts: Trusted Launch, Secure Boot, vTPM, UEFI db signer, signed UKI, lockdown, modules, key-only SSH, Ready, root growth, resource/data disks, reboot, runtime identity"
} >>"$GITHUB_STEP_SUMMARY"
