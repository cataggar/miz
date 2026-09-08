#!/usr/bin/env bash

UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS=()
UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET=
UBUNTU2404_CONFIDENTIAL_GUEST_VM_ID=
UBUNTU2404_CONFIDENTIAL_GUEST_VALIDATION_FILES_COPIED=false
UBUNTU2404_CONFIDENTIAL_GUEST_AZURE_TAGS=()

UBUNTU2404_CONFIDENTIAL_ATTESTATION_PACKAGE_URL=https://packages.microsoft.com/repos/azurecore/pool/main/a/azguestattestation1/azguestattestation1_1.0.5_amd64.deb
UBUNTU2404_CONFIDENTIAL_ATTESTATION_PACKAGE_SHA256=791dd441f84fca9ad3f9c46263a919ce50c987cfc4a80faf2f9d6bfc94d71815
UBUNTU2404_CONFIDENTIAL_ATTESTATION_CLIENT_URL=https://raw.githubusercontent.com/Azure/confidential-computing-cvm-guest-attestation/09bc7bd670d52321760e640486ab5d556b6b5285/cvm-platform-checker-exe/Linux/cvm_linux_attestation_client.zip
UBUNTU2404_CONFIDENTIAL_ATTESTATION_CLIENT_ARCHIVE_SHA256=e046f80a571d73d59494a0c76b3c6277d5b04fc35cf6822901c20052d0487c2f
UBUNTU2404_CONFIDENTIAL_ATTESTATION_CLIENT_SHA256=a2aef93976948443ac981e18a260c2ae9f736368f8713b875916703ab37e9bc6

ubuntu2404_confidential_guest_configure_ssh() {
  local private_key=$1 known_hosts=$2 admin_username=$3 public_ip=$4
  [[ -n "$private_key" && -n "$known_hosts" && -n "$admin_username" ]] ||
    return 1
  [[ "$public_ip" =~ ^[0-9a-fA-F:.]+$ ]] || return 1
  UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS=(
    -i "$private_key"
    -o BatchMode=yes
    -o ConnectTimeout=10
    -o StrictHostKeyChecking=accept-new
    -o "UserKnownHostsFile=$known_hosts"
  )
  UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET="$admin_username@$public_ip"
}

ubuntu2404_confidential_guest_require_ssh() {
  if [[ -z "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" ||
        ${#UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]} -eq 0 ]]; then
    echo "::error::Ubuntu 24.04 Confidential VM guest SSH is not configured" >&2
    return 1
  fi
}

ubuntu2404_confidential_guest_wait_for_ssh() {
  ubuntu2404_confidential_guest_require_ssh || return
  local attempt
  for attempt in {1..180}; do
    if ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
        "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" true >/dev/null 2>&1; then
      return
    fi
    sleep 10
  done
  echo "::error::SSH did not become ready" >&2
  return 1
}

ubuntu2404_confidential_guest_check_readiness() {
  local expected_virtual_size=$1
  [[ "$expected_virtual_size" =~ ^[1-9][0-9]*$ ]] || return 1
  ubuntu2404_confidential_guest_require_ssh || return
  ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
    "/usr/bin/bash -s -- '$expected_virtual_size'" <<'GUEST'
set -Eeuo pipefail
expected_virtual_size=$1
test "$(uname -m)" = x86_64
grep -Fxq 'VERSION_ID="24.04"' /etc/os-release
sudo -n cloud-init status --wait >/dev/null
systemctl is-active --quiet walinuxagent.service
test -s /etc/machine-id
test -s /etc/ssh/ssh_host_ed25519_key
test -d /sys/firmware/efi
test -c /dev/tpmrm0
sudo -n mokutil --sb-state | grep -Fqx 'SecureBoot enabled'
root_source=$(findmnt -n -o SOURCE /)
root_disk=$(lsblk -n -s -o NAME,TYPE "$root_source" | awk '$2 == "disk" {print "/dev/"$1; exit}')
test -b "$root_disk"
root_bytes=$(lsblk -b -dn -o SIZE "$root_disk")
test "$root_bytes" -ge "$expected_virtual_size"
GUEST
}

ubuntu2404_confidential_guest_collect_identity() {
  local output=$1 expected_vm_id=$2
  [[ "$expected_vm_id" =~ ^[0-9a-fA-F-]{36}$ ]] || return 1
  ubuntu2404_confidential_guest_require_ssh || return
  ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
    'curl --fail --silent --show-error -H Metadata:true "http://169.254.169.254/metadata/instance?api-version=2025-04-07"' \
    >"$output" || return
  UBUNTU2404_CONFIDENTIAL_GUEST_VM_ID=$(
    jq -er '.compute.vmId | select(type == "string")' "$output"
  ) || return
  test "${UBUNTU2404_CONFIDENTIAL_GUEST_VM_ID,,}" = "${expected_vm_id,,}"
}

ubuntu2404_confidential_guest_pre_capture_check() {
  local expected_virtual_size=$1 expected_vm_id=$2 guest_imds=$3
  ubuntu2404_confidential_guest_wait_for_ssh || return
  ubuntu2404_confidential_guest_check_readiness "$expected_virtual_size" ||
    return
  ubuntu2404_confidential_guest_collect_identity "$guest_imds" "$expected_vm_id"
}

ubuntu2404_confidential_guest_prepare_attestation_client() {
  local result_dir=$1
  local package="$result_dir/azguestattestation1.deb"
  local archive="$result_dir/attestation-client.zip"
  local client="$result_dir/attestation-client/cvm_linux_attestation_client/AttestationClient"

  curl --fail --silent --show-error --location \
    --output "$package" \
    "$UBUNTU2404_CONFIDENTIAL_ATTESTATION_PACKAGE_URL" || return
  echo "$UBUNTU2404_CONFIDENTIAL_ATTESTATION_PACKAGE_SHA256  $package" |
    sha256sum --check --status || return
  curl --fail --silent --show-error --location \
    --output "$archive" \
    "$UBUNTU2404_CONFIDENTIAL_ATTESTATION_CLIENT_URL" || return
  echo "$UBUNTU2404_CONFIDENTIAL_ATTESTATION_CLIENT_ARCHIVE_SHA256  $archive" |
    sha256sum --check --status || return
  unzip -q "$archive" -d "$result_dir/attestation-client" || return
  echo "$UBUNTU2404_CONFIDENTIAL_ATTESTATION_CLIENT_SHA256  $client" |
    sha256sum --check --status || return
  chmod 0755 "$client"
}

ubuntu2404_confidential_guest_collect_attestation() {
  local endpoint=$1 nonce=$2 result_dir=$3 token=$4 openid=$5 jwks=$6 stderr=$7
  local package="$result_dir/azguestattestation1.deb"
  local client="$result_dir/attestation-client/cvm_linux_attestation_client/AttestationClient"
  local jwks_uri ssh_status
  [[ "$endpoint" =~ ^https://[a-z0-9.-]+\.attest\.azure\.net$ ]] || return 1
  [[ "$nonce" =~ ^[0-9a-f]{64}$ ]] || return 1
  ubuntu2404_confidential_guest_require_ssh || return

  ubuntu2404_confidential_guest_prepare_attestation_client "$result_dir" ||
    return
  UBUNTU2404_CONFIDENTIAL_GUEST_VALIDATION_FILES_COPIED=true
  scp "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$package" \
    "$client" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET:/tmp/" || return

  ssh_status=0
  ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
    "/usr/bin/bash -s -- '$endpoint/' '$nonce'" \
    >"$token" 2>"$stderr" <<'GUEST' || ssh_status=$?
set -Eeuo pipefail
endpoint=$1
nonce=$2
sudo -n dpkg -i /tmp/azguestattestation1.deb >/dev/null
sudo -n chmod 0755 /tmp/AttestationClient
sudo -n /tmp/AttestationClient -a "$endpoint" -n "$nonce" -o TOKEN
GUEST
  if (( ssh_status != 0 )); then
    return "$ssh_status"
  fi
  test -s "$token" || return

  curl --fail --silent --show-error \
    --output "$openid" \
    "$endpoint/.well-known/openid-configuration" || return
  jwks_uri=$(jq -er '.jwks_uri | select(type == "string")' "$openid") ||
    return
  test "$jwks_uri" = "$endpoint/certs" || return
  curl --fail --silent --show-error --output "$jwks" "$jwks_uri"
}

ubuntu2404_confidential_guest_validate_persistent_data_disk() {
  local resource_group=$1 vm_name=$2 data_disk_name=$3 location=$4 nonce=$5
  local data_disk_size_gib=4 data_marker_sha256 old_boot_id new_boot_id attempt
  local -a tag_args=()
  ubuntu2404_confidential_guest_require_ssh || return

  if ((${#UBUNTU2404_CONFIDENTIAL_GUEST_AZURE_TAGS[@]} != 0)); then
    tag_args=(--tags "${UBUNTU2404_CONFIDENTIAL_GUEST_AZURE_TAGS[@]}")
  fi
  az disk create \
    --resource-group "$resource_group" \
    --name "$data_disk_name" \
    --location "$location" \
    --size-gb "$data_disk_size_gib" \
    --sku Standard_LRS \
    "${tag_args[@]}" \
    --output none || return
  az vm disk attach \
    --resource-group "$resource_group" \
    --vm-name "$vm_name" \
    --name "$data_disk_name" \
    --lun 0 \
    --output none || return
  data_marker_sha256=$(
    ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
      "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
      "/usr/bin/bash -s -- '$nonce'" <<'GUEST'
set -Eeuo pipefail
nonce=$1
for _ in {1..60}; do
  test -b /dev/disk/azure/scsi1/lun0 && break
  sleep 2
done
disk=$(readlink -f /dev/disk/azure/scsi1/lun0)
test -b "$disk"
sudo -n mkfs.ext4 -q "$disk"
sudo -n mkdir -p /mnt/miz-acceptance
uuid=$(sudo -n blkid -s UUID -o value "$disk")
echo "UUID=$uuid /mnt/miz-acceptance ext4 defaults,nofail 0 2" |
  sudo -n tee -a /etc/fstab >/dev/null
sudo -n mount /mnt/miz-acceptance
printf '%s' "$nonce" | sudo -n tee /mnt/miz-acceptance/nonce >/dev/null
sudo -n sha256sum /mnt/miz-acceptance/nonce | awk '{print $1}'
GUEST
  ) || return
  [[ "$data_marker_sha256" =~ ^[0-9a-f]{64}$ ]] || return 1
  old_boot_id=$(
    ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
      "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
      cat /proc/sys/kernel/random/boot_id
  ) || return
  ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
    'sudo -n reboot' >/dev/null 2>&1 || true
  new_boot_id=
  for attempt in {1..180}; do
    new_boot_id=$(
      ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
        "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
        cat /proc/sys/kernel/random/boot_id 2>/dev/null || true
    )
    if [[ -n "$new_boot_id" && "$new_boot_id" != "$old_boot_id" ]]; then
      break
    fi
    sleep 10
  done
  [[ -n "$new_boot_id" && "$new_boot_id" != "$old_boot_id" ]] || return 1
  test "$(
    ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
      "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
      'sudo -n sha256sum /mnt/miz-acceptance/nonce' |
      awk '{print $1}'
  )" = "$data_marker_sha256" || return
  ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
    'systemctl is-active --quiet walinuxagent.service && sudo -n mokutil --sb-state' |
    grep -Fqx 'SecureBoot enabled'
}

ubuntu2404_confidential_guest_cleanup_validation_files() {
  if [[ "$UBUNTU2404_CONFIDENTIAL_GUEST_VALIDATION_FILES_COPIED" != true ]]; then
    return
  fi
  ubuntu2404_confidential_guest_require_ssh || return
  ssh "${UBUNTU2404_CONFIDENTIAL_GUEST_SSH_OPTIONS[@]}" \
    "$UBUNTU2404_CONFIDENTIAL_GUEST_SSH_TARGET" \
    'sudo -n rm -f /tmp/azguestattestation1.deb /tmp/AttestationClient' ||
    return
  UBUNTU2404_CONFIDENTIAL_GUEST_VALIDATION_FILES_COPIED=false
}

ubuntu2404_confidential_guest_final_acceptance() {
  local expected_virtual_size=$1 expected_vm_id=$2 guest_imds=$3
  local endpoint=$4 nonce=$5 result_dir=$6 token=$7 openid=$8 jwks=$9
  local stderr=${10} resource_group=${11} vm_name=${12}
  local data_disk_name=${13} location=${14}
  local validation_status=0 cleanup_status=0

  ubuntu2404_confidential_guest_wait_for_ssh || validation_status=$?
  if (( validation_status == 0 )); then
    ubuntu2404_confidential_guest_check_readiness "$expected_virtual_size" ||
      validation_status=$?
  fi
  if (( validation_status == 0 )); then
    ubuntu2404_confidential_guest_collect_attestation \
      "$endpoint" "$nonce" "$result_dir" "$token" "$openid" "$jwks" "$stderr" ||
      validation_status=$?
  fi
  if (( validation_status == 0 )); then
    ubuntu2404_confidential_guest_collect_identity \
      "$guest_imds" "$expected_vm_id" || validation_status=$?
  fi
  if (( validation_status == 0 )); then
    ubuntu2404_confidential_guest_validate_persistent_data_disk \
      "$resource_group" "$vm_name" "$data_disk_name" "$location" "$nonce" ||
      validation_status=$?
  fi
  ubuntu2404_confidential_guest_cleanup_validation_files || cleanup_status=$?
  if (( validation_status != 0 )); then
    return "$validation_status"
  fi
  return "$cleanup_status"
}
