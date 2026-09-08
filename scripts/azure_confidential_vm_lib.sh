#!/usr/bin/env bash

# Each builder fills this array. Callers execute it as
# `az "${AZURE_CONFIDENTIAL_VM_ARGS[@]}"`; no command text is evaluated.
AZURE_CONFIDENTIAL_VM_ARGS=()

azure_confidential_vm_sku_list_args() {
  local location=$1 vm_size=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm list-skus
    --location "$location"
    --resource-type virtualMachines
    --size "$vm_size"
    --all
    --output json
  )
}

azure_confidential_vm_image_definition_create_args() {
  local resource_group=$1 gallery=$2 image=$3 offer=$4 sku=$5 location=$6
  AZURE_CONFIDENTIAL_VM_ARGS=(
    sig image-definition create
    --resource-group "$resource_group"
    --gallery-name "$gallery"
    --gallery-image-definition "$image"
    --publisher miz
    --offer "$offer"
    --sku "$sku"
    --os-type Linux
    --os-state Generalized
    --hyper-v-generation V2
    --architecture x64
    --features SecurityType=ConfidentialVMSupported
    --location "$location"
    --output json
  )
}

azure_confidential_vm_image_definition_show_args() {
  local resource_group=$1 gallery=$2 image=$3
  AZURE_CONFIDENTIAL_VM_ARGS=(
    sig image-definition show
    --resource-group "$resource_group"
    --gallery-name "$gallery"
    --gallery-image-definition "$image"
    --output json
  )
}

azure_confidential_vm_managed_image_create_args() {
  local resource_group=$1 image=$2 location=$3 disk_id=$4
  AZURE_CONFIDENTIAL_VM_ARGS=(
    image create
    --resource-group "$resource_group"
    --name "$image"
    --location "$location"
    --source "$disk_id"
    --os-type Linux
    --hyper-v-generation V2
    --output json
  )
}

azure_confidential_vm_managed_image_show_args() {
  local resource_group=$1 image=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    image show
    --resource-group "$resource_group"
    --name "$image"
    --output json
  )
}

azure_confidential_vm_vm_create_args() {
  local resource_group=$1 vm_name=$2 location=$3 vm_size=$4 image_version_id=$5
  local admin_username=$6 public_key=$7 managed_boot_diagnostics=${8:-false}
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm create
    --resource-group "$resource_group"
    --name "$vm_name"
    --location "$location"
    --size "$vm_size"
    --image "$image_version_id"
    --admin-username "$admin_username"
    --authentication-type ssh
    --ssh-key-values "$public_key"
    --enable-agent true
    --enable-auto-update false
    --security-type ConfidentialVM
    --os-disk-security-encryption-type VMGuestStateOnly
    --enable-secure-boot true
    --enable-vtpm true
    --public-ip-sku Standard
    --nsg-rule SSH
  )
  if [[ "$managed_boot_diagnostics" == true ]]; then
    AZURE_CONFIDENTIAL_VM_ARGS+=(--boot-diagnostics-storage "")
  fi
  AZURE_CONFIDENTIAL_VM_ARGS+=(--output json)
}

azure_confidential_vm_captured_vm_create_args() {
  local resource_group=$1 vm_name=$2 location=$3 vm_size=$4 image_version_id=$5
  local admin_username=$6 public_key=$7 managed_boot_diagnostics=${8:-false}
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm create
    --resource-group "$resource_group"
    --name "$vm_name"
    --location "$location"
    --size "$vm_size"
    --image "$image_version_id"
    --admin-username "$admin_username"
    --authentication-type ssh
    --ssh-key-values "$public_key"
    --enable-agent true
    --enable-auto-update false
    --public-ip-sku Standard
    --nsg-rule SSH
  )
  if [[ "$managed_boot_diagnostics" == true ]]; then
    AZURE_CONFIDENTIAL_VM_ARGS+=(--boot-diagnostics-storage "")
  fi
  AZURE_CONFIDENTIAL_VM_ARGS+=(--output json)
}

azure_confidential_vm_vm_resource_args() {
  local resource_group=$1 vm_name=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm show
    --resource-group "$resource_group"
    --name "$vm_name"
    --query '{id:id,vmId:vmId,securityProfile:securityProfile,osDiskSecurityProfile:storageProfile.osDisk.managedDisk.securityProfile,imageReference:storageProfile.imageReference}'
    --output json
  )
}

azure_confidential_vm_vm_instance_security_args() {
  local resource_group=$1 vm_name=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm get-instance-view
    --resource-group "$resource_group"
    --name "$vm_name"
    --query securityProfile
    --output json
  )
}

azure_confidential_vm_capture_vm_resource_args() {
  local resource_group=$1 vm_name=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm show
    --resource-group "$resource_group"
    --name "$vm_name"
    --query '{id:id,vmId:vmId,location:location,provisioningState:provisioningState,securityProfile:securityProfile,storageProfile:storageProfile}'
    --output json
  )
}

azure_confidential_vm_captured_vm_resource_args() {
  azure_confidential_vm_capture_vm_resource_args "$@"
}

azure_confidential_vm_deallocate_args() {
  local resource_group=$1 vm_name=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm deallocate
    --resource-group "$resource_group"
    --name "$vm_name"
    --output json
  )
}

azure_confidential_vm_generalize_args() {
  local resource_group=$1 vm_name=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    vm generalize
    --resource-group "$resource_group"
    --name "$vm_name"
    --output json
  )
}

azure_confidential_vm_capture_disk_show_args() {
  local disk_id=$1
  AZURE_CONFIDENTIAL_VM_ARGS=(
    disk show
    --ids "$disk_id"
    --output json
  )
}

azure_confidential_vm_snapshot_create_args() {
  local resource_group=$1 snapshot=$2 location=$3 disk_id=$4
  AZURE_CONFIDENTIAL_VM_ARGS=(
    snapshot create
    --resource-group "$resource_group"
    --name "$snapshot"
    --location "$location"
    --source "$disk_id"
    --sku Standard_LRS
    --output json
  )
}

azure_confidential_vm_snapshot_show_args() {
  local resource_group=$1 snapshot=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    snapshot show
    --resource-group "$resource_group"
    --name "$snapshot"
    --output json
  )
}

azure_confidential_vm_capture_image_definition_create_args() {
  local resource_group=$1 gallery=$2 image=$3 offer=$4 sku=$5 location=$6
  AZURE_CONFIDENTIAL_VM_ARGS=(
    sig image-definition create
    --resource-group "$resource_group"
    --gallery-name "$gallery"
    --gallery-image-definition "$image"
    --publisher miz
    --offer "$offer"
    --sku "$sku"
    --os-type Linux
    --os-state Generalized
    --hyper-v-generation V2
    --architecture x64
    --features SecurityType=ConfidentialVM
    --location "$location"
    --output json
  )
}

azure_confidential_vm_capture_image_definition_show_args() {
  local resource_group=$1 gallery=$2 image=$3
  AZURE_CONFIDENTIAL_VM_ARGS=(
    sig image-definition show
    --resource-group "$resource_group"
    --gallery-name "$gallery"
    --gallery-image-definition "$image"
    --output json
  )
}

azure_confidential_vm_resource_group_conditional_create_args() {
  local resource_group_id=$1 request=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    rest
    --method put
    --uri "https://management.azure.com${resource_group_id}?api-version=2022-09-01"
    --headers 'If-None-Match=*'
    --body "@$request"
    --output json
  )
}

azure_confidential_vm_capture_image_definition_conditional_create_args() {
  local image_definition_id=$1 request=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    rest
    --method put
    --uri "https://management.azure.com${image_definition_id}?api-version=2025-03-03"
    --headers 'If-None-Match=*'
    --body "@$request"
    --output json
  )
}

azure_confidential_vm_capture_gallery_version_put_args() {
  local image_version_id=$1 request=$2
  AZURE_CONFIDENTIAL_VM_ARGS=(
    rest
    --method put
    --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03"
    --headers 'If-None-Match=*'
    --body "@$request"
    --output json
  )
}

azure_confidential_vm_capture_gallery_version_get_args() {
  local image_version_id=$1
  AZURE_CONFIDENTIAL_VM_ARGS=(
    rest
    --method get
    --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03&%24expand=ReplicationStatus"
    --output json
  )
}

azure_confidential_vm_print_command() {
  local suffix=${1:-} argument
  printf 'az'
  for argument in "${AZURE_CONFIDENTIAL_VM_ARGS[@]}"; do
    printf ' %q' "$argument"
  done
  printf '%s\n' "$suffix"
}
