#!/usr/bin/env bash

# Each builder fills this array. Callers execute it as
# `az "${AZURE_TRUSTED_LAUNCH_ARGS[@]}"`; no command text is evaluated.
AZURE_TRUSTED_LAUNCH_ARGS=()

azure_trusted_launch_disk_create_args() {
  local resource_group=$1 disk_name=$2 location=$3 upload_bytes=$4 architecture=$5
  AZURE_TRUSTED_LAUNCH_ARGS=(
    disk create
    --resource-group "$resource_group"
    --name "$disk_name"
    --location "$location"
    --sku Standard_LRS
    --upload-type Upload
    --upload-size-bytes "$upload_bytes"
    --os-type Linux
    --hyper-v-generation V2
    --architecture "$architecture"
    --output json
  )
}

azure_trusted_launch_disk_show_args() {
  local resource_group=$1 disk_name=$2
  AZURE_TRUSTED_LAUNCH_ARGS=(
    disk show
    --resource-group "$resource_group"
    --name "$disk_name"
    --output json
  )
}

azure_trusted_launch_disk_revoke_access_args() {
  local resource_group=$1 disk_name=$2
  AZURE_TRUSTED_LAUNCH_ARGS=(
    disk revoke-access
    --resource-group "$resource_group"
    --name "$disk_name"
    --output json
  )
}

azure_trusted_launch_gallery_create_args() {
  local resource_group=$1 gallery=$2 location=$3
  AZURE_TRUSTED_LAUNCH_ARGS=(
    sig create
    --resource-group "$resource_group"
    --gallery-name "$gallery"
    --location "$location"
    --output json
  )
}

azure_trusted_launch_image_definition_create_args() {
  local resource_group=$1 gallery=$2 image=$3 offer=$4 sku=$5 architecture=$6 location=$7
  AZURE_TRUSTED_LAUNCH_ARGS=(
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
    --architecture "$architecture"
    --features SecurityType=TrustedLaunchSupported
    --location "$location"
    --output json
  )
}

azure_trusted_launch_image_definition_show_args() {
  local resource_group=$1 gallery=$2 image=$3
  AZURE_TRUSTED_LAUNCH_ARGS=(
    sig image-definition show
    --resource-group "$resource_group"
    --gallery-name "$gallery"
    --gallery-image-definition "$image"
    --output json
  )
}

azure_trusted_launch_gallery_version_put_args() {
  local image_version_id=$1 request=$2
  AZURE_TRUSTED_LAUNCH_ARGS=(
    rest
    --method put
    --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03"
    --body "@$request"
    --output json
  )
}

azure_trusted_launch_gallery_version_get_args() {
  local image_version_id=$1
  AZURE_TRUSTED_LAUNCH_ARGS=(
    rest
    --method get
    --uri "https://management.azure.com${image_version_id}?api-version=2025-03-03"
    --output json
  )
}

azure_trusted_launch_vm_create_args() {
  local resource_group=$1 vm_name=$2 location=$3 vm_size=$4 image_version_id=$5
  local admin_username=$6 public_key=$7 enable_agent=$8 managed_boot_diagnostics=$9
  AZURE_TRUSTED_LAUNCH_ARGS=(
    vm create
    --resource-group "$resource_group"
    --name "$vm_name"
    --location "$location"
    --size "$vm_size"
    --image "$image_version_id"
    --admin-username "$admin_username"
    --authentication-type ssh
    --ssh-key-values "$public_key"
    --enable-agent "$enable_agent"
    --enable-auto-update false
    --security-type TrustedLaunch
    --enable-secure-boot true
    --enable-vtpm true
    --public-ip-sku Standard
    --nsg-rule SSH
  )
  if [[ "$managed_boot_diagnostics" == true ]]; then
    AZURE_TRUSTED_LAUNCH_ARGS+=(--boot-diagnostics-storage "")
  fi
  AZURE_TRUSTED_LAUNCH_ARGS+=(--output json)
}

azure_trusted_launch_vm_resource_security_args() {
  local resource_group=$1 vm_name=$2
  AZURE_TRUSTED_LAUNCH_ARGS=(
    vm show
    --resource-group "$resource_group"
    --name "$vm_name"
    --query securityProfile
    --output json
  )
}

azure_trusted_launch_vm_instance_security_args() {
  local resource_group=$1 vm_name=$2
  AZURE_TRUSTED_LAUNCH_ARGS=(
    vm get-instance-view
    --resource-group "$resource_group"
    --name "$vm_name"
    --query securityProfile
    --output json
  )
}

azure_trusted_launch_print_command() {
  local suffix=${1:-} argument
  printf 'az'
  for argument in "${AZURE_TRUSTED_LAUNCH_ARGS[@]}"; do
    printf ' %q' "$argument"
  done
  printf '%s\n' "$suffix"
}
