#!/usr/bin/env bash
set -Eeuo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
# shellcheck source=scripts/azure_trusted_launch_lib.sh
source "$script_dir/azure_trusted_launch_lib.sh"
# shellcheck source=scripts/azure_confidential_vm_lib.sh
source "$script_dir/azure_confidential_vm_lib.sh"

printf '%s\n' \
  'input_sha256=QCOW2_SHA256' \
  'virtual_size=VIRTUAL_SIZE_BYTES' \
  'miz azure derive --input-sha256 "$input_sha256" --expected-virtual-size "$virtual_size" image.qcow2 image.vhd'

azure_trusted_launch_disk_create_args \
  RESOURCE_GROUP DISK_NAME REGION VHD_FILE_BYTES x64
azure_trusted_launch_print_command
printf '%s\n' 'azcopy copy image.vhd DISK_UPLOAD_SAS --blob-type PageBlob'
azure_trusted_launch_disk_revoke_access_args RESOURCE_GROUP DISK_NAME
azure_trusted_launch_print_command
azure_trusted_launch_disk_show_args RESOURCE_GROUP DISK_NAME
azure_trusted_launch_print_command ' > managed-disk.json'

azure_confidential_vm_sku_list_args REGION VM_SIZE
azure_confidential_vm_print_command ' > confidential-sku.json'

azure_trusted_launch_gallery_create_args RESOURCE_GROUP GALLERY REGION
azure_trusted_launch_print_command
azure_confidential_vm_image_definition_create_args \
  RESOURCE_GROUP GALLERY IMAGE_DEFINITION ubuntu2404 confidential-x64 REGION
azure_confidential_vm_print_command
azure_confidential_vm_image_definition_show_args \
  RESOURCE_GROUP GALLERY IMAGE_DEFINITION
azure_confidential_vm_print_command ' > image-definition.json'

printf '%s\n' \
  'ubuntu2404_confidential_release gallery-request --output gallery-version.json --location REGION --disk-id MANAGED_DISK_ID'
azure_trusted_launch_gallery_version_put_args \
  '/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION' \
  gallery-version.json
azure_trusted_launch_print_command ' > gallery-version-response.json'
azure_trusted_launch_gallery_version_get_args \
  '/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION'
azure_trusted_launch_print_command ' > gallery-version-final.json'

azure_confidential_vm_vm_create_args \
  RESOURCE_GROUP VM_NAME REGION VM_SIZE \
  '/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION' \
  ADMIN_USER PUBLIC_KEY_FILE
azure_confidential_vm_print_command

azure_confidential_vm_vm_resource_args RESOURCE_GROUP VM_NAME
azure_confidential_vm_print_command ' > vm-resource.json'
azure_confidential_vm_vm_instance_security_args RESOURCE_GROUP VM_NAME
azure_confidential_vm_print_command ' > instance-security.json'
printf '%s\n' \
  'ubuntu2404_confidential_release check-vm --resource vm-resource.json --instance instance-security.json'
