# Azure Confidential VM images

This guide defines the Azure resource contract for a generalized image that
can create an AMD SEV-SNP Confidential VM. Image capability, VM configuration,
OS-disk encryption, and guest attestation are independent claims; acceptance
must verify every one against the same release candidate.

## Initial support boundary

The first miz Confidential VM target is Ubuntu 24.04 LTS on x64 with AMD
SEV-SNP. Its gallery image definition uses
`SecurityType=ConfidentialVMSupported`: the source contains no VM Guest State,
and the resulting version can create either a standard Gen2 VM or a
Confidential VM. Arm64 and Intel TDX are not part of this initial contract.

The source and derived fixed VHD must be strictly smaller than 32 GiB. The
deployed VM must independently request:

- `securityType=ConfidentialVM`;
- OS-disk `securityEncryptionType=VMGuestStateOnly`;
- Secure Boot enabled; and
- vTPM enabled.

`VMGuestStateOnly` encrypts the VM Guest State but does not enable confidential
OS-disk encryption. `DiskWithVMGuestState`, customer-managed confidential disk
keys, and captured `ConfidentialVM` images are separate contracts.

## Build the image

The host-native builder pins Canonical's immutable Ubuntu 24.04 Azure
publication, authenticates its detached `SHA256SUMS` signature with the
embedded Canonical cloud-image key, and safely extracts its sole sparse VHD
member:

```console
zig build generalized-ubuntu2404-confidential -- \
  --work-dir /d/miz-ubuntu2404-confidential \
  --output /d/miz-ubuntu2404-confidential/Ubuntu-24.04-x86_64.confidential.qcow2
```

The builder requires GNU tar, `gpg`, and `gpgv`. Downloads use the native Zig
HTTPS client and are written atomically beneath `--work-dir`; pass
`--proxy URL` only when egress requires an explicit proxy. After one successful
download, `--offline` rejects a missing or changed cache entry instead of
accessing the network.

Before publishing the standalone QCOW2, the builder requires the signed
manifest's Azure kernel and TPM package closure, a Linux 5.15-or-newer Azure
kernel with Hyper-V, TPM, EFI, lockdown, and SEV guest configuration, empty
machine and provisioning state, and valid x86_64 Authenticode signatures on
the fallback shim, Ubuntu shim, and GRUB.

Canonical's fixed VHD retains the internally consistent backup GPT at its
original 3,584 MiB substrate boundary while advertising a larger Azure disk.
The builder verifies that legacy GPT against the signed source, relocates only
the backup GPT metadata and protective-MBR extent to the current disk end, and
then requires a fully verified Gen2 GPT. Partition extents, filesystems, and
guest bytes are unchanged. The candidate is read back through miz and must
expose the same signer and boot-binary digests as the fixed source VHD.

The companion `<output>.provenance.json` binds the signed publication inputs,
extracted fixed VHD, validated kernel release, Secure Boot binaries and signer
certificates, and final QCOW2 SHA-256. This proves the local build chain; live
Azure acceptance remains responsible for proving SEV-SNP execution and guest
attestation.

## Secure Boot trust

The Ubuntu 24.04 target preserves Canonical's stock Azure boot chain:
Microsoft-trusted shim followed by Canonical-signed GRUB, kernel, and modules.
It does not append the miz release certificate to UEFI `db`.

Azure documents custom UEFI keys for `TrustedLaunchSupported` and
`TrustedLaunchAndConfidentialVmSupported` image definitions. It does not
document them for the exact `ConfidentialVMSupported` definition required
here. The gallery-version request therefore omits
`securityProfile.uefiSettings`; the release tooling rejects a request or
response that injects custom UEFI settings.

## Canonical command path

The commands below are generated from the argument-array builders used by the
acceptance harness. `DISK_UPLOAD_SAS` is the short-lived managed-disk write
SAS. The gallery version is built from the exact uploaded disk and the VM is
built from that exact gallery-version ID.

<!-- BEGIN GENERATED AZURE CONFIDENTIAL VM COMMANDS -->
```console
input_sha256=QCOW2_SHA256
virtual_size=VIRTUAL_SIZE_BYTES
miz azure derive --input-sha256 "$input_sha256" --expected-virtual-size "$virtual_size" image.qcow2 image.vhd
az disk create --resource-group RESOURCE_GROUP --name DISK_NAME --location REGION --sku Standard_LRS --upload-type Upload --upload-size-bytes VHD_FILE_BYTES --os-type Linux --hyper-v-generation V2 --architecture x64 --output json
azcopy copy image.vhd DISK_UPLOAD_SAS --blob-type PageBlob
az disk revoke-access --resource-group RESOURCE_GROUP --name DISK_NAME --output json
az disk show --resource-group RESOURCE_GROUP --name DISK_NAME --output json > managed-disk.json
az vm list-skus --location REGION --resource-type virtualMachines --size VM_SIZE --all --output json > confidential-sku.json
az sig create --resource-group RESOURCE_GROUP --gallery-name GALLERY --location REGION --output json
az sig image-definition create --resource-group RESOURCE_GROUP --gallery-name GALLERY --gallery-image-definition IMAGE_DEFINITION --publisher miz --offer ubuntu2404 --sku confidential-x64 --os-type Linux --os-state Generalized --hyper-v-generation V2 --architecture x64 --features SecurityType=ConfidentialVMSupported --location REGION --output json
az sig image-definition show --resource-group RESOURCE_GROUP --gallery-name GALLERY --gallery-image-definition IMAGE_DEFINITION --output json > image-definition.json
ubuntu2404_confidential_release gallery-request --output gallery-version.json --location REGION --disk-id MANAGED_DISK_ID
az rest --method put --uri https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION\?api-version=2025-03-03 --body @gallery-version.json --output json > gallery-version-response.json
az rest --method get --uri https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION\?api-version=2025-03-03 --output json > gallery-version-final.json
az vm create --resource-group RESOURCE_GROUP --name VM_NAME --location REGION --size VM_SIZE --image /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION --admin-username ADMIN_USER --authentication-type ssh --ssh-key-values PUBLIC_KEY_FILE --enable-agent true --enable-auto-update false --security-type ConfidentialVM --os-disk-security-encryption-type VMGuestStateOnly --enable-secure-boot true --enable-vtpm true --public-ip-sku Standard --nsg-rule SSH --output json
az vm show --resource-group RESOURCE_GROUP --name VM_NAME --query \{securityProfile:securityProfile\,osDiskSecurityProfile:storageProfile.osDisk.managedDisk.securityProfile\,imageReference:storageProfile.imageReference\} --output json > vm-resource.json
az vm get-instance-view --resource-group RESOURCE_GROUP --name VM_NAME --query securityProfile --output json > instance-security.json
ubuntu2404_confidential_release check-vm --resource vm-resource.json --instance instance-security.json
```
<!-- END GENERATED AZURE CONFIDENTIAL VM COMMANDS -->

The generated block comes from
`scripts/azure_confidential_vm_examples.sh`. The shared managed-disk, gallery,
and image-version commands use `scripts/azure_trusted_launch_lib.sh`; the
Confidential VM-specific SKU, definition, deployment, and query commands use
`scripts/azure_confidential_vm_lib.sh`.

## Required acceptance

Azure metadata is not proof of confidential execution. Protected acceptance
must also obtain a nonce-bound Microsoft Azure Attestation result from inside
the guest and require AMD SEV-SNP, `azure-compliant-cvm`, Secure Boot, vTPM,
and non-debuggable state. The attested Azure VM identity must match the VM
created from the accepted gallery version.

Microsoft references:

- [Azure Confidential VM options](https://learn.microsoft.com/azure/confidential-computing/virtual-machine-options)
- [Create a Confidential VM from an Azure Compute Gallery image](https://learn.microsoft.com/azure/confidential-computing/create-confidential-vm-from-compute-gallery)
- [Guest attestation for Confidential VMs](https://learn.microsoft.com/azure/confidential-computing/guest-attestation-confidential-vms)
- [Secure Boot custom UEFI keys](https://learn.microsoft.com/azure/virtual-machines/trusted-launch-secure-boot-custom-uefi)
