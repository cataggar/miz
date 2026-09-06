# Azure Trusted Launch images

This guide is the canonical path from a generalized `miz` image to an Azure
Compute Gallery image version that can boot with Trusted Launch, Secure Boot,
and a vTPM. The managed disk, gallery image definition, gallery image version,
and deployed VM are separate resources with separate security contracts.
Success at one stage does not prove the next.

## `TrustedLaunchSupported` and `TrustedLaunch`

`TrustedLaunchSupported` is an **image capability**. Set it on the gallery
image definition with the `SecurityType` feature to state that versions under
that definition can be used for Trusted Launch or standard Gen2 VMs.

`TrustedLaunch` is a **VM configuration**. Set it when deploying the VM,
together with Secure Boot and vTPM. Do not put `TrustedLaunch` on an image
definition, and do not treat `TrustedLaunchSupported` metadata as proof that a
VM was deployed securely.

A generic Gen2 VHD is not automatically a supported Trusted Launch image.
The complete contract also requires:

- a generalized Linux GPT/UEFI image with a Hyper-V V2 managed disk;
- a gallery definition with matching architecture and
  `SecurityType=TrustedLaunchSupported`;
- an image version whose UEFI `db` trusts the certificate that signed the
  accepted boot chain; and
- a compatible VM size deployed as `TrustedLaunch` with Secure Boot and vTPM.

The command path requires `miz` (or the matching native release tool), Azure
CLI authenticated to the target subscription, AzCopy, and permission to
create managed disks, galleries, image definitions and versions, networks,
and VMs. The custom UEFI image-version request also requires direct
`Microsoft.Compute` REST access.

## End-to-end workflow

1. **Build or obtain a generalized Gen2 image.** Use one of the generalized
   Azure Linux 4 or Ubuntu 26.04 full/core QCOW2 artifacts, or build an
   equivalent GPT/UEFI image. Remove machine identity, credentials, host keys,
   and other instance-specific state before capture.
2. **Sign the boot chain.** Sign the UKI or equivalent boot components with
   the release leaf certificate. Retain that certificate in canonical DER
   form and record its SHA-256 fingerprint. The image version and the booted
   guest must report this exact signer; trusting a certificate without signing
   the accepted UKI with it is insufficient.
3. **Derive the Azure VHD.** `miz azure derive` verifies the source digest and
   GPT, rounds the virtual disk to a MiB boundary, relocates the backup GPT,
   and writes a fixed VHD whose footer adds 512 bytes. Validate the result
   before upload.
4. **Create and upload the managed disk.** Create it as Linux, Hyper-V V2,
   with the matching Azure architecture (`x64` or `Arm64`). Transfer the
   complete fixed VHD to the write SAS and revoke access. Query the disk again
   and independently validate its ID, OS type, generation, and
   `supportedCapabilities.architecture`.
5. **Create the gallery definition.** Create an Azure Compute Gallery in the
   selected region, then create a generalized Linux image definition with
   Hyper-V V2, the matching architecture, and exactly one
   `SecurityType=TrustedLaunchSupported` feature. Query and validate the
   definition independently.
6. **Publish the image version.** Build the REST request with the uploaded disk
   as `storageProfile.osDiskImage.source.id`. Keep
   `MicrosoftUefiCertificateAuthorityTemplate` and append the canonical
   Base64 DER signer to `securityProfile.uefiSettings.additionalSignatures.db`
   as type `x509`. The release tooling verifies the exact certificate
   fingerprint and the create response. Poll the version to `Succeeded` and
   validate the final resource.
7. **Deploy the VM.** Use the gallery image-version resource ID, a compatible
   regional Gen2 VM size, `--security-type TrustedLaunch`,
   `--enable-secure-boot true`, and `--enable-vtpm true`.
8. **Verify the deployed system.** Require both the VM resource and instance
   view to report `TrustedLaunch`, Secure Boot, and vTPM. In the guest, verify
   the exact certificate in UEFI `db`, the accepted UKI signature, Secure Boot
   state, kernel lockdown, provisioning, SSH, and the same state after reboot.

The release acceptance harnesses implement all eight steps. Replace the
uppercase operands below with deployment values. `DISK_UPLOAD_SAS` is the
short-lived write SAS returned by the managed disk `beginGetAccess` operation;
mask it in logs and revoke it immediately after `azcopy` completes.
`VHD_FILE_BYTES` includes the 512-byte fixed-VHD footer.

<!-- BEGIN GENERATED AZURE TRUSTED LAUNCH COMMANDS -->
```console
input_sha256=QCOW2_SHA256
virtual_size=VIRTUAL_SIZE_BYTES
miz azure derive --input-sha256 "$input_sha256" --expected-virtual-size "$virtual_size" image.qcow2 image.vhd
az disk create --resource-group RESOURCE_GROUP --name DISK_NAME --location REGION --sku Standard_LRS --upload-type Upload --upload-size-bytes VHD_FILE_BYTES --os-type Linux --hyper-v-generation V2 --architecture ARCHITECTURE --output json
azcopy copy image.vhd DISK_UPLOAD_SAS --blob-type PageBlob
az disk revoke-access --resource-group RESOURCE_GROUP --name DISK_NAME --output json
az disk show --resource-group RESOURCE_GROUP --name DISK_NAME --output json > managed-disk.json
azurelinux4_release check-managed-disk --disk managed-disk.json --architecture ARCHITECTURE
ubuntu2604_release azure-managed-disk --disk managed-disk.json --architecture ARCHITECTURE
az sig create --resource-group RESOURCE_GROUP --gallery-name GALLERY --location REGION --output json
az sig image-definition create --resource-group RESOURCE_GROUP --gallery-name GALLERY --gallery-image-definition IMAGE_DEFINITION --publisher miz --offer OFFER --sku SKU --os-type Linux --os-state Generalized --hyper-v-generation V2 --architecture ARCHITECTURE --features SecurityType=TrustedLaunchSupported --location REGION --output json
az sig image-definition show --resource-group RESOURCE_GROUP --gallery-name GALLERY --gallery-image-definition IMAGE_DEFINITION --output json > image-definition.json
azurelinux4_release check-image-definition --definition image-definition.json --architecture ARCHITECTURE
ubuntu2604_release azure-image-definition --definition image-definition.json --architecture ARCHITECTURE
azurelinux4_release gallery-request --output gallery-version.json --location REGION --disk-id MANAGED_DISK_ID --certificate signing-certificate.der
ubuntu2604_release azure-gallery-request --output gallery-version.json --location REGION --disk-id MANAGED_DISK_ID --certificate signing-certificate.der
az rest --method put --uri https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION\?api-version=2025-03-03 --body @gallery-version.json --output json > gallery-version-response.json
az rest --method get --uri https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION\?api-version=2025-03-03 --output json > gallery-version-final.json
az vm create --resource-group RESOURCE_GROUP --name VM_NAME --location REGION --size VM_SIZE --image /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION --admin-username ADMIN_USER --authentication-type ssh --ssh-key-values PUBLIC_KEY_FILE --enable-agent true --enable-auto-update false --security-type TrustedLaunch --enable-secure-boot true --enable-vtpm true --public-ip-sku Standard --nsg-rule SSH --output json
az vm show --resource-group RESOURCE_GROUP --name VM_NAME --query securityProfile --output json > vm-security.json
az vm get-instance-view --resource-group RESOURCE_GROUP --name VM_NAME --query securityProfile --output json > instance-security.json
azurelinux4_release check-vm-security --profile vm-security.json --profile instance-security.json
ubuntu2604_release azure-vm-security --vm vm-security.json --instance instance-security.json
```
<!-- END GENERATED AZURE TRUSTED LAUNCH COMMANDS -->

The command block is generated by
`scripts/azure_trusted_launch_examples.sh`. Its Azure commands use the same
argument-array builders as both real-Azure release acceptance harnesses. A
source guard rejects documentation drift from the generated output.

## Custom UEFI keys and Azure constraints

Custom UEFI keys require an Azure Compute Gallery image version and the REST
or ARM image-version security profile; the portal and ordinary image-version
CLI path do not express this contract. The request keeps Microsoft's UEFI
template and adds the release certificate to `db`, rather than replacing the
Microsoft template. Use canonical Base64 of the DER certificate, not PEM text.

The gallery, replicated image version, VM size, and VM must be available in a
compatible region. Trusted Launch support varies by VM size and generation, so
query the selected SKU's capabilities rather than assuming every Gen2 size is
eligible. The release harnesses fail closed on the exact configured location
and size.

Azure VM Image Builder has a separate restriction: a
`TrustedLaunchSupported` source is supported only when the distributed image
is also `TrustedLaunchSupported`. A VM Image Builder template cannot use an
image configured as `TrustedLaunch` as its source. This guide publishes the
generalized disk directly and does not use VM Image Builder.

Microsoft references:

- [Trusted Launch for Azure VMs](https://learn.microsoft.com/azure/virtual-machines/trusted-launch)
- [Secure Boot custom UEFI keys](https://learn.microsoft.com/azure/virtual-machines/trusted-launch-secure-boot-custom-uefi)
- [VM Image Builder overview and Trusted Launch restrictions](https://learn.microsoft.com/azure/virtual-machines/image-builder-overview#confidential-vm-and-trusted-launch-support)
- [Create a Trusted Launch VM in the portal](https://learn.microsoft.com/azure/virtual-machines/trusted-launch-portal)

## Real-Azure acceptance coverage

Only the combinations below are claimed as Trusted Launch compatible. Each
row boots the exact digest-bound release candidate in a protected
same-architecture Azure acceptance job and verifies its gallery settings, VM
profiles, signer, Secure Boot, vTPM, provisioning, and reboot behavior.

<!-- BEGIN TRUSTED LAUNCH COVERAGE -->
| Family | Architecture | Flavor | Release candidate |
| --- | --- | --- | --- |
| Azure Linux 4 | `x86_64` | `full` | `AzureLinux-4.0-x86_64.qcow2` |
| Azure Linux 4 | `aarch64` | `full` | `AzureLinux-4.0-aarch64.qcow2` |
| Azure Linux 4 | `x86_64` | `core` | `AzureLinux-4.0-x86_64.core.qcow2` |
| Azure Linux 4 | `aarch64` | `core` | `AzureLinux-4.0-aarch64.core.qcow2` |
| Ubuntu 26.04 | `x86_64` | `full` | `Ubuntu-26.04-x86_64.qcow2` |
| Ubuntu 26.04 | `aarch64` | `full` | `Ubuntu-26.04-aarch64.qcow2` |
| Ubuntu 26.04 | `x86_64` | `core` | `Ubuntu-26.04-x86_64.core.qcow2` |
| Ubuntu 26.04 | `aarch64` | `core` | `Ubuntu-26.04-aarch64.core.qcow2` |
<!-- END TRUSTED LAUNCH COVERAGE -->

Ubuntu's AArch64 bare-metal flavor is intentionally excluded. It has a
different physical-machine contract and no real-Azure acceptance row; its
existence does not imply Trusted Launch support.
