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

The release-qualified Azure deployment profile is `westeurope` on
`Standard_DC2as_v5`. That exact pair has passed the complete live acceptance
path. Azure SKU availability and restrictions are subscription-specific, so
the harness still queries `az vm list-skus` and rejects a configured SKU unless
Azure reports AMD SEV-SNP Confidential Compute support with no blocking
restriction. Other regions and SKUs are not part of the miz support boundary
until the complete acceptance path has qualified them.

The source and derived fixed VHD must be strictly smaller than 32 GiB. The
acceptance path uploads that exact VHD to a managed disk, creates a generalized
Gen2 managed image bound to the disk, and uses the managed image as the
`ConfidentialVmSupported` gallery-version source. Azure does not accept the
intermediate managed disk directly for this image-definition security type.

The deployed VM must independently request:

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
az image create --resource-group RESOURCE_GROUP --name MANAGED_IMAGE --location REGION --source MANAGED_DISK_ID --os-type Linux --hyper-v-generation V2 --output json
az image show --resource-group RESOURCE_GROUP --name MANAGED_IMAGE --output json > managed-image.json
az vm list-skus --location REGION --resource-type virtualMachines --size VM_SIZE --all --output json > confidential-sku.json
az sig create --resource-group RESOURCE_GROUP --gallery-name GALLERY --location REGION --output json
az sig image-definition create --resource-group RESOURCE_GROUP --gallery-name GALLERY --gallery-image-definition IMAGE_DEFINITION --publisher miz --offer ubuntu2404 --sku confidential-x64 --os-type Linux --os-state Generalized --hyper-v-generation V2 --architecture x64 --features SecurityType=ConfidentialVMSupported --location REGION --output json
az sig image-definition show --resource-group RESOURCE_GROUP --gallery-name GALLERY --gallery-image-definition IMAGE_DEFINITION --output json > image-definition.json
ubuntu2404_confidential_release gallery-request --output gallery-version.json --location REGION --source-id MANAGED_IMAGE_ID
az rest --method put --uri https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION\?api-version=2025-03-03 --body @gallery-version.json --output json > gallery-version-response.json
az rest --method get --uri https://management.azure.com/subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION\?api-version=2025-03-03 --output json > gallery-version-final.json
az vm create --resource-group RESOURCE_GROUP --name VM_NAME --location REGION --size VM_SIZE --image /subscriptions/SUBSCRIPTION_ID/resourceGroups/RESOURCE_GROUP/providers/Microsoft.Compute/galleries/GALLERY/images/IMAGE_DEFINITION/versions/IMAGE_VERSION --admin-username ADMIN_USER --authentication-type ssh --ssh-key-values PUBLIC_KEY_FILE --enable-agent true --enable-auto-update false --security-type ConfidentialVM --os-disk-security-encryption-type VMGuestStateOnly --enable-secure-boot true --enable-vtpm true --public-ip-sku Standard --nsg-rule SSH --output json
az vm show --resource-group RESOURCE_GROUP --name VM_NAME --query \{id:id\,vmId:vmId\,securityProfile:securityProfile\,osDiskSecurityProfile:storageProfile.osDisk.managedDisk.securityProfile\,imageReference:storageProfile.imageReference\} --output json > vm-resource.json
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

## Protected release workflow

`.github/workflows/ubuntu2404-confidential-release.yml` is the only publication
path for this target. It can be dispatched manually only on `main`. The
`prepare` job resolves the current remote `main` commit and requires the fixed
release tag to resolve to that same commit, including through an annotated
tag. Every checkout, candidate artifact name, acceptance artifact name, and
published result is then bound to that immutable commit.

Create a GitHub environment named `ubuntu2404-confidential-release`, restrict
it to the `main` branch, and configure:

| Kind | Name | Required value |
|---|---|---|
| Secret | `AZURE_CLIENT_ID` | Entra application client ID |
| Secret | `AZURE_TENANT_ID` | Entra tenant ID |
| Secret | `AZURE_SUBSCRIPTION_ID` | Acceptance subscription ID |
| Variable | `AZURE_LOCATION` | `westeurope` |
| Variable | `AZURE_VM_SIZE` | `Standard_DC2as_v5` |

The Entra application needs a federated credential with subject
`repo:cataggar/miz:environment:ubuntu2404-confidential-release`. Grant only
the Azure permissions needed to create and delete the temporary resource group
and its compute, disk, network, managed-image, and gallery resources. The
workflow does not use a stored Azure client secret.

Before dispatch, create `Ubuntu-24.04-confidential-20260907` at the exact
current `main` commit. The workflow refuses a missing tag, a tag on another
commit, a pull-request ref, or a dispatch against another repository. Dispatch
from the Actions page or with:

```console
gh workflow run ubuntu2404-confidential-release.yml --ref main
```

The release graph is fail-closed:

1. The build job authenticates Canonical's pinned publication, builds the
   standalone QCOW2, emits its provenance JSON, re-hashes the result, and
   uploads those exact two files without artifact recompression.
2. The protected acceptance job downloads that named artifact, validates the
   configured region and SKU, logs in with environment-scoped OIDC, derives
   and uploads the fixed VHD, deploys the exact gallery version, and runs guest
   and attestation checks. An `always()` path refreshes the OIDC credential and
   deletes only the resource group whose name and ownership tags match the
   workflow run and attempt.
3. The publication job runs only after build and acceptance succeed. It
   downloads the exact candidate, provenance, and acceptance artifacts,
   revalidates their source commit, run identity, hashes, sizes, Azure profile,
   and attested security contract, then publishes a draft and downloads every
   asset for a final hash comparison before making the release public.

The release contains exactly:

- `Ubuntu-24.04-x86_64.confidential.qcow2`;
- `Ubuntu-24.04-x86_64.confidential.qcow2.provenance.json`; and
- `Ubuntu-24.04-x86_64.confidential.azure-acceptance.json`.

The acceptance JSON records the QCOW2 and fixed-VHD hashes, Azure resource
identities, MAA token and nonce hashes, VM identity, selected location and SKU,
and the enforced SEV-SNP, Secure Boot, vTPM, compliance, and non-debug state.
The temporary Azure resources are deleted; the result is the durable evidence
that those exact candidate bytes passed the protected deployment.

## Attestation and operational limitations

The guest attestation client and `azguestattestation1` package are pinned by
URL and SHA-256. The harness retrieves a fresh nonce-bound token from Microsoft
Azure Attestation, retrieves the endpoint's OpenID metadata and JWKS over
HTTPS, verifies the RS256 signature, and rejects identity, time, nonce,
compliance, migration, VMPL, debugger, Secure Boot, or vTPM mismatches. A
decoded token without successful JWKS verification is never accepted.

The initial workflow has these intentional limitations:

- Ubuntu 24.04 LTS x86_64 and AMD SEV-SNP only;
- `ConfidentialVMSupported` source images only, not captured
  `ConfidentialVM` images containing VM Guest State;
- `VMGuestStateOnly`, not `DiskWithVMGuestState` or customer-managed
  confidential OS-disk keys;
- Canonical's stock Microsoft/Canonical Secure Boot trust, with no custom UEFI
  `db` keys;
- one qualified Azure profile:
  `westeurope` / `Standard_DC2as_v5`; and
- direct SSH connectivity from the GitHub-hosted acceptance runner to the
  temporary VM, plus outbound HTTPS access to Canonical, Microsoft package,
  Azure management, GitHub raw-content, and MAA endpoints.
