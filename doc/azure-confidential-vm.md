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

## Protected ConfidentialVM capture workflow

`.github/workflows/ubuntu2404-confidential-capture.yml` promotes one already
accepted three-asset source release into a full ConfidentialVM gallery image.
It is manual-dispatch only, accepts only `cataggar/miz` `main`, and serializes
every target version through the stable, non-canceling concurrency group
`ubuntu2404-confidential-cvm-target-version`. Before dispatch, an operator must
create the deterministically derived provenance tag
`Ubuntu-24.04-confidential-cvm-MAJOR.MINOR.PATCH` at the exact current `main`
tool commit. A release must not already exist for that tag.

Create the GitHub environment `ubuntu2404-confidential-capture`, restrict it to
the `main` branch, require at least one designated release reviewer, and
disable self-review so the dispatcher cannot approve the deployment.
Configure:

| Kind | Name | Meaning |
|---|---|---|
| Secret | `AZURE_CAPTURE_CLIENT_ID` | narrow scratch/capture Entra application |
| Secret | `AZURE_PUBLICATION_CLIENT_ID` | distinct exclusive version publisher |
| Secret | `AZURE_TENANT_ID` | common Entra tenant |
| Secret | `AZURE_SUBSCRIPTION_ID` | common capture/target subscription |
| Variable | `AZURE_LOCATION` | previously live-qualified region |
| Variable | `AZURE_VM_SIZE` | previously live-qualified AMD SEV-SNP SKU |
| Variable | `TARGET_RESOURCE_GROUP` | pre-provisioned durable resource group |
| Variable | `TARGET_GALLERY` | pre-provisioned private gallery |
| Variable | `TARGET_IMAGE_DEFINITION` | pre-provisioned full ConfidentialVM definition |
| Variable | `TARGET_OWNER_TAG` | durable `miz-owner` tag on every target parent |
| Secret | `SCRATCH_RESERVATION_TAG` | owner-only reservation value on the empty pre-provisioned scratch RG |
| Variable | `CAPTURE_TARGET_READ_SCOPE` | exact preexisting target resource-group ID |
| Variable | `PUBLICATION_SNAPSHOT_READ_SCOPE` | exact pre-provisioned scratch resource-group ID |
| Variable | `PUBLICATION_VERSION_WRITE_SCOPE` | exact preexisting target image-definition resource ID |

Both applications need a federated credential with subject
`repo:cataggar/miz:environment:ubuntu2404-confidential-capture`. They must not
share a client ID. The workflow logs them into separate owner-only absolute
Azure CLI configuration directories, verifies tenant, subscription, principal
type, and signed-in client ID, and obtains the publisher token only after the
capture state is exactly prepared. It refreshes the capture token immediately
before publication validation and again on the unconditional cleanup path.
No access token, OIDC request token, JWT, SAS, SSH key, Azure CLI configuration,
or raw attestation bundle is serialized into recovery state or uploaded.

Enable **immutable releases** in the repository settings before creating the
accepted source release or dispatching capture. The workflow queries
`GET /repos/cataggar/miz/immutable-releases` with the pinned official GitHub
REST API version before any Azure login or mutation and requires
`enabled=true`; it never changes the repository setting. The accepted source
release itself must report `immutable=true`, be published, and be neither a
draft nor a prerelease. Its exact tag must resolve to the recorded source
commit. A repository or token for which the setting or release immutability
cannot be queried is not eligible for capture.

Before dispatch, provision a unique empty scratch resource group named
`miz-u2404-cvm-capture-SUFFIX` in the configured subscription and region.
Give it exactly the tags
`miz-owner=ubuntu2404-confidential-capture`,
`miz-repository=cataggar/miz`, and
`miz-reservation=SCRATCH_RESERVATION_TAG`. Pass its name as the required
`scratch_resource_group` dispatch input. Both role assignments on this group
therefore exist before dispatch. The harness refuses a missing, nonempty,
mismatched, or already claimed group, atomically replaces the reservation tags
with the immutable origin tags, and later deletes only that exact claimed
group.

Use custom roles with no wildcard control-plane permissions. Assign the
capture scratch-lifecycle role at that exact pre-provisioned scratch
resource-group scope. Assign a separate custom role containing only
`Microsoft.Compute/skus/read` at subscription scope for the configured
region/SKU check. The scratch-lifecycle role's complete action list is:

- `Microsoft.Resources/subscriptions/resourceGroups/read`,
  `Microsoft.Resources/subscriptions/resourceGroups/write`, and
  `Microsoft.Resources/subscriptions/resourceGroups/delete`;
- `Microsoft.Resources/subscriptions/resourceGroups/resources/read`,
  `Microsoft.Resources/tags/write`,
  `Microsoft.Compute/disks/read`,
  `Microsoft.Compute/disks/write`,
  `Microsoft.Compute/disks/beginGetAccess/action`,
  `Microsoft.Compute/disks/endGetAccess/action`,
  `Microsoft.Compute/images/read`,
  `Microsoft.Compute/images/write`,
  `Microsoft.Compute/snapshots/read`,
  `Microsoft.Compute/snapshots/write`,
  `Microsoft.Compute/virtualMachines/read`,
  `Microsoft.Compute/virtualMachines/write`,
  `Microsoft.Compute/virtualMachines/start/action`,
  `Microsoft.Compute/virtualMachines/deallocate/action`,
  `Microsoft.Compute/virtualMachines/generalize/action`,
  `Microsoft.Compute/virtualMachines/instanceView/read`,
  `Microsoft.Compute/virtualMachines/extensions/read`,
  `Microsoft.Compute/virtualMachines/extensions/write`,
  `Microsoft.Compute/galleries/read`,
  `Microsoft.Compute/galleries/write`,
  `Microsoft.Compute/galleries/images/read`,
  `Microsoft.Compute/galleries/images/write`,
  `Microsoft.Compute/galleries/images/versions/read`,
  `Microsoft.Compute/galleries/images/versions/write`,
  `Microsoft.Network/virtualNetworks/read`,
  `Microsoft.Network/virtualNetworks/write`,
  `Microsoft.Network/virtualNetworks/subnets/read`,
  `Microsoft.Network/virtualNetworks/subnets/write`,
  `Microsoft.Network/virtualNetworks/subnets/join/action`,
  `Microsoft.Network/networkSecurityGroups/read`,
  `Microsoft.Network/networkSecurityGroups/write`,
  `Microsoft.Network/networkSecurityGroups/join/action`,
  `Microsoft.Network/networkSecurityGroups/securityRules/read`,
  `Microsoft.Network/networkSecurityGroups/securityRules/write`,
  `Microsoft.Network/publicIPAddresses/read`,
  `Microsoft.Network/publicIPAddresses/write`,
  `Microsoft.Network/publicIPAddresses/join/action`,
  `Microsoft.Network/networkInterfaces/read`,
  `Microsoft.Network/networkInterfaces/write`,
  `Microsoft.Network/networkInterfaces/join/action`; and
- in a separate read-only custom role assigned at the preexisting durable
  target resource-group scope,
  `Microsoft.Resources/subscriptions/resourceGroups/read`,
  `Microsoft.Compute/galleries/read`,
  `Microsoft.Compute/galleries/images/read`, and
  `Microsoft.Compute/galleries/images/versions/read`. These reads cover target
  parent validation, exact target-version validation, and the final deployment
  from that version. The capture principal has no target version delete and no
  target resource-group, gallery, image-definition, or version write.

The exclusive publisher requires **two separate, pre-provisionable role
assignments**:

1. Assign a custom role containing only
   `Microsoft.Compute/snapshots/read` at the pre-provisioned scratch
   resource-group ID
   `/subscriptions/SUBSCRIPTION_ID/resourceGroups/SCRATCH_RESOURCE_GROUP`.
   The role has no other action and the harness accepts only the exact
   origin-tagged snapshot ID in that group.
2. Assign a second custom role at the **preexisting image-definition resource
   ID**
   `/subscriptions/SUBSCRIPTION_ID/resourceGroups/TARGET_RESOURCE_GROUP/providers/Microsoft.Compute/galleries/TARGET_GALLERY/images/TARGET_IMAGE_DEFINITION`.
   Its complete action list is
   `Microsoft.Compute/galleries/read`,
   `Microsoft.Compute/galleries/images/read`,
   `Microsoft.Compute/galleries/images/versions/read`, and
   `Microsoft.Compute/galleries/images/versions/write`.

The publisher has no version delete permission and no resource-group, gallery,
or image-definition write/delete permission. In particular, do not attempt to
assign its writer role at
`.../images/TARGET_IMAGE_DEFINITION/versions/MAJOR.MINOR.PATCH`: that version
scope does not exist before dispatch. The workflow never creates role
definitions or assignments. The exclusive version writer plus the stable,
non-canceling concurrency group is the check-to-PUT race boundary. Azure RBAC
and a malicious subscription Owner are outside what the workflow or harness
can prove, so operators must independently review effective assignments before
dispatch.

The durable target resource group, private gallery, and image definition must
already exist in the same subscription and region as the accepted source. They
carry exact `miz-owner` and `miz-repository=cataggar/miz` tags. The definition
is Ubuntu 24.04 x64 AMD SEV-SNP, generalized Gen2, with
`SecurityType=ConfidentialVM`; it is never created, updated, or deleted by the
workflow. Azure creates the captured VM Guest State. The resulting full image
creates Confidential VMs only: deployed VMs use `VMGuestStateOnly`, while the
gallery version records `EncryptedVMGuestStateOnlyWithPmk`. Replication is
`Full`, and source recreation, capture, snapshot, target, and final acceptance
remain in the same region and subscription.

The source release must be immutable, published, non-draft, non-prerelease, and
contain exactly the QCOW2, build provenance JSON, and Azure acceptance JSON
documented above. The workflow downloads those three assets by exact asset ID,
validates their hashes and shape with the accepted-source tooling, and derives
the source commit, source run/attempt, location, and VM size from the validated
release evidence. It never adds an asset to that source release.

The capture harness has explicit `prepare`, `inspect-recovery`, `publish`,
`recover`, `finalize`, and `cleanup` stages. Normal dispatch fixes
`origin_run_id` and `origin_run_attempt` to the initial run. Manual recovery
requires both original values or neither; current retry identity never replaces
the origin used in resource names, tags, artifact names, or durable provenance.
Before target PUT, the workflow uploads only owner-readable sanitized
`capture-state.json` and `recovery-intent.json`, then a separate sanitized PUT
dispatch marker. All three artifacts are named from origin run, origin attempt,
and target version and are retained for 90 days. They contain identities,
resource IDs, state, and hashes only: no SAS, access token, OIDC token, JWT,
nonce, key, Azure CLI configuration, OpenID document, JWKS, or raw attestation
bundle.

Once PUT is dispatched, scratch deletion is prohibited until the exact
sanitized `capture-result.json` has been uploaded for 90 days and `finalize`
has durably acknowledged its hash. A failed result upload, result
acknowledgement, or post-PUT cleanup therefore leaves the origin-tagged scratch
group visibly quarantined. An unconditional cleanup may delete only a
pre-PUT group or a post-upload durable group.

Recovery downloads the exact origin artifact, verifies the GitHub artifact
digest, owner-only permissions, exact schema and full source/tool/target/origin
identity, then freshly retrieves Azure and MAA evidence from retained scratch.
If the exact target version exists, its tags, snapshot source, security
contract, region, replication state, and origin must all match before recovery
continues final deployment and attestation; recovery never issues a second
PUT. If the version is absent and no durable dispatch marker exists, one new
dispatch marker may be uploaded and publication may proceed once. An absent
version after a durable dispatch marker, or any mismatched/missing artifact,
digest, state, tag, or resource, is ambiguous and fails closed.

If the origin result artifact is already durable—for example, only scratch
cleanup or provenance publication failed—the recovery dispatch downloads and
strictly verifies that exact origin result and proceeds directly to provenance
publication without another Azure login, target PUT, deployment, or
attestation run. This preserves the original result digest and allows an exact
owned draft release to resume.

Use explicit manual recovery rather than rerunning with a new origin:

```console
gh workflow run ubuntu2404-confidential-capture.yml --ref main \
  -f source_release_tag=Ubuntu-24.04-confidential-YYYYMMDD \
  -f target_gallery_version=MAJOR.MINOR.PATCH \
  -f scratch_resource_group=miz-u2404-cvm-capture-SUFFIX \
  -f origin_run_id=ORIGINAL_RUN_ID \
  -f origin_run_attempt=ORIGINAL_RUN_ATTEMPT
```

Only the sanitized `capture-result.json` crosses into provenance publication.
The publication job
re-hashes it, validates protected source/tool/run/target identities with
`verify-capture-publication`, uploads one deterministically named provenance
JSON to a controlled draft GitHub release, downloads and revalidates that exact
asset, then publishes the release. An exact owned draft may be resumed only
when tag, tool commit, title, origin identity, recovery intent digest, and any
staged asset all match; a foreign or mismatched draft is refused, and a
published release is never overwritten. After publication the workflow
requires GitHub to report the release immutable with the exact tag, title, and
commit and exactly one asset with the exact name and SHA-256. Full raw Azure
and MAA verification has already succeeded inside the protected Azure job; the
durable verifier does not claim to reauthenticate discarded transport
evidence.

This workflow is not a substitute for qualification. A new region, SKU,
definition contract, Azure API behavior, role design, or harness change
requires a supervised live Azure qualification run before production use.
Repository CI and this implementation intentionally perform no live Azure
execution.

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
