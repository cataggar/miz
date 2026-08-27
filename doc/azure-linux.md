# Azure Linux images

Azure Linux release images are available in full and core variants for both x86_64 and AArch64. Choose full for a conventional, general-purpose Azure Linux VM; choose core for a smaller appliance-style guest with a deliberately limited runtime.

## Full and core image comparison

| Concern | Full image | Core image |
|---|---|---|
| Intended use | General-purpose Azure Linux VM | Minimal appliance-style Azure Linux VM |
| PID 1 | systemd | `mizinit` |
| Provisioning | cloud-init and WALinuxAgent | `azagent` supervised by `mizinit` |
| SSH | `sshd.service` | OpenSSH directly supervised by `mizinit` |
| Azure extensions | Standard WALinuxAgent extension support | No general WALinuxAgent extension stack |
| Default virtual size | 5 GiB | 1184 MiB |
| Released persistence | Normal writable system | `mizinit.mode=persistent` for provisioned identity and keys |
| Asset naming | Unsuffixed `*.qcow2` | `*.core.qcow2` |

Both flavors are Gen2 direct-UKI images with x86_64 and AArch64 variants. Release candidates use Azure Artifact Signing and are validated with Azure Trusted Launch, Secure Boot, and vTPM. Neither flavor contains baked credentials; supply a public SSH key during provisioning.

`mizinit` supports an immutable default for other appliance uses, but the released Azure core images use `mizinit.mode=persistent` so the provisioned account, SSH keys, host keys, and agent state survive reboot.

Core images format Azure's temporary resource disk as XFS. Its dynamic inode allocation is a better fit for build workspaces and package caches containing many small files than a fixed-inode ext4 filesystem. Managed data disks remain mount-only and are never reformatted by `azagent`.

See [QEMU](qemu.md) for local launch and provisioning behavior.

## Generalized Azure Linux 4 core and full QCOW2

Host-side image builders can reuse `miz.artifact_pipeline` for bounded SHA-256-verified acquisition and transactional publication. Download callbacks receive only a pipeline-owned writer rather than a staging path, `decompressXz` requires an explicit XZ Utils executable plus compressed-input digest, memory limit, and output-size limit, and Linux-only `finalizeQcow2` converts a digest-pinned raw or standalone QCOW2 source to a validated standalone QCOW2. `miz.azure.deriveFixedVhd` converts a digest-pinned standalone GPT QCOW2 into a 1 MiB-aligned fixed VHD through a descriptor-pinned atomic stage, strictly cross-validates the primary and backup GPT copies, preserves the raw partition array and every partition extent, relocates the backup GPT, and revalidates the VHD and both GPT copies before publication. All operations preserve an existing destination until validation succeeds.

`scripts/build_generalized_azurelinux4.zig` (run via
`zig build -Dazurelinux-arch=x86_64|aarch64 -Dazurelinux-flavor=core|full generalized-azurelinux4`)
builds the architecture-matched **core** or **full** recipe. Core remains the
compatible default and is built from
`mcr.microsoft.com/azurelinux-beta/base/core:4.0`: OpenSSH, static
`mizinit`/`azagent`, and no host identity. The build graph compiles those two
guest executables only for the core flavor; the CLI, builder, and preload
library remain native to the build host.

Full materializes a fresh rootfs with the official Azure Linux
[`base/images/vm-base/vm-base.kiwi`](https://github.com/microsoft/azurelinux/blob/5b41bff6ebaf7e8fc78637b564efee23b66e7d67/base/images/vm-base/vm-base.kiwi)
`vm-base` package profile, pinned to commit
`5b41bff6ebaf7e8fc78637b564efee23b66e7d67` and blob
`8c870852e711273275c83f0b94ecd914ff709af8`. Its package manifest is encoded
in the builder, so KIWI is not a build dependency. Full uses systemd PID 1,
cloud-init plus WALinuxAgent 2.15 (`Provisioning.Agent=auto`,
`ResourceDisk.Format=n`), key-only OpenSSH, and no custom `mizinit` or
`azagent`. It uses the profile's explicit 5 GiB default and rejects a root
partition that cannot retain 1 GiB free. Core retains its 1184 MiB default.
Full configures systemd-networkd DHCP for physical Ethernet devices and labels
the completed installroot with its targeted SELinux policy before OCI and ext4
assembly. Final image validation rejects a missing or unusable systemd SELinux
label or root-inode label, so enforcing mode cannot freeze PID 1 on an
unlabelled root filesystem.

Both flavors use `--skip-iso-rootfs`: the ISO supplies only the
architecture-matched kernel, initramfs, and UEFI assets. Full never publishes
the ISO LiveOS/Anaconda rootfs. A pinned core OCI is used only to extract and
checksum/fingerprint-validate the RPM signing key before its filesystem is
discarded. Full verifies ISO kernel/initramfs releases against installed
kernel-core/kernel-modules rather than emitting an incoherent userspace/module
mix. Its kernel and kernel-modules package requests are pinned to the release
inside the checksum-pinned ISO's nested `LiveOS` rootfs, and the builder mounts
that nested rootfs to verify the exact release before image assembly.

`miz build-iso` honors the same `--skip-iso-rootfs` publication policy, in the
optical form. A generated LiveOS ISO always *replaces* the source ISO's LiveOS
payload -- the original live/Anaconda `LiveOS/squashfs.img` is never published;
what ships is the regenerated SquashFS wrapping the customized ext4
`rootfs.img`. With `--skip-iso-rootfs`, that customized root tree is the
container plus only the boot-critical assets carried over from the ISO/squashfs
(kernel, initramfs, EFI binaries, `/lib/modules/<version>`), exactly as the
QCOW2 recipe assembles its root partition; the live/installer userspace is left
out of the nested `rootfs.img` rather than merged into it. Without the flag, the
full merged distro rootfs becomes the nested `rootfs.img`. Either way the
source ISO's boot loaders and boot configuration are retained verbatim so the
regenerated media still boots, and the El Torito catalog is recreated
explicitly -- the ISO's *directory tree and boot catalog* are regenerated
filesystem contents, not preserved byte regions of the original image.

`miz recustomize-iso` honors the same `--skip-iso-rootfs` publication policy
and the same payload replacement, but treats the source Azure Linux ISO as
authoritative: it preserves the source directory tree, node
metadata/timestamps, primary volume metadata, and El Torito catalog exactly
(mapping boot entries back to their source paths, so you never re-specify a
boot image), replacing only the `LiveOS` payload. If the source ISO carries any
feature the native writer cannot losslessly reproduce it refuses with a precise
diagnostic rather than shipping a lossy image. PXE is out of scope.

The recipe creates bounded flavor-specific OCI layers, validates rootfs
identity cleanup, GPT/root GUIDs, fallback EFI, UKI PE sections/cmdline,
partition geometry, free space, and OCI architecture/provenance before
transactional QCOW2 publication. The x86_64 image uses `linuxx64.efi.stub`,
`EFI/BOOT/BOOTX64.EFI`, and `ttyS0`; AArch64 uses `linuxaa64.efi.stub`,
`EFI/BOOT/BOOTAA64.EFI`, and `ttyAMA0`. Core UKIs retain the `mizinit`
contract; full UKIs contain only the root PARTUUID and architecture serial
console. OCI ingestion preserves USTAR uid/gid plus bounded relevant PAX
`user.*`, `trusted.*`, `security.*`, and `system.*` xattrs, including file
capabilities; absent tar metadata remains root:root with no xattrs.

The OpenSSH/sudo package transaction is also reproducibly locked: each
descriptor pins the Azure Linux base repository's `repomd.xml` SHA-256. The
builder verifies the live metadata, populates an isolated per-build DNF
cache/persist directory, verifies DNF's cached `repomd.xml`, and performs the
transaction with metadata expiration disabled globally and for
`azurelinux-base`. That prevents metadata refresh while allowing DNF to
download uncached RPM payloads. Payload downloads use a one-byte-per-second
minimum rate, a five-minute timeout, and twenty retries so a slow Microsoft
package endpoint does not discard an otherwise valid pinned transaction. DNF
then verifies RPM signatures and package payload checksums from that pinned
metadata. The cached and live metadata are verified again after the
transaction; a repository change fails the build. The newly installed, sorted
NEVRA closure is emitted and recorded under the builder work directory's
`provenance/` directory. The typed v3 API generalizes this: `.packages.cache`
declares the cache directory as a request input, `.packages.lock` declares the
NEVRA closure, and `provenance.execution.preserved` records both. See
`doc/library-api.md`.

The image boots directly through `UEFI -> EFI/BOOT/BOOTX64.EFI` (x86_64) or
`EFI/BOOT/BOOTAA64.EFI` (AArch64) `-> UKI -> kernel/initramfs -> mizinit`; it
does not require shim, GRUB, or BLS configuration. Optional host-side signing runs after the unpublished QCOW2 is assembled and before final zstd compression. It verifies the configured certificate's canonical-DER SHA-256, signs every named `EFI/Linux/*.efi`, rewrites the fallback copy with identical signed bytes, verifies each Authenticode signature and PE payload, and re-verifies the exact UKIs extracted from the finalized QCOW2. Signing keys and provider diagnostics never enter the image, build log, artifact staging, or provenance.

```console
# Defaults: AzureLinux-4.0-x86_64.core.qcow2 and .scratch/azurelinux4-core-x86_64
zig build -Dazurelinux-arch=x86_64 -Dazurelinux-flavor=core generalized-azurelinux4 --

# Defaults: AzureLinux-4.0-aarch64.core.qcow2 and .scratch/azurelinux4-core-aarch64
zig build -Dazurelinux-arch=aarch64 -Dazurelinux-flavor=core generalized-azurelinux4 --

# Defaults: AzureLinux-4.0-x86_64.qcow2 and .scratch/azurelinux4-full-x86_64
zig build -Dazurelinux-arch=x86_64 -Dazurelinux-flavor=full generalized-azurelinux4 --

# Defaults: AzureLinux-4.0-aarch64.qcow2 and .scratch/azurelinux4-full-aarch64
zig build -Dazurelinux-arch=aarch64 -Dazurelinux-flavor=full generalized-azurelinux4 --

# Local development signing only
zig build -Dazurelinux-arch=x86_64 -Dazurelinux-flavor=core generalized-azurelinux4 -- \
  --uki-signing-certificate test.crt \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key

# Production Azure Artifact Signing
zig build install-miz
export MIZ_AZURE_TENANT_ID=<Microsoft-Entra-tenant-UUID>
export MIZ_AZURE_CLIENT_ID=<federated-application-client-UUID>
export MIZ_ARTIFACT_SIGNING_ENDPOINT=https://wus.codesigning.azure.net/
export MIZ_ARTIFACT_SIGNING_ACCOUNT=cataggar
export MIZ_ARTIFACT_SIGNING_PROFILE=miz-uki
zig build -Dazurelinux-arch=x86_64 -Dazurelinux-flavor=core generalized-azurelinux4 -- \
  --uki-signing-certificate miz-uki-current-leaf.crt \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-sign-command "$PWD/zig-out/bin/miz" \
  --uki-sign-command-arg sign
```

`miz sign` is the built-in production provider adapter. It validates the unsigned UKI and exact signing-leaf fingerprint, constructs the Authenticode signed attributes locally, obtains a GitHub OIDC token for `api://AzureADTokenExchange`, exchanges it with Microsoft Entra for the `https://codesigning.azure.net/.default` scope, and submits only the SHA-256 digest to Artifact Signing's stable `2024-06-15` `RS256` API. It polls the returned operation without following redirects, decodes the operation's nested Base64 PKCS#7 certificate bundle, requires its encapsulated signing leaf to exactly match the configured certificate, embeds the complete deduplicated chain in Authenticode CMS, and atomically publishes the signed UKI and non-secret provider metadata. `miz sign certificate <absolute-output.pem>` fetches the profile's current leaf from the authenticated certificate-bundle endpoint. The private key never leaves Azure. The external-provider protocol supplies `MIZ_UKI_UNSIGNED`, `MIZ_UKI_SIGNED`, `MIZ_UKI_CERTIFICATE`, `MIZ_UKI_ARCHITECTURE`, `MIZ_UKI_FLAVOR`, `MIZ_UKI_UNSIGNED_SHA256`, `MIZ_UKI_CERTIFICATE_SHA256`, and `MIZ_UKI_SIGNING_METADATA`. The protocol itself, the scratch handling, and the check that what came back is a signature over the bytes that went out are `miz.uki_signing`'s, so a release built by this script and an image built through `boot_security.signing` are signed by the same code; what stays in the release builder is what a release knows and a library does not -- `MIZ_UKI_FLAVOR`, the native Authenticode signature and canonical-DER certificate-fingerprint cross-checks, the `--uki-sign-key` path for a local key, and which signing service a release may be signed by. Certificate normalization, fingerprinting, local-key signing, and signature verification are native, so the release builder itself installs and invokes neither `openssl` nor `sbverify`.

For an existing release, use
[`miz uki certificate`](uki-certificate.md) to recover the leaf referenced
by that image's fallback and named UKIs. Do not use `miz sign certificate`
for this purpose: Artifact Signing leaves rotate, so the profile's current
leaf may differ from the one embedded in an older release. Pin the release
image digest and/or expected certificate fingerprint before enrollment.

Create a dedicated Private Trust certificate profile named `miz-uki` in the existing `cataggar` Artifact Signing account. Configure the Entra federated credential for audience `api://AzureADTokenExchange`, issuer `https://token.actions.githubusercontent.com`, and subject `repo:cataggar/miz:environment:azurelinux4-signing`, then grant `Artifact Signing Certificate Profile Signer` at the `miz-uki` profile scope. The observed Private Trust chain terminates at a shared Microsoft Enterprise identity hierarchy, and UEFI cannot restrict trust with Artifact Signing's subscriber-unique EKU. Secure Boot therefore enrolls the exact short-lived signing leaf for each release, never the broad AOC intermediate or Microsoft root. The workflow fetches the current leaf immediately before signing and fails if the operation returns another leaf; release validation also fails if the leaf or provider identity changes across candidates. Artifact Signing leaves rotate daily and are valid for about three days. The raw digest API does not add an RFC 3161 timestamp; firmware and `sbverify` do not enforce signing-certificate wall-clock validity, but general long-term Authenticode validation requires a separately implemented timestamp policy.

The builder requires Zig 0.16, `curl`, `dnf`, GNU tar, `qemu-img`, and
passwordless or interactive `sudo`. On a host that differs from the selected
guest architecture, the matching enabled binfmt registration plus
`qemu-x86_64-static` or `qemu-aarch64-static` is required so RPM scriptlets
can run inside the target rootfs; the temporary interpreter is removed before
the OCI layout is produced. `--iso` accepts an already-downloaded ISO, but it
is still validated against the architecture's pinned official SHA-256. Use
`--size` overrides the flavor default (1184 MiB core, 5 GiB full). The fixed
512 MiB ESP is retained when the total size is overridden, with the root
partition consuming the remaining aligned capacity; full still requires 1 GiB
root free space. The build system automatically passes the selected
architecture, flavor, native miz, and preload library, plus the guest
mizinit/azagent binaries for core only; no separate `zig build` invocation is
needed.

### Finalized-image native QEMU acceptance

`test-azurelinux4-acceptance` is the reusable, opt-in release-candidate
acceptance step. It receives the completed artifact through
`MIZ_AZURELINUX4_IMAGE` and refuses a mismatched basename, so it never tests
an intermediate builder file. The selected build options map exactly to these
four candidates:

```text
x86_64 full:    AzureLinux-4.0-x86_64.qcow2
aarch64 full:   AzureLinux-4.0-aarch64.qcow2
x86_64 core:    AzureLinux-4.0-x86_64.core.qcow2
aarch64 core:   AzureLinux-4.0-aarch64.core.qcow2
```

For example, run the native x86_64 core entry as:

```text
MIZ_AZURELINUX4_IMAGE=/path/to/AzureLinux-4.0-x86_64.core.qcow2 \
MIZ_AZURELINUX4_SIGNING_CERTIFICATE=/path/to/release.crt \
MIZ_AZURELINUX4_SIGNING_CERTIFICATE_SHA256=<canonical-DER-SHA-256> \
MIZ_AZURELINUX4_UKI_SHA256=<fallback-UKI-SHA-256> \
MIZ_AZURELINUX4_ACCEPTANCE_RESULT=/tmp/local-secure-boot-result.json \
zig build -Dazurelinux-arch=x86_64 -Dazurelinux-flavor=core \
  test-azurelinux4-acceptance
```

When `MIZ_AZURELINUX4_IMAGE` is absent, the opt-in test skips cleanly. Once it
is set, the invocation fails closed: native Linux/KVM, matching host
architecture, QEMU and support tools, readable image, and matching UEFI
Secure-Boot firmware, `sbverify`, and OpenSSL are all mandatory. UEFI variable enrollment is native, so no firmware-variable host tool is required. The step explicitly refuses TCG. It validates the supplied standalone zstd QCOW2, GPT root GUID, UKI architecture/flavor command line and exact signature, appends the release certificate to the Microsoft-enrolled firmware `db`, then boots two concurrent disposable overlays with independent UEFI variables and hybrid NoCloud/OVF seed media.
It proves key-only SSH as `miztest`, first boot, reboot/reconnect, per-guest
machine-ID and SSH-host-key stability, and distinct identities across the two
instances. Both guests must report Secure Boot, the exact release certificate in `db`, kernel lockdown, accepted required modules, and no module-signature failures. A second test changes one Authenticode-covered `.cmdline` space to a tab in a disposable overlay, preserving kernel-option tokenization. It proves the changed UKI boots with Secure Boot disabled and requires a deterministic firmware refusal (`Security Violation` or `Access Denied`) with Secure Boot enabled before any Linux/PID 1/SSH marker. Core additionally verifies `mizinit` PID 1 and its supervised
foreground-sshd restart behavior; full verifies systemd PID 1 plus cloud-init,
WALinuxAgent, sshd, and networkd active/enabled contracts. Both instances must
power off cleanly.

## Azure Linux 4 release images

Release `AzureLinux-4.0-20260814` contains exactly four Gen2 QCOW2 assets:

```text
AzureLinux-4.0-x86_64.qcow2
AzureLinux-4.0-aarch64.qcow2
AzureLinux-4.0-x86_64.core.qcow2
AzureLinux-4.0-aarch64.core.qcow2
```

The unsuffixed **full** images use systemd, cloud-init for the provisioned
account and SSH key, WALinuxAgent for Azure Ready/extensions, and
`sshd.service`. The **core** images use `mizinit` as PID 1, `azagent` for
provisioning/Ready, and directly supervised OpenSSH. Both flavors have no
baked credentials and require a public SSH key at provisioning time; core
cannot expose SSH until that key has been supplied through the Azure OVF
profile. Release UKIs are trusted through the exact Artifact Signing leaf enrolled in UEFI `db`; its fingerprint is recorded in `candidate.json`, `publish-manifest.json`, release notes, local Secure Boot acceptance, and Azure acceptance together with every signing operation ID.

`miz qemu` defaults to the full x86_64 asset pinned as
`AzureLinux-4.0-x86_64.qcow2@AzureLinux-4.0-20260814`. The `AzureLinux`
alias selects the host-native architecture; add `--model core` to select its
matching core asset, or `--arch` to override the host architecture. Explicit
AArch64 and core filenames remain supported. Add `--secure-boot` to verify the
cataloged asset and embedded release signer, enroll only that exact leaf into
a separate Microsoft-keyed variables store, and launch with the
architecture-specific secure firmware contract. Non-catalog images require
`--secure-boot-certificate` and `--secure-boot-certificate-sha256`.

The manual release workflow builds and externally signs all four candidates on
GitHub-hosted `ubuntu-24.04` and `ubuntu-24.04-arm` runners. Hosted jobs perform
structural QCOW2, GPT, UKI, provenance, and digest validation. They do not
require local KVM or claim a local native boot result; the exact candidate
bytes must pass the protected Azure acceptance matrix on matching x86_64 and
AArch64 VMs before publication.

Every validation the release performs outside `miz` itself is one subcommand of
the native release tool, which each job builds from its own checkout with
`zig build install-azurelinux4-release` and runs as
`zig-out/bin/azurelinux4_release`. It binds and re-derives `candidate.json`,
`azure-result.json`, and `publish-manifest.json`; validates the derived upload
VHD, the Azure VM SKU, the gallery image version's custom UEFI settings, the
Trusted Launch profile, and the certificate in the booted guest's UEFI `db`;
stages the four published assets transactionally; and proves the remote release
holds exactly those four. It needs no interpreter and no runtime dependency
beyond itself, and its contracts are covered by
`zig build test-azurelinux4-release`, which is part of `zig build test-ci`.

The fail-closed native KVM test remains available for optional validation on a
suitable machine:

```sh
# AArch64
sudo apt-get update
sudo apt-get install -y qemu-system-arm
scripts/check_azurelinux4_release_runner.sh aarch64
```

It must print `architecture=aarch64 accelerator=kvm`. Use `x86_64` and install
`qemu-system-x86` for optional x86_64 validation. This probe is not part of
the hosted release gate.

Build/sign/local acceptance use the separate protected `azurelinux4-signing` GitHub environment, restricted to `main` with required reviewers. It defines these variables:

```text
MIZ_AZURE_TENANT_ID=<Microsoft-Entra-tenant-UUID>
MIZ_AZURE_CLIENT_ID=<federated-application-client-UUID>
MIZ_ARTIFACT_SIGNING_ENDPOINT=https://wus.codesigning.azure.net/
MIZ_ARTIFACT_SIGNING_ACCOUNT=cataggar
MIZ_ARTIFACT_SIGNING_PROFILE=miz-uki
```

The workflow builds `miz` from the accepted source commit, uses `miz sign certificate` to fetch the current public leaf, and uses the absolute `zig-out/bin/miz sign` path; no separately installed adapter or static certificate secret is trusted. The signer receives `id-token: write`; all other build permissions remain read-only. Grant the federated application `Artifact Signing Certificate Profile Signer` only at the `miz-uki` profile scope. No production private key, access token, OIDC token, or raw provider response is stored in the repository, image, provenance, logs, workflow artifacts, or release assets.

Real-Azure validation and publication use the protected
`azurelinux4-release` GitHub environment. Configure it with required
reviewers, allow deployments only from `main`, and create this OIDC federated
subject:

```text
repo:cataggar/miz:environment:azurelinux4-release
```

The environment must define these secrets:

```text
AZURE_CLIENT_ID
AZURE_TENANT_ID
AZURE_SUBSCRIPTION_ID
```

and these variables:

```text
AZURE_LOCATION_X64=eastus2
AZURE_VM_SIZE_X64=Standard_D2ds_v5
AZURE_LOCATION_ARM64=eastus2
AZURE_VM_SIZE_ARM64=Standard_D2pds_v5
```

Equivalent regions/SKUs are allowed, but each configured SKU must be
available, expose the requested x64/Arm64 architecture and Gen2, and have a
temporary resource disk. Missing credentials, tools, capacity, or
configuration fail the workflow. The OIDC identity needs permission to
create/delete the uniquely tagged temporary resource groups and their
Compute, Network, and Compute Gallery resources; use a dedicated validation
subscription or an equivalent least-privilege custom role.

Every candidate is rebound to its SHA-256 after artifact download. A complete
four-entry protected Azure matrix creates a Gen2 `TrustedLaunchSupported` gallery definition, publishes the image version through Compute REST API `2025-03-03` with `MicrosoftUefiCertificateAuthorityTemplate` plus the canonical DER release certificate in `additionalSignatures.db`, and deploys a Trusted Launch VM with Secure Boot and vTPM enabled. It validates the exact certificate in guest `db`, the signed UKI, lockdown and module trust, key-only SSH, agent Ready, root growth, resource/data disks, reboot/reconnect, and flavor/runtime identity. The configured regions must support custom UEFI keys; unsupported-region and unsupported-Arm64 service responses fail the four-candidate gate rather than weakening it.
Only then can the single publisher stage the release as a draft, clobber the
four QCOW2s, remove stale assets, verify downloaded remote bytes, and publish.
Existing tags are peeled and must resolve to the accepted source commit.
Derived VHDs and Azure resources are temporary and are never retained.
SHA-256 values appear in release notes and job summaries only: **checksum
sidecar assets are not published**.

Artifact Signing leaf rotation is release-scoped: each gallery version enrolls the exact leaf used for that version, and all four candidates must finish under one leaf. Retain old public leaf certificates and release-to-fingerprint mappings through the rollback window. On compromise, stop publication, revoke or rotate immediately, add the compromised leaf or hash to `dbx` in future gallery versions, and require reimage/redeployment; existing image versions and VM firmware state are not assumed to inherit later `db`/`dbx` changes. `NoSignatureTemplate` is not used because it would replace Microsoft/Azure trust anchors.

## Loading kernel modules from inside a core guest

A core image has no `udev` and no `modprobe`, and that shapes what a guest
process must do for itself once it is running. `init_module(2)` is the only way
in, and it performs **no dependency resolution**: it links the module it is
given against the symbols currently exported, and if any are missing it fails.

The failure is unhelpfully shaped. A module loaded before its dependency
returns `ENOENT` and logs a wall of `Unknown symbol` lines, which reads as *this
kernel does not have that feature* rather than as an ordering mistake. KVM is
the case where this bites, because the dependency is not obvious from the
name:

```text
kernel/arch/x86/kvm/kvm.ko.xz: kernel/virt/lib/irqbypass.ko.xz
kernel/arch/x86/kvm/kvm-amd.ko.xz: kernel/drivers/crypto/ccp/ccp.ko.xz kernel/arch/x86/kvm/kvm.ko.xz kernel/virt/lib/irqbypass.ko.xz
```

`modules.dep` in the image is the authority — the same file the emulated
executor already reads to resolve its own closure — so a guest-side loader
should mirror it explicitly rather than hard-code an order that happens to work
on one kernel.

Two errno values are worth telling apart, because they lead opposite ways:

- **`ENOENT`** after `Unknown symbol` is a missing dependency. Load the
  dependency first.
- **`EOPNOTSUPP`** is the module working correctly and declining: the CPU
  genuinely lacks the feature. `kvm_intel` returns this under TCG, where the
  emulated CPU has no VMX. It is the expected result of a local emulated boot
  and the cheapest way to prove a dependency-ordering fix without hardware that
  supports the feature.

A third case looks like failure and is not: **a driver built into the kernel
has no `.ko` to load, so `init_module` always fails for it.** On Azure Linux 4
`tun` and `hv_utils` are built in. `modules.builtin` says so, and the only
authority on what the driver can actually do is the device — opening
`/dev/net/tun` answers the question that a module load cannot.

### Device nodes a core image will not create for you

devtmpfs creates `/dev/kvm` as `0600 root:root`. On a distro with udev the
matching rule immediately relaxes that to `0660 root:kvm`; with no udev present
it simply stays root-only, and every hypervisor front end needs `sudo` for the
rest of the image's life.

The `kvm` group already exists in the base image, so the fix is the one udev
would have applied — `chown` the node to that group, `chmod` it to `0660`, and
add the operator account to the group. Read the gid out of `/etc/group` rather
than assuming the conventional value; a hard-coded gid that disagrees with the
image leaves the device owned by a group nobody is in, which fails exactly as
confusingly as the original mode.

`/dev/net/tun` is worth creating explicitly for a different reason: devtmpfs
does make it when the driver is available, but only if the directory exists, and
a missing node surfaces as a userspace daemon failing to bring up an interface
— a long way from the actual cause.

### Nested virtualization

Nested virtualization works on Azure sizes that expose it, and the guest says so
in a way worth recognizing:

```text
kvm_intel: Using Hyper-V Enlightened VMCS
```

The enlightened path is what makes it usable rather than merely present: the L1
hypervisor talks to Hyper-V directly instead of trapping every VMCS access. A
nested guest booted with `-accel kvm` then reports `Hypervisor detected: KVM`
and `Booting paravirtualized kernel on KVM`, and reaches power-off in seconds
rather than the minutes a TCG boot of the same kernel takes.
