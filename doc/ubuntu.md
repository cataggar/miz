# Ubuntu 26.04 images

The Ubuntu 26.04 release set contains two conventional Server images:

| vmiz architecture | Ubuntu architecture | Asset |
| --- | --- | --- |
| `x86_64` | `amd64` | `Ubuntu-26.04-x86_64.qcow2` |
| `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.qcow2` |

Both are full, generalized Ubuntu Server images. There is no Ubuntu core
flavor in this release.

## Immutable source and package provenance

`scripts/build_generalized_ubuntu2604.zig` uses Canonical's immutable
`release-20260731` cloud-image publication. The official server cloud disk,
not a root tarball reconstructed from packages, is the authoritative
filesystem and initial package input. The builder then extracts that root and
uses the embedded `vmiz.package_family` debz backend against
`https://snapshot.ubuntu.com/ubuntu/20260731T000000Z` to install the coherent
`linux-azure` and `walinuxagent` closures.

The following inputs are compiled into the builder:

- Canonical key fingerprint:
  `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`
- `SHA256SUMS` SHA-256:
  `d562d59dac70f68d67d00e994db5cd89e49e9d93f7f80b4cb868a5eeb057ec36`
- `SHA256SUMS.gpg` SHA-256:
  `2bf5fae8be0c79cc30c5c10223f1d4790b6ef541240896bfe48c7ac57c3404ed`
- amd64 image SHA-256:
  `9dc7c5363c0146a08ba0c9aa834d82c2c6dfbb1c471ad9a2f0aba1189e21be05`
- amd64 manifest SHA-256:
  `05129d9e221665e0009b7c3a4e62b30040c6b4bf5368d622ea44141c06921514`
- arm64 image SHA-256:
  `3e113fdd41f39e13729375173bb2ae793f87dc6db4294e5251ff2476971788ba`
- arm64 manifest SHA-256:
  `2889120db0432e8029f8f01622efb40ce964e434ba2c81e98937ad1e2616e4f5`
- embedded debz API commit:
  `d5385857a44fca753af515e805af70be9f004183`

The builder first verifies the pinned checksum files, imports only the pinned
Canonical fingerprint, verifies the detached signature, and requires exactly
one signed checksum entry for the selected image and manifest. It separately
hashes downloaded or `--source` image bytes. The manifest must contain the
expected architecture and the systemd, cloud-init, cloud-guest-utils,
OpenSSH, sudo, and netplan packages.

Each of `linux-azure` and `walinuxagent` is a separate debz transaction:
resolve an exact closure lock, apply that same lock with strict repository
priority and no recommends or downgrades, and retain both the exact lock and
`transaction-result.json`. The transaction provenance's `lock_sha256` must
equal the lock's semantic digest. The final sorted dpkg inventory at
`/var/lib/vmiz/ubuntu2604-package-lock.tsv` must contain the Azure kernel,
agent, cloud-init, and OpenSSH for the selected architecture and no foreign
amd64/arm64 packages.

## Guest and disk contract

The output is a standalone, zstd-compressed QCOW2 with an exact default
virtual size of 5 GiB. It retains the Canonical Gen2 GPT layout: the root is
`/dev/sda1` and the EFI system partition is `/dev/sda15`. Firmware directly
loads the signed architecture-specific UKI from both the fallback path
(`EFI/BOOT/BOOTX64.EFI` or `EFI/BOOT/BOOTAA64.EFI`) and the corresponding
`EFI/Linux/` path; shim and GRUB are not required for this boot path.

The UKI combines the installed `linux-azure` kernel, its newly generated
initramfs, and matching `/lib/modules/<release>`. The builder refuses a
non-Azure active kernel, missing modules, wrong PE architecture, invalid
signature, missing final UKI, wrong Ubuntu release, backing file, or wrong
virtual size.

The generalized guest uses:

- systemd, cloud-init with only the Azure datasource, and WALinuxAgent with
  agent provisioning enabled while resource-disk formatting and swap remain
  disabled;
- cloud-init growpart and root-filesystem resize;
- netplan rendered by systemd-networkd with DHCPv4 and DHCPv6;
- OpenSSH with password and keyboard-interactive authentication disabled;
- key-only administrator provisioning, with no baked login credentials; and
- removed default `ubuntu` user, machine identity, SSH host keys, random seed,
  cloud-init state, WALinuxAgent state, and Azure logs.

First boot regenerates per-instance identity and host keys. Acceptance launches
two instances to prove those identities differ, remain stable across reboot,
and are not inherited from the candidate.

## Local build

Use Zig 0.16.0 or later on a matching native Ubuntu host. Install the same
builder dependencies as the release workflow:

```console
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  binutils cpio curl file gnupg jq libguestfs-tools liblzma-dev libzstd-dev \
  linux-image-generic openssl \
  python3 python3-pefile qemu-utils sbsigntool systemd-ukify \
  tar xorriso xz-utils zstd
sudo chmod 0644 /boot/vmlinuz-*
```

The permission adjustment lets the unprivileged libguestfs `supermin` process
read the appliance kernel installed by `linux-image-generic`.

Run a source-pin preflight (requiring only `curl` and `gpg`) with:

```console
zig build -Dubuntu2604-arch=x86_64 generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=aarch64 generalized-ubuntu2604 -- --preflight-only
```

A full build requires signing. For local development, supply exactly one
certificate and private key:

```console
zig build -Dubuntu2604-arch=x86_64 generalized-ubuntu2604 -- \
  --provenance-dir artifacts/x86_64/internal-provenance \
  --output artifacts/x86_64/Ubuntu-26.04-x86_64.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key

zig build -Dubuntu2604-arch=aarch64 generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64/internal-provenance \
  --output artifacts/aarch64/Ubuntu-26.04-aarch64.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

For the production external signer, build `vmiz`, configure its Artifact
Signing environment, and replace `--uki-signing-key` with:

```console
zig build install-vmiz
export VMIZ_AZURE_TENANT_ID=<tenant-UUID>
export VMIZ_AZURE_CLIENT_ID=<application-client-UUID>
export VMIZ_ARTIFACT_SIGNING_ENDPOINT=https://<region>.codesigning.azure.net/
export VMIZ_ARTIFACT_SIGNING_ACCOUNT=<account>
export VMIZ_ARTIFACT_SIGNING_PROFILE=<profile>

# Add these arguments to either architecture's command:
--uki-sign-command "$PWD/zig-out/bin/vmiz" \
--uki-sign-command-arg sign
```

The external command must be absolute. Local-key and external-command modes
are mutually exclusive. Private signing material is never copied into the
guest.

Without overrides, outputs are written in the current directory and work is
cached under `.scratch/ubuntu2604-x86_64` or
`.scratch/ubuntu2604-aarch64`. A provenance directory contains the verified
`SHA256SUMS`, signature, architecture manifest,
`ubuntu2604-build-provenance.json`, `uki-signing-full-<architecture>.json`,
and, for both `linux-azure` and `walinuxagent`,
`debz-exact-lock-<package>-<amd64|arm64>.json` plus
`debz-transaction-provenance-<package>-<amd64|arm64>.json`.

The build validates the source chain before modification and revalidates the
final QCOW2, GPT partitions, Ubuntu identity, package inventory, UKI locations,
PE architecture, and signature. The release workflow additionally runs
`qemu-img check`, requires zstd compression and no backing file, binds every
provenance sidecar into `candidate.json`, and rejects private-key material.

## Acceptance infrastructure

Native acceptance is deliberately not emulation. Each architecture requires a
matching Linux runner with readable and writable `/dev/kvm`, QEMU, OVMF or
AAVMF, `swtpm`, `virt-fw-vars`, `sbverify`, OpenSSH, and `xorriso`. It enrolls
the exact candidate leaf in UEFI `db` and asserts the standalone GPT image,
Secure Boot, signed UKI, vTPM, lockdown, signed modules, rejection of a
tampered UKI, key-only SSH, cloud-init, WALinuxAgent, netplan/networkd, root
growth, generalized identity, reboot/reconnect, and clean service health.

Azure acceptance requires an Azure subscription and OIDC application allowed
to create and delete the temporary resource group and its managed disks,
Compute Gallery/image definition/version with custom UEFI `db`, network,
public IP, Trusted Launch VM, and managed data disk. The selected region and
VM size must support the candidate architecture, Gen2, Trusted Launch, Secure
Boot, and vTPM. Acceptance converts the exact QCOW2 to a validated fixed VHD,
then asserts the signer, UKI, provisioning, key-only SSH, runtime Ubuntu
identity, agent Ready state, root growth, data disk, reboot, vTPM, lockdown,
and module signatures. Cleanup deletes only the expected resource group with
the exact run ownership tags.

## Release workflow

`.github/workflows/ubuntu2604-release.yml` is manually dispatched from
`main`. Before dispatch:

1. Create the required tag `Ubuntu-26.04-20260818` at the exact current
   `main` commit. Lightweight and annotated tags are accepted; an existing tag
   is never moved.
2. Configure protected environment `ubuntu2604-signing`, restricted to
   `main` and requiring reviewers, with variables
   `VMIZ_AZURE_TENANT_ID`, `VMIZ_AZURE_CLIENT_ID`,
   `VMIZ_ARTIFACT_SIGNING_ENDPOINT`, `VMIZ_ARTIFACT_SIGNING_ACCOUNT`, and
   `VMIZ_ARTIFACT_SIGNING_PROFILE`.
3. Configure protected environment `ubuntu2604-release` the same way, with
   secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID` and variables `AZURE_LOCATION_X64`,
   `AZURE_LOCATION_ARM64`, `AZURE_VM_SIZE_X64`, and
   `AZURE_VM_SIZE_ARM64`.
4. Configure both Entra federated credentials with issuer
   `https://token.actions.githubusercontent.com` and audience
   `api://AzureADTokenExchange`. Their subjects are respectively
   `repo:cataggar/vmiz:environment:ubuntu2604-signing` and
   `repo:cataggar/vmiz:environment:ubuntu2604-release`.

Top-level permissions are `actions: read` and `contents: read`. Signing and
Azure acceptance add only `id-token: write`; native acceptance remains
read-only. Publication uses `actions: read` and `contents: write`.

The prepare gate binds the run to the current remote `main` commit and tag.
An optional `candidate_run_id` may reuse only a completed manual run on
`main` for that same commit and exact run attempt. Both named build jobs must
have succeeded and exactly two non-expired, nonempty candidate artifacts must
match the commit and attempt. Reused candidates still rerun native and Azure
acceptance.

Publication requires two successful build candidates, two digest-bound native
results, and two exact Azure results. It stages only the two QCOW2 files,
creates or resets the release as a draft, uploads with clobber, removes stale
assets, and verifies the remote draft has exactly the two expected names and
sizes. It then downloads both assets and verifies their SHA-256 and size before
making the release non-draft, followed by one final remote exact-two-asset
check. On publication failure the release is retained as a draft; job cleanup
removes local staging, candidates, derived VHDs, credentials, and only
ownership-tagged Azure resources.

## Catalog aliases

`vmiz qemu Ubuntu` and exact Ubuntu catalog aliases are intentionally not
present yet. They may be added only after the real published asset SHA-256
digests and the final signing-certificate fingerprint are known and pinned.
Do not substitute build-time guesses or copy values from another release.
Until then, boot an explicitly supplied image path and provide its independent
Secure Boot trust material as described in [QEMU](qemu.md).
