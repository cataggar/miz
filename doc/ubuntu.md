# Ubuntu 26.04 images

`miz` has full, core, and bare-metal Ubuntu 26.04 build flavors:

| Flavor | miz architecture | Ubuntu architecture | Candidate | Default disk size | Boot/provisioning |
| --- | --- | --- | --- | --- | --- |
| full | `x86_64` | `amd64` | `Ubuntu-26.04-x86_64.qcow2` | 5 GiB | systemd, cloud-init, WALinuxAgent |
| full | `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.qcow2` | 5 GiB | systemd, cloud-init, WALinuxAgent |
| core | `x86_64` | `amd64` | `Ubuntu-26.04-x86_64.core.qcow2` | 3584 MiB | mizinit, azagent |
| core | `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.core.qcow2` | 3584 MiB | mizinit, azagent |
| baremetal | `aarch64` | `arm64` | `Ubuntu-26.04-aarch64.baremetal.qcow2` | 5 GiB | mizinit, baked administrator |

Bare metal is `aarch64` only: the kernel it names is published for `arm64`
alone, because the machines it exists for are.

The protected release contract is now defined to publish an exact four-asset
matrix: full and core for both architectures. The existing
[`Ubuntu-26.04-20260822`](https://github.com/cataggar/miz/releases/tag/Ubuntu-26.04-20260822)
release remains immutable and full-only. The four-asset workflow uses the new
tag `Ubuntu-26.04-20260829`; that tag and release do not become final until all
four candidates pass digest-bound same-architecture QEMU acceptance
(x86_64 KVM and AArch64 TCG), Azure Trusted Launch acceptance, and publication
redownload verification.

## QEMU catalog aliases

Release [`Ubuntu-26.04-20260822`](https://github.com/cataggar/miz/releases/tag/Ubuntu-26.04-20260822)
publishes the immutable full-image catalog entries:

| Alias | Release asset SHA-256 |
| --- | --- |
| `Ubuntu-26.04-x86_64` | `23116f2a4fb508d1beb60fae673c95636c3540ad3ab8f42f6966367ef86e0511` |
| `Ubuntu-26.04-aarch64` | `f78fb8f8fc54af4bc26ac97f7cb1fd9750abdf4f24e62f7cffffeb2daef4b175` |

`miz qemu Ubuntu` selects the x86_64 asset on x86_64 hosts and the AArch64
asset on AArch64 hosts. Override that host-native choice with
`--arch x86_64` or `--arch aarch64`. The architecture-specific aliases are
exact, and a directory prefix controls where the catalog download and firmware
bundle are placed:

```text
miz qemu Ubuntu
miz qemu Ubuntu --arch aarch64
miz qemu Ubuntu-26.04-x86_64
miz qemu images/Ubuntu-26.04-aarch64
```

The catalog pins both immutable release asset URLs and the digests above.
Secure Boot additionally pins the validated release leaf certificate's
canonical-DER SHA-256,
`08796d5bf0e16eb1731408be816bbbc014e9a81d91c7afbf34bf8c9e4617ae19`.
An existing image is reused and is never refreshed or overwritten.

Only the immutable `20260822` full model is currently cataloged.
`miz qemu Ubuntu --model core` remains rejected until the new release has
actually completed and a follow-up catalog change pins its final core asset
URLs, SHA-256 digests, and signer. The resolver requires a complete x86_64 and
AArch64 pair for both models under one release tag and signing identity, so
partial catalog data cannot enable selection.

## Immutable source and package provenance

`scripts/build_generalized_ubuntu2604.zig` uses Canonical's immutable
`release-20260731` cloud-image publication and
`https://snapshot.ubuntu.com/ubuntu/20260731T000000Z`.

For full, the official server cloud disk is the authoritative filesystem and
installed-package baseline. The embedded `miz.package_family` debz backend
adds exact `linux-azure` and `walinuxagent` closures without reconstructing the
root from packages.

For core, the same signed cloud disk is used only as the pinned Gen2 GPT and
EFI-system-partition substrate. The server root is discarded and a fresh root
is assembled from an empty debz baseline with exact package roots, in stable
order: `ubuntu-minimal`, `linux-azure`, `initramfs-tools`, `openssh-server`,
`sudo`, and `ca-certificates`. The initramfs implementation is explicit
because the kernel only recommends one and debz's exact closure does not
install recommendations; the trust store is explicit because no required
dependency supplies it. The resolved closure must also contain
`openssh-client`, and must not contain cloud-init, WALinuxAgent,
`ubuntu-server`, or `ubuntu-server-minimal`. This source/package decision is
part of core provenance and is not inferred from mutable archive state.

For bare metal, the root is assembled the same way, in stable order:
`ubuntu-minimal`, the pinned NVIDIA BaseOS `linux-image` and `linux-modules`
binary packages, `initramfs-tools`, `openssh-server`, `sudo`, and
`ca-certificates`. The last two are named explicitly because core reached
both through `linux-azure`, which bare metal forbids -- a second kernel in
`/boot` would make the release the UKI is built from ambiguous. The resolved
closure must also contain `openssh-client`, and must not contain cloud-init,
WALinuxAgent, `ubuntu-server`, `ubuntu-server-minimal`, or `linux-azure`.

The package-root round trip is native: the mutable QCOW2 is converted to a
raw staging image, `miz.ext4_mountless.FileSystem` reads the selected ext4
partition without mounting it, and the package-safe staging view is imported
back through the same API before the raw image is converted back. This path
has no libguestfs, guestfish, supermin, or libguestfs `virt-*` dependency;
mode-`000` entries are read from ext4 bytes rather than made readable on the
host, while their original metadata remains in the native tree.

The mountless atomic stage preserves holes from the raw source instead of
allocating zero-filled regions. After a durable ext4 exchange, the builder
closes both image handles and removes the displaced recovery image before it
allocates the staged QCOW2. An uncertain commit retains and reports recovery;
publication failures remove the unpublished QCOW2 stage.

Each package root is a separate debz transaction with its own dpkg admin
state, discarded after it publishes so no stage inherits another's installed
baseline. The downloaded objects are not: every stage reads and writes one
`debz-cache` directory in the work dir, kept between stages and between runs.
Objects there are named by their own SHA-256 and the sources document pins an
immutable snapshot, so a cache hit cannot change what a stage resolves to or
installs, and repository signatures are verified and recorded in provenance
either way. At startup, abandoned staging files are removed under each cache
namespace's writer lock without touching verified objects or manifests.
Deleting the work dir is still a full cold build.

debz metadata manifests are keyed by the normalized repository identity,
including the absolute `Signed-By` keyring path. A cache staged for later
offline use must therefore pass the same `--debz-input-dir` to both builds;
that directory holds only the regenerated source documents and validated
public Ubuntu keyring. Package transaction state remains per-stage and is
never copied between runs.

The root partition is selected by the validated GPT name
`cloudimg-rootfs` and the ext4 filesystem label, not by a fixed `/dev/sdaN`
slot; Canonical's populated partition slots differ between image revisions.

The following inputs are compiled into the builder:

- Canonical key fingerprint:
  `D2EB44626FDDC30B513D5BB71A5D6C4C7DB87C81`
- Pinned Canonical ASCII public-key SHA-256:
  `e581b39fac6bfc199e921788c3c07ac5406fe88db487c7bdcf1e1d2f78fbcf05`
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
  `beac3f20dd93fd98863af71e8fe621d47db663f6`

The builder first verifies the pinned checksum files with its bounded native
OpenPGP verifier. It embeds Canonical's ASCII-armored public key, pins the
complete armored key and its full v4 fingerprint, and accepts only a
4096-bit RSA/65537 key and an unambiguous v4 binary-document RSA/SHA-512
detached signature with Canonical's issuer fingerprint. It has no keyring,
trust database, keyserver, GnuPG configuration, or GnuPG executable
dependency. It then requires exactly one signed checksum entry for the
selected image and manifest. It separately hashes downloaded or `--source`
image bytes. The manifest must contain the expected architecture and the
systemd, cloud-init, cloud-guest-utils, OpenSSH, sudo, netplan, and `udisks2`
packages.

Every requested package is a separate debz transaction. Full resolves
`linux-azure` and `walinuxagent` from the Canonical image's installed dpkg
baseline. Core resolves its four package roots from the empty root. Both apply
the same exact lock with strict repository priority and no recommends or
downgrades, and retain the exact lock and `transaction-result.json`. Missing
baseline packages, versions, architectures, or closure members fail the
build. The transaction provenance's `lock_sha256` must equal the lock's
semantic digest. The final sorted dpkg inventory at
`/var/lib/miz/ubuntu2604-package-lock.tsv` must match the selected flavor and
architecture with no foreign amd64/arm64 packages. Native inspection records
the selected kernel, initramfs, modules directory, and exact lock digest in
`internal-provenance/ubuntu2604-boot-input-evidence.json`.

## Guest and disk contract

Each output is a standalone, zstd-compressed QCOW2. Full has an exact default
virtual size of 5 GiB. Core is exactly 3584 MiB: the size of the pinned signed
substrate, 30% smaller than full. Its fresh root must retain at least 768 MiB
free after package installation and final injection; the measured free bytes,
minimum, and virtual size are provenance fields and validation gates.

The root remains `/dev/sda1` and the EFI system partition remains
`/dev/sda15`. x86_64 retains Canonical's Gen2 partition geometry. Arm64
rebuilds `/dev/sda15` as a 512 MiB FAT32 ESP in the same GPT slot, preserving
its first LBA, partition GUID, and FAT volume ID; the obsolete Canonical
XBOOTLDR entry at `/dev/sda13` is cleared without moving the root or changing
the disk size. The rebuilt Arm64 ESP contains only
`EFI/BOOT/BOOTAA64.EFI`, not Canonical's stale shim/GRUB tree.
The matching legacy `/boot` and `/boot/efi` mounts are removed from Arm64
`fstab`, and the full image disables GRUB's initrd-fallback helper because
firmware boots the signed UKI directly rather than maintaining GRUB state.
The networkd dispatcher remains enabled, but its startup-trigger pass is
ordered after chrony and `network-online.target` so the Arm64 TCG path cannot
race the services those triggers call.
`udisks2` remains installed and D-Bus activatable: its
`org.freedesktop.UDisks2` system-bus activation descriptor and service remain
available, and only the generated
`graphical.target.wants/udisks2.service` eager-start link is removed. The
service is not masked or removed, so an actual D-Bus request can still
activate it without making every headless image boot compete for it.

Firmware directly loads the signed architecture-specific UKI from the
removable-media fallback path (`EFI/BOOT/BOOTX64.EFI` or
`EFI/BOOT/BOOTAA64.EFI`); shim and GRUB are not required for this boot path.
That is the only UKI copy. Firmware loads one binary, and a generalized image
boots on fresh NVRAM, so the fallback is the path it takes. `EFI/Linux/` is
the Boot Loader Specification type 2 directory, which needs a boot loader to
scan it, and these images ship none.

The UKI combines the installed kernel, its newly generated initramfs, and
matching `/lib/modules/<release>`. Which kernel is the right one is a property
of the flavor -- `linux-azure` for full and core, the NVIDIA BaseOS kernel for
bare metal -- and the builder refuses any other, along with missing modules,
wrong PE architecture, invalid signature, missing final UKI, wrong Ubuntu
release, backing file, or wrong virtual size.

The generalized full guest uses:

- systemd, cloud-init with only the Azure datasource, and WALinuxAgent with
  agent provisioning enabled while WALinuxAgent resource-disk formatting and
  swap remain disabled; cloud-init mounts an available Azure temporary disk at
  the conventional `/mnt` path without swap;
- cloud-init growpart and root-filesystem resize;
- netplan rendered by systemd-networkd with DHCPv4 and DHCPv6;
- OpenSSH with password and keyboard-interactive authentication disabled;
- key-only administrator provisioning, with no baked login credentials; and
- removed default `ubuntu` user, machine identity, SSH host keys, random seed,
  cloud-init state, WALinuxAgent state, and Azure logs.

First boot regenerates per-instance identity and host keys. Acceptance launches
two instances to prove those identities differ, remain stable across reboot,
and are not inherited from the candidate.

The generalized core guest has no systemd service manager, cloud-init, or
WALinuxAgent state. The builder injects architecture-matched static
`/usr/sbin/mizinit` and `/usr/sbin/azagent` binaries. The signed UKI selects
`init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=auto`.
`mizinit` is PID 1: it mounts the required kernel filesystems, initializes
networking, generates a machine ID and SSH host keys when absent, supervises
`sshd -D -e`, restarts it after failure, and launches `azagent`.

`azagent` reads Azure's OVF provisioning media, creates the requested
administrator with key-only SSH and passwordless sudo, persists
`/var/lib/azagent/provisioned`, grows the root, formats the Azure resource disk
as XFS at `/d` without swap, mounts managed data disks without formatting
them, and reports Ready in Azure. Explicitly marked local OVF media instead
runs `azagent --skip-ready` for same-architecture QEMU acceptance. Provisioned identity,
authorized keys, host keys, and the sentinel must persist across reboot;
separate instances must not inherit them from the candidate.

`--proxy <url>` reaches the Canonical cloud image and the Ubuntu archive through an HTTP proxy, for a build host with no direct egress. It is named explicitly rather than read from `http_proxy` or `https_proxy`, so a build's egress path is a stated input like every other one and cannot change because of an ambient variable, and it is rejected before anything is downloaded if it is malformed. A proxy carrying a credential is refused, because the credential would have to travel in an argument or an environment variable to get here; debz refuses those on the same grounds. TLS is unaffected: the proxy is asked to `CONNECT`, the session is negotiated end to end with the origin, and the pinned digests and archive signatures still verify the bytes that origin served. The same value is passed to debz, so package download takes the same path the image download does.

### Signed Binder boot

Core's kernel is checked against six `/boot/config-<release>` lines:
`CONFIG_ANDROID_BINDER_IPC=m` and `CONFIG_ANDROID_BINDERFS=m` so Binder ships
as the loadable, signed `binder_linux` module rather than builtin or absent;
`CONFIG_ANDROID_BINDER_DEVICES=""` so the kernel creates no binder device on
its own, leaving device creation entirely to mizinit through binderfs;
`CONFIG_DMABUF_HEAPS=y` and `CONFIG_DMABUF_HEAPS_SYSTEM=y` so the system
DMA heap is present at `/dev/dma_heap/system`; and
`CONFIG_MODULE_DECOMPRESS=y`, which is what lets the kernel decompress and
verify the packaged, signed `.ko.zst` on mizinit's behalf.

The builder locates the packaged `binder_linux` module under the kernel's own
module tree, rejects the build if a DKMS-built shadow tree
(`updates/dkms/`) is present at all -- an Anbox-style out-of-tree Binder
implementation is exactly what this refuses to boot -- and confirms the
packaged bytes end in the kernel's own module-signing trailer before
recording their path and digest as boot-input evidence. It asserts only that
the module is signed, not by whom: the running kernel's own signature
enforcement is the actual verifier. `anbox-modules-dkms` and `anbox-modules`
are also forbidden core package names, checked the same way every other
forbidden package is. Core's `/etc/initramfs-tools/modules` requests
`binder_linux` explicitly, and the generated initramfs is read back and
required to contain it, the same way bare metal's is checked for `nvme` and
`r8152`.

None of this runs anything at boot by itself. The core UKI cmdline requests
the required Binder workload with `mizinit.binder=required` alongside the
flavor's other `mizinit.*` options; bare-metal images leave it disabled. When
present, mizinit -- after mounting the required kernel filesystems and before
starting `sshd` or `azagent` -- loads `binder_linux` with `finit_module()`
against the packaged, possibly `.ko.zst`-compressed module file (asking the
kernel to decompress and verify it, never decompressing or touching the
signed bytes itself), mounts binderfs at `/dev/binderfs`, and creates
`binder`, `hwbinder`, and `vndbinder` through binderfs's `BINDER_CTL_ADD`
device-control ioctl. Every step tolerates already having been done (an
already-loaded module, an already-mounted binderfs, an already-created
device), so a restart or a race with a previous boot's partial setup is not a
failure. A required-mode failure at any step is fatal to readiness: mizinit
never prints its ready line and never starts `sshd` or `azagent`, rather than
booting into a machine that looks up but has no working Binder workload.
`mizinit.binder=disabled` (also the default when the option is absent) skips
all of this.

### Bare metal

The bare-metal guest is the core guest on a physical machine, and every
difference follows from one fact: there is no Azure underneath it to be
provisioned by.

Its UKI selects `mizinit.azure=off` rather than `auto`, so mizinit does not
spend a boot looking for evidence that is never coming. That decision also
means `azagent` never runs -- and `azagent` is what, on core, creates the
administrator, generates the SSH host keys, and writes
`/var/lib/azagent/provisioned`, the sentinel mizinit waits for before it
starts `sshd`. Left alone, a bare-metal image would boot correctly and never
become reachable, with nothing on the network to say why.

So the image is built already holding what provisioning would have delivered.
The administrator `g` is created at build time from `--authorized-key`, with a
locked password and passwordless sudo, and the image ships
`/usr/local/sbin/mizinit-access`: the replacement access provider mizinit
documents for exactly this case, started without waiting on a sentinel because
it brings its own credential path. Before generating host keys, it synchronously
runs `azagent --resize-root-only`; a resize failure emits a warning and does not
prevent access, while every other provider setup failure remains fatal. It then
generates the host keys on first boot, creates `/run/sshd` -- which mizinit
does only on the path it replaces -- and execs `sshd -D -e`. Networking needs
no configuration: mizinit runs its own DHCP client on the first non-loopback
interface.

`validateNoBakedIdentity` refuses SSH host keys for every flavor, because they
must differ per machine. It refuses authorized keys only where identity
arrives at boot, which is what separates bare metal from the two Azure
flavors. A bare-metal build without a key is refused outright: an image nobody
can log in to is not a successful build.

The initramfs is the highest-risk part of the flavor and is checked as such.
An Azure image's dependency-pruned initramfs carries `hv_netvsc` and `sd_mod`;
a machine whose root is behind NVMe and whose management NIC is a USB-attached
Realtek has neither. The image sets `MODULES=most` and names `nvme`,
`nvme_core`, `xhci_hcd`, `xhci_pci`, `usbnet`, `mii`, and `r8152` explicitly,
and then the builder reads the initramfs it is about to seal into the UKI --
the bytes that will boot, not the configuration that asked for them -- and
fails unless `nvme` and `r8152` are in it. Both halves of a concatenated
initramfs are searched; an image whose compressed half cannot be read fails
closed.

`--raw-output` writes a second copy of the validated image with no container
format, for writing to a disk with `dd`. The QCOW2 remains the artifact every
gate is applied to; the raw copy is made from it afterwards, so the two are
the same guest bytes.

## Local build

Use Zig 0.16.0 or later on a matching native Ubuntu host. Install the same
builder dependencies as the release workflow:

```console
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  file jq systemd-boot-efi
```

`systemd-boot-efi` installs only the architecture-matched systemd-boot EFI
stub (`/usr/lib/systemd/boot/efi/linuxx64.efi.stub` on x86_64,
`linuxaa64.efi.stub` on arm64). The Unified Kernel Image is assembled natively:
miz appends the deterministic `.linux`, `.initrd`, `.cmdline`, `.osrel`, and
`.uname` PE/COFF sections onto that stub with architecture-correct headers,
alignment, section flags, and subsystem/entry/image sizing, so the builder no
longer installs or invokes `systemd-ukify`, `binutils`, `python3-pefile`, or a
host `linux-image-generic` kernel — the kernel and initrd are extracted from
the guest image. The stub source path and its SHA-256 are recorded in the
signing provenance sidecar.

The builder inventory is therefore limited to the native UKI stub source
(`systemd-boot-efi`), `file`, and `jq`. The release schema, provenance,
acceptance, staging, and publication checks are a single native tool
(`zig-out/bin/ubuntu2604_release`, built by `zig build`), so no interpreter is
installed or invoked anywhere in the Ubuntu release, core-validation,
acceptance, local end-to-end, or publication paths. HTTPS/OpenPGP artifact
verification and XZ/zstd decoding and encoding plus newc cpio archive creation
are native, bounded implementations; no host codec library or `curl`, GnuPG,
`cpio`, `xz`, or `zstd` executable is used. X.509 certificate normalization,
canonical-DER fingerprinting, local-key Authenticode signing, and Secure Boot
signature verification are likewise native, so the builder neither installs nor
invokes `openssl`, `sbsign`, or `sbverify`. Standalone zstd-compressed QCOW2
finalization is native as well; all resize, copy, GPT, filesystem mutation, and
final structural validation before publication run without `qemu-img`.

A complete build runs the bounded guest-tool allowlist in a private mount,
PID, and network namespace, so it must be invoked with `sudo` on Linux. The executor
establishes and tears down the namespace using direct, audited Linux syscalls
(`clone`, `mount`, `mknod`, and `chroot`) rather than `util-linux` command
helpers such as `unshare`, `mount`, `umount`, or `setsid`. It mounts only
`dev`, `proc`, `sys`, and `run`, creates the four required device
nodes plus an isolated `tmp`, and tears the namespace down after every
command. `update-initramfs`, `dpkg-query`, and optional `cloud-init clean` are
the only guest commands; systemd enablement and account removal are native
mountless operations.

Run a source-pin preflight using the compiled native HTTPS and OpenPGP
verifiers with:

```console
zig build -Dubuntu2604-arch=x86_64 generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=aarch64 generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=x86_64 -Dubuntu2604-flavor=core generalized-ubuntu2604 -- --preflight-only
zig build -Dubuntu2604-arch=aarch64 -Dubuntu2604-flavor=core generalized-ubuntu2604 -- --preflight-only
```

Release artifacts are fetched by miz's native HTTPS downloader. It accepts
only HTTPS URLs, verifies the system TLS certificate chain using TLS 1.2 or
newer, bounds redirects, retries and response sizes, and atomically publishes
only fully downloaded inputs. Pinned artifact SHA-256 values, the complete
Canonical signing-key armor, and its full fingerprint remain mandatory
verification gates. The bounded request-buffer sizing for signed redirects is
informed by [`ghr`'s MIT-licensed HTTP implementation](https://github.com/cataggar/ghr/blob/main/src/http.zig);
miz does not vendor that code.

A complete image build requires signing. For local development, supply exactly
one certificate and private key:

```console
sudo -E zig build -Dubuntu2604-arch=x86_64 generalized-ubuntu2604 -- \
  --provenance-dir artifacts/x86_64/internal-provenance \
  --output artifacts/x86_64/Ubuntu-26.04-x86_64.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key

sudo -E zig build -Dubuntu2604-arch=aarch64 generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64/internal-provenance \
  --output artifacts/aarch64/Ubuntu-26.04-aarch64.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

Build core explicitly for both architectures; the flavor selects the exact
3584 MiB size, core asset name, static guest binaries, and empty-root package
policy:

```console
sudo -E zig build \
  -Dubuntu2604-arch=x86_64 \
  -Dubuntu2604-flavor=core \
  generalized-ubuntu2604 -- \
  --provenance-dir artifacts/x86_64-core/internal-provenance \
  --output artifacts/x86_64-core/Ubuntu-26.04-x86_64.core.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key

sudo -E zig build \
  -Dubuntu2604-arch=aarch64 \
  -Dubuntu2604-flavor=core \
  generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64-core/internal-provenance \
  --output artifacts/aarch64-core/Ubuntu-26.04-aarch64.core.qcow2 \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

Bare metal is built for `aarch64` only, on an `aarch64` host: the guest tools
run in an offline root, so the build host's architecture must match the
guest's. The key is required, and `--raw-output` is what a disk gets written
from:

```console
sudo -E zig build \
  -Dubuntu2604-arch=aarch64 \
  -Dubuntu2604-flavor=baremetal \
  generalized-ubuntu2604 -- \
  --provenance-dir artifacts/aarch64-baremetal/internal-provenance \
  --output artifacts/aarch64-baremetal/Ubuntu-26.04-aarch64.baremetal.qcow2 \
  --raw-output artifacts/aarch64-baremetal/Ubuntu-26.04-aarch64.baremetal.raw \
  --authorized-key ~/.ssh/id_ed25519.pub \
  --uki-signing-certificate test.pem \
  --uki-signing-certificate-sha256 <canonical-DER-SHA-256> \
  --uki-signing-key test.key
```

For the production external signer, build `miz`, configure its Artifact
Signing environment, and replace `--uki-signing-key` with:

```console
zig build install-miz
export MIZ_AZURE_TENANT_ID=<tenant-UUID>
export MIZ_AZURE_CLIENT_ID=<application-client-UUID>
export MIZ_ARTIFACT_SIGNING_ENDPOINT=https://<region>.codesigning.azure.net/
export MIZ_ARTIFACT_SIGNING_ACCOUNT=<account>
export MIZ_ARTIFACT_SIGNING_PROFILE=<profile>

# Add these arguments to either architecture's command:
--uki-sign-command "$PWD/zig-out/bin/miz" \
--uki-sign-command-arg sign
```

The external command must be absolute. Local-key and external-command modes
are mutually exclusive. Private signing material is never copied into the
guest.

Image phase timing is opt-in. Add `--timing-output <path>` to a complete build
to atomically write JSON without changing normal stdout. The option is
disabled by default; timing-file serialization, write, and rename failures
fail the build rather than being ignored.

The stable `miz-ubuntu2604-image-phase-timing` schema has
`schema: 1`, `clock: "monotonic"`,
`duration_unit: "nanoseconds"`, an overall `status`, optional
`failed_phase`/`failed_item`/`error_name`, and an execution-ordered `phases`
array. Each phase record contains `name`, optional `item`, `elapsed_ns`,
`outcome` (`success`, `failure`, or `skipped`), and optional `error_name`.
Phase names are:

- `input_acquisition` (pinned publication inputs and signing configuration)
- `source_qcow2_setup` (source copy, QCOW2 creation, and requested growth)
- `debz_transaction` (one resolve/apply transaction per package root, named by
  `item`)
- `debz_aggregate` (root export, trusted keyring and pinned snapshot setup,
  and all nested transactions)
- `initramfs_ext4_import` (offline-root finalization and mountless ext4 import)
- `uki_assembly` (boot-input extraction and unsigned UKI generation)
- `uki_signing` (signer preparation, signing, and signature verification)
- `qcow2_finalization` (UKI insertion, compression, and structural validation)
- `final_image_validation` (final guest identity and package checks)
- `raw_image_materialization` (recorded as skipped without `--raw-output`)
- `provenance_output`
- `total_runtime`

For example:

```console
sudo -E zig build \
  -Dubuntu2604-arch=aarch64 \
  -Dubuntu2604-flavor=baremetal \
  generalized-ubuntu2604 -- \
  ... \
  --timing-output artifacts/aarch64-baremetal/image-timing.json
```

### Repeatable bare-metal image benchmark

`scripts/ubuntu2604_image_benchmark.zig` is the opt-in host benchmark for issue
#550, built as `zig-out/bin/ubuntu2604-image-benchmark` by
`zig build install-ubuntu2604-image-benchmark`. It is deliberately not part of
normal CI. The profile is fixed to the
pinned 20260731 Ubuntu 26.04 source, `aarch64`, `baremetal`, the exact 5 GiB
size, and `ReleaseSafe`. It performs one warm-up and exactly three measured
runs. Every run has a fresh work and output directory; only the explicitly
named debz content-addressed cache, fixed package locks, and Zig compilation
cache are reused. Every production-builder invocation also uses the fixed
`artifact/Ubuntu-26.04-aarch64.baremetal.raw` path, so the measured interval
includes the required `raw_image_materialization` phase rather than recording
it as skipped.

Prerequisites:

- a native `aarch64` Ubuntu host running as root, because package scripts run
  in the architecture-matched offline root;
- Zig 0.16.0, `file`, and the aarch64 `systemd-boot-efi` stub;
- the pinned Canonical image, `SHA256SUMS`, detached signature, and arm64
  manifest with the hashes listed above;
- the seven exact arm64 lock files emitted by a previously successful
  bare-metal build, named
  `debz-exact-lock-<package>-arm64.json`;
- the corresponding warm debz cache. The runner hashes every CAS object,
  verifies that its filename is its SHA-256, and proves that every package
  hash in every supplied lock is present before starting. All image runs pass
  `--offline`; a missing metadata or package object makes the run invalid
  instead of adding network time;
- an administrator public key plus appropriate UKI certificate and either
  local-key or production external-signer inputs; and
- at least 30 GiB free on the benchmark filesystem. A complete run requires
  substantial additional time and host I/O.

Create the cache and lock inputs once with a successful, reviewed online build.
Keep that build's `work/debz-cache`, copy all seven
`internal-provenance/debz-exact-lock-*-arm64.json` files into one immutable
lock directory, and retain the verified source files from its work directory.
The benchmark never refreshes those inputs. The builder options
`--debz-cache`, `--debz-lock-dir`, and `--offline` exist so the measured runs
consume those exact inputs without a symlink or ambient network fallback.

Invoke the benchmark from a clean checkout at the commit being measured, using
the tool built from that same checkout. The output root must not already exist:

```console
zig build install-ubuntu2604-image-benchmark
sudo -E zig-out/bin/ubuntu2604-image-benchmark run \
  --output-root /data/miz-benchmarks/ubuntu2604-baremetal-<commit> \
  --source /data/miz-inputs/ubuntu-26.04-server-cloudimg-arm64.img \
  --sha256sums /data/miz-inputs/SHA256SUMS \
  --sha256sums-signature /data/miz-inputs/SHA256SUMS.gpg \
  --manifest /data/miz-inputs/ubuntu-26.04-server-cloudimg-arm64.manifest \
  --debz-cache /data/miz-inputs/debz-cache \
  --debz-lock-dir /data/miz-inputs/baremetal-locks \
  --authorized-key /data/miz-inputs/id_ed25519.pub \
  --uki-stub /usr/lib/systemd/boot/efi/linuxaa64.efi.stub \
  --signing-certificate /data/miz-inputs/signing-certificate.pem \
  --signing-certificate-sha256 <canonical-DER-SHA-256> \
  --sign-command /absolute/path/to/miz \
  --sign-command-arg sign \
  --zig /absolute/path/to/zig-0.16.0 \
  --zig-global-cache /data/miz-inputs/zig-global-cache
```

For a local benchmark identity, replace `--sign-command` and its argument with
`--signing-key /absolute/path/to/key`. An optional executable
`--acceptance-command` can run a host-specific physical-machine boot harness;
it receives the candidate in `MIZ_UBUNTU2604_IMAGE`. This repository
currently has no bare-metal boot harness, so the default evidence records that
fact while still running the builder's final guest/filesystem checks plus
`miz check` and `miz info`. Full/core same-architecture QEMU acceptance is not applied
to a different product flavor.

Each run retains timing JSON, host wall/user/system and resource counters,
build/check logs, source manifest, exact locks, transaction and signing
provenance, boot-input evidence, QCOW2 and raw image metadata, package
name/version/hash closure, and a run manifest. The raw output must be a
non-symlink regular file with an exact 5 GiB size and must pass the applicable
native `miz check` and `miz info` validation after the measured builder
process exits. Linux `/proc` descendant sampling supplies available read/write
byte counters; block input/output counters come from `getrusage`. After all
validation and cross-run correctness comparison for a run, cleanup removes
only its exactly resolved `work` directory, QCOW2, and raw output. Use
`--keep-images` only when both large candidates are needed for separate
inspection.

`benchmark-summary.json` and `benchmark-summary.txt` report medians for every
phase, total time, wall/user/system time, peak RSS, I/O, and correctness.
Package closure, provenance/manifest contracts, filesystem/image constraints,
boot-input evidence, and acceptance result must match the warm-up reference.
QCOW2 SHA-256 values and raw structural metadata are retained as evidence.
Raw byte hashes are not computed, and no image bytes are compared: bare-metal
output has no documented byte-identical reproducibility contract.

The historical 8m50s ReleaseSafe result remains the non-regression ceiling
until this protocol is run on the designated production benchmark host. Do
not record a replacement baseline from a different architecture, cold cache,
unreviewed lock set, or incomplete signing/boot environment.

The manual **Benchmark Ubuntu 26.04 aarch64 image** workflow makes this
protocol reproducible on the repository's `ubuntu-24.04-arm` hosted runner.
It is dispatch-only, restricted to the current `main` commit, and has only
read access to repository contents. Before measurement it uses the production
builder once with networking to acquire and verify the pinned Canonical
publication, resolve all seven exact locks, and populate the content-addressed
debz cache. It then deletes that staging image and all mutable staging state,
checks that at least 30 GiB is free, and runs the benchmark inside a new
network namespace. Thus the required warm-up and three measured builds cannot
reach the network and consume only the verified source, exact locks, and warm
cache from the staging build.

The workflow uses the repository's public test-only UKI signing fixture for
one fixed signing identity across the complete session and a newly generated
administrator SSH key. Neither private key is included in artifact paths, an
explicit content scan rejects private-key material before upload, and all key
copies are removed in the unconditional cleanup step. The uploaded artifact
contains the summary, phase/resource timings, exact input/cache/lock
inventories, provenance, validation logs, staging evidence, and an explicit
8m50s non-regression gate, including partial evidence after a failure.

The workflow runs no interpreter of its own: its staging check, its
non-regression gate, and that private-material scan are the
`verify-staging`, `gate`, and `scan-private-material` subcommands of the same
benchmark tool, so each contract is unit tested rather than embedded in a job
step. That tool is built immediately after the Zig toolchain is installed and
before every preflight that can fail, so a runner that is too small, missing a
host dependency, or carrying the wrong Zig version still reaches the gate, the
evidence scan, and the artifact upload instead of losing its partial evidence.

GitHub's standard hosted ARM image carries many unrelated preinstalled tool
stacks. The workflow removes only disposable hosted-runner tool directories
before installing its pinned dependencies, requires at least 36 GiB free
before the staging build, and rechecks the benchmark's 30 GiB minimum after
staging data is pruned. A runner image that cannot meet either threshold fails
before a measured run instead of weakening the storage contract.

There is no repository bare-metal boot harness. The full/core same-architecture QEMU
acceptance suite intentionally rejects this different flavor, so the workflow
does not claim boot acceptance. It runs the benchmark's production
filesystem, package-closure, provenance, signature, QCOW2, and raw-image
validation. Physical-machine boot acceptance remains a separate optional
`--acceptance-command` input when such a harness becomes available.

Because `workflow_dispatch` definitions are loaded from the default branch,
review and merge the workflow before triggering it. Do not run a branch copy
or treat the networked staging build as a benchmark result.

#### Raw-materialization optimization evidence

The source-allocation-unit raw-copy change was also measured locally before
merge because the production benchmark requires native aarch64. This is
supporting evidence for the exact `miz.copyAll` implementation called by
`writeRawCopy`, not a replacement production result and not evidence that the
8m50s gate has passed.

The deterministic fixture had a 5 GiB virtual size and 64 KiB QCOW2 clusters.
Its four equal virtual-size quarters were dense data, one allocated cluster in
four, one allocated cluster per 4 MiB, and all zero. The resulting QCOW2 was
1,699,610,624 logical bytes. On x86_64 Linux 6.18/XFS, an Intel Xeon Platinum
8370C, and Zig 0.16.0 ReleaseSafe, one warm-up was followed by five measured
runs with the source resident in the page cache:

| Median / result | Before | After |
|---|---:|---:|
| wall time | 5.242s | 2.542s |
| user CPU | 1.533s | 1.053s |
| system CPU | 1.558s | 0.789s |
| output blocks written (512-byte units) | 7,864,320 | 3,317,760 |
| raw allocated bytes | 4,026,531,840 | 1,698,787,328 |

The raw logical size remained exactly 5,368,709,120 bytes, and both versions
had SHA-256
`468fc8eeefff28eafb559ec48d50e441f48d769cb717cdf25fd4a6f2fd053672`.
Thus the local median improved by 51.5% while output I/O fell by 57.8%.
Focused tests additionally cover allocated zero and unallocated QCOW2
clusters, a partial final cluster, exact content and size, and undersized
destination failure. The native aarch64 production benchmark must still
confirm the whole-image effect.

Without overrides, outputs are written in the current directory. Full work is
cached under `.scratch/ubuntu2604-x86_64` or
`.scratch/ubuntu2604-aarch64`; core uses the corresponding `-core` suffix. A
provenance directory contains the verified `SHA256SUMS`, signature,
architecture manifest, `ubuntu2604-build-provenance.json`,
`uki-signing-<flavor>-<architecture>.json`, and exact-lock plus transaction
provenance files for every flavor-specific package root.

The build validates the source chain before modification and revalidates the
final QCOW2, GPT partitions, Ubuntu identity, package inventory, UKI locations,
PE architecture, and signature. Both workflows additionally use native
`miz check` and `miz info` to require zstd compression and no backing file,
bind every provenance sidecar into `candidate.json`, and reject private-key
material. External `qemu-img` remains confined to acceptance-time inspection
and the Azure fixed-VHD conversion boundary.

### Local end-to-end release gate

A protected release build must never be dispatched before the corrected
candidate has been built and validated locally. `scripts/ubuntu2604_local_e2e.sh`
runs the strongest feasible local reproduction: it drives the exact release
builder entrypoint (`zig build generalized-ubuntu2604`) through base-image
acquisition and signature verification, embedded debz customize, native UKI
assembly, UKI signing, and standalone zstd QCOW2 finalization, then validates
the finalized candidate exactly as the release workflow does (`miz check` plus
`miz info --output=json` asserting `qcow2`, an exact 5 GiB virtual size, no
backing file, and zstd cluster compression).

The only deviation from the protected workflow is the signing identity: instead
of the Azure Trusted Signing command, the gate signs with a safe, public,
test-only self-signed key/cert committed under
`tests/fixtures/ubuntu2604-local-signing/` (certificate DER SHA-256
`8ca3b80b1a2272a4f3a6d13246a65cfdd89764eb83beb8a0709e3cf591490279`). Those
fixtures are guarded deterministically by `zig build test-generalized-ubuntu2604`
(the test loads them through the native local-key path and verifies a signature
against the enrolled certificate), so a corrupted or mismatched fixture fails
before any multi-gigabyte build.

```console
ZIG=$(command -v zig) SEED_CACHE="$HOME/.cache/zig" \
  scripts/ubuntu2604_local_e2e.sh x86_64
```

The driver isolates its privileged (`sudo`) build in an in-tree
`.zig-global-cache`, writes the candidate and provenance under
`.scratch/local-e2e/<arch>/`, and restores ownership afterward. It prints the
finalized candidate size, SHA-256, and the validated `image-info.json` path.

A full arm64 image build is only reproducible on a host with the aarch64
systemd-boot stub (`/usr/lib/systemd/boot/efi/linuxaa64.efi.stub`); on an
x86_64 host it is not. The arm64 resolve→customize transition that failed in
production is instead covered deterministically and offline by
`zig build test-package-family` (the arm64 exact-lock handoff through the
package-family boundary) and by debz's `production_backend_customize_test.zig`
(the real backend provisioning the absent `var/lib/debz` lock root). Run the
full arm64 gate (`scripts/ubuntu2604_local_e2e.sh aarch64`) only on a matching
aarch64 runner.

## Acceptance infrastructure

Same-architecture QEMU acceptance is accelerator-explicit and fail-closed.
Both `x86_64` legs remain on the `ubuntu-24.04` hosted runner and retain the
existing KVM contract unchanged: `/dev/kvm` must be present, readable, and
writable; the accepted-source release tool must confirm the stable KVM API;
QEMU uses OVMF, `q35,accel=kvm`, and `-cpu host`; and no software fallback is
permitted.

Both AArch64 legs run only on the exact GitHub-hosted `ubuntu-24.04-arm`
label. Before checkout they require Ubuntu on `uname -m == aarch64` and Debian
`arm64`, then install the native `/usr/bin/qemu-system-aarch64`,
Secure-Boot-capable AAVMF, `swtpm`, `qemu-img`, `sbverify`, and OpenSSH. QEMU
is launched explicitly with `-machine virt`, `-accel tcg,thread=multi`, and
`-cpu max`. The Arm path never examines or changes `/dev/kvm`, never calls the
KVM API check, never probes for another accelerator, and never routes the
guest through an x86_64 runner.

This is an intentional provider-limitation contract change for
[#626](https://github.com/cataggar/miz/issues/626) and
[#627](https://github.com/cataggar/miz/issues/627): neither GitHub-hosted Arm
runners nor an Azure-hosted CI alternative supplies Arm64 KVM. Azure Trusted
Launch acceptance remains mandatory for all four candidates and supplies the
real Arm platform evidence; TCG replaces only the unavailable local Arm KVM
leg.

The KVM profile retains its existing 180-minute job ceiling and per-operation
wait limits.
Only the TCG rows receive a bounded 360-minute job ceiling and larger QMP,
boot/reboot/shutdown, SSH-command, and tampered-UKI waits. Every bound still
terminates with failure and serial, QMP, SSH, or swtpm diagnostics rather
than changing accelerator or treating an unknown
state as success.

The two initial identities are still provisioned from independent overlays,
variable stores, seed media, and SSH keys. KVM rows continue to launch both
initial guests concurrently. For AArch64 TCG only, the first Arm TCG guest
reaches and passes the same SSH, key-only login, flavor runtime, required
service, and no-failed-unit checks before the second guest is launched. This
keeps systemd's own bounded service-start deadlines meaningful on a
CPU-constrained hosted runner without weakening any uniqueness, persistence,
reboot, or service-health assertion.

Each QEMU result records an exact execution object containing accelerator,
emulator, guest architecture, runner architecture, machine, and CPU. The
canonical validator requires `/usr/bin/qemu-system-x86_64`, x86_64, `q35`,
`host`, and `kvm` for x86_64; and `/usr/bin/qemu-system-aarch64`, AArch64,
`virt`, `max`, and `tcg` for Arm. Missing, stale, malformed, swapped,
`auto`, or unknown execution identities cannot satisfy either validation
gate. This binding is full-result schema 3 and core-result schema 8.

Both profiles enroll the exact candidate leaf in UEFI `db` and assert the
standalone GPT image, Secure Boot, signed UKI, vTPM, lockdown, signed modules,
rejection of a tampered UKI, key-only SSH, provisioning, root growth,
generalized and persistent unique identity, service/SSH supervision,
reboot/reconnect, shutdown, and the flavor-specific Binder and DMA-heap
contracts.

Per-instance Secure Boot variable stores are created natively by
`miz.efi_varstore`, the same EDK II variable-store parser and editor
`miz qemu --secure-boot` uses, so no firmware-variable host package is
installed. `qemu-utils` remains in QEMU acceptance for candidate inspection
and in Azure acceptance for the documented fixed-VHD conversion boundary.

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

Core acceptance adds the mizinit PID-1 and SSH-supervision contract, local
OVF `azagent --skip-ready`, Azure Ready reporting, provisioning and identity
persistence, resource-disk formatting, managed-data-disk mount-only behavior,
and explicit absence of cloud-init, WALinuxAgent, and a systemd service
manager.

Same-architecture QEMU core acceptance additionally asserts a Binder workload
contract set under Secure Boot/lockdown: the in-tree `binder_linux` module is loaded at
boot from the pinned Ubuntu module tree (not `updates`/DKMS), carries signer
evidence and no taint, and dmesg has no unsigned-module, lockdown, or
out-of-tree binder implementation failures; binderfs is mounted with a
`binder` filesystem type and dynamically creates `binder-control` plus the
`binder`, `hwbinder`, and `vndbinder` devices; and a tiny statically linked,
architecture-neutral probe opens each of those devices and performs
`BINDER_VERSION` to confirm usability rather than only checking paths. These
contracts bumped the core-only QEMU result schema so an older result cannot
satisfy them. They require the image itself to provide boot-time module
autoload, the binderfs mount, and dynamic device creation before acceptance
starts any workload.

Core Azure acceptance additionally verifies the official in-tree Binder IPC
module (`binder_linux`) under Secure Boot and lockdown: it must load from
under `/lib/modules`, never from a DKMS/out-of-tree path, carry a non-empty
`PKCS#7` signer, and be untainted, with no Anbox-style evidence anywhere in
module metadata, loaded-module state, `dkms status`, or the boot log.
Acceptance then asserts binderfs is mounted and that `binder-control`,
`binder`, `hwbinder`, and `vndbinder` exist as dynamic character devices, and
proves real device usability by transferring a small static probe binary
(`tests/binder_probe.zig`, matched to the candidate's own architecture) over
SSH, verifying its checksum, and using it to query the fixed devices and
allocate and query a new dynamic Binder device through `binder-control`.

### Self-contained Binder and DMA-heap acceptance

Core QEMU and Azure acceptance directly require the signed in-tree
`binder_linux` module, BinderFS, usable fixed and dynamically allocated Binder
devices, and the `/dev/dma_heap/system` character device. These checks use only
the candidate image and public in-repository probe source. Acceptance does not
fetch, transfer, unpack, execute, or attest any external runtime or bundle
input, and it requires no repository secret for these core device contracts.
The self-contained contract is QEMU core result schema 8, Azure core result
schema 3, and core validation manifest schema 3. Exact-field validation
rejects older documents that carry removed smoke evidence.

## Core validation workflow

`.github/workflows/ubuntu2604-core-validation.yml` is a separate manually
dispatched workflow restricted to `main`. It uses the same protected
`ubuntu2604-signing` and `ubuntu2604-release` environments and OIDC subjects
described below, with serialized non-cancelling concurrency. No tag is
required.

The workflow builds and signs exactly `x86_64-core` and `aarch64-core`, then
requires x86_64 KVM QEMU, AArch64 TCG QEMU, and both Azure Trusted Launch
jobs. Candidate reuse accepts only a completed manual run of this same
workflow at the exact current remote `main` commit and exact run attempt, with
both named build jobs successful and exactly two nonempty, unexpired candidate
artifacts.

The final gate accepts exactly two candidates, two candidate-key-and-digest
bound QEMU results, and two Azure results. Its validation manifest records
the candidate manifest, QEMU result, and Azure result digests for both
`x86_64-core` and `aarch64-core`; missing, duplicate, cross-key,
cross-architecture, or cross-digest evidence fails closed.

The core Azure acceptance jobs also build the Binder device usability probe
from source for the matching guest architecture before running acceptance,
so no prebuilt probe binary is stored or published.

Candidates, QEMU results, Azure results, and a final digest-bound
two-architecture validation manifest are uploaded only as workflow artifacts.
The workflow has no publish job, release command, tag contract, release asset,
or catalog mutation. It remains a non-publishing preflight for the core
contracts; the release workflow independently requires its own exact four
candidates and reruns both acceptance paths, so preflight evidence cannot
bypass a publication gate.

## Four-asset release workflow

`.github/workflows/ubuntu2604-release.yml` is manually dispatched from `main`
and publishes exactly full/core × x86_64/AArch64. Before dispatch:

1. Create or retarget the required tag `Ubuntu-26.04-20260829` to the exact
   current `main` commit. Lightweight and annotated tags are accepted; force
   push the tag when it already exists, then verify the remote resolves to the
   current `main` commit before dispatch. Mutation is permitted only while the
   release is being iterated on 2026-08-29; after final publication the tag,
   assets, URLs, and digests are immutable.
2. Confirm the exact GitHub-hosted `ubuntu-24.04-arm` label is available.
   Publication cannot proceed without both `aarch64-full` and `aarch64-core`
   Secure Boot acceptance jobs using native Arm64
   `/usr/bin/qemu-system-aarch64` with explicit
   `-accel tcg,thread=multi`; no Arm KVM or self-hosted runner is part of this
   contract.
3. Configure protected environment `ubuntu2604-signing`, restricted to
   `main` and requiring reviewers, with variables
   `MIZ_AZURE_TENANT_ID`, `MIZ_AZURE_CLIENT_ID`,
   `MIZ_ARTIFACT_SIGNING_ENDPOINT`, `MIZ_ARTIFACT_SIGNING_ACCOUNT`, and
   `MIZ_ARTIFACT_SIGNING_PROFILE`.
4. Configure protected environment `ubuntu2604-release` the same way, with
   secrets `AZURE_CLIENT_ID`, `AZURE_TENANT_ID`,
   `AZURE_SUBSCRIPTION_ID` and variables `AZURE_LOCATION_X64`,
   `AZURE_LOCATION_ARM64`, `AZURE_VM_SIZE_X64`, and
   `AZURE_VM_SIZE_ARM64`.
5. Configure both Entra federated credentials with issuer
   `https://token.actions.githubusercontent.com` and audience
   `api://AzureADTokenExchange`. Their subjects are respectively
   `repo:cataggar/miz:environment:ubuntu2604-signing` and
   `repo:cataggar/miz:environment:ubuntu2604-release`.

Top-level permissions are `actions: read` and `contents: read`. Signing and
Azure acceptance add only `id-token: write`; QEMU acceptance remains
read-only. Publication uses `actions: read` and `contents: write`.

The prepare gate binds the run to the current remote `main` commit and tag.
An optional `candidate_run_id` may reuse only a completed manual run on
`main` for that same commit and exact run attempt. All four named build jobs
must have succeeded and exactly four non-expired, nonempty candidate artifacts
must match the commit and attempt. Reused candidates still rerun QEMU and
Azure acceptance.

The build matrix passes flavor explicitly. Full candidates retain the exact
5 GiB virtual-size contract; core remains exactly 3584 MiB, or 3.5 GiB and 30%
smaller. Every leg records host capacity before the build, preserves the #611
post-failure `df`/largest-path diagnostics, and unconditionally removes
privileged build state and signing material.

Publication requires four successful build candidates, exactly one valid
QEMU result per candidate, and exactly one Azure result per candidate. Each
result binds the key, architecture, flavor, asset name, source commit, virtual
size, candidate/certificate/UKI digests, explicit success, complete
flavor-specific contract set, exact
accelerator/emulator/guest/runner/machine/CPU identity, and exact workflow
attempt. Missing, extra, duplicate, stale, malformed, cross-key,
cross-architecture, cross-digest, wrong-signer, wrong-UKI, wrong-source/run,
or unsuccessful evidence fails before publication. Core result schemas are
versioned independently so documents carrying removed fields fail closed.

The release stages exactly four standalone zstd QCOW2 files with no backing
images. Publication creates or resets the release as a draft, uploads with
clobber, deletes every stale asset outside the four-name allowlist, and
verifies the remote draft's exact names and sizes. It then redownloads all four
assets and verifies each size and SHA-256 before making the release non-draft,
followed by one final exact remote allowlist check. On publication failure the
release remains a draft; cleanup removes local staging, candidates, derived
VHDs, credentials, and only ownership-tagged Azure resources.

## Catalog aliases

The full aliases from immutable release `Ubuntu-26.04-20260822` remain pinned
exactly as documented above and are not mutated in place. After the
`Ubuntu-26.04-20260829` workflow completes successfully, a separate catalog
handoff must rotate the full entries and add both core entries using the real
final asset URLs, SHA-256 digests, and signing-certificate fingerprint.

Do not substitute build-time guesses, acceptance-time intermediate values, or
digests copied from the older release. Until those final pins land,
`miz qemu Ubuntu --model core` stays fail-closed; explicit image paths require
independent Secure Boot trust material as described in [QEMU](qemu.md).
