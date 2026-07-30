# FreeBSD images

## Generalized FreeBSD 15.1 QCOW2 images

`zvmi qemu FreeBSD` selects the host-native FreeBSD 15.1 image from release
`FreeBSD-15.1-20260724`; use `--arch x86_64|aarch64` to override the host
architecture.

The FreeBSD builder is driven by an explicit profile table indexed by
architecture, root filesystem, and flavor. Each profile pins its own upstream
source name, URL, compressed SHA-256, virtual size, and output asset name;
nothing is shared by coincidence, because the upstream UFS and ZFS images do
not even agree on virtual size. Selecting an unsupported combination fails with
`UnsupportedProfile` rather than falling back to a default.

| Architecture | Root | Flavor | Asset |
| --- | --- | --- | --- |
| aarch64 | ufs | full | `FreeBSD-15.1-aarch64.qcow2` |
| x86_64 | ufs | full | `FreeBSD-15.1-x86_64.qcow2` |
| aarch64 | zfs | full | `FreeBSD-15.1-aarch64.zfs.qcow2` |
| x86_64 | zfs | full | `FreeBSD-15.1-x86_64.zfs.qcow2` |

All profiles use the official BASIC-CLOUDINIT images so NoCloud provisioning
stays available. The builder downloads the profile's compressed QCOW2, verifies
its pinned SHA-256 (a mismatch is a hard `SourceChecksumMismatch` failure), and
decompresses it with explicit memory and output limits. A private mutable QCOW2
is then booted under architecture-matched UEFI QEMU with a nonce-bound NoCloud
seed.

Guest customization installs the pinned `azure-agent-2.15.0.1` package, enables
SSH and generic `vtnet*` plus Azure `hn0` DHCP, applies FreeBSD's official Azure
multi-console/115200-baud serial settings, removes OS-disk swap, locks root,
removes the default `freebsd` user, deprovisions waagent, and clears guest
identity during a normal shutdown. That generalized guest contract is identical
for every profile and is asserted per profile by the builder's unit tests.

Root storage handling is the one part that is deliberately *not* shared. The
UFS and ZFS seeds embed disjoint shell fragments:

- **UFS** asserts an `ufs` root, keeps `/etc/fstab`'s root entry, and relies on
  `rc.d/growfs` running `gpart resize` plus `growfs -y` on first boot.
- **ZFS** asserts a `zfs` root, pins and re-derives the `zroot` pool name,
  requires `zpool status -x` to report the pool healthy, sets
  `zpool autoexpand=on` so `rc.d/growfs`'s `zpool online -e` keeps working for
  later enlargements, sets `zfs_enable=YES` and `zpool_reguid="zroot"` so each
  fresh instance gets a distinct pool GUID, and destroys any swap zvol.

Both fragments disable swap and strip swap entries from `/etc/fstab`, but they
share no text; a unit test asserts the UFS fragment mentions no ZFS commands
and the ZFS fragment mentions no UFS commands, so a UFS assumption cannot leak
into the ZFS path unnoticed.

Only an authenticated success marker
followed by a clean QEMU exit permits transactional publication as a standalone
zstd-compressed QCOW2.

```text
zig build generalized-freebsd15 -- \
  --architecture aarch64 \
  --filesystem ufs \
  --work-dir /path/to/aarch64-ufs-cache \
  --output /path/to/FreeBSD-15.1-aarch64.qcow2

zig build generalized-freebsd15 -- \
  --architecture x86_64 \
  --filesystem zfs \
  --work-dir /path/to/x86_64-zfs-cache \
  --output /path/to/FreeBSD-15.1-x86_64.zfs.qcow2
```

`--filesystem` defaults to `ufs` and `--flavor` defaults to `full`; both, with
`--architecture`, select exactly one profile, whose defaults for `--output` and
`--work-dir` are used when those options are omitted.

The builder is Linux-only and requires Zig 0.16, `curl`, XZ Utils, `qemu-img`,
the architecture-matched `qemu-system` executable, `xorriso`, matching
EDK2/AAVMF or OVMF firmware, and outbound guest networking for signed FreeBSD
package installation. Use `--source` for a local official compressed image;
the pinned profile checksum remains required unless explicitly overridden with
`--source-sha256`. `--accel auto` uses KVM when the host architecture matches
the guest and `/dev/kvm` is accessible, and TCG otherwise. `--base-only`
retains the verified-base behavior without guest customization.

Run the opt-in dual-instance acceptance against either completed image:

```text
ZVMI_FREEBSD15_ARCHITECTURE=aarch64 \
ZVMI_FREEBSD15_FILESYSTEM=ufs \
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-aarch64.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-aarch64 \
zig build test-freebsd15-boot

ZVMI_FREEBSD15_ARCHITECTURE=x86_64 \
ZVMI_FREEBSD15_FILESYSTEM=zfs \
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-x86_64.zfs.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-x86_64 \
zig build test-freebsd15-boot
```

`ZVMI_FREEBSD15_FILESYSTEM` defaults to `ufs` and must match the image under
test, because the guest-side assertions are filesystem-specific.

The test boots two independent disposable overlays with fresh NoCloud seeds,
proves each injected SSH key works, verifies generalized
agent/network/swap/account/identity state, reboots and reconnects, and powers
off cleanly. Each guest's SSH host fingerprint and host UUID must remain stable
across its reboot, while both values must differ between guests; ZFS guests
additionally compare pool GUIDs, which `rc.d/zpoolreguid` regenerates once per
fresh instance.

Both overlays are created larger than the release asset's virtual size, so
first-boot growth is exercised on every run: the test requires the root
filesystem to have grown past the shipped size, `gpart show` to report no
`CORRUPT` GPT metadata, and every `gpart status` entry to read `OK`.

The manually dispatched **Build, validate, and publish FreeBSD 15.1 images**
workflow takes a `release_set` input that names exactly which assets a run may
publish:

| Release set | Tag | Assets |
| --- | --- | --- |
| `ufs` | `FreeBSD-15.1-20260724` | `FreeBSD-15.1-aarch64.qcow2`, `FreeBSD-15.1-x86_64.qcow2` |
| `zfs` | `FreeBSD-15.1-zfs-20260729` | `FreeBSD-15.1-aarch64.zfs.qcow2`, `FreeBSD-15.1-x86_64.zfs.qcow2` |

`scripts/freebsd15_release.py matrix` expands the selected set into the build
matrix and `describe` resolves its tag, title, and asset count, so the tag, the
allowlist, and the built variants can never disagree. Each candidate builds on
a native GitHub-hosted runner, caches its digest-pinned upstream source,
validates the standalone QCOW2, and runs dual-instance acceptance. A separate
publication job requires every candidate in the set, refuses candidates from
another set or another source commit, stages a draft, uploads exactly the
set's assets, verifies GitHub's asset digests and a fresh download, and then
publishes the non-Latest release. SHA-256 values and complete source/build
provenance are recorded in the release notes; checksum sidecar assets are not
published.

The released QCOW2 files are not directly uploadable to Azure. Derive aligned
fixed VHDs without changing their partitions:

```text
zvmi azure derive \
  --input-sha256 <release-note-sha256> \
  --expected-virtual-size <release-note-virtual-size> \
  FreeBSD-15.1-aarch64.qcow2 \
  FreeBSD-15.1-aarch64.vhd
```

The previous AArch64 build path was validated on an Azure Arm64 Gen2
`Standard_D2pls_v5` VM. Provisioning, `waagent`, injected-key SSH, `hn0` DHCP,
locked root, disabled swap, reboot identity, and managed serial output all
passed. Exact-candidate Azure validation for future multi-architecture releases
should be recorded separately from QEMU acceptance.

See [Image building](image-building.md) for the shared image-format and Azure
VHD tooling. Minimal core variants are tracked in issue
[#248](https://github.com/cataggar/zvmi/issues/248); they will add a second
`--flavor` value to the same profile table.
