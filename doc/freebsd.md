# FreeBSD images

## Generalized FreeBSD 15.1 QCOW2 images

`zvmi qemu FreeBSD` selects the host-native FreeBSD 15.1 image from release
`FreeBSD-15.1-20260724`; use `--arch x86_64|aarch64` to override the host
architecture.

The FreeBSD builder supports AArch64 and x86_64 UFS images. It downloads the
matching official FreeBSD 15.1-RELEASE BASIC-CLOUDINIT QCOW2, verifies its
pinned compressed SHA-256, and decompresses it with explicit memory and output
limits. A private mutable QCOW2 is booted under architecture-matched UEFI QEMU
with a nonce-bound NoCloud seed.

Guest customization installs the pinned `azure-agent-2.15.0.1` package, enables
SSH and generic `vtnet*` plus Azure `hn0` DHCP, applies FreeBSD's official Azure
multi-console/115200-baud serial settings, removes OS-disk swap, locks root,
removes the default `freebsd` user, deprovisions waagent, and clears guest
identity during a normal shutdown. Only an authenticated success marker
followed by a clean QEMU exit permits transactional publication as a standalone
zstd-compressed QCOW2.

```text
zig build generalized-freebsd15 -- \
  --architecture aarch64 \
  --work-dir /path/to/aarch64-cache \
  --output /path/to/FreeBSD-15.1-aarch64.qcow2

zig build generalized-freebsd15 -- \
  --architecture x86_64 \
  --work-dir /path/to/x86_64-cache \
  --output /path/to/FreeBSD-15.1-x86_64.qcow2
```

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
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-aarch64.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-aarch64 \
zig build test-freebsd15-boot

ZVMI_FREEBSD15_ARCHITECTURE=x86_64 \
ZVMI_FREEBSD15_IMAGE=/path/to/FreeBSD-15.1-x86_64.qcow2 \
ZVMI_FREEBSD15_QEMU=/usr/bin/qemu-system-x86_64 \
zig build test-freebsd15-boot
```

The test boots two independent disposable overlays with fresh NoCloud seeds,
proves each injected SSH key works, verifies generalized
agent/network/swap/account/identity state, reboots and reconnects, and powers
off cleanly. Each guest's SSH host fingerprint and host UUID must remain stable
across its reboot, while both values must differ between guests.

The manually dispatched **Build, validate, and publish FreeBSD 15.1 images**
workflow runs each candidate on a native GitHub-hosted runner, caches its
digest-pinned upstream source, validates the standalone QCOW2, and runs
dual-instance acceptance. A separate publication job requires both candidates,
stages a draft, uploads exactly `FreeBSD-15.1-aarch64.qcow2` and
`FreeBSD-15.1-x86_64.qcow2`, verifies GitHub's asset digests and a fresh
download, and then publishes the non-Latest `FreeBSD-15.1-20260724` release.
SHA-256 values and complete source/build provenance are recorded in the release
notes; checksum sidecar assets are not published.

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
VHD tooling. ZFS and minimal core variants are tracked in issues
[#247](https://github.com/cataggar/zvmi/issues/247) and
[#248](https://github.com/cataggar/zvmi/issues/248).
