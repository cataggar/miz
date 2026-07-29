# QEMU

Use `zvmi qemu` to acquire and boot cataloged Azure Linux and FreeBSD images
with architecture-matched QEMU and firmware. See
[Azure Linux images](azure-linux.md) for the full/core image comparison and
release security model.

The same installation is what the `vm` customization backend runs guests in,
including guests of an architecture the host cannot execute: one
`cataggar/qemu` install supplies every `qemu-system-*` and both the OVMF and
AAVMF firmware families. That backend needs an *absolute* emulator path rather
than a name on `PATH`, so provenance records the exact binary that ran:

```text
ghr install cataggar/qemu@v11.0.91-z.15
readlink -f "$(command -v qemu-system-aarch64)"
```

`readlink -f` matters: it resolves the shim ghr links into `~/.local/bin` to
the binary inside the extracted tree, and QEMU locates its ROMs relative to its
own path. See [Library API](library-api.md) for the backend itself.

## Booting the release image with QEMU

Install QEMU once through ghr:

```text
ghr install cataggar/qemu
```

Then run the command from the directory where the VM disk should live:

```text
zvmi qemu AzureLinux
zvmi qemu AzureLinux --model core
zvmi qemu AzureLinux-4.0-x86_64
zvmi qemu FreeBSD
zvmi qemu FreeBSD --arch x86_64
```

The `AzureLinux` short alias selects the host-native catalog image: AArch64
on AArch64 hosts and x86_64 otherwise. The default model is `full`;
`--model core` selects the matching `*.core.qcow2` asset. Model selection
applies to catalog aliases, while an explicit image path remains authoritative.
If the selected image is absent, `zvmi` runs the verified ghr download for its
pinned `AzureLinux-4.0-20260723` release asset.
The `FreeBSD` alias similarly selects the host-native FreeBSD 15.1 image from
release `FreeBSD-15.1-20260724`; on an AArch64 host it downloads
`FreeBSD-15.1-aarch64.qcow2`.
Existing images are never refreshed or overwritten. QEMU and its matching
EDK2 firmware are resolved from the `cataggar/qemu` ghr installation first,
then from a system QEMU/UEFI installation. Directory-prefixed aliases such as
`zvmi qemu images/AzureLinux` or
`zvmi qemu images/AzureLinux-4.0-x86_64` place the downloaded disk and
firmware under that directory.

`FreeBSD` selects the pinned FreeBSD 15.1 release asset for the requested
architecture. It defaults to the host architecture; for example, an ARM64 host
runs the x86_64 image through TCG when explicitly requested:

```text
zvmi qemu FreeBSD --arch x86_64
```

When administrator provisioning is requested, cataloged FreeBSD images receive
the NoCloud seed as a read-only VirtIO block device, matching their release
acceptance configuration.

The published Azure Linux images use the signed direct UKI boot path described in
[Azure Linux images](azure-linux.md). Secure Boot is opt-in:

```text
zvmi qemu AzureLinux --secure-boot
zvmi qemu AzureLinux-4.0-aarch64 --secure-boot
```

This mode requires `virt-fw-vars` from `python3-virt-firmware` and
architecture-appropriate Secure-Boot-capable OVMF or AAVMF. The catalog pins
both the release asset SHA-256 and the canonical-DER SHA-256 of the exact Azure
Artifact Signing leaf. Before first enrollment, `zvmi` verifies the pristine
catalog image digest, extracts the signer from every fallback and named UKI,
and requires that signer to match the catalog fingerprint. It then appends
only that leaf to the Microsoft-enrolled variables template. It never enrolls
the shared intermediate or root and never retries with Secure Boot disabled.

An explicit image that is not a matching catalog entry requires independent
trust material:

```text
zvmi qemu custom.qcow2 --secure-boot \
  --secure-boot-certificate release.pem \
  --secure-boot-certificate-sha256 <canonical-DER-SHA-256>
```

The PEM must contain exactly one certificate. Its canonical DER fingerprint
and bytes must match the signer embedded in every UKI. Certificate options are
rejected without `--secure-boot`, and extra QEMU arguments are rejected in
Secure Boot mode so they cannot replace the machine or firmware contract.

`--architecture x86_64|aarch64` selects q35/OVMF or virt/AAVMF respectively;
`--arch` is its shorter alias. `--architecture auto` requires an unambiguous
architecture-bearing GPT root/USR GUID or UKI PE header. `AzureLinux` and
`FreeBSD` select host-native catalog images by default; an explicit `--arch`
selects that architecture instead. Exact catalog aliases select their
corresponding architecture.

Inside a full image, equivalent manual checks are `mokutil --sb-state`, `mokutil --db`, `mokutil --dbx`, `cat /sys/kernel/security/lockdown`, and `sudo dmesg | grep -Ei 'secure boot|lockdown|module verification'`. Release acceptance parses the EFI variables directly so the core image does not need `mokutil`.

Before launch, the command creates or reuses a complete image-adjacent bundle:

```text
AzureLinux-4.0-x86_64.qcow2
AzureLinux-4.0-x86_64.code.fd
AzureLinux-4.0-x86_64.vars.fd
```

Secure Boot uses separate state and never modifies the ordinary variables
bundle:

```text
AzureLinux-4.0-x86_64.secboot.vars.fd
AzureLinux-4.0-x86_64.secboot.vars.json
```

The metadata binds persistent Secure Boot state to the enrolled leaf.
Cataloged disks may change during persistent guest use after initial
digest-bound enrollment, but every subsequent launch still requires the
pinned embedded signer. `zvmi` also recreates the expected enrollment from the
selected Microsoft template and requires the persistent PK, KEK, and complete
`db` contents to match before reuse.

QEMU and matching EDK2 firmware are resolved from the `cataggar/qemu` ghr
installation first, then from a system QEMU/UEFI installation. Missing bundle
firmware is copied from raw sources or decompressed from `.fd.bz2` sources.
The installed QEMU package is never changed.

The default boot is persistent: QEMU writes directly to the image and its
`.vars.fd` guest UEFI state. Secure Boot launches the verified image inode
through a temporary, validated hard link so replacing the original pathname
cannot substitute different bytes between verification and QEMU open. Guest
writes still reach the original inode and the temporary link is removed after
QEMU exits.

Use snapshot mode when guest changes should be discarded:

```text
zvmi qemu AzureLinux --snapshot
```

Snapshot mode uses the sibling `qemu-img` binary to create a temporary qcow2
overlay and creates temporary UEFI variables directly from the pristine
firmware source, not from persistent `.vars.fd` or `.secboot.vars.fd` state.
Secure Boot snapshots enroll the same verified leaf into that temporary
template. `zvmi` removes both when QEMU exits. The automatic accelerator is
WHPX for x86_64 Windows, HVF for same-architecture macOS guests, KVM for
same-architecture Linux guests when `/dev/kvm` is available, and TCG for
cross-architecture or otherwise unaccelerated guests. Override it when needed:

```text
zvmi qemu AzureLinux --accel tcg
```

An explicit image path must already exist. Without an architecture option it
keeps the x86_64 default; exact Azure Linux catalog filenames select their
corresponding architecture, `FreeBSD` selects the requested catalog
architecture, and `aarch64` or `auto` can be used for other Arm64 images:

```text
zvmi qemu ./AzureLinux-4.0-x86_64.qcow2
zvmi qemu custom.qcow2
```

The AArch64 profile is already wired for `qemu-system-aarch64`, `virt`, and
AArch64 EDK2 firmware:

```text
zvmi qemu AzureLinux-4.0-aarch64
```

The exact `AzureLinux-4.0-aarch64.qcow2` asset is downloaded from release
`AzureLinux-4.0-20260723` when it is not already present.

Use `--qemu`, `--firmware-code`, and `--firmware-vars` (or the compatible
`--ovmf-code`/`--ovmf-vars` names) for non-standard installations. Arguments
after `--` are appended directly to QEMU. The terminal is attached to
QEMU's `-nographic` serial console; use QEMU's `Ctrl+A`, then `X`, escape to
exit. With the default secure command line, a successful local boot reaches
the full image's systemd startup and login prompt. It does not emit
`zvminit` readiness markers.

Those markers apply only when a core image is selected with `--model core` or
an explicit `*.core.qcow2` path. A successful unprovisioned core boot reports
that automatic Azure detection is still pending, the diagnostic root shell is
disabled, and the `ZVMINIT_PID1_READY supervisor loop active` marker.

Core images have no default login, username, or password. To log in locally,
launch with `--admin-username <name> --ssh-public-key <path>` and SSH to that
username through the forwarded localhost port (default `2222`).

To provision an administrator at launch, supply
`--admin-username <name> --ssh-public-key <path>` together. `--ssh-port`
(default `2222`) forwards localhost TCP to guest SSH. The command creates a
short-lived hybrid `cidata` ISO containing NoCloud metadata/user-data, Azure
`ovf-env.xml`, and the explicit `zvmi-local-provisioning` marker, then removes
the seed and temporary launch state when QEMU exits.

This command is intentionally a focused launcher for cataloged Azure Linux and
FreeBSD Gen2 images plus compatible explicit disks, not a general VM
configuration manager.
