# Image building

## Building images and current capabilities

Supports `raw`, fixed `vhd`, dynamic `vhd`, `vhdx`, `qcow2`, MBR/GPT partition tables,
native FAT32 filesystem read/write for ESP-style partitions, native ESP
bootloader population (copy prebuilt EFI binaries + generate `grub.cfg`/BLS
text), an Azure-readiness check, an ISO9660 (+Rock Ridge/Joliet) reader paired
with a native ISO9660 **writer** (deterministic Rock Ridge images with
both-endian path tables and optional El Torito BIOS/UEFI boot support). The ISO
reader additionally models an existing image well enough for a future
recustomization to be *safe*: it combines multi-extent file records, parses
directory-record timestamps and the volume/system/publisher/preparer/application
identifiers, reads back the El Torito boot record and catalog in full
(validation entry, default entry, section headers, per-entry fields, image
extent-to-path mapping), and exposes a **rewrite preflight** that returns a
precise list of any source construct the writer cannot preserve. There is also
a squashfs reader (including
XZ/zstd-compressed squashfs blocks) paired with a native squashfs **writer**
(deterministic zstd or uncompressed images built from a pull-based tree),
automatic unwrapping of nested ext4 or
squashfs rootfs images discovered inside squashfs payloads (matching LiveOS
media such as Azure Linux 4.0), local OCI container image ingestion, a minimal
native ext4 writer/readback library API, a bounded native XFS v5
writer/readback library selectable as the root output filesystem, COSI output packaging, a
`miz build-image` orchestration path that builds `raw`, fixed-`vhd`, `vhdx`,
and `qcow2` disk images from an ISO + local OCI layout, a `miz build-iso`
path that regenerates a customized **LiveOS ISO** from an ISO + local OCI
layout (a deterministic ext4 `rootfs.img` wrapped in a native SquashFS at the
LiveOS payload path, folded back into a regenerated ISO with recreated El
Torito boot entries), and a strict `miz recustomize-iso` path that takes the
source ISO as authoritative -- preserving its directory tree, node
metadata/timestamps, volume metadata, and El Torito catalog and replacing only
the LiveOS payload, or refusing with a precise diagnostic when the source uses
a feature the native writer cannot losslessly reproduce:

```
miz create -f vhd disk.vhd 32M                          # dynamic by default (matches qemu-img)
miz create -f vhd -o subformat=fixed disk.vhd 32M       # required for Azure managed-disk upload
miz info disk.vhd
miz info --output=json disk.vhd
miz convert -f raw -O vhd -o subformat=dynamic disk.img disk.vhd
miz convert -f raw -O vhdx disk.img disk.vhdx
miz convert -f vhdx -O vhd -o subformat=fixed disk.vhdx disk.vhd  # import a VHDX (e.g. Hyper-V export)
miz convert -O raw.gz disk.qcow2 disk.raw.gz    # compressed while writing, never a full raw on disk
miz convert -O raw.gz -o - disk.qcow2 - | ssh host 'cat > disk.raw.gz'
miz write --allow-device-write image.qcow2 <block-device>  # Linux: preflight, confirm, write, flush, refresh partitions
miz write --allow-device-write --yes image.vhdx <block-device>  # non-interactive acknowledgement
miz write --allow-device-write --grow-root image.raw <block-device>  # also grow GPT root + ext4 offline
miz write --allow-device-write --expect-serial <serial> image.raw <block-device>  # require the writable disk's exact sysfs serial
miz resize disk.vhdx +4G
miz resize disk.vhd +4G
miz check disk.vhd
miz map disk.vhd
miz azure derive --input-sha256 <hex> input.qcow2 output.vhd  # transactional aligned Gen2 VHD + GPT relocation
miz azure fixup disk.vhd                     # Gen2 default; fixed VHD is padded and checked in place
miz azure fixup disk.qcow2                   # converts to disk.vhd, then pads and checks for Gen2
miz azure fixup --generation 1 legacy.vhd   # explicit legacy BIOS/MBR validation
miz azure deprovision disk.vhd                    # generalize: reset hostname/SSH host keys/machine-id/DHCP state
miz azure deprovision --user azureuser disk.vhd   # also removes that user account + its home directory
miz azure deprovision --allow-device-write /dev/sda  # generalize an installed system in place on a block device
miz info /dev/sda                           # inspect a block device (Linux); devices are read-only by default
miz cosi disk.img -o disk.cosi              # tar + metadata.json + per-partition raw.zst
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.vhd  # Gen2 default
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.raw -O raw
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.vhdx -O vhdx
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.qcow2 -O qcow2
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.raw.gz -O raw.gz
miz build-image --iso azurelinux.iso --container ./oci-layout --size 384M --skip-iso-rootfs -o output-minimal.raw -O raw
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G --verity -o output.vhd
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G --boot-mode uki --esp-size 512M -o output-uki.vhd
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G -o output-live.iso                 # regenerate a customized LiveOS ISO
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G --uefi-boot-image boot/grub2/efiboot.img -o output-live.iso
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G --source-date-epoch 1735689600 -o output-live.iso   # byte-for-byte reproducible
miz recustomize-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G -o recustomized.iso                          # strict preserve-or-refuse ISO rewrite
miz recustomize-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G --source-date-epoch 1735689600 -o recustomized.iso  # reproducible; source catalog/volume preserved
miz capture --source /dev/sda -O vhd -o captured.vhd   # rebuild an installed system, sized to its content
miz capture --source disk.qcow2 --source-root gpt:2 -O raw -o captured.raw --dry-run
miz qemu AzureLinux
miz qemu AzureLinux --snapshot
```

`miz write` is the only CLI path that writes a complete image to an existing
block device. It accepts raw, VHD, VHDX, and qcow2 sources without first
materializing a temporary raw file. The command requires
`--allow-device-write`, checks size, mounts, holders, and the running root
before opening the destination writable, inventories what is already on the
target, and prints the supplied path with the resolved whole-disk serial (or
clearly reports that no serial is available). `--expect-serial <serial>`
requires an exact match after the destination is opened writable and before
any invalidation or copy. Identity is resolved from the opened descriptor's
major/minor through sysfs; partition destinations use their containing whole
disk's serial, whether exposed as `serial` (for example virtio-blk) or
`device/serial` (for example NVMe/SCSI). Devices without serials remain
writable when the option is not used. The command writes source zero regions
explicitly, flushes the device, and uses the native Linux partition-table
refresh ioctl. A refresh failure is reported as partial success with exit
status 2 because the bytes are durable but the kernel view is stale.
`miz convert` and `Image.create` continue to refuse device destinations.

With `--grow-root`, `miz write` additionally requires a strictly valid GPT
raw source with exactly one supported ext4 root partition, and requires that
partition to be the last partition. Before confirmation it validates the
destination-sized GPT and ext4 growth plan without writing data. After the
copy it extends that partition and its filesystem offline using miz's native
writers; the guest does not need `resize2fs`, cloud-init, or a first-boot
resize service.

OCI ingestion defaults to 64 MiB compressed blobs, 128 MiB decompressed
layers, and 512 MiB docker/podman save archives. Deliberately larger trusted
inputs can opt into explicit bounded limits with `--max-oci-blob-size`,
`--max-oci-layer-size`, and `--max-oci-archive-size`.

`build-image` consumes a local OCI layout. Materialize a remote image first with `miz oci copy docker://registry/repository@sha256:<digest> oci:./oci-layout`, or use the digest-pinned `addOciPull` helper from an external `build.zig`. See [OCI transports](oci.md) and [Library API](library-api.md).

`--skip-iso-rootfs` is useful with genuinely minimal base containers: it keeps
the container as the effective root filesystem and carries over only the
boot-critical assets from the ISO/squashfs (kernel, initramfs, EFI binaries,
Secure Boot helpers, BIOS GRUB stage images, and the installed rootfs's
`/lib/modules/<kernel-version>` tree -- kept in full, since loadable drivers
that aren't statically built into the kernel, e.g. Azure's Hyper-V
`hv_netvsc`/Mellanox `mlx5` NIC drivers, otherwise fail to load on real
hardware even though they work under local QEMU testing where `virtio_net`
happens to be statically built in), instead of merging the
entire live/installer rootfs into the final disk.

For `--boot-mode uki` or `--boot-mode both`, the default 96 MiB ESP is sized
for the GRUB+BLS path and is often too small for real distro UKIs. Start with
`--esp-size 512M` and increase it further if your kernel+initrd payloads are
especially large.

`--uki-signing-certificate <path>` and `--uki-signing-command <path>` have
every generated UKI Authenticode-signed before it is written to the ESP, with
an optional `--uki-signing-argument <arg>` for the command's single
subcommand argument -- `--uki-signing-command "$(command -v miz)"
--uki-signing-argument sign` uses miz's own Azure Artifact Signing provider.
Both halves are required together: a certificate with no command names a
signer that never runs, and a command with no certificate has nothing to check
its result against. The private key is never passed to miz and there is no
flag that could carry one; the command is run with the unsigned UKI and the
certificate in a private scratch directory and is expected to write the signed
file back. What it returns is verified against the bytes that were sent before
the image is written, and the run refuses to publish if it does not match. See
[Library API](library-api.md) for the protocol, the checks, and what is
recorded in provenance.

UKI generation also requires a systemd EFI stub such as `linuxx64.efi.stub`
or `linuxaa64.efi.stub`, typically from the `systemd-boot-unsigned` package,
to exist somewhere in the merged ISO/squashfs/container source tree. If the
base OS image does not ship it, inject that package via an extra container
layer or point `--stub-source-path` at the non-standard in-tree path where you
added the stub.

If `usr/sbin/azagent` (the guest provisioning agent -- see `azagent/` above,
issue #112) is present anywhere in the merged ISO/squashfs/container source
tree, `build-image` automatically installs and enables a oneshot
`azagent.service` systemd unit that runs it once at first boot, mirroring
real `waagent.service`. As with the UKI stub, `miz` never builds or injects
the `azagent` binary itself -- add it via an extra container layer,
cross-compiled for the image's target architecture. This only applies to a
full (non-`--skip-iso-rootfs`) image, since its systemd comes from the
merged distro content; a `--skip-iso-rootfs` image's `/sbin/init` is
responsible for invoking `azagent` itself if it wants first-boot
provisioning, since there's no guarantee of systemd being present at all in
that minimal path (`mizinit` does this -- see `mizinit/README.md`). Generalized
images using `mizinit` must add `mizinit.mode=persistent` to the kernel command
line so provisioned users, SSH keys, host keys, and the azagent sentinel are
written to the root filesystem instead of ephemeral overlays. `mizinit` defaults
to `mizinit.azure=auto`: readable provisioning media or DHCP option 245 selects
Azure, while missing positive evidence remains unknown and is retried because
Azure can expose the provisioning disc after networking completes. Positive
Azure decisions are stored under `/var/lib/azagent` and bound to the current
DMI product UUID; `miz azure deprovision` clears them.
Use `mizinit.azure=on` or `off` as a per-boot diagnostic override. Also add
`init=/sbin/mizinit` when the container includes systemd as an OpenSSH dependency,
ensuring the initramfs launches `mizinit` rather than systemd directly.
The serial root shell is disabled by default and released core-image command
lines do not enable it. `mizinit.shell=on` is an explicit diagnostic-only boot
override. PID 1 logs through `/dev/console`, discovers `ttyS*`/`ttyAMA*` and
other serial console names from the kernel command line or active-console
sysfs state, and emits `MIZINIT_PID1_READY supervisor loop active` after
entering its child-reaping supervisor loop.

`azagent` validates OVF usernames using the conservative policy
`[a-z][a-z0-9_-]{0,31}` (no trailing `-`, and `root` is reserved) and validates
every public key as one printable line of at most 16 KiB containing a plausible
authorized_keys key-type/base64 pair. Local provisioning writes the existing
`/var/lib/azagent/provisioned` sentinel before Azure Ready acknowledgement.
Every normal invocation reports Ready even when that sentinel already exists,
and a WireServer failure is returned so `mizinit` retries without recreating
the account or keys. Synthetic local OVF media must contain the explicit
`miz-local-provisioning` marker; under the default `mizinit.azure=auto`,
only that marker makes `mizinit` invoke `azagent --skip-ready`. An unmarked OVF
document retains normal Azure Ready acknowledgement.
Azure still requires every generalized-VM deployment to supply an
`adminUsername`; use `g` for this image convention. The generated
`waagent.conf` mounts the temporary resource disk at `/d` and enables
managed-data-disk activation by stable Azure LUN at `/e` through `/z`. Managed
disks are mount-only: existing ext4 partition 1 is mounted, while blank and
unknown layouts are left untouched.

`ResourceDisk.Owner` (a miz extension, not an upstream `waagent` key) names an
account to `chown` the resource disk's mount point to once it is mounted;
leaving it unset keeps upstream's root-owned mount point. It is applied on
every boot rather than once at provisioning time because a mount point's
ownership lives in the mounted filesystem's root inode, so it is discarded
whenever Azure hands back a blank or resized resource disk and `azagent`
reformats it. An account named here that does not exist is reported and
otherwise ignored, leaving the disk mounted and root-owned. Only the resource
disk is affected: managed data disks are never formatted by `azagent`, so
their ownership is left as whoever formatted them set it.

## Generating a LiveOS ISO (`build-iso`)

`miz build-iso` produces a *generated* LiveOS ISO. It is stacked on the same
ISO + OCI ingestion, nested-LiveOS flattening, and OS customization pipeline as
`build-image`: it builds the identical customized owned root tree
(`build_image.materializeCustomizedRootTree`) up to the point before
`build-image` would populate a disk, then keeps the optical layout instead of
flattening it onto a partition.

Concretely, `build-iso`:

1. writes the customized root tree to a **deterministic ext4 `rootfs.img`** of
   the size you name with `--rootfs-size` (rounded up to the 4 KiB block size),
   honoring `--ext4-label`, `--journal`/`--journal-size`, and
   `--root-selinux-label` exactly as `build-image`'s root filesystem does;
2. wraps that image in a **native zstd SquashFS** (`--squashfs-compression
   zstd|none`) whose single nested member is `rootfs.img`
   (`--nested-rootfs-path`, default `LiveOS/rootfs.img`);
3. rebuilds the ISO from the **source ISO's own directory tree**, replacing only
   the discovered or `--rootfs-path`-configured LiveOS payload
   (default the best-scoring `squashfs`/`rootfs` candidate, e.g.
   `LiveOS/squashfs.img`) with that regenerated SquashFS, and retaining every
   other file -- boot loaders, `grub.cfg`, `isolinux`, EFI binaries -- verbatim;
4. recreates the **El Torito boot catalog** with the native writer.

An ISO is an optical artifact, not a disk block format, so `.iso` is *not* an
`-O` output format and there is no disk `--size`, generation, or partition
plan. Generated output means filesystem contents -- the directory tree, the
replaced payload, and the boot catalog -- not arbitrary preserved byte regions
of the original image. Constructs that live only outside the directory tree
(hidden El Torito images referenced solely by the source catalog, embedded
partition tables for hybrid USB boot, etc.) are not silently carried over.

```
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G -o live.iso
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G \
    --uefi-boot-image boot/grub2/efiboot.img --bios-boot-image boot/grub2/i386-pc/eltorito.img -o live.iso
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G \
    --volume-id CDROM --squashfs-compression zstd --source-date-epoch 1735689600 -o live.iso
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 512M --skip-iso-rootfs -o live-minimal.iso
miz build-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G --dry-run -o live.iso
```

### ISO ingestion vs. strict rewrite preservation

The ISO9660 reader operates at two clearly separated support levels, and it is
worth stating which one a caller relies on:

- **Ingestion support** is what `build-image` and `build-iso` need to *read* a
  source image: enumerate the tree, resolve Rock Ridge/Joliet names and
  symlinks, and stream file content (including multi-extent regular files, whose
  extents are combined transparently so `readFileAlloc`/read-at consume them
  all). Ingestion tolerates constructs it cannot regenerate as long as the
  supported subset is still readable.
- **Strict rewrite support** is what a *recustomizer* (ISO in -> modified ISO
  out) needs before it may regenerate an image and claim it preserved the
  source. `Reader.inspectForRewrite` models the writer-preservable metadata --
  the volume/system/publisher/preparer/application identifiers, per-entry
  timestamps, and the full El Torito boot catalog with each boot image mapped
  either to a modeled file path or to an explicit *raw/unmapped extent* -- and
  returns an ordered, precise list of every source construct the writer cannot
  preserve. `Reader.requireRewriteSupported` is the strict gate that fails with
  the first such blocker for CLI diagnostics. Nothing is silently dropped.

  Blockers currently reported include Rock Ridge directory relocation
  (`CL`/`PL`/`RE`), unmodeled SUSP/RRIP records (device nodes `PN`, sparse files
  `SF`, and any signature the reader does not model), interleaved files,
  extended attribute record lengths, multi-extent directories, ambiguous
  duplicate names, El Torito floppy/hard-disk emulation, El Torito
  selection-criteria extension records, and boot images that fall outside every
  modeled file. Genuinely malformed structures (bad El Torito
  checksum/signature/bounds, invalid media type, a truncated multi-extent chain)
  are rejected as hard errors rather than listed as features.

The strict rewrite gate is what `miz recustomize-iso` (below) enforces before
it creates any scratch: a source with any listed blocker is refused with a
structured diagnostic rather than losslessly rewritten. `build-iso` remains a
*generated* ISO path (it re-emits the supported subset of the source tree and
authors a fresh catalog from discovered/`--*-boot-image` paths), whereas
`recustomize-iso` treats the source ISO as authoritative and preserves it.

### Boot entries

El Torito entries are explicit and reliable. `--uefi-boot-image <path>` and
`--bios-boot-image <path>` name boot image files that must already exist as
regular files in the output ISO tree (i.e. present in the source ISO's
directory tree); a requested path that does not resolve is a precise
preflight/build error (`error.BootImageNotFound`) that publishes nothing. When
neither is given, `build-iso` probes a small set of common source layouts
(`boot/grub2/efiboot.img`, `images/efiboot.img`, ... for UEFI;
`boot/grub2/i386-pc/eltorito.img`, `isolinux/isolinux.bin`, ... for BIOS) and
uses the first that resolves. At least one entry must resolve; **UEFI-only
output is always supported**, and BIOS and dual-boot output are supported when
the source layout or your options make them available. The source ISO's
volume identifier is reused by default (so a `root=live:CDLABEL=<id>` boot line
still finds the volume) and can be overridden with `--volume-id`.

### Reproducibility, isolation, and cleanup

`--source-date-epoch <seconds>` stamps that timestamp into the ext4
superblock/inodes, the SquashFS superblock, and the ISO recording dates, and
derives a fixed root filesystem UUID from it, so two runs of the same inputs
produce a byte-for-byte identical ISO (the report prints the ISO's SHA-256 and
the root tree digest). The build streams `rootfs.img`, the SquashFS payload,
and the ISO through scratch files alongside the output path, refuses inputs
that alias the output or a scratch path (`error.SourcePathConflict`), publishes
the finished ISO with an atomic rename, and removes every scratch file on
success. There is no runtime dependency on `xorriso` or `mksquashfs`.

### `--skip-iso-rootfs` and the nested rootfs

`--skip-iso-rootfs` has the same meaning as in `build-image`: the container
becomes the effective root filesystem and only boot-critical assets are kept
from the ISO/squashfs (see the `build-image` discussion above). The difference
is only where that customized tree lands -- inside the nested `rootfs.img` of
the regenerated SquashFS payload, rather than on a disk partition. Structural
tests confirm the source boot files survive, the old payload is replaced, and
the nested `rootfs.img` opens as ext4 carrying the customized and OCI-overlay
files; they do **not** assert bootability, which only a real firmware boot can.

## Recustomizing a LiveOS ISO (`recustomize-iso`)

`miz recustomize-iso` is the strict **ISO in -> customized ISO out**
recustomization product. Where `build-iso` *generates* an ISO (re-emitting the
supported subset of the source tree and authoring a fresh El Torito catalog
from discovered or `--*-boot-image` paths), `recustomize-iso` treats the source
ISO as **authoritative** and preserves it. It reuses the exact same customized
root-tree pipeline (`build_image.materializeCustomizedRootTree`) and the same
ext4 `rootfs.img` -> SquashFS -> ISO rewrite mechanics as `build-iso`; the
difference is what it preserves and what it refuses.

```
miz recustomize-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G -o recustomized.iso
miz recustomize-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G --source-date-epoch 1735689600 -o recustomized.iso
miz recustomize-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 512M --skip-iso-rootfs -o recustomized-minimal.iso
miz recustomize-iso --iso azurelinux.iso --container ./oci-layout --rootfs-size 2G --dry-run -o recustomized.iso
```

### Strict preflight, then preserve-or-refuse

Before any mutation or scratch artifact is created (beyond opening and
inspecting the source), `recustomize-iso` runs the strict
`iso9660.Reader.inspectForRewrite` gate. If the source carries **any** feature
the native writer cannot losslessly reproduce, the command refuses with a
structured diagnostic naming the blocker's *kind*, affected *path*, boot
*catalog index*, and *detail* -- and writes no output and no scratch. There is
no best-effort or silent fallback mode.

The refusal boundaries are exactly the strict-rewrite blockers listed above,
surfaced through the public API and CLI:

- Rock Ridge directory relocation (`CL`/`PL`/`RE`);
- unmodeled SUSP/RRIP records (device nodes `PN`, sparse files `SF`, and any
  unknown signature);
- interleaved files, extended attribute record lengths, multi-extent
  directories, and ambiguous duplicate names;
- El Torito floppy/hard-disk emulation, selection-criteria extension records,
  and boot images that fall outside every modeled file (an unmapped extent);
- plus the writer-model boot-catalog mapping limits this product enforces: a
  boot platform other than BIOS/UEFI, more than one entry per platform, and
  selection criteria the writer cannot emit.

Genuinely malformed structures (bad El Torito checksum/signature/bounds,
invalid media type, a truncated multi-extent chain) fail as hard errors.

### What is preserved

When the source is losslessly rewritable, `recustomize-iso`:

1. preserves **every modeled source filesystem node** other than the replaced
   LiveOS payload -- path/name, file and symlink bytes, POSIX mode/uid/gid, and
   modeled timestamps;
2. preserves the **primary volume metadata** (volume/system/volume-set/
   publisher/preparer/application identifiers) through the writer options, and
   re-reads them from the completed scratch image to confirm the round-trip
   *before* it is atomically published (a mismatch fails the build and leaves no
   output);
3. reproduces the **supported El Torito catalog exactly** from the inspected
   source -- the validation entry's platform assignment and 24-byte id string,
   each section header's platform, order, final-vs-more indicator and 28-byte id
   string, and every entry's bootable flag, no-emulation type, load segment,
   system type, and sector count -- mapping each boot entry back to its source
   tree path, so you never re-specify a boot image and the source layout is
   preserved rather than normalized; and
4. replaces **only** the discovered (or `--rootfs-path`-named) LiveOS payload
   with a native zstd SquashFS wrapping the customized ext4 `rootfs.img`. Source
   boot and configuration files are untouched unless one of them *is* the
   payload path.

Because it preserves the source catalog and volume metadata, `recustomize-iso`
deliberately exposes **no** `--uefi-boot-image`/`--bios-boot-image` or
`--volume-id` overrides. Everything else `build-iso` exposes -- `--rootfs-path`,
`--nested-rootfs-path`, `--skip-iso-rootfs`, `--squashfs-compression`,
`--architecture`, the ext4 options (`--ext4-label`, `--journal`/`--journal-size`,
`--root-selinux-label`), the OCI and import limits, `--source-date-epoch`,
`--dry-run`, and `-v` -- is available. Deterministic options produce identical
bytes from identical source + OCI + options; the output need not be byte-for-byte
identical to the source, but the preservation is semantically testable.

The machine-readable report (printed by the CLI and emitted as JSON by the
`addRecustomizeIso` build helper) states the source hash, the output hash and
size, the source and output volume metadata, the replaced payload path, the
customized root-tree digest, the preserved node count, the preserved boot
entry count and platforms, and whether the strict inspection was clean.

**PXE is out of scope** for this feature: `recustomize-iso` only reads an
optical ISO and writes an optical ISO.

### Reading a block device

Every command that opens an image by path also accepts a block-device node,
so an already-installed system can be inspected without first copying it into
an image file:

```
miz info /dev/sda            # physical or attached disk
miz map /dev/nvme0n1
miz info /dev/mapper/vg-lv   # a logical volume, read through device-mapper
```

`stat(2)` reports `st_size == 0` for a device node, so the size comes from
the kernel (`BLKGETSIZE64`, plus `BLKSSZGET` for the logical sector size)
instead, and that size is authoritative: format sniffing, the trailing VHD
footer probe, and `expected_virtual_size` checks all work against it, and
never read past the device's end. A device with no medium (an unbound loop
device, an empty optical drive) is reported as `EmptyBlockDevice` rather than
opened as a zero-length image. Only Linux is supported; elsewhere a device
node is rejected with `UnsupportedBlockDevice`.

Devices are opened **read-only** even when the command would open a regular
file for writing, so inspecting a live disk cannot damage it. Consequently:

- `miz create` refuses a device path outright.
- `miz resize` refuses a device: its size belongs to whatever provides it.
- Writing through a device requires an explicit opt-in --
  `miz azure deprovision --allow-device-write /dev/sda`, or
  `Image.openPathWithOptions(io, path, .{ .allow_device_write = true })` from
  the library. Without it, every write fails with
  `BlockDeviceWriteNotPermitted`.

### Reading LVM2

A guided Ubuntu or Debian install does not put the root filesystem in a
partition. It puts an LVM2 physical volume in the partition and the filesystem
in a logical volume inside that:

```
nvme0n1                      1.7T disk
|-nvme0n1p1                    1G vfat          /boot/efi
|-nvme0n1p2                    2G ext4          /boot
`-nvme0n1p3                  1.7T LVM2_member
  `-vg-lv                    100G ext4          /
```

`miz` reads that layout **offline and read-only**. There is no writer: nothing
in `miz` creates, activates, resizes, or otherwise mutates LVM metadata. On a
*running* system the volume is already published as `/dev/mapper/vg-lv`, and
that node can be opened directly as a block device (see above) without any of
this.

`miz map` lists the volume groups it found after the allocation map:

```
$ miz map disk.img
Offset       Length       Mapped
0x0          0x10000000   true

Volume group ubuntu-vg (seqno 3, 4 MiB extents)
  pv pv0      0x1004400 (GPT partition)
Offset       Length       Type         Volume
0x1104400    0x2800000    striped      ubuntu-lv
-            0x800000     thin         swap (UnsupportedLvmThinSegment)
```

`--output=json` emits `{"extents": [...], "volume_groups": [...]}`. (Before LVM
support it emitted the extent array on its own; the array now lives under
`extents`.) Each logical volume carries `start` and `length` when it has a
single byte range on this disk, and `unmappable` naming the reason when it does
not.

Wherever a partition selector is accepted -- the preserved-image
`root_partition`, and each `source_mounts` entry -- a logical volume can be
named instead:

```zig
.root_partition = .{ .logical_volume = .{ .logical_volume = "ubuntu-lv" } },
.root_partition = .{ .logical_volume = .{
    .volume_group = "ubuntu-vg",
    .logical_volume = "ubuntu-lv",
} },
```

and in the preserved-image configuration JSON (api_version 3 and later; a v2
document is refused with `UnsupportedPartitionSelectorForApiVersion`):

```json
{ "logical_volume": { "volume_group": "ubuntu-vg", "logical_volume": "ubuntu-lv" } }
```

`volume_group` may be left out when the disk carries exactly one volume group;
on a disk with more than one, omitting it is `AmbiguousLvmVolumeGroup` rather
than a guess between them.

What is understood and what is refused:

- Only a `striped` segment with a single stripe -- a plain linear mapping,
  which is what a default install produces. Real striping is told apart from a
  linear map only by `stripe_count`, so reading the first stripe as the whole
  volume would silently produce data that looks right and is not.
- Every other segment type is refused by its own error, so an operator can tell
  what is in the way: `UnsupportedLvmStripedSegment` (multi-stripe),
  `UnsupportedLvmMirrorSegment`, `UnsupportedLvmRaidSegment`,
  `UnsupportedLvmThinSegment`, `UnsupportedLvmCacheSegment`,
  `UnsupportedLvmSnapshotSegment`, and `UnsupportedLvmSegmentType` for anything
  else. Such a volume is still listed by `miz map`; only its mapping fails.
- A volume group may span several physical volumes as long as they are all in
  the image being read. One that is not present is `LvmPhysicalVolumeMissing`.
- A volume handed to a reader has to be one unbroken run on one physical
  volume; anything else is `LogicalVolumeNotContiguous` rather than a silent
  truncation to the first run.
- The metadata area is a circular buffer holding a sequence number and a
  checksum. The copy with the highest `seqno` wins, after its metadata-area
  header checksum and its own checksum have both been verified; an area flagged
  `RAW_LOCN_IGNORED` is stale by design and never competes. Every physical
  volume in a group keeps its own copy, so choosing the wrong one would yield a
  plausible but stale mapping.
- A region whose first sectors hold no `LABELONE` is simply not a physical
  volume and is passed over. One that carries a label and then does not parse
  is corruption and is reported, because a shorter list than the disk really
  has is the more expensive answer.

Rebuilding *into* a logical volume is allowed: the run starts and ends exactly
where the volume does, so rewriting the filesystem leaves every LVM structure
untouched. The `vm` backend is the exception -- the guest reaches its root
through `/dev/vdaN` and this initramfs carries no volume manager, so a logical
volume root there is `UnsupportedRootPartitionInVm`.

### Preserved-image customization backends

Customizing an image that already exists selects one of five backends. They are
ordered by how much they can do, which is the same order as how much they need.

| Backend | Privileges | Runs guest code | Architectures | Can do |
| --- | --- | --- | --- | --- |
| `native_edit` | none | no | any | overwrite, remove existing paths |
| `rebuild` | none | no | any | full tree rebuild of one ext4 partition |
| `native_fresh` | none | no | any | build a new image rather than edit one |
| `unsafe_chroot` | root + `CAP_SYS_CHROOT`/`CAP_SYS_ADMIN`/`CAP_MKNOD` | yes, on the host kernel | host's only | install/remove/update packages through the host's or a declared resolver, from authenticated repositories, configure kernel modules, regenerate initramfs (explicitly or when the packages imply it), run declared hooks in the target root, relabel the root against the policy the target carries |
| `vm` | none | yes, in an isolated guest | any | install/remove/update packages through QEMU's or a declared resolver, configure kernel modules, regenerate initramfs (explicitly or when the packages imply it), run declared hooks in the target root, relabel the root against the policy the target carries, cross-architecture |

`vm` is the only backend that can customize an image the host cannot run, and
the only one that executes guest code without executing it on the host. It
boots the image's own kernel directly (`-kernel`/`-initrd` + `rdinit=`) with a
static agent appended to a copy of the image's initramfs, so no bootloader,
firmware or init system is involved and a fully emulated boot costs seconds.

The cost is a hard requirement on the image: because the agent is `rdinit`, the
guest starts with only the drivers its own kernel built in, and there is no
`modprobe`, `udev` or module tree to reach for at that point. So **`ext4`, a
virtio disk driver and the virtio PCI bus must either be built into the image's
kernel or be present in the image's own `lib/modules/<release>` tree.** The
backend reads `modules.builtin` and `modules.dep` out of the image, resolves the
dependency closure of what the run needs, decompresses those modules host-side,
and appends them to the initramfs beside the agent, which inserts them before it
waits for any device. A driver that is neither built in nor in the tree refuses
the run rather than being guessed at, since a wrong guess is not a wrong answer
but a device that never appears.

Two drivers are asked for that no dependency graph names, because `modules.dep`
records symbol dependencies and neither of these is one: `virtio_pci`, since
every device the backend attaches is a PCI device, and `sd_mod`, since a
virtio-scsi controller with no SCSI disk driver behind it presents no `/dev/sda`.

A built-in driver is never traded for a loadable one, so an image whose kernel
builds everything in boots exactly as it did before, with an empty module list.

#### Which ext4 sources `rebuild` accepts

The `rebuild` backend reads a filesystem's whole tree and writes a new one, so
it has to understand the source. It offers two profiles, selected by
`source_profile` on the `std.Build` helper, in the preserved-image
configuration JSON, and on `preserved_image.RebuildOptions`.

| Profile | Accepts | Reproducible |
| --- | --- | --- |
| `strict` (default) | only `miz_ext4_v1`, the exact layout this project's writer emits | yes, byte for byte |
| `general` | any ext4 the general reader accepts, including a stock distro root | no |

`strict` requires 32-byte group descriptors and exactly the
`filetype`+`extents` incompatible feature set: no journal, no `64bit`, no
`flex_bg`. That is deliberate rather than incidental. It is the promise that
rebuilding the same source twice, on any host, produces the same bytes.
It also requires the 256-byte inodes this writer emits. An image built by an
older miz has 128-byte ones, so it no longer matches `strict` and is read
under `general` instead, where `source_reproducible = false` says plainly that
rebuilding it produces a different -- larger, and correct past 2038 -- image
rather than the same bytes. Reproducibility is a promise about a given writer,
not across versions of one.

The writer is deliberately not parametric in inode size, and will not become
so. It could be: threading the source's size through the layout arithmetic,
the inode encoder, the checksum split and the superblock is mechanical work,
and it would let an image an older miz wrote re-enter `strict` and round-trip
byte for byte. The reason not to is what a 128-byte inode cannot hold. There
is no `i_extra_isize` region there, so there are no epoch bits, so no
timestamp outside 1970..2038 is representable at all. Restoring that path
restores the exact defect the move to 256-byte inodes existed to remove, and
it does not restore it quietly: the range of times the writer can store stops
being a property of the writer and becomes a property of whichever source it
happened to be handed. `root_tree.validateExt4Time` rejects an unrepresentable
time against `ext4.min_representable_time` and `max_representable_time`, two
module constants, which is what keeps the check and the encoder from drifting
apart; a per-run range would have to be plumbed to every caller that validates
a time, and a source whose own timestamps fell outside its own inode size's
range would need a named refusal of its own. That is a large amount of
machinery, and all of it exists to serve rebuilding one class of legacy image
without changing its bytes.

So `strict` is reserved for images the current writer produces. An older
128-byte image migrates by being rebuilt once under `general`, which reports
`source_reproducible = false` for that one rebuild and produces a 256-byte
image that is `strict` from then on. Nothing else is lost in the meantime: a
128-byte image still opens, resizes, edits and rebuilds, because the in-place
paths preserve whatever inode size they find. The only thing it cannot claim
is byte-for-byte reproducibility, and that claim would be false if it were
made.

No filesystem a distro installer produced can satisfy it. `mke2fs` defaults --
Ubuntu 24.04, Debian 12, Azure Linux -- give you 256-byte inodes plus
`has_journal`, `64bit`, `flex_bg`, `metadata_csum`, `metadata_csum_seed`,
`orphan_file`, `dir_nlink`, `extra_isize` and `huge_file`. `general` exists for
exactly those, and reports itself as `ext4_general_v1` with
`source_reproducible = false` in the rebuild report and in provenance. It is
opt-in because giving up reproducibility should be a decision, not a fallback.

`general` preserves every metadata dimension the source carries:

- regular files, directories, and symlinks, both the fast form stored inside
  `i_block` and the slow form with its own data blocks
- hardlinks: a regular file reached by several names is imported once and
  re-linked, not copied, so shared identity survives `rsync -H`, package
  managers and anything else that compares inode numbers
- block devices, character devices and FIFOs, including device numbers wider
  than the legacy 8:8 encoding
- `mode`, `uid`, `gid`, and `atime`/`mtime`/`ctime` per inode, each to
  nanosecond precision rather than truncated to whole seconds
- `crtime`, each file's creation time, kept as the source recorded it rather
  than restamped with the build time. A captured system's files were created
  when they were created, and that is the one fact `crtime` exists to hold; a
  source too narrow to store one -- a 128-byte inode has no room, and a wider
  one may declare an `i_extra_isize` that stops short of the field -- has none
  to preserve, and a node this build genuinely creates gets the build
  timestamp, which is then the honest answer rather than a borrowed one
- extended attributes, both inline in a 256-byte inode's spare space and in an
  external xattr block; this is what carries `security.selinux` and
  `system.posix_acl_access`/`system.posix_acl_default`, so dropping them would
  silently break MAC policy and ACLs

Two limits are inherent to the writer rather than the importer. Timestamps
are stored as ext4 stores them -- a signed 32-bit seconds field plus the two
epoch bits in `i_*_extra` -- so a value outside 1901-12-13..2446-05-10 has
nowhere to go and is refused with `TimestampOutOfRange` rather than wrapped
into a plausible-looking wrong date. And a source journal is never replayed: a source must be cleanly
unmounted, and a superblock still marked as needing recovery or carrying orphan
inodes is a hard error rather than a filesystem imported halfway. The source's
own journal is never carried across either -- the rebuild writes a fresh
filesystem, and whether that one has a journal is `journal`'s decision alone.
The rebuild report and provenance state both `source_has_journal` and the
output's `journal_block_count`, so dropping a journal is visible rather than
silent.

Everything outside the supported set is refused by name, because a partial
import produces an image that looks fine and is subtly wrong:

| Feature | Error |
| --- | --- |
| `bigalloc` | `UnsupportedBigallocFeature` |
| `inline_data` | `UnsupportedInlineDataFeature` |
| `casefold` | `UnsupportedCasefoldFeature` |
| `encrypt` | `UnsupportedEncryptFeature` |
| `verity` | `UnsupportedVerityFeature` |
| `mmp` | `UnsupportedMmpFeature` |
| `fast_commit` | `UnsupportedFastCommitFeature` |
| `quota` | `UnsupportedQuotaFeature` |
| `project` | `UnsupportedProjectFeature` |
| `compression` | `UnsupportedCompressionFeature` |
| `meta_bg` | `UnsupportedMetaBlockGroupFeature` |
| external journal | `UnsupportedExternalJournalFeature` |
| `ea_inode` | `UnsupportedXattrInodeFeature` |
| `large_dir` | `UnsupportedLargeDirFeature` |
| `dirdata` | `UnsupportedDirdataFeature` |
| `snapshot` | `UnsupportedSnapshotFeature` |
| `replica` | `UnsupportedReplicaFeature` |
| `shared_blocks` | `UnsupportedSharedBlocksFeature` |
| `sparse_super2` | `UnsupportedSparseSuper2Feature` |
| `stable_inodes` | `UnsupportedStableInodesFeature` |
| needs journal recovery | `SourceNeedsJournalRecovery` |
| orphan inodes pending | `SourceHasOrphanInodes` |
| not cleanly unmounted | `SourceNotCleanlyUnmounted` |
| missing `extents` or `filetype` | `MissingExtentsFeature`, `MissingFiletypeFeature` |
| anything else unrecognized | `UnsupportedFilesystemFeature` |

Unix domain sockets are refused with `UnsupportedSocketInode`: a socket inode
in an image is meaningless, since the bound socket died with the process.

#### Merging several source filesystems into one root

An installed system is not one filesystem. It is normally an ESP, a separate
`/boot`, and a root filesystem:

```
source                               target
------                               ------
p1  ESP        (vfat)   /boot/efi    p1  ESP  (vfat)
p2  boot       (ext4)   /boot        p2  root (ext4)
p3  root       (ext4)   /                 └── /boot/       (directory)
                                          └── /boot/efi/   (mount point)
```

`source_mounts` re-images that into the simpler layout on the right: `/boot`
and `/boot/efi` become ordinary directories inside the one root filesystem.
That removes a partition and a mount, and it makes the resulting disk
unambiguous for tooling that scans partitions to identify the root. The ESP
partition itself is left on the output disk untouched -- firmware still needs
it -- so only the extra Linux filesystem disappears.

Each mount names a partition and where it lands:

```zig
.storage = .{ .preserve = .{
    .root_partition = .{ .mbr_index = 3 },
    .source_profile = .general,
    .source_mounts = &.{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
    },
} },
```

The same list is spelled `source_mounts` on the `std.Build` helper and in the
preserved-image configuration JSON, where each entry is

```json
{
  "source_path": "",
  "partition": { "mbr_index": 1 },
  "target": "/boot/efi",
  "filesystem": "detect",
  "fat_metadata": { "directory_mode": 493, "file_mode": 420, "uid": 0, "gid": 0 }
}
```

`source_path` is empty for the disk being rebuilt, which is the common case of
several partitions of one disk; naming a path merges a filesystem from another
image or block device. `filesystem` defaults to `detect`, which probes the
ext4 superblock magic and the FAT32 boot sector: a partition that looks like
both is `AmbiguousSourceFilesystem` and one that looks like neither is
`UnrecognizedSourceFilesystem`, because guessing about a filesystem that is
about to be read into a bootable image is not a service.

Sources are merged into one tree **before the writer runs**, so hardlinks,
extended attributes, permissions, device nodes and per-inode timestamps
survive the merge itself and not merely the import.

##### A mount replaces, it does not merge

A later source mounted at a prefix replaces whatever the sources before it had
at that path. It does not merge entry by entry.

This mirrors a real mount, and it is the only safe rule. An installed root
filesystem's `/boot` is a non-empty stub -- an old kernel, an old `grub.cfg` --
that the boot filesystem hides the instant it is mounted. Merging the two would
produce an image with a stale kernel sitting beside the real one. It looks
fine, it passes `e2fsck`, and it can boot the wrong thing.
`RebuildReport.shadowed_node_count`, also recorded in provenance, says how many
nodes were hidden, so the result can be stated rather than diffed for.

##### Ambiguity is refused, never resolved

The target list is validated in full before any source is opened, so a bad
mount costs a rejection rather than a scan of a filesystem it would discard.

| Rejected | Error |
| --- | --- |
| a relative target (`boot`) | `MountTargetNotAbsolute` |
| the root itself (`/`) | `MountTargetIsRoot` |
| a target that is not already normalized (`/boot/`, `/a/./b`, `/a//b`, `/a/../b`) | `MountTargetNotNormalized` |
| the same target twice | `DuplicateMountTarget` |
| a mount an entirely later mount would shadow away | `MountTargetShadowedByLaterMount` |
| a target that does not exist | `MissingMountTarget` |
| a target whose parent directory does not exist | `MissingMountTargetParent` |
| a target that exists but is not a directory | `MountTargetNotDirectory` |
| a target that is itself a symlink | `MountTargetIsSymlink` |
| a target reached through a symlink | `MountTargetTraversesSymlink` |
| a target reached through a non-directory | `MountTargetTraversesNonDirectory` |
| a mount that would strand a hardlink outside it | `MountShadowsHardlinkTarget` |
| a merged partition on a `native_edit`/`vm`/`unsafe_chroot` backend | `UnexpectedSourceMounts` |

A target is never normalized on the caller's behalf, because two spellings of
one path would then slip past the overlap check. A missing mount point is never
created, because that turns a typo into a plausible-looking image -- `mount(8)`
refuses for the same reason.

Overlap reduces to two cases, since these are paths in a tree: two mounts are
either the same target or one is nested inside the other. Nesting is legal only
outermost-first, which is the order a real system mounts in.

##### Synthesized metadata for a FAT source

vfat stores no owner, no permission bits, no symlinks and no extended
attributes, so a POSIX tree built from an ESP needs those invented. That is a
policy, and it is written down rather than assumed:

| Field | Default |
| --- | --- |
| `directory_mode` | `0o755` |
| `file_mode` | `0o644` |
| `uid` | `0` |
| `gid` | `0` |

Every entry from a FAT source gets exactly these, including the mount point
directory itself, which takes the mounted volume's root metadata just as a real
mount does. They are per-mount (`fat_metadata`), so an ESP that should be
`0700`/`0600` says so. A mode carrying anything beyond the permission, setuid
and sticky bits is `InvalidSynthesizedMode`: it would change the file type, not
the permissions.

##### Limits across a merged import

Limits describe the import, not any one source of it. `--max-nodes` and
`--max-total-bytes` are charged against a running total across every source, so
three filesystems that each fit and together do not are refused -- which is
exactly the case the limits exist for. The reported breach always names the
limit as configured, never an internal per-source remainder, so the remediation
it prints is a value the flag can actually be set to. The reported peaks are
likewise combined, so sizing the next run's flags from a dry run works for a
merged import too.

##### Reproducibility

`source_reproducible` is false whenever anything was merged in, even from a
`miz_ext4_v1` source. The output is then a function of several sources rather
than of the one the report names, and the report says so.

#### Reconciling fstab and the bootloader with the new identity

Merging retires identifiers. A `/boot` filesystem folded into the root stops
existing, so every `UUID=` and `PARTUUID=` that named it now names nothing;
the same is true of an ESP merged in at `/boot/efi`. The imported guest still
carries those identifiers in `/etc/fstab` and in its bootloader configuration,
and an image where they have not been corrected does not boot -- it drops to
an initramfs prompt with an unhelpful message. Correcting them out of band
means mounting the result and running `grub-install` / `update-grub` in a
chroot, which is exactly the privileged, host-dependent step this project
exists to avoid.

The `rebuild` backend therefore reconciles the tree with the identifiers the
image actually has, after every other customization pass and before a single
output byte is written. `identity_rewrite` selects what it may do:

| Value | Behaviour |
| --- | --- |
| `rewrite_and_verify` (default) | rewrite, then refuse to publish an image that still names a retired identifier |
| `rewrite_only` | rewrite and report what is still stale, for an operator who intends to finish the job in a chroot |
| `off` | touch nothing; the caller owns the bootability of the result |

The setting is `rebuild`-only. Every other backend keeps the source's
filesystems exactly as they are, so nothing is ever retired, and offering the
knob there would let an operator believe they had turned off a safety net that
was never on. Stating it elsewhere is `UnexpectedIdentityRewrite`.

It is spelled `identity_rewrite` on the `std.Build` helper, on
`PreservedStorage`, and in the preserved-image configuration JSON:

```json
{ "backend": "rebuild", "identity_rewrite": "rewrite_only" }
```

##### Rewriting is surgical, never regenerative

`/etc/fstab` is spliced in place. Only the identifier value of a matching
entry is replaced, and only entries whose filesystem was merged away are
removed; every other byte -- comments, blank lines, tabs, run-on spacing,
CRLF line endings, an absent final newline -- survives verbatim. Emitting a
fresh "minimal correct" fstab is not on offer: a real system's fstab carries
bind mounts, network shares, `tmpfs` entries and the comments that explain
them, and discarding them would be a silent, unrequested edit.

| fstab entry | What happens |
| --- | --- |
| names a filesystem that was merged away, by `UUID=`/`PARTUUID=`/`LABEL=`/`PARTLABEL=` | removed, whole line |
| whose mount point is exactly a merge target | removed, whole line |
| names a filesystem whose identifier changed | that field's value replaced in place |
| names a retired identifier with no replacement | left alone and counted in `fstab_entries_unresolved` |
| anything else | untouched, byte for byte |

A merged-away entry is removed rather than rewritten because its content is a
plain directory inside another filesystem now, and mounting anything over that
directory would hide the very content the merge just imported. Mount points
are matched exactly, never by prefix, and `mount(8)`'s octal escapes (`\040`
and friends) are decoded before the comparison, so `/boot/efi` survives `/boot`
being merged when the ESP is still a real partition of its own.

The bootloader configuration is likewise rewritten in place rather than
regenerated. `root=UUID=`, `root=PARTUUID=`, `search --fs-uuid`,
`search.fs_uuid`, `resume=`, `rd.luks.uuid=` and any other occurrence of a
retired UUID as a whole token is replaced; the menu structure, the indentation
and every unrelated line stay exactly as the distro shipped them. Reproducing
`grub-mkconfig` output faithfully is not a fight worth picking, and a
regenerated `grub.cfg` loses distro-specific structure that nothing here can
put back. Labels are never rewritten in a configuration file, because an
arbitrary word like `boot` or `EFI` appearing as a token would corrupt shell
syntax rather than correct it.

Files rewritten: `/etc/fstab`, `/etc/default/grub`, `/etc/default/grub.d/*`,
`/etc/kernel/cmdline`, and `*.cfg` / `*.conf` under `/boot/grub/`,
`/boot/grub2/`, `/boot/loader/` or a merged ESP.

##### The verification pass

Rewriting what is known about is not the same as knowing nothing was missed,
and a miss here is invisible until the image is booted. After the rewrite, the
tree is scanned again for any surviving occurrence of a retired identifier:

| Scanned | Why |
| --- | --- |
| `/etc/fstab` | the mounts |
| `/etc/crypttab` | `UUID=` sources for encrypted volumes |
| `/etc/default/grub`, `/etc/default/grub.d/`, `/etc/kernel/cmdline` | the kernel command line |
| `/boot/grub/`, `/boot/grub2/`, `/boot/loader/` | the bootloader, including binaries such as `core.img` and `grubenv` |
| every merged ESP, in full | vendor `grub.cfg`, BLS entries, shim's own configuration |

Matching is ASCII case-insensitive, because `blkid` prints lowercase and
plenty of installers write uppercase and they name the same filesystem. A full
36-character UUID is flagged even when it sits inside a longer token -- a
stale value glued to more hex is still a stale value -- while a shorter
identifier such as a FAT volume serial (`5A56-4D49`) is required to stand as a
whole token, so that a coincidental hex run is not reported as a boot failure.

The rest of `/boot` is deliberately not scanned. Kernels and initramfs images
are megabytes of compressed payload in which an identifier is neither readable
nor rewritable, and scanning them would trade a real check for a slow one.

Under `rewrite_and_verify` the first surviving reference fails the build with
`StaleFilesystemIdentifier`, and the diagnostic names the file, the kind of
identifier, its value and the byte offset:

```
/boot/grub/i386-pc/core.img still names the retired UUID
66666666-7777-8888-9999-aaaaaaaaaaaa at offset 6
```

`inspectRebuild` runs the same rewrite and the same verification pass over a
throwaway tree, so a source that cannot be reconciled is refused in preflight,
without creating a file.

##### The escape hatch

`core.img`, a `grubenv`, and a signed EFI binary all carry identifiers no text
rewriter can correct without invalidating them. For those, the answer is the
`unsafe_chroot` backend, which runs the distro's own bootloader tooling inside
the image and is opt-in for exactly that reason. Setting
`identity_rewrite = "rewrite_only"` gets the image built and the surviving
references reported, so that pass can be scheduled deliberately rather than
discovered at boot.

Identifier rewriting corrects identifiers. It does not rewrite *paths*: a
`grub.cfg` that loaded `/vmlinuz` from a separate `/boot` filesystem still says
`/vmlinuz` after that filesystem became `/boot` inside the root. Where the
merged layout changes what a path means, the bootloader configuration has to be
regenerated by the distro's tooling, which is again what the escape hatch is
for.

| Image kernel provides | Result |
| --- | --- |
| `ext4` + `virtio_blk` built in | disks attached over virtio-blk (`/dev/vd*`) |
| `ext4` + `virtio_scsi` + `sd_mod` built in (Azure Linux) | disks attached over virtio-scsi (`/dev/sd*`) |
| the same drivers in `lib/modules` (Debian, Ubuntu, Fedora cloud kernels) | loaded from the image's own tree before the mount |
| neither built in nor in the tree | refused in preflight, named for the missing driver |

`virtio_net` is required only when the plan declares package repositories; an
offline guest is given no network device at all, so a modular `virtio_net` is
inserted only for a run that has somewhere to go.

Every module that was loaded is recorded in provenance by name, by the path
inside the image it came from, and by the digest of the object as the guest
received it.

Acceleration is fail-closed. Hardware acceleration requires host architecture ==
image architecture and a readable and writable `/dev/kvm`, and is refused rather
than degraded. Software emulation must be asked for by name, and is the only
option for a cross-architecture run, since no accelerator crosses architectures.
Whichever ran is recorded in provenance.

## Capturing an installed system

`miz capture` reads an installed system — a block device, a disk image, a
partition inside one, or an LVM logical volume — and writes a **new** disk
image sized to the content rather than to the source. A 1 TB disk holding
6 GB of files becomes a 6 GB image.

```
miz capture --source /dev/sda -O vhd -o captured.vhd
miz capture --source disk.qcow2 --source-root gpt:2 -O raw -o captured.raw
miz capture --source /dev/sda --source-root lvm:vg0/root -O raw -o captured.raw
miz capture --source /dev/sda --source-mount /dev/sda2=/boot -O raw -o captured.raw
miz capture --source /dev/sda -O raw -o captured.raw --dry-run
miz capture --source /dev/sda -O raw.gz -o - | ssh host 'cat > captured.raw.gz'
```

`-o` and a format are always required, `--dry-run` included: a dry run reports
what *that* output would have cost, and the staging it plans for depends on
where the output was going.

This is not `rebuild`. `miz convert` and the preserved-image backends copy a
disk and keep its geometry; capture discards the source geometry entirely and
assembles a fresh GPT with a fresh ESP and a fresh root filesystem from the
*files* it read. Nothing of the source's partition table, free space, or
fragmentation survives.

### What it selects, and how

The root filesystem is `--source-root` if given. Otherwise every partition of
`--source` is probed and the one holding an ext4 filesystem **with an `/etc`**
is the root -- provided exactly one does, which is the ordinary single-root
install. Both halves of that are read off the disk rather than guessed at, and
the `/etc` half matters: a separate `/boot` is ext4 on plenty of machines
whose root is xfs or btrfs, and capturing it would produce a perfectly valid
image of the wrong filesystem.

Two candidates is `AmbiguousSourceRoot`, an ext4 with no `/etc` is
`NoRootLikeFilesystem`, and no ext4 at all is `SourceRootRequired`. All three
name the flag that settles it, because "the biggest Linux partition" would be
right often enough to be trusted and wrong often enough to matter. A root
inside LVM is never auto-detected, since the partition holding it is a
physical volume rather than a filesystem.

A spec is a path (`/dev/sda2`, `root.img`), a partition of `--source`
(`gpt:2`, one-based), or a logical volume (`lvm:<vg>/<lv>`).

The EFI system partition is found by GPT type GUID, which is definitional
rather than a heuristic, and can be named explicitly with `--source-esp`. It
is **copied**, not regenerated: a signed EFI binary that is re-emitted is a
Secure Boot failure, so capture reproduces the bytes it was given.

Naming the root as a partition of `--source` (`gpt:<n>`) rather than by path
also lets the capture retire the source's PARTUUID and PARTLABEL. A root
opened by path is just a filesystem; which partition it came from is not
knowable from it, so a `PARTUUID=`-rooted fstab cannot be corrected. That is
warned about rather than discovered at boot.

`--source-mount <spec>=<path>` names a filesystem mounted elsewhere in the
running system — most often a separate `/boot`. Its content is merged into the
root tree at that path, exactly as [merging several source
filesystems](#merging-several-source-filesystems-into-one-root) describes, and
its `/etc/fstab` entry is *dropped*, because after the merge there is no
separate filesystem left to mount. A real ESP is not a `--source-mount`: it
stays a partition of its own and keeps its `/boot/efi` entry.

### Sizing

Both filesystems are sized from their content. `--root-size` and `--esp-size`
override that, and are refused below the measured minimum rather than silently
raised — the failure states the minimum so the number can be argued with:

```
capture: the smallest root filesystem holding this content is 13 MiB (14262272 bytes)
capture: the smallest EFI system partition holding it is 33 MiB (34603008 bytes)
capture: assembling the image failed: RootSizeBelowMinimum
```

FAT32's 65525-cluster floor means the smallest legal ESP is about 33.5 MiB
however empty it is, so that minimum is usually about FAT32 and not about the
content. `--dry-run` reports every one of these numbers and writes nothing.

### Identity

The captured filesystems get new UUIDs and a new FAT volume serial, so the
image can be attached alongside its source without a duplicate-UUID collision.
That would break every reference to the old ones, so the identity
reconciliation described under [reconciling fstab and the
bootloader](#reconciling-fstab-and-the-bootloader-with-the-new-identity) runs
by default over both the root tree and the ESP, and what it did is reported:

```
capture: root identity rewrite: 2 fstab entries rewritten, 1 dropped, 1 references in 1 config files
capture: ESP identity rewrite: 0 fstab entries rewritten, 0 dropped, 2 references in 1 config files
```

References it retired but could not replace, and references that survived the
rewrite, are warned about rather than passed over: an image that builds and
then fails to boot is the expensive outcome. `--no-identity-rewrite` keeps the
source identifiers, which is correct only when the source will never be
attached at the same time.

### Reading the source

Reading a mounted, running filesystem captures it mid-write. Capture a
quiesced source: a stopped VM's disk, a snapshot, or a device that is not
mounted read-write. Reading a block device generally requires root, and
`EACCES` on `--source` says so rather than leaving the operator to infer it.

Nothing is written to the source, and a failed capture leaves no partial
image. Output to a file is created exclusively, so a capture never overwrites
something it was not asked to and never removes a file it did not create;
non-raw formats are assembled into a staging file beside the destination and
converted only once that is complete.

`-O` accepts the same formats as `convert`, including `raw.gz` and `-o -` for
a stream. `-O vhd` is written *fixed*, as `build-image` writes it, because the
reason to want a captured image as a VHD is almost always an Azure
managed-disk upload and those refuse dynamic.

## The root output filesystem (ext4 or XFS)

The generated root filesystem is ext4 by default, and every surface keeps that
default, so an image built without asking for anything else is byte-for-byte the
image it always was. When a run does ask for XFS instead, the root is written by
the bounded native XFS v5 writer -- the same offline, deterministic,
mount-free construction the ext4 writer uses, not a call out to `mkfs.xfs`. The
ESP is unaffected either way: it is always FAT32, planned and populated as its
own partition.

The two roots are not interchangeable in every combination, and the
incompatible ones are refused up front, by name, rather than half-built:

- **dm-verity** is an ext4-root feature here. The verity split and hash tree are
  computed on ext4's block geometry, and the bounded XFS writer fills an
  in-memory buffer it rounds down to whole allocation groups, so a *verified*
  XFS root is not something this path can seal. `--root-filesystem xfs` with
  `--verity` (or `.root_filesystem = .xfs` with `.verity = true`) is rejected
  before any work.
- **The ext4 journal** does not describe an XFS root. XFS keeps its own internal
  metadata log rather than an ext4-style JBD2 journal, so `--journal` /
  `--journal-size` are ext4-only knobs. Both entry points reject an ext4 journal
  beside an XFS root by name (`Ext4JournalWithXfsRoot`): `miz build-image`
  rejects an explicit `--journal`, and `miz capture` -- which journals by
  default -- passes that default through untouched, so `--root-filesystem xfs`
  must be paired with `--no-journal` rather than having the flag quietly cleared
  behind the user's back. XFS is already crash-safe through its own log.
- **The XFS volume label** is at most 12 bytes, and the writer rejects a longer
  one rather than truncating it, so a `--label` / `--ext4-label` over that on an
  XFS root is refused with the byte limit named.
- **The privileged preserved-image backends** (`unsafe_chroot`, the VM) mount
  the *source* root to preserve it, and only mount ext4, so they refuse an XFS
  *source* the same way they refuse a FAT32 one. This is a different axis from
  the output selection here: an XFS *output* root is written by `native_fresh`,
  which never mounts anything, so choosing it requires no kernel XFS mount
  support and no capability the ext4 output did not already need.

SELinux root labelling (`--root-selinux-label`) is preserved for an XFS root
exactly as for ext4 -- the `security.selinux` attribute is carried in an XFS
shortform xattr rather than dropped -- and the root inode's mode, ownership and
timestamps match the ext4 writer's, so the choice of filesystem is the only
difference between the two outputs.

| Surface | How to ask for it |
| --- | --- |
| `miz build-image` | `--root-filesystem ext4` (default), `--root-filesystem xfs` |
| `miz capture` | `--root-filesystem ext4` (default), `--root-filesystem xfs` |
| `std.Build` helper (`image.addImage`) | `.root_filesystem = .ext4` (default), `.root_filesystem = .xfs` |
| `build_image.build` | `BuildImageOptions.root_filesystem` |
| `disk_assembly.assemble` | `AssembleOptions.root_filesystem` |
| Fresh-storage customization request | `storage.fresh.root_filesystem` |

## Journalling the root filesystem

The native ext4 writer can create a JBD2 journal. It does not by default, and
that default is deliberate rather than an oversight.

Nothing needs a journal while an image is being built. The filesystem is
constructed offline and written atomically, so there is no half-applied
metadata update for a log to protect. That stops being the whole story the
moment the image becomes a running machine's root filesystem. From first boot
onward it is an ordinary mutable ext4 volume, and an unclean shutdown or power
loss leaves a journal-less volume with no recovery log at all: the next boot
faces a full `fsck` with a real chance of data loss, where a journalled volume
would replay in a moment and carry on.

So: build a purpose-built, effectively read-only appliance image without a
journal, and build an image that boots into a mutable root filesystem with one.

`miz capture` is the one surface that inverts the default, because it is the
one surface whose output is by definition a machine that was already running a
mutable root filesystem and will go on doing so.

| Surface | How to ask for it |
| --- | --- |
| `miz build-image` | `--journal`, `--no-journal` (default), `--journal-size <size>` |
| `miz capture` | journalled by default; `--no-journal` to omit |
| `std.Build` helper (`image.addImage`) | `.journal = true`, `.journal_size = <bytes>` |
| `std.Build` helper (`image.addPreservedImage`) | `.journal = .{ .enabled = true, .size_bytes = ... }` |
| Preserved-image configuration JSON (api_version 3) | `"journal": { "enabled": true, "size_bytes": 33554432 }` |
| `preserved_image.RebuildOptions` | `.journal = .{ .enabled = true }` |
| `ext4.populate` / `ext4.preflightPopulate` | `PopulateOptions.journal` |

`--journal-size` implies `--journal`. `--no-journal` clears only the enable
flag, so the last of `--journal` / `--no-journal` on the command line wins.

The journal is `rebuild`-only among the preserved-image backends. Every other
backend keeps the source's filesystem rather than writing a new one, so a
journal setting there would read as a durability choice that nothing acts on;
stating it is `UnexpectedJournalPolicy`.

`--journal` and `--verity` cannot be combined. A dm-verity root is mounted
read-only over a hash tree computed from its exact bytes, so it is never
written to and has nothing to journal.

### Default size

Left unspecified, the journal is sized on `mke2fs`'s own scale -- e2fsprogs'
`ext2fs_default_journal_size`, reproduced exactly -- so an image gets the size
the rest of the ext4 world would have given it. With the 4 KiB blocks this
writer uses:

| Filesystem size | Journal |
| --- | --- |
| below 8 MiB | refused: `FilesystemTooSmallForJournal` |
| 8 MiB .. 128 MiB | 4 MiB |
| 128 MiB .. 1 GiB | 16 MiB |
| 1 GiB .. 2 GiB | 32 MiB |
| 2 GiB .. 16 GiB | 64 MiB |
| 16 GiB .. 32 GiB | 128 MiB |
| 32 GiB .. 64 GiB | 256 MiB |
| 64 GiB .. 128 GiB | 512 MiB |
| 128 GiB and above | 1 GiB |

An explicit size is bounded the same way `mke2fs -J size=` is, and each
rejection has its own name: `UnalignedJournalSize` (not a non-zero whole number
of 4 KiB blocks), `JournalSizeTooSmall` (below the 4 MiB JBD2 minimum),
`JournalSizeTooLarge` (above 40 GiB, or above half the filesystem).

`ext4.defaultJournalBlocks(total_blocks)` exposes the same ladder to callers
that want to size storage before writing anything.

### A journalled image is a different profile

`HAS_JOURNAL` is not part of the `miz_ext4_v1` feature set, and the strict
profile is defined as that exact set. A journalled image is therefore refused
by `scanWriterCompatible` with `UnsupportedWriterProfile` and can only be
imported through `.source_profile = .general`, as `ext4_general_v1` with
`source_reproducible = false`.

This is on purpose. `miz_ext4_v1` is a byte-for-byte reproducibility contract,
and widening it would change what that contract means. A journalled output is a
distinct profile, so a strict rebuild round-trips exactly as it always did.

### What the journal is, and is not

The journal this writer creates is empty. `s_start` is 0, so there is nothing
to replay and no log record is ever written at build time; the kernel takes
over the log on first mount, at which point it also sets
`JBD2_FEATURE_INCOMPAT_CSUM_V3` and the journal-superblock checksum. The
on-disk shape matches what `mke2fs` writes for the same geometry byte for byte,
including the deliberate absence of journal feature bits and a journal
checksum: a journal superblock the kernel trusts but computes differently is
how a bad log gets replayed over good data.

The interim workaround this replaces was `tune2fs -j <image-or-partition>`
after the build. That works, but it puts `e2fsprogs` back on the build host,
which is exactly what a self-contained image builder exists to avoid.

## Sizing the inode table

An ext4 filesystem's inode table is fixed at creation. `mke2fs` sizes it from a
bytes-per-inode ratio -- 16384 by default, so a 16 GiB filesystem gets about a
million inodes -- and the resulting count bounds how many files the filesystem
can *ever* hold, no matter how many blocks are free.

This writer instead sizes the table to the tree it is given: one inode per
node, and nothing spare. For a purpose-built appliance image that is exactly
right. Every byte of an inode table is a byte the image ships, the tree is
known in full before anything is written, and the reproducibility contract
wants the count to be a function of the content rather than of a ratio nobody
recorded.

It is wrong the moment the image becomes a running machine's root filesystem.

### The failure this exists to prevent

A preserved rebuild inherits its `length` from the partition it overwrites, so
a 667 MiB partition holding 450 MiB of content is rebuilt as a 667 MiB
filesystem with 213 MiB free -- and **3 free inodes out of 11808**, because
11805 nodes went in. The first boot then fails to create a single file while a
`df` shows a third of the disk free. What that looks like in practice is a
service reporting `ENOSPC` from somewhere that has nothing to do with space:

```
store.New failed: open /var/lib/tailscale/tailscaled.state: no space left on device
```

`df -i` is the diagnosis, and nothing in the build output would have hinted at
it, which is why the rebuild report and provenance now state `inode_count` and
`free_inode_count` outright.

### Asking for room

`bytes_per_inode` sets the same ratio `mke2fs -i` does: the table is sized to
`filesystem_length / bytes_per_inode` inodes, or to the node count, whichever
is larger. A tree that needs more inodes than the ratio allows still gets them;
the ratio is a floor, not a cap.

| Surface | Spelling |
| --- | --- |
| `std.Build` helper (`image.addPreservedImage`) | `.inodes = .{ .bytes_per_inode = 16384 }` |
| Preserved-image configuration JSON (api_version 3) | `"inodes": { "bytes_per_inode": 16384 }` |
| `preserved_image.RebuildOptions` | `.inodes = .{ .bytes_per_inode = 16384 }` |
| `ext4.populate` / `ext4.preflightPopulate` | `PopulateOptions.inodes` |

16384 is what `mke2fs`, and so a distro installer, would have used. There is no
CLI flag: the ratio only means anything for a preserved rebuild, which is
configured by file rather than by argument.

**The default is unchanged and stays unchanged.** Defaults here are
load-bearing -- they decide the bytes an existing image definition produces --
so an image that never sets this keeps getting the content-derived count it has
always had.

A ratio raises the filesystem's minimum size, since the table has to fit
alongside the content; `ext4.minimumPopulateLength` accounts for it, so a
caller that sizes storage from that number does not have to. `0` is
`InvalidInodeRatio` rather than a synonym for the default, and a ratio that
demands more inodes than the geometry can hold is `TooManyInodes` rather than a
silent clamp.

Like the journal, this is `rebuild`-only among the preserved-image backends --
every other backend keeps the source's filesystem rather than writing a new one
-- and stating it elsewhere is `UnexpectedInodePolicy`.

### Why this is not simply the default

Growing the filesystem is the other answer, and on a cloud image it is the one
that usually runs first: `miz`'s Azure agent resizes the root partition to the
OS disk on first boot, and `resize2fs` adds block groups, each bringing
`inodes_per_group` more inodes with it. That masks the problem on Azure while
leaving it fully present anywhere the image boots at its built size -- a local
QEMU run, a fixed-size disk, a first boot that fails before the resize. An
image should not depend on being grown to be able to create a file.

## Import limits and scratch space

Every import is bounded. The defaults are guardrails sized for a purpose-built
image, not a statement about how large a real root filesystem is: a full server
install with a desktop environment, a toolchain and vendor driver stacks
routinely passes 1,000,000 inodes, and `--max-nodes` is the first wall it hits.
Each limit is raisable on its own, and none is library-only.

| Flag | Bounds | Default |
| --- | --- | --- |
| `--max-nodes` | imported inodes | 1000000 |
| `--max-path-bytes` | longest imported path | 4096 |
| `--max-component-bytes` | longest single path component | 255 |
| `--max-file-bytes` | largest single imported file | 16G |
| `--max-total-bytes` | total imported content | 64G |
| `--max-spool-bytes` | spool file holding the imported content | 128G |
| `--max-xattrs-per-node` | extended attributes on one inode | 256 |
| `--max-xattr-bytes-per-node` | extended attribute bytes on one inode | 1M |
| `--max-scan-metadata-bytes` | metadata a source scan may hold | 256M |
| `--max-source-file-bytes` | largest host file an operation may read in | 1G |

Values accept the same binary suffixes as `--size` (`4M` is 4194304), which is
why a count such as `--max-nodes 8M` is accepted and means 8388608.

`miz build-image` and `miz capture` take the eight that bound the tree they
build. The
`std.Build` helpers (`miz_image.add`, `miz_image.addPreserved`) take all of
them as `limits`, and the preserved-image builder takes all of them, including
the two that only a source scan and an operation can reach.

Exceeding one is reported with everything needed to retry:

```
build-image: failed: error.NodeLimitExceeded: 1000001 nodes exceeds the configured limit of 1000000; raise it with --max-nodes <value>
raise the limit with --max-nodes 1000001 or higher, or import less content.
```

The same breach reaches a build graph as a `limit_exceeded` diagnostic in
`diagnostics.json`, with the flag in its `remediation` field.

Every run also reports the peak each limit actually reached, so the next run
can be sized from a measurement instead of a guess. `miz build-image` prints
them, `--dry-run` included:

```
  peak nodes: 41231 of 1000000 (--max-nodes)
  peak bytes: 2402161 of 17179869184 (--max-file-bytes)
```

`preserved_image.rebuild` and `preserved_image.inspectRebuild` return the same
figures as `limit_peaks`, and provenance records them under
`execution.limit_peaks`.

### Scratch space

A rebuild spools a full copy of every imported file byte, so importing a 35 GB
source needs about 35 GB of scratch space on the filesystem holding the output,
plus the raw staging image (the source's full virtual size), plus the converted
or compressed artifact when the output is not raw. That last one is free for an
uncompressed raw output, which is published by renaming the stage.

The check runs before the spool is created, so a workspace that cannot hold the
import is refused with `error.InsufficientWorkspaceSpace` up front rather than
discovered most of the way through a long copy. A host whose free space cannot
be determined skips the check: unknown is not the same as too little.
`inspectRebuild` reports `workspace_space` without enforcing it, since it
creates no files and the caller may free space before committing.

## Compressed and streamed output

`-O raw.gz` and `-O raw.zst` produce a compressed raw image. The compressor
runs as the image is produced, not as a separate pass over a finished file,
so a build never has to materialize the full uncompressed raw locally --
which is usually the single largest cost of producing a disk image. Both
`convert`, `build-image` and `capture` accept them, as do the customization entry points
(`miz.customize` and the `miz-image-builder`/`miz-preserved-image-builder`
bundle executables) via the same `-O` spelling.

`-o -` writes the artifact to stdout instead of a file, so the result can be
piped:

```
miz convert -O raw.gz -o - disk.qcow2 - | ssh host 'cat > image.raw.gz'
miz build-image --iso azurelinux.iso --container ./oci-layout --size 4G \
    -O raw.gz -o - > image.raw.gz
miz capture --source /dev/sda -O raw.gz -o - | ssh host 'cat > captured.raw.gz'
```

The published gzip artifact is directly consumable by the usual idiom:

```
curl https://example/image.raw.gz | gunzip | dd of=/dev/sdX bs=4M status=progress
```

Only `raw` can be compressed or streamed. `vhd` writes its footer after the
data, `vhdx` amends its block allocation table, and `qcow2` amends its L1 and
refcount tables, so all three need to seek backwards over bytes they already
wrote. A compressor cannot revisit those bytes and stdout cannot be rewound,
so these combinations are rejected up front -- `CompressionRequiresRawFormat`
for `-O vhd.gz` and friends, `FormatRequiresSeekableOutput` for `-o -` with a
seek-back format -- rather than silently producing a corrupt artifact.

`--compress-level <1-9>` selects the gzip level and defaults to `1`. That
default is deliberate: a disk image is dominated by long runs of zeros, which
every deflate level collapses to almost nothing, so higher levels cost
substantial wall-clock time for a very small size gain. zstd has no level
knob here; asking for one with `-O raw.zst` is an error rather than a
silently ignored flag.

Sparse regions stay cheap. The streaming writer walks the source's extent map
and emits unallocated regions as zero runs without reading them, and
all-zero chunks of allocated regions are recognized and emitted the same way.
The zeros are fed *to* the compressor rather than skipped, so the artifact is
always exactly the image's virtual size once decompressed; the writer asserts
that byte count before it reports success.

Because `miz` constructs filesystems natively rather than capturing a
running system, the usual "fill the free space with zeros before imaging so
that it compresses" step is unnecessary. Unallocated blocks in a freshly
built ext4 have never held anything, so they are already zero, and both the
extent map and the all-zero chunk detection reduce them to compressed zero
runs. Skipping that pass saves writing the full virtual size twice.

## Formats and filesystem APIs

`convert` skips all-zero chunks (aligned to the destination's block size for
sparse block formats such as dynamic vhd and vhdx), so converting a
mostly-empty raw image into a sparse image stays sparse instead of eagerly
allocating every block it touches.

MBR/GPT partition-table read/write is available as a library API
(`miz.mbr`, `miz.gpt`, `miz.guid`) with round-trip test coverage, used by
`miz azure fixup` to validate the disk's partition style against the
requested Hyper-V generation (Gen1 = plain MBR, Gen2 = protective MBR + GPT).
Gen2 validation cross-checks both GPT headers and byte-identical partition
arrays. In-place fixup rejects unaligned GPT images before mutation; use
`miz azure derive` for transactional alignment and relocation.
There is no interactive partitioning CLI command yet -- that lands with
`miz build-image`.

FAT32 filesystem support is currently library-only (`miz.fat32`). Callers
format a partition-sized region inside an existing `miz.Image`, then use the
returned/opened filesystem handle to create directories, write full file
contents, list directory entries, and read files back -- including VFAT long
file names such as typical `EFI/...` ESP paths.

VHDX support (`miz.vhdx`) covers create/read/write/resize/check for
non-differencing images with 512-byte logical sectors -- the common case.
`miz build-image` can emit VHDX output directly, and `convert`/`resize`
operate on VHDX images the same way they already do for raw/VHD/qcow2. No real Hyper-V/QEMU install was
available in this environment to generate reference VHDX files, so
correctness was verified against QEMU's own `block/vhdx.c`/`vhdx.h` (struct
layout, CRC-32C checksums, the BAT chunk-ratio interleaving formula, and the
create-path metadata layout) plus writable round-trip tests exercised through
both `miz.vhdx` and the full `Image` API in the test suite.

ext4 support lives at `miz.ext4`. The writer entry point is:

```zig
try miz.ext4.populate(io, file, allocator, &tree, .{
    .offset = 0,
    .length = fs_bytes,
    .block_size = 4096,
    .label = "rootfs",
});
```

`tree` is a small vtable-style `FileTreeView` owned by `ext4.zig`: each
`next()` yields a relative path plus `{ kind, mode, uid, gid, size }` and an
optional `content.readAt(buffer, offset)` callback for regular files and
symlinks. Paths are relative to the ext4 root; the root directory itself is
implicit. The writer emits `DIR_INDEX` htree directories (with interior
index nodes once a directory outgrows a single root index block),
`METADATA_CSUM` crc32c checksums on bitmaps/GDTs/superblocks/inodes/
directory leaf blocks/xattr blocks, and extent trees (inline for small
files, spilling into real extent/index blocks up to depth 4 for larger or
fragmented ones); quota files are never written. A JBD2 journal is
optional and off by default (see "Journalling the root filesystem").
`resize()` supports offline, in-place growth of a filesystem with or
without a journal, and refuses a `resize_inode` filesystem by name with
`ResizeInodeNotSupported`. The paired
reader API can `statPath`, `listDir`, `preadPath`, `readExtents`, and
`readLinkAlloc` for round-trip verification.

Bootloader population lives at `miz.bootconfig`. It reuses the exact same
`FileTreeView` shape as `miz.ext4`, so future orchestration can drive rootfs
population plus either ESP/UEFI or BIOS/MBR boot installation from one merged
source-tree interface. For Gen2/GPT callers pass the planned GPT partitions
plus their unique GUIDs, then `populateEsp()` copies discovered
`EFI/.../*.efi` binaries into a FAT32 ESP and, depending on `boot_mode`,
generates the existing shim/GRUB/BLS text files, named `EFI/Linux/*.efi`
UKIs, or both. The same pass also copies shim/MOK auxiliary assets such as
`mm*.efi`, `MokManager`, and enrollment/config files that already exist in the
source tree. For Gen1/MBR, `installBiosBoot()` discovers prebuilt
`boot/grub2/i386-pc/boot.img` + `core.img` assets (or equivalent common
locations) and embeds them into the post-MBR gap ahead of the first 1 MiB
aligned root partition while preserving the existing MBR partition table.

```zig
try miz.bootconfig.populateEsp(allocator, io, &esp_fs, &tree, .{
    .planned_partitions = planned_partitions,
    .boot_mode = .bls_and_uki,
    .path_strip_prefix = "",
    .extra_kernel_options = "console=ttyS0",
    .uki = .{
        .output_directory = "EFI/Linux",
    },
});
```

The same `extra_kernel_options` text can also be added to an image that already
exists, by whichever mechanism that image's own layout supports.
`miz.customize`'s `native_edit` and `rebuild` backends append it to the GRUB
and BLS entries on the image's ESP instead of generating them. The privileged
`unsafe_chroot` backend instead appends it to `GRUB_CMDLINE_LINUX` in the
target's `/etc/default/grub` and runs the target's own `grub2-mkconfig`, which
is the durable form on a distro image because the generated configuration is
rewritten from that input on every kernel package change. The `vm` backend and
Unified Kernel Images are refused by name. See `doc/library-api.md`.

The low-level PE/COFF rewriting lives in `miz.uki`, which takes a prebuilt
stub plus kernel/initrd/cmdline payloads and emits a structurally valid UKI
with `.linux`, `.initrd`, `.cmdline`, `.osrel`, `.uname`, and optional
`.splash` sections.

`miz build-image` currently writes `raw`, fixed `vhd`, `vhdx`, and `qcow2`
outputs. Both Gen2
(UEFI/protective-MBR+GPT+ESP) and Gen1 (BIOS/plain-MBR with GRUB embedded into
the post-MBR gap) are now fully wired in `miz build-image`, and both
generations can optionally append a same-partition dm-verity SHA-256 hash tree
with `--verity`, wiring the resulting `roothash=`/`systemd.verity_root_*`
parameters through the shared PARTUUID-based cmdline path. Gen1/MBR builds use
Linux's synthesized MBR PARTUUID form (`<8-hex-disk-signature>-<2-hex-partition-number>`);
the matching verity metadata is also exposed through `miz.cosi.writeWithOptions`,
and a v3 customization request can publish that bundle directly with
`-O cosi` (see [Library API](library-api.md) for which backends emit it).

`miz build-image` never rebuilds the initramfs -- it copies whatever
`boot/initramfs*`/`boot/initrd*` blob already exists in the merged
ISO/squashfs/container source tree. Because of that, `--verity` only works
end-to-end if that source initramfs already includes dm-verity userspace
tooling (`systemd-veritysetup-generator`, `systemd-veritysetup`, or
`veritysetup`, e.g. built with `dracut --add systemd-veritysetup`); without it,
`systemd-veritysetup-generator` never runs at boot and the image hangs
forever waiting on `/dev/mapper/root` (see
[issue #77](https://github.com/cataggar/miz/issues/77) for the real-boot
investigation that diagnosed this). `build-image --verity` inspects the
selected initramfs (decompressing it as needed) and fails fast with a
`--verity`-specific error when it can conclusively tell the tooling is
missing, rather than silently producing an image that hangs at boot; if the
initramfs can't be fully parsed (e.g. an unrecognized compression format),
it instead prints a warning and proceeds.

## Producing a verity-capable initramfs (e.g. for Azure Linux)

Live/installer media (such as the Azure Linux ISO) typically ships an
initramfs built for the installer environment itself, which has no need for
dm-verity and so is usually missing the pieces above even when the installed
system's own root filesystem has them (`systemd-udev`'s
`systemd-veritysetup-generator`/`systemd-veritysetup`, and
`cryptsetup`/`veritysetup`'s `libcryptsetup`, plus the `dm-verity`/`dm-mod`
kernel modules). Regenerate the initramfs with `dracut --add systemd-veritysetup`
against a rootfs that has these installed, then supply the result as a
`--container` layer at the *same* `boot/initramfs-<kver>.img` path already
used by the ISO/squashfs rootfs -- OCI container layers always take
precedence over ISO/squashfs entries at the same path, so no `miz` flag is
needed to use it in place of the stock copy.

On a matching-architecture build host (or inside a container/chroot for that
architecture), this is a normal, native `dracut` invocation:

```bash
dracut --add systemd-veritysetup --force --kver <kernel-version> /path/to/initramfs-verity.img
```

Building this cross-architecture (e.g. generating an x86_64 initramfs on an
aarch64 build host, via `qemu-user`/`binfmt_misc` emulation) additionally
needs:

- `dracut --sysroot <mounted-or-extracted-rootfs> --no-hostonly --add
  systemd-veritysetup --force --kver <kernel-version> <output>` (`<output>`
  is a positional argument -- dracut's `-o`/`--omit` flag means something
  else entirely: a list of dracut modules to omit), with
  `DRACUT_ARCH=<target-arch>` and `QEMU_LD_PREFIX=<sysroot>` exported so the
  emulated target-arch helper binaries (e.g. `dracut-install`) can find their
  own shared libraries.
- A working cross-arch `ldd` on `PATH`: dracut-install invokes the plain
  `ldd` command by name to resolve each installed binary's shared-library
  dependencies, but a host system's own `ldd` script typically refuses
  foreign-architecture binaries outright (printing `not a dynamic
  executable`) rather than actually resolving them, which silently drops
  every shared library (including the dynamic loader itself) from the
  generated initramfs -- producing an initramfs that panics at boot with
  `Failed to execute /init`. Shadow `ldd` on `PATH` with a small wrapper that
  invokes the target's own dynamic linker in list mode instead, e.g.:
  ```bash
  #!/bin/bash
  # save as e.g. /tmp/fakebin/ldd (with /tmp/fakebin first on PATH)
  exec qemu-x86_64 -L "$QEMU_LD_PREFIX" "$QEMU_LD_PREFIX/lib64/ld-linux-x86-64.so.2" --list "$1"
  ```

This was verified end-to-end with a real QEMU + OVMF boot of a Gen2 +
`--verity` Azure Linux 4.0 image built this way: the image reaches a real
login prompt and root shell with `veritysetup.target` active.
