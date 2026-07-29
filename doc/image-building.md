# Image building

## Building images and current capabilities

Supports `raw`, fixed `vhd`, dynamic `vhd`, `vhdx`, `qcow2`, MBR/GPT partition tables,
native FAT32 filesystem read/write for ESP-style partitions, native ESP
bootloader population (copy prebuilt EFI binaries + generate `grub.cfg`/BLS
text), an Azure-readiness check, **read-only** ISO9660
(+Rock Ridge/Joliet) and squashfs readers (including
XZ/zstd-compressed squashfs blocks), automatic unwrapping of nested ext4 or
squashfs rootfs images discovered inside squashfs payloads (matching LiveOS
media such as Azure Linux 4.0), local OCI container image ingestion, a minimal
native ext4 writer/readback library API, COSI output packaging, and a first
`zvmi build-image` orchestration path that builds `raw`, fixed-`vhd`, `vhdx`,
and `qcow2` disk images from an ISO + local OCI layout:

```
zvmi create -f vhd disk.vhd 32M                          # dynamic by default (matches qemu-img)
zvmi create -f vhd -o subformat=fixed disk.vhd 32M       # required for Azure managed-disk upload
zvmi info disk.vhd
zvmi info --output=json disk.vhd
zvmi convert -f raw -O vhd -o subformat=dynamic disk.img disk.vhd
zvmi convert -f raw -O vhdx disk.img disk.vhdx
zvmi convert -f vhdx -O vhd -o subformat=fixed disk.vhdx disk.vhd  # import a VHDX (e.g. Hyper-V export)
zvmi resize disk.vhdx +4G
zvmi resize disk.vhd +4G
zvmi check disk.vhd
zvmi map disk.vhd
zvmi azure derive --input-sha256 <hex> input.qcow2 output.vhd  # transactional aligned Gen2 VHD + GPT relocation
zvmi azure fixup disk.vhd                     # Gen2 default; fixed VHD is padded and checked in place
zvmi azure fixup disk.qcow2                   # converts to disk.vhd, then pads and checks for Gen2
zvmi azure fixup --generation 1 legacy.vhd   # explicit legacy BIOS/MBR validation
zvmi azure deprovision disk.vhd                    # generalize: reset hostname/SSH host keys/machine-id/DHCP state
zvmi azure deprovision --user azureuser disk.vhd   # also removes that user account + its home directory
zvmi azure deprovision --allow-device-write /dev/sda  # generalize an installed system in place on a block device
zvmi info /dev/sda                           # inspect a block device (Linux); devices are read-only by default
zvmi cosi disk.img -o disk.cosi              # tar + metadata.json + per-partition raw.zst
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.vhd  # Gen2 default
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.raw -O raw
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.vhdx -O vhdx
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.qcow2 -O qcow2
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 384M --skip-iso-rootfs -o output-minimal.raw -O raw
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G --verity -o output.vhd
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G --boot-mode uki --esp-size 512M -o output-uki.vhd
zvmi qemu AzureLinux
zvmi qemu AzureLinux --snapshot
```

OCI ingestion defaults to 64 MiB compressed blobs, 128 MiB decompressed
layers, and 512 MiB docker/podman save archives. Deliberately larger trusted
inputs can opt into explicit bounded limits with `--max-oci-blob-size`,
`--max-oci-layer-size`, and `--max-oci-archive-size`.

`build-image` consumes a local OCI layout. Materialize a remote image first with `zvmi oci copy docker://registry/repository@sha256:<digest> oci:./oci-layout`, or use the digest-pinned `addOciPull` helper from an external `build.zig`. See [OCI transports](oci.md) and [Library API](library-api.md).

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
real `waagent.service`. As with the UKI stub, `zvmi` never builds or injects
the `azagent` binary itself -- add it via an extra container layer,
cross-compiled for the image's target architecture. This only applies to a
full (non-`--skip-iso-rootfs`) image, since its systemd comes from the
merged distro content; a `--skip-iso-rootfs` image's `/sbin/init` is
responsible for invoking `azagent` itself if it wants first-boot
provisioning, since there's no guarantee of systemd being present at all in
that minimal path (`zvminit` does this -- see `zvminit/README.md`). Generalized
images using `zvminit` must add `zvminit.mode=persistent` to the kernel command
line so provisioned users, SSH keys, host keys, and the azagent sentinel are
written to the root filesystem instead of ephemeral overlays. `zvminit` defaults
to `zvminit.azure=auto`: readable provisioning media or DHCP option 245 selects
Azure, while missing positive evidence remains unknown and is retried because
Azure can expose the provisioning disc after networking completes. Positive
Azure decisions are stored under `/var/lib/azagent` and bound to the current
DMI product UUID; `zvmi azure deprovision` clears them.
Use `zvminit.azure=on` or `off` as a per-boot diagnostic override. Also add
`init=/sbin/zvminit` when the container includes systemd as an OpenSSH dependency,
ensuring the initramfs launches `zvminit` rather than systemd directly.
The serial root shell is disabled by default and released core-image command
lines do not enable it. `zvminit.shell=on` is an explicit diagnostic-only boot
override. PID 1 logs through `/dev/console`, discovers `ttyS*`/`ttyAMA*` and
other serial console names from the kernel command line or active-console
sysfs state, and emits `ZVMINIT_PID1_READY supervisor loop active` after
entering its child-reaping supervisor loop.

`azagent` validates OVF usernames using the conservative policy
`[a-z][a-z0-9_-]{0,31}` (no trailing `-`, and `root` is reserved) and validates
every public key as one printable line of at most 16 KiB containing a plausible
authorized_keys key-type/base64 pair. Local provisioning writes the existing
`/var/lib/azagent/provisioned` sentinel before Azure Ready acknowledgement.
Every normal invocation reports Ready even when that sentinel already exists,
and a WireServer failure is returned so `zvminit` retries without recreating
the account or keys. Synthetic local OVF media must contain the explicit
`zvmi-local-provisioning` marker; under the default `zvminit.azure=auto`,
only that marker makes `zvminit` invoke `azagent --skip-ready`. An unmarked OVF
document retains normal Azure Ready acknowledgement.
Azure still requires every generalized-VM deployment to supply an
`adminUsername`; use `g` for this image convention. The generated
`waagent.conf` mounts the temporary resource disk at `/d` and enables
managed-data-disk activation by stable Azure LUN at `/e` through `/z`. Managed
disks are mount-only: existing ext4 partition 1 is mounted, while blank and
unknown layouts are left untouched.

### Reading a block device

Every command that opens an image by path also accepts a block-device node,
so an already-installed system can be inspected without first copying it into
an image file:

```
zvmi info /dev/sda            # physical or attached disk
zvmi map /dev/nvme0n1
zvmi info /dev/mapper/vg-lv   # a logical volume, read through device-mapper
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

- `zvmi create` refuses a device path outright.
- `zvmi resize` refuses a device: its size belongs to whatever provides it.
- Writing through a device requires an explicit opt-in --
  `zvmi azure deprovision --allow-device-write /dev/sda`, or
  `Image.openPathWithOptions(io, path, .{ .allow_device_write = true })` from
  the library. Without it, every write fails with
  `BlockDeviceWriteNotPermitted`.

### Preserved-image customization backends

Customizing an image that already exists selects one of five backends. They are
ordered by how much they can do, which is the same order as how much they need.

| Backend | Privileges | Runs guest code | Architectures | Can do |
| --- | --- | --- | --- | --- |
| `native_edit` | none | no | any | overwrite, remove existing paths |
| `rebuild` | none | no | any | full tree rebuild of one `zvmi_ext4_v1` partition |
| `native_fresh` | none | no | any | build a new image rather than edit one |
| `unsafe_chroot` | root + `CAP_SYS_CHROOT`/`CAP_SYS_ADMIN`/`CAP_MKNOD` | yes, on the host kernel | host's only | install/remove packages, regenerate initramfs |
| `vm` | none | yes, in an isolated guest | any | install/remove packages, regenerate initramfs, cross-architecture |

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

## Formats and filesystem APIs

`convert` skips all-zero chunks (aligned to the destination's block size for
sparse block formats such as dynamic vhd and vhdx), so converting a
mostly-empty raw image into a sparse image stays sparse instead of eagerly
allocating every block it touches.

MBR/GPT partition-table read/write is available as a library API
(`zvmi.mbr`, `zvmi.gpt`, `zvmi.guid`) with round-trip test coverage, used by
`zvmi azure fixup` to validate the disk's partition style against the
requested Hyper-V generation (Gen1 = plain MBR, Gen2 = protective MBR + GPT).
Gen2 validation cross-checks both GPT headers and byte-identical partition
arrays. In-place fixup rejects unaligned GPT images before mutation; use
`zvmi azure derive` for transactional alignment and relocation.
There is no interactive partitioning CLI command yet -- that lands with
`zvmi build-image`.

FAT32 filesystem support is currently library-only (`zvmi.fat32`). Callers
format a partition-sized region inside an existing `zvmi.Image`, then use the
returned/opened filesystem handle to create directories, write full file
contents, list directory entries, and read files back -- including VFAT long
file names such as typical `EFI/...` ESP paths.

VHDX support (`zvmi.vhdx`) covers create/read/write/resize/check for
non-differencing images with 512-byte logical sectors -- the common case.
`zvmi build-image` can emit VHDX output directly, and `convert`/`resize`
operate on VHDX images the same way they already do for raw/VHD/qcow2. No real Hyper-V/QEMU install was
available in this environment to generate reference VHDX files, so
correctness was verified against QEMU's own `block/vhdx.c`/`vhdx.h` (struct
layout, CRC-32C checksums, the BAT chunk-ratio interleaving formula, and the
create-path metadata layout) plus writable round-trip tests exercised through
both `zvmi.vhdx` and the full `Image` API in the test suite.

ext4 support lives at `zvmi.ext4`. The writer entry point is:

```zig
try zvmi.ext4.populate(io, file, allocator, &tree, .{
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
fragmented ones); it deliberately ships without a journal or quota files,
since the target image-build flow creates filesystems offline and writes
them atomically. `resize()` supports offline, in-place growth. The paired
reader API can `statPath`, `listDir`, `preadPath`, `readExtents`, and
`readLinkAlloc` for round-trip verification.

Bootloader population lives at `zvmi.bootconfig`. It reuses the exact same
`FileTreeView` shape as `zvmi.ext4`, so future orchestration can drive rootfs
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
try zvmi.bootconfig.populateEsp(allocator, io, &esp_fs, &tree, .{
    .planned_partitions = planned_partitions,
    .boot_mode = .bls_and_uki,
    .path_strip_prefix = "",
    .extra_kernel_options = "console=ttyS0",
    .uki = .{
        .output_directory = "EFI/Linux",
    },
});
```

The low-level PE/COFF rewriting lives in `zvmi.uki`, which takes a prebuilt
stub plus kernel/initrd/cmdline payloads and emits a structurally valid UKI
with `.linux`, `.initrd`, `.cmdline`, `.osrel`, `.uname`, and optional
`.splash` sections.

`zvmi build-image` currently writes `raw`, fixed `vhd`, `vhdx`, and `qcow2`
outputs. Both Gen2
(UEFI/protective-MBR+GPT+ESP) and Gen1 (BIOS/plain-MBR with GRUB embedded into
the post-MBR gap) are now fully wired in `zvmi build-image`, and both
generations can optionally append a same-partition dm-verity SHA-256 hash tree
with `--verity`, wiring the resulting `roothash=`/`systemd.verity_root_*`
parameters through the shared PARTUUID-based cmdline path. Gen1/MBR builds use
Linux's synthesized MBR PARTUUID form (`<8-hex-disk-signature>-<2-hex-partition-number>`);
the matching verity metadata is also exposed through `zvmi.cosi.writeWithOptions`.

`zvmi build-image` never rebuilds the initramfs -- it copies whatever
`boot/initramfs*`/`boot/initrd*` blob already exists in the merged
ISO/squashfs/container source tree. Because of that, `--verity` only works
end-to-end if that source initramfs already includes dm-verity userspace
tooling (`systemd-veritysetup-generator`, `systemd-veritysetup`, or
`veritysetup`, e.g. built with `dracut --add systemd-veritysetup`); without it,
`systemd-veritysetup-generator` never runs at boot and the image hangs
forever waiting on `/dev/mapper/root` (see
[issue #77](https://github.com/cataggar/zvmi/issues/77) for the real-boot
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
precedence over ISO/squashfs entries at the same path, so no `zvmi` flag is
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
