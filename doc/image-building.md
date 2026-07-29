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
zvmi convert -O raw.gz disk.qcow2 disk.raw.gz    # compressed while writing, never a full raw on disk
zvmi convert -O raw.gz -o - disk.qcow2 - | ssh host 'cat > disk.raw.gz'
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
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G -o output.raw.gz -O raw.gz
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
| `rebuild` | none | no | any | full tree rebuild of one ext4 partition |
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

#### Which ext4 sources `rebuild` accepts

The `rebuild` backend reads a filesystem's whole tree and writes a new one, so
it has to understand the source. It offers two profiles, selected by
`source_profile` on the `std.Build` helper, in the preserved-image
configuration JSON, and on `preserved_image.RebuildOptions`.

| Profile | Accepts | Reproducible |
| --- | --- | --- |
| `strict` (default) | only `zvmi_ext4_v1`, the exact layout this project's writer emits | yes, byte for byte |
| `general` | any ext4 the general reader accepts, including a stock distro root | no |

`strict` requires 128-byte inodes, 32-byte group descriptors and exactly the
`filetype`+`extents` incompatible feature set: no journal, no `64bit`, no
`flex_bg`. That is deliberate rather than incidental. It is the promise that
rebuilding the same source twice, on any host, produces the same bytes.

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
- `mode`, `uid`, `gid`, and `atime`/`mtime`/`ctime` per inode
- extended attributes, both inline in a 256-byte inode's spare space and in an
  external xattr block; this is what carries `security.selinux` and
  `system.posix_acl_access`/`system.posix_acl_default`, so dropping them would
  silently break MAC policy and ACLs

Two limits are inherent to the writer rather than the importer. Output inodes
are 128 bytes, so a timestamp outside 1970..2106 has nowhere to go and is
refused with `TimestampOutOfRange` rather than wrapped into a plausible-looking
wrong date. And the journal is never replayed: a source must be cleanly
unmounted, and a superblock still marked as needing recovery or carrying orphan
inodes is a hard error rather than a filesystem imported halfway.

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
`zvmi_ext4_v1` source. The output is then a function of several sources rather
than of the one the report names, and the report says so.

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

`zvmi build-image` takes the eight that bound the tree it builds. The
`std.Build` helpers (`zvmi_image.add`, `zvmi_image.addPreserved`) take all of
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
can be sized from a measurement instead of a guess. `zvmi build-image` prints
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
`convert` and `build-image` accept them, as do the customization entry points
(`zvmi.customize` and the `zvmi-image-builder`/`zvmi-preserved-image-builder`
bundle executables) via the same `-O` spelling.

`-o -` writes the artifact to stdout instead of a file, so the result can be
piped:

```
zvmi convert -O raw.gz -o - disk.qcow2 - | ssh host 'cat > image.raw.gz'
zvmi build-image --iso azurelinux.iso --container ./oci-layout --size 4G \
    -O raw.gz -o - > image.raw.gz
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

Because `zvmi` constructs filesystems natively rather than capturing a
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
