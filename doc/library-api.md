# Library API

## Inspect UKI signing certificates

Open a supported disk format with `zvmi.Image`, then use
`zvmi.uki_certificate.extractAlloc` to inspect its ESP without mounting it:

```zig
var image = try zvmi.Image.openPathReadOnly(io, "release.qcow2");
defer image.close(io);

const expected = try zvmi.artifact_pipeline.parseSha256(
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
);
var signer = try zvmi.uki_certificate.extractAlloc(
    allocator,
    io,
    &image,
    .{ .expected_sha256 = expected },
);
defer signer.deinit(allocator);
```

The result owns the exact signer DER, its SHA-256, DER subject/issuer names,
serial number, and sorted fallback/named UKI paths. The API requires one ESP,
one fallback architecture, at least one `EFI/Linux/*.efi`, and the same leaf
certificate on every UKI. QCOW2 dependencies are rejected. Certificate
selection follows CMS `SignerInfo`; extraction does not verify the signature
or establish trust, so callers must independently pin the image and/or
expected fingerprint.

## Use from another `build.zig`

Declare zvmi as a package dependency named `zvmi`, then import its build helper and use the returned `LazyPath` like any other generated file:

```zig
const std = @import("std");
const zvmi = @import("zvmi");

pub fn build(b: *std.Build) void {
    const dependency = b.dependencyFromBuildZig(zvmi, .{
        .target = b.graph.host,
    });

    const image = zvmi.addImage(b, dependency, .{
        .name = "appliance",
        .input = .{
            .iso = b.path("inputs/azurelinux.iso"),
            .container = .{ .oci_layout = b.path("inputs/oci-layout") },
        },
        .output = .{
            .format = .qcow2,
            .basename = "appliance.qcow2",
        },
        .size = 4 * 1024 * 1024 * 1024,
        .target_architecture = .x86_64,
        .generation = .gen2,
        .rootfs_path_in_iso = "images/rootfs.squashfs",
        .reproducibility = .{
            .seed = [_]u8{0x42} ** 32,
            .source_date_epoch = 1_735_689_600,
        },
        .os = .{
            .filesystem = &.{
                .{ .put_file = .{
                    .path = "/etc/appliance.conf",
                    .source = .{ .path = b.path("config/appliance.conf") },
                    .metadata = .{ .mode = 0o640 },
                } },
            },
            .hostname = "appliance",
            .users = &.{.{
                .name = "operator",
                .ssh_authorized_keys = &.{"ssh-ed25519 AAAA..."},
            }},
            .services = &.{.{ .name = "sshd.service", .state = .enabled }},
        },
        .generalization = .{ .azure = .{ .reset_hostname = false } },
        .verity = true,
    });

    const install = b.addInstallFile(image.path, "images/appliance.qcow2");
    const install_provenance = b.addInstallFile(image.provenance_path, "images/appliance.provenance.json");
    b.getInstallStep().dependOn(&install.step);
    b.getInstallStep().dependOn(&install_provenance.step);
}
```

Use `.container = .{ .archive = ... }` for a docker/podman save tarball. OCI layout directories are validated and snapshotted into the Zig build cache so adding, removing, or changing a blob invalidates the image step. Layouts containing symlinks or special files are rejected because Zig 0.16's cached directory-copy step cannot preserve them. The helper runs the dedicated `zvmi-image-builder` artifact for the build host even when the consuming project targets another architecture.

To acquire a registry image as a tracked OCI layout, construct a digest-pinned pull and pass its output directly to `addImage`:

```zig
const pull = zvmi.addOciPull(b, dependency, .{
    .name = "appliance-container",
    .source = "docker://registry.example/team/appliance@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    .platform = .{
        .os = "linux",
        .architecture = "amd64",
    },
    // Optional tracked inputs:
    // .authfile = b.path("registry-auth.json"),
    // .tls_ca = b.path("registry-ca.pem"),
});

const image = zvmi.addImage(b, dependency, .{
    .name = "appliance",
    .input = .{
        .iso = b.path("inputs/azurelinux.iso"),
        .container = .{ .oci_layout = pull.layout },
    },
    // Remaining image options...
});
```

`addOciPull` requires a fully qualified `docker://` SHA-256 digest reference and rejects mutable tags while constructing the build graph. Its selected platform defaults to the build host and may be overridden explicitly; all-platform pulls are intentionally not representable because `addImage` consumes a leaf manifest. `authfile` and `tls_ca` are tracked `LazyPath` inputs, and `plain_http` is an explicit development-registry opt-in. The result exposes `layout` and the underlying run `step`; the network request runs only when a dependent build step needs the layout.

`addImage` also accepts `.journal` and `.journal_size` for the root ext4 filesystem. Both default to journal-less output, which suits a purpose-built appliance whose root is effectively read-only; set `.journal = true` for an image that boots into a mutable root filesystem, where an unclean shutdown would otherwise leave nothing to replay and force a full `fsck`. Left unset, `.journal_size` follows `mke2fs`'s own scale (4 MiB below 128 MiB, 16 MiB below 1 GiB, 32 MiB below 2 GiB, 64 MiB below 16 GiB, up to 1 GiB). It cannot be combined with `.verity`, whose root is mounted read-only over a hash tree and has nothing to journal. See [Journalling the root filesystem](image-building.md#journalling-the-root-filesystem).

`addImage` accepts ordered file/directory/symlink/removal/metadata operations, hostname, groups, users and SSH keys, systemd service state, kernel-module settings, and Azure generalization. File inputs may be inline bytes or tracked `LazyPath` values; plaintext passwords are intentionally not representable, so callers must lock an account or provide a crypt-style pre-hashed value. The helper also returns `plan_path`, `diagnostics_path`, and `provenance_path` from image execution, plus `preflight_plan_path`, `preflight_diagnostics_path`, and `preflight_provenance_path` from a separate non-cacheable capability check. The preflight artifacts remain consumable even when its status gate blocks image execution; unavailable plan or provenance documents contain JSON `null`, while diagnostics explains the failure. Preflight and execution use separate build-cache bundle paths, so their plan hashes intentionally differ; execution repeats preflight against its exact resolved plan before mutation. Successful execution bundles are reused only when a content key covering the host builder, complete request arguments, ISO, container, customization document, and tracked files still matches; failed or stale bundles are cleared and retried instead of becoming permanent cache hits. The target architecture, rootfs path, deterministic seed, and source timestamp are explicit inputs; the resolved plan records generated identifiers and operation ordering, while provenance records source, final root-tree, and output SHA-256 hashes.

To transactionally edit an existing image, use the typed `addPreservedImage` helper:

```zig
const preserved = zvmi.addPreservedImage(b, dependency, .{
    .name = "updated-appliance",
    .input = .{
        .disk = b.path("inputs/appliance.qcow2"),
        .dependencies = &.{
            b.path("inputs/base.qcow2"),
            b.path("inputs/base-data.raw"),
        },
    },
    .root_partition = .{ .gpt_index = 2 },
    .output = .{
        .format = .qcow2,
        .basename = "updated-appliance.qcow2",
    },
    .target_architecture = .x86_64,
    .backend = .rebuild,
    .reproducibility = .{
        .seed = [_]u8{0x24} ** 32,
        .source_date_epoch = 1_735_689_600,
    },
    .operations = &.{
        .{ .overwrite_file = .{
            .path = "/etc/appliance.conf",
            .source = .{ .path = b.path("config/appliance.conf") },
        } },
        .{ .overwrite_file = .{
            .path = "/etc/build-id",
            .source = .{ .inline_bytes = "release-24\n" },
        } },
        .{ .remove_file = "/etc/obsolete.conf" },
        .{ .remove_tree = "/var/cache/obsolete" },
    },
    .os = .{
        .filesystem = &.{
            .{ .put_file = .{
                .path = "/etc/new-appliance.conf",
                .source = .{ .inline_bytes = "created-by=rebuild\n" },
            } },
            .{ .put_directory = .{ .path = "/opt/appliance" } },
        },
        .hostname = "updated-appliance",
    },
});
```

The disk, every transitive qcow2 backing or external-data file, the generated operation configuration, and every replacement are tracked `LazyPath` inputs; inline bytes are materialized through `WriteFiles`. Runtime preflight opens the disk read-only and requires the declared dependency set to exactly match its actual transitive qcow2 closure. The host-native runner preserves the source virtual size, flattens qcow2 dependencies into a standalone output, and returns the same result, preflight, and status-gate artifacts as `addImage`, including when the dependency was configured for a foreign target. GPT and MBR selectors are one-based. A root filesystem on an LVM2 logical volume is selected with `.{ .logical_volume = .{ .volume_group = "ubuntu-vg", .logical_volume = "ubuntu-lv" } }`, where `volume_group` may be omitted on a disk carrying exactly one; see `doc/image-building.md` for what the reader understands and what it refuses.

`addPreservedImage` defaults to `.backend = .native_edit`, which only overwrites existing regular files, removes existing non-directories, and recursively removes existing directories. Select `.backend = .rebuild` to import an ext4 filesystem into owned storage, create/remove files, directories, and symlinks, change represented metadata, apply the pure OS customization model, and generalize the image before rebuilding only the selected partition. Rebuild preserves the ext4 UUID, exact label field, geometry, node contents, metadata and xattrs, and every byte outside the selected filesystem. `.source_profile = .strict` is the default and accepts only the writer-compatible `zvmi_ext4_v1` layout, which is what makes the rebuild reproducible byte for byte; it rejects arbitrary ext4 features, divergent timestamps and partition padding rather than discarding them. `.source_profile = .general` accepts any filesystem the general reader accepts, including a stock `mke2fs` root with 256-byte inodes, a journal, `64bit` and `flex_bg`, and preserves hardlinks, device nodes, FIFOs, per-inode times and inline or block-backed xattrs -- at the cost of the reproducibility claim, which the report states as `source_reproducible = false`. Every feature outside the supported set is refused by its own named error rather than imported partially. `.source_mounts` assembles the rebuild from several filesystems at once, which is what an installed system actually looks like: an ESP, a separate `/boot`, and a root. Each entry names a partition (optionally on another image or block device) and an absolute, normalized mount target, and the sources are merged into one tree before the writer runs, so hardlinks, xattrs, permissions, device nodes and per-inode times survive the merge and not merely the import. A later mount **replaces** whatever the sources before it had at its target rather than merging into it, exactly as a real mount hides the directory underneath -- a root filesystem's stale `/boot` stub must not survive the real `/boot` landing on top of it -- and `shadowed_node_count` reports how much was hidden. Mount targets are validated in full before any source is opened, and every ambiguity has its own error: `MountTargetNotAbsolute`, `MountTargetIsRoot`, `MountTargetNotNormalized`, `DuplicateMountTarget`, `MountTargetShadowedByLaterMount`, `MissingMountTarget`, `MissingMountTargetParent`, `MountTargetNotDirectory`, `MountTargetIsSymlink`, `MountTargetTraversesSymlink`, `MountTargetTraversesNonDirectory` and `MountShadowsHardlinkTarget`. Nothing is normalized or created on the caller's behalf. A source's filesystem is probed from the ext4 superblock magic and the FAT32 boot sector unless stated; looking like both is `AmbiguousSourceFilesystem` and looking like neither is `UnrecognizedSourceFilesystem`. vfat carries no POSIX metadata, so a FAT source's entries take `fat_metadata`, which defaults to the documented `0o755` directories, `0o644` files and `uid = gid = 0` and is settable per mount. Import limits and their reported peaks are accounted across all sources combined rather than per source, and `source_reproducible` is false whenever anything was merged in, since the output is then a function of several sources rather than of the one the report names. Merging retires identifiers, so a rebuild also reconciles the imported tree with the identity the image actually has: `/etc/fstab` is spliced in place -- entries for merged-away filesystems removed whole, changed identifiers replaced field by field, and every other byte including comments, tabs and run-on spacing preserved verbatim -- and the imported bootloader configuration is rewritten in place rather than regenerated, so `root=UUID=`, `root=PARTUUID=`, `search --fs-uuid` and every other whole-token occurrence of a retired UUID is corrected while the distro's menu structure is left alone. The pass then re-scans `/etc/fstab`, `/etc/crypttab`, `/etc/default/grub`, `/etc/default/grub.d/`, `/etc/kernel/cmdline`, `/boot/grub/`, `/boot/grub2/`, `/boot/loader/` and every merged ESP in full, matching case-insensitively, and fails the build with `StaleFilesystemIdentifier` naming the file, the identifier and the byte offset if anything survived; `inspectRebuild` runs the same two passes over a throwaway tree, so an irreconcilable source is refused in preflight. `.identity_rewrite` selects the policy: `.rewrite_and_verify` (the default), `.rewrite_only` for an operator who intends to finish the job with the `unsafe_chroot` backend's own bootloader tooling -- which remains the answer for identifiers embedded in `core.img`, a `grubenv` or a signed EFI binary -- and `.off`. It is `rebuild`-only; stating it elsewhere is `UnexpectedIdentityRewrite`. Identifiers are corrected, paths are not. `.journal` is `rebuild`-only for the same reason -- nothing else writes a filesystem, so stating it elsewhere is `UnexpectedJournalPolicy` -- and defaults to journal-less output; the rebuild writes a fresh filesystem rather than carrying the source's journal across, and both `source_has_journal` and the output's `journal_block_count` appear in the report and in provenance so the change is never silent. Native edit and rebuild do not resize partitions, run package managers, regenerate initramfs, or execute guest code.

Select `.backend = .unsafe_chroot` with `.acknowledge_unsafe = true` to use the first privileged preserved-image executor. It is Linux-only, requires effective root plus `CAP_SYS_CHROOT`, `CAP_SYS_ADMIN`, and `CAP_MKNOD`, and supports only same-architecture execution against an explicitly selected Linux ext4 partition. The current slice accepts online unlocked package install, remove, and update actions through `/usr/bin/tdnf`, literal repository IDs with explicit trust material, and dracut regeneration with `--no-hostonly`; naming no kernel release regenerates every release installed in the target root, discovered after the package actions have run rather than declared in advance, which is what lets an `update_all` that installs a new kernel be paired with regenerating that kernel's initramfs -- a release string the caller could not have known when writing the plan; a run that discovers none fails with `NoInstalledKernels` rather than reporting a completed policy, and the releases it resolved are auditable because provenance records the full `dracut --kver` argv; `update_all` is the one action that names no packages, since its subject is whatever the declared repositories hold when it runs, and every other action must name at least one; dracut builds the replacement on the executor's private `/run` tmpfs before copying it over the existing guest initramfs, avoiding transient or duplicate persistent-space requirements. It also applies the declared kernel-module configuration -- `os.kernel_modules` -- which is the one part of the OS customization model these executors carry out, because its destinations are a closed named set (`etc/modules-load.d/zvmi.conf`, `etc/modprobe.d/zvmi-blacklist.conf`, `etc/modprobe.d/zvmi-options.conf`) rather than anywhere in the tree, so it needs none of the general file creation the rest of that model does. The same request renders the same bytes at the same paths whichever backend carries it out, and the files are written after the package actions -- so a package shipping its own modprobe configuration cannot land on top of the declared one -- and before the initramfs, so a generator reading the configuration sees the declared state. Requesting nothing writes nothing rather than planting empty files. It rejects cache-only and version-lock policies, package paths/URLs/RPM files, existing-path operations and the rest of OS customization, generalization, hooks, SELinux changes, boot-policy changes, and cross-architecture runners before workspace mutation. An unlocked update resolves against whatever the declared repositories hold when it runs, so two executions of one plan can produce different versions; the plan identifier covers the instruction, not the outcome. The exact NEVRAs an execution produced are recorded in provenance, which is what makes the result auditable after the fact rather than predictable before it -- pinning is the job of the cache and lock policies, which remain refused.

Select `.backend = .vm` with a `.vm` policy to customize the image inside an isolated guest, which is the only backend that can customize an image the host cannot run. It is Linux-only on the host, needs no privileges, and never executes guest code on the host. It accepts the same package, kernel-module and initramfs slice as `unsafe_chroot`, plus cross-architecture runners; it rejects hooks and cache-only package policies. The host renders the kernel-module configuration and the guest only places it, at destinations the guest checks against the same closed set the host validated against, so a control document cannot be used to write a file anywhere else.

The guest is an appliance boot of the image's *own* kernel: the backend extracts `vmlinuz`/`initramfs` from the staged copy, appends a static guest agent to a copy of that initramfs, and boots with `rdinit=`. No bootloader, firmware, or init system runs, so a failure is attributable and a fully emulated boot costs seconds rather than minutes. The staged image is never modified to carry control code, so nothing has to be removed again before publication.

Because the agent is `rdinit`, the guest starts with only the drivers its own kernel built in, and there is no `modprobe`, `udev` or module tree available at that point. So **every driver the guest needs must either be built into the image's kernel or be present in the image's own `lib/modules/<release>` tree.** The backend reads `modules.builtin` and `modules.dep` out of the staged image, resolves the dependency closure of what the run needs, decompresses those modules on the host (`.ko`, `.ko.xz`, `.ko.zst`, `.ko.gz`), and appends them to the initramfs beside the agent, which inserts them with `finit_module` before it waits for any device. A driver that is neither built in nor in the tree refuses the run in preflight, named for what was missing rather than guessed at.

The requested set is more than the closure of `modules.dep`, which records symbol dependencies only: it also names `virtio_pci`, because every device the backend attaches is a PCI device, and `sd_mod`, because a virtio-scsi controller with no SCSI disk driver behind it presents no `/dev/sda`. Missing either is a device that never appears, which a guest can only report as a timeout.

A built-in driver is never traded for a loadable one. Azure Linux builds `ext4`, `virtio_scsi`, `sd_mod` and `virtio_net` in and ships `virtio_blk` as a module, so its disks are attached over virtio-scsi and nothing is inserted; a kernel with `virtio_blk` built in gets virtio-blk instead. Debian, Ubuntu and Fedora cloud kernels modularize `ext4` and the virtio drivers, and are booted by loading them out of the image. Provenance records each module that was loaded by name, by the path inside the image it came from, and by the digest of the object the guest received.

`acceleration` defaults to `.hardware` and never silently degrades: it requires host architecture == image architecture and a readable and writable `/dev/kvm`, and is rejected in preflight otherwise. `.software` (TCG) must be requested explicitly, and for a same-architecture run also needs `acknowledge_software_emulation`. Cross-architecture runs are always emulated, because no accelerator crosses architectures. Whichever was used is recorded in provenance, so a run can never claim to have been faster or more faithful than it was.

`emulator_command` must be absolute; resolving a bare name against `PATH` is the caller's job, so provenance names the exact binary that ran. `boot` is a union of `direct_kernel` (the default) and `firmware`; see *Firmware boot* below. `network` is `offline` unless the plan declares repositories, in which case the guest gets a virtio-net device on QEMU's user-mode network. Provenance records the emulator and its version, the machine, CPU and accelerator, the runner architecture, the kernel and initramfs digests, the disk transport, the root device, and the tool versions and installed NEVRAs the guest itself reported.

### Firmware boot

`.boot = .{ .firmware = .{ ... } }` additionally proves that the image *as published* boots through its own firmware, bootloader and init. A direct-kernel run proves nothing about that: an image whose bootloader configuration, ESP contents, kernel command line or Secure Boot chain is broken customizes perfectly and then fails to boot in production.

A firmware boot is **the same direct-kernel customization pass followed by a read-only attestation pass**, run before anything is published. The customization is unchanged, so the published bytes are byte-for-byte what the same plan produces through `direct_kernel`; the backend digests the stage either side of the attestation and fails with `VmFirmwareStageMutated` rather than publish bytes a firmware boot could have touched.

**The agent is not carried into the firmware boot, and that is deliberate.** A firmware boot starts the image's own bootloader, which loads the image's own kernel and init; there is no `rdinit=` seam. Every way of creating one was rejected: appending the agent to the staged initramfs modifies the image and would attest a boot chain nobody will run; a separate agent boot medium or EFI shim is no longer the image's own boot chain; a virtio channel or in-guest hook requires the image to cooperate, which a backend that customizes arbitrary images may not demand; and letting the image's own init run and customizing from inside it cannot be byte-identical, because journald, `machine-id` and first-boot services all mutate the disk. So the attestation guest is *observed*, never driven.

The one thing it is observed through is the channel every boot chain already has. `console_marker` names the bytes the image prints on the serial console once its own boot chain has control, and the run succeeds the moment they appear. **This is the contract an image must satisfy to be attested.** The marker is required and never guessed: nothing on the host knows what a given image says on its way up, and an invented marker would make a boot that never happened indistinguishable from one that did.

- **Variable store: ephemeral, always.** The named `vars_path` is a template. The backend copies it into the transaction, gives the copy to the guest, and deletes it with the transaction; the file the plan names is never written. A preserved store would make the second run of an identical plan a different experiment — a firmware that wrote a `Boot####` entry on the first pass would boot differently on the next — which is the property this backend refuses to give up. `VmVariableStorePolicy` is recorded in provenance as a value, so a future preserved option would be a readable difference rather than a silent one.
- **Secure Boot: policy input only.** `secure_boot` selects a Secure Boot capable firmware pair and, on x86_64, adds the SMM and secure-pflash wiring (`q35,smm=on`, `driver=cfi.pflash01,property=secure,value=on`) without which the firmware's authentication of its own variable store means nothing. It is never an observed output: observing what the guest concluded about its Secure Boot state needs code running inside a guest this backend deliberately does not enter, so no claim about it is recorded as an observation. An explicitly named `machine` is never rewritten.
- **Timeout: its own budget.** `boot_timeout_seconds` defaults to 1800 and is separate from `VmPolicy.boot_timeout_seconds` (900). The appliance boot is bounded by kernel-to-agent; a firmware boot is bounded by firmware, bootloader, kernel and an init system, and under software emulation each of those is paid for one instruction at a time. The budget is one deadline for the whole boot, not per read.
- **The attestation guest shares only the emulator.** No `-kernel`, `-initrd` or `-append`; the EDK2 code on pflash unit 0 read-only and the variable-store copy on unit 1; the stage attached as virtio-blk with `snapshot=on` so every write lands in a host-side overlay; and `-nic none` regardless of the customization's network policy, because whether an image boots must not depend on what a network offered it.
- **Failures are named and attributable.** `VmFirmwareUnavailable`, `VmFirmwareBootTimedOut`, `VmFirmwareBootFailed`, `VmFirmwareConsoleOverflowed` and `VmFirmwareStageMutated` are distinct, and the console — including the emulator's own stderr, where a firmware states why it found nothing bootable — is handed to the caller's console sink. Preflight refuses a plan whose firmware is not on this host with a `vm_firmware` capability naming the file and the architecture; it is never downgraded to a direct-kernel boot.

Provenance records the boot mode as a union, so a firmware run and a direct-kernel run are never the same record read differently: `boot.firmware` names the firmware code and variable-store template by path *and* digest, the variable-store policy, the Secure Boot request, the machine the attestation ran on, the marker waited for, the budget, and the digest of the attested stage.

`code_path` and `vars_path` are absolute host paths, resolved by the caller exactly as `emulator_command` is. `addPreservedImage` resolves them for you when they are omitted, through the same `qemu_host` search `zvmi qemu` uses — the emulator's own `share/` directory first, then the system locations, raw before `.fd.bz2` — so one `ghr` install of `cataggar/qemu` covers both guest architectures. A compressed pair is decompressed into `<bundle>/firmware/`, which is stable across runs of the same plan because the resolved paths are hashed into the plan.

The unsafe executor runs in private mount and PID namespaces with a fresh minimal `/dev`, `/proc`, read-only `/sys`, tmpfs `/run`, isolated TDNF repository configuration, and optional read-only resolver binding. **This is cleanup isolation, not a security sandbox:** package managers and package scriptlets execute as root against the host kernel. Cleanup must unmount every child and detach the selected-partition loop device before publication; uncertain cleanup retains the transaction and active lease instead of deleting potentially mounted storage. Successful provenance records tool versions, exact mutation commands, and the final installed package NEVRAs.

Lower-level backends can use `zvmi.preserved_image.transactRaw` to flatten a source read-only into an exclusive raw stage, receive the selected partition geometry through a mutation hook, and publish raw, VHD, VHDX, or QCOW2 only after the hook releases every child, mount, loop attachment, and file reference. The transaction runtime pins staging-file identity and uses an external sealed lease barrier so cleanup never recursively removes an active backend workspace.

## Runtime customization API

The library exposes the same versioned request-plan runtime used by `addImage`:

```zig
const std = @import("std");
const customize = @import("zvmi").customize;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const request = customize.Request{
        .target_architecture = .x86_64,
        .input = .{ .iso_oci = .{
            .iso_path = "azurelinux.iso",
            .container_path = "oci-layout",
            .rootfs_path_in_iso = "images/rootfs.squashfs",
        } },
        .output = .{ .path = "appliance.qcow2", .format = .qcow2, .size = 4 * 1024 * 1024 * 1024 },
        .storage = .{ .fresh = .{} },
        .os = .{
            .filesystem = &.{
                .{ .put_file = .{
                    .path = "/etc/appliance.conf",
                    .source = .{ .host_path = "config/appliance.conf" },
                } },
            },
            .hostname = "appliance",
            .services = &.{.{ .name = "sshd.service", .state = .enabled }},
        },
        .generalization = .{ .azure = .{ .reset_hostname = false } },
        .execution = .{ .workspace_path = "." },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x42} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };

    var resolved = try customize.resolve(allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(allocator);
    if (resolved.plan == null) return error.InvalidConfiguration;

    var capabilities = try customize.preflight(allocator, init.io, &resolved.plan.?, customize.Platform.system());
    defer capabilities.deinit(allocator);
    if (!capabilities.ready()) return error.PreflightFailed;

    var outcome = try customize.execute(allocator, init.io, &resolved.plan.?, customize.Platform.system(), null);
    defer outcome.deinit(allocator);
    if (outcome.result == null) return error.ImageBuildFailed;
}
```

`resolve` is deterministic and does not inspect or mutate the host. The `native_fresh`, `native_edit`, `rebuild`, `unsafe_chroot`, and `vm` backends require `workspace_path` to be the parent directory of `output.path`, keeping all planned scratch state on the destination filesystem for atomic publication. `preflight` returns all missing capabilities, and `execute` repeats preflight before mutation, stages the image in a planned transaction directory, verifies that source hashes remain unchanged, and atomically publishes the final output. Validation, preflight, and execution diagnostics are structured and independently owned; successful results include source hashes, resolved configuration, generated or preserved-image metadata, source/final rebuild tree manifests, and the final artifact hash.

`customize.current_api_version` identifies the v3 request contract. `adaptV2NativeFresh` explicitly converts the frozen v2 ISO+OCI/native request shape; v3 validation never silently reinterprets a request labeled as v2. Plan and provenance JSON have independent `schema_version` fields so artifact consumers can reject or migrate formats separately.

The v3 contract implements rootless `native_fresh`, constrained `native_edit`, `rebuild` under either source profile, the limited Linux `unsafe_chroot` package/initramfs slice, and the isolated `vm` backend described above, including cross-architecture runners. It still models ordered hooks and SELinux policy without implementing them; unsupported combinations derive semantic capabilities and fail preflight before workspace creation. Direct `customize.execute` users must provide a `Platform` with unsafe runtime callbacks, while `addPreservedImage` wires the host-native preserved-image builder automatically.

`zvmi.lvm` reads LVM2 metadata from an offline disk image. It is read-only by construction: it opens nothing writable, exposes no writer, and every result it hands back is a `*const`. `lvm.scan` walks the whole disk and each GPT or MBR partition looking for an LVM2 label, parses the newest checksum-verified copy of each volume group's metadata, and returns an arena-owned `Scan`. `Scan.findVolumeGroup` and `Scan.findLogicalVolume` resolve by name -- the volume group may be left unnamed on a disk carrying exactly one -- `lvm.mapExtent` converts a logical extent to an absolute byte offset on the disk, and `lvm.contiguousRange` returns the single byte range of a volume that has one, or a distinguishable error naming why it does not. Only single-stripe `striped` segments are mapped; `doc/image-building.md` lists the refused segment types and their errors. `zvmi.preserved_image` accepts a logical volume through `PartitionSelector.logical_volume` wherever it accepts a partition.

`zvmi.root_tree.RootTree` is the lower-level owned filesystem API. It spools bounded file and symlink content independently of ISO, SquashFS, OCI, or ext4 reader lifetimes; owns paths and POSIX metadata; applies deterministic replacement and recursive removal; and exposes a stable manifest digest. `ext4View()` adapts a validated tree to `zvmi.ext4.populate` -- whose `PopulateOptions.journal` decides whether the written filesystem carries a JBD2 journal, and `ext4.defaultJournalBlocks` exposes the `mke2fs`-derived default size -- while `populateFat32()` either requires FAT-representable metadata or applies the caller's explicit lossy POSIX-metadata policy. Unsupported hardlinks, special files, timestamps, or metadata are rejected rather than silently discarded.

`zvmi.output` is the streaming artifact writer shared by `convert`,
`build-image`, and the customization backends. `output.Spec.parseName`
accepts `raw`, `raw.gz`, `raw.zst`, `vhd`, `vhdx`, and `qcow2`;
`output.validate` rejects the combinations that cannot be produced in a
single forward pass (compression for anything but raw, and `-o -` for the
seek-back formats) with named errors; and `output.writeImage`/`writeImageTo`
stream an `Image` into a writer or destination, emitting sparse and all-zero
regions as compressed zero runs and verifying the full virtual size was
produced before reporting success. `customize.OutputFormat` gains `raw_gz`
and `raw_zst` so bundle builds can publish a compressed artifact directly.

`zvmi.limits` owns the import guardrails shared by `root_tree`, the
ext4 scanner, and the preserved-image rebuild. `limits.ImportLimits` is the
flat set every CLI flag maps onto (`limits.Limit.flag()` is the single source
of the flag spelling), and `customize.Request.limits` carries it into a plan,
which hashes every value. A `limits.Diagnostic` passed as `limit_diagnostic`
collects two things: the peak each limit reached, returned as `limit_peaks` on
`build_image.BuildImageReport`, `preserved_image.RebuildReport`,
`preserved_image.RebuildInspection`, and provenance's `execution` record; and
the first breach, as a `limits.Exceeded` that names the observed value, the
configured limit, and the flag that raises it. The library never prints: the
CLI renders the breach, and `customize.execute` emits it as a `limit_exceeded`
diagnostic. Limits that no flag can raise stay separate errors, so
`error.InvalidPath` still means malformed and `error.PathLimitExceeded` means
too long.

`preserved_image.rebuild` checks scratch space before it creates the spool.
`WorkspaceSpace` reports the spool copy of the imported content, the raw
staging image, and the artifact that coexists with it, and `isSufficient`
treats an unknown amount of free space as sufficient rather than as too little.
`RebuildOptions.workspace_space = .report_only` skips enforcement for a
workspace that grows on demand. See
[Import limits and scratch space](image-building.md#import-limits-and-scratch-space).

`zvmi.preserved_image.edit` is the lower-level constrained existing-path API, while `zvmi.preserved_image.rebuild` performs the full-tree rebuild described above, under whichever source profile it is given. Both accept raw, VHD, VHDX, or qcow2 disks, copy guest-visible bytes into exclusive raw staging, flatten qcow2 backing chains, operate on an explicitly selected one-based GPT or MBR partition, convert to a standalone output, and publish without replacing an existing destination. Sources and backing files are opened read-only.


See [Image building](image-building.md) for format, filesystem, boot, and verity details.
