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

`boot_security.extra_kernel_options` is honored on `native_edit` and `rebuild` as well as on `native_fresh`. On a preserved image there is no bootloader installation to feed the options into, so they are **appended** to the command line of every boot entry already on the image's ESP: a GRUB `linux`, `linux16` or `linuxefi` line, and a BLS `options` line. Appending is the whole of it. Replacing or removing arguments is deliberately absent, because the arguments already on those lines are what make the image boot at all -- `root=`, verity parameters, the distro's own console and crash settings -- and a request that could overwrite them would let a one-line customization produce an unbootable image. The rewrite happens on the staged raw disk while the ESP FAT32 is still open, before the output is converted to its published format, and it is line-exact: the entry's existing text, the file's line endings and a final line without a newline all survive byte for byte. It is idempotent -- an entry whose command line already ends with exactly the declared text is counted in `entries_already_current` and left alone -- and it is all-or-nothing, since a partly updated ESP would boot some entries with the options and some without. Every rewritten file is read back and re-parsed afterwards, and the verification pass has the final say. Provenance records the appended text, how many GRUB and BLS entries were changed, how many were already current, and how many files were rewritten and verified.

`unsafe_chroot` honors the same field by a different mechanism, because it can run the target's own programs. Appending to a generated `grub.cfg` there would be the wrong edit: a distro regenerates that file from `/etc/default/grub` on every kernel package change, so an option written into the output survives only until the next `dnf update kernel`. The chroot backend therefore edits the **input** -- the `GRUB_CMDLINE_LINUX` assignment in `/etc/default/grub`, chosen over `GRUB_CMDLINE_LINUX_DEFAULT` because it reaches every generated entry including the recovery ones -- and then runs the target's own `grub2-mkconfig` (or `grub-mkconfig`) to regenerate `/boot/grub2/grub.cfg` or `/boot/grub/grub.cfg`. The edit is surgical: the last uncommented assignment wins, its existing quoting style is kept, and every other byte of the file including comments and line endings survives. The value has to be quoted, and an assignment carrying an unquoted one is refused with `UnquotedCommandLineValue` rather than appended to -- outside quotes `;`, `&`, `|` and `>` are live shell syntax, so the character rule below would no longer be sufficient, and adding the quotes on the file's behalf would change what its existing value means. `GRUB_CMDLINE_LINUX=` with no value at all is the one exception, and is completed into a quoted assignment, since there is no existing text whose meaning the quotes could change. It is idempotent, reporting `defaults_already_current` when the variable already ends with exactly the declared text, and the append is skipped rather than repeated. The regeneration runs in the plan's `bootloader_prepare` phase -- after the initramfs and the `before_seal` hooks, before `finalize` -- so a hook that installs a kernel is reflected in what the generator sees. Provenance records the file that was edited, the generator's absolute path and version, the file it wrote, and how many entries came out carrying the options.

The text is held to a stricter rule on this backend than on the preserved-image ones, and this is the reason it is not merely the same feature with a different writer: `/etc/default/grub` is *sourced by the shell* that runs the generator as root inside the target, so `"`, `'`, `` ` ``, `$` and `\` -- awkward but inert in a GRUB entry -- are a command-injection vector here. All five are refused with `invalid_policy`, at request validation and again by the worker on the far side of the privilege boundary. The layout refusals are named too, and each says what the image is rather than only that something failed: `/etc/fstab` declaring a separate `/boot` is `SeparateBootFilesystem`, since this backend mounts the selected root partition and nothing else, so the generator would find an empty stub, produce a configuration with no entries and write it where nothing reads it; a target carrying `/etc/kernel/cmdline` and no grub generator is `UnsupportedBootloaderGenerator`, because `kernel-install` regenerates per kernel version and image path, which this backend does not yet model; no generator at all is `MissingBootloaderGenerator`; no `/boot/grub2/grub.cfg` or `/boot/grub/grub.cfg` to regenerate is `MissingBootloaderConfiguration`; a missing `/etc/default/grub` is `MissingBootloaderDefaults`, one without the variable is `MissingCommandLineVariable`, since planting the assignment would be guessing at a bootloader the image does not use, and one whose value is unquoted or opens a quote nothing closes is `UnquotedCommandLineValue` or `UnterminatedQuotedValue`. The generator is the target's program run against the target's scripts, so nothing before it can promise what came out: the regenerated file is read back and `KernelOptionsNotApplied` fails the run if no entry carries the options -- which is what catches a root with no kernel installed, or distro scripts that ignore the variable. The check looks for the options as a whole-word run anywhere in an entry's command line rather than at its end, because `/etc/grub.d/10_linux` composes the normal entries as `${GRUB_CMDLINE_LINUX} ${GRUB_CMDLINE_LINUX_DEFAULT}`, so on an image that sets the second variable the edit lands mid-line and a suffix test would fail a run that had done exactly what it was asked.

The refusals are named before anything is written. `vm` rejects kernel options outright with `unsupported_execution_backend`: it neither reaches the ESP nor runs the target's tooling in a way this model describes, and a backend that silently did nothing would be worse than one that says so. Preflight probes the source image for the `kernel_option_change` capability -- no GPT, no ESP, or no recognized boot entry reports the capability missing rather than failing mid-run. A Unified Kernel Image is refused by name: its command line lives in a `.cmdline` PE section that may be covered by a Secure Boot signature, so editing it in place would produce an image that either ignores the change or no longer authenticates. Identifiers embedded in `core.img`, a `grubenv` or a signed EFI binary are out of scope for the same reason they are for the identity rewrite. The other boot-policy fields still raise `boot_policy_mutation` on a preserved image.

Select `.backend = .unsafe_chroot` with `.acknowledge_unsafe = true` to use the first privileged preserved-image executor. It is Linux-only, requires effective root plus `CAP_SYS_CHROOT`, `CAP_SYS_ADMIN`, and `CAP_MKNOD`, and supports only same-architecture execution against an explicitly selected Linux ext4 partition. The current slice accepts online unlocked package install, remove, and update actions through `/usr/bin/tdnf`, literal repository IDs with explicit trust material, and dracut regeneration with `--no-hostonly`; naming no kernel release regenerates every release installed in the target root, discovered after the package actions have run rather than declared in advance, which is what lets an `update_all` that installs a new kernel be paired with regenerating that kernel's initramfs -- a release string the caller could not have known when writing the plan; a run that discovers none fails with `NoInstalledKernels` rather than reporting a completed policy, and the releases it resolved are auditable because provenance records the full `dracut --kver` argv; `update_all` is the one action that names no packages, since its subject is whatever the declared repositories hold when it runs, and every other action must name at least one; dracut builds the replacement on the executor's private `/run` tmpfs before copying it over the existing guest initramfs, avoiding transient or duplicate persistent-space requirements. `initramfs = .when_needed` asks the build to work out whether the initramfs is stale instead of stating the answer: it resolves to `regenerate` naming no kernel release when the request declares any package action, and to `unchanged` otherwise. The decision is made while the plan is resolved rather than while it runs, so the plan states the outcome, the plan hash covers it, provenance records it, and a `when_needed` request produces the byte-identical plan its explicit equivalent would -- it is a way of not having to know the rule, not a different instruction. Package actions are the whole rule because an initramfs is a snapshot of a subset of the root filesystem, so a package shipping a kernel module, a udev rule or one of the binaries dracut copies in leaves the existing image describing a root that no longer exists. Kernel-module configuration is deliberately **not** a trigger: zvmi runs dracut `--no-hostonly`, under which dracut reads and installs the target's own `/etc/modules-load.d` and `/etc/modprobe.d` only when `hostonly` is set, so that configuration never reaches the initramfs and regenerating for it would spend minutes producing an identical image while asserting a causal link that does not exist. It takes effect when the real root boots. A derived regeneration is not merely the explicit one with the answer filled in: `regenerate.no_installed_kernels` defaults to `fail`, because an explicit instruction to regenerate every installed kernel that finds none has not done what it said, but the derived form states `nothing_to_regenerate`, because nothing asked for a regeneration and a root carrying no kernel has no stale initramfs. Without that distinction `when_needed` would fail builds that the identical request completes with `unchanged` -- and it would fail them late, after the workspace copy and the package transaction, since only the run can see the target's kernel inventory. It also applies the declared kernel-module configuration -- `os.kernel_modules` -- which is the one part of the OS customization model these executors carry out, because its destinations are a closed named set (`etc/modules-load.d/zvmi.conf`, `etc/modprobe.d/zvmi-blacklist.conf`, `etc/modprobe.d/zvmi-options.conf`) rather than anywhere in the tree, so it needs none of the general file creation the rest of that model does. The same request renders the same bytes at the same paths whichever backend carries it out, and the files are written after the package actions -- so a package shipping its own modprobe configuration cannot land on top of the declared one -- and before the initramfs, so a generator reading the configuration sees the declared state. Requesting nothing writes nothing rather than planting empty files. It rejects snapshot policies, package paths/URLs/RPM files, existing-path operations and the rest of OS customization, generalization, SELinux changes, the boot-policy changes other than `extra_kernel_options`, and cross-architecture runners before workspace mutation. An unlocked update resolves against whatever the declared repositories hold when it runs, so two executions of one plan can produce different versions; the plan identifier covers the instruction, not the outcome. `.packages.lock = .{ .exact = ... }` is what turns that into predictability before the fact, and both executing backends carry it out.

It also runs declared hooks: `request.hooks` is an ordered list of scripts, each naming a phase, that the executor runs inside the target root. A hook is the one input a plan cannot describe, since its effect is whatever its code does, so the model is about bounding it rather than understanding it. **A hook script must name its own interpreter with a `#!` line.** Without one `execve` returns `ENOEXEC`, which would surface as an unattributed nonzero `chroot` exit several phases into a privileged run; requiring the line also makes what interprets a hook a property of the declaration rather than of whatever the target image happens to have installed. Inline scripts are checked when the request is validated, and a `host_path` when the executor reads it -- the earliest boundary in each case that can see the bytes. A hook receives exactly the same fixed environment every other command in the run receives (`HOME`, `LANG`, `LC_ALL`, `PATH`, `TERM`), containing nothing from the build machine; configuration reaches it through its declared `arguments`, which is why there is no environment map to declare. Its stdin is closed and its output is streamed rather than captured. The script is placed at `/run/zvmi-hook-N` on the executor's private tmpfs at mode `0700`, and deleted as soon as the command returns whether it succeeded or not, so a hook cannot leave its own code in the published image. A nonzero exit or a signal fails the run. Phases run in the order the plan publishes: package actions, `after_packages`, `before_initramfs`, the initramfs, `before_seal`, SELinux, `finalize`, publish. Kernel-module configuration is written after the package actions and before the first hook of any phase, so every hook sees the declared configuration already in place; it is not itself an operation the plan publishes, because its destinations are a closed named set rather than a step a caller can reorder. A hook is bounded by script size (256 KiB), argument count (64) and argument length (4 KiB), and the same bounds are re-checked by the worker on the far side of the privilege boundary rather than trusted from the control document. Provenance records each hook that ran by name, phase, SHA-256 of the bytes that were placed, and exit code -- by digest rather than by origin, because an inline script and a host file with the same bytes are the same run, and a host file that changed between two runs is not.

**A hook is not bounded in time, and that is deliberate.** zvmi runs no wall clock over a hook, so a script that never returns hangs the build. Adding one would mean either requiring a new host tool the backend does not need today, changing what `unsafe_chroot` reports as available for every existing user, or in-process deadline machinery that does not exist -- and it would bound the smallest piece of unbounded target-supplied root code in the run while leaving package scriptlets and dracut modules, which already run unbounded as root, untouched. A deadline that means anything belongs to the whole execution rather than to hooks alone.

Select `.backend = .vm` with a `.vm` policy to customize the image inside an isolated guest, which is the only backend that can customize an image the host cannot run. It is Linux-only on the host, needs no privileges, and never executes guest code on the host. It accepts the same package, kernel-module and initramfs slice as `unsafe_chroot` -- including exact version locks, which the guest enforces and reports on with the same rules -- plus cross-architecture runners; it rejects cache-only and snapshot package policies. A declared `.packages.cache` directory is refused by name for the reason the hook refusal used to give: the control channel carries a rendered document rather than host files, so a host directory has no way to reach the guest, and a request whose cache was silently ignored would report a run that did not use it. It runs declared hooks, with the same phases, ordering, environment, bounds and provenance as `unsafe_chroot`. A hook's bytes are read on the host and carried in the control document base64-encoded, so what the guest executes is what the host read, and the digest provenance records is computed host-side. The guest writes each script to `/run/zvmi-hook-N` on the target's own private tmpfs at mode `0700` and deletes it as soon as the command returns; the destination is derived from the hook's position rather than declared, so the channel cannot be used to place a file anywhere a caller chooses. The guest reports back only an index and an exit code per hook, and the host refuses any result that does not account for every hook it sent, in order, with exit zero -- a run whose hooks were silently skipped fails rather than publishing an image the plan says had them. The channel is bounded by the same per-hook limits plus a count (64 hooks) and a total script weight (4 MiB), since the control document as a whole is bounded. The host renders the kernel-module configuration and the guest only places it, at destinations the guest checks against the same closed set the host validated against, so a control document cannot be used to write a file anywhere else.

`.packages.lock` decides how much of a package transaction's outcome the request fixes in advance. The default, `.unlocked`, fixes none of it: the plan names the instruction and the repositories answer it with whatever they hold at the moment it runs. `.{ .exact = ... }` fixes all of it. Each pin is a whole rpm identity -- name, `EPOCH:VERSION-RELEASE` with the epoch always written, and architecture -- because a bare version matches whatever release a repository happens to hold, which is exactly the freedom a lock exists to remove, and because a multilib root can hold `noarch` and `x86_64` builds of one name and version at once. There is deliberately no repository field: nothing in an rpm-based image records which repository an installed package came from -- tdnf reports installed packages under the pseudo-repository `@System` and its history database has no column for it -- so a lock could only ever restate the repository the request already declared, and a verifier reading it back would be checking a claim the run never made. The repositories a transaction was allowed to use are already in the request, in the plan hash, and in provenance.

An exact lock requires package actions to lock. A request that declares one but asks for no package actions is refused during validation rather than at execution, because a lock is a statement about a transaction and there is none: the run would compare the target's whole installed set against an empty transaction and fail on the first package the input image happened to carry, naming something the request never touched, after the image had already been staged.

An exact lock pins the **closure**, not only the packages the actions name. Installing `openssh` against a lock naming only `openssh` would leave its dependencies free to float, so validation refuses any `install` or `update_selected` naming a package the lock omits, and the run refuses any package the transaction added that no pin covers. `remove` is exempt, since it names what must not be installed rather than a version for what is. `update_all` cannot be combined with an exact lock at all: its subject is by definition whatever the repositories hold. A locked action is executed by asking the package manager for the pinned identity outright rather than for the name, and every pin is then compared against the target's own rpm database afterwards -- a pin the database does not hold under that name fails as missing, one it holds at another identity fails as a mismatch, and either way the run fails before anything is published. Names are compared as rpm parses them rather than by prefix, so a root holding `python3-libs` is not read as holding a differently-versioned `python3`. A pin is asked for once per architecture it names, since a lock may legitimately pin one name at two of them and a multilib root holds both at once.

Every run with package actions emits a lock whether or not it declared one, recorded as `provenance.execution.preserved.emitted_package_lock`. It is the difference between the installed set before the transaction and after -- what this run added or changed, and nothing the input image already carried -- which is what makes it usable directly as the `.exact` lock for the next run. The "before" is read after the declared repository trust has been imported, and rpm's `gpg-pubkey` pseudo-packages are excluded from the difference on both backends: rpm records every trusted key as a package whose architecture is `(none)`, which is not an architecture a pin may state, so a key that reached the difference would produce a lock nobody could restate and, under an existing lock, would fail every run with an error no lock could have prevented. A key is not something a transaction installed. `.{ .snapshot = ... }` is accepted by validation and refused by both backends: it names a state of the repositories, and nothing inside a target root can be compared against one.

A package transaction has to resolve repository names, and the target root has no reason to name a resolver that exists wherever this build runs, so something has to supply one. `.packages.resolver` says what. `.host_resolver`, the default, means the build host's own resolver, which both executing backends inherit by different routes: `unsafe_chroot` binds the host's `/etc/resolv.conf` into the target root read-only, and the VM guest asks `10.0.2.3`, which libslirp answers by rewriting the packet to whatever `/etc/resolv.conf` names in the emulator process. The VM backend therefore depends on the build machine's resolver exactly as much as the chroot does -- only the process that opens the file differs -- so both raise a `read_host_resolver` capability naming `/etc/resolv.conf`, and a consumer that requires every input to come from the request can refuse exactly that one. An offline guest does not raise it: it is started with `-nic none`, so there is no route to a host resolver for it to take and the plan must not declare a dependence the run cannot have. Nor does an offline package transaction, on either backend: a `cache_only` run installs no resolver into the target at all, so there is nothing for it to read and the capability would name a dependence the run does not have. The capability is a declaration rather than a probe and never gates a run, because a transaction that only removes packages, or whose repository URLs are literal addresses, resolves no names at all; refusing those for a file they never read would be a false refusal.

`.packages.cache` decides where the transaction's downloads and repository metadata come from, and it is the difference between a build that reaches the network and one that does not. The default, `.online`, declares nothing: the transaction resolves and downloads over the network into whatever cache the target image carries, and keeps nothing. `.{ .online_populating = "/var/cache/zvmi" }` names a host directory the run fills, and `.{ .cache_only = "/var/cache/zvmi" }` names a host directory the run reads and forbids it any network at all. The two modes are the two halves of one workflow -- populate once, rebuild from the result -- and they are a union rather than a mode flag beside a path so that the invalid state cannot be spelled: an offline build with no stated source is exactly what this policy exists to eliminate.

The directory is a **locator**, not staged content, for the same reason a repository credential is one and the opposite reason: a cache is potentially enormous, the run writes to it, and its whole purpose is to be reused across builds, so a copy the build system owned would be a second cache that is never the one the operator meant. It is bind-mounted at `/run/zvmi-cache` inside the target, under the executor's private `/run` tmpfs, and unmounted before anything is published, so the binding cannot reach the image even if the transaction leaves the cache dirty. A `cache_only` mount is remounted read-only, so an offline run cannot change the input it was asked to reproduce from. The mode also decides what preflight looks for: `cache_only` reads the directory, so a directory that is not there is `missing` -- a run that reached the network instead of failing is the one outcome this policy exists to prevent -- while `online_populating` writes it, so only its parent has to exist and the run creates the directory itself. The path is validated for shape rather than resolved (absolute, not the host root, no trailing slash, no empty, `.` or `..` component) and re-validated inside the privileged worker, because a control document naming a directory that a process running as root mounts into a target root is not something to check once.

The cache reaches the package manager as **configuration**, not as a command-line flag: zvmi renders `cachedir=/run/zvmi-cache` and `keepcache=1` into the `[main]` section of the `tdnf.conf` it already writes for the run. This is deliberate rather than incidental. tdnf grew a flag naming a directory of packages in 4.0, but the images this backend customizes ship 3.x, whose `tdnf --help` has `-C/--cacheonly`, `--downloaddir` and `--repofrompath` and no such flag; `cachedir` and `keepcache` are ordinary configuration keys that 3.x honours, so the feature needs no tdnf newer than the target already has. `keepcache` is what makes a populating run leave the downloaded packages behind at all -- without it tdnf discards them once the transaction commits, and the directory would come back holding only repository metadata.

Offline is enforced in three layers rather than asserted once, because each layer fails differently and a claim that only one of them backs is a claim about intent. The run installs **no resolver** into the target, so the root cannot resolve a name even if something in it tried; the tdnf invocation carries `-C`, so a package the cache does not hold fails as tdnf's own `ERROR_TDNF_CACHE_DISABLED` rather than being fetched; and an exact `.packages.lock` compares the resolved NEVRA set against what was declared. Declaring an explicit `.nameservers` resolver alongside `cache_only` is therefore refused by name rather than silently ignored: a plan recording nameservers the run never consults asserts a dependence it cannot have, and recording it is the whole point of declaring one. The `.host_resolver` default is not refused, because it is what a caller who said nothing about resolution gets.

Only `unsafe_chroot` carries this out. The VM backend refuses a declared cache directory where it is written, as `unsupported_execution_backend` at `/packages/cache`, for the same reason it refuses a credential: the guest control document carries rendered JSON rather than host files, so there is no channel a directory could cross -- a hook crosses only because its bytes are read on the host and carried inside the document, which a directory of unknown size and shape cannot be, and a guest that quietly resolved against the network instead would publish an image whose plan says it was built from a declared cache. A run that used one records `provenance.execution.preserved.package_cache` -- the mode, the host path it read or filled, and the guest path the transaction saw it at. Its absence means the transaction used whatever cache the target image carried, which is the ambient state the record exists to distinguish itself from. `doc/azure-linux.md` describes the hand-rolled predecessor of this feature in zvmi's own Azure Linux builds -- repomd SHA-256 pinning, an isolated per-build cache, disabled metadata expiry and a sorted NEVRA closure written to `provenance/` -- which is what the typed policy generalizes.

A repository that requires authentication declares `.credential` on the repository itself, and declares it **by reference**: `.host_path` names a file on the build machine, `.host_environment` names an environment variable. There is no arm that holds the material, and there is deliberately no way to add one, because every document this library publishes -- the request, the plan and the provenance record -- is stringified from these types by reflection, so a field holding a secret would be published by a public API by default rather than by mistake. The second reason is the plan hash: it covers where the material comes from, never what it is, because a hash over a password would let anyone holding a published plan identifier verify a guess of it offline. What was at that path or in that variable when the run happened is not recoverable from any output, which is the same stance the repository policy already takes towards package versions -- the identifier covers the instruction, not the outcome.

Reading it is a `read_host_credential` capability, raised once per declared source and naming it (`/run/secrets/token`, or `env:ZVMI_REPOSITORY_TOKEN`), so a consumer that requires every input to come from the request can see which file or variable rather than merely that there was one. The user name is not a secret and is stated outright, so a reader can tell which identity a build ran as. A credential path must be absolute: unlike trust material, which sits beside the build file and is meant to, a credential should never be build-relative, and a relative one silently reading a file out of the source tree is the mistake worth making impossible. Every URL of a credentialed repository must be `https://` -- basic authentication puts the password on the wire, and a `file://` URL cannot carry it at all, so declaring one against either is a mistake about what the build will do. The material itself must be a single line of printable bytes, because the package manager reads a repository file as INI and a newline in a password would end the line and let the rest be read back as configuration.

The credential reaches only the package manager. The `unsafe_chroot` executor reads the file or variable inside the worker, after it has re-execed as root, and renders `username=`/`password=` into the repository file on its private `/run` tmpfs -- mode `0600`, unlike every other repository file, and on a filesystem that is unmounted before anything is published, so the material never reaches a block of the finished image. It never appears in an argv, which matters because provenance records every mutation command verbatim. The worker's environment is built rather than inherited, so a declared variable is forwarded by name and nothing else is; a variable the host cannot read is a refusal before the image is opened, not an empty password sent to a server. The worker builds a fresh environment for every command it runs, from that same base and without the credential, and overwrites the variable in its own environment as soon as it has read it -- the worker is PID 1 in the namespace and mounts a real `proc` inside the target root, so a variable left behind would be readable through `/proc/1/environ` by everything that runs in the chroot afterwards, including the package scriptlets and dracut modules that run after the repository file has been deleted. None of this makes `unsafe_chroot` a security boundary, and it does not claim to be one: code running as root in the chroot can leave it and read the file a `host_path` credential names. The point is narrower -- a secret the run needed once should not sit in a process image for the length of the run. The `vm` backend reaches the same place by a different route, because its control document is a cpio member appended to an initramfs on the build host and material written into it would be material written to a host-side file. So the material does not travel in it. The host resolves the credential in its own process, seals it into a `memfd` -- anonymous memory with no name in any filesystem -- and attaches that descriptor to the emulator as a third read-only raw disk, passed as `/proc/self/fd/<n>`. The descriptor is created without `MFD_CLOEXEC` precisely so it survives into the emulator, which resolves the same name in its own `/proc`. What reaches the argv, and so provenance, is that path: a name for a descriptor rather than for a file, and one that names nothing at all once the run is over. The device is framed and digested exactly like the result device, under a different magic so the two can never be read as each other, and it is attached last so the device indices of the two disks every run already had do not shift. The control document names the device and carries the user name and an index into it; there is no field in it a password could occupy. The guest reads the device into a single allocation before it mounts the target root -- material it cannot obtain fails the run before the image has been touched -- renders through the same shared renderer the chroot backend uses, writes the file at mode `0600` on its private `/run` tmpfs, and overwrites the rendered body immediately and the device buffer at teardown. A run that declares no credential has no device, no drive argument and no device name in its control document. Unlike the chroot worker, the VM backend does not scrub a consumed environment variable: that worker is PID 1 with a real `proc` mounted inside the target root, where a variable left behind is readable by every scriptlet that follows, whereas the VM backend runs in the caller's own process and gives the guest no view of it, so scrubbing there would erase a variable belonging to the program that called the library to protect against a reader that does not exist.

`.resolver = .{ .nameservers = &.{"192.0.2.1"} }` states the servers instead, and both backends then render the same `/etc/resolv.conf` bytes from one function, so the resolver stops being a property of where the build ran. At most `MAXNS` (three) dotted-quad addresses are accepted, because a resolver library reads no more than that and a fourth would be a declaration the run never honours. Loopback, unspecified, multicast and reserved addresses are refused wherever they are stated: `127.0.0.53` reaches the build host's own stub resolver from a chroot, which shares the host's network namespace, and reaches nothing at all from inside a guest, so accepting it would put back the dependence the declaration removes. A `vm` run additionally refuses every address inside `10.0.2.0/24`, because slirp aliases its own subnet onto the build machine -- `10.0.2.3` is forwarded to the emulator's `/etc/resolv.conf` and everything else in the subnet is rewritten to the host's loopback -- so naming one would state a resolver while still meaning "whatever this machine has", and would mean an ordinary LAN address on the chroot backend instead. `host_resolver` is how a request asks for the build machine's resolver. Addresses outside the subnet are NATed out through the host and reach what a chroot would reach. The resolver is the package transaction's, so a request with no package actions installs none at all, and whichever policy is in force the image's own file is put back when the transaction ends. Both backends move it aside and rename it back rather than copying its bytes, so an `/etc/resolv.conf` that is a symlink into `/run` -- which is most of them -- comes back a symlink: it is build-time configuration, not a property of the published image. Either way the choice is in the plan, under the plan hash, and in provenance.

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

The v3 contract implements rootless `native_fresh`, constrained `native_edit`, `rebuild` under either source profile, the limited Linux `unsafe_chroot` package/initramfs slice, and the isolated `vm` backend described above, including cross-architecture runners. It implements ordered hooks on both `unsafe_chroot` and `vm` and still models SELinux policy without implementing it; unsupported combinations derive semantic capabilities and fail preflight before workspace creation. Direct `customize.execute` users must provide a `Platform` with unsafe runtime callbacks, while `addPreservedImage` wires the host-native preserved-image builder automatically.

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

`customize.OutputFormat.cosi` publishes a COSI bundle instead of a disk
image. Every backend can emit it -- `native_fresh`, `native_edit`, `rebuild`,
`unsafe_chroot`, and `vm` -- because the bundle is written from the disk
image the backend staged: the backend builds raw, and a trailing
`write_cosi_bundle` operation describes the finished image and commits the
bundle in its place. Two conditions are refused rather than approximated. A
`native_fresh` gen1 request fails validation, because a gen1 image is
MBR-partitioned and COSI describes a GPT disk; a preserved source without a
GPT fails the `gpt_source` preflight capability for the same reason. Only a
backend that sealed the dm-verity tree itself knows its salt and root hash,
so the bundle's verity block is present on a `native_fresh` verity build and
absent everywhere else. Which kind was published is recorded in
`provenance.execution.cosi` alongside the metadata version and partition
count, and `-O cosi` selects it from the CLI builders and from `addImage` /
`addPreservedImage`. `output.Spec.parseName` still refuses `cosi`: it names
disk formats that `convert` and `create` can open and write, and a bundle is
neither.

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
