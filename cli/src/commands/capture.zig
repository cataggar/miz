//! `vmiz capture`: rebuild an installed system into a fresh, right-sized
//! image.
//!
//! The distinguishing property is the sizing. A capture reads what is on a
//! machine's filesystems, not the blocks its disk happens to span, and writes
//! a disk sized to the former. A 1 TB volume holding 12 GB of system becomes
//! roughly a 12 GB image, so the result is something that can be uploaded,
//! stored and booted rather than a full-size copy of mostly nothing.
//!
//! Reading a live system's block devices needs privilege even though nothing
//! is mounted and nothing is written to them, so this normally runs as root.

const std = @import("std");
const vmiz = @import("vmiz");
const opts = @import("opts.zig");

const help_text =
    \\usage: vmiz capture --source <device|image> [--source-root <spec>]
    \\                    [--source-mount <spec>=<path>]... [--source-esp <spec>]
    \\                    [--root-size <size>] [--esp-size <size>]
    \\                    -O <format> -o <output|->
    \\
    \\Rebuilds an installed system into a fresh disk image sized to its
    \\content rather than to the disk it came from.
    \\
    \\Source selection:
    \\  --source <path>          Disk, partition or image to capture from.
    \\  --source-root <spec>     Which filesystem becomes the root. Required
    \\                           when --source is a partitioned disk; there is
    \\                           no guess at which partition is root.
    \\  --source-mount <spec>=<path>
    \\                           A filesystem the source system mounts inside
    \\                           its root, e.g. /dev/sda2=/boot. Repeatable.
    \\                           Its content is merged into the new root and
    \\                           its /etc/fstab entry is dropped.
    \\  --source-esp <spec>      The EFI system partition. Detected from the
    \\                           source's partition table when not given.
    \\  --no-esp                 Write a root-only disk even if an ESP exists.
    \\
    \\A <spec> is a path (/dev/sda2, /dev/mapper/vg-root, disk.img), or
    \\`gpt:<n>` for the nth partition of --source, or `lvm:<vg>/<lv>` for a
    \\logical volume found inside --source.
    \\
    \\Sizing:
    \\  --root-size <size>       Exact root filesystem size. Defaults to the
    \\                           smallest that holds the content, plus 512M of
    \\                           room to grow. A size below the minimum is an
    \\                           error reporting both numbers.
    \\  --esp-size <size>        Exact EFI system partition size. Defaults to
    \\                           its content plus 16M. Note that FAT32 has a
    \\                           floor of about 33.5M whatever it holds.
    \\
    \\Output:
    \\  -O <format>              raw, vhd, vhdx, qcow2, raw.gz, raw.zst.
    \\  -o <path|->              Destination, or - for stdout.
    \\  --compress-level <1-9>   gzip only.
    \\
    \\Other:
    \\  --architecture <auto|x86_64|aarch64>
    \\                           Decides the root partition type GUID that
    \\                           discoverable-partitions logic looks for.
    \\  --label <name>           ext4/XFS volume label for the new root. For an
    \\                           XFS root it must be at most 12 bytes.
    \\  --root-filesystem <ext4|xfs>
    \\                           Filesystem for the captured root (default
    \\                           ext4). xfs uses the bounded native XFS writer
    \\                           and keeps its own internal log; pass
    \\                           --no-journal alongside it, since an ext4
    \\                           journal on an XFS root is rejected rather than
    \\                           quietly ignored. The ESP stays FAT32.
    \\  --root-selinux-label <context>
    \\                           SELinux context for the new root directory.
    \\  --no-journal             Omit the ext4 journal. On by default here,
    \\                           unlike elsewhere in vmiz, because a captured
    \\                           system boots into a mutable root filesystem.
    \\                           Required for an XFS root: XFS journals
    \\                           internally, and asking for an ext4 journal on
    \\                           top of it is rejected by name.
    \\  --no-identity-rewrite    Leave /etc/fstab and the bootloader naming
    \\                           the source's UUIDs. The image will not boot;
    \\                           this exists for inspecting what changed.
    \\  --dry-run                Report what would be written, and stop.
    \\  --max-nodes <n>, --max-total-bytes <n>, ...
    \\                           Raise an import limit. The error naming a
    \\                           limit also names the flag that raises it.
    \\
    \\Reading a live block device requires root.
    \\
;

/// How a filesystem to capture is named on the command line.
pub const SourceSpec = union(enum) {
    /// A path opened in its own right: a device node, a partition node, an
    /// active device-mapper node such as `/dev/mapper/vg-root`, or an image.
    path: []const u8,
    /// The nth entry of `--source`'s GPT, numbered as `lsblk` and `parted`
    /// number them.
    gpt_index: u32,
    /// A logical volume read out of `--source` without device-mapper, for
    /// capturing from an image of a machine rather than the machine.
    logical_volume: struct { group: []const u8, name: []const u8 },
};

pub const SpecError = error{
    EmptySourceSpec,
    InvalidGptIndex,
    InvalidLogicalVolumeSpec,
};

/// Parses a `<spec>`. Anything not carrying a recognised prefix is a path,
/// so `/dev/mapper/vg-root` needs no special handling: on a live system the
/// kernel has already assembled it and it reads like any other device.
pub fn parseSourceSpec(text: []const u8) SpecError!SourceSpec {
    if (text.len == 0) return error.EmptySourceSpec;

    if (std.mem.startsWith(u8, text, "gpt:")) {
        const digits = text["gpt:".len..];
        const index = std.fmt.parseInt(u32, digits, 10) catch return error.InvalidGptIndex;
        if (index == 0) return error.InvalidGptIndex;
        return .{ .gpt_index = index };
    }

    if (std.mem.startsWith(u8, text, "lvm:")) {
        const rest = text["lvm:".len..];
        const slash = std.mem.indexOfScalar(u8, rest, '/') orelse
            return error.InvalidLogicalVolumeSpec;
        const group = rest[0..slash];
        const name = rest[slash + 1 ..];
        if (group.len == 0 or name.len == 0) return error.InvalidLogicalVolumeSpec;
        if (std.mem.indexOfScalar(u8, name, '/') != null) return error.InvalidLogicalVolumeSpec;
        return .{ .logical_volume = .{ .group = group, .name = name } };
    }

    return .{ .path = text };
}

pub const Mount = struct {
    source: SourceSpec,
    /// Absolute path in the captured system, validated by `root_tree`.
    target: []const u8,
};

pub const MountSpecError = error{
    MissingMountTarget,
    EmptyMountSource,
} || SpecError;

/// Parses `<spec>=<path>`. Split on the first `=` because no spec contains
/// one and a mount point conceivably could.
pub fn parseMount(text: []const u8) MountSpecError!Mount {
    const equals = std.mem.indexOfScalar(u8, text, '=') orelse return error.MissingMountTarget;
    const source = text[0..equals];
    const target = text[equals + 1 ..];
    if (source.len == 0) return error.EmptyMountSource;
    if (target.len == 0) return error.MissingMountTarget;
    return .{ .source = try parseSourceSpec(source), .target = target };
}

/// Turns a library error into something that says what to do about it.
/// Errors that already read well are left to `@errorName`; this covers the
/// ones whose name alone would send an operator to the source.
pub fn describeCaptureFailure(err: anyerror) ?[]const u8 {
    return switch (err) {
        error.AccessDenied, error.PermissionDenied => "reading a block device requires root, even though capture only reads it and writes nothing to it",
        error.RootSizeBelowMinimum => "--root-size is smaller than the captured content needs",
        error.EspSizeBelowMinimum => "--esp-size is smaller than the captured EFI system partition needs; note that FAT32 cannot go below about 33.5M whatever it holds",
        error.SourceRootRequired => "no partition of --source holds a supported root filesystem (ext4 or xfs), so name the root explicitly with --source-root (e.g. --source-root gpt:2, or --source-root lvm:<vg>/<lv> for a root inside LVM)",
        error.AmbiguousSourceRoot => "--source holds more than one ext4 or xfs filesystem with an /etc, so which one is the root has to be said with --source-root (e.g. --source-root gpt:2). The others can be merged in with --source-mount <spec>=<path>",
        error.NoRootLikeFilesystem => "--source holds an ext4 or xfs filesystem, but none with an /etc, so none of them looks like a root -- a separate /boot on a machine whose root is btrfs or another unsupported filesystem looks exactly like this. Name the root with --source-root, and merge the rest in with --source-mount <spec>=<path>",
        error.UnrecognizedRootFilesystem => "this is neither an ext4 nor an xfs filesystem",
        error.SourceHasNoPartitionTable => "a gpt:<n> spec needs --source to be a disk with a GPT; name a device or image directly instead",
        error.PartitionNotFound => "--source has no partition with that number; the numbering matches lsblk and parted, from one",
        error.InvalidGptIndex => "a partition spec is gpt:<n>, numbered from one as lsblk and parted number them",
        error.InvalidLogicalVolumeSpec => "a logical volume spec is lvm:<volume-group>/<volume-name>",
        error.LvmVolumeGroupNotFound, error.LogicalVolumeNotFound => "no such logical volume inside --source; note that lvm: reads LVM metadata out of the image itself, so an active volume on this machine is named by its device path instead",
        error.UnsupportedLvmStripedSegment, error.UnsupportedLvmMirrorSegment, error.UnsupportedLvmRaidSegment => "this logical volume is spread across physical volumes in a way the read-only LVM support cannot follow; capture the assembled device node instead (/dev/mapper/<vg>-<lv>)",
        error.UnsupportedLvmThinSegment, error.UnsupportedLvmCacheSegment, error.UnsupportedLvmSnapshotSegment => "thin, cached and snapshot logical volumes are not readable without device-mapper; capture the assembled device node instead (/dev/mapper/<vg>-<lv>)",
        error.LogicalVolumeNotContiguous => "this logical volume's extents are not contiguous on disk; capture the assembled device node instead (/dev/mapper/<vg>-<lv>)",
        error.MissingMountTarget => "the mount point does not exist in the captured root filesystem, so there is nothing to mount over",
        error.MountTargetNotDirectory, error.MountTargetIsSymlink => "the mount point exists in the captured root filesystem but is not a directory",
        error.MountTargetNotAbsolute => "a --source-mount target must be an absolute path, e.g. /boot",
        error.MountTargetIsRoot => "use --source-root rather than --source-mount to name the root filesystem",
        error.DuplicateMountTarget => "two --source-mount options name the same mount point",
        error.NotFat32 => "the EFI system partition is not FAT32",
        error.BorrowedImportRequiresMemoryTree => null,
        else => null,
    };
}

const Architecture = enum { auto, x86_64, aarch64 };

fn hostArchitecture() vmiz.bootconfig.Architecture {
    return switch (@import("builtin").cpu.arch) {
        .aarch64 => .aarch64,
        else => .x86_64,
    };
}

/// A byte range of an open image holding one filesystem. A capture may have
/// several at once -- the root, `/boot`, the ESP -- and each may be a region
/// of `--source` or a device of its own.
///
/// `image` is a pointer rather than a value because an `Image` opened for a
/// source of its own has to outlive the call that opened it. Those are
/// heap-allocated and tracked in a list of their own, so that adding one
/// cannot move the ones already handed out.
const OpenedSource = struct {
    image: *vmiz.Image,
    offset: u64,
    length: u64,
    /// The entry this came from, when it was resolved through `--source`'s
    /// partition table. Its GUID and name are the PARTUUID and PARTLABEL the
    /// captured system may be referring to itself by, and they are retired
    /// along with the filesystem UUID.
    partition: ?vmiz.gpt.PartitionEntry = null,
};

pub fn run(gpa: std.mem.Allocator, io: std.Io, args: []const []const u8) u8 {
    var source_path: ?[]const u8 = null;
    var root_spec_text: ?[]const u8 = null;
    var esp_spec_text: ?[]const u8 = null;
    var no_esp = false;
    var mount_texts = std.array_list.Managed([]const u8).init(gpa);
    defer mount_texts.deinit();

    var root_size: ?u64 = null;
    var esp_size: ?u64 = null;
    var architecture: Architecture = .auto;
    var label: []const u8 = "";
    var root_filesystem: vmiz.layout.FilesystemKind = .ext4;
    var selinux_label: ?[]const u8 = null;
    var journal = true;
    var rewrite_identities = true;
    var dry_run = false;

    var output_path: ?[]const u8 = null;
    var spec: ?vmiz.output.Spec = null;
    var level: ?vmiz.output.Level = null;
    var import_limits = vmiz.limits.ImportLimits{};

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "-h") or std.mem.eql(u8, arg, "--help")) {
            std.debug.print("{s}", .{help_text});
            return 0;
        } else if (std.mem.eql(u8, arg, "--source")) {
            i += 1;
            if (i >= args.len) return fail("capture: --source requires a path", .{});
            source_path = args[i];
        } else if (std.mem.eql(u8, arg, "--source-root")) {
            i += 1;
            if (i >= args.len) return fail("capture: --source-root requires a spec", .{});
            root_spec_text = args[i];
        } else if (std.mem.eql(u8, arg, "--source-esp")) {
            i += 1;
            if (i >= args.len) return fail("capture: --source-esp requires a spec", .{});
            esp_spec_text = args[i];
        } else if (std.mem.eql(u8, arg, "--source-mount")) {
            i += 1;
            if (i >= args.len) return fail("capture: --source-mount requires <spec>=<path>", .{});
            mount_texts.append(args[i]) catch return fail("capture: out of memory", .{});
        } else if (std.mem.eql(u8, arg, "--no-esp")) {
            no_esp = true;
        } else if (std.mem.eql(u8, arg, "--root-size")) {
            i += 1;
            if (i >= args.len) return fail("capture: --root-size requires a size", .{});
            root_size = vmiz.parseSize(args[i]) catch
                return fail("capture: invalid --root-size '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--esp-size")) {
            i += 1;
            if (i >= args.len) return fail("capture: --esp-size requires a size", .{});
            esp_size = vmiz.parseSize(args[i]) catch
                return fail("capture: invalid --esp-size '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            i += 1;
            if (i >= args.len) return fail("capture: --architecture requires a value", .{});
            architecture = std.meta.stringToEnum(Architecture, args[i]) orelse
                return fail("capture: unknown --architecture '{s}' (auto, x86_64, aarch64)", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--label")) {
            i += 1;
            if (i >= args.len) return fail("capture: --label requires a value", .{});
            label = args[i];
        } else if (std.mem.eql(u8, arg, "--root-filesystem")) {
            i += 1;
            if (i >= args.len) return fail("capture: --root-filesystem requires a value", .{});
            if (std.mem.eql(u8, args[i], "ext4")) {
                root_filesystem = .ext4;
            } else if (std.mem.eql(u8, args[i], "xfs")) {
                root_filesystem = .xfs;
            } else {
                return fail("capture: invalid --root-filesystem '{s}': expected ext4 or xfs", .{args[i]});
            }
        } else if (std.mem.eql(u8, arg, "--root-selinux-label")) {
            i += 1;
            if (i >= args.len) return fail("capture: --root-selinux-label requires a context", .{});
            selinux_label = args[i];
        } else if (std.mem.eql(u8, arg, "--no-journal")) {
            journal = false;
        } else if (std.mem.eql(u8, arg, "--no-identity-rewrite")) {
            rewrite_identities = false;
        } else if (std.mem.eql(u8, arg, "--dry-run")) {
            dry_run = true;
        } else if (std.mem.eql(u8, arg, "-o")) {
            i += 1;
            if (i >= args.len) return fail("capture: -o requires a destination", .{});
            output_path = args[i];
        } else if (std.mem.eql(u8, arg, "-O")) {
            i += 1;
            if (i >= args.len) return fail("capture: -O requires a format", .{});
            spec = vmiz.output.Spec.parseName(args[i]) orelse
                return fail("capture: unknown format '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--compress-level")) {
            i += 1;
            if (i >= args.len) return fail("capture: --compress-level requires 1-9", .{});
            level = vmiz.output.parseLevel(args[i]) catch
                return fail("capture: --compress-level must be 1 (fastest) through 9 (smallest)", .{});
        } else if (std.mem.startsWith(u8, arg, "--max-")) {
            i += 1;
            if (i >= args.len) return fail("capture: {s} requires a value", .{arg});
            const recognized = import_limits.parseFlag(arg, args[i]) catch
                return fail("capture: invalid value '{s}' for {s}", .{ args[i], arg });
            if (!recognized) return fail("capture: unknown option '{s}'", .{arg});
        } else {
            return fail("capture: unknown option '{s}'\n\n{s}", .{ arg, help_text });
        }
    }

    const source = source_path orelse
        return fail("capture: --source is required\n\n{s}", .{help_text});
    const destination_text = output_path orelse
        return fail("capture: -o is required\n\n{s}", .{help_text});

    const output_spec = spec orelse blk: {
        if (std.mem.eql(u8, destination_text, "-"))
            break :blk vmiz.output.Spec{ .format = .raw };
        break :blk vmiz.output.Spec.inferFromPath(destination_text) orelse
            return fail("capture: cannot tell the output format from '{s}'; pass -O", .{destination_text});
    };
    const destination: vmiz.output.Destination =
        if (std.mem.eql(u8, destination_text, "-")) .stdout else .{ .path = destination_text };

    vmiz.output.validate(output_spec, destination, level) catch |err|
        return fail("capture: -O {s}: {s}", .{ output_spec.displayName(), opts.describeOutputError(err) });

    var mounts = std.array_list.Managed(Mount).init(gpa);
    defer mounts.deinit();
    for (mount_texts.items) |text| {
        const mount = parseMount(text) catch |err|
            return fail("capture: invalid --source-mount '{s}': {s}", .{ text, @errorName(err) });
        mounts.append(mount) catch return fail("capture: out of memory", .{});
    }

    var targets = std.array_list.Managed([]const u8).init(gpa);
    defer targets.deinit();
    for (mounts.items) |mount| targets.append(mount.target) catch
        return fail("capture: out of memory", .{});
    vmiz.root_tree.validateMountTargets(targets.items) catch |err|
        return failWithHint("capture: --source-mount targets rejected", err);

    return capture(gpa, io, .{
        .source_path = source,
        .root_spec_text = root_spec_text,
        .esp_spec_text = esp_spec_text,
        .no_esp = no_esp,
        .mounts = mounts.items,
        .root_size = root_size,
        .esp_size = esp_size,
        .architecture = architecture,
        .label = label,
        .root_filesystem = root_filesystem,
        .selinux_label = selinux_label,
        .journal = journal,
        .rewrite_identities = rewrite_identities,
        .dry_run = dry_run,
        .spec = output_spec,
        .destination = destination,
        .level = level,
        .limits = import_limits,
    });
}

const CaptureRequest = struct {
    source_path: []const u8,
    root_spec_text: ?[]const u8,
    esp_spec_text: ?[]const u8,
    no_esp: bool,
    mounts: []const Mount,
    root_size: ?u64,
    esp_size: ?u64,
    architecture: Architecture,
    label: []const u8,
    root_filesystem: vmiz.layout.FilesystemKind,
    selinux_label: ?[]const u8,
    journal: bool,
    rewrite_identities: bool,
    dry_run: bool,
    spec: vmiz.output.Spec,
    destination: vmiz.output.Destination,
    level: ?vmiz.output.Level,
    limits: vmiz.limits.ImportLimits,
};

/// The ext4 journal setting a capture hands to `disk_assembly`. The request's
/// flag is returned exactly as it stands -- never masked by the root
/// filesystem kind. Capture defaults the journal on, so this is what makes an
/// ext4 journal asked for on an XFS root reach `disk_assembly` and be rejected
/// by name (`Ext4JournalWithXfsRoot`) instead of being quietly cleared here,
/// before any validation runs, the way an earlier version did. A user who
/// wants an XFS root passes `--no-journal`.
fn ext4JournalSetting(request: CaptureRequest) vmiz.ext4.JournalOptions {
    return .{ .enabled = request.journal };
}

fn capture(gpa: std.mem.Allocator, io: std.Io, request: CaptureRequest) u8 {
    var disk = vmiz.Image.openPathReadOnly(io, request.source_path) catch |err|
        return failOpen(request.source_path, err);
    defer disk.close(io);

    // The partition table is read once and shared: every `gpt:<n>` spec, the
    // ESP search and the PARTUUID of the source root all come out of it.
    const table: ?vmiz.gpt.ParsedGpt = vmiz.gpt.readGpt(disk, io, gpa) catch null;
    defer if (table) |parsed| gpa.free(parsed.partitions);

    var scratch = std.array_list.Managed(*vmiz.Image).init(gpa);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            gpa.destroy(opened);
        }
        scratch.deinit();
    }

    const root_source = resolveRoot(gpa, io, &disk, table, request, &scratch) catch |err|
        return failWithHint("capture: cannot read the root filesystem", err);

    var diagnostic = vmiz.limits.Diagnostic{};

    var root_reader = openSourceFilesystem(gpa, io, root_source) catch |err|
        return failWithHint("capture: the root source is not a supported filesystem (ext4 or xfs)", err);
    defer root_reader.deinit(io);

    // A root named by path rather than as a partition of --source carries no
    // PARTUUID this can retire, so a `PARTUUID=`-rooted fstab would come
    // through naming a disk that no longer exists -- and, since nothing was
    // retired, the verification pass would have nothing to match and would
    // report a clean rewrite. Silence is the failure mode worth avoiding.
    if (request.rewrite_identities and root_source.partition == null) {
        warnUnretirablePartitionReference(gpa, io, &root_reader);
    }

    const spool_path = stagingPath(gpa, request.destination, ".spool") catch
        return fail("capture: out of memory", .{});
    defer gpa.free(spool_path);
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var tree = vmiz.root_tree.RootTree.init(gpa, io, spool_path, request.limits.tree()) catch |err|
        return fail("capture: cannot create the staging spool '{s}': {s}", .{ spool_path, @errorName(err) });
    defer tree.deinit();
    tree.diagnostic = &diagnostic;

    var sources = std.array_list.Managed(vmiz.disk_assembly.SourceFilesystem).init(gpa);
    defer sources.deinit();
    var identifier_storage = std.array_list.Managed([]u8).init(gpa);
    defer {
        for (identifier_storage.items) |owned| gpa.free(owned);
        identifier_storage.deinit();
    }

    // Scanning, importing and identity extraction all read from types that
    // differ by filesystem (`ext4.GeneralTree` vs `xfs.Tree`), so this is
    // the one place that switches on which the root turned out to be; the
    // rest of `capture` -- staging, sizing, identity rewriting, output --
    // never needs to know.
    const root_identity: struct { uuid: []const u8, label: ?[]const u8 } = switch (root_reader) {
        .ext4 => |*reader| blk: {
            var root_scan = vmiz.ext4.scanReadable(reader, io, gpa, scanOptions(request.limits, root_source.length, &diagnostic)) catch |err|
                return failLimits("capture: reading the root filesystem failed", err, &diagnostic);
            defer root_scan.deinit();

            tree.importExt4General(&root_scan) catch |err|
                return failLimits("capture: importing the root filesystem failed", err, &diagnostic);

            const uuid = ownedUuid(gpa, &identifier_storage, &root_scan.identity.uuid) catch
                return fail("capture: out of memory", .{});
            const label = ownedLabel(gpa, &identifier_storage, &root_scan.identity.label) catch
                return fail("capture: out of memory", .{});
            break :blk .{ .uuid = uuid, .label = label };
        },
        .xfs => |*reader| blk: {
            var root_scan = vmiz.xfs.scanReadable(reader, io, gpa, xfsScanOptions(request.limits, root_source.length, &diagnostic)) catch |err|
                return failLimits("capture: reading the root filesystem failed", err, &diagnostic);
            defer root_scan.deinit();

            tree.importXfs(&root_scan) catch |err|
                return failLimits("capture: importing the root filesystem failed", err, &diagnostic);

            const uuid = ownedUuid(gpa, &identifier_storage, &root_scan.identity.uuid) catch
                return fail("capture: out of memory", .{});
            const label = ownedLabel(gpa, &identifier_storage, &root_scan.identity.label) catch
                return fail("capture: out of memory", .{});
            break :blk .{ .uuid = uuid, .label = label };
        },
    };

    var root_before = vmiz.identity_rewrite.Identifiers{ .filesystem_uuid = root_identity.uuid, .filesystem_label = root_identity.label };
    ownedPartition(gpa, &identifier_storage, root_source.partition, &root_before) catch
        return fail("capture: out of memory", .{});
    sources.append(.{
        .before = root_before,
        .successor = .root,
    }) catch return fail("capture: out of memory", .{});

    // Merged filesystems, in the order given. `validateMountTargets` has
    // already refused an order in which a later mount would shadow an
    // earlier one, so nesting /boot then /boot/efi works and the reverse is
    // reported rather than silently losing content.
    for (request.mounts) |mount| {
        const opened = resolveSpec(gpa, io, &disk, table, mount.source, &scratch) catch |err|
            return failWithHint("capture: cannot read a --source-mount filesystem", err);

        var reader = openSourceFilesystem(gpa, io, opened) catch |err|
            return failWithHint("capture: a --source-mount filesystem is not a supported filesystem (ext4 or xfs)", err);
        defer reader.deinit(io);

        const mount_identity: struct { uuid: []const u8, label: ?[]const u8 } = switch (reader) {
            .ext4 => |*r| blk: {
                var scan = vmiz.ext4.scanReadable(r, io, gpa, scanOptions(request.limits, opened.length, &diagnostic)) catch |err|
                    return failLimits("capture: reading a --source-mount filesystem failed", err, &diagnostic);
                defer scan.deinit();

                _ = tree.mountExt4General(&scan, mount.target) catch |err|
                    return failWithHint("capture: mounting a --source-mount filesystem failed", err);

                const uuid = ownedUuid(gpa, &identifier_storage, &scan.identity.uuid) catch
                    return fail("capture: out of memory", .{});
                const label = ownedLabel(gpa, &identifier_storage, &scan.identity.label) catch
                    return fail("capture: out of memory", .{});
                break :blk .{ .uuid = uuid, .label = label };
            },
            .xfs => |*r| blk: {
                var scan = vmiz.xfs.scanReadable(r, io, gpa, xfsScanOptions(request.limits, opened.length, &diagnostic)) catch |err|
                    return failLimits("capture: reading a --source-mount filesystem failed", err, &diagnostic);
                defer scan.deinit();

                _ = tree.mountXfs(&scan, mount.target) catch |err|
                    return failWithHint("capture: mounting a --source-mount filesystem failed", err);

                const uuid = ownedUuid(gpa, &identifier_storage, &scan.identity.uuid) catch
                    return fail("capture: out of memory", .{});
                const label = ownedLabel(gpa, &identifier_storage, &scan.identity.label) catch
                    return fail("capture: out of memory", .{});
                break :blk .{ .uuid = uuid, .label = label };
            },
        };

        var mount_before = vmiz.identity_rewrite.Identifiers{ .filesystem_uuid = mount_identity.uuid, .filesystem_label = mount_identity.label };
        ownedPartition(gpa, &identifier_storage, opened.partition, &mount_before) catch
            return fail("capture: out of memory", .{});
        sources.append(.{
            .before = mount_before,
            .successor = .root,
            .merged_at = mount.target,
        }) catch return fail("capture: out of memory", .{});
    }

    // The ESP becomes a partition of its own rather than a directory in the
    // root, because a merged ESP is not an ESP: firmware looks for a
    // partition with the EFI type GUID and would find nothing to boot.
    var esp_tree: ?vmiz.root_tree.RootTree = null;
    defer if (esp_tree) |*value| value.deinit();
    var esp_spool: ?[]u8 = null;
    defer if (esp_spool) |value| gpa.free(value);
    defer if (esp_spool) |value| std.Io.Dir.cwd().deleteFile(io, value) catch {};

    if (!request.no_esp) {
        const found = findEspSpec(table, request) catch |err|
            return failWithHint("capture: --source-esp is not a valid spec", err);
        if (found) |esp_spec| {
            const opened = resolveSpec(gpa, io, &disk, table, esp_spec, &scratch) catch |err|
                return failWithHint("capture: cannot read the EFI system partition", err);

            var fs = vmiz.fat32.open(opened.image, io, .{
                .offset = opened.offset,
                .length = opened.length,
            }) catch |err| return failWithHint("capture: the EFI system partition is not readable", err);

            var scan = vmiz.fat32.scanTree(&fs, io, gpa, .{
                .max_nodes = request.limits.max_nodes,
                .max_path_bytes = request.limits.max_path_bytes,
                .max_component_bytes = request.limits.max_component_bytes,
                .max_file_bytes = request.limits.max_file_bytes,
                .max_total_bytes = request.limits.max_total_bytes,
                .max_scan_metadata_bytes = request.limits.max_scan_metadata_bytes,
                .diagnostic = &diagnostic,
            }) catch |err| return failLimits("capture: reading the EFI system partition failed", err, &diagnostic);
            defer scan.deinit();

            esp_spool = stagingPath(gpa, request.destination, ".esp-spool") catch
                return fail("capture: out of memory", .{});
            var built = vmiz.root_tree.RootTree.init(gpa, io, esp_spool.?, request.limits.tree()) catch |err|
                return fail("capture: cannot create the ESP staging spool: {s}", .{@errorName(err)});
            built.diagnostic = &diagnostic;
            built.importExt4View(scan.fileTreeView()) catch |err| {
                built.deinit();
                return failLimits("capture: importing the EFI system partition failed", err, &diagnostic);
            };
            esp_tree = built;

            const serial = ownedFatSerial(gpa, &identifier_storage, scan.volume_id) catch
                return fail("capture: out of memory", .{});
            const esp_label = ownedLabel(gpa, &identifier_storage, &scan.label) catch
                return fail("capture: out of memory", .{});
            var esp_before = vmiz.identity_rewrite.Identifiers{ .filesystem_uuid = serial, .filesystem_label = esp_label };
            ownedPartition(gpa, &identifier_storage, opened.partition, &esp_before) catch
                return fail("capture: out of memory", .{});
            sources.append(.{
                .before = esp_before,
                .successor = .esp,
            }) catch return fail("capture: out of memory", .{});
        }
    }

    // `assemble` creates its output exclusively and writes raw. When raw to a
    // real path is what was asked for, that is the output; otherwise it is a
    // staging file this converts from and removes.
    const writes_raw_directly = request.spec.compression == .none and
        request.spec.format == .raw and request.destination == .path;
    // `output.validate` has already refused a compressed or piped container
    // format, so anything left that is not raw is a seekable file this has to
    // build in the requested format rather than stream.
    const converts_container = request.spec.compression == .none and
        request.spec.format != .raw and request.destination == .path;
    const raw_path = if (writes_raw_directly)
        gpa.dupe(u8, request.destination.path) catch return fail("capture: out of memory", .{})
    else
        stagingPath(gpa, request.destination, ".raw") catch return fail("capture: out of memory", .{});
    defer gpa.free(raw_path);
    var wrote_raw = false;
    defer if (wrote_raw and !writes_raw_directly) std.Io.Dir.cwd().deleteFile(io, raw_path) catch {};

    const report = vmiz.disk_assembly.assemble(gpa, io, &tree, .{
        .raw_path = raw_path,
        .architecture = switch (request.architecture) {
            .auto => hostArchitecture(),
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .esp_tree = if (esp_tree) |*value| value else null,
        .esp_size = if (request.esp_size) |size| .{ .exact = size } else .{ .minimum_plus = vmiz.disk_assembly.default_esp_slack },
        .root_size = if (request.root_size) |size| .{ .exact = size } else .{ .minimum_plus = vmiz.disk_assembly.default_root_slack },
        .ext4_label = request.label,
        .root_filesystem = request.root_filesystem,
        // On by default here and nowhere else in vmiz (a captured system boots
        // into a mutable root that needs a journal to replay). The flag is
        // passed through untouched by `ext4JournalSetting` so an ext4 journal
        // asked for on an XFS root is rejected by name rather than dropped here.
        .ext4_journal = ext4JournalSetting(request),
        .root_selinux_label = request.selinux_label,
        .identity = .{
            .policy = if (request.rewrite_identities) .rewrite_and_verify else .off,
            .sources = sources.items,
        },
        .dry_run = request.dry_run,
    }) catch |err| {
        // A size that cannot be honoured is only actionable alongside the
        // number it had to clear, and only the planner knows that. Planning
        // again costs nothing that was going to be written anyway, and the
        // identity rewrite it repeats is idempotent.
        if (err == error.RootSizeBelowMinimum or err == error.EspSizeBelowMinimum) {
            reportMinimums(gpa, io, &tree, if (esp_tree) |*value| value else null, request);
        }
        return failWithHint("capture: assembling the image failed", err);
    };
    wrote_raw = !request.dry_run;

    reportSizes(request, report);

    if (request.dry_run) return 0;
    if (writes_raw_directly) return 0;

    var staged = vmiz.Image.openPathReadOnly(io, raw_path) catch |err|
        return fail("capture: cannot re-open the staged image: {s}", .{@errorName(err)});
    defer staged.close(io);

    if (converts_container) {
        convertStaged(gpa, io, staged, request, report.virtual_size) catch |err|
            return fail("capture: writing {s} output failed: {s}", .{ request.spec.displayName(), @errorName(err) });
        return 0;
    }

    vmiz.output.writeImageTo(gpa, io, staged, request.destination, .{
        .compression = request.spec.compression,
        .level = request.level orelse vmiz.output.default_level,
    }) catch |err|
        return fail("capture: writing {s} output failed: {s}", .{ request.spec.displayName(), @errorName(err) });

    return 0;
}

/// Rewrites the staged raw disk into the requested container format.
/// `output.writeImageTo` copies guest-visible bytes and knows nothing about a
/// VHD footer, a VHDX block allocation table or a qcow2 L1 table, so a
/// container has to be created as that format and copied into.
fn convertStaged(
    gpa: std.mem.Allocator,
    io: std.Io,
    staged: vmiz.Image,
    request: CaptureRequest,
    virtual_size: u64,
) !void {
    var options = vmiz.CreateOptions{};
    // Fixed, as `build-image` does: a captured image's reason to be a VHD at
    // all is almost always an Azure managed-disk upload, which refuses
    // dynamic.
    if (request.spec.format == .vhd) options.vhd_subformat = .fixed;

    // Exclusively, as the raw path already creates its output, so that a
    // capture cannot overwrite a file it was not asked to. It also makes the
    // cleanup below safe: what fails to be created is never deleted, so a
    // pre-existing destination -- or a device node `Image.create` refused --
    // survives the failure that named it.
    var destination = try vmiz.Image.createExclusive(io, request.destination.path, request.spec.format, virtual_size, options);
    // A half-written container is worse than none: it opens, reports a
    // plausible size, and fails somewhere the operator will not look.
    errdefer std.Io.Dir.cwd().deleteFile(io, request.destination.path) catch {};
    defer destination.close(io);
    try vmiz.copyAll(io, staged, &destination, gpa);
}

/// Reads through the image's guest-visible address space rather than the host
/// file. A qcow2 or VHDX source maps guest offsets to entirely different file
/// offsets, so an ext4 opened against the raw file would read the wrong bytes
/// -- or, for a sparse container smaller than the offset, none at all.
fn imageReadAt(ctx: *const anyopaque, io: std.Io, buffer: []u8, offset: u64) anyerror!usize {
    const image: *const vmiz.Image = @ptrCast(@alignCast(ctx));
    return image.pread(io, buffer, offset);
}

fn openSourceExt4(
    gpa: std.mem.Allocator,
    io: std.Io,
    opened: OpenedSource,
) vmiz.ext4.GeneralOpenError!vmiz.ext4.Reader {
    return vmiz.ext4.openGeneralReadOnlySource(
        io,
        opened.image.file,
        .{ .ctx = opened.image, .read_at_fn = imageReadAt },
        gpa,
        .{ .offset = opened.offset },
    );
}

fn openSourceXfs(
    gpa: std.mem.Allocator,
    io: std.Io,
    opened: OpenedSource,
) vmiz.xfs.OpenError!vmiz.xfs.Reader {
    return vmiz.xfs.Reader.openReadOnlySource(
        gpa,
        io,
        opened.image.file,
        .{ .ctx = opened.image, .read_at_fn = imageReadAt },
        opened.offset,
    );
}

/// A root or --source-mount filesystem, once its type has been resolved.
/// Small on purpose: everything that genuinely differs by filesystem type
/// (scanning, importing/mounting into the staging tree, and closing the
/// reader) is a two-armed switch at the one or two call sites that need it,
/// rather than a wider abstraction this task's XFS read path does not need.
const RootReader = union(enum) {
    ext4: vmiz.ext4.Reader,
    xfs: vmiz.xfs.Reader,

    fn deinit(self: *RootReader, io: std.Io) void {
        switch (self.*) {
            .ext4 => |*reader| reader.deinit(),
            .xfs => |*reader| reader.close(io),
        }
    }

    /// Whether this candidate's root directory has an /etc. Any failure to
    /// even stat it -- not just "no such entry" -- is treated as "no",
    /// matching the ext4-only check this generalises.
    fn hasEtc(self: *RootReader, io: std.Io) bool {
        return switch (self.*) {
            .ext4 => |*reader| blk: {
                const stat = reader.statPath(io, "/etc") catch break :blk false;
                break :blk stat.kind == .directory;
            },
            .xfs => |*reader| blk: {
                const stat = reader.statPath(io, "/etc") catch break :blk false;
                break :blk stat.kind == .directory;
            },
        };
    }

    /// Best-effort file read used only by `warnUnretirablePartitionReference`,
    /// which already treats any failure the same way (silence).
    fn readFileAlloc(self: *RootReader, io: std.Io, gpa: std.mem.Allocator, path: []const u8) ![]u8 {
        return switch (self.*) {
            .ext4 => |*reader| try reader.readFileAlloc(io, gpa, path),
            .xfs => |*reader| try reader.readFileAlloc(io, gpa, path),
        };
    }
};

/// Whether opening a candidate as ext4 failed only because it plainly is not
/// one -- wrong magic, an unrecognised feature bit this general reader has
/// no specific name for, or a source too short to even hold a superblock --
/// as opposed to a genuine read failure or a *named*, specifically
/// unsupported ext4 feature, which is a real failure worth reporting rather
/// than silently treating the candidate as absent.
fn isNotExt4(err: vmiz.ext4.GeneralOpenError) bool {
    return switch (err) {
        error.BadMagic,
        error.UnsupportedFilesystemFeature,
        error.UnsupportedBlockSize,
        error.UnexpectedEndOfFile,
        => true,
        else => false,
    };
}

/// The XFS analogue of `isNotExt4`: wrong magic, an unrecognised incompat
/// bit (this reader's equivalent of ext4's own "unknown feature" catch-all),
/// or a source too short to even hold a superblock.
fn isNotXfs(err: vmiz.xfs.OpenError) bool {
    return switch (err) {
        error.BadMagic,
        error.UnsupportedIncompatFeature,
        error.UnexpectedEndOfFile,
        => true,
        else => false,
    };
}

pub const FsOpenError = (vmiz.ext4.GeneralOpenError || vmiz.xfs.OpenError) || error{UnrecognizedRootFilesystem};

/// Opens `opened` as whichever supported filesystem it holds. ext4 is tried
/// first only because its own checks run first; neither guess is favoured
/// once a filesystem is actually found. Failing both guesses in a way that
/// means "plainly neither" (see `isNotExt4`/`isNotXfs`) is reported as
/// `error.UnrecognizedRootFilesystem`, filesystem-neutral by construction so
/// `resolveRoot`'s discovery loop can treat it as "not a candidate" and an
/// explicit --source-root/--source-mount can turn it into a user-facing
/// message. Anything else -- an unreadable disk, an exhausted allocator, a
/// named and specifically unsupported feature -- is a real failure and
/// propagates as itself.
fn openSourceFilesystem(gpa: std.mem.Allocator, io: std.Io, opened: OpenedSource) FsOpenError!RootReader {
    const ext4_reader = openSourceExt4(gpa, io, opened) catch |ext4_err| {
        if (!isNotExt4(ext4_err)) return ext4_err;
        const xfs_reader = openSourceXfs(gpa, io, opened) catch |xfs_err| {
            if (!isNotXfs(xfs_err)) return xfs_err;
            return error.UnrecognizedRootFilesystem;
        };
        return .{ .xfs = xfs_reader };
    };
    return .{ .ext4 = ext4_reader };
}

fn scanOptions(
    limits: vmiz.limits.ImportLimits,
    available_length: u64,
    diagnostic: *vmiz.limits.Diagnostic,
) vmiz.ext4.GeneralScanOptions {
    return .{
        .available_length = available_length,
        .max_nodes = limits.max_nodes,
        .max_path_bytes = limits.max_path_bytes,
        .max_component_bytes = limits.max_component_bytes,
        .max_file_bytes = limits.max_file_bytes,
        .max_total_bytes = limits.max_total_bytes,
        .max_xattrs_per_node = limits.max_xattrs_per_node,
        .max_xattr_bytes_per_node = limits.max_xattr_bytes_per_node,
        .max_scan_metadata_bytes = limits.max_scan_metadata_bytes,
        .diagnostic = diagnostic,
    };
}

fn xfsScanOptions(
    limits: vmiz.limits.ImportLimits,
    available_length: u64,
    diagnostic: *vmiz.limits.Diagnostic,
) vmiz.xfs.ScanOptions {
    return .{
        .available_length = available_length,
        .max_nodes = limits.max_nodes,
        .max_path_bytes = limits.max_path_bytes,
        .max_component_bytes = limits.max_component_bytes,
        .max_file_bytes = limits.max_file_bytes,
        .max_total_bytes = limits.max_total_bytes,
        .max_xattrs_per_node = limits.max_xattrs_per_node,
        .max_xattr_bytes_per_node = limits.max_xattr_bytes_per_node,
        .max_scan_metadata_bytes = limits.max_scan_metadata_bytes,
        .diagnostic = diagnostic,
    };
}

fn resolveRoot(
    gpa: std.mem.Allocator,
    io: std.Io,
    disk: *vmiz.Image,
    table: ?vmiz.gpt.ParsedGpt,
    request: CaptureRequest,
    scratch: *std.array_list.Managed(*vmiz.Image),
) !OpenedSource {
    if (request.root_spec_text) |text| {
        const spec = try parseSourceSpec(text);
        return resolveSpec(gpa, io, disk, table, spec, scratch);
    }
    // With no --source-root, the root is whichever partition holds a
    // supported filesystem -- ext4 or xfs -- provided exactly one does. That
    // is a fact read off the disk rather than a guess, and it covers the
    // ordinary single-root install. Ambiguity is refused, never resolved:
    // "the biggest one" would be right often enough to be trusted and wrong
    // often enough to matter.
    const parsed = table orelse
        return .{ .image = disk, .offset = 0, .length = disk.virtual_size };

    var found: ?OpenedSource = null;
    var saw_supported_fs = false;
    for (parsed.partitions) |entry| {
        if (entry.isEmpty()) continue;
        // An ESP is FAT and would never probe as ext4 or xfs, but skipping
        // it by type keeps the candidate set to partitions that could be a
        // root.
        if (std.mem.eql(u8, &entry.partition_type_guid, &vmiz.guid.esp)) continue;
        const candidate = OpenedSource{
            .image = disk,
            .offset = entry.first_lba * vmiz.gpt.sector_size,
            .length = (entry.last_lba - entry.first_lba + 1) * vmiz.gpt.sector_size,
            .partition = entry,
        };
        var probe = openSourceFilesystem(gpa, io, candidate) catch |err| switch (err) {
            // Neither an ext4 nor an xfs filesystem, or not one this can
            // read: both mean "not a candidate". Anything else -- an
            // unreadable disk, an exhausted allocator -- is a real failure,
            // and reporting it as "no partition holds a supported
            // filesystem" would be a false statement about the disk rather
            // than a diagnosis.
            error.UnrecognizedRootFilesystem => continue,
            else => return err,
        };
        defer probe.deinit(io);
        saw_supported_fs = true;

        // Holding a supported filesystem is not being the root. A separate
        // /boot is ext4 (or xfs) on plenty of systems whose root is
        // something else entirely, and capturing it would produce a
        // plausible image of the wrong thing. Every root has /etc; no
        // /boot, /var or /home does.
        if (!probe.hasEtc(io)) continue;

        if (found != null) return error.AmbiguousSourceRoot;
        found = candidate;
    }
    if (found) |value| return value;
    return if (saw_supported_fs) error.NoRootLikeFilesystem else error.SourceRootRequired;
}

fn resolveSpec(
    gpa: std.mem.Allocator,
    io: std.Io,
    disk: *vmiz.Image,
    table: ?vmiz.gpt.ParsedGpt,
    spec: SourceSpec,
    scratch: *std.array_list.Managed(*vmiz.Image),
) !OpenedSource {
    switch (spec) {
        .path => |path| {
            const owned = try gpa.create(vmiz.Image);
            errdefer gpa.destroy(owned);
            owned.* = try vmiz.Image.openPathReadOnly(io, path);
            errdefer owned.close(io);
            try scratch.append(owned);
            return .{ .image = owned, .offset = 0, .length = owned.virtual_size };
        },
        .gpt_index => |index| {
            const parsed = table orelse return error.SourceHasNoPartitionTable;
            const entry = findPartition(parsed, index) orelse return error.PartitionNotFound;
            return .{
                .image = disk,
                .offset = entry.first_lba * vmiz.gpt.sector_size,
                .length = (entry.last_lba - entry.first_lba + 1) * vmiz.gpt.sector_size,
                .partition = entry,
            };
        },
        .logical_volume => |selector| {
            var scan = try vmiz.lvm.scan(gpa, disk.*, io);
            defer scan.deinit();
            const selected = try scan.findLogicalVolume(selector.group, selector.name);
            const extent = try vmiz.lvm.contiguousRange(selected.group, selected.volume);
            return .{ .image = disk, .offset = extent.offset, .length = extent.length };
        },
    }
}

fn findPartition(parsed: vmiz.gpt.ParsedGpt, index: u32) ?vmiz.gpt.PartitionEntry {
    for (parsed.partitions) |entry| {
        if (entry.table_index + 1 == index) return entry;
    }
    return null;
}

/// The ESP is named explicitly, or found by its type GUID. The type GUID is
/// definitional rather than a heuristic: a partition carrying it *is* an EFI
/// system partition, which is exactly how firmware finds one.
fn findEspSpec(table: ?vmiz.gpt.ParsedGpt, request: CaptureRequest) !?SourceSpec {
    // A malformed --source-esp is a failure, not an absent ESP. Swallowing it
    // would assemble a root-only disk and exit 0, which is a typo turning
    // into an unbootable image with nothing said.
    if (request.esp_spec_text) |text| return try parseSourceSpec(text);
    const parsed = table orelse return null;
    for (parsed.partitions) |entry| {
        if (std.mem.eql(u8, &entry.partition_type_guid, &vmiz.guid.esp)) {
            return .{ .gpt_index = entry.table_index + 1 };
        }
    }
    return null;
}

fn ownedUuid(
    gpa: std.mem.Allocator,
    storage: *std.array_list.Managed([]u8),
    bytes: *const [16]u8,
) ![]const u8 {
    const buffer = try gpa.alloc(u8, vmiz.identity_rewrite.canonical_uuid_bytes);
    errdefer gpa.free(buffer);
    const text = vmiz.identity_rewrite.formatFilesystemUuid(buffer[0..vmiz.identity_rewrite.canonical_uuid_bytes], bytes);
    try storage.append(buffer);
    return text;
}

fn ownedLabel(
    gpa: std.mem.Allocator,
    storage: *std.array_list.Managed([]u8),
    field: []const u8,
) !?[]const u8 {
    const trimmed = vmiz.identity_rewrite.trimLabel(field) orelse return null;
    const copy = try gpa.dupe(u8, trimmed);
    errdefer gpa.free(copy);
    try storage.append(copy);
    return copy;
}

/// Warns when the captured fstab names the source by an identifier this
/// capture cannot replace. Best effort by design: an unreadable or absent
/// fstab is not itself a problem, and this only ever adds a warning.
fn warnUnretirablePartitionReference(gpa: std.mem.Allocator, io: std.Io, reader: *RootReader) void {
    const fstab = reader.readFileAlloc(io, gpa, "/etc/fstab") catch return;
    defer gpa.free(fstab);
    const kind: []const u8 = if (std.mem.indexOf(u8, fstab, "PARTUUID=") != null)
        "PARTUUID"
    else if (std.mem.indexOf(u8, fstab, "PARTLABEL=") != null)
        "PARTLABEL"
    else
        return;
    std.debug.print(
        "capture: warning: /etc/fstab names the root by {s}, but the root was named by path, so this capture does not know which partition it came from and cannot replace that reference. The image will not boot. Name the root as a partition of --source instead (--source <disk> --source-root gpt:<n>)\n",
        .{kind},
    );
}

/// The source partition's GUID and name, as `PARTUUID=` and `PARTLABEL=`
/// spell them. Null when the filesystem was named directly rather than
/// through `--source`'s partition table, because then there is no partition
/// this capture is replacing and nothing to retire.
fn ownedPartition(
    gpa: std.mem.Allocator,
    storage: *std.array_list.Managed([]u8),
    entry: ?vmiz.gpt.PartitionEntry,
    before: *vmiz.identity_rewrite.Identifiers,
) !void {
    const value = entry orelse return;

    const buffer = try gpa.alloc(u8, 36);
    {
        errdefer gpa.free(buffer);
        try storage.append(buffer);
    }
    // `buffer` belongs to `storage` from here on, so no errdefer may free it:
    // the label allocation below can still fail, and freeing it here would
    // leave a dangling entry for the caller's cleanup to free again.
    before.partition_uuid = vmiz.guid.formatLower(buffer[0..36], value.unique_partition_guid);

    var name: [36]u8 = undefined;
    var length: usize = 0;
    for (value.name_utf16le) |code_unit| {
        if (code_unit == 0) break;
        // A PARTLABEL outside ASCII is left alone rather than transcoded:
        // the rewriter matches bytes, and a lossy round trip would match the
        // wrong ones.
        if (code_unit > 0x7f) return;
        name[length] = @intCast(code_unit);
        length += 1;
    }
    before.partition_label = try ownedLabel(gpa, storage, name[0..length]);
}

fn ownedFatSerial(
    gpa: std.mem.Allocator,
    storage: *std.array_list.Managed([]u8),
    volume_id: u32,
) ![]const u8 {
    const buffer = try gpa.alloc(u8, vmiz.identity_rewrite.fat_serial_bytes);
    errdefer gpa.free(buffer);
    const text = vmiz.identity_rewrite.formatFatVolumeSerial(buffer[0..vmiz.identity_rewrite.fat_serial_bytes], volume_id);
    try storage.append(buffer);
    return text;
}

/// A staging path beside the destination, so the staged image lands on the
/// same filesystem the output will and a capture that fills a disk does so
/// where the operator chose rather than in /tmp.
fn stagingPath(
    gpa: std.mem.Allocator,
    destination: vmiz.output.Destination,
    suffix: []const u8,
) ![]u8 {
    return switch (destination) {
        .path => |path| std.fmt.allocPrint(gpa, "{s}.vmiz-capture{s}", .{ path, suffix }),
        .stdout => std.fmt.allocPrint(gpa, "vmiz-capture{s}", .{suffix}),
    };
}

/// Plans the same disk with the sizes left to default, so a rejected
/// `--root-size` or `--esp-size` can be answered with the figure it missed.
fn reportMinimums(
    gpa: std.mem.Allocator,
    io: std.Io,
    tree: *vmiz.root_tree.RootTree,
    esp_tree: ?*vmiz.root_tree.RootTree,
    request: CaptureRequest,
) void {
    const planned = vmiz.disk_assembly.assemble(gpa, io, tree, .{
        // Never opened: a dry run stops after planning. It still has to name
        // something, because an empty path is refused as a mistake.
        .raw_path = "vmiz-capture-dry-run",
        .architecture = switch (request.architecture) {
            .auto => hostArchitecture(),
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .esp_tree = esp_tree,
        .root_filesystem = request.root_filesystem,
        // Matches the real assemble above via the same helper, so the two can
        // never diverge on how the journal flag maps.
        .ext4_journal = ext4JournalSetting(request),
        .identity = .{ .policy = .off },
        .dry_run = true,
    }) catch return;

    std.debug.print("capture: the smallest root filesystem holding this content is {d} MiB ({d} bytes)\n", .{
        planned.root_minimum_bytes >> 20,
        planned.root_minimum_bytes,
    });
    if (planned.esp_minimum_bytes) |minimum| {
        std.debug.print("capture: the smallest EFI system partition holding it is {d} MiB ({d} bytes)\n", .{
            minimum >> 20,
            minimum,
        });
    }
}

fn reportSizes(request: CaptureRequest, report: ?vmiz.disk_assembly.Report) void {
    const value = report orelse return;
    std.debug.print(
        "capture: root filesystem {d} MiB (minimum {d} MiB), {d} files\n",
        .{ value.root.filesystem_length >> 20, value.root_minimum_bytes >> 20, value.root_node_count },
    );
    if (value.esp) |esp| {
        std.debug.print(
            "capture: EFI system partition {d} MiB (minimum {d} MiB), {d} files\n",
            .{ esp.length_bytes >> 20, (value.esp_minimum_bytes orelse 0) >> 20, value.esp_node_count },
        );
    }
    std.debug.print("capture: disk {d} MiB{s}\n", .{
        value.virtual_size >> 20,
        if (request.dry_run) " (dry run, nothing written)" else "",
    });
    reportIdentity("root", value.identity_rewrite);
    if (value.esp != null) reportIdentity("ESP", value.esp_identity_rewrite);
}

/// The rewrite is the part of a capture most likely to leave an image that
/// builds cleanly and then fails to boot, so what it did is stated rather
/// than assumed, and what it could not do is a warning.
fn reportIdentity(which: []const u8, report: vmiz.identity_rewrite.Report) void {
    // A filesystem-type correction (ext4 -> xfs in fstab or a `rootfstype=`)
    // can happen with no identifier retired at all -- a root that keeps its
    // UUID through the conversion -- so the summary must not hinge on
    // `retired_identifiers` alone, or that correction would be made silently.
    const did_anything = report.retired_identifiers > 0 or
        report.fstab_types_rewritten > 0 or
        report.config_rootfstype_rewritten > 0;
    if (!did_anything) return;
    std.debug.print(
        "capture: {s} identity rewrite: {d} fstab entries rewritten, {d} filesystem-type corrections, {d} dropped, {d} references in {d} config files ({d} rootfstype corrections)\n",
        .{
            which,
            report.fstab_entries_rewritten,
            report.fstab_types_rewritten,
            report.fstab_entries_dropped,
            report.config_references_rewritten,
            report.config_files_rewritten,
            report.config_rootfstype_rewritten,
        },
    );
    if (report.fstab_entries_unresolved > 0) {
        std.debug.print(
            "capture: warning: {d} {s} fstab entries name a filesystem this capture retired but did not replace; they were left alone and the image may not boot\n",
            .{ report.fstab_entries_unresolved, which },
        );
    }
    if (report.stale_references > 0) {
        std.debug.print(
            "capture: warning: {d} references to a retired identifier survived the {s} rewrite\n",
            .{ report.stale_references, which },
        );
    }
}

fn failOpen(path: []const u8, err: anyerror) u8 {
    if (describeCaptureFailure(err)) |hint| {
        return fail("capture: cannot open '{s}': {s}\n  {s}", .{ path, @errorName(err), hint });
    }
    return fail("capture: cannot open '{s}': {s}", .{ path, @errorName(err) });
}

fn failWithHint(comptime context: []const u8, err: anyerror) u8 {
    if (describeCaptureFailure(err)) |hint| {
        return fail(context ++ ": {s}\n  {s}", .{ @errorName(err), hint });
    }
    return fail(context ++ ": {s}", .{@errorName(err)});
}

/// A limit breach knows the value that was observed and the flag that admits
/// it, which the error name alone does not.
fn failLimits(
    comptime context: []const u8,
    err: anyerror,
    diagnostic: *const vmiz.limits.Diagnostic,
) u8 {
    if (diagnostic.exceeded) |breach| {
        if (breach.limit.err() == err) {
            var message: [vmiz.limits.Exceeded.max_message_bytes]u8 = undefined;
            var remediation: [vmiz.limits.Exceeded.max_remediation_bytes]u8 = undefined;
            return fail(context ++ ": {s}\n  {s}", .{
                breach.describe(&message) catch @errorName(err),
                breach.remediation(&remediation) catch "",
            });
        }
    }
    return failWithHint(context, err);
}

fn fail(comptime format: []const u8, args: anytype) u8 {
    std.debug.print(format ++ "\n", args);
    return 1;
}

test "a source spec distinguishes a path from a partition or a volume" {
    // A device-mapper node is a path like any other: on a live system the
    // kernel has already assembled the volume, so nothing here has to.
    try std.testing.expectEqualStrings("/dev/mapper/vg-root", (try parseSourceSpec("/dev/mapper/vg-root")).path);
    try std.testing.expectEqualStrings("/dev/nvme0n1p2", (try parseSourceSpec("/dev/nvme0n1p2")).path);
    try std.testing.expectEqualStrings("disk.img", (try parseSourceSpec("disk.img")).path);

    try std.testing.expectEqual(@as(u32, 2), (try parseSourceSpec("gpt:2")).gpt_index);
    try std.testing.expectEqual(@as(u32, 128), (try parseSourceSpec("gpt:128")).gpt_index);

    const volume = (try parseSourceSpec("lvm:vg0/root")).logical_volume;
    try std.testing.expectEqualStrings("vg0", volume.group);
    try std.testing.expectEqualStrings("root", volume.name);
}

test "a malformed source spec is refused rather than read as a path" {
    try std.testing.expectError(error.EmptySourceSpec, parseSourceSpec(""));
    try std.testing.expectError(error.InvalidGptIndex, parseSourceSpec("gpt:"));
    try std.testing.expectError(error.InvalidGptIndex, parseSourceSpec("gpt:x"));
    // Partitions are numbered as every other tool numbers them, from one.
    try std.testing.expectError(error.InvalidGptIndex, parseSourceSpec("gpt:0"));
    try std.testing.expectError(error.InvalidGptIndex, parseSourceSpec("gpt:-1"));
    try std.testing.expectError(error.InvalidLogicalVolumeSpec, parseSourceSpec("lvm:vg0"));
    try std.testing.expectError(error.InvalidLogicalVolumeSpec, parseSourceSpec("lvm:/root"));
    try std.testing.expectError(error.InvalidLogicalVolumeSpec, parseSourceSpec("lvm:vg0/"));
    try std.testing.expectError(error.InvalidLogicalVolumeSpec, parseSourceSpec("lvm:vg0/a/b"));
}

test "a mount splits on the first equals so a target may contain one" {
    const boot = try parseMount("/dev/sda2=/boot");
    try std.testing.expectEqualStrings("/dev/sda2", boot.source.path);
    try std.testing.expectEqualStrings("/boot", boot.target);

    const partition = try parseMount("gpt:1=/boot/efi");
    try std.testing.expectEqual(@as(u32, 1), partition.source.gpt_index);
    try std.testing.expectEqualStrings("/boot/efi", partition.target);

    const odd = try parseMount("gpt:3=/srv/a=b");
    try std.testing.expectEqualStrings("/srv/a=b", odd.target);

    try std.testing.expectError(error.MissingMountTarget, parseMount("/dev/sda2"));
    try std.testing.expectError(error.MissingMountTarget, parseMount("/dev/sda2="));
    try std.testing.expectError(error.EmptyMountSource, parseMount("=/boot"));
}

test "the failures an operator is most likely to hit explain themselves" {
    // The two that would otherwise send someone to the source: a bare
    // AccessDenied from a device node, and a size that cannot be honoured.
    try std.testing.expect(describeCaptureFailure(error.AccessDenied) != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        describeCaptureFailure(error.AccessDenied).?,
        "root",
    ) != null);
    try std.testing.expect(describeCaptureFailure(error.RootSizeBelowMinimum) != null);

    // Both outcomes of root auto-detection have to name the flag that
    // settles them, because neither is actionable as a bare error name.
    inline for (.{ error.SourceRootRequired, error.AmbiguousSourceRoot, error.NoRootLikeFilesystem }) |err| {
        const message = describeCaptureFailure(err) orelse
            return error.TestExpectedExplanation;
        try std.testing.expect(std.mem.indexOf(u8, message, "--source-root") != null);
    }

    // Every LVM refusal points at the same way out, because there is only
    // one: let device-mapper assemble the volume and capture that.
    inline for (.{
        error.UnsupportedLvmStripedSegment,
        error.UnsupportedLvmThinSegment,
        error.LogicalVolumeNotContiguous,
    }) |err| {
        const message = describeCaptureFailure(err) orelse
            return error.TestExpectedExplanation;
        try std.testing.expect(std.mem.indexOf(u8, message, "/dev/mapper/") != null);
    }

    // Errors that already read well are left alone rather than restated.
    try std.testing.expect(describeCaptureFailure(error.OutOfMemory) == null);
}

// ---------------------------------------------------------------------------
// XFS source support: automatic root discovery, ext4/xfs ambiguity, explicit
// root/mount import with identity preservation, and malformed-XFS handling.
//
// These are the first tests in this file to drive `resolveRoot`,
// `resolveSpec` and `openSourceFilesystem` themselves rather than the pure
// parsing/message helpers above, so the ambiguity test needs a genuine ext4
// fixture too; `TestInMemoryTree` below is a local copy of the same
// `FileTreeView` implementation `cosi.zig` keeps privately for exactly this
// purpose (ext4.zig's own equivalent is private to that file).
// ---------------------------------------------------------------------------

const TestInMemoryEntry = struct {
    path: []const u8,
    kind: vmiz.ext4.Kind,
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    size: u64 = 0,
    bytes: []const u8 = "",
};

const TestInMemoryTree = struct {
    entries: []const TestInMemoryEntry,
    index: usize = 0,
    view: vmiz.ext4.FileTreeView,

    fn init(entries: []const TestInMemoryEntry) TestInMemoryTree {
        return .{
            .entries = entries,
            .view = .{ .ctx = undefined, .next_fn = next, .reset_fn = reset },
        };
    }

    /// A separate step from `init` so `view.ctx` is bound only once the tree
    /// is in its final, stable storage location rather than the temporary
    /// returned by `init` itself.
    fn bind(self: *TestInMemoryTree) void {
        self.view = .{ .ctx = self, .next_fn = next, .reset_fn = reset };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *TestInMemoryTree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) vmiz.ext4.FileTreeView.IteratorError!?vmiz.ext4.FileTreeView.Entry {
        const self: *TestInMemoryTree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.size,
            .content = switch (entry.kind) {
                .file, .symlink => .{ .ctx = &self.entries[self.index - 1], .read_at_fn = readContent },
                else => null,
            },
        };
    }

    fn readContent(ctx: *const anyopaque, buffer: []u8, offset: u64) vmiz.ext4.FileTreeView.ContentError!usize {
        const entry: *const TestInMemoryEntry = @ptrCast(@alignCast(ctx));
        const off = std.math.cast(usize, offset) orelse return error.UnexpectedEndOfStream;
        if (off > entry.bytes.len) return error.UnexpectedEndOfStream;
        const n = @min(buffer.len, entry.bytes.len - off);
        std.mem.copyForwards(u8, buffer[0..n], entry.bytes[off .. off + n]);
        return n;
    }
};

/// Writes a real ext4 filesystem holding just `/etc/os-release` at `offset`
/// within `file`, so ambiguity tests have a genuine ext4 root candidate
/// alongside a synthetic xfs one built by `vmiz.xfs.buildEtcOsReleaseVolume`.
fn writeExt4EtcRoot(
    io: std.Io,
    file: std.Io.File,
    offset: u64,
    length: u64,
    uuid: [16]u8,
    label: []const u8,
    os_release: []const u8,
) !void {
    var tree = TestInMemoryTree.init(&[_]TestInMemoryEntry{
        .{ .path = "etc", .kind = .directory, .mode = 0o755 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .size = os_release.len, .bytes = os_release },
    });
    tree.bind();
    _ = try vmiz.ext4.populate(io, file, std.testing.allocator, &tree.view, .{
        .offset = offset,
        .length = length,
        .uuid = uuid,
        .label = label,
    });
}

/// A `CaptureRequest` with every field a test does not care about set to a
/// harmless default; only `root_spec_text` varies across the tests below.
fn testCaptureRequest(root_spec_text: ?[]const u8) CaptureRequest {
    return .{
        .source_path = "",
        .root_spec_text = root_spec_text,
        .esp_spec_text = null,
        .no_esp = true,
        .mounts = &.{},
        .root_size = null,
        .esp_size = null,
        .architecture = .auto,
        .label = "",
        .root_filesystem = .ext4,
        .selinux_label = null,
        .journal = false,
        .rewrite_identities = false,
        .dry_run = true,
        .spec = .{ .format = .raw },
        .destination = .stdout,
        .level = null,
        .limits = .{},
    };
}

test "resolveRoot finds an XFS root automatically, skipping the ESP" {
    const io = std.testing.io;
    const path = "test-capture-xfs-auto-root.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const os_release = "NAME=vmiz\nID=vmiz\n";
    const volume = try vmiz.xfs.buildEtcOsReleaseVolume(std.testing.allocator, os_release);
    defer std.testing.allocator.free(volume);

    var img = try vmiz.Image.create(io, path, .raw, 8 * 1024 * 1024, .{});
    defer img.close(io);

    const specs = [_]vmiz.gpt.PartitionSpec{
        .{
            .type_guid = vmiz.guid.esp,
            .unique_guid = vmiz.guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = 2048,
            .name_utf16le = vmiz.gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = vmiz.guid.parse("22222222-2222-2222-2222-222222222222"),
            .unique_guid = vmiz.guid.parse("33333333-3333-3333-3333-333333333333"),
            .size_sectors = 2048,
            .name_utf16le = vmiz.gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]vmiz.gpt.Placement = undefined;
    try vmiz.gpt.writeGpt(&img, io, vmiz.guid.parse("44444444-4444-4444-4444-444444444444"), &specs, &placements);

    const root_offset = placements[1].first_lba * vmiz.gpt.sector_size;
    try img.pwrite(io, volume, root_offset);

    const table = try vmiz.gpt.readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(table.partitions);

    var scratch = std.array_list.Managed(*vmiz.Image).init(std.testing.allocator);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            std.testing.allocator.destroy(opened);
        }
        scratch.deinit();
    }

    const request = testCaptureRequest(null);
    const found = try resolveRoot(std.testing.allocator, io, &img, table, request, &scratch);
    try std.testing.expectEqual(root_offset, found.offset);
    try std.testing.expectEqual(@as(u64, 2048 * vmiz.gpt.sector_size), found.length);

    var reader = try openSourceFilesystem(std.testing.allocator, io, found);
    defer reader.deinit(io);
    try std.testing.expect(reader == .xfs);
    try std.testing.expect(reader.hasEtc(io));
}

test "resolveRoot refuses ambiguity between an ext4 root and an xfs root" {
    const io = std.testing.io;
    const path = "test-capture-xfs-ext4-ambiguous.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const os_release = "NAME=vmiz\nID=vmiz\n";
    const volume = try vmiz.xfs.buildEtcOsReleaseVolume(std.testing.allocator, os_release);
    defer std.testing.allocator.free(volume);

    var img = try vmiz.Image.create(io, path, .raw, 32 * 1024 * 1024, .{});
    defer img.close(io);

    const specs = [_]vmiz.gpt.PartitionSpec{
        .{
            .type_guid = vmiz.guid.esp,
            .unique_guid = vmiz.guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = 2048,
            .name_utf16le = vmiz.gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = vmiz.guid.parse("22222222-2222-2222-2222-222222222222"),
            .unique_guid = vmiz.guid.parse("33333333-3333-3333-3333-333333333333"),
            .size_sectors = 16384,
            .name_utf16le = vmiz.gpt.asciiName("ext4root"),
        },
        .{
            .type_guid = vmiz.guid.parse("55555555-5555-5555-5555-555555555555"),
            .unique_guid = vmiz.guid.parse("66666666-6666-6666-6666-666666666666"),
            .size_sectors = 2048,
            .name_utf16le = vmiz.gpt.asciiName("xfsroot"),
        },
    };
    var placements: [specs.len]vmiz.gpt.Placement = undefined;
    try vmiz.gpt.writeGpt(&img, io, vmiz.guid.parse("77777777-7777-7777-7777-777777777777"), &specs, &placements);

    const ext4_offset = placements[1].first_lba * vmiz.gpt.sector_size;
    const ext4_length = (placements[1].last_lba - placements[1].first_lba + 1) * vmiz.gpt.sector_size;
    try writeExt4EtcRoot(
        io,
        img.file,
        ext4_offset,
        ext4_length,
        [_]u8{0xAA} ** 16,
        "extroot",
        os_release,
    );

    const xfs_offset = placements[2].first_lba * vmiz.gpt.sector_size;
    try img.pwrite(io, volume, xfs_offset);

    const table = try vmiz.gpt.readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(table.partitions);

    var scratch = std.array_list.Managed(*vmiz.Image).init(std.testing.allocator);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            std.testing.allocator.destroy(opened);
        }
        scratch.deinit();
    }

    const request = testCaptureRequest(null);
    try std.testing.expectError(
        error.AmbiguousSourceRoot,
        resolveRoot(std.testing.allocator, io, &img, table, request, &scratch),
    );
}

test "an explicit XFS --source-root is opened, scanned and imported, preserving its identity" {
    const io = std.testing.io;
    const path = "test-capture-xfs-explicit-root.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const os_release = "NAME=vmiz\nID=vmiz\n";
    const volume = try vmiz.xfs.buildEtcOsReleaseVolume(std.testing.allocator, os_release);
    defer std.testing.allocator.free(volume);

    var img = try vmiz.Image.create(io, path, .raw, volume.len, .{});
    defer img.close(io);
    try img.pwrite(io, volume, 0);

    var disk = try vmiz.Image.openPathReadOnly(io, path);
    defer disk.close(io);

    var scratch = std.array_list.Managed(*vmiz.Image).init(std.testing.allocator);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            std.testing.allocator.destroy(opened);
        }
        scratch.deinit();
    }

    const request = testCaptureRequest(path);
    const found = try resolveRoot(std.testing.allocator, io, &disk, null, request, &scratch);

    var reader = try openSourceFilesystem(std.testing.allocator, io, found);
    defer reader.deinit(io);
    try std.testing.expect(reader == .xfs);

    var diagnostic = vmiz.limits.Diagnostic{};
    var scan = try vmiz.xfs.scanReadable(&reader.xfs, io, std.testing.allocator, xfsScanOptions(.{}, found.length, &diagnostic));
    defer scan.deinit();

    var tree = vmiz.root_tree.RootTree.initMemory(std.testing.allocator, io, (vmiz.limits.ImportLimits{}).tree());
    defer tree.deinit();
    try tree.importXfs(&scan);

    const content = try tree.readFileAlloc(std.testing.allocator, "etc/os-release", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings(os_release, content);

    var identifier_storage = std.array_list.Managed([]u8).init(std.testing.allocator);
    defer {
        for (identifier_storage.items) |owned| std.testing.allocator.free(owned);
        identifier_storage.deinit();
    }
    const uuid = try ownedUuid(std.testing.allocator, &identifier_storage, &scan.identity.uuid);
    try std.testing.expectEqualStrings("01020304-0506-0708-090a-0b0c0d0e0f10", uuid);
    const label = try ownedLabel(std.testing.allocator, &identifier_storage, &scan.identity.label);
    try std.testing.expectEqualStrings("caproot", label.?);
}

test "an explicit XFS --source-mount is opened, scanned and mounted" {
    const io = std.testing.io;
    const path = "test-capture-xfs-explicit-mount.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    const os_release = "NAME=vmiz\nID=vmiz\n";
    const volume = try vmiz.xfs.buildEtcOsReleaseVolume(std.testing.allocator, os_release);
    defer std.testing.allocator.free(volume);

    var img = try vmiz.Image.create(io, path, .raw, volume.len, .{});
    defer img.close(io);
    try img.pwrite(io, volume, 0);

    var disk = try vmiz.Image.openPathReadOnly(io, path);
    defer disk.close(io);

    var scratch = std.array_list.Managed(*vmiz.Image).init(std.testing.allocator);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            std.testing.allocator.destroy(opened);
        }
        scratch.deinit();
    }

    const opened = try resolveSpec(std.testing.allocator, io, &disk, null, .{ .path = path }, &scratch);

    var reader = try openSourceFilesystem(std.testing.allocator, io, opened);
    defer reader.deinit(io);
    try std.testing.expect(reader == .xfs);

    var diagnostic = vmiz.limits.Diagnostic{};
    var scan = try vmiz.xfs.scanReadable(&reader.xfs, io, std.testing.allocator, xfsScanOptions(.{}, opened.length, &diagnostic));
    defer scan.deinit();

    var tree = vmiz.root_tree.RootTree.initMemory(std.testing.allocator, io, (vmiz.limits.ImportLimits{}).tree());
    defer tree.deinit();
    // The mount point must already exist as a directory: `mountXfs` replaces
    // its contents but never creates it, the same way `mount(8)` refuses a
    // missing target rather than inventing one.
    try tree.putDirectory("data", .{ .mode = 0o755 });
    _ = try tree.mountXfs(&scan, "/data");

    const content = try tree.readFileAlloc(std.testing.allocator, "data/etc/os-release", 4096);
    defer std.testing.allocator.free(content);
    try std.testing.expectEqualStrings(os_release, content);
}

test "a malformed XFS candidate propagates as a genuine failure, not a silently skipped one" {
    const io = std.testing.io;
    const path = "test-capture-xfs-malformed.img";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    var img = try vmiz.Image.create(io, path, .raw, 8 * 1024 * 1024, .{});
    defer img.close(io);

    const specs = [_]vmiz.gpt.PartitionSpec{
        .{
            .type_guid = vmiz.guid.esp,
            .unique_guid = vmiz.guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = 2048,
            .name_utf16le = vmiz.gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = vmiz.guid.parse("22222222-2222-2222-2222-222222222222"),
            .unique_guid = vmiz.guid.parse("33333333-3333-3333-3333-333333333333"),
            .size_sectors = 2048,
            .name_utf16le = vmiz.gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]vmiz.gpt.Placement = undefined;
    try vmiz.gpt.writeGpt(&img, io, vmiz.guid.parse("44444444-4444-4444-4444-444444444444"), &specs, &placements);

    // XFS's own magic with an otherwise-zeroed superblock: real enough to
    // rule out "not XFS at all" (`isNotXfs`'s skip list), but a version
    // field no reader supports -- exactly the case that must surface as
    // `error.UnsupportedSuperblockVersion` rather than being reported as
    // "no root filesystem found".
    var malformed = [_]u8{0} ** 512;
    std.mem.writeInt(u32, malformed[0..4], vmiz.xfs.magic, .big);
    const root_offset = placements[1].first_lba * vmiz.gpt.sector_size;
    try img.pwrite(io, &malformed, root_offset);

    const table = try vmiz.gpt.readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(table.partitions);

    var scratch = std.array_list.Managed(*vmiz.Image).init(std.testing.allocator);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            std.testing.allocator.destroy(opened);
        }
        scratch.deinit();
    }

    const request = testCaptureRequest(null);
    try std.testing.expectError(
        error.UnsupportedSuperblockVersion,
        resolveRoot(std.testing.allocator, io, &img, table, request, &scratch),
    );
}

test "capture keeps the journal flag for validation instead of erasing it for an XFS root" {
    // The bug this guards: capture defaults the journal on, and an earlier
    // version silently cleared it whenever the root was XFS, so a contradictory
    // `--root-filesystem xfs` (journal still on by default) was accepted and the
    // setting vanished. The mapping must instead pass the flag straight through
    // so `disk_assembly` sees the contradiction and rejects it by name; the only
    // thing that turns the journal off is the operator's own `--no-journal`.
    var request = testCaptureRequest(null);

    request.root_filesystem = .xfs;
    request.journal = true;
    try std.testing.expect(ext4JournalSetting(request).enabled);

    request.journal = false;
    try std.testing.expect(!ext4JournalSetting(request).enabled);

    // And nothing about an ext4 root changes: the flag is still whatever was
    // asked for, never synthesized.
    request.root_filesystem = .ext4;
    request.journal = true;
    try std.testing.expect(ext4JournalSetting(request).enabled);
}
