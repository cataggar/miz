//! `zvmi capture`: rebuild an installed system into a fresh, right-sized
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
const zvmi = @import("zvmi");
const opts = @import("opts.zig");

const help_text =
    \\usage: zvmi capture --source <device|image> [--source-root <spec>]
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
    \\  --label <name>           ext4 volume label for the new root.
    \\  --root-selinux-label <context>
    \\                           SELinux context for the new root directory.
    \\  --no-journal             Omit the ext4 journal. On by default here,
    \\                           unlike elsewhere in zvmi, because a captured
    \\                           system boots into a mutable root filesystem.
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
        error.SourceRootRequired => "no partition of --source holds an ext4 filesystem, so name the root explicitly with --source-root (e.g. --source-root gpt:2, or --source-root lvm:<vg>/<lv> for a root inside LVM)",
        error.AmbiguousSourceRoot => "--source holds more than one ext4 filesystem with an /etc, so which one is the root has to be said with --source-root (e.g. --source-root gpt:2). The others can be merged in with --source-mount <spec>=<path>",
        error.NoRootLikeFilesystem => "--source holds an ext4 filesystem, but none with an /etc, so none of them looks like a root -- a separate /boot on a machine whose root is xfs or btrfs looks exactly like this. Name the root with --source-root, and merge the rest in with --source-mount <spec>=<path>",
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

fn hostArchitecture() zvmi.bootconfig.Architecture {
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
    image: *zvmi.Image,
    offset: u64,
    length: u64,
    /// The entry this came from, when it was resolved through `--source`'s
    /// partition table. Its GUID and name are the PARTUUID and PARTLABEL the
    /// captured system may be referring to itself by, and they are retired
    /// along with the filesystem UUID.
    partition: ?zvmi.gpt.PartitionEntry = null,
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
    var selinux_label: ?[]const u8 = null;
    var journal = true;
    var rewrite_identities = true;
    var dry_run = false;

    var output_path: ?[]const u8 = null;
    var spec: ?zvmi.output.Spec = null;
    var level: ?zvmi.output.Level = null;
    var import_limits = zvmi.limits.ImportLimits{};

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
            root_size = zvmi.parseSize(args[i]) catch
                return fail("capture: invalid --root-size '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--esp-size")) {
            i += 1;
            if (i >= args.len) return fail("capture: --esp-size requires a size", .{});
            esp_size = zvmi.parseSize(args[i]) catch
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
            spec = zvmi.output.Spec.parseName(args[i]) orelse
                return fail("capture: unknown format '{s}'", .{args[i]});
        } else if (std.mem.eql(u8, arg, "--compress-level")) {
            i += 1;
            if (i >= args.len) return fail("capture: --compress-level requires 1-9", .{});
            level = zvmi.output.parseLevel(args[i]) catch
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
            break :blk zvmi.output.Spec{ .format = .raw };
        break :blk zvmi.output.Spec.inferFromPath(destination_text) orelse
            return fail("capture: cannot tell the output format from '{s}'; pass -O", .{destination_text});
    };
    const destination: zvmi.output.Destination =
        if (std.mem.eql(u8, destination_text, "-")) .stdout else .{ .path = destination_text };

    zvmi.output.validate(output_spec, destination, level) catch |err|
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
    zvmi.root_tree.validateMountTargets(targets.items) catch |err|
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
    selinux_label: ?[]const u8,
    journal: bool,
    rewrite_identities: bool,
    dry_run: bool,
    spec: zvmi.output.Spec,
    destination: zvmi.output.Destination,
    level: ?zvmi.output.Level,
    limits: zvmi.limits.ImportLimits,
};

fn capture(gpa: std.mem.Allocator, io: std.Io, request: CaptureRequest) u8 {
    var disk = zvmi.Image.openPathReadOnly(io, request.source_path) catch |err|
        return failOpen(request.source_path, err);
    defer disk.close(io);

    // The partition table is read once and shared: every `gpt:<n>` spec, the
    // ESP search and the PARTUUID of the source root all come out of it.
    const table: ?zvmi.gpt.ParsedGpt = zvmi.gpt.readGpt(disk, io, gpa) catch null;
    defer if (table) |parsed| gpa.free(parsed.partitions);

    var scratch = std.array_list.Managed(*zvmi.Image).init(gpa);
    defer {
        for (scratch.items) |opened| {
            opened.close(io);
            gpa.destroy(opened);
        }
        scratch.deinit();
    }

    const root_source = resolveRoot(gpa, io, &disk, table, request, &scratch) catch |err|
        return failWithHint("capture: cannot read the root filesystem", err);

    var diagnostic = zvmi.limits.Diagnostic{};

    var root_reader = openSourceExt4(gpa, io, root_source) catch |err|
        return failWithHint("capture: the root source is not an ext4 filesystem", err);
    defer root_reader.deinit();

    // A root named by path rather than as a partition of --source carries no
    // PARTUUID this can retire, so a `PARTUUID=`-rooted fstab would come
    // through naming a disk that no longer exists -- and, since nothing was
    // retired, the verification pass would have nothing to match and would
    // report a clean rewrite. Silence is the failure mode worth avoiding.
    if (request.rewrite_identities and root_source.partition == null) {
        warnUnretirablePartitionReference(gpa, io, root_reader);
    }

    var root_scan = zvmi.ext4.scanReadable(&root_reader, io, gpa, scanOptions(request.limits, root_source.length, &diagnostic)) catch |err|
        return failLimits("capture: reading the root filesystem failed", err, &diagnostic);
    defer root_scan.deinit();

    const spool_path = stagingPath(gpa, request.destination, ".spool") catch
        return fail("capture: out of memory", .{});
    defer gpa.free(spool_path);
    defer std.Io.Dir.cwd().deleteFile(io, spool_path) catch {};

    var tree = zvmi.root_tree.RootTree.init(gpa, io, spool_path, request.limits.tree()) catch |err|
        return fail("capture: cannot create the staging spool '{s}': {s}", .{ spool_path, @errorName(err) });
    defer tree.deinit();
    tree.diagnostic = &diagnostic;

    tree.importExt4General(&root_scan) catch |err|
        return failLimits("capture: importing the root filesystem failed", err, &diagnostic);

    var sources = std.array_list.Managed(zvmi.disk_assembly.SourceFilesystem).init(gpa);
    defer sources.deinit();
    var identifier_storage = std.array_list.Managed([]u8).init(gpa);
    defer {
        for (identifier_storage.items) |owned| gpa.free(owned);
        identifier_storage.deinit();
    }

    const root_uuid = ownedUuid(gpa, &identifier_storage, &root_scan.identity.uuid) catch
        return fail("capture: out of memory", .{});
    const root_label = ownedLabel(gpa, &identifier_storage, &root_scan.identity.label) catch
        return fail("capture: out of memory", .{});
    var root_before = zvmi.identity_rewrite.Identifiers{ .filesystem_uuid = root_uuid, .filesystem_label = root_label };
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

        var reader = openSourceExt4(gpa, io, opened) catch |err|
            return failWithHint("capture: a --source-mount filesystem is not ext4", err);
        defer reader.deinit();

        var scan = zvmi.ext4.scanReadable(&reader, io, gpa, scanOptions(request.limits, opened.length, &diagnostic)) catch |err|
            return failLimits("capture: reading a --source-mount filesystem failed", err, &diagnostic);
        defer scan.deinit();

        _ = tree.mountExt4General(&scan, mount.target) catch |err|
            return failWithHint("capture: mounting a --source-mount filesystem failed", err);

        const uuid = ownedUuid(gpa, &identifier_storage, &scan.identity.uuid) catch
            return fail("capture: out of memory", .{});
        const mount_label = ownedLabel(gpa, &identifier_storage, &scan.identity.label) catch
            return fail("capture: out of memory", .{});
        var mount_before = zvmi.identity_rewrite.Identifiers{ .filesystem_uuid = uuid, .filesystem_label = mount_label };
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
    var esp_tree: ?zvmi.root_tree.RootTree = null;
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

            var fs = zvmi.fat32.open(opened.image, io, .{
                .offset = opened.offset,
                .length = opened.length,
            }) catch |err| return failWithHint("capture: the EFI system partition is not readable", err);

            var scan = zvmi.fat32.scanTree(&fs, io, gpa, .{
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
            var built = zvmi.root_tree.RootTree.init(gpa, io, esp_spool.?, request.limits.tree()) catch |err|
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
            var esp_before = zvmi.identity_rewrite.Identifiers{ .filesystem_uuid = serial, .filesystem_label = esp_label };
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

    const report = zvmi.disk_assembly.assemble(gpa, io, &tree, .{
        .raw_path = raw_path,
        .architecture = switch (request.architecture) {
            .auto => hostArchitecture(),
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .esp_tree = if (esp_tree) |*value| value else null,
        .esp_size = if (request.esp_size) |size| .{ .exact = size } else .{ .minimum_plus = zvmi.disk_assembly.default_esp_slack },
        .root_size = if (request.root_size) |size| .{ .exact = size } else .{ .minimum_plus = zvmi.disk_assembly.default_root_slack },
        .ext4_label = request.label,
        // On by default here and nowhere else in zvmi: this image becomes a
        // machine's live, mutable root filesystem, and an unclean shutdown
        // without a journal has nothing to replay.
        .ext4_journal = .{ .enabled = request.journal },
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

    var staged = zvmi.Image.openPathReadOnly(io, raw_path) catch |err|
        return fail("capture: cannot re-open the staged image: {s}", .{@errorName(err)});
    defer staged.close(io);

    if (converts_container) {
        convertStaged(gpa, io, staged, request, report.virtual_size) catch |err|
            return fail("capture: writing {s} output failed: {s}", .{ request.spec.displayName(), @errorName(err) });
        return 0;
    }

    zvmi.output.writeImageTo(gpa, io, staged, request.destination, .{
        .compression = request.spec.compression,
        .level = request.level orelse zvmi.output.default_level,
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
    staged: zvmi.Image,
    request: CaptureRequest,
    virtual_size: u64,
) !void {
    var options = zvmi.CreateOptions{};
    // Fixed, as `build-image` does: a captured image's reason to be a VHD at
    // all is almost always an Azure managed-disk upload, which refuses
    // dynamic.
    if (request.spec.format == .vhd) options.vhd_subformat = .fixed;

    // Exclusively, as the raw path already creates its output, so that a
    // capture cannot overwrite a file it was not asked to. It also makes the
    // cleanup below safe: what fails to be created is never deleted, so a
    // pre-existing destination -- or a device node `Image.create` refused --
    // survives the failure that named it.
    var destination = try zvmi.Image.createExclusive(io, request.destination.path, request.spec.format, virtual_size, options);
    // A half-written container is worse than none: it opens, reports a
    // plausible size, and fails somewhere the operator will not look.
    errdefer std.Io.Dir.cwd().deleteFile(io, request.destination.path) catch {};
    defer destination.close(io);
    try zvmi.copyAll(io, staged, &destination, gpa);
}

/// Reads through the image's guest-visible address space rather than the host
/// file. A qcow2 or VHDX source maps guest offsets to entirely different file
/// offsets, so an ext4 opened against the raw file would read the wrong bytes
/// -- or, for a sparse container smaller than the offset, none at all.
fn imageReadAt(ctx: *const anyopaque, io: std.Io, buffer: []u8, offset: u64) anyerror!usize {
    const image: *const zvmi.Image = @ptrCast(@alignCast(ctx));
    return image.pread(io, buffer, offset);
}

fn openSourceExt4(
    gpa: std.mem.Allocator,
    io: std.Io,
    opened: OpenedSource,
) zvmi.ext4.GeneralOpenError!zvmi.ext4.Reader {
    return zvmi.ext4.openGeneralReadOnlySource(
        io,
        opened.image.file,
        .{ .ctx = opened.image, .read_at_fn = imageReadAt },
        gpa,
        .{ .offset = opened.offset },
    );
}

fn scanOptions(
    limits: zvmi.limits.ImportLimits,
    available_length: u64,
    diagnostic: *zvmi.limits.Diagnostic,
) zvmi.ext4.GeneralScanOptions {
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
    disk: *zvmi.Image,
    table: ?zvmi.gpt.ParsedGpt,
    request: CaptureRequest,
    scratch: *std.array_list.Managed(*zvmi.Image),
) !OpenedSource {
    if (request.root_spec_text) |text| {
        const spec = try parseSourceSpec(text);
        return resolveSpec(gpa, io, disk, table, spec, scratch);
    }
    // With no --source-root, the root is whichever partition holds an ext4
    // filesystem -- provided exactly one does. That is a fact read off the
    // disk rather than a guess, and it covers the ordinary single-root
    // install. Ambiguity is refused, never resolved: "the biggest one" would
    // be right often enough to be trusted and wrong often enough to matter.
    const parsed = table orelse
        return .{ .image = disk, .offset = 0, .length = disk.virtual_size };

    var found: ?OpenedSource = null;
    var saw_ext4 = false;
    for (parsed.partitions) |entry| {
        if (entry.isEmpty()) continue;
        // An ESP is FAT and would never probe as ext4, but skipping it by
        // type keeps the candidate set to partitions that could be a root.
        if (std.mem.eql(u8, &entry.partition_type_guid, &zvmi.guid.esp)) continue;
        const candidate = OpenedSource{
            .image = disk,
            .offset = entry.first_lba * zvmi.gpt.sector_size,
            .length = (entry.last_lba - entry.first_lba + 1) * zvmi.gpt.sector_size,
            .partition = entry,
        };
        var probe = openSourceExt4(gpa, io, candidate) catch |err| switch (err) {
            // Not an ext4 filesystem, or not one this can read: both mean
            // "not a candidate". Anything else -- an unreadable disk, an
            // exhausted allocator -- is a real failure, and reporting it as
            // "no partition holds an ext4 filesystem" would be a false
            // statement about the disk rather than a diagnosis.
            error.BadMagic,
            error.UnsupportedFilesystemFeature,
            error.UnsupportedBlockSize,
            error.UnexpectedEndOfFile,
            => continue,
            else => return err,
        };
        defer probe.deinit();
        saw_ext4 = true;

        // Holding an ext4 filesystem is not being the root. A separate /boot
        // is ext4 on plenty of systems whose root is xfs or btrfs, and
        // capturing it would produce a plausible image of the wrong thing.
        // Every root has /etc; no /boot, /var or /home does.
        const etc = probe.statPath(io, "/etc") catch continue;
        if (etc.kind != .directory) continue;

        if (found != null) return error.AmbiguousSourceRoot;
        found = candidate;
    }
    if (found) |value| return value;
    return if (saw_ext4) error.NoRootLikeFilesystem else error.SourceRootRequired;
}

fn resolveSpec(
    gpa: std.mem.Allocator,
    io: std.Io,
    disk: *zvmi.Image,
    table: ?zvmi.gpt.ParsedGpt,
    spec: SourceSpec,
    scratch: *std.array_list.Managed(*zvmi.Image),
) !OpenedSource {
    switch (spec) {
        .path => |path| {
            const owned = try gpa.create(zvmi.Image);
            errdefer gpa.destroy(owned);
            owned.* = try zvmi.Image.openPathReadOnly(io, path);
            errdefer owned.close(io);
            try scratch.append(owned);
            return .{ .image = owned, .offset = 0, .length = owned.virtual_size };
        },
        .gpt_index => |index| {
            const parsed = table orelse return error.SourceHasNoPartitionTable;
            const entry = findPartition(parsed, index) orelse return error.PartitionNotFound;
            return .{
                .image = disk,
                .offset = entry.first_lba * zvmi.gpt.sector_size,
                .length = (entry.last_lba - entry.first_lba + 1) * zvmi.gpt.sector_size,
                .partition = entry,
            };
        },
        .logical_volume => |selector| {
            var scan = try zvmi.lvm.scan(gpa, disk.*, io);
            defer scan.deinit();
            const selected = try scan.findLogicalVolume(selector.group, selector.name);
            const extent = try zvmi.lvm.contiguousRange(selected.group, selected.volume);
            return .{ .image = disk, .offset = extent.offset, .length = extent.length };
        },
    }
}

fn findPartition(parsed: zvmi.gpt.ParsedGpt, index: u32) ?zvmi.gpt.PartitionEntry {
    for (parsed.partitions) |entry| {
        if (entry.table_index + 1 == index) return entry;
    }
    return null;
}

/// The ESP is named explicitly, or found by its type GUID. The type GUID is
/// definitional rather than a heuristic: a partition carrying it *is* an EFI
/// system partition, which is exactly how firmware finds one.
fn findEspSpec(table: ?zvmi.gpt.ParsedGpt, request: CaptureRequest) !?SourceSpec {
    // A malformed --source-esp is a failure, not an absent ESP. Swallowing it
    // would assemble a root-only disk and exit 0, which is a typo turning
    // into an unbootable image with nothing said.
    if (request.esp_spec_text) |text| return try parseSourceSpec(text);
    const parsed = table orelse return null;
    for (parsed.partitions) |entry| {
        if (std.mem.eql(u8, &entry.partition_type_guid, &zvmi.guid.esp)) {
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
    const buffer = try gpa.alloc(u8, zvmi.identity_rewrite.canonical_uuid_bytes);
    errdefer gpa.free(buffer);
    const text = zvmi.identity_rewrite.formatFilesystemUuid(buffer[0..zvmi.identity_rewrite.canonical_uuid_bytes], bytes);
    try storage.append(buffer);
    return text;
}

fn ownedLabel(
    gpa: std.mem.Allocator,
    storage: *std.array_list.Managed([]u8),
    field: []const u8,
) !?[]const u8 {
    const trimmed = zvmi.identity_rewrite.trimLabel(field) orelse return null;
    const copy = try gpa.dupe(u8, trimmed);
    errdefer gpa.free(copy);
    try storage.append(copy);
    return copy;
}

/// Warns when the captured fstab names the source by an identifier this
/// capture cannot replace. Best effort by design: an unreadable or absent
/// fstab is not itself a problem, and this only ever adds a warning.
fn warnUnretirablePartitionReference(gpa: std.mem.Allocator, io: std.Io, reader: zvmi.ext4.Reader) void {
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
    entry: ?zvmi.gpt.PartitionEntry,
    before: *zvmi.identity_rewrite.Identifiers,
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
    before.partition_uuid = zvmi.guid.formatLower(buffer[0..36], value.unique_partition_guid);

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
    const buffer = try gpa.alloc(u8, zvmi.identity_rewrite.fat_serial_bytes);
    errdefer gpa.free(buffer);
    const text = zvmi.identity_rewrite.formatFatVolumeSerial(buffer[0..zvmi.identity_rewrite.fat_serial_bytes], volume_id);
    try storage.append(buffer);
    return text;
}

/// A staging path beside the destination, so the staged image lands on the
/// same filesystem the output will and a capture that fills a disk does so
/// where the operator chose rather than in /tmp.
fn stagingPath(
    gpa: std.mem.Allocator,
    destination: zvmi.output.Destination,
    suffix: []const u8,
) ![]u8 {
    return switch (destination) {
        .path => |path| std.fmt.allocPrint(gpa, "{s}.zvmi-capture{s}", .{ path, suffix }),
        .stdout => std.fmt.allocPrint(gpa, "zvmi-capture{s}", .{suffix}),
    };
}

/// Plans the same disk with the sizes left to default, so a rejected
/// `--root-size` or `--esp-size` can be answered with the figure it missed.
fn reportMinimums(
    gpa: std.mem.Allocator,
    io: std.Io,
    tree: *zvmi.root_tree.RootTree,
    esp_tree: ?*zvmi.root_tree.RootTree,
    request: CaptureRequest,
) void {
    const planned = zvmi.disk_assembly.assemble(gpa, io, tree, .{
        // Never opened: a dry run stops after planning. It still has to name
        // something, because an empty path is refused as a mistake.
        .raw_path = "zvmi-capture-dry-run",
        .architecture = switch (request.architecture) {
            .auto => hostArchitecture(),
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .esp_tree = esp_tree,
        .ext4_journal = .{ .enabled = request.journal },
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

fn reportSizes(request: CaptureRequest, report: ?zvmi.disk_assembly.Report) void {
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
fn reportIdentity(which: []const u8, report: zvmi.identity_rewrite.Report) void {
    if (report.retired_identifiers == 0) return;
    std.debug.print(
        "capture: {s} identity rewrite: {d} fstab entries rewritten, {d} dropped, {d} references in {d} config files\n",
        .{
            which,
            report.fstab_entries_rewritten,
            report.fstab_entries_dropped,
            report.config_references_rewritten,
            report.config_files_rewritten,
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
    diagnostic: *const zvmi.limits.Diagnostic,
) u8 {
    if (diagnostic.exceeded) |breach| {
        if (breach.limit.err() == err) {
            var message: [zvmi.limits.Exceeded.max_message_bytes]u8 = undefined;
            var remediation: [zvmi.limits.Exceeded.max_remediation_bytes]u8 = undefined;
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
