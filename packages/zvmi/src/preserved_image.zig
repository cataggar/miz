//! Transactional mutation/rebuild of an existing disk through a full raw
//! staging copy. `edit` changes only existing paths; `rebuild` strictly
//! imports the narrow writer-compatible ext4 profile before applying pure OS
//! customization. `inspectRebuild` performs the same source preflight without
//! creating any files. Sources are always read-only.

const std = @import("std");
const boot_options = @import("boot_options.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const Format = @import("formats.zig").Format;
const free_space = @import("free_space.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const identity_rewrite = @import("identity_rewrite.zig");
const limits_mod = @import("limits.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const mbr = @import("mbr.zig");
const os_customization = @import("os_customization.zig");
const output_mod = @import("output.zig");
const lvm = @import("lvm.zig");
const root_tree = @import("root_tree.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

/// `edit` enforces only the replacement-file limit, but it is the same limit,
/// with the same flag, that a rebuild enforces.
const limit_defaults = limits_mod.ImportLimits{};

/// Names a logical volume inside an LVM2 volume group on the disk, for the
/// installs that put the root filesystem there instead of straight into a
/// partition. Read-only: the volume is located and its bytes are used, and
/// nothing ever writes LVM metadata.
pub const LogicalVolumeSelector = struct {
    /// Empty names the disk's only volume group. Naming one becomes
    /// required as soon as the disk carries more than one, because picking
    /// between them by position would be a guess.
    volume_group: []const u8 = "",
    logical_volume: []const u8,
};

pub const PartitionSelector = union(enum) {
    /// One-based slot in the GPT partition entry array.
    gpt_index: u32,
    /// One-based slot in the four-entry MBR partition table.
    mbr_index: u8,
    /// A logical volume, wherever on the disk the volume group put it.
    logical_volume: LogicalVolumeSelector,
};

pub const FileSource = union(enum) {
    bytes: []const u8,
    host_path: []const u8,
};

pub const Operation = union(enum) {
    overwrite_file: struct {
        path: []const u8,
        source: FileSource,
    },
    remove_file: []const u8,
    remove_tree: []const u8,
};

pub const Options = struct {
    source_path: []const u8,
    output_path: []const u8,
    output_format: Format,
    root_partition: PartitionSelector,
    operations: []const Operation,
    expected_virtual_size: ?u64 = null,
    /// Kernel command-line options appended to every boot entry the image
    /// already carries, applied to the raw stage after every filesystem
    /// change. Empty leaves the boot configuration exactly as the source
    /// wrote it.
    kernel_options: []const u8 = "",
    /// Sink for the boot configuration file that stopped a kernel-option
    /// change, so the caller can name it rather than report only an error.
    kernel_options_diagnostic: ?*boot_options.Diagnostic = null,
    max_source_file_bytes: u64 = limit_defaults.max_source_file_bytes,
    /// Optional sink for the first limit breach, so a caller can name the
    /// flag that raises it instead of only reporting an error value.
    limit_diagnostic: ?*limits_mod.Diagnostic = null,
    output_create_options: image_mod.CreateOptions = .{},
    /// Compresses the published artifact as it is written. Only `.raw`
    /// output can be compressed: every other format amends metadata after
    /// the data it already wrote, which a compressor cannot revisit.
    output_compression: output_mod.Compression = .none,
};

pub const Report = struct {
    source_format: Format,
    output_format: Format,
    virtual_size: u64,
    partition_offset: u64,
    partition_length: u64,
    flattened_backing_chain: bool,
    operation_count: usize,
    /// Present exactly when `kernel_options` asked for a change.
    kernel_options: ?boot_options.Report,
};

pub const PartitionGeometry = struct {
    offset: u64,
    length: u64,
};

pub const RawMutationTarget = struct {
    raw_path: []const u8,
    virtual_size: u64,
    stage_inode: Io.File.INode,
    partition: PartitionGeometry,
};

pub const RawMutationHook = struct {
    context: ?*anyopaque = null,
    runFn: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        target: RawMutationTarget,
    ) anyerror!void,

    fn run(
        self: RawMutationHook,
        allocator: Allocator,
        io: Io,
        target: RawMutationTarget,
    ) !void {
        try self.runFn(self.context, allocator, io, target);
    }
};

pub const RawMutationOptions = struct {
    source_path: []const u8,
    output_path: []const u8,
    output_format: Format,
    root_partition: PartitionSelector,
    expected_source_format: ?Format = null,
    expected_virtual_size: ?u64 = null,
    require_linux_partition: bool = false,
    /// Kernel command-line options appended to every boot entry the image
    /// already carries, applied to the raw stage after every filesystem
    /// change. Empty leaves the boot configuration exactly as the source
    /// wrote it.
    kernel_options: []const u8 = "",
    /// Sink for the boot configuration file that stopped a kernel-option
    /// change, so the caller can name it rather than report only an error.
    kernel_options_diagnostic: ?*boot_options.Diagnostic = null,
    dependency_paths: []const []const u8 = &.{},
    output_create_options: image_mod.CreateOptions = .{},
    /// Compresses the published artifact as it is written. Only `.raw`
    /// output can be compressed: every other format amends metadata after
    /// the data it already wrote, which a compressor cannot revisit.
    output_compression: output_mod.Compression = .none,
};

pub const RawMutationReport = struct {
    source_format: Format,
    output_format: Format,
    virtual_size: u64,
    partition_offset: u64,
    partition_length: u64,
    flattened_backing_chain: bool,
    /// Present exactly when `kernel_options` asked for a change.
    kernel_options: ?boot_options.Report,
};

/// Options for a rootless, full-tree rebuild of the deliberately narrow
/// `zvmi_ext4_v1` source profile. `source_date_epoch` controls pure OS
/// customization data; the ext4 inode/superblock timestamp is validated and
/// preserved from the source.
pub const RebuildOptions = struct {
    source_path: []const u8,
    output_path: []const u8,
    expected_source_format: ?Format = null,
    output_format: Format,
    root_partition: PartitionSelector,
    existing_operations: []const Operation = &.{},
    customization: os_customization.OsCustomization = .{},
    generalization: os_customization.GeneralizationPolicy = .none,
    source_date_epoch: u64,
    /// Which ext4 sources the import will accept. `.strict` is the default
    /// because it is the only one that underwrites the byte-for-byte rebuild
    /// contract; `.general` exists because no filesystem a distro installer
    /// produced can ever satisfy it.
    source_profile: SourceProfilePolicy = .strict,
    /// Whether the rebuilt root filesystem carries a JBD2 journal. Off by
    /// default, so a rebuild keeps producing what it always has -- including
    /// the strict profile's byte-for-byte contract, which HAS_JOURNAL is not
    /// part of. Turn it on when the rebuilt image boots into a mutable root
    /// filesystem: an installed system that loses power without a journal
    /// faces a full fsck rather than a replay. Note that a journalled source
    /// is rebuilt journal-less unless this says otherwise; `PreflightReport`
    /// reports the source's own journal so the change is visible.
    journal: ext4.JournalOptions = .{},
    /// Additional filesystems merged into the root tree, in order, each at
    /// its own mount point. An installed system is normally spread across an
    /// ESP, a `/boot` filesystem and a root filesystem; listing the first two
    /// here collapses them into plain directories inside the one rebuilt root
    /// filesystem. Merging happens before the writer runs, so hardlinks,
    /// extended attributes, permissions and device nodes survive it.
    ///
    /// A mount replaces whatever the sources before it had at its target
    /// rather than merging into it, exactly as a real mount hides the
    /// directory underneath. See `root_tree.RootTree.mountExt4General`.
    source_mounts: []const SourceMount = &.{},
    /// Whether the imported `/etc/fstab` and bootloader configuration are
    /// reconciled with the identifiers the rebuilt image actually has, and
    /// whether a surviving stale identifier fails the build. Merging a
    /// `/boot` filesystem or an ESP into the root retires the identifiers
    /// that named them, and an image whose configuration still names them
    /// does not boot; see `identity_rewrite`.
    identity_rewrite: identity_rewrite.Policy = .rewrite_and_verify,
    /// Optional sink for the first surviving stale identifier. Reports are
    /// returned by value, so a rebuild that fails on one can only hand back
    /// the offending path through a sink the caller still owns.
    identity_diagnostic: ?*identity_rewrite.Diagnostic = null,
    /// Every limit the import enforces, each raisable by its own flag.
    limits: limits_mod.ImportLimits = .{},
    /// Optional sink for the peak measurements and the first limit breach.
    /// Reports are returned by value, so a failed rebuild can only hand back
    /// the breach through a sink the caller still owns.
    limit_diagnostic: ?*limits_mod.Diagnostic = null,
    /// Whether the up-front workspace free-space check may reject a rebuild.
    /// It is a precondition rather than a discovery halfway through a long
    /// import, and `.report_only` exists for callers whose workspace grows on
    /// demand (a network filesystem, a thin pool) where the probe is wrong.
    workspace_space: WorkspaceSpacePolicy = .enforce,
    expected_virtual_size: ?u64 = null,
    output_create_options: image_mod.CreateOptions = .{},
    /// Kernel command-line options appended to every boot entry the rebuilt
    /// image carries, applied to the raw stage after the filesystem is
    /// populated. Empty leaves the boot configuration as the source wrote it.
    kernel_options: []const u8 = "",
    /// Sink for the boot configuration file that stopped a kernel-option
    /// change, so the caller can name it rather than report only an error.
    kernel_options_diagnostic: ?*boot_options.Diagnostic = null,
    /// Compresses the published artifact as it is written. Only `.raw`
    /// output can be compressed: every other format amends metadata after
    /// the data it already wrote, which a compressor cannot revisit.
    output_compression: output_mod.Compression = .none,
};

pub const WorkspaceSpacePolicy = enum {
    enforce,
    report_only,
};

pub const SourceProfilePolicy = enum {
    /// Only the exact feature and layout subset this project's ext4 writer
    /// emits. A rebuild from it is reproducible byte for byte.
    strict,
    /// Any ext4 filesystem the general reader accepts, which covers a stock
    /// distro root filesystem. Metadata is preserved in full, but the source
    /// was not written by this project, so the output cannot be claimed to be
    /// a reproducible function of it.
    general,

    pub fn scanned(self: SourceProfilePolicy) ext4.SourceProfile {
        return switch (self) {
            .strict => .zvmi_ext4_v1,
            .general => .ext4_general_v1,
        };
    }
};

/// Which reader a merged source is handed to. `.detect` is the default only
/// because an operator naming a partition rarely knows or cares; it probes
/// the on-disk magic and refuses anything it cannot name, so it never guesses.
pub const SourceFilesystem = enum {
    detect,
    ext4,
    fat32,
};

/// One filesystem merged into the rebuilt root at a mount point.
pub const SourceMount = struct {
    /// Image file or block-device node holding the filesystem. Empty means
    /// the rebuild's own `source_path`, which is the common case: one disk,
    /// several partitions of it.
    source_path: []const u8 = "",
    partition: PartitionSelector,
    /// Where the filesystem lands in the rebuilt root: absolute, normalized,
    /// and already an existing directory in the sources before it.
    target: []const u8,
    filesystem: SourceFilesystem = .detect,
    /// POSIX metadata synthesized for entries read from a FAT source. vfat
    /// stores no owner, no permission bits, no symlinks and no extended
    /// attributes, so something has to be invented; inventing it silently
    /// would bake an unstated policy into every image, so it is a documented
    /// default (0755 directories, 0644 files, uid=gid=0) that a caller can
    /// override. Ignored for an ext4 source, which carries its own.
    fat_metadata: fat32.SynthesizedMetadata = .{},
};

/// What a rebuild needs from the filesystem holding the output directory, and
/// what that filesystem had when the rebuild started. `available_bytes` is
/// null when the host cannot be asked; that is never treated as too little.
pub const WorkspaceSpace = struct {
    /// A full copy of every imported file byte. The spool is the reason a
    /// ~35 GB source needs ~35 GB of scratch space.
    spool_bytes: u64,
    /// The raw staging image, which is the source's full virtual size.
    stage_bytes: u64,
    /// The converted or compressed artifact, which coexists with the stage
    /// until it is published. Zero when the raw stage is itself published.
    publish_bytes: u64,
    required_bytes: u64,
    available_bytes: ?u64,

    /// An unknown amount of free space is not the same as too little: a host
    /// that cannot answer the probe must not be refused a rebuild it can in
    /// fact complete.
    pub fn isSufficient(self: WorkspaceSpace) bool {
        const available = self.available_bytes orelse return true;
        return available >= self.required_bytes;
    }
};

pub const RebuildReport = struct {
    source_format: Format,
    output_format: Format,
    virtual_size: u64,
    partition_offset: u64,
    partition_length: u64,
    flattened_backing_chain: bool,
    /// Which importer accepted the source. Named rather than implied, because
    /// only `zvmi_ext4_v1` makes the output a reproducible function of the
    /// input; see `source_reproducible`.
    source_profile: ext4.SourceProfile,
    /// False for a general import. The source's own layout, allocation order
    /// and journal state are not reproduced, so rebuilding the same source
    /// twice is stable but rebuilding it from a re-created source is not.
    /// Also false whenever anything was merged in: the output is then a
    /// function of several sources, not of the one this report names.
    source_reproducible: bool,
    ext4_uuid: [16]u8,
    /// Exact preserved ext4 volume-name field.
    ext4_label: [16]u8,
    ext4_block_size: u32,
    filesystem_length: u64,
    ext4_global_timestamp: u32,
    /// Whether the *source* filesystem carried a journal. Stated because a
    /// journal-less rebuild of a journalled source is a real change of
    /// behaviour, and `RebuildOptions.journal` is what decides it.
    source_has_journal: bool,
    /// Blocks the rebuilt filesystem's own journal occupies, or 0.
    journal_block_count: u32,
    source_manifest_sha256: [32]u8,
    final_manifest_sha256: [32]u8,
    /// RootTree node counts exclude its implicit root directory.
    imported_node_count: usize,
    /// Filesystems merged in at a mount point, excluding the root source.
    merged_source_count: usize,
    /// Nodes the mount points hid, summed over every merge. Stated rather
    /// than left to be diffed for, because a stale `/boot` stub silently
    /// surviving a merge is the failure this feature exists to prevent.
    shadowed_node_count: usize,
    final_node_count: usize,
    existing_operation_count: usize,
    os_customization_count: usize,
    generalization_count: usize,
    /// What the identity reconciliation changed, and what it could not.
    identity_rewrite: identity_rewrite.Report,
    /// Present exactly when `kernel_options` asked for a change.
    kernel_options: ?boot_options.Report,
    /// The largest value each limit reached. A caller sizes the next run's
    /// flags from these instead of guessing.
    limit_peaks: limits_mod.Peaks,
    workspace_space: WorkspaceSpace,
};

/// Plain, allocation-independent result of `inspectRebuild`. Inspection
/// validates the complete source/profile contract without creating files.
pub const RebuildInspection = struct {
    source_format: Format,
    virtual_size: u64,
    partition_offset: u64,
    partition_length: u64,
    flattened_backing_chain: bool,
    source_profile: ext4.SourceProfile,
    source_reproducible: bool,
    ext4_uuid: [16]u8,
    ext4_label: [16]u8,
    ext4_block_size: u32,
    filesystem_length: u64,
    ext4_global_timestamp: u32,
    /// Whether the source filesystem carried a journal; see the same field on
    /// `RebuildReport`.
    source_has_journal: bool,
    /// Blocks the rebuilt filesystem's own journal would occupy, or 0.
    journal_block_count: u32,
    /// Excludes the implicit root directory.
    imported_node_count: usize,
    /// Filesystems merged in at a mount point, excluding the root source.
    merged_source_count: usize,
    /// Nodes the mount points hid, summed over every merge.
    shadowed_node_count: usize,
    /// What the identity reconciliation would change, and what it could not.
    /// Inspection runs the same rewrite and the same verification pass over a
    /// throwaway tree, so a source whose configuration cannot be reconciled
    /// is refused before any file is created rather than after a full import.
    identity_rewrite: identity_rewrite.Report,
    /// The largest value each limit reached during the inspection, which
    /// covers the same limits a rebuild enforces. Sizing flags from a dry run
    /// is the point of inspecting.
    limit_peaks: limits_mod.Peaks,
    /// Inspection reports the scratch-space cost but never rejects a source
    /// for it: it creates no files, so it consumes none of that space, and
    /// the caller may free space before committing to the rebuild.
    workspace_space: WorkspaceSpace,
};

const Partition = struct {
    offset: u64,
    length: u64,
};

/// Flattens a preserved source into an exclusive raw stage, closes every
/// source/stage handle, invokes `hook`, and publishes only after the hook
/// returns. The hook must release every loop, mount, and child-process
/// reference to `target.raw_path` before returning.
pub fn transactRaw(
    allocator: Allocator,
    io: Io,
    options: RawMutationOptions,
    hook: RawMutationHook,
) !RawMutationReport {
    return transactRawInternal(allocator, io, options, hook, "raw-mutation");
}

pub fn edit(
    allocator: Allocator,
    io: Io,
    options: Options,
) !Report {
    try validateOperations(options.operations);

    var dependency_paths = try std.array_list.Managed([]const u8).initCapacity(
        allocator,
        options.operations.len,
    );
    defer dependency_paths.deinit();
    for (options.operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| switch (overwrite.source) {
            .host_path => |path| try dependency_paths.append(path),
            .bytes => {},
        },
        .remove_file, .remove_tree => {},
    };
    var context = EditMutationContext{
        .operations = options.operations,
        .max_source_file_bytes = options.max_source_file_bytes,
        .limit_diagnostic = options.limit_diagnostic,
    };
    const mutation = try transactRawInternal(
        allocator,
        io,
        .{
            .source_path = options.source_path,
            .output_path = options.output_path,
            .output_format = options.output_format,
            .root_partition = options.root_partition,
            .expected_virtual_size = options.expected_virtual_size,
            .kernel_options = options.kernel_options,
            .kernel_options_diagnostic = options.kernel_options_diagnostic,
            .dependency_paths = dependency_paths.items,
            .output_create_options = options.output_create_options,
            .output_compression = options.output_compression,
        },
        .{ .context = &context, .runFn = runEditMutation },
        "native-edit",
    );

    return .{
        .source_format = mutation.source_format,
        .output_format = mutation.output_format,
        .virtual_size = mutation.virtual_size,
        .partition_offset = mutation.partition_offset,
        .partition_length = mutation.partition_length,
        .flattened_backing_chain = mutation.flattened_backing_chain,
        .operation_count = options.operations.len,
        .kernel_options = mutation.kernel_options,
    };
}

const EditMutationContext = struct {
    operations: []const Operation,
    max_source_file_bytes: u64,
    limit_diagnostic: ?*limits_mod.Diagnostic,
};

fn runEditMutation(
    context_ptr: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    target: RawMutationTarget,
) !void {
    const context: *EditMutationContext = @ptrCast(@alignCast(context_ptr.?));
    var raw = try openRawStage(
        io,
        target.raw_path,
        target.virtual_size,
        target.stage_inode,
        true,
    );
    defer raw.close(io);
    var editor = try ext4.Editor.open(
        io,
        raw.file,
        allocator,
        .{ .offset = target.partition.offset },
    );
    var editor_open = true;
    defer if (editor_open) editor.deinit();
    const filesystem_bytes = std.math.mul(
        u64,
        editor.reader.total_blocks,
        editor.reader.block_size,
    ) catch return error.InvalidFilesystemBounds;
    const filesystem_end = std.math.add(
        u64,
        target.partition.offset,
        filesystem_bytes,
    ) catch return error.InvalidFilesystemBounds;
    const partition_end = std.math.add(
        u64,
        target.partition.offset,
        target.partition.length,
    ) catch return error.InvalidFilesystemBounds;
    if (filesystem_end > partition_end) return error.InvalidFilesystemBounds;

    try preflightOperations(
        allocator,
        io,
        &editor,
        context.operations,
        context.max_source_file_bytes,
        context.limit_diagnostic,
    );
    for (context.operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| {
            const content = try loadSource(
                allocator,
                io,
                overwrite.source,
                context.max_source_file_bytes,
                context.limit_diagnostic,
            );
            defer allocator.free(content);
            try editor.writeFile(io, overwrite.path, content);
        },
        .remove_file => |path| try editor.deleteFile(io, path),
        .remove_tree => |path| try editor.deleteTree(io, path),
    };
    try editor.close(io);
    editor_open = false;
}

/// A read-only view of the root filesystem a preserved-image run would mutate,
/// opened from the source image without copying or staging anything.
///
/// Exists so a preflight can answer questions whose answer lives inside the
/// image -- whether the target carries the tool an operation needs, what its
/// own configuration says -- before a workspace is created. Refusing after the
/// source has been copied costs the whole copy and leaves a transaction to
/// clean up; refusing from here costs a few reads.
///
/// Initialised in place rather than returned by value: the ext4 reader is
/// handed a pointer to the image beside it, so the pair may not move once
/// opened. This mirrors `MountedSource`, which is a field for the same reason.
pub const SourceRoot = struct {
    image: Image = undefined,
    image_open: bool = false,
    reader: ext4.Reader = undefined,
    reader_open: bool = false,

    pub fn open(
        self: *SourceRoot,
        allocator: Allocator,
        io: Io,
        source_path: []const u8,
        root_partition: PartitionSelector,
    ) !void {
        self.* = .{};
        errdefer self.close(io);
        if (source_path.len == 0) return error.InvalidPath;
        self.image = try Image.openPathReadOnly(io, source_path);
        self.image_open = true;
        // The read-only shape rather than the rebuild one: this view only
        // reads, so a root that is not a Linux-typed MBR partition is still a
        // root it can answer questions about.
        const partition = try selectPartition(allocator, io, self.image, root_partition);
        const end = std.math.add(u64, partition.offset, partition.length) catch
            return error.InvalidPartitionBounds;
        if (partition.length == 0 or end > self.image.virtual_size) {
            return error.InvalidPartitionBounds;
        }
        self.reader = try ext4.openReadOnlySource(
            io,
            self.image.file,
            .{ .ctx = &self.image, .read_at_fn = imageReadAt },
            allocator,
            .{ .offset = partition.offset },
        );
        self.reader_open = true;
    }

    pub fn close(self: *SourceRoot, io: Io) void {
        if (self.reader_open) {
            self.reader.deinit();
            self.reader_open = false;
        }
        if (self.image_open) {
            self.image.close(io);
            self.image_open = false;
        }
    }

    /// Whether `path` resolves to something inside the root. A question rather
    /// than a result because every reason it could fail -- absent, unreadable,
    /// a dangling symlink -- means the same thing to a caller deciding whether
    /// an operation can run.
    pub fn exists(self: *SourceRoot, io: Io, path: []const u8) bool {
        _ = self.reader.statPath(io, path) catch return false;
        return true;
    }

    pub fn readFileAlloc(
        self: *SourceRoot,
        io: Io,
        allocator: Allocator,
        path: []const u8,
    ) ![]u8 {
        return self.reader.readFileAlloc(io, allocator, path);
    }
};

/// Performs the complete rebuild source preflight using read-only handles.
/// No output, staging, spool, workspace, or other file is created.
pub fn inspectRebuild(
    allocator: Allocator,
    io: Io,
    options: RebuildOptions,
) !RebuildInspection {
    if (options.source_path.len == 0 or options.output_path.len == 0) return error.InvalidPath;
    const source_path = try std.fs.path.resolve(allocator, &.{options.source_path});
    defer allocator.free(source_path);
    const output_path = try std.fs.path.resolve(allocator, &.{options.output_path});
    defer allocator.free(output_path);
    if (std.mem.eql(u8, source_path, output_path)) return error.SourceOutputConflict;
    try validateOperations(options.existing_operations);

    var source = try Image.openPathReadOnly(io, source_path);
    defer source.close(io);
    if (options.expected_source_format) |expected| {
        if (source.format != expected) return error.SourceFormatMismatch;
    }
    if (options.expected_virtual_size) |expected| {
        if (expected != source.virtual_size) return error.VirtualSizeMismatch;
    }
    const partition = try selectRebuildPartition(allocator, io, source, options.root_partition);
    const partition_end = std.math.add(u64, partition.offset, partition.length) catch
        return error.InvalidPartitionBounds;
    if (partition.length == 0 or partition_end > source.virtual_size) {
        return error.InvalidPartitionBounds;
    }

    var reader = try ext4.openReadOnlySource(
        io,
        source.file,
        .{ .ctx = &source, .read_at_fn = imageReadAt },
        allocator,
        .{ .offset = partition.offset },
    );
    defer reader.deinit();
    var budget = CombinedBudget{
        .limits = options.limits,
        .sink = options.limit_diagnostic,
    };
    var sources = try SourceSet.open(
        allocator,
        io,
        &reader,
        options,
        source_path,
        partition.length,
        &budget,
    );
    defer sources.deinit(io);
    const scanned = &sources.root;
    // Only the assembled tree says which paths exist once anything is merged
    // in: the root source's view still shows what a mount hides and still
    // lacks everything a mount brings. `preflightTreeOperations` below checks
    // the operations there instead, against the tree the rebuild will write.
    if (options.source_mounts.len == 0) {
        try preflightScannedOperations(scanned.fileTreeView(), options.existing_operations);
    }

    try preflightReadOnlyDependencies(
        io,
        options.existing_operations,
        options.customization,
        options.limits.max_source_file_bytes,
        options.limit_diagnostic,
    );

    const raw_path = try std.fmt.allocPrint(allocator, "{s}.native-rebuild.raw", .{output_path});
    defer allocator.free(raw_path);
    const output_stage_path = try std.fmt.allocPrint(
        allocator,
        "{s}.native-rebuild.output",
        .{output_path},
    );
    defer allocator.free(output_stage_path);
    const spool_path = try std.fmt.allocPrint(
        allocator,
        "{s}.native-rebuild.spool",
        .{output_path},
    );
    defer allocator.free(spool_path);
    try validateRebuildArtifactPaths(
        allocator,
        source,
        source_path,
        output_path,
        raw_path,
        output_stage_path,
        spool_path,
        options.existing_operations,
        options.customization,
        options.source_mounts,
    );
    var validation_tree = root_tree.RootTree.initMemory(allocator, io, options.limits.tree());
    validation_tree.diagnostic = options.limit_diagnostic;
    defer validation_tree.deinit();
    try sources.importBorrowedInto(&validation_tree);
    const imported_node_count = validation_tree.nodeCount();
    try preflightTreeOperations(&validation_tree, options.existing_operations);
    try applyTreeOperations(
        io,
        &validation_tree,
        options.existing_operations,
        options.limits.max_source_file_bytes,
        options.limit_diagnostic,
    );
    try os_customization.apply(
        allocator,
        &validation_tree,
        options.customization,
        options.source_date_epoch,
    );
    try os_customization.generalize(
        allocator,
        &validation_tree,
        options.generalization,
    );
    var identity_plan = try buildIdentityPlan(allocator, io, options, source, &sources);
    defer identity_plan.deinit();
    const identity_report = try identity_rewrite.apply(
        allocator,
        &validation_tree,
        identity_plan.plan,
        options.identity_rewrite,
        options.identity_diagnostic,
    );
    const scanned_label = scanned.label();
    const scanned_timestamp = scanned.globalTimestamp(options.source_date_epoch);
    const preflight = try ext4.preflightPopulate(
        allocator,
        try validation_tree.ext4View(),
        populateOptions(&validation_tree, partition.offset, scanned, &scanned_label, scanned_timestamp, options.journal),
    );

    return .{
        .source_format = source.format,
        .virtual_size = source.virtual_size,
        .partition_offset = partition.offset,
        .partition_length = partition.length,
        .flattened_backing_chain = if (source.qcow2) |info| info.backing_depth != 0 else false,
        .source_profile = scanned.profile(),
        .source_reproducible = scanned.profile().isByteReproducible() and
            options.source_mounts.len == 0,
        .ext4_uuid = scanned.uuid(),
        .ext4_label = scanned_label,
        .ext4_block_size = scanned.blockSize(),
        .filesystem_length = scanned.filesystemLength(),
        .ext4_global_timestamp = scanned_timestamp,
        .source_has_journal = scanned.hasJournal(),
        .journal_block_count = preflight.journal_block_count,
        .imported_node_count = imported_node_count,
        .merged_source_count = sources.mounts.len,
        .shadowed_node_count = sources.shadowed_nodes,
        .identity_rewrite = identity_report,
        .limit_peaks = if (options.limit_diagnostic) |sink| sink.peaks else .{},
        .workspace_space = workspaceSpace(
            output_path,
            sources.contentBytes(),
            source.virtual_size,
            options.output_format,
            options.output_compression,
        ),
    };
}

/// Strictly imports, customizes, and rebuilds a writer-compatible ext4 tree.
/// Source validation (including the complete allocated inode/block graph)
/// finishes before any spool, raw staging, conversion staging, or output file
/// is created.
pub fn rebuild(
    allocator: Allocator,
    io: Io,
    options: RebuildOptions,
) !RebuildReport {
    if (options.source_path.len == 0 or options.output_path.len == 0) return error.InvalidPath;
    const source_path = try std.fs.path.resolve(allocator, &.{options.source_path});
    defer allocator.free(source_path);
    const output_path = try std.fs.path.resolve(allocator, &.{options.output_path});
    defer allocator.free(output_path);
    if (std.mem.eql(u8, source_path, output_path)) return error.SourceOutputConflict;
    try validateOperations(options.existing_operations);

    var source = try Image.openPathReadOnly(io, source_path);
    var source_open = true;
    defer if (source_open) source.close(io);
    if (options.expected_source_format) |expected| {
        if (source.format != expected) return error.SourceFormatMismatch;
    }
    if (options.expected_virtual_size) |expected| {
        if (expected != source.virtual_size) return error.VirtualSizeMismatch;
    }
    const virtual_size = source.virtual_size;
    const source_format = source.format;
    const flattened = if (source.qcow2) |info| info.backing_depth != 0 else false;
    const partition = try selectRebuildPartition(allocator, io, source, options.root_partition);
    const partition_end = std.math.add(u64, partition.offset, partition.length) catch
        return error.InvalidPartitionBounds;
    if (partition.length == 0 or partition_end > virtual_size) {
        return error.InvalidPartitionBounds;
    }

    var reader = try ext4.openReadOnlySource(
        io,
        source.file,
        .{ .ctx = &source, .read_at_fn = imageReadAt },
        allocator,
        .{ .offset = partition.offset },
    );
    defer reader.deinit();
    var budget = CombinedBudget{
        .limits = options.limits,
        .sink = options.limit_diagnostic,
    };
    var sources = try SourceSet.open(
        allocator,
        io,
        &reader,
        options,
        source_path,
        partition.length,
        &budget,
    );
    defer sources.deinit(io);
    const scanned = &sources.root;
    const scanned_label = scanned.label();
    const scanned_timestamp = scanned.globalTimestamp(options.source_date_epoch);

    try preflightReadOnlyDependencies(
        io,
        options.existing_operations,
        options.customization,
        options.limits.max_source_file_bytes,
        options.limit_diagnostic,
    );

    const raw_path = try std.fmt.allocPrint(allocator, "{s}.native-rebuild.raw", .{output_path});
    defer allocator.free(raw_path);
    const output_stage_path = try std.fmt.allocPrint(
        allocator,
        "{s}.native-rebuild.output",
        .{output_path},
    );
    defer allocator.free(output_stage_path);
    const spool_path = try std.fmt.allocPrint(
        allocator,
        "{s}.native-rebuild.spool",
        .{output_path},
    );
    defer allocator.free(spool_path);
    try validateRebuildArtifactPaths(
        allocator,
        source,
        source_path,
        output_path,
        raw_path,
        output_stage_path,
        spool_path,
        options.existing_operations,
        options.customization,
        options.source_mounts,
    );

    // The workspace precondition runs before the spool file exists, so a
    // workspace that cannot hold the import fails now rather than after
    // however long it takes to copy most of a root filesystem into it.
    const workspace = workspaceSpace(
        output_path,
        sources.contentBytes(),
        virtual_size,
        options.output_format,
        options.output_compression,
    );
    if (options.workspace_space == .enforce and !workspace.isSufficient()) {
        return error.InsufficientWorkspaceSpace;
    }

    var tree = try root_tree.RootTree.init(allocator, io, spool_path, options.limits.tree());
    tree.diagnostic = options.limit_diagnostic;
    defer tree.deinit();
    try sources.importInto(&tree);
    const imported_node_count = tree.nodeCount();
    const source_manifest = try tree.manifestDigest();

    try preflightTreeOperations(&tree, options.existing_operations);
    try applyTreeOperations(
        io,
        &tree,
        options.existing_operations,
        options.limits.max_source_file_bytes,
        options.limit_diagnostic,
    );
    try os_customization.apply(
        allocator,
        &tree,
        options.customization,
        options.source_date_epoch,
    );
    try os_customization.generalize(allocator, &tree, options.generalization);

    var identity_plan = try buildIdentityPlan(allocator, io, options, source, &sources);
    defer identity_plan.deinit();
    // Last of the tree passes on purpose: the verification pass has to have
    // the final say on what the image contains, so a customization that
    // reintroduced a retired identifier is caught rather than run after the
    // check that would have caught it. Still ahead of every output file, so
    // a stale identifier costs a rejection and not a published unbootable
    // image.
    const identity_report = try identity_rewrite.apply(
        allocator,
        &tree,
        identity_plan.plan,
        options.identity_rewrite,
        options.identity_diagnostic,
    );

    const final_manifest = try tree.manifestDigest();
    const final_node_count = tree.nodeCount();
    const final_view = try tree.ext4View();

    var raw_exists = false;
    defer if (raw_exists) removeStagingPath(io, raw_path);
    var output_stage_exists = false;
    defer if (output_stage_exists) Io.Dir.cwd().deleteFile(io, output_stage_path) catch {};

    var raw = try Image.createExclusive(io, raw_path, .raw, virtual_size, .{});
    raw_exists = true;
    var raw_open = true;
    defer if (raw_open) raw.close(io);
    try image_mod.copyAll(io, source, &raw, allocator);
    source.close(io);
    source_open = false;

    try zeroFileRange(io, raw.file, partition.offset, partition.length);
    const populated = try ext4.populate(
        io,
        raw.file,
        allocator,
        final_view,
        populateOptions(&tree, partition.offset, scanned, &scanned_label, scanned_timestamp, options.journal),
    );
    // After `populate`, because the rebuilt root filesystem is what the boot
    // entries name, and before the stage is published, because a stage that
    // failed the change must never become an image.
    const kernel_options_report: ?boot_options.Report = if (options.kernel_options.len != 0)
        try boot_options.apply(
            allocator,
            io,
            &raw,
            options.kernel_options,
            options.kernel_options_diagnostic,
        )
    else
        null;

    const raw_inode = (try raw.file.stat(io)).inode;
    raw.close(io);
    raw_open = false;

    publishRawStaging(
        allocator,
        io,
        raw_path,
        output_stage_path,
        output_path,
        options.output_format,
        options.output_compression,
        virtual_size,
        options.output_create_options,
        raw_inode,
        &raw_exists,
        &output_stage_exists,
    ) catch |err| {
        try removeStagingPathChecked(io, raw_path);
        raw_exists = false;
        return err;
    };

    return .{
        .source_format = source_format,
        .output_format = options.output_format,
        .virtual_size = virtual_size,
        .partition_offset = partition.offset,
        .partition_length = partition.length,
        .flattened_backing_chain = flattened,
        .source_profile = scanned.profile(),
        .source_reproducible = scanned.profile().isByteReproducible() and
            options.source_mounts.len == 0,
        .ext4_uuid = scanned.uuid(),
        .ext4_label = scanned_label,
        .ext4_block_size = scanned.blockSize(),
        .filesystem_length = scanned.filesystemLength(),
        .ext4_global_timestamp = scanned_timestamp,
        .source_has_journal = scanned.hasJournal(),
        .journal_block_count = populated.journal_block_count,
        .source_manifest_sha256 = source_manifest,
        .final_manifest_sha256 = final_manifest,
        .imported_node_count = imported_node_count,
        .merged_source_count = sources.mounts.len,
        .shadowed_node_count = sources.shadowed_nodes,
        .final_node_count = final_node_count,
        .existing_operation_count = options.existing_operations.len,
        .os_customization_count = customizationCount(options.customization),
        .generalization_count = generalizationCount(options.generalization),
        .identity_rewrite = identity_report,
        .kernel_options = kernel_options_report,
        .limit_peaks = if (options.limit_diagnostic) |sink| sink.peaks else .{},
        .workspace_space = workspace,
    };
}

fn transactRawInternal(
    allocator: Allocator,
    io: Io,
    options: RawMutationOptions,
    hook: RawMutationHook,
    staging_label: []const u8,
) !RawMutationReport {
    if (options.source_path.len == 0 or options.output_path.len == 0) {
        return error.InvalidPath;
    }
    const source_path = try std.fs.path.resolve(allocator, &.{options.source_path});
    defer allocator.free(source_path);
    const output_path = try std.fs.path.resolve(allocator, &.{options.output_path});
    defer allocator.free(output_path);
    if (std.mem.eql(u8, source_path, output_path)) return error.SourceOutputConflict;

    var source = try Image.openPathReadOnly(io, source_path);
    var source_open = true;
    defer if (source_open) source.close(io);
    if (options.expected_source_format) |expected| {
        if (source.format != expected) return error.SourceFormatMismatch;
    }
    if (options.expected_virtual_size) |expected| {
        if (source.virtual_size != expected) return error.VirtualSizeMismatch;
    }
    const virtual_size = source.virtual_size;
    const source_format = source.format;
    const flattened = if (source.qcow2) |info| info.backing_depth != 0 else false;
    const partition = if (options.require_linux_partition)
        try selectRebuildPartition(allocator, io, source, options.root_partition)
    else
        try selectPartition(allocator, io, source, options.root_partition);
    const partition_end = std.math.add(
        u64,
        partition.offset,
        partition.length,
    ) catch return error.InvalidPartitionBounds;
    if (partition.length == 0 or partition_end > virtual_size) {
        return error.InvalidPartitionBounds;
    }

    const raw_path = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}.raw",
        .{ output_path, staging_label },
    );
    defer allocator.free(raw_path);
    const output_stage_path = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}.output",
        .{ output_path, staging_label },
    );
    defer allocator.free(output_stage_path);
    try validateRawArtifactPaths(
        allocator,
        source,
        source_path,
        output_path,
        raw_path,
        output_stage_path,
        options.dependency_paths,
    );

    var raw_exists = false;
    defer if (raw_exists) Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    var output_stage_exists = false;
    defer if (output_stage_exists) Io.Dir.cwd().deleteFile(io, output_stage_path) catch {};

    var raw = try Image.createExclusive(io, raw_path, .raw, virtual_size, .{});
    raw_exists = true;
    var raw_open = true;
    defer if (raw_open) raw.close(io);
    try image_mod.copyAll(io, source, &raw, allocator);
    source.close(io);
    source_open = false;
    const raw_inode = (try raw.file.stat(io)).inode;
    raw.close(io);
    raw_open = false;

    hook.run(allocator, io, .{
        .raw_path = raw_path,
        .virtual_size = virtual_size,
        .stage_inode = raw_inode,
        .partition = .{
            .offset = partition.offset,
            .length = partition.length,
        },
    }) catch |err| {
        if (err == error.MutationResourcesActive) {
            raw_exists = false;
            return err;
        }
        try removeStagingPathChecked(io, raw_path);
        raw_exists = false;
        return err;
    };
    // After the hook, because the mutation it just ran is allowed to replace
    // the boot configuration, and the declared options have to survive
    // whatever it wrote.
    var kernel_options_report: ?boot_options.Report = null;
    if (options.kernel_options.len != 0) {
        kernel_options_report = applyKernelOptions(
            allocator,
            io,
            raw_path,
            virtual_size,
            raw_inode,
            options.kernel_options,
            options.kernel_options_diagnostic,
        ) catch |err| {
            try removeStagingPathChecked(io, raw_path);
            raw_exists = false;
            return err;
        };
    }

    publishRawStaging(
        allocator,
        io,
        raw_path,
        output_stage_path,
        output_path,
        options.output_format,
        options.output_compression,
        virtual_size,
        options.output_create_options,
        raw_inode,
        &raw_exists,
        &output_stage_exists,
    ) catch |err| {
        try removeStagingPathChecked(io, raw_path);
        raw_exists = false;
        return err;
    };

    return .{
        .source_format = source_format,
        .output_format = options.output_format,
        .virtual_size = virtual_size,
        .partition_offset = partition.offset,
        .partition_length = partition.length,
        .flattened_backing_chain = flattened,
        .kernel_options = kernel_options_report,
    };
}

/// Reopens the finished raw stage to append the declared kernel options.
///
/// Reopened rather than kept open across the mutation because the hook owns
/// the stage while it runs, and a second writable handle to a file a chroot
/// or a guest may be writing is exactly the aliasing `openRawStage` checks
/// for.
fn applyKernelOptions(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    virtual_size: u64,
    raw_inode: Io.File.INode,
    options: []const u8,
    diagnostic: ?*boot_options.Diagnostic,
) !boot_options.Report {
    var raw = try openRawStage(io, raw_path, virtual_size, raw_inode, true);
    defer raw.close(io);
    return boot_options.apply(allocator, io, &raw, options, diagnostic);
}

/// Scratch space a rebuild needs on the filesystem holding the output.
///
/// The spool holds a full copy of every imported file byte, the raw stage
/// holds the source's full virtual size, and a converted or compressed
/// artifact coexists with that stage until it is published. A raw,
/// uncompressed output is published by renaming the stage, so it costs
/// nothing beyond it.
fn workspaceSpace(
    output_path: []const u8,
    content_bytes: u64,
    virtual_size: u64,
    output_format: Format,
    output_compression: output_mod.Compression,
) WorkspaceSpace {
    // The output directory is the filesystem every scratch file lands on,
    // because each one is named after the output path.
    const probe_path = std.fs.path.dirname(output_path) orelse ".";
    return workspaceRequirement(
        content_bytes,
        virtual_size,
        output_format,
        output_compression,
        free_space.availableBytes(probe_path),
    );
}

fn workspaceRequirement(
    content_bytes: u64,
    virtual_size: u64,
    output_format: Format,
    output_compression: output_mod.Compression,
    available_bytes: ?u64,
) WorkspaceSpace {
    const publishes_stage_in_place = output_format == .raw and output_compression == .none;
    const publish_bytes: u64 = if (publishes_stage_in_place) 0 else virtual_size;
    const required = std.math.add(u64, content_bytes, virtual_size) catch
        std.math.maxInt(u64);
    const total = std.math.add(u64, required, publish_bytes) catch std.math.maxInt(u64);
    return .{
        .spool_bytes = content_bytes,
        .stage_bytes = virtual_size,
        .publish_bytes = publish_bytes,
        .required_bytes = total,
        .available_bytes = available_bytes,
    };
}

/// The root directory has no entry in the tree view, so its own metadata has
/// to travel beside the view rather than through it.
fn populateOptions(
    tree: *root_tree.RootTree,
    offset: u64,
    scanned: *const ScannedSource,
    label: *const [16]u8,
    timestamp: u32,
    journal: ext4.JournalOptions,
) ext4.PopulateOptions {
    const root = tree.rootMetadata();
    return .{
        .offset = offset,
        .length = scanned.filesystemLength(),
        .block_size = scanned.blockSize(),
        .label = label,
        .uuid = scanned.uuid(),
        .timestamp = timestamp,
        .journal = journal,
        .root_mode = root.mode,
        .root_uid = root.uid,
        .root_gid = root.gid,
        .root_atime = root.atime,
        .root_mtime = root.mtime,
        .root_ctime = root.ctime,
        .root_atime_nsec = root.atime_nsec,
        .root_mtime_nsec = root.mtime_nsec,
        .root_ctime_nsec = root.ctime_nsec,
        .root_crtime = root.crtime,
        .root_crtime_nsec = root.crtime_nsec,
    };
}

fn generalScanOptions(
    options: RebuildOptions,
    partition_length: u64,
    caps: ScanCaps,
) ext4.GeneralScanOptions {
    return .{
        .available_length = partition_length,
        .max_nodes = caps.max_nodes,
        .max_path_bytes = options.limits.max_path_bytes,
        .max_component_bytes = options.limits.max_component_bytes,
        .max_file_bytes = options.limits.max_file_bytes,
        .max_total_bytes = caps.max_total_bytes,
        .max_xattrs_per_node = options.limits.max_xattrs_per_node,
        .max_xattr_bytes_per_node = options.limits.max_xattr_bytes_per_node,
        .max_scan_metadata_bytes = options.limits.max_scan_metadata_bytes,
        .diagnostic = caps.diagnostic,
    };
}

fn fatScanOptions(
    options: RebuildOptions,
    mount: SourceMount,
    caps: ScanCaps,
) fat32.ScanOptions {
    return .{
        .metadata = mount.fat_metadata,
        .max_nodes = caps.max_nodes,
        .max_path_bytes = options.limits.max_path_bytes,
        .max_component_bytes = options.limits.max_component_bytes,
        .max_file_bytes = options.limits.max_file_bytes,
        .max_total_bytes = caps.max_total_bytes,
        .max_scan_metadata_bytes = options.limits.max_scan_metadata_bytes,
        .diagnostic = caps.diagnostic,
    };
}
/// One handle over both importers, so the rebuild pipeline downstream of the
/// scan does not have to be written twice and cannot drift between profiles.
const ScannedSource = union(enum) {
    strict: ext4.StrictTree,
    general: ext4.GeneralTree,

    fn scan(
        reader: *ext4.Reader,
        io: Io,
        allocator: Allocator,
        options: RebuildOptions,
        partition_length: u64,
        caps: ScanCaps,
    ) !ScannedSource {
        return switch (options.source_profile) {
            .strict => .{ .strict = try ext4.scanWriterCompatible(
                reader,
                io,
                allocator,
                strictScanOptions(options, partition_length, caps),
            ) },
            .general => .{ .general = try ext4.scanReadable(
                reader,
                io,
                allocator,
                generalScanOptions(options, partition_length, caps),
            ) },
        };
    }

    fn deinit(self: *ScannedSource) void {
        switch (self.*) {
            .strict => |*tree| tree.deinit(),
            .general => |*tree| tree.deinit(),
        }
    }

    fn profile(self: *const ScannedSource) ext4.SourceProfile {
        return switch (self.*) {
            .strict => .zvmi_ext4_v1,
            .general => .ext4_general_v1,
        };
    }

    fn uuid(self: *const ScannedSource) [16]u8 {
        return switch (self.*) {
            .strict => |tree| tree.identity.uuid,
            .general => |tree| tree.identity.uuid,
        };
    }

    fn label(self: *const ScannedSource) [16]u8 {
        return switch (self.*) {
            .strict => |tree| tree.identity.label,
            .general => |tree| tree.identity.label,
        };
    }

    /// The strict profile's feature set does not contain HAS_JOURNAL at all,
    /// so a strict source never has one to report.
    fn hasJournal(self: *const ScannedSource) bool {
        return switch (self.*) {
            .strict => false,
            .general => |tree| tree.identity.has_journal,
        };
    }

    fn blockSize(self: *const ScannedSource) u32 {
        return switch (self.*) {
            .strict => |tree| tree.identity.block_size,
            .general => |tree| tree.identity.block_size,
        };
    }

    fn filesystemLength(self: *const ScannedSource) u64 {
        return switch (self.*) {
            .strict => |tree| tree.identity.filesystem_length,
            .general => |tree| tree.identity.filesystem_length,
        };
    }

    /// A general source carries a distinct timestamp per inode, so there is
    /// no single source value to preserve; the caller's `source_date_epoch`
    /// is used instead, which is the same input every other reproducible
    /// output in this project is pinned to.
    fn globalTimestamp(self: *const ScannedSource, source_date_epoch: u64) u32 {
        return switch (self.*) {
            .strict => |tree| tree.identity.global_timestamp,
            .general => std.math.cast(u32, source_date_epoch) orelse std.math.maxInt(u32),
        };
    }

    fn nodeCount(self: *const ScannedSource) usize {
        return switch (self.*) {
            .strict => |tree| tree.nodeCount(),
            .general => |tree| tree.nodeCount(),
        };
    }

    fn contentBytes(self: *const ScannedSource) u64 {
        return switch (self.*) {
            .strict => |tree| tree.content_bytes,
            .general => |tree| tree.content_bytes,
        };
    }

    fn fileTreeView(self: *ScannedSource) *ext4.FileTreeView {
        return switch (self.*) {
            .strict => |*tree| tree.fileTreeView(),
            .general => |*tree| tree.fileTreeView(),
        };
    }

    fn importInto(self: *ScannedSource, tree: *root_tree.RootTree) !void {
        switch (self.*) {
            .strict => |*scanned| try tree.importExt4View(scanned.fileTreeView()),
            .general => |*scanned| try tree.importExt4General(scanned),
        }
    }

    fn importBorrowedInto(self: *ScannedSource, tree: *root_tree.RootTree) !void {
        switch (self.*) {
            .strict => |*scanned| try tree.importExt4ViewBorrowed(scanned.fileTreeView()),
            .general => |*scanned| try tree.importExt4GeneralBorrowed(scanned),
        }
    }
};

fn strictScanOptions(
    options: RebuildOptions,
    partition_length: u64,
    caps: ScanCaps,
) ext4.StrictScanOptions {
    return .{
        .expected_length = partition_length,
        .max_nodes = caps.max_nodes,
        .max_path_bytes = options.limits.max_path_bytes,
        .max_component_bytes = options.limits.max_component_bytes,
        .max_file_bytes = options.limits.max_file_bytes,
        .max_total_bytes = caps.max_total_bytes,
        .max_xattrs_per_node = options.limits.max_xattrs_per_node,
        .max_xattr_bytes_per_node = options.limits.max_xattr_bytes_per_node,
        .max_scan_metadata_bytes = options.limits.max_scan_metadata_bytes,
        .diagnostic = caps.diagnostic,
    };
}

/// What one scan may still spend, and the private sink it reports to. Both
/// come from `CombinedBudget`, which owns the totals across every source.
const ScanCaps = struct {
    max_nodes: usize,
    max_total_bytes: u64,
    diagnostic: *limits_mod.Diagnostic,
};

/// Limits describe an import, not any one source of it. Three filesystems
/// that each fit under `--max-nodes` and together do not still describe one
/// tree the writer has to build, so the two cumulative limits are charged
/// against a running total across every source instead of being reset for
/// each one. Everything else a scanner measures -- the longest path, the
/// largest file, the widest xattr set -- is a property of a single node, so
/// the largest value seen anywhere is already the combined peak.
///
/// Each scan is additionally capped at whatever the scans before it left, so
/// a later source cannot allocate a whole limit's worth of scan metadata on
/// top of the sources already held in memory. That remainder is an artifact
/// of sharing the budget and not a number any flag was ever set to, so a
/// scan that trips it is restated against the configured limit and the
/// combined total before the error escapes: telling an operator to raise
/// `--max-nodes` above a remainder would be advice that does not work.
const CombinedBudget = struct {
    limits: limits_mod.ImportLimits,
    sink: ?*limits_mod.Diagnostic,
    nodes: usize = 0,
    content_bytes: u64 = 0,

    fn caps(self: *const CombinedBudget, local: *limits_mod.Diagnostic) ScanCaps {
        return .{
            .max_nodes = self.limits.max_nodes -| self.nodes,
            .max_total_bytes = self.limits.max_total_bytes -| self.content_bytes,
            .diagnostic = local,
        };
    }

    /// Folds one scan's measurements into the caller's sink, offsetting the
    /// cumulative ones by what earlier sources already spent.
    fn fold(self: *CombinedBudget, local: limits_mod.Diagnostic) void {
        const sink = self.sink orelse return;
        inline for (comptime std.enums.values(limits_mod.Limit)) |limit| {
            const measured = local.peaks.value(limit);
            sink.observe(limit, switch (limit) {
                .nodes => @as(u64, self.nodes) +| measured,
                .total_bytes => self.content_bytes +| measured,
                else => measured,
            });
        }
    }

    /// Restates a breach of the reduced caps in terms of the whole import.
    fn restate(self: *CombinedBudget, breach: limits_mod.Exceeded) limits_mod.Error {
        const observed = switch (breach.limit) {
            .nodes => @as(u64, self.nodes) +| breach.observed,
            .total_bytes => self.content_bytes +| breach.observed,
            else => breach.observed,
        };
        return limits_mod.exceeded(
            self.sink,
            breach.limit,
            observed,
            self.limits.value(breach.limit),
        );
    }

    fn charge(self: *CombinedBudget, nodes: usize, content_bytes: u64) void {
        self.nodes +|= nodes;
        self.content_bytes +|= content_bytes;
    }

    /// Called on the failure path of every scan: the peaks are still worth
    /// reporting, and a limit breach has to be restated before it escapes.
    fn failed(self: *CombinedBudget, local: limits_mod.Diagnostic, err: anyerror) anyerror {
        self.fold(local);
        if (local.exceeded) |breach| return self.restate(breach);
        return err;
    }
};

/// One merged source: the image it lives on, the reader over it, and the
/// tree scanned out of it.
///
/// The image and the ext4 reader are fields rather than locals because the
/// scanned tree holds pointers straight into them, so neither may move after
/// the scan; the slice of these is allocated once at its exact final length
/// for the same reason.
const MountedSource = struct {
    target: []const u8,
    image: Image = undefined,
    image_open: bool = false,
    reader: ext4.Reader = undefined,
    reader_open: bool = false,
    filesystem: fat32.FileSystem = undefined,
    tree: ?MountedTree = null,

    const MountedTree = union(enum) {
        ext4: ScannedSource,
        fat: fat32.Tree,
    };

    fn open(
        self: *MountedSource,
        allocator: Allocator,
        io: Io,
        spec: SourceMount,
        options: RebuildOptions,
        root_source_path: []const u8,
        budget: *CombinedBudget,
    ) !void {
        const path = if (spec.source_path.len == 0) root_source_path else spec.source_path;
        if (path.len == 0) return error.InvalidPath;
        self.image = try Image.openPathReadOnly(io, path);
        self.image_open = true;

        const partition = try selectMountPartition(allocator, io, self.image, spec.partition);
        const end = std.math.add(u64, partition.offset, partition.length) catch
            return error.InvalidPartitionBounds;
        if (partition.length == 0 or end > self.image.virtual_size) {
            return error.InvalidPartitionBounds;
        }

        var local = limits_mod.Diagnostic{};
        switch (try resolveFilesystem(self.image, io, partition, spec.filesystem)) {
            .ext4 => {
                self.reader = try ext4.openReadOnlySource(
                    io,
                    self.image.file,
                    .{ .ctx = &self.image, .read_at_fn = imageReadAt },
                    allocator,
                    .{ .offset = partition.offset },
                );
                self.reader_open = true;
                // Scanned into a local and only then published. Assigning the
                // union member directly would let the result location write
                // the tag before the scan that fills the payload fails, and
                // the cleanup path would then walk a tagged tree full of
                // undefined pointers. Both trees are movable until
                // `fileTreeView` hands out a pointer to one, which happens
                // later, at mount time.
                const scanned = ScannedSource.scan(
                    &self.reader,
                    io,
                    allocator,
                    options,
                    partition.length,
                    budget.caps(&local),
                ) catch |err| return budget.failed(local, err);
                self.tree = .{ .ext4 = scanned };
            },
            .fat32 => {
                self.filesystem = try fat32.open(&self.image, io, .{
                    .offset = partition.offset,
                    .length = partition.length,
                });
                const scanned = fat32.scanTree(
                    &self.filesystem,
                    io,
                    allocator,
                    fatScanOptions(options, spec, budget.caps(&local)),
                ) catch |err| return budget.failed(local, err);
                self.tree = .{ .fat = scanned };
            },
        }
        budget.fold(local);
        budget.charge(self.nodeCount(), self.contentBytes());
    }

    fn deinit(self: *MountedSource, io: Io) void {
        if (self.tree) |*tree| switch (tree.*) {
            .ext4 => |*scanned| scanned.deinit(),
            .fat => |*scanned| scanned.deinit(),
        };
        self.tree = null;
        if (self.reader_open) {
            self.reader.deinit();
            self.reader_open = false;
        }
        if (self.image_open) {
            self.image.close(io);
            self.image_open = false;
        }
    }

    fn nodeCount(self: *const MountedSource) usize {
        const tree = self.tree orelse return 0;
        return switch (tree) {
            .ext4 => |scanned| scanned.nodeCount(),
            .fat => |scanned| scanned.nodeCount(),
        };
    }

    fn contentBytes(self: *const MountedSource) u64 {
        const tree = self.tree orelse return 0;
        return switch (tree) {
            .ext4 => |scanned| scanned.contentBytes(),
            .fat => |scanned| scanned.content_bytes,
        };
    }

    fn mountInto(
        self: *MountedSource,
        tree: *root_tree.RootTree,
        mode: enum { owned, borrowed },
    ) !root_tree.RootTree.MountReport {
        // Addressed through the field rather than through `orelse`, whose
        // result is a copy: `fileTreeView` below hands the writer a pointer
        // into the tree it is called on, and that pointer has to name the
        // tree this source owns.
        if (self.tree == null) return error.MountSourceNotScanned;
        const scanned = &self.tree.?;
        return switch (scanned.*) {
            .ext4 => |*source| switch (source.*) {
                // A strict source's root directory is whatever this project's
                // writer emits for one, which is exactly `RootMetadata`'s
                // defaults; the strict tree deliberately carries no root entry
                // to read it back from.
                .strict => |*strict| switch (mode) {
                    .owned => tree.mountExt4View(
                        strict.fileTreeView(),
                        self.target,
                        strict_root_metadata,
                    ),
                    .borrowed => tree.mountExt4ViewBorrowed(
                        strict.fileTreeView(),
                        self.target,
                        strict_root_metadata,
                    ),
                },
                .general => |*general| switch (mode) {
                    .owned => tree.mountExt4General(general, self.target),
                    .borrowed => tree.mountExt4GeneralBorrowed(general, self.target),
                },
            },
            .fat => |*fat| switch (mode) {
                .owned => tree.mountFat(fat, self.target),
                .borrowed => tree.mountFatBorrowed(fat, self.target),
            },
        };
    }
};

/// The root directory this project's ext4 writer emits, which is the root a
/// strict source was written with and therefore the one a strict mount point
/// takes on.
const strict_root_metadata: root_tree.Metadata = .{ .mode = 0o755, .uid = 0, .gid = 0 };

/// Every filesystem one rebuild reads: the root source plus each merged
/// source, opened and scanned, ready to be assembled into a single tree.
const SourceSet = struct {
    root: ScannedSource,
    mounts: []MountedSource,
    allocator: Allocator,
    /// Nodes hidden by mount points, summed over every merge. Only meaningful
    /// once `importInto` or `importBorrowedInto` has run.
    shadowed_nodes: usize = 0,

    fn open(
        allocator: Allocator,
        io: Io,
        root_reader: *ext4.Reader,
        options: RebuildOptions,
        root_source_path: []const u8,
        root_partition_length: u64,
        budget: *CombinedBudget,
    ) !SourceSet {
        // Every mount target is checked against every other before a single
        // source is opened, so a duplicate or an unreachable target costs a
        // rejection rather than a full scan of a filesystem it would discard.
        const targets = try allocator.alloc([]const u8, options.source_mounts.len);
        defer allocator.free(targets);
        for (options.source_mounts, targets) |mount, *slot| slot.* = mount.target;
        try root_tree.validateMountTargets(targets);

        var local = limits_mod.Diagnostic{};
        var root = ScannedSource.scan(
            root_reader,
            io,
            allocator,
            options,
            root_partition_length,
            budget.caps(&local),
        ) catch |err| return budget.failed(local, err);
        errdefer root.deinit();
        budget.fold(local);
        budget.charge(root.nodeCount(), root.contentBytes());

        const mounts = try allocator.alloc(MountedSource, options.source_mounts.len);
        var opened: usize = 0;
        errdefer {
            for (mounts[0..opened]) |*mount| mount.deinit(io);
            allocator.free(mounts);
        }
        for (options.source_mounts, mounts) |spec, *mount| {
            mount.* = .{ .target = spec.target };
            opened += 1;
            try mount.open(allocator, io, spec, options, root_source_path, budget);
        }

        return .{ .root = root, .mounts = mounts, .allocator = allocator };
    }

    fn deinit(self: *SourceSet, io: Io) void {
        for (self.mounts) |*mount| mount.deinit(io);
        self.allocator.free(self.mounts);
        self.root.deinit();
        self.* = undefined;
    }

    /// Sum over every source, which is what the spool has to hold and what
    /// the workspace check has to be sized against.
    fn contentBytes(self: *const SourceSet) u64 {
        var total = self.root.contentBytes();
        for (self.mounts) |mount| total +|= mount.contentBytes();
        return total;
    }

    fn importInto(self: *SourceSet, tree: *root_tree.RootTree) !void {
        try self.assemble(tree, .owned);
    }

    fn importBorrowedInto(self: *SourceSet, tree: *root_tree.RootTree) !void {
        try self.assemble(tree, .borrowed);
    }

    fn assemble(
        self: *SourceSet,
        tree: *root_tree.RootTree,
        mode: enum { owned, borrowed },
    ) !void {
        switch (mode) {
            .owned => try self.root.importInto(tree),
            .borrowed => try self.root.importBorrowedInto(tree),
        }
        // The root import lands one node per scanned entry and nothing else;
        // a mismatch here means the importer collided two source paths into
        // one, which would silently drop a file.
        if (tree.nodeCount() != self.root.nodeCount()) return error.ImportedNodeCountMismatch;
        self.shadowed_nodes = 0;
        for (self.mounts) |*mount| {
            const report = try mount.mountInto(tree, switch (mode) {
                .owned => .owned,
                .borrowed => .borrowed,
            });
            self.shadowed_nodes +|= report.shadowed_nodes;
        }
    }
};

/// Which identifiers the rebuild retired, derived from what the rebuild
/// actually did rather than from a caller's description of it.
///
/// `rebuild` copies the source disk verbatim and then repopulates only the
/// root partition, so the partition table and the root filesystem's own UUID
/// survive untouched; on their own they retire nothing. Everything retired
/// here comes from a merge, where a filesystem stops being a filesystem and
/// every reference that named it has to name the root instead.
///
/// The strings are arena-owned because they are built while the sources are
/// open and consumed much later, after the tree has been assembled and
/// customized, and threading a dozen individual frees through the failure
/// paths in between buys nothing.
const IdentityPlan = struct {
    arena: std.heap.ArenaAllocator,
    plan: identity_rewrite.Plan,

    fn deinit(self: *IdentityPlan) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

fn buildIdentityPlan(
    allocator: Allocator,
    io: Io,
    options: RebuildOptions,
    root_image: Image,
    sources: *SourceSet,
) !IdentityPlan {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const scratch = arena.allocator();

    var uuid_text: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    const root_label = sources.root.label();
    const root_uuid = sources.root.uuid();
    const root_identifiers = identity_rewrite.Identifiers{
        .filesystem_uuid = try dupeFilesystemUuid(scratch, &root_uuid),
        .filesystem_label = try dupeLabel(scratch, &root_label),
        .partition_uuid = try dupeOptional(scratch, try partitionUuidText(
            allocator,
            io,
            root_image,
            options.root_partition,
            &uuid_text,
        )),
    };

    const filesystems = try scratch.alloc(identity_rewrite.Filesystem, sources.mounts.len + 1);
    // The root is listed even though it retires nothing: it is what every
    // merged filesystem's references have to be pointed at, and stating it
    // once here keeps `after` from being assembled at each use site.
    filesystems[0] = .{ .before = root_identifiers, .after = root_identifiers };

    var esp_roots = try std.array_list.Managed([]const u8).initCapacity(
        scratch,
        sources.mounts.len,
    );
    for (sources.mounts, options.source_mounts, filesystems[1..]) |*mount, spec, *slot| {
        if (mount.tree == null) return error.MountSourceNotScanned;
        var before = identity_rewrite.Identifiers{
            .partition_uuid = try dupeOptional(scratch, try partitionUuidText(
                allocator,
                io,
                mount.image,
                spec.partition,
                &uuid_text,
            )),
        };
        switch (mount.tree.?) {
            .ext4 => |*scanned| {
                const label = scanned.label();
                const uuid = scanned.uuid();
                before.filesystem_uuid = try dupeFilesystemUuid(scratch, &uuid);
                before.filesystem_label = try dupeLabel(scratch, &label);
            },
            .fat => |*fat| {
                before.filesystem_uuid = try dupeFatVolumeSerial(scratch, fat.volume_id);
                before.filesystem_label = try dupeLabel(scratch, &fat.label);
                // Every FAT filesystem anyone merges into a Linux root is an
                // ESP, and treating one as such only widens what the
                // verification pass reads. Guessing the other way -- looking
                // for a directory named `EFI` -- would miss an ESP whose
                // vendor directory an installer spelled differently.
                esp_roots.appendAssumeCapacity(try scratch.dupe(u8, mount.target));
            },
        }
        slot.* = .{
            .before = before,
            .after = root_identifiers,
            .merged_at = try scratch.dupe(u8, mount.target),
        };
    }

    const plan = identity_rewrite.Plan{
        .filesystems = filesystems,
        .esp_roots = try esp_roots.toOwnedSlice(),
    };
    // Validated here, while the caller can still be told which input was
    // wrong, rather than deep inside `apply` after a full import.
    try plan.validate();
    return .{ .arena = arena, .plan = plan };
}

fn dupeFilesystemUuid(allocator: Allocator, bytes: *const [16]u8) ![]const u8 {
    var buffer: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    return allocator.dupe(u8, identity_rewrite.formatFilesystemUuid(&buffer, bytes));
}

fn dupeFatVolumeSerial(allocator: Allocator, volume_id: u32) ![]const u8 {
    var buffer: [identity_rewrite.fat_serial_bytes]u8 = undefined;
    return allocator.dupe(u8, identity_rewrite.formatFatVolumeSerial(&buffer, volume_id));
}

fn dupeLabel(allocator: Allocator, field: []const u8) !?[]const u8 {
    const label = identity_rewrite.trimLabel(field) orelse return null;
    return try allocator.dupe(u8, label);
}

fn dupeOptional(allocator: Allocator, value: ?[]const u8) !?[]const u8 {
    const text = value orelse return null;
    return try allocator.dupe(u8, text);
}

/// The PARTUUID an fstab or a kernel command line would name this partition
/// by, written into `buffer`, or null when the disk carries nothing to build
/// one from. A GPT entry with a nil unique GUID and an MBR disk with a zero
/// signature are both that second case: Linux synthesizes no PARTUUID for
/// either, so returning one would invent an identifier naming nothing.
fn partitionUuidText(
    allocator: Allocator,
    io: Io,
    image: Image,
    selector: PartitionSelector,
    buffer: *[identity_rewrite.canonical_uuid_bytes]u8,
) !?[]const u8 {
    switch (selector) {
        .gpt_index => |one_based| {
            const parsed = try gpt.readGpt(image, io, allocator);
            defer allocator.free(parsed.partitions);
            for (parsed.partitions) |partition| {
                if (partition.table_index + 1 != one_based) continue;
                if (std.mem.eql(u8, &partition.unique_partition_guid, &guid.nil)) return null;
                return guid.formatLower(buffer, partition.unique_partition_guid);
            }
            return error.PartitionNotFound;
        },
        .mbr_index => |one_based| {
            var sector: [mbr.sector_size]u8 = undefined;
            if (try image.pread(io, &sector, 0) != sector.len) return error.UnexpectedEndOfFile;
            const boot_record = try mbr.Mbr.decode(&sector);
            if (boot_record.disk_signature == 0) return null;
            var partuuid: [mbr.partuuid_len]u8 = undefined;
            const text = mbr.formatPartuuid(&partuuid, boot_record.disk_signature, one_based);
            @memcpy(buffer[0..text.len], text);
            return buffer[0..text.len];
        },
        // A logical volume is not a partition and Linux gives it no
        // PARTUUID, so there is genuinely no identifier to report. Callers
        // treat null as "identify this filesystem some other way" rather
        // than inventing a name for something the kernel will not know.
        .logical_volume => return null,
    }
}

/// Names the filesystem on a merged partition, either because the caller
/// already knew or by probing the on-disk magic. Probing never falls back:
/// a partition that looks like both, or like neither, is refused so an
/// operator finds out now rather than through a surprising tree.
fn resolveFilesystem(
    image: Image,
    io: Io,
    partition: Partition,
    requested: SourceFilesystem,
) !ResolvedFilesystem {
    switch (requested) {
        .ext4 => return .ext4,
        .fat32 => return .fat32,
        .detect => {},
    }
    const looks_ext4 = try hasExt4Superblock(image, io, partition);
    const looks_fat32 = try hasFat32BootSector(image, io, partition);
    if (looks_ext4 and looks_fat32) return error.AmbiguousSourceFilesystem;
    if (looks_ext4) return .ext4;
    if (looks_fat32) return .fat32;
    return error.UnrecognizedSourceFilesystem;
}

const ResolvedFilesystem = enum { ext4, fat32 };

/// The ext2/3/4 superblock lives 1024 bytes into the filesystem and carries
/// its magic 0x38 bytes into itself.
fn hasExt4Superblock(image: Image, io: Io, partition: Partition) !bool {
    const magic_offset = 1024 + 0x38;
    if (partition.length < magic_offset + 2) return false;
    var magic: [2]u8 = undefined;
    if (try image.pread(io, &magic, partition.offset + magic_offset) != magic.len) {
        return error.UnexpectedEndOfFile;
    }
    return std.mem.readInt(u16, &magic, .little) == 0xEF53;
}

/// A FAT32 boot sector ends in the 0x55AA signature and names its type in the
/// eight bytes at offset 82. The type string alone is advisory, so both are
/// required before a partition is called vfat.
fn hasFat32BootSector(image: Image, io: Io, partition: Partition) !bool {
    if (partition.length < 512) return false;
    var boot: [512]u8 = undefined;
    if (try image.pread(io, &boot, partition.offset) != boot.len) {
        return error.UnexpectedEndOfFile;
    }
    if (boot[510] != 0x55 or boot[511] != 0xAA) return false;
    return std.mem.eql(u8, boot[82..90], "FAT32   ");
}

fn imageReadAt(
    ctx: *const anyopaque,
    io: Io,
    buffer: []u8,
    offset: u64,
) anyerror!usize {
    const image: *const Image = @ptrCast(@alignCast(ctx));
    return image.pread(io, buffer, offset);
}

fn publishRawStaging(
    allocator: Allocator,
    io: Io,
    raw_path: []const u8,
    output_stage_path: []const u8,
    output_path: []const u8,
    output_format: Format,
    output_compression: output_mod.Compression,
    virtual_size: u64,
    output_create_options: image_mod.CreateOptions,
    expected_raw_inode: Io.File.INode,
    raw_exists: *bool,
    output_stage_exists: *bool,
) !void {
    var raw_source = try openRawStage(
        io,
        raw_path,
        virtual_size,
        expected_raw_inode,
        false,
    );
    defer raw_source.close(io);
    if (output_compression != .none) {
        if (output_format != .raw) return error.CompressionRequiresRawFormat;
        try publishCompressedStage(
            allocator,
            io,
            raw_source,
            output_stage_path,
            output_path,
            output_compression,
            output_stage_exists,
        );
        return;
    }
    if (output_format == .raw) {
        try Io.Dir.cwd().renamePreserve(raw_path, Io.Dir.cwd(), output_path, io);
        raw_exists.* = false;
        return;
    }
    var output = try Image.createExclusive(
        io,
        output_stage_path,
        output_format,
        virtual_size,
        output_create_options,
    );
    output_stage_exists.* = true;
    var output_open = true;
    defer if (output_open) output.close(io);
    try image_mod.copyAll(io, raw_source, &output, allocator);
    const output_inode = (try output.file.stat(io)).inode;
    output.close(io);
    output_open = false;
    const pinned_output = try openPinnedStage(io, output_stage_path, output_inode);
    defer pinned_output.close(io);
    try Io.Dir.cwd().renamePreserve(output_stage_path, Io.Dir.cwd(), output_path, io);
    output_stage_exists.* = false;
}

/// Compresses a finished raw stage into the output stage and publishes it.
/// The compressor is single-pass, so this deliberately reuses the same
/// stage-then-rename discipline as a format conversion rather than writing
/// straight to the caller-visible path.
fn publishCompressedStage(
    allocator: Allocator,
    io: Io,
    raw_source: Image,
    output_stage_path: []const u8,
    output_path: []const u8,
    output_compression: output_mod.Compression,
    output_stage_exists: *bool,
) !void {
    const stage = try Io.Dir.cwd().createFile(io, output_stage_path, .{ .exclusive = true });
    output_stage_exists.* = true;
    var stage_open = true;
    defer if (stage_open) stage.close(io);
    var buffer: [64 * 1024]u8 = undefined;
    var stage_writer = stage.writer(io, &buffer);
    try output_mod.writeImage(allocator, io, raw_source, &stage_writer.interface, .{
        .compression = output_compression,
    });
    const stage_inode = (try stage.stat(io)).inode;
    stage.close(io);
    stage_open = false;
    const pinned_stage = try openPinnedStage(io, output_stage_path, stage_inode);
    defer pinned_stage.close(io);
    try Io.Dir.cwd().renamePreserve(output_stage_path, Io.Dir.cwd(), output_path, io);
    output_stage_exists.* = false;
}

fn openRawStage(
    io: Io,
    path: []const u8,
    expected_size: ?u64,
    expected_inode: ?Io.File.INode,
    writable: bool,
) !Image {
    const file = try Io.Dir.cwd().openFile(io, path, .{
        .mode = if (writable) .read_write else .read_only,
        .follow_symlinks = false,
    });
    errdefer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.RawStageNotRegularFile;
    if (stat.nlink != 1) return error.RawStageAliased;
    if (expected_size) |size| {
        if (stat.size != size) return error.VirtualSizeMismatch;
    }
    if (expected_inode) |inode| {
        if (stat.inode != inode) return error.RawStageReplaced;
    }
    return .{
        .file = file,
        .format = .raw,
        .data_offset = 0,
        .virtual_size = stat.size,
    };
}

fn removeStagingPath(io: Io, path: []const u8) void {
    removeStagingPathChecked(io, path) catch {};
}

fn removeStagingPathChecked(io: Io, path: []const u8) !void {
    const cwd = Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind == .directory) {
        if (std.fs.path.isAbsolute(path)) {
            try Io.Dir.deleteDirAbsolute(io, path);
        } else {
            try cwd.deleteDir(io, path);
        }
    } else {
        if (std.fs.path.isAbsolute(path)) {
            try Io.Dir.deleteFileAbsolute(io, path);
        } else {
            try cwd.deleteFile(io, path);
        }
    }
}

fn openPinnedStage(
    io: Io,
    path: []const u8,
    expected_inode: Io.File.INode,
) !Io.File {
    const file = try Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .follow_symlinks = false,
    });
    errdefer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.OutputStageNotRegularFile;
    if (stat.nlink != 1) return error.OutputStageAliased;
    if (stat.inode != expected_inode) return error.OutputStageReplaced;
    return file;
}

fn zeroFileRange(io: Io, file: Io.File, offset: u64, length: u64) !void {
    const zeroes: [64 * 1024]u8 = [_]u8{0} ** (64 * 1024);
    var written: u64 = 0;
    while (written < length) {
        const chunk: usize = @intCast(@min(@as(u64, zeroes.len), length - written));
        try file.writePositionalAll(io, zeroes[0..chunk], offset + written);
        written += chunk;
    }
}

fn preflightReadOnlyDependencies(
    io: Io,
    operations: []const Operation,
    customization: os_customization.OsCustomization,
    max_source_file_bytes: u64,
    diagnostic: ?*limits_mod.Diagnostic,
) !void {
    for (operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| switch (overwrite.source) {
            .bytes => |bytes| try checkSourceFileBytes(
                bytes.len,
                max_source_file_bytes,
                diagnostic,
            ),
            .host_path => |path| try preflightHostFile(
                io,
                path,
                max_source_file_bytes,
                diagnostic,
            ),
        },
        .remove_file, .remove_tree => {},
    };
    for (customization.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .inline_bytes => |bytes| try checkSourceFileBytes(
                bytes.len,
                max_source_file_bytes,
                diagnostic,
            ),
            .host_path => |path| try preflightHostFile(
                io,
                path,
                max_source_file_bytes,
                diagnostic,
            ),
        },
        else => {},
    };
}

/// A replacement file is loaded whole, so its size is a limit of its own
/// rather than part of the imported tree's byte total.
fn checkSourceFileBytes(
    size: u64,
    max_source_file_bytes: u64,
    diagnostic: ?*limits_mod.Diagnostic,
) limits_mod.Error!void {
    limits_mod.observe(diagnostic, .source_file_bytes, size);
    if (size > max_source_file_bytes) {
        return limits_mod.exceeded(
            diagnostic,
            .source_file_bytes,
            size,
            max_source_file_bytes,
        );
    }
}

fn preflightHostFile(
    io: Io,
    path: []const u8,
    max_bytes: u64,
    diagnostic: ?*limits_mod.Diagnostic,
) !void {
    if (path.len == 0) return error.InvalidSourcePath;
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.SourceNotRegularFile;
    try checkSourceFileBytes(stat.size, max_bytes, diagnostic);
}

fn validateRawArtifactPaths(
    allocator: Allocator,
    source: Image,
    source_path: []const u8,
    output_path: []const u8,
    raw_path: []const u8,
    output_stage_path: []const u8,
    hook_dependencies: []const []const u8,
) !void {
    const artifacts = [_][]const u8{ output_path, raw_path, output_stage_path };
    for (artifacts, 0..) |path, index| {
        if (std.mem.eql(u8, path, source_path)) return error.SourceOutputConflict;
        for (artifacts[index + 1 ..]) |other| {
            if (std.mem.eql(u8, path, other)) return error.SourceOutputConflict;
        }
    }
    const source_dependencies = try source.sourceDependencyPaths(allocator);
    defer {
        for (source_dependencies) |path| allocator.free(path);
        allocator.free(source_dependencies);
    }
    for (source_dependencies) |dependency| {
        try validateDependencyArtifactIsolation(allocator, dependency, &artifacts);
    }
    for (hook_dependencies) |dependency| {
        try validateDependencyArtifactIsolation(allocator, dependency, &artifacts);
    }
}

fn validateRebuildArtifactPaths(
    allocator: Allocator,
    source: Image,
    source_path: []const u8,
    output_path: []const u8,
    raw_path: []const u8,
    output_stage_path: []const u8,
    spool_path: []const u8,
    operations: []const Operation,
    customization: os_customization.OsCustomization,
    source_mounts: []const SourceMount,
) !void {
    const artifacts = [_][]const u8{ output_path, raw_path, output_stage_path, spool_path };
    for (artifacts, 0..) |path, index| {
        if (std.mem.eql(u8, path, source_path)) return error.SourceOutputConflict;
        for (artifacts[index + 1 ..]) |other| {
            if (std.mem.eql(u8, path, other)) return error.SourceOutputConflict;
        }
    }
    // A merged source is read for the whole rebuild, so it must not be one of
    // the files the rebuild is about to create or overwrite. An empty path
    // means the root source, which the loop above already covered.
    for (source_mounts) |mount| {
        if (mount.source_path.len == 0) continue;
        try validateDependencyArtifactIsolation(allocator, mount.source_path, &artifacts);
    }
    const dependencies = try source.sourceDependencyPaths(allocator);
    defer {
        for (dependencies) |path| allocator.free(path);
        allocator.free(dependencies);
    }
    for (dependencies) |dependency| {
        try validateDependencyArtifactIsolation(allocator, dependency, &artifacts);
    }
    for (operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| switch (overwrite.source) {
            .host_path => |path| try validateDependencyArtifactIsolation(
                allocator,
                path,
                &artifacts,
            ),
            .bytes => {},
        },
        .remove_file, .remove_tree => {},
    };
    for (customization.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .host_path => |path| try validateDependencyArtifactIsolation(
                allocator,
                path,
                &artifacts,
            ),
            .inline_bytes => {},
        },
        else => {},
    };
}

fn validateDependencyArtifactIsolation(
    allocator: Allocator,
    dependency_path: []const u8,
    artifacts: []const []const u8,
) !void {
    if (dependency_path.len == 0) return error.InvalidSourcePath;
    const resolved = try std.fs.path.resolve(allocator, &.{dependency_path});
    defer allocator.free(resolved);
    for (artifacts) |artifact| {
        if (std.mem.eql(u8, resolved, artifact)) return error.SourceOutputConflict;
    }
}

fn preflightTreeOperations(
    tree: *const root_tree.RootTree,
    operations: []const Operation,
) !void {
    for (operations) |operation| {
        const absolute_path = switch (operation) {
            .overwrite_file => |overwrite| overwrite.path,
            .remove_file => |path| path,
            .remove_tree => |path| path,
        };
        const path = absolute_path[1..];
        const node = tree.findNode(path) orelse return error.MissingExistingPath;
        switch (operation) {
            .overwrite_file => if (node.kind != .file) return error.NotRegularFile,
            .remove_file => if (node.kind == .directory) return error.IsDirectory,
            .remove_tree => if (node.kind != .directory) return error.NotDirectory,
        }
    }
}

fn preflightScannedOperations(
    view: *ext4.FileTreeView,
    operations: []const Operation,
) !void {
    for (operations) |operation| {
        const absolute_path = switch (operation) {
            .overwrite_file => |overwrite| overwrite.path,
            .remove_file => |path| path,
            .remove_tree => |path| path,
        };
        const path = absolute_path[1..];
        view.reset();
        while (try view.next()) |entry| {
            if (!std.mem.eql(u8, entry.path, path)) continue;
            switch (operation) {
                .overwrite_file => if (entry.kind != .file) return error.NotRegularFile,
                .remove_file => if (entry.kind == .directory) return error.IsDirectory,
                .remove_tree => if (entry.kind != .directory) return error.NotDirectory,
            }
            break;
        } else return error.MissingExistingPath;
    }
}

fn applyTreeOperations(
    io: Io,
    tree: *root_tree.RootTree,
    operations: []const Operation,
    max_source_file_bytes: u64,
    diagnostic: ?*limits_mod.Diagnostic,
) !void {
    for (operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| {
            const path = overwrite.path[1..];
            const node = tree.findNode(path) orelse return error.MissingExistingPath;
            if (node.kind != .file) return error.NotRegularFile;
            switch (overwrite.source) {
                .bytes => |content| {
                    try checkSourceFileBytes(content.len, max_source_file_bytes, diagnostic);
                    try tree.putFileBytes(path, content, node.metadata);
                },
                .host_path => |source_path| {
                    const source = try Io.Dir.cwd().openFile(io, source_path, .{});
                    defer source.close(io);
                    const stat = try source.stat(io);
                    if (stat.kind != .file) return error.SourceNotRegularFile;
                    try checkSourceFileBytes(stat.size, max_source_file_bytes, diagnostic);
                    try tree.putFileFromPath(path, source_path, node.metadata);
                },
            }
        },
        .remove_file => |absolute_path| {
            const path = absolute_path[1..];
            const node = tree.findNode(path) orelse return error.MissingExistingPath;
            if (node.kind == .directory) return error.IsDirectory;
            if (!try tree.remove(path)) return error.MissingExistingPath;
        },
        .remove_tree => |absolute_path| {
            const path = absolute_path[1..];
            const node = tree.findNode(path) orelse return error.MissingExistingPath;
            if (node.kind != .directory) return error.NotDirectory;
            if (!try tree.remove(path)) return error.MissingExistingPath;
        },
    };
}

fn customizationCount(customization: os_customization.OsCustomization) usize {
    return customization.filesystem.len +
        @intFromBool(customization.hostname != null) +
        customization.groups.len +
        customization.users.len +
        customization.services.len +
        customization.kernel_modules.len;
}

fn generalizationCount(policy: os_customization.GeneralizationPolicy) usize {
    return switch (policy) {
        .none => 0,
        .azure => |options| @as(usize, @intFromBool(options.reset_hostname)) +
            @intFromBool(options.clear_machine_id) +
            @intFromBool(options.remove_ssh_host_keys) +
            @intFromBool(options.remove_agent_state) +
            @intFromBool(options.remove_dhcp_leases) +
            @intFromBool(options.remove_logs) +
            @intFromBool(options.remove_caches) +
            @intFromBool(options.clear_random_seed) +
            options.remove_users.len,
    };
}

fn validateOperations(operations: []const Operation) !void {
    for (operations) |operation| {
        const path = switch (operation) {
            .overwrite_file => |overwrite| overwrite.path,
            .remove_file => |path| path,
            .remove_tree => |path| path,
        };
        if (!validAbsoluteImagePath(path)) return error.InvalidImagePath;
        if (operation == .overwrite_file) {
            switch (operation.overwrite_file.source) {
                .bytes => {},
                .host_path => |source| if (source.len == 0) return error.InvalidSourcePath,
            }
        }
    }
}

fn validAbsoluteImagePath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or
            std.mem.indexOfScalar(u8, component, 0) != null)
        {
            return false;
        }
    }
    return true;
}

/// Resolves a logical volume to the byte range it occupies on the disk.
///
/// Only a volume that is one unbroken run on one physical volume can be
/// handed to a reader that takes an offset and a length; anything else is
/// refused by `lvm.contiguousRange` rather than truncated to its first run.
fn selectLogicalVolume(
    allocator: Allocator,
    io: Io,
    image: Image,
    selector: LogicalVolumeSelector,
) !Partition {
    var found = try lvm.scan(allocator, image, io);
    defer found.deinit();
    const selected = try found.findLogicalVolume(
        selector.volume_group,
        selector.logical_volume,
    );
    const range = try lvm.contiguousRange(selected.group, selected.volume);
    const end = std.math.add(u64, range.offset, range.length) catch
        return error.InvalidPartitionBounds;
    if (range.length == 0 or end > image.virtual_size) return error.InvalidPartitionBounds;
    return .{ .offset = range.offset, .length = range.length };
}

fn selectPartition(
    allocator: Allocator,
    io: Io,
    image: Image,
    selector: PartitionSelector,
) !Partition {
    // A logical volume is resolved without reading the boot record at all: a
    // physical volume may occupy the whole disk, in which case there is no
    // partition table, and failing for want of one would be the wrong
    // answer.
    return switch (selector) {
        .logical_volume => |volume| selectLogicalVolume(allocator, io, image, volume),
        .gpt_index, .mbr_index => selectTablePartition(allocator, io, image, selector),
    };
}

fn selectTablePartition(
    allocator: Allocator,
    io: Io,
    image: Image,
    selector: PartitionSelector,
) !Partition {
    var sector: [mbr.sector_size]u8 = undefined;
    if (try image.pread(io, &sector, 0) != sector.len) return error.UnexpectedEndOfFile;
    const boot_record = try mbr.Mbr.decode(&sector);
    const protective = for (boot_record.entries) |entry| {
        if (entry.partition_type == .gpt_protective) break true;
    } else false;

    return switch (selector) {
        .gpt_index => |one_based| blk: {
            if (!protective or one_based == 0) return error.PartitionStyleMismatch;
            const parsed = try gpt.readGpt(image, io, allocator);
            defer allocator.free(parsed.partitions);
            try validateGptLayout(parsed, image.virtual_size);
            for (parsed.partitions) |partition| {
                if (partition.table_index + 1 != one_based) continue;
                const sector_count = std.math.add(u64, partition.last_lba - partition.first_lba, 1) catch
                    return error.InvalidPartitionBounds;
                break :blk .{
                    .offset = std.math.mul(u64, partition.first_lba, mbr.sector_size) catch
                        return error.InvalidPartitionBounds,
                    .length = std.math.mul(u64, sector_count, mbr.sector_size) catch
                        return error.InvalidPartitionBounds,
                };
            }
            return error.PartitionNotFound;
        },
        .mbr_index => |one_based| blk: {
            if (protective or one_based == 0 or one_based > mbr.max_entries) {
                return error.PartitionStyleMismatch;
            }
            const partition = boot_record.entries[one_based - 1];
            if (partition.partition_type == .empty or partition.sector_count == 0) {
                return error.PartitionNotFound;
            }
            break :blk .{
                .offset = @as(u64, partition.first_lba) * mbr.sector_size,
                .length = @as(u64, partition.sector_count) * mbr.sector_size,
            };
        },
        .logical_volume => unreachable, // routed away by `selectPartition`
    };
}

/// Locates a merged source's partition. Unlike the root partition this one
/// is only read, never rewritten, so the MBR type is not constrained: an ESP
/// is type 0xEF and a separate `/boot` may be anything an installer chose.
/// Only the bounds have to hold, because a partition that runs off the end of
/// its disk would be read as whatever happened to follow it.
fn selectMountPartition(
    allocator: Allocator,
    io: Io,
    image: Image,
    selector: PartitionSelector,
) !Partition {
    if (image.virtual_size == 0 or image.virtual_size % mbr.sector_size != 0) {
        return error.InvalidPartitionBounds;
    }
    return selectPartition(allocator, io, image, selector);
}

fn selectRebuildPartition(
    allocator: Allocator,
    io: Io,
    image: Image,
    selector: PartitionSelector,
) !Partition {
    if (image.virtual_size == 0 or image.virtual_size % mbr.sector_size != 0) {
        return error.InvalidPartitionBounds;
    }
    const selected = try selectPartition(allocator, io, image, selector);
    switch (selector) {
        .mbr_index => |one_based| {
            var sector: [mbr.sector_size]u8 = undefined;
            if (try image.pread(io, &sector, 0) != sector.len) {
                return error.UnexpectedEndOfFile;
            }
            const table = try mbr.Mbr.decode(&sector);
            if (table.entries[one_based - 1].partition_type != .linux) {
                return error.UnsupportedRootPartitionType;
            }
            const disk_sectors = image.virtual_size / mbr.sector_size;
            for (table.entries, 0..) |entry, index| {
                if (entry.partition_type == .empty) continue;
                const end = std.math.add(
                    u64,
                    entry.first_lba,
                    entry.sector_count,
                ) catch return error.InvalidPartitionBounds;
                if (entry.sector_count == 0 or end > disk_sectors) {
                    return error.InvalidPartitionBounds;
                }
                for (table.entries[index + 1 ..]) |other| {
                    if (other.partition_type == .empty) continue;
                    const other_end = std.math.add(
                        u64,
                        other.first_lba,
                        other.sector_count,
                    ) catch return error.InvalidPartitionBounds;
                    if (@as(u64, entry.first_lba) < other_end and
                        @as(u64, other.first_lba) < end)
                    {
                        return error.InvalidPartitionBounds;
                    }
                }
            }
        },
        .gpt_index => |one_based| {
            const parsed = try gpt.readGpt(image, io, allocator);
            defer allocator.free(parsed.partitions);
            const partition = for (parsed.partitions) |entry| {
                if (entry.table_index + 1 == one_based) break entry;
            } else return error.PartitionNotFound;
            if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.linux_filesystem_data) and
                !std.mem.eql(u8, &partition.partition_type_guid, &guid.linux_root_x86_64) and
                !std.mem.eql(u8, &partition.partition_type_guid, &guid.linux_root_aarch64))
            {
                return error.UnsupportedRootPartitionType;
            }
        },
        // A logical volume holds a filesystem directly -- there is no
        // partition type to vet, and the volume's own run has already been
        // checked to lie inside its physical volume. Rewriting the
        // filesystem in place leaves every LVM structure untouched, since
        // the range starts and ends exactly where the volume does.
        .logical_volume => {},
    }
    return selected;
}

fn validateGptLayout(parsed: gpt.ParsedGpt, virtual_size: u64) !void {
    if (virtual_size == 0 or virtual_size % gpt.sector_size != 0) {
        return error.InvalidPartitionBounds;
    }
    const total_lbas = virtual_size / gpt.sector_size;
    const header = parsed.header;
    if (header.current_lba != 1 or
        header.backup_lba != total_lbas - 1 or
        header.first_usable_lba > header.last_usable_lba or
        header.last_usable_lba >= total_lbas)
    {
        return error.InvalidPartitionBounds;
    }

    const array_bytes = std.math.mul(
        u64,
        header.num_partition_entries,
        header.partition_entry_size,
    ) catch return error.InvalidPartitionBounds;
    const array_bytes_rounded = std.math.add(
        u64,
        array_bytes,
        gpt.sector_size - 1,
    ) catch return error.InvalidPartitionBounds;
    const array_sectors = array_bytes_rounded / gpt.sector_size;
    if (array_sectors == 0) return error.InvalidPartitionBounds;
    const primary_array_last = std.math.add(
        u64,
        header.partition_entry_lba,
        array_sectors - 1,
    ) catch return error.InvalidPartitionBounds;
    if (primary_array_last >= header.first_usable_lba or
        header.partition_entry_lba <= header.current_lba or
        header.backup_lba < array_sectors)
    {
        return error.InvalidPartitionBounds;
    }
    const backup_array_first = header.backup_lba - array_sectors;
    const backup_array_last = header.backup_lba - 1;
    if (header.last_usable_lba >= backup_array_first) {
        return error.InvalidPartitionBounds;
    }

    for (parsed.partitions, 0..) |partition, index| {
        if (partition.last_lba < partition.first_lba or
            partition.first_lba < header.first_usable_lba or
            partition.last_lba > header.last_usable_lba or
            lbaRangeContains(partition.first_lba, partition.last_lba, header.current_lba) or
            lbaRangeContains(partition.first_lba, partition.last_lba, header.backup_lba) or
            lbaRangesOverlap(
                partition.first_lba,
                partition.last_lba,
                header.partition_entry_lba,
                primary_array_last,
            ) or
            lbaRangesOverlap(
                partition.first_lba,
                partition.last_lba,
                backup_array_first,
                backup_array_last,
            ))
        {
            return error.InvalidPartitionBounds;
        }
        for (parsed.partitions[index + 1 ..]) |other| {
            if (other.last_lba < other.first_lba or
                lbaRangesOverlap(
                    partition.first_lba,
                    partition.last_lba,
                    other.first_lba,
                    other.last_lba,
                ))
            {
                return error.InvalidPartitionBounds;
            }
        }
    }
}

fn lbaRangeContains(first: u64, last: u64, lba: u64) bool {
    return first <= lba and lba <= last;
}

fn lbaRangesOverlap(first_a: u64, last_a: u64, first_b: u64, last_b: u64) bool {
    return first_a <= last_b and first_b <= last_a;
}

fn preflightOperations(
    allocator: Allocator,
    io: Io,
    editor: *ext4.Editor,
    operations: []const Operation,
    max_source_file_bytes: u64,
    diagnostic: ?*limits_mod.Diagnostic,
) !void {
    for (operations) |operation| {
        switch (operation) {
            .overwrite_file => |overwrite| {
                const stat = try editor.reader.statPath(io, overwrite.path);
                if (stat.kind != .file) return error.NotRegularFile;
                switch (overwrite.source) {
                    .bytes => |bytes| try checkSourceFileBytes(
                        bytes.len,
                        max_source_file_bytes,
                        diagnostic,
                    ),
                    .host_path => |path| {
                        const file = try Io.Dir.cwd().openFile(io, path, .{});
                        defer file.close(io);
                        const source_stat = try file.stat(io);
                        if (source_stat.kind != .file) return error.SourceNotRegularFile;
                        try checkSourceFileBytes(
                            source_stat.size,
                            max_source_file_bytes,
                            diagnostic,
                        );
                    },
                }
            },
            .remove_file => |path| {
                const stat = try editor.reader.statPath(io, path);
                if (stat.kind == .directory) return error.IsDirectory;
            },
            .remove_tree => |path| {
                const stat = try editor.reader.statPath(io, path);
                if (stat.kind != .directory) return error.NotDirectory;
            },
        }
    }
    _ = allocator;
}

fn loadSource(
    allocator: Allocator,
    io: Io,
    source: FileSource,
    max_source_file_bytes: u64,
    diagnostic: ?*limits_mod.Diagnostic,
) ![]u8 {
    return switch (source) {
        .bytes => |bytes| blk: {
            try checkSourceFileBytes(bytes.len, max_source_file_bytes, diagnostic);
            break :blk allocator.dupe(u8, bytes);
        },
        .host_path => |path| Io.Dir.cwd().readFileAlloc(
            io,
            path,
            allocator,
            .limited(std.math.cast(usize, max_source_file_bytes) orelse std.math.maxInt(usize)),
        ),
    };
}

const test_disk_size: u64 = 32 * 1024 * 1024;
const test_partition_first_lba: u32 = 2048;
const test_partition_sectors: u32 = 48 * 1024;
const test_unrelated_first_lba: u32 = 54 * 1024;
const test_unrelated_sectors: u32 = 4 * 1024;

fn createTestDisk(io: Io, path: []const u8) !void {
    var image = try Image.createExclusive(io, path, .raw, test_disk_size, .{});
    defer image.close(io);

    var boot_record = mbr.singleLinuxPartitionMbr(test_partition_first_lba, test_partition_sectors);
    boot_record.entries[1] = .{
        .partition_type = .linux,
        .first_lba = test_unrelated_first_lba,
        .sector_count = test_unrelated_sectors,
    };
    boot_record.disk_signature = 0xA1B2_C3D4;
    const encoded_mbr = boot_record.encode();
    try image.pwrite(io, &encoded_mbr, 0);
    try image.pwrite(
        io,
        &([_]u8{0xA5} ** 4096),
        @as(u64, test_unrelated_first_lba) * mbr.sector_size,
    );

    const spool_path = "test-preserved-image-root.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try root_tree.RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    const config_xattrs = [_]ext4.Xattr{.{ .name = "user.origin", .value = "preserved" }};
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/config", "before\n", .{
        .mode = 0o640,
        .uid = 12,
        .gid = 34,
        .xattrs = &config_xattrs,
    });
    try tree.putFileBytes("etc/remove", "remove\n", .{ .mode = 0o644 });
    try tree.putSymlink("config-link", "etc/config", .{ .mode = 0o777, .uid = 56, .gid = 78 });
    try tree.putDirectory("var", .{ .mode = 0o755 });
    try tree.putDirectory("var/tmp", .{ .mode = 0o755 });
    try tree.putDirectory("var/tmp/drop", .{ .mode = 0o700 });
    try tree.putFileBytes("var/tmp/drop/item", "remove tree\n", .{ .mode = 0o600 });

    _ = try ext4.populate(io, image.file, std.testing.allocator, try tree.ext4View(), .{
        .offset = @as(u64, test_partition_first_lba) * mbr.sector_size,
        .length = @as(u64, test_partition_sectors) * mbr.sector_size,
        .label = "preserved-root",
        .uuid = [_]u8{0x42} ** 16,
        .timestamp = 1_735_689_600,
    });
}

fn hashTestPath(io: Io, path: []const u8) ![32]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{});
    defer file.close(io);
    const size = (try file.stat(io)).size;
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), size - offset));
        const count = try file.readPositionalAll(io, buffer[0..wanted], offset);
        if (count == 0) return error.UnexpectedEndOfFile;
        hash.update(buffer[0..count]);
        offset += count;
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn expectOutsideRangeEqual(
    io: Io,
    source: Image,
    output: Image,
    excluded_offset: u64,
    excluded_length: u64,
) !void {
    var source_buffer: [64 * 1024]u8 = undefined;
    var output_buffer: [64 * 1024]u8 = undefined;
    const excluded_end = excluded_offset + excluded_length;
    var offset: u64 = 0;
    while (offset < source.virtual_size) {
        if (offset == excluded_offset) {
            offset = excluded_end;
            continue;
        }
        const range_end = if (offset < excluded_offset) excluded_offset else source.virtual_size;
        const wanted: usize = @intCast(@min(
            @as(u64, source_buffer.len),
            range_end - offset,
        ));
        if (try source.pread(io, source_buffer[0..wanted], offset) != wanted or
            try output.pread(io, output_buffer[0..wanted], offset) != wanted)
        {
            return error.UnexpectedEndOfFile;
        }
        try std.testing.expectEqualSlices(
            u8,
            source_buffer[0..wanted],
            output_buffer[0..wanted],
        );
        offset += wanted;
    }
}

fn expectRebuildArtifactsMissing(io: Io, output_path: []const u8) !void {
    inline for (.{ "", ".native-rebuild.raw", ".native-rebuild.output", ".native-rebuild.spool" }) |suffix| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{
            output_path,
            suffix,
        });
        defer std.testing.allocator.free(path);
        try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, path, .{}));
    }
}

const TestExt4Crc32c = std.hash.crc.Crc(u32, .{
    .polynomial = 0x1edc6f41,
    .initial = 0xffff_ffff,
    .reflect_input = true,
    .reflect_output = true,
    .xor_output = 0x0000_0000,
});

fn updateTestDirectoryLeafChecksum(
    block: []u8,
    uuid: [16]u8,
    inode_number: u32,
) void {
    var inode_le = std.mem.nativeToLittle(u32, inode_number);
    var generation_le = std.mem.nativeToLittle(u32, @as(u32, 0));
    var hasher = TestExt4Crc32c.init();
    hasher.update(&uuid);
    hasher.update(std.mem.asBytes(&inode_le));
    hasher.update(std.mem.asBytes(&generation_le));
    hasher.update(block[0 .. block.len - 12]);
    std.mem.writeInt(u32, block[block.len - 4 ..][0..4], hasher.final(), .little);
}

fn mutateRootDirectoryEntry(
    io: Io,
    path: []const u8,
    entry_name: []const u8,
    replacement_inode: ?u32,
    replacement_file_type: ?u8,
    replacement_name_byte: ?struct { index: usize, value: u8 },
) !void {
    var image = try Image.openPath(io, path);
    defer image.close(io);
    const partition_offset = @as(u64, test_partition_first_lba) * mbr.sector_size;
    var reader = try ext4.open(io, image.file, std.testing.allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    const extents = try reader.readExtents(io, std.testing.allocator, "/");
    defer std.testing.allocator.free(extents);
    var block: [ext4.default_block_size]u8 = undefined;
    for (extents) |extent| {
        var extent_block: u16 = 0;
        while (extent_block < extent.block_count) : (extent_block += 1) {
            const physical_block = extent.start_block + extent_block;
            const block_offset = partition_offset + physical_block * ext4.default_block_size;
            if (try image.pread(io, &block, block_offset) != block.len) {
                return error.UnexpectedEndOfFile;
            }
            var offset: usize = 0;
            while (offset + 8 <= block.len) {
                const rec_len = std.mem.readInt(u16, block[offset + 4 ..][0..2], .little);
                const name_len = block[offset + 6];
                if (rec_len < 8 or offset + rec_len > block.len or name_len > rec_len - 8) {
                    return error.BadDirectoryEntry;
                }
                const name = block[offset + 8 .. offset + 8 + name_len];
                if (std.mem.eql(u8, name, entry_name)) {
                    if (replacement_inode) |inode| {
                        std.mem.writeInt(u32, block[offset..][0..4], inode, .little);
                    }
                    if (replacement_file_type) |file_type| block[offset + 7] = file_type;
                    if (replacement_name_byte) |replacement| {
                        if (replacement.index >= name.len) return error.InvalidTestMutation;
                        block[offset + 8 + replacement.index] = replacement.value;
                    }
                    updateTestDirectoryLeafChecksum(&block, reader.uuid, ext4.root_inode);
                    try image.pwrite(io, &block, block_offset);
                    return;
                }
                offset += rec_len;
            }
        }
    }
    return error.NotFound;
}

test "rebuild inspection validates source without creating artifacts" {
    const io = std.testing.io;
    const source_path = "test-rebuild-inspection-source.raw";
    const output_path = "test-rebuild-inspection-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.output") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.spool") catch {};
    try createTestDisk(io, source_path);
    const source_before = try hashTestPath(io, source_path);

    const inspection = try inspectRebuild(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .source_date_epoch = 1_735_689_600,
        .expected_virtual_size = test_disk_size,
    });
    try std.testing.expectEqual(Format.raw, inspection.source_format);
    try std.testing.expectEqual(test_disk_size, inspection.virtual_size);
    try std.testing.expectEqual(
        @as(u64, test_partition_first_lba) * mbr.sector_size,
        inspection.partition_offset,
    );
    try std.testing.expectEqual(
        @as(u64, test_partition_sectors) * mbr.sector_size,
        inspection.partition_length,
    );
    try std.testing.expectEqual(ext4.SourceProfile.zvmi_ext4_v1, inspection.source_profile);
    try std.testing.expect(inspection.source_reproducible);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x42} ** 16), &inspection.ext4_uuid);
    try std.testing.expectEqual(@as(u32, 1_735_689_600), inspection.ext4_global_timestamp);
    try std.testing.expectEqual(@as(usize, 8), inspection.imported_node_count);
    try std.testing.expectEqualSlices(u8, &source_before, &(try hashTestPath(io, source_path)));
    try expectRebuildArtifactsMissing(io, output_path);
}

test "rebuild inspection strict failure creates no artifacts" {
    const io = std.testing.io;
    const source_path = "test-rebuild-inspection-invalid-source.raw";
    const output_path = "test-rebuild-inspection-invalid-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.output") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.spool") catch {};
    try createTestDisk(io, source_path);
    try mutateRootDirectoryEntry(
        io,
        source_path,
        "config-link",
        null,
        null,
        .{ .index = 6, .value = '/' },
    );

    try std.testing.expectError(error.InvalidImportedPath, inspectRebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = output_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, output_path);
}

test "rebuild inspection simulates ordered mutations without creating artifacts" {
    const io = std.testing.io;
    const source_path = "test-rebuild-inspection-mutations-source.raw";
    const output_path = "test-rebuild-inspection-mutations-output.raw";
    const oversized_path = "test-rebuild-inspection-oversized.bin";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, oversized_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.output") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.spool") catch {};
    try createTestDisk(io, source_path);

    try std.testing.expectError(error.MissingExistingPath, inspectRebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = output_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .existing_operations = &.{
                .{ .remove_tree = "/etc" },
                .{ .overwrite_file = .{
                    .path = "/etc/config",
                    .source = .{ .bytes = "replacement\n" },
                } },
            },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, output_path);

    try std.testing.expectError(error.MissingCustomizationPath, inspectRebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = output_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .customization = .{ .filesystem = &.{
                .{ .remove = "/etc/config" },
                .{ .set_metadata = .{ .path = "/etc/config" } },
            } },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, output_path);

    {
        const oversized = try Io.Dir.cwd().createFile(io, oversized_path, .{});
        defer oversized.close(io);
        try oversized.setLength(io, @as(u64, test_partition_sectors) * mbr.sector_size);
    }
    try std.testing.expectError(error.NotEnoughSpace, inspectRebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = output_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .customization = .{ .filesystem = &.{
                .{ .put_file = .{
                    .path = "/oversized",
                    .source = .{ .host_path = oversized_path },
                } },
            } },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, output_path);
}

test "strict raw rebuild preserves identity tree metadata and outside bytes deterministically" {
    const io = std.testing.io;
    const source_path = "test-preserved-rebuild-source.raw";
    const output_path = "test-preserved-rebuild-output.raw";
    const output2_path = "test-preserved-rebuild-output-2.raw";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        output2_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
        output2_path ++ ".native-rebuild.raw",
        output2_path ++ ".native-rebuild.output",
        output2_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |path| Io.Dir.cwd().deleteFile(io, path) catch {};
    try createTestDisk(io, source_path);
    {
        var source = try Image.openPath(io, source_path);
        defer source.close(io);
        try source.pwrite(
            io,
            &([_]u8{0xA7} ** ext4.default_block_size),
            (@as(u64, test_partition_first_lba + test_partition_sectors) *
                mbr.sector_size) - ext4.default_block_size,
        );
    }
    const source_before = try hashTestPath(io, source_path);

    const existing = [_]Operation{
        .{ .overwrite_file = .{
            .path = "/etc/config",
            .source = .{ .bytes = "rebuilt\n" },
        } },
        .{ .remove_file = "/etc/remove" },
        .{ .remove_tree = "/var/tmp/drop" },
    };
    const filesystem = [_]os_customization.FilesystemOperation{
        .{ .put_directory = .{
            .path = "/opt/new",
            .metadata = .{ .mode = 0o750, .uid = 101, .gid = 202 },
        } },
        .{ .put_file = .{
            .path = "/opt/new/value",
            .source = .{ .inline_bytes = "created\n" },
            .metadata = .{ .mode = 0o600, .uid = 303, .gid = 404 },
        } },
        .{ .put_symlink = .{
            .path = "/created-link",
            .target = "opt/new/value",
            .metadata = .{ .mode = 0o777, .uid = 505, .gid = 606 },
        } },
    };
    const rebuild_options = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .existing_operations = &existing,
        .customization = .{ .filesystem = &filesystem },
        .generalization = .{ .azure = .{} },
        .source_date_epoch = 1_735_689_600,
        .expected_virtual_size = test_disk_size,
    };
    const report = try rebuild(std.testing.allocator, io, rebuild_options);
    var second_options = rebuild_options;
    second_options.output_path = output2_path;
    const second_report = try rebuild(std.testing.allocator, io, second_options);

    try std.testing.expectEqual(ext4.SourceProfile.zvmi_ext4_v1, report.source_profile);
    try std.testing.expect(report.source_reproducible);
    try std.testing.expectEqual(@as(u32, 1_735_689_600), report.ext4_global_timestamp);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x42} ** 16), &report.ext4_uuid);
    try std.testing.expectEqualSlices(
        u8,
        &report.source_manifest_sha256,
        &second_report.source_manifest_sha256,
    );
    try std.testing.expectEqualSlices(
        u8,
        &report.final_manifest_sha256,
        &second_report.final_manifest_sha256,
    );
    try std.testing.expectEqual(report.imported_node_count, second_report.imported_node_count);
    try std.testing.expectEqual(report.final_node_count, second_report.final_node_count);
    try std.testing.expectEqual(@as(usize, existing.len), report.existing_operation_count);
    try std.testing.expectEqual(@as(usize, filesystem.len), report.os_customization_count);
    try std.testing.expect(report.generalization_count > 0);
    try std.testing.expectEqualSlices(u8, &source_before, &(try hashTestPath(io, source_path)));

    var source = try Image.openPathReadOnly(io, source_path);
    defer source.close(io);
    var output = try Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    const partition_offset = @as(u64, test_partition_first_lba) * mbr.sector_size;
    const partition_length = @as(u64, test_partition_sectors) * mbr.sector_size;
    try expectOutsideRangeEqual(
        io,
        source,
        output,
        partition_offset,
        partition_length,
    );
    var cleared_free_block: [ext4.default_block_size]u8 = undefined;
    _ = try output.pread(
        io,
        &cleared_free_block,
        partition_offset + partition_length - cleared_free_block.len,
    );
    try std.testing.expect(std.mem.allEqual(u8, &cleared_free_block, 0));

    var reader = try ext4.open(io, output.file, std.testing.allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    var strict = try ext4.scanWriterCompatible(&reader, io, std.testing.allocator, .{
        .expected_length = partition_length,
    });
    defer strict.deinit();
    try std.testing.expectEqual(report.final_node_count, strict.nodeCount());
    try std.testing.expectEqualSlices(u8, &report.ext4_label, &strict.identity.label);
    try std.testing.expectEqual(report.ext4_global_timestamp, strict.identity.global_timestamp);

    const config = try reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(config);
    try std.testing.expectEqualStrings("rebuilt\n", config);
    const config_stat = try reader.statPath(io, "/etc/config");
    try std.testing.expectEqual(@as(u16, 0o640), config_stat.mode);
    try std.testing.expectEqual(@as(u32, 12), config_stat.uid);
    try std.testing.expectEqual(@as(u32, 34), config_stat.gid);
    const origin = try reader.readXattrAlloc(
        io,
        std.testing.allocator,
        "/etc/config",
        "user.origin",
    );
    defer std.testing.allocator.free(origin);
    try std.testing.expectEqualStrings("preserved", origin);
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/etc/remove"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/var/tmp/drop"));

    const value = try reader.readFileAlloc(io, std.testing.allocator, "/opt/new/value");
    defer std.testing.allocator.free(value);
    try std.testing.expectEqualStrings("created\n", value);
    const value_stat = try reader.statPath(io, "/opt/new/value");
    try std.testing.expectEqual(@as(u16, 0o600), value_stat.mode);
    try std.testing.expectEqual(@as(u32, 303), value_stat.uid);
    try std.testing.expectEqual(@as(u32, 404), value_stat.gid);
    const target = try reader.readLinkAlloc(io, std.testing.allocator, "/created-link");
    defer std.testing.allocator.free(target);
    try std.testing.expectEqualStrings("opt/new/value", target);
    const hostname = try reader.readFileAlloc(io, std.testing.allocator, "/etc/hostname");
    defer std.testing.allocator.free(hostname);
    try std.testing.expectEqualStrings("localhost.localdomain\n", hostname);

    inline for (.{ ".native-rebuild.raw", ".native-rebuild.output", ".native-rebuild.spool" }) |suffix| {
        const path = try std.fmt.allocPrint(std.testing.allocator, "{s}{s}", .{ output_path, suffix });
        defer std.testing.allocator.free(path);
        try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, path, .{}));
    }
}

test "strict rebuild flattens a backed qcow2 source without changing its chain" {
    const io = std.testing.io;
    const raw_path = "test-rebuild-backed-base.raw";
    const base_path = "test-rebuild-backed-base.qcow2";
    const source_path = "test-rebuild-backed-overlay.qcow2";
    const output_path = "test-rebuild-backed-output.qcow2";
    const artifacts = [_][]const u8{
        raw_path,
        base_path,
        source_path,
        output_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |path| Io.Dir.cwd().deleteFile(io, path) catch {};
    try createTestDisk(io, raw_path);
    {
        var raw = try Image.openPathReadOnly(io, raw_path);
        defer raw.close(io);
        var base = try Image.createExclusive(io, base_path, .qcow2, test_disk_size, .{});
        defer base.close(io);
        try image_mod.copyAll(io, raw, &base, std.testing.allocator);
    }
    {
        var overlay = try Image.createExclusive(io, source_path, .qcow2, test_disk_size, .{});
        overlay.close(io);
        const file = try Io.Dir.cwd().openFile(io, source_path, .{ .mode = .read_write });
        defer file.close(io);
        var header: [104]u8 = undefined;
        if (try file.readPositionalAll(io, &header, 0) != header.len) {
            return error.UnexpectedEndOfFile;
        }
        const backing_offset = std.mem.readInt(u32, header[100..104], .big);
        std.mem.writeInt(u64, header[8..16], backing_offset, .big);
        std.mem.writeInt(u32, header[16..20], base_path.len, .big);
        try file.writePositionalAll(io, &header, 0);
        try file.writePositionalAll(io, base_path, backing_offset);
    }
    const source_before = try hashTestPath(io, source_path);
    const base_before = try hashTestPath(io, base_path);

    const report = try rebuild(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .qcow2,
        .output_format = .qcow2,
        .root_partition = .{ .mbr_index = 1 },
        .source_date_epoch = 1_735_689_600,
    });
    try std.testing.expect(report.flattened_backing_chain);
    try std.testing.expectEqualSlices(u8, &source_before, &(try hashTestPath(io, source_path)));
    try std.testing.expectEqualSlices(u8, &base_before, &(try hashTestPath(io, base_path)));

    var output = try Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    try std.testing.expectEqual(Format.qcow2, output.format);
    try std.testing.expectEqual(@as(u8, 0), output.qcow2.?.backing_depth);
    try std.testing.expectEqual(@as(u16, 0), output.qcow2.?.backing_file_len);
    var reader = try ext4.openReadOnlySource(
        io,
        output.file,
        .{ .ctx = &output, .read_at_fn = imageReadAt },
        std.testing.allocator,
        .{ .offset = @as(u64, test_partition_first_lba) * mbr.sector_size },
    );
    defer reader.deinit();
    var strict = try ext4.scanWriterCompatible(&reader, io, std.testing.allocator, .{
        .expected_length = @as(u64, test_partition_sectors) * mbr.sector_size,
    });
    defer strict.deinit();
    try std.testing.expectEqual(report.final_node_count, strict.nodeCount());
}

test "strict rebuild rejects inode aliases before creating staging" {
    const io = std.testing.io;
    const source_path = "test-rebuild-alias-source.raw";
    const output_path = "test-rebuild-alias-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.output") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.spool") catch {};
    try createTestDisk(io, source_path);

    var source = try Image.openPathReadOnly(io, source_path);
    var reader = try ext4.open(io, source.file, std.testing.allocator, .{
        .offset = @as(u64, test_partition_first_lba) * mbr.sector_size,
    });
    const config_inode = (try reader.statPath(io, "/etc/config")).inode;
    reader.deinit();
    source.close(io);
    try mutateRootDirectoryEntry(io, source_path, "config-link", config_inode, 1, null);

    try std.testing.expectError(error.InodeAlias, rebuild(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .source_date_epoch = 1_735_689_600,
    }));
    try expectRebuildArtifactsMissing(io, output_path);
}

test "strict rebuild rejects malformed imported paths before creating staging" {
    const io = std.testing.io;
    const source_path = "test-rebuild-malformed-tree-source.raw";
    const output_path = "test-rebuild-malformed-tree-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.output") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-rebuild.spool") catch {};
    try createTestDisk(io, source_path);
    try mutateRootDirectoryEntry(
        io,
        source_path,
        "config-link",
        null,
        null,
        .{ .index = 6, .value = '/' },
    );

    try std.testing.expectError(error.InvalidImportedPath, rebuild(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .source_date_epoch = 1_735_689_600,
    }));
    try expectRebuildArtifactsMissing(io, output_path);
}

test "strict rebuild rejects filesystem trailers and unsupported partition layout before staging" {
    const io = std.testing.io;
    const trailer_source = "test-rebuild-trailer-source.raw";
    const trailer_output = "test-rebuild-trailer-output.raw";
    const layout_source = "test-rebuild-layout-source.raw";
    const layout_output = "test-rebuild-layout-output.raw";
    const paths = [_][]const u8{
        trailer_source,
        trailer_output,
        trailer_output ++ ".native-rebuild.raw",
        trailer_output ++ ".native-rebuild.output",
        trailer_output ++ ".native-rebuild.spool",
        layout_source,
        layout_output,
        layout_output ++ ".native-rebuild.raw",
        layout_output ++ ".native-rebuild.output",
        layout_output ++ ".native-rebuild.spool",
    };
    defer for (paths) |path| Io.Dir.cwd().deleteFile(io, path) catch {};
    try createTestDisk(io, trailer_source);
    {
        var image = try Image.openPath(io, trailer_source);
        defer image.close(io);
        var sector: [mbr.sector_size]u8 = undefined;
        if (try image.pread(io, &sector, 0) != sector.len) return error.UnexpectedEndOfFile;
        var table = try mbr.Mbr.decode(&sector);
        table.entries[0].sector_count += 8;
        table.encodePartitionTableInto(&sector);
        try image.pwrite(io, &sector, 0);
    }
    try std.testing.expectError(error.FilesystemLengthMismatch, rebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = trailer_source,
            .output_path = trailer_output,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, trailer_output);

    try createTestDisk(io, layout_source);
    {
        var image = try Image.openPath(io, layout_source);
        defer image.close(io);
        var sector: [mbr.sector_size]u8 = undefined;
        if (try image.pread(io, &sector, 0) != sector.len) return error.UnexpectedEndOfFile;
        var table = try mbr.Mbr.decode(&sector);
        table.entries[0].partition_type = @enumFromInt(0x07);
        table.encodePartitionTableInto(&sector);
        try image.pwrite(io, &sector, 0);
    }
    try std.testing.expectError(error.UnsupportedRootPartitionType, rebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = layout_source,
            .output_path = layout_output,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, layout_output);
}

test "failed rebuild customization and publication clean every staging artifact" {
    const io = std.testing.io;
    const source_path = "test-rebuild-cleanup-source.raw";
    const customization_output = "test-rebuild-cleanup-customization.raw";
    const publish_output = "test-rebuild-cleanup-publish.raw";
    const paths = [_][]const u8{
        source_path,
        customization_output,
        customization_output ++ ".native-rebuild.raw",
        customization_output ++ ".native-rebuild.output",
        customization_output ++ ".native-rebuild.spool",
        publish_output,
        publish_output ++ ".native-rebuild.raw",
        publish_output ++ ".native-rebuild.output",
        publish_output ++ ".native-rebuild.spool",
    };
    defer for (paths) |path| Io.Dir.cwd().deleteFile(io, path) catch {};
    try createTestDisk(io, source_path);

    const invalid_customization = [_]os_customization.FilesystemOperation{
        .{ .set_metadata = .{ .path = "/missing", .mode = 0o600 } },
    };
    try std.testing.expectError(error.MissingCustomizationPath, rebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = customization_output,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .customization = .{ .filesystem = &invalid_customization },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    try expectRebuildArtifactsMissing(io, customization_output);

    {
        const output = try Io.Dir.cwd().createFile(io, publish_output, .{});
        defer output.close(io);
        try output.writePositionalAll(io, "preserve-me", 0);
    }
    try std.testing.expectError(error.PathAlreadyExists, rebuild(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = publish_output,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
            .source_date_epoch = 1_735_689_600,
        },
    ));
    inline for (.{ ".native-rebuild.raw", ".native-rebuild.output", ".native-rebuild.spool" }) |suffix| {
        const artifact = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}{s}",
            .{ publish_output, suffix },
        );
        defer std.testing.allocator.free(artifact);
        try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, artifact, .{}));
    }
    const existing = try Io.Dir.cwd().openFile(io, publish_output, .{});
    defer existing.close(io);
    var bytes: ["preserve-me".len]u8 = undefined;
    _ = try existing.readPositionalAll(io, &bytes, 0);
    try std.testing.expectEqualStrings("preserve-me", &bytes);
}

test "raw mutation hook receives a closed standalone stage and controls publication" {
    const io = std.testing.io;
    const source_path = "test-raw-mutation-source.raw";
    const output_path = "test-raw-mutation-output.qcow2";
    const corrupt_path = "test-raw-mutation-corrupt.raw";
    const alias_path = "test-raw-mutation-alias.raw";
    const directory_path = "test-raw-mutation-directory.raw";
    const failed_path = "test-raw-mutation-failed.raw";
    const paths = [_][]const u8{
        source_path,
        output_path,
        output_path ++ ".raw-mutation.raw",
        output_path ++ ".raw-mutation.output",
        corrupt_path,
        corrupt_path ++ ".raw-mutation.raw",
        corrupt_path ++ ".raw-mutation.output",
        alias_path,
        alias_path ++ ".raw-mutation.raw",
        alias_path ++ ".raw-mutation.output",
        directory_path,
        directory_path ++ ".raw-mutation.raw",
        directory_path ++ ".raw-mutation.output",
        failed_path,
        failed_path ++ ".raw-mutation.raw",
        failed_path ++ ".raw-mutation.output",
    };
    for (paths) |path| removeStagingPath(io, path);
    defer for (paths) |path| removeStagingPath(io, path);
    try createTestDisk(io, source_path);
    const source_before = try hashTestPath(io, source_path);

    const SuccessHook = struct {
        fn run(
            context_ptr: ?*anyopaque,
            _: Allocator,
            hook_io: Io,
            target: RawMutationTarget,
        ) !void {
            const called: *bool = @ptrCast(@alignCast(context_ptr.?));
            called.* = true;
            var stage = try Image.openPath(hook_io, target.raw_path);
            defer stage.close(hook_io);
            try stage.pwrite(hook_io, "zvmi", target.partition.offset + 4096);
        }
    };
    var called = false;
    const report = try transactRaw(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .qcow2,
        .root_partition = .{ .mbr_index = 1 },
        .expected_virtual_size = test_disk_size,
        .require_linux_partition = true,
    }, .{ .context = &called, .runFn = SuccessHook.run });
    try std.testing.expect(called);
    try std.testing.expectEqual(test_disk_size, report.virtual_size);
    try std.testing.expectEqual(
        @as(u64, test_partition_first_lba) * mbr.sector_size,
        report.partition_offset,
    );
    try std.testing.expectEqualSlices(
        u8,
        &source_before,
        &(try hashTestPath(io, source_path)),
    );
    var output = try Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    var changed: [4]u8 = undefined;
    _ = try output.pread(io, &changed, report.partition_offset + 4096);
    try std.testing.expectEqualStrings("zvmi", &changed);

    const TruncateHook = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            hook_io: Io,
            target: RawMutationTarget,
        ) !void {
            const stage = try Io.Dir.cwd().openFile(
                hook_io,
                target.raw_path,
                .{ .mode = .read_write },
            );
            defer stage.close(hook_io);
            try stage.setLength(hook_io, target.virtual_size - 1);
        }
    };
    try std.testing.expectError(error.VirtualSizeMismatch, transactRaw(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = corrupt_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
        },
        .{ .runFn = TruncateHook.run },
    ));
    inline for (.{ "", ".raw-mutation.raw", ".raw-mutation.output" }) |suffix| {
        const artifact = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}{s}",
            .{ corrupt_path, suffix },
        );
        defer std.testing.allocator.free(artifact);
        try std.testing.expectError(
            error.FileNotFound,
            Io.Dir.cwd().statFile(io, artifact, .{}),
        );
    }

    const AliasHook = struct {
        fn run(
            context_ptr: ?*anyopaque,
            _: Allocator,
            hook_io: Io,
            target: RawMutationTarget,
        ) !void {
            const original_path: *const []const u8 = @ptrCast(@alignCast(context_ptr.?));
            try Io.Dir.cwd().deleteFile(hook_io, target.raw_path);
            try Io.Dir.cwd().hardLink(
                original_path.*,
                Io.Dir.cwd(),
                target.raw_path,
                hook_io,
                .{},
            );
        }
    };
    var original_path: []const u8 = source_path;
    try std.testing.expectError(error.RawStageAliased, transactRaw(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = alias_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
        },
        .{ .context = @ptrCast(&original_path), .runFn = AliasHook.run },
    ));
    try std.testing.expectEqualSlices(
        u8,
        &source_before,
        &(try hashTestPath(io, source_path)),
    );

    const DirectoryHook = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            hook_io: Io,
            target: RawMutationTarget,
        ) !void {
            try Io.Dir.cwd().deleteFile(hook_io, target.raw_path);
            try Io.Dir.cwd().createDir(hook_io, target.raw_path, .default_dir);
        }
    };
    try std.testing.expectError(error.RawStageNotRegularFile, transactRaw(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = directory_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
        },
        .{ .runFn = DirectoryHook.run },
    ));
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, directory_path ++ ".raw-mutation.raw", .{}),
    );

    const FailureHook = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            _: Io,
            _: RawMutationTarget,
        ) !void {
            return error.InjectedMutationFailure;
        }
    };
    try std.testing.expectError(error.InjectedMutationFailure, transactRaw(
        std.testing.allocator,
        io,
        .{
            .source_path = source_path,
            .output_path = failed_path,
            .output_format = .raw,
            .root_partition = .{ .mbr_index = 1 },
        },
        .{ .runFn = FailureHook.run },
    ));
    inline for (.{ "", ".raw-mutation.raw", ".raw-mutation.output" }) |suffix| {
        const artifact = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}{s}",
            .{ failed_path, suffix },
        );
        defer std.testing.allocator.free(artifact);
        try std.testing.expectError(
            error.FileNotFound,
            Io.Dir.cwd().statFile(io, artifact, .{}),
        );
    }
}

test "preserved editor mutates a raw copy without changing source or unrelated bytes" {
    const io = std.testing.io;
    const source_path = "test-preserved-image-source.raw";
    const output_path = "test-preserved-image-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.raw") catch {};
    try createTestDisk(io, source_path);
    const source_before = try hashTestPath(io, source_path);

    const operations = [_]Operation{
        .{ .overwrite_file = .{
            .path = "/etc/config",
            .source = .{ .bytes = "after\n" },
        } },
        .{ .remove_file = "/etc/remove" },
        .{ .remove_tree = "/var/tmp/drop" },
    };
    const report = try edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .operations = &operations,
        .expected_virtual_size = test_disk_size,
    });
    try std.testing.expectEqual(test_disk_size, report.virtual_size);
    try std.testing.expectEqual(@as(usize, operations.len), report.operation_count);
    try std.testing.expectEqualSlices(u8, &source_before, &(try hashTestPath(io, source_path)));

    var source = try Image.openPathReadOnly(io, source_path);
    defer source.close(io);
    var output = try Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    var source_unrelated: [4096]u8 = undefined;
    var output_unrelated: [4096]u8 = undefined;
    const unrelated_offset = @as(u64, test_unrelated_first_lba) * mbr.sector_size;
    _ = try source.pread(io, &source_unrelated, unrelated_offset);
    _ = try output.pread(io, &output_unrelated, unrelated_offset);
    try std.testing.expectEqualSlices(u8, &source_unrelated, &output_unrelated);
    var source_mbr: [mbr.sector_size]u8 = undefined;
    var output_mbr: [mbr.sector_size]u8 = undefined;
    _ = try source.pread(io, &source_mbr, 0);
    _ = try output.pread(io, &output_mbr, 0);
    try std.testing.expectEqualSlices(u8, &source_mbr, &output_mbr);

    var reader = try ext4.open(io, output.file, std.testing.allocator, .{
        .offset = @as(u64, test_partition_first_lba) * mbr.sector_size,
    });
    defer reader.deinit();
    const config = try reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(config);
    try std.testing.expectEqualStrings("after\n", config);
    const stat = try reader.statPath(io, "/etc/config");
    try std.testing.expectEqual(@as(u16, 0o640), stat.mode);
    try std.testing.expectEqual(@as(u32, 12), stat.uid);
    try std.testing.expectEqual(@as(u32, 34), stat.gid);
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/etc/remove"));
    try std.testing.expectError(error.NotFound, reader.statPath(io, "/var/tmp/drop"));

    var source_reader = try ext4.open(io, source.file, std.testing.allocator, .{
        .offset = @as(u64, test_partition_first_lba) * mbr.sector_size,
    });
    defer source_reader.deinit();
    const original = try source_reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(original);
    try std.testing.expectEqualStrings("before\n", original);
}

/// Builds a disk whose root filesystem lives on a logical volume, which is
/// what a guided Ubuntu or Debian install produces: one MBR partition holding
/// an LVM2 physical volume, and the filesystem inside a volume in it.
///
/// The physical volume is written byte by byte because `lvm2` needs root and
/// device-mapper and cannot be run here.
const lvm_test_disk_size: u64 = 64 * 1024 * 1024;
const lvm_test_pv_offset: u64 = 1024 * 1024;
const lvm_test_pv_size: u64 = 48 * 1024 * 1024;
const lvm_test_mda_offset: u64 = 4096;
const lvm_test_mda_size: u64 = 64 * 1024;
const lvm_test_pe_start: u64 = 2048; // sectors
const lvm_test_extent_sectors: u64 = 8192; // 4 MiB
const lvm_test_extents: u64 = 4;
const lvm_test_pv_uuid: [32]u8 = "0123456789abcdefghijklmnopqrstuv".*;
/// The volume starts at the physical volume's first extent, so the filesystem
/// begins pe_start bytes past where the physical volume itself begins.
const lvm_test_root_offset: u64 = lvm_test_pv_offset + lvm_test_pe_start * lvm.sector_size;
const lvm_test_root_length: u64 = lvm_test_extents * lvm_test_extent_sectors * lvm.sector_size;

fn writeLvmTestPv(allocator: Allocator, io: Io, image: *Image, extra_lv: []const u8) !void {
    var label = [_]u8{0} ** 512;
    label[0..8].* = lvm.label_id;
    std.mem.writeInt(u64, label[8..16], 1, .little);
    std.mem.writeInt(u32, label[20..24], 32, .little);
    label[24..32].* = lvm.label_type;
    label[32..64].* = lvm_test_pv_uuid;
    std.mem.writeInt(u64, label[64..72], lvm_test_pv_size, .little);
    // One data area, then a null terminator, then one metadata area.
    std.mem.writeInt(u64, label[72..80], lvm_test_pe_start * lvm.sector_size, .little);
    std.mem.writeInt(u64, label[80..88], 0, .little);
    std.mem.writeInt(u64, label[104..112], lvm_test_mda_offset, .little);
    std.mem.writeInt(u64, label[112..120], lvm_test_mda_size, .little);
    std.mem.writeInt(u32, label[16..20], lvm.crc(lvm.crc_initial, label[20..]), .little);
    try image.pwrite(io, &label, lvm_test_pv_offset + 512);

    const text = try std.fmt.allocPrint(allocator,
        \\contents = "Text Format Volume Group"
        \\version = 1
        \\description = ""
        \\creation_host = "preserved-image-test"
        \\creation_time = 1735689600
        \\
        \\vg {{
        \\id = "VG0000-0000-0000-0000-0000-0000-000000"
        \\seqno = 2
        \\format = "lvm2"
        \\status = ["RESIZEABLE", "READ", "WRITE"]
        \\extent_size = {d}
        \\physical_volumes {{
        \\pv0 {{
        \\id = "012345-6789-abcd-efgh-ijkl-mnop-qrstuv"
        \\device = "/dev/vda1"
        \\status = ["ALLOCATABLE"]
        \\dev_size = {d}
        \\pe_start = {d}
        \\pe_count = 8
        \\}}
        \\}}
        \\logical_volumes {{
        \\root {{
        \\id = "LV0000-0000-0000-0000-0000-0000-000000"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\segment_count = 1
        \\segment1 {{
        \\start_extent = 0
        \\extent_count = {d}
        \\type = "striped"
        \\stripe_count = 1
        \\stripes = ["pv0", 0]
        \\}}
        \\}}
        \\{s}
        \\}}
        \\}}
        \\
    , .{
        lvm_test_extent_sectors,
        lvm_test_pv_size / lvm.sector_size,
        lvm_test_pe_start,
        lvm_test_extents,
        extra_lv,
    });
    defer allocator.free(text);

    const area = try allocator.alloc(u8, lvm_test_mda_size);
    defer allocator.free(area);
    @memset(area, 0);
    @memcpy(area[512..][0..text.len], text);
    area[4..20].* = lvm.metadata_area_magic;
    std.mem.writeInt(u32, area[20..24], lvm.metadata_area_version, .little);
    std.mem.writeInt(u64, area[24..32], lvm_test_mda_offset, .little);
    std.mem.writeInt(u64, area[32..40], lvm_test_mda_size, .little);
    std.mem.writeInt(u64, area[40..48], 512, .little);
    // The trailing NUL is part of the committed copy and of its checksum.
    std.mem.writeInt(u64, area[48..56], text.len + 1, .little);
    std.mem.writeInt(
        u32,
        area[56..60],
        lvm.crc(lvm.crc_initial, area[512..][0 .. text.len + 1]),
        .little,
    );
    std.mem.writeInt(u32, area[0..4], lvm.crc(lvm.crc_initial, area[4..512]), .little);
    try image.pwrite(io, area, lvm_test_pv_offset + lvm_test_mda_offset);
}

fn createLvmTestDisk(io: Io, path: []const u8, extra_lv: []const u8) !void {
    const allocator = std.testing.allocator;
    var image = try Image.createExclusive(io, path, .raw, lvm_test_disk_size, .{});
    defer image.close(io);

    var boot_record = mbr.singleLinuxPartitionMbr(
        @intCast(lvm_test_pv_offset / mbr.sector_size),
        @intCast(lvm_test_pv_size / mbr.sector_size),
    );
    boot_record.disk_signature = 0x5150_4C56;
    const encoded_mbr = boot_record.encode();
    try image.pwrite(io, &encoded_mbr, 0);

    try writeLvmTestPv(allocator, io, &image, extra_lv);

    const spool_path = "test-preserved-image-lvm-root.spool";
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try root_tree.RootTree.init(allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/config", "before\n", .{ .mode = 0o644 });

    _ = try ext4.populate(io, image.file, allocator, try tree.ext4View(), .{
        .offset = lvm_test_root_offset,
        .length = lvm_test_root_length,
        .label = "lvm-root",
        .uuid = [_]u8{0x77} ** 16,
        .timestamp = 1_735_689_600,
    });
}

test "a logical volume can be named wherever a partition can" {
    const io = std.testing.io;
    const source_path = "test-preserved-image-lvm-source.raw";
    const output_path = "test-preserved-image-lvm-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.raw") catch {};
    try createLvmTestDisk(io, source_path, "");

    const operations = [_]Operation{
        .{ .overwrite_file = .{
            .path = "/etc/config",
            .source = .{ .bytes = "after\n" },
        } },
    };
    const report = try edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .logical_volume = .{ .logical_volume = "root" } },
        .operations = &operations,
    });
    // The reported extent is the volume's, not the partition's: the
    // filesystem starts where the volume does, one pe_start past the
    // physical volume.
    try std.testing.expectEqual(lvm_test_root_offset, report.partition_offset);
    try std.testing.expectEqual(lvm_test_root_length, report.partition_length);

    var output = try Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    var reader = try ext4.open(io, output.file, std.testing.allocator, .{
        .offset = lvm_test_root_offset,
    });
    defer reader.deinit();
    const config = try reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(config);
    try std.testing.expectEqualStrings("after\n", config);

    // Naming the volume group explicitly reaches the same volume.
    try std.testing.expectEqual(lvm_test_root_offset, (try selectPartition(
        std.testing.allocator,
        io,
        output,
        .{ .logical_volume = .{ .volume_group = "vg", .logical_volume = "root" } },
    )).offset);
}

test "a logical volume selector names the volume it cannot reach" {
    const io = std.testing.io;
    const source_path = "test-preserved-image-lvm-refuse.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};

    // A second volume on a thin pool, which is exactly the kind of mapping
    // that must be refused rather than read as if it were linear.
    try createLvmTestDisk(io, source_path,
        \\data {
        \\id = "LV1111-0000-0000-0000-0000-0000-000000"
        \\status = ["READ", "WRITE", "VISIBLE"]
        \\segment_count = 1
        \\segment1 {
        \\start_extent = 0
        \\extent_count = 2
        \\type = "thin"
        \\stripe_count = 1
        \\stripes = ["pv0", 4]
        \\}
        \\}
    );

    var image = try Image.openPathReadOnly(io, source_path);
    defer image.close(io);

    try std.testing.expectError(error.UnsupportedLvmThinSegment, selectPartition(
        std.testing.allocator,
        io,
        image,
        .{ .logical_volume = .{ .logical_volume = "data" } },
    ));
    try std.testing.expectError(error.LogicalVolumeNotFound, selectPartition(
        std.testing.allocator,
        io,
        image,
        .{ .logical_volume = .{ .logical_volume = "swap" } },
    ));
    try std.testing.expectError(error.LvmVolumeGroupNotFound, selectPartition(
        std.testing.allocator,
        io,
        image,
        .{ .logical_volume = .{ .volume_group = "other", .logical_volume = "root" } },
    ));

    // A logical volume has no PARTUUID, and inventing one would name a
    // device the kernel will never publish.
    var buffer: [identity_rewrite.canonical_uuid_bytes]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), try partitionUuidText(
        std.testing.allocator,
        io,
        image,
        .{ .logical_volume = .{ .logical_volume = "root" } },
        &buffer,
    ));
}

test "preserved editor publishes a gzip-compressed raw artifact" {
    const io = std.testing.io;
    const source_path = "test-preserved-image-gzip-source.raw";
    const plain_path = "test-preserved-image-gzip-plain.raw";
    const output_path = "test-preserved-image-gzip-output.raw.gz";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, plain_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, plain_path ++ ".native-edit.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.output") catch {};
    try createTestDisk(io, source_path);

    const operations = [_]Operation{
        .{ .overwrite_file = .{
            .path = "/etc/config",
            .source = .{ .bytes = "after\n" },
        } },
    };
    _ = try edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = plain_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .operations = &operations,
        .expected_virtual_size = test_disk_size,
    });
    _ = try edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .output_compression = .gzip,
        .root_partition = .{ .mbr_index = 1 },
        .operations = &operations,
        .expected_virtual_size = test_disk_size,
    });

    // Neither staging artifact may survive a successful publication.
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, output_path ++ ".native-edit.raw", .{}),
    );
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, output_path ++ ".native-edit.output", .{}),
    );

    const expected = try Io.Dir.cwd().readFileAlloc(
        io,
        plain_path,
        std.testing.allocator,
        .limited(test_disk_size + 1),
    );
    defer std.testing.allocator.free(expected);
    const compressed = try Io.Dir.cwd().readFileAlloc(
        io,
        output_path,
        std.testing.allocator,
        .limited(test_disk_size + 1),
    );
    defer std.testing.allocator.free(compressed);
    try std.testing.expect(compressed.len < expected.len);

    var compressed_reader: Io.Reader = .fixed(compressed);
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var decompress: std.compress.flate.Decompress = .init(&compressed_reader, .gzip, &history);
    const decoded = try decompress.reader.allocRemaining(
        std.testing.allocator,
        .limited(test_disk_size + 1),
    );
    defer std.testing.allocator.free(decoded);
    try std.testing.expectEqualSlices(u8, expected, decoded);
}

test "preserved editor publishes standalone qcow2 and cleans failed staging" {
    const io = std.testing.io;
    const raw_path = "test-preserved-image-base.raw";
    const base_path = "test-preserved-image-base.qcow2";
    const source_path = "test-preserved-image-overlay.qcow2";
    const output_path = "test-preserved-image-result.qcow2";
    const failed_path = "test-preserved-image-failed.qcow2";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, base_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.raw") catch {};
    defer Io.Dir.cwd().deleteFile(io, failed_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, failed_path ++ ".native-edit.raw") catch {};
    try createTestDisk(io, raw_path);
    {
        var raw = try Image.openPathReadOnly(io, raw_path);
        defer raw.close(io);
        var qcow = try Image.createExclusive(io, base_path, .qcow2, test_disk_size, .{});
        defer qcow.close(io);
        try image_mod.copyAll(io, raw, &qcow, std.testing.allocator);
    }
    {
        var overlay = try Image.createExclusive(io, source_path, .qcow2, test_disk_size, .{});
        overlay.close(io);
        const file = try Io.Dir.cwd().openFile(io, source_path, .{ .mode = .read_write });
        defer file.close(io);
        var header: [104]u8 = undefined;
        if (try file.readPositionalAll(io, &header, 0) != header.len) {
            return error.UnexpectedEndOfFile;
        }
        const backing_offset = std.mem.readInt(u32, header[100..104], .big);
        std.mem.writeInt(u64, header[8..16], backing_offset, .big);
        std.mem.writeInt(u32, header[16..20], base_path.len, .big);
        try file.writePositionalAll(io, &header, 0);
        try file.writePositionalAll(io, base_path, backing_offset);
    }
    const source_before = try hashTestPath(io, source_path);
    const base_before = try hashTestPath(io, base_path);

    const operation = [_]Operation{.{ .overwrite_file = .{
        .path = "/etc/config",
        .source = .{ .bytes = "qcow2\n" },
    } }};
    const report = try edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .qcow2,
        .root_partition = .{ .mbr_index = 1 },
        .operations = &operation,
    });
    try std.testing.expect(report.flattened_backing_chain);
    try std.testing.expectEqualSlices(u8, &source_before, &(try hashTestPath(io, source_path)));
    try std.testing.expectEqualSlices(u8, &base_before, &(try hashTestPath(io, base_path)));
    var output = try Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    try std.testing.expectEqual(Format.qcow2, output.format);
    try std.testing.expectEqual(@as(u8, 0), output.qcow2.?.backing_depth);
    try std.testing.expectEqual(@as(u16, 0), output.qcow2.?.backing_file_len);

    const invalid = [_]Operation{.{ .overwrite_file = .{
        .path = "/etc/missing",
        .source = .{ .bytes = "nope" },
    } }};
    try std.testing.expectError(error.NotFound, edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = failed_path,
        .output_format = .qcow2,
        .root_partition = .{ .mbr_index = 1 },
        .operations = &invalid,
    }));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, failed_path, .{}));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, failed_path ++ ".native-edit.raw", .{}));
}

test "preserved editor does not replace an existing output" {
    const io = std.testing.io;
    const source_path = "test-preserved-existing-source.raw";
    const output_path = "test-preserved-existing-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.raw") catch {};
    try createTestDisk(io, source_path);
    {
        const output = try Io.Dir.cwd().createFile(io, output_path, .{});
        defer output.close(io);
        try output.writePositionalAll(io, "preserve-me", 0);
    }

    try std.testing.expectError(error.PathAlreadyExists, edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .operations = &.{},
    }));

    const output = try Io.Dir.cwd().openFile(io, output_path, .{});
    defer output.close(io);
    var bytes: ["preserve-me".len]u8 = undefined;
    _ = try output.readPositionalAll(io, &bytes, 0);
    try std.testing.expectEqualStrings("preserve-me", &bytes);
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, output_path ++ ".native-edit.raw", .{}),
    );
}

test "preserved editor rejects reversed GPT partition extents" {
    const io = std.testing.io;
    const source_path = "test-preserved-reversed-gpt.raw";
    const output_path = "test-preserved-reversed-gpt-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path ++ ".native-edit.raw") catch {};

    const disk_size: u64 = 2 * 1024 * 1024;
    {
        var image = try Image.createExclusive(io, source_path, .raw, disk_size, .{});
        defer image.close(io);
        const protective = mbr.protectiveMbr(disk_size / mbr.sector_size).encode();
        try image.pwrite(io, &protective, 0);

        var entries = [_]u8{0} ** (gpt.default_num_partition_entries * gpt.partition_entry_size);
        entries[0..16].* = [_]u8{1} ** 16;
        entries[16..32].* = [_]u8{2} ** 16;
        std.mem.writeInt(u64, entries[32..40], 100, .little);
        std.mem.writeInt(u64, entries[40..48], 99, .little);
        const header = (gpt.Header{
            .current_lba = 1,
            .backup_lba = disk_size / gpt.sector_size - 1,
            .first_usable_lba = 34,
            .last_usable_lba = disk_size / gpt.sector_size - 34,
            .disk_guid = [_]u8{3} ** 16,
            .partition_entry_lba = 2,
            .partition_array_crc32 = std.hash.crc.Crc32.hash(&entries),
        }).encode();
        try image.pwrite(io, &header, gpt.sector_size);
        try image.pwrite(io, &entries, gpt.sector_size * 2);
    }

    try std.testing.expectError(error.InvalidPartitionBounds, edit(std.testing.allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .gpt_index = 1 },
        .operations = &.{},
    }));
}

test "preserved editor rejects overlapping GPT partitions and metadata" {
    const disk_size: u64 = 2 * 1024 * 1024;
    const total_lbas = disk_size / gpt.sector_size;
    const header = gpt.Header{
        .current_lba = 1,
        .backup_lba = total_lbas - 1,
        .first_usable_lba = 34,
        .last_usable_lba = total_lbas - 34,
        .disk_guid = [_]u8{3} ** 16,
        .partition_entry_lba = 2,
        .partition_array_crc32 = 0,
    };

    var overlapping = [_]gpt.PartitionEntry{
        .{ .table_index = 0, .first_lba = 100, .last_lba = 200 },
        .{ .table_index = 1, .first_lba = 150, .last_lba = 250 },
    };
    try std.testing.expectError(error.InvalidPartitionBounds, validateGptLayout(.{
        .header = header,
        .partitions = &overlapping,
    }, disk_size));

    var metadata_overlap = [_]gpt.PartitionEntry{
        .{ .table_index = 0, .first_lba = 2, .last_lba = 40 },
    };
    var permissive_header = header;
    permissive_header.first_usable_lba = 1;
    try std.testing.expectError(error.InvalidPartitionBounds, validateGptLayout(.{
        .header = permissive_header,
        .partitions = &metadata_overlap,
    }, disk_size));
}

test "workspace requirement counts the spool copy of the imported content" {
    const space = workspaceRequirement(
        35 * 1024 * 1024 * 1024,
        40 * 1024 * 1024 * 1024,
        .raw,
        .none,
        null,
    );

    try std.testing.expectEqual(@as(u64, 35 * 1024 * 1024 * 1024), space.spool_bytes);
    try std.testing.expectEqual(@as(u64, 40 * 1024 * 1024 * 1024), space.stage_bytes);
    // A raw uncompressed artifact is the renamed stage, so it costs nothing.
    try std.testing.expectEqual(@as(u64, 0), space.publish_bytes);
    try std.testing.expectEqual(@as(u64, 75 * 1024 * 1024 * 1024), space.required_bytes);
}

test "a converted or compressed artifact coexists with the stage that fed it" {
    const converted = workspaceRequirement(10, 100, .qcow2, .none, null);
    try std.testing.expectEqual(@as(u64, 100), converted.publish_bytes);
    try std.testing.expectEqual(@as(u64, 210), converted.required_bytes);

    const compressed = workspaceRequirement(10, 100, .raw, .gzip, null);
    try std.testing.expectEqual(@as(u64, 100), compressed.publish_bytes);
    try std.testing.expectEqual(@as(u64, 210), compressed.required_bytes);
}

test "unknown free space is not too little free space" {
    const unknown = workspaceRequirement(10, 100, .raw, .none, null);
    try std.testing.expect(unknown.isSufficient());

    const ample = workspaceRequirement(10, 100, .raw, .none, 110);
    try std.testing.expect(ample.isSufficient());

    const short = workspaceRequirement(10, 100, .raw, .none, 109);
    try std.testing.expect(!short.isSufficient());
}

test "an unmeasurable workspace saturates instead of wrapping" {
    const space = workspaceRequirement(
        std.math.maxInt(u64),
        std.math.maxInt(u64),
        .qcow2,
        .none,
        0,
    );

    try std.testing.expectEqual(std.math.maxInt(u64), space.required_bytes);
    try std.testing.expect(!space.isSufficient());
}

// ---------------------------------------------------------------------------
// General-profile rebuild
//
// The source here is built by `mke2fs` with its own ext4 defaults, so it
// carries the exact feature set the strict importer exists to refuse. That is
// the only way to prove the general path end to end: a fixture this project
// wrote would prove nothing, because the strict path already accepts it.
// ---------------------------------------------------------------------------

const general_fixture_source = "test-preserved-general-src";
const general_fixture_image = "test-preserved-general.img";
const general_fixture_blocks: u64 = @as(u64, test_partition_sectors) * mbr.sector_size / 4096;

fn runGeneralFixtureTool(
    allocator: std.mem.Allocator,
    name: []const u8,
    args: []const []const u8,
) !void {
    // e2fsprogs installs into `sbin`, which an unprivileged `PATH` often omits.
    const prefixes = [_][]const u8{ "", "/sbin/", "/usr/sbin/" };
    for (prefixes) |prefix| {
        const binary = try std.fmt.allocPrint(allocator, "{s}{s}", .{ prefix, name });
        defer allocator.free(binary);
        const argv = try allocator.alloc([]const u8, args.len + 1);
        defer allocator.free(argv);
        argv[0] = binary;
        @memcpy(argv[1..], args);
        const result = std.process.run(allocator, std.testing.io, .{
            .argv = argv,
            .cwd = .{ .path = "." },
        }) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        switch (result.term) {
            .exited => |code| if (code != 0) {
                std.debug.print("{s} failed (exit {d}):\n{s}\n{s}\n", .{
                    name,
                    code,
                    result.stdout,
                    result.stderr,
                });
                return error.ExternalToolFailed;
            },
            else => return error.ExternalToolFailed,
        }
        return;
    }
    // Without e2fsprogs there is no honest way to run this; declining beats
    // passing on a filesystem this project wrote itself.
    return error.SkipZigTest;
}

fn writeGeneralFixtureFile(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

fn createGeneralTestDisk(allocator: std.mem.Allocator, io: Io, path: []const u8) !void {
    const cwd = Io.Dir.cwd();
    cwd.deleteTree(io, general_fixture_source) catch {};
    cwd.deleteFile(io, general_fixture_image) catch {};
    defer cwd.deleteTree(io, general_fixture_source) catch {};
    defer cwd.deleteFile(io, general_fixture_image) catch {};

    try cwd.createDirPath(io, general_fixture_source ++ "/etc");
    try cwd.createDirPath(io, general_fixture_source ++ "/usr/bin");
    try cwd.createDirPath(io, general_fixture_source ++ "/dev");
    try writeGeneralFixtureFile(io, general_fixture_source ++ "/etc/hostname", "general-root\n");
    try writeGeneralFixtureFile(io, general_fixture_source ++ "/usr/bin/tool", "tool\n");
    try cwd.hardLink(
        general_fixture_source ++ "/usr/bin/tool",
        cwd,
        general_fixture_source ++ "/usr/bin/tool-alias",
        io,
        .{},
    );
    try cwd.symLink(io, "../usr/bin/tool", general_fixture_source ++ "/etc/tool-link", .{});

    var size_text: [32]u8 = undefined;
    try runGeneralFixtureTool(allocator, "mke2fs", &.{
        "-q",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-I",
        "256",
        "-d",
        general_fixture_source,
        general_fixture_image,
        try std.fmt.bufPrint(&size_text, "{d}", .{general_fixture_blocks}),
    });

    const script_path = "test-preserved-general-debugfs.txt";
    defer cwd.deleteFile(io, script_path) catch {};
    try writeGeneralFixtureFile(io, script_path,
        \\sif / mode 040755
        \\sif / uid 0
        \\sif / gid 0
        \\cd /dev
        \\mknod console c 5 1
        \\mknod initctl p
        \\sif /dev/console mode 020600
        \\sif /dev/initctl mode 010600
        \\sif /etc/hostname mode 0100640
        \\sif /etc/hostname uid 1234
        \\sif /etc/hostname gid 5678
        \\sif /etc/hostname mtime @1400000000
        \\sif /etc/hostname crtime @1200000000
        \\ea_set /etc/hostname security.selinux system_u:object_r:etc_t:s0
        \\quit
        \\
    );
    try runGeneralFixtureTool(allocator, "debugfs", &.{
        "-w",
        "-f",
        script_path,
        general_fixture_image,
    });

    var image = try Image.createExclusive(io, path, .raw, test_disk_size, .{});
    defer image.close(io);
    const boot_record = mbr.singleLinuxPartitionMbr(test_partition_first_lba, test_partition_sectors);
    const encoded_mbr = boot_record.encode();
    try image.pwrite(io, &encoded_mbr, 0);

    const fixture = try cwd.openFile(io, general_fixture_image, .{});
    defer fixture.close(io);
    const buffer = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(buffer);
    var offset: u64 = 0;
    const total = @as(u64, test_partition_sectors) * mbr.sector_size;
    while (offset < total) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), total - offset));
        const got = try fixture.readPositionalAll(io, buffer[0..wanted], offset);
        if (got == 0) return error.UnexpectedEndOfFile;
        try image.pwrite(io, buffer[0..got], (@as(u64, test_partition_first_lba) * mbr.sector_size) + offset);
        offset += got;
    }
}

test "general rebuild imports a stock mke2fs source and preserves its metadata" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-general-source.raw";
    const output_path = "test-preserved-general-output.raw";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createGeneralTestDisk(allocator, io, source_path) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const strict_options = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .source_date_epoch = 1_735_689_600,
        .expected_virtual_size = test_disk_size,
    };
    // The default profile must keep refusing exactly what it always refused.
    // Which of its guards fires first is incidental -- a stock filesystem
    // violates several of them at once -- so only the refusal is asserted.
    if (rebuild(allocator, io, strict_options)) |_| {
        return error.StrictProfileAcceptedForeignSource;
    } else |err| switch (err) {
        error.DivergentSuperblockTimestamp,
        error.UnsupportedInodeSize,
        error.UnsupportedFeatures,
        => {},
        else => return err,
    }
    try expectRebuildArtifactsMissing(io, output_path);

    var general_options = strict_options;
    general_options.source_profile = .general;
    const report = try rebuild(allocator, io, general_options);
    try std.testing.expectEqual(ext4.SourceProfile.ext4_general_v1, report.source_profile);
    try std.testing.expect(!report.source_reproducible);

    var output = try Image.openPath(io, output_path);
    defer output.close(io);
    var reader = try ext4.openGeneral(io, output.file, allocator, .{
        .offset = @as(u64, test_partition_first_lba) * mbr.sector_size,
    });
    defer reader.deinit();
    var tree = try ext4.scanReadable(&reader, io, allocator, .{
        .available_length = @as(u64, test_partition_sectors) * mbr.sector_size,
    });
    defer tree.deinit();

    var saw_hardlink = false;
    var saw_device = false;
    var saw_fifo = false;
    var saw_symlink = false;
    var saw_hostname = false;
    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        if (std.mem.eql(u8, entry.path, "usr/bin/tool-alias")) {
            saw_hardlink = true;
            try std.testing.expectEqual(ext4.GeneralKind.hardlink, entry.kind);
            try std.testing.expectEqualStrings("usr/bin/tool", entry.hardlink_target);
        }
        if (std.mem.eql(u8, entry.path, "dev/console")) {
            saw_device = true;
            try std.testing.expectEqual(ext4.GeneralKind.char_device, entry.kind);
            try std.testing.expectEqual(@as(u32, 5), entry.device.major);
            try std.testing.expectEqual(@as(u32, 1), entry.device.minor);
            try std.testing.expectEqual(@as(u16, 0o600), entry.mode);
        }
        if (std.mem.eql(u8, entry.path, "dev/initctl")) {
            saw_fifo = true;
            try std.testing.expectEqual(ext4.GeneralKind.fifo, entry.kind);
        }
        if (std.mem.eql(u8, entry.path, "etc/tool-link")) {
            saw_symlink = true;
            try std.testing.expectEqual(ext4.GeneralKind.symlink, entry.kind);
        }
        if (std.mem.eql(u8, entry.path, "etc/hostname")) {
            saw_hostname = true;
            try std.testing.expectEqual(@as(u16, 0o640), entry.mode);
            try std.testing.expectEqual(@as(u32, 1234), entry.uid);
            try std.testing.expectEqual(@as(u32, 5678), entry.gid);
            try std.testing.expectEqual(@as(i64, 1_400_000_000), entry.mtime);
            // The creation time is the source's, not this rebuild's. A
            // captured system's files were created when they were created,
            // and a rebuild that restamped them all with the build time
            // would erase the one fact `crtime` exists to record.
            try std.testing.expectEqual(@as(?i64, 1_200_000_000), entry.crtime);
            var found = false;
            for (entry.xattrs) |xattr| {
                if (!std.mem.eql(u8, xattr.name, "security.selinux")) continue;
                try std.testing.expectEqualStrings(
                    "system_u:object_r:etc_t:s0",
                    xattr.value,
                );
                found = true;
            }
            try std.testing.expect(found);
        }
    }
    try std.testing.expect(saw_hardlink);
    try std.testing.expect(saw_device);
    try std.testing.expect(saw_fifo);
    try std.testing.expect(saw_symlink);
    try std.testing.expect(saw_hostname);
}

test "a rebuild reports the source journal and only writes one when asked" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-journal-source.raw";
    const plain_path = "test-preserved-journal-plain.raw";
    const journalled_path = "test-preserved-journal-output.raw";
    const artifacts = [_][]const u8{
        source_path,
        plain_path,
        plain_path ++ ".native-rebuild.raw",
        plain_path ++ ".native-rebuild.output",
        plain_path ++ ".native-rebuild.spool",
        journalled_path,
        journalled_path ++ ".native-rebuild.raw",
        journalled_path ++ ".native-rebuild.output",
        journalled_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createGeneralTestDisk(allocator, io, source_path) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const base = RebuildOptions{
        .source_path = source_path,
        .output_path = plain_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 1 },
        .source_profile = .general,
        .source_date_epoch = 1_735_689_600,
        .expected_virtual_size = test_disk_size,
    };

    // `mke2fs -t ext4` journals by default, so the source has one and the
    // default rebuild silently drops it -- which is exactly why the report
    // has to say so.
    const plain = try rebuild(allocator, io, base);
    try std.testing.expect(plain.source_has_journal);
    try std.testing.expectEqual(@as(u32, 0), plain.journal_block_count);

    var journalled_options = base;
    journalled_options.output_path = journalled_path;
    journalled_options.journal = .{ .enabled = true };
    const journalled = try rebuild(allocator, io, journalled_options);
    try std.testing.expect(journalled.source_has_journal);
    // 24 MiB of partition is 6144 blocks, the ladder's first tier.
    try std.testing.expectEqual(@as(u32, 1024), journalled.journal_block_count);

    const partition_offset = @as(u64, test_partition_first_lba) * mbr.sector_size;
    var output = try Image.openPath(io, journalled_path);
    defer output.close(io);
    var reader = try ext4.openGeneral(io, output.file, allocator, .{ .offset = partition_offset });
    defer reader.deinit();
    var tree = try ext4.scanReadable(&reader, io, allocator, .{
        .available_length = @as(u64, test_partition_sectors) * mbr.sector_size,
    });
    defer tree.deinit();
    try std.testing.expect(tree.identity.has_journal);
    try std.testing.expectEqual(ext4.SourceProfile.ext4_general_v1, tree.identity.profile);

    // The tree itself has to survive the journal untouched.
    var saw_hostname = false;
    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        if (!std.mem.eql(u8, entry.path, "etc/hostname")) continue;
        saw_hostname = true;
        try std.testing.expectEqual(@as(u32, 1234), entry.uid);
    }
    try std.testing.expect(saw_hostname);
}

// A realistic installed layout: an ESP, a separate `/boot`, and the root
// filesystem, all on one disk. The rebuild collapses the first two into
// directories inside the third.
const merge_disk_size: u64 = 96 * 1024 * 1024;
const merge_esp_first_lba: u32 = 2048;
const merge_esp_sectors: u32 = 48 * 2048;
const merge_boot_first_lba: u32 = merge_esp_first_lba + merge_esp_sectors;
const merge_boot_sectors: u32 = 8 * 2048;
const merge_root_first_lba: u32 = merge_boot_first_lba + merge_boot_sectors;
const merge_root_sectors: u32 = 24 * 2048;
const esp_partition_type: mbr.PartitionType = @enumFromInt(0xEF);

const merge_root_fixture_dir = "test-preserved-merge-root-src";
const merge_boot_fixture_dir = "test-preserved-merge-boot-src";
const merge_root_fixture_image = "test-preserved-merge-root.img";
const merge_boot_fixture_image = "test-preserved-merge-boot.img";

// Pinned so the fixture's own `/etc/fstab` and `grub.cfg` can name the
// filesystems literally. A generated UUID would force the expected text to be
// assembled at run time, and an expectation assembled by the same code that
// produced the output proves nothing about byte-for-byte preservation.
const merge_root_fs_uuid = "11111111-2222-3333-4444-555555555555";
const merge_boot_fs_uuid = "66666666-7777-8888-9999-aaaaaaaaaaaa";
const merge_disk_signature: u32 = 0xC0FFEE01;
const merge_esp_partuuid = "c0ffee01-01";
const merge_boot_partuuid = "c0ffee01-02";
const merge_root_partuuid = "c0ffee01-03";
/// `fat32.format`'s default volume id, as `blkid` and an fstab spell it.
const merge_esp_serial = "5A56-4D49";

// Tabs are written as escapes rather than in a `\\` literal, which Zig does
// not allow them in -- and the exact whitespace is the point of the test.
const merge_fstab_header =
    "# /etc/fstab: static filesystem information.\n" ++
    "#\n" ++
    "# <file system>\t<mount point>\t<type>\t<options>\t<dump>\t<pass>\n" ++
    "UUID=" ++ merge_root_fs_uuid ++ "\t/\text4\terrors=remount-ro\t0\t1\n";
const merge_fstab_boot_entry =
    "UUID=" ++ merge_boot_fs_uuid ++ "\t/boot\text4\tdefaults\t0\t2\n";
const merge_fstab_esp_entry =
    "UUID=" ++ merge_esp_serial ++ "   /boot/efi    vfat    umask=0077,shortname=mixed  0  1\n";
const merge_fstab_tail =
    "tmpfs\t/tmp\ttmpfs\tdefaults,nosuid,nodev\t0\t0\n" ++
    "# The two entries below have nothing to do with the rebuild and must\n" ++
    "# survive it exactly as written, odd spacing and all.\n" ++
    "/swapfile     none            swap    sw              0       0\n" ++
    "PARTUUID=" ++ merge_root_partuuid ++ "\t/srv\text4\tdefaults\t0\t2\n" ++
    "//fileserver/share\t/mnt/share\tcifs\tguest,_netdev\t0\t0";
const merge_fstab = merge_fstab_header ++
    merge_fstab_boot_entry ++
    merge_fstab_esp_entry ++
    merge_fstab_tail;
/// What the rewriter has to produce: the two merged-away mounts gone, and
/// every other byte, including the missing final newline, untouched.
const merge_fstab_expected = merge_fstab_header ++ merge_fstab_tail;

const merge_default_grub =
    "GRUB_DEFAULT=0\n" ++
    "GRUB_TIMEOUT=5\n" ++
    "GRUB_CMDLINE_LINUX=\"root=UUID=" ++ merge_root_fs_uuid ++ " ro\"\n";

const merge_grub_cfg =
    "set default=0\n" ++
    "insmod ext2\n" ++
    "set root='hd0,msdos2'\n" ++
    "search --no-floppy --fs-uuid --set=root " ++ merge_boot_fs_uuid ++ "\n" ++
    "menuentry 'Linux' {\n" ++
    "\tlinux\t/vmlinuz-6.1 root=UUID=" ++ merge_root_fs_uuid ++ " ro quiet\n" ++
    "\tinitrd\t/initrd.img-6.1\n" ++
    "}\n";
const merge_grub_cfg_expected =
    "set default=0\n" ++
    "insmod ext2\n" ++
    "set root='hd0,msdos2'\n" ++
    "search --no-floppy --fs-uuid --set=root " ++ merge_root_fs_uuid ++ "\n" ++
    "menuentry 'Linux' {\n" ++
    "\tlinux\t/vmlinuz-6.1 root=UUID=" ++ merge_root_fs_uuid ++ " ro quiet\n" ++
    "\tinitrd\t/initrd.img-6.1\n" ++
    "}\n";

const merge_esp_grub_cfg =
    "search.fs_uuid " ++ merge_esp_serial ++ " root\n" ++
    "set prefix=($root)'/EFI/BOOT'\n" ++
    "linux /vmlinuz-6.1 root=PARTUUID=" ++ merge_boot_partuuid ++ " ro\n";
const merge_esp_grub_cfg_expected =
    "search.fs_uuid " ++ merge_root_fs_uuid ++ " root\n" ++
    "set prefix=($root)'/EFI/BOOT'\n" ++
    "linux /vmlinuz-6.1 root=PARTUUID=" ++ merge_root_partuuid ++ " ro\n";

const MergeFixtureOptions = struct {
    /// Writes a `/boot/grub/i386-pc/core.img` carrying the boot filesystem's
    /// UUID. GRUB really does embed it there, in a binary the text rewriter
    /// deliberately will not touch, which makes it the honest way to
    /// exercise the verification pass rather than a contrived one.
    embed_unrewritable_uuid: bool = false,
};

fn buildMergeExt4Fixture(
    allocator: std.mem.Allocator,
    directory: []const u8,
    image_path: []const u8,
    sectors: u32,
    uuid: []const u8,
) !void {
    var size_text: [32]u8 = undefined;
    const blocks = @as(u64, sectors) * mbr.sector_size / 4096;
    try runGeneralFixtureTool(allocator, "mke2fs", &.{
        "-q",
        "-t",
        "ext4",
        "-b",
        "4096",
        "-I",
        "256",
        "-U",
        uuid,
        "-d",
        directory,
        image_path,
        try std.fmt.bufPrint(&size_text, "{d}", .{blocks}),
    });
}

fn copyFixtureIntoPartition(
    allocator: std.mem.Allocator,
    io: Io,
    image: *Image,
    fixture_path: []const u8,
    first_lba: u32,
    sectors: u32,
) !void {
    const fixture = try Io.Dir.cwd().openFile(io, fixture_path, .{});
    defer fixture.close(io);
    const buffer = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(buffer);
    const total = @as(u64, sectors) * mbr.sector_size;
    const base = @as(u64, first_lba) * mbr.sector_size;
    var offset: u64 = 0;
    while (offset < total) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), total - offset));
        const got = try fixture.readPositionalAll(io, buffer[0..wanted], offset);
        if (got == 0) return error.UnexpectedEndOfFile;
        try image.pwrite(io, buffer[0..got], base + offset);
        offset += got;
    }
}

fn createMergeTestDisk(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    fixture: MergeFixtureOptions,
) !void {
    const cwd = Io.Dir.cwd();
    cwd.deleteTree(io, merge_root_fixture_dir) catch {};
    cwd.deleteTree(io, merge_boot_fixture_dir) catch {};
    cwd.deleteFile(io, merge_root_fixture_image) catch {};
    cwd.deleteFile(io, merge_boot_fixture_image) catch {};
    defer cwd.deleteTree(io, merge_root_fixture_dir) catch {};
    defer cwd.deleteTree(io, merge_boot_fixture_dir) catch {};
    defer cwd.deleteFile(io, merge_root_fixture_image) catch {};
    defer cwd.deleteFile(io, merge_boot_fixture_image) catch {};

    // The root filesystem's own `/boot` is a non-empty stub, which is what
    // makes shadowing rather than merging the only correct rule.
    try cwd.createDirPath(io, merge_root_fixture_dir ++ "/boot/stale-dir");
    try cwd.createDirPath(io, merge_root_fixture_dir ++ "/etc");
    try cwd.createDirPath(io, merge_root_fixture_dir ++ "/usr/bin");
    try writeGeneralFixtureFile(io, merge_root_fixture_dir ++ "/etc/hostname", "merged\n");
    try writeGeneralFixtureFile(io, merge_root_fixture_dir ++ "/etc/fstab", merge_fstab);
    try cwd.createDirPath(io, merge_root_fixture_dir ++ "/etc/default");
    try writeGeneralFixtureFile(
        io,
        merge_root_fixture_dir ++ "/etc/default/grub",
        merge_default_grub,
    );
    try writeGeneralFixtureFile(io, merge_root_fixture_dir ++ "/usr/bin/tool", "tool\n");
    try cwd.hardLink(
        merge_root_fixture_dir ++ "/usr/bin/tool",
        cwd,
        merge_root_fixture_dir ++ "/usr/bin/tool-alias",
        io,
        .{},
    );
    try writeGeneralFixtureFile(io, merge_root_fixture_dir ++ "/boot/stale-vmlinuz", "stale\n");
    try writeGeneralFixtureFile(
        io,
        merge_root_fixture_dir ++ "/boot/stale-dir/stale.cfg",
        "stale\n",
    );
    try buildMergeExt4Fixture(
        allocator,
        merge_root_fixture_dir,
        merge_root_fixture_image,
        merge_root_sectors,
        merge_root_fs_uuid,
    );

    // `/boot/efi` has to exist in the boot filesystem, because that is the
    // tree the ESP is mounted onto once `/boot` is in place.
    try cwd.createDirPath(io, merge_boot_fixture_dir ++ "/efi");
    try cwd.createDirPath(io, merge_boot_fixture_dir ++ "/grub");
    try writeGeneralFixtureFile(io, merge_boot_fixture_dir ++ "/vmlinuz-6.1", "real kernel\n");
    try writeGeneralFixtureFile(
        io,
        merge_boot_fixture_dir ++ "/grub/grub.cfg",
        merge_grub_cfg,
    );
    if (fixture.embed_unrewritable_uuid) {
        try cwd.createDirPath(io, merge_boot_fixture_dir ++ "/grub/i386-pc");
        try writeGeneralFixtureFile(
            io,
            merge_boot_fixture_dir ++ "/grub/i386-pc/core.img",
            "\x7fELF\x00\x00" ++ merge_boot_fs_uuid ++ "\x00\xff\xfe",
        );
    }
    try buildMergeExt4Fixture(
        allocator,
        merge_boot_fixture_dir,
        merge_boot_fixture_image,
        merge_boot_sectors,
        merge_boot_fs_uuid,
    );

    const script_path = "test-preserved-merge-debugfs.txt";
    defer cwd.deleteFile(io, script_path) catch {};
    try writeGeneralFixtureFile(io, script_path,
        \\sif /vmlinuz-6.1 mode 0100640
        \\sif /vmlinuz-6.1 uid 4242
        \\sif /vmlinuz-6.1 gid 4343
        \\ea_set /vmlinuz-6.1 security.selinux system_u:object_r:boot_t:s0
        \\quit
        \\
    );
    try runGeneralFixtureTool(allocator, "debugfs", &.{
        "-w",
        "-f",
        script_path,
        merge_boot_fixture_image,
    });

    var image = try Image.createExclusive(io, path, .raw, merge_disk_size, .{});
    defer image.close(io);

    var boot_record = mbr.Mbr{};
    // A real disk has one, and without one Linux synthesizes no PARTUUID at
    // all, so a zero here would quietly disable half of what is being tested.
    boot_record.disk_signature = merge_disk_signature;
    boot_record.entries[0] = .{
        .bootable = true,
        .partition_type = esp_partition_type,
        .first_lba = merge_esp_first_lba,
        .sector_count = merge_esp_sectors,
    };
    boot_record.entries[1] = .{
        .partition_type = .linux,
        .first_lba = merge_boot_first_lba,
        .sector_count = merge_boot_sectors,
    };
    boot_record.entries[2] = .{
        .partition_type = .linux,
        .first_lba = merge_root_first_lba,
        .sector_count = merge_root_sectors,
    };
    const encoded_mbr = boot_record.encode();
    try image.pwrite(io, &encoded_mbr, 0);

    // mkfs.vfat is not installed anywhere this runs, so the ESP is written
    // with this project's own FAT32 writer.
    const esp_offset = @as(u64, merge_esp_first_lba) * mbr.sector_size;
    const esp_length = @as(u64, merge_esp_sectors) * mbr.sector_size;
    try fat32.format(&image, io, .{
        .partition_offset = esp_offset,
        .partition_len = esp_length,
    });
    var esp = try fat32.open(&image, io, .{ .offset = esp_offset, .length = esp_length });
    try esp.createDir(io, "EFI/BOOT");
    try esp.writeFile(io, "EFI/BOOT/bootx64.efi", "esp payload\n");
    try esp.writeFile(io, "EFI/BOOT/grub.cfg", merge_esp_grub_cfg);

    try copyFixtureIntoPartition(
        allocator,
        io,
        &image,
        merge_boot_fixture_image,
        merge_boot_first_lba,
        merge_boot_sectors,
    );
    try copyFixtureIntoPartition(
        allocator,
        io,
        &image,
        merge_root_fixture_image,
        merge_root_first_lba,
        merge_root_sectors,
    );
}

/// Copies one partition out of a disk so an external tool that only knows how
/// to open a whole filesystem can be pointed at it.
fn extractPartition(
    allocator: std.mem.Allocator,
    io: Io,
    image: *Image,
    first_lba: u32,
    sectors: u32,
    path: []const u8,
) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    const buffer = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(buffer);
    const total = @as(u64, sectors) * mbr.sector_size;
    const base = @as(u64, first_lba) * mbr.sector_size;
    var offset: u64 = 0;
    while (offset < total) {
        const wanted: usize = @intCast(@min(@as(u64, buffer.len), total - offset));
        if (try image.pread(io, buffer[0..wanted], base + offset) != wanted) {
            return error.UnexpectedEndOfFile;
        }
        try file.writePositionalAll(io, buffer[0..wanted], offset);
        offset += wanted;
    }
}

test "rebuild merges an ESP and a boot filesystem into one root filesystem" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-merge-source.raw";
    const output_path = "test-preserved-merge-output.raw";
    const extracted_path = "test-preserved-merge-extracted.img";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        extracted_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createMergeTestDisk(allocator, io, source_path, .{}) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    // Deliberately non-default, to prove the synthesized FAT metadata is a
    // caller's choice rather than a constant baked into the importer.
    const esp_metadata = fat32.SynthesizedMetadata{
        .directory_mode = 0o700,
        .file_mode = 0o600,
        .uid = 42,
        .gid = 43,
    };
    const mounts = [_]SourceMount{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{
            .partition = .{ .mbr_index = 1 },
            .target = "/boot/efi",
            .fat_metadata = esp_metadata,
        },
    };
    const options = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_mounts = &mounts,
        .source_date_epoch = 1_735_689_600,
        .expected_virtual_size = merge_disk_size,
    };

    const inspection = try inspectRebuild(allocator, io, options);
    try std.testing.expectEqual(@as(usize, 2), inspection.merged_source_count);
    try std.testing.expect(!inspection.source_reproducible);

    const report = try rebuild(allocator, io, options);
    try std.testing.expectEqual(@as(usize, 2), report.merged_source_count);
    // `boot/stale-vmlinuz`, `boot/stale-dir` and `boot/stale-dir/stale.cfg`:
    // the whole stub the real boot filesystem hides.
    try std.testing.expectEqual(@as(usize, 3), report.shadowed_node_count);
    try std.testing.expectEqual(inspection.shadowed_node_count, report.shadowed_node_count);
    try std.testing.expectEqual(inspection.imported_node_count, report.imported_node_count);
    // Merging makes the output a function of three sources, not of the one
    // the report names, so it can no longer be claimed reproducible from it.
    try std.testing.expect(!report.source_reproducible);

    var output = try Image.openPath(io, output_path);
    defer output.close(io);

    // Acceptance criterion: the ESP is still a partition of its own on the
    // output disk, untouched, even though its contents are now also a
    // directory inside the root filesystem.
    var sector: [mbr.sector_size]u8 = undefined;
    try std.testing.expectEqual(sector.len, try output.pread(io, &sector, 0));
    const table = try mbr.Mbr.decode(&sector);
    try std.testing.expectEqual(esp_partition_type, table.entries[0].partition_type);
    try std.testing.expectEqual(merge_esp_sectors, table.entries[0].sector_count);
    var esp_boot: [512]u8 = undefined;
    const esp_offset = @as(u64, merge_esp_first_lba) * mbr.sector_size;
    try std.testing.expectEqual(esp_boot.len, try output.pread(io, &esp_boot, esp_offset));
    try std.testing.expectEqualSlices(u8, "FAT32   ", esp_boot[82..90]);

    var reader = try ext4.openGeneral(io, output.file, allocator, .{
        .offset = @as(u64, merge_root_first_lba) * mbr.sector_size,
    });
    defer reader.deinit();
    var tree = try ext4.scanReadable(&reader, io, allocator, .{
        .available_length = @as(u64, merge_root_sectors) * mbr.sector_size,
    });
    defer tree.deinit();

    var saw_boot_dir = false;
    var saw_efi_dir = false;
    var saw_kernel = false;
    var saw_payload = false;
    var saw_esp_dir = false;
    var saw_hardlink = false;
    var index: usize = 0;
    while (index < tree.nodeCount()) : (index += 1) {
        const entry = tree.entryAt(index);
        // Shadowing must be replacement, not a merge: nothing the root
        // source had under `/boot` may survive the boot filesystem landing
        // on top of it.
        try std.testing.expect(!std.mem.eql(u8, entry.path, "boot/stale-vmlinuz"));
        try std.testing.expect(!std.mem.eql(u8, entry.path, "boot/stale-dir"));
        try std.testing.expect(!std.mem.eql(u8, entry.path, "boot/stale-dir/stale.cfg"));

        if (std.mem.eql(u8, entry.path, "boot")) {
            saw_boot_dir = true;
            try std.testing.expectEqual(ext4.GeneralKind.directory, entry.kind);
        }
        if (std.mem.eql(u8, entry.path, "boot/efi")) {
            saw_efi_dir = true;
            try std.testing.expectEqual(ext4.GeneralKind.directory, entry.kind);
            // The mount point takes the mounted filesystem's root metadata,
            // exactly as a real mount does.
            try std.testing.expectEqual(esp_metadata.directory_mode, entry.mode);
            try std.testing.expectEqual(esp_metadata.uid, entry.uid);
            try std.testing.expectEqual(esp_metadata.gid, entry.gid);
        }
        if (std.mem.eql(u8, entry.path, "boot/vmlinuz-6.1")) {
            saw_kernel = true;
            try std.testing.expectEqual(ext4.GeneralKind.file, entry.kind);
            // Ownership, mode and xattrs survived being merged, not just
            // being imported.
            try std.testing.expectEqual(@as(u16, 0o640), entry.mode);
            try std.testing.expectEqual(@as(u32, 4242), entry.uid);
            try std.testing.expectEqual(@as(u32, 4343), entry.gid);
            var found = false;
            for (entry.xattrs) |xattr| {
                if (!std.mem.eql(u8, xattr.name, "security.selinux")) continue;
                try std.testing.expectEqualStrings(
                    "system_u:object_r:boot_t:s0",
                    xattr.value,
                );
                found = true;
            }
            try std.testing.expect(found);
        }
        if (std.mem.eql(u8, entry.path, "boot/efi/EFI")) {
            saw_esp_dir = true;
            try std.testing.expectEqual(esp_metadata.directory_mode, entry.mode);
        }
        if (std.mem.eql(u8, entry.path, "boot/efi/EFI/BOOT/bootx64.efi")) {
            saw_payload = true;
            try std.testing.expectEqual(ext4.GeneralKind.file, entry.kind);
            try std.testing.expectEqual(esp_metadata.file_mode, entry.mode);
            try std.testing.expectEqual(esp_metadata.uid, entry.uid);
            try std.testing.expectEqual(esp_metadata.gid, entry.gid);
            try std.testing.expectEqual(@as(u64, "esp payload\n".len), entry.size);
        }
        // Acceptance criterion: a hardlink pair wholly inside the root
        // source is still a hardlink pair after the merge.
        if (std.mem.eql(u8, entry.path, "usr/bin/tool-alias")) {
            saw_hardlink = true;
            try std.testing.expectEqual(ext4.GeneralKind.hardlink, entry.kind);
            try std.testing.expectEqualStrings("usr/bin/tool", entry.hardlink_target);
        }
    }
    try std.testing.expect(saw_boot_dir);
    try std.testing.expect(saw_efi_dir);
    try std.testing.expect(saw_kernel);
    try std.testing.expect(saw_esp_dir);
    try std.testing.expect(saw_payload);
    try std.testing.expect(saw_hardlink);

    try extractPartition(
        allocator,
        io,
        &output,
        merge_root_first_lba,
        merge_root_sectors,
        extracted_path,
    );
    try runGeneralFixtureTool(allocator, "e2fsck", &.{ "-f", "-n", extracted_path });
}

/// Reads one file out of the rebuilt root filesystem of a merge fixture's
/// output disk, which is where every identity-rewrite expectation is checked.
fn readMergedRootFile(
    allocator: std.mem.Allocator,
    io: Io,
    output_path: []const u8,
    path: []const u8,
) ![]u8 {
    var output = try Image.openPath(io, output_path);
    defer output.close(io);
    var reader = try ext4.openGeneral(io, output.file, allocator, .{
        .offset = @as(u64, merge_root_first_lba) * mbr.sector_size,
    });
    defer reader.deinit();
    return reader.readFileAlloc(io, allocator, path);
}

test "a merged rebuild rewrites the identifiers it retired and preserves every other fstab byte" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-identity-source.raw";
    const output_path = "test-preserved-identity-output.raw";
    const extracted_path = "test-preserved-identity-extracted.img";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        extracted_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createMergeTestDisk(allocator, io, source_path, .{}) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const mounts = [_]SourceMount{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
    };
    const options = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_mounts = &mounts,
        .source_date_epoch = 1_735_689_600,
    };

    // Inspection runs the same rewrite and the same verification pass, so it
    // has to agree with the rebuild about what would happen.
    const inspection = try inspectRebuild(allocator, io, options);
    const report = try rebuild(allocator, io, options);
    try std.testing.expectEqual(
        inspection.identity_rewrite.fstab_entries_dropped,
        report.identity_rewrite.fstab_entries_dropped,
    );
    try std.testing.expectEqual(
        inspection.identity_rewrite.config_references_rewritten,
        report.identity_rewrite.config_references_rewritten,
    );

    // `/boot` and `/boot/efi` are directories inside the root filesystem now,
    // so both entries go; nothing is left to rewrite in an fstab.
    try std.testing.expectEqual(@as(usize, 2), report.identity_rewrite.fstab_entries_dropped);
    try std.testing.expectEqual(@as(usize, 0), report.identity_rewrite.fstab_entries_rewritten);
    try std.testing.expectEqual(@as(usize, 0), report.identity_rewrite.fstab_entries_unresolved);
    // `search --fs-uuid` in `/boot/grub/grub.cfg`, plus `search.fs_uuid` and
    // `root=PARTUUID=` in the ESP's own configuration.
    try std.testing.expectEqual(@as(usize, 3), report.identity_rewrite.config_references_rewritten);
    try std.testing.expectEqual(@as(usize, 2), report.identity_rewrite.config_files_rewritten);
    try std.testing.expectEqual(@as(usize, 0), report.identity_rewrite.stale_references);
    try std.testing.expect(report.identity_rewrite.verified_files > 0);

    // Acceptance criterion: unrelated fstab entries survive byte for byte,
    // including the tabs, the run-on spacing, the comments and the absent
    // final newline. The expectation is a literal, not something the
    // rewriter's own logic produced.
    const fstab = try readMergedRootFile(allocator, io, output_path, "/etc/fstab");
    defer allocator.free(fstab);
    try std.testing.expectEqualStrings(merge_fstab_expected, fstab);

    // Acceptance criterion: the bootloader configuration is rewritten in
    // place, so its menu structure, indentation and unrelated lines are the
    // ones the distro shipped.
    const grub_cfg = try readMergedRootFile(allocator, io, output_path, "/boot/grub/grub.cfg");
    defer allocator.free(grub_cfg);
    try std.testing.expectEqualStrings(merge_grub_cfg_expected, grub_cfg);

    const esp_cfg = try readMergedRootFile(
        allocator,
        io,
        output_path,
        "/boot/efi/EFI/BOOT/grub.cfg",
    );
    defer allocator.free(esp_cfg);
    try std.testing.expectEqualStrings(merge_esp_grub_cfg_expected, esp_cfg);

    // A file in the scanned set that names nothing retired is read and left
    // exactly alone; being in scope is not a licence to touch it.
    const default_grub = try readMergedRootFile(allocator, io, output_path, "/etc/default/grub");
    defer allocator.free(default_grub);
    try std.testing.expectEqualStrings(merge_default_grub, default_grub);

    var output = try Image.openPath(io, output_path);
    defer output.close(io);
    try extractPartition(
        allocator,
        io,
        &output,
        merge_root_first_lba,
        merge_root_sectors,
        extracted_path,
    );
    try runGeneralFixtureTool(allocator, "e2fsck", &.{ "-f", "-n", extracted_path });
}

test "a stale identifier the rewriter cannot reach fails the build and names the file" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-stale-source.raw";
    const output_path = "test-preserved-stale-output.raw";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createMergeTestDisk(allocator, io, source_path, .{
        .embed_unrewritable_uuid = true,
    }) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const mounts = [_]SourceMount{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
    };
    var diagnostic = identity_rewrite.Diagnostic{};
    var options = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_mounts = &mounts,
        .source_date_epoch = 1_735_689_600,
        .identity_diagnostic = &diagnostic,
    };

    // Acceptance criterion: a retired identifier left anywhere the pass looks
    // fails the build, and the message names the file holding it.
    try std.testing.expectError(
        error.StaleFilesystemIdentifier,
        rebuild(allocator, io, options),
    );
    const stale = diagnostic.stale orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("boot/grub/i386-pc/core.img", stale.path());
    try std.testing.expectEqualStrings(merge_boot_fs_uuid, stale.identifier());
    try std.testing.expectEqual(identity_rewrite.Kind.filesystem_uuid, stale.kind);
    var message: [identity_rewrite.Stale.max_message_bytes]u8 = undefined;
    const described = try stale.describe(&message);
    try std.testing.expect(std.mem.containsAtLeast(
        u8,
        described,
        1,
        "/boot/grub/i386-pc/core.img",
    ));

    // Nothing may be left behind: the refusal happens before the first
    // output byte is written.
    for (artifacts[1..]) |artifact| {
        try std.testing.expectError(
            error.FileNotFound,
            Io.Dir.cwd().statFile(io, artifact, .{}),
        );
    }

    // The same source, inspected, is refused for the same reason without
    // creating anything at all.
    var inspect_diagnostic = identity_rewrite.Diagnostic{};
    options.identity_diagnostic = &inspect_diagnostic;
    try std.testing.expectError(
        error.StaleFilesystemIdentifier,
        inspectRebuild(allocator, io, options),
    );
    try std.testing.expect(inspect_diagnostic.stale != null);

    // The escape hatch: an operator who intends to finish the job with the
    // distro's own tooling gets the image and the report, not a refusal.
    var reported = identity_rewrite.Diagnostic{};
    options.identity_rewrite = .rewrite_only;
    options.identity_diagnostic = &reported;
    const report = try rebuild(allocator, io, options);
    try std.testing.expectEqual(@as(usize, 1), report.identity_rewrite.stale_references);
    try std.testing.expectEqualStrings(
        "boot/grub/i386-pc/core.img",
        (reported.stale orelse return error.TestUnexpectedResult).path(),
    );
    // Everything the rewriter could reach was still reached.
    try std.testing.expectEqual(@as(usize, 2), report.identity_rewrite.fstab_entries_dropped);
    const fstab = try readMergedRootFile(allocator, io, output_path, "/etc/fstab");
    defer allocator.free(fstab);
    try std.testing.expectEqualStrings(merge_fstab_expected, fstab);
}

test "identity rewriting turned off leaves the imported configuration exactly as it was" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-identity-off-source.raw";
    const output_path = "test-preserved-identity-off-output.raw";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createMergeTestDisk(allocator, io, source_path, .{
        .embed_unrewritable_uuid = true,
    }) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const mounts = [_]SourceMount{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
    };
    const report = try rebuild(allocator, io, .{
        .source_path = source_path,
        .output_path = output_path,
        .expected_source_format = .raw,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_mounts = &mounts,
        .source_date_epoch = 1_735_689_600,
        .identity_rewrite = .off,
    });
    // `.off` is not "rewrite quietly": the report says nothing happened,
    // which is what distinguishes it from a rewrite that found nothing.
    try std.testing.expectEqual(@as(usize, 0), report.identity_rewrite.retired_identifiers);
    try std.testing.expectEqual(@as(usize, 0), report.identity_rewrite.verified_files);

    const fstab = try readMergedRootFile(allocator, io, output_path, "/etc/fstab");
    defer allocator.free(fstab);
    try std.testing.expectEqualStrings(merge_fstab, fstab);
    const grub_cfg = try readMergedRootFile(allocator, io, output_path, "/boot/grub/grub.cfg");
    defer allocator.free(grub_cfg);
    try std.testing.expectEqualStrings(merge_grub_cfg, grub_cfg);
}

test "merged sources are refused before anything is opened when the mounts are ambiguous" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-merge-reject-source.raw";
    const output_path = "test-preserved-merge-reject-output.raw";
    const artifacts = [_][]const u8{
        source_path,
        output_path,
        output_path ++ ".native-rebuild.raw",
        output_path ++ ".native-rebuild.output",
        output_path ++ ".native-rebuild.spool",
    };
    defer for (artifacts) |artifact| Io.Dir.cwd().deleteFile(io, artifact) catch {};
    createMergeTestDisk(allocator, io, source_path, .{}) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const base = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_date_epoch = 1_735_689_600,
    };
    const boot = SourceMount{ .partition = .{ .mbr_index = 2 }, .target = "/boot" };

    const Case = struct {
        mounts: []const SourceMount,
        expected: anyerror,
    };
    const cases = [_]Case{
        .{
            .mounts = &.{ boot, .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" } },
            .expected = error.DuplicateMountTarget,
        },
        .{
            .mounts = &.{
                .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
                boot,
            },
            .expected = error.MountTargetShadowedByLaterMount,
        },
        .{
            .mounts = &.{.{ .partition = .{ .mbr_index = 2 }, .target = "boot" }},
            .expected = error.MountTargetNotAbsolute,
        },
        .{
            .mounts = &.{.{ .partition = .{ .mbr_index = 2 }, .target = "/boot/" }},
            .expected = error.MountTargetNotNormalized,
        },
        .{
            .mounts = &.{.{ .partition = .{ .mbr_index = 2 }, .target = "/" }},
            .expected = error.MountTargetIsRoot,
        },
        // `/etc/hostname` is a file in the root source, and `/nowhere` is
        // nothing at all. Neither is a mount point a real mount would accept.
        .{
            .mounts = &.{.{ .partition = .{ .mbr_index = 2 }, .target = "/etc/hostname" }},
            .expected = error.MountTargetNotDirectory,
        },
        .{
            .mounts = &.{.{ .partition = .{ .mbr_index = 2 }, .target = "/nowhere" }},
            .expected = error.MissingMountTarget,
        },
        // The ESP is vfat, so the ext4 reader must not be handed it.
        .{
            .mounts = &.{.{
                .partition = .{ .mbr_index = 1 },
                .target = "/boot",
                .filesystem = .ext4,
            }},
            .expected = error.BadMagic,
        },
    };
    for (cases) |case| {
        var options = base;
        options.source_mounts = case.mounts;
        try std.testing.expectError(case.expected, rebuild(allocator, io, options));
        try expectRebuildArtifactsMissing(io, output_path);
    }
}

test "filesystem detection names a merged source or refuses to guess" {
    const io = std.testing.io;
    const path = "test-preserved-detect.raw";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const length: u64 = 64 * 1024 * 1024;
    var image = try Image.create(io, path, .raw, length, .{});
    defer image.close(io);
    const partition = Partition{ .offset = 0, .length = length };

    // All zeros is neither, and a rebuild must say so rather than pick one.
    try std.testing.expectError(
        error.UnrecognizedSourceFilesystem,
        resolveFilesystem(image, io, partition, .detect),
    );

    try fat32.format(&image, io, .{ .partition_offset = 0, .partition_len = length });
    try std.testing.expectEqual(
        ResolvedFilesystem.fat32,
        try resolveFilesystem(image, io, partition, .detect),
    );

    // An ext4 superblock magic on top of the FAT boot sector describes two
    // filesystems at once, which is corruption, not a preference.
    var magic: [2]u8 = undefined;
    std.mem.writeInt(u16, &magic, 0xEF53, .little);
    try image.pwrite(io, &magic, 1024 + 0x38);
    try std.testing.expectError(
        error.AmbiguousSourceFilesystem,
        resolveFilesystem(image, io, partition, .detect),
    );

    // A caller that already knows is never made to probe.
    try std.testing.expectEqual(
        ResolvedFilesystem.ext4,
        try resolveFilesystem(image, io, partition, .ext4),
    );
}

test "limits and peaks are accounted across every merged source, not per source" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const source_path = "test-preserved-merge-limits-source.raw";
    const output_path = "test-preserved-merge-limits-output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    createMergeTestDisk(allocator, io, source_path, .{}) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    var base = RebuildOptions{
        .source_path = source_path,
        .output_path = output_path,
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_date_epoch = 1_735_689_600,
    };
    const mounts = [_]SourceMount{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
    };

    var root_only = limits_mod.Diagnostic{};
    base.limit_diagnostic = &root_only;
    const alone = try inspectRebuild(allocator, io, base);

    var combined = limits_mod.Diagnostic{};
    var merged_options = base;
    merged_options.source_mounts = &mounts;
    merged_options.limit_diagnostic = &combined;
    const merged = try inspectRebuild(allocator, io, merged_options);

    // The peaks are sums over the sources, not the largest single source.
    try std.testing.expect(combined.peaks.nodes > root_only.peaks.nodes);
    try std.testing.expect(combined.peaks.total_bytes > root_only.peaks.total_bytes);
    // And the spool has to hold every source's bytes, so the workspace
    // requirement grows with them.
    try std.testing.expect(
        merged.workspace_space.spool_bytes > alone.workspace_space.spool_bytes,
    );

    // One below the combined total is still comfortably above what any one
    // source needs on its own, so a per-source accounting would accept this
    // import. A combined one must not.
    const ceiling = combined.peaks.nodes - 1;
    try std.testing.expect(ceiling >= root_only.peaks.nodes);

    var breached = limits_mod.Diagnostic{};
    var capped = merged_options;
    capped.limit_diagnostic = &breached;
    capped.limits.max_nodes = @intCast(ceiling);
    try std.testing.expectError(
        error.NodeLimitExceeded,
        inspectRebuild(allocator, io, capped),
    );
    const breach = breached.exceeded orelse return error.MissingBreach;
    try std.testing.expectEqual(limits_mod.Limit.nodes, breach.limit);
    // The reported limit is the one the flag was set to. A scan that tripped
    // the reduced per-source cap must never report the remainder, because no
    // flag can be raised above a number that was never configured.
    try std.testing.expectEqual(ceiling, breach.configured);
    try std.testing.expect(breach.observed > breach.configured);
}

test "a source whose scan fails leaves nothing behind for cleanup to walk" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;

    const source_path = ".test-merge-failed-scan-cleanup.img";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    createMergeTestDisk(allocator, io, source_path, .{}) catch |err| switch (err) {
        error.SkipZigTest => return error.SkipZigTest,
        else => return err,
    };

    const options = RebuildOptions{
        .source_path = source_path,
        .output_path = ".test-merge-failed-scan-cleanup.out",
        .output_format = .raw,
        .root_partition = .{ .mbr_index = 3 },
        .source_profile = .general,
        .source_date_epoch = 1_735_689_600,
    };

    // Both source kinds, because each publishes its scanned tree through its
    // own branch and each has to leave the field alone when the scan fails.
    // A partially assigned tree is invisible until the cleanup path walks it,
    // and what it walks then is undefined memory: the failure surfaces as a
    // fault somewhere else entirely, if it surfaces at all.
    const cases = [_]SourceMount{
        .{ .partition = .{ .mbr_index = 2 }, .target = "/boot" },
        .{ .partition = .{ .mbr_index = 1 }, .target = "/boot/efi" },
    };
    for (cases) |spec| {
        var budget = CombinedBudget{ .limits = .{ .max_nodes = 1 }, .sink = null };
        var mount = MountedSource{ .target = spec.target };
        defer mount.deinit(io);
        try std.testing.expectError(
            error.NodeLimitExceeded,
            mount.open(allocator, io, spec, options, source_path, &budget),
        );
        try std.testing.expect(mount.tree == null);
        try std.testing.expectEqual(@as(usize, 0), mount.nodeCount());
    }
}
