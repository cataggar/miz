//! Transactional mutation/rebuild of an existing disk through a full raw
//! staging copy. `edit` changes only existing paths; `rebuild` strictly
//! imports the narrow writer-compatible ext4 profile before applying pure OS
//! customization. `inspectRebuild` performs the same source preflight without
//! creating any files. Sources are always read-only.

const std = @import("std");
const ext4 = @import("ext4.zig");
const Format = @import("formats.zig").Format;
const free_space = @import("free_space.zig");
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const limits_mod = @import("limits.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const mbr = @import("mbr.zig");
const os_customization = @import("os_customization.zig");
const output_mod = @import("output.zig");
const root_tree = @import("root_tree.zig");

const Io = std.Io;
const Allocator = std.mem.Allocator;

/// `edit` enforces only the replacement-file limit, but it is the same limit,
/// with the same flag, that a rebuild enforces.
const limit_defaults = limits_mod.ImportLimits{};

pub const PartitionSelector = union(enum) {
    /// One-based slot in the GPT partition entry array.
    gpt_index: u32,
    /// One-based slot in the four-entry MBR partition table.
    mbr_index: u8,
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
    /// Compresses the published artifact as it is written. Only `.raw`
    /// output can be compressed: every other format amends metadata after
    /// the data it already wrote, which a compressor cannot revisit.
    output_compression: output_mod.Compression = .none,
};

pub const WorkspaceSpacePolicy = enum {
    enforce,
    report_only,
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
    strict_profile: ext4.StrictProfile,
    ext4_uuid: [16]u8,
    /// Exact preserved ext4 volume-name field.
    ext4_label: [16]u8,
    ext4_block_size: u32,
    filesystem_length: u64,
    ext4_global_timestamp: u32,
    source_manifest_sha256: [32]u8,
    final_manifest_sha256: [32]u8,
    /// RootTree node counts exclude its implicit root directory.
    imported_node_count: usize,
    final_node_count: usize,
    existing_operation_count: usize,
    os_customization_count: usize,
    generalization_count: usize,
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
    strict_profile: ext4.StrictProfile,
    ext4_uuid: [16]u8,
    ext4_label: [16]u8,
    ext4_block_size: u32,
    filesystem_length: u64,
    ext4_global_timestamp: u32,
    /// Excludes the implicit root directory.
    imported_node_count: usize,
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
    var scanned = try ext4.scanWriterCompatible(&reader, io, allocator, strictScanOptions(
        options,
        partition.length,
    ));
    defer scanned.deinit();
    try preflightScannedOperations(scanned.fileTreeView(), options.existing_operations);

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
    );
    var validation_tree = root_tree.RootTree.initMemory(allocator, io, options.limits.tree());
    validation_tree.diagnostic = options.limit_diagnostic;
    defer validation_tree.deinit();
    try validation_tree.importExt4ViewBorrowed(scanned.fileTreeView());
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
    _ = try ext4.preflightPopulate(
        allocator,
        try validation_tree.ext4View(),
        .{
            .offset = partition.offset,
            .length = scanned.identity.filesystem_length,
            .block_size = scanned.identity.block_size,
            .label = &scanned.identity.label,
            .uuid = scanned.identity.uuid,
            .timestamp = scanned.identity.global_timestamp,
        },
    );

    return .{
        .source_format = source.format,
        .virtual_size = source.virtual_size,
        .partition_offset = partition.offset,
        .partition_length = partition.length,
        .flattened_backing_chain = if (source.qcow2) |info| info.backing_depth != 0 else false,
        .strict_profile = scanned.identity.profile,
        .ext4_uuid = scanned.identity.uuid,
        .ext4_label = scanned.identity.label,
        .ext4_block_size = scanned.identity.block_size,
        .filesystem_length = scanned.identity.filesystem_length,
        .ext4_global_timestamp = scanned.identity.global_timestamp,
        .imported_node_count = scanned.nodeCount(),
        .limit_peaks = if (options.limit_diagnostic) |sink| sink.peaks else .{},
        .workspace_space = workspaceSpace(
            output_path,
            scanned.content_bytes,
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
    var scanned = try ext4.scanWriterCompatible(
        &reader,
        io,
        allocator,
        strictScanOptions(options, partition.length),
    );
    defer scanned.deinit();

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
    );

    // The workspace precondition runs before the spool file exists, so a
    // workspace that cannot hold the import fails now rather than after
    // however long it takes to copy most of a root filesystem into it.
    const workspace = workspaceSpace(
        output_path,
        scanned.content_bytes,
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
    try tree.importExt4View(scanned.fileTreeView());
    const imported_node_count = tree.nodeCount();
    if (imported_node_count != scanned.nodeCount()) return error.ImportedNodeCountMismatch;
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
    _ = try ext4.populate(io, raw.file, allocator, final_view, .{
        .offset = partition.offset,
        .length = scanned.identity.filesystem_length,
        .block_size = scanned.identity.block_size,
        .label = &scanned.identity.label,
        .uuid = scanned.identity.uuid,
        .timestamp = scanned.identity.global_timestamp,
    });
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
        .strict_profile = scanned.identity.profile,
        .ext4_uuid = scanned.identity.uuid,
        .ext4_label = scanned.identity.label,
        .ext4_block_size = scanned.identity.block_size,
        .filesystem_length = scanned.identity.filesystem_length,
        .ext4_global_timestamp = scanned.identity.global_timestamp,
        .source_manifest_sha256 = source_manifest,
        .final_manifest_sha256 = final_manifest,
        .imported_node_count = imported_node_count,
        .final_node_count = final_node_count,
        .existing_operation_count = options.existing_operations.len,
        .os_customization_count = customizationCount(options.customization),
        .generalization_count = generalizationCount(options.generalization),
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
    };
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

fn strictScanOptions(options: RebuildOptions, partition_length: u64) ext4.StrictScanOptions {
    return .{
        .expected_length = partition_length,
        .max_nodes = options.limits.max_nodes,
        .max_path_bytes = options.limits.max_path_bytes,
        .max_component_bytes = options.limits.max_component_bytes,
        .max_file_bytes = options.limits.max_file_bytes,
        .max_total_bytes = options.limits.max_total_bytes,
        .max_xattrs_per_node = options.limits.max_xattrs_per_node,
        .max_xattr_bytes_per_node = options.limits.max_xattr_bytes_per_node,
        .max_scan_metadata_bytes = options.limits.max_scan_metadata_bytes,
        .diagnostic = options.limit_diagnostic,
    };
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
) !void {
    const artifacts = [_][]const u8{ output_path, raw_path, output_stage_path, spool_path };
    for (artifacts, 0..) |path, index| {
        if (std.mem.eql(u8, path, source_path)) return error.SourceOutputConflict;
        for (artifacts[index + 1 ..]) |other| {
            if (std.mem.eql(u8, path, other)) return error.SourceOutputConflict;
        }
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

fn selectPartition(
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
    };
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
    try std.testing.expectEqual(ext4.StrictProfile.zvmi_ext4_v1, inspection.strict_profile);
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

    try std.testing.expectEqual(ext4.StrictProfile.zvmi_ext4_v1, report.strict_profile);
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
