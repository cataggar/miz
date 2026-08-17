//! `build-iso`: generate a customized LiveOS ISO from a source ISO plus an OCI
//! container image.
//!
//! Unlike `build-image`, which flattens the source ISO's LiveOS payload and the
//! container into a single installed disk filesystem, `build-iso` keeps the
//! optical layout: it reuses `build_image.materializeCustomizedRootTree` to
//! build exactly the same customized owned root tree, writes that tree to a
//! deterministic ext4 `rootfs.img`, wraps the image in a native zstd SquashFS
//! at the conventional LiveOS payload path, and regenerates the ISO from the
//! source's ordinary directory tree with that one payload replaced. Boot files
//! and configuration are retained verbatim; El Torito boot entries are
//! recreated explicitly with the native writer.
//!
//! An ISO is an optical artifact, not a disk block format, so it is never a
//! `formats.Format` and this module never claims to be one. What it emits are
//! filesystem contents -- the directory tree, the replaced payload, and the
//! boot catalog -- not arbitrary preserved byte regions from the source image.

const std = @import("std");
const Io = std.Io;

const bootconfig = @import("bootconfig.zig");
const build_image = @import("build_image.zig");
const ext4 = @import("ext4.zig");
const iso9660 = @import("iso9660.zig");
const limits_mod = @import("limits.zig");
const oci = @import("oci.zig");
const os_customization = @import("os_customization.zig");
const root_tree_mod = @import("root_tree.zig");
const squashfs = @import("squashfs.zig");

pub const EventSink = build_image.EventSink;

pub const StageSink = struct {
    context: ?*anyopaque = null,
    advanceFn: *const fn (context: ?*anyopaque, stage: Stage) bool,

    pub fn advance(self: StageSink, stage: Stage) bool {
        return self.advanceFn(self.context, stage);
    }
};

/// Conventional LiveOS payload path: a SquashFS holding the root filesystem.
pub const default_payload_path = "LiveOS/squashfs.img";
/// Conventional path of the ext4 root image nested inside the SquashFS, where
/// dracut's `dmsquash-live` module looks for it.
pub const default_nested_rootfs_path = "LiveOS/rootfs.img";
/// Fallback volume identifier when the source ISO's own cannot be read.
pub const default_volume_id = "VMIZ";

const scratch_infix = "build-iso";
const copy_chunk_size: usize = 1024 * 1024;

/// El Torito firmware platform of a boot entry.
pub const BootPlatform = enum {
    bios,
    uefi,

    fn writerPlatform(self: BootPlatform) iso9660.BootPlatform {
        return switch (self) {
            .bios => .bios,
            .uefi => .uefi,
        };
    }

    pub fn displayName(self: BootPlatform) []const u8 {
        return switch (self) {
            .bios => "bios",
            .uefi => "uefi",
        };
    }
};

/// A boot image the caller names explicitly. `image_path` is root-relative
/// (no leading slash) within the output ISO tree; it must resolve to a regular
/// file, or the build fails precisely with `error.BootImageNotFound`.
pub const BootImage = struct {
    platform: BootPlatform,
    image_path: []const u8,
};

/// Fixed values that make a build byte-for-byte reproducible. Leave null for a
/// one-off build stamped with the wall clock and a random filesystem UUID.
pub const Determinism = struct {
    /// POSIX-seconds timestamp stamped into the ext4 superblock/inodes, the
    /// SquashFS superblock, the ISO recording dates, and inodes customization
    /// creates.
    filesystem_timestamp: u32,
    /// The ext4 root filesystem UUID.
    root_filesystem_uuid: [16]u8,
};

pub const BuildIsoOptions = struct {
    /// Source LiveOS ISO. Its directory tree, boot files, and volume id are
    /// reused; its LiveOS payload is replaced.
    iso_path: []const u8,
    /// OCI image-layout directory or docker/podman `save` archive whose
    /// content is overlaid onto the customized root tree.
    container_path: []const u8,
    oci_load_options: oci.LoadOptions = .{},
    /// Where the generated ISO is written. Published atomically.
    output_path: []const u8,
    /// Size in bytes of the ext4 `rootfs.img` before it is wrapped in SquashFS.
    /// Rounded up to the ext4 block size. Must be large enough to hold the
    /// customized tree, or the build fails with a precise ext4 error.
    rootfs_size: u64,
    /// LiveOS payload path in the source ISO to replace. Null discovers it the
    /// same way `build-image` does (highest-scoring `*.squashfs`/`rootfs`/
    /// `.img` candidate). The regenerated SquashFS is written back to exactly
    /// this path.
    rootfs_path_in_iso: ?[]const u8 = null,
    /// Path of the ext4 image nested inside the regenerated SquashFS.
    nested_rootfs_path: []const u8 = default_nested_rootfs_path,
    /// See `build_image.BuildImageOptions.skip_iso_rootfs`.
    skip_iso_rootfs: bool = false,
    os: os_customization.OsCustomization = .{},
    generalization: os_customization.GeneralizationPolicy = .none,
    architecture: ?bootconfig.Architecture = null,
    limits: root_tree_mod.Limits = .{},
    limit_diagnostic: ?*limits_mod.Diagnostic = null,
    /// ext4 root filesystem label.
    ext4_label: []const u8 = "rootfs",
    /// JBD2 journal policy for the ext4 root image.
    ext4_journal: ext4.JournalOptions = .{},
    /// SELinux context for the ext4 root inode (a trailing NUL is added).
    root_selinux_label: ?[]const u8 = null,
    /// SquashFS block compression. Native zstd by default.
    squashfs_compression: squashfs.WriterCompression = .zstd,
    /// Volume identifier of the output ISO. Null reuses the source ISO's.
    volume_id: ?[]const u8 = null,
    /// El Torito boot entries. When empty, common source layouts are probed;
    /// at least one entry (UEFI-only is fine) must end up resolved.
    boot_images: []const BootImage = &.{},
    determinism: ?Determinism = null,
    event_sink: ?EventSink = null,
    stage_sink: ?StageSink = null,
    dry_run: bool = false,
    verbose: bool = false,
};

pub const BootEntryReport = struct {
    platform: BootPlatform,
    image_path: []u8,
};

pub const Stage = enum {
    load_sources,
    apply_filesystem_changes,
    generalize_and_cleanup,
    write_rootfs_image,
    wrap_squashfs_payload,
    assemble_iso_tree,
    write_iso,
    publish_output,
};

pub const BuildIsoReport = struct {
    architecture: bootconfig.Architecture,
    dry_run: bool,
    /// The LiveOS payload path the regenerated SquashFS was written to.
    rootfs_path_in_iso: []u8,
    /// Path of the ext4 image nested inside the SquashFS.
    nested_rootfs_path: []u8,
    /// ext4 `rootfs.img` size after block rounding.
    rootfs_size: u64,
    root_tree_digest: ?[32]u8 = null,
    /// Output ISO volume identifier.
    volume_id: []u8,
    squashfs_compression: squashfs.WriterCompression,
    boot_entries: []BootEntryReport,
    /// Total output ISO size in bytes (0 for a dry run).
    output_size: u64 = 0,
    /// SHA-256 of the published ISO (all zero for a dry run).
    output_sha256: [32]u8 = [_]u8{0} ** 32,
    limit_peaks: limits_mod.Peaks = .{},

    pub fn deinit(self: *BuildIsoReport, allocator: std.mem.Allocator) void {
        allocator.free(self.rootfs_path_in_iso);
        allocator.free(self.nested_rootfs_path);
        allocator.free(self.volume_id);
        for (self.boot_entries) |entry| allocator.free(entry.image_path);
        allocator.free(self.boot_entries);
        self.* = undefined;
    }
};

fn logStep(options: BuildIsoOptions, message: []const u8) void {
    if (options.event_sink) |sink| {
        sink.emit(.{ .progress = message });
    } else if (options.verbose) {
        std.debug.print("build-iso: {s}\n", .{message});
    }
}

fn enterStage(options: BuildIsoOptions, stage: Stage) !void {
    if (options.stage_sink) |sink| {
        if (!sink.advance(stage)) return error.InvalidOperationOrder;
    }
}

/// Bridges the shared `build_image` materialization stages onto this module's
/// stage sink. Materialization advances `build_image.Stage`, whose value set is
/// a superset of ours (it also covers disk-partition steps build-iso never
/// runs). Only the two materialization stages build-iso declares are forwarded;
/// `load_sources` stays emitted directly by `build`, and any unrelated
/// `build_image` stage is rejected so it cannot leak into build-iso's sequence.
/// `recustomize-iso` shares it (its stage set is identical).
pub const MaterializeStageBridge = struct {
    sink: StageSink,

    pub fn advance(context: ?*anyopaque, stage: build_image.Stage) bool {
        const self: *MaterializeStageBridge = @ptrCast(@alignCast(context.?));
        const mapped: Stage = switch (stage) {
            .apply_filesystem_changes => .apply_filesystem_changes,
            .generalize_and_cleanup => .generalize_and_cleanup,
            else => return false,
        };
        return self.sink.advance(mapped);
    }
};

pub const BuildIsoError = error{
    NoBootImage,
    BootImageNotFound,
    DuplicateBootPlatform,
    UnsupportedContainerArchitecture,
    ContainerArchitectureMismatch,
    InvalidRootSelinuxLabel,
    InvalidSystemTime,
    SourcePathConflict,
    ZeroRootfsSize,
};

pub fn build(
    allocator: std.mem.Allocator,
    io: Io,
    options: BuildIsoOptions,
) !BuildIsoReport {
    try enterStage(options, .load_sources);
    if (options.rootfs_size == 0) return error.ZeroRootfsSize;
    try validateBuildPathIsolation(allocator, io, options);

    logStep(options, "load container image");
    var container_image = try oci.load(io, allocator, options.container_path, options.oci_load_options);
    var container_image_open = true;
    defer if (container_image_open) container_image.deinit();

    const inferred_architecture = build_image.parseArchitecture(container_image.config.architecture);
    if (options.architecture != null and inferred_architecture == null) {
        return error.UnsupportedContainerArchitecture;
    }
    const architecture = options.architecture orelse inferred_architecture orelse .x86_64;
    if (options.architecture != null and inferred_architecture != null and options.architecture.? != inferred_architecture.?) {
        return error.ContainerArchitectureMismatch;
    }

    logStep(options, "open source ISO");
    var iso_reader = try iso9660.Reader.openPath(allocator, io, options.iso_path);
    var iso_reader_open = true;
    defer if (iso_reader_open) iso_reader.close(io);

    const volume_id = if (options.volume_id) |explicit|
        try allocator.dupe(u8, explicit)
    else
        iso9660.readVolumeIdAlloc(allocator, io, iso_reader.file) catch try allocator.dupe(u8, default_volume_id);
    var volume_id_owned = false;
    errdefer if (!volume_id_owned) allocator.free(volume_id);

    const rootfs_path_in_iso = try build_image.discoverRootfsPathInIso(allocator, &iso_reader, options.rootfs_path_in_iso);
    var rootfs_path_owned = false;
    errdefer if (!rootfs_path_owned) allocator.free(rootfs_path_in_iso);

    const nested_rootfs_path = try allocator.dupe(u8, trimLeadingSlash(options.nested_rootfs_path));
    var nested_rootfs_owned = false;
    errdefer if (!nested_rootfs_owned) allocator.free(nested_rootfs_path);

    var report = BuildIsoReport{
        .architecture = architecture,
        .dry_run = options.dry_run,
        .rootfs_path_in_iso = rootfs_path_in_iso,
        .nested_rootfs_path = nested_rootfs_path,
        .rootfs_size = alignUp(options.rootfs_size, ext4.default_block_size),
        .volume_id = volume_id,
        .squashfs_compression = options.squashfs_compression,
        .boot_entries = &.{},
    };
    volume_id_owned = true;
    rootfs_path_owned = true;
    nested_rootfs_owned = true;
    errdefer report.deinit(allocator);

    // Resolve the El Torito boot images against the source directory tree.
    // Boot images are never the replaced payload, so the source tree and the
    // output tree agree on their presence -- resolving here lets a dry run and
    // the real build reject a missing image identically and early.
    logStep(options, "resolve El Torito boot images");
    const boot_entries = try resolveBootImages(allocator, io, &iso_reader, options.boot_images);
    report.boot_entries = boot_entries;

    if (options.dry_run) return report;

    const customization_epoch: u64 = if (options.determinism) |deterministic|
        deterministic.filesystem_timestamp
    else blk: {
        const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
        if (now < 0) return error.InvalidSystemTime;
        break :blk @intCast(now);
    };

    var materialize_stage_bridge = MaterializeStageBridge{ .sink = options.stage_sink orelse undefined };
    var root_tree = try build_image.materializeCustomizedRootTree(
        allocator,
        io,
        &iso_reader,
        &iso_reader_open,
        rootfs_path_in_iso,
        &container_image,
        &container_image_open,
        architecture,
        .{
            .skip_iso_rootfs = options.skip_iso_rootfs,
            .retain_uki_boot_assets = true,
            .os = options.os,
            .generalization = options.generalization,
            .limits = options.limits,
            .limit_diagnostic = options.limit_diagnostic,
            .customization_epoch = customization_epoch,
            .scratch_base = options.output_path,
            .scratch_infix = scratch_infix,
            .reporting = .{
                .event_sink = options.event_sink,
                .stage_sink = if (options.stage_sink != null)
                    .{ .context = &materialize_stage_bridge, .advanceFn = MaterializeStageBridge.advance }
                else
                    null,
                .verbose = options.verbose,
                .label = "build-iso",
            },
        },
    );
    defer root_tree.deinit();

    report.root_tree_digest = try root_tree.manifestDigest();
    if (options.limit_diagnostic) |sink| report.limit_peaks = sink.peaks;

    const timestamp: u32 = if (options.determinism) |d| d.filesystem_timestamp else 0;

    // 1. Write the customized root tree to a deterministic ext4 rootfs.img.
    try enterStage(options, .write_rootfs_image);
    const rootfs_scratch = try std.fmt.allocPrint(allocator, "{s}.{s}-rootfs.img", .{ options.output_path, scratch_infix });
    defer allocator.free(rootfs_scratch);
    var rootfs_written = false;
    defer if (rootfs_written) Io.Dir.cwd().deleteFile(io, rootfs_scratch) catch {};
    logStep(options, "write ext4 rootfs.img");
    try writeRootfsImage(allocator, io, rootfs_scratch, &root_tree, .{
        .length = report.rootfs_size,
        .ext4_label = options.ext4_label,
        .ext4_journal = options.ext4_journal,
        .root_selinux_label = options.root_selinux_label,
        .uuid = resolveRootUuid(io, options.determinism),
        .timestamp = timestamp,
    });
    rootfs_written = true;

    // 2. Wrap rootfs.img in a native SquashFS at the LiveOS payload path.
    try enterStage(options, .wrap_squashfs_payload);
    const payload_scratch = try std.fmt.allocPrint(allocator, "{s}.{s}-payload.sqsh", .{ options.output_path, scratch_infix });
    defer allocator.free(payload_scratch);
    var payload_written = false;
    defer if (payload_written) Io.Dir.cwd().deleteFile(io, payload_scratch) catch {};
    logStep(options, "wrap rootfs.img in SquashFS payload");
    const payload_size = try wrapSquashfsPayload(allocator, io, rootfs_scratch, report.rootfs_size, payload_scratch, nested_rootfs_path, options.squashfs_compression, timestamp);
    payload_written = true;

    // 3. Reassemble the ISO tree: source directory tree with the payload
    //    replaced by the regenerated SquashFS. The source reader was released
    //    by materialization, so reopen it for the duration of the ISO write.
    try enterStage(options, .assemble_iso_tree);
    logStep(options, "reopen source ISO for output tree");
    var source_reader = try iso9660.Reader.openPath(allocator, io, options.iso_path);
    defer source_reader.close(io);

    const payload_file = try Io.Dir.cwd().openFile(io, payload_scratch, .{ .mode = .read_only });
    defer payload_file.close(io);

    var output_tree = try OutputIsoTree.init(
        allocator,
        io,
        &source_reader,
        rootfs_path_in_iso,
        payload_file,
        payload_size,
        .{ .uniform = timestamp },
        timestamp,
    );
    defer output_tree.deinit();

    var boot_writer_entries = try allocator.alloc(iso9660.BootEntry, boot_entries.len);
    defer allocator.free(boot_writer_entries);
    for (boot_entries, 0..) |entry, i| {
        boot_writer_entries[i] = .{
            .platform = entry.platform.writerPlatform(),
            .image_path = entry.image_path,
        };
    }

    // 4. Write the ISO to a scratch path, then publish it atomically.
    try enterStage(options, .write_iso);
    const iso_scratch = try std.fmt.allocPrint(allocator, "{s}.{s}.iso.tmp", .{ options.output_path, scratch_infix });
    defer allocator.free(iso_scratch);
    var iso_written = false;
    defer if (iso_written) Io.Dir.cwd().deleteFile(io, iso_scratch) catch {};
    logStep(options, "write output ISO");
    _ = try iso9660.writeImagePath(allocator, io, iso_scratch, output_tree.source(), .{
        .volume_id = volume_id,
        .boot_entries = boot_writer_entries,
    });
    iso_written = true;

    logStep(options, "hash output ISO");
    const digest = try hashFile(allocator, io, iso_scratch);
    report.output_size = digest.size;
    report.output_sha256 = digest.sha256;

    try enterStage(options, .publish_output);
    logStep(options, "publish output ISO");
    try Io.Dir.rename(Io.Dir.cwd(), iso_scratch, Io.Dir.cwd(), options.output_path, io);
    iso_written = false;

    return report;
}

/// Inputs `writeRootfsImage` needs, independent of any one product's option
/// struct so `build-iso` and `recustomize-iso` share one ext4 rootfs writer.
pub const RootfsImageOptions = struct {
    /// ext4 image length in bytes (already rounded to the block size).
    length: u64,
    ext4_label: []const u8,
    ext4_journal: ext4.JournalOptions,
    /// SELinux context for the ext4 root inode (a trailing NUL is added), or
    /// null. An empty or NUL-bearing label is `error.InvalidRootSelinuxLabel`.
    root_selinux_label: ?[]const u8,
    /// ext4 filesystem UUID.
    uuid: [16]u8,
    /// POSIX-seconds timestamp stamped into the superblock/inodes.
    timestamp: u32,
};

/// Writes `root_tree` to a deterministic ext4 image at `path`. Shared by both
/// ISO pipelines.
pub fn writeRootfsImage(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    root_tree: *root_tree_mod.RootTree,
    options: RootfsImageOptions,
) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var root_xattr_buffer: [1]ext4.Xattr = undefined;
    var root_selinux_value: ?[]u8 = null;
    defer if (root_selinux_value) |value| allocator.free(value);
    const root_xattrs: []const ext4.Xattr = if (options.root_selinux_label) |label| blk: {
        if (label.len == 0 or std.mem.indexOfScalar(u8, label, 0) != null) {
            return error.InvalidRootSelinuxLabel;
        }
        const value = try allocator.alloc(u8, label.len + 1);
        std.mem.copyForwards(u8, value[0..label.len], label);
        value[label.len] = 0;
        root_selinux_value = value;
        root_xattr_buffer[0] = .{ .name = "security.selinux", .value = value };
        break :blk &root_xattr_buffer;
    } else &.{};

    _ = try ext4.populate(io, file, allocator, try root_tree.ext4View(), .{
        .offset = 0,
        .length = options.length,
        .label = options.ext4_label,
        .root_xattrs = root_xattrs,
        .uuid = options.uuid,
        .timestamp = options.timestamp,
        .journal = options.ext4_journal,
    });
}

/// Resolves the ext4 root filesystem UUID: the deterministic one when a
/// `Determinism` is supplied, else a fresh random UUID. Shared so both ISO
/// pipelines derive it identically.
pub fn resolveRootUuid(io: Io, determinism: ?Determinism) [16]u8 {
    if (determinism) |d| return d.root_filesystem_uuid;
    var random_uuid: [16]u8 = undefined;
    Io.random(io, &random_uuid);
    return random_uuid;
}

/// Wraps a completed ext4 rootfs image in a native SquashFS whose single member
/// is the ext4 image at `nested_rootfs_path`. Returns the SquashFS byte length.
/// Shared by both ISO pipelines.
pub fn wrapSquashfsPayload(
    allocator: std.mem.Allocator,
    io: Io,
    rootfs_path: []const u8,
    rootfs_size: u64,
    payload_path: []const u8,
    nested_rootfs_path: []const u8,
    compression: squashfs.WriterCompression,
    timestamp: u32,
) !u64 {
    const rootfs_file = try Io.Dir.cwd().openFile(io, rootfs_path, .{ .mode = .read_only });
    defer rootfs_file.close(io);

    var source = try NestedRootfsSource.init(allocator, io, nested_rootfs_path, rootfs_file, rootfs_size);
    defer source.deinit();

    const result = try squashfs.writeImagePath(allocator, io, payload_path, source.source(), .{
        .compression = compression,
        .mtime = timestamp,
    });
    return result.bytes_written;
}

pub const FileDigest = struct {
    size: u64,
    sha256: [32]u8,
};

/// Streams `path` and returns its byte length and SHA-256. Shared by both ISO
/// pipelines to hash sources and outputs.
pub fn hashFile(allocator: std.mem.Allocator, io: Io, path: []const u8) !FileDigest {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);

    const buffer = try allocator.alloc(u8, copy_chunk_size);
    defer allocator.free(buffer);

    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var offset: u64 = 0;
    while (true) {
        const got = try file.readPositionalAll(io, buffer, offset);
        if (got == 0) break;
        hasher.update(buffer[0..got]);
        offset += got;
        if (got < buffer.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return .{ .size = offset, .sha256 = digest };
}

/// Resolves the caller's explicit boot images, or probes the source tree for
/// common El Torito layouts. Rejects duplicate platforms and a missing image
/// precisely, and requires at least one entry.
fn resolveBootImages(
    allocator: std.mem.Allocator,
    io: Io,
    reader: *iso9660.Reader,
    requested: []const BootImage,
) ![]BootEntryReport {
    var entries = std.array_list.Managed(BootEntryReport).init(allocator);
    errdefer {
        for (entries.items) |entry| allocator.free(entry.image_path);
        entries.deinit();
    }

    var saw_bios = false;
    var saw_uefi = false;

    if (requested.len != 0) {
        for (requested) |image| {
            switch (image.platform) {
                .bios => {
                    if (saw_bios) return error.DuplicateBootPlatform;
                    saw_bios = true;
                },
                .uefi => {
                    if (saw_uefi) return error.DuplicateBootPlatform;
                    saw_uefi = true;
                },
            }
            const path = trimLeadingSlash(image.image_path);
            if (!isFilePath(io, reader, path)) return error.BootImageNotFound;
            try entries.append(.{ .platform = image.platform, .image_path = try allocator.dupe(u8, path) });
        }
    } else {
        if (discoverBootImage(io, reader, &uefi_boot_candidates)) |path| {
            try entries.append(.{ .platform = .uefi, .image_path = try allocator.dupe(u8, path) });
        }
        if (discoverBootImage(io, reader, &bios_boot_candidates)) |path| {
            try entries.append(.{ .platform = .bios, .image_path = try allocator.dupe(u8, path) });
        }
    }

    if (entries.items.len == 0) return error.NoBootImage;
    return entries.toOwnedSlice();
}

// Conventional El Torito boot image paths, ordered by preference. Discovery
// picks the first that resolves to a real file, so a source ISO that follows a
// common layout needs no explicit boot-image options.
const uefi_boot_candidates = [_][]const u8{
    "boot/grub2/efiboot.img",
    "EFI/boot/efiboot.img",
    "efi/boot/efiboot.img",
    "images/efiboot.img",
    "boot/efiboot.img",
};

const bios_boot_candidates = [_][]const u8{
    "boot/grub2/i386-pc/eltorito.img",
    "boot/isolinux/isolinux.bin",
    "isolinux/isolinux.bin",
    "boot/grub2/boot_hybrid.img",
};

fn discoverBootImage(io: Io, reader: *iso9660.Reader, candidates: []const []const u8) ?[]const u8 {
    for (candidates) |candidate| {
        if (isFilePath(io, reader, candidate)) return candidate;
    }
    return null;
}

fn isFilePath(io: Io, reader: *iso9660.Reader, path: []const u8) bool {
    _ = io;
    const lookup_path = std.fmt.allocPrint(reader.allocator, "/{s}", .{path}) catch return false;
    defer reader.allocator.free(lookup_path);
    const index = reader.lookup(lookup_path) catch return false;
    return reader.getEntry(index).kind == .file;
}

fn validateBuildPathIsolation(allocator: std.mem.Allocator, io: Io, options: BuildIsoOptions) !void {
    const output_path = try std.fs.path.resolve(allocator, &.{options.output_path});
    defer allocator.free(output_path);

    const reserved = [_][]const u8{
        try std.fmt.allocPrint(allocator, "{s}.{s}-rootfs.sqsh", .{ output_path, scratch_infix }),
        try std.fmt.allocPrint(allocator, "{s}.{s}-root-tree.spool", .{ output_path, scratch_infix }),
        try std.fmt.allocPrint(allocator, "{s}.{s}-rootfs.img", .{ output_path, scratch_infix }),
        try std.fmt.allocPrint(allocator, "{s}.{s}-payload.sqsh", .{ output_path, scratch_infix }),
        try std.fmt.allocPrint(allocator, "{s}.{s}.iso.tmp", .{ output_path, scratch_infix }),
    };
    defer for (reserved) |path| allocator.free(path);
    const nested_prefix = try std.fmt.allocPrint(allocator, "{s}.{s}-nested", .{ output_path, scratch_infix });
    defer allocator.free(nested_prefix);

    var reserved_with_output: [reserved.len + 1][]const u8 = undefined;
    reserved_with_output[0] = output_path;
    @memcpy(reserved_with_output[1..], &reserved);

    for ([_][]const u8{ options.iso_path, options.container_path }) |source| {
        if (try build_image.buildSourceConflicts(io, source, &reserved_with_output, nested_prefix)) {
            return error.SourcePathConflict;
        }
    }
    for (options.os.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .inline_bytes => {},
            .host_path => |path| {
                if (try build_image.buildSourceConflicts(io, path, &reserved_with_output, nested_prefix)) {
                    return error.SourcePathConflict;
                }
            },
        },
        else => {},
    };
}

pub fn trimLeadingSlash(path: []const u8) []const u8 {
    return if (std.mem.startsWith(u8, path, "/")) path[1..] else path;
}

pub fn alignUp(value: u64, alignment: u64) u64 {
    if (alignment == 0) return value;
    const remainder = value % alignment;
    return if (remainder == 0) value else value + (alignment - remainder);
}

/// SquashFS `TreeSource` holding a single ext4 image at `nested_rootfs_path`,
/// with every parent directory of that path synthesized so the writer never
/// sees a missing parent.
const NestedRootfsSource = struct {
    io: Io,
    file: Io.File,
    size: u64,
    arena: std.heap.ArenaAllocator,
    nodes: []Node,
    file_index: usize,

    const Node = struct {
        path: []const u8,
        kind: squashfs.SourceKind,
        size: u64,
    };

    fn init(allocator: std.mem.Allocator, io: Io, nested_path: []const u8, file: Io.File, size: u64) !NestedRootfsSource {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        var nodes = std.array_list.Managed(Node).init(a);
        const path = trimLeadingSlash(nested_path);

        // Every ancestor directory, shallow to deep.
        var cursor: usize = 0;
        while (std.mem.indexOfScalarPos(u8, path, cursor, '/')) |slash| {
            try nodes.append(.{ .path = try a.dupe(u8, path[0..slash]), .kind = .directory, .size = 0 });
            cursor = slash + 1;
        }
        const file_index = nodes.items.len;
        try nodes.append(.{ .path = try a.dupe(u8, path), .kind = .file, .size = size });

        return .{
            .io = io,
            .file = file,
            .size = size,
            .arena = arena,
            .nodes = try nodes.toOwnedSlice(),
            .file_index = file_index,
        };
    }

    fn deinit(self: *NestedRootfsSource) void {
        self.arena.deinit();
    }

    fn source(self: *const NestedRootfsSource) squashfs.TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable = squashfs.TreeSource.VTable{
        .root = rootFn,
        .count = countFn,
        .node = nodeFn,
        .read = readFn,
    };

    fn ctx(context: *const anyopaque) *const NestedRootfsSource {
        return @ptrCast(@alignCast(context));
    }
    fn rootFn(_: *const anyopaque) squashfs.SourceRoot {
        return .{ .mode = 0o755 };
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!squashfs.SourceNode {
        const node = ctx(context).nodes[index];
        return .{
            .path = node.path,
            .kind = node.kind,
            .mode = if (node.kind == .directory) 0o755 else 0o644,
            .size = node.size,
        };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const self = ctx(context);
        if (index != self.file_index) return 0;
        if (offset >= self.size) return 0;
        const want: usize = @intCast(@min(@as(u64, buffer.len), self.size - offset));
        return self.file.readPositionalAll(self.io, buffer[0..want], offset);
    }
};

/// Timestamp policy for a regenerated ISO tree.
pub const TimestampPolicy = union(enum) {
    /// Stamp `mtime` into every preserved node and the root. `build-iso` uses
    /// this (its determinism timestamp, or 0).
    uniform: i64,
    /// Preserve each source node's modeled modification time, and the source
    /// root's. `recustomize-iso` uses this so timestamps survive a rewrite.
    preserve_source,
};

/// ISO9660 `TreeSource` over a source ISO's directory tree, with the LiveOS
/// payload node replaced by the regenerated SquashFS. Boot files and every
/// other ordinary entry are re-emitted verbatim; the payload's bytes come from
/// the regenerated SquashFS scratch file instead of the source image.
///
/// Shared by `build-iso` (uniform timestamp) and `recustomize-iso` (source
/// timestamps preserved) so there is one implementation of the tree rewrite.
pub const OutputIsoTree = struct {
    io: Io,
    reader: *iso9660.Reader,
    payload_file: Io.File,
    payload_size: u64,
    policy: TimestampPolicy,
    root_mtime: i64,
    replacement_mtime: i64,
    arena: std.heap.ArenaAllocator,
    nodes: []Node,
    payload_index: usize,

    const Content = union(enum) {
        none,
        iso: usize,
        replacement,
    };

    const Node = struct {
        path: []const u8,
        kind: iso9660.SourceKind,
        mode: u16,
        uid: u32,
        gid: u32,
        mtime: i64,
        size: u64,
        symlink_target: []const u8,
        content: Content,
    };

    pub fn init(
        allocator: std.mem.Allocator,
        io: Io,
        reader: *iso9660.Reader,
        payload_path: []const u8,
        payload_file: Io.File,
        payload_size: u64,
        policy: TimestampPolicy,
        replacement_mtime: i64,
    ) !OutputIsoTree {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        var nodes = std.array_list.Managed(Node).init(a);
        try collect(a, io, reader, reader.root_index, "", payload_path, &nodes);

        // Replace the payload in place: same path, regenerated bytes. The
        // source payload node was skipped by `collect`, and its parent
        // directories are already present from the source tree walk.
        const payload_index = nodes.items.len;
        try nodes.append(.{
            .path = try a.dupe(u8, trimLeadingSlash(payload_path)),
            .kind = .file,
            .mode = 0o444,
            .uid = 0,
            .gid = 0,
            .mtime = replacement_mtime,
            .size = payload_size,
            .symlink_target = &.{},
            .content = .replacement,
        });

        return .{
            .io = io,
            .reader = reader,
            .payload_file = payload_file,
            .payload_size = payload_size,
            .policy = policy,
            .root_mtime = reader.getEntry(reader.root_index).mtime,
            .replacement_mtime = replacement_mtime,
            .arena = arena,
            .nodes = try nodes.toOwnedSlice(),
            .payload_index = payload_index,
        };
    }

    /// Number of preserved source nodes (every emitted node except the one
    /// replacement payload node).
    pub fn preservedNodeCount(self: *const OutputIsoTree) usize {
        return self.nodes.len - 1;
    }

    fn collect(
        a: std.mem.Allocator,
        io: Io,
        reader: *iso9660.Reader,
        parent_index: usize,
        prefix: []const u8,
        payload_path: []const u8,
        nodes: *std.array_list.Managed(Node),
    ) !void {
        const children = try reader.listDirAlloc(a, parent_index);
        for (children) |child| {
            const full_path = if (prefix.len == 0)
                try a.dupe(u8, child.name)
            else
                try std.fmt.allocPrint(a, "{s}/{s}", .{ prefix, child.name });

            if (std.ascii.eqlIgnoreCase(full_path, payload_path)) continue;

            const entry = reader.getEntry(child.index);
            switch (entry.kind) {
                .directory => {
                    try nodes.append(.{
                        .path = full_path,
                        .kind = .directory,
                        .mode = @truncate(entry.mode & 0o7777),
                        .uid = entry.uid,
                        .gid = entry.gid,
                        .mtime = entry.mtime,
                        .size = 0,
                        .symlink_target = &.{},
                        .content = .none,
                    });
                    try collect(a, io, reader, child.index, full_path, payload_path, nodes);
                },
                .file => {
                    try nodes.append(.{
                        .path = full_path,
                        .kind = .file,
                        .mode = @truncate(entry.mode & 0o7777),
                        .uid = entry.uid,
                        .gid = entry.gid,
                        .mtime = entry.mtime,
                        .size = entry.size,
                        .symlink_target = &.{},
                        .content = .{ .iso = child.index },
                    });
                },
                .symlink => {
                    const target = try reader.readLink(child.index);
                    try nodes.append(.{
                        .path = full_path,
                        .kind = .symlink,
                        .mode = @truncate(entry.mode & 0o7777),
                        .uid = entry.uid,
                        .gid = entry.gid,
                        .mtime = entry.mtime,
                        .size = target.len,
                        .symlink_target = try a.dupe(u8, target),
                        .content = .none,
                    });
                },
            }
        }
    }

    pub fn deinit(self: *OutputIsoTree) void {
        self.arena.deinit();
    }

    fn source(self: *const OutputIsoTree) iso9660.TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }

    /// The public `iso9660.TreeSource` view of this rewritten tree, for callers
    /// (like `recustomize-iso`) that live in another module.
    pub fn treeSource(self: *const OutputIsoTree) iso9660.TreeSource {
        return self.source();
    }

    const vtable = iso9660.TreeSource.VTable{
        .root = rootFn,
        .count = countFn,
        .node = nodeFn,
        .read = readFn,
    };

    fn ctx(context: *const anyopaque) *const OutputIsoTree {
        return @ptrCast(@alignCast(context));
    }
    fn rootFn(context: *const anyopaque) iso9660.SourceRoot {
        const self = ctx(context);
        const mtime: i64 = switch (self.policy) {
            .uniform => |t| t,
            .preserve_source => self.root_mtime,
        };
        return .{ .mode = 0o755, .mtime = mtime };
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!iso9660.SourceNode {
        const self = ctx(context);
        const node = self.nodes[index];
        const mtime: i64 = if (index == self.payload_index)
            self.replacement_mtime
        else switch (self.policy) {
            .uniform => |t| t,
            .preserve_source => node.mtime,
        };
        return .{
            .path = node.path,
            .kind = node.kind,
            .mode = node.mode,
            .uid = node.uid,
            .gid = node.gid,
            .mtime = mtime,
            .size = node.size,
            .symlink_target = node.symlink_target,
        };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const self = ctx(context);
        const node = self.nodes[index];
        return switch (node.content) {
            .none => 0,
            .iso => |iso_index| build_image.readIsoFileAt(self.io, self.reader, iso_index, buffer, offset),
            .replacement => blk: {
                if (offset >= self.payload_size) break :blk 0;
                const want: usize = @intCast(@min(@as(u64, buffer.len), self.payload_size - offset));
                break :blk self.payload_file.readPositionalAll(self.io, buffer[0..want], offset);
            },
        };
    }
};

/// Counts the source filesystem nodes a rewrite preserves: every node in the
/// source tree except the single replaced payload at `payload_path` (and the
/// root, which the writer never counts). This is exactly the value
/// `OutputIsoTree.preservedNodeCount` reports for the same source and payload,
/// computed without materializing the replacement so a dry run can report the
/// real number ahead of building anything. `payload_path` must be given in the
/// same form passed to `OutputIsoTree.init` (root-relative, no leading slash).
pub fn countPreservedNodes(
    allocator: std.mem.Allocator,
    io: Io,
    reader: *iso9660.Reader,
    payload_path: []const u8,
) !usize {
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    return countPreservedNodesRec(arena.allocator(), io, reader, reader.root_index, "", payload_path);
}

fn countPreservedNodesRec(
    a: std.mem.Allocator,
    io: Io,
    reader: *iso9660.Reader,
    parent_index: usize,
    prefix: []const u8,
    payload_path: []const u8,
) !usize {
    var count: usize = 0;
    const children = try reader.listDirAlloc(a, parent_index);
    for (children) |child| {
        const full_path = if (prefix.len == 0)
            try a.dupe(u8, child.name)
        else
            try std.fmt.allocPrint(a, "{s}/{s}", .{ prefix, child.name });

        // Mirror `OutputIsoTree.collect`: skip the replaced payload, count every
        // other node, and recurse into directories.
        if (std.ascii.eqlIgnoreCase(full_path, payload_path)) continue;
        count += 1;
        if (reader.getEntry(child.index).kind == .directory) {
            count += try countPreservedNodesRec(a, io, reader, child.index, full_path, payload_path);
        }
    }
    return count;
}

test {
    std.testing.refAllDecls(@This());
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

const FixtureNode = struct {
    path: []const u8,
    kind: iso9660.SourceKind,
    bytes: []const u8 = &.{},
};

const FixtureIsoSource = struct {
    nodes: []const FixtureNode,

    fn source(self: *const FixtureIsoSource) iso9660.TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }
    const vtable = iso9660.TreeSource.VTable{
        .root = rootFn,
        .count = countFn,
        .node = nodeFn,
        .read = readFn,
    };
    fn ctx(context: *const anyopaque) *const FixtureIsoSource {
        return @ptrCast(@alignCast(context));
    }
    fn rootFn(_: *const anyopaque) iso9660.SourceRoot {
        return .{ .mode = 0o755 };
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!iso9660.SourceNode {
        const n = ctx(context).nodes[index];
        return .{
            .path = n.path,
            .kind = n.kind,
            .mode = if (n.kind == .directory) 0o755 else 0o644,
            .size = n.bytes.len,
        };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const data = ctx(context).nodes[index].bytes;
        if (offset >= data.len) return 0;
        const start: usize = @intCast(offset);
        const n = @min(buffer.len, data.len - start);
        @memcpy(buffer[0..n], data[start..][0..n]);
        return n;
    }
};

/// Writes a source LiveOS ISO fixture: the SquashFS payload at
/// `LiveOS/squashfs.img`, a UEFI and a BIOS El Torito boot image, and boot
/// configuration under `boot/` and `EFI/`.
fn writeSourceIso(allocator: std.mem.Allocator, io: Io, path: []const u8, squashfs_bytes: []const u8) !void {
    const nodes = [_]FixtureNode{
        .{ .path = "LiveOS", .kind = .directory },
        .{ .path = "LiveOS/squashfs.img", .kind = .file, .bytes = squashfs_bytes },
        .{ .path = "boot", .kind = .directory },
        .{ .path = "boot/grub2", .kind = .directory },
        .{ .path = "boot/grub2/grub.cfg", .kind = .file, .bytes = "set default=0\nlinux /boot/vmlinuz root=live:CDLABEL=VMIZ_SRC rd.live.image\n" },
        .{ .path = "boot/grub2/efiboot.img", .kind = .file, .bytes = "UEFI-EL-TORITO-BOOT-IMAGE-CONTENTS" },
        .{ .path = "boot/grub2/i386-pc", .kind = .directory },
        .{ .path = "boot/grub2/i386-pc/eltorito.img", .kind = .file, .bytes = "BIOS-EL-TORITO-BOOT-IMAGE-CONTENTS" },
        .{ .path = "EFI", .kind = .directory },
        .{ .path = "EFI/BOOT", .kind = .directory },
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .kind = .file, .bytes = "source-ISO-bootx64-payload" },
    };
    const src = FixtureIsoSource{ .nodes = &nodes };
    _ = try iso9660.writeImagePath(allocator, io, path, src.source(), .{ .volume_id = "VMIZ_SRC" });
}

const TarEntry = struct {
    path: []const u8,
    typeflag: u8,
    content: []const u8 = "",
};

fn testWriteOctal(field: []u8, value: u64) void {
    @memset(field, '0');
    field[field.len - 1] = 0;
    var v = value;
    var i: usize = field.len - 1;
    while (v != 0) {
        i -= 1;
        field[i] = '0' + @as(u8, @intCast(v & 7));
        v >>= 3;
    }
}

fn buildTar(allocator: std.mem.Allocator, entries: []const TarEntry) ![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();
    for (entries) |entry| {
        var header = [_]u8{0} ** 512;
        @memcpy(header[0..entry.path.len], entry.path);
        testWriteOctal(header[100..108], 0o644);
        testWriteOctal(header[108..116], 0);
        testWriteOctal(header[116..124], 0);
        testWriteOctal(header[124..136], entry.content.len);
        testWriteOctal(header[136..148], 0);
        @memset(header[148..156], ' ');
        header[156] = entry.typeflag;
        @memcpy(header[257..263], "ustar\x00");
        @memcpy(header[263..265], "00");
        var checksum: u32 = 0;
        for (header) |b| checksum += b;
        testWriteOctal(header[148..156], checksum);
        header[155] = ' ';
        try out.appendSlice(&header);
        try out.appendSlice(entry.content);
        const pad = std.mem.alignForward(usize, entry.content.len, 512) - entry.content.len;
        try out.appendNTimes(0, pad);
    }
    try out.appendNTimes(0, 1024);
    return out.toOwnedSlice();
}

fn gzip(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), data.len));
    errdefer out.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(data);
    try compressor.finish();
    return out.toOwnedSlice();
}

fn writeBlob(allocator: std.mem.Allocator, io: Io, dir: Io.Dir, data: []const u8) ![]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(data, &digest, .{});
    const hex = std.fmt.bytesToHex(digest, .lower);
    const blob_path = try std.fmt.allocPrint(allocator, "blobs/sha256/{s}", .{hex});
    defer allocator.free(blob_path);
    try dir.writeFile(io, .{ .sub_path = blob_path, .data = data });
    return std.fmt.allocPrint(allocator, "sha256:{s}", .{hex});
}

/// Writes a minimal one-layer OCI layout overlaying `app/hello.txt`.
fn createOciLayout(allocator: std.mem.Allocator, io: Io, root: []const u8) !void {
    try Io.Dir.cwd().createDirPath(io, root);
    var dir = try Io.Dir.cwd().openDir(io, root, .{});
    defer dir.close(io);
    try dir.createDirPath(io, "blobs/sha256");

    const layer_tar = try buildTar(allocator, &.{
        .{ .path = "app/", .typeflag = '5' },
        .{ .path = "app/hello.txt", .typeflag = '0', .content = "hello from the OCI overlay\n" },
    });
    defer allocator.free(layer_tar);
    const layer_gzip = try gzip(allocator, layer_tar);
    defer allocator.free(layer_gzip);

    const config_json = "{\"architecture\":\"amd64\",\"os\":\"linux\",\"rootfs\":{\"type\":\"layers\",\"diff_ids\":[]}}";
    const config_digest = try writeBlob(allocator, io, dir, config_json);
    defer allocator.free(config_digest);
    const layer_digest = try writeBlob(allocator, io, dir, layer_gzip);
    defer allocator.free(layer_digest);
    const manifest_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"config\":{{\"mediaType\":\"application/vnd.oci.image.config.v1+json\",\"digest\":\"{s}\",\"size\":{d}}},\"layers\":[{{\"mediaType\":\"application/vnd.oci.image.layer.v1.tar+gzip\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ config_digest, config_json.len, layer_digest, layer_gzip.len },
    );
    defer allocator.free(manifest_json);
    const manifest_digest = try writeBlob(allocator, io, dir, manifest_json);
    defer allocator.free(manifest_digest);
    const index_json = try std.fmt.allocPrint(
        allocator,
        "{{\"schemaVersion\":2,\"manifests\":[{{\"mediaType\":\"application/vnd.oci.image.manifest.v1+json\",\"digest\":\"{s}\",\"size\":{d}}}]}}",
        .{ manifest_digest, manifest_json.len },
    );
    defer allocator.free(index_json);
    try dir.writeFile(io, .{ .sub_path = "oci-layout", .data = "{\"imageLayoutVersion\":\"1.0.0\"}" });
    try dir.writeFile(io, .{ .sub_path = "index.json", .data = index_json });
}

fn extractIsoFileToPath(allocator: std.mem.Allocator, io: Io, reader: *iso9660.Reader, iso_path: []const u8, out_path: []const u8) !void {
    const index = try reader.lookup(iso_path);
    const bytes = try reader.readFileAlloc(allocator, io, index);
    defer allocator.free(bytes);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = bytes });
}

fn extractSquashfsFileToPath(allocator: std.mem.Allocator, io: Io, reader: *squashfs.Reader, sqfs_path: []const u8, out_path: []const u8) !void {
    const index = try reader.lookup(sqfs_path);
    const bytes = try reader.readFileAlloc(allocator, io, index);
    defer allocator.free(bytes);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = bytes });
}

const deterministic_fixture = Determinism{
    .filesystem_timestamp = 1_700_000_000,
    .root_filesystem_uuid = [_]u8{0x11} ** 16,
};

test "build-iso regenerates a LiveOS ISO: boot files survive, payload replaced, nested rootfs carries customized and OCI content" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-src.iso";
    const oci_root = "test-build-iso-oci";
    const output_path = "test-build-iso-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    const StageRecorder = struct {
        stages: [16]Stage = undefined,
        len: usize = 0,
        fn advance(context: ?*anyopaque, stage: Stage) bool {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.stages[self.len] = stage;
            self.len += 1;
            return true;
        }
    };
    var recorder = StageRecorder{};

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .os = .{ .hostname = "vmiz-live" },
        .determinism = deterministic_fixture,
        .stage_sink = .{ .context = &recorder, .advanceFn = StageRecorder.advance },
    });
    defer report.deinit(allocator);

    // Report states the required facts.
    try testing.expectEqualStrings("LiveOS/squashfs.img", report.rootfs_path_in_iso);
    try testing.expectEqualStrings("LiveOS/rootfs.img", report.nested_rootfs_path);
    try testing.expectEqualStrings("VMIZ_SRC", report.volume_id);
    try testing.expectEqual(squashfs.WriterCompression.zstd, report.squashfs_compression);
    try testing.expect(report.root_tree_digest != null);
    try testing.expect(report.output_size > 0);
    // Both boot platforms were discovered.
    try testing.expectEqual(@as(usize, 2), report.boot_entries.len);

    const expected_stages = [_]Stage{
        .load_sources,
        .apply_filesystem_changes,
        .generalize_and_cleanup,
        .write_rootfs_image,
        .wrap_squashfs_payload,
        .assemble_iso_tree,
        .write_iso,
        .publish_output,
    };
    try testing.expectEqualSlices(Stage, &expected_stages, recorder.stages[0..recorder.len]);

    // Open the regenerated ISO and confirm the source boot files survive.
    var out_reader = try iso9660.Reader.openPath(allocator, io, output_path);
    defer out_reader.close(io);
    _ = try out_reader.lookup("/EFI/BOOT/BOOTX64.EFI");
    _ = try out_reader.lookup("/boot/grub2/grub.cfg");
    _ = try out_reader.lookup("/boot/grub2/efiboot.img");
    _ = try out_reader.lookup("/boot/grub2/i386-pc/eltorito.img");

    const grub_cfg_index = try out_reader.lookup("/boot/grub2/grub.cfg");
    const grub_cfg = try out_reader.readFileAlloc(allocator, io, grub_cfg_index);
    defer allocator.free(grub_cfg);
    try testing.expect(std.mem.indexOf(u8, grub_cfg, "rd.live.image") != null);

    // The El Torito catalog names both boot images.
    const out_file = try Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_only });
    defer out_file.close(io);
    var catalog = try iso9660.readBootCatalog(allocator, io, out_file);
    defer catalog.deinit(allocator);
    try testing.expectEqual(@as(usize, 2), catalog.entries.len);

    // The payload was replaced: the new squashfs holds a nested rootfs.img.
    const payload_scratch = "test-build-iso-payload.sqsh";
    defer Io.Dir.cwd().deleteFile(io, payload_scratch) catch {};
    try extractIsoFileToPath(allocator, io, &out_reader, "/LiveOS/squashfs.img", payload_scratch);

    // It differs from the source payload (which had no nested rootfs.img).
    var payload_reader = try squashfs.Reader.openPath(allocator, io, payload_scratch);
    defer payload_reader.close(io);
    _ = try payload_reader.lookup("/LiveOS/rootfs.img");

    const rootfs_scratch = "test-build-iso-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch) catch {};
    try extractSquashfsFileToPath(allocator, io, &payload_reader, "/LiveOS/rootfs.img", rootfs_scratch);

    // The nested rootfs.img opens as ext4 and carries the merged content.
    const rootfs_file = try Io.Dir.cwd().openFile(io, rootfs_scratch, .{ .mode = .read_only });
    defer rootfs_file.close(io);
    var ext4_reader = try ext4.open(io, rootfs_file, allocator, .{});
    defer ext4_reader.deinit();

    // From the source squashfs.
    const message = try ext4_reader.readFileAlloc(io, allocator, "etc/message.txt");
    defer allocator.free(message);
    try testing.expect(message.len > 0);

    // From the OCI overlay.
    const hello = try ext4_reader.readFileAlloc(io, allocator, "app/hello.txt");
    defer allocator.free(hello);
    try testing.expectEqualStrings("hello from the OCI overlay\n", hello);

    // From OS customization.
    const hostname = try ext4_reader.readFileAlloc(io, allocator, "etc/hostname");
    defer allocator.free(hostname);
    try testing.expectEqualStrings("vmiz-live\n", hostname);
}

test "build-iso is byte-for-byte deterministic across identical builds" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-det-src.iso";
    const oci_root = "test-build-iso-det-oci";
    const output_a = "test-build-iso-det-a.iso";
    const output_b = "test-build-iso-det-b.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_a) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_b) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    const opts = BuildIsoOptions{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_a,
        .rootfs_size = 24 * 1024 * 1024,
        .os = .{ .hostname = "vmiz-live" },
        .determinism = deterministic_fixture,
    };

    var report_a = try build(allocator, io, opts);
    defer report_a.deinit(allocator);
    var opts_b = opts;
    opts_b.output_path = output_b;
    var report_b = try build(allocator, io, opts_b);
    defer report_b.deinit(allocator);

    try testing.expectEqualSlices(u8, &report_a.output_sha256, &report_b.output_sha256);
    try testing.expectEqual(report_a.output_size, report_b.output_size);
    try testing.expectEqualSlices(u8, &report_a.root_tree_digest.?, &report_b.root_tree_digest.?);
}

test "build-iso fails precisely when a requested boot image is absent" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-missing-src.iso";
    const oci_root = "test-build-iso-missing-oci";
    const output_path = "test-build-iso-missing-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    try testing.expectError(error.BootImageNotFound, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .boot_images = &.{.{ .platform = .uefi, .image_path = "EFI/BOOT/nope.img" }},
        .determinism = deterministic_fixture,
    }));

    // No output was published on the precise preflight failure.
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));
}

test "build-iso supports an explicit UEFI-only boot entry" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-uefi-src.iso";
    const oci_root = "test-build-iso-uefi-oci";
    const output_path = "test-build-iso-uefi-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .boot_images = &.{.{ .platform = .uefi, .image_path = "boot/grub2/efiboot.img" }},
        .determinism = deterministic_fixture,
    });
    defer report.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), report.boot_entries.len);
    try testing.expectEqual(BootPlatform.uefi, report.boot_entries[0].platform);

    const out_file = try Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_only });
    defer out_file.close(io);
    var catalog = try iso9660.readBootCatalog(allocator, io, out_file);
    defer catalog.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), catalog.entries.len);
}

test "build-iso supports an explicit BIOS-only boot entry" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-bios-src.iso";
    const oci_root = "test-build-iso-bios-oci";
    const output_path = "test-build-iso-bios-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .boot_images = &.{.{ .platform = .bios, .image_path = "boot/grub2/i386-pc/eltorito.img" }},
        .determinism = deterministic_fixture,
    });
    defer report.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), report.boot_entries.len);
    try testing.expectEqual(BootPlatform.bios, report.boot_entries[0].platform);

    const out_file = try Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_only });
    defer out_file.close(io);
    var catalog = try iso9660.readBootCatalog(allocator, io, out_file);
    defer catalog.deinit(allocator);

    // Exactly one El Torito entry, on the BIOS platform, with no UEFI entry.
    try testing.expectEqual(@as(usize, 1), catalog.entries.len);
    try testing.expectEqual(iso9660.boot_platform_bios, catalog.validation_platform);
    try testing.expectEqual(iso9660.boot_platform_bios, catalog.entries[0].platform);
    for (catalog.entries) |entry| {
        try testing.expect(entry.platform != iso9660.boot_platform_uefi);
    }
}

test "build-iso rejects an output path that aliases an input and leaves no scratch behind" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-alias-src.iso";
    const oci_root = "test-build-iso-alias-oci";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    // Writing the output over the source ISO is refused up front.
    try testing.expectError(error.SourcePathConflict, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = iso_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
    }));

    // None of the scratch files were created.
    for ([_][]const u8{
        iso_path ++ "." ++ scratch_infix ++ "-rootfs.img",
        iso_path ++ "." ++ scratch_infix ++ "-payload.sqsh",
        iso_path ++ "." ++ scratch_infix ++ ".iso.tmp",
        iso_path ++ "." ++ scratch_infix ++ "-root-tree.spool",
    }) |scratch| {
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, scratch, .{}));
    }
}

test "build-iso cleans up every scratch file on a successful build" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-clean-src.iso";
    const oci_root = "test-build-iso-clean-oci";
    const output_path = "test-build-iso-clean-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
    });
    defer report.deinit(allocator);

    _ = try Io.Dir.cwd().statFile(io, output_path, .{});
    for ([_][]const u8{
        output_path ++ "." ++ scratch_infix ++ "-rootfs.img",
        output_path ++ "." ++ scratch_infix ++ "-payload.sqsh",
        output_path ++ "." ++ scratch_infix ++ ".iso.tmp",
        output_path ++ "." ++ scratch_infix ++ "-rootfs.sqsh",
        output_path ++ "." ++ scratch_infix ++ "-root-tree.spool",
    }) |scratch| {
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, scratch, .{}));
    }
}

test "build-iso dry run reports the plan without writing an output" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-build-iso-dry-src.iso";
    const oci_root = "test-build-iso-dry-oci";
    const output_path = "test-build-iso-dry-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes);
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .dry_run = true,
        .determinism = deterministic_fixture,
    });
    defer report.deinit(allocator);

    try testing.expect(report.dry_run);
    try testing.expectEqualStrings("LiveOS/squashfs.img", report.rootfs_path_in_iso);
    try testing.expectEqual(@as(u64, 0), report.output_size);
    try testing.expectEqual(@as(usize, 2), report.boot_entries.len);
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));
}
