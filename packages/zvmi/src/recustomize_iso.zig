//! `recustomize-iso`: a strict ISO-in -> customized ISO-out recustomization
//! product.
//!
//! Where `build-iso` regenerates a customized LiveOS ISO by *discovering* (or
//! being told) which boot images to wire into a freshly authored El Torito
//! catalog, `recustomize-iso` treats the source ISO as authoritative and
//! preserves it: before it creates any scratch artifact it runs the strict
//! `iso9660.Reader.inspectForRewrite` gate, and if the source carries any
//! feature the native writer cannot losslessly reproduce it refuses with a
//! structured diagnostic (kind, path, catalog index, detail) rather than
//! silently dropping the construct. There is no best-effort fallback.
//!
//! When the source is losslessly rewritable it:
//!   * preserves every modeled source filesystem node other than the replaced
//!     LiveOS payload -- path/name, file/symlink bytes, POSIX mode/uid/gid, and
//!     modeled timestamps;
//!   * preserves the modeled primary volume metadata (volume/system/volume-set/
//!     publisher/preparer/application ids) through the writer options, and
//!     verifies the round-trip against the completed scratch ISO *before* the
//!     atomic publish, so a failed check leaves no output behind;
//!   * reproduces the supported El Torito catalog exactly from the inspected
//!     source -- the validation entry's platform assignment and 24-byte id
//!     string, each section header's platform, order, final-vs-more indicator
//!     and 28-byte id string, and every entry's bootable flag, no-emulation
//!     type, load segment, system type, and sector count -- passing the source
//!     layout through the writer's `boot_catalog` option rather than
//!     normalizing it, and mapping each boot entry back to its source tree
//!     path, so the user never re-specifies a boot image; and
//!   * replaces only the discovered (or explicitly named) LiveOS payload with a
//!     native zstd SquashFS wrapping a customized ext4 `rootfs.img`.
//!
//! The customized root tree and the ext4/SquashFS/ISO rewrite mechanics are the
//! ones `build-iso` uses -- `build_image.materializeCustomizedRootTree` plus the
//! shared `build_iso` helpers (`writeRootfsImage`, `wrapSquashfsPayload`,
//! `OutputIsoTree`, `hashFile`) -- so there is one pipeline, not a third.
//!
//! PXE is out of scope: this product only reads an optical ISO and writes an
//! optical ISO.

const std = @import("std");
const Io = std.Io;

const bootconfig = @import("bootconfig.zig");
const build_image = @import("build_image.zig");
const build_iso = @import("build_iso.zig");
const ext4 = @import("ext4.zig");
const iso9660 = @import("iso9660.zig");
const limits_mod = @import("limits.zig");
const oci = @import("oci.zig");
const os_customization = @import("os_customization.zig");
const root_tree_mod = @import("root_tree.zig");
const squashfs = @import("squashfs.zig");

pub const EventSink = build_image.EventSink;
/// The customized-root-tree materialization and ISO rewrite advance the same
/// ordered stage set `build-iso` does, so `recustomize-iso` reuses it.
pub const Stage = build_iso.Stage;
pub const StageSink = build_iso.StageSink;
/// El Torito firmware platform, shared with `build-iso`.
pub const BootPlatform = build_iso.BootPlatform;
/// Fixed values that make a rewrite byte-for-byte reproducible, shared with
/// `build-iso`.
pub const Determinism = build_iso.Determinism;

/// Conventional path of the ext4 image nested inside the regenerated SquashFS.
pub const default_nested_rootfs_path = build_iso.default_nested_rootfs_path;

const scratch_infix = "recustomize-iso";

pub const RecustomizeIsoOptions = struct {
    /// Source LiveOS ISO. It is treated as authoritative: its directory tree,
    /// node metadata/timestamps, volume metadata, and El Torito catalog are all
    /// preserved; only its LiveOS payload is replaced.
    iso_path: []const u8,
    /// OCI image-layout directory or docker/podman `save` archive whose content
    /// is overlaid onto the customized root tree.
    container_path: []const u8,
    oci_load_options: oci.LoadOptions = .{},
    /// Where the recustomized ISO is written. Published atomically.
    output_path: []const u8,
    /// Size in bytes of the ext4 `rootfs.img` before it is wrapped in SquashFS.
    /// Rounded up to the ext4 block size. Must be large enough to hold the
    /// customized tree.
    rootfs_size: u64,
    /// LiveOS payload path in the source ISO to replace. Null discovers it the
    /// same way `build-image`/`build-iso` do. The regenerated SquashFS is
    /// written back to exactly this path; every other node is preserved.
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
    determinism: ?Determinism = null,
    /// Receives the first precise rewrite blocker on a strict refusal. Free its
    /// content with `RecustomizeDiagnostic.deinit`.
    diagnostic: ?*RecustomizeDiagnostic = null,
    event_sink: ?EventSink = null,
    stage_sink: ?StageSink = null,
    dry_run: bool = false,
    verbose: bool = false,
};

/// A preserved El Torito boot entry, carrying every field the native writer
/// reproduces plus the source tree path the image was mapped back to.
pub const PreservedBootEntry = struct {
    platform: BootPlatform,
    /// Root-relative path (no leading slash) of the boot image in both the
    /// source and output trees.
    image_path: []u8,
    load_segment: u16,
    system_type: u8,
    load_sectors: u16,
    bootable: bool,
};

/// The precise reason a source ISO cannot be losslessly recustomized. Mirrors
/// the strict gate's `iso9660.UnsupportedFeature` set and adds the writer-model
/// boot-catalog mapping refusals this product enforces.
pub const RecustomizeDiagnostic = struct {
    kind: Kind,
    /// Affected tree path (no leading slash trimming applied), or empty when the
    /// blocker is not tied to a single node. Owned.
    path: []u8 = &.{},
    /// Zero-based catalog index of the offending boot entry, when the blocker is
    /// an El Torito entry.
    catalog_index: ?usize = null,
    /// Short human-readable note (SUSP tag, media type, extent LBA, platform
    /// id, ...) or empty. Owned.
    detail: []u8 = &.{},

    pub const Kind = enum {
        // Source-level blockers surfaced by the strict `inspectForRewrite` gate.
        rock_ridge_relocation,
        rock_ridge_device_node,
        rock_ridge_sparse_file,
        unknown_susp_record,
        interleaved_file,
        extended_attribute_record,
        multi_extent_directory,
        duplicate_directory_entry,
        boot_media_emulation,
        boot_section_extension,
        boot_image_unmapped,
        // Writer-model mapping refusals enforced by this product.
        unsupported_boot_platform,
        duplicate_boot_platform,
        boot_selection_criteria,

        pub fn describe(self: Kind) []const u8 {
            return switch (self) {
                .rock_ridge_relocation => "rock-ridge directory relocation (CL/PL/RE)",
                .rock_ridge_device_node => "rock-ridge device node (PN)",
                .rock_ridge_sparse_file => "rock-ridge sparse file (SF)",
                .unknown_susp_record => "unmodeled SUSP/RRIP system-use record",
                .interleaved_file => "interleaved file (non-zero file unit / interleave gap)",
                .extended_attribute_record => "extended attribute record length",
                .multi_extent_directory => "multi-extent directory",
                .duplicate_directory_entry => "ambiguous duplicate directory entry",
                .boot_media_emulation => "el torito floppy/hard-disk emulation",
                .boot_section_extension => "el torito selection-criteria extension record",
                .boot_image_unmapped => "el torito boot image outside modeled files",
                .unsupported_boot_platform => "el torito boot platform the writer cannot emit",
                .duplicate_boot_platform => "more than one el torito entry for one platform",
                .boot_selection_criteria => "el torito selection criteria the writer cannot emit",
            };
        }
    };

    pub fn deinit(self: *RecustomizeDiagnostic, allocator: std.mem.Allocator) void {
        if (self.path.len > 0) allocator.free(self.path);
        if (self.detail.len > 0) allocator.free(self.detail);
        self.* = .{ .kind = self.kind };
    }
};

pub const RecustomizeIsoReport = struct {
    architecture: bootconfig.Architecture,
    dry_run: bool,
    /// True when the strict inspection found nothing that blocks a lossless
    /// rewrite. Always true on the success path (a blocked source returns an
    /// error and a diagnostic instead).
    strict_inspection_clean: bool,
    /// The LiveOS payload path the regenerated SquashFS was written to.
    rootfs_path_in_iso: []u8,
    /// Path of the ext4 image nested inside the SquashFS.
    nested_rootfs_path: []u8,
    /// ext4 `rootfs.img` size after block rounding.
    rootfs_size: u64,
    root_tree_digest: ?[32]u8 = null,
    /// Number of source filesystem nodes preserved verbatim into the output
    /// (every modeled node except the replaced payload).
    preserved_node_count: usize,
    /// Preserved El Torito boot entries, each mapped back to its source path.
    boot_entries: []PreservedBootEntry,
    squashfs_compression: squashfs.WriterCompression,
    /// SHA-256 and byte length of the source ISO.
    source_sha256: [32]u8 = [_]u8{0} ** 32,
    source_size: u64 = 0,
    /// Volume metadata modeled from the source ISO.
    source_volume: iso9660.VolumeMetadata,
    /// Volume metadata read back from the completed scratch ISO before it is
    /// published (equal to the source's, re-read and verified to prove the
    /// writer preserved it). For a dry run this mirrors the source metadata that
    /// would be written.
    output_volume: iso9660.VolumeMetadata,
    /// Total output ISO size in bytes (0 for a dry run).
    output_size: u64 = 0,
    /// SHA-256 of the published ISO (all zero for a dry run).
    output_sha256: [32]u8 = [_]u8{0} ** 32,
    limit_peaks: limits_mod.Peaks = .{},

    pub fn deinit(self: *RecustomizeIsoReport, allocator: std.mem.Allocator) void {
        allocator.free(self.rootfs_path_in_iso);
        allocator.free(self.nested_rootfs_path);
        for (self.boot_entries) |entry| allocator.free(entry.image_path);
        allocator.free(self.boot_entries);
        self.source_volume.deinit(allocator);
        self.output_volume.deinit(allocator);
        self.* = undefined;
    }

    /// Count of preserved boot entries whose platform is `platform`.
    pub fn bootPlatformCount(self: RecustomizeIsoReport, platform: BootPlatform) usize {
        var count: usize = 0;
        for (self.boot_entries) |entry| {
            if (entry.platform == platform) count += 1;
        }
        return count;
    }
};

fn logStep(options: RecustomizeIsoOptions, message: []const u8) void {
    if (options.event_sink) |sink| {
        sink.emit(.{ .progress = message });
    } else if (options.verbose) {
        std.debug.print("recustomize-iso: {s}\n", .{message});
    }
}

fn enterStage(options: RecustomizeIsoOptions, stage: Stage) !void {
    if (options.stage_sink) |sink| {
        if (!sink.advance(stage)) return error.InvalidOperationOrder;
    }
}

pub fn build(
    allocator: std.mem.Allocator,
    io: Io,
    options: RecustomizeIsoOptions,
) !RecustomizeIsoReport {
    try enterStage(options, .load_sources);
    if (options.rootfs_size == 0) return error.ZeroRootfsSize;
    try validateBuildPathIsolation(allocator, io, options);

    // Open the source ISO and, before any scratch artifact is created, run the
    // strict rewrite gate. A source with any unpreservable feature is refused
    // here with a structured diagnostic and no output/scratch is ever written.
    logStep(options, "open source ISO");
    var iso_reader = try iso9660.Reader.openPath(allocator, io, options.iso_path);
    var iso_reader_open = true;
    defer if (iso_reader_open) iso_reader.close(io);

    logStep(options, "strict rewrite inspection");
    var inspection = try iso_reader.inspectForRewrite(allocator, io);
    var inspection_open = true;
    defer if (inspection_open) inspection.deinit();
    if (inspection.firstUnsupported()) |first| {
        try setDiagnosticFromFeature(options.diagnostic, allocator, inspection, first);
        return error.SourceNotRewritable;
    }

    // Preserve the modeled volume metadata and rebuild the supported El Torito
    // catalog from the inspection, mapping every entry back to a source path.
    var source_volume = try dupeVolumeMetadata(allocator, inspection.volume);
    var source_volume_owned = false;
    defer if (!source_volume_owned) source_volume.deinit(allocator);

    logStep(options, "reconstruct El Torito catalog from source");
    const catalog = try reconstructCatalog(allocator, inspection.boot, options.diagnostic);
    var catalog_entries_owned = false;
    defer if (!catalog_entries_owned) freeBootEntries(allocator, catalog.entries);
    defer if (catalog.layout) |layout| layout.deinit(allocator);
    const boot_entries = catalog.entries;

    inspection.deinit();
    inspection_open = false;

    logStep(options, "hash source ISO");
    const source_digest = try build_iso.hashFile(allocator, io, options.iso_path);

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

    const rootfs_path_in_iso = try build_image.discoverRootfsPathInIso(allocator, &iso_reader, options.rootfs_path_in_iso);
    var rootfs_path_owned = false;
    defer if (!rootfs_path_owned) allocator.free(rootfs_path_in_iso);

    const nested_rootfs_path = try allocator.dupe(u8, build_iso.trimLeadingSlash(options.nested_rootfs_path));
    var nested_rootfs_owned = false;
    defer if (!nested_rootfs_owned) allocator.free(nested_rootfs_path);

    // Capture the source payload's modeled timestamp so a non-deterministic
    // rewrite still stamps the regenerated payload with a stable value rather
    // than the wall clock.
    const source_payload_mtime: i64 = blk: {
        const lookup = std.fmt.allocPrint(allocator, "/{s}", .{build_iso.trimLeadingSlash(rootfs_path_in_iso)}) catch break :blk 0;
        defer allocator.free(lookup);
        const idx = iso_reader.lookup(lookup) catch break :blk 0;
        break :blk iso_reader.getEntry(idx).mtime;
    };

    var output_volume = try dupeVolumeMetadata(allocator, source_volume);
    var output_volume_owned = false;
    defer if (!output_volume_owned) output_volume.deinit(allocator);

    var report = RecustomizeIsoReport{
        .architecture = architecture,
        .dry_run = options.dry_run,
        .strict_inspection_clean = true,
        .rootfs_path_in_iso = rootfs_path_in_iso,
        .nested_rootfs_path = nested_rootfs_path,
        .rootfs_size = build_iso.alignUp(options.rootfs_size, ext4.default_block_size),
        .preserved_node_count = 0,
        .boot_entries = boot_entries,
        .squashfs_compression = options.squashfs_compression,
        .source_sha256 = source_digest.sha256,
        .source_size = source_digest.size,
        .source_volume = source_volume,
        .output_volume = output_volume,
    };
    source_volume_owned = true;
    output_volume_owned = true;
    catalog_entries_owned = true;
    rootfs_path_owned = true;
    nested_rootfs_owned = true;
    errdefer report.deinit(allocator);

    // Compute the real number of preserved source nodes (every source node
    // except the replaced payload) up front, so a dry run reports the same count
    // the full run will. The source reader is still open here; materialization
    // (which releases it) only happens on the non-dry-run path below.
    report.preserved_node_count = try build_iso.countPreservedNodes(allocator, io, &iso_reader, rootfs_path_in_iso);

    if (options.dry_run) return report;

    const customization_epoch: u64 = if (options.determinism) |deterministic|
        deterministic.filesystem_timestamp
    else blk: {
        const now: i64 = @intCast(@divTrunc(Io.Clock.real.now(io).nanoseconds, std.time.ns_per_s));
        if (now < 0) return error.InvalidSystemTime;
        break :blk @intCast(now);
    };

    var materialize_stage_bridge = build_iso.MaterializeStageBridge{ .sink = options.stage_sink orelse undefined };
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
                    .{ .context = &materialize_stage_bridge, .advanceFn = build_iso.MaterializeStageBridge.advance }
                else
                    null,
                .verbose = options.verbose,
                .label = "recustomize-iso",
            },
        },
    );
    defer root_tree.deinit();

    report.root_tree_digest = try root_tree.manifestDigest();
    if (options.limit_diagnostic) |sink| report.limit_peaks = sink.peaks;

    const timestamp: u32 = if (options.determinism) |d| d.filesystem_timestamp else 0;
    const replacement_mtime: i64 = if (options.determinism) |d| @intCast(d.filesystem_timestamp) else source_payload_mtime;

    // 1. Write the customized root tree to a deterministic ext4 rootfs.img.
    try enterStage(options, .write_rootfs_image);
    const rootfs_scratch = try std.fmt.allocPrint(allocator, "{s}.{s}-rootfs.img", .{ options.output_path, scratch_infix });
    defer allocator.free(rootfs_scratch);
    var rootfs_written = false;
    defer if (rootfs_written) Io.Dir.cwd().deleteFile(io, rootfs_scratch) catch {};
    logStep(options, "write ext4 rootfs.img");
    try build_iso.writeRootfsImage(allocator, io, rootfs_scratch, &root_tree, .{
        .length = report.rootfs_size,
        .ext4_label = options.ext4_label,
        .ext4_journal = options.ext4_journal,
        .root_selinux_label = options.root_selinux_label,
        .uuid = build_iso.resolveRootUuid(io, options.determinism),
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
    const payload_size = try build_iso.wrapSquashfsPayload(allocator, io, rootfs_scratch, report.rootfs_size, payload_scratch, nested_rootfs_path, options.squashfs_compression, timestamp);
    payload_written = true;

    // 3. Reassemble the ISO tree: the full source directory tree with only the
    //    payload replaced, preserving every other node's metadata and modeled
    //    timestamps. Materialization released the source reader, so reopen it.
    try enterStage(options, .assemble_iso_tree);
    logStep(options, "reopen source ISO for output tree");
    var source_reader = try iso9660.Reader.openPath(allocator, io, options.iso_path);
    defer source_reader.close(io);

    const payload_file = try Io.Dir.cwd().openFile(io, payload_scratch, .{ .mode = .read_only });
    defer payload_file.close(io);

    var output_tree = try build_iso.OutputIsoTree.init(
        allocator,
        io,
        &source_reader,
        rootfs_path_in_iso,
        payload_file,
        payload_size,
        .preserve_source,
        replacement_mtime,
    );
    defer output_tree.deinit();
    report.preserved_node_count = output_tree.preservedNodeCount();

    // 4. Write the ISO to a scratch path, verify it, then publish it atomically.
    //    Volume metadata is preserved through the writer options and the El
    //    Torito catalog is reproduced exactly (validation platform/id string,
    //    section grouping/order/id strings, entry order) via `boot_catalog`.
    try enterStage(options, .write_iso);
    const iso_scratch = try std.fmt.allocPrint(allocator, "{s}.{s}.iso.tmp", .{ options.output_path, scratch_infix });
    defer allocator.free(iso_scratch);
    var iso_written = false;
    defer if (iso_written) Io.Dir.cwd().deleteFile(io, iso_scratch) catch {};
    logStep(options, "write output ISO");
    _ = try iso9660.writeImagePath(allocator, io, iso_scratch, output_tree.treeSource(), .{
        .volume_id = report.source_volume.volume_id,
        .system_id = report.source_volume.system_id,
        .volume_set_id = report.source_volume.volume_set_id,
        .publisher_id = report.source_volume.publisher_id,
        .preparer_id = report.source_volume.preparer_id,
        .application_id = report.source_volume.application_id,
        .boot_catalog = if (catalog.layout) |layout| layout.writerLayout() else null,
    });
    iso_written = true;

    logStep(options, "hash output ISO");
    const digest = try build_iso.hashFile(allocator, io, iso_scratch);
    report.output_size = digest.size;
    report.output_sha256 = digest.sha256;

    // Verify the volume metadata round-tripped into the *scratch* ISO before the
    // atomic rename. All fallible verification runs pre-publish, so any error
    // returned here leaves no output behind (the scratch is cleaned up).
    logStep(options, "verify output volume metadata round-trip");
    {
        var verified_volume = try verifyOutputVolumeRoundTrip(allocator, io, iso_scratch, report.source_volume);
        report.output_volume.deinit(allocator);
        report.output_volume = verified_volume;
        verified_volume = undefined;
    }

    try enterStage(options, .publish_output);
    logStep(options, "publish output ISO");
    try Io.Dir.rename(Io.Dir.cwd(), iso_scratch, Io.Dir.cwd(), options.output_path, io);
    iso_written = false;

    return report;
}

fn dupeVolumeMetadata(allocator: std.mem.Allocator, src: iso9660.VolumeMetadata) !iso9660.VolumeMetadata {
    var out = iso9660.VolumeMetadata{
        .volume_id = &.{},
        .system_id = &.{},
        .volume_set_id = &.{},
        .publisher_id = &.{},
        .preparer_id = &.{},
        .application_id = &.{},
    };
    errdefer out.deinit(allocator);
    out.volume_id = try allocator.dupe(u8, src.volume_id);
    out.system_id = try allocator.dupe(u8, src.system_id);
    out.volume_set_id = try allocator.dupe(u8, src.volume_set_id);
    out.publisher_id = try allocator.dupe(u8, src.publisher_id);
    out.preparer_id = try allocator.dupe(u8, src.preparer_id);
    out.application_id = try allocator.dupe(u8, src.application_id);
    return out;
}

fn freeBootEntries(allocator: std.mem.Allocator, entries: []PreservedBootEntry) void {
    for (entries) |entry| allocator.free(entry.image_path);
    allocator.free(entries);
}

/// Owns the backing memory for the exact El Torito catalog layout handed to the
/// native writer. The `image_path` fields inside `default_entry` and the section
/// entries borrow from the sibling `ReconstructedCatalog.entries` allocations, so
/// this must be released while those entries are still alive.
const LayoutStorage = struct {
    validation_platform: u8,
    validation_id: [24]u8,
    default_entry: iso9660.BootImageEntry,
    /// Section headers in catalog order; each `.entries` slice points into
    /// `section_entries`.
    sections: []iso9660.BootCatalogSection,
    /// Flat storage for every section's entries, in catalog order.
    section_entries: []iso9660.BootImageEntry,

    fn deinit(self: LayoutStorage, allocator: std.mem.Allocator) void {
        allocator.free(self.sections);
        allocator.free(self.section_entries);
    }

    fn writerLayout(self: LayoutStorage) iso9660.BootCatalogLayout {
        return .{
            .validation_platform = self.validation_platform,
            .validation_id = self.validation_id,
            .default_entry = self.default_entry,
            .sections = self.sections,
        };
    }
};

/// The reconstructed source catalog: a flattened `entries` list for the report
/// plus the exact `layout` the writer reproduces (null when the source carried
/// no boot record). Ownership of `entries` is transferred to the report;
/// `layout` is released by the caller once the write completes.
const ReconstructedCatalog = struct {
    entries: []PreservedBootEntry,
    layout: ?LayoutStorage,
};

fn imageEntryFromPreserved(entry: PreservedBootEntry) iso9660.BootImageEntry {
    return .{
        .image_path = entry.image_path,
        .load_segment = entry.load_segment,
        .system_type = entry.system_type,
        .load_sectors = entry.load_sectors,
        .bootable = entry.bootable,
    };
}

/// Rebuilds the supported El Torito catalog from the inspected source, mapping
/// each boot entry back to a source tree path and preserving every field the
/// native writer reproduces -- including, via the returned `layout`, the exact
/// validation platform assignment and its 24-byte id string, the section
/// grouping/order and final-vs-more indicators, the 28-byte section header id
/// strings, and the entry order. The catalog is passed through unchanged rather
/// than normalized. Refuses -- before any scratch is created -- any entry the
/// writer model cannot represent (a platform other than BIOS/UEFI, more than one
/// entry per platform, or selection criteria), and defensively re-checks the
/// media/emulation and mapping invariants the strict gate already enforced. A
/// source with no boot record yields an empty (non-bootable) catalog with a null
/// layout, faithfully preserving that the source had none.
fn reconstructCatalog(
    allocator: std.mem.Allocator,
    boot: ?iso9660.BootModel,
    diagnostic: ?*RecustomizeDiagnostic,
) !ReconstructedCatalog {
    const model = boot orelse return .{
        .entries = try allocator.alloc(PreservedBootEntry, 0),
        .layout = null,
    };

    var list = std.array_list.Managed(PreservedBootEntry).init(allocator);
    errdefer {
        for (list.items) |entry| allocator.free(entry.image_path);
        list.deinit();
    }

    var saw_bios = false;
    var saw_uefi = false;
    var note_buf: [48]u8 = undefined;

    for (model.entries, 0..) |inspected, idx| {
        const entry = inspected.entry;

        if (entry.media != .no_emulation) {
            const note = std.fmt.bufPrint(&note_buf, "media {d}", .{entry.media_type & 0x0F}) catch "media";
            try setDiagnostic(diagnostic, allocator, .boot_media_emulation, &.{}, idx, note);
            return error.SourceNotRewritable;
        }
        if (entry.kind == .section and entry.selection_criteria_type != 0) {
            const note = std.fmt.bufPrint(&note_buf, "type {d}", .{entry.selection_criteria_type}) catch "type";
            try setDiagnostic(diagnostic, allocator, .boot_selection_criteria, &.{}, idx, note);
            return error.BootSelectionCriteria;
        }

        const path: []const u8 = switch (inspected.image) {
            .mapped => |mapped| mapped.path,
            .raw_extent => |raw| {
                const note = std.fmt.bufPrint(&note_buf, "lba {d}", .{raw.lba}) catch "lba";
                try setDiagnostic(diagnostic, allocator, .boot_image_unmapped, &.{}, idx, note);
                return error.SourceNotRewritable;
            },
        };

        const platform: BootPlatform = switch (entry.platform) {
            iso9660.boot_platform_bios => .bios,
            iso9660.boot_platform_uefi => .uefi,
            else => {
                const note = std.fmt.bufPrint(&note_buf, "platform 0x{X:0>2}", .{entry.platform}) catch "platform";
                try setDiagnostic(diagnostic, allocator, .unsupported_boot_platform, &.{}, idx, note);
                return error.UnsupportedBootPlatform;
            },
        };

        switch (platform) {
            .bios => {
                if (saw_bios) {
                    try setDiagnostic(diagnostic, allocator, .duplicate_boot_platform, &.{}, idx, "bios");
                    return error.DuplicateBootPlatform;
                }
                saw_bios = true;
            },
            .uefi => {
                if (saw_uefi) {
                    try setDiagnostic(diagnostic, allocator, .duplicate_boot_platform, &.{}, idx, "uefi");
                    return error.DuplicateBootPlatform;
                }
                saw_uefi = true;
            },
        }

        try list.append(.{
            .platform = platform,
            .image_path = try allocator.dupe(u8, build_iso.trimLeadingSlash(path)),
            .load_segment = entry.load_segment,
            .system_type = entry.system_type,
            .load_sectors = entry.load_sectors,
            .bootable = entry.bootable,
        });
    }

    const entries = try list.toOwnedSlice();
    errdefer freeBootEntries(allocator, entries);

    // With every entry validated, assemble the exact writer layout. The reader
    // lays the flattened `entries` list out as [default] followed by each
    // section header's run of entries, so re-group them the same way and carry
    // the validation entry and section headers through byte for byte. A source
    // with no boot record was handled above; here `entries` always holds at
    // least the default entry.
    const layout: ?LayoutStorage = if (entries.len == 0) null else blk: {
        const sections = try allocator.alloc(iso9660.BootCatalogSection, model.headers.len);
        errdefer allocator.free(sections);
        const section_entries = try allocator.alloc(iso9660.BootImageEntry, entries.len - 1);
        errdefer allocator.free(section_entries);

        var entry_cursor: usize = 1; // entries[0] is the default entry
        var sec_cursor: usize = 0;
        for (model.headers, 0..) |header, hidx| {
            const start = sec_cursor;
            var c: u16 = 0;
            while (c < header.entry_count and entry_cursor < entries.len) : (c += 1) {
                section_entries[sec_cursor] = imageEntryFromPreserved(entries[entry_cursor]);
                entry_cursor += 1;
                sec_cursor += 1;
            }
            sections[hidx] = .{
                .platform = header.platform,
                .final = header.final,
                .id_string = header.id_string,
                .entries = section_entries[start..sec_cursor],
            };
        }

        break :blk .{
            .validation_platform = model.validation.platform,
            .validation_id = model.validation.id_string,
            .default_entry = imageEntryFromPreserved(entries[0]),
            .sections = sections,
            .section_entries = section_entries,
        };
    };

    return .{ .entries = entries, .layout = layout };
}

/// Reads the volume metadata back from the freshly written but not-yet-published
/// scratch ISO and verifies it round-tripped from `source`. Returns the
/// read-back metadata (caller owns it) so the report can prove preservation.
/// Because callers run this before the atomic rename, a returned error leaves no
/// output published.
fn verifyOutputVolumeRoundTrip(
    allocator: std.mem.Allocator,
    io: Io,
    scratch_path: []const u8,
    source: iso9660.VolumeMetadata,
) !iso9660.VolumeMetadata {
    const file = try Io.Dir.cwd().openFile(io, scratch_path, .{ .mode = .read_only });
    defer file.close(io);
    var readback = try iso9660.readVolumeMetadataAlloc(allocator, io, file);
    errdefer readback.deinit(allocator);
    if (!volumeMetadataEqual(readback, source)) return error.OutputVolumeMismatch;
    return readback;
}

fn volumeMetadataEqual(a: iso9660.VolumeMetadata, b: iso9660.VolumeMetadata) bool {
    return std.mem.eql(u8, a.volume_id, b.volume_id) and
        std.mem.eql(u8, a.system_id, b.system_id) and
        std.mem.eql(u8, a.volume_set_id, b.volume_set_id) and
        std.mem.eql(u8, a.publisher_id, b.publisher_id) and
        std.mem.eql(u8, a.preparer_id, b.preparer_id) and
        std.mem.eql(u8, a.application_id, b.application_id);
}

fn setDiagnostic(
    diagnostic: ?*RecustomizeDiagnostic,
    allocator: std.mem.Allocator,
    kind: RecustomizeDiagnostic.Kind,
    path: []const u8,
    catalog_index: ?usize,
    detail: []const u8,
) !void {
    const slot = diagnostic orelse return;
    const path_copy: []u8 = if (path.len > 0) try allocator.dupe(u8, path) else &.{};
    errdefer if (path_copy.len > 0) allocator.free(path_copy);
    const detail_copy: []u8 = if (detail.len > 0) try allocator.dupe(u8, detail) else &.{};
    slot.* = .{
        .kind = kind,
        .path = path_copy,
        .catalog_index = catalog_index,
        .detail = detail_copy,
    };
}

fn setDiagnosticFromFeature(
    diagnostic: ?*RecustomizeDiagnostic,
    allocator: std.mem.Allocator,
    inspection: iso9660.RewriteInspection,
    detail: iso9660.UnsupportedDetail,
) !void {
    try setDiagnostic(
        diagnostic,
        allocator,
        kindFromFeature(detail.feature),
        detail.path,
        resolveCatalogIndex(inspection, detail.feature),
        detail.note,
    );
}

fn kindFromFeature(feature: iso9660.UnsupportedFeature) RecustomizeDiagnostic.Kind {
    return switch (feature) {
        .rock_ridge_relocation => .rock_ridge_relocation,
        .rock_ridge_device_node => .rock_ridge_device_node,
        .rock_ridge_sparse_file => .rock_ridge_sparse_file,
        .unknown_susp_record => .unknown_susp_record,
        .interleaved_file => .interleaved_file,
        .extended_attribute_record => .extended_attribute_record,
        .multi_extent_directory => .multi_extent_directory,
        .duplicate_directory_entry => .duplicate_directory_entry,
        .boot_media_emulation => .boot_media_emulation,
        .boot_section_extension => .boot_section_extension,
        .boot_image_unmapped => .boot_image_unmapped,
    };
}

/// Best-effort locates the catalog index of the first boot entry that triggered
/// a boot-related gate feature, so the diagnostic can name it.
fn resolveCatalogIndex(inspection: iso9660.RewriteInspection, feature: iso9660.UnsupportedFeature) ?usize {
    const model = inspection.boot orelse return null;
    for (model.entries, 0..) |inspected, idx| {
        const matches = switch (feature) {
            .boot_media_emulation => inspected.entry.media != .no_emulation,
            .boot_section_extension => inspected.entry.has_extension,
            .boot_image_unmapped => inspected.image == .raw_extent,
            else => false,
        };
        if (matches) return idx;
    }
    return null;
}

fn validateBuildPathIsolation(allocator: std.mem.Allocator, io: Io, options: RecustomizeIsoOptions) !void {
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

test {
    std.testing.refAllDecls(@This());
}

// ===========================================================================
// Tests
// ===========================================================================

const testing = std.testing;

const deterministic_fixture = Determinism{
    .filesystem_timestamp = 1_700_000_000,
    .root_filesystem_uuid = [_]u8{0x22} ** 16,
};

const FixtureNode = struct {
    path: []const u8,
    kind: iso9660.SourceKind,
    mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
    bytes: []const u8 = &.{},
    symlink_target: []const u8 = &.{},
};

const FixtureIsoSource = struct {
    nodes: []const FixtureNode,
    root_mtime: i64 = 0,

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
    fn rootFn(context: *const anyopaque) iso9660.SourceRoot {
        return .{ .mode = 0o755, .mtime = ctx(context).root_mtime };
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!iso9660.SourceNode {
        const n = ctx(context).nodes[index];
        return .{
            .path = n.path,
            .kind = n.kind,
            .mode = n.mode,
            .uid = n.uid,
            .gid = n.gid,
            .mtime = n.mtime,
            .size = if (n.kind == .symlink) n.symlink_target.len else n.bytes.len,
            .symlink_target = n.symlink_target,
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

const fixture_volume = iso9660.WriteOptions{
    .volume_id = "ZVMI_SRC",
    .system_id = "ZVMI-SYSTEM",
    .volume_set_id = "ZVMI-SET",
    .publisher_id = "ZVMI-PUBLISHER",
    .preparer_id = "ZVMI-PREPARER",
    .application_id = "ZVMI-APP",
};

/// Distinct, non-zero modeled timestamps per node so timestamp preservation is
/// meaningfully testable (not everything collapsing to 0).
fn fixtureNodes() [11]FixtureNode {
    const base: i64 = 1_600_000_000;
    return [_]FixtureNode{
        .{ .path = "LiveOS", .kind = .directory, .mode = 0o755, .mtime = base + 100 },
        .{ .path = "LiveOS/squashfs.img", .kind = .file, .mode = 0o444, .mtime = base + 200, .bytes = undefined },
        .{ .path = "boot", .kind = .directory, .mode = 0o755, .mtime = base + 300 },
        .{ .path = "boot/grub2", .kind = .directory, .mode = 0o755, .mtime = base + 400 },
        .{ .path = "boot/grub2/grub.cfg", .kind = .file, .mode = 0o644, .uid = 3, .gid = 4, .mtime = base + 500, .bytes = "set default=0\nlinux /boot/vmlinuz root=live:CDLABEL=ZVMI_SRC rd.live.image\n" },
        .{ .path = "boot/grub2/efiboot.img", .kind = .file, .mode = 0o644, .mtime = base + 600, .bytes = "UEFI-EL-TORITO-BOOT-IMAGE-CONTENTS" },
        .{ .path = "boot/grub2/i386-pc", .kind = .directory, .mode = 0o755, .mtime = base + 700 },
        .{ .path = "boot/grub2/i386-pc/eltorito.img", .kind = .file, .mode = 0o644, .mtime = base + 800, .bytes = "BIOS-EL-TORITO-BOOT-IMAGE-CONTENTS" },
        .{ .path = "boot/grub2/alias.cfg", .kind = .symlink, .mode = 0o777, .mtime = base + 900, .symlink_target = "grub.cfg" },
        .{ .path = "EFI", .kind = .directory, .mode = 0o755, .mtime = base + 1000 },
        .{ .path = "EFI/BOOT", .kind = .directory, .mode = 0o755, .mtime = base + 1100 },
    };
}

const uefi_boot_entry = iso9660.BootEntry{ .platform = .uefi, .image_path = "boot/grub2/efiboot.img", .load_segment = 0, .system_type = 0, .load_sectors = 4, .bootable = true };
const bios_boot_entry = iso9660.BootEntry{ .platform = .bios, .image_path = "boot/grub2/i386-pc/eltorito.img", .load_segment = 0x7C0, .system_type = 0x12, .load_sectors = 8, .bootable = true };

/// Writes a source LiveOS ISO fixture with the given SquashFS payload and El
/// Torito boot entries, preserving the standard fixture volume metadata.
fn writeSourceIso(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    squashfs_bytes: []const u8,
    boot_entries: []const iso9660.BootEntry,
) !void {
    var nodes = fixtureNodes();
    nodes[1].bytes = squashfs_bytes;
    const src = FixtureIsoSource{ .nodes = &nodes, .root_mtime = 1_600_000_050 };
    var opts = fixture_volume;
    opts.boot_entries = boot_entries;
    _ = try iso9660.writeImagePath(allocator, io, path, src.source(), opts);
}

/// Writes a source LiveOS ISO fixture whose El Torito catalog is authored with
/// an exact `BootCatalogLayout` (rather than the BIOS-first `boot_entries`
/// convention), so a test can build a source carrying, e.g., a UEFI
/// validation/default entry, a BIOS section, and non-empty id strings.
fn writeSourceIsoWithCatalog(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    squashfs_bytes: []const u8,
    catalog: iso9660.BootCatalogLayout,
) !void {
    var nodes = fixtureNodes();
    nodes[1].bytes = squashfs_bytes;
    const src = FixtureIsoSource{ .nodes = &nodes, .root_mtime = 1_600_000_050 };
    var opts = fixture_volume;
    opts.boot_catalog = catalog;
    _ = try iso9660.writeImagePath(allocator, io, path, src.source(), opts);
}

// --- Minimal OCI layout fixture (mirrors build_iso's test helper) ---

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

// --- Tree comparison helpers ---

const CollectedNode = struct {
    path: []u8,
    kind: iso9660.EntryKind,
    mode: u32,
    uid: u32,
    gid: u32,
    mtime: i64,
    symlink_target: []u8,
};

fn collectTree(arena: std.mem.Allocator, io: Io, reader: *iso9660.Reader, parent: usize, prefix: []const u8, out: *std.array_list.Managed(CollectedNode)) !void {
    const children = try reader.listDirAlloc(arena, parent);
    for (children) |child| {
        const full = if (prefix.len == 0)
            try arena.dupe(u8, child.name)
        else
            try std.fmt.allocPrint(arena, "{s}/{s}", .{ prefix, child.name });
        const entry = reader.getEntry(child.index);
        const target: []u8 = if (entry.kind == .symlink)
            try arena.dupe(u8, try reader.readLink(child.index))
        else
            &.{};
        try out.append(.{
            .path = full,
            .kind = entry.kind,
            .mode = entry.mode & 0o7777,
            .uid = entry.uid,
            .gid = entry.gid,
            .mtime = entry.mtime,
            .symlink_target = target,
        });
        if (entry.kind == .directory) try collectTree(arena, io, reader, child.index, full, out);
    }
}

fn findNode(nodes: []const CollectedNode, path: []const u8) ?CollectedNode {
    for (nodes) |n| {
        if (std.mem.eql(u8, n.path, path)) return n;
    }
    return null;
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

fn hashFilePath(allocator: std.mem.Allocator, io: Io, path: []const u8) ![32]u8 {
    const digest = try build_iso.hashFile(allocator, io, path);
    return digest.sha256;
}

// --- Boot catalog patching helpers (to inject refusable features) ---

fn bootCatalogLba(io: Io, file: Io.File) !u32 {
    var sector: [2048]u8 = undefined;
    var lba: u32 = 16;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * 2048);
        if (!std.mem.eql(u8, sector[1..6], "CD001")) return error.NotFound;
        if (sector[0] == 0 and std.mem.startsWith(u8, sector[7..], "EL TORITO SPECIFICATION")) {
            return std.mem.readInt(u32, sector[71..75], .little);
        }
        if (sector[0] == 255) return error.NoBootRecord;
    }
}

/// Patches `len` bytes at `catalog_offset` inside the boot catalog of the ISO at
/// `path`, optionally recomputing the validation-entry checksum afterward.
fn patchCatalog(io: Io, path: []const u8, catalog_offset: usize, bytes: []const u8, fix_checksum: bool) !void {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    const cat_lba = try bootCatalogLba(io, file);
    const base = @as(u64, cat_lba) * 2048;
    try file.writePositionalAll(io, bytes, base + catalog_offset);
    if (fix_checksum) {
        var validation: [32]u8 = undefined;
        _ = try file.readPositionalAll(io, &validation, base);
        std.mem.writeInt(u16, validation[28..30], 0, .little);
        var sum: u16 = 0;
        var i: usize = 0;
        while (i < 32) : (i += 2) sum +%= std.mem.readInt(u16, validation[i..][0..2], .little);
        std.mem.writeInt(u16, validation[28..30], 0 -% sum, .little);
        try file.writePositionalAll(io, &validation, base);
    }
}

// --- End-to-end preservation ---

test "recustomize-iso preserves a dual BIOS+UEFI ISO: nodes/metadata/timestamps except payload, catalog semantics, and nested customized content" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-dual-src.iso";
    const oci_root = "test-recustomize-dual-oci";
    const output_path = "test-recustomize-dual-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{ bios_boot_entry, uefi_boot_entry });
    try createOciLayout(allocator, io, oci_root);

    const source_hash_before = try hashFilePath(allocator, io, iso_path);

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
        .os = .{ .hostname = "zvmi-live" },
        .determinism = deterministic_fixture,
        .stage_sink = .{ .context = &recorder, .advanceFn = StageRecorder.advance },
    });
    defer report.deinit(allocator);

    // Report facts.
    try testing.expect(report.strict_inspection_clean);
    try testing.expectEqualStrings("LiveOS/squashfs.img", report.rootfs_path_in_iso);
    try testing.expectEqualStrings("LiveOS/rootfs.img", report.nested_rootfs_path);
    try testing.expect(report.output_size > 0);
    try testing.expect(!std.mem.allEqual(u8, &report.source_sha256, 0));
    try testing.expect(!std.mem.allEqual(u8, &report.output_sha256, 0));
    try testing.expect(report.root_tree_digest != null);
    // Source volume metadata modeled and preserved.
    try testing.expectEqualStrings("ZVMI_SRC", report.source_volume.volume_id);
    try testing.expectEqualStrings("ZVMI-SYSTEM", report.source_volume.system_id);
    try testing.expectEqualStrings("ZVMI-PUBLISHER", report.source_volume.publisher_id);
    try testing.expectEqualStrings(report.source_volume.volume_id, report.output_volume.volume_id);
    try testing.expectEqualStrings(report.source_volume.system_id, report.output_volume.system_id);
    try testing.expectEqualStrings(report.source_volume.volume_set_id, report.output_volume.volume_set_id);
    try testing.expectEqualStrings(report.source_volume.publisher_id, report.output_volume.publisher_id);
    try testing.expectEqualStrings(report.source_volume.preparer_id, report.output_volume.preparer_id);
    try testing.expectEqualStrings(report.source_volume.application_id, report.output_volume.application_id);
    // Preserved node count = every fixture node except the payload.
    try testing.expectEqual(@as(usize, fixtureNodes().len - 1), report.preserved_node_count);
    // Both boot platforms preserved and mapped back to source paths.
    try testing.expectEqual(@as(usize, 2), report.boot_entries.len);
    try testing.expectEqual(@as(usize, 1), report.bootPlatformCount(.bios));
    try testing.expectEqual(@as(usize, 1), report.bootPlatformCount(.uefi));

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

    // Compare the source and output trees node-by-node (except the payload).
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var src_reader = try iso9660.Reader.openPath(allocator, io, iso_path);
    defer src_reader.close(io);
    var out_reader = try iso9660.Reader.openPath(allocator, io, output_path);
    defer out_reader.close(io);

    var src_nodes = std.array_list.Managed(CollectedNode).init(arena);
    var out_nodes = std.array_list.Managed(CollectedNode).init(arena);
    try collectTree(arena, io, &src_reader, src_reader.root_index, "", &src_nodes);
    try collectTree(arena, io, &out_reader, out_reader.root_index, "", &out_nodes);

    var saw_symlink = false;
    var saw_distinct_mtime = false;
    const first_mtime = src_nodes.items[0].mtime;
    for (src_nodes.items) |src_node| {
        if (std.mem.eql(u8, src_node.path, "LiveOS/squashfs.img")) continue; // payload
        const out_node = findNode(out_nodes.items, src_node.path) orelse {
            std.debug.print("missing preserved node: {s}\n", .{src_node.path});
            return error.MissingPreservedNode;
        };
        try testing.expectEqual(src_node.kind, out_node.kind);
        try testing.expectEqual(src_node.mode, out_node.mode);
        try testing.expectEqual(src_node.uid, out_node.uid);
        try testing.expectEqual(src_node.gid, out_node.gid);
        try testing.expectEqual(src_node.mtime, out_node.mtime);
        try testing.expectEqualStrings(src_node.symlink_target, out_node.symlink_target);
        if (src_node.kind == .symlink) saw_symlink = true;
        if (src_node.mtime != first_mtime and src_node.mtime != 0) saw_distinct_mtime = true;
    }
    // The fixture exercised a symlink and non-uniform, non-zero timestamps.
    try testing.expect(saw_symlink);
    try testing.expect(saw_distinct_mtime);

    // The payload path still exists in the output (replaced, not removed).
    _ = try out_reader.lookup("/LiveOS/squashfs.img");

    // El Torito catalog: same semantic fields per platform (image LBAs differ).
    const src_file = try Io.Dir.cwd().openFile(io, iso_path, .{ .mode = .read_only });
    defer src_file.close(io);
    const out_file = try Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_only });
    defer out_file.close(io);
    var src_catalog = try iso9660.readBootCatalog(allocator, io, src_file);
    defer src_catalog.deinit(allocator);
    var out_catalog = try iso9660.readBootCatalog(allocator, io, out_file);
    defer out_catalog.deinit(allocator);
    try testing.expectEqual(src_catalog.entries.len, out_catalog.entries.len);
    try testing.expectEqual(src_catalog.validation_platform, out_catalog.validation_platform);
    for (src_catalog.entries, out_catalog.entries) |se, oe| {
        try testing.expectEqual(se.platform, oe.platform);
        try testing.expectEqual(se.bootable, oe.bootable);
        try testing.expectEqual(se.media, oe.media);
        try testing.expectEqual(se.load_segment, oe.load_segment);
        try testing.expectEqual(se.system_type, oe.system_type);
        try testing.expectEqual(se.load_sectors, oe.load_sectors);
    }

    // Payload replaced: the regenerated SquashFS carries a nested rootfs.img
    // (the source payload did not) with the merged customized content.
    const payload_scratch = "test-recustomize-dual-payload.sqsh";
    defer Io.Dir.cwd().deleteFile(io, payload_scratch) catch {};
    try extractIsoFileToPath(allocator, io, &out_reader, "/LiveOS/squashfs.img", payload_scratch);
    var payload_reader = try squashfs.Reader.openPath(allocator, io, payload_scratch);
    defer payload_reader.close(io);

    const rootfs_scratch = "test-recustomize-dual-rootfs.img";
    defer Io.Dir.cwd().deleteFile(io, rootfs_scratch) catch {};
    try extractSquashfsFileToPath(allocator, io, &payload_reader, "/LiveOS/rootfs.img", rootfs_scratch);

    const rootfs_file = try Io.Dir.cwd().openFile(io, rootfs_scratch, .{ .mode = .read_only });
    defer rootfs_file.close(io);
    var ext4_reader = try ext4.open(io, rootfs_file, allocator, .{});
    defer ext4_reader.deinit();

    const message = try ext4_reader.readFileAlloc(io, allocator, "etc/message.txt");
    defer allocator.free(message);
    try testing.expect(message.len > 0);
    const hello = try ext4_reader.readFileAlloc(io, allocator, "app/hello.txt");
    defer allocator.free(hello);
    try testing.expectEqualStrings("hello from the OCI overlay\n", hello);
    const hostname = try ext4_reader.readFileAlloc(io, allocator, "etc/hostname");
    defer allocator.free(hostname);
    try testing.expectEqualStrings("zvmi-live\n", hostname);

    // The source ISO is unchanged.
    const source_hash_after = try hashFilePath(allocator, io, iso_path);
    try testing.expectEqualSlices(u8, &source_hash_before, &source_hash_after);
    try testing.expectEqualSlices(u8, &source_hash_before, &report.source_sha256);
}

test "recustomize-iso preserves a BIOS-only source catalog" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-bios-src.iso";
    const oci_root = "test-recustomize-bios-oci";
    const output_path = "test-recustomize-bios-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{bios_boot_entry});
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
    });
    defer report.deinit(allocator);

    try testing.expectEqual(@as(usize, 1), report.boot_entries.len);
    try testing.expectEqual(BootPlatform.bios, report.boot_entries[0].platform);
    try testing.expectEqual(@as(u16, 0x7C0), report.boot_entries[0].load_segment);
    try testing.expectEqual(@as(u8, 0x12), report.boot_entries[0].system_type);

    const out_file = try Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_only });
    defer out_file.close(io);
    var catalog = try iso9660.readBootCatalog(allocator, io, out_file);
    defer catalog.deinit(allocator);
    try testing.expectEqual(@as(usize, 1), catalog.entries.len);
    try testing.expectEqual(iso9660.boot_platform_bios, catalog.validation_platform);
    try testing.expectEqual(iso9660.boot_platform_bios, catalog.entries[0].platform);
}

test "recustomize-iso preserves a UEFI-only source catalog" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-uefi-src.iso";
    const oci_root = "test-recustomize-uefi-oci";
    const output_path = "test-recustomize-uefi-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{uefi_boot_entry});
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
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
    try testing.expectEqual(iso9660.boot_platform_uefi, catalog.validation_platform);
    try testing.expectEqual(iso9660.boot_platform_uefi, catalog.entries[0].platform);
}

test "recustomize-iso preserves an exact UEFI-validation + BIOS-section catalog with non-empty id strings" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-exact-src.iso";
    const oci_root = "test-recustomize-exact-oci";
    const output_path = "test-recustomize-exact-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);

    // Author a source whose catalog the BIOS-first `boot_entries` convention
    // could never emit: UEFI is the validation/default entry, BIOS is a section,
    // and both the validation entry and the section header carry non-empty id
    // strings.
    var validation_id = [_]u8{0} ** 24;
    @memcpy(validation_id[0..15], "ZVMI-UEFI-VALID");
    var section_id = [_]u8{0} ** 28;
    @memcpy(section_id[0..17], "ZVMI-BIOS-SECTION");
    try writeSourceIsoWithCatalog(allocator, io, iso_path, squashfs_bytes, .{
        .validation_platform = iso9660.boot_platform_uefi,
        .validation_id = validation_id,
        .default_entry = .{ .image_path = "boot/grub2/efiboot.img", .load_sectors = 4, .bootable = true },
        .sections = &.{
            .{
                .platform = iso9660.boot_platform_bios,
                .final = true,
                .id_string = section_id,
                .entries = &.{
                    .{ .image_path = "boot/grub2/i386-pc/eltorito.img", .load_segment = 0x7C0, .system_type = 0x12, .load_sectors = 8, .bootable = true },
                },
            },
        },
    });
    try createOciLayout(allocator, io, oci_root);

    var report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
    });
    defer report.deinit(allocator);

    // The report keeps the source order (UEFI default first, BIOS section next)
    // rather than normalizing to BIOS-first.
    try testing.expectEqual(@as(usize, 2), report.boot_entries.len);
    try testing.expectEqual(BootPlatform.uefi, report.boot_entries[0].platform);
    try testing.expectEqual(BootPlatform.bios, report.boot_entries[1].platform);
    try testing.expectEqual(@as(usize, 1), report.bootPlatformCount(.uefi));
    try testing.expectEqual(@as(usize, 1), report.bootPlatformCount(.bios));

    // Parse both catalogs and prove the output reproduces the source exactly:
    // validation platform + id string, section header sequence + id strings, and
    // entry order/fields (only the regenerated image LBAs are allowed to move).
    const src_file = try Io.Dir.cwd().openFile(io, iso_path, .{ .mode = .read_only });
    defer src_file.close(io);
    const out_file = try Io.Dir.cwd().openFile(io, output_path, .{ .mode = .read_only });
    defer out_file.close(io);
    var src_catalog = try iso9660.readBootCatalog(allocator, io, src_file);
    defer src_catalog.deinit(allocator);
    var out_catalog = try iso9660.readBootCatalog(allocator, io, out_file);
    defer out_catalog.deinit(allocator);

    try testing.expectEqual(iso9660.boot_platform_uefi, out_catalog.validation_platform);
    try testing.expectEqualSlices(u8, &validation_id, &out_catalog.validation.id_string);
    try testing.expectEqualSlices(u8, &src_catalog.validation.id_string, &out_catalog.validation.id_string);

    try testing.expectEqual(src_catalog.headers.len, out_catalog.headers.len);
    try testing.expectEqual(@as(usize, 1), out_catalog.headers.len);
    for (src_catalog.headers, out_catalog.headers) |sh, oh| {
        try testing.expectEqual(sh.platform, oh.platform);
        try testing.expectEqual(iso9660.boot_platform_bios, oh.platform);
        try testing.expectEqual(sh.final, oh.final);
        try testing.expect(oh.final);
        try testing.expectEqualSlices(u8, &sh.id_string, &oh.id_string);
        try testing.expectEqualSlices(u8, &section_id, &oh.id_string);
    }

    try testing.expectEqual(src_catalog.entries.len, out_catalog.entries.len);
    try testing.expectEqual(@as(usize, 2), out_catalog.entries.len);
    for (src_catalog.entries, out_catalog.entries) |se, oe| {
        try testing.expectEqual(se.kind, oe.kind);
        try testing.expectEqual(se.platform, oe.platform);
        try testing.expectEqual(se.bootable, oe.bootable);
        try testing.expectEqual(se.media, oe.media);
        try testing.expectEqual(se.load_segment, oe.load_segment);
        try testing.expectEqual(se.system_type, oe.system_type);
        try testing.expectEqual(se.load_sectors, oe.load_sectors);
    }
    // The default entry is UEFI and the section entry is BIOS, in that order.
    try testing.expectEqual(iso9660.BootEntryKind.default, out_catalog.entries[0].kind);
    try testing.expectEqual(iso9660.boot_platform_uefi, out_catalog.entries[0].platform);
    try testing.expectEqual(iso9660.BootEntryKind.section, out_catalog.entries[1].kind);
    try testing.expectEqual(iso9660.boot_platform_bios, out_catalog.entries[1].platform);
    try testing.expectEqual(@as(u16, 0x7C0), out_catalog.entries[1].load_segment);
    try testing.expectEqual(@as(u8, 0x12), out_catalog.entries[1].system_type);

    // The output still passes the strict rewrite gate unchanged.
    var out_reader = try iso9660.Reader.openPath(allocator, io, output_path);
    defer out_reader.close(io);
    var inspection = try out_reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try testing.expect(inspection.losslessWithinModel());
}

test "recustomize-iso is byte-for-byte deterministic across identical builds" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-det-src.iso";
    const oci_root = "test-recustomize-det-oci";
    const output_a = "test-recustomize-det-a.iso";
    const output_b = "test-recustomize-det-b.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_a) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_b) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{ bios_boot_entry, uefi_boot_entry });
    try createOciLayout(allocator, io, oci_root);

    const opts = RecustomizeIsoOptions{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_a,
        .rootfs_size = 24 * 1024 * 1024,
        .os = .{ .hostname = "zvmi-live" },
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

// --- Strict refusals through the public API, before any output/scratch ---

fn expectNoOutputOrScratch(io: Io, output_path: []const u8) !void {
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));
    var buf: [256]u8 = undefined;
    for ([_][]const u8{
        "-rootfs.img",
        "-payload.sqsh",
        ".iso.tmp",
        "-rootfs.sqsh",
        "-root-tree.spool",
    }) |suffix| {
        const scratch = std.fmt.bufPrint(&buf, "{s}.{s}{s}", .{ output_path, scratch_infix, suffix }) catch unreachable;
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, scratch, .{}));
    }
}

const RefusalCase = struct {
    name: []const u8,
    dual: bool,
    catalog_offset: usize,
    patch: []const u8,
    fix_checksum: bool,
    expected_error: anyerror,
    expected_kind: RecustomizeDiagnostic.Kind,
    expect_index: ?usize,
};

fn runRefusalCase(case: RefusalCase) !void {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-refuse-src.iso";
    const oci_root = "test-recustomize-refuse-oci";
    const output_path = "test-recustomize-refuse-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    const boot: []const iso9660.BootEntry = if (case.dual)
        &.{ bios_boot_entry, uefi_boot_entry }
    else
        &.{bios_boot_entry};
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, boot);
    try createOciLayout(allocator, io, oci_root);
    try patchCatalog(io, iso_path, case.catalog_offset, case.patch, case.fix_checksum);

    var diagnostic = RecustomizeDiagnostic{ .kind = .rock_ridge_relocation };
    defer diagnostic.deinit(allocator);

    try testing.expectError(case.expected_error, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
        .diagnostic = &diagnostic,
    }));
    try testing.expectEqual(case.expected_kind, diagnostic.kind);
    if (case.expect_index) |idx| try testing.expectEqual(@as(?usize, idx), diagnostic.catalog_index);
    try expectNoOutputOrScratch(io, output_path);
}

test "recustomize-iso refuses an unmapped boot extent before any output or scratch" {
    // Repoint the BIOS default entry's image LBA (catalog byte 40) to a
    // system-area sector that is no file's starting extent.
    try runRefusalCase(.{
        .name = "unmapped",
        .dual = false,
        .catalog_offset = 40,
        .patch = &[_]u8{ 3, 0, 0, 0 },
        .fix_checksum = false,
        .expected_error = error.SourceNotRewritable,
        .expected_kind = .boot_image_unmapped,
        .expect_index = 0,
    });
}

test "recustomize-iso refuses El Torito media emulation before any output or scratch" {
    // Set the BIOS default entry's media byte (catalog byte 33) to hard-disk.
    try runRefusalCase(.{
        .name = "media",
        .dual = false,
        .catalog_offset = 33,
        .patch = &[_]u8{4},
        .fix_checksum = false,
        .expected_error = error.SourceNotRewritable,
        .expected_kind = .boot_media_emulation,
        .expect_index = 0,
    });
}

test "recustomize-iso refuses El Torito selection criteria the writer cannot emit" {
    // Set the UEFI section entry's selection-criteria type (catalog byte 108).
    try runRefusalCase(.{
        .name = "selection",
        .dual = true,
        .catalog_offset = 108,
        .patch = &[_]u8{1},
        .fix_checksum = false,
        .expected_error = error.BootSelectionCriteria,
        .expected_kind = .boot_selection_criteria,
        .expect_index = 1,
    });
}

test "recustomize-iso refuses an unsupported boot platform" {
    // Turn the single-entry catalog's validation platform (byte 1) into PPC
    // (0x01); the default entry inherits it. Fix the validation checksum so the
    // catalog parses and only the platform is unpreservable.
    try runRefusalCase(.{
        .name = "platform",
        .dual = false,
        .catalog_offset = 1,
        .patch = &[_]u8{1},
        .fix_checksum = true,
        .expected_error = error.UnsupportedBootPlatform,
        .expected_kind = .unsupported_boot_platform,
        .expect_index = 0,
    });
}

test "recustomize-iso refuses more than one boot entry per platform" {
    // Rewrite the UEFI section header's platform (catalog byte 65) to BIOS, so
    // the section entry collides with the BIOS default entry.
    try runRefusalCase(.{
        .name = "duplicate",
        .dual = true,
        .catalog_offset = 65,
        .patch = &[_]u8{0},
        .fix_checksum = false,
        .expected_error = error.DuplicateBootPlatform,
        .expected_kind = .duplicate_boot_platform,
        .expect_index = 1,
    });
}

test "recustomize-iso refuses a structural rewrite blocker (extended attribute record)" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-ea-src.iso";
    const oci_root = "test-recustomize-ea-oci";
    const output_path = "test-recustomize-ea-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{ bios_boot_entry, uefi_boot_entry });
    try createOciLayout(allocator, io, oci_root);

    // Set the PVD root directory record's Extended Attribute Record Length
    // (byte 1 of the record at PVD offset 156) so the writer cannot preserve it.
    {
        const file = try Io.Dir.cwd().openFile(io, iso_path, .{ .mode = .read_write });
        defer file.close(io);
        const off: u64 = 16 * 2048 + 156 + 1;
        try file.writePositionalAll(io, &[_]u8{1}, off);
    }

    var diagnostic = RecustomizeDiagnostic{ .kind = .rock_ridge_relocation };
    defer diagnostic.deinit(allocator);

    try testing.expectError(error.SourceNotRewritable, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
        .diagnostic = &diagnostic,
    }));
    try testing.expectEqual(RecustomizeDiagnostic.Kind.extended_attribute_record, diagnostic.kind);
    try expectNoOutputOrScratch(io, output_path);
}

// --- Path isolation, cleanup, dry run ---

test "recustomize-iso rejects an output path that aliases an input and leaves no scratch behind" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-alias-src.iso";
    const oci_root = "test-recustomize-alias-oci";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{ bios_boot_entry, uefi_boot_entry });
    try createOciLayout(allocator, io, oci_root);

    try testing.expectError(error.SourcePathConflict, build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = iso_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
    }));

    for ([_][]const u8{
        iso_path ++ "." ++ scratch_infix ++ "-rootfs.img",
        iso_path ++ "." ++ scratch_infix ++ "-payload.sqsh",
        iso_path ++ "." ++ scratch_infix ++ ".iso.tmp",
        iso_path ++ "." ++ scratch_infix ++ "-root-tree.spool",
    }) |scratch| {
        try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, scratch, .{}));
    }
}

test "recustomize-iso cleans up every scratch file on a successful build and leaves the source unchanged" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-clean-src.iso";
    const oci_root = "test-recustomize-clean-oci";
    const output_path = "test-recustomize-clean-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{ bios_boot_entry, uefi_boot_entry });
    try createOciLayout(allocator, io, oci_root);

    const before = try hashFilePath(allocator, io, iso_path);

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

    const after = try hashFilePath(allocator, io, iso_path);
    try testing.expectEqualSlices(u8, &before, &after);
}

test "recustomize-iso dry run reports the preservation plan without writing an output" {
    const allocator = testing.allocator;
    const io = testing.io;

    const iso_path = "test-recustomize-dry-src.iso";
    const oci_root = "test-recustomize-dry-oci";
    const output_path = "test-recustomize-dry-out.iso";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, oci_root) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, iso_path, squashfs_bytes, &.{ bios_boot_entry, uefi_boot_entry });
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
    try testing.expect(report.strict_inspection_clean);
    try testing.expectEqualStrings("LiveOS/squashfs.img", report.rootfs_path_in_iso);
    try testing.expectEqual(@as(u64, 0), report.output_size);
    try testing.expectEqual(@as(usize, 2), report.boot_entries.len);
    // The dry run computes the real preserved node count (every fixture node
    // except the replaced payload), not a placeholder zero.
    try testing.expectEqual(@as(usize, fixtureNodes().len - 1), report.preserved_node_count);
    // The source was still hashed and its metadata modeled.
    try testing.expect(!std.mem.allEqual(u8, &report.source_sha256, 0));
    try testing.expectEqualStrings("ZVMI_SRC", report.source_volume.volume_id);
    try testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));

    // The dry-run count matches what a real run reports for the same source.
    var real_report = try build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_root,
        .output_path = output_path,
        .rootfs_size = 24 * 1024 * 1024,
        .determinism = deterministic_fixture,
    });
    defer real_report.deinit(allocator);
    try testing.expect(!real_report.dry_run);
    try testing.expectEqual(report.preserved_node_count, real_report.preserved_node_count);
}

test "recustomize-iso verifies output volume metadata on the scratch ISO before publishing" {
    const allocator = testing.allocator;
    const io = testing.io;

    // This is the pre-publish gate `build` runs: it reads the volume metadata
    // back from the freshly written *scratch* ISO and refuses (before any atomic
    // rename) if it does not round-trip from the source. Proven directly on the
    // helper so a failure is guaranteed to happen while only the scratch exists.
    const scratch_path = "test-recustomize-verify-scratch.iso";
    defer Io.Dir.cwd().deleteFile(io, scratch_path) catch {};

    const squashfs_bytes = try squashfs.buildSyntheticSquashfsImage(allocator, .{ .compression = .zstd });
    defer allocator.free(squashfs_bytes);
    try writeSourceIso(allocator, io, scratch_path, squashfs_bytes, &.{bios_boot_entry});

    // The source metadata the pipeline would preserve.
    var source_meta = blk: {
        const file = try Io.Dir.cwd().openFile(io, scratch_path, .{ .mode = .read_only });
        defer file.close(io);
        break :blk try iso9660.readVolumeMetadataAlloc(allocator, io, file);
    };
    defer source_meta.deinit(allocator);
    try testing.expectEqualStrings("ZVMI_SRC", source_meta.volume_id);

    // Matching scratch: the helper returns the read-back metadata and no error.
    var verified = try verifyOutputVolumeRoundTrip(allocator, io, scratch_path, source_meta);
    verified.deinit(allocator);

    // Corrupt the scratch's primary-volume-descriptor volume identifier
    // (LBA 16, bytes [40..72]) so the read-back no longer matches the source.
    {
        const file = try Io.Dir.cwd().openFile(io, scratch_path, .{ .mode = .read_write });
        defer file.close(io);
        var mutated = [_]u8{' '} ** 32;
        @memcpy(mutated[0..10], "MUTATEDVOL");
        try file.writePositionalAll(io, &mutated, 16 * 2048 + 40);
    }

    // The helper now refuses. Because callers run it before the rename, this
    // error path leaves the scratch in place (for cleanup) and never publishes.
    try testing.expectError(error.OutputVolumeMismatch, verifyOutputVolumeRoundTrip(allocator, io, scratch_path, source_meta));

    // Verification only reads the scratch: it neither renamed nor removed it.
    _ = try Io.Dir.cwd().statFile(io, scratch_path, .{});
}
