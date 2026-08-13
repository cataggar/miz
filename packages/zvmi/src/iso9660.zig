//! ISO9660 (ECMA-119) reader **and** writer with enough Rock Ridge (RRIP)
//! and Joliet support to enumerate directory trees, read file extents, and
//! resolve symbolic links without shelling out to external tooling.
//!
//! Two distinct support levels apply, and they must not be conflated:
//!
//!  - **Ingestion support** is what `build-image`/`build-iso` need to *read*
//!    a source image: enumerate the tree, resolve names/symlinks, and stream
//!    file content. The reader tolerates constructs it cannot regenerate as
//!    long as it can still read the supported subset.
//!  - **Strict rewrite support** is what a recustomizer needs before it may
//!    regenerate an image and claim it preserved the source. `inspectForRewrite`
//!    / `requireRewriteSupported` model the volume metadata and El Torito boot
//!    catalog and return an explicit, precise list of source features the
//!    writer cannot preserve, so a lossy rewrite is refused rather than
//!    silently performed. Nothing about the source is dropped without a
//!    diagnostic.
//!
//! Scope / limitations:
//!  - The reader is read-only; the writer (`writeImage`/`writeImagePath`)
//!    emits a deterministic ISO9660 image from a generic pull-based
//!    `TreeSource`, streaming file content so large files never load into
//!    memory whole. It writes directories, regular files, and symlinks with
//!    POSIX mode/uid/gid and per-entry modification time via Rock Ridge,
//!    both-endian path tables, a primary volume descriptor (with volume,
//!    system, volume-set, publisher, preparer, and application identifiers)
//!    and terminator, and optional El Torito boot support (no-emulation BIOS
//!    and/or UEFI entries with a validation entry and boot catalog). Joliet
//!    emission is out of scope for this pass.
//!  - Rock Ridge support covers the SUSP/RRIP records needed for real Linux
//!    install media navigation: `SP`, `ST`, `RR`, `PX`, `NM`, `SL`, `TF`, and
//!    `CE`. Directory relocation (`CL`/`PL`/`RE`) is neither followed nor
//!    regeneratable; the reader flags it (and other unmodeled SUSP records such
//!    as `PN` device nodes and `SF` sparse files) as an explicit rewrite
//!    blocker via `inspectForRewrite` rather than mis-modeling the namespace.
//!  - Joliet support decodes UCS-2BE names from a supplementary volume
//!    descriptor and prefers Rock Ridge names when both are present, matching
//!    common Unix reader behavior.
//!  - Multi-extent regular files (consecutive directory records for the same
//!    file, all but the last carrying the multi-extent flag) are combined into
//!    a single `Entry.extents` array. Interleaved files, extended attribute
//!    record lengths, and multi-extent directories are not modeled and are
//!    surfaced as rewrite blockers.

const std = @import("std");
const Io = std.Io;

pub const volume_descriptor_lba: u32 = 16;
pub const descriptor_size: usize = 2048;
pub const standard_id: [5]u8 = "CD001".*;

pub const EntryKind = enum {
    file,
    directory,
    symlink,
};

pub const Extent = struct {
    lba: u32,
    size: u32,
};

pub const DirEntry = struct {
    name: []const u8,
    index: usize,
    kind: EntryKind,
};

pub const PathTableEntry = struct {
    name: []const u8,
    extent_lba: u32,
    parent_index: u16,
};

pub const Entry = struct {
    name: []const u8,
    parent: ?usize,
    kind: EntryKind,
    size: u64,
    mode: u32,
    uid: u32,
    gid: u32,
    /// Modification time in epoch seconds, decoded from the directory record's
    /// 7-byte recording date (or the Rock Ridge `TF` modify time when present).
    /// The native writer stamps this back verbatim, so it round-trips.
    mtime: i64,
    extents: []Extent,
    symlink_target: ?[]const u8,

    pub fn isDirectory(self: Entry) bool {
        return self.kind == .directory;
    }
};

pub const NameSource = enum {
    iso9660,
    rock_ridge,
    joliet,
};

/// A source feature the reader can ingest (or partially ingest) but the writer
/// cannot regenerate. `inspectForRewrite` returns these so a recustomizer can
/// refuse a lossy rewrite with a precise, structured reason instead of silently
/// dropping the construct.
pub const UnsupportedFeature = enum {
    /// Rock Ridge `CL`/`PL`/`RE` directory relocation (deep-tree workaround).
    rock_ridge_relocation,
    /// Rock Ridge `PN` POSIX device number (block/char device node).
    rock_ridge_device_node,
    /// Rock Ridge `SF` sparse-file record.
    rock_ridge_sparse_file,
    /// A SUSP/RRIP System Use entry whose signature the reader does not model,
    /// so its namespace/metadata effect cannot be preserved.
    unknown_susp_record,
    /// A directory record with a non-zero File Unit Size / Interleave Gap Size
    /// (an interleaved file). The writer only emits contiguous extents.
    interleaved_file,
    /// A directory record carrying an Extended Attribute Record (non-zero
    /// extended attribute record length). The writer emits none.
    extended_attribute_record,
    /// A directory whose content spans multiple extents. The writer emits each
    /// directory as a single extent.
    multi_extent_directory,
    /// Two entries in one directory decode to the same name, so a regenerated
    /// tree would be ambiguous.
    duplicate_directory_entry,
    /// An El Torito boot entry using floppy/hard-disk emulation. The writer
    /// only emits no-emulation entries.
    boot_media_emulation,
    /// An El Torito section entry that declares a following selection-criteria
    /// extension record (`0x44`). The writer emits none.
    boot_section_extension,
    /// An El Torito boot image whose LBA does not fall inside any modeled file,
    /// so the writer cannot re-derive it from a tree node.
    boot_image_unmapped,
};

pub fn unsupportedFeatureName(feature: UnsupportedFeature) []const u8 {
    return switch (feature) {
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
    };
}

/// One precise rewrite blocker: the feature plus optional locating context (an
/// affected path and a short note such as a SUSP signature or extent LBA).
pub const UnsupportedDetail = struct {
    feature: UnsupportedFeature,
    /// Affected path, or empty when not tied to a single tree entry. Borrowed
    /// from the owning `RewriteInspection` arena.
    path: []const u8 = &.{},
    /// Short human-readable note (SUSP tag, media type, extent LBA, ...) or
    /// empty. Borrowed from the owning `RewriteInspection` arena.
    note: []const u8 = &.{},
};

// A rewrite blocker discovered while the tree is built, stored compactly on the
// Reader (no owned strings) and materialized into an `UnsupportedDetail` on
// demand. `entry_index` points at the nearest relevant tree entry so the path
// can be reconstructed lazily; `note` is a tiny inline buffer.
const BuildDiagnostic = struct {
    feature: UnsupportedFeature,
    entry_index: ?usize = null,
    note_buf: [8]u8 = [_]u8{0} ** 8,
    note_len: u8 = 0,

    fn note(self: *const BuildDiagnostic) []const u8 {
        return self.note_buf[0..self.note_len];
    }
};

pub const OpenError = error{
    BadVolumeDescriptor,
    MissingPrimaryVolumeDescriptor,
    InvalidRootDirectoryRecord,
    UnsupportedLogicalBlockSize,
    TooManyRockRidgeContinuations,
    UnsupportedRockRidgeRelocation,
    InvalidDirectoryRecord,
    InvalidMultiExtent,
    InvalidJolietName,
} || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError || std.mem.Allocator.Error;

pub const LookupError = error{ NotFound, NotADirectory, TooManySymlinks, BrokenSymlink } || std.mem.Allocator.Error;
pub const ReadError = error{ NotAFile, NotASymlink } || Io.File.ReadPositionalError || std.mem.Allocator.Error;

pub const Reader = struct {
    allocator: std.mem.Allocator,
    file: Io.File,
    logical_block_size: u16,
    path_table: []PathTableEntry,
    entries: []Entry,
    root_index: usize,
    has_rock_ridge: bool,
    has_joliet: bool,
    name_source: NameSource,
    /// Rewrite blockers discovered while building the tree (relocation,
    /// interleaved files, duplicate names, ...). Empty for the writer's own
    /// deterministic output. Surfaced through `inspectForRewrite`.
    build_diagnostics: []BuildDiagnostic,

    pub fn openPath(allocator: std.mem.Allocator, io: Io, path: []const u8) OpenError!Reader {
        const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
        errdefer file.close(io);
        return openFile(allocator, io, file);
    }

    pub fn openFile(allocator: std.mem.Allocator, io: Io, file: Io.File) OpenError!Reader {
        const descriptors = try scanDescriptors(io, file);
        const path_table = try parsePathTable(allocator, io, file, descriptors.primary);
        errdefer freePathTable(allocator, path_table);

        var primary_tree = try buildTree(allocator, io, file, descriptors.primary, false);
        errdefer primary_tree.deinit(allocator);

        if (primary_tree.has_rock_ridge or descriptors.joliet == null) {
            const diagnostics = try primary_tree.diagnostics.toOwnedSlice();
            errdefer allocator.free(diagnostics);
            return .{
                .allocator = allocator,
                .file = file,
                .logical_block_size = descriptors.primary.logical_block_size,
                .path_table = path_table,
                .entries = try primary_tree.entries.toOwnedSlice(),
                .root_index = primary_tree.root_index,
                .has_rock_ridge = primary_tree.has_rock_ridge,
                .has_joliet = descriptors.joliet != null,
                .name_source = if (primary_tree.has_rock_ridge) .rock_ridge else .iso9660,
                .build_diagnostics = diagnostics,
            };
        }

        primary_tree.deinit(allocator);

        var joliet_tree = try buildTree(allocator, io, file, descriptors.joliet.?, true);
        errdefer joliet_tree.deinit(allocator);

        const diagnostics = try joliet_tree.diagnostics.toOwnedSlice();
        errdefer allocator.free(diagnostics);
        return .{
            .allocator = allocator,
            .file = file,
            .logical_block_size = descriptors.joliet.?.logical_block_size,
            .path_table = path_table,
            .entries = try joliet_tree.entries.toOwnedSlice(),
            .root_index = joliet_tree.root_index,
            .has_rock_ridge = false,
            .has_joliet = true,
            .name_source = .joliet,
            .build_diagnostics = diagnostics,
        };
    }

    pub fn close(self: *Reader, io: Io) void {
        freeEntries(self.allocator, self.entries);
        freePathTable(self.allocator, self.path_table);
        self.allocator.free(self.build_diagnostics);
        self.file.close(io);
        self.* = undefined;
    }

    pub fn getEntry(self: Reader, index: usize) *const Entry {
        return &self.entries[index];
    }

    /// Reconstructs the absolute '/'-separated path of `index` by walking
    /// parents. The root is "/". Caller owns the returned slice.
    pub fn pathAlloc(self: Reader, allocator: std.mem.Allocator, index: usize) std.mem.Allocator.Error![]u8 {
        if (index == self.root_index) return allocator.dupe(u8, "/");

        var parts = std.array_list.Managed([]const u8).init(allocator);
        defer parts.deinit();
        var cur = index;
        var guard: usize = 0;
        while (cur != self.root_index) {
            guard += 1;
            if (guard > self.entries.len) break;
            try parts.append(self.entries[cur].name);
            cur = self.entries[cur].parent orelse break;
        }

        var out = std.array_list.Managed(u8).init(allocator);
        errdefer out.deinit();
        var i: usize = parts.items.len;
        while (i > 0) {
            i -= 1;
            try out.append('/');
            try out.appendSlice(parts.items[i]);
        }
        return out.toOwnedSlice();
    }

    pub fn lookup(self: Reader, path: []const u8) LookupError!usize {
        return self.lookupFrom(self.root_index, path, false, 0);
    }

    pub fn listDirAlloc(self: Reader, allocator: std.mem.Allocator, index: usize) (std.mem.Allocator.Error || error{NotADirectory})![]DirEntry {
        if (self.entries[index].kind != .directory) return error.NotADirectory;

        var list = std.array_list.Managed(DirEntry).init(allocator);
        errdefer list.deinit();

        for (self.entries, 0..) |entry, i| {
            if (entry.parent == index) {
                try list.append(.{ .name = entry.name, .index = i, .kind = entry.kind });
            }
        }
        std.mem.sort(DirEntry, list.items, {}, dirEntryLessThan);
        return list.toOwnedSlice();
    }

    pub fn readFileAlloc(self: Reader, allocator: std.mem.Allocator, io: Io, index: usize) ReadError![]u8 {
        const entry = self.entries[index];
        if (entry.kind != .file) return error.NotAFile;

        const out = try allocator.alloc(u8, @intCast(entry.size));
        errdefer allocator.free(out);

        var dst_offset: usize = 0;
        for (entry.extents) |extent| {
            const extent_len: usize = @intCast(@min(@as(u64, extent.size), entry.size - dst_offset));
            const file_offset = @as(u64, extent.lba) * self.logical_block_size;
            const got = try self.file.readPositionalAll(io, out[dst_offset..][0..extent_len], file_offset);
            if (got < extent_len) @memset(out[dst_offset + got ..][0 .. extent_len - got], 0);
            dst_offset += extent_len;
            if (dst_offset == out.len) break;
        }
        return out;
    }

    pub fn readLink(self: Reader, index: usize) ReadError![]const u8 {
        if (self.entries[index].kind != .symlink) return error.NotASymlink;
        return self.entries[index].symlink_target.?;
    }

    pub fn resolveSymlink(self: Reader, index: usize) LookupError!usize {
        const entry = self.entries[index];
        if (entry.kind != .symlink) return error.BrokenSymlink;
        return self.lookupFrom(entry.parent orelse self.root_index, entry.symlink_target.?, true, 1);
    }

    fn lookupFrom(self: Reader, start_index: usize, path: []const u8, follow_final_symlink: bool, depth: u8) LookupError!usize {
        if (depth > 16) return error.TooManySymlinks;

        var current = if (std.mem.startsWith(u8, path, "/")) self.root_index else start_index;
        var it = std.mem.tokenizeScalar(u8, path, '/');
        var had_component = false;

        while (it.next()) |component| {
            had_component = true;
            if (component.len == 0 or std.mem.eql(u8, component, ".")) continue;
            if (std.mem.eql(u8, component, "..")) {
                current = self.entries[current].parent orelse self.root_index;
                continue;
            }

            if (self.entries[current].kind != .directory) return error.NotADirectory;
            const child = self.findChild(current, component) orelse return error.NotFound;
            const is_last = it.peek() == null;
            if (self.entries[child].kind == .symlink and (!is_last or follow_final_symlink)) {
                const target = self.entries[child].symlink_target.?;
                current = self.lookupFrom(self.entries[child].parent orelse self.root_index, target, true, depth + 1) catch |err| switch (err) {
                    error.NotFound, error.NotADirectory => return error.BrokenSymlink,
                    else => return err,
                };
            } else {
                current = child;
            }
        }

        if (!had_component and std.mem.startsWith(u8, path, "/")) return self.root_index;
        return current;
    }

    fn findChild(self: Reader, parent: usize, name: []const u8) ?usize {
        for (self.entries, 0..) |entry, i| {
            if (entry.parent == parent and std.mem.eql(u8, entry.name, name)) return i;
        }
        return null;
    }

    fn findFileByExtentLba(self: Reader, lba: u32) ?usize {
        for (self.entries, 0..) |entry, idx| {
            if (entry.kind != .file) continue;
            // A boot image is only a mapped file when it starts at the file's
            // leading extent. Matching an interior extent of a multi-extent
            // file would misrepresent a mid-file offset as the whole file, so
            // such a boot LBA stays raw/unmapped (and thus unsupported).
            if (entry.extents.len == 0) continue;
            if (entry.extents[0].lba == lba) return idx;
        }
        return null;
    }

    /// Models the writer-preservable metadata (volume identifiers, El Torito
    /// boot catalog with each image mapped to a tree file or an explicit raw
    /// extent) and returns every source construct the writer cannot preserve.
    /// An empty `RewriteInspection.unsupported` list means a regeneration is
    /// lossless within the supported model. Genuinely malformed structures
    /// (bad checksum/signature/bounds) fail precisely rather than being listed.
    /// Caller owns the returned inspection and must `deinit` it.
    pub fn inspectForRewrite(self: Reader, allocator: std.mem.Allocator, io: Io) InspectError!RewriteInspection {
        var arena = std.heap.ArenaAllocator.init(allocator);
        errdefer arena.deinit();
        const a = arena.allocator();

        const volume = try readVolumeMetadataAlloc(a, io, self.file);

        var unsupported = std.array_list.Managed(UnsupportedDetail).init(a);

        // Structural (tree) blockers first, in discovery order.
        for (self.build_diagnostics) |diag| {
            try unsupported.append(.{
                .feature = diag.feature,
                .path = if (diag.entry_index) |idx| try self.pathAlloc(a, idx) else &.{},
                .note = try a.dupe(u8, diag.note()),
            });
        }

        // El Torito boot state and its blockers. A malformed catalog is a hard,
        // precise failure; a missing boot record simply leaves `boot` null.
        var boot: ?BootModel = null;
        const maybe_cat: ?BootCatalog = readBootCatalog(a, io, self.file) catch |err| blk: {
            if (err == error.NoBootRecord) break :blk null;
            return @as(InspectError, @errorCast(err));
        };
        if (maybe_cat) |cat| {
            const inspected = try a.alloc(InspectedBootEntry, cat.entries.len);
            for (cat.entries, 0..) |entry, idx| {
                const mapping: BootImageMapping = if (self.findFileByExtentLba(entry.image_lba)) |file_idx| .{
                    .mapped = .{ .entry_index = file_idx, .path = try self.pathAlloc(a, file_idx) },
                } else .{
                    .raw_extent = .{ .lba = entry.image_lba, .sectors = entry.load_sectors },
                };
                inspected[idx] = .{ .entry = entry, .image = mapping };

                if (entry.media != .no_emulation) {
                    try unsupported.append(.{
                        .feature = .boot_media_emulation,
                        .note = try std.fmt.allocPrint(a, "media {d}", .{entry.media_type & 0x0F}),
                    });
                }
                if (entry.has_extension) {
                    try unsupported.append(.{ .feature = .boot_section_extension });
                }
                if (mapping == .raw_extent) {
                    try unsupported.append(.{
                        .feature = .boot_image_unmapped,
                        .note = try std.fmt.allocPrint(a, "lba {d}", .{entry.image_lba}),
                    });
                }
            }
            boot = .{
                .validation = cat.validation,
                .headers = cat.headers,
                .entries = inspected,
                .has_extension_records = cat.has_extension_records,
            };
        }

        return .{
            .arena = arena,
            .volume = volume,
            .boot = boot,
            .unsupported = try unsupported.toOwnedSlice(),
        };
    }

    /// Strict gate for a recustomizer: returns normally only when the source is
    /// losslessly rewritable within the supported model. Otherwise returns
    /// `error.SourceNotRewritable`; when `out_detail` is non-null it receives
    /// the first precise blocker with `path`/`note` duplicated into `allocator`
    /// (free them with `freeUnsupportedDetail`).
    pub fn requireRewriteSupported(self: Reader, allocator: std.mem.Allocator, io: Io, out_detail: ?*UnsupportedDetail) RewriteSupportError!void {
        var inspection = try self.inspectForRewrite(allocator, io);
        defer inspection.deinit();
        if (inspection.firstUnsupported()) |first| {
            if (out_detail) |slot| {
                slot.* = .{
                    .feature = first.feature,
                    .path = if (first.path.len > 0) try allocator.dupe(u8, first.path) else &.{},
                    .note = if (first.note.len > 0) try allocator.dupe(u8, first.note) else &.{},
                };
            }
            return error.SourceNotRewritable;
        }
    }
};

const DescriptorRef = struct {
    logical_block_size: u16,
    path_table_size: u32,
    type_l_path_table: u32,
    root_record: DirectoryRecord,
};

const ScannedDescriptors = struct {
    primary: DescriptorRef,
    joliet: ?DescriptorRef,
};

const DirectoryRecord = struct {
    length: u8,
    ext_attr_length: u8,
    extent_lba: u32,
    data_length: u32,
    /// Modification time decoded from the 7-byte recording date field.
    recorded_at: i64,
    flags: u8,
    file_unit_size: u8,
    interleave_gap: u8,
    file_identifier: []const u8,
    system_use: []const u8,

    /// ISO9660 multi-extent flag (bit 7): another record continues this file.
    fn isMultiExtent(self: DirectoryRecord) bool {
        return self.flags & 0x80 != 0;
    }

    fn isDirectory(self: DirectoryRecord) bool {
        return self.flags & 0x02 != 0;
    }
};

const RockRidgeInfo = struct {
    name: ?[]u8 = null,
    symlink_target: ?[]u8 = null,
    mode: ?u32 = null,
    uid: ?u32 = null,
    gid: ?u32 = null,
    mtime: ?i64 = null,
    /// A rewrite-blocking SUSP/RRIP construct was seen on this record.
    unsupported: ?UnsupportedFeature = null,
    /// Signature of the offending record (for diagnostics), when applicable.
    unsupported_tag: [4]u8 = [_]u8{0} ** 4,
    unsupported_tag_len: u8 = 0,

    fn deinit(self: *RockRidgeInfo, allocator: std.mem.Allocator) void {
        if (self.name) |name| allocator.free(name);
        if (self.symlink_target) |target| allocator.free(target);
        self.* = .{};
    }
};

const TreeBuilder = struct {
    entries: std.array_list.Managed(Entry),
    diagnostics: std.array_list.Managed(BuildDiagnostic),
    root_index: usize,
    has_rock_ridge: bool = false,
    logical_block_size: u16,
    joliet: bool,
    susp_skip: ?u8 = null,

    fn deinit(self: *TreeBuilder, allocator: std.mem.Allocator) void {
        for (self.entries.items) |entry| {
            allocator.free(entry.name);
            allocator.free(entry.extents);
            if (entry.symlink_target) |target| allocator.free(target);
        }
        self.entries.deinit();
        self.diagnostics.deinit();
    }

    fn note(self: *TreeBuilder, feature: UnsupportedFeature, entry_index: ?usize, tag: []const u8) std.mem.Allocator.Error!void {
        var diag = BuildDiagnostic{ .feature = feature, .entry_index = entry_index };
        const n = @min(tag.len, diag.note_buf.len);
        @memcpy(diag.note_buf[0..n], tag[0..n]);
        diag.note_len = @intCast(n);
        try self.diagnostics.append(diag);
    }
};

fn buildTree(allocator: std.mem.Allocator, io: Io, file: Io.File, descriptor: DescriptorRef, joliet: bool) OpenError!TreeBuilder {
    var builder = TreeBuilder{
        .entries = std.array_list.Managed(Entry).init(allocator),
        .diagnostics = std.array_list.Managed(BuildDiagnostic).init(allocator),
        .root_index = 0,
        .logical_block_size = descriptor.logical_block_size,
        .joliet = joliet,
    };
    errdefer builder.deinit(allocator);

    const root_name = try allocator.dupe(u8, "/");
    const root_extents = allocator.alloc(Extent, 1) catch |err| {
        allocator.free(root_name);
        return err;
    };
    root_extents[0] = .{ .lba = descriptor.root_record.extent_lba, .size = descriptor.root_record.data_length };

    // On failure free the parts; once appended the builder owns them and its
    // deinit frees them exactly once (so no standalone errdefer for them).
    builder.entries.append(.{
        .name = root_name,
        .parent = null,
        .kind = .directory,
        .size = descriptor.root_record.data_length,
        .mode = 0o040755,
        .uid = 0,
        .gid = 0,
        .mtime = descriptor.root_record.recorded_at,
        .extents = root_extents,
        .symlink_target = null,
    }) catch |err| {
        allocator.free(root_name);
        allocator.free(root_extents);
        return err;
    };
    builder.root_index = 0;

    // The PVD root directory record is subject to the same rewrite blockers as
    // any other directory record: an extended attribute record length, a
    // File Unit Size / Interleave Gap (interleaving), or the multi-extent flag
    // (a directory spanning multiple extents) cannot be regenerated verbatim.
    if (descriptor.root_record.ext_attr_length != 0)
        try builder.note(.extended_attribute_record, 0, "");
    if (descriptor.root_record.file_unit_size != 0 or descriptor.root_record.interleave_gap != 0)
        try builder.note(.interleaved_file, 0, "");
    if (descriptor.root_record.isMultiExtent())
        try builder.note(.multi_extent_directory, 0, "");

    try parseDirectory(allocator, io, file, &builder, 0, descriptor.root_record, 0);
    return builder;
}

fn parseDirectory(allocator: std.mem.Allocator, io: Io, file: Io.File, builder: *TreeBuilder, parent_index: usize, record: DirectoryRecord, depth: usize) OpenError!void {
    if (depth > 128) return error.InvalidDirectoryRecord;
    const size: usize = @intCast(record.data_length);
    const dir_buf = try allocator.alloc(u8, size);
    defer allocator.free(dir_buf);
    _ = try file.readPositionalAll(io, dir_buf, @as(u64, record.extent_lba) * builder.logical_block_size);

    // Names already seen in this directory, for ambiguous-duplicate detection.
    var seen_names = std.StringHashMap(void).init(allocator);
    defer {
        var it = seen_names.keyIterator();
        while (it.next()) |k| allocator.free(k.*);
        seen_names.deinit();
    }

    var offset: usize = 0;
    while (offset < dir_buf.len) {
        const length = dir_buf[offset];
        if (length == 0) {
            const sector_off = offset % builder.logical_block_size;
            offset += builder.logical_block_size - sector_off;
            continue;
        }
        if (offset + length > dir_buf.len) return error.InvalidDirectoryRecord;

        const child_record = try parseDirectoryRecord(dir_buf[offset .. offset + length]);

        const is_special = child_record.file_identifier.len == 1 and (child_record.file_identifier[0] == 0 or child_record.file_identifier[0] == 1);

        var rr = RockRidgeInfo{};
        defer rr.deinit(allocator);
        if (!builder.joliet) {
            rr = try parseRockRidge(allocator, io, file, builder, child_record.system_use);
        }

        if (is_special) {
            if (child_record.file_identifier[0] == 0) {
                if (rr.mode) |mode| builder.entries.items[parent_index].mode = mode;
                if (rr.uid) |uid| builder.entries.items[parent_index].uid = uid;
                if (rr.gid) |gid| builder.entries.items[parent_index].gid = gid;
                if (rr.mtime) |mtime| builder.entries.items[parent_index].mtime = mtime;
            }
            offset += child_record.length;
            continue;
        }

        const kind: EntryKind = if (rr.symlink_target != null)
            .symlink
        else if (child_record.isDirectory())
            .directory
        else
            .file;

        var saw_ext_attr = child_record.ext_attr_length != 0;
        var saw_interleave = child_record.file_unit_size != 0 or child_record.interleave_gap != 0;

        // Gather extents. A regular file may span several consecutive directory
        // records (multi-extent), all but the last carrying the multi-extent
        // flag and repeating the same File Identifier.
        var extent_list = std.array_list.Managed(Extent).init(allocator);
        defer extent_list.deinit();
        try extent_list.append(.{ .lba = child_record.extent_lba, .size = child_record.data_length });
        var total_size: u64 = child_record.data_length;
        const multi_extent = child_record.isMultiExtent();

        offset += child_record.length;
        if (multi_extent) {
            while (true) {
                if (offset >= dir_buf.len) return error.InvalidMultiExtent;
                const nlen = dir_buf[offset];
                if (nlen == 0) {
                    const sector_off = offset % builder.logical_block_size;
                    offset += builder.logical_block_size - sector_off;
                    continue;
                }
                if (offset + nlen > dir_buf.len) return error.InvalidDirectoryRecord;
                const next = try parseDirectoryRecord(dir_buf[offset .. offset + nlen]);
                if (!std.mem.eql(u8, next.file_identifier, child_record.file_identifier)) return error.InvalidMultiExtent;
                if (next.isDirectory() != child_record.isDirectory()) return error.InvalidMultiExtent;
                if (next.ext_attr_length != 0) saw_ext_attr = true;
                if (next.file_unit_size != 0 or next.interleave_gap != 0) saw_interleave = true;
                try extent_list.append(.{ .lba = next.extent_lba, .size = next.data_length });
                total_size = std.math.add(u64, total_size, next.data_length) catch return error.InvalidMultiExtent;
                offset += next.length;
                if (!next.isMultiExtent()) break;
            }
        }

        const decoded_name = if (rr.name) |name|
            try allocator.dupe(u8, name)
        else if (builder.joliet)
            try decodeJolietName(allocator, child_record.file_identifier)
        else
            try decodeIsoName(allocator, child_record.file_identifier);

        const target: ?[]u8 = if (rr.symlink_target) |link| (allocator.dupe(u8, link) catch |err| {
            allocator.free(decoded_name);
            return err;
        }) else null;

        const extents = extent_list.toOwnedSlice() catch |err| {
            allocator.free(decoded_name);
            if (target) |t| allocator.free(t);
            return err;
        };

        const entry_mode: u32 = rr.mode orelse switch (kind) {
            .directory => @as(u32, 0o040755),
            .file => @as(u32, 0o100644),
            .symlink => @as(u32, 0o120777),
        };

        const entry_size: u64 = switch (kind) {
            .symlink => if (target) |t| t.len else 0,
            else => total_size,
        };

        builder.entries.append(.{
            .name = decoded_name,
            .parent = parent_index,
            .kind = kind,
            .size = entry_size,
            .mode = entry_mode,
            .uid = rr.uid orelse 0,
            .gid = rr.gid orelse 0,
            .mtime = rr.mtime orelse child_record.recorded_at,
            .extents = extents,
            .symlink_target = target,
        }) catch |err| {
            allocator.free(decoded_name);
            allocator.free(extents);
            if (target) |t| allocator.free(t);
            return err;
        };
        // From here the builder owns name/extents/target; on later error the
        // builder's deinit frees them exactly once.
        const child_index = builder.entries.items.len - 1;

        if (saw_ext_attr) try builder.note(.extended_attribute_record, child_index, "");
        if (saw_interleave) try builder.note(.interleaved_file, child_index, "");
        if (multi_extent and kind == .directory) try builder.note(.multi_extent_directory, child_index, "");
        if (rr.unsupported) |feature| try builder.note(feature, child_index, rr.unsupported_tag[0..rr.unsupported_tag_len]);

        const name = builder.entries.items[child_index].name;
        if (seen_names.contains(name)) {
            try builder.note(.duplicate_directory_entry, child_index, "");
        } else {
            const key = try allocator.dupe(u8, name);
            seen_names.put(key, {}) catch |err| {
                allocator.free(key);
                return err;
            };
        }

        if (kind == .directory) {
            try parseDirectory(allocator, io, file, builder, child_index, child_record, depth + 1);
        }
    }
}

fn scanDescriptors(io: Io, file: Io.File) OpenError!ScannedDescriptors {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    var primary: ?DescriptorRef = null;
    var joliet: ?DescriptorRef = null;

    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.BadVolumeDescriptor;

        switch (sector[0]) {
            1 => {
                if (primary == null) primary = try parseDescriptorRef(&sector);
            },
            2 => {
                if (joliet == null and isJolietEscape(sector[88..120])) {
                    joliet = try parseDescriptorRef(&sector);
                }
            },
            255 => break,
            else => {},
        }
    }

    return .{
        .primary = primary orelse return error.MissingPrimaryVolumeDescriptor,
        .joliet = joliet,
    };
}

fn parseDescriptorRef(sector: *const [descriptor_size]u8) OpenError!DescriptorRef {
    const logical_block_size = read723(sector[128..132]);
    if (logical_block_size == 0) return error.UnsupportedLogicalBlockSize;
    const root = try parseDirectoryRecord(sector[156..190]);
    return .{
        .logical_block_size = logical_block_size,
        .path_table_size = read733(sector[132..140]),
        .type_l_path_table = read731(sector[140..144]),
        .root_record = root,
    };
}

fn parsePathTable(allocator: std.mem.Allocator, io: Io, file: Io.File, descriptor: DescriptorRef) OpenError![]PathTableEntry {
    if (descriptor.path_table_size == 0 or descriptor.type_l_path_table == 0) return allocator.alloc(PathTableEntry, 0);

    const buf = try allocator.alloc(u8, descriptor.path_table_size);
    defer allocator.free(buf);
    _ = try file.readPositionalAll(io, buf, @as(u64, descriptor.type_l_path_table) * descriptor.logical_block_size);

    var list = std.array_list.Managed(PathTableEntry).init(allocator);
    errdefer {
        for (list.items) |item| allocator.free(item.name);
        list.deinit();
    }

    var offset: usize = 0;
    while (offset + 8 <= buf.len) {
        const name_len = buf[offset];
        if (name_len == 0) break;
        const extent = read731(buf[offset + 2 .. offset + 6]);
        const parent = read721(buf[offset + 6 .. offset + 8]);
        const name_start = offset + 8;
        const name_end = name_start + name_len;
        if (name_end > buf.len) break;

        const name = if (name_len == 1 and buf[name_start] == 0)
            try allocator.dupe(u8, "/")
        else
            try allocator.dupe(u8, buf[name_start..name_end]);
        try list.append(.{ .name = name, .extent_lba = extent, .parent_index = parent });

        offset = name_end;
        if (name_len % 2 == 1) offset += 1;
    }

    return list.toOwnedSlice();
}

fn parseDirectoryRecord(buf: []const u8) OpenError!DirectoryRecord {
    if (buf.len < 34) return error.InvalidDirectoryRecord;
    const length = buf[0];
    if (length < 34 or length > buf.len) return error.InvalidDirectoryRecord;

    const name_len = buf[32];
    const name_start = 33;
    const name_end = name_start + name_len;
    if (name_end > length) return error.InvalidDirectoryRecord;
    const pad = if (name_len % 2 == 0) @as(usize, 1) else 0;
    const system_use_start = name_end + pad;
    if (system_use_start > length) return error.InvalidDirectoryRecord;

    return .{
        .length = length,
        .ext_attr_length = buf[1],
        .extent_lba = read733(buf[2..10]),
        .data_length = read733(buf[10..18]),
        .recorded_at = parseRecordDate(buf[18..25]),
        .flags = buf[25],
        .file_unit_size = buf[26],
        .interleave_gap = buf[27],
        .file_identifier = buf[name_start..name_end],
        .system_use = buf[system_use_start..length],
    };
}

/// Decodes the 7-byte directory-record recording date (ECMA-119 9.1.5) into
/// epoch seconds. Byte 6 is the offset from GMT in 15-minute intervals (signed).
fn parseRecordDate(bytes: []const u8) i64 {
    const year: i64 = @as(i64, bytes[0]) + 1900;
    const month: i64 = bytes[1];
    const day: i64 = bytes[2];
    const hour: i64 = bytes[3];
    const minute: i64 = bytes[4];
    const second: i64 = bytes[5];
    const gmt_offset: i8 = @bitCast(bytes[6]);

    if (month < 1 or month > 12 or day < 1 or day > 31) return 0;
    var epoch = epochFromCivil(year, @intCast(month), @intCast(day));
    epoch += hour * 3600 + minute * 60 + second;
    epoch -= @as(i64, gmt_offset) * 15 * 60;
    return if (epoch < 0) 0 else epoch;
}

/// Days-from-civil (Howard Hinnant), then to epoch seconds at 00:00:00 UTC.
fn epochFromCivil(year: i64, month: u8, day: u8) i64 {
    const y = if (month <= 2) year - 1 else year;
    const era = @divFloor(if (y >= 0) y else y - 399, 400);
    const yoe = y - era * 400;
    const m: i64 = month;
    const d: i64 = day;
    const doy = @divFloor(153 * (if (m > 2) m - 3 else m + 9) + 2, 5) + d - 1;
    const doe = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    const days = era * 146097 + doe - 719468;
    return days * 86400;
}

fn parseRockRidge(allocator: std.mem.Allocator, io: Io, file: Io.File, builder: *TreeBuilder, system_use: []const u8) OpenError!RockRidgeInfo {
    var info = RockRidgeInfo{};
    errdefer info.deinit(allocator);

    var name_buf = std.array_list.Managed(u8).init(allocator);
    defer name_buf.deinit();
    var link_buf = std.array_list.Managed(u8).init(allocator);
    defer link_buf.deinit();

    var pending = std.array_list.Managed(Continuation).init(allocator);
    defer pending.deinit();

    var initial = system_use;
    if (builder.susp_skip) |skip| {
        if (skip <= initial.len) initial = initial[skip..] else initial = &.{};
    }

    var queue = std.array_list.Managed([]const u8).init(allocator);
    defer queue.deinit();
    try queue.append(initial);

    var continuation_loops: usize = 0;
    var index: usize = 0;
    while (index < queue.items.len) : (index += 1) {
        var rest = queue.items[index];
        while (rest.len >= 4) {
            const sig = rest[0..2];
            const entry_len = rest[2];
            if (entry_len < 4 or entry_len > rest.len) break;
            const entry = rest[0..entry_len];
            rest = rest[entry_len..];

            if (std.mem.eql(u8, sig, "SP")) {
                if (entry_len >= 7 and entry[4] == 0xBE and entry[5] == 0xEF) {
                    builder.susp_skip = entry[6];
                    builder.has_rock_ridge = true;
                }
            } else if (std.mem.eql(u8, sig, "RR")) {
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "CE")) {
                if (entry_len >= 28) {
                    try pending.append(.{
                        .extent_lba = read733(entry[4..12]),
                        .offset = read733(entry[12..20]),
                        .size = read733(entry[20..28]),
                    });
                }
            } else if (std.mem.eql(u8, sig, "ST")) {
                break;
            } else if (std.mem.eql(u8, sig, "ER")) {
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "PX")) {
                if (entry_len >= 36) {
                    info.mode = read733(entry[4..12]);
                    info.uid = read733(entry[20..28]);
                    info.gid = read733(entry[28..36]);
                    builder.has_rock_ridge = true;
                }
            } else if (std.mem.eql(u8, sig, "NM")) {
                if (entry_len >= 5) {
                    const flags = entry[4];
                    if ((flags & 0x06) == 0) {
                        try name_buf.appendSlice(entry[5..]);
                        builder.has_rock_ridge = true;
                    }
                }
            } else if (std.mem.eql(u8, sig, "SL")) {
                if (entry_len >= 5) {
                    try appendSymlinkComponents(&link_buf, entry[5..]);
                    builder.has_rock_ridge = true;
                }
            } else if (std.mem.eql(u8, sig, "TF")) {
                if (parseTimeFlags(entry)) |mtime| info.mtime = mtime;
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "CL") or std.mem.eql(u8, sig, "PL") or std.mem.eql(u8, sig, "RE")) {
                // Directory relocation (deep-tree workaround). The reader neither
                // follows nor regenerates it, so mark it as a rewrite blocker.
                markUnsupported(&info, .rock_ridge_relocation, sig);
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "PN")) {
                markUnsupported(&info, .rock_ridge_device_node, sig);
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "SF")) {
                markUnsupported(&info, .rock_ridge_sparse_file, sig);
                builder.has_rock_ridge = true;
            } else if (std.mem.eql(u8, sig, "ES") or std.mem.eql(u8, sig, "PD")) {
                // Extension-sourcing / padding: benign SUSP framing, ignored.
            } else if (builder.susp_skip != null and isSuspSignature(sig)) {
                // A SUSP-framed image carried a system-use record whose semantics
                // the reader does not model; its effect cannot be preserved.
                markUnsupported(&info, .unknown_susp_record, sig);
            }
        }

        while (pending.items.len > 0) {
            if (continuation_loops >= 32) return error.TooManyRockRidgeContinuations;
            continuation_loops += 1;
            const ce = pending.orderedRemove(0);
            const continuation = try allocator.alloc(u8, ce.size);
            _ = try file.readPositionalAll(io, continuation, @as(u64, ce.extent_lba) * builder.logical_block_size + ce.offset);
            try queue.append(continuation);
        }
    }

    for (queue.items[1..]) |item| allocator.free(item);

    if (name_buf.items.len > 0) info.name = try name_buf.toOwnedSlice();
    if (link_buf.items.len > 0) info.symlink_target = try link_buf.toOwnedSlice();
    return info;
}

const Continuation = struct {
    extent_lba: u32,
    offset: u32,
    size: u32,
};

fn markUnsupported(info: *RockRidgeInfo, feature: UnsupportedFeature, sig: []const u8) void {
    if (info.unsupported != null) return;
    info.unsupported = feature;
    const n = @min(sig.len, info.unsupported_tag.len);
    @memcpy(info.unsupported_tag[0..n], sig[0..n]);
    info.unsupported_tag_len = @intCast(n);
}

fn isSuspSignature(sig: []const u8) bool {
    return sig.len == 2 and
        sig[0] >= 'A' and sig[0] <= 'Z' and
        sig[1] >= 'A' and sig[1] <= 'Z';
}

/// Parses a Rock Ridge `TF` (timestamps) record and returns the modify time in
/// epoch seconds when present. Only the 7-byte short form is decoded; the rare
/// 17-byte long form is ignored (the directory-record date is used instead).
fn parseTimeFlags(entry: []const u8) ?i64 {
    if (entry.len < 5) return null;
    const flags = entry[4];
    if (flags & 0x80 != 0) return null; // long form: not decoded
    if (flags & 0x02 == 0) return null; // no modify time present
    var offset: usize = 5;
    // The modify bit is bit 1; only the creation bit (0) precedes it.
    if (flags & 0x01 != 0) offset += 7;
    if (offset + 7 > entry.len) return null;
    return parseRecordDate(entry[offset .. offset + 7]);
}

fn appendSymlinkComponents(buf: *std.array_list.Managed(u8), payload: []const u8) std.mem.Allocator.Error!void {
    var rest = payload;
    while (rest.len >= 2) {
        const flags = rest[0];
        const len = rest[1];
        if (2 + len > rest.len) break;
        const text = rest[2 .. 2 + len];

        const continued = (flags & 0x01) != 0;
        switch (flags & ~@as(u8, 0x01)) {
            0 => try buf.appendSlice(text),
            2 => try buf.append('.'),
            4 => try buf.appendSlice(".."),
            8 => try buf.append('/'),
            else => {},
        }

        rest = rest[2 + len ..];
        if ((flags & ~@as(u8, 0x01)) != 8 and !continued and rest.len >= 2) {
            try buf.append('/');
        }
    }
}

fn decodeIsoName(allocator: std.mem.Allocator, raw: []const u8) std.mem.Allocator.Error![]u8 {
    var name = raw;
    if (std.mem.lastIndexOfScalar(u8, name, ';')) |semi| {
        if (semi + 2 == name.len and name[semi + 1] == '1') name = name[0..semi];
    }
    while (name.len > 0 and name[name.len - 1] == '.') name = name[0 .. name.len - 1];
    return allocator.dupe(u8, name);
}

fn decodeJolietName(allocator: std.mem.Allocator, raw: []const u8) OpenError![]u8 {
    if (raw.len % 2 != 0) return error.InvalidJolietName;

    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();

    var i: usize = 0;
    while (i < raw.len) : (i += 2) {
        const codepoint = std.mem.readInt(u16, raw[i..][0..2], .big);
        if (codepoint == 0) break;
        var utf8: [4]u8 = undefined;
        const len = std.unicode.utf8Encode(codepoint, &utf8) catch return error.InvalidJolietName;
        try list.appendSlice(utf8[0..len]);
    }

    var name = try list.toOwnedSlice();
    errdefer allocator.free(name);

    if (name.len >= 2 and name[name.len - 2] == ';' and name[name.len - 1] == '1') {
        name = try allocator.realloc(name, name.len - 2);
    }
    while (name.len > 0 and name[name.len - 1] == '.') {
        name = try allocator.realloc(name, name.len - 1);
    }
    return name;
}

fn isJolietEscape(escape: []const u8) bool {
    return escape.len >= 3 and escape[0] == '%' and escape[1] == '/' and (escape[2] == '@' or escape[2] == 'C' or escape[2] == 'E');
}

fn read721(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}

fn read723(bytes: []const u8) u16 {
    return std.mem.readInt(u16, bytes[0..2], .little);
}

fn read731(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn read733(bytes: []const u8) u32 {
    return std.mem.readInt(u32, bytes[0..4], .little);
}

fn freeEntries(allocator: std.mem.Allocator, entries: []Entry) void {
    for (entries) |entry| {
        allocator.free(entry.name);
        allocator.free(entry.extents);
        if (entry.symlink_target) |target| allocator.free(target);
    }
    allocator.free(entries);
}

fn freePathTable(allocator: std.mem.Allocator, path_table: []PathTableEntry) void {
    for (path_table) |entry| allocator.free(entry.name);
    allocator.free(path_table);
}

fn dirEntryLessThan(_: void, a: DirEntry, b: DirEntry) bool {
    return std.mem.lessThan(u8, a.name, b.name);
}

fn appendU16Le(list: *std.array_list.Managed(u8), value: u16) !void {
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn appendU32Le(list: *std.array_list.Managed(u8), value: u32) !void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .little);
    try list.appendSlice(&buf);
}

fn write723(dst: []u8, value: u16) void {
    std.mem.writeInt(u16, dst[0..2], value, .little);
    std.mem.writeInt(u16, dst[2..4], value, .big);
}

fn write733(dst: []u8, value: u32) void {
    std.mem.writeInt(u32, dst[0..4], value, .little);
    std.mem.writeInt(u32, dst[4..8], value, .big);
}

/// Computes the directory-record length in a wide type so callers can validate
/// it against the 255-byte record limit (`max_record_len`) before narrowing to
/// the single-byte on-disk field. Casting here would truncate/panic for records
/// whose Rock Ridge system-use area must spill into a `CE` continuation.
fn recordLength(name_len: usize, system_use_len: usize) usize {
    const pad: usize = if (name_len % 2 == 0) 1 else 0;
    return 33 + name_len + pad + system_use_len;
}

fn makeDirectoryRecord(name: []const u8, extent_lba: u32, size: u32, flags: u8, system_use: []const u8) [256]u8 {
    var out: [256]u8 = [_]u8{0} ** 256;
    const len = recordLength(name.len, system_use.len);
    out[0] = @intCast(len);
    out[1] = 0;
    write733(out[2..10], extent_lba);
    write733(out[10..18], size);
    out[18] = 124; // 2024-01-01 00:00:00 GMT offset 0, synthetic/stable enough for tests.
    out[19] = 1;
    out[20] = 1;
    out[21] = 0;
    out[22] = 0;
    out[23] = 0;
    out[24] = 0;
    out[25] = flags;
    out[26] = 0;
    out[27] = 0;
    write723(out[28..32], 1);
    out[32] = @intCast(name.len);
    @memcpy(out[33 .. 33 + name.len], name);
    const pad: usize = if (name.len % 2 == 0) 1 else 0;
    if (pad == 1) out[33 + name.len] = 0;
    @memcpy(out[33 + name.len + pad ..][0..system_use.len], system_use);
    return out;
}

fn buildSpSystemUse() [7]u8 {
    return .{ 'S', 'P', 7, 1, 0xBE, 0xEF, 7 };
}

fn buildErSystemUse() [20]u8 {
    return .{ 'E', 'R', 20, 1, 10, 0, 0, 1, 'R', 'R', 'I', 'P', '_', '1', '9', '9', '1', 'A', 0, 0 };
}

fn buildRrSystemUse(flags: u8) [5]u8 {
    return .{ 'R', 'R', 5, 1, flags };
}

fn buildPxSystemUse(mode: u32, uid: u32, gid: u32) [36]u8 {
    var out: [36]u8 = [_]u8{0} ** 36;
    out[0] = 'P';
    out[1] = 'X';
    out[2] = 36;
    out[3] = 1;
    write733(out[4..12], mode);
    write733(out[12..20], 1);
    write733(out[20..28], uid);
    write733(out[28..36], gid);
    return out;
}

fn buildNmSystemUse(name: []const u8) [260]u8 {
    var out: [260]u8 = [_]u8{0} ** 260;
    out[0] = 'N';
    out[1] = 'M';
    out[2] = @intCast(5 + name.len);
    out[3] = 1;
    out[4] = 0;
    @memcpy(out[5 .. 5 + name.len], name);
    return out;
}

fn buildSlSystemUse(target: []const u8) [260]u8 {
    var out: [260]u8 = [_]u8{0} ** 260;
    var cursor: usize = 5;
    out[0] = 'S';
    out[1] = 'L';
    out[3] = 1;
    out[4] = 0;

    var it = std.mem.tokenizeScalar(u8, target, '/');
    const absolute = std.mem.startsWith(u8, target, "/");
    if (absolute) {
        out[cursor] = 8;
        out[cursor + 1] = 0;
        cursor += 2;
    }
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, ".")) {
            out[cursor] = 2;
            out[cursor + 1] = 0;
            cursor += 2;
        } else if (std.mem.eql(u8, component, "..")) {
            out[cursor] = 4;
            out[cursor + 1] = 0;
            cursor += 2;
        } else {
            out[cursor] = 0;
            out[cursor + 1] = @intCast(component.len);
            @memcpy(out[cursor + 2 .. cursor + 2 + component.len], component);
            cursor += 2 + component.len;
        }
    }
    out[2] = @intCast(cursor);
    return out;
}

fn buildStSystemUse() [4]u8 {
    return .{ 'S', 'T', 4, 1 };
}

fn writeIsoFile(path: []const u8, bytes: []const u8) !void {
    const io = std.testing.io;
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

test "iso9660 reader enumerates rock ridge names and resolves symlinks" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-rr.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const root_lba: u32 = 20;
    const dir_lba: u32 = 21;
    const file_lba: u32 = 22;
    const file_bytes = "hello from rock ridge\n";
    const susp_prefix = [_]u8{0} ** 7;

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize((file_lba + 1) * descriptor_size);
    @memset(image.items, 0);

    var pvd: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = standard_id;
    pvd[6] = 1;
    pvd[40..48].* = .{ 'Z', 'V', 'M', 'I', ' ', 'R', 'R', ' ' };
    write733(pvd[80..88], @intCast(image.items.len / descriptor_size));
    write723(pvd[128..132], descriptor_size);
    write733(pvd[132..140], 0);
    std.mem.writeInt(u32, pvd[140..144], 19, .little);

    const root_record = makeDirectoryRecord(&.{0}, root_lba, descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_record[0]], root_record[0..root_record[0]]);
    image.items[volume_descriptor_lba * descriptor_size .. (volume_descriptor_lba + 1) * descriptor_size].* = pvd;

    var terminator: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    terminator[0] = 255;
    terminator[1..6].* = standard_id;
    terminator[6] = 1;
    image.items[(volume_descriptor_lba + 1) * descriptor_size .. (volume_descriptor_lba + 2) * descriptor_size].* = terminator;

    var path_table = std.array_list.Managed(u8).init(allocator);
    defer path_table.deinit();
    try path_table.append(1);
    try path_table.append(0);
    try appendU32Le(&path_table, root_lba);
    try appendU16Le(&path_table, 1);
    try path_table.append(0);
    try path_table.append(0);
    try path_table.append(3);
    try path_table.append(0);
    try appendU32Le(&path_table, dir_lba);
    try appendU16Le(&path_table, 1);
    try path_table.appendSlice("DIR");
    try path_table.append(0);
    write733(image.items[16 * descriptor_size + 132 .. 16 * descriptor_size + 140], @intCast(path_table.items.len));
    @memcpy(image.items[19 * descriptor_size ..][0..path_table.items.len], path_table.items);

    var root_dir = std.array_list.Managed(u8).init(allocator);
    defer root_dir.deinit();
    var dot_su = std.array_list.Managed(u8).init(allocator);
    defer dot_su.deinit();
    try dot_su.appendSlice(&buildSpSystemUse());
    try dot_su.appendSlice(&buildErSystemUse());
    try dot_su.appendSlice(&buildPxSystemUse(0o040755, 0, 0));
    try dot_su.appendSlice(&buildStSystemUse());
    const dot = makeDirectoryRecord(&.{0}, root_lba, descriptor_size, 0x02, dot_su.items);
    try root_dir.appendSlice(dot[0..dot[0]]);

    var dotdot_su = std.array_list.Managed(u8).init(allocator);
    defer dotdot_su.deinit();
    try dotdot_su.appendSlice(&susp_prefix);
    try dotdot_su.appendSlice(&buildPxSystemUse(0o040755, 0, 0));
    try dotdot_su.appendSlice(&buildStSystemUse());
    const dotdot = makeDirectoryRecord(&.{1}, root_lba, descriptor_size, 0x02, dotdot_su.items);
    try root_dir.appendSlice(dotdot[0..dotdot[0]]);

    var file_su = std.array_list.Managed(u8).init(allocator);
    defer file_su.deinit();
    try file_su.appendSlice(&susp_prefix);
    try file_su.appendSlice(&buildRrSystemUse(1 | 8));
    try file_su.appendSlice(&buildPxSystemUse(0o100644, 1000, 1000));
    const file_nm = buildNmSystemUse("hello.txt");
    try file_su.appendSlice(file_nm[0..file_nm[2]]);
    try file_su.appendSlice(&buildStSystemUse());
    const file_record = makeDirectoryRecord("HELLO.TXT;1", file_lba, file_bytes.len, 0, file_su.items);
    try root_dir.appendSlice(file_record[0..file_record[0]]);

    var dir_su = std.array_list.Managed(u8).init(allocator);
    defer dir_su.deinit();
    try dir_su.appendSlice(&susp_prefix);
    try dir_su.appendSlice(&buildRrSystemUse(1 | 8));
    try dir_su.appendSlice(&buildPxSystemUse(0o040755, 0, 0));
    const dir_nm = buildNmSystemUse("dir");
    try dir_su.appendSlice(dir_nm[0..dir_nm[2]]);
    try dir_su.appendSlice(&buildStSystemUse());
    const dir_record = makeDirectoryRecord("DIR", dir_lba, descriptor_size, 0x02, dir_su.items);
    try root_dir.appendSlice(dir_record[0..dir_record[0]]);
    @memcpy(image.items[root_lba * descriptor_size ..][0..root_dir.items.len], root_dir.items);

    var subdir = std.array_list.Managed(u8).init(allocator);
    defer subdir.deinit();
    const sub_dot = makeDirectoryRecord(&.{0}, dir_lba, descriptor_size, 0x02, dotdot_su.items);
    try subdir.appendSlice(sub_dot[0..sub_dot[0]]);
    const sub_dotdot = makeDirectoryRecord(&.{1}, root_lba, descriptor_size, 0x02, dotdot_su.items);
    try subdir.appendSlice(sub_dotdot[0..sub_dotdot[0]]);

    var link_su = std.array_list.Managed(u8).init(allocator);
    defer link_su.deinit();
    try link_su.appendSlice(&susp_prefix);
    try link_su.appendSlice(&buildRrSystemUse(1 | 4 | 8));
    try link_su.appendSlice(&buildPxSystemUse(0o120777, 0, 0));
    const link_nm = buildNmSystemUse("motd-link");
    try link_su.appendSlice(link_nm[0..link_nm[2]]);
    const link_sl = buildSlSystemUse("../hello.txt");
    try link_su.appendSlice(link_sl[0..link_sl[2]]);
    try link_su.appendSlice(&buildStSystemUse());
    const link_record = makeDirectoryRecord("MOTD.LNK;1", file_lba, 0, 0, link_su.items);
    try subdir.appendSlice(link_record[0..link_record[0]]);
    @memcpy(image.items[dir_lba * descriptor_size ..][0..subdir.items.len], subdir.items);

    @memcpy(image.items[file_lba * descriptor_size ..][0..file_bytes.len], file_bytes);

    try writeIsoFile(path, image.items);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expect(reader.has_rock_ridge);
    try std.testing.expectEqual(NameSource.rock_ridge, reader.name_source);
    try std.testing.expectEqual(@as(usize, 2), reader.path_table.len);

    const file_index = try reader.lookup("/hello.txt");
    try std.testing.expectEqual(EntryKind.file, reader.getEntry(file_index).kind);
    const contents = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings(file_bytes, contents);

    const link_index = try reader.lookup("/dir/motd-link");
    try std.testing.expectEqualStrings("../hello.txt", try reader.readLink(link_index));
    const resolved_index = try reader.resolveSymlink(link_index);
    try std.testing.expectEqual(file_index, resolved_index);

    const dir_entries = try reader.listDirAlloc(allocator, reader.root_index);
    defer allocator.free(dir_entries);
    try std.testing.expectEqualStrings("dir", dir_entries[0].name);
    try std.testing.expectEqualStrings("hello.txt", dir_entries[1].name);
}

test "iso9660 reader falls back to joliet unicode names" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-joliet.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const primary_root_lba: u32 = 21;
    const joliet_root_lba: u32 = 22;
    const file_lba: u32 = 23;
    const file_bytes = "joliet works\n";

    var image = std.array_list.Managed(u8).init(allocator);
    defer image.deinit();
    try image.resize((file_lba + 1) * descriptor_size);
    @memset(image.items, 0);

    var pvd: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = standard_id;
    pvd[6] = 1;
    write733(pvd[80..88], @intCast(image.items.len / descriptor_size));
    write723(pvd[128..132], descriptor_size);
    write733(pvd[132..140], 0);
    std.mem.writeInt(u32, pvd[140..144], 20, .little);
    const root_record = makeDirectoryRecord(&.{0}, primary_root_lba, descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_record[0]], root_record[0..root_record[0]]);
    image.items[16 * descriptor_size .. 17 * descriptor_size].* = pvd;

    var svd: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    svd[0] = 2;
    svd[1..6].* = standard_id;
    svd[6] = 1;
    svd[88] = '%';
    svd[89] = '/';
    svd[90] = 'E';
    write733(svd[80..88], @intCast(image.items.len / descriptor_size));
    write723(svd[128..132], descriptor_size);
    write733(svd[132..140], 0);
    std.mem.writeInt(u32, svd[140..144], 20, .little);
    const joliet_root = makeDirectoryRecord(&.{0}, joliet_root_lba, descriptor_size, 0x02, &.{});
    @memcpy(svd[156 .. 156 + joliet_root[0]], joliet_root[0..joliet_root[0]]);
    image.items[17 * descriptor_size .. 18 * descriptor_size].* = svd;

    var terminator: [descriptor_size]u8 = [_]u8{0} ** descriptor_size;
    terminator[0] = 255;
    terminator[1..6].* = standard_id;
    terminator[6] = 1;
    image.items[18 * descriptor_size .. 19 * descriptor_size].* = terminator;

    var path_table = std.array_list.Managed(u8).init(allocator);
    defer path_table.deinit();
    try path_table.append(1);
    try path_table.append(0);
    try appendU32Le(&path_table, primary_root_lba);
    try appendU16Le(&path_table, 1);
    try path_table.append(0);
    try path_table.append(0);
    @memcpy(image.items[20 * descriptor_size ..][0..path_table.items.len], path_table.items);
    write733(image.items[16 * descriptor_size + 132 .. 16 * descriptor_size + 140], @intCast(path_table.items.len));
    write733(image.items[17 * descriptor_size + 132 .. 17 * descriptor_size + 140], @intCast(path_table.items.len));

    var primary_root = std.array_list.Managed(u8).init(allocator);
    defer primary_root.deinit();
    const primary_dot = makeDirectoryRecord(&.{0}, primary_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try primary_root.appendSlice(primary_dot[0..primary_dot[0]]);
    const primary_dotdot = makeDirectoryRecord(&.{1}, primary_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try primary_root.appendSlice(primary_dotdot[0..primary_dotdot[0]]);
    const primary_file = makeDirectoryRecord("UNICODE.TXT;1", file_lba, file_bytes.len, 0, &buildStSystemUse());
    try primary_root.appendSlice(primary_file[0..primary_file[0]]);
    @memcpy(image.items[primary_root_lba * descriptor_size ..][0..primary_root.items.len], primary_root.items);

    var joliet_root_dir = std.array_list.Managed(u8).init(allocator);
    defer joliet_root_dir.deinit();
    const joliet_dot = makeDirectoryRecord(&.{0}, joliet_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try joliet_root_dir.appendSlice(joliet_dot[0..joliet_dot[0]]);
    const joliet_dotdot = makeDirectoryRecord(&.{1}, joliet_root_lba, descriptor_size, 0x02, &buildStSystemUse());
    try joliet_root_dir.appendSlice(joliet_dotdot[0..joliet_dotdot[0]]);
    const joliet_name = [_]u8{ 0x00, 'h', 0x00, 0xE9, 0x00, 'l', 0x00, 'l', 0x00, 'o', 0x00, '.', 0x00, 't', 0x00, 'x', 0x00, 't', 0x00, ';', 0x00, '1' };
    const joliet_file = makeDirectoryRecord(&joliet_name, file_lba, file_bytes.len, 0, &buildStSystemUse());
    try joliet_root_dir.appendSlice(joliet_file[0..joliet_file[0]]);
    @memcpy(image.items[joliet_root_lba * descriptor_size ..][0..joliet_root_dir.items.len], joliet_root_dir.items);

    @memcpy(image.items[file_lba * descriptor_size ..][0..file_bytes.len], file_bytes);

    try writeIsoFile(path, image.items);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expect(!reader.has_rock_ridge);
    try std.testing.expect(reader.has_joliet);
    try std.testing.expectEqual(NameSource.joliet, reader.name_source);

    const file_index = try reader.lookup("/héllo.txt");
    const contents = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(contents);
    try std.testing.expectEqualStrings(file_bytes, contents);
}

// ===========================================================================
// El Torito boot catalog modeling
// ===========================================================================

pub const boot_platform_bios: u8 = 0x00;
pub const boot_platform_ppc: u8 = 0x01;
pub const boot_platform_mac: u8 = 0x02;
pub const boot_platform_uefi: u8 = 0xEF;

/// El Torito boot media / emulation type (initial/section entry byte 1, low
/// nibble). The native writer only emits `no_emulation`.
pub const BootMediaType = enum(u8) {
    no_emulation = 0,
    diskette_1_2m = 1,
    diskette_1_44m = 2,
    diskette_2_88m = 3,
    hard_disk = 4,
    _,
};

/// Whether an entry is the catalog's initial/default entry or belongs to a
/// section introduced by a section header.
pub const BootEntryKind = enum { default, section };

/// The catalog validation entry (El Torito §2.1): platform id plus the 24-byte
/// developer id string. A parsed catalog always has a verified checksum and
/// `0x55AA` key signature.
pub const BootValidationEntry = struct {
    platform: u8,
    id_string: [24]u8,
};

/// A section header (0x90 = more headers follow, 0x91 = final header).
pub const BootSectionHeader = struct {
    platform: u8,
    entry_count: u16,
    /// True for the final header (0x91).
    final: bool,
    id_string: [28]u8,
};

/// A single El Torito boot entry as recovered from the catalog. Every field the
/// writer can preserve is captured; `selection_criteria` bytes are retained for
/// section entries even though the current writer emits none.
pub const BootCatalogEntry = struct {
    kind: BootEntryKind,
    /// Platform id inherited from the validation entry (default entry) or the
    /// governing section header (section entries).
    platform: u8,
    bootable: bool,
    /// Raw boot indicator byte (0x88 bootable, 0x00 not bootable).
    boot_indicator: u8,
    /// Raw media byte (low nibble is media type, upper bits are flags).
    media_type: u8,
    /// Decoded media/emulation type.
    media: BootMediaType,
    load_segment: u16,
    system_type: u8,
    load_sectors: u16,
    image_lba: u32,
    /// Selection-criteria type byte (section entries only; 0 otherwise).
    selection_criteria_type: u8,
    /// Vendor selection-criteria bytes (section entries only).
    selection_criteria: [19]u8,
    /// A selection-criteria extension record (0x44) follows this entry.
    has_extension: bool,
};

pub const BootCatalog = struct {
    /// Platform id declared by the catalog validation entry. Retained as a
    /// convenience for callers that only need the primary platform.
    validation_platform: u8,
    validation: BootValidationEntry,
    /// Section headers in catalog order (empty for a default-entry-only image).
    headers: []BootSectionHeader,
    entries: []BootCatalogEntry,
    /// True when any section entry declared a following extension record.
    has_extension_records: bool,

    pub fn deinit(self: *BootCatalog, allocator: std.mem.Allocator) void {
        allocator.free(self.entries);
        allocator.free(self.headers);
        self.* = undefined;
    }
};

pub const BootCatalogError = error{
    NoBootRecord,
    InvalidBootCatalog,
    BadBootCatalogChecksum,
} || Io.File.ReadPositionalError || Io.File.StatError || std.mem.Allocator.Error;

/// Locates the El Torito boot record volume descriptor, follows it to the boot
/// catalog, validates the validation-entry signature/checksum and every entry's
/// indicators, media type, and referenced extent against the source file, and
/// returns the modeled catalog. Returns `error.NoBootRecord` when the image
/// carries no El Torito boot record. Caller owns the returned catalog.
pub fn readBootCatalog(allocator: std.mem.Allocator, io: Io, file: Io.File) BootCatalogError!BootCatalog {
    const file_size = (try file.stat(io)).size;

    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    var catalog_lba: ?u32 = null;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.InvalidBootCatalog;
        switch (sector[0]) {
            0 => {
                if (std.mem.startsWith(u8, sector[7..], "EL TORITO SPECIFICATION")) {
                    catalog_lba = read731(sector[71..75]);
                }
            },
            255 => break,
            else => {},
        }
    }

    const cat_lba = catalog_lba orelse return error.NoBootRecord;
    if (@as(u64, cat_lba) * descriptor_size + descriptor_size > file_size) return error.InvalidBootCatalog;
    var catalog: [descriptor_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &catalog, @as(u64, cat_lba) * descriptor_size);

    // Validation entry: header id 0x01, key bytes 0x55 0xAA, and all 16-bit
    // little-endian words summing to zero.
    if (catalog[0] != 0x01 or catalog[30] != 0x55 or catalog[31] != 0xAA) return error.InvalidBootCatalog;
    var sum: u16 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 2) sum +%= std.mem.readInt(u16, catalog[i..][0..2], .little);
    if (sum != 0) return error.BadBootCatalogChecksum;
    const validation_platform = catalog[1];

    var validation = BootValidationEntry{ .platform = validation_platform, .id_string = undefined };
    @memcpy(&validation.id_string, catalog[4..28]);

    var entries = std.array_list.Managed(BootCatalogEntry).init(allocator);
    errdefer entries.deinit();
    var headers = std.array_list.Managed(BootSectionHeader).init(allocator);
    errdefer headers.deinit();
    var has_extension_records = false;

    // Default/initial entry immediately follows the validation entry and
    // inherits the validation entry's platform id.
    try entries.append(try parseBootEntry(catalog[32..64], validation_platform, .default, file_size));

    // Section headers (0x90/0x91) each introduce a run of section entries for a
    // possibly different platform.
    var offset: usize = 64;
    while (offset + 32 <= catalog.len) {
        const header_id = catalog[offset];
        if (header_id != 0x90 and header_id != 0x91) break;
        const section_platform = catalog[offset + 1];
        const count = std.mem.readInt(u16, catalog[offset + 2 ..][0..2], .little);
        var header = BootSectionHeader{
            .platform = section_platform,
            .entry_count = count,
            .final = header_id == 0x91,
            .id_string = undefined,
        };
        @memcpy(&header.id_string, catalog[offset + 4 .. offset + 32]);
        try headers.append(header);
        offset += 32;
        var seen: u16 = 0;
        while (seen < count) : (seen += 1) {
            if (offset + 32 > catalog.len) return error.InvalidBootCatalog;
            const entry = try parseBootEntry(catalog[offset .. offset + 32], section_platform, .section, file_size);
            offset += 32;
            if (entry.has_extension) {
                has_extension_records = true;
                // A selection-criteria extension record (0x44) must follow.
                if (offset + 32 > catalog.len or catalog[offset] != 0x44) return error.InvalidBootCatalog;
                offset += 32;
            }
            try entries.append(entry);
        }
        if (header_id == 0x91) break;
    }

    return .{
        .validation_platform = validation_platform,
        .validation = validation,
        .headers = try headers.toOwnedSlice(),
        .entries = try entries.toOwnedSlice(),
        .has_extension_records = has_extension_records,
    };
}

fn parseBootEntry(entry: []const u8, platform: u8, kind: BootEntryKind, file_size: u64) BootCatalogError!BootCatalogEntry {
    const boot_indicator = entry[0];
    if (boot_indicator != 0x88 and boot_indicator != 0x00) return error.InvalidBootCatalog;
    const media_byte = entry[1];
    if (media_byte & 0x0F > 4) return error.InvalidBootCatalog;
    const image_lba = std.mem.readInt(u32, entry[8..12], .little);
    if (@as(u64, image_lba) * descriptor_size >= file_size) return error.InvalidBootCatalog;

    var result = BootCatalogEntry{
        .kind = kind,
        .platform = platform,
        .bootable = boot_indicator == 0x88,
        .boot_indicator = boot_indicator,
        .media_type = media_byte,
        .media = @enumFromInt(media_byte & 0x0F),
        .load_segment = std.mem.readInt(u16, entry[2..4], .little),
        .system_type = entry[4],
        .load_sectors = std.mem.readInt(u16, entry[6..8], .little),
        .image_lba = image_lba,
        .selection_criteria_type = 0,
        .selection_criteria = [_]u8{0} ** 19,
        // A section entry declares a following extension record via bit 5
        // (0x20) of the media byte.
        .has_extension = kind == .section and (media_byte & 0x20 != 0),
    };
    if (kind == .section) {
        result.selection_criteria_type = entry[12];
        @memcpy(&result.selection_criteria, entry[13..32]);
    }
    return result;
}

// ===========================================================================
// Rewrite preservation preflight
// ===========================================================================

/// How a boot image's LBA relates to the modeled ISO tree.
pub const BootImageMapping = union(enum) {
    /// The boot image begins at a modeled regular file's extent. A recustomizer
    /// can re-derive the image from that tree node during regeneration.
    mapped: struct {
        entry_index: usize,
        /// Absolute path, owned by the enclosing `RewriteInspection` arena.
        path: []const u8,
    },
    /// The boot image LBA falls outside every modeled file. There is no path to
    /// re-derive it from, so the recustomizer must treat the extent as opaque
    /// raw bytes (or refuse). Never invents a path.
    raw_extent: struct {
        lba: u32,
        sectors: u16,
    },
};

/// A boot catalog entry paired with its resolved image mapping.
pub const InspectedBootEntry = struct {
    entry: BootCatalogEntry,
    image: BootImageMapping,
};

/// Modeled El Torito boot state for a rewrite: the validation entry, section
/// headers, and every entry with its image mapping resolved against the tree.
pub const BootModel = struct {
    validation: BootValidationEntry,
    headers: []BootSectionHeader,
    entries: []InspectedBootEntry,
    has_extension_records: bool,
};

/// Result of `Reader.inspectForRewrite`: the writer-preservable metadata plus an
/// explicit, ordered list of every source construct the writer cannot preserve.
/// An empty `unsupported` list means a regeneration is lossless within the
/// supported model. Owns an arena; release with `deinit`.
pub const RewriteInspection = struct {
    arena: std.heap.ArenaAllocator,
    volume: VolumeMetadata,
    /// El Torito state, or null when the image carries no boot record.
    boot: ?BootModel,
    unsupported: []UnsupportedDetail,

    pub fn deinit(self: *RewriteInspection) void {
        self.arena.deinit();
        self.* = undefined;
    }

    /// True when nothing blocks a lossless regeneration.
    pub fn losslessWithinModel(self: RewriteInspection) bool {
        return self.unsupported.len == 0;
    }

    /// The first (most structural) blocker, or null when lossless.
    pub fn firstUnsupported(self: RewriteInspection) ?UnsupportedDetail {
        return if (self.unsupported.len > 0) self.unsupported[0] else null;
    }
};

pub const InspectError = error{
    InvalidBootCatalog,
    BadBootCatalogChecksum,
    BadVolumeDescriptor,
    MissingPrimaryVolumeDescriptor,
} || Io.File.ReadPositionalError || Io.File.StatError || std.mem.Allocator.Error;

pub const RewriteSupportError = error{SourceNotRewritable} || InspectError;

/// Frees the `path`/`note` copies returned through `requireRewriteSupported`'s
/// out-parameter.
pub fn freeUnsupportedDetail(allocator: std.mem.Allocator, detail: UnsupportedDetail) void {
    if (detail.path.len > 0) allocator.free(detail.path);
    if (detail.note.len > 0) allocator.free(detail.note);
}

pub const VolumeIdError = error{
    BadVolumeDescriptor,
    MissingPrimaryVolumeDescriptor,
} || Io.File.ReadPositionalError || std.mem.Allocator.Error;

/// Reads the primary volume descriptor's 32-byte volume identifier, trimmed of
/// trailing spaces and NULs. A regenerating pipeline (e.g. `build_iso`) reuses
/// it so a `root=live:CDLABEL=<id>` boot line still finds the volume after the
/// image is rewritten. Caller owns the returned slice.
pub fn readVolumeIdAlloc(allocator: std.mem.Allocator, io: Io, file: Io.File) VolumeIdError![]u8 {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.BadVolumeDescriptor;
        switch (sector[0]) {
            1 => {
                const raw = sector[40..72];
                var end: usize = raw.len;
                while (end > 0 and (raw[end - 1] == ' ' or raw[end - 1] == 0)) end -= 1;
                return allocator.dupe(u8, raw[0..end]);
            },
            255 => break,
            else => {},
        }
    }
    return error.MissingPrimaryVolumeDescriptor;
}

/// Primary-volume-descriptor identifier strings worth preserving across a
/// regeneration. Each field is trimmed of trailing spaces and NULs; an unset
/// field decodes to an empty slice. All slices are owned by the struct and
/// released together by `deinit`. The native writer can emit every field, so a
/// round-trip through `WriteOptions` is lossless.
pub const VolumeMetadata = struct {
    volume_id: []u8,
    system_id: []u8,
    volume_set_id: []u8,
    publisher_id: []u8,
    preparer_id: []u8,
    application_id: []u8,

    pub fn deinit(self: *VolumeMetadata, allocator: std.mem.Allocator) void {
        allocator.free(self.volume_id);
        allocator.free(self.system_id);
        allocator.free(self.volume_set_id);
        allocator.free(self.publisher_id);
        allocator.free(self.preparer_id);
        allocator.free(self.application_id);
        self.* = undefined;
    }
};

/// Reads the primary volume descriptor's identifier strings. Caller owns the
/// returned metadata and must `deinit` it.
pub fn readVolumeMetadataAlloc(allocator: std.mem.Allocator, io: Io, file: Io.File) VolumeIdError!VolumeMetadata {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (!std.mem.eql(u8, sector[1..6], &standard_id)) return error.BadVolumeDescriptor;
        switch (sector[0]) {
            1 => {
                var meta = VolumeMetadata{
                    .volume_id = &.{},
                    .system_id = &.{},
                    .volume_set_id = &.{},
                    .publisher_id = &.{},
                    .preparer_id = &.{},
                    .application_id = &.{},
                };
                errdefer meta.deinit(allocator);
                meta.system_id = try dupeTrimmed(allocator, sector[8..40]);
                meta.volume_id = try dupeTrimmed(allocator, sector[40..72]);
                meta.volume_set_id = try dupeTrimmed(allocator, sector[190..318]);
                meta.publisher_id = try dupeTrimmed(allocator, sector[318..446]);
                meta.preparer_id = try dupeTrimmed(allocator, sector[446..574]);
                meta.application_id = try dupeTrimmed(allocator, sector[574..702]);
                return meta;
            },
            255 => break,
            else => {},
        }
    }
    return error.MissingPrimaryVolumeDescriptor;
}

fn dupeTrimmed(allocator: std.mem.Allocator, raw: []const u8) std.mem.Allocator.Error![]u8 {
    var end: usize = raw.len;
    while (end > 0 and (raw[end - 1] == ' ' or raw[end - 1] == 0)) end -= 1;
    return allocator.dupe(u8, raw[0..end]);
}

// ===========================================================================
// Writer
// ===========================================================================

/// Node kinds the writer can encode. Adapters reject anything outside this set
/// (hardlinks, devices, fifos) with a precise error rather than dropping it.
pub const SourceKind = enum { directory, file, symlink };

/// One node pulled from a `TreeSource`, addressed by its root-relative path.
/// Paths carry no leading slash and use '/' separators; the root directory is
/// described separately by `SourceRoot` and is never returned as a node.
pub const SourceNode = struct {
    path: []const u8,
    kind: SourceKind,
    /// POSIX mode. Only the low 12 bits (permissions + setuid/setgid/sticky)
    /// are used; the type bits are derived from `kind`.
    mode: u16,
    uid: u32 = 0,
    gid: u32 = 0,
    /// Deterministic modification time in epoch seconds, stamped into the
    /// directory record's recording date. Negative values clamp to 0.
    mtime: i64 = 0,
    /// Byte length for regular files; ignored for directories and symlinks.
    size: u64 = 0,
    /// Link target for symlinks, borrowed for the duration of the write call.
    /// May be empty for sources that expose the target through `read` (in
    /// which case `size` gives its length); ignored for other kinds.
    symlink_target: []const u8 = &.{},
};

/// Metadata for the image root directory.
pub const SourceRoot = struct {
    mode: u16 = 0o755,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
};

/// Generic pull-based source the writer consumes. Any tree (RootTree included)
/// can expose one without the ISO codec depending on its concrete type.
/// `node` may fail so an adapter can reject unrepresentable nodes precisely.
pub const TreeSource = struct {
    context: *const anyopaque,
    vtable: *const VTable,

    pub const VTable = struct {
        root: *const fn (context: *const anyopaque) SourceRoot,
        count: *const fn (context: *const anyopaque) usize,
        node: *const fn (context: *const anyopaque, index: usize) anyerror!SourceNode,
        read: *const fn (context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize,
    };

    pub fn root(self: TreeSource) SourceRoot {
        return self.vtable.root(self.context);
    }
    pub fn count(self: TreeSource) usize {
        return self.vtable.count(self.context);
    }
    pub fn node(self: TreeSource, index: usize) anyerror!SourceNode {
        return self.vtable.node(self.context, index);
    }
    pub fn read(self: TreeSource, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        return self.vtable.read(self.context, index, buffer, offset);
    }
};

/// El Torito firmware platform for a boot entry.
pub const BootPlatform = enum(u8) {
    bios = boot_platform_bios,
    uefi = boot_platform_uefi,
};

/// A single El Torito boot entry the writer should emit. `image_path` names a
/// regular file already present in the source tree; its assigned LBA is wired
/// into the boot catalog.
pub const BootEntry = struct {
    platform: BootPlatform,
    /// Root-relative path (no leading slash) of the boot image file.
    image_path: []const u8,
    /// Load segment in real-mode paragraphs; 0 selects the El Torito default
    /// (0x07C0). Ignored by UEFI firmware but preserved in the catalog.
    load_segment: u16 = 0,
    /// System type byte (partition type of the boot image); 0 is typical for
    /// no-emulation images.
    system_type: u8 = 0,
    /// Virtual 512-byte sectors to load; 0 lets the writer derive it from the
    /// boot image size.
    load_sectors: u16 = 0,
    bootable: bool = true,
};

/// A single El Torito boot image entry within a `BootCatalogLayout`. Unlike
/// `BootEntry` it carries no platform id: the platform is inherited from the
/// validation entry (for the default entry) or the governing section header
/// (for section entries), exactly as El Torito lays the catalog out on disk.
/// `image_path` names a regular file already present in the source tree; its
/// assigned LBA is wired into the catalog.
pub const BootImageEntry = struct {
    /// Root-relative path (no leading slash) of the boot image file.
    image_path: []const u8,
    /// Load segment in real-mode paragraphs; 0 selects the El Torito default
    /// (0x07C0). Ignored by UEFI firmware but preserved in the catalog.
    load_segment: u16 = 0,
    /// System type byte (partition type of the boot image).
    system_type: u8 = 0,
    /// Virtual 512-byte sectors to load; 0 lets the writer derive it from the
    /// boot image size.
    load_sectors: u16 = 0,
    bootable: bool = true,
};

/// A section header plus its entries, reproduced verbatim so a rewrite can
/// preserve a source catalog's section grouping, order, and id strings.
pub const BootCatalogSection = struct {
    /// Section header platform id; the section's entries inherit it.
    platform: u8,
    /// True emits a final section header (0x91); false emits a "more headers
    /// follow" header (0x90). Reproduces the source's final-vs-more indicator.
    final: bool = true,
    /// 28-byte section header id string, emitted verbatim.
    id_string: [28]u8 = [_]u8{0} ** 28,
    /// Section entries, in catalog order.
    entries: []const BootImageEntry,
};

/// A fully specified El Torito boot catalog layout for exact reproduction. When
/// set on `WriteOptions.boot_catalog` it wholly determines the catalog and
/// `boot_entries` is ignored: the validation entry (platform assignment plus its
/// 24-byte id string), the initial/default entry, and the section headers and
/// their entries are emitted in the given order. `recustomize-iso` builds this
/// from `Reader.inspectForRewrite` so a source catalog round-trips byte-for-byte
/// within the supported (no-emulation) model; authoring callers such as
/// `build-iso` keep using the simpler `boot_entries` convention and leave this
/// null. The whole catalog must fit in one 2048-byte logical sector.
pub const BootCatalogLayout = struct {
    /// Validation entry platform id; the default entry inherits it.
    validation_platform: u8,
    /// Validation entry 24-byte developer id string, emitted verbatim.
    validation_id: [24]u8 = [_]u8{0} ** 24,
    /// The initial/default boot entry (immediately follows the validation
    /// entry and inherits `validation_platform`).
    default_entry: BootImageEntry,
    /// Section headers and their entries, in catalog order.
    sections: []const BootCatalogSection = &.{},
};

/// Projects a platform-tagged `BootEntry` onto the platform-less
/// `BootImageEntry` the catalog emitter writes; the platform is carried by the
/// validation entry / section header, not the 32-byte boot entry itself.
fn toImageEntry(entry: BootEntry) BootImageEntry {
    return .{
        .image_path = entry.image_path,
        .load_segment = entry.load_segment,
        .system_type = entry.system_type,
        .load_sectors = entry.load_sectors,
        .bootable = entry.bootable,
    };
}

/// Writes the 32-byte El Torito validation entry into `cat[0..32]`: header id
/// 0x01, platform id, up to 24 bytes of developer id string at [4..28], the
/// 0x55AA key signature, and the checksum word chosen so all 16 words sum to
/// zero. The id string is space for the whole 24-byte field (zero-padded).
fn writeValidationEntry(cat: []u8, platform: u8, id_string: []const u8) void {
    cat[0] = 0x01;
    cat[1] = platform;
    @memset(cat[4..28], 0);
    const n = @min(id_string.len, 24);
    @memcpy(cat[4..][0..n], id_string[0..n]);
    cat[30] = 0x55;
    cat[31] = 0xAA;
    var sum: u16 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 2) {
        if (i == 28) continue;
        sum +%= std.mem.readInt(u16, cat[i..][0..2], .little);
    }
    std.mem.writeInt(u16, cat[28..30], (~sum +% 1), .little);
}

pub const WriteOptions = struct {
    /// Volume identifier written to the primary volume descriptor (d-chars,
    /// truncated/space-padded to 32 bytes).
    volume_id: []const u8 = "ISOIMAGE",
    /// System identifier (a-chars, truncated/space-padded to 32 bytes).
    system_id: []const u8 = "",
    /// Volume set identifier (d-chars, truncated/space-padded to 128 bytes).
    volume_set_id: []const u8 = "",
    /// Publisher identifier (a-chars, truncated/space-padded to 128 bytes).
    publisher_id: []const u8 = "",
    /// Data preparer identifier (a-chars, truncated/space-padded to 128 bytes).
    preparer_id: []const u8 = "",
    /// Application identifier (a-chars, truncated/space-padded to 128 bytes).
    application_id: []const u8 = "",
    /// El Torito boot entries. Empty means a plain (non-bootable) ISO. At most
    /// one entry per platform is supported. Ignored when `boot_catalog` is set.
    boot_entries: []const BootEntry = &.{},
    /// Precise El Torito catalog layout for exact reproduction. When non-null it
    /// wholly determines the boot catalog (validation platform assignment and
    /// 24-byte id string, section grouping/order and 28-byte id strings, and
    /// entry order/fields) and `boot_entries` is ignored. When null the writer
    /// emits `boot_entries` using its default BIOS-first authoring convention.
    boot_catalog: ?BootCatalogLayout = null,
};

pub const WriteResult = struct {
    /// Total image length in bytes (always a multiple of 2048).
    bytes_written: u64,
    /// Number of 2048-byte logical sectors in the image.
    total_sectors: u32,
    /// Directory + file + symlink nodes emitted (excludes the root directory).
    node_count: u32,
};

pub const WriteError = error{
    InvalidPath,
    MissingParentDirectory,
    DuplicatePath,
    NameTooLong,
    SymlinkTargetTooLong,
    EmptyName,
    TooManyBootEntries,
    DuplicateBootPlatform,
    BootImageNotFound,
    BootCatalogTooLarge,
    ContentReadShort,
    SystemUseAreaTooLong,
};

/// Writes a deterministic ISO9660 image describing `source` to `output`, which
/// must be a writable file positioned at offset 0. Streams file content sector
/// by sector and returns the image length plus counts.
pub fn writeImage(
    allocator: std.mem.Allocator,
    io: Io,
    output: Io.File,
    source: TreeSource,
    options: WriteOptions,
) anyerror!WriteResult {
    var arena_state = std.heap.ArenaAllocator.init(allocator);
    defer arena_state.deinit();

    var writer = IsoWriter{
        .allocator = allocator,
        .arena = arena_state.allocator(),
        .io = io,
        .file = output,
        .options = options,
    };
    return writer.run(source);
}

/// Convenience wrapper that creates (truncating) `path` and writes the image.
pub fn writeImagePath(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    source: TreeSource,
    options: WriteOptions,
) anyerror!WriteResult {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    return writeImage(allocator, io, file, source, options);
}

const sector_size: u32 = descriptor_size;
const system_area_sectors: u32 = 16;
const max_record_len: usize = 255;
const max_name_len: usize = 250;

const IsoBuildNode = struct {
    kind: SourceKind,
    name: []const u8,
    iso_id: []const u8,
    mode: u16,
    uid: u32,
    gid: u32,
    mtime: i64,
    file_size: u64,
    symlink_target: []const u8,
    source_index: ?usize,
    parent_index: usize,
    children: std.array_list.Managed(usize),

    // The full Rock Ridge SUSP for this node's record inside its parent
    // directory, and the record length that produces.
    child_susp: []u8 = &.{},
    child_uses_ce: bool = false,
    child_record_len: u8 = 0,
    ce_offset: u32 = 0,

    // Assigned during layout.
    extent_lba: u32 = 0,
    data_len: u32 = 0,
    dir_number: u16 = 0,
};

const IsoWriter = struct {
    allocator: std.mem.Allocator,
    arena: std.mem.Allocator,
    io: Io,
    file: Io.File,
    options: WriteOptions,

    nodes: []IsoBuildNode = &.{},
    dir_order: []usize = &.{},
    continuation: std.array_list.Managed(u8) = undefined,

    // Layout.
    pvd_lba: u32 = 0,
    boot_record_lba: u32 = 0,
    terminator_lba: u32 = 0,
    path_table_l_lba: u32 = 0,
    path_table_m_lba: u32 = 0,
    path_table_size: u32 = 0,
    continuation_lba: u32 = 0,
    boot_catalog_lba: u32 = 0,
    total_sectors: u32 = 0,

    fn run(self: *IsoWriter, source: TreeSource) anyerror!WriteResult {
        self.continuation = std.array_list.Managed(u8).init(self.arena);

        try self.buildTree(source);
        try self.orderDirectories();
        try self.buildSusp();
        try self.assignLayout();
        try self.emit(source);

        return .{
            .bytes_written = @as(u64, self.total_sectors) * sector_size,
            .total_sectors = self.total_sectors,
            .node_count = @intCast(self.nodes.len - 1),
        };
    }

    fn buildTree(self: *IsoWriter, source: TreeSource) anyerror!void {
        const total = source.count();
        const Collected = struct { index: usize, node: SourceNode };
        var collected = try std.array_list.Managed(Collected).initCapacity(self.arena, total);
        var i: usize = 0;
        while (i < total) : (i += 1) {
            collected.appendAssumeCapacity(.{ .index = i, .node = try source.node(i) });
        }
        std.mem.sort(Collected, collected.items, {}, struct {
            fn less(_: void, a: Collected, b: Collected) bool {
                return std.mem.lessThan(u8, a.node.path, b.node.path);
            }
        }.less);

        var nodes = std.array_list.Managed(IsoBuildNode).init(self.arena);
        var map = std.StringHashMap(usize).init(self.arena);

        const root = source.root();
        try nodes.append(.{
            .kind = .directory,
            .name = "",
            .iso_id = "",
            .mode = root.mode,
            .uid = root.uid,
            .gid = root.gid,
            .mtime = clamp(root.mtime),
            .file_size = 0,
            .symlink_target = &.{},
            .source_index = null,
            .parent_index = 0,
            .children = std.array_list.Managed(usize).init(self.arena),
        });
        try map.put("", 0);

        for (collected.items) |item| {
            const sn = item.node;
            var path = sn.path;
            while (path.len > 0 and path[0] == '/') path = path[1..];
            if (path.len == 0) return error.InvalidPath;

            const parent_path, const name = splitLast(path);
            if (name.len == 0) return error.EmptyName;
            if (name.len > max_name_len) return error.NameTooLong;
            const parent_index = map.get(parent_path) orelse return error.MissingParentDirectory;
            if (map.contains(path)) return error.DuplicatePath;

            const symlink_target: []const u8 = if (sn.kind == .symlink) blk: {
                const target = if (sn.symlink_target.len > 0)
                    try self.arena.dupe(u8, sn.symlink_target)
                else target_blk: {
                    const buffer = try self.arena.alloc(u8, @intCast(sn.size));
                    try self.readExact(source, item.index, buffer, 0);
                    break :target_blk buffer;
                };
                break :blk target;
            } else &.{};

            const new_index = nodes.items.len;
            try nodes.append(.{
                .kind = sn.kind,
                .name = try self.arena.dupe(u8, name),
                .iso_id = "",
                .mode = sn.mode,
                .uid = sn.uid,
                .gid = sn.gid,
                .mtime = clamp(sn.mtime),
                .file_size = if (sn.kind == .file) sn.size else 0,
                .symlink_target = symlink_target,
                .source_index = item.index,
                .parent_index = parent_index,
                .children = std.array_list.Managed(usize).init(self.arena),
            });
            try map.put(try self.arena.dupe(u8, path), new_index);
            try nodes.items[parent_index].children.append(new_index);
        }

        self.nodes = nodes.items;
        for (self.nodes) |*node| {
            std.mem.sort(usize, node.children.items, self.nodes, childNameLess);
        }
        try self.assignIsoIdentifiers();
    }

    fn assignIsoIdentifiers(self: *IsoWriter) anyerror!void {
        for (self.nodes) |*dir| {
            if (dir.kind != .directory) continue;
            var used = std.StringHashMap(void).init(self.arena);
            for (dir.children.items) |child_index| {
                const child = &self.nodes[child_index];
                child.iso_id = try self.mangleIdentifier(child.name, child.kind == .directory, &used);
            }
        }
    }

    fn mangleIdentifier(self: *IsoWriter, name: []const u8, is_dir: bool, used: *std.StringHashMap(void)) anyerror![]const u8 {
        var base = std.array_list.Managed(u8).init(self.arena);
        const limit: usize = if (is_dir) 30 else 26;
        for (name) |c| {
            if (base.items.len >= limit) break;
            const up = std.ascii.toUpper(c);
            if ((up >= 'A' and up <= 'Z') or (up >= '0' and up <= '9') or up == '_') {
                try base.append(up);
            } else {
                try base.append('_');
            }
        }
        if (base.items.len == 0) try base.append('_');

        var suffix: u32 = 0;
        while (true) {
            var candidate = std.array_list.Managed(u8).init(self.arena);
            try candidate.appendSlice(base.items);
            if (suffix > 0) {
                var buf: [12]u8 = undefined;
                const s = std.fmt.bufPrint(&buf, "{d}", .{suffix}) catch unreachable;
                const keep = @min(base.items.len, limit - s.len);
                candidate.clearRetainingCapacity();
                try candidate.appendSlice(base.items[0..keep]);
                try candidate.appendSlice(s);
            }
            if (!is_dir) try candidate.appendSlice(";1");
            const key = candidate.items;
            if (!used.contains(key)) {
                try used.put(key, {});
                return key;
            }
            suffix += 1;
        }
    }

    fn orderDirectories(self: *IsoWriter) anyerror!void {
        var order = std.array_list.Managed(usize).init(self.arena);
        try order.append(0);
        self.nodes[0].dir_number = 1;
        var cursor: usize = 0;
        while (cursor < order.items.len) : (cursor += 1) {
            const dir_index = order.items[cursor];
            for (self.nodes[dir_index].children.items) |child_index| {
                if (self.nodes[child_index].kind == .directory) {
                    self.nodes[child_index].dir_number = @intCast(order.items.len + 1);
                    try order.append(child_index);
                }
            }
        }
        self.dir_order = order.items;
    }

    fn buildSusp(self: *IsoWriter) anyerror!void {
        for (self.nodes, 0..) |*node, idx| {
            if (idx == 0) continue;
            var susp = std.array_list.Managed(u8).init(self.arena);
            try susp.appendSlice(&buildPxSystemUse(fullMode(node.kind, node.mode), node.uid, node.gid));
            const nm = buildNmSystemUse(node.name);
            try susp.appendSlice(nm[0..nm[2]]);
            if (node.kind == .symlink) {
                if (symlinkComponentsLen(node.symlink_target) > max_record_len) return error.SymlinkTargetTooLong;
                const sl = buildSlSystemUse(node.symlink_target);
                try susp.appendSlice(sl[0..sl[2]]);
            }
            node.child_susp = susp.items;

            const id_len = node.iso_id.len;
            const inline_len = recordLength(id_len, susp.items.len);
            if (inline_len <= max_record_len) {
                node.child_uses_ce = false;
                node.child_record_len = @intCast(inline_len);
            } else {
                // The record itself only carries the fixed-size `CE` pointer, so
                // its length is always well within `max_record_len`.
                node.child_uses_ce = true;
                node.child_record_len = @intCast(recordLength(id_len, ce_record_len));

                // A System Use payload referenced by `CE` must not straddle a
                // logical-block boundary (SUSP §4). Pad the continuation area up
                // to the next sector when the payload would not fit in what
                // remains of the current one. A single payload larger than a
                // logical block cannot be represented; reject it precisely.
                if (susp.items.len > sector_size) return error.SystemUseAreaTooLong;
                const used = self.continuation.items.len % sector_size;
                const remaining = sector_size - used;
                if (susp.items.len > remaining) {
                    try self.continuation.appendNTimes(0, remaining);
                }

                node.ce_offset = @intCast(self.continuation.items.len);
                try self.continuation.appendSlice(susp.items);
            }
        }

        // Compute each directory's extent size from its record layout.
        for (self.dir_order) |dir_index| {
            self.nodes[dir_index].data_len = self.directoryExtentSize(dir_index);
        }
    }

    fn directoryExtentSize(self: *IsoWriter, dir_index: usize) u32 {
        const dir = &self.nodes[dir_index];
        var pos: u32 = 0;
        // '.' and '..' records.
        pos = placeRecord(pos, dotRecordLen(dir_index == 0));
        pos = placeRecord(pos, dotdotRecordLen());
        for (dir.children.items) |child_index| {
            pos = placeRecord(pos, self.nodes[child_index].child_record_len);
        }
        return roundUpSector(pos);
    }

    fn assignLayout(self: *IsoWriter) anyerror!void {
        const has_boot = self.hasBoot();
        try self.validateBootEntries();

        var lba: u32 = system_area_sectors;
        self.pvd_lba = lba;
        lba += 1;
        if (has_boot) {
            self.boot_record_lba = lba;
            lba += 1;
        }
        self.terminator_lba = lba;
        lba += 1;

        self.path_table_size = self.computePathTableSize();
        const path_table_sectors = sectorsFor(self.path_table_size);
        self.path_table_l_lba = lba;
        lba += path_table_sectors;
        self.path_table_m_lba = lba;
        lba += path_table_sectors;

        for (self.dir_order) |dir_index| {
            self.nodes[dir_index].extent_lba = lba;
            lba += sectorsFor(self.nodes[dir_index].data_len);
        }

        if (self.continuation.items.len > 0) {
            self.continuation_lba = lba;
            lba += sectorsFor(@intCast(self.continuation.items.len));
        }

        if (has_boot) {
            self.boot_catalog_lba = lba;
            lba += 1;
        }

        // File data extents (symlinks carry their target in Rock Ridge and use
        // no data extent). Deterministic path order = build order.
        for (self.nodes) |*node| {
            if (node.kind != .file) continue;
            node.extent_lba = lba;
            lba += sectorsFor64(node.file_size);
        }

        // ISO9660 addresses sectors with a 32-bit count; `lba` is already u32,
        // so accumulation past that range would have trapped earlier.
        self.total_sectors = lba;
    }

    fn hasBoot(self: *const IsoWriter) bool {
        return self.options.boot_catalog != null or self.options.boot_entries.len > 0;
    }

    fn validateBootEntries(self: *IsoWriter) anyerror!void {
        if (self.options.boot_catalog) |layout| {
            try self.validateBootCatalogLayout(layout);
            return;
        }
        if (self.options.boot_entries.len == 0) return;
        if (self.options.boot_entries.len > 2) return error.TooManyBootEntries;
        var seen_bios = false;
        var seen_uefi = false;
        for (self.options.boot_entries) |entry| {
            switch (entry.platform) {
                .bios => {
                    if (seen_bios) return error.DuplicateBootPlatform;
                    seen_bios = true;
                },
                .uefi => {
                    if (seen_uefi) return error.DuplicateBootPlatform;
                    seen_uefi = true;
                },
            }
            _ = self.findFileNode(entry.image_path) orelse return error.BootImageNotFound;
        }
    }

    /// Validates an exact `BootCatalogLayout`: every referenced boot image must
    /// resolve to a modeled file, and the whole catalog (validation entry,
    /// default entry, and each section header plus its entries) must fit in a
    /// single 2048-byte logical sector, which is all El Torito lays out and all
    /// the reader models.
    fn validateBootCatalogLayout(self: *IsoWriter, layout: BootCatalogLayout) anyerror!void {
        _ = self.findFileNode(layout.default_entry.image_path) orelse return error.BootImageNotFound;
        var bytes: usize = 64; // validation entry (32) + default entry (32)
        for (layout.sections) |section| {
            bytes += 32; // section header
            for (section.entries) |entry| {
                _ = self.findFileNode(entry.image_path) orelse return error.BootImageNotFound;
                bytes += 32;
            }
        }
        if (bytes > sector_size) return error.BootCatalogTooLarge;
    }

    fn findFileNode(self: *IsoWriter, path: []const u8) ?usize {
        var p = path;
        while (p.len > 0 and p[0] == '/') p = p[1..];
        for (self.nodes, 0..) |node, idx| {
            if (node.kind != .file) continue;
            if (std.mem.eql(u8, self.nodePath(idx), p)) return idx;
        }
        return null;
    }

    fn nodePath(self: *IsoWriter, index: usize) []const u8 {
        // Reconstruct the root-relative path by walking parents. Bounded by
        // tree depth; used only for boot-image resolution.
        var parts = std.array_list.Managed([]const u8).init(self.arena);
        var cur = index;
        while (cur != 0) {
            parts.append(self.nodes[cur].name) catch return "";
            cur = self.nodes[cur].parent_index;
        }
        var out = std.array_list.Managed(u8).init(self.arena);
        var i: usize = parts.items.len;
        while (i > 0) {
            i -= 1;
            if (out.items.len > 0) out.append('/') catch return "";
            out.appendSlice(parts.items[i]) catch return "";
        }
        return out.items;
    }

    fn computePathTableSize(self: *IsoWriter) u32 {
        var size: u32 = 0;
        for (self.dir_order) |dir_index| {
            const id_len: usize = if (dir_index == 0) 1 else self.nodes[dir_index].iso_id.len;
            size += @intCast(8 + id_len + (id_len & 1));
        }
        return size;
    }

    fn emit(self: *IsoWriter, source: TreeSource) anyerror!void {
        try self.emitPrimaryVolumeDescriptor();
        if (self.hasBoot()) try self.emitBootRecord();
        try self.emitTerminator();
        try self.emitPathTable(true);
        try self.emitPathTable(false);
        try self.emitDirectories();
        try self.emitContinuation();
        if (self.hasBoot()) try self.emitBootCatalog();
        try self.emitFiles(source);
        try self.padImage();
    }

    fn emitPrimaryVolumeDescriptor(self: *IsoWriter) anyerror!void {
        var pvd = [_]u8{0} ** sector_size;
        pvd[0] = 1;
        pvd[1..6].* = standard_id;
        pvd[6] = 1;
        setAField(pvd[8..40], self.options.system_id);
        setDField(pvd[40..72], self.options.volume_id);
        write733(pvd[80..88], self.total_sectors);
        write723(pvd[120..124], 1); // volume set size
        write723(pvd[124..128], 1); // volume sequence number
        write723(pvd[128..132], sector_size);
        write733(pvd[132..140], self.path_table_size);
        write731(pvd[140..144], self.path_table_l_lba);
        write731(pvd[144..148], 0);
        write732(pvd[148..152], self.path_table_m_lba);
        write732(pvd[152..156], 0);
        const root_record = self.makeRootRecord();
        @memcpy(pvd[156 .. 156 + root_record.len], &root_record);
        setDField(pvd[190..318], self.options.volume_set_id);
        setAField(pvd[318..446], self.options.publisher_id);
        setAField(pvd[446..574], self.options.preparer_id);
        setAField(pvd[574..702], self.options.application_id);
        // Volume descriptor date/time fields left as zeros for determinism.
        pvd[881] = 1; // file structure version
        try self.writeSector(self.pvd_lba, &pvd);
    }

    fn makeRootRecord(self: *IsoWriter) [34]u8 {
        var out = [_]u8{0} ** 34;
        const root = &self.nodes[0];
        out[0] = 34;
        write733(out[2..10], root.extent_lba);
        write733(out[10..18], root.data_len);
        writeRecordDate(out[18..25], root.mtime);
        out[25] = 0x02;
        write723(out[28..32], 1);
        out[32] = 1;
        out[33] = 0;
        return out;
    }

    fn emitBootRecord(self: *IsoWriter) anyerror!void {
        var br = [_]u8{0} ** sector_size;
        br[0] = 0;
        br[1..6].* = standard_id;
        br[6] = 1;
        const boot_sys_id = "EL TORITO SPECIFICATION";
        @memcpy(br[7 .. 7 + boot_sys_id.len], boot_sys_id);
        write731(br[71..75], self.boot_catalog_lba);
        try self.writeSector(self.boot_record_lba, &br);
    }

    fn emitTerminator(self: *IsoWriter) anyerror!void {
        var term = [_]u8{0} ** sector_size;
        term[0] = 255;
        term[1..6].* = standard_id;
        term[6] = 1;
        try self.writeSector(self.terminator_lba, &term);
    }

    fn emitPathTable(self: *IsoWriter, little_endian: bool) anyerror!void {
        const bytes = try self.arena.alloc(u8, roundUpSector(self.path_table_size));
        @memset(bytes, 0);
        var pos: usize = 0;
        for (self.dir_order) |dir_index| {
            const dir = &self.nodes[dir_index];
            const is_root = dir_index == 0;
            const id: []const u8 = if (is_root) &[_]u8{0} else dir.iso_id;
            const parent_number: u16 = if (is_root) 1 else self.nodes[dir.parent_index].dir_number;
            bytes[pos] = @intCast(id.len);
            bytes[pos + 1] = 0;
            if (little_endian) {
                write731(bytes[pos + 2 .. pos + 6], dir.extent_lba);
                write721(bytes[pos + 6 .. pos + 8], parent_number);
            } else {
                write732(bytes[pos + 2 .. pos + 6], dir.extent_lba);
                write722(bytes[pos + 6 .. pos + 8], parent_number);
            }
            @memcpy(bytes[pos + 8 ..][0..id.len], id);
            pos += 8 + id.len;
            if (id.len & 1 == 1) {
                bytes[pos] = 0;
                pos += 1;
            }
        }
        const lba = if (little_endian) self.path_table_l_lba else self.path_table_m_lba;
        try self.writeSector(lba, bytes);
    }

    fn emitDirectories(self: *IsoWriter) anyerror!void {
        for (self.dir_order) |dir_index| {
            const dir = &self.nodes[dir_index];
            const bytes = try self.arena.alloc(u8, dir.data_len);
            @memset(bytes, 0);
            var pos: u32 = 0;
            pos = try self.writeDirRecord(bytes, pos, dir_index, .dot);
            pos = try self.writeDirRecord(bytes, pos, dir_index, .dotdot);
            for (dir.children.items) |child_index| {
                pos = try self.writeDirRecord(bytes, pos, child_index, .child);
            }
            try self.writeSector(dir.extent_lba, bytes);
        }
    }

    const RecordRole = enum { dot, dotdot, child };

    fn writeDirRecord(self: *IsoWriter, buf: []u8, pos_in: u32, node_index: usize, role: RecordRole) anyerror!u32 {
        var pos = pos_in;
        const rec_len = switch (role) {
            .dot => dotRecordLen(node_index == 0),
            .dotdot => dotdotRecordLen(),
            .child => self.nodes[node_index].child_record_len,
        };
        // Records may not span a 2048-byte logical sector boundary.
        const sector_off = pos % sector_size;
        if (sector_off + rec_len > sector_size) {
            pos += sector_size - sector_off;
        }

        var identifier: []const u8 = undefined;
        var extent_lba: u32 = 0;
        var data_len: u32 = 0;
        var flags: u8 = 0;
        var mtime: i64 = 0;
        var susp: []const u8 = &.{};
        var ce: ?CeRef = null;

        switch (role) {
            .dot => {
                identifier = &[_]u8{0};
                const dir = &self.nodes[node_index];
                extent_lba = dir.extent_lba;
                data_len = dir.data_len;
                flags = 0x02;
                mtime = dir.mtime;
                susp = self.dotSusp(node_index);
            },
            .dotdot => {
                identifier = &[_]u8{1};
                const parent = &self.nodes[self.nodes[node_index].parent_index];
                extent_lba = parent.extent_lba;
                data_len = parent.data_len;
                flags = 0x02;
                mtime = parent.mtime;
            },
            .child => {
                const child = &self.nodes[node_index];
                identifier = child.iso_id;
                flags = if (child.kind == .directory) 0x02 else 0x00;
                mtime = child.mtime;
                switch (child.kind) {
                    .directory => {
                        extent_lba = child.extent_lba;
                        data_len = child.data_len;
                    },
                    .file => {
                        extent_lba = child.extent_lba;
                        data_len = @intCast(child.file_size);
                    },
                    .symlink => {
                        extent_lba = 0;
                        data_len = 0;
                    },
                }
                if (child.child_uses_ce) {
                    ce = .{
                        .lba = self.continuation_lba + child.ce_offset / sector_size,
                        .offset = child.ce_offset % sector_size,
                        .len = @intCast(child.child_susp.len),
                    };
                } else {
                    susp = child.child_susp;
                }
            },
        }

        writeDirectoryRecordInto(buf[pos..], identifier, extent_lba, data_len, flags, mtime, susp, ce);
        return pos + rec_len;
    }

    fn dotSusp(self: *IsoWriter, dir_index: usize) []u8 {
        // Recomputed lazily so the byte layout matches dotRecordLen exactly.
        var susp = std.array_list.Managed(u8).init(self.arena);
        if (dir_index == 0) {
            susp.appendSlice(&buildSpSkip0()) catch return &.{};
            susp.appendSlice(&buildErSystemUse()) catch return &.{};
        }
        const dir = &self.nodes[dir_index];
        susp.appendSlice(&buildPxSystemUse(fullMode(.directory, dir.mode), dir.uid, dir.gid)) catch return &.{};
        return susp.items;
    }

    fn emitContinuation(self: *IsoWriter) anyerror!void {
        if (self.continuation.items.len == 0) return;
        const bytes = try self.arena.alloc(u8, roundUpSector(@intCast(self.continuation.items.len)));
        @memset(bytes, 0);
        @memcpy(bytes[0..self.continuation.items.len], self.continuation.items);
        try self.writeSector(self.continuation_lba, bytes);
    }

    fn emitBootCatalog(self: *IsoWriter) anyerror!void {
        var cat = [_]u8{0} ** sector_size;
        if (self.options.boot_catalog) |layout| {
            self.emitBootCatalogLayout(&cat, layout);
        } else {
            self.emitBootCatalogFromEntries(&cat);
        }
        try self.writeSector(self.boot_catalog_lba, &cat);
    }

    /// Emits a boot catalog from `boot_entries` using the default authoring
    /// convention: BIOS (if present) becomes the validation platform and default
    /// entry; the remaining platform is emitted as a final section. Id strings
    /// are left empty. This preserves `build-iso`'s historical output byte for
    /// byte.
    fn emitBootCatalogFromEntries(self: *IsoWriter, cat: []u8) void {
        var default_entry: ?BootEntry = null;
        var section_entry: ?BootEntry = null;
        for (self.options.boot_entries) |entry| {
            if (entry.platform == .bios) default_entry = entry else section_entry = entry;
        }
        if (default_entry == null) {
            // UEFI-only: the single entry is the default with a UEFI-platform
            // validation entry.
            default_entry = section_entry;
            section_entry = null;
        }
        const default = default_entry.?;

        writeValidationEntry(cat, @intFromEnum(default.platform), &.{});
        self.writeBootImageEntry(cat[32..64], toImageEntry(default));

        if (section_entry) |entry| {
            cat[64] = 0x91; // final section header
            cat[65] = @intFromEnum(entry.platform);
            std.mem.writeInt(u16, cat[66..68], 1, .little);
            self.writeBootImageEntry(cat[96..128], toImageEntry(entry));
        }
    }

    /// Emits a boot catalog that reproduces `layout` exactly: the validation
    /// entry's platform and 24-byte id string, the default entry, and each
    /// section header (platform, final-vs-more indicator, 28-byte id string)
    /// followed by its entries in order. `validateBootCatalogLayout` has already
    /// guaranteed every image resolves and the whole catalog fits one sector.
    fn emitBootCatalogLayout(self: *IsoWriter, cat: []u8, layout: BootCatalogLayout) void {
        writeValidationEntry(cat, layout.validation_platform, &layout.validation_id);
        self.writeBootImageEntry(cat[32..64], layout.default_entry);

        var offset: usize = 64;
        for (layout.sections) |section| {
            cat[offset] = if (section.final) 0x91 else 0x90;
            cat[offset + 1] = section.platform;
            std.mem.writeInt(u16, cat[offset + 2 ..][0..2], @intCast(section.entries.len), .little);
            @memcpy(cat[offset + 4 .. offset + 32], &section.id_string);
            offset += 32;
            for (section.entries) |entry| {
                self.writeBootImageEntry(cat[offset .. offset + 32], entry);
                offset += 32;
            }
        }
    }

    fn writeBootImageEntry(self: *IsoWriter, dst: []u8, entry: BootImageEntry) void {
        const node_index = self.findFileNode(entry.image_path).?;
        const image_lba = self.nodes[node_index].extent_lba;
        const image_size = self.nodes[node_index].file_size;
        const sectors: u16 = if (entry.load_sectors != 0)
            entry.load_sectors
        else
            @intCast(@min(@as(u64, std.math.maxInt(u16)), std.math.divCeil(u64, @max(image_size, 1), 512) catch 1));
        dst[0] = if (entry.bootable) 0x88 else 0x00;
        dst[1] = 0x00; // no emulation
        std.mem.writeInt(u16, dst[2..4], entry.load_segment, .little);
        dst[4] = entry.system_type;
        dst[5] = 0;
        std.mem.writeInt(u16, dst[6..8], sectors, .little);
        std.mem.writeInt(u32, dst[8..12], image_lba, .little);
    }

    fn emitFiles(self: *IsoWriter, source: TreeSource) anyerror!void {
        var chunk = try self.allocator.alloc(u8, sector_size * 8);
        defer self.allocator.free(chunk);
        for (self.nodes) |*node| {
            if (node.kind != .file or node.file_size == 0) continue;
            const source_index = node.source_index.?;
            var offset: u64 = 0;
            var sector = node.extent_lba;
            while (offset < node.file_size) {
                const want: usize = @intCast(@min(@as(u64, chunk.len), node.file_size - offset));
                try self.readExact(source, source_index, chunk[0..want], offset);
                // Pad the final partial sector with zeros so extents stay
                // sector-aligned on disk.
                const padded = roundUpSector(@intCast(want));
                if (padded != want) @memset(chunk[want..padded], 0);
                try self.file.writePositionalAll(self.io, chunk[0..padded], @as(u64, sector) * sector_size);
                offset += want;
                sector += @intCast(padded / sector_size);
            }
        }
    }

    fn padImage(self: *IsoWriter) anyerror!void {
        // Guarantee the backing file spans the full image even when it ends on
        // a hole (e.g. trailing zero-length files) by writing the final sector.
        const last = self.total_sectors - 1;
        var probe: [1]u8 = undefined;
        const end = @as(u64, self.total_sectors) * sector_size;
        const got = try self.file.readPositionalAll(self.io, probe[0..], end - 1);
        if (got == 0) {
            var zero = [_]u8{0} ** sector_size;
            try self.writeSector(last, &zero);
        }
    }

    fn writeSector(self: *IsoWriter, lba: u32, bytes: []const u8) anyerror!void {
        try self.file.writePositionalAll(self.io, bytes, @as(u64, lba) * sector_size);
    }

    fn readExact(self: *IsoWriter, source: TreeSource, index: usize, buffer: []u8, offset: u64) anyerror!void {
        _ = self;
        var done: usize = 0;
        while (done < buffer.len) {
            const got = try source.read(index, buffer[done..], offset + done);
            if (got == 0) return error.ContentReadShort;
            done += got;
        }
    }
};

const CeRef = struct { lba: u32, offset: u32, len: u32 };

const ce_record_len: usize = 28;

fn splitLast(path: []const u8) struct { []const u8, []const u8 } {
    const separator = std.mem.lastIndexOfScalar(u8, path, '/') orelse return .{ "", path };
    return .{ path[0..separator], path[separator + 1 ..] };
}

fn childNameLess(nodes: []IsoBuildNode, a: usize, b: usize) bool {
    return std.mem.lessThan(u8, nodes[a].name, nodes[b].name);
}

fn clamp(value: i64) i64 {
    return if (value < 0) 0 else value;
}

fn fullMode(kind: SourceKind, mode: u16) u32 {
    const type_bits: u32 = switch (kind) {
        .directory => 0o040000,
        .file => 0o100000,
        .symlink => 0o120000,
    };
    return type_bits | (@as(u32, mode) & 0o7777);
}

fn dotRecordLen(is_root: bool) u8 {
    // '.' identifier is one byte (0x00): 33 + 1 + pad(0) + susp.
    var susp: usize = px_len;
    if (is_root) susp += sp_len + er_len;
    return @intCast(recordLength(1, susp));
}

fn dotdotRecordLen() u8 {
    return @intCast(recordLength(1, 0));
}

fn placeRecord(pos: u32, rec_len: u8) u32 {
    var p = pos;
    const sector_off = p % sector_size;
    if (sector_off + rec_len > sector_size) {
        p += sector_size - sector_off;
    }
    return p + rec_len;
}

fn roundUpSector(len: u32) u32 {
    return (len + sector_size - 1) / sector_size * sector_size;
}

fn sectorsFor(len: u32) u32 {
    return (len + sector_size - 1) / sector_size;
}

fn sectorsFor64(len: u64) u32 {
    return @intCast((len + sector_size - 1) / sector_size);
}

const px_len: usize = 36;
const sp_len: usize = 7;
const er_len: usize = 20;

fn buildSpSkip0() [7]u8 {
    return .{ 'S', 'P', 7, 1, 0xBE, 0xEF, 0 };
}

fn symlinkComponentsLen(target: []const u8) usize {
    var len: usize = 5;
    if (std.mem.startsWith(u8, target, "/")) len += 2;
    var it = std.mem.tokenizeScalar(u8, target, '/');
    while (it.next()) |component| {
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            len += 2;
        } else {
            len += 2 + component.len;
        }
    }
    return len;
}

fn writeDirectoryRecordInto(
    dst: []u8,
    identifier: []const u8,
    extent_lba: u32,
    data_len: u32,
    flags: u8,
    mtime: i64,
    susp: []const u8,
    ce: ?CeRef,
) void {
    const ce_len: usize = if (ce != null) ce_record_len else 0;
    const rec_len = recordLength(identifier.len, susp.len + ce_len);
    @memset(dst[0..rec_len], 0);
    dst[0] = @intCast(rec_len);
    dst[1] = 0;
    write733(dst[2..10], extent_lba);
    write733(dst[10..18], data_len);
    writeRecordDate(dst[18..25], mtime);
    dst[25] = flags;
    dst[26] = 0;
    dst[27] = 0;
    write723(dst[28..32], 1);
    dst[32] = @intCast(identifier.len);
    @memcpy(dst[33 .. 33 + identifier.len], identifier);
    const pad: usize = if (identifier.len % 2 == 0) 1 else 0;
    if (pad == 1) dst[33 + identifier.len] = 0;
    var su = 33 + identifier.len + pad;
    if (ce) |c| {
        writeCe(dst[su .. su + ce_record_len], c);
        su += ce_record_len;
    }
    @memcpy(dst[su .. su + susp.len], susp);
}

fn writeCe(dst: []u8, ce: CeRef) void {
    dst[0] = 'C';
    dst[1] = 'E';
    dst[2] = 28;
    dst[3] = 1;
    write733(dst[4..12], ce.lba);
    write733(dst[12..20], ce.offset);
    write733(dst[20..28], ce.len);
}

fn writeRecordDate(dst: []u8, epoch: i64) void {
    const dt = civilFromEpoch(epoch);
    dst[0] = @intCast(@as(i64, dt.year) - 1900);
    dst[1] = dt.month;
    dst[2] = dt.day;
    dst[3] = dt.hour;
    dst[4] = dt.minute;
    dst[5] = dt.second;
    dst[6] = 0; // GMT offset in 15-minute intervals
}

const CivilTime = struct { year: i64, month: u8, day: u8, hour: u8, minute: u8, second: u8 };

fn civilFromEpoch(epoch_in: i64) CivilTime {
    const epoch = if (epoch_in < 0) 0 else epoch_in;
    var days = @divFloor(epoch, 86400);
    const secs_of_day = epoch - days * 86400;
    const hour: u8 = @intCast(@divFloor(secs_of_day, 3600));
    const minute: u8 = @intCast(@divFloor(@mod(secs_of_day, 3600), 60));
    const second: u8 = @intCast(@mod(secs_of_day, 60));

    // Howard Hinnant's civil_from_days.
    days += 719468;
    const era = @divFloor(if (days >= 0) days else days - 146096, 146097);
    const doe = days - era * 146097;
    const yoe = @divFloor(doe - @divFloor(doe, 1460) + @divFloor(doe, 36524) - @divFloor(doe, 146096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const d = doy - @divFloor(153 * mp + 2, 5) + 1;
    const m = if (mp < 10) mp + 3 else mp - 9;
    const year = if (m <= 2) y + 1 else y;
    return .{
        .year = year,
        .month = @intCast(m),
        .day = @intCast(d),
        .hour = hour,
        .minute = minute,
        .second = second,
    };
}

fn setAField(dst: []u8, value: []const u8) void {
    @memset(dst, ' ');
    const n = @min(dst.len, value.len);
    for (value[0..n], 0..) |c, i| dst[i] = std.ascii.toUpper(c);
}

fn setDField(dst: []u8, value: []const u8) void {
    @memset(dst, ' ');
    const n = @min(dst.len, value.len);
    for (value[0..n], 0..) |c, i| {
        const up = std.ascii.toUpper(c);
        dst[i] = if ((up >= 'A' and up <= 'Z') or (up >= '0' and up <= '9') or up == '_') up else '_';
    }
}

fn write721(dst: []u8, value: u16) void {
    std.mem.writeInt(u16, dst[0..2], value, .little);
}

fn write722(dst: []u8, value: u16) void {
    std.mem.writeInt(u16, dst[0..2], value, .big);
}

fn write731(dst: []u8, value: u32) void {
    std.mem.writeInt(u32, dst[0..4], value, .little);
}

fn write732(dst: []u8, value: u32) void {
    std.mem.writeInt(u32, dst[0..4], value, .big);
}

// ===========================================================================
// Writer tests
// ===========================================================================

const TestNode = struct {
    path: []const u8,
    kind: SourceKind,
    mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: i64 = 0,
    bytes: []const u8 = &.{},
    target: []const u8 = &.{},
};

const TestSource = struct {
    root_meta: SourceRoot = .{},
    nodes: []const TestNode,

    fn source(self: *const TestSource) TreeSource {
        return .{ .context = self, .vtable = &vtable };
    }

    const vtable = TreeSource.VTable{
        .root = rootFn,
        .count = countFn,
        .node = nodeFn,
        .read = readFn,
    };

    fn ctx(context: *const anyopaque) *const TestSource {
        return @ptrCast(@alignCast(context));
    }
    fn rootFn(context: *const anyopaque) SourceRoot {
        return ctx(context).root_meta;
    }
    fn countFn(context: *const anyopaque) usize {
        return ctx(context).nodes.len;
    }
    fn nodeFn(context: *const anyopaque, index: usize) anyerror!SourceNode {
        const n = ctx(context).nodes[index];
        return .{
            .path = n.path,
            .kind = n.kind,
            .mode = n.mode,
            .uid = n.uid,
            .gid = n.gid,
            .mtime = n.mtime,
            .size = if (n.kind == .file) n.bytes.len else n.target.len,
            .symlink_target = n.target,
        };
    }
    fn readFn(context: *const anyopaque, index: usize, buffer: []u8, offset: u64) anyerror!usize {
        const n = ctx(context).nodes[index];
        const data = if (n.kind == .symlink) n.target else n.bytes;
        if (offset >= data.len) return 0;
        const n_bytes = @min(buffer.len, data.len - @as(usize, @intCast(offset)));
        @memcpy(buffer[0..n_bytes], data[@intCast(offset)..][0..n_bytes]);
        return n_bytes;
    }
};

/// Walks every directory extent in `reader`, inspecting each directory record's
/// System Use area for `CE` continuation references. Asserts that every
/// referenced continuation range stays within a single logical block, appends
/// the Rock Ridge `NM` name decoded from each continuation to `names` (each
/// entry owned by the caller), and returns the number of `CE` records found.
fn collectContinuationRefs(
    allocator: std.mem.Allocator,
    io: Io,
    reader: *const Reader,
    names: *std.array_list.Managed([]u8),
) !usize {
    const bs: u64 = reader.logical_block_size;
    var ce_count: usize = 0;
    for (reader.entries) |entry| {
        if (entry.kind != .directory) continue;
        for (entry.extents) |ext| {
            const dir_buf = try allocator.alloc(u8, ext.size);
            defer allocator.free(dir_buf);
            _ = try reader.file.readPositionalAll(io, dir_buf, @as(u64, ext.lba) * bs);

            var off: usize = 0;
            while (off < dir_buf.len) {
                const len = dir_buf[off];
                if (len == 0) {
                    off += @intCast(bs - (off % bs));
                    continue;
                }
                const rec = dir_buf[off .. off + len];
                const name_len = rec[32];
                const pad: usize = if (name_len % 2 == 0) 1 else 0;
                const su = rec[33 + name_len + pad ..];

                var p: usize = 0;
                while (p + 4 <= su.len) {
                    const elen = su[p + 2];
                    if (elen < 4 or p + elen > su.len) break;
                    if (su[p] == 'C' and su[p + 1] == 'E' and elen >= 28) {
                        const ce_lba = read733(su[p + 4 .. p + 12]);
                        const ce_off = read733(su[p + 12 .. p + 20]);
                        const ce_size = read733(su[p + 20 .. p + 28]);
                        ce_count += 1;

                        // The continuation range referenced by CE must lie
                        // entirely within one logical block.
                        try std.testing.expect(ce_off < bs);
                        try std.testing.expect(@as(u64, ce_off) + ce_size <= bs);

                        const cont = try allocator.alloc(u8, ce_size);
                        defer allocator.free(cont);
                        _ = try reader.file.readPositionalAll(io, cont, @as(u64, ce_lba) * bs + ce_off);

                        var q: usize = 0;
                        while (q + 4 <= cont.len) {
                            const clen = cont[q + 2];
                            if (clen < 4 or q + clen > cont.len) break;
                            if (cont[q] == 'N' and cont[q + 1] == 'M' and clen >= 5) {
                                try names.append(try allocator.dupe(u8, cont[q + 5 .. q + clen]));
                            }
                            q += clen;
                        }
                    }
                    p += elen;
                }
                off += len;
            }
        }
    }
    return ce_count;
}

test "iso writer spills a ~200-character name into a CE continuation and round-trips" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-ce-longname.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // A regular filename long enough that PX + NM overflow a 255-byte directory
    // record and must spill into a CE continuation. Before the fix, computing
    // the record length in a u8 panicked here.
    var name_buf: [200]u8 = undefined;
    for (&name_buf, 0..) |*c, i| c.* = 'a' + @as(u8, @intCast(i % 26));
    const long_name = &name_buf;

    const nodes = [_]TestNode{
        .{ .path = long_name, .kind = .file, .mode = 0o644, .uid = 7, .gid = 8, .bytes = "long name payload\n" },
    };
    const ts = TestSource{ .nodes = &nodes };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    try std.testing.expect(reader.has_rock_ridge);

    // The name round-trips through the CE continuation.
    const lookup_path = try std.fmt.allocPrint(allocator, "/{s}", .{long_name});
    defer allocator.free(lookup_path);
    const idx = try reader.lookup(lookup_path);
    const entry = reader.getEntry(idx);
    try std.testing.expectEqual(@as(u32, 7), entry.uid);
    try std.testing.expectEqual(@as(u32, 8), entry.gid);
    const bytes = try reader.readFileAlloc(allocator, io, idx);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("long name payload\n", bytes);

    // The record actually exercised a CE continuation, and that continuation
    // stays within one logical block.
    var names = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit();
    }
    const ce_count = try collectContinuationRefs(allocator, io, &reader, &names);
    try std.testing.expect(ce_count >= 1);

    var found = false;
    for (names.items) |n| {
        if (std.mem.eql(u8, n, long_name)) found = true;
    }
    try std.testing.expect(found);
}

test "iso writer keeps many long-name CE continuations within one logical block" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-ce-manylong.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Enough long-named files that the accumulated continuation area spans
    // several logical blocks; without boundary padding, some CE payloads would
    // straddle a 2048-byte block.
    const count = 40;
    var name_bufs = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (name_bufs.items) |nb| allocator.free(nb);
        name_bufs.deinit();
    }
    var nodes = std.array_list.Managed(TestNode).init(allocator);
    defer nodes.deinit();

    var i: usize = 0;
    while (i < count) : (i += 1) {
        // ~200-character unique names (each forces a CE continuation).
        var nb = try allocator.alloc(u8, 200);
        for (nb, 0..) |*c, j| c.* = 'a' + @as(u8, @intCast((i + j) % 26));
        const tag = try std.fmt.allocPrint(allocator, "{d:0>3}", .{i});
        defer allocator.free(tag);
        @memcpy(nb[0..3], tag);
        try name_bufs.append(nb);
        try nodes.append(.{ .path = nb, .kind = .file, .mode = 0o644, .bytes = "x" });
    }
    const ts = TestSource{ .nodes = nodes.items };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    try std.testing.expect(reader.has_rock_ridge);

    // Every file round-trips by its full Rock Ridge name.
    for (name_bufs.items) |nb| {
        const p = try std.fmt.allocPrint(allocator, "/{s}", .{nb});
        defer allocator.free(p);
        const idx = try reader.lookup(p);
        const got = try reader.readFileAlloc(allocator, io, idx);
        defer allocator.free(got);
        try std.testing.expectEqualStrings("x", got);
    }

    // Parse the emitted CE references and prove each referenced continuation
    // range stays within one logical block; every long name is recovered from
    // its continuation.
    var names = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (names.items) |n| allocator.free(n);
        names.deinit();
    }
    const ce_count = try collectContinuationRefs(allocator, io, &reader, &names);
    try std.testing.expectEqual(@as(usize, count), ce_count);

    for (name_bufs.items) |nb| {
        var found = false;
        for (names.items) |n| {
            if (std.mem.eql(u8, n, nb)) found = true;
        }
        try std.testing.expect(found);
    }
}

test "iso writer round-trips nested rock ridge tree with metadata and symlinks" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-rr.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const long_name = "a-Very-Long-Mixed-Case-Directory-Name-For-Rock-Ridge-Round-Tripping";
    const nodes = [_]TestNode{
        .{ .path = "etc", .kind = .directory, .mode = 0o755, .uid = 0, .gid = 0 },
        .{ .path = "etc/os-release", .kind = .file, .mode = 0o644, .uid = 5, .gid = 6, .bytes = "NAME=zvmi\n" },
        .{ .path = "etc/alias", .kind = .symlink, .mode = 0o777, .target = "os-release" },
        .{ .path = long_name, .kind = .directory, .mode = 0o750, .uid = 1, .gid = 2 },
        .{ .path = long_name ++ "/Readme.TXT", .kind = .file, .mode = 0o600, .bytes = "mixed case file\n" },
    };
    const ts = TestSource{ .nodes = &nodes };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{ .volume_id = "ZVMI_TEST" });

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    try std.testing.expect(reader.has_rock_ridge);

    const file_index = try reader.lookup("/etc/os-release");
    const entry = reader.getEntry(file_index);
    try std.testing.expectEqual(@as(u32, 5), entry.uid);
    try std.testing.expectEqual(@as(u32, 6), entry.gid);
    try std.testing.expectEqual(@as(u32, 0o100644), entry.mode);
    const bytes = try reader.readFileAlloc(allocator, io, file_index);
    defer allocator.free(bytes);
    try std.testing.expectEqualStrings("NAME=zvmi\n", bytes);

    const link_index = try reader.lookup("/etc/alias");
    try std.testing.expectEqual(EntryKind.symlink, reader.getEntry(link_index).kind);
    try std.testing.expectEqualStrings("os-release", try reader.readLink(link_index));
    try std.testing.expectEqual(file_index, try reader.resolveSymlink(link_index));

    const long_dir_index = try reader.lookup("/" ++ long_name);
    try std.testing.expectEqual(EntryKind.directory, reader.getEntry(long_dir_index).kind);
    try std.testing.expectEqual(@as(u32, 1), reader.getEntry(long_dir_index).uid);
    const long_file_index = try reader.lookup("/" ++ long_name ++ "/Readme.TXT");
    const long_bytes = try reader.readFileAlloc(allocator, io, long_file_index);
    defer allocator.free(long_bytes);
    try std.testing.expectEqualStrings("mixed case file\n", long_bytes);
}

test "iso writer handles multi-sector files and directories crossing sector boundaries" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-multisector.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // A file spanning several logical sectors.
    const big = try allocator.alloc(u8, 5000);
    defer allocator.free(big);
    for (big, 0..) |*b, i| b.* = @intCast(i % 251);

    // Enough children that the root directory extent crosses a 2048-byte
    // boundary (each Rock Ridge record is ~90-120 bytes).
    var name_bufs = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (name_bufs.items) |nb| allocator.free(nb);
        name_bufs.deinit();
    }
    var nodes = std.array_list.Managed(TestNode).init(allocator);
    defer nodes.deinit();
    try nodes.append(.{ .path = "bigfile.bin", .kind = .file, .mode = 0o644, .bytes = big });
    var i: usize = 0;
    while (i < 60) : (i += 1) {
        const nb = try std.fmt.allocPrint(allocator, "file-entry-number-{d:0>3}.txt", .{i});
        try name_bufs.append(nb);
        try nodes.append(.{ .path = nb, .kind = .file, .mode = 0o644, .bytes = "x" });
    }
    const ts = TestSource{ .nodes = nodes.items };

    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const idx = try reader.lookup("/bigfile.bin");
    const got = try reader.readFileAlloc(allocator, io, idx);
    defer allocator.free(got);
    try std.testing.expectEqualSlices(u8, big, got);

    const listing = try reader.listDirAlloc(allocator, reader.root_index);
    defer allocator.free(listing);
    try std.testing.expectEqual(@as(usize, 61), listing.len);

    const last = try reader.lookup("/file-entry-number-059.txt");
    const last_bytes = try reader.readFileAlloc(allocator, io, last);
    defer allocator.free(last_bytes);
    try std.testing.expectEqualStrings("x", last_bytes);
}

test "iso writer output is deterministic" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path_a = "test-iso-writer-det-a.iso";
    const path_b = "test-iso-writer-det-b.iso";
    defer Io.Dir.cwd().deleteFile(io, path_a) catch {};
    defer Io.Dir.cwd().deleteFile(io, path_b) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/grub.cfg", .kind = .file, .mode = 0o644, .bytes = "set timeout=0\n" },
        .{ .path = "readme", .kind = .file, .mode = 0o644, .bytes = "hello\n" },
    };
    const ts = TestSource{ .nodes = &nodes };

    _ = try writeImagePath(allocator, io, path_a, ts.source(), .{ .volume_id = "DET" });
    _ = try writeImagePath(allocator, io, path_b, ts.source(), .{ .volume_id = "DET" });

    const a = try Io.Dir.cwd().readFileAlloc(io, path_a, allocator, .unlimited);
    defer allocator.free(a);
    const b = try Io.Dir.cwd().readFileAlloc(io, path_b, allocator, .unlimited);
    defer allocator.free(b);
    try std.testing.expectEqualSlices(u8, a, b);
}

test "iso writer sets configurable volume identifier" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-volid.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{ .volume_id = "MYVOL123" });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var pvd: [descriptor_size]u8 = undefined;
    _ = try file.readPositionalAll(io, &pvd, volume_descriptor_lba * descriptor_size);
    try std.testing.expectEqualStrings("MYVOL123", pvd[40..48]);
    try std.testing.expectEqual(@as(u8, ' '), pvd[48]);
}

fn expectBootEntry(entry: BootCatalogEntry, platform: u8, media: u8) !void {
    try std.testing.expectEqual(platform, entry.platform);
    try std.testing.expectEqual(media, entry.media_type);
    try std.testing.expect(entry.bootable);
    try std.testing.expect(entry.image_lba != 0);
}

test "iso writer emits BIOS-only el torito catalog" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-bios.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/isolinux.bin", .kind = .file, .mode = 0o644, .bytes = "BIOSBOOT" ** 100 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/isolinux.bin", .load_sectors = 4 },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_bios, catalog.validation_platform);
    try std.testing.expectEqual(@as(usize, 1), catalog.entries.len);
    try expectBootEntry(catalog.entries[0], boot_platform_bios, 0);
    try std.testing.expectEqual(@as(u16, 4), catalog.entries[0].load_sectors);

    // The referenced boot image LBA must hold the boot image bytes.
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const idx = try reader.lookup("/boot/isolinux.bin");
    try std.testing.expectEqual(reader.getEntry(idx).extents[0].lba, catalog.entries[0].image_lba);
}

test "iso writer emits UEFI-only el torito catalog" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-uefi.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "EFI", .kind = .directory, .mode = 0o755 },
        .{ .path = "EFI/BOOT", .kind = .directory, .mode = 0o755 },
        .{ .path = "EFI/BOOT/bootx64.efi", .kind = .file, .mode = 0o644, .bytes = "EFIBOOT!" ** 300 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .uefi, .image_path = "EFI/BOOT/bootx64.efi" },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_uefi, catalog.validation_platform);
    try std.testing.expectEqual(@as(usize, 1), catalog.entries.len);
    try expectBootEntry(catalog.entries[0], boot_platform_uefi, 0);
}

test "iso writer emits dual BIOS and UEFI el torito catalog" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-dual.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/bios.img", .kind = .file, .mode = 0o644, .bytes = "BIOS" ** 200 },
        .{ .path = "EFI", .kind = .directory, .mode = 0o755 },
        .{ .path = "EFI/efiboot.img", .kind = .file, .mode = 0o644, .bytes = "UEFI" ** 200 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/bios.img" },
            .{ .platform = .uefi, .image_path = "EFI/efiboot.img" },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_bios, catalog.validation_platform);
    try std.testing.expectEqual(@as(usize, 2), catalog.entries.len);
    try expectBootEntry(catalog.entries[0], boot_platform_bios, 0);
    try expectBootEntry(catalog.entries[1], boot_platform_uefi, 0);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const bios_idx = try reader.lookup("/boot/bios.img");
    const uefi_idx = try reader.lookup("/EFI/efiboot.img");
    try std.testing.expectEqual(reader.getEntry(bios_idx).extents[0].lba, catalog.entries[0].image_lba);
    try std.testing.expectEqual(reader.getEntry(uefi_idx).extents[0].lba, catalog.entries[1].image_lba);
}

test "iso writer reproduces an exact boot catalog layout: UEFI validation/default + BIOS section with id strings" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-exact-layout.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    var validation_id = [_]u8{0} ** 24;
    @memcpy(validation_id[0..11], "ZVMI-VALID.");
    var section_id = [_]u8{0} ** 28;
    @memcpy(section_id[0..13], "ZVMI-SECTION.");

    // Exact layout the default `boot_entries` convention could never emit: the
    // UEFI entry is the validation/default (not BIOS-first), and the BIOS entry
    // lives in a section carrying a non-empty id string.
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_catalog = .{
            .validation_platform = boot_platform_uefi,
            .validation_id = validation_id,
            .default_entry = .{ .image_path = "EFI/efiboot.img", .load_sectors = 4, .bootable = true },
            .sections = &.{
                .{
                    .platform = boot_platform_bios,
                    .final = true,
                    .id_string = section_id,
                    .entries = &.{
                        .{ .image_path = "boot/bios.img", .load_segment = 0x7C0, .system_type = 0x12, .load_sectors = 8 },
                    },
                },
            },
        },
    });

    // The parsed catalog keeps UEFI as the validation platform and preserves the
    // section header sequence and both entries' fields in order.
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(boot_platform_uefi, catalog.validation_platform);
    try std.testing.expectEqualSlices(u8, &validation_id, &catalog.validation.id_string);
    try std.testing.expectEqual(@as(usize, 1), catalog.headers.len);
    try std.testing.expectEqual(boot_platform_bios, catalog.headers[0].platform);
    try std.testing.expect(catalog.headers[0].final);
    try std.testing.expectEqualSlices(u8, &section_id, &catalog.headers[0].id_string);

    try std.testing.expectEqual(@as(usize, 2), catalog.entries.len);
    try std.testing.expectEqual(BootEntryKind.default, catalog.entries[0].kind);
    try std.testing.expectEqual(boot_platform_uefi, catalog.entries[0].platform);
    try std.testing.expectEqual(@as(u16, 4), catalog.entries[0].load_sectors);
    try std.testing.expectEqual(BootEntryKind.section, catalog.entries[1].kind);
    try std.testing.expectEqual(boot_platform_bios, catalog.entries[1].platform);
    try std.testing.expectEqual(@as(u16, 0x7C0), catalog.entries[1].load_segment);
    try std.testing.expectEqual(@as(u8, 0x12), catalog.entries[1].system_type);
    try std.testing.expectEqual(@as(u16, 8), catalog.entries[1].load_sectors);

    // Both boot images still map to their real files and the image survives the
    // strict rewrite gate unchanged.
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const uefi_idx = try reader.lookup("/EFI/efiboot.img");
    const bios_idx = try reader.lookup("/boot/bios.img");
    try std.testing.expectEqual(reader.getEntry(uefi_idx).extents[0].lba, catalog.entries[0].image_lba);
    try std.testing.expectEqual(reader.getEntry(bios_idx).extents[0].lba, catalog.entries[1].image_lba);

    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspection.losslessWithinModel());
}

test "iso writer reports no boot record for a plain image" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-noboot.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{.{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" }};
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.NoBootRecord, readBootCatalog(allocator, io, file));
}

test "iso writer rejects a missing boot image" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso-writer-badboot.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{.{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" }};
    const ts = TestSource{ .nodes = &nodes };
    try std.testing.expectError(error.BootImageNotFound, writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "does/not/exist" }},
    }));
}

// ===========================================================================
// Reader model + rewrite-preflight tests
// ===========================================================================

const synth_root_lba: u32 = 20;
const synth_path_table_lba: u32 = 19;

const SynthOptions = struct {
    total_sectors: u32 = 48,
    volume_id: []const u8 = "SYNTH",
    rr_root: bool = false,
    /// When set, a valid El Torito boot record volume descriptor and boot
    /// catalog are emitted so a test can exercise boot-image mapping.
    boot: ?SynthBoot = null,
};

const SynthBoot = struct {
    catalog_lba: u32,
    image_lba: u32,
    load_sectors: u16 = 4,
};

// Writes a minimal, checksum-correct El Torito boot catalog (validation entry
// plus a single no-emulation default entry) whose default entry references
// `image_lba` for `load_sectors` sectors.
fn writeBootCatalog(sector: []u8, image_lba: u32, load_sectors: u16) void {
    @memset(sector[0..descriptor_size], 0);
    sector[0] = 0x01; // validation entry header id
    sector[1] = 0x00; // platform: x86
    sector[30] = 0x55;
    sector[31] = 0xAA;
    var sum: u16 = 0;
    var i: usize = 0;
    while (i < 32) : (i += 2) sum +%= std.mem.readInt(u16, sector[i..][0..2], .little);
    std.mem.writeInt(u16, sector[28..30], 0 -% sum, .little); // checksum word

    sector[32] = 0x88; // default entry: bootable
    sector[33] = 0x00; // no emulation
    std.mem.writeInt(u16, sector[38..40], load_sectors, .little);
    std.mem.writeInt(u32, sector[40..44], image_lba, .little);
}

// Assembles a minimal ISO9660 image (PVD, terminator, one-entry path table,
// root directory of `.`/`..` plus caller-supplied child record bytes) so a test
// can inject exactly the directory records it needs. The returned buffer is
// owned by the caller; file-data sectors can be filled before writing it out.
fn synthIsoAlloc(allocator: std.mem.Allocator, opts: SynthOptions, child_records: []const u8) ![]u8 {
    const image = try allocator.alloc(u8, opts.total_sectors * descriptor_size);
    errdefer allocator.free(image);
    @memset(image, 0);

    var pvd = [_]u8{0} ** descriptor_size;
    pvd[0] = 1;
    pvd[1..6].* = standard_id;
    pvd[6] = 1;
    setDField(pvd[40..72], opts.volume_id);
    write733(pvd[80..88], opts.total_sectors);
    write723(pvd[120..124], 1);
    write723(pvd[124..128], 1);
    write723(pvd[128..132], descriptor_size);
    write733(pvd[132..140], 8);
    std.mem.writeInt(u32, pvd[140..144], synth_path_table_lba, .little);
    const root_rec = makeDirectoryRecord(&.{0}, synth_root_lba, descriptor_size, 0x02, &.{});
    @memcpy(pvd[156 .. 156 + root_rec[0]], root_rec[0..root_rec[0]]);
    @memcpy(image[volume_descriptor_lba * descriptor_size ..][0..descriptor_size], &pvd);

    // Optionally emit an El Torito boot record VD, shifting the terminator down
    // one sector to keep the descriptor sequence contiguous.
    var terminator_lba = volume_descriptor_lba + 1;
    if (opts.boot) |boot| {
        var brvd = [_]u8{0} ** descriptor_size;
        brvd[0] = 0; // boot record volume descriptor
        brvd[1..6].* = standard_id;
        brvd[6] = 1;
        @memcpy(brvd[7..][0.."EL TORITO SPECIFICATION".len], "EL TORITO SPECIFICATION");
        std.mem.writeInt(u32, brvd[71..75], boot.catalog_lba, .little);
        @memcpy(image[terminator_lba * descriptor_size ..][0..descriptor_size], &brvd);
        terminator_lba += 1;

        var cat = [_]u8{0} ** descriptor_size;
        writeBootCatalog(&cat, boot.image_lba, boot.load_sectors);
        @memcpy(image[boot.catalog_lba * descriptor_size ..][0..descriptor_size], &cat);
    }

    var term = [_]u8{0} ** descriptor_size;
    term[0] = 255;
    term[1..6].* = standard_id;
    term[6] = 1;
    @memcpy(image[terminator_lba * descriptor_size ..][0..descriptor_size], &term);

    var pt = [_]u8{0} ** 8;
    pt[0] = 1;
    write731(pt[2..6], synth_root_lba);
    write721(pt[6..8], 1);
    @memcpy(image[synth_path_table_lba * descriptor_size ..][0..8], &pt);

    var dir = std.array_list.Managed(u8).init(allocator);
    defer dir.deinit();
    var dot_su = std.array_list.Managed(u8).init(allocator);
    defer dot_su.deinit();
    if (opts.rr_root) {
        try dot_su.appendSlice(&buildSpSystemUse());
        try dot_su.appendSlice(&buildErSystemUse());
    }
    const dot = makeDirectoryRecord(&.{0}, synth_root_lba, descriptor_size, 0x02, dot_su.items);
    try dir.appendSlice(dot[0..dot[0]]);
    const dotdot = makeDirectoryRecord(&.{1}, synth_root_lba, descriptor_size, 0x02, &.{});
    try dir.appendSlice(dotdot[0..dotdot[0]]);
    try dir.appendSlice(child_records);
    @memcpy(image[synth_root_lba * descriptor_size ..][0..dir.items.len], dir.items);

    return image;
}

fn buildClSystemUse(child_lba: u32) [12]u8 {
    var out: [12]u8 = [_]u8{0} ** 12;
    out[0] = 'C';
    out[1] = 'L';
    out[2] = 12;
    out[3] = 1;
    write733(out[4..12], child_lba);
    return out;
}

fn inspectionHasFeature(inspection: RewriteInspection, feature: UnsupportedFeature) bool {
    for (inspection.unsupported) |detail| {
        if (detail.feature == feature) return true;
    }
    return false;
}

test "iso9660 reader combines multi-extent file records and reads across them" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-multiextent.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const first_lba: u32 = 21;
    const second_lba: u32 = 22;
    const second_len: u32 = 100;

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    // First record carries the multi-extent flag (0x80); the second finalizes.
    var rec0 = makeDirectoryRecord("BIG.BIN;1", first_lba, descriptor_size, 0x80, &.{});
    try children.appendSlice(rec0[0..rec0[0]]);
    var rec1 = makeDirectoryRecord("BIG.BIN;1", second_lba, second_len, 0x00, &.{});
    try children.appendSlice(rec1[0..rec1[0]]);

    const image = try synthIsoAlloc(allocator, .{}, children.items);
    defer allocator.free(image);
    @memset(image[first_lba * descriptor_size ..][0..descriptor_size], 'A');
    @memset(image[second_lba * descriptor_size ..][0..second_len], 'B');
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    const idx = try reader.lookup("/BIG.BIN");
    const entry = reader.getEntry(idx);
    try std.testing.expectEqual(@as(usize, 2), entry.extents.len);
    try std.testing.expectEqual(@as(u64, descriptor_size + second_len), entry.size);
    try std.testing.expectEqual(first_lba, entry.extents[0].lba);
    try std.testing.expectEqual(second_lba, entry.extents[1].lba);

    const bytes = try reader.readFileAlloc(allocator, io, idx);
    defer allocator.free(bytes);
    try std.testing.expectEqual(@as(usize, descriptor_size + second_len), bytes.len);
    try std.testing.expect(std.mem.allEqual(u8, bytes[0..descriptor_size], 'A'));
    try std.testing.expect(std.mem.allEqual(u8, bytes[descriptor_size..], 'B'));

    // A well-formed multi-extent file is fully rewritable.
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspection.losslessWithinModel());
}

test "iso9660 reader keeps a boot image pointing mid-file unmapped" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-boot-mid-extent.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const first_lba: u32 = 21;
    const second_lba: u32 = 22;
    const second_len: u32 = 100;
    const catalog_lba: u32 = 23;

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    // A two-extent file: the leading record carries the multi-extent flag.
    var rec0 = makeDirectoryRecord("BIG.BIN;1", first_lba, descriptor_size, 0x80, &.{});
    try children.appendSlice(rec0[0..rec0[0]]);
    var rec1 = makeDirectoryRecord("BIG.BIN;1", second_lba, second_len, 0x00, &.{});
    try children.appendSlice(rec1[0..rec1[0]]);

    // The boot catalog references the file's SECOND extent, not its leading
    // one. That is a mid-file offset, so it must never be reported as a mapped
    // file (which would misrepresent the offset as the whole file).
    const image = try synthIsoAlloc(allocator, .{ .boot = .{
        .catalog_lba = catalog_lba,
        .image_lba = second_lba,
    } }, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    // The internal mapper must not resolve an interior extent to the file.
    try std.testing.expect(reader.findFileByExtentLba(second_lba) == null);
    // The leading extent still maps.
    try std.testing.expect(reader.findFileByExtentLba(first_lba) != null);

    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(!inspection.losslessWithinModel());
    try std.testing.expect(inspectionHasFeature(inspection, .boot_image_unmapped));
    try std.testing.expect(inspection.boot != null);
    switch (inspection.boot.?.entries[0].image) {
        .raw_extent => |raw| try std.testing.expectEqual(second_lba, raw.lba),
        .mapped => return error.TestUnexpectedResult,
    }

    // The strict gate must refuse this source rather than call it lossless.
    var detail: UnsupportedDetail = undefined;
    try std.testing.expectError(error.SourceNotRewritable, reader.requireRewriteSupported(allocator, io, &detail));
    freeUnsupportedDetail(allocator, detail);
}

test "iso9660 reader rejects a truncated multi-extent chain" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-badmultiextent.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    // A lone record with the multi-extent flag set but no continuation record.
    var rec0 = makeDirectoryRecord("BIG.BIN;1", 21, descriptor_size, 0x80, &.{});
    try children.appendSlice(rec0[0..rec0[0]]);

    const image = try synthIsoAlloc(allocator, .{}, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    try std.testing.expectError(error.InvalidMultiExtent, Reader.openPath(allocator, io, path));
}

test "iso9660 reader flags an interleaved file for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-interleaved.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    var rec = makeDirectoryRecord("INTER.BIN;1", 21, 512, 0x00, &.{});
    rec[26] = 1; // non-zero File Unit Size => interleaved
    try children.appendSlice(rec[0..rec[0]]);

    const image = try synthIsoAlloc(allocator, .{}, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(!inspection.losslessWithinModel());
    try std.testing.expect(inspectionHasFeature(inspection, .interleaved_file));
}

test "iso9660 reader flags an extended attribute record for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-ealen.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    var rec = makeDirectoryRecord("EA.BIN;1", 21, 512, 0x00, &.{});
    rec[1] = 1; // non-zero Extended Attribute Record Length
    try children.appendSlice(rec[0..rec[0]]);

    const image = try synthIsoAlloc(allocator, .{}, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .extended_attribute_record));
}

// Offset of the PVD root directory record within the synthesized image, and the
// byte offsets of the fields exercised by the root-record mutation tests.
const synth_root_record_off: usize = volume_descriptor_lba * descriptor_size + 156;

test "iso9660 reader flags a root record extended attribute for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-root-ealen.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const image = try synthIsoAlloc(allocator, .{}, &.{});
    defer allocator.free(image);
    image[synth_root_record_off + 1] = 1; // root record Extended Attribute Record Length
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .extended_attribute_record));

    var detail: UnsupportedDetail = undefined;
    try std.testing.expectError(error.SourceNotRewritable, reader.requireRewriteSupported(allocator, io, &detail));
    freeUnsupportedDetail(allocator, detail);
}

test "iso9660 reader flags a root record interleave for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-root-interleave.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const image = try synthIsoAlloc(allocator, .{}, &.{});
    defer allocator.free(image);
    image[synth_root_record_off + 26] = 1; // root record File Unit Size => interleaved
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .interleaved_file));

    var detail: UnsupportedDetail = undefined;
    try std.testing.expectError(error.SourceNotRewritable, reader.requireRewriteSupported(allocator, io, &detail));
    freeUnsupportedDetail(allocator, detail);
}

test "iso9660 reader flags a multi-extent root record for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-root-multiextent.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const image = try synthIsoAlloc(allocator, .{}, &.{});
    defer allocator.free(image);
    image[synth_root_record_off + 25] |= 0x80; // set the multi-extent flag on the root record
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .multi_extent_directory));

    var detail: UnsupportedDetail = undefined;
    try std.testing.expectError(error.SourceNotRewritable, reader.requireRewriteSupported(allocator, io, &detail));
    freeUnsupportedDetail(allocator, detail);
}

test "iso9660 reader flags ambiguous duplicate names for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-dupnames.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    var a = makeDirectoryRecord("DUP.TXT;1", 21, 16, 0x00, &.{});
    try children.appendSlice(a[0..a[0]]);
    var b = makeDirectoryRecord("DUP.TXT;1", 22, 16, 0x00, &.{});
    try children.appendSlice(b[0..b[0]]);

    const image = try synthIsoAlloc(allocator, .{}, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .duplicate_directory_entry));
}

test "iso9660 reader flags rock ridge relocation and requireRewriteSupported reports it" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-relocation.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var su = std.array_list.Managed(u8).init(allocator);
    defer su.deinit();
    // Non-dot records carry the 7-byte SUSP skip prefix declared by the root SP.
    try su.appendSlice(&[_]u8{0} ** 7);
    try su.appendSlice(&buildRrSystemUse(0x80)); // RR flags: CL present
    try su.appendSlice(&buildClSystemUse(23));

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    var rec = makeDirectoryRecord("GONE.;1", 21, 0, 0x00, su.items);
    try children.appendSlice(rec[0..rec[0]]);

    const image = try synthIsoAlloc(allocator, .{ .rr_root = true }, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);

    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .rock_ridge_relocation));

    var detail: UnsupportedDetail = undefined;
    try std.testing.expectError(error.SourceNotRewritable, reader.requireRewriteSupported(allocator, io, &detail));
    defer freeUnsupportedDetail(allocator, detail);
    try std.testing.expectEqual(UnsupportedFeature.rock_ridge_relocation, detail.feature);
}

test "iso9660 reader parses per-entry timestamps written by the native writer" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-timestamps.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const stamp: i64 = 1_700_000_000; // 2023-11-14T22:13:20Z
    const nodes = [_]TestNode{
        .{ .path = "stamped.txt", .kind = .file, .mode = 0o644, .mtime = stamp, .bytes = "hi\n" },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{});

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    const idx = try reader.lookup("/stamped.txt");
    try std.testing.expectEqual(stamp, reader.getEntry(idx).mtime);
}

test "iso9660 writer round-trips volume identifier metadata" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-volmeta.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{.{ .path = "f", .kind = .file, .mode = 0o644, .bytes = "x" }};
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .volume_id = "MYVOL",
        .system_id = "MYSYS",
        .volume_set_id = "MYSET",
        .publisher_id = "ACME PUBLISHER",
        .preparer_id = "ACME PREPARER",
        .application_id = "ZVMI ISO WRITER",
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var meta = try readVolumeMetadataAlloc(allocator, io, file);
    defer meta.deinit(allocator);
    try std.testing.expectEqualStrings("MYVOL", meta.volume_id);
    try std.testing.expectEqualStrings("MYSYS", meta.system_id);
    try std.testing.expectEqualStrings("MYSET", meta.volume_set_id);
    try std.testing.expectEqualStrings("ACME PUBLISHER", meta.publisher_id);
    try std.testing.expectEqualStrings("ACME PREPARER", meta.preparer_id);
    try std.testing.expectEqualStrings("ZVMI ISO WRITER", meta.application_id);
}

// ===========================================================================
// El Torito modeling + rewrite-preflight tests
// ===========================================================================

fn synthCatalogLba(io: Io, file: Io.File) !u32 {
    var sector: [descriptor_size]u8 = undefined;
    var lba: u32 = volume_descriptor_lba;
    while (true) : (lba += 1) {
        _ = try file.readPositionalAll(io, &sector, @as(u64, lba) * descriptor_size);
        if (sector[0] == 0 and std.mem.startsWith(u8, sector[7..], "EL TORITO SPECIFICATION"))
            return read731(sector[71..75]);
        if (sector[0] == 255) break;
    }
    return error.NoBootRecord;
}

fn readCatalogSector(io: Io, path: []const u8, out: *[descriptor_size]u8) !u32 {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    const cat_lba = try synthCatalogLba(io, file);
    _ = try file.readPositionalAll(io, out, @as(u64, cat_lba) * descriptor_size);
    return cat_lba;
}

fn writeCatalogSector(io: Io, path: []const u8, cat_lba: u32, bytes: *const [descriptor_size]u8) !void {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, @as(u64, cat_lba) * descriptor_size);
}

fn dualBootTestSource() TestSource {
    const nodes = struct {
        const list = [_]TestNode{
            .{ .path = "boot", .kind = .directory, .mode = 0o755 },
            .{ .path = "boot/bios.img", .kind = .file, .mode = 0o644, .bytes = "BIOS" ** 200 },
            .{ .path = "EFI", .kind = .directory, .mode = 0o755 },
            .{ .path = "EFI/efiboot.img", .kind = .file, .mode = 0o644, .bytes = "UEFI" ** 200 },
        };
    };
    return .{ .nodes = &nodes.list };
}

test "el torito reader preserves entry fields and maps boot images to paths" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-fields.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const nodes = [_]TestNode{
        .{ .path = "boot", .kind = .directory, .mode = 0o755 },
        .{ .path = "boot/isolinux.bin", .kind = .file, .mode = 0o644, .bytes = "BIOSBOOT" ** 100 },
    };
    const ts = TestSource{ .nodes = &nodes };
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/isolinux.bin", .load_segment = 0x7C0, .system_type = 0x12, .load_sectors = 4 },
        },
    });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 1), catalog.entries.len);
    const entry = catalog.entries[0];
    try std.testing.expectEqual(BootEntryKind.default, entry.kind);
    try std.testing.expectEqual(BootMediaType.no_emulation, entry.media);
    try std.testing.expect(entry.bootable);
    try std.testing.expectEqual(@as(u16, 0x7C0), entry.load_segment);
    try std.testing.expectEqual(@as(u8, 0x12), entry.system_type);
    try std.testing.expectEqual(@as(u16, 4), entry.load_sectors);
    try std.testing.expectEqual(@as(usize, 0), catalog.headers.len);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspection.losslessWithinModel());
    try std.testing.expect(inspection.boot != null);
    try std.testing.expectEqual(@as(usize, 1), inspection.boot.?.entries.len);
    switch (inspection.boot.?.entries[0].image) {
        .mapped => |m| try std.testing.expectEqualStrings("/boot/isolinux.bin", m.path),
        .raw_extent => return error.TestUnexpectedResult,
    }
}

test "el torito reader rejects a corrupted validation checksum" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-badsum.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    cat[4] +%= 1; // perturb the validation entry id => checksum no longer zero
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.BadBootCatalogChecksum, readBootCatalog(allocator, io, file));
}

test "el torito reader rejects a corrupted key signature" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-badsig.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    cat[30] = 0x00; // was 0x55
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.InvalidBootCatalog, readBootCatalog(allocator, io, file));
}

test "el torito reader rejects an out-of-bounds boot image extent" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-badbounds.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    std.mem.writeInt(u32, cat[40..44], 0x00FF_FFFF, .little); // default entry image LBA
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.InvalidBootCatalog, readBootCatalog(allocator, io, file));
}

test "el torito reader rejects an invalid media type" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-badmedia.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    cat[33] = 0x07; // default entry media byte low nibble 7 (reserved)
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.InvalidBootCatalog, readBootCatalog(allocator, io, file));
}

test "el torito inspection flags floppy/hard-disk emulation" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-emul.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    cat[33] = 0x04; // hard-disk emulation on the default entry
    try writeCatalogSector(io, path, cat_lba, &cat);

    // The catalog is still valid El Torito; only rewrite preservation fails.
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(BootMediaType.hard_disk, catalog.entries[0].media);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(!inspection.losslessWithinModel());
    try std.testing.expect(inspectionHasFeature(inspection, .boot_media_emulation));
}

test "el torito inspection flags an unmapped boot image as a raw extent" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-unmapped.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{.{ .platform = .bios, .image_path = "boot/bios.img" }},
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    // Point the default entry at the PVD sector: in-bounds, but no modeled file.
    std.mem.writeInt(u32, cat[40..44], volume_descriptor_lba, .little);
    try writeCatalogSector(io, path, cat_lba, &cat);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .boot_image_unmapped));
    try std.testing.expect(inspection.boot != null);
    switch (inspection.boot.?.entries[0].image) {
        .raw_extent => |raw| try std.testing.expectEqual(volume_descriptor_lba, raw.lba),
        .mapped => return error.TestUnexpectedResult,
    }
}

test "el torito reader models a multi-section catalog and its final indicator" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-multisection.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/bios.img" },
            .{ .platform = .uefi, .image_path = "EFI/efiboot.img" },
        },
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);

    const bios_lba = std.mem.readInt(u32, cat[40..44], .little);
    const uefi_sectors = std.mem.readInt(u16, cat[102..104], .little);

    // Rebuild the section region: header 0x90 (UEFI, more follow) + the existing
    // UEFI entry, then header 0x91 (BIOS, final) + a second BIOS entry.
    cat[64] = 0x90;
    cat[65] = boot_platform_uefi;
    std.mem.writeInt(u16, cat[66..68], 1, .little);
    // UEFI section entry already occupies cat[96..128].
    cat[128] = 0x91;
    cat[129] = boot_platform_bios;
    std.mem.writeInt(u16, cat[130..132], 1, .little);
    @memset(cat[160..192], 0);
    cat[160] = 0x88; // bootable
    cat[161] = 0x00; // no emulation
    std.mem.writeInt(u16, cat[166..168], uefi_sectors, .little);
    std.mem.writeInt(u32, cat[168..172], bios_lba, .little);
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expectEqual(@as(usize, 2), catalog.headers.len);
    try std.testing.expect(!catalog.headers[0].final);
    try std.testing.expect(catalog.headers[1].final);
    try std.testing.expectEqual(@as(usize, 3), catalog.entries.len); // default + 2 sections
    try std.testing.expectEqual(BootEntryKind.default, catalog.entries[0].kind);
    try std.testing.expectEqual(BootEntryKind.section, catalog.entries[1].kind);
    try std.testing.expectEqual(boot_platform_uefi, catalog.entries[1].platform);
    try std.testing.expectEqual(boot_platform_bios, catalog.entries[2].platform);

    // Both section images map back to real files, so the catalog is rewritable.
    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspection.losslessWithinModel());
}

test "el torito reader models a section extension record and inspection rejects it" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-extension.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/bios.img" },
            .{ .platform = .uefi, .image_path = "EFI/efiboot.img" },
        },
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    // Declare a selection-criteria extension on the UEFI section entry, and
    // supply the following 0x44 extension record.
    cat[97] |= 0x20;
    @memset(cat[128..160], 0);
    cat[128] = 0x44;
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var catalog = try readBootCatalog(allocator, io, file);
    defer catalog.deinit(allocator);
    try std.testing.expect(catalog.has_extension_records);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .boot_section_extension));
}

test "el torito reader rejects a declared extension with no following record" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-el-torito-badextension.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const ts = dualBootTestSource();
    _ = try writeImagePath(allocator, io, path, ts.source(), .{
        .boot_entries = &.{
            .{ .platform = .bios, .image_path = "boot/bios.img" },
            .{ .platform = .uefi, .image_path = "EFI/efiboot.img" },
        },
    });

    var cat: [descriptor_size]u8 = undefined;
    const cat_lba = try readCatalogSector(io, path, &cat);
    cat[97] |= 0x20; // extension declared, but cat[128..160] stays zero (no 0x44)
    try writeCatalogSector(io, path, cat_lba, &cat);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    try std.testing.expectError(error.InvalidBootCatalog, readBootCatalog(allocator, io, file));
}

test "iso9660 reader flags an unmodeled SUSP record for rewrite" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const path = "test-iso9660-unknownsusp.iso";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    var su = std.array_list.Managed(u8).init(allocator);
    defer su.deinit();
    try su.appendSlice(&[_]u8{0} ** 7); // SUSP skip prefix declared by the root SP
    try su.appendSlice(&[_]u8{ 'X', 'Z', 4, 1 }); // an unmodeled system-use record

    var children = std.array_list.Managed(u8).init(allocator);
    defer children.deinit();
    var rec = makeDirectoryRecord("FILE.;1", 21, 8, 0x00, su.items);
    try children.appendSlice(rec[0..rec[0]]);

    const image = try synthIsoAlloc(allocator, .{ .rr_root = true }, children.items);
    defer allocator.free(image);
    try writeIsoFile(path, image);

    var reader = try Reader.openPath(allocator, io, path);
    defer reader.close(io);
    var inspection = try reader.inspectForRewrite(allocator, io);
    defer inspection.deinit();
    try std.testing.expect(inspectionHasFeature(inspection, .unknown_susp_record));
}
