//! qcow2 (QEMU copy-on-write v2/v3) support for standalone images, including
//! backing-file chains, internal snapshot reads, deflate/zstd-compressed
//! clusters, extended L2 entries, and external data files.
//!
//! The on-disk header layout, feature bits, refcount structures, and two-level
//! L1/L2 guest-cluster mapping implemented here are transcribed from QEMU's
//! public qcow2 interoperability documentation and `block/qcow2.h`/
//! `block/qcow2.c`, the de-facto interoperability reference for this format.
//! All multi-byte fields are big-endian.
//!
//! Scope / limitations:
//!  - Backing-file chains are resolved for reads (via `openAtPath()` or
//!    `Image.openPath()` so relative paths can be resolved against the qcow2
//!    file's directory), and writes copy backing-visible cluster contents into
//!    newly allocated active clusters before applying guest changes.
//!  - Deflate- and zstd-compressed clusters (`compression_type` 0 and 1) are
//!    both supported for reads, and writes to existing compressed clusters
//!    transparently decompress them into standard data clusters. Emitting new
//!    compressed clusters of either kind is still deferred. Other
//!    `compression_type` values are rejected with
//!    `error.UnsupportedCompressionType`.
//!  - Internal snapshots can be enumerated with `listSnapshots()`, switched
//!    for reads with `openSnapshot()`, and created with `createSnapshot()`.
//!    Active-image writes/resizes honor snapshot refcounts with copy-on-write;
//!    `openSnapshot()` views remain read-only.
//!  - Encryption is detected and rejected (`error.EncryptionNotSupported`).
//!  - Extended L2 entries and external data files are supported for reads.
//!    Writes/resizes/snapshot creation still reject them until qcow2 write
//!    support grows the corresponding metadata handling.
//!  - qcow2 creation always writes a version 3 header with 64 KiB clusters,
//!    an empty L1 table, and fully provisioned refcount metadata for the
//!    current virtual size.

const std = @import("std");
const Io = std.Io;

pub const file_signature: [4]u8 = .{ 'Q', 'F', 'I', 0xFB };
pub const min_cluster_bits: u32 = 9;
pub const max_cluster_bits: u32 = 21;
pub const default_cluster_bits: u32 = 16;
pub const default_refcount_order: u32 = 4;
pub const l2_entry_size: u64 = 8;
pub const copied_mask: u64 = 1 << 63;
pub const compressed_mask: u64 = 1 << 62;
pub const zero_mask: u64 = 1 << 0;
pub const host_offset_mask: u64 = 0x00FF_FFFF_FFFF_FE00;

pub const incompatible_dirty: u64 = 1 << 0;
pub const incompatible_corrupt: u64 = 1 << 1;
pub const incompatible_data_file: u64 = 1 << 2;
pub const incompatible_compression: u64 = 1 << 3;
pub const incompatible_extl2: u64 = 1 << 4;
pub const incompatible_known_mask: u64 = incompatible_dirty |
    incompatible_corrupt |
    incompatible_data_file |
    incompatible_compression |
    incompatible_extl2;

const header_length_v3: u32 = 104;
const header_buffer_size: usize = 112;
const header_extension_end_magic: u32 = 0;
const header_extension_external_data_file_magic: u32 = 0x4441_5441;
const extl2_subcluster_count: u32 = 32;

pub const OpenError = error{
    BadFileSignature,
    UnsupportedVersion,
    UnsupportedClusterSize,
    HeaderTooShort,
    HeaderExceedsClusterSize,
    HeaderPastEndOfFile,
    EncryptionNotSupported,
    UnsupportedIncompatibleFeature,
    ExternalDataFileNotSupported,
    BackingFileNotSupported,
    UnsupportedCompressionType,
    ExtendedL2NotSupported,
    MissingExternalDataFileName,
    RelativeExternalDataFilePath,
    RelativeBackingFilePath,
    BackingChainTooDeep,
    BackingChainLoop,
    HeaderStringTooLong,
    InvalidHeaderStringRange,
    InvalidRefcountOrder,
    MissingRefcountTable,
    MisalignedRefcountTable,
    InvalidRefcountBlock,
    MisalignedL1Table,
    RefcountTablePastEndOfFile,
    L1TablePastEndOfFile,
    L1TableTooSmall,
} || std.mem.Allocator.Error || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.StatError;

pub const LookupError = error{
    L1TableTooSmall,
    InvalidL1Entry,
    InvalidL2Entry,
    CompressedClusterNotSupported,
} || Io.File.ReadPositionalError;

pub const PreadError = LookupError || std.mem.Allocator.Error || Io.File.OpenError || error{
    InvalidCompressedCluster,
    UnsupportedCompressionType,
};

pub const CheckError = LookupError || error{
    ImageMarkedDirty,
    ImageMarkedCorrupt,
    MissingRefcountBlock,
    ReferencedClusterHasZeroRefcount,
};

pub const CreateError = error{
    SizeNotSectorAligned,
    UnsupportedClusterSize,
    UnsupportedRefcountOrderForWrite,
    ImageTooLarge,
    MissingRefcountBlock,
} || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError;

pub const PwriteError = LookupError || error{
    ImageMarkedDirty,
    ImageMarkedCorrupt,
    SnapshotsNotSupported,
    SnapshotViewNotWritable,
    ExternalDataFileNotSupported,
    ExtendedL2NotSupported,
    SharedL2TableNotSupported,
    SharedClusterNotSupported,
    UnsupportedRefcountOrderForWrite,
    WritePastEndOfImage,
    MissingRefcountBlock,
    RefcountTableTooSmall,
    InvalidCompressedCluster,
    UnsupportedCompressionType,
} || std.mem.Allocator.Error || Io.File.OpenError || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError;

pub const ResizeError = error{
    ShrinkNotSupported,
    ImageMarkedDirty,
    ImageMarkedCorrupt,
    SnapshotsNotSupported,
    SnapshotViewNotWritable,
    ExternalDataFileNotSupported,
    ExtendedL2NotSupported,
    UnsupportedRefcountOrderForWrite,
    MissingRefcountBlock,
    RefcountTableTooSmall,
    ImageTooLarge,
} || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError;

pub const Extent = struct {
    offset: u64,
    length: u64,
    allocated: bool,
};

pub const MapError = LookupError || std.mem.Allocator.Error;

pub const Info = struct {
    virtual_size: u64,
    file_size: u64,
    version: u32,
    cluster_bits: u32,
    cluster_size: u64,
    l1_size: u32,
    l1_table_offset: u64,
    active_l1_table_offset: u64,
    l2_entries: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    /// Number of refcount-table slots reserved by the current contiguous
    /// refcount-table allocation, including zero (currently unused) entries.
    refcount_table_capacity_blocks: u64,
    /// Number of refcount blocks currently referenced by the active table.
    refcount_block_count: u32,
    refcount_order: u32,
    header_length: u32,
    incompatible_features: u64,
    crypt_method: u32,
    compression_type: u8,
    snapshot_count: u32,
    snapshots_offset: u64,
    source_path_len: u16 = 0,
    source_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
    data_file_len: u16 = 0,
    data_file_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
    data_file_size: u64 = 0,
    backing_file_len: u16 = 0,
    backing_file_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
    backing_depth: u8 = 0,
    backing_chain: [max_backing_chain_depth]BackingLayer = undefined,
};

pub const Snapshot = struct {
    l1_table_offset: u64,
    l1_size: u32,
    id: []const u8,
    name: []const u8,
    timestamp_seconds: u32,
    timestamp_nanoseconds: u32,
    vm_clock_nanoseconds: u64,
    vm_state_size: u64,
    virtual_size: ?u64,

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
        self.* = undefined;
    }
};

pub fn openSnapshot(info: Info, snapshot: Snapshot) Info {
    var snapshot_info = info;
    snapshot_info.l1_table_offset = snapshot.l1_table_offset;
    snapshot_info.l1_size = snapshot.l1_size;
    if (snapshot.virtual_size) |virtual_size| {
        snapshot_info.virtual_size = virtual_size;
    }
    return snapshot_info;
}

pub const ListSnapshotsError = std.mem.Allocator.Error || Io.File.ReadPositionalError || error{
    SnapshotTablePastEndOfFile,
    InvalidSnapshotEntry,
};

pub const SnapshotCreateOptions = struct {
    id: []const u8,
    name: []const u8,
    timestamp_seconds: u32 = 0,
    timestamp_nanoseconds: u32 = 0,
    vm_clock_nanoseconds: u64 = 0,
    vm_state_size: u64 = 0,
    icount: i64 = -1,
};

pub const CreateSnapshotError = LookupError || error{
    ImageMarkedDirty,
    ImageMarkedCorrupt,
    SnapshotsNotSupported,
    SnapshotViewNotWritable,
    ExternalDataFileNotSupported,
    ExtendedL2NotSupported,
    UnsupportedRefcountOrderForWrite,
    MissingRefcountBlock,
    RefcountTableTooSmall,
    SnapshotIdTooLong,
    SnapshotNameTooLong,
    SnapshotTablePastEndOfFile,
    InvalidSnapshotEntry,
} || std.mem.Allocator.Error || Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError;

const max_backing_chain_depth: u8 = 8;

const LayerInfo = struct {
    virtual_size: u64,
    file_size: u64,
    version: u32,
    cluster_bits: u32,
    cluster_size: u64,
    l1_size: u32,
    l1_table_offset: u64,
    l2_entries: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    refcount_table_capacity_blocks: u64,
    refcount_block_count: u32,
    refcount_order: u32,
    header_length: u32,
    incompatible_features: u64,
    crypt_method: u32,
    compression_type: u8,
    snapshot_count: u32,
    snapshots_offset: u64,
    data_file_len: u16 = 0,
    data_file_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
    data_file_size: u64 = 0,
};

const BackingLayer = struct {
    info: LayerInfo,
    path_len: u16 = 0,
    path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
};

const ParsedLayer = struct {
    info: LayerInfo,
    data_file_len: u16 = 0,
    data_file_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
    backing_file_len: u16 = 0,
    backing_file_path: [std.fs.max_path_bytes]u8 = [_]u8{0} ** std.fs.max_path_bytes,
};

const ClusterKind = enum {
    backing,
    zero,
    standard,
    compressed,
};

const ClusterMapping = struct {
    kind: ClusterKind,
    host_offset: ?u64,
    physically_allocated: bool,
    compressed_byte_len: u64 = 0,
};

const GuestRegionMapping = struct {
    mapping: ClusterMapping,
    length: u64,
};

const Layout = struct {
    cluster_size: u64,
    l2_entries: u64,
    guest_clusters: u64,
    l1_size: u32,
    l1_clusters: u32,
    refcount_block_entries: u64,
    refcount_block_count: u32,
    refcount_table_clusters: u32,
    max_host_clusters: u64,
};

pub fn open(io: Io, file: Io.File) OpenError!Info {
    return openInternal(io, file, null);
}

/// Parses a top-level qcow2 without opening any referenced host path.
/// Digest-pinned artifact pipelines use this to reject backing and external
/// data files before an untrusted image can cause dependency I/O.
pub fn openStandalone(io: Io, file: Io.File) OpenError!Info {
    const parsed = try parseLayer(file, io);
    if (parsed.backing_file_len != 0) return error.BackingFileNotSupported;
    if (parsed.data_file_len != 0) return error.ExternalDataFileNotSupported;
    return infoFromParsed(parsed);
}

pub fn openAtPath(io: Io, file: Io.File, path: []const u8) OpenError!Info {
    return openInternal(io, file, path);
}

fn openInternal(io: Io, file: Io.File, source_path: ?[]const u8) OpenError!Info {
    const parsed = try parseLayer(file, io);
    var info = infoFromParsed(parsed);
    if (source_path) |path| {
        const normalized = try std.fs.path.resolve(std.heap.page_allocator, &.{path});
        defer std.heap.page_allocator.free(normalized);
        try copyPathInto(&info.source_path, &info.source_path_len, normalized);
    }
    try resolveLayerDataFile(io, &info, if (info.source_path_len == 0) null else info.source_path[0..info.source_path_len]);
    try populateBackingChain(io, &info);
    return info;
}

fn parseLayer(file: Io.File, io: Io) OpenError!ParsedLayer {
    const file_size = (try file.stat(io)).size;

    var header: [header_buffer_size]u8 = undefined;
    const n = try file.readPositionalAll(io, &header, 0);
    if (n < 72) return error.HeaderTooShort;
    if (!std.mem.eql(u8, header[0..4], &file_signature)) return error.BadFileSignature;

    const version = std.mem.readInt(u32, header[4..8], .big);
    if (version < 2 or version > 3) return error.UnsupportedVersion;

    const backing_file_offset = std.mem.readInt(u64, header[8..16], .big);
    const backing_file_size = std.mem.readInt(u32, header[16..20], .big);
    const cluster_bits = std.mem.readInt(u32, header[20..24], .big);
    if (cluster_bits < min_cluster_bits or cluster_bits > max_cluster_bits) {
        return error.UnsupportedClusterSize;
    }
    const cluster_size = @as(u64, 1) << @intCast(cluster_bits);

    const virtual_size = std.mem.readInt(u64, header[24..32], .big);
    const crypt_method = std.mem.readInt(u32, header[32..36], .big);
    const l1_size = std.mem.readInt(u32, header[36..40], .big);
    const l1_table_offset = std.mem.readInt(u64, header[40..48], .big);
    const refcount_table_offset = std.mem.readInt(u64, header[48..56], .big);
    const refcount_table_clusters = std.mem.readInt(u32, header[56..60], .big);
    const snapshot_count = std.mem.readInt(u32, header[60..64], .big);
    const snapshots_offset = std.mem.readInt(u64, header[64..72], .big);

    var incompatible_features: u64 = 0;
    var refcount_order: u32 = default_refcount_order;
    var header_length: u32 = 72;
    var compression_type: u8 = 0;

    if (version == 3) {
        if (n < 104) return error.HeaderTooShort;
        incompatible_features = std.mem.readInt(u64, header[72..80], .big);
        refcount_order = std.mem.readInt(u32, header[96..100], .big);
        header_length = std.mem.readInt(u32, header[100..104], .big);
        if (header_length < header_length_v3) return error.HeaderTooShort;
        if (header_length > 104) {
            if (n < 105) return error.HeaderTooShort;
            compression_type = header[104];
        }
    }
    if (header_length > cluster_size) return error.HeaderExceedsClusterSize;
    if (file_size < header_length) return error.HeaderPastEndOfFile;

    if (crypt_method != 0) return error.EncryptionNotSupported;

    if (incompatible_features & ~incompatible_known_mask != 0) {
        return error.UnsupportedIncompatibleFeature;
    }
    if (compression_type > 1) {
        return error.UnsupportedCompressionType;
    }
    if (incompatible_features & incompatible_extl2 != 0 and cluster_bits < 14) {
        return error.UnsupportedClusterSize;
    }

    if (refcount_order > 6) return error.InvalidRefcountOrder;
    if (refcount_table_clusters == 0) return error.MissingRefcountTable;

    const refcount_table_bytes = std.math.mul(u64, @as(u64, refcount_table_clusters), cluster_size) catch return error.RefcountTablePastEndOfFile;
    if (!tableFits(file_size, refcount_table_offset, refcount_table_bytes, cluster_size, cluster_size)) {
        if (!isAligned(refcount_table_offset, cluster_size) or refcount_table_offset < cluster_size) {
            return error.MisalignedRefcountTable;
        }
        return error.RefcountTablePastEndOfFile;
    }

    const l1_table_bytes = std.math.mul(u64, @as(u64, l1_size), l2_entry_size) catch return error.L1TablePastEndOfFile;
    if (!tableFits(file_size, l1_table_offset, l1_table_bytes, cluster_size, cluster_size)) {
        if (!isAligned(l1_table_offset, cluster_size) or l1_table_offset < cluster_size) {
            return error.MisalignedL1Table;
        }
        return error.L1TablePastEndOfFile;
    }

    const l2_entries = cluster_size / l2EntrySizeBytes(incompatible_features);
    const guest_clusters = divCeil(virtual_size, cluster_size);
    const required_l1_entries = divCeil(guest_clusters, l2_entries);
    if (l1_size < required_l1_entries) return error.L1TableTooSmall;

    const refcount_table_capacity_blocks = @as(u64, refcount_table_clusters) * cluster_size / 8;
    const refcount_block_count = try scanRefcountBlockCount(file, io, refcount_table_offset, refcount_table_clusters, cluster_size, file_size);

    var parsed = ParsedLayer{
        .info = .{
            .virtual_size = virtual_size,
            .file_size = file_size,
            .version = version,
            .cluster_bits = cluster_bits,
            .cluster_size = cluster_size,
            .l1_size = l1_size,
            .l1_table_offset = l1_table_offset,
            .l2_entries = l2_entries,
            .refcount_table_offset = refcount_table_offset,
            .refcount_table_clusters = refcount_table_clusters,
            .refcount_table_capacity_blocks = refcount_table_capacity_blocks,
            .refcount_block_count = refcount_block_count,
            .refcount_order = refcount_order,
            .header_length = header_length,
            .incompatible_features = incompatible_features,
            .crypt_method = crypt_method,
            .compression_type = compression_type,
            .snapshot_count = snapshot_count,
            .snapshots_offset = snapshots_offset,
        },
    };
    if (backing_file_size != 0) {
        try readHeaderString(file, io, backing_file_offset, backing_file_size, file_size, &parsed.backing_file_path, &parsed.backing_file_len);
    } else if (backing_file_offset != 0) {
        return error.InvalidHeaderStringRange;
    }
    if (version >= 3) {
        const extensions_end = if (backing_file_offset != 0) backing_file_offset else cluster_size;
        try readHeaderExtensions(file, io, header_length, extensions_end, file_size, &parsed);
    }
    if (incompatible_features & incompatible_data_file != 0 and parsed.data_file_len == 0) {
        return error.MissingExternalDataFileName;
    }
    return parsed;
}

/// Creates a new qcow2 image with a version 3 header, 64 KiB clusters, an
/// empty L1 table, and preallocated refcount metadata sized for `size`.
pub fn validateCreateSize(size: u64) CreateError!void {
    if (size % 512 != 0) return error.SizeNotSectorAligned;
    _ = try layoutForSize(size, default_cluster_bits, default_refcount_order);
}

pub fn create(io: Io, file: Io.File, size: u64) CreateError!Info {
    try validateCreateSize(size);
    const layout = try layoutForSize(size, default_cluster_bits, default_refcount_order);

    const refcount_table_offset = layout.cluster_size;
    const refcount_blocks_offset = refcount_table_offset + @as(u64, layout.refcount_table_clusters) * layout.cluster_size;
    const l1_table_offset = refcount_blocks_offset + @as(u64, layout.refcount_block_count) * layout.cluster_size;
    const initial_file_size = l1_table_offset + @as(u64, layout.l1_clusters) * layout.cluster_size;
    try file.setLength(io, initial_file_size);

    const info = Info{
        .virtual_size = size,
        .file_size = initial_file_size,
        .version = 3,
        .cluster_bits = default_cluster_bits,
        .cluster_size = layout.cluster_size,
        .l1_size = layout.l1_size,
        .l1_table_offset = l1_table_offset,
        .active_l1_table_offset = l1_table_offset,
        .l2_entries = layout.l2_entries,
        .refcount_table_offset = refcount_table_offset,
        .refcount_table_clusters = layout.refcount_table_clusters,
        .refcount_table_capacity_blocks = @as(u64, layout.refcount_table_clusters) * layout.cluster_size / 8,
        .refcount_block_count = layout.refcount_block_count,
        .refcount_order = default_refcount_order,
        .header_length = header_length_v3,
        .incompatible_features = 0,
        .crypt_method = 0,
        .compression_type = 0,
        .snapshot_count = 0,
        .snapshots_offset = 0,
    };

    try writeInitialHeader(file, io, info);

    var block_index: u32 = 0;
    while (block_index < info.refcount_block_count) : (block_index += 1) {
        const block_offset = refcount_blocks_offset + @as(u64, block_index) * info.cluster_size;
        try writeRefcountTableEntry(file, io, info.refcount_table_offset, block_index, block_offset);
    }

    const metadata_clusters = 1 + @as(u64, info.refcount_table_clusters) + @as(u64, info.refcount_block_count) + @as(u64, layout.l1_clusters);
    var cluster_index: u64 = 0;
    while (cluster_index < metadata_clusters) : (cluster_index += 1) {
        try writeRefcountByClusterIndex(file, io, info, cluster_index, 1);
    }

    return info;
}

pub fn pread(file: Io.File, io: Io, info: Info, buffer: []u8, offset: u64) PreadError!usize {
    return preadLayer(file, io, info, info.backing_chain[0..info.backing_depth], buffer, offset);
}

fn preadLayer(
    file: Io.File,
    io: Io,
    info: anytype,
    backing_chain: []const BackingLayer,
    buffer: []u8,
    offset: u64,
) PreadError!usize {
    if (offset >= info.virtual_size) return 0;

    var backing_file: ?Io.File = null;
    defer if (backing_file) |f| f.close(io);
    var data_file: ?Io.File = null;
    defer if (data_file) |f| f.close(io);

    var total: usize = 0;
    var off = offset;
    var remaining = @min(buffer.len, info.virtual_size - offset);
    while (remaining > 0) {
        const in_cluster_offset: u32 = @intCast(off % info.cluster_size);
        const region = try lookupGuestRegion(file, io, info, off);
        const mapping = region.mapping;
        const chunk: usize = @intCast(@min(@as(u64, remaining), region.length));

        switch (mapping.kind) {
            .zero => {
                @memset(buffer[total..][0..chunk], 0);
            },
            .standard => {
                const data_source = blk: {
                    if (!usesExternalDataFile(info)) break :blk file;
                    if (data_file == null) {
                        data_file = try Io.Dir.cwd().openFile(io, info.data_file_path[0..info.data_file_len], .{ .mode = .read_only });
                    }
                    break :blk data_file.?;
                };
                const got = try data_source.readPositionalAll(io, buffer[total..][0..chunk], mapping.host_offset.?);
                if (got < chunk) @memset(buffer[total + got ..][0 .. chunk - got], 0);
            },
            .compressed => {
                try readCompressedClusterChunk(file, io, info.cluster_size, info.compression_type, mapping, buffer[total..][0..chunk], in_cluster_offset);
            },
            .backing => {
                if (backing_chain.len == 0) {
                    @memset(buffer[total..][0..chunk], 0);
                } else {
                    if (backing_file == null) {
                        backing_file = try Io.Dir.cwd().openFile(io, backing_chain[0].path[0..backing_chain[0].path_len], .{ .mode = .read_only });
                    }
                    const got = try preadLayer(
                        backing_file.?,
                        io,
                        backing_chain[0].info,
                        backing_chain[1..],
                        buffer[total..][0..chunk],
                        off,
                    );
                    if (got < chunk) @memset(buffer[total + got ..][0 .. chunk - got], 0);
                }
            },
        }

        total += chunk;
        off += chunk;
        remaining -= chunk;
    }
    return total;
}

fn readCompressedClusterChunk(
    file: Io.File,
    io: Io,
    cluster_size: u64,
    compression_type: u8,
    mapping: ClusterMapping,
    out: []u8,
    in_cluster_offset: u32,
) PreadError!void {
    const compressed = try std.heap.page_allocator.alloc(u8, @intCast(mapping.compressed_byte_len));
    defer std.heap.page_allocator.free(compressed);
    _ = try file.readPositionalAll(io, compressed, mapping.host_offset.?);

    var input = Io.Reader.fixed(compressed);
    const full_cluster = try std.heap.page_allocator.alloc(u8, @intCast(cluster_size));
    defer std.heap.page_allocator.free(full_cluster);

    switch (compression_type) {
        0 => {
            // Raw deflate (no zlib header). It stops at its end-of-block
            // marker, so streaming exactly one cluster's worth out is safe
            // and ignores the trailing sector padding.
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decompressor: std.compress.flate.Decompress = .init(&input, .raw, &window);
            var writer = Io.Writer.fixed(full_cluster);
            decompressor.reader.streamExact(&writer, @intCast(cluster_size)) catch |err| switch (err) {
                else => return error.InvalidCompressedCluster,
            };
        },
        1 => {
            // Indirect mode: give the decoder a window buffer sized to the
            // cluster, then read exactly one cluster out. We must NOT drain
            // the input, since qcow2 pads the compressed payload to a sector
            // boundary and reading past the frame would misparse the
            // trailing padding as a second zstd frame.
            const wlen: u32 = @intCast(@max(cluster_size, 1));
            const zbuf = try std.heap.page_allocator.alloc(u8, @as(usize, wlen) + std.compress.zstd.block_size_max);
            defer std.heap.page_allocator.free(zbuf);
            var decompressor: std.compress.zstd.Decompress = .init(&input, zbuf, .{ .window_len = wlen });
            const produced = decompressor.reader.readSliceShort(full_cluster) catch return error.InvalidCompressedCluster;
            if (produced < full_cluster.len) @memset(full_cluster[produced..], 0);
        },
        else => return error.UnsupportedCompressionType,
    }
    @memcpy(out, full_cluster[in_cluster_offset..][0..out.len]);
}

/// Writes guest-visible bytes, allocating qcow2 L2/data clusters on demand.
/// Writes into backing-file regions, compressed clusters, and snapshot-shared
/// metadata/data all transparently allocate a private active-image copy before
/// the caller's bytes are applied.
pub fn pwrite(file: Io.File, io: Io, info: *Info, buffer: []const u8, offset: u64) PwriteError!void {
    try ensureWritableImage(info.*);
    const write_end = std.math.add(u64, offset, buffer.len) catch return error.WritePastEndOfImage;
    if (write_end > info.virtual_size) return error.WritePastEndOfImage;

    var dirty_marked = false;
    var ok = false;
    if (info.version >= 3) {
        try setDirtyState(file, io, info, true);
        dirty_marked = true;
    }
    defer if (dirty_marked and ok) setDirtyState(file, io, info, false) catch {};

    var off = offset;
    var remaining = buffer.len;
    var src: usize = 0;
    while (remaining > 0) {
        const guest_cluster_index = off / info.cluster_size;
        const in_cluster_offset: u32 = @intCast(off % info.cluster_size);
        const chunk: usize = @intCast(@min(@as(u64, remaining), info.cluster_size - in_cluster_offset));

        const l2_table_offset = try ensureL2TableWritable(file, io, info, guest_cluster_index);
        const l2_index = guest_cluster_index % info.l2_entries;
        const host_cluster_offset = try ensureDataClusterWritable(file, io, info, guest_cluster_index, l2_table_offset, l2_index);
        try file.writePositionalAll(io, buffer[src..][0..chunk], host_cluster_offset + in_cluster_offset);

        src += chunk;
        off += chunk;
        remaining -= chunk;
    }

    ok = true;
}

/// Grows the guest-visible virtual size. If the new size requires a larger L1
/// table or more refcount metadata, qcow2 metadata is expanded in place and
/// the header is updated accordingly.
pub fn resize(file: Io.File, io: Io, info: *Info, new_size: u64) ResizeError!void {
    try ensureWritableImage(info.*);
    if (new_size < info.virtual_size) return error.ShrinkNotSupported;
    if (new_size == info.virtual_size) return;

    var dirty_marked = false;
    var ok = false;
    if (info.version >= 3) {
        try setDirtyState(file, io, info, true);
        dirty_marked = true;
    }
    defer if (dirty_marked and ok) setDirtyState(file, io, info, false) catch {};

    const layout = layoutForSize(new_size, info.cluster_bits, info.refcount_order) catch |err| switch (err) {
        error.ImageTooLarge => return error.ImageTooLarge,
        error.UnsupportedRefcountOrderForWrite => return error.UnsupportedRefcountOrderForWrite,
        error.UnsupportedClusterSize => unreachable,
    };
    try ensureRefcountCapacity(file, io, info, layout);
    try ensureL1Capacity(file, io, info, layout.l1_size, layout.l1_clusters);

    try writeHeaderU64Field(file, io, 24, new_size);
    info.virtual_size = new_size;
    ok = true;
}

pub fn check(file: Io.File, io: Io, info: Info) CheckError!void {
    if (info.incompatible_features & incompatible_dirty != 0) return error.ImageMarkedDirty;
    if (info.incompatible_features & incompatible_corrupt != 0) return error.ImageMarkedCorrupt;

    try expectClusterRefcountNonZero(file, io, info, 0);
    try setClusterRangeRefcountExpected(file, io, info, info.refcount_table_offset / info.cluster_size, info.refcount_table_clusters);
    try setClusterRangeRefcountExpected(file, io, info, info.l1_table_offset / info.cluster_size, tableClusterCount(@as(u64, info.l1_size) * 8, info.cluster_size));

    const table_entries = info.refcount_table_capacity_blocks;
    var table_index: u64 = 0;
    while (table_index < table_entries) : (table_index += 1) {
        const block_offset = try readU64(file, io, info.refcount_table_offset + table_index * 8);
        if (block_offset == 0) continue;
        try expectClusterRefcountNonZero(file, io, info, block_offset / info.cluster_size);
    }

    const guest_clusters = divCeil(info.virtual_size, info.cluster_size);
    var guest_cluster_index: u64 = 0;
    while (guest_cluster_index < guest_clusters) : (guest_cluster_index += 1) {
        const l1_index = guest_cluster_index / info.l2_entries;
        if (l1_index >= info.l1_size) return error.L1TableTooSmall;

        const l1_entry = try readU64(file, io, info.l1_table_offset + l1_index * 8);
        const l2_table_offset = l1_entry & host_offset_mask;
        if (l2_table_offset == 0) continue;
        try expectClusterRefcountNonZero(file, io, info, l2_table_offset / info.cluster_size);

        if (usesExternalDataFile(info)) continue;

        const l2_index = guest_cluster_index % info.l2_entries;
        const l2_entry_offset = l2_table_offset + l2_index * l2EntrySizeBytes(info.incompatible_features);
        const l2_entry = try readU64(file, io, l2_entry_offset);
        if (l2_entry & compressed_mask != 0) {
            const mapping = try compressedClusterMapping(info, l2_entry);
            const host_offset = mapping.host_offset.?;
            try expectClusterRefcountNonZero(file, io, info, hostOffsetClusterIndex(host_offset, info.cluster_size));
            const end_cluster_index = hostOffsetClusterIndex(host_offset + mapping.compressed_byte_len - 1, info.cluster_size);
            if (end_cluster_index != hostOffsetClusterIndex(host_offset, info.cluster_size)) {
                try expectClusterRefcountNonZero(file, io, info, end_cluster_index);
            }
            continue;
        }

        if (isExtendedL2(info)) {
            const bitmap = try readU64(file, io, l2_entry_offset + 8);
            if ((bitmap & 0xFFFF_FFFF) == 0) continue;
        } else if (!hasDataHostCluster(info, guest_cluster_index, l2_entry)) {
            continue;
        }

        try expectClusterRefcountNonZero(file, io, info, hostOffsetClusterIndex(l2_entry & host_offset_mask, info.cluster_size));
    }
}

pub fn mapExtents(file: Io.File, io: Io, info: Info, allocator: std.mem.Allocator) MapError![]Extent {
    var extents = std.array_list.Managed(Extent).init(allocator);
    errdefer extents.deinit();

    var offset: u64 = 0;
    while (offset < info.virtual_size) {
        const first = try lookupGuestRegion(file, io, info, offset);
        const allocated = first.mapping.physically_allocated;
        const start = offset;
        var end = @min(info.virtual_size, offset + first.length);

        while (end < info.virtual_size) {
            const next = try lookupGuestRegion(file, io, info, end);
            if (next.mapping.physically_allocated != allocated) break;
            end = @min(info.virtual_size, end + next.length);
        }

        try extents.append(.{ .offset = start, .length = end - start, .allocated = allocated });
        offset = end;
    }

    return extents.toOwnedSlice();
}

fn lookupGuestCluster(file: Io.File, io: Io, info: anytype, guest_cluster_index: u64) LookupError!ClusterMapping {
    const l1_index = guest_cluster_index / info.l2_entries;
    if (l1_index >= info.l1_size) return error.L1TableTooSmall;

    const l1_entry = try readU64(file, io, info.l1_table_offset + l1_index * 8);
    const l2_table_offset = l1_entry & host_offset_mask;
    if (l2_table_offset == 0) {
        return .{ .kind = .backing, .host_offset = null, .physically_allocated = false };
    }
    if (!isAligned(l2_table_offset, info.cluster_size) or l2_table_offset < info.cluster_size or l2_table_offset + info.cluster_size > info.file_size) {
        return error.InvalidL1Entry;
    }

    const l2_index = guest_cluster_index % info.l2_entries;
    const l2_entry_offset = l2_table_offset + l2_index * l2EntrySizeBytes(info.incompatible_features);
    const l2_entry = try readU64(file, io, l2_entry_offset);
    if (l2_entry & compressed_mask != 0) {
        if (usesExternalDataFile(info)) return error.InvalidL2Entry;
        const sector_count_bits = info.cluster_bits - 8;
        const offset_bits = 62 - sector_count_bits;
        const offset_mask = if (offset_bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(offset_bits)) - 1;
        const additional_sector_mask = (@as(u64, 1) << @intCast(sector_count_bits)) - 1;
        const host_offset = l2_entry & offset_mask;
        const additional_sectors = (l2_entry >> @intCast(offset_bits)) & additional_sector_mask;
        const compressed_byte_len = (@as(u64, additional_sectors) + 1) * 512 - (host_offset % 512);
        const end = std.math.add(u64, host_offset, compressed_byte_len) catch return error.InvalidL2Entry;
        if (host_offset < info.header_length or end > info.file_size) return error.InvalidL2Entry;
        return .{
            .kind = .compressed,
            .host_offset = host_offset,
            .physically_allocated = true,
            .compressed_byte_len = compressed_byte_len,
        };
    }

    if (isExtendedL2(info)) {
        const region = try lookupGuestRegion(file, io, info, guest_cluster_index * info.cluster_size);
        if (region.length != info.cluster_size) return error.InvalidL2Entry;
        return region.mapping;
    }

    const host_cluster_offset = l2_entry & host_offset_mask;
    const reads_as_zero = (l2_entry & zero_mask) != 0;
    const has_host_cluster = hasDataHostCluster(info, guest_cluster_index, l2_entry);
    if (!has_host_cluster) {
        return .{
            .kind = if (reads_as_zero) .zero else .backing,
            .host_offset = null,
            .physically_allocated = false,
        };
    }
    if (!validDataHostClusterOffset(info, guest_cluster_index, host_cluster_offset)) {
        return error.InvalidL2Entry;
    }

    return .{
        .kind = if (reads_as_zero) .zero else .standard,
        .host_offset = host_cluster_offset,
        .physically_allocated = true,
    };
}

fn lookupGuestRegion(file: Io.File, io: Io, info: anytype, guest_offset: u64) LookupError!GuestRegionMapping {
    const guest_cluster_index = guest_offset / info.cluster_size;
    const offset_in_cluster = guest_offset % info.cluster_size;
    const remaining_cluster = info.cluster_size - offset_in_cluster;

    const l1_index = guest_cluster_index / info.l2_entries;
    if (l1_index >= info.l1_size) return error.L1TableTooSmall;

    const l1_entry = try readU64(file, io, info.l1_table_offset + l1_index * 8);
    const l2_table_offset = l1_entry & host_offset_mask;
    if (l2_table_offset == 0) {
        return .{
            .mapping = .{ .kind = .backing, .host_offset = null, .physically_allocated = false },
            .length = remaining_cluster,
        };
    }
    if (!isAligned(l2_table_offset, info.cluster_size) or l2_table_offset < info.cluster_size or l2_table_offset + info.cluster_size > info.file_size) {
        return error.InvalidL1Entry;
    }

    const l2_index = guest_cluster_index % info.l2_entries;
    const l2_entry_offset = l2_table_offset + l2_index * l2EntrySizeBytes(info.incompatible_features);
    const l2_entry = try readU64(file, io, l2_entry_offset);
    if (l2_entry & compressed_mask != 0) {
        if (usesExternalDataFile(info)) return error.InvalidL2Entry;
        const mapping = try compressedClusterMapping(info, l2_entry);
        return .{ .mapping = mapping, .length = remaining_cluster };
    }

    if (!isExtendedL2(info)) {
        const mapping = try standardClusterMapping(info, guest_cluster_index, l2_entry);
        var adjusted = mapping;
        if (mapping.host_offset) |host_offset| {
            adjusted.host_offset = host_offset + offset_in_cluster;
        }
        return .{ .mapping = adjusted, .length = remaining_cluster };
    }

    if ((l2_entry & zero_mask) != 0) return error.InvalidL2Entry;
    const bitmap = try readU64(file, io, l2_entry_offset + 8);
    const host_cluster_offset = l2_entry & host_offset_mask;
    const host_cluster_valid = hasDataHostCluster(info, guest_cluster_index, l2_entry);
    if (host_cluster_valid and !validDataHostClusterOffset(info, guest_cluster_index, host_cluster_offset)) {
        return error.InvalidL2Entry;
    }

    const subcluster_size = subclusterSize(info);
    const subcluster_index: u32 = @intCast(offset_in_cluster / subcluster_size);
    const alloc_bit = ((bitmap >> @intCast(subcluster_index)) & 1) != 0;
    const zero_bit = ((bitmap >> @intCast(subcluster_index + extl2_subcluster_count)) & 1) != 0;
    if (alloc_bit and zero_bit) return error.InvalidL2Entry;
    if (alloc_bit and !host_cluster_valid) return error.InvalidL2Entry;

    const run_kind: ClusterKind = if (alloc_bit)
        .standard
    else if (zero_bit)
        .zero
    else
        .backing;
    const run_allocated = alloc_bit;

    var run_end = subcluster_index + 1;
    while (run_end < extl2_subcluster_count) : (run_end += 1) {
        const next_alloc = ((bitmap >> @intCast(run_end)) & 1) != 0;
        const next_zero = ((bitmap >> @intCast(run_end + extl2_subcluster_count)) & 1) != 0;
        if (next_alloc and next_zero) return error.InvalidL2Entry;
        const next_kind: ClusterKind = if (next_alloc)
            .standard
        else if (next_zero)
            .zero
        else
            .backing;
        if (next_kind != run_kind) break;
    }

    const run_end_offset = @as(u64, run_end) * subcluster_size;
    const run_length = run_end_offset - offset_in_cluster;
    return .{
        .mapping = .{
            .kind = run_kind,
            .host_offset = if (run_kind == .standard) host_cluster_offset + offset_in_cluster else null,
            .physically_allocated = run_allocated,
        },
        .length = run_length,
    };
}

fn compressedClusterMapping(info: anytype, l2_entry: u64) LookupError!ClusterMapping {
    const sector_count_bits = info.cluster_bits - 8;
    const offset_bits = 62 - sector_count_bits;
    const offset_mask = if (offset_bits == 64) std.math.maxInt(u64) else (@as(u64, 1) << @intCast(offset_bits)) - 1;
    const additional_sector_mask = (@as(u64, 1) << @intCast(sector_count_bits)) - 1;
    const host_offset = l2_entry & offset_mask;
    const additional_sectors = (l2_entry >> @intCast(offset_bits)) & additional_sector_mask;
    const compressed_byte_len = (@as(u64, additional_sectors) + 1) * 512 - (host_offset % 512);
    const end = std.math.add(u64, host_offset, compressed_byte_len) catch return error.InvalidL2Entry;
    if (host_offset < info.header_length or end > info.file_size) return error.InvalidL2Entry;
    return .{
        .kind = .compressed,
        .host_offset = host_offset,
        .physically_allocated = true,
        .compressed_byte_len = compressed_byte_len,
    };
}

fn standardClusterMapping(info: anytype, guest_cluster_index: u64, l2_entry: u64) LookupError!ClusterMapping {
    const host_cluster_offset = l2_entry & host_offset_mask;
    const reads_as_zero = (l2_entry & zero_mask) != 0;
    const has_host_cluster = hasDataHostCluster(info, guest_cluster_index, l2_entry);
    if (!has_host_cluster) {
        return .{
            .kind = if (reads_as_zero) .zero else .backing,
            .host_offset = null,
            .physically_allocated = false,
        };
    }
    if (!validDataHostClusterOffset(info, guest_cluster_index, host_cluster_offset)) {
        return error.InvalidL2Entry;
    }
    return .{
        .kind = if (reads_as_zero) .zero else .standard,
        .host_offset = host_cluster_offset,
        .physically_allocated = true,
    };
}

fn usesExternalDataFile(info: anytype) bool {
    return info.data_file_len != 0;
}

fn isExtendedL2(info: anytype) bool {
    return (info.incompatible_features & incompatible_extl2) != 0;
}

fn l2EntrySizeBytes(incompatible_features: u64) u64 {
    return if (incompatible_features & incompatible_extl2 != 0) 16 else 8;
}

fn subclusterSize(info: anytype) u64 {
    return info.cluster_size / extl2_subcluster_count;
}

fn hasDataHostCluster(info: anytype, guest_cluster_index: u64, l2_entry: u64) bool {
    const host_cluster_offset = l2_entry & host_offset_mask;
    if (host_cluster_offset != 0) return true;
    if (!usesExternalDataFile(info)) return false;
    return (l2_entry & copied_mask) != 0 and guest_cluster_index == 0;
}

fn validDataHostClusterOffset(info: anytype, guest_cluster_index: u64, host_cluster_offset: u64) bool {
    if (!isAligned(host_cluster_offset, info.cluster_size)) return false;
    if (usesExternalDataFile(info)) {
        if (host_cluster_offset != guest_cluster_index * info.cluster_size) return false;
        const end = std.math.add(u64, host_cluster_offset, info.cluster_size) catch return false;
        return end <= info.data_file_size;
    }
    const end = std.math.add(u64, host_cluster_offset, info.cluster_size) catch return false;
    return host_cluster_offset >= info.cluster_size and end <= info.file_size;
}

fn layoutForSize(virtual_size: u64, cluster_bits: u32, refcount_order: u32) error{ UnsupportedClusterSize, UnsupportedRefcountOrderForWrite, ImageTooLarge }!Layout {
    if (cluster_bits < min_cluster_bits or cluster_bits > max_cluster_bits) return error.UnsupportedClusterSize;
    if (refcount_order != default_refcount_order) return error.UnsupportedRefcountOrderForWrite;

    const cluster_size = @as(u64, 1) << @intCast(cluster_bits);
    const l2_entries = cluster_size / l2_entry_size;
    const guest_clusters = divCeil(virtual_size, cluster_size);
    const l1_size_u64 = @max(@as(u64, 1), divCeil(guest_clusters, l2_entries));
    const l1_size = std.math.cast(u32, l1_size_u64) orelse return error.ImageTooLarge;
    const l1_clusters = std.math.cast(u32, divCeil(std.math.mul(u64, l1_size_u64, 8) catch return error.ImageTooLarge, cluster_size)) orelse return error.ImageTooLarge;
    const refcount_block_entries = cluster_size / 2;

    var refcount_block_count_u64: u64 = 1;
    var refcount_table_clusters_u64: u64 = 1;
    while (true) {
        const host_clusters = 1 + refcount_table_clusters_u64 + refcount_block_count_u64 + @as(u64, l1_clusters) + l1_size_u64 + guest_clusters;
        const needed_blocks = divCeil(host_clusters, refcount_block_entries);
        const needed_table_clusters = @max(@as(u64, 1), divCeil(needed_blocks * 8, cluster_size));
        if (needed_blocks == refcount_block_count_u64 and needed_table_clusters == refcount_table_clusters_u64) {
            return .{
                .cluster_size = cluster_size,
                .l2_entries = l2_entries,
                .guest_clusters = guest_clusters,
                .l1_size = l1_size,
                .l1_clusters = l1_clusters,
                .refcount_block_entries = refcount_block_entries,
                .refcount_block_count = std.math.cast(u32, refcount_block_count_u64) orelse return error.ImageTooLarge,
                .refcount_table_clusters = std.math.cast(u32, refcount_table_clusters_u64) orelse return error.ImageTooLarge,
                .max_host_clusters = host_clusters,
            };
        }
        refcount_block_count_u64 = needed_blocks;
        refcount_table_clusters_u64 = needed_table_clusters;
    }
}

fn infoFromParsed(parsed: ParsedLayer) Info {
    var info = Info{
        .virtual_size = parsed.info.virtual_size,
        .file_size = parsed.info.file_size,
        .version = parsed.info.version,
        .cluster_bits = parsed.info.cluster_bits,
        .cluster_size = parsed.info.cluster_size,
        .l1_size = parsed.info.l1_size,
        .l1_table_offset = parsed.info.l1_table_offset,
        .active_l1_table_offset = parsed.info.l1_table_offset,
        .l2_entries = parsed.info.l2_entries,
        .refcount_table_offset = parsed.info.refcount_table_offset,
        .refcount_table_clusters = parsed.info.refcount_table_clusters,
        .refcount_table_capacity_blocks = parsed.info.refcount_table_capacity_blocks,
        .refcount_block_count = parsed.info.refcount_block_count,
        .refcount_order = parsed.info.refcount_order,
        .header_length = parsed.info.header_length,
        .incompatible_features = parsed.info.incompatible_features,
        .crypt_method = parsed.info.crypt_method,
        .compression_type = parsed.info.compression_type,
        .snapshot_count = parsed.info.snapshot_count,
        .snapshots_offset = parsed.info.snapshots_offset,
    };
    info.data_file_len = parsed.data_file_len;
    if (parsed.data_file_len != 0) {
        @memcpy(info.data_file_path[0..parsed.data_file_len], parsed.data_file_path[0..parsed.data_file_len]);
    }
    info.backing_file_len = parsed.backing_file_len;
    if (parsed.backing_file_len != 0) {
        @memcpy(info.backing_file_path[0..parsed.backing_file_len], parsed.backing_file_path[0..parsed.backing_file_len]);
    }
    return info;
}

fn copyPathInto(dest: *[std.fs.max_path_bytes]u8, dest_len: *u16, path: []const u8) OpenError!void {
    if (path.len > std.fs.max_path_bytes or path.len > std.math.maxInt(u16)) {
        return error.HeaderStringTooLong;
    }
    dest_len.* = @intCast(path.len);
    if (path.len != 0) @memcpy(dest[0..path.len], path);
}

fn readHeaderString(
    file: Io.File,
    io: Io,
    offset: u64,
    size: u32,
    file_size: u64,
    dest: *[std.fs.max_path_bytes]u8,
    dest_len: *u16,
) OpenError!void {
    if (size > std.fs.max_path_bytes or size > std.math.maxInt(u16)) return error.HeaderStringTooLong;
    const end = std.math.add(u64, offset, size) catch return error.InvalidHeaderStringRange;
    if (offset == 0 or end > file_size) return error.InvalidHeaderStringRange;
    dest_len.* = @intCast(size);
    _ = try file.readPositionalAll(io, dest[0..size], offset);
}

fn readHeaderExtensions(
    file: Io.File,
    io: Io,
    header_length: u32,
    extensions_end: u64,
    file_size: u64,
    parsed: *ParsedLayer,
) OpenError!void {
    var offset = @as(u64, header_length);
    while (offset + 8 <= extensions_end and offset + 8 <= file_size) {
        var ext_header: [8]u8 = undefined;
        _ = try file.readPositionalAll(io, &ext_header, offset);
        const magic = std.mem.readInt(u32, ext_header[0..4], .big);
        const len = std.mem.readInt(u32, ext_header[4..8], .big);
        if (magic == header_extension_end_magic) return;

        const data_offset = offset + 8;
        const data_end = std.math.add(u64, data_offset, len) catch return error.InvalidHeaderStringRange;
        const ext_end = std.mem.alignForward(u64, data_end, 8);
        if (ext_end > extensions_end or data_end > file_size) return error.InvalidHeaderStringRange;

        switch (magic) {
            header_extension_external_data_file_magic => {
                try readHeaderString(file, io, data_offset, len, file_size, &parsed.data_file_path, &parsed.data_file_len);
            },
            else => {},
        }

        offset = ext_end;
    }
}

fn resolveLayerDataFile(io: Io, info: anytype, source_path: ?[]const u8) OpenError!void {
    if (info.data_file_len == 0) return;

    const resolved = try resolveExternalDataPath(source_path, info.data_file_path[0..info.data_file_len]);
    defer std.heap.page_allocator.free(resolved);
    try copyPathInto(&info.data_file_path, &info.data_file_len, resolved);

    const data_file = try Io.Dir.cwd().openFile(io, resolved, .{ .mode = .read_only });
    defer data_file.close(io);
    info.data_file_size = (try data_file.stat(io)).size;
}

fn populateBackingChain(io: Io, info: *Info) OpenError!void {
    if (info.backing_file_len == 0) return;

    var depth: u8 = 0;
    var current_base_path: ?[]const u8 = if (info.source_path_len == 0) null else info.source_path[0..info.source_path_len];
    var current_backing: []const u8 = info.backing_file_path[0..info.backing_file_len];

    while (current_backing.len != 0) {
        if (depth >= max_backing_chain_depth) return error.BackingChainTooDeep;

        const resolved = try resolveBackingPath(current_base_path, current_backing);
        defer std.heap.page_allocator.free(resolved);

        if (pathSeenInChain(info.*, depth, resolved)) return error.BackingChainLoop;

        const backing_file = try Io.Dir.cwd().openFile(io, resolved, .{ .mode = .read_only });
        defer backing_file.close(io);

        const parsed = try parseLayer(backing_file, io);
        const layer = &info.backing_chain[depth];
        layer.info = parsed.info;
        try copyPathInto(&layer.path, &layer.path_len, resolved);
        layer.info.data_file_len = parsed.data_file_len;
        if (parsed.data_file_len != 0) {
            @memcpy(layer.info.data_file_path[0..parsed.data_file_len], parsed.data_file_path[0..parsed.data_file_len]);
        }
        try resolveLayerDataFile(io, &layer.info, resolved);

        depth += 1;
        info.backing_depth = depth;

        if (parsed.backing_file_len == 0) break;
        current_base_path = layer.path[0..layer.path_len];
        current_backing = parsed.backing_file_path[0..parsed.backing_file_len];
    }
}

/// Returns every host file, other than the top-level qcow2 itself, that can
/// contribute guest-visible bytes. Paths are resolved by `openAtPath`.
pub fn sourceDependencyPaths(
    allocator: std.mem.Allocator,
    info: Info,
) std.mem.Allocator.Error![][]u8 {
    var paths = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit();
    }

    if (info.data_file_len != 0) {
        try appendUniqueOwnedPath(
            &paths,
            allocator,
            info.data_file_path[0..info.data_file_len],
        );
    }
    for (info.backing_chain[0..info.backing_depth]) |layer| {
        try appendUniqueOwnedPath(&paths, allocator, layer.path[0..layer.path_len]);
        if (layer.info.data_file_len != 0) {
            try appendUniqueOwnedPath(
                &paths,
                allocator,
                layer.info.data_file_path[0..layer.info.data_file_len],
            );
        }
    }
    return paths.toOwnedSlice();
}

fn appendUniqueOwnedPath(
    paths: *std.array_list.Managed([]u8),
    allocator: std.mem.Allocator,
    path: []const u8,
) std.mem.Allocator.Error!void {
    for (paths.items) |existing| {
        if (std.mem.eql(u8, existing, path)) return;
    }
    try paths.append(try allocator.dupe(u8, path));
}

fn pathSeenInChain(info: Info, depth: u8, path: []const u8) bool {
    if (info.source_path_len != 0 and std.mem.eql(u8, info.source_path[0..info.source_path_len], path)) return true;
    var index: u8 = 0;
    while (index < depth) : (index += 1) {
        const layer = info.backing_chain[index];
        if (std.mem.eql(u8, layer.path[0..layer.path_len], path)) return true;
    }
    return false;
}

fn resolveBackingPath(source_path: ?[]const u8, backing_path: []const u8) OpenError![]u8 {
    if (std.fs.path.isAbsolute(backing_path)) {
        return std.heap.page_allocator.dupe(u8, backing_path);
    }
    const base = source_path orelse return error.RelativeBackingFilePath;
    const base_dir = std.fs.path.dirname(base) orelse ".";
    return std.fs.path.resolve(std.heap.page_allocator, &.{ base_dir, backing_path });
}

fn resolveExternalDataPath(source_path: ?[]const u8, data_path: []const u8) OpenError![]u8 {
    if (std.fs.path.isAbsolute(data_path)) {
        return std.heap.page_allocator.dupe(u8, data_path);
    }
    const base = source_path orelse return error.RelativeExternalDataFilePath;
    const base_dir = std.fs.path.dirname(base) orelse ".";
    return std.fs.path.resolve(std.heap.page_allocator, &.{ base_dir, data_path });
}

fn hostOffsetClusterIndex(host_offset: u64, cluster_size: u64) u64 {
    return host_offset / cluster_size;
}

pub fn listSnapshots(file: Io.File, io: Io, info: Info, allocator: std.mem.Allocator) ListSnapshotsError![]Snapshot {
    var snapshots = std.array_list.Managed(Snapshot).init(allocator);
    errdefer {
        for (snapshots.items) |*snapshot| snapshot.deinit(allocator);
        snapshots.deinit();
    }

    if (info.snapshot_count == 0) return snapshots.toOwnedSlice();
    if (info.snapshots_offset == 0 or info.snapshots_offset >= info.file_size) return error.SnapshotTablePastEndOfFile;

    var cursor = info.snapshots_offset;
    var index: u32 = 0;
    while (index < info.snapshot_count) : (index += 1) {
        if (cursor + 40 > info.file_size) return error.SnapshotTablePastEndOfFile;

        var entry_header: [40]u8 = undefined;
        _ = try file.readPositionalAll(io, &entry_header, cursor);

        const l1_table_offset = std.mem.readInt(u64, entry_header[0..8], .big);
        const l1_size = std.mem.readInt(u32, entry_header[8..12], .big);
        const id_len = std.mem.readInt(u16, entry_header[12..14], .big);
        const name_len = std.mem.readInt(u16, entry_header[14..16], .big);
        const timestamp_seconds = std.mem.readInt(u32, entry_header[16..20], .big);
        const timestamp_nanoseconds = std.mem.readInt(u32, entry_header[20..24], .big);
        const vm_clock_nanoseconds = std.mem.readInt(u64, entry_header[24..32], .big);
        const extra_data_size = std.mem.readInt(u32, entry_header[36..40], .big);

        const raw_entry_size = std.math.add(u64, 40, extra_data_size) catch return error.InvalidSnapshotEntry;
        const with_id = std.math.add(u64, raw_entry_size, id_len) catch return error.InvalidSnapshotEntry;
        const entry_size = std.math.add(u64, with_id, name_len) catch return error.InvalidSnapshotEntry;
        const padded_entry_size = std.mem.alignForward(u64, entry_size, 8);
        const entry_end = std.math.add(u64, cursor, padded_entry_size) catch return error.InvalidSnapshotEntry;
        if (entry_end > info.file_size) return error.SnapshotTablePastEndOfFile;

        const extra_data = try allocator.alloc(u8, extra_data_size);
        defer allocator.free(extra_data);
        if (extra_data_size != 0) {
            _ = try file.readPositionalAll(io, extra_data, cursor + 40);
        }

        const id = try allocator.alloc(u8, id_len);
        errdefer allocator.free(id);
        if (id_len != 0) {
            _ = try file.readPositionalAll(io, id, cursor + 40 + extra_data_size);
        }

        const name = try allocator.alloc(u8, name_len);
        errdefer allocator.free(name);
        if (name_len != 0) {
            _ = try file.readPositionalAll(io, name, cursor + 40 + extra_data_size + id_len);
        }

        const vm_state_size_legacy = std.mem.readInt(u32, entry_header[32..36], .big);
        const vm_state_size = if (extra_data_size >= 8)
            std.mem.readInt(u64, extra_data[0..8], .big)
        else
            @as(u64, vm_state_size_legacy);
        const virtual_size = if (extra_data_size >= 16)
            std.mem.readInt(u64, extra_data[8..16], .big)
        else
            null;

        try snapshots.append(.{
            .l1_table_offset = l1_table_offset,
            .l1_size = l1_size,
            .id = id,
            .name = name,
            .timestamp_seconds = timestamp_seconds,
            .timestamp_nanoseconds = timestamp_nanoseconds,
            .vm_clock_nanoseconds = vm_clock_nanoseconds,
            .vm_state_size = vm_state_size,
            .virtual_size = virtual_size,
        });

        cursor = entry_end;
    }

    return snapshots.toOwnedSlice();
}

fn snapshotTableByteLen(file: Io.File, io: Io, info: Info) ListSnapshotsError!u64 {
    if (info.snapshot_count == 0) return 0;
    if (info.snapshots_offset == 0 or info.snapshots_offset >= info.file_size) return error.SnapshotTablePastEndOfFile;

    var cursor = info.snapshots_offset;
    var index: u32 = 0;
    while (index < info.snapshot_count) : (index += 1) {
        if (cursor + 40 > info.file_size) return error.SnapshotTablePastEndOfFile;

        var entry_header: [40]u8 = undefined;
        _ = try file.readPositionalAll(io, &entry_header, cursor);

        const id_len = std.mem.readInt(u16, entry_header[12..14], .big);
        const name_len = std.mem.readInt(u16, entry_header[14..16], .big);
        const extra_data_size = std.mem.readInt(u32, entry_header[36..40], .big);

        const raw_entry_size = std.math.add(u64, 40, extra_data_size) catch return error.InvalidSnapshotEntry;
        const with_id = std.math.add(u64, raw_entry_size, id_len) catch return error.InvalidSnapshotEntry;
        const entry_size = std.math.add(u64, with_id, name_len) catch return error.InvalidSnapshotEntry;
        const padded_entry_size = std.mem.alignForward(u64, entry_size, 8);
        const entry_end = std.math.add(u64, cursor, padded_entry_size) catch return error.InvalidSnapshotEntry;
        if (entry_end > info.file_size) return error.SnapshotTablePastEndOfFile;
        cursor = entry_end;
    }

    return cursor - info.snapshots_offset;
}

fn snapshotTableClusterCount(info: Info, byte_len: u64) u32 {
    if (byte_len == 0) return 0;
    return tableClusterCount(byte_len, info.cluster_size);
}

pub fn createSnapshot(file: Io.File, io: Io, info: *Info, options: SnapshotCreateOptions) CreateSnapshotError!void {
    try ensureWritableImage(info.*);
    if (options.id.len > std.math.maxInt(u16)) return error.SnapshotIdTooLong;
    if (options.name.len > std.math.maxInt(u16)) return error.SnapshotNameTooLong;

    var dirty_marked = false;
    var ok = false;
    if (info.version >= 3) {
        try setDirtyState(file, io, info, true);
        dirty_marked = true;
    }
    defer if (dirty_marked and ok) setDirtyState(file, io, info, false) catch {};

    const l1_clusters = tableClusterCount(@as(u64, info.l1_size) * 8, info.cluster_size);
    const snapshot_l1_offset = try allocateContiguousMetadataClustersAtEnd(file, io, info, l1_clusters);
    try copyRange(file, io, info.l1_table_offset, snapshot_l1_offset, @as(u64, info.l1_size) * 8);

    try incrementReferencedClustersForL1(file, io, info.*, snapshot_l1_offset, info.l1_size);

    const old_table_bytes_len = try snapshotTableByteLen(file, io, info.*);
    const old_table = try std.heap.page_allocator.alloc(u8, @intCast(old_table_bytes_len));
    defer std.heap.page_allocator.free(old_table);
    if (old_table_bytes_len != 0) {
        _ = try file.readPositionalAll(io, old_table, info.snapshots_offset);
    }

    var snapshot_bytes = std.array_list.Managed(u8).init(std.heap.page_allocator);
    defer snapshot_bytes.deinit();
    if (old_table_bytes_len != 0) try snapshot_bytes.appendSlice(old_table);
    try appendSnapshotEntry(&snapshot_bytes, .{
        .l1_table_offset = snapshot_l1_offset,
        .id = options.id,
        .name = options.name,
        .timestamp_seconds = options.timestamp_seconds,
        .timestamp_nanoseconds = options.timestamp_nanoseconds,
        .vm_clock_nanoseconds = options.vm_clock_nanoseconds,
        .vm_state_size = options.vm_state_size,
        .virtual_size = info.virtual_size,
        .icount = options.icount,
    });

    const old_snapshot_table_offset = info.snapshots_offset;
    const old_snapshot_table_clusters = snapshotTableClusterCount(info.*, old_table_bytes_len);

    const new_snapshot_table_clusters = tableClusterCount(snapshot_bytes.items.len, info.cluster_size);
    const new_snapshot_table_offset = try allocateContiguousMetadataClustersAtEnd(file, io, info, new_snapshot_table_clusters);
    try file.writePositionalAll(io, snapshot_bytes.items, new_snapshot_table_offset);

    try writeHeaderU32Field(file, io, 60, info.snapshot_count + 1);
    try writeHeaderU64Field(file, io, 64, new_snapshot_table_offset);
    info.snapshot_count += 1;
    info.snapshots_offset = new_snapshot_table_offset;

    if (old_snapshot_table_clusters != 0 and isAligned(old_snapshot_table_offset, info.cluster_size) and old_snapshot_table_offset >= info.cluster_size) {
        try setClusterRangeRefcount(file, io, info.*, old_snapshot_table_offset / info.cluster_size, old_snapshot_table_clusters, 0);
    }

    ok = true;
}

fn ensureWritableImage(info: Info) error{
    ImageMarkedDirty,
    ImageMarkedCorrupt,
    SnapshotsNotSupported,
    SnapshotViewNotWritable,
    ExternalDataFileNotSupported,
    ExtendedL2NotSupported,
    UnsupportedRefcountOrderForWrite,
}!void {
    if (info.incompatible_features & incompatible_dirty != 0) return error.ImageMarkedDirty;
    if (info.incompatible_features & incompatible_corrupt != 0) return error.ImageMarkedCorrupt;
    if (info.l1_table_offset != info.active_l1_table_offset) return error.SnapshotViewNotWritable;
    if (info.data_file_len != 0) return error.ExternalDataFileNotSupported;
    if (isExtendedL2(info)) return error.ExtendedL2NotSupported;
    if (info.refcount_order != default_refcount_order) return error.UnsupportedRefcountOrderForWrite;
}

fn incrementReferencedClustersForL1(file: Io.File, io: Io, info: Info, l1_table_offset: u64, l1_size: u32) CreateSnapshotError!void {
    const guest_clusters = divCeil(info.virtual_size, info.cluster_size);
    var l1_index: u64 = 0;
    while (l1_index < l1_size) : (l1_index += 1) {
        const l2_table_entry = try readU64(file, io, l1_table_offset + l1_index * 8);
        const l2_table_offset = l2_table_entry & host_offset_mask;
        if (l2_table_offset == 0) continue;
        if (!isAligned(l2_table_offset, info.cluster_size) or l2_table_offset < info.cluster_size or l2_table_offset + info.cluster_size > info.file_size) {
            return error.InvalidL1Entry;
        }
        try adjustRefcountAtOffset(file, io, info, l2_table_offset, 1);

        var l2_index: u64 = 0;
        while (l2_index < info.l2_entries) : (l2_index += 1) {
            const guest_cluster_index = l1_index * info.l2_entries + l2_index;
            if (guest_cluster_index >= guest_clusters) break;
            const l2_entry_offset = l2_table_offset + l2_index * l2EntrySizeBytes(info.incompatible_features);
            const l2_entry = try readU64(file, io, l2_entry_offset);
            try adjustL2EntryRefcounts(file, io, info, guest_cluster_index, l2_entry, 1);
        }
    }
}

fn setDirtyState(file: Io.File, io: Io, info: *Info, dirty: bool) Io.File.WritePositionalError!void {
    if (info.version < 3) return;
    if (dirty) {
        info.incompatible_features |= incompatible_dirty;
    } else {
        info.incompatible_features &= ~incompatible_dirty;
    }
    try writeHeaderU64Field(file, io, 72, info.incompatible_features);
}

fn expectClusterRefcountNonZero(file: Io.File, io: Io, info: Info, cluster_index: u64) CheckError!void {
    if (try readRefcountByClusterIndex(file, io, info, cluster_index) == 0) {
        return error.ReferencedClusterHasZeroRefcount;
    }
}

fn setClusterRangeRefcountExpected(file: Io.File, io: Io, info: Info, start_cluster_index: u64, cluster_count: u32) CheckError!void {
    var i: u32 = 0;
    while (i < cluster_count) : (i += 1) {
        try expectClusterRefcountNonZero(file, io, info, start_cluster_index + i);
    }
}

fn ensureL2TableWritable(file: Io.File, io: Io, info: *Info, guest_cluster_index: u64) PwriteError!u64 {
    const l1_index = guest_cluster_index / info.l2_entries;
    if (l1_index >= info.l1_size) return error.WritePastEndOfImage;

    const l1_entry_offset = info.l1_table_offset + l1_index * 8;
    const l1_entry = try readU64(file, io, l1_entry_offset);
    const l2_table_offset = l1_entry & host_offset_mask;
    if (l2_table_offset == 0) {
        const new_table_offset = try allocateCluster(file, io, info);
        try writeU64(file, io, l1_entry_offset, new_table_offset | copied_mask);
        return new_table_offset;
    }
    if (!isAligned(l2_table_offset, info.cluster_size) or l2_table_offset < info.cluster_size or l2_table_offset + info.cluster_size > info.file_size) {
        return error.InvalidL1Entry;
    }

    const refcount = try readRefcountAtOffset(file, io, info.*, l2_table_offset);
    if (refcount != 1) {
        const new_table_offset = try allocateCluster(file, io, info);
        try copyRange(file, io, l2_table_offset, new_table_offset, info.cluster_size);
        try adjustRefcountAtOffset(file, io, info.*, l2_table_offset, -1);
        try writeU64(file, io, l1_entry_offset, new_table_offset | copied_mask);
        return new_table_offset;
    }
    if ((l1_entry & copied_mask) == 0) {
        try writeU64(file, io, l1_entry_offset, l2_table_offset | copied_mask);
    }
    return l2_table_offset;
}

fn replaceClusterWithCOWCopy(file: Io.File, io: Io, info: *Info, guest_cluster_index: u64, entry_offset: u64, old_l2_entry: u64) PwriteError!u64 {
    const new_cluster_offset = try allocateCluster(file, io, info);
    try copyGuestVisibleCluster(file, io, info.*, guest_cluster_index, new_cluster_offset);
    try writeU64(file, io, entry_offset, new_cluster_offset | copied_mask);
    try adjustL2EntryRefcounts(file, io, info.*, guest_cluster_index, old_l2_entry, -1);
    return new_cluster_offset;
}

fn ensureDataClusterWritable(file: Io.File, io: Io, info: *Info, guest_cluster_index: u64, l2_table_offset: u64, l2_index: u64) PwriteError!u64 {
    const entry_offset = l2_table_offset + l2_index * 8;
    const l2_entry = try readU64(file, io, entry_offset);
    if (l2_entry & compressed_mask != 0) {
        return try replaceClusterWithCOWCopy(file, io, info, guest_cluster_index, entry_offset, l2_entry);
    }

    const host_cluster_offset = l2_entry & host_offset_mask;
    if (host_cluster_offset != 0 and (!isAligned(host_cluster_offset, info.cluster_size) or host_cluster_offset < info.cluster_size or host_cluster_offset + info.cluster_size > info.file_size)) {
        return error.InvalidL2Entry;
    }
    if (host_cluster_offset == 0) {
        return try replaceClusterWithCOWCopy(file, io, info, guest_cluster_index, entry_offset, l2_entry);
    }

    const refcount = try readRefcountAtOffset(file, io, info.*, host_cluster_offset);
    if (refcount != 1) {
        return try replaceClusterWithCOWCopy(file, io, info, guest_cluster_index, entry_offset, l2_entry);
    }
    if ((l2_entry & zero_mask) != 0) {
        try zeroRange(file, io, host_cluster_offset, info.cluster_size);
    }
    if ((l2_entry & copied_mask) == 0 or (l2_entry & zero_mask) != 0) {
        try writeU64(file, io, entry_offset, host_cluster_offset | copied_mask);
    }
    return host_cluster_offset;
}

fn copyGuestVisibleCluster(file: Io.File, io: Io, info: Info, guest_cluster_index: u64, dst_cluster_offset: u64) PwriteError!void {
    const cluster = try std.heap.page_allocator.alloc(u8, @intCast(info.cluster_size));
    defer std.heap.page_allocator.free(cluster);

    const guest_offset = guest_cluster_index * info.cluster_size;
    const got = try pread(file, io, info, cluster, guest_offset);
    if (got < cluster.len) @memset(cluster[got..], 0);
    try file.writePositionalAll(io, cluster, dst_cluster_offset);
}

fn ensureRefcountCapacity(file: Io.File, io: Io, info: *Info, layout: Layout) ResizeError!void {
    if (layout.refcount_block_count <= info.refcount_block_count and layout.refcount_table_clusters <= info.refcount_table_clusters) return;
    try rebuildRefcountStructure(file, io, info, layout.refcount_table_clusters, layout.refcount_block_count);
}

fn rebuildRefcountStructure(file: Io.File, io: Io, info: *Info, new_table_clusters: u32, new_block_count: u32) (Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || error{MissingRefcountBlock})!void {
    const old_info = info.*;
    const old_cluster_count = divCeil(old_info.file_size, old_info.cluster_size);
    const new_table_offset = std.mem.alignForward(u64, old_info.file_size, old_info.cluster_size);
    const new_blocks_offset = new_table_offset + @as(u64, new_table_clusters) * old_info.cluster_size;
    const new_file_size = new_blocks_offset + @as(u64, new_block_count) * old_info.cluster_size;

    try file.setLength(io, new_file_size);
    try zeroRange(file, io, new_table_offset, new_file_size - new_table_offset);

    var block_index: u32 = 0;
    while (block_index < new_block_count) : (block_index += 1) {
        const block_offset = new_blocks_offset + @as(u64, block_index) * old_info.cluster_size;
        try writeRefcountTableEntry(file, io, new_table_offset, block_index, block_offset);
    }

    var new_info = old_info;
    new_info.file_size = new_file_size;
    new_info.refcount_table_offset = new_table_offset;
    new_info.refcount_table_clusters = new_table_clusters;
    new_info.refcount_table_capacity_blocks = @as(u64, new_table_clusters) * new_info.cluster_size / 8;
    new_info.refcount_block_count = new_block_count;

    var cluster_index: u64 = 0;
    while (cluster_index < old_cluster_count) : (cluster_index += 1) {
        if (try readRefcountByClusterIndex(file, io, old_info, cluster_index) != 0) {
            try writeRefcountByClusterIndex(file, io, new_info, cluster_index, 1);
        }
    }

    try setClusterRangeRefcount(file, io, new_info, new_table_offset / new_info.cluster_size, new_table_clusters, 1);
    try setClusterRangeRefcount(file, io, new_info, new_blocks_offset / new_info.cluster_size, new_block_count, 1);
    try setClusterRangeRefcount(file, io, new_info, old_info.refcount_table_offset / old_info.cluster_size, old_info.refcount_table_clusters, 0);

    var old_block_index: u32 = 0;
    while (old_block_index < old_info.refcount_block_count) : (old_block_index += 1) {
        const old_block_offset = try readU64(file, io, old_info.refcount_table_offset + @as(u64, old_block_index) * 8);
        if (old_block_offset == 0) continue;
        try writeRefcountByClusterIndex(file, io, new_info, old_block_offset / old_info.cluster_size, 0);
    }

    try writeHeaderU64Field(file, io, 48, new_table_offset);
    try writeHeaderU32Field(file, io, 56, new_table_clusters);
    info.* = new_info;
}

fn ensureL1Capacity(file: Io.File, io: Io, info: *Info, new_l1_size: u32, new_l1_clusters: u32) ResizeError!void {
    if (new_l1_size <= info.l1_size) return;

    const old_l1_clusters = tableClusterCount(@as(u64, info.l1_size) * 8, info.cluster_size);
    if (new_l1_clusters <= old_l1_clusters) {
        const old_entries_bytes = @as(u64, info.l1_size) * 8;
        const new_entries_bytes = @as(u64, new_l1_size - info.l1_size) * 8;
        try zeroRange(file, io, info.l1_table_offset + old_entries_bytes, new_entries_bytes);
        try writeHeaderU32Field(file, io, 36, new_l1_size);
        info.l1_size = new_l1_size;
        return;
    }

    const new_l1_offset = try allocateContiguousMetadataClustersAtEnd(file, io, info, new_l1_clusters);
    try copyRange(file, io, info.l1_table_offset, new_l1_offset, @as(u64, info.l1_size) * 8);

    const old_l1_offset = info.l1_table_offset;
    try writeHeaderU32Field(file, io, 36, new_l1_size);
    try writeHeaderU64Field(file, io, 40, new_l1_offset);
    info.l1_size = new_l1_size;
    info.l1_table_offset = new_l1_offset;
    info.active_l1_table_offset = new_l1_offset;

    try setClusterRangeRefcount(file, io, info.*, old_l1_offset / info.cluster_size, old_l1_clusters, 0);
}

fn allocateCluster(file: Io.File, io: Io, info: *Info) PwriteError!u64 {
    var existing_clusters = divCeil(info.file_size, info.cluster_size);
    var cluster_index: u64 = 0;
    while (cluster_index < existing_clusters) : (cluster_index += 1) {
        if (try readRefcountByClusterIndex(file, io, info.*, cluster_index) == 0) {
            try writeRefcountByClusterIndex(file, io, info.*, cluster_index, 1);
            try zeroRange(file, io, cluster_index * info.cluster_size, info.cluster_size);
            return cluster_index * info.cluster_size;
        }
    }

    while (existing_clusters >= maxAddressableHostClusters(info.*)) {
        try ensureRefcountBlocksForClusterIndex(file, io, info, existing_clusters);
        existing_clusters = divCeil(info.file_size, info.cluster_size);
    }
    const cluster_offset = std.mem.alignForward(u64, info.file_size, info.cluster_size);
    const new_file_size = cluster_offset + info.cluster_size;
    try file.setLength(io, new_file_size);
    info.file_size = new_file_size;
    try writeRefcountByClusterIndex(file, io, info.*, existing_clusters, 1);
    try zeroRange(file, io, cluster_offset, info.cluster_size);
    return cluster_offset;
}

fn allocateContiguousMetadataClustersAtEnd(file: Io.File, io: Io, info: *Info, cluster_count: u32) (Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || error{ MissingRefcountBlock, RefcountTableTooSmall })!u64 {
    if (cluster_count == 0) return info.file_size;

    while (true) {
        const start_index = divCeil(info.file_size, info.cluster_size);
        const end_index = start_index + cluster_count;
        if (end_index <= maxAddressableHostClusters(info.*)) break;
        try ensureRefcountBlocksForClusterIndex(file, io, info, end_index - 1);
        if (end_index > maxAddressableHostClusters(info.*)) return error.RefcountTableTooSmall;
    }

    const start_index = divCeil(info.file_size, info.cluster_size);
    const start_offset = std.mem.alignForward(u64, info.file_size, info.cluster_size);
    const byte_len = @as(u64, cluster_count) * info.cluster_size;
    const new_file_size = start_offset + byte_len;
    try file.setLength(io, new_file_size);
    info.file_size = new_file_size;
    try zeroRange(file, io, start_offset, byte_len);

    var i: u32 = 0;
    while (i < cluster_count) : (i += 1) {
        try writeRefcountByClusterIndex(file, io, info.*, start_index + i, 1);
    }
    return start_offset;
}

fn ensureRefcountBlocksForClusterIndex(file: Io.File, io: Io, info: *Info, cluster_index: u64) (Io.File.ReadPositionalError || Io.File.WritePositionalError || Io.File.SetLengthError || error{ MissingRefcountBlock, RefcountTableTooSmall })!void {
    const needed_blocks = divCeil(cluster_index + 1, refcountBlockEntries(info.*));
    if (needed_blocks <= info.refcount_block_count) return;

    var new_table_clusters = info.refcount_table_clusters;
    if (needed_blocks > info.refcount_table_capacity_blocks) {
        const table_bytes = std.math.mul(u64, needed_blocks, 8) catch return error.RefcountTableTooSmall;
        new_table_clusters = tableClusterCount(table_bytes, info.cluster_size);
    }

    try rebuildRefcountStructure(file, io, info, new_table_clusters, @intCast(needed_blocks));
}

fn setClusterRangeRefcount(file: Io.File, io: Io, info: Info, start_cluster_index: u64, cluster_count: u32, value: u16) (Io.File.ReadPositionalError || Io.File.WritePositionalError || error{MissingRefcountBlock})!void {
    var i: u32 = 0;
    while (i < cluster_count) : (i += 1) {
        try writeRefcountByClusterIndex(file, io, info, start_cluster_index + i, value);
    }
}

fn scanRefcountBlockCount(file: Io.File, io: Io, refcount_table_offset: u64, refcount_table_clusters: u32, cluster_size: u64, file_size: u64) (Io.File.ReadPositionalError || error{InvalidRefcountBlock})!u32 {
    const entry_count = @as(u64, refcount_table_clusters) * cluster_size / 8;
    var last_nonzero: u64 = 0;
    var saw_nonzero = false;
    var index: u64 = 0;
    while (index < entry_count) : (index += 1) {
        const entry = try readU64(file, io, refcount_table_offset + index * 8);
        if (entry != 0) {
            if (!tableFits(file_size, entry, cluster_size, cluster_size, cluster_size)) return error.InvalidRefcountBlock;
            saw_nonzero = true;
            last_nonzero = index + 1;
        }
    }
    if (!saw_nonzero) return 0;
    return std.math.cast(u32, last_nonzero) orelse std.math.maxInt(u32);
}

fn readRefcountAtOffset(file: Io.File, io: Io, info: Info, offset: u64) (Io.File.ReadPositionalError || error{MissingRefcountBlock})!u16 {
    return readRefcountByClusterIndex(file, io, info, offset / info.cluster_size);
}

fn adjustRefcountAtOffset(file: Io.File, io: Io, info: Info, offset: u64, delta: i32) (Io.File.ReadPositionalError || Io.File.WritePositionalError || error{MissingRefcountBlock})!void {
    const cluster_index = offset / info.cluster_size;
    const current = try readRefcountByClusterIndex(file, io, info, cluster_index);
    const next = @as(i32, current) + delta;
    std.debug.assert(next >= 0 and next <= std.math.maxInt(u16));
    try writeRefcountByClusterIndex(file, io, info, cluster_index, @intCast(next));
}

fn readRefcountByClusterIndex(file: Io.File, io: Io, info: Info, cluster_index: u64) (Io.File.ReadPositionalError || error{MissingRefcountBlock})!u16 {
    const table_index = cluster_index / refcountBlockEntries(info);
    if (table_index >= info.refcount_block_count) return 0;

    const block_offset = try readU64(file, io, info.refcount_table_offset + table_index * 8);
    if (block_offset == 0) return 0;
    if (!isAligned(block_offset, info.cluster_size)) return error.MissingRefcountBlock;

    const block_index = cluster_index % refcountBlockEntries(info);
    var buf: [2]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, block_offset + block_index * 2);
    return std.mem.readInt(u16, &buf, .big);
}

fn writeRefcountByClusterIndex(file: Io.File, io: Io, info: Info, cluster_index: u64, value: u16) (Io.File.ReadPositionalError || Io.File.WritePositionalError || error{MissingRefcountBlock})!void {
    const table_index = cluster_index / refcountBlockEntries(info);
    if (table_index >= info.refcount_block_count) return error.MissingRefcountBlock;

    const block_offset = try readU64(file, io, info.refcount_table_offset + table_index * 8);
    if (block_offset == 0 or !isAligned(block_offset, info.cluster_size)) return error.MissingRefcountBlock;

    const block_index = cluster_index % refcountBlockEntries(info);
    var buf: [2]u8 = undefined;
    std.mem.writeInt(u16, &buf, value, .big);
    try file.writePositionalAll(io, &buf, block_offset + block_index * 2);
}

fn adjustL2EntryRefcounts(file: Io.File, io: Io, info: Info, guest_cluster_index: u64, l2_entry: u64, delta: i32) (LookupError || Io.File.ReadPositionalError || Io.File.WritePositionalError || error{MissingRefcountBlock})!void {
    if (l2_entry & compressed_mask != 0) {
        const mapping = try compressedClusterMapping(info, l2_entry);
        const host_offset = mapping.host_offset.?;
        const start_cluster_index = hostOffsetClusterIndex(host_offset, info.cluster_size);
        try adjustRefcountAtOffset(file, io, info, start_cluster_index * info.cluster_size, delta);
        const end_cluster_index = hostOffsetClusterIndex(host_offset + mapping.compressed_byte_len - 1, info.cluster_size);
        if (end_cluster_index != start_cluster_index) {
            try adjustRefcountAtOffset(file, io, info, end_cluster_index * info.cluster_size, delta);
        }
        return;
    }

    if (!hasDataHostCluster(info, guest_cluster_index, l2_entry)) return;

    if (usesExternalDataFile(info)) return;

    const host_cluster_offset = l2_entry & host_offset_mask;
    if (!validDataHostClusterOffset(info, guest_cluster_index, host_cluster_offset)) return error.InvalidL2Entry;
    try adjustRefcountAtOffset(file, io, info, host_cluster_offset, delta);
}

fn writeInitialHeader(file: Io.File, io: Io, info: Info) Io.File.WritePositionalError!void {
    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], info.version, .big);
    std.mem.writeInt(u32, header[20..24], info.cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], info.virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], info.l1_size, .big);
    std.mem.writeInt(u64, header[40..48], info.l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], info.refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], info.refcount_table_clusters, .big);
    std.mem.writeInt(u64, header[72..80], info.incompatible_features, .big);
    std.mem.writeInt(u32, header[96..100], info.refcount_order, .big);
    std.mem.writeInt(u32, header[100..104], info.header_length, .big);
    try file.writePositionalAll(io, &header, 0);
}

fn writeHeaderU32Field(file: Io.File, io: Io, offset: u64, value: u32) Io.File.WritePositionalError!void {
    var buf: [4]u8 = undefined;
    std.mem.writeInt(u32, &buf, value, .big);
    try file.writePositionalAll(io, &buf, offset);
}

fn writeHeaderU64Field(file: Io.File, io: Io, offset: u64, value: u64) Io.File.WritePositionalError!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    try file.writePositionalAll(io, &buf, offset);
}

fn writeRefcountTableEntry(file: Io.File, io: Io, refcount_table_offset: u64, index: u32, block_offset: u64) Io.File.WritePositionalError!void {
    try writeU64(file, io, refcount_table_offset + @as(u64, index) * 8, block_offset);
}

fn copyRange(file: Io.File, io: Io, src_offset: u64, dst_offset: u64, byte_length: u64) (Io.File.ReadPositionalError || Io.File.WritePositionalError)!void {
    var buf: [4096]u8 = undefined;
    var copied: u64 = 0;
    while (copied < byte_length) {
        const n: usize = @intCast(@min(byte_length - copied, buf.len));
        _ = try file.readPositionalAll(io, buf[0..n], src_offset + copied);
        try file.writePositionalAll(io, buf[0..n], dst_offset + copied);
        copied += n;
    }
}

fn zeroRange(file: Io.File, io: Io, offset: u64, byte_length: u64) Io.File.WritePositionalError!void {
    const zeroes: [4096]u8 = [_]u8{0} ** 4096;
    var written: u64 = 0;
    while (written < byte_length) {
        const n: usize = @intCast(@min(byte_length - written, zeroes.len));
        try file.writePositionalAll(io, zeroes[0..n], offset + written);
        written += n;
    }
}

fn tableClusterCount(byte_length: u64, cluster_size: u64) u32 {
    return @intCast(@max(@as(u64, 1), divCeil(byte_length, cluster_size)));
}

fn maxAddressableHostClusters(info: Info) u64 {
    return @as(u64, info.refcount_block_count) * refcountBlockEntries(info);
}

fn refcountBlockEntries(info: Info) u64 {
    return info.cluster_size / 2;
}

fn tableFits(file_size: u64, offset: u64, byte_length: u64, alignment: u64, minimum_offset: u64) bool {
    if (!isAligned(offset, alignment) or offset < minimum_offset) return false;
    const end = std.math.add(u64, offset, byte_length) catch return false;
    return end <= file_size;
}

fn writeU64(file: Io.File, io: Io, offset: u64, value: u64) Io.File.WritePositionalError!void {
    var buf: [8]u8 = undefined;
    std.mem.writeInt(u64, &buf, value, .big);
    try file.writePositionalAll(io, &buf, offset);
}

fn readU64(file: Io.File, io: Io, offset: u64) Io.File.ReadPositionalError!u64 {
    var buf: [8]u8 = undefined;
    _ = try file.readPositionalAll(io, &buf, offset);
    return std.mem.readInt(u64, &buf, .big);
}

fn isAligned(value: u64, alignment: u64) bool {
    return alignment != 0 and value % alignment == 0;
}

fn divCeil(numerator: u64, denominator: u64) u64 {
    if (numerator == 0) return 0;
    return std.math.divCeil(u64, numerator, denominator) catch unreachable;
}

test "open parses a minimal qcow2 header" {
    const io = std.testing.io;
    const path = "test-qcow2-open.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    _ = try writeTestFixture(io, path, .{});

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    try std.testing.expectEqual(@as(u32, 3), info.version);
    try std.testing.expectEqual(@as(u32, 12), info.cluster_bits);
    try std.testing.expectEqual(@as(u64, 4096), info.cluster_size);
    try std.testing.expectEqual(@as(u64, 3 * 4096), info.virtual_size);
    try std.testing.expectEqual(@as(u32, 1), info.l1_size);
    try std.testing.expectEqual(@as(u64, 3 * 4096), info.l1_table_offset);
    try std.testing.expectEqual(@as(u64, 4096 / 8), info.l2_entries);
    try std.testing.expectEqual(@as(u64, 4096), info.refcount_table_offset);
    try std.testing.expectEqual(@as(u32, 1), info.refcount_table_clusters);
}

test "lookupGuestCluster maps allocated and sparse clusters" {
    const io = std.testing.io;
    const path = "test-qcow2-lookup.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const fixture = try writeTestFixture(io, path, .{});

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);

    const cluster0 = try lookupGuestCluster(file, io, info, 0);
    try std.testing.expectEqual(ClusterKind.standard, cluster0.kind);
    try std.testing.expectEqual(@as(?u64, fixture.data0_offset), cluster0.host_offset);
    try std.testing.expect(cluster0.physically_allocated);

    const cluster1 = try lookupGuestCluster(file, io, info, 1);
    try std.testing.expectEqual(ClusterKind.backing, cluster1.kind);
    try std.testing.expectEqual(@as(?u64, null), cluster1.host_offset);
    try std.testing.expect(!cluster1.physically_allocated);

    const cluster2 = try lookupGuestCluster(file, io, info, 2);
    try std.testing.expectEqual(ClusterKind.standard, cluster2.kind);
    try std.testing.expectEqual(@as(?u64, fixture.data2_offset), cluster2.host_offset);
    try std.testing.expect(cluster2.physically_allocated);
}

test "pread zero-fills sparse clusters" {
    const io = std.testing.io;
    const path = "test-qcow2-pread.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    _ = try writeTestFixture(io, path, .{});

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);

    var payload: [13]u8 = undefined;
    const got = try pread(file, io, info, &payload, 0);
    try std.testing.expectEqual(payload.len, got);
    try std.testing.expectEqualSlices(u8, "QCOW2BLOCK000", &payload);

    var zeroes: [64]u8 = undefined;
    _ = try pread(file, io, info, &zeroes, info.cluster_size);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &zeroes);
}

test "openAtPath resolves recursive backing files" {
    const io = std.testing.io;
    const base_path = "test-qcow2-backing-base.qcow2";
    const mid_path = "test-qcow2-backing-mid.qcow2";
    const root_path = "test-qcow2-backing-root.qcow2";
    defer Io.Dir.cwd().deleteFile(io, base_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, mid_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, root_path) catch {};

    const base = try writeSingleClusterFixture(io, base_path, .{
        .guest_cluster_index = 0,
        .payload = "BASE-CLUSTER-0",
        .payload_offset = 32,
    });
    _ = try writeSingleClusterFixture(io, mid_path, .{
        .backing_file = base_path,
        .guest_cluster_index = 1,
        .payload = "MID-CLUSTER-1",
        .payload_offset = 64,
    });
    _ = try writeSingleClusterFixture(io, root_path, .{
        .backing_file = mid_path,
        .guest_cluster_index = 2,
        .payload = "ROOT-CLUSTER-2",
        .payload_offset = 96,
    });

    const file = try Io.Dir.cwd().openFile(io, root_path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try openAtPath(io, file, root_path);
    try std.testing.expectEqual(@as(u8, 2), info.backing_depth);

    var base_buf: [14]u8 = undefined;
    _ = try pread(file, io, info, &base_buf, 32);
    try std.testing.expectEqualSlices(u8, "BASE-CLUSTER-0", &base_buf);

    var mid_buf: [13]u8 = undefined;
    _ = try pread(file, io, info, &mid_buf, base.cluster_size + 64);
    try std.testing.expectEqualSlices(u8, "MID-CLUSTER-1", &mid_buf);

    var root_buf: [14]u8 = undefined;
    _ = try pread(file, io, info, &root_buf, 2 * base.cluster_size + 96);
    try std.testing.expectEqualSlices(u8, "ROOT-CLUSTER-2", &root_buf);
}

test "openStandalone rejects a backing path without opening it" {
    const io = std.testing.io;
    const path = "test-qcow2-standalone-reject.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    _ = try writeSingleClusterFixture(io, path, .{
        .backing_file = "/path/that/must/not/be/opened",
        .guest_cluster_index = 0,
        .payload = "standalone",
    });
    const file = try Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
    });
    defer file.close(io);
    try std.testing.expectError(
        error.BackingFileNotSupported,
        openStandalone(io, file),
    );
}

test "pread zero-fills beyond a shorter backing image" {
    const io = std.testing.io;
    const base_path = "test-qcow2-short-backing-base.qcow2";
    const overlay_path = "test-qcow2-short-backing-overlay.qcow2";
    defer Io.Dir.cwd().deleteFile(io, base_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, overlay_path) catch {};

    _ = try writeSingleClusterFixture(io, base_path, .{
        .guest_cluster_index = 0,
        .payload = "BASE",
        .virtual_cluster_count = 1,
    });
    const overlay_fixture = try writeSingleClusterFixture(io, overlay_path, .{
        .backing_file = base_path,
        .guest_cluster_index = 2,
        .payload = "OVERLAY",
    });

    const overlay_file = try Io.Dir.cwd().openFile(io, overlay_path, .{ .mode = .read_only });
    defer overlay_file.close(io);
    const overlay = try openAtPath(io, overlay_file, overlay_path);

    var inherited: [64]u8 = [_]u8{0xaa} ** 64;
    const got = try pread(overlay_file, io, overlay, &inherited, overlay_fixture.cluster_size);
    try std.testing.expectEqual(inherited.len, got);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** inherited.len), &inherited);
}

test "pwrite copy-on-write preserves backing-file contents" {
    const io = std.testing.io;
    const base_path = "test-qcow2-backing-cow-base.qcow2";
    const overlay_path = "test-qcow2-backing-cow-overlay.qcow2";
    defer Io.Dir.cwd().deleteFile(io, base_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, overlay_path) catch {};

    const base = try writeTestFixture(io, base_path, .{});
    _ = try writeSingleClusterFixture(io, overlay_path, .{
        .backing_file = base_path,
        .guest_cluster_index = 1,
        .payload = "OVERLAY-CLUSTER",
        .payload_offset = 24,
    });

    const overlay_file = try Io.Dir.cwd().openFile(io, overlay_path, .{ .mode = .read_write });
    defer overlay_file.close(io);

    var overlay = try openAtPath(io, overlay_file, overlay_path);
    var inherited_before: [13]u8 = undefined;
    _ = try pread(overlay_file, io, overlay, &inherited_before, 0);
    try std.testing.expectEqualSlices(u8, "QCOW2BLOCK000", &inherited_before);

    try pwrite(overlay_file, io, &overlay, "COW", 5);

    var inherited_after: [13]u8 = undefined;
    _ = try pread(overlay_file, io, overlay, &inherited_after, 0);
    try std.testing.expectEqualSlices(u8, "QCOW2COWCK000", &inherited_after);

    var overlay_buf: [15]u8 = undefined;
    _ = try pread(overlay_file, io, overlay, &overlay_buf, base.cluster_size + 24);
    try std.testing.expectEqualSlices(u8, "OVERLAY-CLUSTER", &overlay_buf);

    var base_cluster2: [13]u8 = undefined;
    _ = try pread(overlay_file, io, overlay, &base_cluster2, 2 * base.cluster_size + 32);
    try std.testing.expectEqualSlices(u8, "QCOW2BLOCK222", &base_cluster2);

    const base_file = try Io.Dir.cwd().openFile(io, base_path, .{ .mode = .read_write });
    defer base_file.close(io);
    const base_info = try open(io, base_file);

    var base_unchanged: [13]u8 = undefined;
    _ = try pread(base_file, io, base_info, &base_unchanged, 0);
    try std.testing.expectEqualSlices(u8, "QCOW2BLOCK000", &base_unchanged);
}

test "pread inflates deflate-compressed clusters" {
    const io = std.testing.io;
    const path = "test-qcow2-compressed.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const cluster_size = try writeCompressedFixture(io, path);
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    const mapping = try lookupGuestCluster(file, io, info, 0);
    try std.testing.expectEqual(ClusterKind.compressed, mapping.kind);

    var buf: [256]u8 = undefined;
    _ = try pread(file, io, info, &buf, 512);
    try std.testing.expectEqualSlices(u8, &([_]u8{'A'} ** 256), &buf);

    var tail: [64]u8 = undefined;
    _ = try pread(file, io, info, &tail, cluster_size - tail.len);
    try std.testing.expectEqualSlices(u8, &([_]u8{'A'} ** 64), &tail);
}

test "pwrite inflates compressed clusters into standard data clusters" {
    const io = std.testing.io;
    const path = "test-qcow2-compressed-write.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    _ = try writeCompressedFixture(io, path);
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    var info = try open(io, file);
    try pwrite(file, io, &info, "BLOB", 1024);

    const mapping = try lookupGuestCluster(file, io, info, 0);
    try std.testing.expectEqual(ClusterKind.standard, mapping.kind);

    var buf: [16]u8 = undefined;
    _ = try pread(file, io, info, &buf, 1016);
    var expected = [_]u8{'A'} ** 16;
    @memcpy(expected[8..12], "BLOB");
    try std.testing.expectEqualSlices(u8, &expected, &buf);
}

test "pread decompresses zstd-compressed clusters" {
    const io = std.testing.io;
    const path = "test-qcow2-zstd-compressed.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const cluster_size = try writeZstdCompressedFixture(io, path);
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    try std.testing.expectEqual(@as(u8, 1), info.compression_type);
    const mapping = try lookupGuestCluster(file, io, info, 0);
    try std.testing.expectEqual(ClusterKind.compressed, mapping.kind);

    var buf: [256]u8 = undefined;
    _ = try pread(file, io, info, &buf, 512);
    try std.testing.expectEqualSlices(u8, &([_]u8{'A'} ** 256), &buf);

    var tail: [64]u8 = undefined;
    _ = try pread(file, io, info, &tail, cluster_size - tail.len);
    try std.testing.expectEqualSlices(u8, &([_]u8{'A'} ** 64), &tail);
}

test "pwrite decompresses zstd-compressed clusters into standard data clusters" {
    const io = std.testing.io;
    const path = "test-qcow2-zstd-compressed-write.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    _ = try writeZstdCompressedFixture(io, path);
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    var info = try open(io, file);
    try pwrite(file, io, &info, "BLOB", 1024);

    const mapping = try lookupGuestCluster(file, io, info, 0);
    try std.testing.expectEqual(ClusterKind.standard, mapping.kind);

    var buf: [16]u8 = undefined;
    _ = try pread(file, io, info, &buf, 1016);
    var expected = [_]u8{'A'} ** 16;
    @memcpy(expected[8..12], "BLOB");
    try std.testing.expectEqualSlices(u8, &expected, &buf);
}

test "open() rejects an unknown compression_type" {
    const io = std.testing.io;
    const path = "test-qcow2-unknown-compression-type.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    // Reuse the zstd fixture layout, but with an unrecognized compression
    // algorithm ID (2) instead of zstd (1). The data doesn't matter since
    // open() should reject this before any cluster is ever decompressed.
    const uncompressed = [_]u8{'A'} ** 4096;
    const compressed = try zstdCompress(std.testing.allocator, &uncompressed);
    defer std.testing.allocator.free(compressed);
    _ = try writeCompressedClusterFixture(io, path, 2, compressed);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);
    try std.testing.expectError(error.UnsupportedCompressionType, open(io, file));
}

test "listSnapshots enumerates qcow2 snapshot table entries" {
    const io = std.testing.io;
    const path = "test-qcow2-snapshots.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeSnapshotFixture(io, path);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    const snapshots = try listSnapshots(file, io, info, std.testing.allocator);
    defer {
        for (snapshots) |*snapshot| snapshot.deinit(std.testing.allocator);
        std.testing.allocator.free(snapshots);
    }

    try std.testing.expectEqual(@as(usize, 2), snapshots.len);
    try std.testing.expectEqual(@as(u64, 4 * 4096), snapshots[0].l1_table_offset);
    try std.testing.expectEqualStrings("snap-1", snapshots[0].id);
    try std.testing.expectEqualStrings("first snapshot", snapshots[0].name);
    try std.testing.expectEqual(@as(u32, 1_700_000_000), snapshots[0].timestamp_seconds);
    try std.testing.expectEqual(@as(?u64, 3 * 4096), snapshots[0].virtual_size);

    try std.testing.expectEqual(@as(u64, 5 * 4096), snapshots[1].l1_table_offset);
    try std.testing.expectEqualStrings("snap-2", snapshots[1].id);
    try std.testing.expectEqualStrings("second snapshot", snapshots[1].name);
}

test "openSnapshot switches reads to snapshot L1 tables" {
    const io = std.testing.io;
    const path = "test-qcow2-snapshot-read.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeSnapshotFixture(io, path);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    const snapshots = try listSnapshots(file, io, info, std.testing.allocator);
    defer {
        for (snapshots) |*snapshot| snapshot.deinit(std.testing.allocator);
        std.testing.allocator.free(snapshots);
    }

    var active_buf: [14]u8 = undefined;
    _ = try pread(file, io, info, &active_buf, 0);
    try std.testing.expectEqualSlices(u8, "ACTIVE-CLUSTER", &active_buf);

    const first = openSnapshot(info, snapshots[0]);
    var first_buf: [14]u8 = undefined;
    _ = try pread(file, io, first, &first_buf, 0);
    try std.testing.expectEqualSlices(u8, "SNAP-1-CLUSTER", &first_buf);

    const second = openSnapshot(info, snapshots[1]);
    var second_buf: [14]u8 = undefined;
    _ = try pread(file, io, second, &second_buf, 0);
    try std.testing.expectEqualSlices(u8, "SNAP-2-CLUSTER", &second_buf);

    var shared_buf: [13]u8 = undefined;
    _ = try pread(file, io, first, &shared_buf, info.cluster_size + 64);
    try std.testing.expectEqualSlices(u8, "SHARED-CLSTR", shared_buf[0..12]);
}

test "createSnapshot preserves pre-write active state" {
    const io = std.testing.io;
    const path = "test-qcow2-create-snapshot.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var info = try create(io, file, 2 * (1 << default_cluster_bits));
    try pwrite(file, io, &info, "SNAPSHOT-OLD", 0);
    try pwrite(file, io, &info, "SHARED-CLSTR", info.cluster_size + 64);

    try createSnapshot(file, io, &info, .{
        .id = "snap-1",
        .name = "first snapshot",
        .timestamp_seconds = 1_700_000_000,
    });
    try pwrite(file, io, &info, "SNAPSHOT-NEW", 0);

    const reopened = try open(io, file);
    try std.testing.expectEqual(@as(u32, 1), reopened.snapshot_count);

    const snapshots = try listSnapshots(file, io, reopened, std.testing.allocator);
    defer {
        for (snapshots) |*snapshot| snapshot.deinit(std.testing.allocator);
        std.testing.allocator.free(snapshots);
    }

    try std.testing.expectEqual(@as(usize, 1), snapshots.len);
    try std.testing.expectEqualStrings("snap-1", snapshots[0].id);
    try std.testing.expectEqualStrings("first snapshot", snapshots[0].name);
    try std.testing.expect(snapshots[0].l1_table_offset != reopened.l1_table_offset);

    var active_buf: [12]u8 = undefined;
    _ = try pread(file, io, reopened, &active_buf, 0);
    try std.testing.expectEqualSlices(u8, "SNAPSHOT-NEW", &active_buf);

    const snapshot_info = openSnapshot(reopened, snapshots[0]);
    var snapshot_buf: [12]u8 = undefined;
    _ = try pread(file, io, snapshot_info, &snapshot_buf, 0);
    try std.testing.expectEqualSlices(u8, "SNAPSHOT-OLD", &snapshot_buf);

    var shared_snapshot: [12]u8 = undefined;
    _ = try pread(file, io, snapshot_info, &shared_snapshot, reopened.cluster_size + 64);
    try std.testing.expectEqualSlices(u8, "SHARED-CLSTR", &shared_snapshot);

    try check(file, io, reopened);
}

test "openSnapshot views remain read-only for writes" {
    const io = std.testing.io;
    const path = "test-qcow2-snapshot-write-reject.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var info = try create(io, file, 2 * (1 << default_cluster_bits));
    try pwrite(file, io, &info, "SNAPSHOT-OLD", 0);
    try createSnapshot(file, io, &info, .{ .id = "snap-1", .name = "first snapshot" });

    const reopened = try open(io, file);
    const snapshots = try listSnapshots(file, io, reopened, std.testing.allocator);
    defer {
        for (snapshots) |*snapshot| snapshot.deinit(std.testing.allocator);
        std.testing.allocator.free(snapshots);
    }

    var snapshot_info = openSnapshot(reopened, snapshots[0]);
    try std.testing.expectError(error.SnapshotViewNotWritable, pwrite(file, io, &snapshot_info, "NEW", 0));
}

test "openAtPath reads qcow2 external data files" {
    const io = std.testing.io;
    const meta_path = "test-qcow2-external-data.qcow2";
    const data_path = "test-qcow2-external-data.bin";
    defer Io.Dir.cwd().deleteFile(io, meta_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, data_path) catch {};

    const cluster_size = try writeExternalDataFixture(io, meta_path, data_path);

    const file = try Io.Dir.cwd().openFile(io, meta_path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try openAtPath(io, file, meta_path);
    try std.testing.expectEqual(@as(u64, 2), info.data_file_size / cluster_size);

    var head: [12]u8 = undefined;
    _ = try pread(file, io, info, &head, 0);
    try std.testing.expectEqualSlices(u8, "EXT-DATA-000", &head);

    var tail: [12]u8 = undefined;
    _ = try pread(file, io, info, &tail, cluster_size + 32);
    try std.testing.expectEqualSlices(u8, "EXT-DATA-111", &tail);
}

test "pread and mapExtents handle extended L2 entries" {
    const io = std.testing.io;
    const path = "test-qcow2-extl2.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const fixture = try writeExtendedL2Fixture(io, path);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    try std.testing.expectEqual(fixture.cluster_size / 16, info.l2_entries);

    var mixed: [1536]u8 = undefined;
    _ = try pread(file, io, info, &mixed, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{'A'} ** 512), mixed[0..512]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 512), mixed[512..1024]);
    try std.testing.expectEqualSlices(u8, &([_]u8{'B'} ** 512), mixed[1024..1536]);

    const extents = try mapExtents(file, io, info, std.testing.allocator);
    defer std.testing.allocator.free(extents);
    try std.testing.expectEqual(@as(usize, 4), extents.len);
    try std.testing.expectEqual(Extent{ .offset = 0, .length = 512, .allocated = true }, extents[0]);
    try std.testing.expectEqual(Extent{ .offset = 512, .length = 512, .allocated = false }, extents[1]);
    try std.testing.expectEqual(Extent{ .offset = 1024, .length = 512, .allocated = true }, extents[2]);
    try std.testing.expectEqual(Extent{ .offset = 1536, .length = fixture.cluster_size - 1536, .allocated = false }, extents[3]);
}

test "open rejects encrypted qcow2 images" {
    const io = std.testing.io;
    const path = "test-qcow2-encrypted.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    try writeEncryptedFixture(io, path, 1);

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    try std.testing.expectError(error.EncryptionNotSupported, open(io, file));
}

test "check detects referenced clusters with zero refcounts" {
    const io = std.testing.io;
    const path = "test-qcow2-bad-refcount.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const fixture = try writeTestFixture(io, path, .{});

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    try writeRefcountByClusterIndex(file, io, info, fixture.data0_offset / fixture.cluster_size, 0);
    try std.testing.expectError(error.ReferencedClusterHasZeroRefcount, check(file, io, info));
}

test "check reports dirty images" {
    const io = std.testing.io;
    const path = "test-qcow2-dirty.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    _ = try writeTestFixture(io, path, .{ .dirty = true });

    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_write });
    defer file.close(io);

    const info = try open(io, file);
    try std.testing.expectError(error.ImageMarkedDirty, check(file, io, info));
}

test "pwrite zero-fills allocated zero clusters before partial writes" {
    const io = std.testing.io;
    const path = "test-qcow2-zero-cluster-write.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var info = try create(io, file, 2 * (1 << default_cluster_bits));
    try pwrite(file, io, &info, "seed", 0);

    const l1_entry = try readU64(file, io, info.l1_table_offset);
    const l2_offset = l1_entry & host_offset_mask;
    const data_entry_offset = l2_offset;
    const data_offset = (try readU64(file, io, data_entry_offset)) & host_offset_mask;

    const stale = [_]u8{0x7B} ** 64;
    try file.writePositionalAll(io, &stale, data_offset);
    try writeU64(file, io, data_entry_offset, data_offset | copied_mask | zero_mask);

    var zeros_before: [64]u8 = undefined;
    _ = try pread(file, io, info, &zeros_before, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &zeros_before);

    try pwrite(file, io, &info, "hi", 32);

    var buf: [64]u8 = undefined;
    _ = try pread(file, io, info, &buf, 0);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), buf[0..32]);
    try std.testing.expectEqualSlices(u8, "hi", buf[32..34]);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 30), buf[34..64]);
}

test "resize clears newly exposed in-place L1 entries" {
    const io = std.testing.io;
    const path = "test-qcow2-l1-slack.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var info = try create(io, file, 256 * 1024 * 1024);
    try writeU64(file, io, info.l1_table_offset + 8, info.refcount_table_offset | copied_mask);

    try resize(file, io, &info, 1024 * 1024 * 1024);

    var buf: [64]u8 = undefined;
    _ = try pread(file, io, info, &buf, 512 * 1024 * 1024);
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 64), &buf);
}

test "create, write, resize, and validate refcounts" {
    const io = std.testing.io;
    const path = "test-qcow2-write.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const initial_size: u64 = 256 * 1024 * 1024;
    const grown_size: u64 = 1024 * 1024 * 1024;
    const cross_boundary_offset: u64 = 512 * 1024 * 1024 - 96;
    const sparse_offset: u64 = 3 * 65536 + 37;
    const distant_offset: u64 = 768 * 1024 * 1024 + 123;
    const payload0 = "qcow2-direct-0";
    const payload1 = "qcow2-direct-1";
    const payload2 = [_]u8{0x5A} ** 256;

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    var info = try create(io, file, initial_size);
    try pwrite(file, io, &info, payload0, sparse_offset);
    try resize(file, io, &info, grown_size);
    try pwrite(file, io, &info, payload1, distant_offset);
    try pwrite(file, io, &info, &payload2, cross_boundary_offset);

    const reopened = try open(io, file);
    try std.testing.expectEqual(grown_size, reopened.virtual_size);

    var buf0: [payload0.len]u8 = undefined;
    _ = try pread(file, io, reopened, &buf0, sparse_offset);
    try std.testing.expectEqualSlices(u8, payload0, &buf0);

    var buf1: [payload1.len]u8 = undefined;
    _ = try pread(file, io, reopened, &buf1, distant_offset);
    try std.testing.expectEqualSlices(u8, payload1, &buf1);

    var buf2: [payload2.len]u8 = undefined;
    _ = try pread(file, io, reopened, &buf2, cross_boundary_offset);
    try std.testing.expectEqualSlices(u8, &payload2, &buf2);

    try verifyAllocatedClustersMatchRefcounts(file, io, reopened);
}

test "resize grows refcount metadata past a full legacy coverage boundary" {
    const io = std.testing.io;
    const path = "test-qcow2-refcount-grow.qcow2";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);

    try writeFullCoverage4kFixture(file, io);

    var info = try open(io, file);
    const old_virtual_size = info.virtual_size;
    try resize(file, io, &info, old_virtual_size + info.cluster_size);
    try std.testing.expect(info.refcount_block_count > 1);
    try std.testing.expectEqual(@as(u16, 0), try readRefcountByClusterIndex(file, io, info, 1));
    try std.testing.expectEqual(@as(u16, 0), try readRefcountByClusterIndex(file, io, info, 2));

    try pwrite(file, io, &info, "grow", old_virtual_size);
    var buf: [4]u8 = undefined;
    _ = try pread(file, io, info, &buf, old_virtual_size);
    try std.testing.expectEqualSlices(u8, "grow", &buf);
}

const TestFixture = struct {
    cluster_size: u64,
    l1_table_offset: u64,
    l2_table_offset: u64,
    data0_offset: u64,
    data2_offset: u64,
};

const TestFixtureOptions = struct {
    dirty: bool = false,
    corrupt: bool = false,
};

const SingleClusterFixtureOptions = struct {
    backing_file: ?[]const u8 = null,
    guest_cluster_index: u32,
    payload: []const u8,
    payload_offset: u32 = 0,
    virtual_cluster_count: u32 = 3,
};

const SingleClusterFixture = struct {
    cluster_size: u64,
    data_offset: u64,
};

const SnapshotEntrySpec = struct {
    l1_table_offset: u64,
    id: []const u8,
    name: []const u8,
    timestamp_seconds: u32,
    timestamp_nanoseconds: u32,
    vm_clock_nanoseconds: u64,
    vm_state_size: u64,
    virtual_size: u64,
    icount: i64 = -1,
};

const ExtendedL2Fixture = struct {
    cluster_size: u64,
};

fn writeTestFixture(io: Io, path: []const u8, options: TestFixtureOptions) !TestFixture {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const l2_table_offset: u64 = 4 * cluster_size;
    const data0_offset: u64 = 5 * cluster_size;
    const data2_offset: u64 = 6 * cluster_size;
    const total_file_size: u64 = 7 * cluster_size;
    const virtual_size: u64 = 3 * cluster_size;

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    var incompatible_features: u64 = 0;
    if (options.dirty) incompatible_features |= incompatible_dirty;
    if (options.corrupt) incompatible_features |= incompatible_corrupt;
    std.mem.writeInt(u64, header[72..80], incompatible_features, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);

    var refcount_block: [4096]u8 = [_]u8{0} ** 4096;
    var cluster_index: usize = 0;
    while (cluster_index < 7) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, &refcount_block, refcount_block_offset);

    var l1_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l1_table[0..8], l2_table_offset | copied_mask, .big);
    try file.writePositionalAll(io, &l1_table, l1_table_offset);

    var l2_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l2_table[0..8], data0_offset | copied_mask, .big);
    std.mem.writeInt(u64, l2_table[16..24], data2_offset | copied_mask, .big);
    try file.writePositionalAll(io, &l2_table, l2_table_offset);

    try file.writePositionalAll(io, "QCOW2BLOCK000", data0_offset);
    try file.writePositionalAll(io, "QCOW2BLOCK222", data2_offset + 32);

    return .{
        .cluster_size = cluster_size,
        .l1_table_offset = l1_table_offset,
        .l2_table_offset = l2_table_offset,
        .data0_offset = data0_offset,
        .data2_offset = data2_offset,
    };
}

fn writeSingleClusterFixture(io: Io, path: []const u8, options: SingleClusterFixtureOptions) !SingleClusterFixture {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const l2_table_offset: u64 = 4 * cluster_size;
    const data_offset: u64 = 5 * cluster_size;
    const total_file_size: u64 = 6 * cluster_size;
    const virtual_size: u64 = @as(u64, options.virtual_cluster_count) * cluster_size;

    std.debug.assert(options.payload_offset + options.payload.len <= cluster_size);
    std.debug.assert(options.guest_cluster_index < options.virtual_cluster_count);

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    if (options.backing_file) |backing_file| {
        std.mem.writeInt(u64, header[8..16], header_length_v3, .big);
        std.mem.writeInt(u32, header[16..20], @intCast(backing_file.len), .big);
    }
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);
    if (options.backing_file) |backing_file| {
        try file.writePositionalAll(io, backing_file, header_length_v3);
    }

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);

    var refcount_block: [4096]u8 = [_]u8{0} ** 4096;
    var cluster_index: usize = 0;
    while (cluster_index < 6) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, &refcount_block, refcount_block_offset);

    var l1_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l1_table[0..8], l2_table_offset | copied_mask, .big);
    try file.writePositionalAll(io, &l1_table, l1_table_offset);

    var l2_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l2_table[options.guest_cluster_index * 8 ..][0..8], data_offset | copied_mask, .big);
    try file.writePositionalAll(io, &l2_table, l2_table_offset);
    try file.writePositionalAll(io, options.payload, data_offset + options.payload_offset);

    return .{ .cluster_size = cluster_size, .data_offset = data_offset };
}

fn writeCompressedFixture(io: Io, path: []const u8) !u64 {
    const uncompressed = [_]u8{'A'} ** 4096;
    var out = try std.Io.Writer.Allocating.initCapacity(std.testing.allocator, 128);
    defer out.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .raw, .default);
    try compressor.writer.writeAll(&uncompressed);
    try compressor.finish();
    const compressed = try out.toOwnedSlice();
    defer std.testing.allocator.free(compressed);

    return writeCompressedClusterFixture(io, path, 0, compressed);
}

/// Builds a minimal valid zstd frame decompressing to `bytes`, using this
/// repo's small built-in zstd encoder (`zstd.zig`, already used by
/// `squashfs.zig`/`cosi.zig` test fixtures for the same reason: Zig's
/// standard library only ships a zstd *decoder*
/// (`std.compress.zstd.Decompress`), not an encoder).
fn zstdCompress(allocator: std.mem.Allocator, bytes: []const u8) ![]u8 {
    const zstd_enc = @import("zstd.zig");
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), bytes.len));
    errdefer out.deinit();
    try zstd_enc.writeFrameForSlice(&out.writer, bytes, null);
    return out.toOwnedSlice();
}

fn writeZstdCompressedFixture(io: Io, path: []const u8) !u64 {
    const uncompressed = [_]u8{'A'} ** 4096;
    const compressed = try zstdCompress(std.testing.allocator, &uncompressed);
    defer std.testing.allocator.free(compressed);

    return writeCompressedClusterFixture(io, path, 1, compressed);
}

fn writeCompressedClusterFixture(io: Io, path: []const u8, compression_type: u8, compressed: []const u8) !u64 {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const l2_table_offset: u64 = 4 * cluster_size;
    const data_offset: u64 = 5 * cluster_size;
    const virtual_size: u64 = cluster_size;

    const stored_bytes = std.mem.alignForward(usize, compressed.len, 512);
    std.debug.assert(stored_bytes <= cluster_size);

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, data_offset + stored_bytes);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    if (compression_type != 0) {
        std.mem.writeInt(u64, header[72..80], incompatible_compression, .big);
    }
    std.mem.writeInt(u32, header[96..100], 4, .big);
    if (compression_type != 0) {
        std.mem.writeInt(u32, header[100..104], header_length_v3 + 1, .big);
        header[104] = compression_type;
    } else {
        std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    }
    try file.writePositionalAll(io, &header, 0);

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);

    var refcount_block: [4096]u8 = [_]u8{0} ** 4096;
    var cluster_index: usize = 0;
    while (cluster_index < 6) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, &refcount_block, refcount_block_offset);

    var l1_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l1_table[0..8], l2_table_offset | copied_mask, .big);
    try file.writePositionalAll(io, &l1_table, l1_table_offset);

    const additional_sectors: u64 = stored_bytes / 512 - 1;
    const offset_bits = 62 - (cluster_bits - 8);
    const l2_entry = compressed_mask | data_offset | (additional_sectors << @intCast(offset_bits));
    var l2_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l2_table[0..8], l2_entry, .big);
    try file.writePositionalAll(io, &l2_table, l2_table_offset);
    try file.writePositionalAll(io, compressed, data_offset);

    return cluster_size;
}

fn appendSnapshotEntry(out: *std.array_list.Managed(u8), spec: SnapshotEntrySpec) !void {
    const entry_start = out.items.len;
    const extra_data_size: u32 = 24;

    var header: [40]u8 = [_]u8{0} ** 40;
    std.mem.writeInt(u64, header[0..8], spec.l1_table_offset, .big);
    std.mem.writeInt(u32, header[8..12], 1, .big);
    std.mem.writeInt(u16, header[12..14], @intCast(spec.id.len), .big);
    std.mem.writeInt(u16, header[14..16], @intCast(spec.name.len), .big);
    std.mem.writeInt(u32, header[16..20], spec.timestamp_seconds, .big);
    std.mem.writeInt(u32, header[20..24], spec.timestamp_nanoseconds, .big);
    std.mem.writeInt(u64, header[24..32], spec.vm_clock_nanoseconds, .big);
    std.mem.writeInt(u32, header[32..36], @truncate(spec.vm_state_size), .big);
    std.mem.writeInt(u32, header[36..40], extra_data_size, .big);
    try out.appendSlice(&header);

    var extra: [24]u8 = [_]u8{0} ** 24;
    std.mem.writeInt(u64, extra[0..8], spec.vm_state_size, .big);
    std.mem.writeInt(u64, extra[8..16], spec.virtual_size, .big);
    std.mem.writeInt(i64, extra[16..24], spec.icount, .big);
    try out.appendSlice(&extra);
    try out.appendSlice(spec.id);
    try out.appendSlice(spec.name);

    const padding = std.mem.alignForward(usize, out.items.len - entry_start, 8) - (out.items.len - entry_start);
    if (padding != 0) {
        const zeroes: [8]u8 = [_]u8{0} ** 8;
        try out.appendSlice(zeroes[0..padding]);
    }
}

fn writeSnapshotFixture(io: Io, path: []const u8) !void {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const snapshot_l1_offset_0: u64 = 4 * cluster_size;
    const snapshot_l1_offset_1: u64 = 5 * cluster_size;
    const active_l2_offset: u64 = 6 * cluster_size;
    const snapshot_l2_offset_0: u64 = 7 * cluster_size;
    const snapshot_l2_offset_1: u64 = 8 * cluster_size;
    const active_data_offset: u64 = 9 * cluster_size;
    const snapshot_data_offset_0: u64 = 10 * cluster_size;
    const snapshot_data_offset_1: u64 = 11 * cluster_size;
    const shared_data_offset: u64 = 12 * cluster_size;
    const snapshots_offset: u64 = 13 * cluster_size;
    const total_file_size: u64 = 14 * cluster_size;
    const virtual_size: u64 = 3 * cluster_size;

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    std.mem.writeInt(u32, header[60..64], 2, .big);
    std.mem.writeInt(u64, header[64..72], snapshots_offset, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);

    var refcount_block: [4096]u8 = [_]u8{0} ** 4096;
    var cluster_index: usize = 0;
    while (cluster_index < 14) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, &refcount_block, refcount_block_offset);

    var active_l1: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, active_l1[0..8], active_l2_offset | copied_mask, .big);
    try file.writePositionalAll(io, &active_l1, l1_table_offset);

    var snapshot_l1_0: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, snapshot_l1_0[0..8], snapshot_l2_offset_0 | copied_mask, .big);
    try file.writePositionalAll(io, &snapshot_l1_0, snapshot_l1_offset_0);

    var snapshot_l1_1: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, snapshot_l1_1[0..8], snapshot_l2_offset_1 | copied_mask, .big);
    try file.writePositionalAll(io, &snapshot_l1_1, snapshot_l1_offset_1);

    var active_l2: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, active_l2[0..8], active_data_offset | copied_mask, .big);
    std.mem.writeInt(u64, active_l2[8..16], shared_data_offset | copied_mask, .big);
    try file.writePositionalAll(io, &active_l2, active_l2_offset);

    var snapshot_l2_0: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, snapshot_l2_0[0..8], snapshot_data_offset_0 | copied_mask, .big);
    std.mem.writeInt(u64, snapshot_l2_0[8..16], shared_data_offset | copied_mask, .big);
    try file.writePositionalAll(io, &snapshot_l2_0, snapshot_l2_offset_0);

    var snapshot_l2_1: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, snapshot_l2_1[0..8], snapshot_data_offset_1 | copied_mask, .big);
    std.mem.writeInt(u64, snapshot_l2_1[8..16], shared_data_offset | copied_mask, .big);
    try file.writePositionalAll(io, &snapshot_l2_1, snapshot_l2_offset_1);

    try file.writePositionalAll(io, "ACTIVE-CLUSTER", active_data_offset);
    try file.writePositionalAll(io, "SNAP-1-CLUSTER", snapshot_data_offset_0);
    try file.writePositionalAll(io, "SNAP-2-CLUSTER", snapshot_data_offset_1);
    try file.writePositionalAll(io, "SHARED-CLSTR", shared_data_offset + 64);

    var snapshot_bytes = std.array_list.Managed(u8).init(std.testing.allocator);
    defer snapshot_bytes.deinit();
    try appendSnapshotEntry(&snapshot_bytes, .{
        .l1_table_offset = snapshot_l1_offset_0,
        .id = "snap-1",
        .name = "first snapshot",
        .timestamp_seconds = 1_700_000_000,
        .timestamp_nanoseconds = 123,
        .vm_clock_nanoseconds = 456,
        .vm_state_size = 0,
        .virtual_size = virtual_size,
    });
    try appendSnapshotEntry(&snapshot_bytes, .{
        .l1_table_offset = snapshot_l1_offset_1,
        .id = "snap-2",
        .name = "second snapshot",
        .timestamp_seconds = 1_700_000_100,
        .timestamp_nanoseconds = 456,
        .vm_clock_nanoseconds = 789,
        .vm_state_size = 0,
        .virtual_size = virtual_size,
    });
    try file.writePositionalAll(io, snapshot_bytes.items, snapshots_offset);
}

fn writeExternalDataFixture(io: Io, meta_path: []const u8, data_path: []const u8) !u64 {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const l2_table_offset: u64 = 4 * cluster_size;
    const virtual_size: u64 = 2 * cluster_size;
    const total_file_size: u64 = 5 * cluster_size;

    const data_file = try Io.Dir.cwd().createFile(io, data_path, .{ .read = true, .truncate = true });
    defer data_file.close(io);
    try data_file.setLength(io, virtual_size);
    try data_file.writePositionalAll(io, "EXT-DATA-000", 0);
    try data_file.writePositionalAll(io, "EXT-DATA-111", cluster_size + 32);

    const file = try Io.Dir.cwd().createFile(io, meta_path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    std.mem.writeInt(u64, header[72..80], incompatible_data_file, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);

    var ext: [64]u8 = [_]u8{0} ** 64;
    std.mem.writeInt(u32, ext[0..4], header_extension_external_data_file_magic, .big);
    std.mem.writeInt(u32, ext[4..8], @intCast(data_path.len), .big);
    @memcpy(ext[8 .. 8 + data_path.len], data_path);
    try file.writePositionalAll(io, &ext, header_length_v3);

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);

    var refcount_block: [4096]u8 = [_]u8{0} ** 4096;
    var cluster_index: usize = 0;
    while (cluster_index < 5) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, &refcount_block, refcount_block_offset);

    var l1_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l1_table[0..8], l2_table_offset | copied_mask, .big);
    try file.writePositionalAll(io, &l1_table, l1_table_offset);

    var l2_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, l2_table[0..8], copied_mask, .big);
    std.mem.writeInt(u64, l2_table[8..16], cluster_size | copied_mask, .big);
    try file.writePositionalAll(io, &l2_table, l2_table_offset);

    return cluster_size;
}

fn writeExtendedL2Fixture(io: Io, path: []const u8) !ExtendedL2Fixture {
    const cluster_bits: u32 = 14;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const l2_table_offset: u64 = 4 * cluster_size;
    const data_offset: u64 = 5 * cluster_size;
    const total_file_size: u64 = 6 * cluster_size;
    const virtual_size: u64 = cluster_size;
    const subcluster_size = cluster_size / extl2_subcluster_count;

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    std.mem.writeInt(u64, header[72..80], incompatible_extl2, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);

    var refcount_table = try std.testing.allocator.alloc(u8, @intCast(cluster_size));
    defer std.testing.allocator.free(refcount_table);
    @memset(refcount_table, 0);
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, refcount_table, refcount_table_offset);

    var refcount_block = try std.testing.allocator.alloc(u8, @intCast(cluster_size));
    defer std.testing.allocator.free(refcount_block);
    @memset(refcount_block, 0);
    var cluster_index: usize = 0;
    while (cluster_index < 6) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, refcount_block, refcount_block_offset);

    var l1_table = try std.testing.allocator.alloc(u8, @intCast(cluster_size));
    defer std.testing.allocator.free(l1_table);
    @memset(l1_table, 0);
    std.mem.writeInt(u64, l1_table[0..8], l2_table_offset | copied_mask, .big);
    try file.writePositionalAll(io, l1_table, l1_table_offset);

    var l2_table = try std.testing.allocator.alloc(u8, @intCast(cluster_size));
    defer std.testing.allocator.free(l2_table);
    @memset(l2_table, 0);
    std.mem.writeInt(u64, l2_table[0..8], data_offset | copied_mask, .big);
    const bitmap: u64 = (@as(u64, 1) << 0) | (@as(u64, 1) << 2) | (@as(u64, 1) << (extl2_subcluster_count + 1));
    std.mem.writeInt(u64, l2_table[8..16], bitmap, .big);
    try file.writePositionalAll(io, l2_table, l2_table_offset);

    const a_buf = [_]u8{'A'} ** 512;
    const b_buf = [_]u8{'B'} ** 512;
    try file.writePositionalAll(io, &a_buf, data_offset);
    try file.writePositionalAll(io, &b_buf, data_offset + 2 * subcluster_size);

    return .{ .cluster_size = cluster_size };
}

fn writeEncryptedFixture(io: Io, path: []const u8, crypt_method: u32) !void {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const total_file_size: u64 = 4 * cluster_size;

    const file = try Io.Dir.cwd().createFile(io, path, .{ .read = true, .truncate = true });
    defer file.close(io);
    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], cluster_size, .big);
    std.mem.writeInt(u32, header[32..36], crypt_method, .big);
    std.mem.writeInt(u32, header[36..40], 1, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);
}

fn writeFullCoverage4kFixture(file: Io.File, io: Io) !void {
    const cluster_bits: u32 = 12;
    const cluster_size: u64 = 1 << cluster_bits;
    const l2_entries: u64 = cluster_size / 8;
    const guest_clusters: u64 = 2040;
    const l1_size: u32 = 4;
    const refcount_table_offset: u64 = 1 * cluster_size;
    const refcount_block_offset: u64 = 2 * cluster_size;
    const l1_table_offset: u64 = 3 * cluster_size;
    const l2_tables_offset: u64 = 4 * cluster_size;
    const data_offset_base: u64 = 8 * cluster_size;
    const total_clusters: u64 = 2048;
    const total_file_size: u64 = total_clusters * cluster_size;
    const virtual_size: u64 = guest_clusters * cluster_size;

    try file.setLength(io, total_file_size);

    var header: [header_buffer_size]u8 = [_]u8{0} ** header_buffer_size;
    header[0..4].* = file_signature;
    std.mem.writeInt(u32, header[4..8], 3, .big);
    std.mem.writeInt(u32, header[20..24], cluster_bits, .big);
    std.mem.writeInt(u64, header[24..32], virtual_size, .big);
    std.mem.writeInt(u32, header[36..40], l1_size, .big);
    std.mem.writeInt(u64, header[40..48], l1_table_offset, .big);
    std.mem.writeInt(u64, header[48..56], refcount_table_offset, .big);
    std.mem.writeInt(u32, header[56..60], 1, .big);
    std.mem.writeInt(u32, header[96..100], 4, .big);
    std.mem.writeInt(u32, header[100..104], header_length_v3, .big);
    try file.writePositionalAll(io, &header, 0);

    var refcount_table: [4096]u8 = [_]u8{0} ** 4096;
    std.mem.writeInt(u64, refcount_table[0..8], refcount_block_offset, .big);
    try file.writePositionalAll(io, &refcount_table, refcount_table_offset);

    var refcount_block: [4096]u8 = [_]u8{0} ** 4096;
    var cluster_index: usize = 0;
    while (cluster_index < total_clusters) : (cluster_index += 1) {
        std.mem.writeInt(u16, refcount_block[cluster_index * 2 ..][0..2], 1, .big);
    }
    try file.writePositionalAll(io, &refcount_block, refcount_block_offset);

    var l1_table: [4096]u8 = [_]u8{0} ** 4096;
    var l1_index: u32 = 0;
    while (l1_index < l1_size) : (l1_index += 1) {
        std.mem.writeInt(u64, l1_table[l1_index * 8 ..][0..8], l2_tables_offset + @as(u64, l1_index) * cluster_size | copied_mask, .big);
    }
    try file.writePositionalAll(io, &l1_table, l1_table_offset);

    var guest_cluster_index: u64 = 0;
    while (guest_cluster_index < guest_clusters) : (guest_cluster_index += 1) {
        const table_index = guest_cluster_index / l2_entries;
        const entry_index = guest_cluster_index % l2_entries;
        const l2_offset = l2_tables_offset + table_index * cluster_size;
        const data_offset = data_offset_base + guest_cluster_index * cluster_size;
        var entry_buf: [8]u8 = undefined;
        std.mem.writeInt(u64, &entry_buf, data_offset | copied_mask, .big);
        try file.writePositionalAll(io, &entry_buf, l2_offset + entry_index * 8);
    }
}

fn verifyAllocatedClustersMatchRefcounts(file: Io.File, io: Io, info: Info) !void {
    var expected = std.array_list.Managed(u64).init(std.testing.allocator);
    defer expected.deinit();
    var actual = std.array_list.Managed(u64).init(std.testing.allocator);
    defer actual.deinit();

    try expected.append(0);
    var i: u32 = 0;
    while (i < info.refcount_table_clusters) : (i += 1) {
        try expected.append(1 + i);
    }

    var block_index: u32 = 0;
    while (block_index < info.refcount_block_count) : (block_index += 1) {
        const block_offset = try readU64(file, io, info.refcount_table_offset + @as(u64, block_index) * 8);
        try expected.append(block_offset / info.cluster_size);
    }

    const l1_clusters = tableClusterCount(@as(u64, info.l1_size) * 8, info.cluster_size);
    var l1_cluster: u32 = 0;
    while (l1_cluster < l1_clusters) : (l1_cluster += 1) {
        try expected.append(info.l1_table_offset / info.cluster_size + l1_cluster);
    }

    var l1_index: u64 = 0;
    while (l1_index < info.l1_size) : (l1_index += 1) {
        const l1_entry = try readU64(file, io, info.l1_table_offset + l1_index * 8);
        const l2_offset = l1_entry & host_offset_mask;
        if (l2_offset == 0) continue;
        try expected.append(l2_offset / info.cluster_size);

        var l2_index: u64 = 0;
        while (l2_index < info.l2_entries) : (l2_index += 1) {
            const l2_entry = try readU64(file, io, l2_offset + l2_index * 8);
            const data_offset = l2_entry & host_offset_mask;
            if (data_offset == 0) continue;
            try expected.append(data_offset / info.cluster_size);
        }
    }

    const cluster_count = divCeil(info.file_size, info.cluster_size);
    var cluster_index: u64 = 0;
    while (cluster_index < cluster_count) : (cluster_index += 1) {
        if (try readRefcountByClusterIndex(file, io, info, cluster_index) != 0) {
            try actual.append(cluster_index);
        }
    }

    std.mem.sort(u64, expected.items, {}, std.sort.asc(u64));
    std.mem.sort(u64, actual.items, {}, std.sort.asc(u64));

    var deduped_expected = std.array_list.Managed(u64).init(std.testing.allocator);
    defer deduped_expected.deinit();
    var last: ?u64 = null;
    for (expected.items) |value| {
        if (last != null and last.? == value) continue;
        try deduped_expected.append(value);
        last = value;
    }

    try std.testing.expectEqualSlices(u64, deduped_expected.items, actual.items);
}
