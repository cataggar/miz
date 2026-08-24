//! Native Zig qcow2 image reader.
//!
//! A clean-room implementation of the qcow2 on-disk format (see
//! `docs/interop/qcow2.rst` in the QEMU tree). No QEMU C code is used.
//!
//! Scope: read path for v2/v3 images, including standard, zero, unallocated,
//! and compressed clusters, backing-file chains, and Extended L2 Entries
//! (per-subcluster allocation), refcount lookups and a basic consistency
//! check (`Image.check`), and read-only access to internal snapshots
//! (`Image.snapshots` / `Image.openSnapshot`). See `writer.zig` for image
//! creation.
//!
//! All multi-byte integers in qcow2 are stored big-endian.

const std = @import("std");
const Io = std.Io;
const flate = std.compress.flate;
const zstd = std.compress.zstd;

pub const magic: u32 = 0x514649fb; // "QFI\xfb"

/// Image creation / writer support.
pub const writer = @import("writer.zig");

/// Header field offsets and layout, per the qcow2 spec.
pub const Header = struct {
    version: u32,
    backing_file_offset: u64,
    backing_file_size: u32,
    cluster_bits: u32,
    size: u64, // virtual disk size in bytes
    crypt_method: u32,
    l1_size: u32, // number of active L1 entries
    l1_table_offset: u64,
    refcount_table_offset: u64,
    refcount_table_clusters: u32,
    nb_snapshots: u32,
    snapshots_offset: u64,

    // v3+ fields (zero for v2).
    incompatible_features: u64 = 0,
    compatible_features: u64 = 0,
    autoclear_features: u64 = 0,
    refcount_order: u32 = 4, // refcount_bits = 1 << refcount_order; default 4 => 16-bit
    header_length: u32 = 72,
    compression_type: u8 = 0, // 0 = deflate, 1 = zstd

    pub const IncompatibleBit = enum(u6) {
        dirty = 0,
        corrupt = 1,
        external_data_file = 2,
        compression_type = 3,
        extended_l2 = 4,
    };

    /// Number of subclusters per standard data cluster in Extended L2 images.
    pub const subclusters_per_cluster: u64 = 32;

    pub fn clusterSize(self: Header) u64 {
        return @as(u64, 1) << @intCast(self.cluster_bits);
    }

    /// Number of L2 entries per L2 table cluster. Extended L2 Entries
    /// (incompatible bit 4) use 16-byte entries instead of 8, halving the
    /// number of entries per table.
    pub fn l2Entries(self: Header) u64 {
        return self.clusterSize() / self.l2EntrySize();
    }

    /// Size in bytes of a single L2 entry: 16 for Extended L2 images, 8
    /// otherwise.
    pub fn l2EntrySize(self: Header) u64 {
        return if (self.hasIncompatible(.extended_l2)) 16 else @sizeOf(u64);
    }

    /// Size in bytes of a subcluster. Only meaningful for Extended L2
    /// images, which divide each standard data cluster into 32 subclusters.
    pub fn subclusterSize(self: Header) u64 {
        return self.clusterSize() / Header.subclusters_per_cluster;
    }

    /// Bits per refcount entry: `1 << refcount_order` (1 to 64).
    pub fn refcountBits(self: Header) u64 {
        return @as(u64, 1) << @intCast(self.refcount_order);
    }

    /// Number of refcount entries per refcount block cluster.
    pub fn refcountBlockEntries(self: Header) u64 {
        return self.clusterSize() * 8 / self.refcountBits();
    }

    pub fn hasIncompatible(self: Header, bit: IncompatibleBit) bool {
        return (self.incompatible_features & (@as(u64, 1) << @intFromEnum(bit))) != 0;
    }

    /// Parse a header from at least the first 104 bytes of an image.
    pub fn parse(buf: []const u8) Error!Header {
        if (buf.len < 72) return error.Truncated;
        if (rd32(buf, 0) != magic) return error.BadMagic;

        var h: Header = .{
            .version = rd32(buf, 4),
            .backing_file_offset = rd64(buf, 8),
            .backing_file_size = rd32(buf, 16),
            .cluster_bits = rd32(buf, 20),
            .size = rd64(buf, 24),
            .crypt_method = rd32(buf, 32),
            .l1_size = rd32(buf, 36),
            .l1_table_offset = rd64(buf, 40),
            .refcount_table_offset = rd64(buf, 48),
            .refcount_table_clusters = rd32(buf, 56),
            .nb_snapshots = rd32(buf, 60),
            .snapshots_offset = rd64(buf, 64),
        };

        if (h.version < 2 or h.version > 3) return error.UnsupportedVersion;
        if (h.cluster_bits < 9 or h.cluster_bits > 21) return error.BadClusterBits;

        if (h.version >= 3) {
            if (buf.len < 104) return error.Truncated;
            h.incompatible_features = rd64(buf, 72);
            h.compatible_features = rd64(buf, 80);
            h.autoclear_features = rd64(buf, 88);
            h.refcount_order = rd32(buf, 96);
            h.header_length = rd32(buf, 100);
            if (h.header_length >= 105 and buf.len > 104) {
                h.compression_type = buf[104];
            }
        }

        // Per spec: fail to open if an unknown incompatible bit is set.
        const known_incompatible: u64 =
            (1 << 0) | (1 << 1) | (1 << 2) | (1 << 3) | (1 << 4);
        if ((h.incompatible_features & ~known_incompatible) != 0)
            return error.UnknownIncompatibleFeature;

        // Per spec: Extended L2 Entries require cluster_bits >= 14 (i.e.
        // clusters of at least 16 KiB, so a 16-byte L2 entry still leaves
        // room for a whole number of subclusters).
        if (h.hasIncompatible(.extended_l2) and h.cluster_bits < 14)
            return error.BadClusterBits;

        // Per spec: refcount_order may not exceed 6 (i.e. refcount_bits = 64).
        if (h.refcount_order > 6) return error.BadRefcountOrder;

        return h;
    }
};

pub const Error = error{
    Truncated,
    BadMagic,
    UnsupportedVersion,
    BadClusterBits,
    BadRefcountOrder,
    UnknownIncompatibleFeature,
    // Read path
    OutOfRange,
    UnsupportedCompressionType,
    CorruptMapping,
    DecompressFailed,
    BackingChainTooDeep,
};

/// Location of a compressed cluster's payload within the image file.
pub const CompressedRef = struct {
    coffset: u64, // exact byte offset of compressed data (not sector aligned)
    csize: u32, // number of compressed bytes to read
};

/// Classification of a single guest cluster's backing store.
pub const Mapping = union(enum) {
    unallocated, // read from backing file or zeros
    zero, // reads as zeros (zero bit set)
    standard: u64, // host file offset of the cluster data
    compressed: CompressedRef,
};

/// A single consistency issue found by `Image.check`.
pub const Finding = struct {
    pub const Kind = enum {
        /// A cluster referenced by metadata has a stored refcount of 0.
        used_cluster_zero_refcount,
        /// A cluster's stored refcount doesn't match the number of times
        /// this walk found it referenced.
        refcount_mismatch,
        /// A cluster has a nonzero stored refcount but nothing in this
        /// walk referenced it.
        leaked_cluster,
    };
    kind: Kind,
    /// Cluster index (host_offset / cluster_size), not a byte offset.
    cluster_index: u64,
    stored: u64,
    computed: u64,
};

/// Result of `Image.check`: a basic (not exhaustive) consistency check
/// against the reference-counting metadata.
pub const CheckReport = struct {
    /// Distinct clusters referenced by the metadata walk.
    allocated_clusters: u64 = 0,
    findings: std.ArrayList(Finding) = .empty,

    pub fn deinit(self: *CheckReport, allocator: std.mem.Allocator) void {
        self.findings.deinit(allocator);
    }

    pub fn isClean(self: CheckReport) bool {
        return self.findings.items.len == 0;
    }
};

/// A single entry in the qcow2 snapshot directory (see `Image.snapshots`).
/// `id` and `name` are owned; free with `deinit` (or `freeSnapshots` for a
/// whole slice returned by `Image.snapshots`).
pub const Snapshot = struct {
    id: []u8,
    name: []u8,
    l1_table_offset: u64,
    l1_size: u32,
    date_sec: u32,
    date_nsec: u32,
    vm_clock_nsec: u64,
    /// Size of the saved VM state, in bytes (0 if none was saved). Prefers
    /// the 64-bit extra-data field when present, falling back to the
    /// original 32-bit field otherwise.
    vm_state_size: u64,
    /// Virtual disk size of the snapshot, in bytes. 0 if the image doesn't
    /// carry this (v3) extra-data field.
    disk_size: u64 = 0,
    /// Record/replay instruction count, or `no_icount` if disabled/absent.
    icount: u64 = no_icount,

    pub const no_icount: u64 = std.math.maxInt(u64); // spec: "-1 if disabled"

    pub fn deinit(self: *Snapshot, allocator: std.mem.Allocator) void {
        allocator.free(self.id);
        allocator.free(self.name);
    }
};

/// Free a slice of `Snapshot` returned by `Image.snapshots`, including each
/// entry's owned `id`/`name` strings.
pub fn freeSnapshots(allocator: std.mem.Allocator, snaps: []Snapshot) void {
    for (snaps) |*s| s.deinit(allocator);
    allocator.free(snaps);
}

const l2e_offset_mask: u64 = 0x00fffffffffffe00; // bits 9..55
const l2e_compressed: u64 = @as(u64, 1) << 62;
const l1e_offset_mask: u64 = 0x00fffffffffffe00;
const standard_zero_bit: u64 = 1; // bit 0 of standard cluster descriptor
const refcount_table_offset_mask: u64 = ~@as(u64, 0x1ff); // bits 9..63

/// An opened qcow2 image. Backed by a file handle; caller owns lifetime via
/// `close`.
pub const Image = struct {
    io: Io,
    dir: Io.Dir,
    file: Io.File,
    header: Header,
    l1: []u64, // active L1 table, host-endian
    allocator: std.mem.Allocator,
    backing: ?*Image = null, // backing image in the chain, if any
    backing_name: ?[]u8 = null, // owned; the raw backing file name

    const max_backing_depth = 32;

    pub fn open(
        allocator: std.mem.Allocator,
        io: Io,
        dir: Io.Dir,
        path: []const u8,
    ) !Image {
        return openDepth(allocator, io, dir, path, 0);
    }

    fn openDepth(
        allocator: std.mem.Allocator,
        io: Io,
        dir: Io.Dir,
        path: []const u8,
        depth: u32,
    ) !Image {
        if (depth >= max_backing_depth) return error.BackingChainTooDeep;
        const file = try dir.openFile(io, path, .{ .mode = .read_only });
        errdefer file.close(io);

        // Read enough for the full v3 header including the compression_type
        // field at offset 104 and any leading padding.
        var head_buf: [512]u8 = undefined;
        const n = try file.readPositionalAll(io, &head_buf, 0);
        if (n < 72) return error.Truncated;
        const header = try Header.parse(head_buf[0..n]);

        // Read the active L1 table.
        const l1 = try allocator.alloc(u64, header.l1_size);
        errdefer allocator.free(l1);
        if (header.l1_size != 0) {
            const bytes = std.mem.sliceAsBytes(l1);
            const got = try file.readPositionalAll(io, bytes, header.l1_table_offset);
            if (got != bytes.len) return error.Truncated;
            for (l1) |*e| e.* = std.mem.bigToNative(u64, e.*);
        }

        var img: Image = .{
            .io = io,
            .dir = dir,
            .file = file,
            .header = header,
            .l1 = l1,
            .allocator = allocator,
        };

        // Open the backing image, if any. Its name is relative to the
        // directory containing this image (unless absolute).
        if (header.backing_file_offset != 0 and header.backing_file_size != 0) {
            if (header.backing_file_size > 1023) return error.CorruptMapping;
            const name = try allocator.alloc(u8, header.backing_file_size);
            errdefer allocator.free(name);
            const got = try file.readPositionalAll(io, name, header.backing_file_offset);
            if (got != name.len) return error.Truncated;
            img.backing_name = name;

            const full = try resolveBackingPath(allocator, path, name);
            defer allocator.free(full);
            const child = try allocator.create(Image);
            errdefer allocator.destroy(child);
            child.* = try openDepth(allocator, io, dir, full, depth + 1);
            img.backing = child;
        }

        return img;
    }

    pub fn close(self: *Image) void {
        if (self.backing) |b| {
            b.close();
            self.allocator.destroy(b);
        }
        if (self.backing_name) |name| self.allocator.free(name);
        self.allocator.free(self.l1);
        self.file.close(self.io);
        self.* = undefined;
    }

    /// Resolve the mapping for `guest_offset`. For standard clusters in an
    /// Extended L2 image this resolves down to the *subcluster* containing
    /// `guest_offset` (host offsets are adjusted to the subcluster's byte
    /// offset); compressed clusters have no subclusters and are always
    /// resolved at full cluster granularity.
    pub fn mapCluster(self: *Image, guest_offset: u64) !Mapping {
        return self.mapClusterIn(self.l1, self.header.size, guest_offset);
    }

    /// Core of `mapCluster`, parametrized on an explicit L1 table + virtual
    /// disk size instead of always using `self.l1`/`self.header.size`. This
    /// lets `SnapshotView` (see `openSnapshot`) share the exact same
    /// cluster-mapping logic against a snapshot's L1 table: the reader never
    /// consults L1/L2 entry bit 63 (the "refcount==1" hint, which the spec
    /// says is only accurate in the *active* L1 table) -- only the offset
    /// and zero/compressed/allocation bits -- so no bit-63 reconstruction is
    /// needed for read-only access.
    fn mapClusterIn(self: *Image, l1: []const u64, size: u64, guest_offset: u64) !Mapping {
        if (guest_offset >= size) return error.OutOfRange;

        const cs = self.header.clusterSize();
        const l2_entries = self.header.l2Entries();
        const cluster_index = guest_offset / cs;
        const l2_index = cluster_index % l2_entries;
        const l1_index = cluster_index / l2_entries;

        if (l1_index >= l1.len) return error.OutOfRange;
        const l1_entry = l1[l1_index];
        const l2_offset = l1_entry & l1e_offset_mask;
        if (l2_offset == 0) return .unallocated;

        const ext_l2 = self.header.hasIncompatible(.extended_l2);
        const entry_size = self.header.l2EntrySize();

        // Read the single (8- or 16-byte) L2 entry we need.
        var entry_buf: [16]u8 = undefined;
        const at = l2_offset + l2_index * entry_size;
        const got = try self.file.readPositionalAll(self.io, entry_buf[0..entry_size], at);
        if (got != entry_size) return error.CorruptMapping;
        const l2_entry = std.mem.readInt(u64, entry_buf[0..8], .big);

        if ((l2_entry & l2e_compressed) != 0) {
            // Compressed cluster descriptor. Unaffected by Extended L2 (no
            // subclusters for compressed clusters).
            //   csize_shift = 62 - (cluster_bits - 8)
            //   csize_mask  = (1 << (cluster_bits - 8)) - 1
            //   offset_mask = (1 << csize_shift) - 1
            const csize_shift: u6 = @intCast(62 - (self.header.cluster_bits - 8));
            const csize_mask: u64 = (@as(u64, 1) << @intCast(self.header.cluster_bits - 8)) - 1;
            const offset_mask: u64 = (@as(u64, 1) << csize_shift) - 1;
            const coffset = l2_entry & offset_mask;
            const nb_csectors = ((l2_entry >> csize_shift) & csize_mask) + 1;
            const sector_size: u64 = 512;
            const csize = nb_csectors * sector_size - (coffset & (sector_size - 1));
            return .{ .compressed = .{ .coffset = coffset, .csize = @intCast(csize) } };
        }

        const host_offset = l2_entry & l2e_offset_mask;

        if (!ext_l2) {
            if ((l2_entry & standard_zero_bit) != 0) return .zero;
            if (host_offset == 0) return .unallocated;
            return .{ .standard = host_offset };
        }

        // Extended L2: bit 0 of the standard descriptor is unused (always
        // 0); subcluster status instead comes from the second 8-byte
        // allocation/zero bitmap.
        const bitmap = std.mem.readInt(u64, entry_buf[8..16], .big);
        const subcluster_size = self.header.subclusterSize();
        const subcluster_index: u6 = @intCast((guest_offset % cs) / subcluster_size);
        const alloc_bit = (bitmap >> subcluster_index) & 1;
        const zero_bit = (bitmap >> (32 + subcluster_index)) & 1;

        if (zero_bit != 0) return .zero;
        if (alloc_bit == 0) return .unallocated;
        if (host_offset == 0) return error.CorruptMapping; // allocated subcluster needs a valid offset
        return .{ .standard = host_offset + @as(u64, subcluster_index) * subcluster_size };
    }

    /// Look up the reference count of the cluster containing `host_offset`
    /// (a byte offset into the image *file*, not the guest disk). Per spec,
    /// a refcount block that has never been allocated (refcount table entry
    /// == 0) implicitly means every cluster it would cover has a refcount
    /// of 0.
    pub fn refcountAt(self: *Image, host_offset: u64) !u64 {
        const cs = self.header.clusterSize();
        const rb_entries = self.header.refcountBlockEntries();
        const cluster_index = host_offset / cs;
        const rt_index = cluster_index / rb_entries;
        const rb_index = cluster_index % rb_entries;

        var rt_buf: [8]u8 = undefined;
        const rt_at = self.header.refcount_table_offset + rt_index * @sizeOf(u64);
        const rt_got = try self.file.readPositionalAll(self.io, &rt_buf, rt_at);
        if (rt_got != rt_buf.len) return error.CorruptMapping;
        const rb_offset = std.mem.readInt(u64, &rt_buf, .big) & refcount_table_offset_mask;
        if (rb_offset == 0) return 0;

        // Layout matches QEMU's get_refcount_ro{0..6} (block/qcow2-refcount.c):
        // orders 0-2 pack 8/4/2 sub-byte entries per byte, LSB-first; orders
        // 3-6 are plain big-endian 1/2/4/8-byte entries.
        const order = self.header.refcount_order;
        switch (order) {
            0, 1, 2 => {
                const entries_per_byte: u64 = @as(u64, 1) << @intCast(3 - order);
                const byte_index = rb_index / entries_per_byte;
                const width_bits: u3 = @as(u3, 1) << @intCast(order);
                const shift: u3 = @intCast((rb_index % entries_per_byte) << @intCast(order));
                const mask: u8 = (@as(u8, 1) << width_bits) - 1;
                var b: [1]u8 = undefined;
                const got = try self.file.readPositionalAll(self.io, &b, rb_offset + byte_index);
                if (got != 1) return error.CorruptMapping;
                return (b[0] >> shift) & mask;
            },
            3, 4, 5, 6 => {
                const width_bytes: u64 = @as(u64, 1) << @intCast(order - 3);
                var b: [8]u8 = undefined;
                const at = rb_offset + rb_index * width_bytes;
                const got = try self.file.readPositionalAll(self.io, b[0..width_bytes], at);
                if (got != width_bytes) return error.CorruptMapping;
                return switch (width_bytes) {
                    1 => b[0],
                    2 => std.mem.readInt(u16, b[0..2], .big),
                    4 => std.mem.readInt(u32, b[0..4], .big),
                    8 => std.mem.readInt(u64, b[0..8], .big),
                    else => unreachable,
                };
            },
            else => unreachable, // Header.parse rejects refcount_order > 6
        }
    }

    const ClusterRef = struct {
        count: u64 = 0,
        // False for clusters only ever referenced by a compressed payload:
        // per spec, multiple compressed extents may validly share a single
        // host cluster, so an exact refcount match can't be required there
        // (only that the stored refcount is nonzero).
        exact: bool = true,
    };

    fn markCluster(map: *std.AutoHashMap(u64, ClusterRef), cluster_index: u64, exact: bool) !void {
        const gop = try map.getOrPut(cluster_index);
        if (!gop.found_existing) gop.value_ptr.* = .{};
        gop.value_ptr.count += 1;
        if (!exact) gop.value_ptr.exact = false;
    }

    /// Walk one L1 table (active or a snapshot's) and mark every L2 table
    /// cluster and data/compressed cluster it reaches. Shared by `check`
    /// for both the active image and each entry from `snapshots`.
    fn markL1Table(
        self: *Image,
        allocator: std.mem.Allocator,
        computed: *std.AutoHashMap(u64, ClusterRef),
        l1: []const u64,
    ) !void {
        const cs = self.header.clusterSize();
        const entry_size = self.header.l2EntrySize();
        const l2_entries = self.header.l2Entries();
        const l2_buf = try allocator.alloc(u8, cs);
        defer allocator.free(l2_buf);

        for (l1) |l1_entry| {
            const l2_offset = l1_entry & l1e_offset_mask;
            if (l2_offset == 0) continue;
            try markCluster(computed, l2_offset / cs, true);

            const got = try self.file.readPositionalAll(self.io, l2_buf, l2_offset);
            if (got != l2_buf.len) return error.Truncated;

            var idx: u64 = 0;
            while (idx < l2_entries) : (idx += 1) {
                const at = idx * entry_size;
                const l2_entry = std.mem.readInt(u64, l2_buf[at..][0..8], .big);

                if ((l2_entry & l2e_compressed) != 0) {
                    const csize_shift: u6 = @intCast(62 - (self.header.cluster_bits - 8));
                    const csize_mask: u64 = (@as(u64, 1) << @intCast(self.header.cluster_bits - 8)) - 1;
                    const offset_mask: u64 = (@as(u64, 1) << csize_shift) - 1;
                    const coffset = l2_entry & offset_mask;
                    const nb_csectors = ((l2_entry >> csize_shift) & csize_mask) + 1;
                    const sector_size: u64 = 512;
                    const csize = nb_csectors * sector_size - (coffset & (sector_size - 1));
                    if (csize != 0) {
                        const first_cluster = coffset / cs;
                        const last_cluster = (coffset + csize - 1) / cs;
                        var cc = first_cluster;
                        while (cc <= last_cluster) : (cc += 1) try markCluster(computed, cc, false);
                    }
                    continue;
                }

                const host_offset = l2_entry & l2e_offset_mask;
                if (host_offset != 0) try markCluster(computed, host_offset / cs, true);
            }
        }
    }

    /// Byte offset immediately after the last snapshot table entry (the end
    /// of the variable-length snapshot directory), without allocating the
    /// id/name strings `snapshots` does. Used by `check` to mark the
    /// directory's own cluster(s).
    fn snapshotDirectoryEnd(self: *Image) !u64 {
        var pos: u64 = self.header.snapshots_offset;
        var i: u32 = 0;
        while (i < self.header.nb_snapshots) : (i += 1) {
            var fixed: [40]u8 = undefined;
            const got = try self.file.readPositionalAll(self.io, &fixed, pos);
            if (got != fixed.len) return error.Truncated;
            const id_len = std.mem.readInt(u16, fixed[12..14], .big);
            const name_len = std.mem.readInt(u16, fixed[14..16], .big);
            const extra_data_size = std.mem.readInt(u32, fixed[36..40], .big);
            const entry_size = 40 + @as(u64, extra_data_size) + id_len + name_len;
            pos += std.mem.alignForward(u64, entry_size, 8);
        }
        return pos;
    }

    /// Walk this image's own metadata (header, L1/L2 tables, data clusters,
    /// refcount table/blocks, and the snapshot directory + each snapshot's
    /// own L1/L2/data clusters) and cross-check it against stored refcounts:
    /// every referenced cluster must have a nonzero stored refcount and
    /// (except for compressed-cluster hosts, see `ClusterRef`) match the
    /// number of times it was referenced; every cluster in the file with a
    /// nonzero stored refcount must have been referenced at least once
    /// (otherwise it's reported as leaked).
    ///
    /// This intentionally does not recurse into a backing image (matching
    /// `qemu-img check`, which checks one image at a time). It also isn't
    /// optimized for huge images: the leaked-cluster pass calls
    /// `refcountAt` once per cluster in the file.
    pub fn check(self: *Image, allocator: std.mem.Allocator) !CheckReport {
        var computed = std.AutoHashMap(u64, ClusterRef).init(allocator);
        defer computed.deinit();

        const cs = self.header.clusterSize();

        // The header always occupies the first cluster of the file.
        try markCluster(&computed, 0, true);

        // L1 table cluster(s).
        if (self.header.l1_size != 0) {
            const l1_bytes = @as(u64, self.header.l1_size) * @sizeOf(u64);
            const l1_clusters = (l1_bytes + cs - 1) / cs;
            const l1_start = self.header.l1_table_offset / cs;
            var i: u64 = 0;
            while (i < l1_clusters) : (i += 1) try markCluster(&computed, l1_start + i, true);
        }

        // Backing file name bytes (bounded to 1023 bytes by Image.open, but
        // may still span more than one cluster on tiny-cluster images).
        // Skip cluster 0: the name commonly lives inside the header cluster
        // itself (already marked above), and that's not an independent
        // reference -- only a name that spills into cluster(s) beyond the
        // header needs its own mark.
        if (self.header.backing_file_offset != 0 and self.header.backing_file_size != 0) {
            const start = self.header.backing_file_offset / cs;
            const end = (self.header.backing_file_offset + self.header.backing_file_size - 1) / cs;
            var c = start;
            while (c <= end) : (c += 1) {
                if (c == 0) continue;
                try markCluster(&computed, c, true);
            }
        }

        try self.markL1Table(allocator, &computed, self.l1);

        // Snapshot directory: its own cluster(s), plus each snapshot's own
        // L1 table cluster(s) and everything reachable from it.
        if (self.header.nb_snapshots != 0) {
            const dir_end = try self.snapshotDirectoryEnd();
            var dc = self.header.snapshots_offset / cs;
            const dir_end_cluster = (dir_end - 1) / cs;
            while (dc <= dir_end_cluster) : (dc += 1) try markCluster(&computed, dc, true);

            const snaps = try self.snapshots(allocator);
            defer freeSnapshots(allocator, snaps);

            for (snaps) |snap| {
                if (snap.l1_size == 0) continue;
                const l1_bytes = @as(u64, snap.l1_size) * @sizeOf(u64);
                const l1_clusters = (l1_bytes + cs - 1) / cs;
                const l1_start = snap.l1_table_offset / cs;
                var i: u64 = 0;
                while (i < l1_clusters) : (i += 1) try markCluster(&computed, l1_start + i, true);

                const snap_l1 = try allocator.alloc(u64, snap.l1_size);
                defer allocator.free(snap_l1);
                const bytes = std.mem.sliceAsBytes(snap_l1);
                const got = try self.file.readPositionalAll(self.io, bytes, snap.l1_table_offset);
                if (got != bytes.len) return error.Truncated;
                for (snap_l1) |*e| e.* = std.mem.bigToNative(u64, e.*);

                try self.markL1Table(allocator, &computed, snap_l1);
            }
        }

        // Refcount table cluster(s) and the refcount blocks they point to.
        var rti: u64 = 0;
        while (rti < self.header.refcount_table_clusters) : (rti += 1) {
            try markCluster(&computed, (self.header.refcount_table_offset / cs) + rti, true);
        }
        if (self.header.refcount_table_clusters != 0) {
            const rt_bytes = @as(u64, self.header.refcount_table_clusters) * cs;
            const rt_buf = try allocator.alloc(u8, rt_bytes);
            defer allocator.free(rt_buf);
            const got = try self.file.readPositionalAll(self.io, rt_buf, self.header.refcount_table_offset);
            if (got != rt_buf.len) return error.Truncated;
            var off: u64 = 0;
            while (off < rt_bytes) : (off += @sizeOf(u64)) {
                const entry = std.mem.readInt(u64, rt_buf[off..][0..8], .big);
                const rb_offset = entry & refcount_table_offset_mask;
                if (rb_offset != 0) try markCluster(&computed, rb_offset / cs, true);
            }
        }

        var report: CheckReport = .{};
        errdefer report.deinit(allocator);

        var it = computed.iterator();
        while (it.next()) |entry| {
            const cluster_index = entry.key_ptr.*;
            const ref = entry.value_ptr.*;
            report.allocated_clusters += 1;
            const stored = try self.refcountAt(cluster_index * cs);
            if (stored == 0) {
                try report.findings.append(allocator, .{
                    .kind = .used_cluster_zero_refcount,
                    .cluster_index = cluster_index,
                    .stored = 0,
                    .computed = ref.count,
                });
            } else if (ref.exact and stored != ref.count) {
                try report.findings.append(allocator, .{
                    .kind = .refcount_mismatch,
                    .cluster_index = cluster_index,
                    .stored = stored,
                    .computed = ref.count,
                });
            }
        }

        // Leaked clusters: a nonzero stored refcount that nothing above
        // referenced.
        const stat = try self.file.stat(self.io);
        const total_clusters = stat.size / cs;
        var ci: u64 = 0;
        while (ci < total_clusters) : (ci += 1) {
            if (computed.contains(ci)) continue;
            const stored = try self.refcountAt(ci * cs);
            if (stored != 0) {
                try report.findings.append(allocator, .{
                    .kind = .leaked_cluster,
                    .cluster_index = ci,
                    .stored = stored,
                    .computed = 0,
                });
            }
        }

        return report;
    }

    /// Parse the snapshot directory (`header.nb_snapshots` variable-length
    /// entries starting at `header.snapshots_offset`). Returns an owned
    /// slice; free it with `freeSnapshots`.
    pub fn snapshots(self: *Image, allocator: std.mem.Allocator) ![]Snapshot {
        var list: std.ArrayList(Snapshot) = .empty;
        errdefer {
            for (list.items) |*s| s.deinit(allocator);
            list.deinit(allocator);
        }

        var pos: u64 = self.header.snapshots_offset;
        var i: u32 = 0;
        while (i < self.header.nb_snapshots) : (i += 1) {
            var fixed: [40]u8 = undefined;
            const got = try self.file.readPositionalAll(self.io, &fixed, pos);
            if (got != fixed.len) return error.Truncated;

            const l1_table_offset = std.mem.readInt(u64, fixed[0..8], .big);
            const l1_size = std.mem.readInt(u32, fixed[8..12], .big);
            const id_len = std.mem.readInt(u16, fixed[12..14], .big);
            const name_len = std.mem.readInt(u16, fixed[14..16], .big);
            const date_sec = std.mem.readInt(u32, fixed[16..20], .big);
            const date_nsec = std.mem.readInt(u32, fixed[20..24], .big);
            const vm_clock_nsec = std.mem.readInt(u64, fixed[24..32], .big);
            const vm_state_size32 = std.mem.readInt(u32, fixed[32..36], .big);
            const extra_data_size = std.mem.readInt(u32, fixed[36..40], .big);

            var vm_state_size: u64 = vm_state_size32;
            var disk_size: u64 = 0;
            var icount: u64 = Snapshot.no_icount;
            if (extra_data_size > 0) {
                const extra = try allocator.alloc(u8, extra_data_size);
                defer allocator.free(extra);
                const got_extra = try self.file.readPositionalAll(self.io, extra, pos + 40);
                if (got_extra != extra.len) return error.Truncated;
                // Per spec: unknown/absent extra fields are ignored, not errors.
                if (extra.len >= 8) vm_state_size = std.mem.readInt(u64, extra[0..8], .big);
                if (extra.len >= 16) disk_size = std.mem.readInt(u64, extra[8..16], .big);
                if (extra.len >= 24) icount = std.mem.readInt(u64, extra[16..24], .big);
            }

            const id_offset = pos + 40 + extra_data_size;
            const id = try allocator.alloc(u8, id_len);
            errdefer allocator.free(id);
            const got_id = try self.file.readPositionalAll(self.io, id, id_offset);
            if (got_id != id.len) return error.Truncated;

            const name_offset = id_offset + id_len;
            const name = try allocator.alloc(u8, name_len);
            errdefer allocator.free(name);
            const got_name = try self.file.readPositionalAll(self.io, name, name_offset);
            if (got_name != name.len) return error.Truncated;

            try list.append(allocator, .{
                .id = id,
                .name = name,
                .l1_table_offset = l1_table_offset,
                .l1_size = l1_size,
                .date_sec = date_sec,
                .date_nsec = date_nsec,
                .vm_clock_nsec = vm_clock_nsec,
                .vm_state_size = vm_state_size,
                .disk_size = disk_size,
                .icount = icount,
            });

            const entry_size = 40 + @as(u64, extra_data_size) + id_len + name_len;
            pos += std.mem.alignForward(u64, entry_size, 8);
        }

        return list.toOwnedSlice(allocator);
    }

    /// Open a read-only view of `snap`'s virtual disk contents (as obtained
    /// from `snapshots`): loads the snapshot's own L1 table and reuses the
    /// same `mapClusterIn`/`readIn` core the active image uses. Free with
    /// `SnapshotView.deinit`.
    ///
    /// If the snapshot doesn't carry a disk-size extra field (pre-v3-style
    /// snapshots, or a very old writer), falls back to the active image's
    /// current virtual size.
    pub fn openSnapshot(self: *Image, allocator: std.mem.Allocator, snap: Snapshot) !SnapshotView {
        const l1 = try allocator.alloc(u64, snap.l1_size);
        errdefer allocator.free(l1);
        if (snap.l1_size != 0) {
            const bytes = std.mem.sliceAsBytes(l1);
            const got = try self.file.readPositionalAll(self.io, bytes, snap.l1_table_offset);
            if (got != bytes.len) return error.Truncated;
            for (l1) |*e| e.* = std.mem.bigToNative(u64, e.*);
        }
        return .{
            .image = self,
            .l1 = l1,
            .size = if (snap.disk_size != 0) snap.disk_size else self.header.size,
            .allocator = allocator,
        };
    }

    /// Decompress the single guest cluster described by `ref` into `dst`,
    /// which must be exactly one cluster in size. Any tail not produced by the
    /// decompressor is zero-filled.
    fn decompressCluster(self: *Image, ref: CompressedRef, dst: []u8) !void {
        const comp = try self.allocator.alloc(u8, ref.csize);
        defer self.allocator.free(comp);
        const got = try self.file.readPositionalAll(self.io, comp, ref.coffset);
        if (got != comp.len) return error.Truncated;

        var in: Io.Reader = .fixed(comp[0..got]);

        const produced = switch (self.header.compression_type) {
            0 => blk: {
                // Raw deflate (no zlib header). It stops at its end-of-block
                // marker, so streaming the remainder into a cluster-sized
                // writer is safe and ignores the trailing sector padding.
                var out: Io.Writer = .fixed(dst);
                var d: flate.Decompress = .init(&in, .raw, &.{});
                break :blk d.reader.streamRemaining(&out) catch |e| switch (e) {
                    error.WriteFailed => dst.len, // filled a whole cluster
                    else => return error.DecompressFailed,
                };
            },
            1 => blk: {
                // Indirect mode: give the decoder a window buffer sized to the
                // cluster, then read exactly one cluster out. We must NOT drain
                // the input, since qcow2 pads the payload to a sector boundary
                // and streamRemaining would misparse the trailing bytes as a
                // second zstd frame.
                const wlen: u32 = @intCast(@max(dst.len, 1));
                const zbuf = try self.allocator.alloc(u8, @as(usize, wlen) + zstd.block_size_max);
                defer self.allocator.free(zbuf);
                var d: zstd.Decompress = .init(&in, zbuf, .{ .window_len = wlen });
                break :blk d.reader.readSliceShort(dst) catch return error.DecompressFailed;
            },
            else => return error.UnsupportedCompressionType,
        };
        if (produced < dst.len) @memset(dst[produced..], 0);
    }

    /// Read `buf.len` bytes starting at `guest_offset` from the virtual disk.
    /// Unallocated and zero clusters read as zeros (backing files not yet
    /// followed). Compressed clusters are decoded in-place. For Extended L2
    /// images, standard/zero/unallocated status is resolved per-subcluster.
    pub fn read(self: *Image, guest_offset: u64, buf: []u8) !void {
        return self.readIn(self.l1, self.header.size, guest_offset, buf);
    }

    /// Core of `read`, parametrized on an explicit L1 table + virtual disk
    /// size (see `mapClusterIn`).
    fn readIn(self: *Image, l1: []const u64, size: u64, guest_offset: u64, buf: []u8) !void {
        const cs = self.header.clusterSize();
        const ext_l2 = self.header.hasIncompatible(.extended_l2);
        const subcluster_size = if (ext_l2) self.header.subclusterSize() else cs;
        var pos: u64 = guest_offset;
        var written: usize = 0;
        while (written < buf.len) {
            if (pos >= size) return error.OutOfRange;
            const in_cluster = pos % cs;
            const mapping = try self.mapClusterIn(l1, size, pos);

            // Compressed clusters have no subclusters, so they're always
            // resolved (and chunked) at full cluster granularity; everything
            // else is safe to chunk at subcluster granularity for Extended
            // L2 images (which is just the cluster size otherwise).
            const region = if (std.meta.activeTag(mapping) == .compressed) cs else subcluster_size;
            const in_region = pos % region;
            const chunk = @min(region - in_region, buf.len - written);
            const dst = buf[written .. written + chunk];

            switch (mapping) {
                .zero => @memset(dst, 0),
                .unallocated => try self.readBacking(pos, dst),
                .compressed => |ref| {
                    // Decompress the full cluster, then copy the requested slice.
                    const tmp = try self.allocator.alloc(u8, cs);
                    defer self.allocator.free(tmp);
                    try self.decompressCluster(ref, tmp);
                    @memcpy(dst, tmp[in_cluster .. in_cluster + chunk]);
                },
                .standard => |host_offset| {
                    const got = try self.file.readPositionalAll(
                        self.io,
                        dst,
                        host_offset + in_region,
                    );
                    if (got != dst.len) return error.Truncated;
                },
            }
            pos += chunk;
            written += chunk;
        }
    }

    /// Fill `dst` (covering guest range [pos, pos+dst.len)) from the backing
    /// image. Ranges with no backing file, or beyond the backing image's
    /// virtual size, read as zeros.
    fn readBacking(self: *Image, pos: u64, dst: []u8) anyerror!void {
        const backing = self.backing orelse {
            @memset(dst, 0);
            return;
        };
        if (pos >= backing.header.size) {
            @memset(dst, 0);
            return;
        }
        const avail = backing.header.size - pos;
        const from_backing: usize = @intCast(@min(@as(u64, dst.len), avail));
        try backing.read(pos, dst[0..from_backing]);
        if (from_backing < dst.len) @memset(dst[from_backing..], 0);
    }
};

/// A read-only view of a qcow2 snapshot's virtual disk, opened via
/// `Image.openSnapshot`. Shares the parent `Image`'s file handle and header
/// (cluster size, Extended L2/compression settings are image-wide), but maps
/// guest offsets through the snapshot's own L1 table and disk size.
pub const SnapshotView = struct {
    image: *Image,
    l1: []u64,
    size: u64,
    allocator: std.mem.Allocator,

    pub fn deinit(self: *SnapshotView) void {
        self.allocator.free(self.l1);
        self.* = undefined;
    }

    pub fn mapCluster(self: *SnapshotView, guest_offset: u64) !Mapping {
        return self.image.mapClusterIn(self.l1, self.size, guest_offset);
    }

    pub fn read(self: *SnapshotView, guest_offset: u64, buf: []u8) !void {
        return self.image.readIn(self.l1, self.size, guest_offset, buf);
    }
};

/// Resolve a backing-file name against the directory of the parent image path.
/// Absolute names are returned as-is. Caller owns the returned slice.
fn resolveBackingPath(
    allocator: std.mem.Allocator,
    parent_path: []const u8,
    name: []const u8,
) ![]u8 {
    if (name.len > 0 and name[0] == '/') return allocator.dupe(u8, name);
    const dir = std.fs.path.dirname(parent_path) orelse return allocator.dupe(u8, name);
    return std.fs.path.join(allocator, &.{ dir, name });
}

fn rd32(buf: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, buf[off..][0..4], .big);
}
fn rd64(buf: []const u8, off: usize) u64 {
    return std.mem.readInt(u64, buf[off..][0..8], .big);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Test-only helper: write a minimal v3 header with the Extended L2
/// incompatible bit set into `buf[0..104]`.
const ExtL2HeaderOpts = struct {
    cluster_bits: u32,
    size: u64,
    l1_size: u32,
    l1_table_offset: u64,
    backing_file_offset: u64 = 0,
    backing_file_size: u32 = 0,
};
fn writeExtL2ImageHeader(buf: []u8, opts: ExtL2HeaderOpts) void {
    @memset(buf[0..104], 0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big); // version
    std.mem.writeInt(u64, buf[8..16], opts.backing_file_offset, .big);
    std.mem.writeInt(u32, buf[16..20], opts.backing_file_size, .big);
    std.mem.writeInt(u32, buf[20..24], opts.cluster_bits, .big);
    std.mem.writeInt(u64, buf[24..32], opts.size, .big);
    std.mem.writeInt(u32, buf[36..40], opts.l1_size, .big);
    std.mem.writeInt(u64, buf[40..48], opts.l1_table_offset, .big);
    std.mem.writeInt(u64, buf[72..80], @as(u64, 1) << 4, .big); // incompatible: extended_l2
    std.mem.writeInt(u32, buf[100..104], 104, .big); // header_length
}

/// Test-only helper: write a minimal v3 header (no incompatible features)
/// into `buf[0..104]`, with configurable refcount fields for refcountAt
/// tests. L1 fields default to empty (no L1 table needed for those tests).
const V3HeaderOpts = struct {
    cluster_bits: u32,
    size: u64 = 0,
    l1_size: u32 = 0,
    l1_table_offset: u64 = 0,
    refcount_table_offset: u64 = 0,
    refcount_order: u32 = 4,
    backing_file_offset: u64 = 0,
    backing_file_size: u32 = 0,
    nb_snapshots: u32 = 0,
    snapshots_offset: u64 = 0,
};
fn writeV3ImageHeader(buf: []u8, opts: V3HeaderOpts) void {
    @memset(buf[0..104], 0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big); // version
    std.mem.writeInt(u64, buf[8..16], opts.backing_file_offset, .big);
    std.mem.writeInt(u32, buf[16..20], opts.backing_file_size, .big);
    std.mem.writeInt(u32, buf[20..24], opts.cluster_bits, .big);
    std.mem.writeInt(u64, buf[24..32], opts.size, .big);
    std.mem.writeInt(u32, buf[36..40], opts.l1_size, .big);
    std.mem.writeInt(u64, buf[40..48], opts.l1_table_offset, .big);
    std.mem.writeInt(u64, buf[48..56], opts.refcount_table_offset, .big);
    std.mem.writeInt(u32, buf[60..64], opts.nb_snapshots, .big);
    std.mem.writeInt(u64, buf[64..72], opts.snapshots_offset, .big);
    std.mem.writeInt(u32, buf[96..100], opts.refcount_order, .big);
    std.mem.writeInt(u32, buf[100..104], 104, .big); // header_length
}

test "parse minimal v3 header" {
    var buf: [104]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big); // version
    std.mem.writeInt(u32, buf[20..24], 16, .big); // cluster_bits => 64KiB
    std.mem.writeInt(u64, buf[24..32], 64 * 1024 * 1024, .big); // size
    std.mem.writeInt(u32, buf[36..40], 1, .big); // l1_size
    std.mem.writeInt(u64, buf[40..48], 0x30000, .big); // l1_table_offset
    std.mem.writeInt(u32, buf[100..104], 104, .big); // header_length

    const h = try Header.parse(&buf);
    try std.testing.expectEqual(@as(u32, 3), h.version);
    try std.testing.expectEqual(@as(u64, 65536), h.clusterSize());
    try std.testing.expectEqual(@as(u64, 8192), h.l2Entries());
    try std.testing.expect(!h.hasIncompatible(.dirty));
}

test "refcount_order affects refcountBits/refcountBlockEntries" {
    var buf: [104]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big);
    std.mem.writeInt(u32, buf[20..24], 16, .big); // 64 KiB clusters
    std.mem.writeInt(u32, buf[96..100], 4, .big); // refcount_order = 4 (default): 16-bit
    std.mem.writeInt(u32, buf[100..104], 104, .big);
    const h4 = try Header.parse(&buf);
    try std.testing.expectEqual(@as(u64, 16), h4.refcountBits());
    try std.testing.expectEqual(@as(u64, 32768), h4.refcountBlockEntries()); // 65536*8/16

    std.mem.writeInt(u32, buf[96..100], 6, .big); // refcount_order = 6 => 64-bit refcounts
    const h6 = try Header.parse(&buf);
    try std.testing.expectEqual(@as(u64, 64), h6.refcountBits());
    try std.testing.expectEqual(@as(u64, 8192), h6.refcountBlockEntries()); // 65536*8/64
}

test "reject refcount_order > 6" {
    var buf: [104]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big);
    std.mem.writeInt(u32, buf[20..24], 16, .big);
    std.mem.writeInt(u32, buf[96..100], 7, .big); // refcount_order = 7: invalid
    std.mem.writeInt(u32, buf[100..104], 104, .big);
    try std.testing.expectError(error.BadRefcountOrder, Header.parse(&buf));
}

test "parse compression_type field (zstd)" {
    var buf: [112]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big);
    std.mem.writeInt(u32, buf[20..24], 16, .big);
    std.mem.writeInt(u64, buf[72..80], 1 << 3, .big); // incompatible: compression type bit
    std.mem.writeInt(u32, buf[100..104], 112, .big); // header_length includes byte 104
    buf[104] = 1; // compression_type = zstd
    const h = try Header.parse(&buf);
    try std.testing.expectEqual(@as(u8, 1), h.compression_type);
    try std.testing.expect(h.hasIncompatible(.compression_type));
}

test "reject bad magic" {
    var buf: [104]u8 = @splat(0);
    try std.testing.expectError(error.BadMagic, Header.parse(&buf));
}

test "reject unknown incompatible feature" {
    var buf: [104]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big);
    std.mem.writeInt(u32, buf[20..24], 16, .big);
    std.mem.writeInt(u32, buf[100..104], 104, .big);
    std.mem.writeInt(u64, buf[72..80], @as(u64, 1) << 20, .big); // unknown bit
    try std.testing.expectError(error.UnknownIncompatibleFeature, Header.parse(&buf));
}

test "writer round-trip: create then read back" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Data spanning allocated + unallocated (zero) clusters.
    const vsize: u64 = 512 * 1024;
    const data = try a.alloc(u8, vsize);
    defer a.free(data);
    @memset(data, 0);
    for (data[0..1000], 0..) |*b, i| b.* = @intCast(i % 251); // first cluster
    for (data[300 * 1024 ..][0..2048], 0..) |*b, i| b.* = @intCast((i * 7) % 253);

    try writer.createFromRaw(a, io, tmp.dir, "rt.qcow2", data, vsize, .{});

    var img = try Image.open(a, io, tmp.dir, "rt.qcow2");
    defer img.close();
    try std.testing.expectEqual(vsize, img.header.size);

    const out = try a.alloc(u8, vsize);
    defer a.free(out);
    try img.read(0, out);
    try std.testing.expectEqualSlices(u8, data, out);
}

test "writer round-trip: extended L2 image, create then read back" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vsize: u64 = 512 * 1024;
    const data = try a.alloc(u8, vsize);
    defer a.free(data);
    @memset(data, 0);
    for (data[0..1000], 0..) |*b, i| b.* = @intCast(i % 251); // first cluster
    for (data[300 * 1024 ..][0..2048], 0..) |*b, i| b.* = @intCast((i * 7) % 253);

    try writer.createFromRaw(a, io, tmp.dir, "ext-rt.qcow2", data, vsize, .{
        .cluster_bits = 14,
        .extended_l2 = true,
    });

    var img = try Image.open(a, io, tmp.dir, "ext-rt.qcow2");
    defer img.close();
    try std.testing.expectEqual(vsize, img.header.size);
    try std.testing.expect(img.header.hasIncompatible(.extended_l2));
    try std.testing.expectEqual(@as(u64, 16384 / 16), img.header.l2Entries());

    const out = try a.alloc(u8, vsize);
    defer a.free(out);
    try img.read(0, out);
    try std.testing.expectEqualSlices(u8, data, out);
}

test "writer: extended L2 requires cluster_bits >= 14" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const data = [_]u8{0} ** 16;
    try std.testing.expectError(error.BadClusterBits, writer.createFromRaw(
        a,
        io,
        tmp.dir,
        "bad.qcow2",
        &data,
        data.len,
        .{ .cluster_bits = 13, .extended_l2 = true },
    ));
}

test "reject extended L2 with cluster_bits < 14" {
    var buf: [104]u8 = @splat(0);
    std.mem.writeInt(u32, buf[0..4], magic, .big);
    std.mem.writeInt(u32, buf[4..8], 3, .big);
    std.mem.writeInt(u32, buf[20..24], 13, .big); // 8 KiB clusters: too small
    std.mem.writeInt(u32, buf[100..104], 104, .big);
    std.mem.writeInt(u64, buf[72..80], @as(u64, 1) << 4, .big); // extended_l2
    try std.testing.expectError(error.BadClusterBits, Header.parse(&buf));
}

test "extended L2: per-subcluster allocation and zero bitmap" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14; // minimum allowed; 16 KiB clusters
    const cs: u64 = @as(u64, 1) << cluster_bits;
    const subcluster_size = cs / Header.subclusters_per_cluster; // 512 bytes

    // Layout: cluster 0 = header, 1 = L1 table, 2 = L2 table (extended),
    // 3 = the one allocated data cluster (shared by every allocated
    // subcluster; per-subcluster host offset = base + index*subcluster_size).
    const file = try a.alloc(u8, 4 * cs);
    defer a.free(file);
    @memset(file, 0);

    const l1_offset = 1 * cs;
    const l2_offset = 2 * cs;
    const data_offset = 3 * cs;

    writeExtL2ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .l1_size = 1,
        .l1_table_offset = l1_offset,
    });

    const copied: u64 = @as(u64, 1) << 63;
    std.mem.writeInt(u64, file[@intCast(l1_offset)..][0..8], l2_offset | copied, .big);

    // L2 entry 0 (16 bytes): first 8 = standard descriptor (host offset,
    // bit 0 unused for extended L2); last 8 = alloc bitmap (bits 0-31) |
    // zero bitmap (bits 32-63). Subcluster 0 and 3 allocated, subcluster 1
    // zero, everything else (including subcluster 2) unallocated.
    std.mem.writeInt(u64, file[@intCast(l2_offset)..][0..8], data_offset | copied, .big);
    const alloc_bits: u64 = (@as(u64, 1) << 0) | (@as(u64, 1) << 3);
    const zero_bits: u64 = @as(u64, 1) << (32 + 1);
    std.mem.writeInt(u64, file[@intCast(l2_offset + 8)..][0..8], alloc_bits | zero_bits, .big);

    // Recognizable pattern in the data cluster.
    for (file[@intCast(data_offset)..][0..cs], 0..) |*b, i| b.* = @intCast((i * 7 + 1) % 251);

    const out_file = try tmp.dir.createFile(io, "ext.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "ext.qcow2");
    defer img.close();

    // mapCluster resolves per-subcluster status directly.
    switch (try img.mapCluster(0)) {
        .standard => |h| try std.testing.expectEqual(data_offset, h),
        else => return error.TestUnexpectedResult,
    }
    switch (try img.mapCluster(1 * subcluster_size)) {
        .zero => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try img.mapCluster(2 * subcluster_size)) {
        .unallocated => {},
        else => return error.TestUnexpectedResult,
    }
    switch (try img.mapCluster(3 * subcluster_size)) {
        .standard => |h| try std.testing.expectEqual(data_offset + 3 * subcluster_size, h),
        else => return error.TestUnexpectedResult,
    }

    // A whole-cluster read should splice together allocated / zero /
    // unallocated (no backing file => zero) subcluster ranges correctly.
    const got = try a.alloc(u8, cs);
    defer a.free(got);
    try img.read(0, got);

    const expected = try a.alloc(u8, cs);
    defer a.free(expected);
    @memset(expected, 0);
    for (expected[0..subcluster_size], 0..) |*b, i| b.* = @intCast((i * 7 + 1) % 251);
    for (expected[3 * subcluster_size ..][0..subcluster_size], 0..) |*b, i| {
        b.* = @intCast(((3 * subcluster_size + i) * 7 + 1) % 251);
    }
    try std.testing.expectEqualSlices(u8, expected, got);
}

test "extended L2: unallocated subclusters fall through to the backing file" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;
    const subcluster_size = cs / Header.subclusters_per_cluster;
    const vsize = cs; // single guest cluster, matching the backing image size

    // Backing image: a plain (non-extended-L2) qcow2 with a known pattern.
    const backing_data = try a.alloc(u8, vsize);
    defer a.free(backing_data);
    for (backing_data, 0..) |*b, i| b.* = @intCast((i * 3 + 5) % 253);
    try writer.createFromRaw(a, io, tmp.dir, "backing.qcow2", backing_data, vsize, .{});

    // Main extended-L2 image referencing it.
    const file = try a.alloc(u8, 4 * cs);
    defer a.free(file);
    @memset(file, 0);

    const backing_name = "backing.qcow2";
    const backing_name_offset: u64 = 512; // clear of the 104-byte header
    @memcpy(file[@intCast(backing_name_offset)..][0..backing_name.len], backing_name);

    const l1_offset = 1 * cs;
    const l2_offset = 2 * cs;
    const data_offset = 3 * cs;

    writeExtL2ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = vsize,
        .l1_size = 1,
        .l1_table_offset = l1_offset,
        .backing_file_offset = backing_name_offset,
        .backing_file_size = @intCast(backing_name.len),
    });

    const copied: u64 = @as(u64, 1) << 63;
    std.mem.writeInt(u64, file[@intCast(l1_offset)..][0..8], l2_offset | copied, .big);

    // Only subcluster 0 (allocated) and subcluster 1 (zero) override the
    // backing file; every other subcluster is unallocated and must read
    // from the backing image.
    std.mem.writeInt(u64, file[@intCast(l2_offset)..][0..8], data_offset | copied, .big);
    const alloc_bits: u64 = @as(u64, 1) << 0;
    const zero_bits: u64 = @as(u64, 1) << (32 + 1);
    std.mem.writeInt(u64, file[@intCast(l2_offset + 8)..][0..8], alloc_bits | zero_bits, .big);

    for (file[@intCast(data_offset)..][0..cs], 0..) |*b, i| b.* = @intCast((i * 11 + 2) % 241);

    const out_file = try tmp.dir.createFile(io, "main.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "main.qcow2");
    defer img.close();
    try std.testing.expect(img.backing != null);

    const got = try a.alloc(u8, vsize);
    defer a.free(got);
    try img.read(0, got);

    const expected = try a.alloc(u8, vsize);
    defer a.free(expected);
    @memcpy(expected, backing_data); // default: everything comes from backing
    for (expected[0..subcluster_size], 0..) |*b, i| b.* = @intCast((i * 11 + 2) % 241);
    @memset(expected[subcluster_size .. 2 * subcluster_size], 0);
    try std.testing.expectEqualSlices(u8, expected, got);
}

test "extended L2: compressed cluster descriptor is unaffected by subclusters" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    const file = try a.alloc(u8, 3 * cs); // header, L1, L2 (no data cluster needed)
    defer a.free(file);
    @memset(file, 0);

    const l1_offset = 1 * cs;
    const l2_offset = 2 * cs;

    writeExtL2ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .l1_size = 1,
        .l1_table_offset = l1_offset,
    });

    const copied: u64 = @as(u64, 1) << 63;
    std.mem.writeInt(u64, file[@intCast(l1_offset)..][0..8], l2_offset | copied, .big);

    // Compressed cluster descriptor (bit 62 set); the trailing subcluster
    // bitmap word is reserved/unused for compressed clusters and must be
    // ignored, so fill it with garbage to make sure it isn't consulted.
    const csize_shift: u6 = 62 - (cluster_bits - 8);
    const coffset: u64 = 5000;
    const nb_extra_sectors: u64 = 2;
    const compressed_bit: u64 = @as(u64, 1) << 62;
    const first8 = compressed_bit | (nb_extra_sectors << csize_shift) | coffset;
    std.mem.writeInt(u64, file[@intCast(l2_offset)..][0..8], first8, .big);
    std.mem.writeInt(u64, file[@intCast(l2_offset + 8)..][0..8], 0xffffffffffffffff, .big);

    const out_file = try tmp.dir.createFile(io, "comp.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "comp.qcow2");
    defer img.close();

    switch (try img.mapCluster(0)) {
        .compressed => |ref| {
            try std.testing.expectEqual(@as(u64, 5000), ref.coffset);
            const expected_csize = (nb_extra_sectors + 1) * 512 - (coffset % 512);
            try std.testing.expectEqual(@as(u32, @intCast(expected_csize)), ref.csize);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "refcountAt: order 4 (16-bit) refcount block lookups" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14; // 16 KiB clusters
    const cs: u64 = @as(u64, 1) << cluster_bits;

    // Layout: cluster 0 = header, 1 = refcount table, 2 = refcount block.
    // refcountAt never touches L1/L2, so this file needs nothing else.
    const file = try a.alloc(u8, 3 * cs);
    defer a.free(file);
    @memset(file, 0);

    const rt_offset = 1 * cs;
    const rb_offset = 2 * cs;

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .refcount_table_offset = rt_offset,
        .refcount_order = 4,
    });
    std.mem.writeInt(u64, file[@intCast(rt_offset)..][0..8], rb_offset, .big);

    // 16-bit big-endian refcount entries: index 0 = 1, index 1 = 5, index 2
    // = 0, index 5 = 1; everything else is implicitly 0 (zeroed buffer).
    std.mem.writeInt(u16, file[@intCast(rb_offset + 0 * 2)..][0..2], 1, .big);
    std.mem.writeInt(u16, file[@intCast(rb_offset + 1 * 2)..][0..2], 5, .big);
    std.mem.writeInt(u16, file[@intCast(rb_offset + 5 * 2)..][0..2], 1, .big);

    const out_file = try tmp.dir.createFile(io, "rc.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "rc.qcow2");
    defer img.close();

    try std.testing.expectEqual(@as(u64, 1), try img.refcountAt(0 * cs));
    try std.testing.expectEqual(@as(u64, 5), try img.refcountAt(1 * cs));
    try std.testing.expectEqual(@as(u64, 0), try img.refcountAt(2 * cs));
    try std.testing.expectEqual(@as(u64, 1), try img.refcountAt(5 * cs));
    try std.testing.expectEqual(@as(u64, 0), try img.refcountAt(100 * cs)); // same block, unset
}

test "refcountAt: sub-byte order 0 (1-bit) packing" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    const file = try a.alloc(u8, 3 * cs);
    defer a.free(file);
    @memset(file, 0);

    const rt_offset = 1 * cs;
    const rb_offset = 2 * cs;

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .refcount_table_offset = rt_offset,
        .refcount_order = 0,
    });
    std.mem.writeInt(u64, file[@intCast(rt_offset)..][0..8], rb_offset, .big);

    // 1-bit entries, LSB-first: byte 0 = 0b0000_0101 -> index0=1, index1=0,
    // index2=1, indices 3-7=0 (matches QEMU's get_refcount_ro0).
    file[@intCast(rb_offset)] = 0b0000_0101;

    const out_file = try tmp.dir.createFile(io, "rc0.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "rc0.qcow2");
    defer img.close();

    try std.testing.expectEqual(@as(u64, 1), try img.refcountAt(0 * cs));
    try std.testing.expectEqual(@as(u64, 0), try img.refcountAt(1 * cs));
    try std.testing.expectEqual(@as(u64, 1), try img.refcountAt(2 * cs));
    try std.testing.expectEqual(@as(u64, 0), try img.refcountAt(3 * cs));
}

test "refcountAt: unallocated refcount block reads as 0" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    // Only cluster 0 (header) and cluster 1 (refcount table) exist; the
    // table's only entry is left 0, so every refcount block it would cover
    // is implicitly unallocated (refcount 0), including cluster index 0.
    const file = try a.alloc(u8, 2 * cs);
    defer a.free(file);
    @memset(file, 0);

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .refcount_table_offset = 1 * cs,
        .refcount_order = 4,
    });

    const out_file = try tmp.dir.createFile(io, "rc-empty.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "rc-empty.qcow2");
    defer img.close();

    try std.testing.expectEqual(@as(u64, 0), try img.refcountAt(0));
}

test "refcountAt: writer-created image has refcount 1 for the header cluster" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vsize: u64 = 128 * 1024;
    const data = try a.alloc(u8, vsize);
    defer a.free(data);
    for (data, 0..) |*b, i| b.* = @intCast(i % 251);

    try writer.createFromRaw(a, io, tmp.dir, "rc-writer.qcow2", data, vsize, .{});

    var img = try Image.open(a, io, tmp.dir, "rc-writer.qcow2");
    defer img.close();

    // The writer sets every cluster's refcount to exactly 1 (see writer.zig).
    try std.testing.expectEqual(@as(u64, 1), try img.refcountAt(0));
}

test "check(): writer-created image is clean" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const vsize: u64 = 512 * 1024;
    const data = try a.alloc(u8, vsize);
    defer a.free(data);
    @memset(data, 0);
    for (data[0..1000], 0..) |*b, i| b.* = @intCast(i % 251);
    for (data[300 * 1024 ..][0..2048], 0..) |*b, i| b.* = @intCast((i * 7) % 253);

    try writer.createFromRaw(a, io, tmp.dir, "check-clean.qcow2", data, vsize, .{});

    var img = try Image.open(a, io, tmp.dir, "check-clean.qcow2");
    defer img.close();

    var report = try img.check(a);
    defer report.deinit(a);
    try std.testing.expect(report.isClean());
    try std.testing.expect(report.allocated_clusters > 0);
}

/// Builds a minimal, fully cross-linked qcow2 image by hand for check()
/// tests: header (cluster 0), L1 table (1), L2 table (2), one data cluster
/// (3), refcount table (4), refcount block (5). `data_refcount` lets tests
/// deliberately corrupt the one stored refcount that matters; every other
/// referenced cluster gets a correct refcount of 1.
fn buildCheckFixture(a: std.mem.Allocator, io: Io, dir: Io.Dir, path: []const u8, data_refcount: u16) !void {
    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    const file = try a.alloc(u8, 6 * cs);
    defer a.free(file);
    @memset(file, 0);

    const l1_offset = 1 * cs;
    const l2_offset = 2 * cs;
    const data_offset = 3 * cs;
    const rt_offset = 4 * cs;
    const rb_offset = 5 * cs;

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .l1_size = 1,
        .l1_table_offset = l1_offset,
        .refcount_table_offset = rt_offset,
        .refcount_order = 4,
    });
    std.mem.writeInt(u32, file[56..60], 1, .big); // refcount_table_clusters

    std.mem.writeInt(u64, file[@intCast(l1_offset)..][0..8], l2_offset, .big);
    std.mem.writeInt(u64, file[@intCast(l2_offset)..][0..8], data_offset, .big);
    for (file[@intCast(data_offset)..][0..cs], 0..) |*b, i| b.* = @intCast((i * 7 + 1) % 251);
    std.mem.writeInt(u64, file[@intCast(rt_offset)..][0..8], rb_offset, .big);

    // 16-bit refcounts: clusters 0-2 (header/L1/L2), 4 (refcount table), 5
    // (refcount block) are correctly 1; cluster 3 (the data cluster) is
    // whatever the test wants to check.
    inline for (.{ 0, 1, 2, 4, 5 }) |idx| {
        std.mem.writeInt(u16, file[@intCast(rb_offset + idx * 2)..][0..2], 1, .big);
    }
    std.mem.writeInt(u16, file[@intCast(rb_offset + 3 * 2)..][0..2], data_refcount, .big);

    const out_file = try dir.createFile(io, path, .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);
}

test "check(): detects a used cluster with stored refcount 0" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildCheckFixture(a, io, tmp.dir, "check-zero.qcow2", 0);

    var img = try Image.open(a, io, tmp.dir, "check-zero.qcow2");
    defer img.close();

    var report = try img.check(a);
    defer report.deinit(a);
    try std.testing.expect(!report.isClean());
    try std.testing.expectEqual(@as(usize, 1), report.findings.items.len);
    const f = report.findings.items[0];
    try std.testing.expectEqual(Finding.Kind.used_cluster_zero_refcount, f.kind);
    try std.testing.expectEqual(@as(u64, 3), f.cluster_index);
}

test "check(): detects a refcount mismatch" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try buildCheckFixture(a, io, tmp.dir, "check-mismatch.qcow2", 3);

    var img = try Image.open(a, io, tmp.dir, "check-mismatch.qcow2");
    defer img.close();

    var report = try img.check(a);
    defer report.deinit(a);
    try std.testing.expect(!report.isClean());
    try std.testing.expectEqual(@as(usize, 1), report.findings.items.len);
    const f = report.findings.items[0];
    try std.testing.expectEqual(Finding.Kind.refcount_mismatch, f.kind);
    try std.testing.expectEqual(@as(u64, 3), f.cluster_index);
    try std.testing.expectEqual(@as(u64, 3), f.stored);
    try std.testing.expectEqual(@as(u64, 1), f.computed);
}

test "check(): detects a leaked cluster" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // Correct data-cluster refcount (1), but extend the file with one extra
    // unreferenced cluster (6) that the refcount block still marks as
    // refcount 1 -- a leak nothing in L1/L2/refcount-table metadata points to.
    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;
    try buildCheckFixture(a, io, tmp.dir, "check-leak.qcow2", 1);

    {
        const f = try tmp.dir.openFile(io, "check-leak.qcow2", .{ .mode = .read_write });
        defer f.close(io);
        var extra: [16384]u8 = @splat(0);
        try f.writePositionalAll(io, &extra, 6 * cs);
        // Refcount block (cluster 5) entry for cluster 6 = 1, but nothing
        // references cluster 6.
        var rb6: [2]u8 = undefined;
        std.mem.writeInt(u16, &rb6, 1, .big);
        try f.writePositionalAll(io, &rb6, 5 * cs + 6 * 2);
    }

    var img = try Image.open(a, io, tmp.dir, "check-leak.qcow2");
    defer img.close();

    var report = try img.check(a);
    defer report.deinit(a);
    try std.testing.expect(!report.isClean());
    try std.testing.expectEqual(@as(usize, 1), report.findings.items.len);
    const f = report.findings.items[0];
    try std.testing.expectEqual(Finding.Kind.leaked_cluster, f.kind);
    try std.testing.expectEqual(@as(u64, 6), f.cluster_index);
    try std.testing.expectEqual(@as(u64, 1), f.stored);
}

test "check(): a backing-file name inside the header cluster isn't double-counted" {
    // Regression test: the header cluster and a backing-file name that lives
    // in the same cluster used to each be marked as an independent
    // reference, making check() report a spurious "refcount 1 but 2
    // references were found" mismatch on cluster 0 for any image with a
    // small backing-file name (the common case).
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    // A trivial backing image; content doesn't matter for this test.
    const backing_data = [_]u8{0} ** 512;
    try writer.createFromRaw(a, io, tmp.dir, "backing.qcow2", &backing_data, backing_data.len, .{});

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    const file = try a.alloc(u8, 6 * cs);
    defer a.free(file);
    @memset(file, 0);

    const l1_offset = 1 * cs;
    const l2_offset = 2 * cs;
    const data_offset = 3 * cs;
    const rt_offset = 4 * cs;
    const rb_offset = 5 * cs;

    const backing_name = "backing.qcow2";
    const backing_name_offset: u64 = 512; // well clear of the 104-byte header
    @memcpy(file[@intCast(backing_name_offset)..][0..backing_name.len], backing_name);

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .l1_size = 1,
        .l1_table_offset = l1_offset,
        .refcount_table_offset = rt_offset,
        .refcount_order = 4,
        .backing_file_offset = backing_name_offset,
        .backing_file_size = @intCast(backing_name.len),
    });
    std.mem.writeInt(u32, file[56..60], 1, .big); // refcount_table_clusters

    std.mem.writeInt(u64, file[@intCast(l1_offset)..][0..8], l2_offset, .big);
    std.mem.writeInt(u64, file[@intCast(l2_offset)..][0..8], data_offset, .big);
    std.mem.writeInt(u64, file[@intCast(rt_offset)..][0..8], rb_offset, .big);
    inline for (.{ 0, 1, 2, 3, 4, 5 }) |idx| {
        std.mem.writeInt(u16, file[@intCast(rb_offset + idx * 2)..][0..2], 1, .big);
    }

    const out_file = try tmp.dir.createFile(io, "check-backing-name.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "check-backing-name.qcow2");
    defer img.close();
    try std.testing.expect(img.backing != null);

    var report = try img.check(a);
    defer report.deinit(a);
    try std.testing.expect(report.isClean());
}

test "snapshots(): parses id/name/timestamps/extra data" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;
    const snap_offset = 1 * cs;

    const id = "snap1";
    const name = "my snapshot";
    const extra_data_size: u32 = 24; // vm_state_size(64) + disk_size + icount

    const file = try a.alloc(u8, 2 * cs);
    defer a.free(file);
    @memset(file, 0);

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .nb_snapshots = 1,
        .snapshots_offset = snap_offset,
    });

    const e = file[@intCast(snap_offset)..];
    std.mem.writeInt(u64, e[0..8], 2 * cs, .big); // l1_table_offset
    std.mem.writeInt(u32, e[8..12], 5, .big); // l1_size
    std.mem.writeInt(u16, e[12..14], @intCast(id.len), .big);
    std.mem.writeInt(u16, e[14..16], @intCast(name.len), .big);
    std.mem.writeInt(u32, e[16..20], 1000, .big); // date_sec
    std.mem.writeInt(u32, e[20..24], 2000, .big); // date_nsec
    std.mem.writeInt(u64, e[24..32], 123456789, .big); // vm_clock_nsec
    std.mem.writeInt(u32, e[32..36], 0, .big); // vm_state_size (32-bit, superseded below)
    std.mem.writeInt(u32, e[36..40], extra_data_size, .big);
    std.mem.writeInt(u64, e[40..48], 999, .big); // vm_state_size (64-bit)
    std.mem.writeInt(u64, e[48..56], 2 * 1024 * 1024, .big); // disk_size
    std.mem.writeInt(u64, e[56..64], 42, .big); // icount
    @memcpy(e[64..][0..id.len], id);
    @memcpy(e[64 + id.len ..][0..name.len], name);

    const out_file = try tmp.dir.createFile(io, "snap.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "snap.qcow2");
    defer img.close();

    const snaps = try img.snapshots(a);
    defer freeSnapshots(a, snaps);

    try std.testing.expectEqual(@as(usize, 1), snaps.len);
    const s = snaps[0];
    try std.testing.expectEqualStrings("snap1", s.id);
    try std.testing.expectEqualStrings("my snapshot", s.name);
    try std.testing.expectEqual(@as(u64, 2 * cs), s.l1_table_offset);
    try std.testing.expectEqual(@as(u32, 5), s.l1_size);
    try std.testing.expectEqual(@as(u32, 1000), s.date_sec);
    try std.testing.expectEqual(@as(u32, 2000), s.date_nsec);
    try std.testing.expectEqual(@as(u64, 123456789), s.vm_clock_nsec);
    try std.testing.expectEqual(@as(u64, 999), s.vm_state_size);
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024), s.disk_size);
    try std.testing.expectEqual(@as(u64, 42), s.icount);
}

test "snapshots(): no snapshots returns an empty slice" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    var buf: [104]u8 = @splat(0);
    writeV3ImageHeader(&buf, .{ .cluster_bits = 16, .size = 65536 });

    const out_file = try tmp.dir.createFile(io, "nosnap.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, &buf, 0);

    var img = try Image.open(a, io, tmp.dir, "nosnap.qcow2");
    defer img.close();

    const snaps = try img.snapshots(a);
    defer freeSnapshots(a, snaps);
    try std.testing.expectEqual(@as(usize, 0), snaps.len);
}

test "openSnapshot(): reads distinct data from active vs. snapshot L1 tables" {
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    const active_l1_offset = 1 * cs;
    const active_l2_offset = 2 * cs;
    const active_data_offset = 3 * cs;
    const snap_l1_offset = 4 * cs;
    const snap_l2_offset = 5 * cs;
    const snap_data_offset = 6 * cs;
    const snap_table_offset = 7 * cs;

    const file = try a.alloc(u8, 8 * cs);
    defer a.free(file);
    @memset(file, 0);

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .l1_size = 1,
        .l1_table_offset = active_l1_offset,
        .nb_snapshots = 1,
        .snapshots_offset = snap_table_offset,
    });

    std.mem.writeInt(u64, file[@intCast(active_l1_offset)..][0..8], active_l2_offset, .big);
    std.mem.writeInt(u64, file[@intCast(active_l2_offset)..][0..8], active_data_offset, .big);
    for (file[@intCast(active_data_offset)..][0..cs], 0..) |*b, i| b.* = @intCast((i * 7 + 1) % 251); // pattern A

    std.mem.writeInt(u64, file[@intCast(snap_l1_offset)..][0..8], snap_l2_offset, .big);
    std.mem.writeInt(u64, file[@intCast(snap_l2_offset)..][0..8], snap_data_offset, .big);
    for (file[@intCast(snap_data_offset)..][0..cs], 0..) |*b, i| b.* = @intCast((i * 13 + 3) % 241); // pattern B

    // Snapshot table entry.
    const id = "snap0";
    const e = file[@intCast(snap_table_offset)..];
    std.mem.writeInt(u64, e[0..8], snap_l1_offset, .big);
    std.mem.writeInt(u32, e[8..12], 1, .big); // l1_size
    std.mem.writeInt(u16, e[12..14], @intCast(id.len), .big);
    std.mem.writeInt(u16, e[14..16], 0, .big); // name_len
    std.mem.writeInt(u32, e[36..40], 16, .big); // extra_data_size (vm_state64 + disk_size)
    std.mem.writeInt(u64, e[40..48], 0, .big); // vm_state_size
    std.mem.writeInt(u64, e[48..56], cs, .big); // disk_size
    @memcpy(e[56..][0..id.len], id);

    const out_file = try tmp.dir.createFile(io, "snaprd.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "snaprd.qcow2");
    defer img.close();

    const snaps = try img.snapshots(a);
    defer freeSnapshots(a, snaps);
    try std.testing.expectEqual(@as(usize, 1), snaps.len);

    var view = try img.openSnapshot(a, snaps[0]);
    defer view.deinit();

    var active_out: [16384]u8 = undefined;
    try img.read(0, &active_out);
    var snap_out: [16384]u8 = undefined;
    try view.read(0, &snap_out);

    var expected_active: [16384]u8 = undefined;
    for (&expected_active, 0..) |*b, i| b.* = @intCast((i * 7 + 1) % 251);
    var expected_snap: [16384]u8 = undefined;
    for (&expected_snap, 0..) |*b, i| b.* = @intCast((i * 13 + 3) % 241);

    try std.testing.expectEqualSlices(u8, &expected_active, &active_out);
    try std.testing.expectEqualSlices(u8, &expected_snap, &snap_out);
    // Sanity: the two are genuinely different.
    try std.testing.expect(!std.mem.eql(u8, &active_out, &snap_out));
}

test "check(): clean image with a snapshot (walks snapshot L1/L2/data + directory)" {
    // Regression test: check() used to only walk the active L1 table, so
    // any image with a snapshot reported the snapshot's L1/L2/data clusters
    // (and the snapshot directory itself) as spuriously "leaked".
    const io = std.testing.io;
    const a = std.testing.allocator;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    const cluster_bits: u32 = 14;
    const cs: u64 = @as(u64, 1) << cluster_bits;

    const active_l1_offset = 1 * cs;
    const active_l2_offset = 2 * cs;
    const active_data_offset = 3 * cs;
    const snap_l1_offset = 4 * cs;
    const snap_l2_offset = 5 * cs;
    const snap_data_offset = 6 * cs;
    const snap_table_offset = 7 * cs;
    const rt_offset = 8 * cs;
    const rb_offset = 9 * cs;
    const total_clusters = 10;

    const file = try a.alloc(u8, total_clusters * cs);
    defer a.free(file);
    @memset(file, 0);

    writeV3ImageHeader(file[0..104], .{
        .cluster_bits = cluster_bits,
        .size = cs,
        .l1_size = 1,
        .l1_table_offset = active_l1_offset,
        .refcount_table_offset = rt_offset,
        .refcount_order = 4,
        .nb_snapshots = 1,
        .snapshots_offset = snap_table_offset,
    });
    std.mem.writeInt(u32, file[56..60], 1, .big); // refcount_table_clusters

    std.mem.writeInt(u64, file[@intCast(active_l1_offset)..][0..8], active_l2_offset, .big);
    std.mem.writeInt(u64, file[@intCast(active_l2_offset)..][0..8], active_data_offset, .big);
    std.mem.writeInt(u64, file[@intCast(snap_l1_offset)..][0..8], snap_l2_offset, .big);
    std.mem.writeInt(u64, file[@intCast(snap_l2_offset)..][0..8], snap_data_offset, .big);
    std.mem.writeInt(u64, file[@intCast(rt_offset)..][0..8], rb_offset, .big);

    // Snapshot table entry: id="s", no name, no extra data (32-bit
    // vm_state_size only -- exercises the pre-v3-extra-data fallback path).
    const id = "s";
    const e = file[@intCast(snap_table_offset)..];
    std.mem.writeInt(u64, e[0..8], snap_l1_offset, .big);
    std.mem.writeInt(u32, e[8..12], 1, .big); // l1_size
    std.mem.writeInt(u16, e[12..14], @intCast(id.len), .big);
    std.mem.writeInt(u16, e[14..16], 0, .big); // name_len
    std.mem.writeInt(u32, e[36..40], 0, .big); // extra_data_size
    @memcpy(e[40..][0..id.len], id);

    // Every cluster in the file (0-9) has a correct refcount of 1.
    var idx: u64 = 0;
    while (idx < total_clusters) : (idx += 1) {
        std.mem.writeInt(u16, file[@intCast(rb_offset + idx * 2)..][0..2], 1, .big);
    }

    const out_file = try tmp.dir.createFile(io, "check-snap.qcow2", .{ .truncate = true });
    defer out_file.close(io);
    try out_file.writePositionalAll(io, file, 0);

    var img = try Image.open(a, io, tmp.dir, "check-snap.qcow2");
    defer img.close();

    var report = try img.check(a);
    defer report.deinit(a);
    try std.testing.expect(report.isClean());
    try std.testing.expectEqual(@as(u64, total_clusters), report.allocated_clusters);
}
