//! GUID Partition Table (GPT) codec: header + partition entry array,
//! including the CRC-32 checksums and the mixed-endian GUIDs both use.
//! Field layout, offsets, and the CRC-32 algorithm (standard ISO-HDLC/zlib
//! CRC-32) are verified against the UEFI spec's GPT chapter (via Wikipedia's
//! "GUID Partition Table" article, which transcribes the spec's header and
//! partition-entry tables directly).
//!
//! Unlike the VHD footer (big-endian), every multi-byte GPT field is
//! little-endian -- easy to mix up when working on both formats in the same
//! codebase, so it's called out explicitly here.

const std = @import("std");
const Io = std.Io;
const guid = @import("guid.zig");
const mbr = @import("mbr.zig");
const image_mod = @import("image.zig");
const Image = image_mod.Image;

pub const sector_size: usize = 512;
pub const header_size: u32 = 92;
pub const default_num_partition_entries: u32 = 128;
pub const partition_entry_size: u32 = 128;
pub const signature: [8]u8 = "EFI PART".*;

/// Sectors occupied by the (default 128-entry, 128-byte-entry) partition
/// array: 128*128 / 512 = 32.
pub const partition_array_sectors: u64 = (default_num_partition_entries * partition_entry_size) / sector_size;
pub const default_max_partition_array_bytes: u64 = 1024 * 1024;

pub const Header = struct {
    revision: u32 = 0x0001_0000,
    header_size: u32 = header_size,
    current_lba: u64,
    backup_lba: u64,
    first_usable_lba: u64,
    last_usable_lba: u64,
    disk_guid: guid.Guid,
    partition_entry_lba: u64,
    num_partition_entries: u32 = default_num_partition_entries,
    partition_entry_size: u32 = partition_entry_size,
    partition_array_crc32: u32,

    pub fn encode(self: Header) [sector_size]u8 {
        var buf: [sector_size]u8 = [_]u8{0} ** sector_size;
        buf[0..8].* = signature;
        std.mem.writeInt(u32, buf[8..12], self.revision, .little);
        std.mem.writeInt(u32, buf[12..16], self.header_size, .little);
        // buf[16..20] header_crc32 placeholder, filled below.
        // buf[20..24] reserved, stays zero.
        std.mem.writeInt(u64, buf[24..32], self.current_lba, .little);
        std.mem.writeInt(u64, buf[32..40], self.backup_lba, .little);
        std.mem.writeInt(u64, buf[40..48], self.first_usable_lba, .little);
        std.mem.writeInt(u64, buf[48..56], self.last_usable_lba, .little);
        buf[56..72].* = self.disk_guid;
        std.mem.writeInt(u64, buf[72..80], self.partition_entry_lba, .little);
        std.mem.writeInt(u32, buf[80..84], self.num_partition_entries, .little);
        std.mem.writeInt(u32, buf[84..88], self.partition_entry_size, .little);
        std.mem.writeInt(u32, buf[88..92], self.partition_array_crc32, .little);

        const crc = std.hash.crc.Crc32.hash(buf[0..self.header_size]);
        std.mem.writeInt(u32, buf[16..20], crc, .little);
        return buf;
    }

    pub const DecodeError = error{ BadSignature, InvalidHeaderSize, BadHeaderChecksum };

    pub fn decode(buf: *const [sector_size]u8) DecodeError!Header {
        if (!std.mem.eql(u8, buf[0..8], &signature)) return error.BadSignature;

        const hdr_size = std.mem.readInt(u32, buf[12..16], .little);
        if (hdr_size < header_size or hdr_size > sector_size) return error.InvalidHeaderSize;
        const stored_crc = std.mem.readInt(u32, buf[16..20], .little);

        var checked = buf.*;
        checked[16..20].* = .{ 0, 0, 0, 0 };
        const computed_crc = std.hash.crc.Crc32.hash(checked[0..hdr_size]);
        if (computed_crc != stored_crc) return error.BadHeaderChecksum;

        return .{
            .revision = std.mem.readInt(u32, buf[8..12], .little),
            .header_size = hdr_size,
            .current_lba = std.mem.readInt(u64, buf[24..32], .little),
            .backup_lba = std.mem.readInt(u64, buf[32..40], .little),
            .first_usable_lba = std.mem.readInt(u64, buf[40..48], .little),
            .last_usable_lba = std.mem.readInt(u64, buf[48..56], .little),
            .disk_guid = buf[56..72].*,
            .partition_entry_lba = std.mem.readInt(u64, buf[72..80], .little),
            .num_partition_entries = std.mem.readInt(u32, buf[80..84], .little),
            .partition_entry_size = std.mem.readInt(u32, buf[84..88], .little),
            .partition_array_crc32 = std.mem.readInt(u32, buf[88..92], .little),
        };
    }
};

pub const PartitionEntry = struct {
    /// Zero-based slot in the on-disk partition entry array when decoded.
    /// Writers ignore this field.
    table_index: u32 = 0,
    partition_type_guid: guid.Guid = guid.nil,
    unique_partition_guid: guid.Guid = guid.nil,
    first_lba: u64 = 0,
    last_lba: u64 = 0,
    attributes: u64 = 0,
    /// 36 UTF-16LE code units, matching the spec's fixed-width name field.
    name_utf16le: [36]u16 = [_]u16{0} ** 36,

    pub fn isEmpty(self: PartitionEntry) bool {
        return std.mem.eql(u8, &self.partition_type_guid, &guid.nil);
    }

    fn encode(self: PartitionEntry, buf: *[partition_entry_size]u8) void {
        buf[0..16].* = self.partition_type_guid;
        buf[16..32].* = self.unique_partition_guid;
        std.mem.writeInt(u64, buf[32..40], self.first_lba, .little);
        std.mem.writeInt(u64, buf[40..48], self.last_lba, .little);
        std.mem.writeInt(u64, buf[48..56], self.attributes, .little);
        for (self.name_utf16le, 0..) |code_unit, i| {
            std.mem.writeInt(u16, buf[56 + i * 2 ..][0..2], code_unit, .little);
        }
    }

    fn decode(buf: *const [partition_entry_size]u8) PartitionEntry {
        var name: [36]u16 = undefined;
        for (&name, 0..) |*code_unit, i| {
            code_unit.* = std.mem.readInt(u16, buf[56 + i * 2 ..][0..2], .little);
        }
        return .{
            .partition_type_guid = buf[0..16].*,
            .unique_partition_guid = buf[16..32].*,
            .first_lba = std.mem.readInt(u64, buf[32..40], .little),
            .last_lba = std.mem.readInt(u64, buf[40..48], .little),
            .attributes = std.mem.readInt(u64, buf[48..56], .little),
            .name_utf16le = name,
        };
    }
};

/// Encodes an ASCII partition name into the fixed 36-UTF-16LE-code-unit
/// field (truncated if too long; zero-padded if shorter).
pub fn asciiName(name: []const u8) [36]u16 {
    var out: [36]u16 = [_]u16{0} ** 36;
    const n = @min(name.len, 36);
    for (name[0..n], 0..) |c, i| out[i] = c;
    return out;
}

pub const PartitionSpec = struct {
    type_guid: guid.Guid,
    unique_guid: guid.Guid,
    size_sectors: u64,
    name_utf16le: [36]u16 = [_]u16{0} ** 36,
};

pub const Placement = struct {
    first_lba: u64,
    /// Inclusive, matching the spec's own "Last LBA" field.
    last_lba: u64,
};

pub const WriteError = error{
    TooManyPartitions,
    NotEnoughSpace,
    InvalidPlacement,
} || Image.PreadError || Image.PwriteError;

pub const PlacedPartitionSpec = struct {
    type_guid: guid.Guid,
    unique_guid: guid.Guid,
    placement: Placement,
    name_utf16le: [36]u16 = [_]u16{0} ** 36,
};

fn writePartitionTables(
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    entries: []const PartitionEntry,
) WriteError!void {
    var array_buf: [default_num_partition_entries * partition_entry_size]u8 = [_]u8{0} ** (default_num_partition_entries * partition_entry_size);
    for (entries, 0..) |entry, i| {
        entry.encode(array_buf[i * partition_entry_size ..][0..partition_entry_size]);
    }
    const array_crc = std.hash.crc.Crc32.hash(&array_buf);

    const total_sectors = img.virtual_size / sector_size;
    const first_usable_lba: u64 = 2 + partition_array_sectors;
    const last_usable_lba: u64 = total_sectors - 2 - partition_array_sectors;
    const backup_array_lba = total_sectors - 1 - partition_array_sectors;

    const primary = Header{
        .current_lba = 1,
        .backup_lba = total_sectors - 1,
        .first_usable_lba = first_usable_lba,
        .last_usable_lba = last_usable_lba,
        .disk_guid = disk_guid,
        .partition_entry_lba = 2,
        .partition_array_crc32 = array_crc,
    };
    const backup = Header{
        .current_lba = total_sectors - 1,
        .backup_lba = 1,
        .first_usable_lba = first_usable_lba,
        .last_usable_lba = last_usable_lba,
        .disk_guid = disk_guid,
        .partition_entry_lba = backup_array_lba,
        .partition_array_crc32 = array_crc,
    };

    const protective_mbr = mbr.protectiveMbr(total_sectors).encode();
    try img.pwrite(io, &protective_mbr, 0);
    try img.pwrite(io, &primary.encode(), sector_size * 1);
    try img.pwrite(io, &array_buf, sector_size * 2);
    try img.pwrite(io, &array_buf, sector_size * backup_array_lba);
    try img.pwrite(io, &backup.encode(), sector_size * (total_sectors - 1));
}

/// Writes a full protective-MBR + primary GPT (header+array) + backup GPT
/// (array+header) layout to `img`, placing each of `specs` back-to-back
/// starting at the first usable LBA. `img`'s current virtual size
/// determines the disk's total sector count -- create/resize it to its
/// final size *before* calling this. Returns each spec's chosen
/// (first_lba,last_lba) into `out_placements` (same length as `specs`).
pub fn writeGpt(
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    specs: []const PartitionSpec,
    out_placements: []Placement,
) WriteError!void {
    std.debug.assert(specs.len == out_placements.len);
    if (specs.len > default_num_partition_entries) return error.TooManyPartitions;

    const total_sectors = img.virtual_size / sector_size;
    const first_usable_lba: u64 = 2 + partition_array_sectors;
    const last_usable_lba: u64 = total_sectors - 2 - partition_array_sectors;

    var entries: [default_num_partition_entries]PartitionEntry = [_]PartitionEntry{.{}} ** default_num_partition_entries;
    var cursor = first_usable_lba;
    for (specs, 0..) |spec, i| {
        if (spec.size_sectors == 0) return error.NotEnoughSpace;
        const last = cursor + spec.size_sectors - 1;
        if (last > last_usable_lba) return error.NotEnoughSpace;
        out_placements[i] = .{ .first_lba = cursor, .last_lba = last };
        entries[i] = .{
            .partition_type_guid = spec.type_guid,
            .unique_partition_guid = spec.unique_guid,
            .first_lba = cursor,
            .last_lba = last,
            .name_utf16le = spec.name_utf16le,
        };
        cursor = last + 1;
    }

    try writePartitionTables(img, io, disk_guid, entries[0..specs.len]);
}

/// Writes a full protective-MBR + GPT layout to `img` using explicit
/// partition placements chosen by the caller. Each placement must be
/// within the GPT's usable LBA range, non-empty, and in strictly
/// increasing non-overlapping order.
pub fn writeGptPlaced(
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    specs: []const PlacedPartitionSpec,
) WriteError!void {
    if (specs.len > default_num_partition_entries) return error.TooManyPartitions;

    const total_sectors = img.virtual_size / sector_size;
    const first_usable_lba: u64 = 2 + partition_array_sectors;
    const last_usable_lba: u64 = total_sectors - 2 - partition_array_sectors;

    var entries: [default_num_partition_entries]PartitionEntry = [_]PartitionEntry{.{}} ** default_num_partition_entries;
    var prev_last_lba: u64 = 0;
    for (specs, 0..) |spec, i| {
        const placement = spec.placement;
        if (placement.first_lba < first_usable_lba) return error.InvalidPlacement;
        if (placement.last_lba < placement.first_lba) return error.InvalidPlacement;
        if (placement.last_lba > last_usable_lba) return error.NotEnoughSpace;
        if (i > 0 and placement.first_lba <= prev_last_lba) return error.InvalidPlacement;

        entries[i] = .{
            .partition_type_guid = spec.type_guid,
            .unique_partition_guid = spec.unique_guid,
            .first_lba = placement.first_lba,
            .last_lba = placement.last_lba,
            .name_utf16le = spec.name_utf16le,
        };
        prev_last_lba = placement.last_lba;
    }

    try writePartitionTables(img, io, disk_guid, entries[0..specs.len]);
}

pub const ParsedGpt = struct {
    header: Header,
    /// Only non-empty entries (`!isEmpty()`), in table order. Caller-owned.
    partitions: []PartitionEntry,
};

pub const GrowError = error{
    NoPartitions,
    NotEnoughSpace,
} || WriteError;

/// Grows the *last* partition in `partitions` (by table order, matching
/// both vmiz-built images and real Azure Linux images, where root is
/// always the last partition) to reach the disk's new, larger end, and
/// rewrites the full protective-MBR + GPT (primary + backup) layout.
///
/// Every field of every partition entry other than the last one's
/// `last_lba` is preserved byte-for-byte -- GUIDs, name, and (unlike a
/// round-trip through `writeGptPlaced`/`PlacedPartitionSpec`, which has no
/// `attributes` field and would silently zero it) `attributes` too --
/// because this reuses the original decoded `PartitionEntry` values
/// directly instead of re-deriving them from a narrower spec type.
///
/// `img.virtual_size` must already reflect the disk's new, real byte size
/// (e.g. from a `BLKGETSIZE64` ioctl) -- the new `last_usable_lba`, and
/// thus the backup header/array's new location, is derived from it, the
/// same way `writeGpt`/`writeGptPlaced` derive it from a fresh disk's
/// size. Returns `error.NotEnoughSpace` if the disk isn't actually larger
/// than the last partition's current extent (e.g. called on an
/// already-grown disk, or one that didn't grow at all) -- callers that
/// want a silent every-boot no-op should check this first rather than
/// relying on the error, since re-writing an unchanged table on every
/// boot is wasted (harmless, but unnecessary) I/O.
pub fn growLastPartition(
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    partitions: []PartitionEntry,
) GrowError!void {
    if (partitions.len == 0) return error.NoPartitions;

    const total_sectors = img.virtual_size / sector_size;
    const last_usable_lba: u64 = total_sectors - 2 - partition_array_sectors;

    const last_idx = partitions.len - 1;
    if (last_usable_lba <= partitions[last_idx].last_lba) return error.NotEnoughSpace;

    partitions[last_idx].last_lba = last_usable_lba;

    try writePartitionTables(img, io, disk_guid, partitions);
}

pub const ReadError = error{
    UnsupportedPartitionEntrySize,
    InvalidPartitionArrayBounds,
    UnexpectedEndOfFile,
    BadPartitionArrayChecksum,
} || Header.DecodeError || Image.PreadError || std.mem.Allocator.Error;

/// Reads and validates the primary GPT header + partition array from `img`
/// (LBA 1 and LBA 2.. respectively). Does not cross-check the backup copy
/// (see `check` in `image.zig` for basic consistency checks; a full
/// primary/backup reconciliation is a possible future enhancement).
pub fn readGpt(img: Image, io: Io, allocator: std.mem.Allocator) ReadError!ParsedGpt {
    var header_buf: [sector_size]u8 = undefined;
    if (try img.pread(io, &header_buf, sector_size * 1) != header_buf.len) {
        return error.UnexpectedEndOfFile;
    }
    const header = try Header.decode(&header_buf);

    if (header.partition_entry_size != partition_entry_size) return error.UnsupportedPartitionEntrySize;

    const array_bytes_u64 = std.math.mul(
        u64,
        header.num_partition_entries,
        header.partition_entry_size,
    ) catch return error.InvalidPartitionArrayBounds;
    const array_offset = std.math.mul(
        u64,
        sector_size,
        header.partition_entry_lba,
    ) catch return error.InvalidPartitionArrayBounds;
    const array_end = std.math.add(
        u64,
        array_offset,
        array_bytes_u64,
    ) catch return error.InvalidPartitionArrayBounds;
    if (array_end > img.virtual_size) return error.InvalidPartitionArrayBounds;
    const array_bytes_len = std.math.cast(usize, array_bytes_u64) orelse
        return error.InvalidPartitionArrayBounds;
    const array_buf = try allocator.alloc(u8, array_bytes_len);
    defer allocator.free(array_buf);
    if (try img.pread(io, array_buf, array_offset) != array_buf.len) {
        return error.UnexpectedEndOfFile;
    }

    if (std.hash.crc.Crc32.hash(array_buf) != header.partition_array_crc32) {
        return error.BadPartitionArrayChecksum;
    }

    var list = std.array_list.Managed(PartitionEntry).init(allocator);
    errdefer list.deinit();

    var i: u32 = 0;
    while (i < header.num_partition_entries) : (i += 1) {
        const entry_offset = @as(usize, i) * partition_entry_size;
        var entry = PartitionEntry.decode(array_buf[entry_offset..][0..partition_entry_size]);
        entry.table_index = i;
        if (!entry.isEmpty()) try list.append(entry);
    }

    return .{ .header = header, .partitions = try list.toOwnedSlice() };
}

pub const VerifiedGpt = struct {
    primary_header: Header,
    backup_header: Header,
    primary_header_sector: [sector_size]u8,
    backup_header_sector: [sector_size]u8,
    partition_array: []u8,
    partitions: []PartitionEntry,
    protective_mbr_sector: [sector_size]u8,
    protective_entry_index: u8,

    pub fn deinit(self: *VerifiedGpt, allocator: std.mem.Allocator) void {
        allocator.free(self.partition_array);
        allocator.free(self.partitions);
        self.* = undefined;
    }
};

pub const DetectedGpt = union(enum) {
    not_gpt,
    verified: VerifiedGpt,

    pub fn deinit(self: *DetectedGpt, allocator: std.mem.Allocator) void {
        switch (self.*) {
            .not_gpt => {},
            .verified => |*verified| verified.deinit(allocator),
        }
        self.* = undefined;
    }
};

pub const VerifyError = error{
    ImageNotSectorAligned,
    InvalidProtectiveMbr,
    UnsupportedRevision,
    UnsupportedHeaderSize,
    InvalidHeaderReservedBytes,
    InvalidHeaderGeometry,
    HeaderMismatch,
    PartitionArrayMismatch,
    PartitionArrayTooLarge,
    InvalidPartitionBounds,
    OverlappingPartitions,
} || ReadError || mbr.Mbr.DecodeError;

/// Detects whether an image is a GPT source and strictly verifies it when it
/// is. A protective partition entry or a primary GPT signature is enough to
/// classify the image as GPT-shaped, so damaged GPT metadata is reported as
/// an error rather than silently treated as a non-GPT image.
pub fn detectVerifiedGpt(
    img: Image,
    io: Io,
    allocator: std.mem.Allocator,
    max_partition_array_bytes: u64,
) VerifyError!DetectedGpt {
    var first_blocks: [2 * sector_size]u8 = [_]u8{0} ** (2 * sector_size);
    const available = @min(img.virtual_size, first_blocks.len);
    if (available != 0) {
        const available_len: usize = @intCast(available);
        if (try img.pread(io, first_blocks[0..available_len], 0) != available_len) {
            return error.UnexpectedEndOfFile;
        }
    }

    var has_protective_entry = false;
    if (available >= sector_size) {
        for (0..4) |i| {
            const entry_offset = mbr.partition_table_offset + i * mbr.entry_size;
            if (first_blocks[entry_offset + 4] == @intFromEnum(mbr.PartitionType.gpt_protective)) {
                has_protective_entry = true;
                break;
            }
        }
    }
    const has_primary_signature = available >= 2 * sector_size and
        std.mem.eql(u8, first_blocks[sector_size .. sector_size + signature.len], &signature);
    if (!has_protective_entry and !has_primary_signature) return .not_gpt;

    return .{ .verified = try readVerifiedGpt(
        img,
        io,
        allocator,
        max_partition_array_bytes,
    ) };
}

pub const InvalidateDestinationError = error{
    ImageNotSectorAligned,
    InvalidPartitionArrayLimit,
    UnexpectedEndOfFile,
} || Image.PreadError || Image.PwriteError;

/// Erases possible GPT/MBR metadata before a destructive image copy.
///
/// The start range covers the MBR, primary header, and the maximum accepted
/// partition array. The end range covers an array of the same size plus the
/// final backup header. If a primary GPT header advertises metadata elsewhere,
/// those ranges are erased too, preventing an old smaller table from surviving
/// between the copied image and the destination's physical end.
pub fn invalidateDestinationPartitionStructures(
    img: *Image,
    io: Io,
    max_partition_array_bytes: u64,
) InvalidateDestinationError!void {
    if (img.virtual_size == 0 or img.virtual_size % sector_size != 0) {
        return error.ImageNotSectorAligned;
    }
    if (max_partition_array_bytes == 0) {
        return error.InvalidPartitionArrayLimit;
    }

    const array_sectors = std.math.divCeil(
        u64,
        max_partition_array_bytes,
        sector_size,
    ) catch return error.InvalidPartitionArrayLimit;
    const start_sectors = std.math.add(u64, array_sectors, 2) catch
        return error.InvalidPartitionArrayLimit;
    const end_sectors = std.math.add(u64, array_sectors, 1) catch
        return error.InvalidPartitionArrayLimit;
    const total_sectors = img.virtual_size / sector_size;

    var primary_sector: [sector_size]u8 = undefined;
    var has_primary_sector = false;
    if (total_sectors > 1) {
        try preadExact(img.*, io, &primary_sector, sector_size);
        has_primary_sector = true;
    }

    if (has_primary_sector) {
        const primary = Header.decode(&primary_sector) catch null;
        if (primary) |header| {
            try eraseSectorRange(
                img,
                io,
                header.partition_entry_lba,
                array_sectors,
                total_sectors,
            );

            if (header.backup_lba < total_sectors) {
                const backup_start = header.backup_lba -|
                    @min(header.backup_lba, array_sectors);
                try eraseSectorRange(
                    img,
                    io,
                    backup_start,
                    header.backup_lba - backup_start + 1,
                    total_sectors,
                );
            }
        }
    }

    try eraseSectorRange(
        img,
        io,
        total_sectors -| end_sectors,
        @min(total_sectors, end_sectors),
        total_sectors,
    );
    try eraseSectorRange(
        img,
        io,
        0,
        @min(total_sectors, start_sectors),
        total_sectors,
    );
}

/// Strictly validates the protective MBR and both GPT copies. Unlike
/// `readGpt`, this is intended for image publication and conversion, where a
/// stale or disagreeing backup table must be rejected rather than repaired
/// implicitly. Raw partition-array bytes are retained so relocation can copy
/// every slot exactly, including empty and vendor-extended entry bytes.
pub fn readVerifiedGpt(
    img: Image,
    io: Io,
    allocator: std.mem.Allocator,
    max_partition_array_bytes: u64,
) VerifyError!VerifiedGpt {
    if (img.virtual_size == 0 or img.virtual_size % sector_size != 0) {
        return error.ImageNotSectorAligned;
    }
    const total_sectors = img.virtual_size / sector_size;
    if (total_sectors < 3) return error.InvalidHeaderGeometry;

    var protective_mbr_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &protective_mbr_sector, 0);
    const protective_mbr = try mbr.Mbr.decode(&protective_mbr_sector);
    var protective_entry_index: ?u8 = null;
    for (protective_mbr.entries, 0..) |entry, i| {
        if (entry.partition_type == .gpt_protective) {
            if (protective_entry_index != null or entry.bootable or
                entry.first_lba != 1 or
                entry.sector_count != protectiveSectorCount(total_sectors))
            {
                return error.InvalidProtectiveMbr;
            }
            protective_entry_index = @intCast(i);
        } else if (entry.partition_type != .empty) {
            return error.InvalidProtectiveMbr;
        }
    }
    const protective_index = protective_entry_index orelse
        return error.InvalidProtectiveMbr;

    var primary_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &primary_sector, sector_size);
    const primary = try decodeStrictHeader(&primary_sector);
    if (primary.current_lba != 1 or primary.backup_lba != total_sectors - 1) {
        return error.InvalidHeaderGeometry;
    }

    var backup_sector: [sector_size]u8 = undefined;
    try preadExact(
        img,
        io,
        &backup_sector,
        try sectorOffset(primary.backup_lba),
    );
    const backup = try decodeStrictHeader(&backup_sector);
    if (backup.current_lba != primary.backup_lba or
        backup.backup_lba != primary.current_lba)
    {
        return error.InvalidHeaderGeometry;
    }
    if (primary.revision != backup.revision or
        primary.header_size != backup.header_size or
        primary.first_usable_lba != backup.first_usable_lba or
        primary.last_usable_lba != backup.last_usable_lba or
        !std.mem.eql(u8, &primary.disk_guid, &backup.disk_guid) or
        primary.num_partition_entries != backup.num_partition_entries or
        primary.partition_entry_size != backup.partition_entry_size or
        primary.partition_array_crc32 != backup.partition_array_crc32)
    {
        return error.HeaderMismatch;
    }

    const array_bytes = try partitionArrayBytes(primary);
    if (array_bytes == 0 or array_bytes > max_partition_array_bytes) {
        return error.PartitionArrayTooLarge;
    }
    const array_sectors = std.math.divCeil(u64, array_bytes, sector_size) catch
        return error.InvalidPartitionArrayBounds;
    const primary_array_end = std.math.add(
        u64,
        primary.partition_entry_lba,
        array_sectors,
    ) catch return error.InvalidPartitionArrayBounds;
    const backup_array_end = std.math.add(
        u64,
        backup.partition_entry_lba,
        array_sectors,
    ) catch return error.InvalidPartitionArrayBounds;
    if (primary.partition_entry_lba <= primary.current_lba or
        primary_array_end > primary.first_usable_lba or
        primary.first_usable_lba > primary.last_usable_lba or
        backup.partition_entry_lba <= primary.last_usable_lba or
        backup_array_end > backup.current_lba)
    {
        return error.InvalidHeaderGeometry;
    }

    const array_len = std.math.cast(usize, array_bytes) orelse
        return error.PartitionArrayTooLarge;
    const primary_array = try allocator.alloc(u8, array_len);
    errdefer allocator.free(primary_array);
    try preadExact(
        img,
        io,
        primary_array,
        try sectorOffset(primary.partition_entry_lba),
    );
    if (std.hash.crc.Crc32.hash(primary_array) !=
        primary.partition_array_crc32)
    {
        return error.BadPartitionArrayChecksum;
    }

    const backup_array = try allocator.alloc(u8, array_len);
    defer allocator.free(backup_array);
    try preadExact(
        img,
        io,
        backup_array,
        try sectorOffset(backup.partition_entry_lba),
    );
    if (std.hash.crc.Crc32.hash(backup_array) !=
        backup.partition_array_crc32)
    {
        return error.BadPartitionArrayChecksum;
    }
    if (!std.mem.eql(u8, primary_array, backup_array)) {
        return error.PartitionArrayMismatch;
    }

    var list = std.array_list.Managed(PartitionEntry).init(allocator);
    errdefer list.deinit();
    const entry_size: usize = @intCast(primary.partition_entry_size);
    var i: u32 = 0;
    while (i < primary.num_partition_entries) : (i += 1) {
        const entry_offset = @as(usize, i) * entry_size;
        var entry = PartitionEntry.decode(
            primary_array[entry_offset..][0..partition_entry_size],
        );
        entry.table_index = i;
        if (entry.isEmpty()) continue;
        if (entry.first_lba < primary.first_usable_lba or
            entry.last_lba < entry.first_lba or
            entry.last_lba > primary.last_usable_lba)
        {
            return error.InvalidPartitionBounds;
        }
        for (list.items) |existing| {
            if (entry.first_lba <= existing.last_lba and
                existing.first_lba <= entry.last_lba)
            {
                return error.OverlappingPartitions;
            }
        }
        try list.append(entry);
    }

    return .{
        .primary_header = primary,
        .backup_header = backup,
        .primary_header_sector = primary_sector,
        .backup_header_sector = backup_sector,
        .partition_array = primary_array,
        .partitions = try list.toOwnedSlice(),
        .protective_mbr_sector = protective_mbr_sector,
        .protective_entry_index = protective_index,
    };
}

pub const RelocationResult = struct {
    was_relocated: bool,
    old_backup_lba: u64,
    new_backup_lba: u64,
    old_last_usable_lba: u64,
    new_last_usable_lba: u64,
};

pub const RelocateError = error{
    ImageNotSectorAligned,
    ImageDidNotGrow,
    SourceMetadataChanged,
    PartitionArrayTooLarge,
    InvalidPartitionArrayBounds,
    InvalidPartitionBounds,
} || Image.PreadError || Image.PwriteError || std.mem.Allocator.Error ||
    error{UnexpectedEndOfFile};

pub const GrowPartitionResult = struct {
    old_last_lba: u64,
    new_last_lba: u64,
    relocation: RelocationResult,
};

pub const ReplacementGuids = struct {
    disk_guid: guid.Guid,
    /// One GUID per non-empty partition, in `VerifiedGpt.partitions` table order.
    partition_guids: []const guid.Guid,
};

pub const OwnedReplacementGuids = struct {
    disk_guid: guid.Guid,
    partition_guids: []guid.Guid,

    pub fn borrowed(self: OwnedReplacementGuids) ReplacementGuids {
        return .{
            .disk_guid = self.disk_guid,
            .partition_guids = self.partition_guids,
        };
    }

    pub fn deinit(self: *OwnedReplacementGuids, allocator: std.mem.Allocator) void {
        allocator.free(self.partition_guids);
        self.* = undefined;
    }
};

pub const PartitionGuidRewrite = struct {
    table_index: u32,
    partition_type_guid: guid.Guid,
    first_lba: u64,
    last_lba: u64,
    attributes: u64 = 0,
    name_utf16le: [36]u16 = [_]u16{0} ** 36,
    old_unique_guid: guid.Guid,
    new_unique_guid: guid.Guid,
};

pub const IdentityRewriteReport = struct {
    old_disk_guid: guid.Guid,
    new_disk_guid: guid.Guid,
    partitions: []PartitionGuidRewrite,

    pub fn deinit(self: *IdentityRewriteReport, allocator: std.mem.Allocator) void {
        allocator.free(self.partitions);
        self.* = undefined;
    }
};

pub const IdentityRewriteValidationError = error{
    InvalidSourceDiskGuid,
    InvalidSourcePartitionGuid,
    DuplicateSourcePartitionGuid,
    InvalidReplacementCount,
    InvalidReplacementGuid,
    DuplicateReplacementGuid,
    ReplacementGuidCollidesWithSource,
};

pub const GenerateReplacementGuidsError = IdentityRewriteValidationError || std.mem.Allocator.Error;

pub const RewriteIdentityError = IdentityRewriteValidationError || error{
    SourceMetadataChanged,
    InvalidPartitionArrayBounds,
    UnexpectedEndOfFile,
} || Image.PreadError || Image.PwriteError || std.mem.Allocator.Error;

/// Generates a fresh disk GUID plus one fresh partition GUID per non-empty
/// GPT entry. The result owns the partition-guid slice and can be passed to
/// `rewriteIdentity` via `borrowed()`.
pub fn generateReplacementGuids(
    allocator: std.mem.Allocator,
    io: Io,
    verified: VerifiedGpt,
) GenerateReplacementGuidsError!OwnedReplacementGuids {
    try validateSourceIdentity(verified);
    const partition_guids = try allocator.alloc(guid.Guid, verified.partitions.len);
    errdefer allocator.free(partition_guids);

    const disk_guid = generateFreshGuid(io, verified, null, partition_guids[0..0]);
    for (partition_guids, 0..) |*partition_guid, i| {
        partition_guid.* = generateFreshGuid(
            io,
            verified,
            disk_guid,
            partition_guids[0..i],
        );
    }

    return .{
        .disk_guid = disk_guid,
        .partition_guids = partition_guids,
    };
}

/// Rewrites the disk GUID and every non-empty partition unique GUID in an
/// already verified GPT while preserving all other GPT/MBR bytes and the
/// current GPT geometry. `replacement.partition_guids` must be in
/// `VerifiedGpt.partitions` table order.
pub fn rewriteIdentity(
    img: *Image,
    io: Io,
    allocator: std.mem.Allocator,
    verified: VerifiedGpt,
    replacement: ReplacementGuids,
) RewriteIdentityError!IdentityRewriteReport {
    try validateReplacementGuids(verified, replacement);
    try verifySourceMetadataUnchanged(img, io, allocator, verified);

    const entry_size_u64: u64 = verified.primary_header.partition_entry_size;
    const updated_array = try allocator.dupe(u8, verified.partition_array);
    defer allocator.free(updated_array);

    const rewrites = try allocator.alloc(
        PartitionGuidRewrite,
        verified.partitions.len,
    );
    errdefer allocator.free(rewrites);

    for (verified.partitions, replacement.partition_guids, 0..) |partition, new_guid, i| {
        const guid_offset_u64 = std.math.add(
            u64,
            std.math.mul(u64, partition.table_index, entry_size_u64) catch
                return error.InvalidPartitionArrayBounds,
            16,
        ) catch return error.InvalidPartitionArrayBounds;
        const guid_end_u64 = std.math.add(
            u64,
            guid_offset_u64,
            @as(u64, @sizeOf(guid.Guid)),
        ) catch return error.InvalidPartitionArrayBounds;
        if (guid_end_u64 > updated_array.len) return error.InvalidPartitionArrayBounds;
        const guid_offset = std.math.cast(usize, guid_offset_u64) orelse
            return error.InvalidPartitionArrayBounds;

        updated_array[guid_offset..][0..@sizeOf(guid.Guid)].* = new_guid;
        rewrites[i] = .{
            .table_index = partition.table_index,
            .partition_type_guid = partition.partition_type_guid,
            .first_lba = partition.first_lba,
            .last_lba = partition.last_lba,
            .attributes = partition.attributes,
            .name_utf16le = partition.name_utf16le,
            .old_unique_guid = partition.unique_partition_guid,
            .new_unique_guid = new_guid,
        };
    }

    const array_crc = std.hash.crc.Crc32.hash(updated_array);
    var primary_sector = verified.primary_header_sector;
    primary_sector[56..72].* = replacement.disk_guid;
    std.mem.writeInt(u32, primary_sector[88..92], array_crc, .little);
    updateHeaderChecksum(&primary_sector);

    var backup_sector = verified.backup_header_sector;
    backup_sector[56..72].* = replacement.disk_guid;
    std.mem.writeInt(u32, backup_sector[88..92], array_crc, .little);
    updateHeaderChecksum(&backup_sector);

    try img.pwrite(
        io,
        updated_array,
        try sectorOffset(verified.primary_header.partition_entry_lba),
    );
    try img.pwrite(
        io,
        updated_array,
        try sectorOffset(verified.backup_header.partition_entry_lba),
    );
    try img.pwrite(
        io,
        &backup_sector,
        try sectorOffset(verified.backup_header.current_lba),
    );
    try img.pwrite(
        io,
        &primary_sector,
        try sectorOffset(verified.primary_header.current_lba),
    );

    return .{
        .old_disk_guid = verified.primary_header.disk_guid,
        .new_disk_guid = replacement.disk_guid,
        .partitions = rewrites,
    };
}

fn validateSourceIdentity(verified: VerifiedGpt) IdentityRewriteValidationError!void {
    if (guidEql(verified.primary_header.disk_guid, guid.nil)) {
        return error.InvalidSourceDiskGuid;
    }
    for (verified.partitions, 0..) |partition, i| {
        if (guidEql(partition.unique_partition_guid, guid.nil)) {
            return error.InvalidSourcePartitionGuid;
        }
        for (verified.partitions[0..i]) |existing| {
            if (guidEql(partition.unique_partition_guid, existing.unique_partition_guid)) {
                return error.DuplicateSourcePartitionGuid;
            }
        }
    }
}

fn validateReplacementGuids(
    verified: VerifiedGpt,
    replacement: ReplacementGuids,
) IdentityRewriteValidationError!void {
    try validateSourceIdentity(verified);
    if (replacement.partition_guids.len != verified.partitions.len) {
        return error.InvalidReplacementCount;
    }
    if (guidEql(replacement.disk_guid, guid.nil)) return error.InvalidReplacementGuid;
    if (sourceContainsGuid(verified, replacement.disk_guid)) {
        return error.ReplacementGuidCollidesWithSource;
    }

    for (replacement.partition_guids, 0..) |new_guid, i| {
        if (guidEql(new_guid, guid.nil)) return error.InvalidReplacementGuid;
        if (sourceContainsGuid(verified, new_guid)) {
            return error.ReplacementGuidCollidesWithSource;
        }
        if (guidEql(new_guid, replacement.disk_guid)) {
            return error.DuplicateReplacementGuid;
        }
        for (replacement.partition_guids[0..i]) |existing| {
            if (guidEql(new_guid, existing)) return error.DuplicateReplacementGuid;
        }
    }
}

fn verifySourceMetadataUnchanged(
    img: *Image,
    io: Io,
    allocator: std.mem.Allocator,
    verified: VerifiedGpt,
) RewriteIdentityError!void {
    var current_primary: [sector_size]u8 = undefined;
    try preadExact(
        img.*,
        io,
        &current_primary,
        try sectorOffset(verified.primary_header.current_lba),
    );
    if (!std.mem.eql(u8, &current_primary, &verified.primary_header_sector)) {
        return error.SourceMetadataChanged;
    }

    var current_backup: [sector_size]u8 = undefined;
    try preadExact(
        img.*,
        io,
        &current_backup,
        try sectorOffset(verified.backup_header.current_lba),
    );
    if (!std.mem.eql(u8, &current_backup, &verified.backup_header_sector)) {
        return error.SourceMetadataChanged;
    }

    var current_mbr: [sector_size]u8 = undefined;
    try preadExact(img.*, io, &current_mbr, 0);
    if (!std.mem.eql(u8, &current_mbr, &verified.protective_mbr_sector)) {
        return error.SourceMetadataChanged;
    }

    const current_array = try allocator.alloc(u8, verified.partition_array.len);
    defer allocator.free(current_array);

    try preadExact(
        img.*,
        io,
        current_array,
        try sectorOffset(verified.primary_header.partition_entry_lba),
    );
    if (!std.mem.eql(u8, current_array, verified.partition_array)) {
        return error.SourceMetadataChanged;
    }

    try preadExact(
        img.*,
        io,
        current_array,
        try sectorOffset(verified.backup_header.partition_entry_lba),
    );
    if (!std.mem.eql(u8, current_array, verified.partition_array)) {
        return error.SourceMetadataChanged;
    }
}

fn generateFreshGuid(
    io: Io,
    verified: VerifiedGpt,
    disk_guid: ?guid.Guid,
    partition_guids: []const guid.Guid,
) guid.Guid {
    while (true) {
        const candidate = randomGuid(io);
        if (sourceContainsGuid(verified, candidate)) continue;
        if (disk_guid) |new_disk_guid| {
            if (guidEql(candidate, new_disk_guid)) continue;
        }
        var duplicate = false;
        for (partition_guids) |existing| {
            if (guidEql(candidate, existing)) {
                duplicate = true;
                break;
            }
        }
        if (!duplicate) return candidate;
    }
}

fn sourceContainsGuid(verified: VerifiedGpt, candidate: guid.Guid) bool {
    if (guidEql(candidate, verified.primary_header.disk_guid)) return true;
    for (verified.partitions) |partition| {
        if (guidEql(candidate, partition.unique_partition_guid)) return true;
    }
    return false;
}

fn guidEql(a: guid.Guid, b: guid.Guid) bool {
    return std.mem.eql(u8, &a, &b);
}

fn randomGuid(io: Io) guid.Guid {
    var bytes: guid.Guid = undefined;
    Io.random(io, &bytes);
    bytes[7] = (bytes[7] & 0x0F) | 0x40;
    bytes[8] = (bytes[8] & 0x3F) | 0x80;
    return bytes;
}

/// Relocates the backup GPT to the current end of `img`, then extends the
/// selected partition to the new last usable LBA. The partition array is
/// treated as opaque bytes: only the selected entry's `last_lba` field and
/// the two GPT array/header checksums change. Partition ordering, GUIDs,
/// attributes, names, vendor bytes, the protective MBR, and every unrelated
/// entry remain byte-for-byte unchanged.
pub fn growPartitionToEnd(
    img: *Image,
    io: Io,
    allocator: std.mem.Allocator,
    verified: VerifiedGpt,
    table_index: u32,
) !GrowPartitionResult {
    var target: ?PartitionEntry = null;
    for (verified.partitions) |partition| {
        if (partition.table_index == table_index) {
            target = partition;
            break;
        }
    }
    const selected = target orelse return error.PartitionNotFound;
    for (verified.partitions) |partition| {
        if (partition.table_index != table_index and
            partition.last_lba > selected.last_lba)
        {
            return error.PartitionNotLast;
        }
    }

    const relocation = try relocateBackup(img, io, allocator, verified);
    if (selected.last_lba >= relocation.new_last_usable_lba) {
        return error.NotEnoughSpace;
    }

    var primary_sector: [sector_size]u8 = undefined;
    try preadExact(img.*, io, &primary_sector, sector_size);
    var backup_sector: [sector_size]u8 = undefined;
    try preadExact(
        img.*,
        io,
        &backup_sector,
        try sectorOffset(relocation.new_backup_lba),
    );

    const entry_size = std.mem.readInt(u32, primary_sector[84..88], .little);
    if (entry_size < partition_entry_size or entry_size % 8 != 0) {
        return error.UnsupportedPartitionEntrySize;
    }
    const array_bytes = try partitionArrayBytes(Header.decode(&primary_sector) catch
        return error.InvalidPartitionArrayBounds);
    const array_len = std.math.cast(usize, array_bytes) orelse
        return error.PartitionArrayTooLarge;
    const entry_offset_u64 = std.math.mul(
        u64,
        table_index,
        entry_size,
    ) catch return error.InvalidPartitionArrayBounds;
    const entry_end = std.math.add(
        u64,
        entry_offset_u64,
        partition_entry_size,
    ) catch return error.InvalidPartitionArrayBounds;
    if (entry_end > array_bytes) return error.PartitionNotFound;
    const entry_offset = std.math.cast(usize, entry_offset_u64) orelse
        return error.InvalidPartitionArrayBounds;

    const primary_array_lba = std.mem.readInt(u64, primary_sector[72..80], .little);
    const backup_array_lba = std.mem.readInt(u64, backup_sector[72..80], .little);
    const array = try allocator.alloc(u8, array_len);
    defer allocator.free(array);
    try preadExact(img.*, io, array, try sectorOffset(primary_array_lba));
    const current_last = std.mem.readInt(
        u64,
        array[entry_offset + 40 ..][0..8],
        .little,
    );
    if (current_last != selected.last_lba) return error.SourceMetadataChanged;
    std.mem.writeInt(
        u64,
        array[entry_offset + 40 ..][0..8],
        relocation.new_last_usable_lba,
        .little,
    );
    const array_crc = std.hash.crc.Crc32.hash(array);
    std.mem.writeInt(u32, primary_sector[88..92], array_crc, .little);
    std.mem.writeInt(u32, backup_sector[88..92], array_crc, .little);
    updateHeaderChecksum(&primary_sector);
    updateHeaderChecksum(&backup_sector);

    try img.pwrite(io, array, try sectorOffset(primary_array_lba));
    try img.pwrite(io, array, try sectorOffset(backup_array_lba));
    try img.pwrite(io, &backup_sector, try sectorOffset(relocation.new_backup_lba));
    try img.pwrite(io, &primary_sector, sector_size);

    return .{
        .old_last_lba = selected.last_lba,
        .new_last_lba = relocation.new_last_usable_lba,
        .relocation = relocation,
    };
}

/// Relocates a verified backup GPT to the current end of `img` without
/// changing any partition entry or partition extent. The partition array is
/// copied as opaque bytes, and the protective MBR update preserves bootstrap
/// code, disk signature, and unrelated bytes.
pub fn relocateBackup(
    img: *Image,
    io: Io,
    allocator: std.mem.Allocator,
    verified: VerifiedGpt,
) RelocateError!RelocationResult {
    if (img.virtual_size == 0 or img.virtual_size % sector_size != 0) {
        return error.ImageNotSectorAligned;
    }
    const new_backup_lba = img.virtual_size / sector_size - 1;
    const old_backup_lba = verified.primary_header.backup_lba;
    if (new_backup_lba < old_backup_lba) return error.ImageDidNotGrow;
    if (new_backup_lba == old_backup_lba) {
        return .{
            .was_relocated = false,
            .old_backup_lba = old_backup_lba,
            .new_backup_lba = new_backup_lba,
            .old_last_usable_lba = verified.primary_header.last_usable_lba,
            .new_last_usable_lba = verified.primary_header.last_usable_lba,
        };
    }

    var current_primary: [sector_size]u8 = undefined;
    try preadExact(img.*, io, &current_primary, sector_size);
    if (!std.mem.eql(
        u8,
        &current_primary,
        &verified.primary_header_sector,
    )) return error.SourceMetadataChanged;
    const current_array = try allocator.alloc(
        u8,
        verified.partition_array.len,
    );
    defer allocator.free(current_array);
    try preadExact(
        img.*,
        io,
        current_array,
        try sectorOffset(verified.primary_header.partition_entry_lba),
    );
    if (!std.mem.eql(u8, current_array, verified.partition_array)) {
        return error.SourceMetadataChanged;
    }
    var current_mbr: [sector_size]u8 = undefined;
    try preadExact(img.*, io, &current_mbr, 0);
    if (!std.mem.eql(u8, &current_mbr, &verified.protective_mbr_sector)) {
        return error.SourceMetadataChanged;
    }

    const array_bytes: u64 = @intCast(verified.partition_array.len);
    const array_sectors = std.math.divCeil(u64, array_bytes, sector_size) catch
        return error.InvalidPartitionArrayBounds;
    if (new_backup_lba <= array_sectors) {
        return error.InvalidPartitionArrayBounds;
    }
    const new_backup_array_lba = new_backup_lba - array_sectors;
    if (new_backup_array_lba == 0) return error.InvalidPartitionArrayBounds;
    const new_last_usable_lba = new_backup_array_lba - 1;
    if (new_last_usable_lba < verified.primary_header.last_usable_lba) {
        return error.ImageDidNotGrow;
    }
    for (verified.partitions) |partition| {
        if (partition.last_lba > new_last_usable_lba) {
            return error.InvalidPartitionBounds;
        }
    }

    var primary_sector = verified.primary_header_sector;
    std.mem.writeInt(u64, primary_sector[32..40], new_backup_lba, .little);
    std.mem.writeInt(
        u64,
        primary_sector[48..56],
        new_last_usable_lba,
        .little,
    );
    updateHeaderChecksum(&primary_sector);

    var backup_sector = verified.backup_header_sector;
    std.mem.writeInt(u64, backup_sector[24..32], new_backup_lba, .little);
    std.mem.writeInt(
        u64,
        backup_sector[32..40],
        verified.primary_header.current_lba,
        .little,
    );
    std.mem.writeInt(
        u64,
        backup_sector[48..56],
        new_last_usable_lba,
        .little,
    );
    std.mem.writeInt(
        u64,
        backup_sector[72..80],
        new_backup_array_lba,
        .little,
    );
    updateHeaderChecksum(&backup_sector);

    var protective_mbr = verified.protective_mbr_sector;
    const entry_offset = mbr.partition_table_offset +
        @as(usize, verified.protective_entry_index) * mbr.entry_size;
    const sector_count = protectiveSectorCount(new_backup_lba + 1);
    const end_chs = mbr.chsForLba(sector_count);
    @memcpy(protective_mbr[entry_offset + 5 .. entry_offset + 8], &end_chs);
    std.mem.writeInt(
        u32,
        protective_mbr[entry_offset + 12 ..][0..4],
        sector_count,
        .little,
    );

    try img.pwrite(
        io,
        verified.partition_array,
        try sectorOffset(new_backup_array_lba),
    );
    try img.pwrite(
        io,
        &backup_sector,
        try sectorOffset(new_backup_lba),
    );
    try img.pwrite(io, &protective_mbr, 0);
    try img.pwrite(io, &primary_sector, sector_size);

    return .{
        .was_relocated = true,
        .old_backup_lba = old_backup_lba,
        .new_backup_lba = new_backup_lba,
        .old_last_usable_lba = verified.primary_header.last_usable_lba,
        .new_last_usable_lba = new_last_usable_lba,
    };
}

fn decodeStrictHeader(buf: *const [sector_size]u8) VerifyError!Header {
    const header = try Header.decode(buf);
    if (header.revision != 0x0001_0000) return error.UnsupportedRevision;
    if (header.header_size != header_size) return error.UnsupportedHeaderSize;
    if (!std.mem.allEqual(u8, buf[20..24], 0) or
        !std.mem.allEqual(u8, buf[header_size..], 0))
    {
        return error.InvalidHeaderReservedBytes;
    }
    if (header.partition_entry_size < partition_entry_size or
        header.partition_entry_size % 8 != 0 or
        header.num_partition_entries == 0)
    {
        return error.UnsupportedPartitionEntrySize;
    }
    return header;
}

fn partitionArrayBytes(header: Header) error{InvalidPartitionArrayBounds}!u64 {
    return std.math.mul(
        u64,
        header.num_partition_entries,
        header.partition_entry_size,
    ) catch error.InvalidPartitionArrayBounds;
}

fn sectorOffset(lba: u64) error{InvalidPartitionArrayBounds}!u64 {
    return std.math.mul(u64, lba, sector_size) catch
        error.InvalidPartitionArrayBounds;
}

fn preadExact(
    img: Image,
    io: Io,
    buffer: []u8,
    offset: u64,
) (Image.PreadError || error{UnexpectedEndOfFile})!void {
    if (try img.pread(io, buffer, offset) != buffer.len) {
        return error.UnexpectedEndOfFile;
    }
}

fn writeZeros(
    img: *Image,
    io: Io,
    offset: u64,
    len: u64,
) Image.PwriteError!void {
    const zeros: [64 * 1024]u8 = [_]u8{0} ** (64 * 1024);
    var written: u64 = 0;
    while (written < len) {
        const chunk_len: usize = @intCast(@min(len - written, zeros.len));
        try img.pwrite(io, zeros[0..chunk_len], offset + written);
        written += chunk_len;
    }
}

fn eraseSectorRange(
    img: *Image,
    io: Io,
    start_lba: u64,
    sector_count: u64,
    total_sectors: u64,
) Image.PwriteError!void {
    if (start_lba >= total_sectors or sector_count == 0) return;
    const bounded_count = @min(sector_count, total_sectors - start_lba);
    try writeZeros(
        img,
        io,
        start_lba * sector_size,
        bounded_count * sector_size,
    );
}

fn protectiveSectorCount(total_sectors: u64) u32 {
    return @intCast(@min(total_sectors - 1, std.math.maxInt(u32)));
}

fn updateHeaderChecksum(buf: *[sector_size]u8) void {
    const encoded_header_size = std.mem.readInt(u32, buf[12..16], .little);
    std.debug.assert(encoded_header_size >= header_size);
    std.debug.assert(encoded_header_size <= sector_size);
    buf[16..20].* = .{ 0, 0, 0, 0 };
    const checksum = std.hash.crc.Crc32.hash(buf[0..encoded_header_size]);
    std.mem.writeInt(u32, buf[16..20], checksum, .little);
}

const TestRawPartitionEntry = struct {
    entry: PartitionEntry,
    opaque_tail: []const u8 = &.{},
};

const TestOpaqueTail = struct {
    table_index: u32,
    bytes: []const u8,
};

fn writeCustomPartitionTablesForTest(
    img: *Image,
    io: Io,
    disk_guid: guid.Guid,
    entry_size: u32,
    num_entries: u32,
    entries: []const TestRawPartitionEntry,
    unused_tails: []const TestOpaqueTail,
) !void {
    const entry_size_usize: usize = @intCast(entry_size);
    const num_entries_usize: usize = @intCast(num_entries);
    std.debug.assert(entry_size >= partition_entry_size);
    std.debug.assert(entry_size % 8 == 0);
    std.debug.assert(entries.len <= num_entries_usize);

    const total_sectors = img.virtual_size / sector_size;
    const array_bytes: u64 = @as(u64, num_entries) * entry_size;
    const array_sectors = std.math.divCeil(u64, array_bytes, sector_size) catch unreachable;
    const first_usable_lba: u64 = 2 + array_sectors;
    const backup_array_lba = total_sectors - 1 - array_sectors;
    const last_usable_lba = backup_array_lba - 1;
    const array_len: usize = @intCast(array_bytes);
    const array = try std.testing.allocator.alloc(u8, array_len);
    defer std.testing.allocator.free(array);
    @memset(array, 0);

    var previous_last_lba = first_usable_lba - 1;
    for (entries, 0..) |fixture, i| {
        if (fixture.entry.first_lba < first_usable_lba or
            fixture.entry.last_lba < fixture.entry.first_lba or
            fixture.entry.last_lba > last_usable_lba or
            (i > 0 and fixture.entry.first_lba <= previous_last_lba))
        {
            return error.InvalidPlacement;
        }
        previous_last_lba = fixture.entry.last_lba;

        const entry_offset = i * entry_size_usize;
        fixture.entry.encode(array[entry_offset..][0..partition_entry_size]);
        const opaque_bytes = array[entry_offset + partition_entry_size .. entry_offset + entry_size_usize];
        std.debug.assert(fixture.opaque_tail.len <= opaque_bytes.len);
        @memcpy(opaque_bytes[0..fixture.opaque_tail.len], fixture.opaque_tail);
    }

    for (unused_tails) |unused| {
        const table_index: usize = @intCast(unused.table_index);
        std.debug.assert(table_index < num_entries_usize);
        std.debug.assert(table_index >= entries.len);
        const entry_offset = table_index * entry_size_usize;
        const opaque_bytes = array[entry_offset + partition_entry_size .. entry_offset + entry_size_usize];
        std.debug.assert(unused.bytes.len <= opaque_bytes.len);
        @memcpy(opaque_bytes[0..unused.bytes.len], unused.bytes);
    }

    const array_crc = std.hash.crc.Crc32.hash(array);
    const primary = Header{
        .current_lba = 1,
        .backup_lba = total_sectors - 1,
        .first_usable_lba = first_usable_lba,
        .last_usable_lba = last_usable_lba,
        .disk_guid = disk_guid,
        .partition_entry_lba = 2,
        .num_partition_entries = num_entries,
        .partition_entry_size = entry_size,
        .partition_array_crc32 = array_crc,
    };
    const backup = Header{
        .current_lba = total_sectors - 1,
        .backup_lba = 1,
        .first_usable_lba = first_usable_lba,
        .last_usable_lba = last_usable_lba,
        .disk_guid = disk_guid,
        .partition_entry_lba = backup_array_lba,
        .num_partition_entries = num_entries,
        .partition_entry_size = entry_size,
        .partition_array_crc32 = array_crc,
    };

    const protective_mbr = mbr.protectiveMbr(total_sectors).encode();
    try img.pwrite(io, &protective_mbr, 0);
    try img.pwrite(io, &primary.encode(), sector_size);
    try img.pwrite(io, array, 2 * sector_size);
    try img.pwrite(io, array, backup_array_lba * sector_size);
    try img.pwrite(io, &backup.encode(), (total_sectors - 1) * sector_size);
}

fn testEntrySlice(array: []const u8, entry_size: u32, table_index: u32) []const u8 {
    const entry_size_usize: usize = @intCast(entry_size);
    const start = @as(usize, @intCast(table_index)) * entry_size_usize;
    return array[start .. start + entry_size_usize];
}

test "invalidateDestinationPartitionStructures clears both GPT metadata regions" {
    const io = std.testing.io;
    const path = "test-gpt-destination-invalidate.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const array_bytes: u64 =
        default_num_partition_entries * partition_entry_size;
    const start_len: usize = @intCast(2 * sector_size + array_bytes);
    const end_len: usize = @intCast(sector_size + array_bytes);
    const size: u64 = 2 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, size, .{});
    defer img.close(io);

    const stale_start = [_]u8{0xa5} ** start_len;
    const stale_end = [_]u8{0x5a} ** end_len;
    const start_guard = [_]u8{0x3c} ** sector_size;
    const end_guard = [_]u8{0xc3} ** sector_size;
    const end_guard_offset = size - end_len - sector_size;
    try img.pwrite(io, &stale_start, 0);
    try img.pwrite(io, &stale_end, size - end_len);
    try img.pwrite(io, &start_guard, start_len);
    try img.pwrite(io, &end_guard, end_guard_offset);

    try invalidateDestinationPartitionStructures(&img, io, array_bytes);

    var cleared_start: [start_len]u8 = undefined;
    var cleared_end: [end_len]u8 = undefined;
    var preserved_start_guard: [sector_size]u8 = undefined;
    var preserved_end_guard: [sector_size]u8 = undefined;
    try preadExact(img, io, &cleared_start, 0);
    try preadExact(img, io, &cleared_end, size - end_len);
    try preadExact(img, io, &preserved_start_guard, start_len);
    try preadExact(img, io, &preserved_end_guard, end_guard_offset);
    try std.testing.expect(std.mem.allEqual(u8, &cleared_start, 0));
    try std.testing.expect(std.mem.allEqual(u8, &cleared_end, 0));
    try std.testing.expectEqualSlices(u8, &start_guard, &preserved_start_guard);
    try std.testing.expectEqualSlices(u8, &end_guard, &preserved_end_guard);
}

test "invalidateDestinationPartitionStructures clears small destinations safely" {
    const io = std.testing.io;
    const path = "test-gpt-destination-invalid-geometry.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const array_bytes: u64 =
        default_num_partition_entries * partition_entry_size;
    const metadata_sectors =
        2 * (array_bytes / sector_size) + 3;
    var img = try Image.create(
        io,
        path,
        .raw,
        metadata_sectors * sector_size,
        .{},
    );
    defer img.close(io);

    try img.pwrite(io, &([_]u8{0xa5} ** sector_size), 0);
    try invalidateDestinationPartitionStructures(&img, io, array_bytes);
    var first_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &first_sector, 0);
    try std.testing.expect(std.mem.allEqual(u8, &first_sector, 0));
    try std.testing.expectError(
        error.InvalidPartitionArrayLimit,
        invalidateDestinationPartitionStructures(&img, io, 0),
    );

    img.virtual_size -= 1;
    try std.testing.expectError(
        error.ImageNotSectorAligned,
        invalidateDestinationPartitionStructures(&img, io, array_bytes),
    );
}

test "invalidateDestinationPartitionStructures clears an advertised intermediate backup" {
    const io = std.testing.io;
    const path = "test-gpt-destination-intermediate-backup.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 8 * 1024 * 1024;
    const advertised_backup_lba: u64 = 4095;
    const array_bytes: u64 =
        default_num_partition_entries * partition_entry_size;
    var img = try Image.create(io, path, .raw, size, .{});
    defer img.close(io);

    var primary: [sector_size]u8 = [_]u8{0} ** sector_size;
    @memcpy(primary[0..signature.len], &signature);
    std.mem.writeInt(u32, primary[8..12], 0x0001_0000, .little);
    std.mem.writeInt(u32, primary[12..16], header_size, .little);
    std.mem.writeInt(u64, primary[32..40], advertised_backup_lba, .little);
    std.mem.writeInt(u64, primary[72..80], 2, .little);
    updateHeaderChecksum(&primary);
    try img.pwrite(io, &primary, sector_size);
    try img.pwrite(
        io,
        &([_]u8{0xa5} ** sector_size),
        advertised_backup_lba * sector_size,
    );

    try invalidateDestinationPartitionStructures(&img, io, array_bytes);

    var backup: [sector_size]u8 = undefined;
    try preadExact(
        img,
        io,
        &backup,
        advertised_backup_lba * sector_size,
    );
    try std.testing.expect(std.mem.allEqual(u8, &backup, 0));
}

test "detectVerifiedGpt passes through non-GPT and rejects malformed GPT" {
    const io = std.testing.io;
    const path = "test-gpt-detect.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 8 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, size, .{});
    defer img.close(io);

    var blank = try detectVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer blank.deinit(std.testing.allocator);
    try std.testing.expect(blank == .not_gpt);

    const protective = mbr.protectiveMbr(size / sector_size).encode();
    try img.pwrite(io, &protective, 0);
    try std.testing.expectError(
        error.BadSignature,
        detectVerifiedGpt(
            img,
            io,
            std.testing.allocator,
            default_max_partition_array_bytes,
        ),
    );

    const disk_guid = guid.parse("99999999-8888-7777-6666-555555555555");
    const entries = [_]PartitionEntry{.{
        .partition_type_guid = guid.linux_filesystem_data,
        .unique_partition_guid = guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        .first_lba = 2048,
        .last_lba = 4095,
    }};
    try writePartitionTables(&img, io, disk_guid, &entries);
    var detected = try detectVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer detected.deinit(std.testing.allocator);
    try std.testing.expect(detected == .verified);
    const relocation = try relocateBackup(
        &img,
        io,
        std.testing.allocator,
        detected.verified,
    );
    try std.testing.expect(!relocation.was_relocated);

    var primary: [sector_size]u8 = undefined;
    try preadExact(img, io, &primary, sector_size);
    primary[16] ^= 0xff;
    try img.pwrite(io, &primary, sector_size);
    try std.testing.expectError(
        error.BadHeaderChecksum,
        detectVerifiedGpt(
            img,
            io,
            std.testing.allocator,
            default_max_partition_array_bytes,
        ),
    );
}

test "readVerifiedGpt and relocateBackup preserve partition bytes and extents" {
    const io = std.testing.io;
    const path = "test-gpt-verified-relocate.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const source_size: u64 = 64 * 1024 * 1024 - sector_size;
    var img = try Image.create(io, path, .raw, source_size, .{});
    defer img.close(io);

    const disk_guid = guid.parse("11111111-2222-3333-4444-555555555555");
    const entries = [_]PartitionEntry{
        .{
            .partition_type_guid = guid.esp,
            .unique_partition_guid = guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
            .first_lba = 2048,
            .last_lba = 4095,
            .attributes = 0x1000_0000_0000_0001,
            .name_utf16le = asciiName("efi"),
        },
        .{
            .partition_type_guid = guid.linux_filesystem_data,
            .unique_partition_guid = guid.parse("01234567-89ab-cdef-0123-456789abcdef"),
            .first_lba = 8192,
            .last_lba = 32767,
            .attributes = 0x8000_0000_0000_0000,
            .name_utf16le = asciiName("root"),
        },
    };
    try writePartitionTables(&img, io, disk_guid, &entries);

    var mbr_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &mbr_sector, 0);
    mbr_sector[17] = 0xa5;
    try img.pwrite(io, &mbr_sector, 0);

    var verified = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        1024 * 1024,
    );
    defer verified.deinit(std.testing.allocator);
    const original_array = try std.testing.allocator.dupe(
        u8,
        verified.partition_array,
    );
    defer std.testing.allocator.free(original_array);
    const original_partitions = try std.testing.allocator.dupe(
        PartitionEntry,
        verified.partitions,
    );
    defer std.testing.allocator.free(original_partitions);

    const target_size: u64 = 64 * 1024 * 1024;
    try img.resize(io, target_size);
    const relocation = try relocateBackup(
        &img,
        io,
        std.testing.allocator,
        verified,
    );
    try std.testing.expect(relocation.was_relocated);
    try std.testing.expectEqual(
        target_size / sector_size - 1,
        relocation.new_backup_lba,
    );

    var relocated = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        1024 * 1024,
    );
    defer relocated.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(
        u8,
        original_array,
        relocated.partition_array,
    );
    try std.testing.expectEqual(original_partitions.len, relocated.partitions.len);
    for (original_partitions, relocated.partitions) |before, after| {
        try std.testing.expectEqual(before.table_index, after.table_index);
        try std.testing.expectEqual(before.first_lba, after.first_lba);
        try std.testing.expectEqual(before.last_lba, after.last_lba);
        try std.testing.expectEqual(before.attributes, after.attributes);
        try std.testing.expectEqualSlices(
            u8,
            std.mem.asBytes(&before.name_utf16le),
            std.mem.asBytes(&after.name_utf16le),
        );
    }
    try std.testing.expectEqual(@as(u8, 0xa5), relocated.protective_mbr_sector[17]);
}

test "readVerifiedGpt rejects backup corruption and overlapping partitions" {
    const io = std.testing.io;
    const path = "test-gpt-verified-corruption.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const size: u64 = 32 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, size, .{});
    defer img.close(io);
    const disk_guid = guid.parse("22222222-3333-4444-5555-666666666666");
    const entries = [_]PartitionEntry{
        .{
            .partition_type_guid = guid.esp,
            .unique_partition_guid = guid.parse("aaaaaaaa-0000-0000-0000-000000000001"),
            .first_lba = 2048,
            .last_lba = 4095,
        },
        .{
            .partition_type_guid = guid.linux_filesystem_data,
            .unique_partition_guid = guid.parse("aaaaaaaa-0000-0000-0000-000000000002"),
            .first_lba = 4095,
            .last_lba = 8191,
        },
    };
    try writePartitionTables(&img, io, disk_guid, &entries);
    try std.testing.expectError(
        error.OverlappingPartitions,
        readVerifiedGpt(img, io, std.testing.allocator, 1024 * 1024),
    );

    const valid_entries = [_]PartitionEntry{entries[0]};
    try writePartitionTables(&img, io, disk_guid, &valid_entries);
    const backup_array_lba =
        size / sector_size - 1 - partition_array_sectors;
    var byte: [1]u8 = undefined;
    try preadExact(img, io, &byte, try sectorOffset(backup_array_lba));
    byte[0] ^= 0xff;
    try img.pwrite(io, &byte, try sectorOffset(backup_array_lba));
    try std.testing.expectError(
        error.BadPartitionArrayChecksum,
        readVerifiedGpt(img, io, std.testing.allocator, 1024 * 1024),
    );
}

test "growLastPartition extends the last partition and relocates the backup header/array" {
    const io = std.testing.io;
    const path = "test-gpt-grow.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const initial_size: u64 = 128 * 1024 * 1024; // 128 MiB
    var img = try Image.create(io, path, .raw, initial_size, .{});
    defer img.close(io);

    const disk_guid = guid.parse("66666666-6666-6666-6666-666666666666");
    const esp_sectors: u64 = (32 * 1024 * 1024) / sector_size;
    const first_usable_lba: u64 = 2 + partition_array_sectors;
    const esp_last_lba = first_usable_lba + esp_sectors - 1;
    const root_first_lba = esp_last_lba + 1;
    const initial_total_sectors = initial_size / sector_size;
    const initial_last_usable_lba = initial_total_sectors - 2 - partition_array_sectors;

    // Arbitrary nonzero attribute bits, standing in for whatever a real
    // ESP sets (e.g. the "required partition" bit) -- there's no public
    // way to set these via `writeGpt`/`writeGptPlaced` today (neither
    // `PartitionSpec` nor `PlacedPartitionSpec` has an `attributes` field),
    // so this test writes the initial layout directly via the
    // module-private `writePartitionTables` to exercise the case anyway.
    const esp_attributes: u64 = 0x3;

    var entries = [_]PartitionEntry{
        .{
            .partition_type_guid = guid.esp,
            .unique_partition_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .first_lba = first_usable_lba,
            .last_lba = esp_last_lba,
            .attributes = esp_attributes,
            .name_utf16le = asciiName("EFI System"),
        },
        .{
            .partition_type_guid = guid.linux_filesystem_data,
            .unique_partition_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .first_lba = root_first_lba,
            .last_lba = initial_last_usable_lba / 2, // deliberately not filling the disk
            .name_utf16le = asciiName("root"),
        },
    };
    try writePartitionTables(&img, io, disk_guid, &entries);

    // Simulate the disk having been deployed at a larger size than the
    // image was built at.
    const grown_size: u64 = 512 * 1024 * 1024; // 512 MiB
    try img.resize(io, grown_size);

    const before = try readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(before.partitions);
    try std.testing.expectEqual(@as(usize, 2), before.partitions.len);

    try growLastPartition(&img, io, disk_guid, before.partitions);

    const after = try readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(after.partitions);
    try std.testing.expectEqual(@as(usize, 2), after.partitions.len);

    // ESP is untouched: GUIDs, name, LBAs, and attributes all preserved.
    try std.testing.expectEqualSlices(u8, &guid.esp, &after.partitions[0].partition_type_guid);
    try std.testing.expectEqualSlices(u8, &entries[0].unique_partition_guid, &after.partitions[0].unique_partition_guid);
    try std.testing.expectEqual(entries[0].first_lba, after.partitions[0].first_lba);
    try std.testing.expectEqual(entries[0].last_lba, after.partitions[0].last_lba);
    try std.testing.expectEqual(esp_attributes, after.partitions[0].attributes);
    try std.testing.expectEqualSlices(u16, &entries[0].name_utf16le, &after.partitions[0].name_utf16le);

    // Root's last_lba now reaches the new, larger disk's last usable LBA.
    const grown_total_sectors = grown_size / sector_size;
    const grown_last_usable_lba = grown_total_sectors - 2 - partition_array_sectors;
    try std.testing.expectEqual(entries[1].first_lba, after.partitions[1].first_lba);
    try std.testing.expectEqual(grown_last_usable_lba, after.partitions[1].last_lba);
    try std.testing.expect(grown_last_usable_lba > initial_last_usable_lba);
    try std.testing.expectEqual(grown_last_usable_lba, after.header.last_usable_lba);

    // Backup header/array parse correctly from their new, relocated
    // position at the disk's new true end -- proving the backup copy
    // physically moved, not just the primary.
    try std.testing.expectEqual(grown_total_sectors - 1, after.header.backup_lba);
    var backup_header_buf: [sector_size]u8 = undefined;
    _ = try img.pread(io, &backup_header_buf, sector_size * (grown_total_sectors - 1));
    const backup_header = try Header.decode(&backup_header_buf);
    try std.testing.expectEqual(@as(u64, 1), backup_header.backup_lba);
    try std.testing.expectEqual(grown_last_usable_lba, backup_header.last_usable_lba);
}

test "sparse multi-terabyte GPT growth uses 64-bit offsets and validates both copies" {
    const io = std.testing.io;
    const path = "test-gpt-grow-sparse-multiterabyte.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const initial_size: u64 = 64 * 1024 * 1024;
    const grown_size: u64 = 4 * 1024 * 1024 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, initial_size, .{});
    defer img.close(io);

    const total_sectors = initial_size / sector_size;
    const first_usable_lba: u64 = 2 + partition_array_sectors;
    const initial_last_usable_lba = total_sectors - 2 - partition_array_sectors;
    const specs = [_]PartitionSpec{.{
        .type_guid = guid.linux_filesystem_data,
        .unique_guid = guid.parse("44444444-4444-4444-4444-444444444444"),
        .size_sectors = initial_last_usable_lba - first_usable_lba + 1,
        .name_utf16le = asciiName("root"),
    }};
    var placements: [specs.len]Placement = undefined;
    const disk_guid = guid.parse("55555555-5555-5555-5555-555555555555");
    try writeGpt(&img, io, disk_guid, &specs, &placements);
    const old_backup_lba = total_sectors - 1;

    // setLength creates a sparse logical disk; only the GPT sectors at the
    // beginning and end are written during this test.
    try img.resize(io, grown_size);
    try std.testing.expectEqual(grown_size, (try img.file.stat(io)).size);

    const before = try readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(before.partitions);
    try growLastPartition(&img, io, disk_guid, before.partitions);

    var after = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        1024 * 1024,
    );
    defer after.deinit(std.testing.allocator);

    const grown_total_sectors = grown_size / sector_size;
    const new_backup_lba = grown_total_sectors - 1;
    const grown_last_usable_lba =
        grown_total_sectors - 2 - partition_array_sectors;
    try std.testing.expect(new_backup_lba > std.math.maxInt(u32));
    try std.testing.expect(new_backup_lba > old_backup_lba);
    try std.testing.expectEqual(new_backup_lba, after.primary_header.backup_lba);
    try std.testing.expectEqual(new_backup_lba, after.backup_header.current_lba);
    try std.testing.expectEqual(@as(u64, 1), after.backup_header.backup_lba);
    try std.testing.expectEqual(@as(usize, 1), after.partitions.len);
    try std.testing.expectEqual(grown_last_usable_lba, after.partitions[0].last_lba);
    try std.testing.expectEqual(
        std.hash.crc.Crc32.hash(after.partition_array),
        after.primary_header.partition_array_crc32,
    );
    try std.testing.expectEqual(
        after.primary_header.partition_array_crc32,
        after.backup_header.partition_array_crc32,
    );

    const retry = try readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(retry.partitions);
    try std.testing.expectError(
        error.NotEnoughSpace,
        growLastPartition(&img, io, disk_guid, retry.partitions),
    );
}

test "growLastPartition rejects a disk that hasn't actually grown" {
    const io = std.testing.io;
    const path = "test-gpt-grow-noop.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    // Fill the partition all the way to the disk's current last usable
    // LBA, so there's genuinely no free space left to grow into.
    const total_sectors = disk_size / sector_size;
    const first_usable_lba: u64 = 2 + partition_array_sectors;
    const last_usable_lba: u64 = total_sectors - 2 - partition_array_sectors;
    const specs = [_]PartitionSpec{
        .{ .type_guid = guid.linux_filesystem_data, .unique_guid = guid.parse("77777777-7777-7777-7777-777777777777"), .size_sectors = last_usable_lba - first_usable_lba + 1 },
    };
    var placements: [specs.len]Placement = undefined;
    const disk_guid = guid.parse("88888888-8888-8888-8888-888888888888");
    try writeGpt(&img, io, disk_guid, &specs, &placements);

    const parsed = try readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(parsed.partitions);

    try std.testing.expectError(error.NotEnoughSpace, growLastPartition(&img, io, disk_guid, parsed.partitions));
}

test "writeGpt + readGpt round-trip an ESP + Linux root layout" {
    const io = std.testing.io;
    const path = "test-gpt-roundtrip.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 256 * 1024 * 1024; // 256 MiB
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const esp_sectors: u64 = (100 * 1024 * 1024) / sector_size; // 100 MiB ESP
    const specs = [_]PartitionSpec{
        .{ .type_guid = guid.esp, .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"), .size_sectors = esp_sectors, .name_utf16le = asciiName("EFI System") },
        .{ .type_guid = guid.linux_filesystem_data, .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222"), .size_sectors = (disk_size / sector_size) / 2, .name_utf16le = asciiName("root") },
    };
    var placements: [specs.len]Placement = undefined;
    const disk_guid = guid.parse("33333333-3333-3333-3333-333333333333");
    try writeGpt(&img, io, disk_guid, &specs, &placements);

    const parsed = try readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(parsed.partitions);

    try std.testing.expectEqual(@as(usize, 2), parsed.partitions.len);
    try std.testing.expectEqualSlices(u8, &guid.esp, &parsed.partitions[0].partition_type_guid);
    try std.testing.expectEqual(placements[0].first_lba, parsed.partitions[0].first_lba);
    try std.testing.expectEqual(placements[0].last_lba, parsed.partitions[0].last_lba);
    try std.testing.expectEqualSlices(u8, &guid.linux_filesystem_data, &parsed.partitions[1].partition_type_guid);
    try std.testing.expectEqual(placements[1].first_lba, parsed.partitions[1].first_lba);
    try std.testing.expectEqualSlices(u8, &disk_guid, &parsed.header.disk_guid);

    // Partitions must not overlap and must be within the disk.
    try std.testing.expect(parsed.partitions[1].first_lba > parsed.partitions[0].last_lba);
    try std.testing.expect(parsed.partitions[1].last_lba <= parsed.header.last_usable_lba);
}

test "readGpt detects a corrupted partition array" {
    const io = std.testing.io;
    const path = "test-gpt-corrupt.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 64 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]PartitionSpec{
        .{ .type_guid = guid.linux_filesystem_data, .unique_guid = guid.parse("44444444-4444-4444-4444-444444444444"), .size_sectors = (disk_size / sector_size) / 2 },
    };
    var placements: [specs.len]Placement = undefined;
    try writeGpt(&img, io, guid.parse("55555555-5555-5555-5555-555555555555"), &specs, &placements);

    // Corrupt one byte inside the primary partition array (LBA 2..33).
    var one: [1]u8 = .{0xAB};
    try img.pwrite(io, &one, sector_size * 2 + 5);

    try std.testing.expectError(error.BadPartitionArrayChecksum, readGpt(img, io, std.testing.allocator));
}

test "Header.decode rejects invalid header sizes before checksumming" {
    var encoded = [_]u8{0} ** sector_size;
    encoded[0..signature.len].* = signature;

    std.mem.writeInt(u32, encoded[12..16], header_size - 1, .little);
    try std.testing.expectError(error.InvalidHeaderSize, Header.decode(&encoded));

    std.mem.writeInt(u32, encoded[12..16], sector_size + 1, .little);
    try std.testing.expectError(error.InvalidHeaderSize, Header.decode(&encoded));
}

test "readGpt rejects truncated headers and partition arrays" {
    const io = std.testing.io;
    const header_path = "test-gpt-truncated-header.img";
    const array_path = "test-gpt-truncated-array.img";
    defer Io.Dir.cwd().deleteFile(io, header_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, array_path) catch {};

    {
        var img = try Image.create(io, header_path, .raw, sector_size, .{});
        defer img.close(io);
        try std.testing.expectError(error.UnexpectedEndOfFile, readGpt(img, io, std.testing.allocator));
    }

    {
        var img = try Image.create(io, array_path, .raw, sector_size * 2, .{});
        defer img.close(io);
        const encoded = (Header{
            .current_lba = 1,
            .backup_lba = 1,
            .first_usable_lba = 2,
            .last_usable_lba = 2,
            .disk_guid = guid.nil,
            .partition_entry_lba = 2,
            .partition_array_crc32 = 0,
        }).encode();
        try img.pwrite(io, &encoded, sector_size);
        try std.testing.expectError(error.InvalidPartitionArrayBounds, readGpt(img, io, std.testing.allocator));
    }
}

test "rewriteIdentity preserves opaque GPT entry bytes on same-size disks" {
    const io = std.testing.io;
    const path = "test-gpt-identity-rewrite-same-size.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 32 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const entry_size: u32 = 160;
    const num_entries: u32 = 4;
    const disk_guid = guid.parse("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee");
    const entries = [_]TestRawPartitionEntry{
        .{ .entry = .{
            .partition_type_guid = guid.esp,
            .unique_partition_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .first_lba = 2048,
            .last_lba = 4095,
            .attributes = 0x0123_4567_89ab_cdef,
            .name_utf16le = asciiName("EFI System"),
        }, .opaque_tail = &([_]u8{0xa1} ** 32) },
        .{ .entry = .{
            .partition_type_guid = guid.linux_filesystem_data,
            .unique_partition_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .first_lba = 8192,
            .last_lba = 32767,
            .attributes = 0xfedc_ba98_7654_3210,
            .name_utf16le = asciiName("root"),
        }, .opaque_tail = &([_]u8{0xb2} ** 32) },
    };
    const unused_tails = [_]TestOpaqueTail{
        .{ .table_index = 2, .bytes = &([_]u8{0xc3} ** 32) },
        .{ .table_index = 3, .bytes = &([_]u8{0xd4} ** 32) },
    };
    try writeCustomPartitionTablesForTest(
        &img,
        io,
        disk_guid,
        entry_size,
        num_entries,
        &entries,
        &unused_tails,
    );

    var mbr_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &mbr_sector, 0);
    mbr_sector[17] = 0x7a;
    std.mem.writeInt(u32, mbr_sector[0x1B8..0x1BC], 0x7856_3412, .little);
    try img.pwrite(io, &mbr_sector, 0);

    var verified = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer verified.deinit(std.testing.allocator);

    const replacement_partition_guids = [_]guid.Guid{
        guid.parse("33333333-3333-3333-3333-333333333333"),
        guid.parse("44444444-4444-4444-4444-444444444444"),
    };
    const replacement = ReplacementGuids{
        .disk_guid = guid.parse("55555555-5555-5555-5555-555555555555"),
        .partition_guids = &replacement_partition_guids,
    };
    var report = try rewriteIdentity(
        &img,
        io,
        std.testing.allocator,
        verified,
        replacement,
    );
    defer report.deinit(std.testing.allocator);

    var after = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer after.deinit(std.testing.allocator);

    try std.testing.expectEqual(@as(usize, 2), report.partitions.len);
    try std.testing.expectEqualSlices(u8, &disk_guid, &report.old_disk_guid);
    try std.testing.expectEqualSlices(u8, &replacement.disk_guid, &report.new_disk_guid);
    for (report.partitions, verified.partitions, replacement_partition_guids) |rewrite, before, expected_new| {
        try std.testing.expectEqual(before.table_index, rewrite.table_index);
        try std.testing.expectEqualSlices(u8, &before.partition_type_guid, &rewrite.partition_type_guid);
        try std.testing.expectEqual(before.first_lba, rewrite.first_lba);
        try std.testing.expectEqual(before.last_lba, rewrite.last_lba);
        try std.testing.expectEqual(before.attributes, rewrite.attributes);
        try std.testing.expectEqualSlices(u16, &before.name_utf16le, &rewrite.name_utf16le);
        try std.testing.expectEqualSlices(u8, &before.unique_partition_guid, &rewrite.old_unique_guid);
        try std.testing.expectEqualSlices(u8, &expected_new, &rewrite.new_unique_guid);
    }

    try std.testing.expectEqual(verified.primary_header.current_lba, after.primary_header.current_lba);
    try std.testing.expectEqual(verified.primary_header.backup_lba, after.primary_header.backup_lba);
    try std.testing.expectEqual(verified.primary_header.first_usable_lba, after.primary_header.first_usable_lba);
    try std.testing.expectEqual(verified.primary_header.last_usable_lba, after.primary_header.last_usable_lba);
    try std.testing.expectEqual(verified.primary_header.partition_entry_lba, after.primary_header.partition_entry_lba);
    try std.testing.expectEqual(verified.primary_header.num_partition_entries, after.primary_header.num_partition_entries);
    try std.testing.expectEqual(verified.primary_header.partition_entry_size, after.primary_header.partition_entry_size);
    try std.testing.expectEqual(verified.backup_header.current_lba, after.backup_header.current_lba);
    try std.testing.expectEqual(verified.backup_header.partition_entry_lba, after.backup_header.partition_entry_lba);
    try std.testing.expectEqualSlices(u8, &verified.protective_mbr_sector, &after.protective_mbr_sector);
    try std.testing.expectEqualSlices(u8, &replacement.disk_guid, &after.primary_header.disk_guid);
    try std.testing.expectEqualSlices(u8, &replacement.disk_guid, &after.backup_header.disk_guid);
    try std.testing.expectEqual(
        std.hash.crc.Crc32.hash(after.partition_array),
        after.primary_header.partition_array_crc32,
    );
    try std.testing.expectEqual(
        after.primary_header.partition_array_crc32,
        after.backup_header.partition_array_crc32,
    );

    for (after.partitions, verified.partitions, replacement_partition_guids) |rewritten, before, expected_new| {
        try std.testing.expectEqual(before.table_index, rewritten.table_index);
        try std.testing.expectEqualSlices(u8, &before.partition_type_guid, &rewritten.partition_type_guid);
        try std.testing.expectEqual(before.first_lba, rewritten.first_lba);
        try std.testing.expectEqual(before.last_lba, rewritten.last_lba);
        try std.testing.expectEqual(before.attributes, rewritten.attributes);
        try std.testing.expectEqualSlices(u16, &before.name_utf16le, &rewritten.name_utf16le);
        try std.testing.expectEqualSlices(u8, &expected_new, &rewritten.unique_partition_guid);
    }

    for (verified.partitions, replacement_partition_guids) |before, expected_new| {
        const before_entry = testEntrySlice(
            verified.partition_array,
            entry_size,
            before.table_index,
        );
        const after_entry = testEntrySlice(
            after.partition_array,
            entry_size,
            before.table_index,
        );
        try std.testing.expectEqualSlices(u8, before_entry[0..16], after_entry[0..16]);
        try std.testing.expectEqualSlices(u8, before_entry[32..], after_entry[32..]);
        try std.testing.expectEqualSlices(u8, &expected_new, after_entry[16..32]);
    }
    for (unused_tails) |unused| {
        try std.testing.expectEqualSlices(
            u8,
            testEntrySlice(verified.partition_array, entry_size, unused.table_index),
            testEntrySlice(after.partition_array, entry_size, unused.table_index),
        );
    }
}

test "rewriteIdentity preserves relocated GPT geometry with generated GUIDs" {
    const io = std.testing.io;
    const path = "test-gpt-identity-rewrite-relocated.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const initial_size: u64 = 32 * 1024 * 1024 - sector_size;
    var img = try Image.create(io, path, .raw, initial_size, .{});
    defer img.close(io);

    const disk_guid = guid.parse("66666666-6666-6666-6666-666666666666");
    const entries = [_]PartitionEntry{
        .{
            .partition_type_guid = guid.esp,
            .unique_partition_guid = guid.parse("77777777-7777-7777-7777-777777777777"),
            .first_lba = 2048,
            .last_lba = 4095,
            .attributes = 0x1,
            .name_utf16le = asciiName("efi"),
        },
        .{
            .partition_type_guid = guid.linux_filesystem_data,
            .unique_partition_guid = guid.parse("88888888-8888-8888-8888-888888888888"),
            .first_lba = 8192,
            .last_lba = 24575,
            .attributes = 0x8000_0000_0000_0000,
            .name_utf16le = asciiName("root"),
        },
    };
    try writePartitionTables(&img, io, disk_guid, &entries);

    var mbr_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &mbr_sector, 0);
    mbr_sector[23] = 0x9d;
    try img.pwrite(io, &mbr_sector, 0);

    var verified = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer verified.deinit(std.testing.allocator);

    const relocated_size: u64 = 48 * 1024 * 1024;
    try img.resize(io, relocated_size);
    const relocation = try relocateBackup(
        &img,
        io,
        std.testing.allocator,
        verified,
    );
    try std.testing.expect(relocation.was_relocated);

    var relocated = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer relocated.deinit(std.testing.allocator);

    var generated = try generateReplacementGuids(
        std.testing.allocator,
        io,
        relocated,
    );
    defer generated.deinit(std.testing.allocator);
    try std.testing.expect(!sourceContainsGuid(relocated, generated.disk_guid));
    for (generated.partition_guids) |new_guid| {
        try std.testing.expect(!sourceContainsGuid(relocated, new_guid));
    }

    var report = try rewriteIdentity(
        &img,
        io,
        std.testing.allocator,
        relocated,
        generated.borrowed(),
    );
    defer report.deinit(std.testing.allocator);

    var after = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer after.deinit(std.testing.allocator);

    try std.testing.expectEqual(relocated.primary_header.backup_lba, after.primary_header.backup_lba);
    try std.testing.expectEqual(relocated.primary_header.last_usable_lba, after.primary_header.last_usable_lba);
    try std.testing.expectEqual(relocated.primary_header.partition_entry_lba, after.primary_header.partition_entry_lba);
    try std.testing.expectEqual(relocated.backup_header.partition_entry_lba, after.backup_header.partition_entry_lba);
    try std.testing.expectEqualSlices(u8, &relocated.protective_mbr_sector, &after.protective_mbr_sector);
    try std.testing.expectEqualSlices(u8, &generated.disk_guid, &after.primary_header.disk_guid);
    try std.testing.expectEqualSlices(u8, &generated.disk_guid, &after.backup_header.disk_guid);
    try std.testing.expectEqual(@as(usize, relocated.partitions.len), report.partitions.len);
    for (after.partitions, relocated.partitions, generated.partition_guids) |rewritten, before, expected_new| {
        try std.testing.expectEqual(before.table_index, rewritten.table_index);
        try std.testing.expectEqual(before.first_lba, rewritten.first_lba);
        try std.testing.expectEqual(before.last_lba, rewritten.last_lba);
        try std.testing.expectEqual(before.attributes, rewritten.attributes);
        try std.testing.expectEqualSlices(u8, &expected_new, &rewritten.unique_partition_guid);
    }
}

test "rewriteIdentity refuses when source GPT metadata changed" {
    const io = std.testing.io;
    const path = "test-gpt-identity-rewrite-source-changed.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 16 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const disk_guid = guid.parse("99999999-9999-9999-9999-999999999999");
    const entries = [_]PartitionEntry{.{
        .partition_type_guid = guid.linux_filesystem_data,
        .unique_partition_guid = guid.parse("aaaaaaaa-1111-2222-3333-bbbbbbbbbbbb"),
        .first_lba = 2048,
        .last_lba = 8191,
        .name_utf16le = asciiName("root"),
    }};
    try writePartitionTables(&img, io, disk_guid, &entries);

    var verified = try readVerifiedGpt(
        img,
        io,
        std.testing.allocator,
        default_max_partition_array_bytes,
    );
    defer verified.deinit(std.testing.allocator);

    var one: [1]u8 = undefined;
    const mutate_offset = try std.math.add(
        u64,
        try sectorOffset(verified.primary_header.partition_entry_lba),
        40,
    );
    try preadExact(img, io, &one, mutate_offset);
    one[0] ^= 0xff;
    try img.pwrite(io, &one, mutate_offset);

    const replacement_partition_guids = [_]guid.Guid{
        guid.parse("bbbbbbbb-2222-3333-4444-cccccccccccc"),
    };
    try std.testing.expectError(
        error.SourceMetadataChanged,
        rewriteIdentity(
            &img,
            io,
            std.testing.allocator,
            verified,
            .{
                .disk_guid = guid.parse("cccccccc-3333-4444-5555-dddddddddddd"),
                .partition_guids = &replacement_partition_guids,
            },
        ),
    );

    var primary_header_sector: [sector_size]u8 = undefined;
    try preadExact(img, io, &primary_header_sector, sector_size);
    const header = try Header.decode(&primary_header_sector);
    try std.testing.expectEqualSlices(u8, &disk_guid, &header.disk_guid);
}

test "writeGpt rejects a layout that doesn't fit" {
    const io = std.testing.io;
    const path = "test-gpt-too-big.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size: u64 = 4 * 1024 * 1024; // tiny disk
    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]PartitionSpec{
        .{ .type_guid = guid.linux_filesystem_data, .unique_guid = guid.nil, .size_sectors = (disk_size / sector_size) * 2 },
    };
    var placements: [specs.len]Placement = undefined;
    try std.testing.expectError(error.NotEnoughSpace, writeGpt(&img, io, guid.nil, &specs, &placements));
}
