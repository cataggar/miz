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
