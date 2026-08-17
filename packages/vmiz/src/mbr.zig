//! MBR (Master Boot Record) partition table codec. Supports two shapes:
//! a *protective MBR* (a single 0xEE "GPT protective" entry spanning the
//! disk, required at LBA 0 ahead of a GPT for Gen2/UEFI Azure VMs), and a
//! plain single-partition MBR (a bootable 0x83 "Linux" entry, for Gen1/BIOS
//! Azure VMs). Field layout and offsets verified against the classic MBR
//! structure (partition table at offset 0x1BE, boot signature 0x55AA at
//! 0x1FE) documented on Wikipedia's "Master boot record" article.

const std = @import("std");

pub const sector_size: usize = 512;
pub const partition_table_offset: usize = 0x1BE;
pub const entry_size: usize = 16;
pub const max_entries: usize = 4;

pub const boot_signature: [2]u8 = .{ 0x55, 0xAA };
pub const partuuid_len: usize = 11;

pub const PartitionType = enum(u8) {
    empty = 0x00,
    linux = 0x83,
    gpt_protective = 0xEE,
    _,
};

pub const PartitionEntry = struct {
    bootable: bool = false,
    /// CHS is legacy and ignored by virtually every modern reader in favor
    /// of the LBA fields, but is still computed/filled in for maximum
    /// compatibility with anything that still looks at it.
    start_chs: [3]u8 = .{ 0, 0, 0 },
    partition_type: PartitionType = .empty,
    end_chs: [3]u8 = .{ 0, 0, 0 },
    first_lba: u32 = 0,
    sector_count: u32 = 0,

    fn encode(self: PartitionEntry, buf: *[entry_size]u8) void {
        buf[0] = if (self.bootable) 0x80 else 0x00;
        buf[1..4].* = self.start_chs;
        buf[4] = @intFromEnum(self.partition_type);
        buf[5..8].* = self.end_chs;
        std.mem.writeInt(u32, buf[8..12], self.first_lba, .little);
        std.mem.writeInt(u32, buf[12..16], self.sector_count, .little);
    }

    fn decode(buf: *const [entry_size]u8) PartitionEntry {
        return .{
            .bootable = buf[0] == 0x80,
            .start_chs = buf[1..4].*,
            .partition_type = @enumFromInt(buf[4]),
            .end_chs = buf[5..8].*,
            .first_lba = std.mem.readInt(u32, buf[8..12], .little),
            .sector_count = std.mem.readInt(u32, buf[12..16], .little),
        };
    }
};

pub const Mbr = struct {
    entries: [max_entries]PartitionEntry = [_]PartitionEntry{.{}} ** max_entries,
    /// 32-bit disk signature at offset 0x1B8; zero is valid (means "unset").
    disk_signature: u32 = 0,

    pub fn encode(self: Mbr) [sector_size]u8 {
        var buf: [sector_size]u8 = [_]u8{0} ** sector_size;
        // Bootstrap code area (0..0x1B8) intentionally starts zeroed because
        // this codec only produces partition *tables*, not boot code.
        // Higher-level callers such as `build_image` may later overlay BIOS
        // stage-1 bytes here while preserving the table/signature tail.
        self.encodePartitionTableInto(&buf);
        return buf;
    }

    /// Updates only the disk-signature/partition-table tail of an existing
    /// sector 0, preserving any BIOS bootstrap code in bytes 0..0x1B8.
    pub fn encodePartitionTableInto(self: Mbr, buf: *[sector_size]u8) void {
        std.mem.writeInt(u32, buf[0x1B8..0x1BC], self.disk_signature, .little);

        for (self.entries, 0..) |entry, i| {
            const off = partition_table_offset + i * entry_size;
            entry.encode(buf[off..][0..entry_size]);
        }
        buf[510..512].* = boot_signature;
    }

    pub const DecodeError = error{BadBootSignature};

    pub fn decode(buf: *const [sector_size]u8) DecodeError!Mbr {
        if (!std.mem.eql(u8, buf[510..512], &boot_signature)) return error.BadBootSignature;

        var entries: [max_entries]PartitionEntry = undefined;
        for (&entries, 0..) |*entry, i| {
            const off = partition_table_offset + i * entry_size;
            entry.* = PartitionEntry.decode(buf[off..][0..entry_size]);
        }
        return .{
            .entries = entries,
            .disk_signature = std.mem.readInt(u32, buf[0x1B8..0x1BC], .little),
        };
    }
};

/// Standard CHS-address translation (heads=255, sectors/track=63), clamped
/// to the maximum representable CHS value (1023, 254, 63) for LBAs beyond
/// what 10-bit cylinders can address -- exactly what real partitioning
/// tools (fdisk, parted) do for any disk too large for pure CHS addressing,
/// which is virtually all disks in practice today. The clamped sentinel
/// signals readers to trust the LBA fields instead.
pub fn chsForLba(lba: u32) [3]u8 {
    const heads: u32 = 255;
    const sectors_per_track: u32 = 63;
    const max_cylinder: u32 = 1023;

    const cylinder = lba / (heads * sectors_per_track);
    if (cylinder > max_cylinder) {
        return .{ 0xFE, 0xFF, 0xFF };
    }
    const head: u32 = (lba / sectors_per_track) % heads;
    const sector: u32 = (lba % sectors_per_track) + 1;

    return .{
        @intCast(head),
        @intCast((sector & 0x3F) | ((cylinder >> 2) & 0xC0)),
        @intCast(cylinder & 0xFF),
    };
}

/// Builds a protective MBR (a single 0xEE entry spanning the disk),
/// required at LBA 0 immediately before a GPT header, per the UEFI spec.
/// `disk_total_sectors` is the whole disk's size in 512-byte sectors.
pub fn protectiveMbr(disk_total_sectors: u64) Mbr {
    // The MBR's LBA/size fields are 32-bit; a disk larger than that gets
    // its protective entry clipped to 0xFFFFFFFF sectors, same as real
    // implementations (the GPT header carries the real, 64-bit extents).
    const size_sectors: u32 = @intCast(@min(disk_total_sectors - 1, 0xFFFF_FFFF));
    var mbr = Mbr{};
    mbr.entries[0] = .{
        .bootable = false,
        .start_chs = chsForLba(1),
        .partition_type = .gpt_protective,
        .end_chs = chsForLba(1 + size_sectors - 1),
        .first_lba = 1,
        .sector_count = size_sectors,
    };
    return mbr;
}

/// Builds a plain single-partition MBR: one bootable 0x83 (Linux) entry
/// starting at `first_lba` and spanning `sector_count` sectors. Used for
/// Gen1 (BIOS) Azure VMs, which boot via a classic MBR + a single root
/// partition (no separate ESP).
pub fn singleLinuxPartitionMbr(first_lba: u32, sector_count: u32) Mbr {
    var mbr = Mbr{};
    mbr.entries[0] = .{
        .bootable = true,
        .start_chs = chsForLba(first_lba),
        .partition_type = .linux,
        .end_chs = chsForLba(first_lba + sector_count - 1),
        .first_lba = first_lba,
        .sector_count = sector_count,
    };
    return mbr;
}

pub const GrowError = error{
    NoPartition,
    NotEnoughSpace,
};

/// Grows partition `index` in `mb` in place: extends its `sector_count` to
/// reach the disk's new, larger `new_total_sectors`. Unlike GPT, a plain
/// MBR has no backup header/array to relocate -- growing is nothing more
/// than this one field, matching `singleLinuxPartitionMbr`'s single
/// bootable-0x83-entry layout used for Gen1 (BIOS) Azure VMs. Returns
/// `error.NoPartition` if `index` names an empty entry, and
/// `error.NotEnoughSpace` if the disk isn't actually larger than the
/// partition's current end (e.g. called on an already-grown or
/// unchanged-size disk).
pub fn growPartition(mb: *Mbr, index: usize, new_total_sectors: u64) GrowError!void {
    const entry = &mb.entries[index];
    if (entry.partition_type == .empty) return error.NoPartition;

    const current_end: u64 = @as(u64, entry.first_lba) + entry.sector_count;
    if (new_total_sectors <= current_end) return error.NotEnoughSpace;

    // MBR's sector_count/first_lba are 32-bit; clamp the same way
    // `protectiveMbr` does for disks too large to fully address via
    // classic 32-bit MBR fields.
    const new_end = @min(new_total_sectors, 0xFFFF_FFFF);
    entry.sector_count = @intCast(new_end - entry.first_lba);
    entry.end_chs = chsForLba(entry.first_lba + entry.sector_count - 1);
}

/// Formats the Linux/udev-synthesized PARTUUID used for DOS/MBR partition
/// tables: `<8-hex-disk-signature>-<2-hex-partition-number>`.
pub fn formatPartuuid(buf: *[partuuid_len]u8, disk_signature: u32, partition_index_1based: u8) []const u8 {
    return std.fmt.bufPrint(buf, "{x:0>8}-{x:0>2}", .{ disk_signature, partition_index_1based }) catch unreachable;
}

test "growPartition extends sector_count and CHS to the disk's new end" {
    var mb = singleLinuxPartitionMbr(2048, 1 * 1024 * 1024);
    const original_first_lba = mb.entries[0].first_lba;

    const new_total_sectors: u64 = 8 * 1024 * 1024;
    try growPartition(&mb, 0, new_total_sectors);

    try std.testing.expectEqual(original_first_lba, mb.entries[0].first_lba);
    try std.testing.expectEqual(@as(u32, new_total_sectors) - original_first_lba, mb.entries[0].sector_count);
    try std.testing.expectEqualSlices(u8, &chsForLba(original_first_lba + mb.entries[0].sector_count - 1), &mb.entries[0].end_chs);

    // Round-trips through encode/decode too.
    const encoded = mb.encode();
    const decoded = try Mbr.decode(&encoded);
    try std.testing.expectEqual(mb.entries[0].sector_count, decoded.entries[0].sector_count);
}

test "growPartition rejects an empty entry" {
    var mb = Mbr{};
    try std.testing.expectError(error.NoPartition, growPartition(&mb, 0, 8 * 1024 * 1024));
}

test "growPartition rejects a disk that hasn't actually grown" {
    var mb = singleLinuxPartitionMbr(2048, 1 * 1024 * 1024);
    const current_end: u64 = @as(u64, mb.entries[0].first_lba) + mb.entries[0].sector_count;
    try std.testing.expectError(error.NotEnoughSpace, growPartition(&mb, 0, current_end));
}

test "protectiveMbr encode/decode round-trip" {
    const total_sectors: u64 = 32 * 1024 * 1024 / 512; // 32 MiB disk
    const mbr = protectiveMbr(total_sectors);
    const encoded = mbr.encode();

    try std.testing.expectEqualSlices(u8, &boot_signature, encoded[510..512]);

    const decoded = try Mbr.decode(&encoded);
    try std.testing.expectEqual(PartitionType.gpt_protective, decoded.entries[0].partition_type);
    try std.testing.expectEqual(@as(u32, 1), decoded.entries[0].first_lba);
    try std.testing.expectEqual(@as(u32, total_sectors - 1), decoded.entries[0].sector_count);
    try std.testing.expectEqual(PartitionType.empty, decoded.entries[1].partition_type);
}

test "singleLinuxPartitionMbr encode/decode round-trip" {
    const mbr = singleLinuxPartitionMbr(2048, 1 * 1024 * 1024);
    const encoded = mbr.encode();
    const decoded = try Mbr.decode(&encoded);

    try std.testing.expectEqual(PartitionType.linux, decoded.entries[0].partition_type);
    try std.testing.expect(decoded.entries[0].bootable);
    try std.testing.expectEqual(@as(u32, 2048), decoded.entries[0].first_lba);
    try std.testing.expectEqual(@as(u32, 1 * 1024 * 1024), decoded.entries[0].sector_count);
}

test "encodePartitionTableInto preserves BIOS bootstrap code" {
    var sector0 = [_]u8{0xA5} ** sector_size;
    const mb = singleLinuxPartitionMbr(2048, 1 * 1024 * 1024);

    mb.encodePartitionTableInto(&sector0);

    try std.testing.expectEqualSlices(u8, &([_]u8{0xA5} ** 0x1B8), sector0[0..0x1B8]);
    const decoded = try Mbr.decode(&sector0);
    try std.testing.expectEqual(mb.entries[0], decoded.entries[0]);
}

test "Mbr.decode rejects a bad boot signature" {
    var buf = [_]u8{0} ** sector_size;
    try std.testing.expectError(error.BadBootSignature, Mbr.decode(&buf));
}

test "chsForLba clamps to the sentinel for large LBAs" {
    const chs = chsForLba(0xFFFF_FFFF);
    try std.testing.expectEqualSlices(u8, &[_]u8{ 0xFE, 0xFF, 0xFF }, &chs);
}

test "formatPartuuid renders Linux MBR-style PARTUUID text" {
    var buf: [partuuid_len]u8 = undefined;
    try std.testing.expectEqualStrings("a1b2c3d4-01", formatPartuuid(&buf, 0xA1B2C3D4, 1));
    try std.testing.expectEqualStrings("0000000f-0a", formatPartuuid(&buf, 0x0000000F, 10));
}
