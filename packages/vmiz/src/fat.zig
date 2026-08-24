//! Strict native FAT boot-sector identity inspection and rewrite.
//!
//! This module reads the existing FAT volume id from a boot sector layout it
//! understands and, when asked, rewrites every authoritative copy before
//! rereading the result. The rewrite is deliberately narrow: geometry,
//! signatures and FAT32 backup consistency are validated up front, only the
//! volume-id field is changed, and every other byte stays as it was.

const std = @import("std");
const Io = std.Io;
const Image = @import("image.zig").Image;

/// Byte range inside a backing `Image` that contains one FAT volume.
pub const Region = struct {
    offset: u64,
    length: u64,
};

/// Length of a FAT volume serial in the `XXXX-XXXX` form `blkid` reports.
pub const serial_bytes: usize = 9;

/// Formats a FAT volume serial the way `blkid` prints it: uppercase, with the
/// high and low halves separated.
pub fn formatVolumeSerial(buffer: *[serial_bytes]u8, volume_id: u32) []const u8 {
    _ = std.fmt.bufPrint(buffer, "{X:0>4}-{X:0>4}", .{
        @as(u16, @truncate(volume_id >> 16)),
        @as(u16, @truncate(volume_id)),
    }) catch unreachable;
    return buffer;
}

/// FAT layout identified from the boot sector geometry.
pub const Variant = enum {
    fat12,
    fat16,
    fat32,

    pub fn name(self: Variant) []const u8 {
        return switch (self) {
            .fat12 => "FAT12",
            .fat16 => "FAT16",
            .fat32 => "FAT32",
        };
    }

    fn typeLabel(self: Variant) []const u8 {
        return switch (self) {
            .fat12 => "FAT12   ",
            .fat16 => "FAT16   ",
            .fat32 => "FAT32   ",
        };
    }

    fn bootSignatureOffset(self: Variant) usize {
        return switch (self) {
            .fat12, .fat16 => 38,
            .fat32 => 66,
        };
    }

    fn volumeIdOffset(self: Variant) usize {
        return switch (self) {
            .fat12, .fat16 => 39,
            .fat32 => 67,
        };
    }
};

/// The volume-id-bearing FAT identity recorded in boot metadata.
pub const Identity = struct {
    variant: Variant,
    bytes_per_sector: u16,
    volume_id: u32,
    /// FAT32 keeps a second authoritative copy of the boot sector here when
    /// this field is non-null.
    backup_boot_sector: ?u16 = null,

    pub fn serial(self: Identity, buffer: *[serial_bytes]u8) []const u8 {
        return formatVolumeSerial(buffer, self.volume_id);
    }

    pub fn bootSectorCopies(self: Identity) u8 {
        return if (self.backup_boot_sector == null) 1 else 2;
    }
};

/// Result of a successful identity rewrite and verification pass.
pub const RewriteReport = struct {
    before: Identity,
    after: Identity,
    boot_sector_copies_rewritten: u8,
    device_flushed: bool,
};

pub const Error = error{
    InvalidVolumeId,
    UnexpectedEndOfFile,
    InvalidBootSector,
    UnsupportedBytesPerSector,
    InvalidSectorsPerCluster,
    InvalidFatCount,
    PartitionOutOfBounds,
    InconsistentBackupBootSector,
    IdentityVerificationFailed,
};

pub const ReadError = Error || Image.PreadError;
pub const RewriteError = ReadError || Image.PwriteError || Image.FlushDeviceWriteError;

const min_boot_sector_bytes: usize = 512;
const max_bytes_per_sector: usize = 4096;
const fat12_upper_cluster_count: u32 = 4_084;
const fat16_upper_cluster_count: u32 = 65_524;

const ParsedBootSector = struct {
    identity: Identity,
    volume_id_offset: usize,
};

/// Reads and validates the current FAT volume identity.
pub fn readIdentity(image: *const Image, io: Io, region: Region) ReadError!Identity {
    var primary: [max_bytes_per_sector]u8 = undefined;
    var backup: [max_bytes_per_sector]u8 = undefined;
    const parsed = try loadBootSectors(image, io, region, &primary, &backup);
    return parsed.identity;
}

/// Rewrites a FAT volume id everywhere the supported on-disk layout stores it,
/// flushes any device-backed write through `Image.flushDeviceWrite`, then
/// rereads and verifies the new identity before returning.
pub fn rewriteIdentity(
    image: *Image,
    io: Io,
    region: Region,
    new_volume_id: u32,
) RewriteError!RewriteReport {
    if (new_volume_id == 0) return error.InvalidVolumeId;

    var primary: [max_bytes_per_sector]u8 = undefined;
    var backup: [max_bytes_per_sector]u8 = undefined;
    const parsed = try loadBootSectors(image, io, region, &primary, &backup);
    const sector_bytes: usize = parsed.identity.bytes_per_sector;

    std.mem.writeInt(
        u32,
        primary[parsed.volume_id_offset..][0..@sizeOf(u32)],
        new_volume_id,
        .little,
    );
    try image.pwrite(io, primary[0..sector_bytes], try bootSectorOffset(region, parsed.identity.bytes_per_sector, 0));

    var copies_rewritten: u8 = 1;
    if (parsed.identity.backup_boot_sector) |backup_sector| {
        std.mem.writeInt(
            u32,
            backup[parsed.volume_id_offset..][0..@sizeOf(u32)],
            new_volume_id,
            .little,
        );
        try image.pwrite(io, backup[0..sector_bytes], try bootSectorOffset(region, parsed.identity.bytes_per_sector, backup_sector));
        copies_rewritten += 1;
    }

    const device_flushed = try image.flushDeviceWrite(io);
    const verified = try readIdentity(image, io, region);
    if (verified.variant != parsed.identity.variant or
        verified.bytes_per_sector != parsed.identity.bytes_per_sector or
        verified.volume_id != new_volume_id or
        verified.backup_boot_sector != parsed.identity.backup_boot_sector)
    {
        return error.IdentityVerificationFailed;
    }

    return .{
        .before = parsed.identity,
        .after = verified,
        .boot_sector_copies_rewritten = copies_rewritten,
        .device_flushed = device_flushed,
    };
}

fn loadBootSectors(
    image: *const Image,
    io: Io,
    region: Region,
    primary: *[max_bytes_per_sector]u8,
    backup: *[max_bytes_per_sector]u8,
) ReadError!ParsedBootSector {
    if (region.length < min_boot_sector_bytes) return error.InvalidBootSector;

    try readAllAt(image, io, primary[0..min_boot_sector_bytes], region.offset);
    const parsed = try parseBootSector(primary[0..min_boot_sector_bytes], region);
    const sector_bytes: usize = parsed.identity.bytes_per_sector;

    if (sector_bytes > min_boot_sector_bytes) {
        try readAllAt(image, io, primary[0..sector_bytes], try bootSectorOffset(region, parsed.identity.bytes_per_sector, 0));
    }

    if (parsed.identity.backup_boot_sector) |backup_sector| {
        try readAllAt(image, io, backup[0..sector_bytes], try bootSectorOffset(region, parsed.identity.bytes_per_sector, backup_sector));
        if (!std.mem.eql(u8, primary[0..sector_bytes], backup[0..sector_bytes])) {
            return error.InconsistentBackupBootSector;
        }
    }

    return parsed;
}

fn readAllAt(
    image: *const Image,
    io: Io,
    buffer: []u8,
    offset: u64,
) ReadError!void {
    const got = try image.pread(io, buffer, offset);
    if (got != buffer.len) return error.UnexpectedEndOfFile;
}

fn parseBootSector(boot_sector: []const u8, region: Region) Error!ParsedBootSector {
    if (boot_sector.len < min_boot_sector_bytes) return error.InvalidBootSector;
    if (boot_sector[510] != 0x55 or boot_sector[511] != 0xAA) return error.InvalidBootSector;

    const bytes_per_sector = std.mem.readInt(u16, boot_sector[11..13], .little);
    if (!isSupportedBytesPerSector(bytes_per_sector)) return error.UnsupportedBytesPerSector;

    const sectors_per_cluster = boot_sector[13];
    if (!isValidSectorsPerCluster(sectors_per_cluster)) return error.InvalidSectorsPerCluster;

    const reserved_sector_count = std.mem.readInt(u16, boot_sector[14..16], .little);
    if (reserved_sector_count == 0) return error.InvalidBootSector;

    const fat_count = boot_sector[16];
    if (fat_count == 0) return error.InvalidFatCount;

    const root_entry_count = std.mem.readInt(u16, boot_sector[17..19], .little);
    const total_sectors_16 = std.mem.readInt(u16, boot_sector[19..21], .little);
    const fat_size_16 = std.mem.readInt(u16, boot_sector[22..24], .little);
    const total_sectors_32 = std.mem.readInt(u32, boot_sector[32..36], .little);

    if ((total_sectors_16 == 0) == (total_sectors_32 == 0)) return error.InvalidBootSector;

    const total_sectors: u32 = if (total_sectors_16 != 0) total_sectors_16 else total_sectors_32;
    if (try totalBytes(total_sectors, bytes_per_sector) > region.length) return error.PartitionOutOfBounds;

    const fat_size_sectors: u32 = if (root_entry_count == 0) blk: {
        if (fat_size_16 != 0) return error.InvalidBootSector;
        const value = std.mem.readInt(u32, boot_sector[36..40], .little);
        if (value == 0) return error.InvalidBootSector;
        break :blk value;
    } else blk: {
        if (fat_size_16 == 0) return error.InvalidBootSector;
        break :blk fat_size_16;
    };
    const root_dir_sectors: u32 = @intCast(
        std.math.divCeil(
            u32,
            @as(u32, root_entry_count) * 32,
            bytes_per_sector,
        ) catch unreachable,
    );

    const data_start_sector = std.math.add(
        u64,
        reserved_sector_count,
        std.math.add(
            u64,
            std.math.mul(u64, fat_count, fat_size_sectors) catch return error.InvalidBootSector,
            root_dir_sectors,
        ) catch return error.InvalidBootSector,
    ) catch return error.InvalidBootSector;
    if (data_start_sector >= total_sectors) return error.InvalidBootSector;

    const data_cluster_count: u32 = @intCast((@as(u64, total_sectors) - data_start_sector) / sectors_per_cluster);
    if (data_cluster_count == 0) return error.InvalidBootSector;

    const variant = classifyVariant(data_cluster_count);
    if ((root_entry_count == 0 and variant != .fat32) or
        (root_entry_count != 0 and variant == .fat32))
    {
        return error.InvalidBootSector;
    }
    if (boot_sector[variant.bootSignatureOffset()] != 0x29) return error.InvalidBootSector;

    const type_label = variant.typeLabel();
    const label_offset: usize = switch (variant) {
        .fat12, .fat16 => 54,
        .fat32 => 82,
    };
    if (!std.mem.eql(u8, boot_sector[label_offset .. label_offset + type_label.len], type_label)) {
        return error.InvalidBootSector;
    }

    switch (variant) {
        .fat12, .fat16 => {
            if (root_entry_count == 0 or fat_size_16 == 0) {
                return error.InvalidBootSector;
            }
        },
        .fat32 => {
            if (root_entry_count != 0 or fat_size_16 != 0) {
                return error.InvalidBootSector;
            }

            const root_cluster = std.mem.readInt(u32, boot_sector[44..48], .little);
            if (root_cluster < 2 or root_cluster > data_cluster_count + 1) {
                return error.InvalidBootSector;
            }
        },
    }

    var backup_boot_sector: ?u16 = null;
    if (variant == .fat32) {
        const backup_candidate = std.mem.readInt(u16, boot_sector[50..52], .little);
        if (backup_candidate != 0 and backup_candidate != 0xFFFF) {
            if (backup_candidate >= reserved_sector_count) return error.InvalidBootSector;
            backup_boot_sector = backup_candidate;
        }
    }

    return .{
        .identity = .{
            .variant = variant,
            .bytes_per_sector = bytes_per_sector,
            .volume_id = std.mem.readInt(u32, boot_sector[variant.volumeIdOffset()..][0..@sizeOf(u32)], .little),
            .backup_boot_sector = backup_boot_sector,
        },
        .volume_id_offset = variant.volumeIdOffset(),
    };
}

fn totalBytes(total_sectors: u32, bytes_per_sector: u16) Error!u64 {
    return std.math.mul(u64, total_sectors, bytes_per_sector) catch error.PartitionOutOfBounds;
}

fn bootSectorOffset(region: Region, bytes_per_sector: u16, sector_index: u16) Error!u64 {
    const relative = std.math.mul(u64, sector_index, bytes_per_sector) catch return error.PartitionOutOfBounds;
    const end = std.math.add(u64, relative, bytes_per_sector) catch return error.PartitionOutOfBounds;
    if (end > region.length) return error.PartitionOutOfBounds;
    return std.math.add(u64, region.offset, relative) catch error.PartitionOutOfBounds;
}

fn isSupportedBytesPerSector(value: u16) bool {
    return value == 512 or value == 1024 or value == 2048 or value == 4096;
}

fn isValidSectorsPerCluster(value: u8) bool {
    return value != 0 and std.math.isPowerOfTwo(value) and value <= 128;
}

fn classifyVariant(cluster_count: u32) Variant {
    if (cluster_count <= fat12_upper_cluster_count) return .fat12;
    if (cluster_count <= fat16_upper_cluster_count) return .fat16;
    return .fat32;
}

const TestLayout = struct {
    variant: Variant,
    bytes_per_sector: u16,
    sectors_per_cluster: u8,
    reserved_sector_count: u16,
    fat_count: u8 = 2,
    root_entry_count: u16,
    total_sectors: u32,
    fat_size_sectors: u32,
    volume_id: u32,
    backup_boot_sector: ?u16 = null,
    root_cluster: u32 = 2,

    fn regionLength(self: TestLayout) !u64 {
        return std.math.mul(u64, self.total_sectors, self.bytes_per_sector);
    }
};

const TestVolume = struct {
    image: Image,
    region: Region,
};

fn buildTestBootSector(layout: TestLayout, fill_seed: u8) [max_bytes_per_sector]u8 {
    var sector: [max_bytes_per_sector]u8 = undefined;
    for (sector[0..@as(usize, layout.bytes_per_sector)], 0..) |*byte, index| {
        byte.* = @truncate(index * 37 + fill_seed);
    }

    sector[0] = 0xEB;
    sector[1] = 0x58;
    sector[2] = 0x90;
    sector[3..11].* = "vmizFAT ".*;
    std.mem.writeInt(u16, sector[11..13], layout.bytes_per_sector, .little);
    sector[13] = layout.sectors_per_cluster;
    std.mem.writeInt(u16, sector[14..16], layout.reserved_sector_count, .little);
    sector[16] = layout.fat_count;
    std.mem.writeInt(u16, sector[17..19], layout.root_entry_count, .little);

    if (layout.variant == .fat32 or layout.total_sectors > std.math.maxInt(u16)) {
        std.mem.writeInt(u16, sector[19..21], 0, .little);
        std.mem.writeInt(u32, sector[32..36], layout.total_sectors, .little);
    } else {
        std.mem.writeInt(u16, sector[19..21], @intCast(layout.total_sectors), .little);
        std.mem.writeInt(u32, sector[32..36], 0, .little);
    }

    sector[21] = 0xF8;
    if (layout.variant == .fat32) {
        std.mem.writeInt(u16, sector[22..24], 0, .little);
        std.mem.writeInt(u32, sector[36..40], layout.fat_size_sectors, .little);
    } else {
        std.mem.writeInt(u16, sector[22..24], @intCast(layout.fat_size_sectors), .little);
        std.mem.writeInt(u32, sector[36..40], 0, .little);
    }
    std.mem.writeInt(u16, sector[24..26], 63, .little);
    std.mem.writeInt(u16, sector[26..28], 255, .little);
    std.mem.writeInt(u32, sector[28..32], 0, .little);

    switch (layout.variant) {
        .fat12, .fat16 => {
            sector[36] = 0x80;
            sector[37] = 0;
            sector[38] = 0x29;
            std.mem.writeInt(u32, sector[39..43], layout.volume_id, .little);
            sector[43..54].* = "NO NAME    ".*;
            @memcpy(sector[54..62], layout.variant.typeLabel());
        },
        .fat32 => {
            std.mem.writeInt(u16, sector[40..42], 0, .little);
            std.mem.writeInt(u16, sector[42..44], 0, .little);
            std.mem.writeInt(u32, sector[44..48], layout.root_cluster, .little);
            std.mem.writeInt(u16, sector[48..50], 1, .little);
            std.mem.writeInt(u16, sector[50..52], layout.backup_boot_sector orelse 0, .little);
            sector[64] = 0x80;
            sector[65] = 0;
            sector[66] = 0x29;
            std.mem.writeInt(u32, sector[67..71], layout.volume_id, .little);
            sector[71..82].* = "NO NAME    ".*;
            @memcpy(sector[82..90], layout.variant.typeLabel());
        },
    }

    sector[510] = 0x55;
    sector[511] = 0xAA;
    return sector;
}

fn createTestVolume(
    io: Io,
    path: []const u8,
    layout: TestLayout,
    region_offset: u64,
    fill_seed: u8,
) !TestVolume {
    const region = Region{
        .offset = region_offset,
        .length = try layout.regionLength(),
    };
    const image_length = region.offset + region.length + @as(u64, layout.bytes_per_sector);
    var image = try Image.create(io, path, .raw, image_length, .{});

    var boot_sector = buildTestBootSector(layout, fill_seed);
    const sector_bytes: usize = layout.bytes_per_sector;
    try image.pwrite(io, boot_sector[0..sector_bytes], region.offset);
    if (layout.backup_boot_sector) |backup_sector| {
        try image.pwrite(io, boot_sector[0..sector_bytes], try bootSectorOffset(region, layout.bytes_per_sector, backup_sector));
    }

    return .{ .image = image, .region = region };
}

fn readSector(
    image: *const Image,
    io: Io,
    region: Region,
    bytes_per_sector: u16,
    sector_index: u16,
    buffer: *[max_bytes_per_sector]u8,
) ![]u8 {
    const sector_bytes: usize = bytes_per_sector;
    try readAllAt(image, io, buffer[0..sector_bytes], try bootSectorOffset(region, bytes_per_sector, sector_index));
    return buffer[0..sector_bytes];
}

fn expectOnlyVolumeIdChanged(
    before: []const u8,
    after: []const u8,
    offset: usize,
    expected_new_volume_id: u32,
) !void {
    try std.testing.expectEqualSlices(u8, before[0..offset], after[0..offset]);
    try std.testing.expectEqual(
        expected_new_volume_id,
        std.mem.readInt(u32, after[offset..][0..@sizeOf(u32)], .little),
    );
    try std.testing.expectEqualSlices(u8, before[offset + @sizeOf(u32) ..], after[offset + @sizeOf(u32) ..]);
}

fn fat12Layout() TestLayout {
    return .{
        .variant = .fat12,
        .bytes_per_sector = 512,
        .sectors_per_cluster = 1,
        .reserved_sector_count = 1,
        .root_entry_count = 224,
        .total_sectors = 2_880,
        .fat_size_sectors = 9,
        .volume_id = 0x1234_5678,
    };
}

fn fat16Layout() TestLayout {
    return .{
        .variant = .fat16,
        .bytes_per_sector = 2_048,
        .sectors_per_cluster = 1,
        .reserved_sector_count = 1,
        .root_entry_count = 512,
        .total_sectors = 8_192,
        .fat_size_sectors = 16,
        .volume_id = 0xA1B2_C3D4,
    };
}

fn fat32Layout() TestLayout {
    return .{
        .variant = .fat32,
        .bytes_per_sector = 512,
        .sectors_per_cluster = 1,
        .reserved_sector_count = 32,
        .root_entry_count = 0,
        .total_sectors = 70_000,
        .fat_size_sectors = 600,
        .volume_id = 0x5A56_4D49,
        .backup_boot_sector = 6,
    };
}

fn fat32LargeSectorLayout() TestLayout {
    return .{
        .variant = .fat32,
        .bytes_per_sector = 4_096,
        .sectors_per_cluster = 1,
        .reserved_sector_count = 32,
        .root_entry_count = 0,
        .total_sectors = 65_840,
        .fat_size_sectors = 128,
        .volume_id = 0x0BAD_C0DE,
        .backup_boot_sector = 6,
    };
}

test "fat identity supports FAT12, FAT16, and FAT32 boot layouts" {
    const io = std.testing.io;
    const cases = [_]struct {
        path: []const u8,
        layout: TestLayout,
        new_volume_id: u32,
        expected_copies: u8,
    }{
        .{
            .path = "test-fat-identity-fat12.img",
            .layout = fat12Layout(),
            .new_volume_id = 0x8765_4321,
            .expected_copies = 1,
        },
        .{
            .path = "test-fat-identity-fat16.img",
            .layout = fat16Layout(),
            .new_volume_id = 0xCAFEBABE,
            .expected_copies = 1,
        },
        .{
            .path = "test-fat-identity-fat32.img",
            .layout = fat32Layout(),
            .new_volume_id = 0x1020_3040,
            .expected_copies = 2,
        },
    };

    for (cases, 0..) |case, index| {
        {
            defer Io.Dir.cwd().deleteFile(io, case.path) catch {};
            var volume = try createTestVolume(
                io,
                case.path,
                case.layout,
                @as(u64, case.layout.bytes_per_sector) * 2,
                @intCast(0x40 + index),
            );
            defer volume.image.close(io);

            const before = try readIdentity(&volume.image, io, volume.region);
            try std.testing.expectEqual(case.layout.variant, before.variant);
            try std.testing.expectEqual(case.layout.volume_id, before.volume_id);
            try std.testing.expectEqual(case.expected_copies, before.bootSectorCopies());

            const report = try rewriteIdentity(&volume.image, io, volume.region, case.new_volume_id);
            try std.testing.expectEqual(case.layout.volume_id, report.before.volume_id);
            try std.testing.expectEqual(case.new_volume_id, report.after.volume_id);
            try std.testing.expectEqual(case.layout.variant, report.after.variant);
            try std.testing.expectEqual(case.expected_copies, report.boot_sector_copies_rewritten);
            try std.testing.expectEqual(false, report.device_flushed);

            const after = try readIdentity(&volume.image, io, volume.region);
            try std.testing.expectEqual(case.new_volume_id, after.volume_id);
            try std.testing.expectEqual(case.expected_copies, after.bootSectorCopies());
        }
    }
}

test "fat identity refuses inconsistent FAT32 backup boot sectors" {
    const io = std.testing.io;
    const path = "test-fat-identity-backup-mismatch.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const layout = fat32Layout();
    var volume = try createTestVolume(io, path, layout, 4 * 512, 0x55);
    defer volume.image.close(io);

    var before: [max_bytes_per_sector]u8 = undefined;
    const primary_before = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &before);

    var corrupt_byte = [_]u8{0x7F};
    const backup_offset = try bootSectorOffset(volume.region, layout.bytes_per_sector, layout.backup_boot_sector.?);
    try volume.image.pwrite(io, &corrupt_byte, backup_offset + 90);

    try std.testing.expectError(
        error.InconsistentBackupBootSector,
        rewriteIdentity(&volume.image, io, volume.region, 0x1122_3344),
    );

    var after: [max_bytes_per_sector]u8 = undefined;
    const primary_after = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &after);
    try std.testing.expectEqualSlices(u8, primary_before, primary_after);
}

test "fat identity preserves unrelated bytes in and around rewritten boot sectors" {
    const io = std.testing.io;
    const path = "test-fat-identity-preserve.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const layout = fat32LargeSectorLayout();
    const region_offset: u64 = 3 * 4_096;
    var volume = try createTestVolume(io, path, layout, region_offset, 0x93);
    defer volume.image.close(io);

    var prefix = [_]u8{0xA5} ** 4_096;
    var tail = [_]u8{0x5A} ** 4_096;
    try volume.image.pwrite(io, &prefix, 0);
    try volume.image.pwrite(io, &tail, volume.region.offset + volume.region.length);

    var before_primary_storage: [max_bytes_per_sector]u8 = undefined;
    const before_primary = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &before_primary_storage);

    const report = try rewriteIdentity(&volume.image, io, volume.region, 0xFACE_B00C);
    try std.testing.expectEqual(@as(u8, 2), report.boot_sector_copies_rewritten);

    var after_prefix = [_]u8{0} ** 4_096;
    try readAllAt(&volume.image, io, &after_prefix, 0);
    try std.testing.expectEqualSlices(u8, &prefix, &after_prefix);

    var after_tail = [_]u8{0} ** 4_096;
    try readAllAt(&volume.image, io, &after_tail, volume.region.offset + volume.region.length);
    try std.testing.expectEqualSlices(u8, &tail, &after_tail);

    var after_primary_storage: [max_bytes_per_sector]u8 = undefined;
    const after_primary = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &after_primary_storage);
    try expectOnlyVolumeIdChanged(before_primary, after_primary, layout.variant.volumeIdOffset(), 0xFACE_B00C);

    var after_backup_storage: [max_bytes_per_sector]u8 = undefined;
    const after_backup = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, layout.backup_boot_sector.?, &after_backup_storage);
    try expectOnlyVolumeIdChanged(before_primary, after_backup, layout.variant.volumeIdOffset(), 0xFACE_B00C);
}

test "fat identity refuses malformed input before writing" {
    const io = std.testing.io;

    {
        const path = "test-fat-identity-invalid-volume-id.img";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};

        const layout = fat12Layout();
        var volume = try createTestVolume(io, path, layout, 2 * 512, 0x31);
        defer volume.image.close(io);

        var before_storage: [max_bytes_per_sector]u8 = undefined;
        const before = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &before_storage);

        try std.testing.expectError(
            error.InvalidVolumeId,
            rewriteIdentity(&volume.image, io, volume.region, 0),
        );

        var after_storage: [max_bytes_per_sector]u8 = undefined;
        const after = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &after_storage);
        try std.testing.expectEqualSlices(u8, before, after);
    }

    {
        const path = "test-fat-identity-invalid-signature.img";
        defer Io.Dir.cwd().deleteFile(io, path) catch {};

        const layout = fat16Layout();
        var volume = try createTestVolume(io, path, layout, 2 * 2_048, 0x4B);
        defer volume.image.close(io);

        var before_storage: [max_bytes_per_sector]u8 = undefined;
        const before = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &before_storage);

        var bad_signature = [_]u8{ 0x00, 0x00 };
        try volume.image.pwrite(io, &bad_signature, volume.region.offset + 510);

        try std.testing.expectError(
            error.InvalidBootSector,
            rewriteIdentity(&volume.image, io, volume.region, 0x5566_7788),
        );

        var after_storage: [max_bytes_per_sector]u8 = undefined;
        const after = try readSector(&volume.image, io, volume.region, layout.bytes_per_sector, 0, &after_storage);
        try std.testing.expectEqualSlices(u8, before[0..510], after[0..510]);
        try std.testing.expectEqual(@as(u8, 0), after[510]);
        try std.testing.expectEqual(@as(u8, 0), after[511]);
        try std.testing.expectEqualSlices(u8, before[512..], after[512..]);
    }
}

test "fat identity rereads, verifies, and reports the rewritten serial" {
    const io = std.testing.io;
    const path = "test-fat-identity-verify.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const layout = fat32Layout();
    const region_offset: u64 = 8 * 512;
    {
        var volume = try createTestVolume(io, path, layout, region_offset, 0x77);
        defer volume.image.close(io);

        const report = try rewriteIdentity(&volume.image, io, volume.region, 0xABCD_1234);
        try std.testing.expectEqual(layout.variant, report.before.variant);
        try std.testing.expectEqual(layout.volume_id, report.before.volume_id);
        try std.testing.expectEqual(@as(u32, 0xABCD_1234), report.after.volume_id);
        try std.testing.expectEqual(@as(?u16, 6), report.after.backup_boot_sector);
        try std.testing.expectEqual(@as(u8, 2), report.boot_sector_copies_rewritten);
        try std.testing.expectEqual(false, report.device_flushed);

        var old_serial: [serial_bytes]u8 = undefined;
        var new_serial: [serial_bytes]u8 = undefined;
        try std.testing.expectEqualStrings("5A56-4D49", report.before.serial(&old_serial));
        try std.testing.expectEqualStrings("ABCD-1234", report.after.serial(&new_serial));
    }

    var reopened = try Image.openPathReadOnly(io, path);
    defer reopened.close(io);

    const reopened_identity = try readIdentity(&reopened, io, .{
        .offset = region_offset,
        .length = try layout.regionLength(),
    });
    try std.testing.expectEqual(@as(u32, 0xABCD_1234), reopened_identity.volume_id);
    try std.testing.expectEqual(@as(?u16, 6), reopened_identity.backup_boot_sector);
}
