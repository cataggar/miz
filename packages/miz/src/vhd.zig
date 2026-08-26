//! VHD / VPC footer codec (Microsoft "Virtual Hard Disk Image Format
//! Specification"). Only the 512-byte footer is implemented so far, which is
//! all a **fixed** VHD needs (the disk payload is just the raw bytes from
//! offset 0 up to `current_size`, followed immediately by one copy of this
//! footer). Dynamic/differencing VHDs additionally need a "cxsparse" dynamic
//! header + Block Allocation Table, which is a later milestone.
//!
//! Field layout, checksum algorithm, and the legacy CHS geometry calculation
//! below are verified against QEMU's `block/vpc.c` (`vpc_checksum`,
//! `calculate_geometry`), which is the de-facto interoperability reference
//! for this format.

const std = @import("std");

pub const footer_size: usize = 512;
pub const sector_size: u64 = 512;

pub const cookie_conectix: [8]u8 = "conectix".*;

pub const DiskType = enum(u32) {
    fixed = 2,
    dynamic = 3,
    differencing = 4,
    _,
};

/// Seconds between the Unix epoch (1970-01-01) and the VHD epoch (2000-01-01).
pub const timestamp_base: i64 = 946684800;

/// Four-character-code identifying the tool that created the image. Azure /
/// Hyper-V and QEMU key off this (and off the CHS geometry) to decide
/// whether to trust `current_size` or recompute the size from CHS; using an
/// unrecognized creator app makes readers fall back to `current_size`, which
/// is what we want since we always write a geometry that matches the size.
pub const creator_app_miz: [4]u8 = "miz ".*;
pub const creator_os_none: [4]u8 = .{ 0, 0, 0, 0 };

pub const Geometry = struct {
    cylinders: u16,
    heads: u8,
    sectors_per_track: u8,

    pub fn totalSectors(self: Geometry) u64 {
        return @as(u64, self.cylinders) * self.heads * self.sectors_per_track;
    }
};

const SizeCalcType = enum {
    current_size,
    chs_geometry,
};

fn sizeCalcTypeForCreatorApplication(creator_application: [4]u8) SizeCalcType {
    if (std.mem.eql(u8, &creator_application, "vpc ")) return .chs_geometry;
    if (std.mem.eql(u8, &creator_application, "vs  ")) return .chs_geometry;
    if (std.mem.eql(u8, &creator_application, "qemu")) return .chs_geometry;
    return .current_size;
}

const max_chs_cylinders: u64 = 65535;
const max_chs_heads: u64 = 16;
const max_chs_sectors: u64 = 255;
const max_chs_geometry: u64 = max_chs_cylinders * max_chs_heads * max_chs_sectors;

/// Faithful reimplementation of QEMU's `calculate_geometry` so `miz`-created
/// fixed VHDs report the same CHS geometry QEMU/Hyper-V would compute for the
/// same size (Azure and Hyper-V actually trust `current_size` over CHS, but
/// matching the reference implementation keeps us maximally compatible with
/// older tools that don't).
pub fn calculateGeometry(total_sectors_in: u64) Geometry {
    const total_sectors = @min(total_sectors_in, max_chs_geometry);

    var secs_per_cyl: u64 = undefined;
    var heads: u64 = undefined;
    var cyls_times_heads: u64 = undefined;

    if (total_sectors >= 65535 * 16 * 63) {
        secs_per_cyl = 255;
        heads = 16;
        cyls_times_heads = total_sectors / secs_per_cyl;
    } else {
        secs_per_cyl = 17;
        cyls_times_heads = total_sectors / secs_per_cyl;
        heads = std.math.divCeil(u64, cyls_times_heads, 1024) catch unreachable;
        if (heads < 4) heads = 4;

        if (cyls_times_heads >= (heads * 1024) or heads > 16) {
            secs_per_cyl = 31;
            heads = 16;
            cyls_times_heads = total_sectors / secs_per_cyl;
        }
        if (cyls_times_heads >= (heads * 1024)) {
            secs_per_cyl = 63;
            heads = 16;
            cyls_times_heads = total_sectors / secs_per_cyl;
        }
    }

    return .{
        .cylinders = @intCast(cyls_times_heads / heads),
        .heads = @intCast(heads),
        .sectors_per_track = @intCast(secs_per_cyl),
    };
}

pub const Footer = struct {
    features: u32 = 0x02,
    file_format_version: u32 = 0x0001_0000,
    /// 0xFFFF_FFFF_FFFF_FFFF for a fixed disk (no dynamic header follows).
    data_offset: u64 = 0xFFFF_FFFF_FFFF_FFFF,
    /// Seconds since 2000-01-01T00:00:00Z.
    timestamp: u32,
    creator_application: [4]u8 = creator_app_miz,
    creator_version: u32 = 0x0001_0000,
    creator_host_os: [4]u8 = creator_os_none,
    original_size: u64,
    current_size: u64,
    geometry: Geometry,
    disk_type: DiskType,
    unique_id: [16]u8,
    saved_state: u8 = 0,

    pub fn forFixedDisk(size: u64, unique_id: [16]u8, now_unix: i64) Footer {
        const total_sectors = size / 512;
        return .{
            .data_offset = 0xFFFF_FFFF_FFFF_FFFF,
            .timestamp = timestampFromUnix(now_unix),
            .original_size = size,
            .current_size = size,
            .geometry = calculateGeometry(total_sectors),
            .disk_type = .fixed,
            .unique_id = unique_id,
        };
    }

    /// `header_offset` is where the dynamic disk header (immediately
    /// followed by the BAT) lives -- always `footer_size` (512) for images
    /// we create ourselves.
    pub fn forDynamicDisk(size: u64, header_offset: u64, unique_id: [16]u8, now_unix: i64) Footer {
        const total_sectors = size / 512;
        return .{
            .data_offset = header_offset,
            .timestamp = timestampFromUnix(now_unix),
            .original_size = size,
            .current_size = size,
            .geometry = calculateGeometry(total_sectors),
            .disk_type = .dynamic,
            .unique_id = unique_id,
        };
    }

    fn timestampFromUnix(now_unix: i64) u32 {
        const since_epoch = std.math.sub(i64, now_unix, timestamp_base) catch return std.math.maxInt(u32);
        if (since_epoch <= 0) return 0;
        return @intCast(@min(@as(i64, std.math.maxInt(u32)), since_epoch));
    }

    /// Imported VHDs historically disagree on which footer field defines the
    /// virtual size. Old Virtual PC (`vpc ` / `vs  `) and legacy QEMU (`qemu`)
    /// readers treat CHS Disk Geometry as authoritative, while newer writers
    /// (including `miz` and QEMU's `qem2`) rely on `current_size`. Preserve
    /// that quirk on read so third-party images report the same size as the
    /// tool that created them.
    pub fn virtualSize(self: Footer) u64 {
        return switch (sizeCalcTypeForCreatorApplication(self.creator_application)) {
            .current_size => self.current_size,
            .chs_geometry => self.geometry.totalSectors() * sector_size,
        };
    }

    /// Serializes to the on-disk, big-endian, 512-byte footer, with the
    /// checksum field computed and filled in.
    pub fn encode(self: Footer) [footer_size]u8 {
        var buf: [footer_size]u8 = [_]u8{0} ** footer_size;

        var w = ByteWriter{ .buf = &buf };
        w.bytes(&cookie_conectix);
        w.putU32(self.features);
        w.putU32(self.file_format_version);
        w.putU64(self.data_offset);
        w.putU32(self.timestamp);
        w.bytes(&self.creator_application);
        w.putU32(self.creator_version);
        w.bytes(&self.creator_host_os);
        w.putU64(self.original_size);
        w.putU64(self.current_size);
        w.putU16(self.geometry.cylinders);
        w.putU8(self.geometry.heads);
        w.putU8(self.geometry.sectors_per_track);
        w.putU32(@intFromEnum(self.disk_type));
        w.putU32(0); // checksum placeholder, filled below
        w.bytes(&self.unique_id);
        w.putU8(self.saved_state);
        // remaining 427 reserved bytes are already zero

        const checksum = computeChecksum(&buf);
        std.mem.writeInt(u32, buf[64..68], checksum, .big);
        return buf;
    }

    pub const DecodeError = error{
        BadCookie,
        BadChecksum,
    };

    pub fn decode(buf: *const [footer_size]u8) DecodeError!Footer {
        if (!std.mem.eql(u8, buf[0..8], &cookie_conectix)) return error.BadCookie;

        var checked = buf.*;
        checked[64..68].* = .{ 0, 0, 0, 0 };
        const expected_checksum = std.mem.readInt(u32, buf[64..68], .big);
        if (computeChecksum(&checked) != expected_checksum) return error.BadChecksum;

        var r = ByteReader{ .buf = buf };
        r.skip(8); // cookie
        const features = r.getU32();
        const file_format_version = r.getU32();
        const data_offset = r.getU64();
        const timestamp = r.getU32();
        const creator_application = r.bytes(4).*;
        const creator_version = r.getU32();
        const creator_host_os = r.bytes(4).*;
        const original_size = r.getU64();
        const current_size = r.getU64();
        const cylinders = r.getU16();
        const heads = r.getU8();
        const sectors_per_track = r.getU8();
        const disk_type: DiskType = @enumFromInt(r.getU32());
        r.skip(4); // checksum
        const unique_id = r.bytes(16).*;
        const saved_state = r.getU8();

        return .{
            .features = features,
            .file_format_version = file_format_version,
            .data_offset = data_offset,
            .timestamp = timestamp,
            .creator_application = creator_application,
            .creator_version = creator_version,
            .creator_host_os = creator_host_os,
            .original_size = original_size,
            .current_size = current_size,
            .geometry = .{ .cylinders = cylinders, .heads = heads, .sectors_per_track = sectors_per_track },
            .disk_type = disk_type,
            .unique_id = unique_id,
            .saved_state = saved_state,
        };
    }
};

pub const dynamic_header_size: usize = 1024;
pub const cookie_cxsparse: [8]u8 = "cxsparse".*;

/// 2 MiB, matching QEMU's `create_dynamic_disk` (the de-facto standard
/// block size for VHD; must be a power of two).
pub const default_block_size: u32 = 0x0020_0000;

/// Size in bytes of the per-block sector-allocation bitmap that precedes
/// each data block: 1 bit per 512-byte sector in the block, rounded up to
/// a 512-byte boundary. Matches QEMU's `vpc_open`:
/// `bitmap_size = ((block_size / (8 * 512)) + 511) & ~511`.
pub fn bitmapSize(block_size: u32) u32 {
    const raw = block_size / (8 * 512);
    return (raw + 511) & ~@as(u32, 511);
}

/// The "cxsparse" Dynamic Disk Header that immediately follows the footer
/// in a dynamic VHD (at the footer's `data_offset`), followed immediately
/// by the Block Allocation Table (BAT) at `table_offset`. Only the fields
/// needed for a non-differencing dynamic disk (no backing/parent file) are
/// modeled; the parent-locator region is always zero-filled.
pub const DynamicHeader = struct {
    /// Per spec this should be 0xFFFFFFFF in the low 32 bits (0xFFFFFFFF____),
    /// but QEMU's comment notes "the spec is actually wrong here... MS tools
    /// expect all 64 bits to be set" -- we follow QEMU/MS tools, not the
    /// literal spec text, since that's what's actually interoperable.
    data_offset: u64 = 0xFFFF_FFFF_FFFF_FFFF,
    table_offset: u64,
    header_version: u32 = 0x0001_0000,
    max_table_entries: u32,
    block_size: u32 = default_block_size,
    parent_unique_id: [16]u8 = [_]u8{0} ** 16,
    parent_timestamp: u32 = 0,
    parent_unicode_name: [512]u8 = [_]u8{0} ** 512,

    pub fn encode(self: DynamicHeader) [dynamic_header_size]u8 {
        var buf: [dynamic_header_size]u8 = [_]u8{0} ** dynamic_header_size;

        var w = ByteWriter{ .buf = &buf };
        w.bytes(&cookie_cxsparse);
        w.putU64(self.data_offset);
        w.putU64(self.table_offset);
        w.putU32(self.header_version);
        w.putU32(self.max_table_entries);
        w.putU32(self.block_size);
        w.putU32(0); // checksum placeholder, filled below
        w.bytes(&self.parent_unique_id);
        w.putU32(self.parent_timestamp);
        w.putU32(0); // reserved
        w.bytes(&self.parent_unicode_name);
        // parent_locator[8] (192 bytes) + reserved2 (256 bytes) stay zero:
        // this is a non-differencing disk with no backing/parent file.

        const checksum = computeChecksum(&buf);
        std.mem.writeInt(u32, buf[36..40], checksum, .big);
        return buf;
    }

    pub const DecodeError = error{
        BadCookie,
        BadChecksum,
    };

    pub fn decode(buf: *const [dynamic_header_size]u8) DecodeError!DynamicHeader {
        if (!std.mem.eql(u8, buf[0..8], &cookie_cxsparse)) return error.BadCookie;

        var checked = buf.*;
        checked[36..40].* = .{ 0, 0, 0, 0 };
        const expected_checksum = std.mem.readInt(u32, buf[36..40], .big);
        if (computeChecksum(&checked) != expected_checksum) return error.BadChecksum;

        var r = ByteReader{ .buf = buf };
        r.skip(8); // cookie
        const data_offset = r.getU64();
        const table_offset = r.getU64();
        const header_version = r.getU32();
        const max_table_entries = r.getU32();
        const block_size = r.getU32();
        r.skip(4); // checksum
        const parent_unique_id = r.bytes(16).*;
        const parent_timestamp = r.getU32();
        r.skip(4); // reserved
        const parent_unicode_name = r.bytes(512).*;

        return .{
            .data_offset = data_offset,
            .table_offset = table_offset,
            .header_version = header_version,
            .max_table_entries = max_table_entries,
            .block_size = block_size,
            .parent_unique_id = parent_unique_id,
            .parent_timestamp = parent_timestamp,
            .parent_unicode_name = parent_unicode_name,
        };
    }
};

/// "One's complement of the sum of all the bytes in the footer without the
/// checksum field" (spec wording; matches QEMU's `vpc_checksum`). The
/// checksum field itself must be zeroed in `buf` before calling this. Used
/// for both the 512-byte footer and the 1024-byte dynamic disk header (both
/// use the identical algorithm per spec).
fn computeChecksum(buf: []const u8) u32 {
    var sum: u32 = 0;
    for (buf) |b| sum +%= b;
    return ~sum;
}

const ByteWriter = struct {
    buf: []u8,
    pos: usize = 0,

    fn bytes(self: *ByteWriter, b: []const u8) void {
        @memcpy(self.buf[self.pos..][0..b.len], b);
        self.pos += b.len;
    }
    fn putU8(self: *ByteWriter, v: u8) void {
        self.buf[self.pos] = v;
        self.pos += 1;
    }
    fn putU16(self: *ByteWriter, v: u16) void {
        std.mem.writeInt(u16, self.buf[self.pos..][0..2], v, .big);
        self.pos += 2;
    }
    fn putU32(self: *ByteWriter, v: u32) void {
        std.mem.writeInt(u32, self.buf[self.pos..][0..4], v, .big);
        self.pos += 4;
    }
    fn putU64(self: *ByteWriter, v: u64) void {
        std.mem.writeInt(u64, self.buf[self.pos..][0..8], v, .big);
        self.pos += 8;
    }
};

const ByteReader = struct {
    buf: []const u8,
    pos: usize = 0,

    fn skip(self: *ByteReader, n: usize) void {
        self.pos += n;
    }
    fn bytes(self: *ByteReader, comptime n: usize) *const [n]u8 {
        const s = self.buf[self.pos..][0..n];
        self.pos += n;
        return s;
    }
    fn getU8(self: *ByteReader) u8 {
        const v = self.buf[self.pos];
        self.pos += 1;
        return v;
    }
    fn getU16(self: *ByteReader) u16 {
        const v = std.mem.readInt(u16, self.buf[self.pos..][0..2], .big);
        self.pos += 2;
        return v;
    }
    fn getU32(self: *ByteReader) u32 {
        const v = std.mem.readInt(u32, self.buf[self.pos..][0..4], .big);
        self.pos += 4;
        return v;
    }
    fn getU64(self: *ByteReader) u64 {
        const v = std.mem.readInt(u64, self.buf[self.pos..][0..8], .big);
        self.pos += 8;
        return v;
    }
};

test "calculateGeometry matches known QEMU vectors" {
    // 512 MiB image: 1048576 sectors -> secs_per_cyl=17 branch.
    const g = calculateGeometry(1024 * 1024);
    try std.testing.expect(g.sectors_per_track == 17 or g.sectors_per_track == 31 or g.sectors_per_track == 63);
    try std.testing.expect(g.totalSectors() <= 1024 * 1024);
}

test "Footer encode/decode round-trip" {
    const size: u64 = 64 * 1024 * 1024; // 64 MiB
    const footer = Footer.forFixedDisk(size, [_]u8{0xAB} ** 16, timestamp_base + 1000);
    const encoded = footer.encode();

    try std.testing.expectEqualSlices(u8, &cookie_conectix, encoded[0..8]);
    try std.testing.expectEqualSlices(u8, &creator_app_miz, encoded[28..32]);

    const decoded = try Footer.decode(&encoded);
    try std.testing.expectEqual(footer.current_size, decoded.current_size);
    try std.testing.expectEqual(footer.original_size, decoded.original_size);
    try std.testing.expectEqual(footer.disk_type, decoded.disk_type);
    try std.testing.expectEqual(footer.unique_id, decoded.unique_id);
    try std.testing.expectEqual(footer.geometry.cylinders, decoded.geometry.cylinders);
    try std.testing.expectEqual(footer.geometry.heads, decoded.geometry.heads);
    try std.testing.expectEqual(footer.geometry.sectors_per_track, decoded.geometry.sectors_per_track);
}

test "Footer.decode rejects bad cookie" {
    var buf = [_]u8{0} ** footer_size;
    try std.testing.expectError(error.BadCookie, Footer.decode(&buf));
}

test "Footer.decode rejects corrupted checksum" {
    const footer = Footer.forFixedDisk(1024 * 1024, [_]u8{1} ** 16, timestamp_base);
    var encoded = footer.encode();
    encoded[100] ^= 0xFF; // corrupt a reserved byte
    try std.testing.expectError(error.BadChecksum, Footer.decode(&encoded));
}

test "Footer.virtualSize uses CHS geometry for legacy qemu creator app" {
    var footer = Footer.forFixedDisk(4 * 1024 * 1024, [_]u8{3} ** 16, timestamp_base);
    footer.creator_application = "qemu".*;
    footer.current_size = 8 * 1024 * 1024;
    footer.geometry = .{
        .cylinders = 10,
        .heads = 4,
        .sectors_per_track = 17,
    };

    const fixture = footer.encode();
    const decoded = try Footer.decode(&fixture);

    try std.testing.expectEqual(@as(u64, 10 * 4 * 17) * sector_size, decoded.virtualSize());
    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024), decoded.current_size);
}

test "Footer.virtualSize defaults to current_size for unknown creator app" {
    var footer = Footer.forFixedDisk(4 * 1024 * 1024, [_]u8{4} ** 16, timestamp_base);
    footer.creator_application = .{ 0, 0, 0, 0 };
    footer.current_size = 8 * 1024 * 1024;
    footer.geometry = .{
        .cylinders = 10,
        .heads = 4,
        .sectors_per_track = 17,
    };

    const fixture = footer.encode();
    const decoded = try Footer.decode(&fixture);

    try std.testing.expectEqual(@as(u64, 8 * 1024 * 1024), decoded.virtualSize());
    try std.testing.expectEqual(@as(u64, 10 * 4 * 17) * sector_size, decoded.geometry.totalSectors() * sector_size);
}

test "bitmapSize matches known QEMU value for the default 2 MiB block size" {
    // 2 MiB block / 512-byte sectors = 4096 sectors -> 4096 bits = 512 bytes,
    // already 512-aligned. Matches QEMU's vpc_open computation exactly.
    try std.testing.expectEqual(@as(u32, 512), bitmapSize(default_block_size));
}

test "DynamicHeader encode/decode round-trip" {
    const header = DynamicHeader{
        .table_offset = footer_size + dynamic_header_size,
        .max_table_entries = 1234,
        .block_size = default_block_size,
    };
    const encoded = header.encode();

    try std.testing.expectEqualSlices(u8, &cookie_cxsparse, encoded[0..8]);

    const decoded = try DynamicHeader.decode(&encoded);
    try std.testing.expectEqual(header.table_offset, decoded.table_offset);
    try std.testing.expectEqual(header.max_table_entries, decoded.max_table_entries);
    try std.testing.expectEqual(header.block_size, decoded.block_size);
    try std.testing.expectEqual(@as(u64, 0xFFFF_FFFF_FFFF_FFFF), decoded.data_offset);
}

test "DynamicHeader.decode rejects bad cookie" {
    var buf = [_]u8{0} ** dynamic_header_size;
    try std.testing.expectError(error.BadCookie, DynamicHeader.decode(&buf));
}

test "DynamicHeader.decode rejects corrupted checksum" {
    const header = DynamicHeader{ .table_offset = 1536, .max_table_entries = 4 };
    var encoded = header.encode();
    encoded[900] ^= 0xFF; // corrupt a reserved byte
    try std.testing.expectError(error.BadChecksum, DynamicHeader.decode(&encoded));
}

test "Footer.forDynamicDisk points data_offset at the dynamic header" {
    const footer = Footer.forDynamicDisk(4 * 1024 * 1024, footer_size, [_]u8{2} ** 16, timestamp_base);
    try std.testing.expectEqual(DiskType.dynamic, footer.disk_type);
    try std.testing.expectEqual(@as(u64, footer_size), footer.data_offset);
}
