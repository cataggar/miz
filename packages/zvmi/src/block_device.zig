//! Block-device geometry probing.
//!
//! `stat(2)` on a block-device special file reports `st_size == 0` on Linux
//! -- the size belongs to the device the node points at, not to the node
//! itself -- so an image opened from `/dev/nvme0n1`, `/dev/sda`, or a
//! device-mapper node like `/dev/mapper/vg-lv` has to ask the kernel for its
//! real size instead of trusting `Io.File.stat`. Linux answers that with the
//! `BLKGETSIZE64`/`BLKSSZGET` ioctls; every other platform gets a clear
//! `error.UnsupportedBlockDevice` rather than a silently zero-length image.

const std = @import("std");
const builtin = @import("builtin");
const Io = std.Io;

/// The Linux `BLKGETSIZE64` ioctl request code (`_IOR(0x12, 114, size_t)`),
/// which reports the device's size in bytes. Same constant as the one
/// `azagent/resource_disk.zig` uses for the resource disk.
const blkgetsize64: u32 = 0x80081272;

/// The Linux `BLKSSZGET` ioctl request code (`_IO(0x12, 104)`), which
/// reports the logical (smallest addressable) sector size as a C `int`.
const blkssget: u32 = 0x1268;

/// Smallest logical sector size any supported disk layout can use: every
/// partition table this library writes addresses 512-byte LBAs at minimum.
pub const min_logical_sector_size: u32 = 512;

/// Generous upper bound on a sane logical sector size. Real hardware tops
/// out at 4096 today; anything beyond this is a garbage ioctl answer rather
/// than a disk we could lay out.
pub const max_logical_sector_size: u32 = 64 * 1024;

pub const ProbeError = error{
    /// The platform has no block-device size interface wired up here.
    UnsupportedBlockDevice,
    /// The `BLKGETSIZE64` ioctl failed.
    BlockDeviceSizeUnavailable,
    /// The `BLKSSZGET` ioctl failed.
    BlockDeviceSectorSizeUnavailable,
    /// The device exists but has no medium/backing extent (an empty loop
    /// device, an optical drive with no disc). Reported instead of handing
    /// back a zero-length image whose every read silently returns nothing.
    EmptyBlockDevice,
    InvalidLogicalSectorSize,
    UnalignedBlockDeviceSize,
};

pub const Geometry = struct {
    /// The device's real size in bytes, as reported by the kernel. This, not
    /// the `stat` size, is authoritative for a device-backed image.
    size_bytes: u64,
    logical_sector_size: u32,
};

/// Reads `file`'s real geometry. `file` must already be known to be a
/// block-device node (`Io.File.Stat.kind == .block_device`); the ioctls are
/// not meaningful on anything else.
pub fn probe(file: Io.File) ProbeError!Geometry {
    return switch (builtin.os.tag) {
        .linux => probeLinux(file),
        else => error.UnsupportedBlockDevice,
    };
}

fn probeLinux(file: Io.File) ProbeError!Geometry {
    const linux = std.os.linux;

    var size_bytes: u64 = 0;
    const size_rc = linux.ioctl(file.handle, blkgetsize64, @intFromPtr(&size_bytes));
    if (linux.errno(size_rc) != .SUCCESS) return error.BlockDeviceSizeUnavailable;

    var logical_sector_size: c_int = 0;
    const sector_rc = linux.ioctl(file.handle, blkssget, @intFromPtr(&logical_sector_size));
    if (linux.errno(sector_rc) != .SUCCESS) return error.BlockDeviceSectorSizeUnavailable;

    return geometryFrom(size_bytes, logical_sector_size);
}

/// Validates the raw ioctl answers and turns them into a `Geometry`. Split
/// out from `probeLinux` so the validation rules are testable without a real
/// device (which no CI runner is guaranteed to have).
pub fn geometryFrom(size_bytes: u64, logical_sector_size: c_int) ProbeError!Geometry {
    if (size_bytes == 0) return error.EmptyBlockDevice;
    if (logical_sector_size <= 0) return error.InvalidLogicalSectorSize;

    const sector_size: u64 = @intCast(logical_sector_size);
    if (sector_size < min_logical_sector_size or
        sector_size > max_logical_sector_size or
        !std.math.isPowerOfTwo(sector_size))
    {
        return error.InvalidLogicalSectorSize;
    }
    if (size_bytes % sector_size != 0) return error.UnalignedBlockDeviceSize;

    return .{ .size_bytes = size_bytes, .logical_sector_size = @intCast(sector_size) };
}

test "geometryFrom accepts real-world device geometries" {
    const nvme = try geometryFrom(1_024_209_543_168, 512);
    try std.testing.expectEqual(@as(u64, 1_024_209_543_168), nvme.size_bytes);
    try std.testing.expectEqual(@as(u32, 512), nvme.logical_sector_size);

    const advanced_format = try geometryFrom(8 * 1024 * 1024 * 1024, 4096);
    try std.testing.expectEqual(@as(u32, 4096), advanced_format.logical_sector_size);
}

test "geometryFrom rejects a device with no medium" {
    try std.testing.expectError(error.EmptyBlockDevice, geometryFrom(0, 512));
}

test "geometryFrom rejects implausible sector sizes" {
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, 0));
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, -1));
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, 256));
    try std.testing.expectError(error.InvalidLogicalSectorSize, geometryFrom(4096, 1536));
    try std.testing.expectError(
        error.InvalidLogicalSectorSize,
        geometryFrom(4096, max_logical_sector_size * 2),
    );
}

test "geometryFrom rejects a size that is not a whole number of sectors" {
    try std.testing.expectError(error.UnalignedBlockDeviceSize, geometryFrom(4096 + 512, 4096));
}
