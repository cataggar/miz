//! Free-space probe for the filesystem holding a workspace path.
//!
//! Zig 0.16 exposes no `statfs` and `std.Io` has no portable free-space API,
//! so this issues the syscall directly on 64-bit Linux and answers "unknown"
//! everywhere else. Every caller must treat unknown as permission to proceed:
//! an unknown amount of free space is not the same as too little.

const std = @import("std");
const builtin = @import("builtin");

pub const FileUsage = struct {
    logical_bytes: u64,
    allocated_bytes: u64,
};

/// The 64-bit Linux `struct statfs`.
const LinuxStatfs = extern struct {
    type: i64,
    bsize: i64,
    blocks: u64,
    bfree: u64,
    bavail: u64,
    files: u64,
    ffree: u64,
    fsid: [2]i32,
    namelen: i64,
    frsize: i64,
    flags: i64,
    spare: [4]i64,
};

/// Bytes available to an unprivileged writer under `path`, or null when the
/// host offers no way to ask.
pub fn availableBytes(path: []const u8) ?u64 {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return null;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= path_buffer.len) return null;
    @memcpy(path_buffer[0..path.len], path);
    path_buffer[path.len] = 0;

    var info: LinuxStatfs = undefined;
    const result = std.os.linux.syscall2(
        .statfs,
        @intFromPtr(&path_buffer),
        @intFromPtr(&info),
    );
    if (std.os.linux.errno(result) != .SUCCESS) return null;
    if (info.bsize <= 0) return null;
    return std.math.mul(u64, info.bavail, @intCast(info.bsize)) catch null;
}

/// Logical and physically allocated bytes for `path`, or null when the host
/// cannot report both values. Linux reports allocation in 512-byte blocks.
pub fn fileUsage(path: []const u8) ?FileUsage {
    if (builtin.os.tag != .linux) return null;
    var path_buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (path.len >= path_buffer.len) return null;
    @memcpy(path_buffer[0..path.len], path);
    path_buffer[path.len] = 0;

    var info: std.os.linux.Statx = undefined;
    const result = std.os.linux.statx(
        std.os.linux.AT.FDCWD,
        @ptrCast(&path_buffer),
        std.os.linux.AT.SYMLINK_NOFOLLOW | std.os.linux.AT.STATX_DONT_SYNC,
        std.os.linux.STATX.BASIC_STATS,
        &info,
    );
    if (@as(isize, @bitCast(result)) < 0 or !info.mask.SIZE or !info.mask.BLOCKS) return null;
    return .{
        .logical_bytes = info.size,
        .allocated_bytes = std.math.mul(u64, info.blocks, 512) catch return null,
    };
}

test "free space is reported for an existing directory on Linux" {
    if (builtin.os.tag != .linux or @sizeOf(usize) != 8) return error.SkipZigTest;
    try std.testing.expect(availableBytes(".") != null);
}

test "an unreachable path reports unknown rather than zero" {
    try std.testing.expectEqual(
        @as(?u64, null),
        availableBytes("miz-free-space-nonexistent/probe"),
    );
    try std.testing.expectEqual(
        @as(?FileUsage, null),
        fileUsage("miz-free-space-nonexistent/probe"),
    );
}
