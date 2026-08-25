//! Deterministic no-follow snapshots of an OCI bundle rootfs.
const std = @import("std");
const builtin = @import("builtin");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Kind = enum {
    file,
    directory,
    symlink,
    fifo,
    character_device,
    block_device,
};

pub const Timestamp = struct {
    seconds: i64,
    nanoseconds: u32,
};

pub const Xattr = struct {
    name: []const u8,
    value_base64: []const u8,
};

pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    mode: u32,
    uid: u32 = 0,
    gid: u32 = 0,
    mtime: Timestamp,
    size: u64 = 0,
    digest: ?[]const u8 = null,
    link_name: ?[]const u8 = null,
    inode: u64 = 0,
    nlink: u64 = 1,
    filesystem_device: u64 = 0,
    device_major: u32 = 0,
    device_minor: u32 = 0,
    xattrs: []const Xattr = &.{},

    pub fn same(left: Entry, right: Entry) bool {
        return left.kind == right.kind and
            left.mode == right.mode and
            left.uid == right.uid and
            left.gid == right.gid and
            left.mtime.seconds == right.mtime.seconds and
            left.mtime.nanoseconds == right.mtime.nanoseconds and
            left.size == right.size and
            left.inode == right.inode and
            left.nlink == right.nlink and
            left.filesystem_device == right.filesystem_device and
            optionalEqual(left.digest, right.digest) and
            optionalEqual(left.link_name, right.link_name) and
            xattrsEqual(left.xattrs, right.xattrs);
    }
};

pub const Captured = struct {
    arena: std.heap.ArenaAllocator,
    entries: []Entry,

    pub fn deinit(self: *Captured) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub fn capture(
    allocator: std.mem.Allocator,
    io: Io,
    rootfs: Io.Dir,
) !Captured {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();
    var entries = std.array_list.Managed(Entry).init(owned);
    const root_stat = try rootfs.stat(io);
    const root_system = try systemMetadataRoot(rootfs);
    try entries.append(.{
        .path = "",
        .kind = .directory,
        .mode = @intFromEnum(root_stat.permissions) & 0o7777,
        .uid = root_system.uid,
        .gid = root_system.gid,
        .mtime = timestamp(root_stat.mtime),
        .inode = @intCast(root_stat.inode),
        .nlink = @intCast(root_stat.nlink),
        .filesystem_device = root_system.filesystem_device,
        .xattrs = try readXattrs(owned, rootfs, "."),
    });
    var walker = try rootfs.walk(owned);
    defer walker.deinit();
    while (try walker.next(io)) |item| {
        const stat = try item.dir.statFile(io, item.basename, .{
            .follow_symlinks = false,
        });
        const kind = try snapshotKind(stat.kind);
        const system = try systemMetadata(item.dir, item.basename);
        const path = try owned.dupe(u8, item.path);
        var entry = Entry{
            .path = path,
            .kind = kind,
            .mode = @intFromEnum(stat.permissions) & 0o7777,
            .mtime = timestamp(stat.mtime),
            .size = if (kind == .file) stat.size else 0,
            .inode = @intCast(stat.inode),
            .nlink = @intCast(stat.nlink),
            .uid = system.uid,
            .gid = system.gid,
            .device_major = system.device_major,
            .device_minor = system.device_minor,
            .filesystem_device = system.filesystem_device,
        };
        switch (kind) {
            .file => entry.digest = try hashFile(owned, io, item.dir, item.basename, stat.size),
            .symlink => entry.link_name = try readLink(owned, io, item.dir, item.basename),
            else => {},
        }
        if (kind != .symlink) {
            entry.xattrs = try readXattrs(owned, item.dir, item.basename);
        }

        try entries.append(entry);
    }
    std.mem.sort(Entry, entries.items, {}, lessThan);
    return .{
        .arena = arena,
        .entries = try entries.toOwnedSlice(),
    };
}

const SystemMetadata = struct {
    uid: u32 = 0,
    gid: u32 = 0,
    device_major: u32 = 0,
    device_minor: u32 = 0,
    filesystem_device: u64 = 0,
};

fn systemMetadata(dir: Io.Dir, path: [:0]const u8) !SystemMetadata {
    if (builtin.os.tag != .linux) return .{};
    const linux = std.os.linux;
    var statx = std.mem.zeroes(linux.Statx);
    while (true) switch (linux.errno(linux.statx(
        dir.handle,
        path.ptr,
        linux.AT.SYMLINK_NOFOLLOW,
        linux.STATX.BASIC_STATS,
        &statx,
    ))) {
        .SUCCESS => return .{
            .uid = statx.uid,
            .gid = statx.gid,
            .device_major = statx.rdev_major,
            .device_minor = statx.rdev_minor,
            .filesystem_device = (@as(u64, statx.dev_major) << 32) | statx.dev_minor,
        },
        .INTR => continue,
        else => return error.FilesystemMetadataUnavailable,
    };
}

fn systemMetadataRoot(dir: Io.Dir) !SystemMetadata {
    if (builtin.os.tag != .linux) return .{};
    const linux = std.os.linux;
    var statx = std.mem.zeroes(linux.Statx);
    while (true) switch (linux.errno(linux.statx(
        dir.handle,
        "",
        linux.AT.EMPTY_PATH | linux.AT.SYMLINK_NOFOLLOW,
        linux.STATX.BASIC_STATS,
        &statx,
    ))) {
        .SUCCESS => return .{
            .uid = statx.uid,
            .gid = statx.gid,
            .device_major = statx.rdev_major,
            .device_minor = statx.rdev_minor,
            .filesystem_device = (@as(u64, statx.dev_major) << 32) | statx.dev_minor,
        },
        .INTR => continue,
        else => return error.FilesystemMetadataUnavailable,
    };
}

fn snapshotKind(kind: Io.File.Kind) !Kind {
    return switch (kind) {
        .file => .file,
        .directory => .directory,
        .sym_link => .symlink,
        .named_pipe => .fifo,
        .character_device => .character_device,
        .block_device => .block_device,
        else => error.UnsupportedFilesystemEntry,
    };
}

fn hashFile(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    path: []const u8,
    expected_size: u64,
) ![]const u8 {
    var file = try dir.openFile(io, path, .{
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    var hasher = Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < expected_size) {
        const count = try file.readPositionalAll(
            io,
            buffer[0..@intCast(@min(buffer.len, expected_size - offset))],
            offset,
        );
        if (count == 0) return error.FileChangedDuringSnapshot;
        hasher.update(buffer[0..count]);
        offset += count;
    }
    var digest: [Sha256.digest_length]u8 = undefined;
    hasher.final(&digest);
    const hex = std.fmt.bytesToHex(digest, .lower);
    return try allocator.dupe(u8, &hex);
}

fn readLink(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    path: []const u8,
) ![]const u8 {
    const buffer = try allocator.alloc(u8, Io.Dir.max_path_bytes);
    const length = try dir.readLink(io, path, buffer);
    return buffer[0..length];
}

fn readXattrs(
    allocator: std.mem.Allocator,
    dir: Io.Dir,
    path: []const u8,
) ![]const Xattr {
    if (builtin.os.tag != .linux) return &.{};
    const proc_path = try std.fmt.allocPrintSentinel(
        allocator,
        "/proc/self/fd/{d}/{s}",
        .{ dir.handle, path },
        0,
    );
    const linux = std.os.linux;
    var empty: [1]u8 = undefined;
    const size_result = linux.llistxattr(proc_path.ptr, &empty, 0);
    if (linux.errno(size_result) != .SUCCESS) return error.ReadXattrFailed;
    if (size_result == 0) return &.{};
    if (size_result > 1024 * 1024) return error.XattrDataTooLarge;
    const names = try allocator.alloc(u8, size_result);
    const list_result = linux.llistxattr(proc_path.ptr, names.ptr, names.len);
    if (linux.errno(list_result) != .SUCCESS or list_result != names.len) {
        return error.ReadXattrFailed;
    }

    var values = std.array_list.Managed(Xattr).init(allocator);
    var offset: usize = 0;
    while (offset < names.len) {
        const end = std.mem.indexOfScalarPos(u8, names, offset, 0) orelse
            return error.ReadXattrFailed;
        if (end == offset) return error.ReadXattrFailed;
        const name = names[offset..end];
        const name_z = try allocator.dupeZ(u8, name);
        const value_size_result = linux.lgetxattr(proc_path.ptr, name_z.ptr, &empty, 0);
        if (linux.errno(value_size_result) != .SUCCESS or value_size_result > 1024 * 1024) {
            return error.ReadXattrFailed;
        }
        const value = try allocator.alloc(u8, value_size_result);
        if (value.len != 0) {
            const value_result = linux.lgetxattr(
                proc_path.ptr,
                name_z.ptr,
                value.ptr,
                value.len,
            );
            if (linux.errno(value_result) != .SUCCESS or value_result != value.len) {
                return error.ReadXattrFailed;
            }
        }
        const encoded = try allocator.alloc(
            u8,
            std.base64.standard.Encoder.calcSize(value.len),
        );
        _ = std.base64.standard.Encoder.encode(encoded, value);
        try values.append(.{
            .name = name_z[0..name_z.len],
            .value_base64 = encoded,
        });
        offset = end + 1;
    }
    std.mem.sort(Xattr, values.items, {}, xattrLessThan);
    return try values.toOwnedSlice();
}

fn timestamp(value: Io.Timestamp) Timestamp {
    const total = value.nanoseconds;
    const seconds = @divFloor(total, std.time.ns_per_s);
    return .{
        .seconds = std.math.cast(i64, seconds) orelse
            if (seconds < 0) std.math.minInt(i64) else std.math.maxInt(i64),
        .nanoseconds = @intCast(total - seconds * std.time.ns_per_s),
    };
}

fn optionalEqual(left: ?[]const u8, right: ?[]const u8) bool {
    if (left == null or right == null) return left == null and right == null;
    return std.mem.eql(u8, left.?, right.?);
}

fn xattrsEqual(left: []const Xattr, right: []const Xattr) bool {
    if (left.len != right.len) return false;
    for (left, right) |a, b| {
        if (!std.mem.eql(u8, a.name, b.name) or
            !std.mem.eql(u8, a.value_base64, b.value_base64)) return false;
    }
    return true;
}

fn xattrLessThan(_: void, left: Xattr, right: Xattr) bool {
    return std.mem.lessThan(u8, left.name, right.name);
}

fn lessThan(_: void, left: Entry, right: Entry) bool {
    return std.mem.lessThan(u8, left.path, right.path);
}

test "snapshot captures sorted content and symlink metadata" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const root_path = "test-oci-snapshot-root";
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    try Io.Dir.cwd().createDirPath(io, root_path ++ "/z");
    var root = try Io.Dir.cwd().openDir(io, root_path, .{ .iterate = true });
    defer root.close(io);
    try root.writeFile(io, .{ .sub_path = "z/file", .data = "payload" });
    try root.symLink(io, "z/file", "link", .{});

    var captured = try capture(allocator, io, root);
    defer captured.deinit();
    try std.testing.expectEqual(@as(usize, 4), captured.entries.len);
    try std.testing.expectEqualStrings("", captured.entries[0].path);
    try std.testing.expectEqualStrings("link", captured.entries[1].path);
    try std.testing.expectEqual(Kind.symlink, captured.entries[1].kind);
    try std.testing.expectEqualStrings("z/file", captured.entries[1].link_name.?);
    try std.testing.expectEqualStrings("z/file", captured.entries[3].path);
    try std.testing.expectEqualStrings(
        "239f59ed55e737c77147cf55ad0c1b030b6d7ee748a7426952f9b852d5a935e5",
        captured.entries[3].digest.?,
    );
}

test "snapshot equality detects broken hardlink topology" {
    const common = Entry{
        .path = "file",
        .kind = .file,
        .mode = 0o644,
        .mtime = .{ .seconds = 1, .nanoseconds = 2 },
        .size = 4,
        .digest = "abcd",
        .inode = 10,
        .nlink = 2,
        .filesystem_device = 1,
    };
    var broken = common;
    broken.inode = 11;
    broken.nlink = 1;
    try std.testing.expect(!Entry.same(common, broken));
}
