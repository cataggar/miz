//! Bounded file reads and atomic output staging for the Zig release tooling.
//!
//! Release tooling reads attacker-influenced files (build metadata, provenance
//! documents, downloaded artifacts) and writes files that other jobs consume.
//! Both directions have exactly one correct shape: reads are bounded and
//! re-checked for concurrent replacement, and writes land through an
//! unnamed-then-renamed stage so no consumer ever sees a partial document.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;

/// Failures this module adds on top of the underlying I/O errors.
pub const ReadError = error{
    NotRegularFile,
    FileTooLarge,
    FileTooSmall,
    FileChangedDuringRead,
    ShortRead,
};

/// Snapshot of the metadata that identifies a specific file revision. Two
/// snapshots that compare equal mean nothing observable about the file changed
/// between the two `stat` calls that produced them.
pub const Identity = struct {
    inode: File.INode,
    nlink: File.NLink,
    size: u64,
    mtime_nanoseconds: i96,
    ctime_nanoseconds: i96,

    pub fn of(stat: File.Stat) Identity {
        return .{
            .inode = stat.inode,
            .nlink = stat.nlink,
            .size = stat.size,
            .mtime_nanoseconds = stat.mtime.nanoseconds,
            .ctime_nanoseconds = stat.ctime.nanoseconds,
        };
    }

    pub fn eql(self: Identity, other: Identity) bool {
        return self.inode == other.inode and
            self.nlink == other.nlink and
            self.size == other.size and
            self.mtime_nanoseconds == other.mtime_nanoseconds and
            self.ctime_nanoseconds == other.ctime_nanoseconds;
    }
};

pub const Contents = struct {
    bytes: []u8,
    identity: Identity,

    pub fn deinit(self: *Contents, allocator: Allocator) void {
        allocator.free(self.bytes);
        self.* = undefined;
    }
};

/// Reads all of `path`, refusing anything larger than `max_bytes` before any
/// memory is committed, and refusing a file that was replaced mid-read.
pub fn readBounded(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    max_bytes: u64,
) ![]u8 {
    const contents = try readBoundedIdentified(allocator, io, path, max_bytes);
    return contents.bytes;
}

/// `readBounded` plus the file identity the bytes were read from, for callers
/// that must later prove they acted on the same revision.
pub fn readBoundedIdentified(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    max_bytes: u64,
) !Contents {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer file.close(io);

    const before = try file.stat(io);
    if (before.kind != .file) return error.NotRegularFile;
    if (before.size > max_bytes) return error.FileTooLarge;

    const length = std.math.cast(usize, before.size) orelse
        return error.FileTooLarge;
    const bytes = try allocator.alloc(u8, length);
    errdefer allocator.free(bytes);
    if (try file.readPositionalAll(io, bytes, 0) != length) {
        return error.ShortRead;
    }

    const after = try file.stat(io);
    const identity = Identity.of(before);
    if (!identity.eql(Identity.of(after))) return error.FileChangedDuringRead;
    return .{ .bytes = bytes, .identity = identity };
}

/// Reads the trailing `buffer.len` bytes of `path`. Fixed-size trailers (a VHD
/// footer, a backup GPT) are the one case where a whole-file read is both
/// unnecessary and unbounded, so they get a dedicated bounded path.
pub fn readTrailer(io: Io, path: []const u8, buffer: []u8) !Identity {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer file.close(io);

    const before = try file.stat(io);
    if (before.kind != .file) return error.NotRegularFile;
    if (before.size < buffer.len) return error.FileTooSmall;

    const offset = before.size - buffer.len;
    if (try file.readPositionalAll(io, buffer, offset) != buffer.len) {
        return error.ShortRead;
    }

    const after = try file.stat(io);
    const identity = Identity.of(before);
    if (!identity.eql(Identity.of(after))) return error.FileChangedDuringRead;
    return identity;
}

/// Size of a regular file, rejecting anything that is not one.
pub fn regularFileSize(io: Io, path: []const u8) !u64 {
    const stat = try Dir.cwd().statFile(io, path, .{});
    if (stat.kind != .file) return error.NotRegularFile;
    return stat.size;
}

/// Replaces `path` with `data` atomically, creating parent directories the way
/// the Python `write_json` helper does. Consumers see either the previous file
/// or the complete new one, never a truncated document.
pub fn writeAtomic(io: Io, path: []const u8, data: []const u8) !void {
    var stage = try Dir.cwd().createFileAtomic(io, path, .{
        .replace = true,
        .make_path = true,
    });
    defer stage.deinit(io);
    try stage.file.writeStreamingAll(io, data);
    try stage.replace(io);
}

test "readBounded refuses a file above the limit before allocating" {
    const io = std.testing.io;
    const path = "test-release-file-bounded.bin";
    defer Dir.cwd().deleteFile(io, path) catch {};
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "0123456789" });

    try std.testing.expectError(
        error.FileTooLarge,
        readBounded(std.testing.allocator, io, path, 9),
    );

    const exact = try readBounded(std.testing.allocator, io, path, 10);
    defer std.testing.allocator.free(exact);
    try std.testing.expectEqualStrings("0123456789", exact);
}

test "readBounded rejects a directory and a missing path" {
    const io = std.testing.io;
    const directory = "test-release-file-directory";
    Dir.cwd().deleteTree(io, directory) catch {};
    try Dir.cwd().createDirPath(io, directory);
    defer Dir.cwd().deleteTree(io, directory) catch {};

    try std.testing.expectError(
        error.IsDir,
        readBounded(std.testing.allocator, io, directory, 1024),
    );
    try std.testing.expectError(
        error.FileNotFound,
        readBounded(std.testing.allocator, io, "test-release-file-absent", 1024),
    );
}

test "readTrailer returns only the trailing window" {
    const io = std.testing.io;
    const path = "test-release-file-trailer.bin";
    defer Dir.cwd().deleteFile(io, path) catch {};
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "headertrailer" });

    var buffer: [7]u8 = undefined;
    const identity = try readTrailer(io, path, &buffer);
    try std.testing.expectEqualStrings("trailer", &buffer);
    try std.testing.expectEqual(@as(u64, 13), identity.size);

    var oversized: [64]u8 = undefined;
    try std.testing.expectError(
        error.FileTooSmall,
        readTrailer(io, path, &oversized),
    );
}

test "writeAtomic creates parents and replaces existing content" {
    const io = std.testing.io;
    const root = "test-release-file-atomic";
    Dir.cwd().deleteTree(io, root) catch {};
    defer Dir.cwd().deleteTree(io, root) catch {};

    const path = root ++ "/nested/document.json";
    try writeAtomic(io, path, "first\n");
    const first = try readBounded(std.testing.allocator, io, path, 1024);
    defer std.testing.allocator.free(first);
    try std.testing.expectEqualStrings("first\n", first);

    try writeAtomic(io, path, "second\n");
    const second = try readBounded(std.testing.allocator, io, path, 1024);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualStrings("second\n", second);

    // No stage file is left behind next to the destination.
    var directory = try Dir.cwd().openDir(io, root ++ "/nested", .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    var entries: usize = 0;
    while (try iterator.next(io)) |entry| {
        entries += 1;
        try std.testing.expectEqualStrings("document.json", entry.name);
    }
    try std.testing.expectEqual(@as(usize, 1), entries);
}

test "regularFileSize reports the size and rejects directories" {
    const io = std.testing.io;
    const path = "test-release-file-size.bin";
    defer Dir.cwd().deleteFile(io, path) catch {};
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "abcd" });
    try std.testing.expectEqual(@as(u64, 4), try regularFileSize(io, path));

    const directory = "test-release-file-size-directory";
    Dir.cwd().deleteTree(io, directory) catch {};
    try Dir.cwd().createDirPath(io, directory);
    defer Dir.cwd().deleteTree(io, directory) catch {};
    try std.testing.expectError(
        error.NotRegularFile,
        regularFileSize(io, directory),
    );
}
