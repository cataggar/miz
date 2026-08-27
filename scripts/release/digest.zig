//! SHA-256 digests and file identity for the Zig release tooling.
//!
//! Every release document in this repository binds a file to a lowercase
//! SHA-256 hex digest, and every consumer re-derives that digest before
//! trusting the file. The Python scripts implement this as a streaming
//! `hashlib` loop plus `hexdigest()`; this module is the same contract with a
//! bound on the input size and a check that the file did not change between
//! the size decision and the last block hashed.

const std = @import("std");

const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const file_support = @import("file.zig");

pub const Identity = file_support.Identity;

pub const Digest = [Sha256.digest_length]u8;
pub const Hex = [Sha256.digest_length * 2]u8;

/// Block size of the streaming hash. Matches the 1 MiB chunk the Python
/// helpers read so large artifacts hash at the same order of syscall cost.
const block_bytes = 1024 * 1024;

pub const FileDigest = struct {
    digest: Digest,
    hex: Hex,
    size: u64,
    identity: Identity,
};

pub fn hashBytes(bytes: []const u8) Digest {
    var digest: Digest = undefined;
    Sha256.hash(bytes, &digest, .{});
    return digest;
}

pub fn hex(digest: Digest) Hex {
    return std.fmt.bytesToHex(digest, .lower);
}

pub fn hexBytes(bytes: []const u8) Hex {
    return hex(hashBytes(bytes));
}

pub const ParseError = error{InvalidSha256};

/// Accepts both the bare hex digest and the `sha256:`-prefixed spelling used
/// in OCI references, and rejects everything else including uppercase.
pub fn parseHex(text: []const u8) ParseError!Digest {
    const body = if (std.mem.startsWith(u8, text, "sha256:"))
        text["sha256:".len..]
    else
        text;
    if (body.len != Sha256.digest_length * 2) return error.InvalidSha256;
    for (body) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return error.InvalidSha256,
    };
    var digest: Digest = undefined;
    _ = std.fmt.hexToBytes(&digest, body) catch return error.InvalidSha256;
    return digest;
}

/// Streams `path` through SHA-256, refusing a file larger than `max_bytes` and
/// refusing a file that was replaced while it was being hashed.
pub fn hashFile(io: Io, path: []const u8, max_bytes: u64) !FileDigest {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer file.close(io);
    return hashOpenFile(io, file, max_bytes);
}

pub fn hashOpenFile(io: Io, file: File, max_bytes: u64) !FileDigest {
    const before = try file.stat(io);
    if (before.kind != .file) return error.NotRegularFile;
    if (before.size > max_bytes) return error.FileTooLarge;

    var hash = Sha256.init(.{});
    var buffer: [block_bytes]u8 = undefined;
    var offset: u64 = 0;
    while (offset < before.size) {
        const length: usize = @intCast(@min(before.size - offset, buffer.len));
        if (try file.readPositionalAll(io, buffer[0..length], offset) != length) {
            return error.ShortRead;
        }
        hash.update(buffer[0..length]);
        offset += length;
    }

    const after = try file.stat(io);
    const identity = Identity.of(before);
    if (!identity.eql(Identity.of(after))) return error.FileChangedDuringRead;

    var digest: Digest = undefined;
    hash.final(&digest);
    return .{
        .digest = digest,
        .hex = hex(digest),
        .size = before.size,
        .identity = identity,
    };
}

test "hashBytes matches the published empty and short-input vectors" {
    try std.testing.expectEqualStrings(
        "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        &hexBytes(""),
    );
    try std.testing.expectEqualStrings(
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
        &hexBytes("abc"),
    );
}

test "parseHex accepts canonical spellings and rejects the rest" {
    const expected = hashBytes("abc");
    try std.testing.expectEqualSlices(
        u8,
        &expected,
        &try parseHex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );
    try std.testing.expectEqualSlices(
        u8,
        &expected,
        &try parseHex("sha256:ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"),
    );
    try std.testing.expectError(
        error.InvalidSha256,
        parseHex("BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"),
    );
    try std.testing.expectError(error.InvalidSha256, parseHex(""));
    try std.testing.expectError(error.InvalidSha256, parseHex("ab"));
}

test "hashFile streams past the block size and enforces the bound" {
    const io = std.testing.io;
    const path = "test-release-digest.bin";
    defer Dir.cwd().deleteFile(io, path) catch {};

    const size = block_bytes + 4096;
    const data = try std.testing.allocator.alloc(u8, size);
    defer std.testing.allocator.free(data);
    for (data, 0..) |*byte, index| byte.* = @truncate(index * 7 + 3);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });

    const result = try hashFile(io, path, size);
    try std.testing.expectEqual(@as(u64, size), result.size);
    try std.testing.expectEqualStrings(&hexBytes(data), &result.hex);

    try std.testing.expectError(
        error.FileTooLarge,
        hashFile(io, path, size - 1),
    );
}

test "hashFile rejects a missing file and a directory" {
    const io = std.testing.io;
    try std.testing.expectError(
        error.FileNotFound,
        hashFile(io, "test-release-digest-absent.bin", 1024),
    );

    const directory = "test-release-digest-directory";
    Dir.cwd().deleteTree(io, directory) catch {};
    try Dir.cwd().createDirPath(io, directory);
    defer Dir.cwd().deleteTree(io, directory) catch {};
    try std.testing.expectError(
        error.IsDir,
        hashFile(io, directory, 1024),
    );
}
