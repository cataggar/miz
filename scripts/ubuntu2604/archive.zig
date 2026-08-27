//! Archive readers for the external Android container smoke inputs.
//!
//! Both archives arrive from outside this repository, so both are read
//! defensively and to an exact contract rather than "extracted".
//!
//! The ZIP reader works from the central directory, which is what decides
//! which members a consumer sees, and enforces the member set, the absence of
//! encryption, and a regular-file mode before a single byte is written. The
//! tar reader never extracts at all: it locates exactly one `config.json`
//! entry and streams it through SHA-256 within its declared size.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const ZipError = error{
    MalformedArchive,
    MemberSetMismatch,
    UnsafeMember,
    ExtractionFailed,
};

const eocd_signature: u32 = 0x0605_4b50;
const central_signature: u32 = 0x0201_4b50;
const local_signature: u32 = 0x0403_4b50;
const eocd_size: usize = 22;
const central_entry_size: usize = 46;
const local_header_size: usize = 30;
/// A member name longer than this is not something this repository produces
/// and is rejected before any allocation follows from it.
const max_name_len: usize = 4096;
/// The ZIP comment field is a 16-bit length, so the end-of-directory record
/// can never start further back than this.
const max_eocd_search: usize = eocd_size + 65535;

/// The subset of a central-directory record the extraction contract needs.
pub const Member = struct {
    name: []const u8,
    flags: u16,
    method: u16,
    compressed_size: u64,
    uncompressed_size: u64,
    external_attributes: u32,
    local_offset: u64,

    /// `ZipInfo.is_dir()`.
    pub fn isDirectory(self: Member) bool {
        return std.mem.endsWith(u8, self.name, "/");
    }

    /// General purpose bit 0: the member is encrypted.
    pub fn isEncrypted(self: Member) bool {
        return self.flags & 0x1 != 0;
    }

    /// `stat.S_IFMT((external_attr >> 16) & 0xFFFF)`. A zero file type is the
    /// spelling a non-Unix producer writes, and is the only other value the
    /// Python accepted.
    pub fn fileType(self: Member) u16 {
        const mode: u16 = @truncate(self.external_attributes >> 16);
        return mode & 0xF000;
    }

    pub fn isRegular(self: Member) bool {
        const file_type = self.fileType();
        return file_type == 0 or file_type == 0x8000;
    }
};

pub const Directory = struct {
    members: []Member,
    names: []u8,

    pub fn deinit(self: *Directory, allocator: Allocator) void {
        allocator.free(self.members);
        allocator.free(self.names);
        self.* = undefined;
    }
};

fn readU16(bytes: []const u8, offset: usize) u16 {
    return std.mem.readInt(u16, bytes[offset..][0..2], .little);
}

fn readU32(bytes: []const u8, offset: usize) u32 {
    return std.mem.readInt(u32, bytes[offset..][0..4], .little);
}

/// Reads the central directory of `path`.
pub fn readDirectory(
    allocator: Allocator,
    io: Io,
    path: []const u8,
) !Directory {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer file.close(io);
    const stat = try file.stat(io);
    if (stat.kind != .file) return error.MalformedArchive;
    if (stat.size < eocd_size) return error.MalformedArchive;

    const tail_length: usize = @intCast(@min(stat.size, max_eocd_search));
    const tail = try allocator.alloc(u8, tail_length);
    defer allocator.free(tail);
    const tail_offset = stat.size - tail_length;
    if (try file.readPositionalAll(io, tail, tail_offset) != tail_length) {
        return error.MalformedArchive;
    }

    var eocd_index: ?usize = null;
    var scan = tail_length - eocd_size + 1;
    while (scan > 0) {
        scan -= 1;
        if (readU32(tail, scan) != eocd_signature) continue;
        const comment_length = readU16(tail, scan + 20);
        if (scan + eocd_size + comment_length != tail_length) continue;
        eocd_index = scan;
        break;
    }
    const eocd = tail[eocd_index orelse return error.MalformedArchive ..];

    const total_entries = readU16(eocd, 10);
    if (readU16(eocd, 4) != 0 or readU16(eocd, 6) != 0 or
        readU16(eocd, 8) != total_entries)
    {
        return error.MalformedArchive;
    }
    const directory_size = readU32(eocd, 12);
    const directory_offset = readU32(eocd, 16);
    if (directory_offset == 0xFFFF_FFFF or directory_size == 0xFFFF_FFFF or
        total_entries == 0xFFFF)
    {
        // Zip64 is not something this pipeline produces; refusing it keeps the
        // reader from guessing at sizes it cannot see.
        return error.MalformedArchive;
    }
    if (@as(u64, directory_offset) + directory_size > stat.size) {
        return error.MalformedArchive;
    }

    const directory = try allocator.alloc(u8, directory_size);
    defer allocator.free(directory);
    if (try file.readPositionalAll(io, directory, directory_offset) != directory_size) {
        return error.MalformedArchive;
    }

    const members = try allocator.alloc(Member, total_entries);
    errdefer allocator.free(members);
    var names: std.ArrayList(u8) = .empty;
    errdefer names.deinit(allocator);

    // Names are collected into one buffer and pointed at afterwards, so a
    // growing list never leaves a member holding a stale slice.
    const name_ranges = try allocator.alloc([2]usize, total_entries);
    defer allocator.free(name_ranges);

    var cursor: usize = 0;
    for (members, name_ranges) |*member, *range| {
        if (cursor + central_entry_size > directory.len) return error.MalformedArchive;
        const record = directory[cursor..];
        if (readU32(record, 0) != central_signature) return error.MalformedArchive;
        const name_length = readU16(record, 28);
        const extra_length = readU16(record, 30);
        const comment_length = readU16(record, 32);
        if (name_length == 0 or name_length > max_name_len) {
            return error.MalformedArchive;
        }
        const total = central_entry_size + @as(usize, name_length) +
            extra_length + comment_length;
        if (cursor + total > directory.len) return error.MalformedArchive;
        const name = record[central_entry_size..][0..name_length];
        range.* = .{ names.items.len, names.items.len + name_length };
        try names.appendSlice(allocator, name);
        member.* = .{
            .name = &.{},
            .flags = readU16(record, 8),
            .method = readU16(record, 10),
            .compressed_size = readU32(record, 20),
            .uncompressed_size = readU32(record, 24),
            .external_attributes = readU32(record, 38),
            .local_offset = readU32(record, 42),
        };
        if (member.compressed_size == 0xFFFF_FFFF or
            member.uncompressed_size == 0xFFFF_FFFF or
            member.local_offset == 0xFFFF_FFFF)
        {
            return error.MalformedArchive;
        }
        if (member.local_offset + local_header_size > stat.size) {
            return error.MalformedArchive;
        }
        cursor += total;
    }
    if (cursor != directory.len) return error.MalformedArchive;

    const owned_names = try names.toOwnedSlice(allocator);
    errdefer allocator.free(owned_names);
    for (members, name_ranges) |*member, range| {
        member.name = owned_names[range[0]..range[1]];
    }
    return .{ .members = members, .names = owned_names };
}

/// Extracts one member into `destination`, which must not already exist and is
/// created with mode 0600.
pub fn extractMember(
    io: Io,
    archive_path: []const u8,
    member: Member,
    destination: []const u8,
) !void {
    const source = try Dir.cwd().openFile(io, archive_path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer source.close(io);

    var header: [local_header_size]u8 = undefined;
    if (try source.readPositionalAll(io, &header, member.local_offset) !=
        local_header_size)
    {
        return error.MalformedArchive;
    }
    if (readU32(&header, 0) != local_signature) return error.MalformedArchive;
    const name_length = readU16(&header, 26);
    const extra_length = readU16(&header, 28);
    const data_offset = member.local_offset + local_header_size +
        name_length + extra_length;

    const output = try Dir.cwd().createFile(io, destination, .{
        .exclusive = true,
        .permissions = .fromMode(0o600),
    });
    defer output.close(io);

    var read_buffer: [64 * 1024]u8 = undefined;
    var reader: File.Reader = .init(source, io, &read_buffer);
    try reader.seekTo(data_offset);
    var limited_buffer: [64 * 1024]u8 = undefined;
    var limited = reader.interface.limited(
        .limited64(member.compressed_size),
        &limited_buffer,
    );

    var write_buffer: [64 * 1024]u8 = undefined;
    var writer: File.Writer = .init(output, io, &write_buffer);

    const written = switch (member.method) {
        0 => blk: {
            if (member.compressed_size != member.uncompressed_size) {
                return error.MalformedArchive;
            }
            break :blk try limited.interface.streamRemaining(&writer.interface);
        },
        8 => blk: {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decompress: std.compress.flate.Decompress = .init(
                &limited.interface,
                .raw,
                &window,
            );
            break :blk try decompress.reader.streamRemaining(&writer.interface);
        },
        // Only stored and deflate are produced by any tool this pipeline uses;
        // anything else is refused rather than guessed at.
        else => return error.MalformedArchive,
    };
    try writer.interface.flush();
    if (written != member.uncompressed_size) return error.MalformedArchive;
}

pub const TarError = error{
    MalformedArchive,
    InvalidConfigEntry,
    TruncatedConfigEntry,
};

pub const ConfigDigest = struct {
    hex: [Sha256.digest_length * 2]u8,
};

/// `_android_bundle_config_sha256`: exactly one regular `config.json` member,
/// no larger than `max_bytes`, hashed within its declared size.
pub fn bundleConfigDigest(
    io: Io,
    path: []const u8,
    max_bytes: u64,
) !ConfigDigest {
    const file = try Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = true,
    });
    defer file.close(io);

    var read_buffer: [64 * 1024]u8 = undefined;
    var reader: File.Reader = .init(file, io, &read_buffer);
    var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var iterator: std.tar.Iterator = .init(&reader.interface, .{
        .file_name_buffer = &name_buffer,
        .link_name_buffer = &link_buffer,
    });

    var matches: usize = 0;
    var digest: [Sha256.digest_length]u8 = undefined;
    while (iterator.next() catch return error.MalformedArchive) |entry| {
        const name = if (std.mem.startsWith(u8, entry.name, "./"))
            entry.name[2..]
        else
            entry.name;
        if (!std.mem.eql(u8, name, "config.json")) continue;
        matches += 1;
        if (matches > 1) return error.InvalidConfigEntry;
        if (entry.kind != .file or entry.size > max_bytes) {
            return error.InvalidConfigEntry;
        }
        // The declared size bounds the read, so a header that claims more
        // content than the archive holds is a truncation rather than a short
        // digest over whatever happened to follow.
        var hash = Sha256.init(.{});
        var block: [64 * 1024]u8 = undefined;
        var remaining = entry.size;
        while (remaining > 0) {
            const length: usize = @intCast(@min(remaining, block.len));
            iterator.reader.readSliceAll(block[0..length]) catch
                return error.TruncatedConfigEntry;
            hash.update(block[0..length]);
            remaining -= length;
        }
        iterator.unread_file_bytes = 0;
        hash.final(&digest);
    }
    if (matches != 1) return error.InvalidConfigEntry;
    return .{ .hex = std.fmt.bytesToHex(digest, .lower) };
}

const TempTree = @import("../release/testing.zig").TempTree;

/// Builds a single-entry stored ZIP in memory, so the reader's contract can be
/// exercised without a fixture file in the tree.
fn buildZip(
    allocator: Allocator,
    entries: []const struct {
        name: []const u8,
        data: []const u8,
        external_attributes: u32 = 0o100644 << 16,
        flags: u16 = 0,
    },
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    const offsets = try allocator.alloc(u32, entries.len);
    defer allocator.free(offsets);

    for (entries, offsets) |entry, *offset| {
        offset.* = @intCast(out.items.len);
        var header: [local_header_size]u8 = @splat(0);
        std.mem.writeInt(u32, header[0..4], local_signature, .little);
        std.mem.writeInt(u16, header[6..8], entry.flags, .little);
        std.mem.writeInt(u32, header[14..18], std.hash.Crc32.hash(entry.data), .little);
        std.mem.writeInt(u32, header[18..22], @intCast(entry.data.len), .little);
        std.mem.writeInt(u32, header[22..26], @intCast(entry.data.len), .little);
        std.mem.writeInt(u16, header[26..28], @intCast(entry.name.len), .little);
        try out.appendSlice(allocator, &header);
        try out.appendSlice(allocator, entry.name);
        try out.appendSlice(allocator, entry.data);
    }

    const directory_offset = out.items.len;
    for (entries, offsets) |entry, offset| {
        var record: [central_entry_size]u8 = @splat(0);
        std.mem.writeInt(u32, record[0..4], central_signature, .little);
        std.mem.writeInt(u16, record[8..10], entry.flags, .little);
        std.mem.writeInt(u32, record[16..20], std.hash.Crc32.hash(entry.data), .little);
        std.mem.writeInt(u32, record[20..24], @intCast(entry.data.len), .little);
        std.mem.writeInt(u32, record[24..28], @intCast(entry.data.len), .little);
        std.mem.writeInt(u16, record[28..30], @intCast(entry.name.len), .little);
        std.mem.writeInt(u32, record[38..42], entry.external_attributes, .little);
        std.mem.writeInt(u32, record[42..46], offset, .little);
        try out.appendSlice(allocator, &record);
        try out.appendSlice(allocator, entry.name);
    }
    const directory_size = out.items.len - directory_offset;

    var eocd: [eocd_size]u8 = @splat(0);
    std.mem.writeInt(u32, eocd[0..4], eocd_signature, .little);
    std.mem.writeInt(u16, eocd[8..10], @intCast(entries.len), .little);
    std.mem.writeInt(u16, eocd[10..12], @intCast(entries.len), .little);
    std.mem.writeInt(u32, eocd[12..16], @intCast(directory_size), .little);
    std.mem.writeInt(u32, eocd[16..20], @intCast(directory_offset), .little);
    try out.appendSlice(allocator, &eocd);
    return out.toOwnedSlice(allocator);
}

test "readDirectory reports member names, modes, and flags" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var path_buffer: [TempTree.max_path_len]u8 = undefined;
    const path = tree.path(&path_buffer, "archive.zip");

    const bytes = try buildZip(std.testing.allocator, &.{
        .{ .name = "provenance.json", .data = "{}" },
        .{ .name = "nested/", .data = "", .external_attributes = 0o40755 << 16 },
        .{ .name = "encrypted", .data = "x", .flags = 0x1 },
    });
    defer std.testing.allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });

    var directory = try readDirectory(std.testing.allocator, io, path);
    defer directory.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 3), directory.members.len);
    try std.testing.expectEqualStrings("provenance.json", directory.members[0].name);
    try std.testing.expect(directory.members[0].isRegular());
    try std.testing.expect(!directory.members[0].isDirectory());
    try std.testing.expect(!directory.members[0].isEncrypted());
    try std.testing.expect(directory.members[1].isDirectory());
    try std.testing.expect(!directory.members[1].isRegular());
    try std.testing.expect(directory.members[2].isEncrypted());
}

test "extractMember writes stored content with a private mode" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var path_buffer: [TempTree.max_path_len]u8 = undefined;
    const path = tree.path(&path_buffer, "stored.zip");
    var output_buffer: [TempTree.max_path_len]u8 = undefined;
    const output = tree.path(&output_buffer, "extracted.bin");

    const bytes = try buildZip(std.testing.allocator, &.{
        .{ .name = "android-runtime", .data = "runtime bytes" },
    });
    defer std.testing.allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });

    var directory = try readDirectory(std.testing.allocator, io, path);
    defer directory.deinit(std.testing.allocator);
    try extractMember(io, path, directory.members[0], output);

    const extracted = try Dir.cwd().readFileAlloc(
        io,
        output,
        std.testing.allocator,
        .limited(1024),
    );
    defer std.testing.allocator.free(extracted);
    try std.testing.expectEqualStrings("runtime bytes", extracted);
    const stat = try Dir.cwd().statFile(io, output, .{});
    try std.testing.expectEqual(@as(std.posix.mode_t, 0o600), stat.permissions.toMode() & 0o777);

    // A destination that already exists is never overwritten.
    try std.testing.expectError(
        error.PathAlreadyExists,
        extractMember(io, path, directory.members[0], output),
    );
}

test "a truncated or signature-free archive is malformed" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var path_buffer: [TempTree.max_path_len]u8 = undefined;
    const path = tree.path(&path_buffer, "broken.zip");

    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "not a zip" });
    try std.testing.expectError(
        error.MalformedArchive,
        readDirectory(std.testing.allocator, io, path),
    );

    const bytes = try buildZip(std.testing.allocator, &.{
        .{ .name = "provenance.json", .data = "{}" },
    });
    defer std.testing.allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes[0 .. bytes.len - 4],
    });
    try std.testing.expectError(
        error.MalformedArchive,
        readDirectory(std.testing.allocator, io, path),
    );
}

fn buildTar(
    allocator: Allocator,
    entries: []const struct { name: []const u8, data: []const u8, kind: u8 = '0' },
) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (entries) |entry| {
        var header: [512]u8 = @splat(0);
        @memcpy(header[0..entry.name.len], entry.name);
        _ = try std.fmt.bufPrint(header[100..108], "0000644\x00", .{});
        _ = try std.fmt.bufPrint(header[108..116], "0000000\x00", .{});
        _ = try std.fmt.bufPrint(header[116..124], "0000000\x00", .{});
        _ = try std.fmt.bufPrint(header[124..136], "{o:0>11} ", .{entry.data.len});
        _ = try std.fmt.bufPrint(header[136..148], "{o:0>11} ", .{@as(u64, 0)});
        @memset(header[148..156], ' ');
        header[156] = entry.kind;
        @memcpy(header[257..262], "ustar");
        @memcpy(header[263..265], "00");
        var checksum: u32 = 0;
        for (header) |byte| checksum += byte;
        _ = try std.fmt.bufPrint(header[148..156], "{o:0>6}\x00 ", .{checksum});
        try out.appendSlice(allocator, &header);
        try out.appendSlice(allocator, entry.data);
        const padding = (512 - (entry.data.len % 512)) % 512;
        try out.appendNTimes(allocator, 0, padding);
    }
    try out.appendNTimes(allocator, 0, 1024);
    return out.toOwnedSlice(allocator);
}

test "bundleConfigDigest hashes exactly one config.json entry" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var path_buffer: [TempTree.max_path_len]u8 = undefined;
    const path = tree.path(&path_buffer, "bundle.tar");

    const bytes = try buildTar(std.testing.allocator, &.{
        .{ .name = "rootfs/init", .data = "binary" },
        .{ .name = "./config.json", .data = "{\"ociVersion\": \"1.0.0\"}" },
    });
    defer std.testing.allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });

    const digest = try bundleConfigDigest(io, path, 1024 * 1024);
    var expected: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("{\"ociVersion\": \"1.0.0\"}", &expected, .{});
    try std.testing.expectEqualStrings(
        &std.fmt.bytesToHex(expected, .lower),
        &digest.hex,
    );

    try std.testing.expectError(
        error.InvalidConfigEntry,
        bundleConfigDigest(io, path, 4),
    );
}

test "a bundle without exactly one config.json is refused" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();

    var missing_buffer: [TempTree.max_path_len]u8 = undefined;
    const missing = tree.path(&missing_buffer, "missing.tar");
    const without = try buildTar(std.testing.allocator, &.{
        .{ .name = "rootfs/init", .data = "binary" },
    });
    defer std.testing.allocator.free(without);
    try Dir.cwd().writeFile(io, .{ .sub_path = missing, .data = without });
    try std.testing.expectError(
        error.InvalidConfigEntry,
        bundleConfigDigest(io, missing, 1024),
    );

    var duplicate_buffer: [TempTree.max_path_len]u8 = undefined;
    const duplicate = tree.path(&duplicate_buffer, "duplicate.tar");
    const twice = try buildTar(std.testing.allocator, &.{
        .{ .name = "config.json", .data = "{}" },
        .{ .name = "./config.json", .data = "{}" },
    });
    defer std.testing.allocator.free(twice);
    try Dir.cwd().writeFile(io, .{ .sub_path = duplicate, .data = twice });
    try std.testing.expectError(
        error.InvalidConfigEntry,
        bundleConfigDigest(io, duplicate, 1024),
    );
}
