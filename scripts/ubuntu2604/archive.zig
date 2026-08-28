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
const bzip2 = @import("bzip2z");

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

/// The container `tarfile.open(mode="r:*")` picks by sniffing the leading
/// bytes. The producer of the Android bundle is external and its `.tar` name
/// says nothing about whether it is compressed, so the same set is recognised
/// here rather than assuming an uncompressed stream and hashing whatever a
/// compressed header happened to decode to.
pub const Compression = enum { none, gzip, bzip2, xz, zstd };

fn detectCompression(reader: *std.Io.Reader) Compression {
    // A short archive cannot be any of the compressed containers, and the tar
    // reader is the one that gets to reject it.
    const prefix = reader.peek(6) catch return .none;
    if (std.mem.startsWith(u8, prefix, "\x1f\x8b")) return .gzip;
    if (std.mem.startsWith(u8, prefix, "BZh")) return .bzip2;
    if (std.mem.startsWith(u8, prefix, "\xfd7zXZ\x00")) return .xz;
    if (std.mem.startsWith(u8, prefix, "\x28\xb5\x2f\xfd")) return .zstd;
    return .none;
}

/// `_android_bundle_config_sha256`: exactly one regular `config.json` member,
/// no larger than `max_bytes`, hashed within its declared size. The bundle may
/// be a plain tar or any container `tarfile`'s `r:*` mode accepts.
pub fn bundleConfigDigest(
    allocator: Allocator,
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
    switch (detectCompression(&reader.interface)) {
        .none => return scanTar(&reader.interface, max_bytes),
        .gzip => {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decompress: std.compress.flate.Decompress = .init(
                &reader.interface,
                .gzip,
                &window,
            );
            return scanTar(&decompress.reader, max_bytes);
        },
        .xz => {
            // `Decompress` takes ownership of this buffer and resizes it, so
            // it is freed by `deinit` rather than here.
            const window = try allocator.alloc(u8, 1 << 20);
            var decompress = std.compress.xz.Decompress.init(
                &reader.interface,
                allocator,
                window,
            ) catch {
                allocator.free(window);
                return error.MalformedArchive;
            };
            defer decompress.deinit();
            return scanTar(&decompress.reader, max_bytes);
        },
        .zstd => {
            const window_len = std.compress.zstd.default_window_len;
            const window = try allocator.alloc(
                u8,
                window_len + std.compress.zstd.block_size_max,
            );
            defer allocator.free(window);
            var decompress: std.compress.zstd.Decompress = .init(
                &reader.interface,
                window,
                .{ .window_len = window_len },
            );
            return scanTar(&decompress.reader, max_bytes);
        },
        // bzip2 has no streaming decoder here, so the archive is decoded whole
        // under an explicit bound rather than left unreadable. The bound is the
        // same one the download path applies to the artifact it came from.
        .bzip2 => {
            const compressed = try reader.interface.allocRemaining(
                allocator,
                .limited(max_compressed_bundle_bytes),
            );
            defer allocator.free(compressed);
            const plain = bzip2.core.decompress(allocator, compressed, .{
                .max_output_bytes = max_inflated_bundle_bytes,
            }) catch return error.MalformedArchive;
            defer allocator.free(plain);
            var plain_reader: std.Io.Reader = .fixed(plain);
            return scanTar(&plain_reader, max_bytes);
        },
    }
}

/// The compressed bundle is bounded by what the download path would accept,
/// and its inflated form by the largest container rootfs this pipeline has a
/// use for. Both exist so a hostile archive cannot turn a digest check into an
/// out-of-memory abort.
const max_compressed_bundle_bytes: usize = 2 * 1024 * 1024 * 1024;
const max_inflated_bundle_bytes: usize = 8 * 1024 * 1024 * 1024;

fn scanTar(reader: *std.Io.Reader, max_bytes: u64) !ConfigDigest {
    var name_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var link_buffer: [std.fs.max_path_bytes]u8 = undefined;
    var iterator: std.tar.Iterator = .init(reader, .{
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

    const digest = try bundleConfigDigest(std.testing.allocator, io, path, 1024 * 1024);
    var expected: [Sha256.digest_length]u8 = undefined;
    Sha256.hash("{\"ociVersion\": \"1.0.0\"}", &expected, .{});
    try std.testing.expectEqualStrings(
        &std.fmt.bytesToHex(expected, .lower),
        &digest.hex,
    );

    try std.testing.expectError(
        error.InvalidConfigEntry,
        bundleConfigDigest(std.testing.allocator, io, path, 4),
    );
}

// The producer of the Android bundle is outside this repository, so the
// fixtures below are the bytes an external `tarfile`/`gzip`/`bzip2`/`xz`/`zstd`
// producer actually emits for one tar rather than something this file
// compressed itself: the claim under test is interoperability, not round-trip.

/// The same tar, gzip-compressed by an external producer.
const gzip_bundle =
    "\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff\xed\xd3" ++
    "\x31\x0e\xc2\x30\x0c\x85\xe1\x1c\xa5\xca\x01\xd2" ++
    "\xa4\x44\x20\x71\x10\xf6\x52\x51\x64\x86\x58\x4a" ++
    "\xca\x80\x10\x77\x27\x30\xa1\xee\x14\xa1\xfe\xdf" ++
    "\xf2\x2c\x7b\xf0\xf4\xb2\xea\x34\x96\x56\x92\x4c" ++
    "\xe6\x5b\x7c\xb5\x8d\xf1\x9d\xd5\x3c\x5f\xd7\x8f" ++
    "\xb9\xee\x83\x0f\x71\x63\x1a\x6f\x16\x70\x2d\x53" ++
    "\x9f\xeb\x7b\xb3\x4e\x47\x49\x7d\xbe\x19\xac\x94" ++
    "\x6b\x07\x4d\xa3\x9c\xdd\xa5\x68\xfa\x55\xff\xbb" ++
    "\xdd\xbc\xff\x5d\x0c\xf4\x7f\x09\x77\xab\x83\x1c" ++
    "\x4e\xb9\x88\x26\xbb\x6f\x6c\x70\xde\x79\xfb\xa0" ++
    "\x18\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" ++
    "\x00\x7f\xe2\x09\xea\x0c\x0b\x97\x00\x28\x00\x00";

/// The same tar, bzip2-compressed.
const bzip2_bundle =
    "\x42\x5a\x68\x39\x31\x41\x59\x26\x53\x59\x5d\x07" ++
    "\x3f\xc1\x00\x00\x9e\x5b\x80\xcb\x80\x50\x01\xfd" ++
    "\x90\x0b\x00\x7b\xb1\x9e\x2a\x08\x88\x20\x00\x92" ++
    "\x88\xa6\x4d\xa9\x84\x68\x00\x06\x9a\x0c\x10\x49" ++
    "\x2a\x7a\x9e\x53\xd2\x32\x3d\x27\xa4\x32\x64\x0d" ++
    "\x0f\x53\x4d\x3b\xe7\x58\x38\xf8\xc0\x05\x20\x92" ++
    "\x11\x6c\xbd\x93\x37\x05\xdc\xa4\x56\x54\x21\x0c" ++
    "\x03\x73\x63\x8c\xa8\xfd\x1a\xcc\xfa\x52\x23\xc1" ++
    "\x38\xa8\xd4\x08\xc7\x27\x08\x89\x6f\x58\x06\x0e" ++
    "\x59\x3e\x66\x31\x0c\x82\x83\x88\x1c\x86\x12\x8b" ++
    "\x7b\x30\x9d\xd0\x79\xf4\x3e\x6a\x04\x10\x8b\x12" ++
    "\xa5\xa2\xf0\xea\x05\x58\xc6\x40\x95\x02\x64\x42" ++
    "\x76\x5c\x24\x1f\xc5\xdc\x91\x4e\x14\x24\x17\x41" ++
    "\xcf\xf0\x40";

/// The same tar, xz-compressed.
const xz_bundle =
    "\xfd\x37\x7a\x58\x5a\x00\x00\x04\xe6\xd6\xb4\x46" ++
    "\x02\x00\x21\x01\x1c\x00\x00\x00\x10\xcf\x58\xcc" ++
    "\xe0\x27\xff\x00\x95\x5d\x00\x39\x1b\xec\xe8\x67" ++
    "\xbd\x21\x4e\x0e\xcd\xec\xe4\xd4\xcf\x63\x97\x0a" ++
    "\x48\xff\xbf\xa1\xcf\x8c\x64\xd3\xef\xbc\x97\xc5" ++
    "\xbf\x51\x3e\x6d\x4b\x3a\x9a\xc8\xc9\x65\xe5\x49" ++
    "\x17\x68\xdb\x79\xed\x40\xde\xa8\x55\xfd\x26\x23" ++
    "\x0f\x63\xa7\xf6\x91\x95\x2d\x3b\x7f\xfd\x0f\x61" ++
    "\x40\x93\x8a\x34\xb9\xec\x78\xaf\xa9\x40\xae\x80" ++
    "\x2a\xde\x8c\x8e\xb3\xb5\xb7\x90\x56\xb6\xa8\x68" ++
    "\x2e\x48\xb8\x17\x36\x29\x0c\x7e\x71\x02\x17\x17" ++
    "\xe7\x77\xcf\xaa\x31\x78\x6b\x9f\xb9\xe4\x6f\xa1" ++
    "\x03\x58\x71\x52\x03\xe3\xd0\xd8\xf9\xea\xe5\x36" ++
    "\x84\x52\x9a\x6b\xb2\xf2\x0e\x6c\x5e\x20\x05\x32" ++
    "\xf3\x96\xbe\xea\x84\x79\xb1\x66\xd8\xed\xb3\x00" ++
    "\x00\x00\x00\x00\x02\x6e\x8b\x75\xa5\xa2\x56\xe5" ++
    "\x00\x01\xb1\x01\x80\x50\x00\x00\x36\xa5\x46\xae" ++
    "\xb1\xc4\x67\xfb\x02\x00\x00\x00\x00\x04\x59\x5a";

/// The same tar, zstd-compressed.
const zstd_bundle =
    "\x28\xb5\x2f\xfd\x60\x00\x27\x85\x03\x00\xa2\x85" ++
    "\x12\x11\x90\x7d\x64\x84\x8b\xa8\x45\x1e\x33\x2a" ++
    "\x1f\x58\x01\x31\xd3\x85\x14\x3d\x10\x41\x44\x09" ++
    "\x60\x85\x6a\x27\xbe\x90\xcd\x67\x03\x2f\xc8\x28" ++
    "\x53\x2d\xa6\x42\xce\x58\xed\x1b\xe2\xf7\x6d\x75" ++
    "\xba\x27\xe4\x6f\xcb\x58\xff\x13\xf0\x07\x15\x52" ++
    "\xc8\x93\x4f\xe4\x11\x4a\xe4\xf3\xac\x73\xe0\x98" ++
    "\xad\xbd\x01\x0e\x20\xd0\xd7\x37\xfd\xdf\x83\xe6" ++
    "\x6a\x1b\x53\x47\x20\x58\x1d\x20\xfd\xf6\x55\x33" ++
    "\xa7\xce\xcf\xb4\x27\x06\xf0\x80\x41\x01\x56\x13" ++
    "\xa3\x03";

const compressed_config = "{\"ociVersion\": \"1.0.0\"}";

fn expectBundleConfig(name: []const u8, bytes: []const u8) !void {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var path_buffer: [TempTree.max_path_len]u8 = undefined;
    // The contract is the member name, not the file name: the producer always
    // calls it `android-bundle.tar` whatever it is compressed with.
    const path = tree.path(&path_buffer, "android-bundle.tar");
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });

    const digest = bundleConfigDigest(
        std.testing.allocator,
        io,
        path,
        1024 * 1024,
    ) catch |err| {
        std.debug.print("{s}: {s}\n", .{ name, @errorName(err) });
        return err;
    };
    var expected: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(compressed_config, &expected, .{});
    try std.testing.expectEqualStrings(
        &std.fmt.bytesToHex(expected, .lower),
        &digest.hex,
    );

    // The size bound still applies once the stream is decoded.
    try std.testing.expectError(
        error.InvalidConfigEntry,
        bundleConfigDigest(std.testing.allocator, io, path, 4),
    );
}

test "a compressed bundle is read the way tarfile's r:* mode reads it" {
    try expectBundleConfig("gzip", gzip_bundle);
    try expectBundleConfig("bzip2", bzip2_bundle);
    try expectBundleConfig("xz", xz_bundle);
    try expectBundleConfig("zstd", zstd_bundle);
}

test "a truncated compressed bundle is malformed rather than empty" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var path_buffer: [TempTree.max_path_len]u8 = undefined;
    const path = tree.path(&path_buffer, "android-bundle.tar");
    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = gzip_bundle[0 .. gzip_bundle.len - 40],
    });
    try std.testing.expectError(
        error.MalformedArchive,
        bundleConfigDigest(std.testing.allocator, io, path, 1024 * 1024),
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
        bundleConfigDigest(std.testing.allocator, io, missing, 1024),
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
        bundleConfigDigest(std.testing.allocator, io, duplicate, 1024),
    );
}
