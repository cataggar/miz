//! Native reader and deterministic writer for the `newc` cpio variants.
//!
//! `newc` is deliberately a small format, but it is often consumed before a
//! filesystem is mounted.  Treat names and metadata as untrusted: callers can
//! use this module without extracting an archive to the host filesystem.

const std = @import("std");

pub const magic_newc = "070701";
pub const magic_newc_crc = "070702";

const header_size = 110;
const trailer_name = "TRAILER!!!";

pub const Format = enum {
    newc,
    crc,

    fn magic(self: Format) []const u8 {
        return switch (self) {
            .newc => magic_newc,
            .crc => magic_newc_crc,
        };
    }
};

pub const Kind = enum {
    file,
    directory,
    symlink,
    other,
};

/// Every field that newc stores other than the byte count and CRC checksum.
/// Keeping them intact lets a caller make an explicit policy choice instead of
/// accidentally discarding ownership, device, or hard-link information.
pub const Metadata = struct {
    ino: u32 = 0,
    mode: u32 = 0,
    uid: u32 = 0,
    gid: u32 = 0,
    nlink: u32 = 1,
    mtime: u32 = 0,
    devmajor: u32 = 0,
    devminor: u32 = 0,
    rdevmajor: u32 = 0,
    rdevminor: u32 = 0,
};

pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    metadata: Metadata,
    size: u64,
    content: []const u8,
};

pub const WriteEntry = struct {
    path: []const u8,
    content: []const u8,
    metadata: Metadata = .{},
};

pub const Error = error{
    InvalidHeader,
    InvalidHexField,
    InvalidPath,
    InvalidMetadata,
    InvalidChecksum,
    TruncatedArchive,
    MissingTrailer,
    TrailingData,
    FieldOutOfRange,
    ArchiveFinished,
};

/// Returns true if `data` starts with a recognized newc-format cpio magic.
pub fn looksLikeArchive(data: []const u8) bool {
    return data.len >= magic_newc.len and
        (std.mem.eql(u8, data[0..magic_newc.len], magic_newc) or
            std.mem.eql(u8, data[0..magic_newc.len], magic_newc_crc));
}

/// Rejects names that could escape an extraction root.  A single leading
/// `./` is common in real initramfs archives and is safe, so it is accepted;
/// all remaining components must be non-empty and non-special.
pub fn isSafePath(path: []const u8) bool {
    var normalized = path;
    while (std.mem.startsWith(u8, normalized, "./")) normalized = normalized[2..];
    if (normalized.len == 0 or normalized[0] == '/') return false;

    var components = std.mem.splitScalar(u8, normalized, '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, "..") or
            std.mem.indexOfScalar(u8, component, 0) != null)
        {
            return false;
        }
    }
    return true;
}

/// Reader for one or more directly-concatenated newc archives.  After a
/// trailer, `next()` stops before a non-cpio segment (for example a compressed
/// initramfs segment); `finish()` is available when the caller requires the
/// whole input to be exactly one or more cpio archives plus NUL padding.
pub const Reader = struct {
    data: []const u8,
    /// Bytes consumed so far, including NUL padding skipped after a trailer.
    offset: usize = 0,
    saw_archive: bool = false,
    saw_trailer: bool = false,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    pub fn next(self: *Reader) Error!?Entry {
        while (true) {
            self.skipPadding();
            if (self.offset == self.data.len) {
                if (self.saw_archive and !self.saw_trailer) return error.MissingTrailer;
                return null;
            }
            if (!looksLikeArchive(self.data[self.offset..])) {
                if (self.saw_trailer) return null;
                return error.InvalidHeader;
            }

            self.saw_archive = true;
            self.saw_trailer = false;
            const parsed = try self.parseEntry();
            if (std.mem.eql(u8, parsed.path, trailer_name)) {
                if (parsed.size != 0 or parsed.metadata.mode != 0 or parsed.metadata.nlink != 1) {
                    return error.InvalidMetadata;
                }
                self.saw_trailer = true;
                continue;
            }
            if (!isSafePath(parsed.path)) return error.InvalidPath;
            return parsed;
        }
    }

    /// Requires that all input has been consumed by complete cpio archives
    /// (except for alignment NULs).  This detects missing trailers and
    /// concatenation with arbitrary bytes rather than silently accepting it.
    pub fn finish(self: *Reader) Error!void {
        while (try self.next()) |_| {}
        self.skipPadding();
        if (!self.saw_archive or !self.saw_trailer) return error.MissingTrailer;
        if (self.offset != self.data.len) return error.TrailingData;
    }

    fn parseEntry(self: *Reader) Error!Entry {
        const header_end = std.math.add(usize, self.offset, header_size) catch
            return error.TruncatedArchive;
        if (header_end > self.data.len) return error.TruncatedArchive;
        const header = self.data[self.offset..header_end];
        const format: Format = if (std.mem.eql(u8, header[0..6], magic_newc))
            .newc
        else if (std.mem.eql(u8, header[0..6], magic_newc_crc))
            .crc
        else
            return error.InvalidHeader;

        const metadata = Metadata{
            .ino = try parseHexField(header[6..14]),
            .mode = try parseHexField(header[14..22]),
            .uid = try parseHexField(header[22..30]),
            .gid = try parseHexField(header[30..38]),
            .nlink = try parseHexField(header[38..46]),
            .mtime = try parseHexField(header[46..54]),
            .devmajor = try parseHexField(header[62..70]),
            .devminor = try parseHexField(header[70..78]),
            .rdevmajor = try parseHexField(header[78..86]),
            .rdevminor = try parseHexField(header[86..94]),
        };
        if (metadata.nlink == 0) return error.InvalidMetadata;
        const filesize = try parseHexField(header[54..62]);
        const namesize = try parseHexField(header[94..102]);
        const check = try parseHexField(header[102..110]);
        if (format == .newc and check != 0) return error.InvalidChecksum;
        if (namesize == 0) return error.InvalidHeader;

        const name_start = header_end;
        const name_with_nul_end = std.math.add(usize, name_start, namesize) catch
            return error.TruncatedArchive;
        if (name_with_nul_end > self.data.len) return error.TruncatedArchive;
        if (self.data[name_with_nul_end - 1] != 0) return error.InvalidHeader;
        const raw_name = self.data[name_start .. name_with_nul_end - 1];
        if (std.mem.indexOfScalar(u8, raw_name, 0) != null) return error.InvalidPath;

        const content_start = try align4(name_with_nul_end);
        const content_end = std.math.add(usize, content_start, filesize) catch
            return error.TruncatedArchive;
        if (content_end > self.data.len) return error.TruncatedArchive;
        const content = self.data[content_start..content_end];
        self.offset = try align4(content_end);
        if (self.offset > self.data.len) return error.TruncatedArchive;

        if (format == .crc and check != checksum(content)) return error.InvalidChecksum;
        return .{
            .path = raw_name,
            .kind = kindFromMode(metadata.mode),
            .metadata = metadata,
            .size = filesize,
            .content = content,
        };
    }

    fn skipPadding(self: *Reader) void {
        while (self.offset < self.data.len and self.data[self.offset] == 0) {
            self.offset += 1;
        }
    }
};

/// Deterministic in-memory newc/CRC writer.  It does not sort entries: callers
/// supply their canonical order, which keeps archive ordering an explicit
/// policy and preserves metadata exactly.
pub const Writer = struct {
    output: *std.array_list.Managed(u8),
    format: Format,
    finished: bool = false,

    pub fn init(output: *std.array_list.Managed(u8), format: Format) Writer {
        return .{ .output = output, .format = format };
    }

    pub fn append(self: *Writer, entry: WriteEntry) (std.mem.Allocator.Error || Error)!void {
        if (self.finished) return error.ArchiveFinished;
        if (!isSafePath(entry.path) or std.mem.eql(u8, entry.path, trailer_name)) {
            return error.InvalidPath;
        }
        if (entry.metadata.nlink == 0) return error.InvalidMetadata;
        try writeEntry(self.output, self.format, entry);
    }

    pub fn finish(self: *Writer) (std.mem.Allocator.Error || Error)!void {
        if (self.finished) return error.ArchiveFinished;
        try writeEntry(self.output, self.format, .{
            .path = trailer_name,
            .content = &.{},
            .metadata = .{ .nlink = 1 },
        });
        self.finished = true;
    }
};

fn writeEntry(
    output: *std.array_list.Managed(u8),
    format: Format,
    entry: WriteEntry,
) (std.mem.Allocator.Error || Error)!void {
    if (entry.path.len + 1 > std.math.maxInt(u32) or
        entry.content.len > std.math.maxInt(u32))
    {
        return error.FieldOutOfRange;
    }

    var header: [header_size]u8 = undefined;
    _ = std.fmt.bufPrint(
        &header,
        "{s}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}{X:0>8}",
        .{
            format.magic(),
            entry.metadata.ino,
            entry.metadata.mode,
            entry.metadata.uid,
            entry.metadata.gid,
            entry.metadata.nlink,
            entry.metadata.mtime,
            @as(u32, @intCast(entry.content.len)),
            entry.metadata.devmajor,
            entry.metadata.devminor,
            entry.metadata.rdevmajor,
            entry.metadata.rdevminor,
            @as(u32, @intCast(entry.path.len + 1)),
            if (format == .crc) checksum(entry.content) else 0,
        },
    ) catch unreachable;
    try output.appendSlice(&header);
    try output.appendSlice(entry.path);
    try output.append(0);
    try pad4(output);
    try output.appendSlice(entry.content);
    try pad4(output);
}

fn parseHexField(field: []const u8) Error!u32 {
    return std.fmt.parseUnsigned(u32, field, 16) catch error.InvalidHexField;
}

fn align4(value: usize) Error!usize {
    const increment = (4 - (value % 4)) % 4;
    return std.math.add(usize, value, increment) catch error.TruncatedArchive;
}

fn pad4(output: *std.array_list.Managed(u8)) std.mem.Allocator.Error!void {
    const count = (4 - (output.items.len % 4)) % 4;
    var index: usize = 0;
    while (index < count) : (index += 1) try output.append(0);
}

fn checksum(bytes: []const u8) u32 {
    var sum: u32 = 0;
    for (bytes) |byte| sum +%= byte;
    return sum;
}

fn kindFromMode(mode: u32) Kind {
    return switch (mode & 0o170000) {
        0o100000 => .file,
        0o040000 => .directory,
        0o120000 => .symlink,
        else => .other,
    };
}

fn buildArchiveForTest(
    allocator: std.mem.Allocator,
    format: Format,
    entries: []const WriteEntry,
) ![]u8 {
    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();
    var writer = Writer.init(&list, format);
    for (entries) |entry| try writer.append(entry);
    try writer.finish();
    return list.toOwnedSlice();
}

test "reader preserves newc metadata and exact termination" {
    const archive = try buildArchiveForTest(std.testing.allocator, .newc, &.{
        .{
            .path = "./usr/bin/veritysetup",
            .content = "elf-bytes",
            .metadata = .{
                .ino = 17,
                .mode = 0o100755,
                .uid = 12,
                .gid = 34,
                .nlink = 2,
                .mtime = 1_735_689_600,
                .devmajor = 8,
                .devminor = 1,
                .rdevmajor = 2,
                .rdevminor = 3,
            },
        },
    });
    defer std.testing.allocator.free(archive);

    var reader = Reader.init(archive);
    const entry = (try reader.next()).?;
    try std.testing.expectEqualStrings("./usr/bin/veritysetup", entry.path);
    try std.testing.expectEqual(Kind.file, entry.kind);
    try std.testing.expectEqual(@as(u32, 17), entry.metadata.ino);
    try std.testing.expectEqual(@as(u32, 0o100755), entry.metadata.mode);
    try std.testing.expectEqual(@as(u32, 1_735_689_600), entry.metadata.mtime);
    try std.testing.expectEqualStrings("elf-bytes", entry.content);
    try reader.finish();
}

test "CRC archives validate content checksums" {
    var archive = try buildArchiveForTest(std.testing.allocator, .crc, &.{
        .{ .path = "etc/fstab", .content = "rootfs" },
    });
    defer std.testing.allocator.free(archive);

    var reader = Reader.init(archive);
    try std.testing.expectEqualStrings("etc/fstab", (try reader.next()).?.path);
    try reader.finish();

    archive[header_size + "etc/fstab".len + 1] ^= 1;
    var corrupt = Reader.init(archive);
    try std.testing.expectError(error.InvalidChecksum, corrupt.next());
}

test "writer rejects unsafe names and reader rejects unsafe metadata" {
    var list = std.array_list.Managed(u8).init(std.testing.allocator);
    defer list.deinit();
    var writer = Writer.init(&list, .newc);
    try std.testing.expectError(error.InvalidPath, writer.append(.{
        .path = "../escape",
        .content = "",
    }));
    try std.testing.expectError(error.InvalidPath, writer.append(.{
        .path = "/absolute",
        .content = "",
    }));
    try std.testing.expectError(error.InvalidPath, writer.append(.{
        .path = trailer_name,
        .content = "",
    }));

    const safe = try buildArchiveForTest(std.testing.allocator, .newc, &.{
        .{ .path = "safe", .content = "" },
    });
    defer std.testing.allocator.free(safe);
    var unsafe = try std.testing.allocator.dupe(u8, safe);
    defer std.testing.allocator.free(unsafe);
    @memcpy(unsafe[header_size .. header_size + "../x".len], "../x");
    var reader = Reader.init(unsafe);
    try std.testing.expectError(error.InvalidPath, reader.next());
}

test "reader rejects truncated archives, missing trailers, and trailing bytes" {
    var truncated = Reader.init("070701");
    try std.testing.expectError(error.TruncatedArchive, truncated.next());

    const empty_archive = try buildArchiveForTest(std.testing.allocator, .newc, &.{});
    defer std.testing.allocator.free(empty_archive);
    // Drop the trailer and make the archive empty.  A valid stream cannot end
    // before a trailer, even if it happened to contain no entries.
    var no_trailer = Reader.init(empty_archive[0..0]);
    try std.testing.expect((try no_trailer.next()) == null);
    try std.testing.expectError(error.MissingTrailer, no_trailer.finish());

    const archive = try buildArchiveForTest(std.testing.allocator, .newc, &.{});
    defer std.testing.allocator.free(archive);
    var combined = try std.testing.allocator.alloc(u8, archive.len + 1);
    defer std.testing.allocator.free(combined);
    @memcpy(combined[0..archive.len], archive);
    combined[archive.len] = 1;
    var reader = Reader.init(combined);
    try std.testing.expect((try reader.next()) == null);
    try std.testing.expectError(error.TrailingData, reader.finish());
}

test "writer output is deterministic and concatenated archives are readable" {
    const entries = [_]WriteEntry{
        .{ .path = "init", .content = "first", .metadata = .{ .mode = 0o100755 } },
        .{ .path = "etc/fstab", .content = "second", .metadata = .{ .mode = 0o100644 } },
    };
    const first = try buildArchiveForTest(std.testing.allocator, .newc, &entries);
    defer std.testing.allocator.free(first);
    const second = try buildArchiveForTest(std.testing.allocator, .newc, &entries);
    defer std.testing.allocator.free(second);
    try std.testing.expectEqualSlices(u8, first, second);

    var combined = std.array_list.Managed(u8).init(std.testing.allocator);
    defer combined.deinit();
    try combined.appendSlice(first);
    try combined.appendSlice(second);
    var reader = Reader.init(combined.items);
    var count: usize = 0;
    while (try reader.next()) |_| count += 1;
    try std.testing.expectEqual(@as(usize, 4), count);
    try reader.finish();
}
