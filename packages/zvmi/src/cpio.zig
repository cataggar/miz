//! Minimal read-only "newc" (`070701`/`070702`) format cpio archive reader.
//!
//! This only needs to enumerate entry pathnames (and expose each entry's raw
//! content slice), so unlike `tar.zig` it doesn't attempt to support writing
//! or any of the older cpio header formats. It exists to support inspecting
//! initramfs images (see `verity_tooling.zig`) without extracting them to disk.
//!
//! Handles the `TRAILER!!!` end-of-archive marker and multiple **concatenated**
//! archives: `next()` keeps scanning past a trailer (and any NUL padding
//! after it) for another archive's magic bytes, which mirrors how tools like
//! dracut concatenate an uncompressed "early cpio" (e.g. microcode) archive
//! in front of the main initramfs archive.

const std = @import("std");

pub const Kind = enum {
    file,
    directory,
    symlink,
    other,
};

pub const Entry = struct {
    path: []const u8,
    kind: Kind,
    mode: u32,
    size: u64,
    content: []const u8,
};

pub const Error = error{
    InvalidHeader,
    InvalidHexField,
    TruncatedArchive,
};

const header_size = 110;
const trailer_name = "TRAILER!!!";

pub const magic_newc = "070701";
pub const magic_newc_crc = "070702";

/// Returns true if `data` starts with a recognized newc-format cpio magic.
pub fn looksLikeArchive(data: []const u8) bool {
    if (data.len < magic_newc.len) return false;
    return std.mem.eql(u8, data[0..magic_newc.len], magic_newc) or
        std.mem.eql(u8, data[0..magic_newc.len], magic_newc_crc);
}

pub const Reader = struct {
    data: []const u8,
    /// Bytes of `data` consumed so far, including any trailing NUL padding
    /// skipped while looking for a subsequent concatenated archive.
    offset: usize = 0,

    pub fn init(data: []const u8) Reader {
        return .{ .data = data };
    }

    /// Returns the next non-trailer entry, transparently skipping past
    /// `TRAILER!!!` markers and NUL padding to look for another concatenated
    /// archive. Returns `null` once no further archive magic can be found.
    pub fn next(self: *Reader) Error!?Entry {
        while (true) {
            if (!self.skipToNextMagic()) return null;

            if (self.offset + header_size > self.data.len) return error.TruncatedArchive;
            const header = self.data[self.offset..][0..header_size];

            const mode = try parseHexField(header[14..22]);
            const filesize = try parseHexField(header[54..62]);
            const namesize = try parseHexField(header[94..102]);
            if (namesize == 0) return error.InvalidHeader;

            const name_start = self.offset + header_size;
            const name_end_with_nul = std.math.add(usize, name_start, @intCast(namesize)) catch return error.TruncatedArchive;
            if (name_end_with_nul > self.data.len) return error.TruncatedArchive;
            const raw_name = self.data[name_start .. name_end_with_nul - 1];

            const content_start = alignUp(name_end_with_nul, 4);
            const content_end = std.math.add(usize, content_start, @intCast(filesize)) catch return error.TruncatedArchive;
            if (content_start > self.data.len or content_end > self.data.len) return error.TruncatedArchive;
            const content = self.data[content_start..content_end];

            self.offset = alignUp(content_end, 4);

            if (std.mem.eql(u8, raw_name, trailer_name)) {
                // End of this archive -- keep scanning in case another
                // (e.g. dracut early-cpio + main) archive follows.
                continue;
            }

            return .{
                .path = raw_name,
                .kind = kindFromMode(@intCast(mode)),
                .mode = @intCast(mode),
                .size = filesize,
                .content = content,
            };
        }
    }

    /// Advances past NUL padding and reports whether a recognized cpio
    /// magic follows. Leaves `offset` at the start of that magic on success.
    fn skipToNextMagic(self: *Reader) bool {
        while (self.offset < self.data.len and self.data[self.offset] == 0) {
            self.offset += 1;
        }
        return looksLikeArchive(self.data[self.offset..]);
    }
};

fn parseHexField(field: []const u8) Error!u64 {
    return std.fmt.parseUnsigned(u64, field, 16) catch error.InvalidHexField;
}

fn alignUp(value: usize, alignment: usize) usize {
    return (value + alignment - 1) / alignment * alignment;
}

fn kindFromMode(mode: u32) Kind {
    return switch (mode & 0o170000) {
        0o100000 => .file,
        0o040000 => .directory,
        0o120000 => .symlink,
        else => .other,
    };
}

fn buildEntryBytes(allocator: std.mem.Allocator, list: *std.array_list.Managed(u8), name: []const u8, mode: u32, content: []const u8) !void {
    var header: [header_size]u8 = undefined;
    _ = try std.fmt.bufPrint(&header, "070701{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}", .{
        0, // c_ino
        mode, // c_mode
        0, // c_uid
        0, // c_gid
        1, // c_nlink
        0, // c_mtime
        content.len, // c_filesize
        0, // c_devmajor
        0, // c_devminor
        0, // c_rdevmajor
        0, // c_rdevminor
        name.len + 1, // c_namesize (includes NUL)
        0, // c_check
    });
    try list.appendSlice(header[0..]);
    try list.appendSlice(name);
    try list.append(0);
    try padTo4(allocator, list);
    try list.appendSlice(content);
    try padTo4(allocator, list);
}

fn padTo4(allocator: std.mem.Allocator, list: *std.array_list.Managed(u8)) !void {
    _ = allocator;
    const pad = (4 - (list.items.len % 4)) % 4;
    var i: usize = 0;
    while (i < pad) : (i += 1) try list.append(0);
}

/// Test-only helper: builds a minimal newc cpio archive in memory containing
/// the given (path, mode, content) entries followed by a trailer, so tests
/// don't need to hand-encode header bytes.
fn buildArchiveForTest(allocator: std.mem.Allocator, entries: []const struct { path: []const u8, mode: u32 = 0o100644, content: []const u8 = "" }) ![]u8 {
    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();
    for (entries) |entry| {
        try buildEntryBytes(allocator, &list, entry.path, entry.mode, entry.content);
    }
    try buildEntryBytes(allocator, &list, trailer_name, 0, "");
    return list.toOwnedSlice();
}

test "reader iterates a single cpio archive" {
    const allocator = std.testing.allocator;
    const archive = try buildArchiveForTest(allocator, &.{
        .{ .path = "usr/bin/veritysetup", .content = "elf-bytes" },
        .{ .path = "etc/fstab", .content = "" },
    });
    defer allocator.free(archive);

    var reader = Reader.init(archive);

    const first = (try reader.next()).?;
    try std.testing.expectEqualStrings("usr/bin/veritysetup", first.path);
    try std.testing.expectEqualStrings("elf-bytes", first.content);
    try std.testing.expectEqual(Kind.file, first.kind);

    const second = (try reader.next()).?;
    try std.testing.expectEqualStrings("etc/fstab", second.path);

    try std.testing.expect((try reader.next()) == null);
}

test "reader skips a directory entry's mode correctly" {
    const allocator = std.testing.allocator;
    const archive = try buildArchiveForTest(allocator, &.{
        .{ .path = "usr/lib/systemd", .mode = 0o040755, .content = "" },
    });
    defer allocator.free(archive);

    var reader = Reader.init(archive);
    const entry = (try reader.next()).?;
    try std.testing.expectEqual(Kind.directory, entry.kind);
    try std.testing.expect((try reader.next()) == null);
}

test "reader continues past a trailer into a concatenated archive" {
    const allocator = std.testing.allocator;
    const first_archive = try buildArchiveForTest(allocator, &.{
        .{ .path = "kernel/x86/microcode/GenuineIntel.bin", .content = "ucode" },
    });
    defer allocator.free(first_archive);
    const second_archive = try buildArchiveForTest(allocator, &.{
        .{ .path = "usr/lib/systemd/systemd-veritysetup-generator", .content = "elf" },
    });
    defer allocator.free(second_archive);

    var combined = std.array_list.Managed(u8).init(allocator);
    defer combined.deinit();
    try combined.appendSlice(first_archive);
    try combined.appendSlice(second_archive);

    var reader = Reader.init(combined.items);
    const first = (try reader.next()).?;
    try std.testing.expectEqualStrings("kernel/x86/microcode/GenuineIntel.bin", first.path);

    const second = (try reader.next()).?;
    try std.testing.expectEqualStrings("usr/lib/systemd/systemd-veritysetup-generator", second.path);

    try std.testing.expect((try reader.next()) == null);
}

test "reader returns null on empty data" {
    var reader = Reader.init(&.{});
    try std.testing.expect((try reader.next()) == null);
}

test "reader rejects a truncated header" {
    var reader = Reader.init("070701");
    try std.testing.expectError(error.TruncatedArchive, reader.next());
}

test "looksLikeArchive recognizes both newc magic variants" {
    try std.testing.expect(looksLikeArchive("070701" ++ "rest"));
    try std.testing.expect(looksLikeArchive("070702" ++ "rest"));
    try std.testing.expect(!looksLikeArchive("gzipped-not-cpio"));
    try std.testing.expect(!looksLikeArchive("07"));
}
