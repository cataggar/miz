//! Best-effort detection of dm-verity userspace tooling
//! (`systemd-veritysetup-generator`, `systemd-veritysetup`, `veritysetup`)
//! inside an initramfs image.
//!
//! `zvmi build-image` never rebuilds the initramfs -- it copies whatever
//! `boot/initramfs*` blob already exists in the merged ISO/squashfs/OCI
//! source tree. If that initramfs doesn't include dm-verity userspace
//! tooling, `--verity` produces a kernel cmdline
//! (`roothash=`/`systemd.verity_root_*`) that is correct but that the
//! initrd can never act on: `systemd-veritysetup-generator` never runs, no
//! `systemd-veritysetup@root.service` unit is generated, and the boot hangs
//! forever waiting on `dev-mapper-root.device`. See
//! https://github.com/cataggar/zvmi/issues/77 for the investigation that
//! diagnosed this.
//!
//! This module lets `build-image --verity` detect that condition and fail
//! fast at build time instead of producing an image that hangs at boot.
//!
//! Initramfs images are one or more concatenated cpio ("newc" format)
//! archives, where all but (optionally) the last are uncompressed (e.g.
//! dracut's "early cpio" holding microcode) and the last is typically
//! compressed (gzip, xz, or zstd). Since `zvmi` never needs to *extract*
//! the initramfs, only enumerate its entry paths, this walks each segment
//! with `cpio.zig`, decompressing a trailing compressed segment as needed.

const std = @import("std");
const cpio = @import("cpio.zig");
const zstd_encode = @import("zstd.zig");

pub const VerityToolingStatus = enum {
    /// At least one dm-verity userspace tool was found in the initramfs.
    present,
    /// Every cpio segment in the initramfs was successfully parsed and none
    /// of them contained a known dm-verity userspace tool path.
    absent,
    /// The initramfs could not be fully parsed (e.g. it uses a compression
    /// format this reader doesn't recognize, such as lz4 or lzop, or a
    /// malformed/unsupported xz filter chain). Callers should treat this as
    /// "unknown" rather than a hard failure, since it may be a false
    /// negative rather than evidence of a missing tool.
    inconclusive,
};

/// Known on-disk locations for dm-verity userspace tooling across distros
/// that ship systemd's `systemd-veritysetup-generator` and/or the standalone
/// `veritysetup` binary from cryptsetup. Matched against the raw cpio entry
/// path, tolerating an optional leading "./" (common in cpio archives).
const verity_tool_paths = [_][]const u8{
    "usr/lib/systemd/systemd-veritysetup-generator",
    "usr/lib/systemd/system-generators/systemd-veritysetup-generator",
    "usr/lib/systemd/systemd-veritysetup",
    "usr/bin/veritysetup",
    "usr/sbin/veritysetup",
    "bin/veritysetup",
    "sbin/veritysetup",
};

/// Generous ceiling on a decompressed initramfs size, to bound memory use
/// if given corrupt or hostile input; real initramfs images are typically
/// tens of MiB.
const max_decompressed_size: usize = 1 << 30;

pub fn checkVerityTooling(allocator: std.mem.Allocator, initramfs_bytes: []const u8) std.mem.Allocator.Error!VerityToolingStatus {
    var cursor: usize = 0;
    var parsed_any_segment = false;

    while (cursor < initramfs_bytes.len) {
        const remaining = initramfs_bytes[cursor..];

        if (cpio.looksLikeArchive(remaining)) {
            parsed_any_segment = true;
            const result = scanCpioSegment(remaining);
            if (result.found) return .present;
            if (result.parse_error or result.consumed == 0) return .inconclusive;
            cursor += result.consumed;
            continue;
        }

        if (detectCompression(remaining)) |format| {
            parsed_any_segment = true;
            const decompressed = decompress(allocator, format, remaining) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return .inconclusive,
            };
            defer allocator.free(decompressed);

            const result = scanCpioSegment(decompressed);
            if (result.found) return .present;
            // A compressed segment is assumed to run through the rest of
            // the input; there's nothing meaningful to scan afterward.
            return if (result.parse_error) .inconclusive else .absent;
        }

        // Skip NUL padding between segments (e.g. after an early-cpio
        // trailer, before a compressed main archive begins).
        var next_cursor = cursor;
        while (next_cursor < initramfs_bytes.len and initramfs_bytes[next_cursor] == 0) : (next_cursor += 1) {}
        if (next_cursor == cursor) return .inconclusive; // unrecognized, non-NUL bytes
        cursor = next_cursor;
    }

    return if (parsed_any_segment) .absent else .inconclusive;
}

const CpioScanResult = struct {
    found: bool,
    consumed: usize,
    parse_error: bool,
};

fn scanCpioSegment(data: []const u8) CpioScanResult {
    var reader = cpio.Reader.init(data);
    while (true) {
        const entry = reader.next() catch return .{ .found = false, .consumed = reader.offset, .parse_error = true };
        const e = entry orelse break;
        if (isVerityToolPath(e.path)) return .{ .found = true, .consumed = reader.offset, .parse_error = false };
    }
    return .{ .found = false, .consumed = reader.offset, .parse_error = false };
}

fn isVerityToolPath(raw_path: []const u8) bool {
    const path = if (std.mem.startsWith(u8, raw_path, "./")) raw_path[2..] else raw_path;
    for (verity_tool_paths) |candidate| {
        if (std.mem.eql(u8, path, candidate)) return true;
    }
    return false;
}

const CompressionFormat = enum { gzip, xz, zstd };

fn detectCompression(data: []const u8) ?CompressionFormat {
    if (data.len >= 2 and data[0] == 0x1f and data[1] == 0x8b) return .gzip;
    if (data.len >= 6 and std.mem.eql(u8, data[0..6], &.{ 0xFD, '7', 'z', 'X', 'Z', 0x00 })) return .xz;
    if (data.len >= 4 and data[0] == 0x28 and data[1] == 0xb5 and data[2] == 0x2f and data[3] == 0xfd) return .zstd;
    return null;
}

const DecompressError = std.mem.Allocator.Error || error{ Unsupported, Invalid, StreamTooLong };

fn decompress(allocator: std.mem.Allocator, format: CompressionFormat, bytes: []const u8) DecompressError![]u8 {
    return switch (format) {
        .gzip => decompressGzip(allocator, bytes),
        .zstd => decompressZstd(allocator, bytes),
        .xz => decompressXz(allocator, bytes),
    };
}

fn decompressGzip(allocator: std.mem.Allocator, bytes: []const u8) DecompressError![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    var window: [std.compress.flate.max_window_len]u8 = undefined;
    var decompressor: std.compress.flate.Decompress = .init(&input, .gzip, &window);
    return decompressor.reader.allocRemaining(allocator, .limited(max_decompressed_size)) catch |err| switch (err) {
        error.ReadFailed => error.Invalid,
        error.StreamTooLong => error.StreamTooLong,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn decompressZstd(allocator: std.mem.Allocator, bytes: []const u8) DecompressError![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    // Use "indirect" mode with an explicitly-sized window buffer rather than
    // the empty-buffer "direct" mode used previously: direct mode requires
    // the destination `Writer`'s own buffer to already satisfy
    // `window_len + block_size_max` capacity on each read, an invariant
    // `allocRemaining`'s incrementally-growing destination buffer doesn't
    // guarantee. That produced correct output for small synthetic test
    // archives (and even some real initramfs images), but silently returned
    // truncated/corrupted data for other real, large (~50+ MiB decompressed)
    // dracut-produced initramfs images -- discovered via issue #105's
    // real-boot verity fixture, where this function misreported an
    // initramfs as lacking `systemd-veritysetup` when it was genuinely
    // present.
    const window_len = std.compress.zstd.default_window_len;
    const window_buf = try allocator.alloc(u8, window_len + std.compress.zstd.block_size_max);
    defer allocator.free(window_buf);
    var decompressor = std.compress.zstd.Decompress.init(&input, window_buf, .{ .window_len = window_len });
    return decompressor.reader.allocRemaining(allocator, .limited(max_decompressed_size)) catch |err| switch (err) {
        error.ReadFailed => error.Invalid,
        error.StreamTooLong => error.StreamTooLong,
        error.OutOfMemory => error.OutOfMemory,
    };
}

fn decompressXz(allocator: std.mem.Allocator, bytes: []const u8) DecompressError![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    var decompressor = std.compress.xz.Decompress.init(&input, allocator, &.{}) catch |err| switch (err) {
        error.NotXzStream, error.WrongChecksum, error.EndOfStream, error.ReadFailed => return error.Invalid,
    };
    defer decompressor.deinit();
    return decompressor.reader.allocRemaining(allocator, .limited(max_decompressed_size)) catch |err| switch (err) {
        error.ReadFailed => switch (decompressor.err orelse error.Invalid) {
            error.Unsupported => error.Unsupported,
            else => error.Invalid,
        },
        error.StreamTooLong => error.StreamTooLong,
        error.OutOfMemory => error.OutOfMemory,
    };
}

const testing = std.testing;

fn appendCpioEntry(allocator: std.mem.Allocator, list: *std.array_list.Managed(u8), path: []const u8, content: []const u8) !void {
    var header: [110]u8 = undefined;
    _ = try std.fmt.bufPrint(&header, "070701{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}{x:0>8}", .{
        0, @as(u32, 0o100644), 0, 0, 1, 0, content.len, 0, 0, 0, 0, path.len + 1, 0,
    });
    try list.appendSlice(&header);
    try list.appendSlice(path);
    try list.append(0);
    while (list.items.len % 4 != 0) try list.append(0);
    try list.appendSlice(content);
    while (list.items.len % 4 != 0) try list.append(0);
    _ = allocator;
}

fn buildTestArchive(allocator: std.mem.Allocator, paths: []const []const u8) ![]u8 {
    var list = std.array_list.Managed(u8).init(allocator);
    errdefer list.deinit();
    for (paths) |path| try appendCpioEntry(allocator, &list, path, "bytes");
    try appendCpioEntry(allocator, &list, "TRAILER!!!", "");
    return list.toOwnedSlice();
}

test "checkVerityTooling finds veritysetup in an uncompressed archive" {
    const archive = try buildTestArchive(testing.allocator, &.{ "etc/fstab", "usr/bin/veritysetup" });
    defer testing.allocator.free(archive);

    try testing.expectEqual(VerityToolingStatus.present, try checkVerityTooling(testing.allocator, archive));
}

test "checkVerityTooling reports absent when fully parsed without a match" {
    const archive = try buildTestArchive(testing.allocator, &.{ "etc/fstab", "usr/bin/bash" });
    defer testing.allocator.free(archive);

    try testing.expectEqual(VerityToolingStatus.absent, try checkVerityTooling(testing.allocator, archive));
}

test "checkVerityTooling finds the generator across a concatenated early-cpio segment" {
    const early = try buildTestArchive(testing.allocator, &.{"kernel/x86/microcode/GenuineIntel.bin"});
    defer testing.allocator.free(early);
    const main = try buildTestArchive(testing.allocator, &.{"usr/lib/systemd/systemd-veritysetup-generator"});
    defer testing.allocator.free(main);

    var combined = std.array_list.Managed(u8).init(testing.allocator);
    defer combined.deinit();
    try combined.appendSlice(early);
    try combined.appendSlice(main);

    try testing.expectEqual(VerityToolingStatus.present, try checkVerityTooling(testing.allocator, combined.items));
}

test "checkVerityTooling tolerates a leading ./ prefix" {
    const archive = try buildTestArchive(testing.allocator, &.{"./usr/sbin/veritysetup"});
    defer testing.allocator.free(archive);

    try testing.expectEqual(VerityToolingStatus.present, try checkVerityTooling(testing.allocator, archive));
}

test "checkVerityTooling is inconclusive for unrecognized data" {
    try testing.expectEqual(VerityToolingStatus.inconclusive, try checkVerityTooling(testing.allocator, "not-a-cpio-or-known-compression"));
}

test "checkVerityTooling is inconclusive for empty input" {
    try testing.expectEqual(VerityToolingStatus.inconclusive, try checkVerityTooling(testing.allocator, &.{}));
}

test "checkVerityTooling decompresses a gzip-wrapped archive" {
    const archive = try buildTestArchive(testing.allocator, &.{"usr/lib/systemd/systemd-veritysetup"});
    defer testing.allocator.free(archive);

    const gzipped = try gzipBytesForTest(testing.allocator, archive);
    defer testing.allocator.free(gzipped);

    try testing.expectEqual(VerityToolingStatus.present, try checkVerityTooling(testing.allocator, gzipped));
}

fn gzipBytesForTest(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    var out = try std.Io.Writer.Allocating.initCapacity(allocator, @max(@as(usize, 64), data.len));
    errdefer out.deinit();

    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(&out.writer, &history, .gzip, .default);
    try compressor.writer.writeAll(data);
    try compressor.finish();
    return out.toOwnedSlice();
}

test "checkVerityTooling decompresses a zstd-wrapped archive" {
    const archive = try buildTestArchive(testing.allocator, &.{"usr/lib/systemd/systemd-veritysetup-generator"});
    defer testing.allocator.free(archive);

    var out = std.Io.Writer.Allocating.init(testing.allocator);
    defer out.deinit();
    try zstd_encode.writeRawFrameForSlice(&out.writer, archive, null);

    try testing.expectEqual(VerityToolingStatus.present, try checkVerityTooling(testing.allocator, out.written()));
}

test "checkVerityTooling decompresses a plain xz-wrapped archive" {
    // A single-filter (plain LZMA2, no BCJ) xz stream wrapping a newc cpio
    // archive containing one entry, "usr/bin/veritysetup", generated via
    // Python's lzma module (lzma.compress(..., format=FORMAT_XZ,
    // filters=[{"id": FILTER_LZMA2, "preset": 6}])).
    const encoded = [_]u8{
        0xfd, 0x37, 0x7a, 0x58, 0x5a, 0x00, 0x00, 0x04, 0xe6, 0xd6, 0xb4, 0x46,
        0x02, 0x00, 0x21, 0x01, 0x16, 0x00, 0x00, 0x00, 0x74, 0x2f, 0xe5, 0xa3,
        0xe0, 0x01, 0x07, 0x00, 0x4d, 0x5d, 0x00, 0x18, 0x0d, 0xdd, 0x04, 0x63,
        0x9d, 0x11, 0xdb, 0x41, 0x9d, 0x1a, 0x18, 0xfb, 0x35, 0x13, 0x64, 0x1f,
        0x09, 0xa0, 0x06, 0xb7, 0xd7, 0x91, 0x37, 0x67, 0x1e, 0x4e, 0x22, 0x14,
        0xa5, 0x30, 0x33, 0xdf, 0x3d, 0x2d, 0x53, 0x3b, 0x56, 0x5d, 0xe1, 0x6d,
        0x1a, 0x37, 0x8c, 0xcc, 0x0c, 0x4c, 0x46, 0xcf, 0x61, 0xe2, 0xbd, 0x01,
        0xe2, 0xa1, 0x26, 0x85, 0x8f, 0xfa, 0x22, 0xbc, 0x05, 0x4b, 0xc9, 0x2c,
        0x17, 0x2a, 0xc9, 0xe4, 0x31, 0x84, 0x2d, 0xd5, 0xdf, 0x43, 0xd8, 0x80,
        0x00, 0x00, 0x00, 0x00, 0xb9, 0x8e, 0xd7, 0x38, 0x07, 0xe4, 0xa9, 0xdb,
        0x00, 0x01, 0x69, 0x88, 0x02, 0x00, 0x00, 0x00, 0x97, 0xb9, 0x31, 0xc7,
        0xb1, 0xc4, 0x67, 0xfb, 0x02, 0x00, 0x00, 0x00, 0x00, 0x04, 0x59, 0x5a,
    };

    try testing.expectEqual(VerityToolingStatus.present, try checkVerityTooling(testing.allocator, &encoded));
}
