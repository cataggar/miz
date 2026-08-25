//! Delivery of a finished disk image: one forward-only pass over the
//! guest-visible bytes, optionally compressed on the way out, to a file or
//! to stdout.
//!
//! This exists because the useful artifact is usually not an uncompressed
//! file on local disk. The canonical way to consume a raw image is
//! `curl <url> | gunzip | dd of=/dev/<disk>`, so the published artifact
//! wants to be gzip; and writing the full raw size to local disk only to
//! compress it in a second pass is frequently the most expensive step of a
//! build. Compression therefore happens *while* the bytes are produced,
//! never as a post-pass over a finished file.
//!
//! Only `raw` is delivered this way. `vhd` (footer written after the data),
//! `vhdx` (BAT), and `qcow2` (L1/L2/refcount tables) all have to go back and
//! amend metadata they already wrote, which a pipe cannot do and a
//! compressor cannot undo -- those combinations are rejected by name rather
//! than silently producing a corrupt artifact.
//!
//! Unallocated regions and all-zero chunks are fed to the compressor as runs
//! of zero bytes rather than being skipped. A skipped run would shorten the
//! stream, and a shortened raw stream is a truncated disk; runs of zeros
//! cost the compressor almost nothing (a mostly-empty 20 GiB image gzips to
//! a few MiB), which is what makes compressed output cheap for the sparse
//! images `miz` produces.

const std = @import("std");
const Io = std.Io;
const flate = std.compress.flate;
const image_mod = @import("image.zig");
const Image = image_mod.Image;
const zstd = @import("zstd.zig");

pub const Format = @import("formats.zig").Format;

/// How the raw bytes are encoded on the way out. `zstd` emits a standard
/// zstd stream and also backs COSI output. `gzip` remains the default choice
/// for published artifacts because it is the most widely supported option.
pub const Compression = enum {
    none,
    gzip,
    zstd,

    /// Parses the compression suffix of an `-O` argument or a filename,
    /// e.g. the `gz` of `raw.gz`. Both the short and long spellings are
    /// accepted since `.gz`/`.gzip` and `.zst`/`.zstd` are both in the wild.
    pub fn parseSuffix(suffix: []const u8) ?Compression {
        if (std.ascii.eqlIgnoreCase(suffix, "gz")) return .gzip;
        if (std.ascii.eqlIgnoreCase(suffix, "gzip")) return .gzip;
        if (std.ascii.eqlIgnoreCase(suffix, "zst")) return .zstd;
        if (std.ascii.eqlIgnoreCase(suffix, "zstd")) return .zstd;
        return null;
    }

    /// The canonical filename suffix, including the dot, or the empty
    /// string for uncompressed output.
    pub fn displaySuffix(self: Compression) []const u8 {
        return switch (self) {
            .none => "",
            .gzip => ".gz",
            .zstd => ".zst",
        };
    }
};

/// gzip compression level, 1 (fastest) through 9 (smallest).
pub const Level = u4;

/// Deliberately the *fastest* level, not the smallest. For a large,
/// mostly-zero disk image the wall-clock difference between level 1 and
/// level 9 is large while the size difference is small: the bulk of the
/// image is runs of zeros, which every level collapses to nearly nothing.
/// Callers that are optimizing a published artifact can still ask for 9.
pub const default_level: Level = 1;

pub const LevelError = error{CompressionLevelOutOfRange};

pub fn parseLevel(text: []const u8) LevelError!Level {
    const value = std.fmt.parseInt(u8, text, 10) catch return error.CompressionLevelOutOfRange;
    if (value < 1 or value > 9) return error.CompressionLevelOutOfRange;
    return @intCast(value);
}

/// A destination format together with how it is encoded, i.e. everything
/// `-O raw.gz` says.
pub const Spec = struct {
    format: Format,
    compression: Compression = .none,

    /// Parses an `-O` argument: a format name, optionally followed by a
    /// compression suffix (`raw.gz`, `raw.zst`). Returns null for anything
    /// that is not a recognized format/compression pair, so the caller can
    /// report the original spelling.
    pub fn parseName(name: []const u8) ?Spec {
        if (std.mem.lastIndexOfScalar(u8, name, '.')) |dot| {
            if (Compression.parseSuffix(name[dot + 1 ..])) |compression| {
                return .{
                    .format = Format.parseName(name[0..dot]) orelse return null,
                    .compression = compression,
                };
            }
        }
        return .{ .format = Format.parseName(name) orelse return null };
    }

    /// Infers a spec from an output filename's extensions, e.g.
    /// `image.raw.gz`. Returns null when the name carries no recognizable
    /// format extension, leaving the choice of default to the caller.
    pub fn inferFromPath(path: []const u8) ?Spec {
        const base = std.fs.path.basename(path);
        const dot = std.mem.lastIndexOfScalar(u8, base, '.') orelse return null;
        if (Compression.parseSuffix(base[dot + 1 ..])) |compression| {
            const stem = base[0..dot];
            const stem_dot = std.mem.lastIndexOfScalar(u8, stem, '.') orelse return null;
            return .{
                .format = parseFormatExtension(stem[stem_dot + 1 ..]) orelse return null,
                .compression = compression,
            };
        }
        return .{ .format = parseFormatExtension(base[dot + 1 ..]) orelse return null };
    }

    pub fn displayName(self: Spec) []const u8 {
        return switch (self.compression) {
            .none => self.format.displayName(),
            .gzip => switch (self.format) {
                .raw => "raw.gz",
                .vhd => "vhd.gz",
                .vhdx => "vhdx.gz",
                .qcow2 => "qcow2.gz",
            },
            .zstd => switch (self.format) {
                .raw => "raw.zst",
                .vhd => "vhd.zst",
                .vhdx => "vhdx.zst",
                .qcow2 => "qcow2.zst",
            },
        };
    }
};

/// `.raw` and `.img` both name a raw image; the rest match their format
/// name. Kept separate from `Format.parseName` because `vpc` is a format
/// name people type but never a file extension, and `img` is the reverse.
fn parseFormatExtension(extension: []const u8) ?Format {
    if (std.ascii.eqlIgnoreCase(extension, "img")) return .raw;
    if (std.ascii.eqlIgnoreCase(extension, "vpc")) return null;
    return Format.parseName(extension);
}

/// Where the finished image goes. `stdout` is the `-o -` case: the process's
/// standard output, which may be a pipe and therefore cannot be seeked.
pub const Destination = union(enum) {
    path: []const u8,
    stdout,
};

pub const SpecError = error{
    /// A compressed artifact is produced by compressing the bytes as they
    /// are written. Only `raw` is written in a single forward pass; every
    /// other format has to go back and amend metadata it already emitted,
    /// which cannot be done through a compressor.
    CompressionRequiresRawFormat,
    /// Writing to stdout means never seeking backwards, which `vhd` (footer
    /// after the data), `vhdx` (BAT), and `qcow2` (L1/L2 and refcount
    /// tables) all require.
    FormatRequiresSeekableOutput,
    /// Zstd output uses one pinned deterministic parameter set, so there is no
    /// level to select. Rejected rather than silently ignored.
    CompressionLevelNotSupportedForZstd,
} || LevelError;

/// Checks a `-O`/`-o` combination before anything is opened or written.
/// `level` is the explicitly requested level, or null when the caller did
/// not ask for one.
pub fn validate(spec: Spec, destination: Destination, level: ?Level) SpecError!void {
    if (spec.compression != .none and spec.format != .raw) {
        return error.CompressionRequiresRawFormat;
    }
    if (destination == .stdout and spec.format != .raw) {
        return error.FormatRequiresSeekableOutput;
    }
    if (level) |value| {
        if (value < 1 or value > 9) return error.CompressionLevelOutOfRange;
        if (spec.compression == .zstd) return error.CompressionLevelNotSupportedForZstd;
    }
}

pub const WriteOptions = struct {
    compression: Compression = .none,
    level: Level = default_level,
};

pub const WriteError = error{
    /// The source image reported fewer bytes than its virtual size, so the
    /// stream would be short. A short raw stream is a truncated disk.
    UnexpectedEndOfFile,
} || LevelError || Image.PreadError || Image.MapError ||
    Io.Writer.Error || zstd.Error || std.mem.Allocator.Error;

/// How much of the source is read at a time. Only affects zero-run
/// detection granularity and peak memory; the emitted stream is identical
/// for any chunk size.
const read_chunk_size: usize = 1024 * 1024;

/// Writes every guest-visible byte of `src` to `out`, in order, exactly
/// once. `out` is flushed before returning, so a caller that gets a success
/// back has a complete artifact.
pub fn writeImage(
    allocator: std.mem.Allocator,
    io: Io,
    src: Image,
    out: *Io.Writer,
    options: WriteOptions,
) WriteError!void {
    var sink = try Sink.init(allocator, out, src.virtual_size, options);
    defer sink.deinit(allocator);

    // Walking extents rather than the flat range means an unallocated
    // region of a sparse source is never read at all -- it goes straight to
    // the compressor as a run of zeros, which is what keeps compressing a
    // 20 GiB image with 2 GiB of content cheap.
    const extents = try src.mapExtents(io, allocator);
    defer allocator.free(extents);

    const buffer = try allocator.alloc(u8, read_chunk_size);
    defer allocator.free(buffer);

    for (extents) |extent| {
        if (!extent.allocated) {
            try sink.writeZeroes(extent.length);
            continue;
        }
        var offset = extent.offset;
        const end = extent.offset + extent.length;
        while (offset < end) {
            const chunk: usize = @intCast(@min(end - offset, buffer.len));
            const got = try src.pread(io, buffer[0..chunk], offset);
            if (got != chunk) return error.UnexpectedEndOfFile;
            if (image_mod.isAllZero(buffer[0..chunk])) {
                try sink.writeZeroes(chunk);
            } else {
                try sink.writeAll(buffer[0..chunk]);
            }
            offset += chunk;
        }
    }

    try sink.finish();
    try out.flush();
}

/// Opens `destination` and streams `src` into it. A path is created and
/// truncated; stdout is written through a non-seeking writer so a pipe
/// works exactly like a redirect to a file.
pub fn writeImageTo(
    allocator: std.mem.Allocator,
    io: Io,
    src: Image,
    destination: Destination,
    options: WriteOptions,
) (WriteError || Io.File.OpenError)!void {
    var buffer: [64 * 1024]u8 = undefined;
    switch (destination) {
        .path => |path| {
            const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
            defer file.close(io);
            var file_writer = file.writer(io, &buffer);
            try writeImage(allocator, io, src, &file_writer.interface, options);
        },
        .stdout => {
            var stdout_writer = Io.File.stdout().writerStreaming(io, &buffer);
            try writeImage(allocator, io, src, &stdout_writer.interface, options);
        },
    }
}

/// A forward-only sink for image bytes that knows how to emit a run of
/// zeros without materializing it (gzip, uncompressed) or with a single
/// reusable bounded zstd frame encoder.
const Sink = struct {
    out: *Io.Writer,
    /// Total number of guest-visible bytes this sink will be given. zstd
    /// declares it in the frame header, and it doubles as a completeness
    /// check at `finish`.
    total: u64,
    written: u64 = 0,
    state: State,

    const State = union(Compression) {
        none: void,
        gzip: Gzip,
        zstd: Zstd,
    };

    const Gzip = struct {
        compressor: *flate.Compress,
        history: []u8,
    };

    const Zstd = struct {
        block: []u8,
        encoder: zstd.FrameEncoder,
    };

    fn init(
        allocator: std.mem.Allocator,
        out: *Io.Writer,
        total: u64,
        options: WriteOptions,
    ) WriteError!Sink {
        switch (options.compression) {
            .none => return .{ .out = out, .total = total, .state = .none },
            .gzip => {
                const opts = try flateOptions(options.level);
                const history = try allocator.alloc(u8, flate.max_window_len);
                errdefer allocator.free(history);
                const compressor = try allocator.create(flate.Compress);
                errdefer allocator.destroy(compressor);
                compressor.* = try flate.Compress.init(out, history, .gzip, opts);
                return .{
                    .out = out,
                    .total = total,
                    .state = .{ .gzip = .{ .compressor = compressor, .history = history } },
                };
            },
            .zstd => {
                const block = try allocator.alloc(u8, zstd.max_block_size);
                errdefer allocator.free(block);
                const encoder = try zstd.FrameEncoder.init(out, block, .{
                    .content_size = total,
                });
                return .{
                    .out = out,
                    .total = total,
                    .state = .{ .zstd = .{ .block = block, .encoder = encoder } },
                };
            },
        }
    }

    fn deinit(self: *Sink, allocator: std.mem.Allocator) void {
        switch (self.state) {
            .none => {},
            .gzip => |gzip| {
                allocator.destroy(gzip.compressor);
                allocator.free(gzip.history);
            },
            .zstd => |*zstd_state| {
                zstd_state.encoder.deinit();
                allocator.free(zstd_state.block);
            },
        }
        self.* = undefined;
    }

    fn writeAll(self: *Sink, bytes: []const u8) WriteError!void {
        switch (self.state) {
            .none => try self.out.writeAll(bytes),
            .gzip => |gzip| try gzip.compressor.writer.writeAll(bytes),
            .zstd => |*zstd_state| try zstd_state.encoder.writeAll(bytes),
        }
        self.written += bytes.len;
    }

    fn writeZeroes(self: *Sink, count: u64) WriteError!void {
        switch (self.state) {
            .none => try splatZeroes(self.out, count),
            .gzip => |gzip| try splatZeroes(&gzip.compressor.writer, count),
            .zstd => |*zstd_state| try zstd_state.encoder.writeZeroes(count),
        }
        self.written += count;
    }

    fn finish(self: *Sink) WriteError!void {
        // Every byte of the virtual disk must have been handed over: a
        // stream that is short is a disk image that is truncated, and for
        // zstd it would also contradict the size declared in the frame
        // header.
        std.debug.assert(self.written == self.total);
        switch (self.state) {
            .none => {},
            .gzip => |gzip| try gzip.compressor.finish(),
            .zstd => |*zstd_state| try zstd_state.encoder.finish(),
        }
    }
};

fn splatZeroes(writer: *Io.Writer, count: u64) Io.Writer.Error!void {
    var remaining = count;
    while (remaining > 0) {
        const chunk: usize = @intCast(@min(remaining, @as(u64, std.math.maxInt(u32))));
        try writer.splatByteAll(0, chunk);
        remaining -= chunk;
    }
}

fn flateOptions(level: Level) LevelError!flate.Compress.Options {
    return switch (level) {
        1 => .level_1,
        2 => .level_2,
        3 => .level_3,
        4 => .level_4,
        5 => .level_5,
        6 => .level_6,
        7 => .level_7,
        8 => .level_8,
        9 => .level_9,
        else => error.CompressionLevelOutOfRange,
    };
}

test "Spec.parseName accepts plain and compressed format names" {
    try std.testing.expectEqual(Spec{ .format = .raw }, Spec.parseName("raw").?);
    try std.testing.expectEqual(Spec{ .format = .vhd }, Spec.parseName("vpc").?);
    try std.testing.expectEqual(
        Spec{ .format = .raw, .compression = .gzip },
        Spec.parseName("raw.gz").?,
    );
    try std.testing.expectEqual(
        Spec{ .format = .raw, .compression = .gzip },
        Spec.parseName("RAW.GZIP").?,
    );
    try std.testing.expectEqual(
        Spec{ .format = .raw, .compression = .zstd },
        Spec.parseName("raw.zst").?,
    );
    try std.testing.expectEqual(
        Spec{ .format = .qcow2, .compression = .zstd },
        Spec.parseName("qcow2.zstd").?,
    );
    try std.testing.expectEqual(@as(?Spec, null), Spec.parseName("raw.bz2"));
    try std.testing.expectEqual(@as(?Spec, null), Spec.parseName("tar.gz"));
    try std.testing.expectEqual(@as(?Spec, null), Spec.parseName("nonsense"));
}

test "Spec.inferFromPath reads the format and compression extensions" {
    try std.testing.expectEqual(
        Spec{ .format = .raw, .compression = .gzip },
        Spec.inferFromPath("out/image.raw.gz").?,
    );
    try std.testing.expectEqual(
        Spec{ .format = .raw, .compression = .zstd },
        Spec.inferFromPath("image.img.zst").?,
    );
    try std.testing.expectEqual(Spec{ .format = .qcow2 }, Spec.inferFromPath("image.qcow2").?);
    try std.testing.expectEqual(@as(?Spec, null), Spec.inferFromPath("image.gz"));
    try std.testing.expectEqual(@as(?Spec, null), Spec.inferFromPath("image"));
    // A directory component must not be mistaken for the extension.
    try std.testing.expectEqual(@as(?Spec, null), Spec.inferFromPath("v1.0/image"));
}

test "validate rejects compression and stdout for seek-back formats" {
    try validate(.{ .format = .raw, .compression = .gzip }, .stdout, 9);
    try validate(.{ .format = .raw }, .stdout, null);
    try validate(.{ .format = .qcow2 }, .{ .path = "out.qcow2" }, null);

    for ([_]Format{ .vhd, .vhdx, .qcow2 }) |format| {
        try std.testing.expectError(
            error.FormatRequiresSeekableOutput,
            validate(.{ .format = format }, .stdout, null),
        );
        try std.testing.expectError(
            error.CompressionRequiresRawFormat,
            validate(.{ .format = format, .compression = .gzip }, .{ .path = "out" }, null),
        );
    }

    try std.testing.expectError(
        error.CompressionLevelNotSupportedForZstd,
        validate(.{ .format = .raw, .compression = .zstd }, .{ .path = "out.raw.zst" }, 3),
    );
    try std.testing.expectError(
        error.CompressionLevelOutOfRange,
        validate(.{ .format = .raw, .compression = .gzip }, .{ .path = "out.raw.gz" }, 0),
    );
}

test "parseLevel accepts 1 through 9 only" {
    try std.testing.expectEqual(@as(Level, 1), try parseLevel("1"));
    try std.testing.expectEqual(@as(Level, 9), try parseLevel("9"));
    try std.testing.expectError(error.CompressionLevelOutOfRange, parseLevel("0"));
    try std.testing.expectError(error.CompressionLevelOutOfRange, parseLevel("10"));
    try std.testing.expectError(error.CompressionLevelOutOfRange, parseLevel("fast"));
}

/// Builds a source image whose content is mostly zeros with a couple of
/// recognizable payloads, and returns the expected raw bytes.
fn writeTestSource(io: Io, path: []const u8, size: usize) !void {
    var img = try Image.create(io, path, .raw, size, .{});
    defer img.close(io);
    try img.pwrite(io, "first-payload", 512);
    try img.pwrite(io, "last-payload", size - 4096);
}

fn expectedTestSource(allocator: std.mem.Allocator, size: usize) ![]u8 {
    const expected = try allocator.alloc(u8, size);
    @memset(expected, 0);
    @memcpy(expected[512..][0.."first-payload".len], "first-payload");
    @memcpy(expected[size - 4096 ..][0.."last-payload".len], "last-payload");
    return expected;
}

test "gzip output round-trips back to the original raw bytes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const src_path = "test-output-gzip-src.img";
    const dst_path = "test-output-gzip-dst.raw.gz";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const size: usize = 3 * 1024 * 1024;
    try writeTestSource(io, src_path, size);

    var src = try Image.openPathReadOnly(io, src_path);
    defer src.close(io);
    try writeImageTo(allocator, io, src, .{ .path = dst_path }, .{ .compression = .gzip });

    const compressed = try Io.Dir.cwd().readFileAlloc(io, dst_path, allocator, .limited(size + 1));
    defer allocator.free(compressed);
    // The point of compressing a mostly-zero image: it must be far smaller
    // than the raw size, not merely smaller.
    try std.testing.expect(compressed.len < size / 100);

    const expected = try expectedTestSource(allocator, size);
    defer allocator.free(expected);
    const decompressed = try gunzip(allocator, compressed, size);
    defer allocator.free(decompressed);
    try std.testing.expectEqualSlices(u8, expected, decompressed);
}

test "zstd output round-trips back to the original raw bytes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const src_path = "test-output-zstd-src.img";
    const dst_path = "test-output-zstd-dst.raw.zst";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const size: usize = 3 * 1024 * 1024;
    try writeTestSource(io, src_path, size);

    var src = try Image.openPathReadOnly(io, src_path);
    defer src.close(io);
    try writeImageTo(allocator, io, src, .{ .path = dst_path }, .{ .compression = .zstd });

    const compressed = try Io.Dir.cwd().readFileAlloc(io, dst_path, allocator, .limited(size + 1));
    defer allocator.free(compressed);
    try std.testing.expect(compressed.len < size / 10);

    const expected = try expectedTestSource(allocator, size);
    defer allocator.free(expected);
    const decoded = try zstd.decodeAlloc(allocator, compressed);
    defer allocator.free(decoded.bytes);
    try std.testing.expectEqualSlices(u8, expected, decoded.bytes);
}

test "uncompressed streaming reproduces the source byte for byte" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const src_path = "test-output-plain-src.img";
    const dst_path = "test-output-plain-dst.raw";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const size: usize = 2 * 1024 * 1024;
    try writeTestSource(io, src_path, size);

    var src = try Image.openPathReadOnly(io, src_path);
    defer src.close(io);
    try writeImageTo(allocator, io, src, .{ .path = dst_path }, .{});

    const written = try Io.Dir.cwd().readFileAlloc(io, dst_path, allocator, .limited(size + 1));
    defer allocator.free(written);
    const expected = try expectedTestSource(allocator, size);
    defer allocator.free(expected);
    try std.testing.expectEqualSlices(u8, expected, written);
}

test "sparse source regions become zeros in the stream, not gaps" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const raw_path = "test-output-sparse-src.img";
    const qcow2_path = "test-output-sparse-src.qcow2";
    const dst_path = "test-output-sparse-dst.raw.gz";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, qcow2_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    // A qcow2 whose middle clusters were never allocated: `mapExtents`
    // reports them as holes, and the stream must still contain their bytes.
    const size: usize = 4 * 1024 * 1024;
    try writeTestSource(io, raw_path, size);
    {
        var raw = try Image.openPathReadOnly(io, raw_path);
        defer raw.close(io);
        var qcow = try Image.create(io, qcow2_path, .qcow2, size, .{});
        defer qcow.close(io);
        _ = try image_mod.copyAll(io, raw, &qcow, allocator);
    }

    var src = try Image.openPathReadOnly(io, qcow2_path);
    defer src.close(io);
    const extents = try src.mapExtents(io, allocator);
    defer allocator.free(extents);
    var holes: usize = 0;
    for (extents) |extent| {
        if (!extent.allocated) holes += 1;
    }
    try std.testing.expect(holes > 0);

    try writeImageTo(allocator, io, src, .{ .path = dst_path }, .{ .compression = .gzip });

    const compressed = try Io.Dir.cwd().readFileAlloc(io, dst_path, allocator, .limited(size + 1));
    defer allocator.free(compressed);
    const decompressed = try gunzip(allocator, compressed, size);
    defer allocator.free(decompressed);

    const expected = try expectedTestSource(allocator, size);
    defer allocator.free(expected);
    try std.testing.expectEqual(size, decompressed.len);
    try std.testing.expectEqualSlices(u8, expected, decompressed);
}

test "compression levels all produce the same bytes" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const src_path = "test-output-levels-src.img";
    const dst_path = "test-output-levels-dst.raw.gz";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, dst_path) catch {};

    const size: usize = 1024 * 1024;
    try writeTestSource(io, src_path, size);
    const expected = try expectedTestSource(allocator, size);
    defer allocator.free(expected);

    for ([_]Level{ 1, 6, 9 }) |level| {
        var src = try Image.openPathReadOnly(io, src_path);
        defer src.close(io);
        try writeImageTo(allocator, io, src, .{ .path = dst_path }, .{
            .compression = .gzip,
            .level = level,
        });
        const compressed = try Io.Dir.cwd().readFileAlloc(io, dst_path, allocator, .limited(size + 1));
        defer allocator.free(compressed);
        const decompressed = try gunzip(allocator, compressed, size);
        defer allocator.free(decompressed);
        try std.testing.expectEqualSlices(u8, expected, decompressed);
    }
}

test "writeImage rejects a compression level it cannot honor" {
    const io = std.testing.io;
    const allocator = std.testing.allocator;
    const src_path = "test-output-bad-level-src.img";
    defer Io.Dir.cwd().deleteFile(io, src_path) catch {};
    try writeTestSource(io, src_path, 512 * 1024);

    var src = try Image.openPathReadOnly(io, src_path);
    defer src.close(io);

    var discarding = Io.Writer.Discarding.init(&.{});
    try std.testing.expectError(error.CompressionLevelOutOfRange, writeImage(
        allocator,
        io,
        src,
        &discarding.writer,
        .{ .compression = .gzip, .level = 15 },
    ));
}

fn gunzip(allocator: std.mem.Allocator, compressed: []const u8, max_len: usize) ![]u8 {
    var input: Io.Reader = .fixed(compressed);
    var window: [flate.max_window_len]u8 = undefined;
    var decompressor: flate.Decompress = .init(&input, .gzip, &window);
    return decompressor.reader.allocRemaining(allocator, .limited(max_len + 1));
}
