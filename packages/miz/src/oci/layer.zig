//! Verified streaming OCI layer decoding.
const std = @import("std");
const content = @import("content.zig");
const layout = @import("layout.zig");
const model = @import("model.zig");
const tar = @import("../tar.zig");

const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Compression = enum {
    none,
    gzip,
    zstd,
};

pub const Limits = struct {
    max_uncompressed_bytes: u64 = 64 * 1024 * 1024 * 1024,
    max_entry_size: u64 = 8 * 1024 * 1024 * 1024,
    max_entries: usize = 1_000_000,
    max_path_bytes: usize = Io.Dir.max_path_bytes,
    max_pax_bytes: usize = 1024 * 1024 + 64 * 1024,
    max_pax_records: usize = 512,

    fn tarLimits(self: Limits) tar.StreamLimits {
        return .{
            .max_archive_bytes = self.max_uncompressed_bytes,
            .max_entry_size = self.max_entry_size,
            .max_entries = self.max_entries,
            .max_path_bytes = self.max_path_bytes,
            .max_pax_bytes = self.max_pax_bytes,
            .max_pax_records = self.max_pax_records,
        };
    }
};

pub const Error = error{
    UnsupportedLayerMediaType,
    LayerDecompressionFailed,
    LayerTooLarge,
    DiffIdMismatch,
    InvalidDiffId,
    CorruptLayer,
};

pub fn processLayout(
    allocator: std.mem.Allocator,
    source: layout.Source,
    descriptor: model.Descriptor,
    diff_id_text: []const u8,
    limits: Limits,
    context: anytype,
    comptime visit: anytype,
) !void {
    const file = try source.openBlob(descriptor);
    defer file.close(source.io);
    var file_buffer: [64 * 1024]u8 = undefined;
    var file_reader = file.reader(source.io, &file_buffer);
    try processReader(
        allocator,
        &file_reader.interface,
        descriptor,
        diff_id_text,
        limits,
        context,
        visit,
    );
}

pub fn processReader(
    allocator: std.mem.Allocator,
    input: *Io.Reader,
    descriptor: model.Descriptor,
    diff_id_text: []const u8,
    limits: Limits,
    context: anytype,
    comptime visit: anytype,
) !void {
    const compressed_digest = content.Digest.parse(descriptor.digest) catch
        return error.CorruptLayer;
    const diff_id = content.Digest.parse(diff_id_text) catch
        return error.InvalidDiffId;
    const compression = compressionForMediaType(descriptor.mediaType) orelse
        return error.UnsupportedLayerMediaType;

    var compressed: VerifyingReader = undefined;
    compressed.init(input, compressed_digest, descriptor.size);
    switch (compression) {
        .none => processDecoded(
            allocator,
            &compressed.interface,
            diff_id,
            limits,
            context,
            visit,
        ) catch |err| return readerError(err, &compressed),
        .gzip => {
            var window: [std.compress.flate.max_window_len]u8 = undefined;
            var decompressor: std.compress.flate.Decompress = .init(
                &compressed.interface,
                .gzip,
                &window,
            );
            processDecoded(
                allocator,
                &decompressor.reader,
                diff_id,
                limits,
                context,
                visit,
            ) catch |err| return readerError(err, &compressed);
        },
        .zstd => {
            const window_len = std.compress.zstd.default_window_len;
            const window = try allocator.alloc(
                u8,
                window_len + std.compress.zstd.block_size_max,
            );
            defer allocator.free(window);
            var decompressor = std.compress.zstd.Decompress.init(
                &compressed.interface,
                window,
                .{ .window_len = window_len },
            );
            processDecoded(
                allocator,
                &decompressor.reader,
                diff_id,
                limits,
                context,
                visit,
            ) catch |err| return readerError(err, &compressed);
        },
    }
    compressed.finish() catch |err| return switch (err) {
        error.SizeMismatch, error.DigestMismatch, error.SizeOverflow => error.CorruptLayer,
        else => err,
    };
}

fn processDecoded(
    allocator: std.mem.Allocator,
    decoded: *Io.Reader,
    diff_id: content.Digest,
    limits: Limits,
    context: anytype,
    comptime visit: anytype,
) !void {
    var digesting = DigestingReader.init(
        decoded,
        diff_id,
        limits.max_uncompressed_bytes,
    );
    var archive = tar.StreamReader.init(
        allocator,
        &digesting.interface,
        limits.tarLimits(),
    );
    defer archive.deinit();

    while (archive.next() catch |err| {
        if (digesting.error_state) |source_err| return source_err;
        if (err == error.ReadFailed) return error.LayerDecompressionFailed;
        return err;
    }) |entry| {
        try visit(context, &archive, entry);
    }
    archive.finishEntry() catch |err| {
        if (digesting.error_state) |source_err| return source_err;
        return err;
    };
    try digesting.finish();
}

fn compressionForMediaType(media_type: ?[]const u8) ?Compression {
    const value = media_type orelse return null;
    if (std.mem.eql(u8, value, model.media_type_oci_layer) or
        std.mem.eql(u8, value, model.media_type_oci_nondistributable_layer) or
        std.mem.eql(u8, value, model.media_type_docker_layer) or
        std.mem.eql(u8, value, model.media_type_docker_foreign_layer))
    {
        return .none;
    }
    if (std.mem.eql(u8, value, model.media_type_oci_layer_gzip) or
        std.mem.eql(u8, value, model.media_type_oci_nondistributable_layer_gzip) or
        std.mem.eql(u8, value, model.media_type_docker_layer_gzip) or
        std.mem.eql(u8, value, model.media_type_docker_foreign_layer_gzip))
    {
        return .gzip;
    }
    if (std.mem.eql(u8, value, model.media_type_oci_layer_zstd) or
        std.mem.eql(u8, value, model.media_type_oci_nondistributable_layer_zstd) or
        std.mem.eql(u8, value, model.media_type_docker_layer_zstd))
    {
        return .zstd;
    }
    return null;
}

fn readerError(err: anyerror, compressed: *VerifyingReader) anyerror {
    if (compressed.error_state) |_| return error.CorruptLayer;
    if (err == error.ReadFailed) return error.LayerDecompressionFailed;
    return err;
}

const VerifyingReader = struct {
    source: *Io.Reader,
    verifier: content.Verifier,
    interface: Io.Reader,
    interface_buffer: [64 * 1024]u8 = undefined,
    scratch: [64 * 1024]u8 = undefined,
    error_state: ?anyerror = null,

    fn init(
        self: *VerifyingReader,
        source: *Io.Reader,
        digest: content.Digest,
        size: u64,
    ) void {
        self.* = .{
            .source = source,
            .verifier = content.Verifier.init(digest, size),
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = &self.interface_buffer,
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(
        reader: *Io.Reader,
        writer: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const self: *VerifyingReader = @alignCast(@fieldParentPtr("interface", reader));
        const remaining = self.verifier.expected_size - self.verifier.size;
        if (remaining == 0) return error.EndOfStream;
        const amount = limit.minInt64(@min(remaining, self.scratch.len));
        if (amount == 0) return 0;
        const count = self.source.readSliceShort(self.scratch[0..amount]) catch {
            self.error_state = error.ReadFailed;
            return error.ReadFailed;
        };
        if (count == 0) {
            self.error_state = error.SizeMismatch;
            return error.ReadFailed;
        }
        self.verifier.update(self.scratch[0..count]) catch |err| {
            self.error_state = err;
            return error.ReadFailed;
        };
        try writer.writeAll(self.scratch[0..count]);
        return count;
    }

    fn finish(self: *VerifyingReader) !void {
        var discard: [8192]u8 = undefined;
        while (true) {
            const count = self.interface.readSliceShort(&discard) catch |err| {
                return self.error_state orelse err;
            };
            if (count == 0) break;
        }
        if (self.error_state) |err| return err;
        try self.verifier.finish();
    }
};

const DigestingReader = struct {
    source: *Io.Reader,
    expected: content.Digest,
    max_size: u64,
    size: u64 = 0,
    hash: Sha256 = Sha256.init(.{}),
    interface: Io.Reader,
    scratch: [64 * 1024]u8 = undefined,
    error_state: ?anyerror = null,

    fn init(
        source: *Io.Reader,
        expected: content.Digest,
        max_size: u64,
    ) DigestingReader {
        return .{
            .source = source,
            .expected = expected,
            .max_size = max_size,
            .interface = .{
                .vtable = &.{ .stream = stream },
                .buffer = &.{},
                .seek = 0,
                .end = 0,
            },
        };
    }

    fn stream(
        reader: *Io.Reader,
        writer: *Io.Writer,
        limit: Io.Limit,
    ) Io.Reader.StreamError!usize {
        const self: *DigestingReader = @alignCast(@fieldParentPtr("interface", reader));
        if (self.size == self.max_size) {
            var extra: [1]u8 = undefined;
            const count = self.source.readSliceShort(&extra) catch {
                self.error_state = error.ReadFailed;
                return error.ReadFailed;
            };
            if (count == 0) return error.EndOfStream;
            self.error_state = error.LayerTooLarge;
            return error.ReadFailed;
        }
        const remaining = self.max_size - self.size;
        const amount = limit.minInt64(@min(remaining, self.scratch.len));
        if (amount == 0) return 0;
        const count = self.source.readSliceShort(self.scratch[0..amount]) catch {
            self.error_state = error.ReadFailed;
            return error.ReadFailed;
        };
        if (count == 0) return error.EndOfStream;
        self.size += count;
        self.hash.update(self.scratch[0..count]);
        try writer.writeAll(self.scratch[0..count]);
        return count;
    }

    fn finish(self: *DigestingReader) !void {
        var discard: [8192]u8 = undefined;
        while (true) {
            const count = self.interface.readSliceShort(&discard) catch |err| {
                return self.error_state orelse err;
            };
            if (count == 0) break;
        }
        if (self.error_state) |err| return err;
        var actual: [Sha256.digest_length]u8 = undefined;
        self.hash.final(&actual);
        if (!std.mem.eql(u8, &actual, &self.expected.bytes)) {
            return error.DiffIdMismatch;
        }
    }
};

const Capture = struct {
    allocator: std.mem.Allocator,
    path: ?[]u8 = null,
    payload: ?[]u8 = null,

    fn deinit(self: *Capture) void {
        if (self.path) |value| self.allocator.free(value);
        if (self.payload) |value| self.allocator.free(value);
    }
};

fn captureEntry(
    capture: *Capture,
    archive: *tar.StreamReader,
    entry: tar.StreamEntry,
) !void {
    if (entry.kind != .file) return;
    capture.path = try capture.allocator.dupe(u8, entry.path);
    const payload = try capture.allocator.alloc(u8, @intCast(entry.size));
    errdefer capture.allocator.free(payload);
    var offset: usize = 0;
    while (offset < payload.len) {
        const count = try archive.readEntry(payload[offset..]);
        if (count == 0) return error.TruncatedArchive;
        offset += count;
    }
    capture.payload = payload;
}

test "layer processor verifies compressed digest and uncompressed DiffID" {
    const allocator = std.testing.allocator;
    var tar_bytes = Io.Writer.Allocating.init(allocator);
    defer tar_bytes.deinit();
    var tar_writer = tar.Writer.init(&tar_bytes.writer);
    try tar_writer.writeFile("hello", 0o644, "world");
    try tar_writer.finish();

    var compressed = try Io.Writer.Allocating.initCapacity(allocator, 1024);
    defer compressed.deinit();
    var history: [std.compress.flate.max_window_len]u8 = undefined;
    var compressor = try std.compress.flate.Compress.init(
        &compressed.writer,
        &history,
        .gzip,
        .default,
    );
    try compressor.writer.writeAll(tar_bytes.written());
    try compressor.finish();

    const descriptor_digest = content.digestBytes(compressed.written()).format();
    const diff_id = content.digestBytes(tar_bytes.written()).format();
    const descriptor = model.Descriptor{
        .mediaType = model.media_type_oci_layer_gzip,
        .digest = &descriptor_digest,
        .size = compressed.written().len,
    };
    var input = Io.Reader.fixed(compressed.written());
    var capture = Capture{ .allocator = allocator };
    defer capture.deinit();
    try processReader(
        allocator,
        &input,
        descriptor,
        &diff_id,
        .{},
        &capture,
        captureEntry,
    );
    try std.testing.expectEqualStrings("hello", capture.path.?);
    try std.testing.expectEqualStrings("world", capture.payload.?);

    const wrong_diff_id = content.digestBytes("wrong").format();
    var mismatch_input = Io.Reader.fixed(compressed.written());
    var ignored = Capture{ .allocator = allocator };
    defer ignored.deinit();
    try std.testing.expectError(
        error.DiffIdMismatch,
        processReader(
            allocator,
            &mismatch_input,
            descriptor,
            &wrong_diff_id,
            .{},
            &ignored,
            captureEntry,
        ),
    );
}
