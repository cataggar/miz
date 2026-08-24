//! Deterministic Zstandard framing backed by upstream libzstd.
//!
//! Compressed frames pin every setting that affects their wire representation.
//! Raw stored frames remain native so callers can request framing without
//! compression. Compressed operations return `error.ZstdUnavailable` in
//! libc-free module graphs that intentionally include headers without linking
//! libzstd; raw framing remains available there.

const std = @import("std");
const builtin = @import("builtin");
const c = @cImport({
    @cInclude("zstd.h");
});
const Context = if (builtin.link_libc) ?*c.ZSTD_CCtx else ?*anyopaque;

pub const zstd_magic: u32 = 0xFD2F_B528;
pub const skippable_magic: u32 = 0x184D_2A50;
pub const skippable_payload_len: u32 = 16;
pub const max_block_size: usize = 128 * 1024;

const compression_level: c_int = 3;
const window_log: c_int = 21;
const zero_chunk = [_]u8{0} ** 4096;

pub const ZstdError = error{
    ZstdGeneric,
    ZstdPrefixUnknown,
    ZstdVersionUnsupported,
    ZstdFrameParameterUnsupported,
    ZstdWindowTooLarge,
    ZstdCorruptionDetected,
    ZstdChecksumWrong,
    ZstdLiteralsHeaderWrong,
    ZstdDictionaryCorrupted,
    ZstdDictionaryWrong,
    ZstdDictionaryCreationFailed,
    ZstdParameterUnsupported,
    ZstdParameterCombinationUnsupported,
    ZstdParameterOutOfBounds,
    ZstdTableLogTooLarge,
    ZstdMaxSymbolValueTooLarge,
    ZstdMaxSymbolValueTooSmall,
    ZstdCannotProduceUncompressedBlock,
    ZstdStabilityConditionNotRespected,
    ZstdStageWrong,
    ZstdInitMissing,
    ZstdMemoryAllocation,
    ZstdWorkspaceTooSmall,
    ZstdDestinationTooSmall,
    ZstdSourceSizeWrong,
    ZstdDestinationBufferNull,
    ZstdNoForwardProgressDestinationFull,
    ZstdNoForwardProgressInputEmpty,
    ZstdFrameIndexTooLarge,
    ZstdSeekableIo,
    ZstdDestinationBufferWrong,
    ZstdSourceBufferWrong,
    ZstdSequenceProducerFailed,
    ZstdExternalSequencesInvalid,
    ZstdUnknownError,
    ZstdUnavailable,
};

pub const Error = std.Io.Writer.Error || ZstdError || error{
    BlockTooLarge,
    EmptyBlockBuffer,
    ContentSizeExceeded,
    ContentSizeMismatch,
    EncoderFinished,
};

pub const DecodeError = std.mem.Allocator.Error || ZstdError || error{
    BadMagic,
    BadSkippableFrame,
    Truncated,
    DecompressionFailed,
};

pub const Compression = enum {
    compressed,
    raw,
};

/// Parameters for a streaming zstd frame. The pledged content size is
/// mandatory and is verified before the frame can be finished.
pub const EncoderOptions = struct {
    content_size: u64,
    skippable_payload: ?[skippable_payload_len]u8 = null,
    compression: Compression = .compressed,
};

/// A streaming encoder for one zstd frame.
///
/// `block_buffer` is caller-owned output scratch space and must remain alive
/// until `finish` or `deinit`. A successful `finish` releases the libzstd
/// context. Call `deinit` when abandoning an unfinished encoder.
pub const FrameEncoder = struct {
    writer: *std.Io.Writer,
    block_buffer: []u8,
    content_size: u64,
    written: u64 = 0,
    fill: usize = 0,
    compression: Compression,
    cctx: Context = null,
    finished: bool = false,

    pub fn init(
        writer: *std.Io.Writer,
        block_buffer: []u8,
        options: EncoderOptions,
    ) Error!FrameEncoder {
        if (block_buffer.len == 0) return error.EmptyBlockBuffer;
        const bounded_buffer = block_buffer[0..@min(block_buffer.len, max_block_size)];

        var cctx: Context = null;
        if (options.compression == .compressed) {
            if (builtin.link_libc) {
                const context = c.ZSTD_createCCtx() orelse return error.ZstdMemoryAllocation;
                errdefer _ = c.ZSTD_freeCCtx(context);

                _ = try checkZstd(c.ZSTD_CCtx_setParameter(
                    context,
                    c.ZSTD_c_compressionLevel,
                    compression_level,
                ));
                _ = try checkZstd(c.ZSTD_CCtx_setParameter(
                    context,
                    c.ZSTD_c_windowLog,
                    window_log,
                ));
                _ = try checkZstd(c.ZSTD_CCtx_setParameter(
                    context,
                    c.ZSTD_c_contentSizeFlag,
                    1,
                ));
                _ = try checkZstd(c.ZSTD_CCtx_setParameter(
                    context,
                    c.ZSTD_c_checksumFlag,
                    0,
                ));
                _ = try checkZstd(c.ZSTD_CCtx_setParameter(
                    context,
                    c.ZSTD_c_dictIDFlag,
                    0,
                ));
                _ = try checkZstd(c.ZSTD_CCtx_setParameter(
                    context,
                    c.ZSTD_c_nbWorkers,
                    0,
                ));
                _ = try checkZstd(c.ZSTD_CCtx_setPledgedSrcSize(
                    context,
                    @intCast(options.content_size),
                ));
                cctx = context;
            } else {
                return error.ZstdUnavailable;
            }
        }
        errdefer if (builtin.link_libc) {
            if (cctx) |context| {
                _ = c.ZSTD_freeCCtx(context);
            }
        };

        if (options.skippable_payload) |payload| try writeSkippableFrame(writer, payload);
        if (options.compression == .raw) try writeFrameHeader(writer, options.content_size);

        return .{
            .writer = writer,
            .block_buffer = bounded_buffer,
            .content_size = options.content_size,
            .compression = options.compression,
            .cctx = cctx,
        };
    }

    /// Adds exactly these uncompressed bytes to the frame. Writing beyond the
    /// pledged content size fails before mutating the frame.
    pub fn writeAll(self: *FrameEncoder, bytes: []const u8) Error!void {
        if (self.finished) return error.EncoderFinished;
        const count = std.math.cast(u64, bytes.len) orelse return error.ContentSizeExceeded;
        if (count > self.content_size - self.written) return error.ContentSizeExceeded;

        switch (self.compression) {
            .compressed => if (builtin.link_libc)
                try self.compressInput(bytes)
            else
                return error.ZstdUnavailable,
            .raw => self.bufferRaw(bytes) catch |err| {
                self.fail();
                return err;
            },
        }
        self.written += count;
    }

    /// Adds a zero run without requiring the caller to allocate it.
    pub fn writeZeroes(self: *FrameEncoder, count: u64) Error!void {
        if (self.finished) return error.EncoderFinished;
        if (count > self.content_size - self.written) return error.ContentSizeExceeded;

        var remaining = count;
        while (remaining > 0) {
            const take: usize = @intCast(@min(remaining, zero_chunk.len));
            switch (self.compression) {
                .compressed => if (builtin.link_libc)
                    try self.compressInput(zero_chunk[0..take])
                else
                    return error.ZstdUnavailable,
                .raw => self.bufferRaw(zero_chunk[0..take]) catch |err| {
                    self.fail();
                    return err;
                },
            }
            remaining -= take;
        }
        self.written += count;
    }

    /// Completes the frame only after exactly the pledged size was supplied.
    /// A size mismatch is recoverable: the caller may provide the missing
    /// bytes and call `finish` again.
    pub fn finish(self: *FrameEncoder) Error!void {
        if (self.finished) return error.EncoderFinished;
        if (self.written != self.content_size) return error.ContentSizeMismatch;

        switch (self.compression) {
            .compressed => if (builtin.link_libc)
                try self.finishCompressed()
            else
                return error.ZstdUnavailable,
            .raw => self.flushRawBlock(true) catch |err| {
                self.fail();
                return err;
            },
        }
        self.releaseContext();
        self.finished = true;
    }

    pub fn deinit(self: *FrameEncoder) void {
        self.releaseContext();
        self.finished = true;
    }

    fn compressInput(self: *FrameEncoder, bytes: []const u8) Error!void {
        if (bytes.len == 0) return;
        var input: c.ZSTD_inBuffer = .{
            .src = bytes.ptr,
            .size = bytes.len,
            .pos = 0,
        };
        while (input.pos < input.size) {
            _ = try self.compressStream(&input, c.ZSTD_e_continue);
        }
    }

    fn finishCompressed(self: *FrameEncoder) Error!void {
        var input: c.ZSTD_inBuffer = .{
            .src = null,
            .size = 0,
            .pos = 0,
        };
        while (true) {
            const remaining = try self.compressStream(&input, c.ZSTD_e_end);
            if (remaining == 0) return;
        }
    }

    fn compressStream(
        self: *FrameEncoder,
        input: *c.ZSTD_inBuffer,
        directive: c.ZSTD_EndDirective,
    ) Error!usize {
        var output: c.ZSTD_outBuffer = .{
            .dst = self.block_buffer.ptr,
            .size = self.block_buffer.len,
            .pos = 0,
        };
        const result = c.ZSTD_compressStream2(self.cctx.?, &output, input, directive);
        const remaining = checkZstd(result) catch |err| {
            self.fail();
            return err;
        };
        self.writer.writeAll(self.block_buffer[0..output.pos]) catch |err| {
            self.fail();
            return err;
        };
        return remaining;
    }

    fn bufferRaw(self: *FrameEncoder, bytes: []const u8) Error!void {
        var remaining = bytes;
        while (remaining.len > 0) {
            if (self.fill == self.block_buffer.len) try self.flushRawBlock(false);
            const take = @min(remaining.len, self.block_buffer.len - self.fill);
            @memcpy(self.block_buffer[self.fill..][0..take], remaining[0..take]);
            self.fill += take;
            remaining = remaining[take..];
        }
    }

    fn flushRawBlock(self: *FrameEncoder, is_last: bool) Error!void {
        try writeRawBlock(self.writer, self.block_buffer[0..self.fill], is_last);
        self.fill = 0;
    }

    fn fail(self: *FrameEncoder) void {
        self.releaseContext();
        self.finished = true;
    }

    fn releaseContext(self: *FrameEncoder) void {
        if (builtin.link_libc) {
            if (self.cctx) |context| {
                _ = c.ZSTD_freeCCtx(context);
                self.cctx = null;
            }
        } else {
            self.cctx = null;
        }
    }
};

pub fn frameHeaderSize() usize {
    return 4 + 1 + 8;
}

/// Strict upper bound for one compressed libzstd frame with the pinned
/// settings, optionally including this module's leading skippable frame.
pub fn compressionBound(
    uncompressed_size: u64,
    include_skippable: bool,
) error{ SizeOverflow, ZstdUnavailable }!u64 {
    if (builtin.link_libc) {
        const source_size = std.math.cast(usize, uncompressed_size) orelse
            return error.SizeOverflow;
        const bound = c.ZSTD_compressBound(source_size);
        if (c.ZSTD_isError(bound) != 0) return error.SizeOverflow;

        const prefix: u64 = if (include_skippable)
            8 + @as(u64, skippable_payload_len)
        else
            0;
        return std.math.add(u64, @intCast(bound), prefix) catch error.SizeOverflow;
    }
    return error.ZstdUnavailable;
}

/// Strict upper bound for either encoder mode when raw frames use blocks no
/// larger than `block_size`.
pub fn maxEncodedSizeForBlockSize(
    uncompressed_size: u64,
    block_size: usize,
    include_skippable: bool,
) error{SizeOverflow}!u64 {
    const raw_bound = try rawEncodedSizeForBlockSize(
        uncompressed_size,
        block_size,
        include_skippable,
    );
    if (!builtin.link_libc) return raw_bound;
    const compressed_bound = compressionBound(uncompressed_size, include_skippable) catch
        return error.SizeOverflow;
    return @max(compressed_bound, raw_bound);
}

/// Strict upper bound for either encoder mode with a full
/// `max_block_size` scratch buffer.
pub fn maxEncodedSize(
    uncompressed_size: u64,
    include_skippable: bool,
) error{SizeOverflow}!u64 {
    return maxEncodedSizeForBlockSize(
        uncompressed_size,
        max_block_size,
        include_skippable,
    );
}

fn rawEncodedSizeForBlockSize(
    uncompressed_size: u64,
    block_size: usize,
    include_skippable: bool,
) error{SizeOverflow}!u64 {
    if (block_size == 0 or block_size > max_block_size) return error.SizeOverflow;
    const blocks = @max(
        @as(u64, 1),
        std.math.divCeil(u64, uncompressed_size, block_size) catch
            return error.SizeOverflow,
    );
    const block_headers = std.math.mul(u64, blocks, 3) catch
        return error.SizeOverflow;
    const skippable_size: u64 = if (include_skippable)
        8 + @as(u64, skippable_payload_len)
    else
        0;
    const prefix = std.math.add(
        u64,
        skippable_size,
        @intCast(frameHeaderSize()),
    ) catch return error.SizeOverflow;
    const with_headers = std.math.add(u64, prefix, block_headers) catch
        return error.SizeOverflow;
    return std.math.add(u64, with_headers, uncompressed_size) catch
        error.SizeOverflow;
}

fn writeSkippableFrame(
    writer: *std.Io.Writer,
    payload: [skippable_payload_len]u8,
) Error!void {
    var header: [8]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], skippable_magic, .little);
    std.mem.writeInt(u32, header[4..8], skippable_payload_len, .little);
    try writer.writeAll(&header);
    try writer.writeAll(&payload);
}

fn writeFrameHeader(writer: *std.Io.Writer, uncompressed_size: u64) Error!void {
    var header: [frameHeaderSize()]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], zstd_magic, .little);
    header[4] = 0xE0;
    std.mem.writeInt(u64, header[5..13], uncompressed_size, .little);
    try writer.writeAll(&header);
}

fn writeBlockHeader(
    writer: *std.Io.Writer,
    block_type: u2,
    block_size: usize,
    is_last: bool,
) Error!void {
    if (block_size > max_block_size) return error.BlockTooLarge;
    const header_value: u32 =
        (@as(u32, @intCast(block_size)) << 3) |
        (@as(u32, block_type) << 1) |
        @as(u32, @intFromBool(is_last));
    const header: [3]u8 = .{
        @truncate(header_value),
        @truncate(header_value >> 8),
        @truncate(header_value >> 16),
    };
    try writer.writeAll(&header);
}

fn writeRawBlock(
    writer: *std.Io.Writer,
    bytes: []const u8,
    is_last: bool,
) Error!void {
    try writeBlockHeader(writer, 0, bytes.len, is_last);
    try writer.writeAll(bytes);
}

pub fn writeRawFrameForSlice(
    writer: *std.Io.Writer,
    bytes: []const u8,
    payload: ?[skippable_payload_len]u8,
) Error!void {
    var block_buffer: [max_block_size]u8 = undefined;
    var encoder = try FrameEncoder.init(writer, &block_buffer, .{
        .content_size = bytes.len,
        .skippable_payload = payload,
        .compression = .raw,
    });
    defer encoder.deinit();
    try encoder.writeAll(bytes);
    try encoder.finish();
}

pub fn writeFrameForSlice(
    writer: *std.Io.Writer,
    bytes: []const u8,
    payload: ?[skippable_payload_len]u8,
) Error!void {
    var block_buffer: [max_block_size]u8 = undefined;
    var encoder = try FrameEncoder.init(writer, &block_buffer, .{
        .content_size = bytes.len,
        .skippable_payload = payload,
    });
    defer encoder.deinit();
    try encoder.writeAll(bytes);
    try encoder.finish();
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= 4);
    return std.mem.readInt(u32, bytes[0..4], .little);
}

pub const Decoded = struct {
    payload: ?[skippable_payload_len]u8,
    bytes: []u8,
};

pub fn decodeAlloc(
    allocator: std.mem.Allocator,
    encoded: []const u8,
) DecodeError!Decoded {
    var offset: usize = 0;
    var payload: ?[skippable_payload_len]u8 = null;

    if (encoded.len >= 8) {
        const maybe_magic = readU32Le(encoded[0..4]);
        if (maybe_magic >= skippable_magic and maybe_magic <= skippable_magic + 0xF) {
            const frame_size: usize = readU32Le(encoded[4..8]);
            if (frame_size != skippable_payload_len) return error.BadSkippableFrame;
            if (encoded.len < 8 + frame_size) return error.Truncated;
            var extracted: [skippable_payload_len]u8 = undefined;
            @memcpy(&extracted, encoded[8 .. 8 + frame_size]);
            payload = extracted;
            offset = 8 + frame_size;
        }
    }

    if (encoded.len < offset + 4) return error.Truncated;
    if (readU32Le(encoded[offset .. offset + 4]) != zstd_magic) {
        return error.BadMagic;
    }

    return .{
        .payload = payload,
        .bytes = try decodeFrameAlloc(allocator, encoded[offset..]),
    };
}

fn decodeFrameAlloc(
    allocator: std.mem.Allocator,
    frame: []const u8,
) DecodeError![]u8 {
    if (builtin.link_libc) return decodeFrameAllocLinked(allocator, frame);
    return error.ZstdUnavailable;
}

fn decodeFrameAllocLinked(
    allocator: std.mem.Allocator,
    frame: []const u8,
) DecodeError![]u8 {
    const context = c.ZSTD_createDCtx() orelse return error.ZstdMemoryAllocation;
    defer _ = c.ZSTD_freeDCtx(context);

    var decoded = std.Io.Writer.Allocating.init(allocator);
    errdefer decoded.deinit();

    var input: c.ZSTD_inBuffer = .{
        .src = frame.ptr,
        .size = frame.len,
        .pos = 0,
    };
    var scratch: [max_block_size]u8 = undefined;
    var remaining: usize = 1;

    while (input.pos < input.size or remaining != 0) {
        const input_pos = input.pos;
        var output: c.ZSTD_outBuffer = .{
            .dst = &scratch,
            .size = scratch.len,
            .pos = 0,
        };
        remaining = try checkZstd(c.ZSTD_decompressStream(
            context,
            &output,
            &input,
        ));
        decoded.writer.writeAll(scratch[0..output.pos]) catch
            return error.OutOfMemory;

        if (input.pos == input_pos and output.pos == 0) {
            if (input.pos == input.size) return error.Truncated;
            return error.DecompressionFailed;
        }
    }

    return try decoded.toOwnedSlice();
}

fn checkZstd(result: usize) ZstdError!usize {
    if (c.ZSTD_isError(result) == 0) return result;
    return mapZstdError(c.ZSTD_getErrorCode(result));
}

fn mapZstdError(code: c.ZSTD_ErrorCode) ZstdError {
    return switch (code) {
        c.ZSTD_error_GENERIC => error.ZstdGeneric,
        c.ZSTD_error_prefix_unknown => error.ZstdPrefixUnknown,
        c.ZSTD_error_version_unsupported => error.ZstdVersionUnsupported,
        c.ZSTD_error_frameParameter_unsupported => error.ZstdFrameParameterUnsupported,
        c.ZSTD_error_frameParameter_windowTooLarge => error.ZstdWindowTooLarge,
        c.ZSTD_error_corruption_detected => error.ZstdCorruptionDetected,
        c.ZSTD_error_checksum_wrong => error.ZstdChecksumWrong,
        c.ZSTD_error_literals_headerWrong => error.ZstdLiteralsHeaderWrong,
        c.ZSTD_error_dictionary_corrupted => error.ZstdDictionaryCorrupted,
        c.ZSTD_error_dictionary_wrong => error.ZstdDictionaryWrong,
        c.ZSTD_error_dictionaryCreation_failed => error.ZstdDictionaryCreationFailed,
        c.ZSTD_error_parameter_unsupported => error.ZstdParameterUnsupported,
        c.ZSTD_error_parameter_combination_unsupported => error.ZstdParameterCombinationUnsupported,
        c.ZSTD_error_parameter_outOfBound => error.ZstdParameterOutOfBounds,
        c.ZSTD_error_tableLog_tooLarge => error.ZstdTableLogTooLarge,
        c.ZSTD_error_maxSymbolValue_tooLarge => error.ZstdMaxSymbolValueTooLarge,
        c.ZSTD_error_maxSymbolValue_tooSmall => error.ZstdMaxSymbolValueTooSmall,
        c.ZSTD_error_cannotProduce_uncompressedBlock => error.ZstdCannotProduceUncompressedBlock,
        c.ZSTD_error_stabilityCondition_notRespected => error.ZstdStabilityConditionNotRespected,
        c.ZSTD_error_stage_wrong => error.ZstdStageWrong,
        c.ZSTD_error_init_missing => error.ZstdInitMissing,
        c.ZSTD_error_memory_allocation => error.ZstdMemoryAllocation,
        c.ZSTD_error_workSpace_tooSmall => error.ZstdWorkspaceTooSmall,
        c.ZSTD_error_dstSize_tooSmall => error.ZstdDestinationTooSmall,
        c.ZSTD_error_srcSize_wrong => error.ZstdSourceSizeWrong,
        c.ZSTD_error_dstBuffer_null => error.ZstdDestinationBufferNull,
        c.ZSTD_error_noForwardProgress_destFull => error.ZstdNoForwardProgressDestinationFull,
        c.ZSTD_error_noForwardProgress_inputEmpty => error.ZstdNoForwardProgressInputEmpty,
        c.ZSTD_error_frameIndex_tooLarge => error.ZstdFrameIndexTooLarge,
        c.ZSTD_error_seekableIO => error.ZstdSeekableIo,
        c.ZSTD_error_dstBuffer_wrong => error.ZstdDestinationBufferWrong,
        c.ZSTD_error_srcBuffer_wrong => error.ZstdSourceBufferWrong,
        c.ZSTD_error_sequenceProducer_failed => error.ZstdSequenceProducerFailed,
        c.ZSTD_error_externalSequences_invalid => error.ZstdExternalSequencesInvalid,
        else => error.ZstdUnknownError,
    };
}

fn expectLibZstdDecode(
    encoded: []const u8,
    expected: []const u8,
    payload: ?[skippable_payload_len]u8,
) !void {
    const decoded = try decodeAlloc(std.testing.allocator, encoded);
    defer std.testing.allocator.free(decoded.bytes);
    try std.testing.expectEqual(payload, decoded.payload);
    try std.testing.expectEqualSlices(u8, expected, decoded.bytes);
}

fn writeAndCheck(
    input: []const u8,
    payload: ?[skippable_payload_len]u8,
) ![]u8 {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    errdefer out.deinit();
    try writeFrameForSlice(&out.writer, input, payload);
    return try out.toOwnedSlice();
}

test "compressed frame shrinks zeros and round-trips through linked libzstd" {
    var input: [max_block_size]u8 = undefined;
    @memset(&input, 0);

    const payload: [skippable_payload_len]u8 =
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const encoded = try writeAndCheck(&input, payload);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len < input.len / 100);
    try expectLibZstdDecode(encoded, &input, payload);
}

test "compressed frame shrinks repeated text and round-trips" {
    const input = ("The quick brown fox jumps over the lazy dog.\n" ** 2048);
    const encoded = try writeAndCheck(input[0..], null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len < input.len / 10);
    try expectLibZstdDecode(encoded, input[0..], null);
}

test "compressed frame shrinks mixed repeated and noisy data" {
    var noise: [8192]u8 = undefined;
    var x: u32 = 0x1234_5678;
    for (&noise) |*byte| {
        x = x *% 1664525 +% 1013904223;
        byte.* = @truncate(x >> 24);
    }

    const repeated = "root=/dev/dm-0 ro quiet splash console=ttyS0\n" ** 512;
    var input: [repeated.len + noise.len + repeated.len]u8 = undefined;
    @memcpy(input[0..repeated.len], repeated[0..]);
    @memcpy(input[repeated.len .. repeated.len + noise.len], &noise);
    @memcpy(input[repeated.len + noise.len ..], repeated[0..]);

    const encoded = try writeAndCheck(&input, null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len < input.len - 2048);
    try expectLibZstdDecode(encoded, &input, null);
}

test "pinned compression is repeatable" {
    const input = ("repeatable zstd output\n" ** 4096);
    const first = try writeAndCheck(input, null);
    defer std.testing.allocator.free(first);
    const second = try writeAndCheck(input, null);
    defer std.testing.allocator.free(second);

    try std.testing.expectEqualSlices(u8, first, second);
}

test "compressed frame advertises content size without checksum or dictionary id" {
    const input = "pinned frame metadata" ** 32;
    const encoded = try writeAndCheck(input, null);
    defer std.testing.allocator.free(encoded);

    const descriptor = encoded[4];
    try std.testing.expectEqual(@as(u8, 0), descriptor & 0x04);
    try std.testing.expectEqual(@as(u8, 0), descriptor & 0x03);
    try std.testing.expectEqual(
        @as(c_ulonglong, input.len),
        c.ZSTD_getFrameContentSize(encoded.ptr, encoded.len),
    );
}

test "empty input emits a valid empty frame" {
    const encoded = try writeAndCheck("", null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len <= try compressionBound(0, false));
    try expectLibZstdDecode(encoded, "", null);
}

test "native raw frame interoperates with linked libzstd decoder" {
    const input = "hello zstd raw blocks" ** 4096;

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    const payload: [skippable_payload_len]u8 =
        .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try writeRawFrameForSlice(&out.writer, input[0..], payload);
    try std.testing.expect(
        out.written().len <= try maxEncodedSize(input.len, true),
    );
    try expectLibZstdDecode(out.written(), input[0..], payload);
}

test "streaming encoder preserves data across bounded writes" {
    var input: [max_block_size + 501]u8 = undefined;
    var value: u32 = 0x1234_5678;
    for (&input) |*byte| {
        value = value *% 1664525 +% 1013904223;
        byte.* = @truncate(value >> 24);
    }

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var block_buffer: [4096]u8 = undefined;
    var encoder = try FrameEncoder.init(&out.writer, &block_buffer, .{
        .content_size = input.len,
    });
    defer encoder.deinit();

    var offset: usize = 0;
    while (offset < input.len) {
        const chunk_len = @min(@as(usize, 733), input.len - offset);
        try encoder.writeAll(input[offset .. offset + chunk_len]);
        offset += chunk_len;
    }
    try encoder.finish();
    try std.testing.expectError(error.EncoderFinished, encoder.writeAll(""));
    try std.testing.expect(
        out.written().len <=
            try maxEncodedSizeForBlockSize(input.len, block_buffer.len, false),
    );
    try std.testing.expect(
        out.written().len <= try compressionBound(input.len, false),
    );
    try expectLibZstdDecode(out.written(), &input, null);
}

test "streaming encoder requires exact pledged content size" {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();
    var block_buffer: [8]u8 = undefined;
    var encoder = try FrameEncoder.init(&out.writer, &block_buffer, .{
        .content_size = 4,
        .compression = .raw,
    });
    defer encoder.deinit();

    try encoder.writeAll("a");
    try std.testing.expectError(error.ContentSizeMismatch, encoder.finish());
    try std.testing.expectError(error.ContentSizeExceeded, encoder.writeAll("bcde"));
    try std.testing.expectError(error.ContentSizeExceeded, encoder.writeZeroes(4));
    try encoder.writeZeroes(2);
    try encoder.writeAll("d");
    try encoder.finish();
    try expectLibZstdDecode(out.written(), "a\x00\x00d", null);
}

test "streaming encoder rejects empty buffers and size overflow" {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    try std.testing.expectError(error.EmptyBlockBuffer, FrameEncoder.init(
        &out.writer,
        &.{},
        .{ .content_size = 0 },
    ));
    try std.testing.expectEqual(@as(usize, 0), out.written().len);
    try std.testing.expectError(
        error.SizeOverflow,
        compressionBound(std.math.maxInt(u64), false),
    );
}

test "compression bound includes optional skippable frame" {
    const plain = try compressionBound(4096, false);
    const with_payload = try compressionBound(4096, true);
    try std.testing.expectEqual(
        plain + 8 + skippable_payload_len,
        with_payload,
    );
}
