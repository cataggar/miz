//! Small Zstandard encoder/decoder support for COSI output.
//!
//! Implemented encoder subset:
//! - optional leading skippable frame carrying a 16-byte image identifier,
//! - a single-segment zstd frame,
//! - raw blocks as a fallback path,
//! - compressed blocks that use:
//!   - raw literals sections,
//!   - a single LZ77 back-reference sequence per compressed block,
//!   - RLE sequence coding mode for literal-length, offset-code, and
//!     match-length symbols (so no per-block FSE tables are emitted).
//!
//! This is intentionally much smaller than a full zstd encoder: it does not yet
//! implement Huffman-compressed literals, multi-sequence/FSE-coded blocks,
//! dictionaries, or frame checksums. Even so, it produces real, spec-compliant
//! zstd frames that meaningfully shrink highly repetitive data such as zeroed
//! regions and repeated file content while remaining decodable by both Zig's
//! stdlib zstd decoder and the real `zstd` CLI.

const std = @import("std");
const spec = std.compress.zstd;

pub const zstd_magic: u32 = 0xFD2F_B528;
pub const skippable_magic: u32 = 0x184D_2A50;
pub const skippable_payload_len: u32 = 16;
pub const max_block_size: usize = 128 * 1024;

const min_match_len: usize = 4;
const max_supported_match_len: usize = 65_538;
const hash_table_size: usize = 1 << 15;
const invalid_pos = std.math.maxInt(u32);

pub const Error = std.Io.Writer.Error || error{
    BlockTooLarge,
};

pub const DecodeError = std.mem.Allocator.Error || error{
    BadMagic,
    BadSkippableFrame,
    Truncated,
    DecompressionFailed,
};

const Match = struct {
    start: usize,
    len: usize,
    offset: usize,
    compressed_size: usize,
    raw_size: usize,
};

const Code = struct {
    symbol: u8,
    extra_bits: u5,
    extra_value: u32,
};

const Bitstream = struct {
    bytes: [8]u8,
    len: usize,

    fn slice(self: *const Bitstream) []const u8 {
        return self.bytes[0..self.len];
    }
};

pub fn frameHeaderSize() usize {
    return 4 + 1 + 8;
}

/// Worst-case size for this module's frame writer, assuming every block falls
/// back to raw storage.
pub fn encodedSize(uncompressed_size: u64, include_skippable: bool) u64 {
    const blocks = @max(@as(u64, 1), std.math.divCeil(u64, uncompressed_size, max_block_size) catch unreachable);
    return (if (include_skippable) 8 + skippable_payload_len else 0) + frameHeaderSize() + blocks * 3 + uncompressed_size;
}

pub fn writeSkippableFrame(writer: *std.Io.Writer, payload: [skippable_payload_len]u8) Error!void {
    var header: [8]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], skippable_magic, .little);
    std.mem.writeInt(u32, header[4..8], skippable_payload_len, .little);
    try writer.writeAll(&header);
    try writer.writeAll(&payload);
}

pub fn writeFrameHeader(writer: *std.Io.Writer, uncompressed_size: u64) Error!void {
    var header: [frameHeaderSize()]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], zstd_magic, .little);
    header[4] = 0xE0; // FCS=8 bytes, single-segment, no checksum/dict.
    std.mem.writeInt(u64, header[5..13], uncompressed_size, .little);
    try writer.writeAll(&header);
}

fn writeBlockHeader(writer: *std.Io.Writer, block_type: u2, block_size: usize, is_last: bool) Error!void {
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

pub fn writeRawBlock(writer: *std.Io.Writer, bytes: []const u8, is_last: bool) Error!void {
    try writeBlockHeader(writer, 0, bytes.len, is_last);
    try writer.writeAll(bytes);
}

pub fn writeRawFrameForSlice(writer: *std.Io.Writer, bytes: []const u8, payload: ?[skippable_payload_len]u8) Error!void {
    if (payload) |p| try writeSkippableFrame(writer, p);
    try writeFrameHeader(writer, bytes.len);

    if (bytes.len == 0) {
        try writeRawBlock(writer, &.{}, true);
        return;
    }

    var offset: usize = 0;
    while (offset < bytes.len) {
        const remaining = bytes.len - offset;
        const chunk_len = @min(remaining, max_block_size);
        const is_last = offset + chunk_len == bytes.len;
        try writeRawBlock(writer, bytes[offset .. offset + chunk_len], is_last);
        offset += chunk_len;
    }
}

pub fn writeBlocksForSlice(writer: *std.Io.Writer, bytes: []const u8, is_last_chunk: bool) Error!void {
    std.debug.assert(bytes.len <= max_block_size);

    if (bytes.len == 0) {
        if (is_last_chunk) try writeRawBlock(writer, &.{}, true);
        return;
    }

    var cursor: usize = 0;
    while (cursor < bytes.len) {
        if (findBestMatch(bytes, cursor)) |match| {
            try writeSingleSequenceBlock(
                writer,
                bytes[cursor .. match.start + match.len],
                match.start - cursor,
                match.len,
                match.offset,
                is_last_chunk and match.start + match.len == bytes.len,
            );
            cursor = match.start + match.len;
            continue;
        }

        try writeRawBlock(writer, bytes[cursor..], is_last_chunk);
        break;
    }
}

pub fn writeFrameForSlice(writer: *std.Io.Writer, bytes: []const u8, payload: ?[skippable_payload_len]u8) Error!void {
    if (payload) |p| try writeSkippableFrame(writer, p);
    try writeFrameHeader(writer, bytes.len);

    if (bytes.len == 0) {
        try writeRawBlock(writer, &.{}, true);
        return;
    }

    var offset: usize = 0;
    while (offset < bytes.len) {
        const remaining = bytes.len - offset;
        const chunk_len = @min(remaining, max_block_size);
        try writeBlocksForSlice(writer, bytes[offset .. offset + chunk_len], offset + chunk_len == bytes.len);
        offset += chunk_len;
    }
}

fn findBestMatch(bytes: []const u8, cursor: usize) ?Match {
    if (bytes.len < cursor + min_match_len + 1) return null;

    var table = [_]u32{invalid_pos} ** hash_table_size;
    var preload: usize = 0;
    while (preload < cursor and preload + min_match_len <= bytes.len) : (preload += 1) {
        table[hash4(bytes[preload .. preload + 4])] = @intCast(preload);
    }

    var best: ?Match = null;
    var pos = cursor;
    while (pos + min_match_len <= bytes.len) : (pos += 1) {
        const hash = hash4(bytes[pos .. pos + 4]);
        const candidate_u32 = table[hash];
        table[hash] = @intCast(pos);
        if (candidate_u32 == invalid_pos) continue;

        const candidate: usize = candidate_u32;
        if (candidate >= pos) continue;
        if (!std.mem.eql(u8, bytes[candidate .. candidate + 4], bytes[pos .. pos + 4])) continue;

        const offset = pos - candidate;
        const match_len = @min(matchLength(bytes, candidate, pos), max_supported_match_len);
        if (match_len < min_match_len) continue;

        const literal_len = pos - cursor;
        const raw_size = literal_len + match_len;
        const compressed_size = estimateSingleSequenceBlockSize(literal_len, match_len, offset);
        if (compressed_size >= raw_size) continue;

        const gain = raw_size - compressed_size;
        if (best == null or gain > best.?.raw_size - best.?.compressed_size or (gain == best.?.raw_size - best.?.compressed_size and match_len > best.?.len)) {
            best = .{
                .start = pos,
                .len = match_len,
                .offset = offset,
                .compressed_size = compressed_size,
                .raw_size = raw_size,
            };
            if (match_len == max_supported_match_len or pos + match_len == bytes.len) return best;
        }
    }

    return best;
}

fn hash4(bytes: []const u8) usize {
    std.debug.assert(bytes.len >= 4);
    const value = std.mem.readInt(u32, bytes[0..4], .little);
    return @as(usize, (value *% 0x9E37_79B1) >> (32 - 15));
}

fn matchLength(bytes: []const u8, candidate: usize, pos: usize) usize {
    const offset = pos - candidate;
    var len: usize = 0;
    while (pos + len < bytes.len and bytes[pos + len - offset] == bytes[pos + len]) {
        len += 1;
    }
    return len;
}

fn estimateSingleSequenceBlockSize(literal_len: usize, match_len: usize, offset: usize) usize {
    const literal_code = lengthCode(literal_len, &spec.literals_length_code_table);
    const match_code = lengthCode(match_len, &spec.match_length_code_table);
    const offset_code = offsetCode(offset);
    const bit_count: usize = @as(usize, offset_code.extra_bits) + @as(usize, match_code.extra_bits) + @as(usize, literal_code.extra_bits);
    const sequence_section_len = 1 + 1 + 3 + reverseBitstreamByteCount(bit_count);
    return rawLiteralsSectionHeaderSize(literal_len) + literal_len + sequence_section_len;
}

fn writeSingleSequenceBlock(
    writer: *std.Io.Writer,
    bytes: []const u8,
    literal_len: usize,
    match_len: usize,
    offset: usize,
    is_last: bool,
) Error!void {
    const literal_code = lengthCode(literal_len, &spec.literals_length_code_table);
    const match_code = lengthCode(match_len, &spec.match_length_code_table);
    const offset_code = offsetCode(offset);

    var content: [max_block_size]u8 = undefined;
    var content_writer: std.Io.Writer = .fixed(&content);

    try writeRawLiteralsSection(&content_writer, bytes[0..literal_len]);
    try content_writer.writeByte(1); // one sequence
    try content_writer.writeByte(0x54); // RLE modes for LL/OF/ML, reserved bits clear
    try content_writer.writeByte(literal_code.symbol);
    try content_writer.writeByte(offset_code.symbol);
    try content_writer.writeByte(match_code.symbol);

    const bitstream = encodeSingleSequenceBitstream(literal_code, match_code, offset_code);
    try content_writer.writeAll(bitstream.slice());

    const block_content = content_writer.buffered();
    try writeBlockHeader(writer, 2, block_content.len, is_last);
    try writer.writeAll(block_content);
}

fn writeRawLiteralsSection(writer: *std.Io.Writer, literals: []const u8) Error!void {
    if (literals.len <= 31) {
        try writer.writeByte(@intCast(literals.len << 3));
    } else if (literals.len <= 4095) {
        try writer.writeByte(@intCast(((literals.len & 0xF) << 4) | 0x04));
        try writer.writeByte(@intCast(literals.len >> 4));
    } else {
        try writer.writeByte(@intCast(((literals.len & 0xF) << 4) | 0x0C));
        try writer.writeByte(@intCast((literals.len >> 4) & 0xFF));
        try writer.writeByte(@intCast((literals.len >> 12) & 0xFF));
    }
    try writer.writeAll(literals);
}

fn rawLiteralsSectionHeaderSize(literal_len: usize) usize {
    return if (literal_len <= 31) 1 else if (literal_len <= 4095) 2 else 3;
}

fn lengthCode(len: usize, table: anytype) Code {
    var index = table.len - 1;
    while (index > 0 and table[index][0] > len) : (index -= 1) {}
    const base = table[index][0];
    const extra_bits = table[index][1];
    return .{
        .symbol = @intCast(index),
        .extra_bits = extra_bits,
        .extra_value = @intCast(len - base),
    };
}

fn offsetCode(offset: usize) Code {
    const value = offset + 3;
    const symbol: u8 = @intCast(std.math.log2_int(usize, value));
    return .{
        .symbol = symbol,
        .extra_bits = @intCast(symbol),
        .extra_value = @intCast(value - (@as(usize, 1) << @as(u6, @intCast(symbol)))),
    };
}

fn reverseBitstreamByteCount(bit_count: usize) usize {
    return bit_count / 8 + 1;
}

fn encodeSingleSequenceBitstream(literal_code: Code, match_code: Code, offset_code: Code) Bitstream {
    const total_bits: usize = @as(usize, offset_code.extra_bits) + @as(usize, match_code.extra_bits) + @as(usize, literal_code.extra_bits);
    var stream: u64 = 0;
    var bit_len: usize = 0;
    appendBits(&stream, &bit_len, offset_code.extra_value, offset_code.extra_bits);
    appendBits(&stream, &bit_len, match_code.extra_value, match_code.extra_bits);
    appendBits(&stream, &bit_len, literal_code.extra_value, literal_code.extra_bits);

    var out: Bitstream = .{ .bytes = undefined, .len = reverseBitstreamByteCount(total_bits) };
    @memset(out.bytes[0..out.len], 0);

    var remaining = bit_len;
    var out_index = out.len - 1;
    const prefix_bits = bit_len % 8;
    const prefix_value: u8 = if (prefix_bits == 0) 0 else @truncate(stream >> @intCast(bit_len - prefix_bits));
    out.bytes[out_index] = (@as(u8, 1) << @intCast(prefix_bits)) | prefix_value;
    if (prefix_bits != 0) remaining -= prefix_bits;

    while (remaining > 0) {
        out_index -= 1;
        remaining -= 8;
        out.bytes[out_index] = @truncate(stream >> @intCast(remaining));
    }

    return out;
}

fn appendBits(stream: *u64, bit_len: *usize, value: u32, count: u5) void {
    if (count == 0) return;
    stream.* = (stream.* << count) | value;
    bit_len.* += count;
}

fn readU32Le(bytes: []const u8) u32 {
    std.debug.assert(bytes.len >= 4);
    return @as(u32, bytes[0]) | (@as(u32, bytes[1]) << 8) | (@as(u32, bytes[2]) << 16) | (@as(u32, bytes[3]) << 24);
}

pub const Decoded = struct {
    payload: ?[skippable_payload_len]u8,
    bytes: []u8,
};

pub fn decodeAlloc(allocator: std.mem.Allocator, encoded: []const u8) DecodeError!Decoded {
    var offset: usize = 0;
    var payload: ?[skippable_payload_len]u8 = null;

    if (encoded.len >= 8) {
        const maybe_magic = readU32Le(encoded[0..4]);
        if (maybe_magic >= skippable_magic and maybe_magic <= skippable_magic + 0xF) {
            const frame_size = readU32Le(encoded[4..8]);
            if (frame_size != skippable_payload_len) return error.BadSkippableFrame;
            if (encoded.len < 8 + frame_size) return error.Truncated;
            var tmp: [skippable_payload_len]u8 = undefined;
            @memcpy(&tmp, encoded[8 .. 8 + frame_size]);
            payload = tmp;
            offset = 8 + frame_size;
        }
    }

    if (encoded.len < offset + 4) return error.Truncated;
    if (readU32Le(encoded[offset .. offset + 4]) != zstd_magic) return error.BadMagic;

    var input: std.Io.Reader = .fixed(encoded[offset..]);
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    var decompressor = spec.Decompress.init(&input, &.{}, .{});
    _ = decompressor.reader.streamRemaining(&out.writer) catch return error.DecompressionFailed;

    return .{ .payload = payload, .bytes = try out.toOwnedSlice() };
}

fn decodeWithCli(allocator: std.mem.Allocator, data: []const u8) ![]u8 {
    const encoded_len = std.base64.standard.Encoder.calcSize(data.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, data);

    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{
            "sh",
            "-c",
            "printf '%s' \"$1\" | base64 -d | zstd -q -d -c",
            "sh",
            encoded,
        },
        .cwd = .{ .path = "." },
    });
    defer allocator.free(result.stderr);
    errdefer allocator.free(result.stdout);

    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }

    allocator.free(result.stdout);
    return error.ExternalDecompressionFailed;
}

fn expectCliAndLocalDecode(encoded: []const u8, expected: []const u8, payload: ?[skippable_payload_len]u8) !void {
    const cli_decoded = try decodeWithCli(std.testing.allocator, encoded);
    defer std.testing.allocator.free(cli_decoded);
    try std.testing.expectEqualSlices(u8, expected, cli_decoded);

    const decoded = try decodeAlloc(std.testing.allocator, encoded);
    defer std.testing.allocator.free(decoded.bytes);
    try std.testing.expectEqual(payload, decoded.payload);
    try std.testing.expectEqualSlices(u8, expected, decoded.bytes);
}

fn writeAndCheck(input: []const u8, payload: ?[skippable_payload_len]u8) ![]u8 {
    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    errdefer out.deinit();
    try writeFrameForSlice(&out.writer, input, payload);
    return try out.toOwnedSlice();
}

test "compressing frame shrinks zeros and round-trips via CLI and local decoder" {
    var input: [max_block_size]u8 = undefined;
    @memset(&input, 0);

    const payload: [skippable_payload_len]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    const encoded = try writeAndCheck(&input, payload);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len < input.len / 100);
    try expectCliAndLocalDecode(encoded, &input, payload);
}

test "compressing frame shrinks repeated text and round-trips" {
    const input = ("The quick brown fox jumps over the lazy dog.\n" ** 2048);
    const encoded = try writeAndCheck(input[0..], null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len < input.len / 10);
    try expectCliAndLocalDecode(encoded, input[0..], null);
}

test "compressing frame shrinks mixed repeated and noisy data" {
    var noise: [8192]u8 = undefined;
    var x: u32 = 0x1234_5678;
    for (&noise) |*byte| {
        x = x *% 1664525 +% 1013904223;
        byte.* = @truncate(x >> 24);
    }

    const repeated = "root=/dev/dm-0 ro quiet splash console=ttyS0\n" ** 512;
    var input_buf: [repeated.len + noise.len + repeated.len]u8 = undefined;
    @memcpy(input_buf[0..repeated.len], repeated[0..]);
    @memcpy(input_buf[repeated.len .. repeated.len + noise.len], &noise);
    @memcpy(input_buf[repeated.len + noise.len ..], repeated[0..]);

    const encoded = try writeAndCheck(&input_buf, null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expect(encoded.len < input_buf.len - 2048);
    try expectCliAndLocalDecode(encoded, &input_buf, null);
}

test "empty input emits a valid empty frame" {
    const encoded = try writeAndCheck("", null);
    defer std.testing.allocator.free(encoded);

    try std.testing.expectEqual(encodedSize(0, false), encoded.len);
    try expectCliAndLocalDecode(encoded, "", null);
}

test "raw-frame encoder still round-trips via stdlib-backed decoder" {
    const input = "hello zstd raw blocks" ** 4096;

    var out = std.Io.Writer.Allocating.init(std.testing.allocator);
    defer out.deinit();

    const payload: [skippable_payload_len]u8 = .{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 };
    try writeRawFrameForSlice(&out.writer, input[0..], payload);
    try std.testing.expectEqual(encodedSize(input.len, true), out.written().len);
    try expectCliAndLocalDecode(out.written(), input[0..], payload);
}
