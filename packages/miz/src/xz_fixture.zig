//! Deterministic XZ container writer for tests.
//!
//! Nothing in this project compresses to xz, but the readers must handle it
//! because Azure Linux, Fedora and Debian ship kernel modules and SquashFS
//! images that way. Tests therefore need xz bytes without shelling out to an
//! external compressor, which would make coverage depend on whatever happens
//! to be installed on the machine running the suite.
//!
//! The encoder here writes a real `.xz` stream -- stream header, one block
//! with an LZMA2 filter, block padding, the check field, the index, and the
//! stream footer -- but the LZMA2 payload uses only uncompressed chunks, so
//! the output is slightly larger than its input. That is deliberate: the
//! container framing is exactly what production decoders parse, while the
//! entropy coder that would be needed to shrink the payload stays out of the
//! tree. `verifyStream` re-parses the result strictly, so the tests below can
//! prove the framing is well-formed rather than only that this file's writer
//! agrees with itself.

const std = @import("std");

const Crc32 = std.hash.Crc32;
const Crc64 = std.hash.crc.Crc64Xz;

pub const stream_magic = [6]u8{ 0xFD, '7', 'z', 'X', 'Z', 0x00 };
pub const footer_magic = [2]u8{ 'Y', 'Z' };

/// Largest payload an LZMA2 uncompressed chunk can carry.
pub const max_chunk_size: usize = 1 << 16;

/// Integrity check stored after each block, matching the xz check ids.
pub const Check = enum(u4) {
    none = 0x00,
    crc32 = 0x01,
    crc64 = 0x04,

    fn size(self: Check) usize {
        return switch (self) {
            .none => 0,
            .crc32 => 4,
            .crc64 => 8,
        };
    }
};

pub const Options = struct {
    check: Check = .crc32,
    /// Bytes per LZMA2 uncompressed chunk. Values above `max_chunk_size` are
    /// clamped; small values exist so tests can force multi-chunk blocks
    /// without allocating 64 KiB payloads.
    chunk_size: usize = max_chunk_size,
};

pub const VerifyError = error{
    Truncated,
    TrailingBytes,
    BadMagic,
    BadStreamFlags,
    BadStreamHeaderCrc,
    BadBlockHeader,
    BadBlockHeaderCrc,
    UnsupportedFilter,
    BadChunk,
    BadSizeField,
    PayloadMismatch,
    BadPadding,
    BadCheck,
    BadIndex,
    BadIndexCrc,
    BadFooter,
    BadFooterCrc,
};

/// Writes `payload` as a complete xz stream. An empty payload produces a
/// stream with no blocks, which is what real encoders emit for empty input.
pub fn writeStream(w: *std.Io.Writer, payload: []const u8, options: Options) std.Io.Writer.Error!void {
    const chunk_size = @max(@as(usize, 1), @min(options.chunk_size, max_chunk_size));
    const check_size = options.check.size();

    const stream_flags = [2]u8{ 0, @intFromEnum(options.check) };
    try w.writeAll(&stream_magic);
    try w.writeAll(&stream_flags);
    try w.writeInt(u32, Crc32.hash(&stream_flags), .little);

    var unpadded_size: u64 = 0;
    if (payload.len != 0) {
        const packed_size = lzma2PackedSize(payload.len, chunk_size);

        var header_buf: [max_block_header_size]u8 = undefined;
        const header = blockHeader(&header_buf, packed_size, payload.len);
        try w.writeAll(header);

        var offset: usize = 0;
        while (offset < payload.len) {
            const chunk = payload[offset..@min(offset + chunk_size, payload.len)];
            // Only the first chunk resets the dictionary; later chunks in the
            // same block continue it, exactly as a real LZMA2 stream does.
            try w.writeByte(if (offset == 0) 0x01 else 0x02);
            try w.writeInt(u16, @intCast(chunk.len - 1), .big);
            try w.writeAll(chunk);
            offset += chunk.len;
        }
        try w.writeByte(lzma2_end_marker);

        try w.splatByteAll(0, padding(header.len + packed_size));
        switch (options.check) {
            .none => {},
            .crc32 => try w.writeInt(u32, Crc32.hash(payload), .little),
            .crc64 => try w.writeInt(u64, Crc64.hash(payload), .little),
        }
        unpadded_size = header.len + packed_size + check_size;
    }

    var index_buf: [max_index_size]u8 = undefined;
    const index = buildIndex(&index_buf, if (payload.len == 0) null else .{
        .unpadded_size = unpadded_size,
        .uncompressed_size = payload.len,
    });
    try w.writeAll(index);

    var footer_buf: [6]u8 = undefined;
    std.mem.writeInt(u32, footer_buf[0..4], @intCast(index.len / 4 - 1), .little);
    footer_buf[4..6].* = stream_flags;
    try w.writeInt(u32, Crc32.hash(&footer_buf), .little);
    try w.writeAll(&footer_buf);
    try w.writeAll(&footer_magic);
}

/// Convenience wrapper around `writeStream` for callers that want a slice.
pub fn allocStream(gpa: std.mem.Allocator, payload: []const u8, options: Options) std.mem.Allocator.Error![]u8 {
    var out: std.Io.Writer.Allocating = try .initCapacity(gpa, payload.len + 128);
    errdefer out.deinit();
    writeStream(&out.writer, payload, options) catch |err| switch (err) {
        error.WriteFailed => return error.OutOfMemory,
    };
    return out.toOwnedSlice();
}

/// Strictly re-parses a stream produced by `writeStream`, checking every
/// length, checksum and padding field against `expected_payload`.
pub fn verifyStream(bytes: []const u8, expected_payload: []const u8) VerifyError!void {
    var cursor: Cursor = .{ .bytes = bytes };

    if (!std.mem.eql(u8, try cursor.take(stream_magic.len), &stream_magic)) return error.BadMagic;
    const stream_flags = try cursor.take(2);
    if (stream_flags[0] != 0) return error.BadStreamFlags;
    if (stream_flags[1] & 0xF0 != 0) return error.BadStreamFlags;
    const check: Check = switch (stream_flags[1] & 0x0F) {
        0x00 => .none,
        0x01 => .crc32,
        0x04 => .crc64,
        else => return error.BadStreamFlags,
    };
    if (try cursor.int(u32) != Crc32.hash(stream_flags)) return error.BadStreamHeaderCrc;

    var consumed: u64 = 0;
    var block_count: usize = 0;
    var record: ?Record = null;
    while ((try cursor.peek()) != index_indicator) {
        if (block_count != 0) return error.BadIndex;
        block_count += 1;
        record = try verifyBlock(&cursor, check, expected_payload, &consumed);
    }
    if (consumed != expected_payload.len) return error.PayloadMismatch;

    const index_start = cursor.pos;
    if (try cursor.byte() != index_indicator) return error.BadIndex;
    if (try cursor.uleb() != block_count) return error.BadIndex;
    if (record) |expected| {
        if (try cursor.uleb() != expected.unpadded_size) return error.BadIndex;
        if (try cursor.uleb() != expected.uncompressed_size) return error.BadIndex;
    }
    for (try cursor.take(padding(cursor.pos - index_start))) |byte| {
        if (byte != 0) return error.BadPadding;
    }
    const index_body = bytes[index_start..cursor.pos];
    if (try cursor.int(u32) != Crc32.hash(index_body)) return error.BadIndexCrc;
    const index_size = cursor.pos - index_start;

    const footer_crc = try cursor.int(u32);
    const footer_body = try cursor.take(6);
    if (footer_crc != Crc32.hash(footer_body)) return error.BadFooterCrc;
    const backward_size = (@as(u64, std.mem.readInt(u32, footer_body[0..4], .little)) + 1) * 4;
    if (backward_size != index_size) return error.BadFooter;
    if (!std.mem.eql(u8, footer_body[4..6], stream_flags)) return error.BadFooter;
    if (!std.mem.eql(u8, try cursor.take(2), &footer_magic)) return error.BadFooter;

    if (cursor.pos != bytes.len) return error.TrailingBytes;
}

const lzma2_filter_id: u64 = 0x21;
const lzma2_end_marker: u8 = 0x00;
const index_indicator: u8 = 0x00;
const max_block_header_size: usize = 32;
const max_index_size: usize = 32;

const Record = struct {
    unpadded_size: u64,
    uncompressed_size: u64,
};

fn padding(len: usize) usize {
    return (4 - (len % 4)) % 4;
}

fn lzma2PackedSize(payload_len: usize, chunk_size: usize) u64 {
    const chunk_count = std.math.divCeil(usize, payload_len, chunk_size) catch unreachable;
    return @as(u64, payload_len) + @as(u64, chunk_count) * 3 + 1;
}

/// Encodes the LZMA2 dictionary size property byte: the smallest size the
/// spec can express that still covers `payload_len`.
fn dictionarySizeByte(payload_len: usize) u8 {
    var bits: u8 = 0;
    while (bits < 40) : (bits += 1) {
        const size = (@as(u64, 2) | (bits & 1)) << @intCast(bits / 2 + 11);
        if (size >= payload_len) return bits;
    }
    return 40;
}

fn blockHeader(buf: *[max_block_header_size]u8, packed_size: u64, uncompressed_size: usize) []u8 {
    var writer = std.Io.Writer.fixed(buf[1..]);
    // Both size fields are declared so decoders cross-check the framing.
    writer.writeByte(0b1100_0000) catch unreachable;
    writer.writeUleb128(packed_size) catch unreachable;
    writer.writeUleb128(@as(u64, uncompressed_size)) catch unreachable;
    writer.writeUleb128(lzma2_filter_id) catch unreachable;
    writer.writeUleb128(@as(u64, 1)) catch unreachable;
    writer.writeByte(dictionarySizeByte(uncompressed_size)) catch unreachable;

    // The stored size counts everything but the trailing CRC32, so the whole
    // header occupies `(stored + 1) * 4` bytes.
    const body_size = std.mem.alignForward(usize, 1 + writer.end, 4);
    buf[0] = @intCast(body_size / 4);
    @memset(buf[1 + writer.end .. body_size], 0);
    std.mem.writeInt(u32, buf[body_size..][0..4], Crc32.hash(buf[0..body_size]), .little);
    return buf[0 .. body_size + 4];
}

fn buildIndex(buf: *[max_index_size]u8, record: ?Record) []u8 {
    var writer = std.Io.Writer.fixed(buf);
    writer.writeByte(index_indicator) catch unreachable;
    writer.writeUleb128(@as(u64, if (record == null) 0 else 1)) catch unreachable;
    if (record) |r| {
        writer.writeUleb128(r.unpadded_size) catch unreachable;
        writer.writeUleb128(r.uncompressed_size) catch unreachable;
    }
    const body_len = writer.end + padding(writer.end);
    @memset(buf[writer.end..body_len], 0);
    std.mem.writeInt(u32, buf[body_len..][0..4], Crc32.hash(buf[0..body_len]), .little);
    return buf[0 .. body_len + 4];
}

fn verifyBlock(cursor: *Cursor, check: Check, expected_payload: []const u8, consumed: *u64) VerifyError!Record {
    const header_start = cursor.pos;
    // The stored byte counts the header without its trailing CRC32.
    const declared_body_size = @as(usize, try cursor.byte()) * 4;
    if (declared_body_size == 0) return error.BadBlockHeader;
    const header_size = declared_body_size + 4;

    const flags = try cursor.byte();
    if (flags & 0b0011_1100 != 0) return error.BadBlockHeader;
    if (flags & 0b0000_0011 != 0) return error.UnsupportedFilter;
    const declared_packed_size = if (flags & 0b0100_0000 != 0) try cursor.uleb() else null;
    const declared_uncompressed_size = if (flags & 0b1000_0000 != 0) try cursor.uleb() else null;

    if (try cursor.uleb() != lzma2_filter_id) return error.UnsupportedFilter;
    if (try cursor.uleb() != 1) return error.BadBlockHeader;
    if (try cursor.byte() > 40) return error.BadBlockHeader;

    const header_used = cursor.pos - header_start;
    if (header_used > declared_body_size) return error.BadBlockHeader;
    for (try cursor.take(declared_body_size - header_used)) |byte| {
        if (byte != 0) return error.BadPadding;
    }
    const header_body = cursor.bytes[header_start .. header_start + declared_body_size];
    if (try cursor.int(u32) != Crc32.hash(header_body)) return error.BadBlockHeaderCrc;

    const data_start = cursor.pos;
    const block_start_consumed = consumed.*;
    var chunk_index: usize = 0;
    while (true) {
        const control = try cursor.byte();
        if (control == lzma2_end_marker) break;
        // A dictionary reset is required on the first chunk of a block and
        // forbidden afterwards; compressed chunks set the high bit.
        const expected_control: u8 = if (chunk_index == 0) 0x01 else 0x02;
        if (control != expected_control) return error.BadChunk;
        const chunk_len = @as(usize, try cursor.int(u16)) + 1;
        const chunk = try cursor.take(chunk_len);
        const remaining = expected_payload[@intCast(consumed.*)..];
        if (chunk.len > remaining.len) return error.PayloadMismatch;
        if (!std.mem.eql(u8, chunk, remaining[0..chunk.len])) return error.PayloadMismatch;
        consumed.* += chunk.len;
        chunk_index += 1;
    }
    const packed_size = cursor.pos - data_start;
    const uncompressed_size = consumed.* - block_start_consumed;
    if (uncompressed_size == 0) return error.BadChunk;
    if (declared_packed_size) |declared| {
        if (declared != packed_size) return error.BadSizeField;
    }
    if (declared_uncompressed_size) |declared| {
        if (declared != uncompressed_size) return error.BadSizeField;
    }

    for (try cursor.take(padding(header_size + packed_size))) |byte| {
        if (byte != 0) return error.BadPadding;
    }

    const block_payload = expected_payload[@intCast(block_start_consumed)..@intCast(consumed.*)];
    switch (check) {
        .none => {},
        .crc32 => if (try cursor.int(u32) != Crc32.hash(block_payload)) return error.BadCheck,
        .crc64 => if (try cursor.int(u64) != Crc64.hash(block_payload)) return error.BadCheck,
    }

    return .{
        .unpadded_size = header_size + packed_size + check.size(),
        .uncompressed_size = uncompressed_size,
    };
}

const Cursor = struct {
    bytes: []const u8,
    pos: usize = 0,

    fn take(self: *Cursor, len: usize) VerifyError![]const u8 {
        if (self.pos + len > self.bytes.len) return error.Truncated;
        defer self.pos += len;
        return self.bytes[self.pos..][0..len];
    }

    fn peek(self: *Cursor) VerifyError!u8 {
        if (self.pos >= self.bytes.len) return error.Truncated;
        return self.bytes[self.pos];
    }

    fn byte(self: *Cursor) VerifyError!u8 {
        return (try self.take(1))[0];
    }

    fn int(self: *Cursor, comptime T: type) VerifyError!T {
        const size = @divExact(@typeInfo(T).int.bits, 8);
        const slice = try self.take(size);
        return std.mem.readInt(T, slice[0..size], if (T == u16) .big else .little);
    }

    fn uleb(self: *Cursor) VerifyError!u64 {
        var value: u64 = 0;
        var shift: u6 = 0;
        while (true) {
            const b = try self.byte();
            value |= @as(u64, b & 0x7F) << shift;
            if (b & 0x80 == 0) break;
            if (shift >= 57) return error.BadSizeField;
            shift += 7;
        }
        return value;
    }
};

const testing = std.testing;

fn decompressAlloc(gpa: std.mem.Allocator, bytes: []const u8) ![]u8 {
    var input = std.Io.Reader.fixed(bytes);
    var decompressor = try std.compress.xz.Decompress.init(&input, gpa, &.{});
    defer decompressor.deinit();
    return decompressor.reader.allocRemaining(gpa, .unlimited);
}

fn testPayload(gpa: std.mem.Allocator, len: usize) ![]u8 {
    const bytes = try gpa.alloc(u8, len);
    var prng: std.Random.DefaultPrng = .init(0x5EED);
    prng.random().bytes(bytes);
    // Mix in a run so the payload is neither purely random nor purely flat.
    if (len > 32) @memset(bytes[8..24], 0xAB);
    return bytes;
}

test "streams round-trip through the production xz decoder" {
    const gpa = testing.allocator;
    for ([_]usize{ 0, 1, 3, 4, 5, 1024, max_chunk_size - 1, max_chunk_size, max_chunk_size + 1, 3 * max_chunk_size + 7 }) |len| {
        const payload = try testPayload(gpa, len);
        defer gpa.free(payload);

        const stream = try allocStream(gpa, payload, .{});
        defer gpa.free(stream);

        try verifyStream(stream, payload);
        const decoded = try decompressAlloc(gpa, stream);
        defer gpa.free(decoded);
        try testing.expectEqualSlices(u8, payload, decoded);
    }
}

test "small chunk sizes produce multi-chunk blocks that still decode" {
    const gpa = testing.allocator;
    const payload = try testPayload(gpa, 700);
    defer gpa.free(payload);

    const stream = try allocStream(gpa, payload, .{ .chunk_size = 64 });
    defer gpa.free(stream);

    try verifyStream(stream, payload);
    const decoded = try decompressAlloc(gpa, stream);
    defer gpa.free(decoded);
    try testing.expectEqualSlices(u8, payload, decoded);
}

test "every check kind is framed and validated" {
    const gpa = testing.allocator;
    const payload = "squashfs metadata block";
    for ([_]Check{ .none, .crc32, .crc64 }) |check| {
        const stream = try allocStream(gpa, payload, .{ .check = check });
        defer gpa.free(stream);

        try testing.expectEqual(@as(u8, @intFromEnum(check)), stream[7]);
        try verifyStream(stream, payload);
        const decoded = try decompressAlloc(gpa, stream);
        defer gpa.free(decoded);
        try testing.expectEqualStrings(payload, decoded);
    }
}

test "an empty payload produces a block-free stream" {
    const gpa = testing.allocator;
    const stream = try allocStream(gpa, "", .{});
    defer gpa.free(stream);

    try verifyStream(stream, "");
    try testing.expectEqualSlices(u8, &stream_magic, stream[0..6]);
    try testing.expectEqualSlices(u8, &footer_magic, stream[stream.len - 2 ..]);
    // Stream header, empty index, footer: no block bytes at all.
    try testing.expectEqual(@as(usize, 12 + 8 + 12), stream.len);
    const decoded = try decompressAlloc(gpa, stream);
    defer gpa.free(decoded);
    try testing.expectEqual(@as(usize, 0), decoded.len);
}

test "the layout matches the xz container spec byte for byte" {
    const gpa = testing.allocator;
    const payload = "kernel module bytes";
    const stream = try allocStream(gpa, payload, .{});
    defer gpa.free(stream);

    try testing.expectEqualSlices(u8, &stream_magic, stream[0..6]);
    try testing.expectEqual(@as(u8, 0), stream[6]);
    try testing.expectEqual(@as(u8, 0x01), stream[7]);
    try testing.expectEqual(Crc32.hash(stream[6..8]), std.mem.readInt(u32, stream[8..12], .little));

    const header_size = @as(usize, stream[12]) * 4 + 4;
    try testing.expectEqual(@as(usize, 0), header_size % 4);
    try testing.expectEqual(@as(u8, 0b1100_0000), stream[13]);
    try testing.expectEqual(
        Crc32.hash(stream[12 .. 12 + header_size - 4]),
        std.mem.readInt(u32, stream[12 + header_size - 4 ..][0..4], .little),
    );

    const data_start = 12 + header_size;
    try testing.expectEqual(@as(u8, 0x01), stream[data_start]);
    try testing.expectEqual(@as(u16, payload.len - 1), std.mem.readInt(u16, stream[data_start + 1 ..][0..2], .big));
    try testing.expectEqualStrings(payload, stream[data_start + 3 ..][0..payload.len]);
    const packed_size = payload.len + 4;
    try testing.expectEqual(@as(u8, 0), stream[data_start + packed_size - 1]);

    var offset = data_start + packed_size;
    for (0..padding(header_size + packed_size)) |i| try testing.expectEqual(@as(u8, 0), stream[offset + i]);
    offset += padding(header_size + packed_size);
    try testing.expectEqual(Crc32.hash(payload), std.mem.readInt(u32, stream[offset..][0..4], .little));
    offset += 4;

    const index_start = offset;
    try testing.expectEqual(@as(u8, 0), stream[index_start]);
    try testing.expectEqual(@as(u8, 1), stream[index_start + 1]);
    try testing.expectEqual(@as(u8, @intCast(header_size + packed_size + 4)), stream[index_start + 2]);
    try testing.expectEqual(@as(u8, payload.len), stream[index_start + 3]);

    const index_size = stream.len - 12 - index_start;
    try testing.expectEqual(@as(usize, 0), index_size % 4);
    try testing.expectEqual(
        @as(u32, @intCast(index_size / 4 - 1)),
        std.mem.readInt(u32, stream[stream.len - 8 ..][0..4], .little),
    );
    try testing.expectEqual(
        Crc32.hash(stream[stream.len - 8 .. stream.len - 2]),
        std.mem.readInt(u32, stream[stream.len - 12 ..][0..4], .little),
    );
    try testing.expectEqualSlices(u8, stream[6..8], stream[stream.len - 4 .. stream.len - 2]);
    try testing.expectEqualSlices(u8, &footer_magic, stream[stream.len - 2 ..]);
}

test "verification rejects corrupted checksums, lengths and framing" {
    const gpa = testing.allocator;
    const payload = "the quick brown fox jumps over the lazy dog";
    const stream = try allocStream(gpa, payload, .{});
    defer gpa.free(stream);
    const header_size = @as(usize, stream[12]) * 4 + 4;
    const data_start = 12 + header_size;
    const packed_size = payload.len + 4;
    const check_offset = data_start + packed_size + padding(header_size + packed_size);
    const index_start = check_offset + 4;
    const index_size = stream.len - 12 - index_start;

    const Case = struct {
        name: []const u8,
        offset: usize,
        xor: u8,
        expected: VerifyError,
    };
    const cases = [_]Case{
        .{ .name = "stream magic", .offset = 1, .xor = 0xFF, .expected = error.BadMagic },
        .{ .name = "stream flags reserved byte", .offset = 6, .xor = 0x01, .expected = error.BadStreamFlags },
        .{ .name = "stream check id", .offset = 7, .xor = 0x02, .expected = error.BadStreamFlags },
        .{ .name = "stream check kind", .offset = 7, .xor = 0x01, .expected = error.BadStreamHeaderCrc },
        .{ .name = "stream header crc", .offset = 8, .xor = 0x01, .expected = error.BadStreamHeaderCrc },
        .{ .name = "block header flags", .offset = 13, .xor = 0x04, .expected = error.BadBlockHeader },
        .{ .name = "declared packed size", .offset = 14, .xor = 0x01, .expected = error.BadBlockHeaderCrc },
        .{ .name = "block header crc", .offset = data_start - 1, .xor = 0x80, .expected = error.BadBlockHeaderCrc },
        .{ .name = "chunk control byte", .offset = data_start, .xor = 0x02, .expected = error.BadChunk },
        .{ .name = "chunk payload", .offset = data_start + 4, .xor = 0x20, .expected = error.PayloadMismatch },
        .{ .name = "block check", .offset = check_offset, .xor = 0x08, .expected = error.BadCheck },
        .{ .name = "index record count", .offset = index_start + 1, .xor = 0x02, .expected = error.BadIndex },
        .{ .name = "index unpadded size", .offset = index_start + 2, .xor = 0x01, .expected = error.BadIndex },
        .{ .name = "index uncompressed size", .offset = index_start + 3, .xor = 0x01, .expected = error.BadIndex },
        .{ .name = "index crc", .offset = index_start + index_size - 4, .xor = 0x40, .expected = error.BadIndexCrc },
        .{ .name = "footer backward size", .offset = stream.len - 8, .xor = 0x01, .expected = error.BadFooterCrc },
        .{ .name = "footer crc", .offset = stream.len - 12, .xor = 0x10, .expected = error.BadFooterCrc },
        .{ .name = "footer magic", .offset = stream.len - 1, .xor = 0x01, .expected = error.BadFooter },
    };

    for (cases) |case| {
        const mutated = try gpa.dupe(u8, stream);
        defer gpa.free(mutated);
        mutated[case.offset] ^= case.xor;
        testing.expectError(case.expected, verifyStream(mutated, payload)) catch |err| {
            std.debug.print("case '{s}' did not fail as expected\n", .{case.name});
            return err;
        };
    }

    try testing.expectError(error.Truncated, verifyStream(stream[0 .. stream.len - 1], payload));
    const extended = try gpa.alloc(u8, stream.len + 1);
    defer gpa.free(extended);
    @memcpy(extended[0..stream.len], stream);
    extended[stream.len] = 0;
    try testing.expectError(error.TrailingBytes, verifyStream(extended, payload));
    try testing.expectError(error.PayloadMismatch, verifyStream(stream, payload[0 .. payload.len - 1]));
}

test "corrupted streams are rejected by the production decoder too" {
    const gpa = testing.allocator;
    const payload = "the quick brown fox jumps over the lazy dog";
    const stream = try allocStream(gpa, payload, .{});
    defer gpa.free(stream);
    const header_size = @as(usize, stream[12]) * 4 + 4;
    const data_start = 12 + header_size;
    const index_start = data_start + payload.len + 4 + padding(header_size + payload.len + 4) + 4;

    {
        const mutated = try gpa.dupe(u8, stream);
        defer gpa.free(mutated);
        mutated[8] ^= 0x01;
        try testing.expectError(error.WrongChecksum, decompressAlloc(gpa, mutated));
    }
    {
        const mutated = try gpa.dupe(u8, stream);
        defer gpa.free(mutated);
        // Flip the declared uncompressed size in the block header.
        mutated[15] ^= 0x01;
        try testing.expectError(error.ReadFailed, decompressAlloc(gpa, mutated));
    }
    {
        const mutated = try gpa.dupe(u8, stream);
        defer gpa.free(mutated);
        // Claim two index records when the stream carries one block.
        mutated[index_start + 1] ^= 0x03;
        try testing.expectError(error.ReadFailed, decompressAlloc(gpa, mutated));
    }
    {
        const mutated = try gpa.dupe(u8, stream);
        defer gpa.free(mutated);
        mutated[mutated.len - 8] ^= 0x01;
        try testing.expectError(error.ReadFailed, decompressAlloc(gpa, mutated));
    }
}

test "dictionary size property covers the payload" {
    try testing.expectEqual(@as(u8, 0), dictionarySizeByte(0));
    try testing.expectEqual(@as(u8, 0), dictionarySizeByte(4096));
    try testing.expectEqual(@as(u8, 1), dictionarySizeByte(4097));
    try testing.expectEqual(@as(u8, 2), dictionarySizeByte(8192));
    try testing.expectEqual(@as(u8, 3), dictionarySizeByte(8193));
    try testing.expectEqual(@as(u8, 40), dictionarySizeByte(std.math.maxInt(usize)));
    for ([_]usize{ 1, 4095, 6144, 100_000, 1 << 24 }) |len| {
        const bits = dictionarySizeByte(len);
        const size = (@as(u64, 2) | (bits & 1)) << @intCast(bits / 2 + 11);
        try testing.expect(size >= len);
    }
}
