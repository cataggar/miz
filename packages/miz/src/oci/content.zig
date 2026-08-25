const std = @import("std");

const Sha256 = std.crypto.hash.sha2.Sha256;

pub const Error = error{
    InvalidDigest,
    UnsupportedDigestAlgorithm,
    SizeMismatch,
    DigestMismatch,
    SizeOverflow,
};

/// A canonical, SHA-256 OCI content digest.
pub const Digest = struct {
    bytes: [Sha256.digest_length]u8,

    pub fn parse(text: []const u8) Error!Digest {
        const separator = std.mem.indexOfScalar(u8, text, ':') orelse return error.InvalidDigest;
        const algorithm = text[0..separator];
        if (!std.mem.eql(u8, algorithm, "sha256")) {
            if (isDigestAlgorithm(algorithm)) return error.UnsupportedDigestAlgorithm;
            return error.InvalidDigest;
        }
        if (text.len != "sha256:".len + Sha256.digest_length * 2) return error.InvalidDigest;
        for (text["sha256:".len..]) |byte| {
            if (!std.ascii.isDigit(byte) and (byte < 'a' or byte > 'f')) {
                return error.InvalidDigest;
            }
        }
        var bytes: [Sha256.digest_length]u8 = undefined;
        _ = std.fmt.hexToBytes(&bytes, text["sha256:".len..]) catch return error.InvalidDigest;
        return .{ .bytes = bytes };
    }

    pub fn format(self: Digest) [71]u8 {
        var text: [71]u8 = undefined;
        @memcpy(text[0.."sha256:".len], "sha256:");
        const hex = std.fmt.bytesToHex(self.bytes, .lower);
        @memcpy(text["sha256:".len..], &hex);
        return text;
    }

    /// Returns the only safe filename component for an OCI SHA-256 blob.
    pub fn blobPathComponent(self: Digest) [Sha256.digest_length * 2]u8 {
        return std.fmt.bytesToHex(self.bytes, .lower);
    }
};

fn isDigestAlgorithm(algorithm: []const u8) bool {
    if (algorithm.len == 0 or !std.ascii.isLower(algorithm[0]) and !std.ascii.isDigit(algorithm[0])) return false;
    var previous_separator = false;
    for (algorithm[1..]) |byte| {
        const separator = byte == '+' or byte == '.' or byte == '_' or byte == '-';
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and !separator) return false;
        if (separator and previous_separator) return false;
        previous_separator = separator;
    }
    return !previous_separator;
}

pub const Verifier = struct {
    expected: Digest,
    expected_size: u64,
    size: u64 = 0,
    hash: Sha256 = Sha256.init(.{}),

    pub fn init(expected: Digest, expected_size: u64) Verifier {
        return .{ .expected = expected, .expected_size = expected_size };
    }

    pub fn update(self: *Verifier, bytes: []const u8) Error!void {
        const byte_count: u64 = @intCast(bytes.len);
        self.size = std.math.add(u64, self.size, byte_count) catch return error.SizeOverflow;
        if (self.size > self.expected_size) return error.SizeMismatch;
        self.hash.update(bytes);
    }

    pub fn finish(self: *Verifier) Error!void {
        if (self.size != self.expected_size) return error.SizeMismatch;
        var actual: [Sha256.digest_length]u8 = undefined;
        self.hash.final(&actual);
        if (!std.mem.eql(u8, &actual, &self.expected.bytes)) return error.DigestMismatch;
    }
};

pub fn verifyBytes(expected: Digest, expected_size: u64, bytes: []const u8) Error!void {
    var verifier = Verifier.init(expected, expected_size);
    try verifier.update(bytes);
    try verifier.finish();
}

pub fn digestBytes(bytes: []const u8) Digest {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(bytes, &digest, .{});
    return .{ .bytes = digest };
}

test "digest parsing and formatting is canonical" {
    const text = "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    const digest = try Digest.parse(text);
    const formatted = digest.format();
    try std.testing.expectEqualStrings(text, &formatted);
    try std.testing.expectError(error.InvalidDigest, Digest.parse("sha256:ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef0123456789"));
    try std.testing.expectError(error.UnsupportedDigestAlgorithm, Digest.parse("sha512:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"));
    try std.testing.expectError(error.UnsupportedDigestAlgorithm, Digest.parse("blake3:xyz"));
    try std.testing.expectError(error.InvalidDigest, Digest.parse("sha256:0123"));
    try std.testing.expectError(error.InvalidDigest, Digest.parse("sha256-:0123"));
}

test "verifier detects size and digest mismatches" {
    const digest = digestBytes("abc");
    try std.testing.expectError(error.SizeMismatch, verifyBytes(digest, 2, "abc"));
    try std.testing.expectError(error.DigestMismatch, verifyBytes(digest, 3, "abd"));
}

test "verifier accepts streamed content" {
    const digest = digestBytes("streamed content");
    var verifier = Verifier.init(digest, "streamed content".len);
    try verifier.update("streamed ");
    try verifier.update("content");
    try verifier.finish();
}
