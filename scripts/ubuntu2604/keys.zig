//! Detects private key material in bytes that are about to be published.
//!
//! Internal provenance is attached to a candidate and re-read by every later
//! job, so a signing key that leaked into the provenance tree would be
//! published with the release. The check is deliberately shape-based rather
//! than name-based: it looks for the PEM headers and the OpenSSH container
//! magic, and then walks the buffer for a DER `SEQUENCE` whose shape is one of
//! the private key structures (PKCS#1/SEC1 `version INTEGER` first, or PKCS#8
//! `AlgorithmIdentifier` followed by an `OCTET STRING` that ends the
//! sequence). A public key, a certificate, and a signature all fail both
//! shapes, so ordinary provenance is unaffected.

const std = @import("std");

const contracts = @import("contracts.zig");

/// A parsed DER tag-length-value header: the tag plus the half-open content
/// range it introduces.
const Tlv = struct {
    tag: u8,
    start: usize,
    end: usize,
};

fn readTlv(data: []const u8, offset: usize, limit: usize) ?Tlv {
    if (offset + 2 > limit) return null;
    const tag = data[offset];
    var length: usize = data[offset + 1];
    var cursor = offset + 2;
    if (length & 0x80 != 0) {
        const length_bytes = length & 0x7F;
        if (length_bytes == 0 or length_bytes > 4 or cursor + length_bytes > limit) {
            return null;
        }
        length = 0;
        for (data[cursor..][0..length_bytes]) |byte| {
            length = (length << 8) | byte;
        }
        cursor += length_bytes;
    }
    const end = std.math.add(usize, cursor, length) catch return null;
    if (end > limit) return null;
    return .{ .tag = tag, .start = cursor, .end = end };
}

fn derPrivateKeyAt(data: []const u8, offset: usize) bool {
    const root = readTlv(data, offset, data.len) orelse return false;
    if (root.tag != 0x30) return false;
    const first = readTlv(data, root.start, root.end) orelse return false;
    if (first.tag == 0x02) {
        const version = data[first.start..first.end];
        return std.mem.eql(u8, version, "\x00") or
            std.mem.eql(u8, version, "\x01") or
            std.mem.eql(u8, version, "\x03");
    }

    const second = readTlv(data, first.end, root.end) orelse return false;
    if (first.tag != 0x30 or second.tag != 0x04 or second.end != root.end) {
        return false;
    }
    const algorithm_oid = readTlv(data, first.start, first.end) orelse return false;
    return algorithm_oid.tag == 0x06;
}

/// `contains_private_key`.
pub fn containsPrivateKey(data: []const u8) bool {
    for (contracts.private_key_pem_markers) |marker| {
        if (std.mem.indexOf(u8, data, marker) != null) return true;
    }
    if (std.mem.indexOf(u8, data, contracts.openssh_private_key_magic) != null) {
        return true;
    }

    var cursor: usize = 0;
    while (std.mem.indexOfScalarPos(u8, data, cursor, 0x30)) |candidate| {
        if (derPrivateKeyAt(data, candidate)) return true;
        cursor = candidate + 1;
    }
    return false;
}

test "PEM and OpenSSH markers are detected anywhere in the buffer" {
    try std.testing.expect(containsPrivateKey(
        "trailing text\n-----BEGIN PRIVATE KEY-----\n",
    ));
    try std.testing.expect(containsPrivateKey(
        "-----BEGIN OPENSSH PRIVATE KEY-----",
    ));
    try std.testing.expect(containsPrivateKey("prefix openssh-key-v1\x00rest"));
    try std.testing.expect(!containsPrivateKey(
        "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n",
    ));
    try std.testing.expect(!containsPrivateKey("-----BEGIN PUBLIC KEY-----"));
}

test "DER private key shapes are detected and public shapes are not" {
    // PKCS#1: SEQUENCE { INTEGER 0, ... }
    const pkcs1 = [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 };
    try std.testing.expect(containsPrivateKey(&pkcs1));

    // SEC1: SEQUENCE { INTEGER 1, OCTET STRING }
    const sec1 = [_]u8{ 0x30, 0x07, 0x02, 0x01, 0x01, 0x04, 0x02, 0xAA, 0xBB };
    try std.testing.expect(containsPrivateKey(&sec1));

    // PKCS#8: SEQUENCE { SEQUENCE { OID }, OCTET STRING } ending the sequence.
    const pkcs8 = [_]u8{
        0x30, 0x0B, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03,
        0x04, 0x04, 0x02, 0xAA, 0xBB,
    };
    try std.testing.expect(containsPrivateKey(&pkcs8));

    // A public key: SEQUENCE { SEQUENCE { OID }, BIT STRING } is not matched.
    const public = [_]u8{
        0x30, 0x0B, 0x30, 0x05, 0x06, 0x03, 0x2A, 0x03,
        0x04, 0x03, 0x02, 0x00, 0xAA,
    };
    try std.testing.expect(!containsPrivateKey(&public));

    // A version integer that is not 0, 1, or 3 is not a private key version.
    const other_version = [_]u8{ 0x30, 0x03, 0x02, 0x01, 0x05 };
    try std.testing.expect(!containsPrivateKey(&other_version));
}

test "truncated and malformed DER never reports a private key" {
    try std.testing.expect(!containsPrivateKey(&[_]u8{0x30}));
    try std.testing.expect(!containsPrivateKey(&[_]u8{ 0x30, 0x7F }));
    // Long-form length larger than the buffer.
    try std.testing.expect(!containsPrivateKey(&[_]u8{
        0x30, 0x84, 0xFF, 0xFF, 0xFF, 0xFF, 0x02, 0x01, 0x00,
    }));
    // Indefinite length (0x80) is rejected outright.
    try std.testing.expect(!containsPrivateKey(&[_]u8{
        0x30, 0x80, 0x02, 0x01, 0x00, 0x00, 0x00,
    }));
    try std.testing.expect(!containsPrivateKey(""));
    try std.testing.expect(!containsPrivateKey("ordinary provenance text\n"));
}

test "an embedded DER private key inside a larger blob is found" {
    const blob = "log line\n" ++
        [_]u8{ 0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x01 } ++
        "\nmore log";
    try std.testing.expect(containsPrivateKey(blob));
}
