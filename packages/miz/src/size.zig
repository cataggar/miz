//! Human-readable size parsing, matching qemu-img's `create <file> <size>`
//! suffix conventions (binary/1024-based units).

const std = @import("std");

pub const ParseError = error{
    Empty,
    InvalidDigit,
    Overflow,
    UnknownSuffix,
};

/// Parses sizes like "20G", "512M", "1024" (bytes), "64K", "2T".
/// Suffixes are case-insensitive: K/M/G/T (powers of 1024). A bare number is
/// bytes, matching qemu-img.
pub fn parseSize(text: []const u8) ParseError!u64 {
    if (text.len == 0) return error.Empty;

    const last = text[text.len - 1];
    const multiplier: u64, const digits = switch (last) {
        'k', 'K' => .{ 1024, text[0 .. text.len - 1] },
        'm', 'M' => .{ 1024 * 1024, text[0 .. text.len - 1] },
        'g', 'G' => .{ 1024 * 1024 * 1024, text[0 .. text.len - 1] },
        't', 'T' => .{ 1024 * 1024 * 1024 * 1024, text[0 .. text.len - 1] },
        else => .{ 1, text },
    };
    if (digits.len == 0) return error.Empty;

    const value = std.fmt.parseUnsigned(u64, digits, 10) catch |err| switch (err) {
        error.InvalidCharacter => return error.InvalidDigit,
        error.Overflow => return error.Overflow,
    };
    return std.math.mul(u64, value, multiplier) catch error.Overflow;
}

test "parseSize parses bytes and binary suffixes" {
    try std.testing.expectEqual(@as(u64, 1024), try parseSize("1024"));
    try std.testing.expectEqual(@as(u64, 64 * 1024), try parseSize("64K"));
    try std.testing.expectEqual(@as(u64, 20 * 1024 * 1024 * 1024), try parseSize("20G"));
    try std.testing.expectEqual(@as(u64, 512 * 1024 * 1024), try parseSize("512m"));
    try std.testing.expectEqual(@as(u64, 2 * 1024 * 1024 * 1024 * 1024), try parseSize("2T"));
}

test "parseSize rejects garbage" {
    try std.testing.expectError(error.Empty, parseSize(""));
    try std.testing.expectError(error.InvalidDigit, parseSize("abc"));
    try std.testing.expectError(error.Empty, parseSize("G"));
}
