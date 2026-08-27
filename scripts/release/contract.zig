//! Release-contract primitives shared by the Zig release tooling.
//!
//! The Python release scripts this repository is migrating away from all
//! repeat the same three contracts verbatim: a `fail(message)` that exits with
//! a single human-readable line, `require_sha256` / `require_commit` shape
//! checks over untrusted JSON, and a `format_mib` renderer used in operator
//! diagnostics. Those contracts are part of the published behavior (CI logs
//! and shell callers match on the text), so they are ported once, here, rather
//! than re-derived per script.

const std = @import("std");

/// Upper bound on a single failure line. Every message the Python scripts
/// produce is a short sentence plus a handful of decimal sizes, so a fixed
/// buffer removes allocation (and therefore a failure mode) from the failure
/// path itself.
pub const message_capacity = 512;

/// Carries the exact operator-facing text for a failed validation. Validation
/// functions return a typed error for programmatic use and fill a `Diagnostic`
/// with the message their Python predecessor passed to `fail()`.
pub const Diagnostic = struct {
    buffer: [message_capacity]u8 = undefined,
    length: usize = 0,

    pub fn message(self: *const Diagnostic) []const u8 {
        return self.buffer[0..self.length];
    }

    /// Records `fmt`. A message that does not fit is truncated rather than
    /// dropped: a truncated diagnostic still names the failure, while an error
    /// here would mask the failure being reported.
    pub fn set(self: *Diagnostic, comptime fmt: []const u8, args: anytype) void {
        const written = std.fmt.bufPrint(&self.buffer, fmt, args) catch blk: {
            break :blk self.buffer[0..];
        };
        self.length = written.len;
    }

    /// Records `fmt` and returns `err`, so callers can `return diagnostic.fail(
    /// error.X, "...", .{})` in one statement.
    pub fn fail(
        self: *Diagnostic,
        err: anytype,
        comptime fmt: []const u8,
        args: anytype,
    ) @TypeOf(err) {
        self.set(fmt, args);
        return err;
    }
};

pub const DigestError = error{InvalidSha256};
pub const CommitError = error{InvalidCommit};

/// Whether `text` is a lowercase, unprefixed SHA-256 hex digest.
pub fn isSha256Hex(text: []const u8) bool {
    return isLowerHex(text, 64);
}

/// Whether `text` is a full lowercase Git commit SHA (SHA-1, 40 hex digits).
pub fn isCommitHex(text: []const u8) bool {
    return isLowerHex(text, 40);
}

fn isLowerHex(text: []const u8, length: usize) bool {
    if (text.len != length) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

/// `require_sha256` from the Python release scripts: the value must be present,
/// a string, and a lowercase SHA-256.
pub fn requireSha256(
    value: ?std.json.Value,
    label: []const u8,
    diagnostic: *Diagnostic,
) DigestError![]const u8 {
    const text = stringOrNull(value) orelse return diagnostic.fail(
        error.InvalidSha256,
        "{s} is not a lowercase SHA-256",
        .{label},
    );
    if (!isSha256Hex(text)) return diagnostic.fail(
        error.InvalidSha256,
        "{s} is not a lowercase SHA-256",
        .{label},
    );
    return text;
}

/// `require_commit` from the Python release scripts.
pub fn requireCommit(
    value: ?std.json.Value,
    label: []const u8,
    diagnostic: *Diagnostic,
) CommitError![]const u8 {
    const text = stringOrNull(value) orelse return diagnostic.fail(
        error.InvalidCommit,
        "{s} is not a full lowercase commit SHA",
        .{label},
    );
    if (!isCommitHex(text)) return diagnostic.fail(
        error.InvalidCommit,
        "{s} is not a full lowercase commit SHA",
        .{label},
    );
    return text;
}

fn stringOrNull(value: ?std.json.Value) ?[]const u8 {
    const present = value orelse return null;
    return switch (present) {
        .string => |text| text,
        else => null,
    };
}

pub const MibText = struct {
    buffer: [40]u8,
    length: usize,

    pub fn slice(self: *const MibText) []const u8 {
        return self.buffer[0..self.length];
    }
};

/// `format_mib` from the Python release scripts: one fractional digit, rounded
/// half up, always suffixed with " MiB".
pub fn formatMib(byte_count: u64) MibText {
    const mib = 1024 * 1024;
    // `byte_count * 10` cannot overflow for any real artifact, but a bogus
    // footer field can reach the u64 ceiling, so widen instead of trapping.
    const scaled = @as(u128, byte_count) * 10;
    var tenths = scaled / mib;
    if ((scaled % mib) * 2 >= mib) tenths += 1;
    var result: MibText = .{ .buffer = undefined, .length = 0 };
    const written = std.fmt.bufPrint(&result.buffer, "{d}.{d} MiB", .{
        tenths / 10,
        tenths % 10,
    }) catch unreachable;
    result.length = written.len;
    return result;
}

test "diagnostic records the failure text alongside the typed error" {
    var diagnostic: Diagnostic = .{};
    try std.testing.expectEqual(@as(usize, 0), diagnostic.message().len);
    const result = diagnostic.fail(error.InvalidSha256, "{s} is bad", .{"digest"});
    try std.testing.expectError(error.InvalidSha256, @as(anyerror!void, result));
    try std.testing.expectEqualStrings("digest is bad", diagnostic.message());
}

test "diagnostic truncates rather than dropping an oversized message" {
    var diagnostic: Diagnostic = .{};
    const long = "x" ** (message_capacity * 2);
    diagnostic.set("{s}", .{long});
    try std.testing.expectEqual(message_capacity, diagnostic.message().len);
}

test "sha256 and commit shapes reject every non-canonical spelling" {
    try std.testing.expect(isSha256Hex("a" ** 64));
    try std.testing.expect(!isSha256Hex("A" ** 64));
    try std.testing.expect(!isSha256Hex("a" ** 63));
    try std.testing.expect(!isSha256Hex("a" ** 65));
    try std.testing.expect(!isSha256Hex("sha256:" ++ "a" ** 64));
    try std.testing.expect(!isSha256Hex("g" ** 64));
    try std.testing.expect(isCommitHex("0" ** 40));
    try std.testing.expect(!isCommitHex("0" ** 39));
    try std.testing.expect(!isCommitHex("F" ** 40));
}

test "require helpers mirror the Python failure text" {
    var diagnostic: Diagnostic = .{};
    const good: std.json.Value = .{ .string = "b" ** 64 };
    try std.testing.expectEqualStrings(
        "b" ** 64,
        try requireSha256(good, "candidate digest", &diagnostic),
    );

    try std.testing.expectError(
        error.InvalidSha256,
        requireSha256(null, "candidate digest", &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "candidate digest is not a lowercase SHA-256",
        diagnostic.message(),
    );

    try std.testing.expectError(
        error.InvalidSha256,
        requireSha256(.{ .integer = 7 }, "candidate digest", &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "candidate digest is not a lowercase SHA-256",
        diagnostic.message(),
    );

    try std.testing.expectEqualStrings(
        "c" ** 40,
        try requireCommit(.{ .string = "c" ** 40 }, "source_commit", &diagnostic),
    );
    try std.testing.expectError(
        error.InvalidCommit,
        requireCommit(.{ .string = "c" ** 39 }, "source_commit", &diagnostic),
    );
    try std.testing.expectEqualStrings(
        "source_commit is not a full lowercase commit SHA",
        diagnostic.message(),
    );
}

test "formatMib rounds half up like the Python renderer" {
    try std.testing.expectEqualStrings("0.0 MiB", formatMib(0).slice());
    try std.testing.expectEqualStrings("1.0 MiB", formatMib(1024 * 1024).slice());
    try std.testing.expectEqualStrings(
        "1.5 MiB",
        formatMib(1024 * 1024 + 512 * 1024).slice(),
    );
    // The rounding boundary itself: one byte below stays down, at it rounds up.
    try std.testing.expectEqualStrings("1.0 MiB", formatMib(1101004).slice());
    try std.testing.expectEqualStrings("1.1 MiB", formatMib(1101005).slice());
    try std.testing.expectEqualStrings(
        "30720.0 MiB",
        formatMib(30 * 1024 * 1024 * 1024).slice(),
    );
}
