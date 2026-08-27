//! Shared JSON accessors and validators for the FreeBSD 15.1 release tooling.
//!
//! The Python this replaces reached into freshly parsed documents with
//! `document.get(...)` and compared with `type(value) is not int`, so a JSON
//! `true` was never an integer and a missing key was never an empty string.
//! These accessors keep that strictness explicit, and `Context` carries the
//! one operator-facing line a failed validation is allowed to produce -- the
//! text a Python `ValueError` used to carry.

const std = @import("std");
const support = @import("release");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const contract = support.contract;

/// Every validation failure. The message is the payload; the error only says
/// that there is one, exactly like the single `ValueError` the Python raised.
pub const Error = error{ Invalid, OutOfMemory };

/// Whitespace `str.strip()` removes from the values this tooling handles.
pub const ascii_whitespace = " \t\n\r\x0b\x0c";

pub const Context = struct {
    /// Scratch allocations that are freed before the command returns.
    gpa: Allocator,
    /// Document and string lifetimes that last until the command exits.
    arena: Allocator,
    io: Io,
    diagnostic: contract.Diagnostic = .{},

    pub fn fail(
        self: *Context,
        comptime fmt: []const u8,
        args: anytype,
    ) error{Invalid} {
        self.diagnostic.set(fmt, args);
        return error.Invalid;
    }

    pub fn message(self: *const Context) []const u8 {
        return self.diagnostic.message();
    }
};

pub fn stringOf(value: ?std.json.Value) ?[]const u8 {
    const present = value orelse return null;
    return switch (present) {
        .string => |text| text,
        else => null,
    };
}

/// Python's `type(value) is not int`: a JSON boolean is not an integer, and
/// neither is a float that happens to be integral.
pub fn integerOf(value: ?std.json.Value) ?i64 {
    const present = value orelse return null;
    return switch (present) {
        .integer => |number| number,
        else => null,
    };
}

pub fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const present = value orelse return null;
    return switch (present) {
        .object => |map| map,
        else => null,
    };
}

pub fn arrayOf(value: ?std.json.Value) ?std.json.Array {
    const present = value orelse return null;
    return switch (present) {
        .array => |items| items,
        else => null,
    };
}

/// Whether `value` is absent, JSON `null`, or the empty string -- the
/// `value not in (None, "")` idiom the Azure metadata checks use for fields
/// Azure sometimes omits.
pub fn isAbsentOrEmpty(value: ?std.json.Value) bool {
    const present = value orelse return true;
    return switch (present) {
        .null => true,
        .string => |text| text.len == 0,
        else => false,
    };
}

pub fn eqlString(value: ?std.json.Value, expected: []const u8) bool {
    const text = stringOf(value) orelse return false;
    return std.mem.eql(u8, text, expected);
}

/// Deep structural equality, used where the Python compared two parsed
/// subdocuments with `==`.
pub fn valueEql(left: std.json.Value, right: std.json.Value) bool {
    return switch (left) {
        .null => right == .null,
        .bool => |flag| right == .bool and right.bool == flag,
        .integer => |number| right == .integer and right.integer == number,
        .float => |number| right == .float and right.float == number,
        .number_string => |text| right == .number_string and
            std.mem.eql(u8, right.number_string, text),
        .string => |text| right == .string and std.mem.eql(u8, right.string, text),
        .array => |items| {
            if (right != .array) return false;
            if (right.array.items.len != items.items.len) return false;
            for (items.items, right.array.items) |a, b| {
                if (!valueEql(a, b)) return false;
            }
            return true;
        },
        .object => |map| {
            if (right != .object) return false;
            if (right.object.count() != map.count()) return false;
            var entries = map.iterator();
            while (entries.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse return false;
                if (!valueEql(entry.value_ptr.*, other)) return false;
            }
            return true;
        },
    };
}

pub fn trim(text: []const u8) []const u8 {
    return std.mem.trim(u8, text, ascii_whitespace);
}

/// `require_sha256`.
pub fn requireSha256(
    context: *Context,
    value: ?[]const u8,
    label: []const u8,
) error{Invalid}!void {
    const text = value orelse return context.fail(
        "{s} must be a lowercase SHA-256",
        .{label},
    );
    if (!contract.isSha256Hex(text)) return context.fail(
        "{s} must be a lowercase SHA-256",
        .{label},
    );
}

/// `require_non_empty`, returning the stripped value the Python recorded.
pub fn requireNonEmpty(
    context: *Context,
    value: ?[]const u8,
    label: []const u8,
) error{Invalid}![]const u8 {
    const text = value orelse return context.fail("{s} must be non-empty", .{label});
    const stripped = trim(text);
    if (stripped.len == 0) return context.fail("{s} must be non-empty", .{label});
    return stripped;
}

/// `require_positive_int`.
pub fn requirePositiveInt(
    context: *Context,
    value: ?std.json.Value,
    comptime label_fmt: []const u8,
    label_args: anytype,
) error{Invalid}!i64 {
    const number = integerOf(value) orelse return context.fail(
        label_fmt ++ " must be a positive integer",
        label_args,
    );
    if (number <= 0) return context.fail(
        label_fmt ++ " must be a positive integer",
        label_args,
    );
    return number;
}

/// `require_reduction_percent`.
pub fn requireReductionPercent(
    context: *Context,
    value: i64,
) error{Invalid}!i64 {
    if (value < 1 or value > 99) return context.fail(
        "minimum core reduction percent must be from 1 to 99",
        .{},
    );
    return value;
}

/// `datetime.strptime(value, "%Y%m%d")` reduced to the question it answers:
/// whether the eight digits name a real calendar day.
pub fn isCalendarDate(text: []const u8) bool {
    if (text.len != 8) return false;
    for (text) |character| if (!std.ascii.isDigit(character)) return false;
    const year = std.fmt.parseInt(u16, text[0..4], 10) catch return false;
    const month = std.fmt.parseInt(u8, text[4..6], 10) catch return false;
    const day = std.fmt.parseInt(u8, text[6..8], 10) catch return false;
    // `datetime.MINYEAR` is 1, so a zero year is not a date.
    if (year < 1 or month < 1 or month > 12 or day < 1) return false;
    return day <= daysInMonth(year, month);
}

fn daysInMonth(year: u16, month: u8) u8 {
    return switch (month) {
        1, 3, 5, 7, 8, 10, 12 => 31,
        4, 6, 9, 11 => 30,
        2 => if (isLeapYear(year)) 29 else 28,
        else => unreachable,
    };
}

fn isLeapYear(year: u16) bool {
    if (year % 4 != 0) return false;
    if (year % 100 != 0) return true;
    return year % 400 == 0;
}

/// `require_release_date`.
pub fn requireReleaseDate(
    context: *Context,
    value: ?[]const u8,
) error{Invalid}![]const u8 {
    const text = value orelse return context.fail(
        "release date must be an explicit YYYYMMDD value",
        .{},
    );
    if (text.len != 8) return context.fail(
        "release date must be an explicit YYYYMMDD value",
        .{},
    );
    for (text) |character| if (!std.ascii.isDigit(character)) return context.fail(
        "release date must be an explicit YYYYMMDD value",
        .{},
    );
    if (!isCalendarDate(text)) return context.fail(
        "release date is not a valid calendar date",
        .{},
    );
    return text;
}

fn testContext(arena: Allocator) Context {
    return .{
        .gpa = std.testing.allocator,
        .arena = arena,
        .io = std.testing.io,
    };
}

test "strict accessors separate absent, null, and wrong-typed values" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"text": "x", "count": 7, "flag": true, "nothing": null, "list": [1],
        \\ "map": {"a": 1}, "blank": ""}
    ,
        .{},
    );
    defer parsed.deinit();
    const object = parsed.value.object;

    try std.testing.expectEqualStrings("x", stringOf(object.get("text")).?);
    try std.testing.expectEqual(@as(?[]const u8, null), stringOf(object.get("count")));
    try std.testing.expectEqual(@as(?[]const u8, null), stringOf(object.get("absent")));
    try std.testing.expectEqual(@as(i64, 7), integerOf(object.get("count")).?);
    try std.testing.expectEqual(@as(?i64, null), integerOf(object.get("flag")));
    try std.testing.expectEqual(@as(?i64, null), integerOf(object.get("nothing")));
    try std.testing.expect(objectOf(object.get("map")) != null);
    try std.testing.expect(objectOf(object.get("list")) == null);
    try std.testing.expect(arrayOf(object.get("list")) != null);

    try std.testing.expect(isAbsentOrEmpty(object.get("absent")));
    try std.testing.expect(isAbsentOrEmpty(object.get("nothing")));
    try std.testing.expect(isAbsentOrEmpty(object.get("blank")));
    try std.testing.expect(!isAbsentOrEmpty(object.get("text")));
    try std.testing.expect(eqlString(object.get("text"), "x"));
    try std.testing.expect(!eqlString(object.get("count"), "7"));
}

test "deep equality distinguishes shape, order-independent keys, and types" {
    var left = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"a": [1, {"b": "c"}], "d": null}
    ,
        .{},
    );
    defer left.deinit();
    var right = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"d": null, "a": [1, {"b": "c"}]}
    ,
        .{},
    );
    defer right.deinit();
    var different = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"d": null, "a": [1, {"b": "C"}]}
    ,
        .{},
    );
    defer different.deinit();
    var extra = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"d": null, "a": [1, {"b": "c"}], "e": 1}
    ,
        .{},
    );
    defer extra.deinit();

    try std.testing.expect(valueEql(left.value, right.value));
    try std.testing.expect(!valueEql(left.value, different.value));
    try std.testing.expect(!valueEql(left.value, extra.value));
}

test "validators carry the Python failure text" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator());

    try requireSha256(&context, "a" ** 64, "candidate SHA-256");
    try std.testing.expectError(
        error.Invalid,
        requireSha256(&context, "A" ** 64, "candidate SHA-256"),
    );
    try std.testing.expectEqualStrings(
        "candidate SHA-256 must be a lowercase SHA-256",
        context.message(),
    );
    try std.testing.expectError(
        error.Invalid,
        requireSha256(&context, null, "source SHA-256"),
    );

    try std.testing.expectEqualStrings(
        "eastus2",
        try requireNonEmpty(&context, "  eastus2 ", "location"),
    );
    try std.testing.expectError(
        error.Invalid,
        requireNonEmpty(&context, "   ", "location"),
    );
    try std.testing.expectEqualStrings("location must be non-empty", context.message());

    try std.testing.expectEqual(
        @as(i64, 5),
        try requirePositiveInt(&context, .{ .integer = 5 }, "{s} size", .{"asset"}),
    );
    try std.testing.expectError(
        error.Invalid,
        requirePositiveInt(&context, .{ .integer = 0 }, "{s} size", .{"asset"}),
    );
    try std.testing.expectEqualStrings(
        "asset size must be a positive integer",
        context.message(),
    );
    try std.testing.expectError(
        error.Invalid,
        requirePositiveInt(&context, .{ .bool = true }, "{s} size", .{"asset"}),
    );

    try std.testing.expectEqual(@as(i64, 10), try requireReductionPercent(&context, 10));
    for ([_]i64{ 0, 100, -1 }) |threshold| {
        try std.testing.expectError(
            error.Invalid,
            requireReductionPercent(&context, threshold),
        );
        try std.testing.expectEqualStrings(
            "minimum core reduction percent must be from 1 to 99",
            context.message(),
        );
    }
}

test "release dates must be explicit, eight digits, and real calendar days" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    var context = testContext(arena.allocator());

    try std.testing.expectEqualStrings(
        "20260812",
        try requireReleaseDate(&context, "20260812"),
    );
    try std.testing.expectEqualStrings(
        "20240229",
        try requireReleaseDate(&context, "20240229"),
    );

    for ([_]?[]const u8{ null, "", "2026073", "2026-08-12", "2026081a" }) |value| {
        try std.testing.expectError(error.Invalid, requireReleaseDate(&context, value));
        try std.testing.expectEqualStrings(
            "release date must be an explicit YYYYMMDD value",
            context.message(),
        );
    }
    for ([_][]const u8{ "20260230", "20261301", "20260000", "00000101" }) |value| {
        try std.testing.expectError(error.Invalid, requireReleaseDate(&context, value));
        try std.testing.expectEqualStrings(
            "release date is not a valid calendar date",
            context.message(),
        );
    }
    try std.testing.expect(!isCalendarDate("21000229"));
    try std.testing.expect(isCalendarDate("20000229"));
}
