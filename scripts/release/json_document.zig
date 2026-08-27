//! Strict reads and canonical writes for release JSON documents.
//!
//! The Python release scripts share two JSON contracts. `read_json` reads a
//! document, fails with `cannot read {path}: {error}` on any I/O, encoding, or
//! syntax problem, and fails with `{path} must contain a JSON object` when the
//! top level is not a mapping. `write_json` emits
//! `json.dumps(value, indent=2, sort_keys=True) + "\n"`, and provenance
//! digests hash `json.dumps(value, separators=(",", ":"), sort_keys=True)`.
//! Both spellings are byte-for-byte reproduced here, because the digests
//! published by earlier releases were computed over exactly those bytes.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Writer = std.Io.Writer;
const contract = @import("contract.zig");
const file_support = @import("file.zig");

pub const Diagnostic = contract.Diagnostic;

/// Bound applied to release documents that do not declare their own. Release
/// metadata is kilobytes; a megabyte is generous and still finite.
pub const default_max_bytes: u64 = 1024 * 1024;

pub const ReadError = error{
    CannotRead,
    NotAnObject,
    OutOfMemory,
};

pub const Document = struct {
    parsed: std.json.Parsed(std.json.Value),
    identity: file_support.Identity,

    pub fn object(self: *const Document) *const std.json.ObjectMap {
        return &self.parsed.value.object;
    }

    pub fn get(self: *const Document, key: []const u8) ?std.json.Value {
        return self.parsed.value.object.get(key);
    }

    pub fn deinit(self: *Document) void {
        self.parsed.deinit();
        self.* = undefined;
    }
};

/// `read_json`: bounded read, strict parse, and a required top-level object.
pub fn readObject(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    max_bytes: u64,
    diagnostic: *Diagnostic,
) ReadError!Document {
    var contents = file_support.readBoundedIdentified(
        allocator,
        io,
        path,
        max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    defer contents.deinit(allocator);

    if (!std.unicode.utf8ValidateSlice(contents.bytes)) return diagnostic.fail(
        error.CannotRead,
        "cannot read {s}: {s}",
        .{ path, "InvalidUtf8" },
    );

    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        contents.bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    errdefer parsed.deinit();

    if (parsed.value != .object) return diagnostic.fail(
        error.NotAnObject,
        "{s} must contain a JSON object",
        .{path},
    );
    return .{ .parsed = parsed, .identity = contents.identity };
}

pub const FieldError = error{
    MissingField,
    WrongFieldType,
};

/// Strict string accessor: absent and wrong-typed are distinct failures, and a
/// JSON `null` is never treated as a string.
pub fn requireString(
    object: *const std.json.ObjectMap,
    key: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) FieldError![]const u8 {
    const value = object.get(key) orelse return diagnostic.fail(
        error.MissingField,
        "{s} is missing",
        .{label},
    );
    return switch (value) {
        .string => |text| text,
        else => diagnostic.fail(
            error.WrongFieldType,
            "{s} is not a string",
            .{label},
        ),
    };
}

/// Strict integer accessor. Python's release scripts spell this
/// `type(value) is not int`, which rejects booleans and floats; the JSON value
/// union gives the same distinction for free, and a float that happens to be
/// integral is still rejected.
pub fn requireInteger(
    object: *const std.json.ObjectMap,
    key: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) FieldError!i64 {
    const value = object.get(key) orelse return diagnostic.fail(
        error.MissingField,
        "{s} is missing",
        .{label},
    );
    return switch (value) {
        .integer => |number| number,
        else => diagnostic.fail(
            error.WrongFieldType,
            "{s} is not an integer",
            .{label},
        ),
    };
}

pub const CanonicalError = error{
    /// Canonical release documents carry no floating point numbers: their text
    /// is digested, and no two JSON writers agree on float spelling.
    UnsupportedFloat,
    OutOfMemory,
};

pub const Layout = enum {
    /// `json.dumps(value, indent=2, sort_keys=True) + "\n"`.
    document,
    /// `json.dumps(value, separators=(",", ":"), sort_keys=True)`.
    compact,
};

/// Serializes `value` with object keys sorted by code point, non-ASCII escaped,
/// and the layout the Python helpers use.
pub fn canonicalAlloc(
    allocator: Allocator,
    value: std.json.Value,
    layout: Layout,
) CanonicalError![]u8 {
    var allocating: Writer.Allocating = .init(allocator);
    defer allocating.deinit();
    var stringify: std.json.Stringify = .{
        .writer = &allocating.writer,
        .options = .{
            .whitespace = switch (layout) {
                .document => .indent_2,
                .compact => .minified,
            },
            .escape_unicode = true,
        },
    };
    writeCanonical(allocator, &stringify, value) catch |err| switch (err) {
        error.UnsupportedFloat => return error.UnsupportedFloat,
        else => return error.OutOfMemory,
    };
    if (layout == .document) {
        allocating.writer.writeByte('\n') catch return error.OutOfMemory;
    }
    return allocating.toOwnedSlice();
}

/// `write_json`: canonical document bytes replacing `path` atomically.
pub fn writeDocument(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    value: std.json.Value,
) !void {
    const bytes = try canonicalAlloc(allocator, value, .document);
    defer allocator.free(bytes);
    try file_support.writeAtomic(io, path, bytes);
}

fn writeCanonical(
    allocator: Allocator,
    stringify: *std.json.Stringify,
    value: std.json.Value,
) !void {
    switch (value) {
        .null => try stringify.write(null),
        .bool => |flag| try stringify.write(flag),
        .integer => |number| try stringify.write(number),
        .float => return error.UnsupportedFloat,
        .number_string => |text| {
            try stringify.beginWriteRaw();
            try stringify.writer.writeAll(text);
            stringify.endWriteRaw();
        },
        .string => |text| try stringify.write(text),
        .array => |items| {
            try stringify.beginArray();
            for (items.items) |item| {
                try writeCanonical(allocator, stringify, item);
            }
            try stringify.endArray();
        },
        .object => |map| {
            const keys = try allocator.dupe([]const u8, map.keys());
            defer allocator.free(keys);
            std.mem.sort([]const u8, keys, {}, lessThanKey);
            try stringify.beginObject();
            for (keys) |key| {
                try stringify.objectField(key);
                try writeCanonical(allocator, stringify, map.get(key).?);
            }
            try stringify.endObject();
        },
    }
}

fn lessThanKey(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

const testing_max_bytes: u64 = 64 * 1024;

fn parseForTest(text: []const u8) !std.json.Parsed(std.json.Value) {
    return std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        text,
        .{},
    );
}

test "readObject reports the Python failure text for every rejection" {
    const io = std.testing.io;
    var diagnostic: Diagnostic = .{};

    try std.testing.expectError(error.CannotRead, readObject(
        std.testing.allocator,
        io,
        "test-release-json-absent.json",
        testing_max_bytes,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "cannot read test-release-json-absent.json: FileNotFound",
        diagnostic.message(),
    );

    const path = "test-release-json-document.json";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "{" });
    try std.testing.expectError(error.CannotRead, readObject(
        std.testing.allocator,
        io,
        path,
        testing_max_bytes,
        &diagnostic,
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        diagnostic.message(),
        "cannot read test-release-json-document.json: ",
    ));

    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = "[1, 2]" });
    try std.testing.expectError(error.NotAnObject, readObject(
        std.testing.allocator,
        io,
        path,
        testing_max_bytes,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "test-release-json-document.json must contain a JSON object",
        diagnostic.message(),
    );

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = "{\"format\": \"vpc\"}",
    });
    var document = try readObject(
        std.testing.allocator,
        io,
        path,
        testing_max_bytes,
        &diagnostic,
    );
    defer document.deinit();
    try std.testing.expectEqualStrings(
        "vpc",
        try requireString(document.object(), "format", "format", &diagnostic),
    );
}

test "readObject enforces the byte bound and valid UTF-8" {
    const io = std.testing.io;
    var diagnostic: Diagnostic = .{};
    const path = "test-release-json-bounded.json";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = "{\"key\": \"value\"}",
    });
    try std.testing.expectError(error.CannotRead, readObject(
        std.testing.allocator,
        io,
        path,
        4,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "cannot read test-release-json-bounded.json: FileTooLarge",
        diagnostic.message(),
    );

    try std.Io.Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = "{\"key\": \"\xff\xfe\"}",
    });
    try std.testing.expectError(error.CannotRead, readObject(
        std.testing.allocator,
        io,
        path,
        testing_max_bytes,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "cannot read test-release-json-bounded.json: InvalidUtf8",
        diagnostic.message(),
    );
}

test "strict accessors separate missing from wrong-typed" {
    var diagnostic: Diagnostic = .{};
    var parsed = try parseForTest(
        \\{"text": "value", "count": 7, "flag": true, "ratio": 1.5, "nothing": null}
    );
    defer parsed.deinit();
    const object = &parsed.value.object;

    try std.testing.expectEqualStrings(
        "value",
        try requireString(object, "text", "text", &diagnostic),
    );
    try std.testing.expectEqual(
        @as(i64, 7),
        try requireInteger(object, "count", "count", &diagnostic),
    );

    try std.testing.expectError(
        error.MissingField,
        requireString(object, "absent", "absent field", &diagnostic),
    );
    try std.testing.expectEqualStrings("absent field is missing", diagnostic.message());

    try std.testing.expectError(
        error.WrongFieldType,
        requireString(object, "nothing", "nothing", &diagnostic),
    );
    try std.testing.expectEqualStrings("nothing is not a string", diagnostic.message());

    try std.testing.expectError(
        error.WrongFieldType,
        requireInteger(object, "flag", "flag", &diagnostic),
    );
    try std.testing.expectError(
        error.WrongFieldType,
        requireInteger(object, "ratio", "ratio", &diagnostic),
    );
    try std.testing.expectEqualStrings("ratio is not an integer", diagnostic.message());
}

test "canonical output matches json.dumps with sorted keys" {
    var parsed = try parseForTest(
        \\{"zeta": [3, {"b": false, "a": null}], "alpha": "x", "Beta": 10}
    );
    defer parsed.deinit();

    const compact = try canonicalAlloc(
        std.testing.allocator,
        parsed.value,
        .compact,
    );
    defer std.testing.allocator.free(compact);
    try std.testing.expectEqualStrings(
        \\{"Beta":10,"alpha":"x","zeta":[3,{"a":null,"b":false}]}
    ,
        compact,
    );

    const document = try canonicalAlloc(
        std.testing.allocator,
        parsed.value,
        .document,
    );
    defer std.testing.allocator.free(document);
    try std.testing.expectEqualStrings(
        \\{
        \\  "Beta": 10,
        \\  "alpha": "x",
        \\  "zeta": [
        \\    3,
        \\    {
        \\      "a": null,
        \\      "b": false
        \\    }
        \\  ]
        \\}
        \\
    ,
        document,
    );
}

test "canonical output escapes non-ASCII and rejects floats" {
    var parsed = try parseForTest(
        \\{"name": "caf\u00e9"}
    );
    defer parsed.deinit();
    const compact = try canonicalAlloc(
        std.testing.allocator,
        parsed.value,
        .compact,
    );
    defer std.testing.allocator.free(compact);
    try std.testing.expectEqualStrings(
        \\{"name":"caf\u00e9"}
    ,
        compact,
    );

    var floating = try parseForTest(
        \\{"ratio": 1.5}
    );
    defer floating.deinit();
    try std.testing.expectError(error.UnsupportedFloat, canonicalAlloc(
        std.testing.allocator,
        floating.value,
        .compact,
    ));
}

test "writeDocument replaces the destination with canonical bytes" {
    const io = std.testing.io;
    const path = "test-release-json-write.json";
    defer std.Io.Dir.cwd().deleteFile(io, path) catch {};

    var parsed = try parseForTest(
        \\{"b": 2, "a": 1}
    );
    defer parsed.deinit();
    try writeDocument(std.testing.allocator, io, path, parsed.value);

    const written = try file_support.readBounded(
        std.testing.allocator,
        io,
        path,
        testing_max_bytes,
    );
    defer std.testing.allocator.free(written);
    try std.testing.expectEqualStrings(
        \\{
        \\  "a": 1,
        \\  "b": 2
        \\}
        \\
    ,
        written,
    );
}
