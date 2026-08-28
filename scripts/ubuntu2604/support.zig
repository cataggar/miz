//! Shared plumbing for the Ubuntu 26.04 release tool.
//!
//! The Python this replaces expresses every rejection as `fail(message)`, a
//! `SystemExit` carrying one operator-facing line. That single failure shape is
//! reproduced here as `error.Failed` plus a `Diagnostic` holding the exact
//! text, so callers keep the Python's control flow (`try`) while CI logs and
//! the shell callers that match on the text keep seeing the same sentences.
//!
//! The rest of the module is the handful of Python idioms the release logic
//! leans on that Zig has no direct spelling for: deep `==` over parsed JSON,
//! `set(document) != {...}` key-set exactness, `type(value) is not int`, and
//! `sorted(root.rglob("*"))` with `pathlib`'s component-wise ordering.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const release = @import("../release/root.zig");

pub const Diagnostic = release.contract.Diagnostic;
pub const digest = release.digest;
pub const file_support = release.file;
pub const json_document = release.json_document;

/// Every rejection in the Python is one `fail()` line; `error.Failed` is that
/// line, and the diagnostic carries its text.
pub const Error = error{ Failed, OutOfMemory };

pub fn fail(
    diagnostic: *Diagnostic,
    comptime fmt: []const u8,
    args: anytype,
) Error {
    diagnostic.set(fmt, args);
    return error.Failed;
}

/// Release documents are metadata: kilobytes at most.
pub const document_max_bytes: u64 = 1024 * 1024;
/// Upper bound on any single artifact this tool hashes. The published QCOW2s
/// are gigabytes; 64 GiB is far above any real candidate and still finite.
pub const artifact_max_bytes: u64 = 64 * 1024 * 1024 * 1024;

pub fn readObject(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!json_document.Document {
    return json_document.readObject(
        allocator,
        io,
        path,
        document_max_bytes,
        diagnostic,
    ) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Failed,
    };
}

/// `require_sha256`.
pub fn requireSha256(
    value: ?std.json.Value,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error![]const u8 {
    return release.contract.requireSha256(value, label, diagnostic) catch
        error.Failed;
}

/// `require_commit`.
pub fn requireCommit(
    value: ?std.json.Value,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error![]const u8 {
    return release.contract.requireCommit(value, label, diagnostic) catch
        error.Failed;
}

pub fn isSha256(text: []const u8) bool {
    return release.contract.isSha256Hex(text);
}

pub fn isCommit(text: []const u8) bool {
    return release.contract.isCommitHex(text);
}

pub fn stringOf(value: ?std.json.Value) ?[]const u8 {
    const present = value orelse return null;
    return switch (present) {
        .string => |text| text,
        else => null,
    };
}

/// `type(value) is not int`: a JSON boolean is a distinct variant here, and an
/// integral-valued float is still not an integer.
pub fn integerOf(value: ?std.json.Value) ?i64 {
    const present = value orelse return null;
    return switch (present) {
        .integer => |number| number,
        else => null,
    };
}

/// Returned by value: a pointer into the switch capture of a by-value
/// parameter would dangle the moment this returns, and the map itself is a
/// handful of slices into the parsed document, so copying it is free and safe
/// for the read-only use every caller makes of it.
pub fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const present = value orelse return null;
    return switch (present) {
        .object => |map| map,
        else => null,
    };
}

pub fn arrayOf(value: ?std.json.Value) ?[]const std.json.Value {
    const present = value orelse return null;
    return switch (present) {
        .array => |items| items.items,
        else => null,
    };
}

pub fn isTrue(value: ?std.json.Value) bool {
    const present = value orelse return false;
    return present == .bool and present.bool;
}

/// Whether `value` is a string equal to `expected`.
pub fn stringIs(value: ?std.json.Value, expected: []const u8) bool {
    const text = stringOf(value) orelse return false;
    return std.mem.eql(u8, text, expected);
}

/// `set(object) == expected`, with `expected` sorted and duplicate-free.
pub fn hasExactFields(
    object: std.json.ObjectMap,
    expected: []const []const u8,
) bool {
    if (object.count() != expected.len) return false;
    for (expected) |name| {
        if (!object.contains(name)) return false;
    }
    return true;
}

/// `has_exact_contracts`: a list of strings whose set equals `expected` and
/// whose length matches, so duplicates are rejected.
pub fn hasExactContracts(
    value: ?std.json.Value,
    expected: []const []const u8,
) bool {
    const items = arrayOf(value) orelse return false;
    if (items.len != expected.len) return false;
    for (expected) |name| {
        var found = false;
        for (items) |item| {
            if (stringIs(item, name)) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    for (items) |item| {
        if (item != .string) return false;
    }
    return true;
}

/// `value == expected` for a list of strings, order included.
pub fn isExactOrderedStrings(
    value: ?std.json.Value,
    expected: []const []const u8,
) bool {
    const items = arrayOf(value) orelse return false;
    if (items.len != expected.len) return false;
    for (items, expected) |item, name| {
        if (!stringIs(item, name)) return false;
    }
    return true;
}

/// Python's `==` over decoded JSON.
pub fn jsonEqual(left: std.json.Value, right: std.json.Value) bool {
    return switch (left) {
        .null => right == .null,
        .bool => |flag| right == .bool and right.bool == flag,
        .integer => |number| switch (right) {
            .integer => |other| other == number,
            else => false,
        },
        .float => |number| switch (right) {
            .float => |other| other == number,
            else => false,
        },
        .number_string => |text| switch (right) {
            .number_string => |other| std.mem.eql(u8, other, text),
            else => false,
        },
        .string => |text| switch (right) {
            .string => |other| std.mem.eql(u8, other, text),
            else => false,
        },
        .array => |items| switch (right) {
            .array => |others| blk: {
                if (items.items.len != others.items.len) break :blk false;
                for (items.items, others.items) |item, other| {
                    if (!jsonEqual(item, other)) break :blk false;
                }
                break :blk true;
            },
            else => false,
        },
        .object => |map| switch (right) {
            .object => |other| blk: {
                if (map.count() != other.count()) break :blk false;
                var iterator = map.iterator();
                while (iterator.next()) |entry| {
                    const counterpart = other.get(entry.key_ptr.*) orelse
                        break :blk false;
                    if (!jsonEqual(entry.value_ptr.*, counterpart)) break :blk false;
                }
                break :blk true;
            },
            else => false,
        },
    };
}

/// Builds JSON values into an arena, so a document under construction is freed
/// in one step and no intermediate needs its own lifetime.
pub const Builder = struct {
    arena: Allocator,

    pub fn init(arena: Allocator) Builder {
        return .{ .arena = arena };
    }

    /// `std.json.ObjectMap` is unmanaged, so the arena is threaded through
    /// every mutation rather than stored in the map.
    pub fn object(self: Builder) std.json.ObjectMap {
        _ = self;
        return .empty;
    }

    pub fn array(self: Builder) std.json.Array {
        return .init(self.arena);
    }

    pub fn string(self: Builder, text: []const u8) Error!std.json.Value {
        return .{ .string = try self.arena.dupe(u8, text) };
    }

    pub fn print(
        self: Builder,
        comptime fmt: []const u8,
        args: anytype,
    ) Error!std.json.Value {
        return .{ .string = try std.fmt.allocPrint(self.arena, fmt, args) };
    }

    pub fn strings(self: Builder, items: []const []const u8) Error!std.json.Value {
        var list: std.json.Array = .init(self.arena);
        try list.ensureTotalCapacity(items.len);
        for (items) |item| list.appendAssumeCapacity(try self.string(item));
        return .{ .array = list };
    }

    pub fn put(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        value: std.json.Value,
    ) Error!void {
        try map.put(self.arena, try self.arena.dupe(u8, key), value);
    }

    pub fn putString(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        text: []const u8,
    ) Error!void {
        try self.put(map, key, try self.string(text));
    }

    pub fn putInteger(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        number: i64,
    ) Error!void {
        try self.put(map, key, .{ .integer = number });
    }

    /// Deep copy, so a value borrowed from a parsed document can outlive it.
    pub fn clone(self: Builder, value: std.json.Value) Error!std.json.Value {
        return switch (value) {
            .null, .bool, .integer, .float => value,
            .number_string => |text| .{
                .number_string = try self.arena.dupe(u8, text),
            },
            .string => |text| try self.string(text),
            .array => |items| blk: {
                var list: std.json.Array = .init(self.arena);
                try list.ensureTotalCapacity(items.items.len);
                for (items.items) |item| {
                    list.appendAssumeCapacity(try self.clone(item));
                }
                break :blk .{ .array = list };
            },
            .object => |map| blk: {
                var copy: std.json.ObjectMap = .empty;
                var iterator = map.iterator();
                while (iterator.next()) |entry| {
                    try copy.put(
                        self.arena,
                        try self.arena.dupe(u8, entry.key_ptr.*),
                        try self.clone(entry.value_ptr.*),
                    );
                }
                break :blk .{ .object = copy };
            },
        };
    }
};

/// `write_json`.
pub fn writeDocument(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    value: std.json.Value,
    diagnostic: *Diagnostic,
) Error!void {
    json_document.writeDocument(allocator, io, path, value) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot write {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
}

/// `hashlib.sha256(json.dumps(value, separators=(",", ":"), sort_keys=True))`.
pub fn canonicalDigest(
    allocator: Allocator,
    value: std.json.Value,
) Error!digest.Hex {
    const bytes = json_document.canonicalAlloc(allocator, value, .compact) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.UnsupportedFloat => return error.OutOfMemory,
        };
    defer allocator.free(bytes);
    return digest.hexBytes(bytes);
}

/// `pathlib` orders paths by their components, so `a/b` sorts before `a-c`
/// even though the whole strings compare the other way. Provenance records are
/// emitted in this order and their digest is over the emitted list, so the
/// ordering is part of the published contract.
pub fn lessThanPath(_: void, left: []const u8, right: []const u8) bool {
    var left_parts = std.mem.splitScalar(u8, left, '/');
    var right_parts = std.mem.splitScalar(u8, right, '/');
    while (true) {
        const left_part = left_parts.next() orelse return right_parts.next() != null;
        const right_part = right_parts.next() orelse return false;
        if (!std.mem.eql(u8, left_part, right_part)) {
            return std.mem.lessThan(u8, left_part, right_part);
        }
    }
}

/// Relative POSIX paths of every regular file under `root`, sorted the way
/// `sorted(root.rglob("*"))` sorts them. A `root` that is not a directory
/// yields `error.NotADirectory`; a directory that cannot be walked is an error
/// rather than an empty list, so an unreadable tree never looks empty.
///
/// "Regular file" is decided the way Python's `Path.is_file()` decides it:
/// by following the entry. A symlink to a regular file is therefore a file
/// here, which is what keeps the private-key scan and the provenance allowlist
/// looking at the same set -- a symlink that the walker's raw directory-entry
/// type alone would have skipped is exactly the one that could otherwise carry
/// key material into a published bundle. Symlinked directories are still not
/// descended into, matching `rglob`.
pub fn listFiles(
    allocator: Allocator,
    io: Io,
    root: []const u8,
) ![][]const u8 {
    var results: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (results.items) |item| allocator.free(item);
        results.deinit(allocator);
    }

    var directory = try Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    var walker = try directory.walk(allocator);
    defer walker.deinit();
    while (try walker.next(io)) |entry| {
        if (entry.kind == .directory) continue;
        if (!entryIsFile(io, entry.dir, entry.basename)) continue;
        const relative = try allocator.dupe(u8, entry.path);
        errdefer allocator.free(relative);
        try results.append(allocator, relative);
    }

    const items = try results.toOwnedSlice(allocator);
    std.mem.sort([]const u8, items, {}, lessThanPath);
    return items;
}

pub fn freePaths(allocator: Allocator, paths: [][]const u8) void {
    for (paths) |path| allocator.free(path);
    allocator.free(paths);
}

/// Relative POSIX paths of every regular file under `root` whose final
/// component is `filename`, sorted. Mirrors `sorted(root.rglob(filename))`.
pub fn listFilesNamed(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    filename: []const u8,
) ![][]const u8 {
    const all = try listFiles(allocator, io, root);
    defer freePaths(allocator, all);

    var results: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (results.items) |item| allocator.free(item);
        results.deinit(allocator);
    }
    for (all) |path| {
        if (!std.mem.eql(u8, std.fs.path.basename(path), filename)) continue;
        try results.append(allocator, try allocator.dupe(u8, path));
    }
    return results.toOwnedSlice(allocator);
}

/// Relative POSIX paths of every regular file under `root` whose name ends
/// with `suffix`, sorted. Mirrors `sorted(root.rglob("*" ++ suffix))`.
pub fn listFilesWithSuffix(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    suffix: []const u8,
) ![][]const u8 {
    const all = try listFiles(allocator, io, root);
    defer freePaths(allocator, all);

    var results: std.ArrayList([]const u8) = .empty;
    errdefer {
        for (results.items) |item| allocator.free(item);
        results.deinit(allocator);
    }
    for (all) |path| {
        if (!std.mem.endsWith(u8, std.fs.path.basename(path), suffix)) continue;
        try results.append(allocator, try allocator.dupe(u8, path));
    }
    return results.toOwnedSlice(allocator);
}

/// `Path.resolve()`: an absolute, normalized spelling that does not require
/// the path to exist. The resolved form is what the Python prints in its
/// "missing" diagnostics, so a relative argument has to come back anchored at
/// the working directory rather than merely lexically tidied --
/// `std.fs.path.resolve` alone leaves `bundle/asset.qcow2` relative, which
/// would print a path the operator cannot paste back.
///
/// Like `Path.resolve(strict=False)`, symlinks are followed for the part of
/// the path that exists and the remaining tail is kept lexically: a component
/// that does not exist cannot be a symlink, so its spelling is already final.
pub fn resolvePath(allocator: Allocator, io: Io, path: []const u8) Error![]u8 {
    const absolute = try absolutePath(allocator, io, path);
    defer allocator.free(absolute);
    const lexical = std.fs.path.resolve(allocator, &.{absolute}) catch
        return error.OutOfMemory;
    defer allocator.free(lexical);
    return canonicalizeExisting(allocator, io, lexical, 0);
}

/// The lexical path anchored at the working directory. A failure to read the
/// working directory leaves the caller's spelling untouched: resolution is for
/// diagnostics, and a broken `.` must not turn a real rejection into an error
/// about the process's own state.
fn absolutePath(allocator: Allocator, io: Io, path: []const u8) Error![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        return allocator.dupe(u8, path) catch error.OutOfMemory;
    }
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = Dir.cwd().realPathFile(io, ".", &buffer) catch
        return allocator.dupe(u8, path) catch error.OutOfMemory;
    return std.fmt.allocPrint(
        allocator,
        "{s}/{s}",
        .{ buffer[0..length], path },
    ) catch error.OutOfMemory;
}

/// Canonicalizes the longest existing prefix of `lexical` and re-attaches the
/// tail that does not exist yet.
fn canonicalizeExisting(
    allocator: Allocator,
    io: Io,
    lexical: []const u8,
    depth: usize,
) Error![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (Dir.cwd().realPathFile(io, lexical, &buffer)) |length| {
        return allocator.dupe(u8, buffer[0..length]) catch error.OutOfMemory;
    } else |_| {}
    // A bound on how much of the tail may be missing, so a pathological
    // spelling cannot turn a diagnostic into an unbounded walk.
    if (depth >= 64) return allocator.dupe(u8, lexical) catch error.OutOfMemory;
    const parent = std.fs.path.dirname(lexical) orelse
        return allocator.dupe(u8, lexical) catch error.OutOfMemory;
    if (parent.len == 0 or parent.len >= lexical.len) {
        return allocator.dupe(u8, lexical) catch error.OutOfMemory;
    }
    const base = std.fs.path.basename(lexical);
    if (base.len == 0) return allocator.dupe(u8, lexical) catch error.OutOfMemory;
    const resolved_parent = try canonicalizeExisting(allocator, io, parent, depth + 1);
    defer allocator.free(resolved_parent);
    const separator: []const u8 = if (std.mem.endsWith(u8, resolved_parent, "/"))
        ""
    else
        "/";
    return std.fmt.allocPrint(
        allocator,
        "{s}{s}{s}",
        .{ resolved_parent, separator, base },
    ) catch error.OutOfMemory;
}

pub fn joinPath(
    allocator: Allocator,
    parts: []const []const u8,
) Allocator.Error![]u8 {
    return std.fs.path.join(allocator, parts) catch error.OutOfMemory;
}

pub fn isRegularFile(io: Io, path: []const u8) bool {
    const stat = Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .file;
}

/// `Path.is_file()` for one entry of an open directory.
///
/// The kind `readdir` reports is a hint, never the answer. A symlink to a
/// regular file is a file to `is_file()`, so filtering on the raw dirent kind
/// would let a symlinked asset slip past an "exactly these names" check; and a
/// filesystem is free to report `.unknown` for every entry it returns, which
/// would make the same filter drop everything. The verdict therefore always
/// comes from a `stat` that follows links, exactly as the Python's `is_file()`
/// did -- including its answer for an entry that cannot be stat'ed at all.
pub fn entryIsFile(io: Io, directory: Dir, name: []const u8) bool {
    const stat = directory.statFile(io, name, .{}) catch return false;
    return stat.kind == .file;
}

pub fn isDirectory(io: Io, path: []const u8) bool {
    const stat = Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

pub fn pathExists(io: Io, path: []const u8) bool {
    _ = Dir.cwd().statFile(io, path, .{}) catch return false;
    return true;
}

/// `sha256(path)` plus the file size, both of which the callers need together.
pub fn hashArtifact(io: Io, path: []const u8) !digest.FileDigest {
    return digest.hashFile(io, path, artifact_max_bytes);
}

const TempTree = @import("../release/testing.zig").TempTree;

test "jsonEqual is a deep comparison that separates types" {
    const parse = struct {
        fn call(text: []const u8) !std.json.Parsed(std.json.Value) {
            return std.json.parseFromSlice(
                std.json.Value,
                std.testing.allocator,
                text,
                .{},
            );
        }
    }.call;

    var left = try parse(
        \\{"a": [1, {"b": null, "c": true}], "d": "x"}
    );
    defer left.deinit();
    var same = try parse(
        \\{"d": "x", "a": [1, {"c": true, "b": null}]}
    );
    defer same.deinit();
    var different = try parse(
        \\{"a": [1, {"b": null, "c": false}], "d": "x"}
    );
    defer different.deinit();
    var extra = try parse(
        \\{"a": [1, {"b": null, "c": true}], "d": "x", "e": 1}
    );
    defer extra.deinit();

    try std.testing.expect(jsonEqual(left.value, same.value));
    try std.testing.expect(!jsonEqual(left.value, different.value));
    try std.testing.expect(!jsonEqual(left.value, extra.value));

    var boolean = try parse("true");
    defer boolean.deinit();
    var one = try parse("1");
    defer one.deinit();
    try std.testing.expect(!jsonEqual(boolean.value, one.value));
}

test "integerOf rejects booleans and floats like type(value) is not int" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"i": 3, "b": true, "f": 3.0, "s": "3"}
    ,
        .{},
    );
    defer parsed.deinit();
    const object = &parsed.value.object;
    try std.testing.expectEqual(@as(?i64, 3), integerOf(object.get("i")));
    try std.testing.expectEqual(@as(?i64, null), integerOf(object.get("b")));
    try std.testing.expectEqual(@as(?i64, null), integerOf(object.get("f")));
    try std.testing.expectEqual(@as(?i64, null), integerOf(object.get("s")));
    try std.testing.expectEqual(@as(?i64, null), integerOf(object.get("absent")));
}

test "hasExactContracts rejects duplicates, extras, and non-strings" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"ok": ["a", "b"], "dup": ["a", "a"], "extra": ["a", "b", "c"],
        \\ "typed": ["a", 2], "short": ["a"]}
    ,
        .{},
    );
    defer parsed.deinit();
    const object = &parsed.value.object;
    const expected = [_][]const u8{ "a", "b" };
    try std.testing.expect(hasExactContracts(object.get("ok"), &expected));
    try std.testing.expect(!hasExactContracts(object.get("dup"), &expected));
    try std.testing.expect(!hasExactContracts(object.get("extra"), &expected));
    try std.testing.expect(!hasExactContracts(object.get("typed"), &expected));
    try std.testing.expect(!hasExactContracts(object.get("short"), &expected));
    try std.testing.expect(!hasExactContracts(null, &expected));
}

test "path ordering matches pathlib's component-wise comparison" {
    var paths = [_][]const u8{ "a.txt", "a/b", "a-c", "B", "a/b/c" };
    std.mem.sort([]const u8, &paths, {}, lessThanPath);
    try std.testing.expectEqualStrings("B", paths[0]);
    try std.testing.expectEqualStrings("a/b", paths[1]);
    try std.testing.expectEqualStrings("a/b/c", paths[2]);
    try std.testing.expectEqualStrings("a-c", paths[3]);
    try std.testing.expectEqualStrings("a.txt", paths[4]);
}

test "listFiles walks recursively and skips directories" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "tree");
    var nested_buffer: [TempTree.max_path_len]u8 = undefined;
    const nested = tree.path(&nested_buffer, "tree/nested");
    try Dir.cwd().createDirPath(io, nested);

    var first_buffer: [TempTree.max_path_len]u8 = undefined;
    try Dir.cwd().writeFile(io, .{
        .sub_path = tree.path(&first_buffer, "tree/top.json"),
        .data = "{}",
    });
    var second_buffer: [TempTree.max_path_len]u8 = undefined;
    try Dir.cwd().writeFile(io, .{
        .sub_path = tree.path(&second_buffer, "tree/nested/inner.json"),
        .data = "{}",
    });

    const files = try listFiles(std.testing.allocator, io, root);
    defer freePaths(std.testing.allocator, files);
    try std.testing.expectEqual(@as(usize, 2), files.len);
    try std.testing.expectEqualStrings("nested/inner.json", files[0]);
    try std.testing.expectEqualStrings("top.json", files[1]);

    const named = try listFilesNamed(
        std.testing.allocator,
        io,
        root,
        "inner.json",
    );
    defer freePaths(std.testing.allocator, named);
    try std.testing.expectEqual(@as(usize, 1), named.len);
    try std.testing.expectEqualStrings("nested/inner.json", named[0]);
}

test "listFiles follows symlinks the way Path.is_file does" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "linked");
    try Dir.cwd().createDirPath(io, root);

    var target_buffer: [TempTree.max_path_len]u8 = undefined;
    const target = tree.path(&target_buffer, "outside.pem");
    try Dir.cwd().writeFile(io, .{ .sub_path = target, .data = "secret" });

    var directory = try Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    // A symlink to a regular file outside the tree is still a file, so it is
    // enumerated and therefore scanned and attested rather than invisible.
    try directory.symLink(io, "../outside.pem", "linked.pem", .{});
    // A dangling symlink resolves to nothing and is skipped, exactly as
    // `is_file()` reports False for it.
    try directory.symLink(io, "../absent", "dangling", .{});
    // A symlinked directory is neither a file nor descended into.
    var nested_buffer: [TempTree.max_path_len]u8 = undefined;
    const nested = tree.path(&nested_buffer, "elsewhere");
    try Dir.cwd().createDirPath(io, nested);
    try directory.symLink(io, "../elsewhere", "directory", .{});

    const files = try listFiles(std.testing.allocator, io, root);
    defer freePaths(std.testing.allocator, files);
    try std.testing.expectEqual(@as(usize, 1), files.len);
    try std.testing.expectEqualStrings("linked.pem", files[0]);
}

test "resolvePath anchors a relative path the way Path.resolve does" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "resolve");
    try Dir.cwd().createDirPath(io, root);

    // A relative path comes back absolute rather than merely tidied, which is
    // what makes a "missing" diagnostic paste-able.
    const absolute_root = try resolvePath(std.testing.allocator, io, root);
    defer std.testing.allocator.free(absolute_root);
    try std.testing.expect(std.fs.path.isAbsolute(absolute_root));
    try std.testing.expect(std.mem.endsWith(u8, absolute_root, "/resolve"));

    // Redundant components normalize away, and a tail that does not exist is
    // still resolved rather than rejected.
    const noisy = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/./nested/../asset.qcow2",
        .{root},
    );
    defer std.testing.allocator.free(noisy);
    const normalized = try resolvePath(std.testing.allocator, io, noisy);
    defer std.testing.allocator.free(normalized);
    const expected = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/asset.qcow2",
        .{absolute_root},
    );
    defer std.testing.allocator.free(expected);
    try std.testing.expectEqualStrings(expected, normalized);

    // `.` resolves to the working directory itself, not to ".".
    const here = try resolvePath(std.testing.allocator, io, ".");
    defer std.testing.allocator.free(here);
    try std.testing.expect(std.fs.path.isAbsolute(here));
    try std.testing.expect(!std.mem.eql(u8, here, "."));
}

test "resolvePath canonicalizes the existing prefix and keeps the missing tail" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var real_buffer: [TempTree.max_path_len]u8 = undefined;
    const real = tree.path(&real_buffer, "real");
    try Dir.cwd().createDirPath(io, real);
    var link_buffer: [TempTree.max_path_len]u8 = undefined;
    const link = tree.path(&link_buffer, "link");
    try Dir.cwd().symLink(io, "real", link, .{});

    // `Path.resolve()` follows symlinks through the part of the path that
    // exists, so the printed path names the real location.
    const through_link = try std.fmt.allocPrint(
        std.testing.allocator,
        "{s}/absent/deeper.json",
        .{link},
    );
    defer std.testing.allocator.free(through_link);
    const resolved = try resolvePath(std.testing.allocator, io, through_link);
    defer std.testing.allocator.free(resolved);
    try std.testing.expect(std.mem.endsWith(
        u8,
        resolved,
        "/real/absent/deeper.json",
    ));
    try std.testing.expect(std.mem.indexOf(u8, resolved, "/link/") == null);
}

test "entryIsFile answers from the stat, not from what readdir reported" {
    const io = std.testing.io;
    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "entries");
    try Dir.cwd().createDirPath(io, root);

    var directory = try Dir.cwd().openDir(io, root, .{ .iterate = true });
    defer directory.close(io);
    try directory.writeFile(io, .{ .sub_path = "asset.qcow2", .data = "payload" });
    try directory.createDirPath(io, "nested");
    try directory.symLink(io, "asset.qcow2", "linked.qcow2", .{});
    try directory.symLink(io, "nested", "linked-directory", .{});
    try directory.symLink(io, "absent", "dangling", .{});

    // A symlink to a regular file is a file, which is what makes an "exactly
    // these names" check see an extra staged asset rather than skip it.
    try std.testing.expect(entryIsFile(io, directory, "asset.qcow2"));
    try std.testing.expect(entryIsFile(io, directory, "linked.qcow2"));
    try std.testing.expect(!entryIsFile(io, directory, "nested"));
    try std.testing.expect(!entryIsFile(io, directory, "linked-directory"));
    try std.testing.expect(!entryIsFile(io, directory, "dangling"));
    try std.testing.expect(!entryIsFile(io, directory, "never-created"));

    // The same verdicts hold whatever kind the directory iteration reported,
    // which is what makes the callers correct on a filesystem that answers
    // `.unknown` for every entry.
    var iterator = directory.iterate();
    var files: usize = 0;
    var disagreements: usize = 0;
    while (try iterator.next(io)) |item| {
        const is_file = entryIsFile(io, directory, item.name);
        if (is_file) files += 1;
        if ((item.kind == .file) != is_file) disagreements += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), files);
    // `linked.qcow2` is reported as a symlink and is nonetheless a file: the
    // dirent kind and the answer are not the same question.
    try std.testing.expectEqual(@as(usize, 1), disagreements);
}

test "canonicalDigest hashes the compact sorted encoding" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"b": 2, "a": 1}
    ,
        .{},
    );
    defer parsed.deinit();
    const hex = try canonicalDigest(std.testing.allocator, parsed.value);
    try std.testing.expectEqualStrings(
        &digest.hexBytes("{\"a\":1,\"b\":2}"),
        &hex,
    );
}
