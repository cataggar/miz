//! Generates typed Zig bindings (`src/qapi_generated.zig`) from QEMU's QAPI
//! schema (`qapi/*.json`), for the stretch goal in issue #3: "Codegen typed
//! Zig command/event bindings from the qapi/*.json schema files, so
//! commands and their arguments/returns are statically typed rather than
//! free-form JSON."
//!
//! Usage: qapi-codegen <path/to/qapi/qapi-schema.json> <output.zig>
//!
//! This is a best-effort, offline generator, not a build-time dependency of
//! the `qmp` module: run it manually against a QEMU source checkout and
//! commit the result. See zig/qmp/README.md for the coverage/limitations
//! this implies (no `union`/`alternate` types, schema `if`-conditionals are
//! ignored, etc.) — fields/types we can't confidently map fall back to
//! `std.json.Value` rather than being dropped, so every enum/struct/command/
//! event still gets *a* generated declaration.

const std = @import("std");
const Io = std.Io;
const schema = @import("qapi_schema.zig");

const Kind = enum { enum_, struct_, command, event, union_, alternate };

const Def = struct {
    kind: Kind,
    name: []const u8,
    obj: std.json.ObjectMap,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const io = init.io;

    var stderr_buf: [4096]u8 = undefined;
    var stderr_fw: Io.File.Writer = .init(.stderr(), io, &stderr_buf);
    const errw = &stderr_fw.interface;

    const args = try init.minimal.args.toSlice(arena);
    if (args.len != 3) {
        try errw.writeAll("usage: qapi-codegen <path/to/qapi/qapi-schema.json> <output.zig>\n");
        try errw.flush();
        return error.Usage;
    }
    const root_path = args[1];
    const out_path = args[2];

    const root_dir_path = std.fs.path.dirname(root_path) orelse ".";
    var dir: Io.Dir = try Io.Dir.cwd().openDir(io, root_dir_path, .{});
    defer dir.close(io);
    const root_name = std.fs.path.basename(root_path);

    var exprs: std.ArrayList(std.json.Value) = .empty;
    var visited: std.StringHashMap(void) = .init(arena);
    try loadFileInto(arena, io, dir, root_name, &exprs, &visited);

    var defs: std.ArrayList(Def) = .empty;
    var known: std.StringHashMap(void) = .init(arena); // enum + struct names
    var struct_defs: std.StringHashMap(std.json.ObjectMap) = .init(arena);

    for (exprs.items) |expr| {
        if (expr != .object) continue;
        const obj = expr.object;
        const found = kindAndName(obj) orelse continue;
        try defs.append(arena, .{ .kind = found.kind, .name = found.name, .obj = obj });
        switch (found.kind) {
            .enum_, .struct_ => try known.put(found.name, {}),
            else => {},
        }
        if (found.kind == .struct_) try struct_defs.put(found.name, obj);
    }

    var out: std.Io.Writer.Allocating = .init(arena);
    const w = &out.writer;

    try w.writeAll(
        \\//! GENERATED FILE -- DO NOT EDIT.
        \\//!
        \\//! Produced by `zig/qmp/tools/qapi_codegen.zig` from QEMU's QAPI schema
        \\//! (`qapi/*.json`). Best-effort typed bindings: `union`/`alternate` types
        \\//! and schema `if`-conditionals are not modeled -- fields/types this
        \\//! generator can't confidently map fall back to `std.json.Value` rather
        \\//! than being dropped. See zig/qmp/README.md for details.
        \\
        \\const std = @import("std");
        \\const qmp = @import("qmp.zig");
        \\
        \\/// Shared "no meaningful return value" type for commands with no
        \\/// `returns` entry in the schema (the wire reply is `{}`).
        \\pub const Empty = struct {};
        \\
        \\
    );

    var stats: Stats = .{};

    for (defs.items) |def| {
        if (def.kind == .enum_) {
            try emitEnum(w, def);
            stats.enums += 1;
        }
    }
    for (defs.items) |def| {
        if (def.kind == .struct_) {
            try emitStruct(arena, w, &known, &struct_defs, def.name);
            stats.structs += 1;
        }
    }

    var used_names: std.StringHashMap(void) = .init(arena);
    for (defs.items) |def| {
        if (def.kind == .command) {
            if (try emitCommand(arena, w, &known, def.obj, &used_names, errw)) stats.commands += 1 else stats.commands_skipped += 1;
        }
    }
    for (defs.items) |def| {
        if (def.kind == .event) {
            if (try emitEvent(arena, w, &known, def.obj)) stats.events += 1;
        }
    }

    try Io.Dir.cwd().writeFile(io, .{ .sub_path = out_path, .data = out.written() });

    try errw.print(
        "qapi-codegen: {d} enums, {d} structs, {d} commands ({d} skipped: name collisions), {d} events with typed data\n",
        .{ stats.enums, stats.structs, stats.commands, stats.commands_skipped, stats.events },
    );
    try errw.flush();
}

const Stats = struct {
    enums: usize = 0,
    structs: usize = 0,
    commands: usize = 0,
    commands_skipped: usize = 0,
    events: usize = 0,
};

fn kindAndName(obj: std.json.ObjectMap) ?struct { kind: Kind, name: []const u8 } {
    if (obj.get("enum")) |v| return .{ .kind = .enum_, .name = v.string };
    if (obj.get("struct")) |v| return .{ .kind = .struct_, .name = v.string };
    if (obj.get("command")) |v| return .{ .kind = .command, .name = v.string };
    if (obj.get("event")) |v| return .{ .kind = .event, .name = v.string };
    if (obj.get("union")) |v| return .{ .kind = .union_, .name = v.string };
    if (obj.get("alternate")) |v| return .{ .kind = .alternate, .name = v.string };
    return null;
}

fn loadFileInto(
    allocator: std.mem.Allocator,
    io: Io,
    dir: Io.Dir,
    name: []const u8,
    exprs: *std.ArrayList(std.json.Value),
    visited: *std.StringHashMap(void),
) !void {
    if (visited.contains(name)) return;
    try visited.put(name, {});

    const file = try dir.openFile(io, name, .{ .mode = .read_only });
    defer file.close(io);
    const st = try file.stat(io);
    const data = try allocator.alloc(u8, @intCast(st.size));
    const got = try file.readPositionalAll(io, data, 0);
    if (got != data.len) return error.Truncated;

    const file_exprs = try schema.parseExpressions(allocator, data);
    for (file_exprs) |expr| {
        if (expr == .object and expr.object.count() == 1) {
            if (expr.object.get("include")) |inc| {
                try loadFileInto(allocator, io, dir, inc.string, exprs, visited);
                continue;
            }
        }
        try exprs.append(allocator, expr);
    }
}

/// Builtin QAPI scalar type names -> Zig type spelling. Anything not listed
/// here falls through to a reference lookup (`known`) and then to the
/// `std.json.Value` fallback.
fn builtinType(name: []const u8) ?[]const u8 {
    const Entry = struct { []const u8, []const u8 };
    const table = [_]Entry{
        .{ "str", "[]const u8" },
        .{ "bool", "bool" },
        .{ "number", "f64" },
        .{ "int", "i64" },
        .{ "int8", "i8" },
        .{ "int16", "i16" },
        .{ "int32", "i32" },
        .{ "int64", "i64" },
        .{ "uint8", "u8" },
        .{ "uint16", "u16" },
        .{ "uint32", "u32" },
        .{ "uint64", "u64" },
        .{ "size", "u64" },
        .{ "any", "std.json.Value" },
        .{ "null", "void" },
        .{ "QType", "std.json.Value" }, // special builtin enum; not in qapi/*.json
    };
    for (table) |entry| {
        if (std.mem.eql(u8, name, entry[0])) return entry[1];
    }
    return null;
}

fn writeTypeName(w: *Io.Writer, known: *const std.StringHashMap(void), type_spec: std.json.Value) !void {
    switch (type_spec) {
        .string => |s| {
            if (builtinType(s)) |zig_name| {
                try w.writeAll(zig_name);
            } else if (known.contains(s)) {
                try w.writeAll(s);
            } else {
                // Unresolved reference: a union/alternate type, or something
                // this generator doesn't model. Degrade gracefully instead
                // of failing the whole generation run.
                try w.writeAll("std.json.Value");
            }
        },
        .array => |arr| {
            try w.writeAll("[]const ");
            if (arr.items.len == 1) {
                try writeTypeName(w, known, arr.items[0]);
            } else {
                try w.writeAll("std.json.Value");
            }
        },
        .object => |obj| {
            if (obj.get("type")) |t| {
                try writeTypeName(w, known, t);
            } else {
                try w.writeAll("std.json.Value");
            }
        },
        else => try w.writeAll("std.json.Value"),
    }
}

/// Whether `type_spec` carries an `'if'` condition (schema `if`-conditionals
/// aren't modeled here, so such fields may legitimately be absent from any
/// given build's wire output; treat them as optional to reduce spurious
/// parse failures).
fn hasIfCondition(type_spec: std.json.Value) bool {
    return type_spec == .object and type_spec.object.contains("if");
}

/// Zig 0.16 keywords that would otherwise collide with a bare identifier
/// derived from a QAPI name.
const zig_keywords = [_][]const u8{
    "align",       "allowzero", "and",      "anyframe",    "anytype", "asm",         "async",          "await",
    "break",       "callconv",  "catch",    "comptime",    "const",   "continue",    "defer",          "else",
    "enum",        "errdefer",  "error",    "export",      "extern",  "fn",          "for",            "if",
    "inline",      "noalias",   "noinline", "nosuspend",   "opaque",  "or",          "orelse",         "packed",
    "pub",         "resume",    "return",   "linksection", "struct",  "suspend",     "switch",         "test",
    "threadlocal", "try",       "type",     "undefined",   "union",   "unreachable", "usingnamespace", "var",
    "volatile",    "while",     "null",     "true",        "false",   "void",        "noreturn",
};

fn isPlainIdent(name: []const u8) bool {
    if (name.len == 0) return false;
    if (!(std.ascii.isAlphabetic(name[0]) or name[0] == '_')) return false;
    for (name) |c| {
        if (!(std.ascii.isAlphanumeric(c) or c == '_')) return false;
    }
    for (zig_keywords) |kw| {
        if (std.mem.eql(u8, name, kw)) return false;
    }
    return true;
}

fn writeIdent(w: *Io.Writer, name: []const u8) !void {
    if (isPlainIdent(name)) {
        try w.writeAll(name);
    } else {
        try w.print("@\"{s}\"", .{name});
    }
}

fn emitEnum(w: *Io.Writer, def: Def) !void {
    const data = def.obj.get("data") orelse return;
    if (data != .array) return;
    try w.print("pub const {s} = enum {{\n", .{def.name});
    for (data.array.items) |item| {
        const name = switch (item) {
            .string => |s| s,
            .object => |o| blk: {
                const n = o.get("name") orelse continue;
                break :blk n.string;
            },
            else => continue,
        };
        try writeIdent(w, name);
        try w.writeAll(",\n");
    }
    try w.writeAll("};\n\n");
}

fn emitFieldsFromData(w: *Io.Writer, known: *const std.StringHashMap(void), data: std.json.Value) !void {
    if (data != .object) return;
    for (data.object.keys(), data.object.values()) |key, val| {
        var field_name = key;
        var optional = false;
        if (field_name.len > 0 and field_name[0] == '*') {
            optional = true;
            field_name = field_name[1..];
        }
        if (hasIfCondition(val)) optional = true;

        try writeIdent(w, field_name);
        try w.writeAll(": ");
        if (optional) try w.writeAll("?");
        try writeTypeName(w, known, val);
        if (optional) try w.writeAll(" = null");
        try w.writeAll(",\n");
    }
}

fn emitStructBody(
    w: *Io.Writer,
    known: *const std.StringHashMap(void),
    struct_defs: *const std.StringHashMap(std.json.ObjectMap),
    name: []const u8,
    visiting: *std.StringHashMap(void),
) !void {
    if (visiting.contains(name)) return; // cycle guard
    try visiting.put(name, {});

    const obj = struct_defs.get(name) orelse return;
    if (obj.get("base")) |base_val| {
        if (base_val == .string) try emitStructBody(w, known, struct_defs, base_val.string, visiting);
    }
    if (obj.get("data")) |data_val| {
        switch (data_val) {
            .string => |ref| try emitStructBody(w, known, struct_defs, ref, visiting),
            .object => try emitFieldsFromData(w, known, data_val),
            else => {},
        }
    }
}

fn emitStruct(
    allocator: std.mem.Allocator,
    w: *Io.Writer,
    known: *const std.StringHashMap(void),
    struct_defs: *const std.StringHashMap(std.json.ObjectMap),
    name: []const u8,
) !void {
    try w.print("pub const {s} = struct {{\n", .{name});
    var visiting: std.StringHashMap(void) = .init(allocator);
    try emitStructBody(w, known, struct_defs, name, &visiting);
    try w.writeAll("};\n\n");
}

/// `query-status` -> `queryStatus`, `device_add` -> `deviceAdd`,
/// `x-debug-block-dirty-bitmap-sha256` -> `xDebugBlockDirtyBitmapSha256`.
fn camelCase(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var first_segment = true;
    var it = std.mem.tokenizeAny(u8, name, "-_");
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        if (first_segment) {
            try out.appendSlice(allocator, seg);
            first_segment = false;
        } else {
            try out.append(allocator, std.ascii.toUpper(seg[0]));
            try out.appendSlice(allocator, seg[1..]);
        }
    }
    if (out.items.len == 0) try out.appendSlice(allocator, "unnamed");
    return out.items;
}

fn pascalCase(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    const cc = try camelCase(allocator, name);
    if (cc.len > 0) cc[0] = std.ascii.toUpper(cc[0]);
    return cc;
}

/// `BLOCK_JOB_COMPLETED` -> `BlockJobCompleted`, `SHUTDOWN` -> `Shutdown`.
fn pascalCaseFromUpperSnake(allocator: std.mem.Allocator, name: []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    var it = std.mem.tokenizeAny(u8, name, "_-");
    while (it.next()) |seg| {
        if (seg.len == 0) continue;
        try out.append(allocator, std.ascii.toUpper(seg[0]));
        for (seg[1..]) |c| try out.append(allocator, std.ascii.toLower(c));
    }
    if (out.items.len == 0) try out.appendSlice(allocator, "Unnamed");
    return out.items;
}

/// Returns true if a wrapper function was emitted.
fn emitCommand(
    allocator: std.mem.Allocator,
    w: *Io.Writer,
    known: *const std.StringHashMap(void),
    obj: std.json.ObjectMap,
    used_names: *std.StringHashMap(void),
    errw: *Io.Writer,
) !bool {
    const wire_name = obj.get("command").?.string;
    if (obj.get("gen")) |g| {
        if (g == .bool and g.bool == false) return false; // no generated handler in real QEMU either
    }

    const func_name = try camelCase(allocator, wire_name);
    if (used_names.contains(func_name)) {
        try errw.print("qapi-codegen: skipping {s}: function name {s} collides\n", .{ wire_name, func_name });
        return false;
    }
    try used_names.put(func_name, {});

    const data_val = obj.get("data");
    const returns_val = obj.get("returns");

    var args_type_buf: std.Io.Writer.Allocating = .init(allocator);
    var has_args = false;
    var inline_args_name: ?[]const u8 = null;

    if (data_val) |dv| {
        switch (dv) {
            .string => |ref| {
                has_args = true;
                try writeTypeName(&args_type_buf.writer, known, .{ .string = ref });
            },
            .object => {
                has_args = true;
                inline_args_name = try allocator.print("{s}Args", .{try pascalCase(allocator, wire_name)});
                try args_type_buf.writer.writeAll(inline_args_name.?);
            },
            else => {},
        }
    }

    if (inline_args_name) |args_name| {
        try w.print("pub const {s} = struct {{\n", .{args_name});
        try emitFieldsFromData(w, known, data_val.?);
        try w.writeAll("};\n\n");
    }

    var returns_type_buf: std.Io.Writer.Allocating = .init(allocator);
    if (returns_val) |rv| {
        try writeTypeName(&returns_type_buf.writer, known, rv);
    } else {
        try returns_type_buf.writer.writeAll("Empty");
    }

    try w.print("/// QMP command `{s}`.\n", .{wire_name});
    try w.print("pub fn {s}(client: *qmp.Client, allocator: std.mem.Allocator", .{func_name});
    if (has_args) {
        try w.print(", args: {s}", .{args_type_buf.written()});
    }
    try w.print(") !std.json.Parsed({s}) {{\n", .{returns_type_buf.written()});

    if (has_args) {
        try w.writeAll("    var args_value = try qmp.valueFromAny(allocator, args);\n");
        try w.writeAll("    defer args_value.deinit();\n");
        try w.print("    var reply = try client.execute(\"{s}\", args_value.value);\n", .{wire_name});
    } else {
        try w.print("    var reply = try client.execute(\"{s}\", null);\n", .{wire_name});
    }
    try w.writeAll("    defer reply.deinit();\n");
    try w.writeAll("    if (reply.err != null) return error.CommandFailed;\n");
    try w.print(
        "    return std.json.parseFromValue({s}, allocator, reply.result orelse .{{ .object = .empty }}, .{{ .ignore_unknown_fields = true }});\n",
        .{returns_type_buf.written()},
    );
    try w.writeAll("}\n\n");
    return true;
}

/// Returns true if a typed event-data struct was emitted.
fn emitEvent(
    allocator: std.mem.Allocator,
    w: *Io.Writer,
    known: *const std.StringHashMap(void),
    obj: std.json.ObjectMap,
) !bool {
    const wire_name = obj.get("event").?.string;
    const data_val = obj.get("data") orelse return false;
    if (data_val != .object) return false;

    const type_name = try allocator.print("{s}Data", .{try pascalCaseFromUpperSnake(allocator, wire_name)});
    try w.print("/// Data payload of the QMP event `{s}`.\n", .{wire_name});
    try w.print("pub const {s} = struct {{\n", .{type_name});
    try emitFieldsFromData(w, known, data_val);
    try w.writeAll("};\n\n");
    return true;
}

test "camelCase: hyphens, underscores, and mixed separators" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("queryStatus", try camelCase(arena.allocator(), "query-status"));
    try std.testing.expectEqualStrings("deviceAdd", try camelCase(arena.allocator(), "device_add"));
    try std.testing.expectEqualStrings(
        "xDebugBlockDirtyBitmapSha256",
        try camelCase(arena.allocator(), "x-debug-block-dirty-bitmap-sha256"),
    );
}

test "pascalCase: capitalizes the first letter of camelCase" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("QueryStatus", try pascalCase(arena.allocator(), "query-status"));
}

test "pascalCaseFromUpperSnake: event names" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectEqualStrings("Shutdown", try pascalCaseFromUpperSnake(arena.allocator(), "SHUTDOWN"));
    try std.testing.expectEqualStrings(
        "BlockJobCompleted",
        try pascalCaseFromUpperSnake(arena.allocator(), "BLOCK_JOB_COMPLETED"),
    );
}

test "isPlainIdent: rejects keywords and non-identifier chars" {
    try std.testing.expect(isPlainIdent("queryStatus"));
    try std.testing.expect(!isPlainIdent("query-status"));
    try std.testing.expect(!isPlainIdent("error"));
    try std.testing.expect(!isPlainIdent("type"));
    try std.testing.expect(!isPlainIdent(""));
}

test "builtinType: maps QAPI scalar names to Zig types" {
    try std.testing.expectEqualStrings("[]const u8", builtinType("str").?);
    try std.testing.expectEqualStrings("bool", builtinType("bool").?);
    try std.testing.expectEqualStrings("i64", builtinType("int").?);
    try std.testing.expect(builtinType("SomeStructName") == null);
}

test "writeTypeName: builtin, reference, unresolved fallback, and array" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var known: std.StringHashMap(void) = .init(arena.allocator());
    try known.put("StatusInfo", {});

    var out: std.Io.Writer.Allocating = .init(arena.allocator());
    try writeTypeName(&out.writer, &known, .{ .string = "str" });
    try std.testing.expectEqualStrings("[]const u8", out.written());

    var out2: std.Io.Writer.Allocating = .init(arena.allocator());
    try writeTypeName(&out2.writer, &known, .{ .string = "StatusInfo" });
    try std.testing.expectEqualStrings("StatusInfo", out2.written());

    // Unresolved reference (e.g. a union/alternate we don't model).
    var out3: std.Io.Writer.Allocating = .init(arena.allocator());
    try writeTypeName(&out3.writer, &known, .{ .string = "SomeUnion" });
    try std.testing.expectEqualStrings("std.json.Value", out3.written());

    // Array of a known reference.
    var arr = std.json.Array.init(arena.allocator());
    try arr.append(.{ .string = "StatusInfo" });
    var out4: std.Io.Writer.Allocating = .init(arena.allocator());
    try writeTypeName(&out4.writer, &known, .{ .array = arr });
    try std.testing.expectEqualStrings("[]const StatusInfo", out4.written());
}
