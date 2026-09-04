//! The published, provenance-bound form of the core runtime contract.
//!
//! `runtime_contract.zig` holds the contract itself and nothing else, so that
//! the same tables can be compiled into a static guest probe. This module is
//! the host-side half: it writes the contract into a candidate's internal
//! provenance, re-validates the written document, checks a built root against
//! the entries that are supposed to already exist in it, checks the shipped
//! package lock against the entries that name packages, and turns a guest
//! probe report into one operator-facing sentence.
//!
//! The document is deliberately *complete* rather than a digest alone. A
//! digest proves the contract did not change; the full table is what lets a
//! reviewer see what a candidate promised without checking out the commit that
//! built it, which is the whole point of putting it in provenance.

const std = @import("std");

const contract = @import("ubuntu2604_runtime_contract");
const release_contract = @import("../release/contract.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

pub const Diagnostic = release_contract.Diagnostic;
pub const Error = error{ Failed, OutOfMemory };

pub fn fail(
    diagnostic: *Diagnostic,
    comptime fmt: []const u8,
    args: anytype,
) Error {
    diagnostic.set(fmt, args);
    return error.Failed;
}

pub const schema_version: i64 = 1;
pub const document_type = "miz-ubuntu2604-runtime-contract";
pub const release_id = "26.04";
pub const document_max_bytes: u64 = 4 * 1024 * 1024;

/// The provenance filename a candidate binds. Flavor-qualified because only
/// the core appliance has this contract, and a name that did not say so would
/// invite a full-flavor document that describes nothing.
pub fn filenameAlloc(
    allocator: Allocator,
    flavor: []const u8,
    architecture: []const u8,
) Error![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "ubuntu2604-runtime-contract-{s}-{s}.json",
        .{ flavor, architecture },
    );
}

pub const requirement_fields = [_][]const u8{
    "audience",
    "behavior",
    "expect",
    "id",
    "kind",
    "presence",
    "target",
    "why",
};

pub const document_fields = [_][]const u8{
    "architecture",
    "contract_sha256",
    "counts",
    "flavor",
    "forbidden_packages",
    "package_roots",
    "release",
    "requirements",
    "schema",
    "type",
};

pub const count_fields = [_][]const u8{
    "acceptance_only",
    "build_tooling",
    "guest_runtime",
    "total",
};

// ---------------------------------------------------------------------------
// JSON construction.
// ---------------------------------------------------------------------------

const Builder = struct {
    arena: Allocator,

    fn object(_: Builder) std.json.ObjectMap {
        return .empty;
    }

    fn array(self: Builder) std.json.Array {
        return .init(self.arena);
    }

    fn put(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        value: std.json.Value,
    ) Error!void {
        try map.put(self.arena, try self.arena.dupe(u8, key), value);
    }

    fn putString(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        text: []const u8,
    ) Error!void {
        try self.put(map, key, .{ .string = try self.arena.dupe(u8, text) });
    }

    fn putCount(
        self: Builder,
        map: *std.json.ObjectMap,
        key: []const u8,
        number: usize,
    ) Error!void {
        try self.put(map, key, .{ .integer = @intCast(number) });
    }
};

/// Builds the complete document for `architecture`/`flavor`.
pub fn documentValue(
    arena: Allocator,
    architecture: []const u8,
    flavor: []const u8,
) Error!std.json.Value {
    const builder: Builder = .{ .arena = arena };
    var entries = builder.array();
    try entries.ensureTotalCapacity(contract.requirements().len);
    for (contract.requirements()) |entry| {
        var map = builder.object();
        try builder.putString(&map, "audience", entry.audience.key());
        try builder.putString(&map, "behavior", entry.behavior.key());
        try builder.putString(&map, "expect", entry.expect);
        try builder.putString(&map, "id", entry.id);
        try builder.putString(&map, "kind", entry.kind.key());
        try builder.putString(&map, "presence", entry.presence.key());
        try builder.putString(&map, "target", entry.target);
        try builder.putString(&map, "why", entry.why);
        entries.appendAssumeCapacity(.{ .object = map });
    }

    // Issue #677 step 3 publishes the closure statement, not only the
    // requirement list: the explicit roots the build resolves and the
    // convenience packages the closure must never contain.
    var roots = builder.array();
    try roots.ensureTotalCapacity(contract.package_roots.len);
    for (contract.package_roots) |name| {
        roots.appendAssumeCapacity(.{ .string = try arena.dupe(u8, name) });
    }
    var forbidden = builder.array();
    try forbidden.ensureTotalCapacity(contract.forbidden_packages.len);
    for (contract.forbidden_packages) |name| {
        forbidden.appendAssumeCapacity(.{ .string = try arena.dupe(u8, name) });
    }

    var counts = builder.object();
    try builder.putCount(&counts, "acceptance_only", contract.countFor(.acceptance_only));
    try builder.putCount(&counts, "build_tooling", contract.countFor(.build_tooling));
    try builder.putCount(&counts, "guest_runtime", contract.countFor(.guest_runtime));
    try builder.putCount(&counts, "total", contract.requirements().len);

    const contract_digest = contract.digest();
    var document = builder.object();
    try builder.put(&document, "schema", .{ .integer = schema_version });
    try builder.putString(&document, "type", document_type);
    try builder.putString(&document, "release", release_id);
    try builder.putString(&document, "architecture", architecture);
    try builder.putString(&document, "flavor", flavor);
    try builder.putString(&document, "contract_sha256", &contract_digest);
    try builder.put(&document, "counts", .{ .object = counts });
    try builder.put(&document, "package_roots", .{ .array = roots });
    try builder.put(&document, "forbidden_packages", .{ .array = forbidden });
    try builder.put(&document, "requirements", .{ .array = entries });
    return .{ .object = document };
}

/// Writes the document as pretty-printed JSON with a trailing newline, the
/// same shape `support.writeDocument` produces for every other release
/// document.
pub fn write(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const value = try documentValue(arena.allocator(), architecture, flavor);
    const text = std.json.Stringify.valueAlloc(
        allocator,
        value,
        .{ .whitespace = .indent_2 },
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
    };
    defer allocator.free(text);
    var full: std.ArrayList(u8) = .empty;
    defer full.deinit(allocator);
    try full.appendSlice(allocator, text);
    try full.append(allocator, '\n');
    Dir.cwd().writeFile(io, .{ .sub_path = path, .data = full.items }) catch |err|
        return fail(
            diagnostic,
            "cannot write runtime contract {s}: {s}",
            .{ path, @errorName(err) },
        );
}

// ---------------------------------------------------------------------------
// Validation.
// ---------------------------------------------------------------------------

pub const ValidateOptions = struct {
    architecture: ?[]const u8 = null,
    flavor: ?[]const u8 = null,
};

pub const Summary = struct {
    architecture: []const u8,
    flavor: []const u8,
    contract_sha256: []const u8,
    guest_runtime: usize,
    build_tooling: usize,
    acceptance_only: usize,
    total: usize,
};

fn stringOf(value: ?std.json.Value) ?[]const u8 {
    const entry = value orelse return null;
    return switch (entry) {
        .string => |text| text,
        else => null,
    };
}

fn objectOf(value: ?std.json.Value) ?std.json.ObjectMap {
    const entry = value orelse return null;
    return switch (entry) {
        .object => |map| map,
        else => null,
    };
}

fn arrayOf(value: ?std.json.Value) ?[]const std.json.Value {
    const entry = value orelse return null;
    return switch (entry) {
        .array => |items| items.items,
        else => null,
    };
}

fn integerOf(value: ?std.json.Value) ?i64 {
    const entry = value orelse return null;
    return switch (entry) {
        .integer => |number| number,
        else => null,
    };
}

fn hasExactFields(map: std.json.ObjectMap, expected: []const []const u8) bool {
    if (map.count() != expected.len) return false;
    for (expected) |key| {
        if (!map.contains(key)) return false;
    }
    return true;
}

/// Re-checks a document against the contract this build was compiled with.
///
/// The check is exact equality, entry by entry and field by field, rather than
/// a digest comparison alone: a mismatch should say which requirement moved,
/// because "the digest differs" is not a reviewable statement.
pub fn validateDocument(
    value: std.json.Value,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!Summary {
    const object = objectOf(value) orelse return fail(
        diagnostic,
        "runtime contract is not a JSON object",
        .{},
    );
    if (!hasExactFields(object, &document_fields)) return fail(
        diagnostic,
        "runtime contract has unexpected fields",
        .{},
    );
    if (integerOf(object.get("schema")) != schema_version) return fail(
        diagnostic,
        "runtime contract schema is not {d}",
        .{schema_version},
    );
    const kind = stringOf(object.get("type")) orelse "";
    if (!std.mem.eql(u8, kind, document_type)) return fail(
        diagnostic,
        "runtime contract type is not {s}",
        .{document_type},
    );
    const release = stringOf(object.get("release")) orelse "";
    if (!std.mem.eql(u8, release, release_id)) return fail(
        diagnostic,
        "runtime contract release is not {s}",
        .{release_id},
    );
    const architecture = stringOf(object.get("architecture")) orelse return fail(
        diagnostic,
        "runtime contract architecture is invalid",
        .{},
    );
    const flavor = stringOf(object.get("flavor")) orelse return fail(
        diagnostic,
        "runtime contract flavor is invalid",
        .{},
    );
    if (options.architecture) |expected| {
        if (!std.mem.eql(u8, architecture, expected)) return fail(
            diagnostic,
            "runtime contract describes {s}, not {s}",
            .{ architecture, expected },
        );
    }
    if (options.flavor) |expected| {
        if (!std.mem.eql(u8, flavor, expected)) return fail(
            diagnostic,
            "runtime contract describes the {s} flavor, not {s}",
            .{ flavor, expected },
        );
    }

    const entries = arrayOf(object.get("requirements")) orelse return fail(
        diagnostic,
        "runtime contract requirements are invalid",
        .{},
    );
    const expected_entries = contract.requirements();
    if (entries.len != expected_entries.len) return fail(
        diagnostic,
        "runtime contract lists {d} requirements, expected {d}",
        .{ entries.len, expected_entries.len },
    );
    for (entries, expected_entries) |entry_value, expected| {
        const entry = objectOf(entry_value) orelse return fail(
            diagnostic,
            "runtime contract requirement {s} is not an object",
            .{expected.id},
        );
        if (!hasExactFields(entry, &requirement_fields)) return fail(
            diagnostic,
            "runtime contract requirement {s} has unexpected fields",
            .{expected.id},
        );
        try expectField(entry, "id", expected.id, expected.id, diagnostic);
        try expectField(entry, "kind", expected.kind.key(), expected.id, diagnostic);
        try expectField(entry, "target", expected.target, expected.id, diagnostic);
        try expectField(entry, "behavior", expected.behavior.key(), expected.id, diagnostic);
        try expectField(entry, "audience", expected.audience.key(), expected.id, diagnostic);
        try expectField(entry, "presence", expected.presence.key(), expected.id, diagnostic);
        try expectField(entry, "expect", expected.expect, expected.id, diagnostic);
        try expectField(entry, "why", expected.why, expected.id, diagnostic);
    }

    const counts = objectOf(object.get("counts")) orelse return fail(
        diagnostic,
        "runtime contract counts are invalid",
        .{},
    );
    if (!hasExactFields(counts, &count_fields)) return fail(
        diagnostic,
        "runtime contract counts have unexpected fields",
        .{},
    );
    const guest_runtime = contract.countFor(.guest_runtime);
    const build_tooling = contract.countFor(.build_tooling);
    const acceptance_only = contract.countFor(.acceptance_only);
    if (integerOf(counts.get("guest_runtime")) != @as(i64, @intCast(guest_runtime)) or
        integerOf(counts.get("build_tooling")) != @as(i64, @intCast(build_tooling)) or
        integerOf(counts.get("acceptance_only")) != @as(i64, @intCast(acceptance_only)) or
        integerOf(counts.get("total")) != @as(i64, @intCast(expected_entries.len)))
    {
        return fail(diagnostic, "runtime contract counts disagree with its requirements", .{});
    }

    try expectExactStrings(
        object.get("package_roots"),
        &contract.package_roots,
        "package roots",
        diagnostic,
    );
    try expectExactStrings(
        object.get("forbidden_packages"),
        &contract.forbidden_packages,
        "forbidden packages",
        diagnostic,
    );

    const recorded = stringOf(object.get("contract_sha256")) orelse return fail(
        diagnostic,
        "runtime contract digest is invalid",
        .{},
    );
    const expected_digest = contract.digest();
    if (!std.mem.eql(u8, recorded, &expected_digest)) return fail(
        diagnostic,
        "runtime contract digest is {s}, expected {s}",
        .{ recorded, expected_digest },
    );

    return .{
        .architecture = architecture,
        .flavor = flavor,
        .contract_sha256 = recorded,
        .guest_runtime = guest_runtime,
        .build_tooling = build_tooling,
        .acceptance_only = acceptance_only,
        .total = expected_entries.len,
    };
}

/// A published string list must be the compiled one, member for member and in
/// the same order. "Contains" would let a candidate quietly drop an exclusion.
fn expectExactStrings(
    value: ?std.json.Value,
    expected: []const []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const items = arrayOf(value) orelse return fail(
        diagnostic,
        "runtime contract {s} are invalid",
        .{label},
    );
    if (items.len != expected.len) return fail(
        diagnostic,
        "runtime contract lists {d} {s}, expected {d}",
        .{ items.len, label, expected.len },
    );
    for (items, expected) |item, name| {
        const actual = stringOf(item) orelse return fail(
            diagnostic,
            "runtime contract {s} contain a non-string entry",
            .{label},
        );
        if (!std.mem.eql(u8, actual, name)) return fail(
            diagnostic,
            "runtime contract {s} declare {s}, expected {s}",
            .{ label, actual, name },
        );
    }
}

fn expectField(
    entry: std.json.ObjectMap,
    field: []const u8,
    expected: []const u8,
    id: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const actual = stringOf(entry.get(field)) orelse return fail(
        diagnostic,
        "runtime contract requirement {s} has a non-string {s}",
        .{ id, field },
    );
    if (!std.mem.eql(u8, actual, expected)) return fail(
        diagnostic,
        "runtime contract requirement {s} declares {s} {s}, expected {s}",
        .{ id, field, actual, expected },
    );
}

pub fn readValidated(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    options: ValidateOptions,
    diagnostic: *Diagnostic,
) Error!std.json.Parsed(std.json.Value) {
    const bytes = Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(document_max_bytes),
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read runtime contract {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    defer allocator.free(bytes);
    const parsed = std.json.parseFromSlice(
        std.json.Value,
        allocator,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "cannot read runtime contract {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    errdefer parsed.deinit();
    _ = try validateDocument(parsed.value, options, diagnostic);
    return parsed;
}

// ---------------------------------------------------------------------------
// Built-root enforcement.
// ---------------------------------------------------------------------------

pub const EntryKind = enum { regular, directory, symlink, other };

/// How the caller inspects the root being checked.
///
/// The builder holds a mountless ext4 filesystem, the tests hold an ordinary
/// host directory, and the release tool holds neither; an interface keeps this
/// module from having to know which. Every function returns null for "not
/// found or not readable", because the distinction does not change the
/// verdict: the contract says the entry must be there and usable.
pub const RootProbe = struct {
    context: *anyopaque,
    statFn: *const fn (context: *anyopaque, path: []const u8) ?EntryKind,
    readLinkFn: *const fn (context: *anyopaque, path: []const u8, out: []u8) ?[]const u8,
    readFn: *const fn (context: *anyopaque, path: []const u8, out: []u8) ?[]const u8,

    fn stat(self: RootProbe, path: []const u8) ?EntryKind {
        return self.statFn(self.context, path);
    }

    fn readLink(self: RootProbe, path: []const u8, out: []u8) ?[]const u8 {
        return self.readLinkFn(self.context, path, out);
    }

    fn read(self: RootProbe, path: []const u8, out: []u8) ?[]const u8 {
        return self.readFn(self.context, path, out);
    }
};

/// Whether `requirement` is one a built root can be asked about.
pub fn checkedInRoot(requirement: contract.Requirement) bool {
    return requirement.required() and
        requirement.presence == .image and
        requirement.kind.checkableInRoot();
}

/// Fails, by requirement id, when a built root is missing anything the
/// contract says it must already carry.
///
/// This is the gate #677 asks for in "failing clearly if required items
/// disappear": the closure work of step 3 will delete packages, and a deletion
/// that removes `/usr/bin/sudo` should stop the build that made it rather than
/// an Azure VM forty minutes later.
pub fn verifyRoot(
    allocator: Allocator,
    probe: RootProbe,
    diagnostic: *Diagnostic,
) Error!void {
    const scratch = try allocator.alloc(u8, 512 * 1024);
    defer allocator.free(scratch);
    for (contract.requirements()) |requirement| {
        if (!checkedInRoot(requirement)) continue;
        switch (requirement.kind) {
            .command, .file => {
                const kind = probe.stat(requirement.target) orelse return missing(
                    diagnostic,
                    requirement,
                );
                if (kind != .regular) return wrongKind(diagnostic, requirement, "a regular file");
            },
            .directory => {
                const kind = probe.stat(requirement.target) orelse return missing(
                    diagnostic,
                    requirement,
                );
                if (kind != .directory) return wrongKind(diagnostic, requirement, "a directory");
            },
            .symlink => {
                const kind = probe.stat(requirement.target) orelse return missing(
                    diagnostic,
                    requirement,
                );
                if (kind != .symlink) return wrongKind(diagnostic, requirement, "a symbolic link");
                const link = probe.readLink(requirement.target, scratch) orelse return fail(
                    diagnostic,
                    "runtime contract requirement {s} ({s}) is unreadable",
                    .{ requirement.id, requirement.target },
                );
                if (!std.mem.eql(u8, link, requirement.expect)) return fail(
                    diagnostic,
                    "runtime contract requirement {s} ({s}) points at {s}, expected {s}",
                    .{ requirement.id, requirement.target, link, requirement.expect },
                );
            },
            .config, .trust_store => {
                const kind = probe.stat(requirement.target) orelse return missing(
                    diagnostic,
                    requirement,
                );
                if (kind != .regular) return wrongKind(diagnostic, requirement, "a regular file");
                const contents = probe.read(requirement.target, scratch) orelse return fail(
                    diagnostic,
                    "runtime contract requirement {s} ({s}) is unreadable",
                    .{ requirement.id, requirement.target },
                );
                if (std.mem.indexOf(u8, contents, requirement.expect) == null) return fail(
                    diagnostic,
                    "runtime contract requirement {s} ({s}) does not contain {s}",
                    .{ requirement.id, requirement.target, requirement.expect },
                );
            },
            else => unreachable,
        }
    }
}

fn missing(diagnostic: *Diagnostic, requirement: contract.Requirement) Error {
    return fail(
        diagnostic,
        "runtime contract requirement {s} ({s}) is missing from the built root",
        .{ requirement.id, requirement.target },
    );
}

fn wrongKind(
    diagnostic: *Diagnostic,
    requirement: contract.Requirement,
    expected: []const u8,
) Error {
    return fail(
        diagnostic,
        "runtime contract requirement {s} ({s}) is not {s}",
        .{ requirement.id, requirement.target, expected },
    );
}

/// Confirms the shipped exact lock carries every package the contract requires
/// and none of the packages it forbids.
///
/// The lock is the tab-separated `name<TAB>version<TAB>architecture` table the
/// image carries at `/var/lib/miz/ubuntu2604-package-lock.tsv`. Both the
/// `guest_runtime` packages and the `build_tooling` ones are required, because
/// until #677 step 4 moves initramfs generation out of the guest the generator
/// is genuinely installed and a lock without it is a lock that did not describe
/// the image. Whether the closure is *exactly* the resolved set is a separate,
/// stronger check the builder makes against the final debz lock; this one names
/// the missing behavior or the returned convenience.
pub fn verifyPackages(
    lock_text: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    for (contract.requirements()) |requirement| {
        if (requirement.kind != .package) continue;
        if (requirement.audience == .acceptance_only) continue;
        if (!lockContains(lock_text, requirement.target)) return fail(
            diagnostic,
            "runtime contract requirement {s} (package {s}) is absent from the shipped package lock",
            .{ requirement.id, requirement.target },
        );
    }
    for (contract.forbidden_packages) |forbidden| {
        if (lockContains(lock_text, forbidden)) return fail(
            diagnostic,
            "package {s} is installed but no runtime contract behavior needs it",
            .{forbidden},
        );
    }
}

fn lockContains(lock_text: []const u8, name: []const u8) bool {
    var lines = std.mem.splitScalar(u8, lock_text, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (trimmed.len == 0) continue;
        const end = std.mem.indexOfScalar(u8, trimmed, '\t') orelse trimmed.len;
        if (std.mem.eql(u8, trimmed[0..end], name)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Guest probe reports.
// ---------------------------------------------------------------------------

/// Turns a guest probe report into a pass or one operator-facing sentence.
pub fn verifyProbeReport(output: []const u8, diagnostic: *Diagnostic) Error!void {
    var seen: [contract.core_requirements.len]bool = undefined;
    const rejection = contract.verifyReport(output, &seen) orelse return;
    var buffer: [512]u8 = undefined;
    const text = contract.describe(rejection, &buffer);
    return fail(diagnostic, "{s}", .{text});
}

/// The first `filesystem path=<path> ...` line for `path`, which is the ext4
/// accounting the size inventory's `first_boot` phase records.
pub fn filesystemUsage(
    output: []const u8,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!contract.FilesystemLine {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        if (!std.mem.startsWith(u8, line, contract.filesystem_prefix ++ " ")) continue;
        const parsed = contract.parseFilesystemLine(line) catch return fail(
            diagnostic,
            "runtime contract probe emitted an unparseable filesystem line",
            .{},
        );
        if (std.mem.eql(u8, parsed.path, path)) {
            if (parsed.block_size == 0 or parsed.total_blocks == 0 or
                parsed.total_inodes == 0 or
                parsed.free_blocks > parsed.total_blocks or
                parsed.free_inodes > parsed.total_inodes)
            {
                return fail(
                    diagnostic,
                    "runtime contract probe reported inconsistent accounting for {s}",
                    .{path},
                );
            }
            return parsed;
        }
    }
    return fail(
        diagnostic,
        "runtime contract probe reported no filesystem accounting for {s}",
        .{path},
    );
}
