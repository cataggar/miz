//! Repeatable host benchmark for the pinned Ubuntu 26.04 arm64 bare-metal image.
//!
//! Native port of `scripts/ubuntu2604_image_benchmark.py`. The benchmark is a
//! measurement instrument, so every contract it enforces exists to make a
//! number trustworthy: the profile is fixed, the inputs are content-addressed
//! and verified before the clock starts, the measured builds are offline, the
//! semantic result of every run is compared against the warm-up reference, and
//! cleanup only ever removes paths it re-resolved inside the run directory it
//! created. A benchmark that cannot prove those things is reported invalid
//! rather than reported slow.
//!
//! The command interface adds the subcommands the benchmark workflow used to
//! spell as inline Python:
//!
//!     ubuntu2604-image-benchmark run --output-root DIR ...
//!     ubuntu2604-image-benchmark verify-staging --input-root DIR
//!     ubuntu2604-image-benchmark gate --summary S --status T --output G \
//!         --step-summary M --ceiling-ns N
//!     ubuntu2604-image-benchmark scan-private-material --evidence-root E \
//!         --benchmark-root B
//!
//! `run` keeps the exact option set, validation, and exit codes of the Python:
//! a validation failure prints `benchmark invalid: <message>` to stderr and
//! exits 1, a usage error exits 2, and success prints the summary path.
//!
//! One documented difference: the recorded host identity no longer carries a
//! `python` version field, because nothing in this benchmark runs Python.

const builtin = @import("builtin");
const std = @import("std");
const release = @import("release/root.zig");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const File = std.Io.File;
const Io = std.Io;
const Sha256 = std.crypto.hash.sha2.Sha256;
const Value = std.json.Value;
const ObjectMap = std.json.ObjectMap;
const JsonArray = std.json.Array;
const contract = release.contract;
const digest_support = release.digest;
const file_support = release.file;
const json_document = release.json_document;

pub const schema = 1;
pub const architecture = "aarch64";
pub const ubuntu_architecture = "arm64";
pub const flavor = "baremetal";
pub const optimize_mode = "ReleaseSafe";
pub const virtual_size: i64 = 5 * 1024 * 1024 * 1024;
pub const minimum_free_disk: u64 = 30 * 1024 * 1024 * 1024;
pub const measured_runs = 3;
pub const source_name = "ubuntu-26.04-server-cloudimg-arm64.img";
pub const source_sha256 =
    "3e113fdd41f39e13729375173bb2ae793f87dc6db4294e5251ff2476971788ba";
pub const manifest_name = "ubuntu-26.04-server-cloudimg-arm64.manifest";
pub const manifest_sha256 =
    "2889120db0432e8029f8f01622efb40ce964e434ba2c81e98937ad1e2616e4f5";
pub const sums_sha256 =
    "d562d59dac70f68d67d00e994db5cd89e49e9d93f7f80b4cb868a5eeb057ec36";
pub const sums_signature_sha256 =
    "2bf5fae8be0c79cc30c5c10223f1d4790b6ef541240896bfe48c7ac57c3404ed";
pub const debz_api_commit = "beac3f20dd93fd98863af71e8fe621d47db663f6";
pub const canonical_fingerprint = "d2eb44626fddc30b513d5bb71a5d6c4c7db87c81";
pub const asset_name = "Ubuntu-26.04-aarch64.baremetal.qcow2";
pub const raw_asset_name = "Ubuntu-26.04-aarch64.baremetal.raw";

pub const package_roots = [_][]const u8{
    "ubuntu-minimal",
    "linux-image-7.0.0-2015-nvidia-bos-64k",
    "linux-modules-7.0.0-2015-nvidia-bos-64k",
    "initramfs-tools",
    "openssh-server",
    "sudo",
    "ca-certificates",
};

/// Every timing key the summary reports, in the order the builder produces
/// them. `debz_transaction` appears once per package root, keyed by package.
pub const phase_order = blk: {
    var phases: [package_roots.len + 11][]const u8 = undefined;
    phases[0] = "input_acquisition";
    phases[1] = "source_qcow2_setup";
    var next: usize = 2;
    for (package_roots) |package| {
        phases[next] = "debz_transaction:" ++ package;
        next += 1;
    }
    for ([_][]const u8{
        "debz_aggregate",
        "initramfs_ext4_import",
        "uki_assembly",
        "uki_signing",
        "qcow2_finalization",
        "final_image_validation",
        "raw_image_materialization",
        "provenance_output",
        "total_runtime",
    }) |phase| {
        phases[next] = phase;
        next += 1;
    }
    std.debug.assert(next == phases.len);
    const frozen = phases;
    break :blk frozen;
};

/// Phase names the timing schema may carry. `debz_transaction` is the only one
/// that also carries an item.
pub const timing_phases = [_][]const u8{
    "input_acquisition",
    "source_qcow2_setup",
    "debz_transaction",
    "debz_aggregate",
    "initramfs_ext4_import",
    "uki_assembly",
    "uki_signing",
    "qcow2_finalization",
    "final_image_validation",
    "raw_image_materialization",
    "provenance_output",
    "total_runtime",
};

const debz_snapshot_base = "https://snapshot.ubuntu.com/ubuntu/20260731T000000Z";
const debz_suites = [_][]const u8{ "resolute", "resolute-updates", "resolute-security" };
const debz_components = [_][]const u8{ "main", "restricted", "universe", "multiverse" };
const debz_refresh_snapshot = "repository-refresh-v2";
const debz_policy_snapshot = "repository-policy-v1";
const debz_aggregate_snapshot = "multi-repository-v1";
const debz_unbounded_deadline_ms: i64 = std.math.maxInt(i64);

/// Bound on the JSON documents the benchmark reads back from a build. Exact
/// package closures are the largest of them and stay well under this.
const max_document_bytes: u64 = 64 * 1024 * 1024;
/// A metadata manifest is eight short lines; the schema itself caps it at 4 KiB.
const max_manifest_bytes: u64 = 4096;
/// `miz info --output=json` emits a handful of fields.
const max_info_bytes: u64 = 1024 * 1024;
/// How much of a candidate evidence file the private-material scan reads,
/// matching the Python prefix read.
const private_material_prefix_bytes = 1024 * 1024;

/// A validation failure. The operator-facing text lives in `Context`, exactly
/// as the Python `BenchmarkError` carried it.
pub const Failure = error{Benchmark};

/// Carries the message a Python `fail()` would have raised. Messages here are
/// unbounded because the correctness diagnostic names every differing field.
pub const Context = struct {
    allocator: Allocator,
    owned: ?[]u8 = null,

    pub fn init(allocator: Allocator) Context {
        return .{ .allocator = allocator };
    }

    pub fn deinit(self: *Context) void {
        if (self.owned) |text| self.allocator.free(text);
        self.* = undefined;
    }

    pub fn message(self: *const Context) []const u8 {
        return self.owned orelse "";
    }

    /// Records `fmt`. A message that cannot be rendered leaves the previous
    /// one in place rather than masking the failure being reported.
    pub fn set(self: *Context, comptime fmt: []const u8, args: anytype) void {
        const rendered = std.fmt.allocPrint(self.allocator, fmt, args) catch return;
        if (self.owned) |text| self.allocator.free(text);
        self.owned = rendered;
    }

    pub fn fail(self: *Context, comptime fmt: []const u8, args: anytype) Failure {
        self.set(fmt, args);
        return error.Benchmark;
    }

    /// Adopts a non-validation failure the way the Python top level did, so a
    /// stray I/O error is still reported as `TypeName: text`.
    pub fn adopt(self: *Context, err: anyerror) void {
        if (self.owned != null) return;
        self.set("{s}", .{@errorName(err)});
    }
};

// ---------------------------------------------------------------- primitives

fn lessThanString(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn isSha256Name(text: []const u8) bool {
    return contract.isSha256Hex(text);
}

/// `sha256(path)`: streaming digest of a file of any size.
pub fn hashFileHex(io: Io, path: []const u8) ![64]u8 {
    const result = try digest_support.hashFile(io, path, std.math.maxInt(u64));
    return result.hex;
}

/// `canonical_digest(value)`: SHA-256 over
/// `json.dumps(value, sort_keys=True, separators=(",", ":"))`.
pub fn canonicalDigest(allocator: Allocator, value: Value) ![64]u8 {
    const bytes = try json_document.canonicalAlloc(allocator, value, .compact);
    defer allocator.free(bytes);
    return digest_support.hexBytes(bytes);
}

fn canonicalDigestAlloc(allocator: Allocator, value: Value) ![]const u8 {
    const hex = try canonicalDigest(allocator, value);
    return allocator.dupe(u8, &hex);
}

/// `read_json(path)`: bounded read, strict parse, required top-level object.
/// The failure text is the benchmark's own, not the shared release spelling.
pub fn readJson(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    context: *Context,
) !Value {
    const bytes = file_support.readBounded(
        allocator,
        io,
        path,
        max_document_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read JSON {s}: {s}", .{ path, @errorName(err) }),
    };
    defer allocator.free(bytes);
    if (!std.unicode.utf8ValidateSlice(bytes)) {
        return context.fail("cannot read JSON {s}: InvalidUtf8", .{path});
    }
    const value = std.json.parseFromSliceLeaky(
        Value,
        allocator,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read JSON {s}: {s}", .{ path, @errorName(err) }),
    };
    if (value != .object) {
        return context.fail("JSON document is not an object: {s}", .{path});
    }
    return value;
}

/// `write_json(path, value)`.
pub fn writeJson(allocator: Allocator, io: Io, path: []const u8, value: Value) !void {
    try json_document.writeDocument(allocator, io, path, value);
}

const Field = struct { []const u8, Value };

fn object(allocator: Allocator, fields: []const Field) !Value {
    var map = ObjectMap.empty;
    for (fields) |field| try map.put(allocator, field[0], field[1]);
    return .{ .object = map };
}

fn array(allocator: Allocator, items: []const Value) !Value {
    var list = JsonArray.init(allocator);
    try list.appendSlice(items);
    return .{ .array = list };
}

fn str(text: []const u8) Value {
    return .{ .string = text };
}

fn int(number: i64) Value {
    return .{ .integer = number };
}

fn optionalInt(number: ?i64) Value {
    return if (number) |present| .{ .integer = present } else .null;
}

fn getField(value: Value, key: []const u8) ?Value {
    return switch (value) {
        .object => |map| map.get(key),
        else => null,
    };
}

fn stringField(value: Value, key: []const u8) ?[]const u8 {
    const field = getField(value, key) orelse return null;
    return switch (field) {
        .string => |text| text,
        else => null,
    };
}

fn integerField(value: Value, key: []const u8) ?i64 {
    const field = getField(value, key) orelse return null;
    return switch (field) {
        .integer => |number| number,
        else => null,
    };
}

fn isNullField(value: Value, key: []const u8) bool {
    const field = getField(value, key) orelse return false;
    return field == .null;
}

fn stringEquals(value: Value, key: []const u8, expected: []const u8) bool {
    const text = stringField(value, key) orelse return false;
    return std.mem.eql(u8, text, expected);
}

/// Python's `set(document) != {...}`: the object carries exactly these keys.
fn hasExactFields(value: Value, expected: []const []const u8) bool {
    const map = switch (value) {
        .object => |present| present,
        else => return false,
    };
    if (map.count() != expected.len) return false;
    for (expected) |key| {
        if (!map.contains(key)) return false;
    }
    return true;
}

fn isMember(text: []const u8, members: []const []const u8) bool {
    for (members) |member| {
        if (std.mem.eql(u8, text, member)) return true;
    }
    return false;
}

/// `require_sha256(value, label)`.
fn requireSha256(
    value: ?Value,
    label: []const u8,
    context: *Context,
) ![]const u8 {
    const present = value orelse return context.fail(
        "{s} is not a lowercase SHA-256",
        .{label},
    );
    const text = switch (present) {
        .string => |candidate| candidate,
        else => return context.fail("{s} is not a lowercase SHA-256", .{label}),
    };
    if (!isSha256Name(text)) {
        return context.fail("{s} is not a lowercase SHA-256", .{label});
    }
    return text;
}

/// Python `str.splitlines()` over the separators a manifest could plausibly
/// carry. Any unexpected separator changes the line count, which the schema
/// check then rejects.
fn splitLines(allocator: Allocator, text: []const u8) ![][]const u8 {
    var lines: std.ArrayList([]const u8) = .empty;
    errdefer lines.deinit(allocator);
    var start: usize = 0;
    var index: usize = 0;
    while (index < text.len) {
        const byte = text[index];
        const is_terminator = switch (byte) {
            '\n', '\r', 0x0b, 0x0c, 0x1c, 0x1d, 0x1e => true,
            else => false,
        };
        if (!is_terminator) {
            index += 1;
            continue;
        }
        try lines.append(allocator, text[start..index]);
        if (byte == '\r' and index + 1 < text.len and text[index + 1] == '\n') {
            index += 1;
        }
        index += 1;
        start = index;
    }
    if (start < text.len) try lines.append(allocator, text[start..]);
    return lines.toOwnedSlice(allocator);
}

/// Names in a directory, sorted the way `sorted(directory.iterdir())` orders
/// them. `error.FileNotFound` is left to the caller, which reports it.
fn sortedEntryNames(allocator: Allocator, io: Io, path: []const u8) ![][]const u8 {
    var directory = try Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer directory.close(io);
    var names: std.ArrayList([]const u8) = .empty;
    errdefer names.deinit(allocator);
    var iterator = directory.iterate();
    while (try iterator.next(io)) |entry| {
        try names.append(allocator, try allocator.dupe(u8, entry.name));
    }
    const owned = try names.toOwnedSlice(allocator);
    std.mem.sort([]const u8, owned, {}, lessThanString);
    return owned;
}

fn joinPath(allocator: Allocator, parts: []const []const u8) ![]u8 {
    return std.fs.path.join(allocator, parts);
}

fn statNoFollow(io: Io, path: []const u8) !File.Stat {
    return Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
}

fn isDirectoryNoFollow(io: Io, path: []const u8) bool {
    const stat = statNoFollow(io, path) catch return false;
    return stat.kind == .directory;
}

fn pathExistsOrSymlink(io: Io, path: []const u8) bool {
    _ = statNoFollow(io, path) catch return false;
    return true;
}

/// `Path.resolve()`: canonicalizes the existing prefix and normalizes the rest.
pub fn resolvePathAlloc(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    const absolute = if (std.fs.path.isAbsolute(path))
        try allocator.dupe(u8, path)
    else absolute: {
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try Dir.cwd().realPathFile(io, ".", &buffer);
        break :absolute try joinPath(allocator, &.{ buffer[0..length], path });
    };
    const lexical = try std.fs.path.resolve(allocator, &.{absolute});
    return resolveExisting(allocator, io, lexical, 0);
}

fn resolveExisting(
    allocator: Allocator,
    io: Io,
    lexical: []const u8,
    depth: usize,
) ![]u8 {
    if (Dir.cwd().realPathFileAlloc(io, lexical, allocator)) |resolved| {
        return resolved;
    } else |_| {}
    // A path component that does not exist yet cannot hold a symlink, so the
    // lexical spelling of the tail is already its resolved spelling.
    if (depth >= 64) return allocator.dupe(u8, lexical);
    const parent = std.fs.path.dirname(lexical) orelse
        return allocator.dupe(u8, lexical);
    if (parent.len >= lexical.len) return allocator.dupe(u8, lexical);
    const base = std.fs.path.basename(lexical);
    if (base.len == 0) return allocator.dupe(u8, lexical);
    const resolved_parent = try resolveExisting(allocator, io, parent, depth + 1);
    return joinPath(allocator, &.{ resolved_parent, base });
}

/// `regular_file(path, label, expected_sha256=...)`.
pub const FileRecord = struct {
    path: []const u8,
    bytes: i64,
    sha256: []const u8,

    pub fn toJson(self: FileRecord, allocator: Allocator) !Value {
        return object(allocator, &.{
            .{ "path", str(self.path) },
            .{ "bytes", int(self.bytes) },
            .{ "sha256", str(self.sha256) },
        });
    }
};

pub fn regularFile(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    label: []const u8,
    expected_sha256: ?[]const u8,
    context: *Context,
) !FileRecord {
    const stat = statNoFollow(io, path) catch |err| switch (err) {
        error.FileNotFound => return context.fail("{s} is missing: {s}", .{ label, path }),
        else => return err,
    };
    if (stat.kind != .file) {
        return context.fail(
            "{s} must be a non-symlink regular file: {s}",
            .{ label, path },
        );
    }
    if (stat.size == 0) return context.fail("{s} is empty: {s}", .{ label, path });
    const hex = try hashFileHex(io, path);
    if (expected_sha256) |expected| {
        if (!std.mem.eql(u8, &hex, expected)) return context.fail(
            "{s} SHA-256 mismatch: expected {s}, got {s}",
            .{ label, expected, &hex },
        );
    }
    return .{
        .path = try resolvePathAlloc(allocator, io, path),
        .bytes = @intCast(stat.size),
        .sha256 = try allocator.dupe(u8, &hex),
    };
}

// -------------------------------------------------- session and cleanup

/// `prepare_session_dir`: the output root must name a new directory inside a
/// real parent directory, and it is created rather than reused.
pub fn prepareSessionDir(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    context: *Context,
) ![]u8 {
    const name = std.fs.path.basename(path);
    if (name.len == 0 or std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) {
        return context.fail("output root must name a new directory", .{});
    }
    const parent_path = std.fs.path.dirname(path) orelse ".";
    const parent = Dir.cwd().realPathFileAlloc(io, parent_path, allocator) catch
        return context.fail("output root parent must be a real directory", .{});
    if (!isDirectoryNoFollow(io, parent)) {
        return context.fail("output root parent must be a real directory", .{});
    }
    const candidate = try joinPath(allocator, &.{ parent, name });
    if (pathExistsOrSymlink(io, candidate)) {
        return context.fail("output root must not already exist: {s}", .{candidate});
    }
    try Dir.cwd().createDir(io, candidate, @enumFromInt(0o755));
    return candidate;
}

fn isWithin(path: []const u8, parent: []const u8) bool {
    if (!std.mem.startsWith(u8, path, parent)) return false;
    if (path.len == parent.len) return true;
    return path[parent.len] == '/';
}

/// `require_run_path`: a cleanup target is only ever the one path the run
/// layout puts at `expected_relative`, re-resolved through every symlink.
pub fn requireRunPath(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    run_dir: []const u8,
    expected_relative: []const u8,
    context: *Context,
) ![]u8 {
    const resolved_run = Dir.cwd().realPathFileAlloc(io, run_dir, allocator) catch
        return context.fail("unsafe benchmark cleanup path: {s}", .{path});
    const resolved = Dir.cwd().realPathFileAlloc(io, path, allocator) catch
        return context.fail("unsafe benchmark cleanup path: {s}", .{path});
    const run_stat = statNoFollow(io, run_dir) catch
        return context.fail("unsafe benchmark cleanup path: {s}", .{path});
    if (run_stat.kind == .sym_link) {
        return context.fail("unsafe benchmark cleanup path: {s}", .{path});
    }
    const expected = try joinPath(allocator, &.{ resolved_run, expected_relative });
    if (!std.mem.eql(u8, resolved, expected) or !isWithin(resolved, resolved_run)) {
        return context.fail(
            "benchmark cleanup escaped its run directory: {s}",
            .{path},
        );
    }
    return resolved;
}

pub const CleanupKind = enum { file, tree };

pub const CleanupDecision = struct {
    kind: CleanupKind,
    target: []const u8,
};

/// `cleanup_decisions`: which of the three large per-run artifacts are removed,
/// each one already proven to be inside the run directory.
pub fn cleanupDecisions(
    allocator: Allocator,
    io: Io,
    run_dir: []const u8,
    image: []const u8,
    raw_output: []const u8,
    work_dir: []const u8,
    keep_images: bool,
    context: *Context,
) ![]CleanupDecision {
    var decisions: std.ArrayList(CleanupDecision) = .empty;
    errdefer decisions.deinit(allocator);
    if (pathExistsOrSymlink(io, image) and !keep_images) {
        const relative = try std.fmt.allocPrint(allocator, "artifact/{s}", .{asset_name});
        try decisions.append(allocator, .{
            .kind = .file,
            .target = try requireRunPath(allocator, io, image, run_dir, relative, context),
        });
    }
    if (pathExistsOrSymlink(io, raw_output) and !keep_images) {
        const relative = try std.fmt.allocPrint(
            allocator,
            "artifact/{s}",
            .{raw_asset_name},
        );
        try decisions.append(allocator, .{
            .kind = .file,
            .target = try requireRunPath(
                allocator,
                io,
                raw_output,
                run_dir,
                relative,
                context,
            ),
        });
    }
    if (pathExistsOrSymlink(io, work_dir)) {
        try decisions.append(allocator, .{
            .kind = .tree,
            .target = try requireRunPath(allocator, io, work_dir, run_dir, "work", context),
        });
    }
    return decisions.toOwnedSlice(allocator);
}

/// `cleanup_run`: removes exactly the decided targets and reports them
/// relative to the resolved run directory.
pub fn cleanupRun(
    allocator: Allocator,
    io: Io,
    run_dir: []const u8,
    image: []const u8,
    raw_output: []const u8,
    work_dir: []const u8,
    keep_images: bool,
    context: *Context,
) ![][]const u8 {
    const decisions = try cleanupDecisions(
        allocator,
        io,
        run_dir,
        image,
        raw_output,
        work_dir,
        keep_images,
        context,
    );
    const resolved_run = try Dir.cwd().realPathFileAlloc(io, run_dir, allocator);
    var removed: std.ArrayList([]const u8) = .empty;
    errdefer removed.deinit(allocator);
    for (decisions) |decision| {
        switch (decision.kind) {
            .file => try Dir.cwd().deleteFile(io, decision.target),
            .tree => try Dir.cwd().deleteTree(io, decision.target),
        }
        const relative = decision.target[@min(
            decision.target.len,
            resolved_run.len + 1,
        )..];
        try removed.append(allocator, try allocator.dupe(u8, relative));
    }
    return removed.toOwnedSlice(allocator);
}

// ------------------------------------------------------- debz cache identity

fn hashPart(hash: *Sha256, value: []const u8) void {
    var length: [8]u8 = undefined;
    std.mem.writeInt(u64, &length, value.len, .big);
    hash.update(&length);
    hash.update(value);
}

fn hashInt(hash: *Sha256, value: i64) void {
    var encoded: [8]u8 = undefined;
    std.mem.writeInt(i64, &encoded, value, .big);
    hash.update(&encoded);
}

/// Mirrors the pinned debz `repository_policy` identity: Signed-By is
/// deliberately part of the key, while the config file location and
/// credentials are not.
pub fn debzRepositoryId(
    suite: []const u8,
    component: []const u8,
    keyring_path: []const u8,
) [64]u8 {
    var hash = Sha256.init(.{});
    hashPart(&hash, "enabled");
    hashPart(&hash, debz_snapshot_base);
    hashPart(&hash, suite);
    hashPart(&hash, component);
    hashPart(&hash, ubuntu_architecture);
    hashPart(&hash, keyring_path);
    hashInt(&hash, 500);
    hashPart(&hash, "");
    hashPart(&hash, "immutable_url");
    hashPart(&hash, "");
    hashPart(&hash, "direct");
    hashInt(&hash, debz_unbounded_deadline_ms);
    hashInt(&hash, debz_unbounded_deadline_ms);
    hashInt(&hash, debz_unbounded_deadline_ms);
    var raw: [Sha256.digest_length]u8 = undefined;
    hash.final(&raw);
    return digest_support.hex(raw);
}

/// `debz_manifest_name(repository, snapshot)`.
pub fn debzManifestName(repository: []const u8, snapshot: []const u8) [64]u8 {
    var hash = Sha256.init(.{});
    hash.update(repository);
    hash.update(&[_]u8{0});
    hash.update(snapshot);
    var raw: [Sha256.digest_length]u8 = undefined;
    hash.final(&raw);
    return digest_support.hex(raw);
}

pub const CacheRequirement = struct {
    phase: []const u8,
    repository: []const u8,
    snapshot: []const u8,
    filename: []const u8,
};

/// `benchmark_cache_requirements`: the metadata manifests a warm cache must
/// already hold for every offline run to stay offline.
pub fn benchmarkCacheRequirements(
    allocator: Allocator,
    io: Io,
    input_dir: []const u8,
) ![]CacheRequirement {
    const resolved_input = try resolvePathAlloc(allocator, io, input_dir);
    const keyring = try joinPath(
        allocator,
        &.{ resolved_input, "ubuntu-archive-keyring.gpg" },
    );

    var repositories: std.ArrayList([]const u8) = .empty;
    defer repositories.deinit(allocator);
    for (debz_suites) |suite| {
        for (debz_components) |component| {
            const identity = debzRepositoryId(suite, component, keyring);
            try repositories.append(allocator, try allocator.dupe(u8, &identity));
        }
    }
    std.mem.sort([]const u8, repositories.items, {}, lessThanString);

    var requirements: std.ArrayList(CacheRequirement) = .empty;
    errdefer requirements.deinit(allocator);
    for (repositories.items) |repository| {
        inline for (.{
            .{ "repository-refresh", debz_refresh_snapshot },
            .{ "repository-policy", debz_policy_snapshot },
        }) |pair| {
            const filename = debzManifestName(repository, pair[1]);
            try requirements.append(allocator, .{
                .phase = pair[0],
                .repository = repository,
                .snapshot = pair[1],
                .filename = try allocator.dupe(u8, &filename),
            });
        }
    }

    var configuration = Sha256.init(.{});
    hashPart(&configuration, "debz-multi-repository-configuration-v1");
    for (repositories.items) |repository| hashPart(&configuration, repository);
    var configuration_raw: [Sha256.digest_length]u8 = undefined;
    configuration.final(&configuration_raw);
    const configuration_id = try allocator.dupe(
        u8,
        &digest_support.hex(configuration_raw),
    );
    const aggregate_filename = debzManifestName(
        configuration_id,
        debz_aggregate_snapshot,
    );
    try requirements.append(allocator, .{
        .phase = "repository-aggregate",
        .repository = configuration_id,
        .snapshot = debz_aggregate_snapshot,
        .filename = try allocator.dupe(u8, &aggregate_filename),
    });
    return requirements.toOwnedSlice(allocator);
}

// ------------------------------------------------------- warm cache contract

pub const CacheObject = struct {
    path: []const u8,
    bytes: i64,
    sha256: []const u8,

    fn toJson(self: CacheObject, allocator: Allocator) !Value {
        return object(allocator, &.{
            .{ "path", str(self.path) },
            .{ "bytes", int(self.bytes) },
            .{ "sha256", str(self.sha256) },
        });
    }
};

pub const ManifestRecord = struct {
    path: []const u8,
    bytes: i64,
    sha256: []const u8,
    repository: []const u8,
    snapshot: []const u8,
    object_sha256: []const u8,
    object_bytes: i64,

    fn toJson(self: ManifestRecord, allocator: Allocator) !Value {
        return object(allocator, &.{
            .{ "path", str(self.path) },
            .{ "bytes", int(self.bytes) },
            .{ "sha256", str(self.sha256) },
            .{ "repository", str(self.repository) },
            .{ "snapshot", str(self.snapshot) },
            .{ "object_sha256", str(self.object_sha256) },
            .{ "object_bytes", int(self.object_bytes) },
        });
    }
};

/// The public inventory document plus the two private indexes the Python
/// carried as `_`-prefixed keys. Keeping them as typed fields means the
/// private data can never reach an evidence document by accident.
pub const CacheInventory = struct {
    public: Value,
    metadata_objects: usize,
    metadata_manifests: usize,
    package_objects: usize,
    object_inventory_sha256: []const u8,
    manifest_inventory_sha256: []const u8,
    inventory_sha256: []const u8,
    package_object_names: std.StringArrayHashMapUnmanaged(void),
    manifests: std.StringArrayHashMapUnmanaged(ManifestRecord),

    pub fn hasPackageObject(self: *const CacheInventory, name: []const u8) bool {
        return self.package_object_names.contains(name);
    }

    pub fn manifest(self: *const CacheInventory, filename: []const u8) ?ManifestRecord {
        return self.manifests.get(filename);
    }
};

fn requireSha256Text(
    text: []const u8,
    label: []const u8,
    context: *Context,
) ![]const u8 {
    if (!isSha256Name(text)) {
        return context.fail("{s} is not a lowercase SHA-256", .{label});
    }
    return text;
}

/// `verify_cache_objects`: every entry is a non-symlink regular file whose
/// name is its own SHA-256.
fn verifyCacheObjects(
    allocator: Allocator,
    io: Io,
    directory: []const u8,
    label: []const u8,
    context: *Context,
) ![]CacheObject {
    const names = sortedEntryNames(allocator, io, directory) catch |err| switch (err) {
        error.FileNotFound => return context.fail(
            "warm debz cache is missing {s}: {s}",
            .{ label, directory },
        ),
        else => return err,
    };
    var records: std.ArrayList(CacheObject) = .empty;
    errdefer records.deinit(allocator);
    for (names) |name| {
        const path = try joinPath(allocator, &.{ directory, name });
        const stat = try statNoFollow(io, path);
        if (stat.kind != .file or !isSha256Name(name)) {
            return context.fail("{s} contains a non-CAS entry: {s}", .{ label, path });
        }
        const hex = try hashFileHex(io, path);
        if (!std.mem.eql(u8, &hex, name)) {
            return context.fail(
                "{s} object digest does not match its name: {s}",
                .{ label, path },
            );
        }
        try records.append(allocator, .{
            .path = name,
            .bytes = @intCast(stat.size),
            .sha256 = try allocator.dupe(u8, &hex),
        });
    }
    if (records.items.len == 0) {
        return context.fail("warm debz cache has no {s} objects", .{label});
    }
    return records.toOwnedSlice(allocator);
}

fn objectsToJson(allocator: Allocator, records: []const CacheObject) !Value {
    var list = JsonArray.init(allocator);
    for (records) |record| try list.append(try record.toJson(allocator));
    return .{ .array = list };
}

fn manifestsToJson(allocator: Allocator, records: []const ManifestRecord) !Value {
    var list = JsonArray.init(allocator);
    for (records) |record| try list.append(try record.toJson(allocator));
    return .{ .array = list };
}

fn sumBytes(records: []const CacheObject) i64 {
    var total: i64 = 0;
    for (records) |record| total += record.bytes;
    return total;
}

const manifest_field_names = [_][]const u8{
    "repository",
    "snapshot",
    "digest",
    "size",
    "verification",
    "verified-at",
    "verifier-input",
};

const verification_modes = [_][]const u8{
    "unauthenticated_release",
    "in_release",
    "detached_release",
    "trusted_snapshot",
};

fn isValidSnapshot(snapshot: []const u8) bool {
    if (snapshot.len == 0 or snapshot.len > 255) return false;
    for (snapshot) |character| switch (character) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.' => {},
        else => return false,
    };
    return true;
}

/// Python's `int(text)`: an optionally signed decimal, surrounded by optional
/// whitespace.
fn parsePythonInt(text: []const u8) ?i64 {
    const trimmed = std.mem.trim(u8, text, " \t\n\r\x0b\x0c");
    if (trimmed.len == 0) return null;
    return std.fmt.parseInt(i64, trimmed, 10) catch null;
}

/// `verify_warm_cache`: hashes every content-addressed object, then proves
/// every metadata manifest is well formed and bound to an object that is
/// present at the size the manifest claims.
pub fn verifyWarmCache(
    allocator: Allocator,
    io: Io,
    cache: []const u8,
    context: *Context,
) !CacheInventory {
    const stat = statNoFollow(io, cache) catch |err| switch (err) {
        error.FileNotFound => return context.fail("debz cache is missing: {s}", .{cache}),
        else => return err,
    };
    if (stat.kind != .directory) {
        return context.fail("debz cache must be a non-symlink directory", .{});
    }

    const metadata_dir = try joinPath(allocator, &.{ cache, "metadata-v1", "objects" });
    const metadata_objects = try verifyCacheObjects(
        allocator,
        io,
        metadata_dir,
        "metadata",
        context,
    );
    var metadata_by_digest: std.StringArrayHashMapUnmanaged(CacheObject) = .empty;
    for (metadata_objects) |item| {
        try metadata_by_digest.put(allocator, item.path, item);
    }

    const packages_dir = try joinPath(allocator, &.{ cache, "packages-v1", "objects" });
    const package_objects = try verifyCacheObjects(
        allocator,
        io,
        packages_dir,
        "package",
        context,
    );

    const manifests_dir = try joinPath(allocator, &.{ cache, "metadata-v1", "manifests" });
    const manifest_names = sortedEntryNames(allocator, io, manifests_dir) catch |err| switch (err) {
        error.FileNotFound => return context.fail(
            "warm debz cache is missing metadata manifests",
            .{},
        ),
        else => return err,
    };

    var manifest_records: std.ArrayList(ManifestRecord) = .empty;
    for (manifest_names) |name| {
        const path = try joinPath(allocator, &.{ manifests_dir, name });
        const manifest_stat = try statNoFollow(io, path);
        if (manifest_stat.kind != .file or !isSha256Name(name)) {
            return context.fail(
                "metadata manifest is not a CAS-keyed regular file: {s}",
                .{path},
            );
        }
        if (manifest_stat.size == 0 or manifest_stat.size > max_manifest_bytes) {
            return context.fail("metadata manifest size is invalid: {s}", .{path});
        }
        const bytes = file_support.readBounded(
            allocator,
            io,
            path,
            max_manifest_bytes,
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return context.fail(
                "cannot read metadata manifest {s}: {s}",
                .{ path, @errorName(err) },
            ),
        };
        if (!std.unicode.utf8ValidateSlice(bytes)) return context.fail(
            "cannot read metadata manifest {s}: InvalidUtf8",
            .{path},
        );
        const lines = try splitLines(allocator, bytes);
        if (lines.len != 8 or !std.mem.eql(u8, lines[0], "debz-metadata-manifest-v1")) {
            return context.fail("metadata manifest has the wrong schema: {s}", .{path});
        }

        var values: [manifest_field_names.len]?[]const u8 = @splat(null);
        var seen: std.ArrayList([]const u8) = .empty;
        for (lines[1..]) |line| {
            const separator = std.mem.indexOfScalar(u8, line, '=') orelse
                return context.fail("metadata manifest has invalid fields: {s}", .{path});
            const name_part = line[0..separator];
            const value_part = line[separator + 1 ..];
            for (seen.items) |previous| {
                if (std.mem.eql(u8, previous, name_part)) return context.fail(
                    "metadata manifest has invalid fields: {s}",
                    .{path},
                );
            }
            try seen.append(allocator, name_part);
            for (manifest_field_names, 0..) |field_name, index| {
                if (std.mem.eql(u8, field_name, name_part)) values[index] = value_part;
            }
        }
        for (values) |value| {
            if (value == null) return context.fail(
                "metadata manifest has unexpected fields: {s}",
                .{path},
            );
        }

        const repository_label = try std.fmt.allocPrint(
            allocator,
            "metadata manifest {s} repository",
            .{name},
        );
        const repository = try requireSha256Text(
            values[0].?,
            repository_label,
            context,
        );
        const snapshot = values[1].?;
        if (!isValidSnapshot(snapshot)) return context.fail(
            "metadata manifest {s} snapshot is invalid",
            .{name},
        );
        const expected_name = debzManifestName(repository, snapshot);
        if (!std.mem.eql(u8, name, &expected_name)) return context.fail(
            "metadata manifest filename does not match its cache key: {s}",
            .{path},
        );
        const object_label = try std.fmt.allocPrint(
            allocator,
            "metadata manifest {s} object",
            .{name},
        );
        const object_digest = try requireSha256Text(values[2].?, object_label, context);
        const object_size = parsePythonInt(values[3].?) orelse return context.fail(
            "metadata manifest has invalid numeric fields: {s}",
            .{path},
        );
        _ = parsePythonInt(values[5].?) orelse return context.fail(
            "metadata manifest has invalid numeric fields: {s}",
            .{path},
        );
        if (object_size <= 0) return context.fail(
            "metadata manifest has invalid object size: {s}",
            .{path},
        );
        if (!isMember(values[4].?, &verification_modes)) return context.fail(
            "metadata manifest has invalid verification mode: {s}",
            .{path},
        );
        const verifier = values[6].?;
        if (!std.mem.eql(u8, verifier, "-")) {
            const verifier_label = try std.fmt.allocPrint(
                allocator,
                "metadata manifest {s} verifier input",
                .{name},
            );
            _ = try requireSha256Text(verifier, verifier_label, context);
        }
        const referenced = metadata_by_digest.get(object_digest) orelse
            return context.fail(
                "metadata manifest {s} references missing object {s}",
                .{ name, object_digest },
            );
        if (object_size != referenced.bytes) return context.fail(
            "metadata manifest {s} object size differs from {s}",
            .{ name, object_digest },
        );
        const manifest_hex = try hashFileHex(io, path);
        try manifest_records.append(allocator, .{
            .path = name,
            .bytes = @intCast(manifest_stat.size),
            .sha256 = try allocator.dupe(u8, &manifest_hex),
            .repository = repository,
            .snapshot = snapshot,
            .object_sha256 = object_digest,
            .object_bytes = object_size,
        });
    }
    if (manifest_records.items.len == 0) {
        return context.fail("warm debz cache has no metadata manifests", .{});
    }

    const metadata_json = try objectsToJson(allocator, metadata_objects);
    const packages_json = try objectsToJson(allocator, package_objects);
    const manifests_json = try manifestsToJson(allocator, manifest_records.items);
    const object_inventory = try canonicalDigestAlloc(allocator, try object(allocator, &.{
        .{ "metadata", metadata_json },
        .{ "packages", packages_json },
    }));
    const manifest_inventory = try canonicalDigestAlloc(allocator, manifests_json);
    const inventory = try canonicalDigestAlloc(allocator, try object(allocator, &.{
        .{ "metadata", metadata_json },
        .{ "manifests", manifests_json },
        .{ "packages", packages_json },
    }));

    var package_object_names: std.StringArrayHashMapUnmanaged(void) = .empty;
    for (package_objects) |item| try package_object_names.put(allocator, item.path, {});
    var manifests: std.StringArrayHashMapUnmanaged(ManifestRecord) = .empty;
    for (manifest_records.items) |item| try manifests.put(allocator, item.path, item);

    return .{
        .public = try object(allocator, &.{
            .{ "schema", int(schema) },
            .{ "type", str("miz-debz-cache-inventory") },
            .{ "metadata_objects", int(@intCast(metadata_objects.len)) },
            .{ "metadata_bytes", int(sumBytes(metadata_objects)) },
            .{ "metadata_manifests", int(@intCast(manifest_records.items.len)) },
            .{ "package_objects", int(@intCast(package_objects.len)) },
            .{ "package_bytes", int(sumBytes(package_objects)) },
            .{ "object_inventory_sha256", str(object_inventory) },
            .{ "manifest_inventory_sha256", str(manifest_inventory) },
            .{ "inventory_sha256", str(inventory) },
        }),
        .metadata_objects = metadata_objects.len,
        .metadata_manifests = manifest_records.items.len,
        .package_objects = package_objects.len,
        .object_inventory_sha256 = object_inventory,
        .manifest_inventory_sha256 = manifest_inventory,
        .inventory_sha256 = inventory,
        .package_object_names = package_object_names,
        .manifests = manifests,
    };
}

/// `verify_benchmark_cache`: the warm cache plus proof that it already binds
/// every repository identity this exact benchmark profile will ask for.
pub fn verifyBenchmarkCache(
    allocator: Allocator,
    io: Io,
    cache: []const u8,
    input_dir: []const u8,
    context: *Context,
) !CacheInventory {
    const inventory = try verifyWarmCache(allocator, io, cache, context);
    const requirements = try benchmarkCacheRequirements(allocator, io, input_dir);
    const resolved_input = try resolvePathAlloc(allocator, io, input_dir);
    const keyring = try joinPath(
        allocator,
        &.{ resolved_input, "ubuntu-archive-keyring.gpg" },
    );
    for (requirements) |requirement| {
        const manifest = inventory.manifest(requirement.filename) orelse
            return context.fail(
                "warm debz cache is missing metadata manifest {s} for phase {s}," ++
                    " repository {s}, snapshot {s}; repository identity binds" ++
                    " Signed-By {s}",
                .{
                    requirement.filename,
                    requirement.phase,
                    requirement.repository,
                    requirement.snapshot,
                    keyring,
                },
            );
        if (!std.mem.eql(u8, manifest.repository, requirement.repository) or
            !std.mem.eql(u8, manifest.snapshot, requirement.snapshot))
        {
            return context.fail(
                "warm debz cache metadata manifest {s} does not bind phase {s} to" ++
                    " repository {s} and snapshot {s}",
                .{
                    requirement.filename,
                    requirement.phase,
                    requirement.repository,
                    requirement.snapshot,
                },
            );
        }
    }
    return inventory;
}

// ---------------------------------------------------------- exact lock set

pub fn lockFilename(allocator: Allocator, package: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "debz-exact-lock-{s}-{s}.json",
        .{ package, ubuntu_architecture },
    );
}

const ClosurePackage = struct {
    name: []const u8,
    version: []const u8,
    architecture: []const u8,
    sha256: []const u8,

    fn toJson(self: ClosurePackage, allocator: Allocator) !Value {
        return object(allocator, &.{
            .{ "name", str(self.name) },
            .{ "version", str(self.version) },
            .{ "architecture", str(self.architecture) },
            .{ "sha256", str(self.sha256) },
        });
    }

    fn lessThan(_: void, left: ClosurePackage, right: ClosurePackage) bool {
        const by_name = std.mem.order(u8, left.name, right.name);
        if (by_name != .eq) return by_name == .lt;
        const by_architecture = std.mem.order(u8, left.architecture, right.architecture);
        if (by_architecture != .eq) return by_architecture == .lt;
        const by_version = std.mem.order(u8, left.version, right.version);
        if (by_version != .eq) return by_version == .lt;
        return std.mem.lessThan(u8, left.sha256, right.sha256);
    }
};

/// `validate_package`: a closure entry names a package, a version, and an
/// architecture this image can install, bound to a content hash.
fn validatePackage(
    entry: Value,
    label: []const u8,
    context: *Context,
) !ClosurePackage {
    if (entry != .object) {
        return context.fail("{s} package entry is not an object", .{label});
    }
    var result: ClosurePackage = undefined;
    inline for (.{ "name", "version", "architecture" }, 0..) |field, index| {
        const text = stringField(entry, field) orelse return context.fail(
            "{s} package {s} is invalid",
            .{ label, field },
        );
        if (text.len == 0) return context.fail(
            "{s} package {s} is invalid",
            .{ label, field },
        );
        switch (index) {
            0 => result.name = text,
            1 => result.version = text,
            else => result.architecture = text,
        }
    }
    const hash_label = try std.fmt.allocPrint(
        context.allocator,
        "{s} package hash",
        .{label},
    );
    defer context.allocator.free(hash_label);
    result.sha256 = try requireSha256(getField(entry, "sha256"), hash_label, context);
    if (!std.mem.eql(u8, result.architecture, ubuntu_architecture) and
        !std.mem.eql(u8, result.architecture, "all"))
    {
        return context.fail("{s} contains a foreign package architecture", .{label});
    }
    return result;
}

pub const LockRecord = struct {
    package: []const u8,
    filename: []const u8,
    file_sha256: []const u8,
    digest_sha256: []const u8,
    packages: i64,

    fn toJson(self: LockRecord, allocator: Allocator) !Value {
        return object(allocator, &.{
            .{ "package", str(self.package) },
            .{ "filename", str(self.filename) },
            .{ "file_sha256", str(self.file_sha256) },
            .{ "digest_sha256", str(self.digest_sha256) },
            .{ "packages", int(self.packages) },
        });
    }
};

pub const LockSet = struct {
    document: Value,
    locks: []LockRecord,
    locks_json: Value,
    final_closure: Value,
    closure_sha256: []const u8,

    pub fn find(self: *const LockSet, package: []const u8) ?LockRecord {
        for (self.locks) |lock| {
            if (std.mem.eql(u8, lock.package, package)) return lock;
        }
        return null;
    }
};

/// `verify_lock_set`: every package root has an exact-closure lock whose every
/// package hash is already a warm cache object, so no measured run can need the
/// network.
pub fn verifyLockSet(
    allocator: Allocator,
    io: Io,
    lock_dir: []const u8,
    inventory: *const CacheInventory,
    context: *Context,
) !LockSet {
    if (!isDirectoryNoFollow(io, lock_dir)) {
        return context.fail("debz lock directory must be a non-symlink directory", .{});
    }
    var locks: std.ArrayList(LockRecord) = .empty;
    var final_closure: []ClosurePackage = &.{};
    for (package_roots) |package| {
        const filename = try lockFilename(allocator, package);
        const path = try joinPath(allocator, &.{ lock_dir, filename });
        const label = try std.fmt.allocPrint(allocator, "{s} exact lock", .{package});
        const file_record = try regularFile(allocator, io, path, label, null, context);
        const document = try readJson(allocator, io, path, context);
        if (!stringEquals(
            document,
            "schema",
            "https://debz.dev/schema/exact-closure-lock-v1",
        ) or
            integerField(document, "version") != @as(i64, 1) or
            !stringEquals(document, "target_architecture", ubuntu_architecture))
        {
            return context.fail(
                "{s} exact lock has the wrong schema or architecture",
                .{package},
            );
        }
        const digest_label = try std.fmt.allocPrint(
            allocator,
            "{s} exact-lock digest",
            .{package},
        );
        const lock_digest = try requireSha256(
            getField(document, "digest_sha256"),
            digest_label,
            context,
        );
        const packages = getField(document, "packages") orelse Value.null;
        if (packages != .array or packages.array.items.len == 0) {
            return context.fail("{s} exact lock has an empty closure", .{package});
        }
        var closure = try allocator.alloc(ClosurePackage, packages.array.items.len);
        for (packages.array.items, 0..) |entry, index| {
            closure[index] = try validatePackage(entry, label, context);
        }
        for (closure, 0..) |left, index| {
            for (closure[index + 1 ..]) |right| {
                if (std.mem.eql(u8, left.name, right.name) and
                    std.mem.eql(u8, left.version, right.version) and
                    std.mem.eql(u8, left.architecture, right.architecture))
                {
                    return context.fail(
                        "{s} exact lock has duplicate package identities",
                        .{package},
                    );
                }
            }
        }
        var requested = false;
        for (closure) |item| {
            if (std.mem.eql(u8, item.name, package)) requested = true;
        }
        if (!requested) return context.fail(
            "{s} exact lock does not contain its requested package",
            .{package},
        );

        var missing: std.ArrayList([]const u8) = .empty;
        defer missing.deinit(allocator);
        for (closure) |item| {
            if (!inventory.hasPackageObject(item.sha256)) {
                try missing.append(allocator, item.sha256);
            }
        }
        if (missing.items.len > 0) {
            std.mem.sort([]const u8, missing.items, {}, lessThanString);
            return context.fail(
                "{s} exact lock has {d} package cache miss(es); first missing" ++
                    " object: {s}",
                .{ package, missing.items.len, missing.items[0] },
            );
        }

        std.mem.sort(ClosurePackage, closure, {}, ClosurePackage.lessThan);
        try locks.append(allocator, .{
            .package = package,
            .filename = filename,
            .file_sha256 = file_record.sha256,
            .digest_sha256 = lock_digest,
            .packages = @intCast(closure.len),
        });
        final_closure = closure;
    }

    var closure_json = JsonArray.init(allocator);
    for (final_closure) |item| try closure_json.append(try item.toJson(allocator));
    const closure_value: Value = .{ .array = closure_json };
    var locks_json = JsonArray.init(allocator);
    for (locks.items) |lock| try locks_json.append(try lock.toJson(allocator));
    const locks_value: Value = .{ .array = locks_json };
    const closure_sha256 = try canonicalDigestAlloc(allocator, closure_value);
    return .{
        .document = try object(allocator, &.{
            .{ "schema", int(schema) },
            .{ "type", str("miz-ubuntu2604-benchmark-lock-set") },
            .{ "locks", locks_value },
            .{ "final_closure", closure_value },
            .{ "closure_sha256", str(closure_sha256) },
        }),
        .locks = try locks.toOwnedSlice(allocator),
        .locks_json = locks_value,
        .final_closure = closure_value,
        .closure_sha256 = closure_sha256,
    };
}

// ------------------------------------------------------------------- timing

pub const Timing = struct {
    document: Value,
    values: std.StringArrayHashMapUnmanaged(i64),

    pub fn get(self: *const Timing, phase: []const u8) ?i64 {
        return self.values.get(phase);
    }
};

const timing_document_fields = [_][]const u8{
    "schema",
    "type",
    "clock",
    "duration_unit",
    "status",
    "failed_phase",
    "failed_item",
    "error_name",
    "phases",
};

const timing_phase_fields = [_][]const u8{
    "name",
    "item",
    "elapsed_ns",
    "outcome",
    "error_name",
};

/// `load_timing`: the builder's own phase timing, accepted only when it
/// records a complete, successful, schema-v1 run of this exact profile.
pub fn loadTiming(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    context: *Context,
) !Timing {
    const document = try readJson(allocator, io, path, context);
    if (!hasExactFields(document, &timing_document_fields)) {
        return context.fail("timing JSON has unexpected fields", .{});
    }
    if (integerField(document, "schema") != @as(i64, 1) or
        !stringEquals(document, "type", "miz-ubuntu2604-image-phase-timing") or
        !stringEquals(document, "clock", "monotonic") or
        !stringEquals(document, "duration_unit", "nanoseconds") or
        !stringEquals(document, "status", "success") or
        !isNullField(document, "failed_phase") or
        !isNullField(document, "failed_item") or
        !isNullField(document, "error_name"))
    {
        return context.fail("timing JSON does not record a successful schema-v1 run", .{});
    }
    const phases = getField(document, "phases") orelse Value.null;
    if (phases != .array or phases.array.items.len == 0) {
        return context.fail("timing JSON has no phases", .{});
    }

    var values: std.StringArrayHashMapUnmanaged(i64) = .empty;
    var debz_items: std.ArrayList([]const u8) = .empty;
    defer debz_items.deinit(allocator);
    for (phases.array.items, 0..) |phase, index| {
        if (phase != .object or !hasExactFields(phase, &timing_phase_fields)) {
            return context.fail("timing phase {d} has unexpected fields", .{index});
        }
        const name = stringField(phase, "name") orelse "";
        const item = stringField(phase, "item");
        const elapsed = getField(phase, "elapsed_ns") orelse Value.null;
        const outcome = stringField(phase, "outcome") orelse "";
        if (!isMember(name, &timing_phases)) {
            return context.fail("timing phase {d} has an unknown name", .{index});
        }
        if (elapsed != .integer or elapsed.integer < 0) {
            return context.fail("timing phase {d} has an invalid elapsed_ns", .{index});
        }
        if ((!std.mem.eql(u8, outcome, "success") and
            !std.mem.eql(u8, outcome, "skipped")) or
            !isNullField(phase, "error_name"))
        {
            return context.fail("timing phase {d} did not succeed", .{index});
        }
        var key: []const u8 = name;
        if (std.mem.eql(u8, name, "debz_transaction")) {
            const present = item orelse "";
            if (!isMember(present, &package_roots)) {
                return context.fail("timing JSON has an unknown debz package item", .{});
            }
            try debz_items.append(allocator, present);
            key = try std.fmt.allocPrint(allocator, "{s}:{s}", .{ name, present });
        } else if (!isNullField(phase, "item")) {
            return context.fail("timing phase {s} unexpectedly has an item", .{name});
        }
        if (values.contains(key)) {
            return context.fail("timing JSON contains duplicate phase {s}", .{key});
        }
        if (std.mem.eql(u8, key, "raw_image_materialization") and
            !std.mem.eql(u8, outcome, "success"))
        {
            return context.fail(
                "timing JSON raw_image_materialization was not successful",
                .{},
            );
        }
        try values.put(allocator, key, elapsed.integer);
    }
    if (debz_items.items.len != package_roots.len) {
        return context.fail(
            "timing JSON does not contain the exact ordered package transactions",
            .{},
        );
    }
    for (debz_items.items, package_roots) |actual, expected| {
        if (!std.mem.eql(u8, actual, expected)) return context.fail(
            "timing JSON does not contain the exact ordered package transactions",
            .{},
        );
    }
    for (phase_order) |phase| {
        if (!values.contains(phase)) {
            return context.fail("timing JSON is missing phase {s}", .{phase});
        }
    }
    const last = phases.array.items[phases.array.items.len - 1];
    if (!stringEquals(last, "name", "total_runtime")) {
        return context.fail("timing JSON total_runtime is not last", .{});
    }
    return .{ .document = document, .values = values };
}

/// `median_int`: integer median with the even case floored, so a summary never
/// carries a fractional nanosecond.
pub fn medianInt(allocator: Allocator, values: []const i64, context: *Context) !i64 {
    if (values.len == 0) {
        return context.fail("cannot calculate a median of no values", .{});
    }
    const ordered = try allocator.dupe(i64, values);
    defer allocator.free(ordered);
    std.mem.sort(i64, ordered, {}, std.sort.asc(i64));
    const middle = ordered.len / 2;
    if (ordered.len % 2 == 1) return ordered[middle];
    return @divFloor(ordered[middle - 1] + ordered[middle], 2);
}

// ------------------------------------------------------- image and raw output

/// `validate_image_info`: the benchmark output is a standalone zstd QCOW2 of
/// exactly the profile's virtual size.
pub fn validateImageInfo(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    context: *Context,
) !Value {
    const info = try readJson(allocator, io, path, context);
    if (!stringEquals(info, "format", "qcow2")) {
        return context.fail("benchmark output is not QCOW2", .{});
    }
    if (integerField(info, "virtual-size") != virtual_size) {
        return context.fail(
            "benchmark output does not have the exact 5 GiB virtual size",
            .{},
        );
    }
    if (isTruthy(getField(info, "backing-filename")) or
        isTruthy(getField(info, "full-backing-filename")))
    {
        return context.fail("benchmark output unexpectedly has a backing file", .{});
    }
    const format_specific = getField(info, "format-specific") orelse Value.null;
    const data = if (format_specific == .object)
        getField(format_specific, "data") orelse Value.null
    else
        Value.null;
    if (data != .object or !stringEquals(data, "compression-type", "zstd")) {
        return context.fail("benchmark output is not a standalone zstd QCOW2", .{});
    }
    return object(allocator, &.{
        .{ "format", str("qcow2") },
        .{ "virtual_size", int(virtual_size) },
        .{ "compression_type", str("zstd") },
        .{ "backing_file", .null },
    });
}

/// Python truthiness for the JSON values a `qemu-img`-shaped document holds.
fn isTruthy(value: ?Value) bool {
    const present = value orelse return false;
    return switch (present) {
        .null => false,
        .bool => |flag| flag,
        .integer => |number| number != 0,
        .float => |number| number != 0,
        .number_string => |text| text.len != 0,
        .string => |text| text.len != 0,
        .array => |items| items.items.len != 0,
        .object => |map| map.count() != 0,
    };
}

pub const RawOutput = struct {
    bytes: i64,
    retention_policy: ?[]const u8 = null,

    pub fn toJson(self: RawOutput, allocator: Allocator) !Value {
        var map = ObjectMap.empty;
        try map.put(allocator, "filename", str(raw_asset_name));
        try map.put(allocator, "format", str("raw"));
        try map.put(allocator, "bytes", int(self.bytes));
        try map.put(allocator, "virtual_size", int(virtual_size));
        try map.put(allocator, "structural_validation", str("miz-check-and-info"));
        try map.put(allocator, "byte_hash_recorded", .{ .bool = false });
        try map.put(allocator, "byte_reproducibility_compared", .{ .bool = false });
        if (self.retention_policy) |policy| try map.put(allocator, "retention_policy", str(policy));
        return .{ .object = map };
    }
};

/// `validate_raw_file`: a non-symlink regular file of exactly the profile's
/// virtual size.
pub fn validateRawFile(io: Io, path: []const u8, context: *Context) !i64 {
    const stat = statNoFollow(io, path) catch |err| switch (err) {
        error.FileNotFound => return context.fail(
            "raw benchmark output is missing: {s}",
            .{path},
        ),
        else => return err,
    };
    if (stat.kind != .file) return context.fail(
        "raw benchmark output must be a non-symlink regular file: {s}",
        .{path},
    );
    if (stat.size != virtual_size) return context.fail(
        "raw benchmark output does not have the exact 5 GiB virtual size",
        .{},
    );
    return @intCast(stat.size);
}

const raw_info_fields = [_][]const u8{
    "filename",
    "format",
    "virtual-size",
    "actual-size",
    "subformat",
    "backing-filename",
    "format-specific",
};

/// `validate_raw_output`: the file plus the exact metadata document `miz info`
/// reports for it.
pub fn validateRawOutput(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    info_path: []const u8,
    context: *Context,
) !RawOutput {
    const size = try validateRawFile(io, path, context);
    const info = try readJson(allocator, io, info_path, context);
    if (!hasExactFields(info, &raw_info_fields) or
        !stringEquals(info, "filename", path) or
        !stringEquals(info, "format", "raw") or
        integerField(info, "virtual-size") != virtual_size or
        integerField(info, "actual-size") != virtual_size or
        !isNullField(info, "subformat") or
        !isNullField(info, "backing-filename") or
        !isNullField(info, "format-specific"))
    {
        return context.fail("raw benchmark output metadata is invalid", .{});
    }
    return .{ .bytes = size };
}

// -------------------------------------------------- transaction provenance

/// debz records the per-run root-stage path in argv and hashes that argv, so
/// the run-specific directory is replaced before two runs are compared.
pub fn normalizeTransactionArgument(
    allocator: Allocator,
    value: []const u8,
) ![]const u8 {
    const marker = "/work/root-stage-";
    const marker_index = std.mem.indexOf(u8, value, marker) orelse return value;
    const equals_index = std.mem.lastIndexOfScalar(u8, value[0..marker_index], '=');
    const path_start = if (equals_index) |at| at + 1 else 0;
    return std.fmt.allocPrint(allocator, "{s}$BENCHMARK_RUN{s}", .{
        value[0..path_start],
        value[marker_index..],
    });
}

/// `semantic_transaction_digest`: the transaction's meaning, with the two
/// fields that are inherently per-run -- its own digest and the argv hashes
/// over run-specific paths -- removed.
pub fn semanticTransactionDigest(
    allocator: Allocator,
    document: Value,
    context: *Context,
) ![]const u8 {
    const commands = getField(document, "commands") orelse Value.null;
    if (commands != .array) {
        return context.fail("transaction provenance commands are invalid", .{});
    }
    var normalized_commands = JsonArray.init(allocator);
    for (commands.array.items) |command| {
        if (command != .object) {
            return context.fail("transaction provenance command is invalid", .{});
        }
        const argv = getField(command, "argv") orelse Value.null;
        if (argv != .array) {
            return context.fail("transaction provenance command argv is invalid", .{});
        }
        var normalized_argv = JsonArray.init(allocator);
        for (argv.array.items) |item| {
            if (item != .string) return context.fail(
                "transaction provenance command argv is invalid",
                .{},
            );
            try normalized_argv.append(
                str(try normalizeTransactionArgument(allocator, item.string)),
            );
        }
        var map = ObjectMap.empty;
        var entries = command.object.iterator();
        while (entries.next()) |entry| {
            if (std.mem.eql(u8, entry.key_ptr.*, "command_sha256")) continue;
            if (std.mem.eql(u8, entry.key_ptr.*, "argv")) continue;
            try map.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
        }
        try map.put(allocator, "argv", .{ .array = normalized_argv });
        try normalized_commands.append(.{ .object = map });
    }
    var normalized = ObjectMap.empty;
    var entries = document.object.iterator();
    while (entries.next()) |entry| {
        if (std.mem.eql(u8, entry.key_ptr.*, "digest_sha256")) continue;
        if (std.mem.eql(u8, entry.key_ptr.*, "commands")) continue;
        try normalized.put(allocator, entry.key_ptr.*, entry.value_ptr.*);
    }
    try normalized.put(allocator, "commands", .{ .array = normalized_commands });
    return canonicalDigestAlloc(allocator, .{ .object = normalized });
}

pub const TransactionEvidence = struct {
    contract: Value,
    file: Value,
};

/// `validate_transaction`: the transaction document proves an exact,
/// successful application of the exact lock it names.
pub fn validateTransaction(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    binding: Value,
    lock_digest: []const u8,
    package: []const u8,
    context: *Context,
) !TransactionEvidence {
    const file_hex = try hashFileHex(io, path);
    const bound_digest = stringField(binding, "sha256") orelse "";
    if (!std.mem.eql(u8, &file_hex, bound_digest)) {
        return context.fail(
            "{s} transaction provenance file hash mismatch",
            .{package},
        );
    }
    const document = try readJson(allocator, io, path, context);
    const final = getField(document, "final_verification") orelse Value.null;
    const digest_label = try std.fmt.allocPrint(
        allocator,
        "{s} transaction digest",
        .{package},
    );
    const provenance_digest = try requireSha256(
        getField(binding, "digest_sha256"),
        digest_label,
        context,
    );
    if (!stringEquals(
        document,
        "schema",
        "https://debz.dev/schema/transaction-result-v1",
    ) or
        integerField(document, "version") != @as(i64, 1) or
        !stringEquals(document, "target_architecture", ubuntu_architecture) or
        !stringEquals(document, "lock_sha256", lock_digest) or
        !stringEquals(document, "digest_sha256", provenance_digest) or
        !stringEquals(document, "outcome", "succeeded") or
        final != .object or
        !stringEquals(final, "status", "exact_match"))
    {
        return context.fail(
            "{s} transaction provenance does not prove exact success",
            .{package},
        );
    }
    const semantic = try semanticTransactionDigest(allocator, document, context);
    return .{
        .contract = try object(allocator, &.{
            .{ "package", str(package) },
            .{ "semantic_digest_sha256", str(semantic) },
            .{ "lock_sha256", str(lock_digest) },
        }),
        .file = try object(allocator, &.{
            .{ "package", str(package) },
            .{ "filename", str(std.fs.path.basename(path)) },
            .{ "file_sha256", str(try allocator.dupe(u8, &file_hex)) },
            .{ "transaction_digest_sha256", str(provenance_digest) },
        }),
    };
}

// ---------------------------------------------------------- build provenance

const ArtifactBinding = struct {
    key: []const u8,
    filename: []const u8,
    sha256: []const u8,
};

const expected_artifacts = [_]ArtifactBinding{
    .{ .key = "sha256sums", .filename = "SHA256SUMS", .sha256 = sums_sha256 },
    .{
        .key = "sha256sums_signature",
        .filename = "SHA256SUMS.gpg",
        .sha256 = sums_signature_sha256,
    },
    .{ .key = "source_image", .filename = source_name, .sha256 = source_sha256 },
    .{ .key = "image_manifest", .filename = manifest_name, .sha256 = manifest_sha256 },
};

const build_provenance_fields = [_][]const u8{
    "schema",
    "type",
    "architecture",
    "flavor",
    "release",
    "virtual_size",
    "minimum_root_free_bytes",
    "validated_root_free_bytes",
    "snapshot",
    "canonical_key_fingerprint",
    "sha256sums_signature_verified",
    "artifacts",
    "debz",
};

pub const ProvenanceEvidence = struct {
    contract: Value,
    transaction_files: Value,
};

/// `validate_provenance`: the whole output-side contract -- pinned source
/// identity, exact package roots and locks, per-package transaction proofs,
/// boot-input evidence, and UKI signing -- re-derived from the documents the
/// builder wrote.
pub fn validateProvenance(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    lock_set: *const LockSet,
    certificate_sha256: []const u8,
    context: *Context,
) !ProvenanceEvidence {
    if (!isDirectoryNoFollow(io, root)) {
        return context.fail("provenance directory is missing or unsafe", .{});
    }
    const build_path = try joinPath(
        allocator,
        &.{ root, "ubuntu2604-build-provenance.json" },
    );
    const build = try readJson(allocator, io, build_path, context);
    if (!hasExactFields(build, &build_provenance_fields)) {
        return context.fail("Ubuntu build provenance has unexpected fields", .{});
    }
    const snapshot = getField(build, "snapshot") orelse Value.null;
    const snapshot_matches = hasExactFields(snapshot, &.{ "id", "base_url" }) and
        stringEquals(snapshot, "id", "release-20260731") and
        stringEquals(
            snapshot,
            "base_url",
            "https://cloud-images.ubuntu.com/releases/26.04/release-20260731/",
        );
    const signature_verified = switch (getField(build, "sha256sums_signature_verified") orelse
        Value.null) {
        .bool => |flag| flag,
        else => false,
    };
    if (integerField(build, "schema") != @as(i64, 1) or
        !stringEquals(build, "type", "miz-ubuntu2604-build-provenance") or
        !stringEquals(build, "architecture", architecture) or
        !stringEquals(build, "flavor", flavor) or
        !stringEquals(build, "release", "26.04") or
        integerField(build, "virtual_size") != virtual_size or
        !snapshot_matches or
        !stringEquals(build, "canonical_key_fingerprint", canonical_fingerprint) or
        !signature_verified)
    {
        return context.fail("Ubuntu build provenance identity is invalid", .{});
    }
    const minimum_free = integerField(build, "minimum_root_free_bytes");
    const validated_free = integerField(build, "validated_root_free_bytes");
    if (minimum_free == null or validated_free == null or
        minimum_free.? <= 0 or
        validated_free.? < minimum_free.? or
        validated_free.? >= virtual_size)
    {
        return context.fail(
            "Ubuntu build provenance free-space constraint is invalid",
            .{},
        );
    }

    const artifacts = getField(build, "artifacts") orelse Value.null;
    var artifact_keys: [expected_artifacts.len][]const u8 = undefined;
    for (expected_artifacts, 0..) |expected, index| artifact_keys[index] = expected.key;
    if (artifacts != .object or !hasExactFields(artifacts, &artifact_keys)) {
        return context.fail("Ubuntu source artifact provenance is not exact", .{});
    }
    for (expected_artifacts) |expected| {
        const binding = artifacts.object.get(expected.key) orelse Value.null;
        if (binding != .object) {
            return context.fail("Ubuntu {s} binding is invalid", .{expected.key});
        }
        const is_source = std.mem.eql(u8, expected.key, "source_image");
        const required: []const []const u8 = if (is_source)
            &.{ "filename", "sha256", "role" }
        else
            &.{ "filename", "sha256" };
        if (!hasExactFields(binding, required) or
            !stringEquals(binding, "filename", expected.filename) or
            !stringEquals(binding, "sha256", expected.sha256))
        {
            return context.fail("Ubuntu {s} binding is invalid", .{expected.key});
        }
        if (is_source) {
            if (!stringEquals(binding, "role", "signed-gpt-esp-substrate")) {
                return context.fail("Ubuntu source image role is invalid", .{});
            }
        } else {
            const bound_path = try joinPath(allocator, &.{ root, expected.filename });
            const hex = try hashFileHex(io, bound_path);
            if (!std.mem.eql(u8, &hex, expected.sha256)) return context.fail(
                "Ubuntu {s} provenance file hash mismatch",
                .{expected.key},
            );
        }
    }

    const debz = getField(build, "debz") orelse Value.null;
    const baseline = getField(debz, "baseline") orelse Value.null;
    const baseline_matches = hasExactFields(baseline, &.{ "source", "enforcement" }) and
        stringEquals(baseline, "source", "empty-debz-root") and
        stringEquals(baseline, "enforcement", "exact-final-closure");
    const roots = getField(debz, "package_roots") orelse Value.null;
    var roots_match = roots == .array and roots.array.items.len == package_roots.len;
    if (roots_match) {
        for (roots.array.items, package_roots) |actual, expected| {
            if (actual != .string or !std.mem.eql(u8, actual.string, expected)) {
                roots_match = false;
            }
        }
    }
    if (debz != .object or
        !hasExactFields(debz, &.{ "api_commit", "baseline", "package_roots", "transactions" }) or
        !stringEquals(debz, "api_commit", debz_api_commit) or
        !baseline_matches or
        !roots_match)
    {
        return context.fail("Ubuntu debz package roots are not exact", .{});
    }
    const transactions = getField(debz, "transactions") orelse Value.null;
    if (transactions != .array or transactions.array.items.len != package_roots.len) {
        return context.fail("Ubuntu debz transaction count is not exact", .{});
    }

    var contracts = JsonArray.init(allocator);
    var files = JsonArray.init(allocator);
    for (package_roots, transactions.array.items) |package, transaction| {
        if (transaction != .object or !stringEquals(transaction, "package", package)) {
            return context.fail("Ubuntu debz transactions are not stably ordered", .{});
        }
        const lock_binding = getField(transaction, "exact_lock") orelse Value.null;
        const provenance_binding =
            getField(transaction, "transaction_provenance") orelse Value.null;
        if (lock_binding != .object or provenance_binding != .object) {
            return context.fail("{s} transaction bindings are absent", .{package});
        }
        const expected_lock = lock_set.find(package) orelse return context.fail(
            "{s} output exact lock differs from the pinned input",
            .{package},
        );
        var lock_matches = stringEquals(lock_binding, "filename", expected_lock.filename) and
            stringEquals(lock_binding, "sha256", expected_lock.file_sha256) and
            stringEquals(lock_binding, "digest_sha256", expected_lock.digest_sha256);
        if (lock_matches) {
            const bound_path = try joinPath(
                allocator,
                &.{ root, stringField(lock_binding, "filename").? },
            );
            const hex = try hashFileHex(io, bound_path);
            lock_matches = std.mem.eql(u8, &hex, expected_lock.file_sha256);
        }
        if (!lock_matches) return context.fail(
            "{s} output exact lock differs from the pinned input",
            .{package},
        );
        if (!stringEquals(provenance_binding, "lock_sha256", expected_lock.digest_sha256)) {
            return context.fail(
                "{s} transaction is not bound to its exact lock",
                .{package},
            );
        }
        const provenance_path = try joinPath(
            allocator,
            &.{ root, stringField(provenance_binding, "filename") orelse "" },
        );
        const evidence = try validateTransaction(
            allocator,
            io,
            provenance_path,
            provenance_binding,
            expected_lock.digest_sha256,
            package,
            context,
        );
        try contracts.append(evidence.contract);
        try files.append(evidence.file);
    }

    const boot_path = try joinPath(
        allocator,
        &.{ root, "ubuntu2604-boot-input-evidence.json" },
    );
    const boot = try readJson(allocator, io, boot_path, context);
    const kernel_release = stringField(boot, "kernel_release");
    if (integerField(boot, "schema") != @as(i64, 1) or
        !stringEquals(boot, "type", "miz-ubuntu2604-boot-input-evidence") or
        !stringEquals(boot, "architecture", architecture) or
        !stringEquals(boot, "package_lock", "/var/lib/miz/ubuntu2604-package-lock.tsv") or
        kernel_release == null or
        !std.mem.endsWith(u8, kernel_release.?, "-nvidia-bos-64k"))
    {
        return context.fail("bare-metal boot input evidence is invalid", .{});
    }
    const package_lock_sha256 = try requireSha256(
        getField(boot, "package_lock_sha256"),
        "embedded package inventory digest",
        context,
    );

    const signing_path = try joinPath(
        allocator,
        &.{ root, "uki-signing-baremetal-aarch64.json" },
    );
    const signing = try readJson(allocator, io, signing_path, context);
    if (integerField(signing, "schema") != @as(i64, 1) or
        !stringEquals(signing, "type", "miz-uki-signing") or
        !stringEquals(signing, "architecture", architecture) or
        !stringEquals(signing, "flavor", flavor) or
        !stringEquals(signing, "certificate_sha256", certificate_sha256) or
        !stringEquals(signing, "signature_verification", "success"))
    {
        return context.fail("UKI signing provenance is invalid", .{});
    }
    const stub = getField(signing, "uki_stub") orelse Value.null;
    if (stub != .object) return context.fail("UKI stub provenance is missing", .{});
    const stub_sha256 = try requireSha256(
        getField(stub, "sha256"),
        "UKI stub digest",
        context,
    );

    var artifacts_contract = ObjectMap.empty;
    for (expected_artifacts) |expected| {
        try artifacts_contract.put(allocator, expected.key, try array(allocator, &.{
            str(expected.filename),
            str(expected.sha256),
        }));
    }
    var roots_contract = JsonArray.init(allocator);
    for (package_roots) |package| try roots_contract.append(str(package));

    return .{
        .contract = try object(allocator, &.{
            .{ "source_artifacts", .{ .object = artifacts_contract } },
            .{ "package_roots", .{ .array = roots_contract } },
            .{
                "lock_set_sha256",
                str(try canonicalDigestAlloc(allocator, lock_set.locks_json)),
            },
            .{ "transaction_provenance", .{ .array = contracts } },
            .{ "closure_sha256", str(lock_set.closure_sha256) },
            .{ "virtual_size", int(virtual_size) },
            .{ "minimum_root_free_bytes", int(minimum_free.?) },
            .{ "validated_root_free_bytes", int(validated_free.?) },
            .{ "kernel_release", str(kernel_release.?) },
            .{ "embedded_package_inventory_sha256", str(package_lock_sha256) },
            .{ "signing", try object(allocator, &.{
                .{ "mode", getField(signing, "signer_mode") orelse Value.null },
                .{ "certificate_sha256", str(certificate_sha256) },
                .{ "uki_stub_sha256", str(stub_sha256) },
                .{ "signature_verification", str("success") },
            }) },
        }),
        .transaction_files = .{ .array = files },
    };
}

// -------------------------------------------------- correctness comparison

const Difference = struct {
    path: []const u8,
    /// `null` is the Python `MISSING` sentinel: the key is absent on this side.
    reference: ?Value,
    candidate: ?Value,
};

fn typeClass(value: Value) u8 {
    return switch (value) {
        .null => 0,
        .bool => 1,
        .integer, .number_string => 2,
        .float => 3,
        .string => 4,
        .array => 5,
        .object => 6,
    };
}

fn scalarEquals(left: Value, right: Value) bool {
    return switch (left) {
        .null => true,
        .bool => |flag| flag == right.bool,
        .integer => |number| right == .integer and number == right.integer,
        .float => |number| right == .float and number == right.float,
        .number_string => |text| right == .number_string and
            std.mem.eql(u8, text, right.number_string),
        .string => |text| right == .string and std.mem.eql(u8, text, right.string),
        else => false,
    };
}

fn isIdentifier(key: []const u8) bool {
    if (key.len == 0) return false;
    switch (key[0]) {
        'A'...'Z', 'a'...'z', '_' => {},
        else => return false,
    }
    for (key[1..]) |byte| switch (byte) {
        'A'...'Z', 'a'...'z', '0'...'9', '_' => {},
        else => return false,
    };
    return true;
}

fn jsonText(allocator: Allocator, value: Value) ![]const u8 {
    return json_document.canonicalAlloc(allocator, value, .compact);
}

fn jsonPath(allocator: Allocator, parent: []const u8, key: []const u8) ![]const u8 {
    if (isIdentifier(key)) {
        return std.fmt.allocPrint(allocator, "{s}.{s}", .{ parent, key });
    }
    const quoted = try jsonText(allocator, str(key));
    return std.fmt.allocPrint(allocator, "{s}[{s}]", .{ parent, quoted });
}

/// `json_differences`: every differing field path, so a failed comparison
/// names all of them rather than the first one.
fn jsonDifferences(
    allocator: Allocator,
    differences: *std.ArrayList(Difference),
    path: []const u8,
    reference: Value,
    candidate: Value,
) !void {
    if (typeClass(reference) != typeClass(candidate)) {
        try differences.append(allocator, .{
            .path = path,
            .reference = reference,
            .candidate = candidate,
        });
        return;
    }
    switch (reference) {
        .object => |reference_map| {
            const candidate_map = candidate.object;
            var keys: std.ArrayList([]const u8) = .empty;
            defer keys.deinit(allocator);
            for (reference_map.keys()) |key| try keys.append(allocator, key);
            for (candidate_map.keys()) |key| {
                if (!reference_map.contains(key)) try keys.append(allocator, key);
            }
            std.mem.sort([]const u8, keys.items, {}, lessThanString);
            for (keys.items) |key| {
                const child = try jsonPath(allocator, path, key);
                const in_reference = reference_map.get(key);
                const in_candidate = candidate_map.get(key);
                if (in_reference == null) {
                    try differences.append(allocator, .{
                        .path = child,
                        .reference = null,
                        .candidate = in_candidate,
                    });
                } else if (in_candidate == null) {
                    try differences.append(allocator, .{
                        .path = child,
                        .reference = in_reference,
                        .candidate = null,
                    });
                } else {
                    try jsonDifferences(
                        allocator,
                        differences,
                        child,
                        in_reference.?,
                        in_candidate.?,
                    );
                }
            }
        },
        .array => |reference_items| {
            const candidate_items = candidate.array;
            if (reference_items.items.len != candidate_items.items.len) {
                try differences.append(allocator, .{
                    .path = try std.fmt.allocPrint(allocator, "{s}.length", .{path}),
                    .reference = int(@intCast(reference_items.items.len)),
                    .candidate = int(@intCast(candidate_items.items.len)),
                });
            }
            const shared = @min(reference_items.items.len, candidate_items.items.len);
            for (0..shared) |index| {
                const child = try std.fmt.allocPrint(
                    allocator,
                    "{s}[{d}]",
                    .{ path, index },
                );
                try jsonDifferences(
                    allocator,
                    differences,
                    child,
                    reference_items.items[index],
                    candidate_items.items[index],
                );
            }
        },
        else => {
            if (!scalarEquals(reference, candidate)) try differences.append(allocator, .{
                .path = path,
                .reference = reference,
                .candidate = candidate,
            });
        },
    }
}

/// Whether a string looks like a filesystem path, in which case the diagnostic
/// reports its digest instead of its text: the benchmark's own diagnostics must
/// not leak an operator's private signer or key locations.
fn looksLikePath(text: []const u8) bool {
    for (text, 0..) |byte, index| {
        if (byte != '/') continue;
        if (index == 0) return true;
        const previous = text[index - 1];
        if (previous == '=' or std.ascii.isWhitespace(previous)) return true;
    }
    if (text.len >= 3 and std.ascii.isAlphabetic(text[0]) and text[1] == ':' and
        (text[2] == '\\' or text[2] == '/')) return true;
    return false;
}

/// `safe_difference_value`: a renderable, non-leaking spelling of one side of
/// a difference.
fn safeDifferenceValue(allocator: Allocator, value: ?Value) ![]const u8 {
    const present = value orelse return "<missing>";
    switch (present) {
        .null, .bool, .integer, .float, .number_string => return jsonText(allocator, present),
        .string => |text| {
            if (isSha256Name(text)) return text;
            if (looksLikePath(text)) return std.fmt.allocPrint(
                allocator,
                "<absolute-path sha256={s}>",
                .{&digest_support.hexBytes(text)},
            );
            if (text.len <= 96 and std.mem.indexOfScalar(u8, text, '\n') == null) {
                return jsonText(allocator, present);
            }
            return std.fmt.allocPrint(
                allocator,
                "<string bytes={d} sha256={s}>",
                .{ text.len, &digest_support.hexBytes(text) },
            );
        },
        .object => |map| return std.fmt.allocPrint(
            allocator,
            "<object fields={d} sha256={s}>",
            .{ map.count(), &try canonicalDigest(allocator, present) },
        ),
        .array => |items| return std.fmt.allocPrint(
            allocator,
            "<array items={d} sha256={s}>",
            .{ items.items.len, &try canonicalDigest(allocator, present) },
        ),
    }
}

/// `compare_correctness`: any semantic difference from the warm-up reference
/// invalidates the benchmark, and the diagnostic names every differing field.
pub fn compareCorrectness(
    allocator: Allocator,
    reference: Value,
    candidate: Value,
    context: *Context,
) !void {
    var differences: std.ArrayList(Difference) = .empty;
    defer differences.deinit(allocator);
    try jsonDifferences(allocator, &differences, "$", reference, candidate);
    if (differences.items.len == 0) return;

    var details: std.ArrayList(u8) = .empty;
    defer details.deinit(allocator);
    for (differences.items, 0..) |difference, index| {
        if (index > 0) try details.appendSlice(allocator, "; ");
        const rendered = try std.fmt.allocPrint(
            allocator,
            "{s}: reference={s}, candidate={s}",
            .{
                difference.path,
                try safeDifferenceValue(allocator, difference.reference),
                try safeDifferenceValue(allocator, difference.candidate),
            },
        );
        try details.appendSlice(allocator, rendered);
    }
    return context.fail(
        "correctness evidence differs from the warm-up reference" ++
            " ({d} differing field(s)): {s}",
        .{ differences.items.len, details.items },
    );
}

// ------------------------------------------------------------------ summary

pub const resource_fields = [_][]const u8{
    "wall_ns",
    "user_ns",
    "system_ns",
    "peak_rss_bytes",
    "read_bytes",
    "write_bytes",
    "block_inputs",
    "block_outputs",
};

pub const Resources = struct {
    status: []const u8,
    exit_code: i64,
    wall_ns: i64,
    user_ns: i64,
    system_ns: i64,
    peak_rss_bytes: ?i64,
    read_bytes: ?i64,
    write_bytes: ?i64,
    block_inputs: i64,
    block_outputs: i64,
    io_bytes_source: []const u8,

    pub fn field(self: Resources, name: []const u8) ?i64 {
        if (std.mem.eql(u8, name, "wall_ns")) return self.wall_ns;
        if (std.mem.eql(u8, name, "user_ns")) return self.user_ns;
        if (std.mem.eql(u8, name, "system_ns")) return self.system_ns;
        if (std.mem.eql(u8, name, "peak_rss_bytes")) return self.peak_rss_bytes;
        if (std.mem.eql(u8, name, "read_bytes")) return self.read_bytes;
        if (std.mem.eql(u8, name, "write_bytes")) return self.write_bytes;
        if (std.mem.eql(u8, name, "block_inputs")) return self.block_inputs;
        if (std.mem.eql(u8, name, "block_outputs")) return self.block_outputs;
        return null;
    }

    pub fn toJson(self: Resources, allocator: Allocator) !Value {
        return object(allocator, &.{
            .{ "schema", int(schema) },
            .{ "type", str("miz-host-resource-timing") },
            .{ "status", str(self.status) },
            .{ "exit_code", int(self.exit_code) },
            .{ "wall_ns", int(self.wall_ns) },
            .{ "user_ns", int(self.user_ns) },
            .{ "system_ns", int(self.system_ns) },
            .{ "peak_rss_bytes", optionalInt(self.peak_rss_bytes) },
            .{ "read_bytes", optionalInt(self.read_bytes) },
            .{ "write_bytes", optionalInt(self.write_bytes) },
            .{ "block_inputs", int(self.block_inputs) },
            .{ "block_outputs", int(self.block_outputs) },
            .{ "io_bytes_source", str(self.io_bytes_source) },
        });
    }
};

pub const RunRecord = struct {
    name: []const u8,
    kind: []const u8,
    timing_values: std.StringArrayHashMapUnmanaged(i64),
    resources: Resources,
    correctness_sha256: []const u8,
    image_sha256: []const u8,
    image_bytes: i64,
    raw_output: RawOutput,
    evidence: []const u8,
    cleanup: []const []const u8,
};

/// `build_summary`: medians over exactly the three measured runs, with the
/// warm-up kept as the correctness reference.
pub fn buildSummary(
    allocator: Allocator,
    runs: []const RunRecord,
    source_commit: []const u8,
    host: Value,
    cache_inventory: Value,
    closure_sha256: []const u8,
    locks: Value,
    context: *Context,
) !Value {
    var measured: std.ArrayList(RunRecord) = .empty;
    defer measured.deinit(allocator);
    for (runs) |run| {
        if (std.mem.eql(u8, run.kind, "measured")) try measured.append(allocator, run);
    }
    if (measured.items.len != measured_runs) {
        return context.fail("summary requires exactly three measured runs", .{});
    }

    var phase_medians = ObjectMap.empty;
    var samples = try allocator.alloc(i64, measured.items.len);
    defer allocator.free(samples);
    for (phase_order) |phase| {
        for (measured.items, 0..) |run, index| {
            samples[index] = run.timing_values.get(phase) orelse return context.fail(
                "summary is missing phase {s}",
                .{phase},
            );
        }
        try phase_medians.put(allocator, phase, int(try medianInt(allocator, samples, context)));
    }

    var resource_medians = ObjectMap.empty;
    for (resource_fields) |name| {
        var complete = true;
        for (measured.items, 0..) |run, index| {
            const value = run.resources.field(name) orelse {
                complete = false;
                break;
            };
            samples[index] = value;
        }
        try resource_medians.put(allocator, name, if (complete)
            int(try medianInt(allocator, samples, context))
        else
            .null);
    }
    try resource_medians.put(allocator, "io_bytes_source", str("linux-proc-descendant-sampling"));

    var run_entries = JsonArray.init(allocator);
    for (runs) |run| {
        var cleanup = JsonArray.init(allocator);
        for (run.cleanup) |removed| try cleanup.append(str(removed));
        try run_entries.append(try object(allocator, &.{
            .{ "name", str(run.name) },
            .{ "kind", str(run.kind) },
            .{ "evidence", str(run.evidence) },
            .{ "image_sha256", str(run.image_sha256) },
            .{ "image_bytes", int(run.image_bytes) },
            .{ "raw_output", try run.raw_output.toJson(allocator) },
            .{ "cleanup", .{ .array = cleanup } },
        }));
    }

    return object(allocator, &.{
        .{ "schema", int(schema) },
        .{ "type", str("miz-ubuntu2604-image-benchmark-summary") },
        .{ "status", str("valid") },
        .{ "profile", try object(allocator, &.{
            .{ "source", str(source_name) },
            .{ "source_sha256", str(source_sha256) },
            .{ "release", str("26.04") },
            .{ "architecture", str(architecture) },
            .{ "flavor", str(flavor) },
            .{ "optimization", str(optimize_mode) },
            .{ "virtual_size", int(virtual_size) },
            .{ "warmup_runs", int(1) },
            .{ "measured_runs", int(measured_runs) },
            .{ "network_policy", str("offline") },
            .{ "raw_image_materialization", str("required") },
        }) },
        .{ "source_commit", str(source_commit) },
        .{ "host", host },
        .{ "cache_inventory", cache_inventory },
        .{ "package_lock_set", try object(allocator, &.{
            .{ "closure_sha256", str(closure_sha256) },
            .{ "locks", locks },
        }) },
        .{ "medians", try object(allocator, &.{
            .{ "phase_elapsed_ns", .{ .object = phase_medians } },
            .{ "resources", .{ .object = resource_medians } },
        }) },
        .{ "correctness", try object(allocator, &.{
            .{ "status", str("identical") },
            .{ "reference_sha256", str(runs[0].correctness_sha256) },
            .{
                "byte_hash_comparison",
                str("not-applicable-no-image-byte-reproducibility-contract"),
            },
        }) },
        .{ "runs", .{ .array = run_entries } },
    });
}

/// `format_seconds`: three fractional digits, or `unavailable` for a counter
/// the host could not supply. The rounding is done on the exact nanosecond
/// count rather than on a float, so the rendering is deterministic; an exact
/// half-millisecond tie rounds up, where Python's float formatting rounded to
/// even. Only this human-readable text is affected -- every consumed value is
/// the integer nanosecond count next to it.
pub fn formatSeconds(allocator: Allocator, nanoseconds: ?i64) ![]const u8 {
    const present = nanoseconds orelse return "unavailable";
    const negative = present < 0;
    const magnitude: u128 = @intCast(if (negative) -present else present);
    const thousandths = (magnitude + 500_000) / 1_000_000;
    return std.fmt.allocPrint(allocator, "{s}{d}.{d:0>3} s", .{
        if (negative) "-" else "",
        thousandths / 1000,
        thousandths % 1000,
    });
}

fn medianInteger(summary: Value, group: []const u8, key: []const u8) ?i64 {
    const medians = getField(summary, "medians") orelse return null;
    const bucket = getField(medians, group) orelse return null;
    return integerField(bucket, key);
}

/// `readable_summary`: the operator-facing rendering of the summary document.
pub fn readableSummary(allocator: Allocator, summary: Value) ![]u8 {
    var text: std.ArrayList(u8) = .empty;
    errdefer text.deinit(allocator);
    const writer = struct {
        fn line(
            list: *std.ArrayList(u8),
            gpa: Allocator,
            comptime fmt: []const u8,
            args: anytype,
        ) !void {
            const rendered = try std.fmt.allocPrint(gpa, fmt ++ "\n", args);
            defer gpa.free(rendered);
            try list.appendSlice(gpa, rendered);
        }
    };
    try writer.line(
        &text,
        allocator,
        "Ubuntu 26.04 aarch64 bare-metal ReleaseSafe image benchmark",
        .{},
    );
    try writer.line(&text, allocator, "", .{});
    try writer.line(&text, allocator, "Status: valid", .{});
    try writer.line(
        &text,
        allocator,
        "Protocol: one warm-up followed by three measured offline runs",
        .{},
    );
    try writer.line(&text, allocator, "Source commit: {s}", .{
        stringField(summary, "source_commit") orelse "",
    });
    try writer.line(&text, allocator, "Median total phase time: {s}", .{
        try formatSeconds(
            allocator,
            medianInteger(summary, "phase_elapsed_ns", "total_runtime"),
        ),
    });
    try writer.line(&text, allocator, "Median host wall time: {s}", .{
        try formatSeconds(allocator, medianInteger(summary, "resources", "wall_ns")),
    });
    try writer.line(&text, allocator, "Median user time: {s}", .{
        try formatSeconds(allocator, medianInteger(summary, "resources", "user_ns")),
    });
    try writer.line(&text, allocator, "Median system time: {s}", .{
        try formatSeconds(allocator, medianInteger(summary, "resources", "system_ns")),
    });
    try writer.line(&text, allocator, "Median peak RSS: {s} bytes", .{
        try optionalCount(allocator, medianInteger(summary, "resources", "peak_rss_bytes")),
    });
    try writer.line(&text, allocator, "Median sampled read bytes: {s}", .{
        try optionalCount(allocator, medianInteger(summary, "resources", "read_bytes")),
    });
    try writer.line(&text, allocator, "Median sampled write bytes: {s}", .{
        try optionalCount(allocator, medianInteger(summary, "resources", "write_bytes")),
    });
    try writer.line(&text, allocator, "", .{});
    try writer.line(&text, allocator, "Phase medians:", .{});
    for (phase_order) |phase| {
        try writer.line(&text, allocator, "  {s}: {s}", .{
            phase,
            try formatSeconds(allocator, medianInteger(summary, "phase_elapsed_ns", phase)),
        });
    }
    try writer.line(&text, allocator, "", .{});
    try writer.line(
        &text,
        allocator,
        "Correctness: package name/version/hash closure, provenance, " ++
            "manifest, boot-input evidence, image structure, and acceptance " ++
            "result were identical.",
        .{},
    );
    try writer.line(
        &text,
        allocator,
        "QCOW2 byte hashes are recorded and raw output metadata is retained. " ++
            "Image bytes are not compared because bare-metal output has no " ++
            "documented byte-reproducibility contract.",
        .{},
    );
    return text.toOwnedSlice(allocator);
}

fn optionalCount(allocator: Allocator, value: ?i64) ![]const u8 {
    const present = value orelse return "None";
    return std.fmt.allocPrint(allocator, "{d}", .{present});
}

// -------------------------------------------------- host facts and processes

const Statfs = extern struct {
    f_type: i64,
    f_bsize: i64,
    f_blocks: u64,
    f_bfree: u64,
    f_bavail: u64,
    f_files: u64,
    f_ffree: u64,
    f_fsid: [2]i32,
    f_namelen: i64,
    f_frsize: i64,
    f_flags: i64,
    f_spare: [4]i64,
};

/// `shutil.disk_usage(path).free`: available bytes for an unprivileged writer.
fn freeDiskBytes(allocator: Allocator, path: []const u8) !u64 {
    if (builtin.os.tag != .linux) return error.Unsupported;
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    var buffer: Statfs = undefined;
    const result = std.os.linux.syscall2(
        .statfs,
        @intFromPtr(path_z.ptr),
        @intFromPtr(&buffer),
    );
    if (std.os.linux.errno(result) != .SUCCESS) return error.StatfsFailed;
    const unit: u64 = if (buffer.f_frsize > 0)
        @intCast(buffer.f_frsize)
    else
        @intCast(buffer.f_bsize);
    return buffer.f_bavail * unit;
}

fn utsField(field: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, field, 0) orelse field.len;
    return field[0..end];
}

/// A borrowed view of the three `utsname` fields the benchmark records. The
/// slices point into the caller's `utsname`, so they are only valid while that
/// value is alive -- use `hostDocument` for anything that outlives it.
const HostIdentity = struct {
    system: []const u8,
    kernel: []const u8,
    machine: []const u8,
};

fn hostIdentity(uts: *const std.posix.utsname) HostIdentity {
    return .{
        .system = utsField(&uts.sysname),
        .kernel = utsField(&uts.release),
        .machine = utsField(&uts.machine),
    };
}

/// The recorded host identity, with every string copied out of `uts`.
///
/// `uts` is a `std.posix.uname()` value on the caller's stack, while this
/// document is returned upwards and ends up embedded in the benchmark summary.
/// Borrowing the `utsname` storage would leave the summary's `system`,
/// `kernel`, and `machine` reading a dead frame. The copies are owned by
/// `allocator`, which is the arena that owns every other document the run
/// produces, so they are released with it.
pub fn hostDocument(
    allocator: Allocator,
    uts: *const std.posix.utsname,
    zig_version: []const u8,
    cpu_count: i64,
) !Value {
    const host = hostIdentity(uts);
    return object(allocator, &.{
        .{ "system", str(try allocator.dupe(u8, host.system)) },
        .{ "kernel", str(try allocator.dupe(u8, host.kernel)) },
        .{ "machine", str(try allocator.dupe(u8, host.machine)) },
        .{ "cpu_count", int(cpu_count) },
        .{ "zig", str(try allocator.dupe(u8, zig_version)) },
    });
}

fn monotonicNanoseconds(io: Io) i96 {
    return Io.Clock.Timestamp.now(io, .awake).raw.nanoseconds;
}

fn timevalNanoseconds(value: std.posix.timeval) i128 {
    return @as(i128, value.sec) * std.time.ns_per_s +
        @as(i128, value.usec) * std.time.ns_per_us;
}

fn exitCodeOf(term: std.process.Child.Term) i64 {
    return switch (term) {
        .exited => |code| code,
        .signal => |signal| -@as(i64, @intFromEnum(signal)),
        .stopped => |signal| -@as(i64, @intFromEnum(signal)),
        .unknown => |code| @intCast(code),
    };
}

fn spawnLogged(
    io: Io,
    argv: []const []const u8,
    cwd: []const u8,
    environ: *const std.process.Environ.Map,
    log_path: []const u8,
) !struct { child: std.process.Child, log: File } {
    const log = try Dir.cwd().createFile(io, log_path, .{});
    errdefer log.close(io);
    const child = try std.process.spawn(io, .{
        .argv = argv,
        .cwd = .{ .path = cwd },
        .environ_map = environ,
        .stdin = .ignore,
        .stdout = .{ .file = log },
        .stderr = .{ .file = log },
    });
    return .{ .child = child, .log = log };
}

/// `run_logged`: run a command with both streams captured, and fail with the
/// log location when it does not succeed.
fn runLogged(
    io: Io,
    argv: []const []const u8,
    cwd: []const u8,
    environ: *const std.process.Environ.Map,
    log_path: []const u8,
    context: *Context,
) !void {
    var spawned = try spawnLogged(io, argv, cwd, environ, log_path);
    const term = spawned.child.wait(io);
    spawned.log.close(io);
    const code = exitCodeOf(try term);
    if (code != 0) return context.fail(
        "command failed ({d}); see {s}",
        .{ code, log_path },
    );
}

const ProcessIdentity = struct { pid: u32, start_time: u64 };
const ProcessIo = struct { read_bytes: u64, write_bytes: u64 };

/// One `/proc` sample of a process tree: total resident bytes now, and the
/// per-process I/O counters, keyed by an identity that survives PID reuse.
///
/// A build is sampled every 50 ms for minutes, so the per-sample process table
/// is built in a scratch arena that is reset each time. Only the accumulated
/// per-process maxima outlive a sample.
const Sampler = struct {
    allocator: Allocator,
    scratch: *std.heap.ArenaAllocator,
    io: Io,
    peak_rss: u64 = 0,
    per_process: std.AutoArrayHashMapUnmanaged(ProcessIdentity, ProcessIo) = .empty,

    fn sample(self: *Sampler, root_pid: u32) !void {
        _ = self.scratch.reset(.retain_capacity);
        const scratch = self.scratch.allocator();
        var processes: std.AutoArrayHashMapUnmanaged(u32, struct {
            parent: u32,
            start_time: u64,
        }) = .empty;

        var proc = Dir.cwd().openDir(self.io, "/proc", .{ .iterate = true }) catch return;
        defer proc.close(self.io);
        var entries = proc.iterate();
        var stat_buffer: [8192]u8 = undefined;
        while (entries.next(self.io) catch null) |entry| {
            const pid = std.fmt.parseInt(u32, entry.name, 10) catch continue;
            var path_buffer: [64]u8 = undefined;
            const stat_path = std.fmt.bufPrint(
                &path_buffer,
                "/proc/{d}/stat",
                .{pid},
            ) catch continue;
            const text = Dir.cwd().readFile(self.io, stat_path, &stat_buffer) catch continue;
            const close = std.mem.lastIndexOfScalar(u8, text, ')') orelse continue;
            if (close + 2 >= text.len) continue;
            var fields = std.mem.tokenizeAny(u8, text[close + 2 ..], " \t\n");
            var index: usize = 0;
            var parent: ?u32 = null;
            var start_time: ?u64 = null;
            while (fields.next()) |field| : (index += 1) {
                if (index == 1) parent = std.fmt.parseInt(u32, field, 10) catch null;
                if (index == 19) {
                    start_time = std.fmt.parseInt(u64, field, 10) catch null;
                    break;
                }
            }
            if (parent == null or start_time == null) continue;
            try processes.put(scratch, pid, .{
                .parent = parent.?,
                .start_time = start_time.?,
            });
        }

        var descendants: std.AutoArrayHashMapUnmanaged(u32, void) = .empty;
        try descendants.put(scratch, root_pid, {});
        var changed = true;
        while (changed) {
            changed = false;
            for (processes.keys(), processes.values()) |pid, entry| {
                if (descendants.contains(entry.parent) and !descendants.contains(pid)) {
                    try descendants.put(scratch, pid, {});
                    changed = true;
                }
            }
        }

        var resident: u64 = 0;
        var buffer: [8192]u8 = undefined;
        for (descendants.keys()) |pid| {
            const entry = processes.get(pid) orelse continue;
            var path_buffer: [64]u8 = undefined;
            const status_path = std.fmt.bufPrint(
                &path_buffer,
                "/proc/{d}/status",
                .{pid},
            ) catch continue;
            const status = Dir.cwd().readFile(self.io, status_path, &buffer) catch continue;
            var rss_kib: u64 = 0;
            var status_lines = std.mem.splitScalar(u8, status, '\n');
            while (status_lines.next()) |line| {
                if (!std.mem.startsWith(u8, line, "VmRSS:")) continue;
                var parts = std.mem.tokenizeAny(u8, line["VmRSS:".len..], " \t");
                const value = parts.next() orelse break;
                rss_kib = std.fmt.parseInt(u64, value, 10) catch 0;
                break;
            }
            var io_path_buffer: [64]u8 = undefined;
            const io_path = std.fmt.bufPrint(
                &io_path_buffer,
                "/proc/{d}/io",
                .{pid},
            ) catch continue;
            var read_bytes: u64 = 0;
            var write_bytes: u64 = 0;
            if (Dir.cwd().readFile(self.io, io_path, &buffer)) |counters| {
                var io_lines = std.mem.splitScalar(u8, counters, '\n');
                while (io_lines.next()) |line| {
                    const separator = std.mem.indexOfScalar(u8, line, ':') orelse continue;
                    const name = line[0..separator];
                    const value = std.mem.trim(u8, line[separator + 1 ..], " \t\r");
                    const parsed = std.fmt.parseInt(u64, value, 10) catch continue;
                    if (std.mem.eql(u8, name, "read_bytes")) read_bytes = parsed;
                    if (std.mem.eql(u8, name, "write_bytes")) write_bytes = parsed;
                }
            } else |_| {}
            resident += rss_kib * 1024;
            const identity: ProcessIdentity = .{
                .pid = pid,
                .start_time = entry.start_time,
            };
            const previous = self.per_process.get(identity) orelse
                ProcessIo{ .read_bytes = 0, .write_bytes = 0 };
            try self.per_process.put(self.allocator, identity, .{
                .read_bytes = @max(previous.read_bytes, read_bytes),
                .write_bytes = @max(previous.write_bytes, write_bytes),
            });
        }
        self.peak_rss = @max(self.peak_rss, resident);
    }

    fn totals(self: *const Sampler) ?ProcessIo {
        if (self.per_process.count() == 0) return null;
        var result: ProcessIo = .{ .read_bytes = 0, .write_bytes = 0 };
        for (self.per_process.values()) |value| {
            result.read_bytes += value.read_bytes;
            result.write_bytes += value.write_bytes;
        }
        return result;
    }
};

/// Waits 50 ms for the child to exit, reporting whether it has. A kernel that
/// cannot supply a pidfd falls back to an unsampled wait rather than to a busy
/// loop that would itself distort the measurement.
fn childExited(pidfd: i32) bool {
    var fds = [_]std.os.linux.pollfd{.{
        .fd = pidfd,
        .events = std.os.linux.POLL.IN,
        .revents = 0,
    }};
    const result = std.os.linux.poll(&fds, fds.len, 50);
    return switch (std.os.linux.errno(result)) {
        .SUCCESS => result != 0,
        .INTR => false,
        else => true,
    };
}

/// `run_measured_command`: the measured interval, plus the host counters the
/// summary reports medians of.
fn runMeasuredCommand(
    io: Io,
    argv: []const []const u8,
    cwd: []const u8,
    environ: *const std.process.Environ.Map,
    log_path: []const u8,
) !Resources {
    const usage_before = std.posix.getrusage(std.posix.rusage.CHILDREN);
    const started = monotonicNanoseconds(io);
    var spawned = try spawnLogged(io, argv, cwd, environ, log_path);
    // The sampler owns its memory outright: the measured interval is minutes
    // long, so nothing it allocates may accumulate in the run's arena.
    var sampler_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer sampler_arena.deinit();
    var scratch_arena: std.heap.ArenaAllocator = .init(std.heap.page_allocator);
    defer scratch_arena.deinit();
    var sampler: Sampler = .{
        .allocator = sampler_arena.allocator(),
        .scratch = &scratch_arena,
        .io = io,
    };
    const pid: u32 = @intCast(spawned.child.id orelse 0);
    if (builtin.os.tag == .linux and pid != 0) {
        const opened = std.os.linux.pidfd_open(@intCast(pid), 0);
        if (std.os.linux.errno(opened) == .SUCCESS) {
            const pidfd: i32 = @intCast(opened);
            defer _ = std.os.linux.close(pidfd);
            while (true) {
                sampler.sample(pid) catch {};
                if (childExited(pidfd)) break;
            }
        }
    }
    const term = spawned.child.wait(io);
    spawned.log.close(io);
    const finished = monotonicNanoseconds(io);
    const usage_after = std.posix.getrusage(std.posix.rusage.CHILDREN);
    const code = exitCodeOf(try term);
    const totals = sampler.totals();
    return .{
        .status = if (code == 0) "success" else "failure",
        .exit_code = code,
        .wall_ns = @intCast(finished - started),
        .user_ns = @intCast(timevalNanoseconds(usage_after.utime) -
            timevalNanoseconds(usage_before.utime)),
        .system_ns = @intCast(timevalNanoseconds(usage_after.stime) -
            timevalNanoseconds(usage_before.stime)),
        .peak_rss_bytes = if (sampler.peak_rss == 0)
            null
        else
            @intCast(sampler.peak_rss),
        .read_bytes = if (totals) |value| @intCast(value.read_bytes) else null,
        .write_bytes = if (totals) |value| @intCast(value.write_bytes) else null,
        .block_inputs = @intCast(usage_after.inblock - usage_before.inblock),
        .block_outputs = @intCast(usage_after.oublock - usage_before.oublock),
        .io_bytes_source = if (totals == null)
            "unavailable"
        else
            "linux-proc-descendant-sampling",
    };
}

/// `git_output`: a git query that must succeed, with git's own stderr behind
/// the failure line.
fn gitOutput(
    allocator: Allocator,
    io: Io,
    repo: []const u8,
    arguments: []const []const u8,
    context: *Context,
) ![]const u8 {
    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.append(allocator, "git");
    try argv.appendSlice(allocator, arguments);
    const result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .cwd = .{ .path = repo },
        .stdout_limit = .limited(4 * 1024 * 1024),
        .stderr_limit = .limited(4 * 1024 * 1024),
    });
    defer allocator.free(result.stderr);
    const joined = try std.mem.join(allocator, " ", arguments);
    switch (result.term) {
        .exited => |code| if (code != 0) return context.fail(
            "git {s} failed: {s}",
            .{ joined, std.mem.trim(u8, result.stderr, " \t\r\n") },
        ),
        else => return context.fail(
            "git {s} failed: {s}",
            .{ joined, std.mem.trim(u8, result.stderr, " \t\r\n") },
        ),
    }
    return std.mem.trim(u8, result.stdout, " \t\r\n");
}

// ------------------------------------------------------------------ options

pub const Arguments = struct {
    output_root: []const u8,
    source: []const u8,
    sha256sums: []const u8,
    sha256sums_signature: []const u8,
    manifest: []const u8,
    debz_cache: []const u8,
    debz_input_dir: []const u8,
    debz_lock_dir: []const u8,
    authorized_key: []const u8,
    uki_stub: []const u8,
    signing_certificate: []const u8,
    signing_certificate_sha256: []const u8,
    signing_key: ?[]const u8,
    sign_command: ?[]const u8,
    sign_command_arg: ?[]const u8,
    zig: []const u8,
    zig_global_cache: []const u8,
    acceptance_command: ?[]const u8,
    keep_images: bool,
};

/// Accepts both `--name value` and `--name=value`, like `argparse`.
fn optionValue(
    argv: []const []const u8,
    index: *usize,
    argument: []const u8,
    name: []const u8,
) ?[]const u8 {
    if (std.mem.eql(u8, argument, name)) {
        if (index.* + 1 >= argv.len) return null;
        index.* += 1;
        return argv[index.*];
    }
    if (argument.len > name.len + 1 and
        std.mem.startsWith(u8, argument, name) and
        argument[name.len] == '=')
    {
        return argument[name.len + 1 ..];
    }
    return null;
}

/// `parse_args`: the full option set, its mutually exclusive signing group,
/// and the same path normalization -- `abspath` for the output root that does
/// not exist yet, `resolve` for every input.
pub fn parseArgs(allocator: Allocator, io: Io, argv: []const []const u8) !Arguments {
    var output_root: ?[]const u8 = null;
    var source: ?[]const u8 = null;
    var sha256sums: ?[]const u8 = null;
    var sha256sums_signature: ?[]const u8 = null;
    var manifest: ?[]const u8 = null;
    var debz_cache: ?[]const u8 = null;
    var debz_input_dir: ?[]const u8 = null;
    var debz_lock_dir: ?[]const u8 = null;
    var authorized_key: ?[]const u8 = null;
    var uki_stub: ?[]const u8 = null;
    var signing_certificate: ?[]const u8 = null;
    var signing_certificate_sha256: ?[]const u8 = null;
    var signing_key: ?[]const u8 = null;
    var sign_command: ?[]const u8 = null;
    var sign_command_arg: ?[]const u8 = null;
    var zig: ?[]const u8 = null;
    var zig_global_cache: ?[]const u8 = null;
    var acceptance_command: ?[]const u8 = null;
    var keep_images = false;

    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        if (std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help")) {
            return error.HelpRequested;
        }
        if (std.mem.eql(u8, argument, "--keep-images")) {
            keep_images = true;
            continue;
        }
        if (optionValue(argv, &index, argument, "--output-root")) |value| {
            output_root = value;
        } else if (optionValue(argv, &index, argument, "--source")) |value| {
            source = value;
        } else if (optionValue(argv, &index, argument, "--sha256sums-signature")) |value| {
            sha256sums_signature = value;
        } else if (optionValue(argv, &index, argument, "--sha256sums")) |value| {
            sha256sums = value;
        } else if (optionValue(argv, &index, argument, "--manifest")) |value| {
            manifest = value;
        } else if (optionValue(argv, &index, argument, "--debz-cache")) |value| {
            debz_cache = value;
        } else if (optionValue(argv, &index, argument, "--debz-input-dir")) |value| {
            debz_input_dir = value;
        } else if (optionValue(argv, &index, argument, "--debz-lock-dir")) |value| {
            debz_lock_dir = value;
        } else if (optionValue(argv, &index, argument, "--authorized-key")) |value| {
            authorized_key = value;
        } else if (optionValue(argv, &index, argument, "--uki-stub")) |value| {
            uki_stub = value;
        } else if (optionValue(
            argv,
            &index,
            argument,
            "--signing-certificate-sha256",
        )) |value| {
            signing_certificate_sha256 = value;
        } else if (optionValue(argv, &index, argument, "--signing-certificate")) |value| {
            signing_certificate = value;
        } else if (optionValue(argv, &index, argument, "--signing-key")) |value| {
            signing_key = value;
        } else if (optionValue(argv, &index, argument, "--sign-command-arg")) |value| {
            sign_command_arg = value;
        } else if (optionValue(argv, &index, argument, "--sign-command")) |value| {
            sign_command = value;
        } else if (optionValue(argv, &index, argument, "--zig-global-cache")) |value| {
            zig_global_cache = value;
        } else if (optionValue(argv, &index, argument, "--zig")) |value| {
            zig = value;
        } else if (optionValue(argv, &index, argument, "--acceptance-command")) |value| {
            acceptance_command = value;
        } else return error.Usage;
    }

    const certificate_digest = signing_certificate_sha256 orelse return error.Usage;
    if (!contract.isSha256Hex(certificate_digest)) return error.Usage;
    if (signing_key == null and sign_command == null) return error.Usage;
    if (signing_key != null and sign_command != null) return error.Usage;
    if (sign_command_arg != null and sign_command == null) return error.Usage;
    if (sign_command) |command| {
        if (!std.fs.path.isAbsolute(command)) return error.Usage;
    }

    return .{
        .output_root = try absolutePathAlloc(allocator, io, output_root orelse
            return error.Usage),
        .source = try resolvePathAlloc(allocator, io, source orelse return error.Usage),
        .sha256sums = try resolvePathAlloc(allocator, io, sha256sums orelse
            return error.Usage),
        .sha256sums_signature = try resolvePathAlloc(
            allocator,
            io,
            sha256sums_signature orelse return error.Usage,
        ),
        .manifest = try resolvePathAlloc(allocator, io, manifest orelse
            return error.Usage),
        .debz_cache = try resolvePathAlloc(allocator, io, debz_cache orelse
            return error.Usage),
        .debz_input_dir = try resolvePathAlloc(allocator, io, debz_input_dir orelse
            return error.Usage),
        .debz_lock_dir = try resolvePathAlloc(allocator, io, debz_lock_dir orelse
            return error.Usage),
        .authorized_key = try resolvePathAlloc(allocator, io, authorized_key orelse
            return error.Usage),
        .uki_stub = try resolvePathAlloc(allocator, io, uki_stub orelse
            return error.Usage),
        .signing_certificate = try resolvePathAlloc(
            allocator,
            io,
            signing_certificate orelse return error.Usage,
        ),
        .signing_certificate_sha256 = certificate_digest,
        .signing_key = if (signing_key) |value|
            try resolvePathAlloc(allocator, io, value)
        else
            null,
        .sign_command = if (sign_command) |value|
            try resolvePathAlloc(allocator, io, value)
        else
            null,
        .sign_command_arg = sign_command_arg,
        .zig = try resolvePathAlloc(allocator, io, zig orelse return error.Usage),
        .zig_global_cache = try resolvePathAlloc(allocator, io, zig_global_cache orelse
            return error.Usage),
        .acceptance_command = if (acceptance_command) |value|
            try resolvePathAlloc(allocator, io, value)
        else
            null,
        .keep_images = keep_images,
    };
}

/// `os.path.abspath`: absolute and lexically normalized, without resolving a
/// symlink, because the output root is required not to exist yet.
fn absolutePathAlloc(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    if (std.fs.path.isAbsolute(path)) {
        return std.fs.path.resolve(allocator, &.{path});
    }
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const length = try Dir.cwd().realPathFile(io, ".", &buffer);
    return std.fs.path.resolve(allocator, &.{ buffer[0..length], path });
}

/// `benchmark_command`: the fixed production-builder invocation. The profile,
/// the raw output path, and `--offline` are not options here on purpose.
pub fn benchmarkCommand(
    allocator: Allocator,
    args: Arguments,
    work_dir: []const u8,
    provenance_dir: []const u8,
    image: []const u8,
    timing: []const u8,
) ![][]const u8 {
    const raw_output = try joinPath(
        allocator,
        &.{ std.fs.path.dirname(image) orelse ".", raw_asset_name },
    );
    const size = try std.fmt.allocPrint(allocator, "{d}", .{virtual_size});
    var command: std.ArrayList([]const u8) = .empty;
    try command.appendSlice(allocator, &.{
        args.zig,
        "build",
        "-Doptimize=ReleaseSafe",
        "-Dubuntu2604-arch=aarch64",
        "-Dubuntu2604-flavor=baremetal",
        "generalized-ubuntu2604",
        "--",
        "--work-dir",
        work_dir,
        "--provenance-dir",
        provenance_dir,
        "--output",
        image,
        "--raw-output",
        raw_output,
        "--source",
        args.source,
        "--size",
        size,
        "--authorized-key",
        args.authorized_key,
        "--uki-stub",
        args.uki_stub,
        "--uki-signing-certificate",
        args.signing_certificate,
        "--uki-signing-certificate-sha256",
        args.signing_certificate_sha256,
        "--debz-cache",
        args.debz_cache,
        "--debz-input-dir",
        args.debz_input_dir,
        "--debz-lock-dir",
        args.debz_lock_dir,
        "--timing-output",
        timing,
        "--offline",
    });
    if (args.signing_key) |key| {
        try command.appendSlice(allocator, &.{ "--uki-signing-key", key });
    } else {
        try command.appendSlice(
            allocator,
            &.{ "--uki-sign-command", args.sign_command.? },
        );
        if (args.sign_command_arg) |value| {
            try command.appendSlice(allocator, &.{ "--uki-sign-command-arg", value });
        }
    }
    return command.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------- the run

const PreflightResult = struct {
    cache_inventory: CacheInventory,
    lock_set: LockSet,
    environ: std.process.Environ.Map,
    source_commit: []const u8,
    host: Value,
};

fn isExecutable(io: Io, path: []const u8) bool {
    Dir.cwd().access(io, path, .{ .execute = true }) catch return false;
    return true;
}

/// `preflight`: everything that must be true before the first measured
/// nanosecond, in the order the Python checked it.
fn preflight(
    allocator: Allocator,
    io: Io,
    base_environ: std.process.Environ,
    args: Arguments,
    repo: []const u8,
    session: []const u8,
    context: *Context,
) !PreflightResult {
    const uts = std.posix.uname();
    const host = hostIdentity(&uts);
    if (!std.mem.eql(u8, host.system, "Linux") or
        (!std.mem.eql(u8, host.machine, "aarch64") and
            !std.mem.eql(u8, host.machine, "arm64")))
    {
        return context.fail(
            "the production benchmark requires a native aarch64 Linux host",
            .{},
        );
    }
    if (std.os.linux.geteuid() != 0) {
        return context.fail(
            "run the production benchmark as root for offline-root customization",
            .{},
        );
    }
    if (try freeDiskBytes(allocator, session) < minimum_free_disk) {
        return context.fail(
            "the benchmark output filesystem has less than 30 GiB free",
            .{},
        );
    }

    var inputs = ObjectMap.empty;
    const bindings = [_]struct {
        key: []const u8,
        path: []const u8,
        label: []const u8,
        expected: ?[]const u8,
    }{
        .{
            .key = "source",
            .path = args.source,
            .label = "source image",
            .expected = source_sha256,
        },
        .{
            .key = "sha256sums",
            .path = args.sha256sums,
            .label = "SHA256SUMS",
            .expected = sums_sha256,
        },
        .{
            .key = "sha256sums_signature",
            .path = args.sha256sums_signature,
            .label = "SHA256SUMS signature",
            .expected = sums_signature_sha256,
        },
        .{
            .key = "manifest",
            .path = args.manifest,
            .label = "source manifest",
            .expected = manifest_sha256,
        },
        .{
            .key = "authorized_key",
            .path = args.authorized_key,
            .label = "authorized key",
            .expected = null,
        },
        .{
            .key = "uki_stub",
            .path = args.uki_stub,
            .label = "aarch64 UKI stub",
            .expected = null,
        },
        .{
            .key = "signing_certificate",
            .path = args.signing_certificate,
            .label = "signing certificate",
            .expected = null,
        },
        .{ .key = "zig", .path = args.zig, .label = "Zig executable", .expected = null },
    };
    for (bindings) |binding| {
        const record = try regularFile(
            allocator,
            io,
            binding.path,
            binding.label,
            binding.expected,
            context,
        );
        try inputs.put(allocator, binding.key, try record.toJson(allocator));
    }
    if (!isDirectoryNoFollow(io, args.debz_input_dir)) {
        return context.fail(
            "debz input directory must be a non-symlink directory",
            .{},
        );
    }
    try inputs.put(allocator, "debz_repository_inputs", try object(allocator, &.{
        .{ "path", str(try resolvePathAlloc(allocator, io, args.debz_input_dir)) },
        .{ "cache_identity", str("stable-signed-by-path") },
    }));
    if (!isExecutable(io, args.zig)) {
        return context.fail("Zig path is not executable", .{});
    }
    if (args.signing_key) |key| {
        _ = try regularFile(allocator, io, key, "signing key", null, context);
        try inputs.put(allocator, "signing", try object(allocator, &.{
            .{ "mode", str("local-key") },
            .{ "private_key_recorded", .{ .bool = false } },
        }));
    } else {
        const record = try regularFile(
            allocator,
            io,
            args.sign_command.?,
            "sign command",
            null,
            context,
        );
        try inputs.put(allocator, "sign_command", try record.toJson(allocator));
        if (!isExecutable(io, args.sign_command.?)) {
            return context.fail("sign command is not executable", .{});
        }
    }
    if (args.acceptance_command) |command| {
        const record = try regularFile(
            allocator,
            io,
            command,
            "acceptance command",
            null,
            context,
        );
        try inputs.put(allocator, "acceptance_command", try record.toJson(allocator));
        if (!isExecutable(io, command)) {
            return context.fail("acceptance command is not executable", .{});
        }
    }

    const cache_inventory = try verifyBenchmarkCache(
        allocator,
        io,
        args.debz_cache,
        args.debz_input_dir,
        context,
    );
    const lock_set = try verifyLockSet(
        allocator,
        io,
        args.debz_lock_dir,
        &cache_inventory,
        context,
    );

    const version = try std.process.run(allocator, io, .{
        .argv = &.{ args.zig, "version" },
        .stdout_limit = .limited(4096),
        .stderr_limit = .limited(4096),
    });
    const version_text = std.mem.trim(u8, version.stdout, " \t\r\n");
    if (exitCodeOf(version.term) != 0 or !std.mem.eql(u8, version_text, "0.16.0")) {
        return context.fail("benchmark requires Zig 0.16.0", .{});
    }

    const host_document = try hostDocument(
        allocator,
        &uts,
        version_text,
        @intCast(std.Thread.getCpuCount() catch 0),
    );

    const source_commit = try gitOutput(
        allocator,
        io,
        repo,
        &.{ "rev-parse", "HEAD" },
        context,
    );
    const status = try gitOutput(
        allocator,
        io,
        repo,
        &.{ "status", "--porcelain", "--untracked-files=no" },
        context,
    );
    if (status.len != 0) {
        return context.fail(
            "benchmark source worktree has tracked modifications",
            .{},
        );
    }

    if (statNoFollow(io, args.zig_global_cache)) |stat| {
        if (stat.kind != .directory) return context.fail(
            "Zig global cache must be a non-symlink directory",
            .{},
        );
    } else |_| {}
    try Dir.cwd().createDirPath(io, args.zig_global_cache);

    var environ = try base_environ.createMap(allocator);
    try environ.put(
        "ZIG_GLOBAL_CACHE_DIR",
        try resolvePathAlloc(allocator, io, args.zig_global_cache),
    );
    const local_cache = try joinPath(allocator, &.{ session, "zig-local-cache" });
    try environ.put(
        "ZIG_LOCAL_CACHE_DIR",
        try resolvePathAlloc(allocator, io, local_cache),
    );

    const compile_log = try joinPath(allocator, &.{ session, "preflight-build.log" });
    try runLogged(io, &.{
        args.zig,
        "build",
        "-Doptimize=ReleaseSafe",
        "-Dubuntu2604-arch=aarch64",
        "-Dubuntu2604-flavor=baremetal",
        "install-miz",
        "check-generalized-ubuntu2604",
    }, repo, &environ, compile_log, context);

    const miz = try joinPath(allocator, &.{ repo, "zig-out", "bin", "miz" });
    _ = try regularFile(allocator, io, miz, "miz validator", null, context);

    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ session, "inputs.json" }),
        .{ .object = inputs },
    );
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ session, "cache-inventory.json" }),
        cache_inventory.public,
    );
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ session, "package-lock-set.json" }),
        lock_set.document,
    );
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ session, "host.json" }),
        host_document,
    );

    return .{
        .cache_inventory = cache_inventory,
        .lock_set = lock_set,
        .environ = environ,
        .source_commit = source_commit,
        .host = host_document,
    };
}

/// `run_acceptance`: the optional host-specific bare-metal boot harness, which
/// this repository does not currently supply.
fn runAcceptance(
    allocator: Allocator,
    io: Io,
    command: ?[]const u8,
    image: []const u8,
    cwd: []const u8,
    environ: *const std.process.Environ.Map,
    log_path: []const u8,
    context: *Context,
) !Value {
    const present = command orelse return object(allocator, &.{
        .{ "status", str("not-available") },
        .{
            "reason",
            str("repository-has-no-baremetal-boot-acceptance-harness"),
        },
    });
    var acceptance_environ = try environ.clone(allocator);
    defer acceptance_environ.deinit();
    try acceptance_environ.put("MIZ_UBUNTU2604_IMAGE", image);
    try acceptance_environ.put("MIZ_UBUNTU2604_ARCHITECTURE", architecture);
    try acceptance_environ.put("MIZ_UBUNTU2604_FLAVOR", flavor);
    try runLogged(io, &.{present}, cwd, &acceptance_environ, log_path, context);
    return object(allocator, &.{
        .{ "status", str("success") },
        .{ "command", str(present) },
    });
}

fn runInfo(
    allocator: Allocator,
    io: Io,
    miz: []const u8,
    target: []const u8,
    repo: []const u8,
    environ: *const std.process.Environ.Map,
    output_path: []const u8,
    label: []const u8,
    context: *Context,
) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = &.{ miz, "info", "--output=json", target },
        .cwd = .{ .path = repo },
        .environ_map = environ,
        .stdout_limit = .limited(max_info_bytes),
        .stderr_limit = .limited(1024 * 1024),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    if (exitCodeOf(result.term) != 0) {
        return context.fail("{s} failed: {s}", .{ label, result.stderr });
    }
    try file_support.writeAtomic(io, output_path, result.stdout);
}

const RunOutcome = struct {
    record: RunRecord,
    correctness: Value,
};

/// `run_once`: one complete measured or warm-up build, from a fresh work and
/// output directory through validation, evidence, comparison, and cleanup.
fn runOnce(
    allocator: Allocator,
    io: Io,
    args: Arguments,
    repo: []const u8,
    session: []const u8,
    environ: *const std.process.Environ.Map,
    cache_inventory: *const CacheInventory,
    lock_set: *const LockSet,
    name: []const u8,
    kind: []const u8,
    reference: ?Value,
    context: *Context,
) !RunOutcome {
    const run_dir = try joinPath(allocator, &.{ session, name });
    try Dir.cwd().createDir(io, run_dir, .default_dir);
    const work_dir = try joinPath(allocator, &.{ run_dir, "work" });
    const artifact_dir = try joinPath(allocator, &.{ run_dir, "artifact" });
    const evidence_dir = try joinPath(allocator, &.{ run_dir, "evidence" });
    const provenance_dir = try joinPath(allocator, &.{ evidence_dir, "provenance" });
    try Dir.cwd().createDir(io, work_dir, .default_dir);
    try Dir.cwd().createDir(io, artifact_dir, .default_dir);
    try Dir.cwd().createDir(io, evidence_dir, .default_dir);
    try Dir.cwd().createDir(io, provenance_dir, .default_dir);

    try Dir.cwd().copyFile(
        args.sha256sums,
        Dir.cwd(),
        try joinPath(allocator, &.{ work_dir, "SHA256SUMS" }),
        io,
        .{},
    );
    try Dir.cwd().copyFile(
        args.sha256sums_signature,
        Dir.cwd(),
        try joinPath(allocator, &.{ work_dir, "SHA256SUMS.gpg" }),
        io,
        .{},
    );
    try Dir.cwd().copyFile(
        args.manifest,
        Dir.cwd(),
        try joinPath(allocator, &.{ work_dir, manifest_name }),
        io,
        .{},
    );

    const image = try joinPath(allocator, &.{ artifact_dir, asset_name });
    const raw_output = try joinPath(allocator, &.{ artifact_dir, raw_asset_name });
    const timing_path = try joinPath(allocator, &.{ evidence_dir, "timing.json" });
    const resources_path = try joinPath(allocator, &.{ evidence_dir, "resources.json" });
    const build_log = try joinPath(allocator, &.{ evidence_dir, "build.log" });

    const command = try benchmarkCommand(
        allocator,
        args,
        work_dir,
        provenance_dir,
        image,
        timing_path,
    );
    const resources = try runMeasuredCommand(
        io,
        command,
        repo,
        environ,
        build_log,
    );
    try writeJson(allocator, io, resources_path, try resources.toJson(allocator));
    if (!std.mem.eql(u8, resources.status, "success")) {
        return context.fail("{s} build failed; benchmark is invalid", .{name});
    }

    const cache_after = try verifyBenchmarkCache(
        allocator,
        io,
        args.debz_cache,
        args.debz_input_dir,
        context,
    );
    // A cache-only refresh may republish validated manifests with a new
    // verified-at timestamp; the content-addressed objects must not change.
    if (!std.mem.eql(
        u8,
        cache_after.object_inventory_sha256,
        cache_inventory.object_inventory_sha256,
    )) {
        return context.fail(
            "{s} changed the verified content-addressed cache objects",
            .{name},
        );
    }

    const timing = try loadTiming(allocator, io, timing_path, context);
    const image_stat = statNoFollow(io, image) catch |err| switch (err) {
        error.FileNotFound => return context.fail(
            "{s} did not produce the expected image",
            .{name},
        ),
        else => return err,
    };
    if (image_stat.kind != .file or image_stat.size == 0) {
        return context.fail("{s} did not produce the expected image", .{name});
    }
    _ = try validateRawFile(io, raw_output, context);

    const miz = try joinPath(allocator, &.{ repo, "zig-out", "bin", "miz" });
    try runLogged(
        io,
        &.{ miz, "check", image },
        repo,
        environ,
        try joinPath(allocator, &.{ evidence_dir, "miz-check.log" }),
        context,
    );
    const image_info_path = try joinPath(allocator, &.{ evidence_dir, "image-info.json" });
    try runInfo(
        allocator,
        io,
        miz,
        image,
        repo,
        environ,
        image_info_path,
        try std.fmt.allocPrint(allocator, "{s} miz info", .{name}),
        context,
    );
    const image_contract = try validateImageInfo(allocator, io, image_info_path, context);

    try runLogged(
        io,
        &.{ miz, "check", raw_output },
        repo,
        environ,
        try joinPath(allocator, &.{ evidence_dir, "raw-miz-check.log" }),
        context,
    );
    const raw_info_path = try joinPath(
        allocator,
        &.{ evidence_dir, "raw-image-info.json" },
    );
    try runInfo(
        allocator,
        io,
        miz,
        raw_output,
        repo,
        environ,
        raw_info_path,
        try std.fmt.allocPrint(allocator, "{s} raw miz info", .{name}),
        context,
    );
    var raw_output_record = try validateRawOutput(
        allocator,
        io,
        raw_output,
        raw_info_path,
        context,
    );
    raw_output_record.retention_policy = if (args.keep_images)
        "keep"
    else
        "delete-after-validation";

    const provenance = try validateProvenance(
        allocator,
        io,
        provenance_dir,
        lock_set,
        args.signing_certificate_sha256,
        context,
    );
    const acceptance = try runAcceptance(
        allocator,
        io,
        args.acceptance_command,
        image,
        repo,
        environ,
        try joinPath(allocator, &.{ evidence_dir, "acceptance.log" }),
        context,
    );

    const correctness = try object(allocator, &.{
        .{ "profile", try object(allocator, &.{
            .{ "architecture", str(architecture) },
            .{ "flavor", str(flavor) },
            .{ "optimization", str(optimize_mode) },
            .{ "source_sha256", str(source_sha256) },
        }) },
        .{ "image", image_contract },
        .{ "raw_output", try object(allocator, &.{
            .{ "format", str("raw") },
            .{ "virtual_size", int(virtual_size) },
            .{ "structural_validation", str("miz-check-and-info") },
        }) },
        .{ "provenance", provenance.contract },
        .{ "package_closure_sha256", str(lock_set.closure_sha256) },
        .{ "acceptance", acceptance },
    });
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ evidence_dir, "package-closure.json" }),
        lock_set.final_closure,
    );
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ evidence_dir, "correctness.json" }),
        correctness,
    );
    if (reference) |expected| {
        try compareCorrectness(allocator, expected, correctness, context);
    }

    const image_digest = try allocator.dupe(u8, &try hashFileHex(io, image));
    const image_size: i64 = @intCast(image_stat.size);
    const correctness_sha256 = try canonicalDigestAlloc(allocator, correctness);
    var command_json = JsonArray.init(allocator);
    for (command) |argument| try command_json.append(str(argument));
    const evidence_manifest = try object(allocator, &.{
        .{ "schema", int(schema) },
        .{ "type", str("miz-ubuntu2604-image-benchmark-run") },
        .{ "name", str(name) },
        .{ "kind", str(kind) },
        .{ "command", .{ .array = command_json } },
        .{ "image", try object(allocator, &.{
            .{ "filename", str(asset_name) },
            .{ "bytes", int(image_size) },
            .{ "sha256", str(image_digest) },
            .{ "byte_reproducibility_compared", .{ .bool = false } },
        }) },
        .{ "raw_output", try raw_output_record.toJson(allocator) },
        .{ "transaction_provenance_files", provenance.transaction_files },
        .{ "correctness_sha256", str(correctness_sha256) },
        .{ "cache_inventory_sha256", str(cache_inventory.inventory_sha256) },
    });
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ evidence_dir, "run-manifest.json" }),
        evidence_manifest,
    );

    const removed = try cleanupRun(
        allocator,
        io,
        run_dir,
        image,
        raw_output,
        work_dir,
        args.keep_images,
        context,
    );
    return .{
        .record = .{
            .name = name,
            .kind = kind,
            .timing_values = timing.values,
            .resources = resources,
            .correctness_sha256 = correctness_sha256,
            .image_sha256 = image_digest,
            .image_bytes = image_size,
            .raw_output = raw_output_record,
            .evidence = try std.fmt.allocPrint(allocator, "{s}/evidence", .{name}),
            .cleanup = removed,
        },
        .correctness = correctness,
    };
}

/// The checkout being measured. The Python derived it from the script's own
/// location; the built binary uses its own location the same way, and falls
/// back to the working directory the operator started it in.
fn repositoryRootAlloc(allocator: Allocator, io: Io, context: *Context) ![]u8 {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    if (Dir.cwd().readLink(io, "/proc/self/exe", &buffer)) |length| {
        if (try ascendToRepository(allocator, io, buffer[0..length])) |root| return root;
    } else |_| {}
    const length = try Dir.cwd().realPathFile(io, ".", &buffer);
    if (try ascendToRepository(allocator, io, buffer[0..length])) |root| return root;
    return context.fail("cannot locate the benchmark source repository", .{});
}

fn ascendToRepository(allocator: Allocator, io: Io, start: []const u8) !?[]u8 {
    var candidate: []const u8 = start;
    while (true) {
        const build_file = try joinPath(allocator, &.{ candidate, "build.zig" });
        const manifest_file = try joinPath(allocator, &.{ candidate, "build.zig.zon" });
        const has_build = Dir.cwd().statFile(io, build_file, .{}) catch null;
        const has_manifest = Dir.cwd().statFile(io, manifest_file, .{}) catch null;
        if (has_build != null and has_manifest != null) {
            return try allocator.dupe(u8, candidate);
        }
        candidate = std.fs.path.dirname(candidate) orelse return null;
        if (candidate.len == 0) return null;
    }
}

/// `run_benchmark`: one warm-up plus three measured runs, a summary, and a
/// status document that is written whether or not the benchmark stayed valid.
pub fn runBenchmark(
    allocator: Allocator,
    io: Io,
    base_environ: std.process.Environ,
    args: Arguments,
    context: *Context,
) ![]const u8 {
    const repo = try repositoryRootAlloc(allocator, io, context);
    const session = try prepareSessionDir(allocator, io, args.output_root, context);
    const status_path = try joinPath(allocator, &.{ session, "benchmark-status.json" });
    runSession(allocator, io, base_environ, args, repo, session, context) catch |err| {
        context.adopt(err);
        const status = object(allocator, &.{
            .{ "schema", int(schema) },
            .{ "type", str("miz-ubuntu2604-image-benchmark-status") },
            .{ "status", str("invalid") },
            .{ "error", str(context.message()) },
        }) catch return err;
        writeJson(allocator, io, status_path, status) catch {};
        return err;
    };
    try writeJson(allocator, io, status_path, try object(allocator, &.{
        .{ "schema", int(schema) },
        .{ "type", str("miz-ubuntu2604-image-benchmark-status") },
        .{ "status", str("valid") },
    }));
    return session;
}

fn runSession(
    allocator: Allocator,
    io: Io,
    base_environ: std.process.Environ,
    args: Arguments,
    repo: []const u8,
    session: []const u8,
    context: *Context,
) !void {
    var prepared = try preflight(
        allocator,
        io,
        base_environ,
        args,
        repo,
        session,
        context,
    );
    var runs: std.ArrayList(RunRecord) = .empty;
    defer runs.deinit(allocator);
    var reference: ?Value = null;
    for (0..measured_runs + 1) |index| {
        const name = if (index == 0)
            try allocator.dupe(u8, "run-warmup")
        else
            try std.fmt.allocPrint(allocator, "run-measured-{d:0>2}", .{index});
        const kind: []const u8 = if (index == 0) "warmup" else "measured";
        const outcome = try runOnce(
            allocator,
            io,
            args,
            repo,
            session,
            &prepared.environ,
            &prepared.cache_inventory,
            &prepared.lock_set,
            name,
            kind,
            reference,
            context,
        );
        if (reference == null) reference = outcome.correctness;
        try runs.append(allocator, outcome.record);
    }
    const summary = try buildSummary(
        allocator,
        runs.items,
        prepared.source_commit,
        prepared.host,
        prepared.cache_inventory.public,
        prepared.lock_set.closure_sha256,
        prepared.lock_set.locks_json,
        context,
    );
    try writeJson(
        allocator,
        io,
        try joinPath(allocator, &.{ session, "benchmark-summary.json" }),
        summary,
    );
    const readable = try readableSummary(allocator, summary);
    try file_support.writeAtomic(
        io,
        try joinPath(allocator, &.{ session, "benchmark-summary.txt" }),
        readable,
    );
}

// ----------------------------------------------------- workflow subcommands

/// The staging check the benchmark workflow runs before the measured protocol:
/// the cache and locks it just produced are exactly what the offline runs need.
pub fn verifyStaging(
    allocator: Allocator,
    io: Io,
    input_root: []const u8,
    context: *Context,
) !void {
    const cache = try joinPath(allocator, &.{ input_root, "debz-cache" });
    const inputs = try joinPath(allocator, &.{ input_root, "debz-inputs" });
    const locks = try joinPath(allocator, &.{ input_root, "locks" });
    const inventory = try verifyBenchmarkCache(allocator, io, cache, inputs, context);
    const lock_set = try verifyLockSet(allocator, io, locks, &inventory, context);
    if (lock_set.locks.len != package_roots.len) {
        return context.fail(
            "staging did not produce the exact benchmark lock set",
            .{},
        );
    }
}

pub const GateOptions = struct {
    summary: []const u8,
    status: []const u8,
    output: []const u8,
    step_summary: []const u8,
    ceiling_ns: i64,
};

fn isRegularFile(io: Io, path: []const u8) bool {
    const stat = Dir.cwd().statFile(io, path, .{}) catch return false;
    return stat.kind == .file;
}

fn appendFile(io: Io, path: []const u8, data: []const u8) !void {
    const existing = Dir.cwd().statFile(io, path, .{}) catch null;
    const file = if (existing != null)
        try Dir.cwd().openFile(io, path, .{ .mode = .write_only })
    else
        try Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, data, if (existing) |stat| stat.size else 0);
}

/// The production non-regression gate: the summary's median total runtime
/// against the published ceiling, recorded as evidence and as a job summary.
/// Returns whether the gate passed.
pub fn runGate(
    allocator: Allocator,
    io: Io,
    options: GateOptions,
    context: *Context,
) !bool {
    var gate = ObjectMap.empty;
    try gate.put(allocator, "schema", int(schema));
    try gate.put(allocator, "type", str("miz-ubuntu2604-production-benchmark-gate"));
    try gate.put(allocator, "ceiling_ns", int(options.ceiling_ns));
    try gate.put(allocator, "status", str("invalid"));

    var lines: std.ArrayList(u8) = .empty;
    defer lines.deinit(allocator);
    try lines.appendSlice(allocator, "## Ubuntu 26.04 production image benchmark\n\n");

    var passed = false;
    if (isRegularFile(io, options.summary)) {
        const summary = try readJson(allocator, io, options.summary, context);
        const total = medianInteger(summary, "phase_elapsed_ns", "total_runtime") orelse
            return context.fail(
                "benchmark summary has no median total_runtime: {s}",
                .{options.summary},
            );
        const raw = medianInteger(
            summary,
            "phase_elapsed_ns",
            "raw_image_materialization",
        ) orelse return context.fail(
            "benchmark summary has no median raw_image_materialization: {s}",
            .{options.summary},
        );
        passed = total <= options.ceiling_ns;
        try gate.put(
            allocator,
            "benchmark_status",
            getField(summary, "status") orelse Value.null,
        );
        try gate.put(
            allocator,
            "source_commit",
            getField(summary, "source_commit") orelse Value.null,
        );
        try gate.put(allocator, "median_total_ns", int(total));
        try gate.put(allocator, "median_raw_image_materialization_ns", int(raw));
        try gate.put(allocator, "status", str(if (passed) "pass" else "fail"));
        const rendered = try std.fmt.allocPrint(allocator,
            \\- Source: `{s}`
            \\- Protocol: one warm-up plus three measured offline runs
            \\- Median total: `{s}`
            \\- Median raw materialization: `{s}`
            \\- Ceiling: `{s}`
            \\- Gate: **{s}**
            \\- Boot acceptance: unavailable for the bare-metal flavor; the benchmark ran native image/filesystem/provenance validation
            \\
        , .{
            stringField(summary, "source_commit") orelse "",
            try formatSeconds(allocator, total),
            try formatSeconds(allocator, raw),
            try formatSeconds(allocator, options.ceiling_ns),
            if (passed) "pass" else "fail",
        });
        try lines.appendSlice(allocator, rendered);
    } else {
        const status = if (isRegularFile(io, options.status))
            try readJson(allocator, io, options.status, context)
        else
            try object(allocator, &.{.{ "status", str("missing") }});
        try gate.put(allocator, "benchmark_status", status);
        const rendered = try std.fmt.allocPrint(
            allocator,
            "- Benchmark did not complete: `{s}`\n",
            .{try jsonText(allocator, status)},
        );
        try lines.appendSlice(allocator, rendered);
    }

    try writeJson(allocator, io, options.output, .{ .object = gate });
    try appendFile(io, options.step_summary, lines.items);
    return passed;
}

const private_material_markers = [_][]const u8{
    "-----BEGIN PRIVATE KEY-----",
    "-----BEGIN RSA PRIVATE KEY-----",
    "-----BEGIN OPENSSH PRIVATE KEY-----",
};

const uploaded_session_files = [_][]const u8{
    "benchmark-status.json",
    "benchmark-summary.json",
    "benchmark-summary.txt",
    "inputs.json",
    "cache-inventory.json",
    "package-lock-set.json",
    "host.json",
    "preflight-build.log",
};

fn scanCandidate(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    context: *Context,
) !void {
    if (!isRegularFile(io, path)) return;
    // A candidate that cannot be opened fails the scan. This gate decides
    // whether the artifact is uploaded at all, so a file it could not read is
    // a file it cannot vouch for.
    const file = Dir.cwd().openFile(io, path, .{}) catch |err| return context.fail(
        "cannot scan benchmark evidence {s}: {s}",
        .{ path, @errorName(err) },
    );
    defer file.close(io);
    const prefix = try allocator.alloc(u8, private_material_prefix_bytes);
    defer allocator.free(prefix);
    const length = try file.readPositionalAll(io, prefix, 0);
    for (private_material_markers) |marker| {
        if (std.mem.indexOf(u8, prefix[0..length], marker) != null) {
            return context.fail("private material found in evidence: {s}", .{path});
        }
    }
}

fn scanTree(allocator: Allocator, io: Io, root: []const u8, context: *Context) !void {
    var directory = Dir.cwd().openDir(io, root, .{ .iterate = true }) catch return;
    defer directory.close(io);
    var entries = directory.iterate();
    while (try entries.next(io)) |entry| {
        const path = try joinPath(allocator, &.{ root, entry.name });
        switch (entry.kind) {
            .directory => try scanTree(allocator, io, path, context),
            else => try scanCandidate(allocator, io, path, context),
        }
    }
}

/// Proves the upload set carries no private key material. A benchmark that
/// cannot prove that is not uploaded at all.
pub fn scanPrivateMaterial(
    allocator: Allocator,
    io: Io,
    evidence_root: []const u8,
    benchmark_root: []const u8,
    context: *Context,
) !void {
    try scanTree(allocator, io, evidence_root, context);
    for (uploaded_session_files) |name| {
        try scanCandidate(
            allocator,
            io,
            try joinPath(allocator, &.{ benchmark_root, name }),
            context,
        );
    }
    var directory = Dir.cwd().openDir(io, benchmark_root, .{ .iterate = true }) catch return;
    defer directory.close(io);
    var entries = directory.iterate();
    while (try entries.next(io)) |entry| {
        if (!std.mem.startsWith(u8, entry.name, "run-")) continue;
        const evidence = try joinPath(
            allocator,
            &.{ benchmark_root, entry.name, "evidence" },
        );
        try scanTree(allocator, io, evidence, context);
    }
}

// ------------------------------------------------------------ command line

const usage_text =
    \\usage: ubuntu2604-image-benchmark <command> [options]
    \\
    \\Repeatable host benchmark for the pinned Ubuntu 26.04 arm64 bare-metal image.
    \\
    \\commands:
    \\  run                     run one warm-up and three measured offline builds
    \\  verify-staging          check a staged warm cache and exact lock set
    \\  gate                    record and enforce the non-regression ceiling
    \\  scan-private-material   reject private key material in upload evidence
    \\
    \\run options:
    \\  --output-root DIR --source FILE --sha256sums FILE
    \\  --sha256sums-signature FILE --manifest FILE --debz-cache DIR
    \\  --debz-input-dir DIR --debz-lock-dir DIR --authorized-key FILE
    \\  --uki-stub FILE --signing-certificate FILE
    \\  --signing-certificate-sha256 SHA256
    \\  (--signing-key FILE | --sign-command ABSOLUTE [--sign-command-arg ARG])
    \\  --zig FILE --zig-global-cache DIR [--acceptance-command FILE]
    \\  [--keep-images]
    \\
    \\verify-staging options:
    \\  --input-root DIR
    \\
    \\gate options:
    \\  --summary FILE --status FILE --output FILE --step-summary FILE
    \\  --ceiling-ns NANOSECONDS
    \\
    \\scan-private-material options:
    \\  --evidence-root DIR --benchmark-root DIR
    \\
;

const usage_exit_code = 2;
const failure_exit_code = 1;

pub fn main(init: std.process.Init) !void {
    var arena_state: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const io = init.io;
    const argv = try init.minimal.args.toSlice(init.arena.allocator());

    var stdout_buffer: [4096]u8 = undefined;
    var stdout_writer: File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: File.Writer = .init(.stderr(), io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    for (argv[1..]) |argument| {
        if (std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help")) {
            try out.writeAll(usage_text);
            try out.flush();
            return;
        }
    }
    if (argv.len < 2) {
        try err_out.writeAll(usage_text);
        try err_out.flush();
        std.process.exit(usage_exit_code);
    }

    var context: Context = .init(arena);
    const command = argv[1];
    const rest = argv[2..];

    if (std.mem.eql(u8, command, "run")) {
        const args = parseArgs(arena, io, rest) catch |err| switch (err) {
            error.HelpRequested => {
                try out.writeAll(usage_text);
                try out.flush();
                return;
            },
            error.Usage => {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            },
            else => return err,
        };
        const session = runBenchmark(
            arena,
            io,
            init.minimal.environ,
            args,
            &context,
        ) catch |err| {
            context.adopt(err);
            try err_out.print("benchmark invalid: {s}\n", .{context.message()});
            try err_out.flush();
            std.process.exit(failure_exit_code);
        };
        try out.print("benchmark complete: {s}/benchmark-summary.json\n", .{session});
        try out.flush();
        return;
    }

    if (std.mem.eql(u8, command, "verify-staging")) {
        var input_root: ?[]const u8 = null;
        var index: usize = 0;
        while (index < rest.len) : (index += 1) {
            if (optionValue(rest, &index, rest[index], "--input-root")) |value| {
                input_root = value;
            } else {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            }
        }
        const root = input_root orelse {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        };
        verifyStaging(arena, io, root, &context) catch |err| {
            context.adopt(err);
            try err_out.print("benchmark invalid: {s}\n", .{context.message()});
            try err_out.flush();
            std.process.exit(failure_exit_code);
        };
        try out.print("staging verified: {s}\n", .{root});
        try out.flush();
        return;
    }

    if (std.mem.eql(u8, command, "gate")) {
        var summary: ?[]const u8 = null;
        var status: ?[]const u8 = null;
        var output: ?[]const u8 = null;
        var step_summary: ?[]const u8 = null;
        var ceiling: ?[]const u8 = null;
        var index: usize = 0;
        while (index < rest.len) : (index += 1) {
            const argument = rest[index];
            if (optionValue(rest, &index, argument, "--summary")) |value| {
                summary = value;
            } else if (optionValue(rest, &index, argument, "--status")) |value| {
                status = value;
            } else if (optionValue(rest, &index, argument, "--step-summary")) |value| {
                step_summary = value;
            } else if (optionValue(rest, &index, argument, "--output")) |value| {
                output = value;
            } else if (optionValue(rest, &index, argument, "--ceiling-ns")) |value| {
                ceiling = value;
            } else {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            }
        }
        const ceiling_ns = std.fmt.parseInt(
            i64,
            ceiling orelse "",
            10,
        ) catch {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        };
        const options: GateOptions = .{
            .summary = summary orelse {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            },
            .status = status orelse {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            },
            .output = output orelse {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            },
            .step_summary = step_summary orelse {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            },
            .ceiling_ns = ceiling_ns,
        };
        const passed = runGate(arena, io, options, &context) catch |err| {
            context.adopt(err);
            try err_out.print("benchmark invalid: {s}\n", .{context.message()});
            try err_out.flush();
            std.process.exit(failure_exit_code);
        };
        if (!passed) {
            try err_out.writeAll("production image benchmark did not pass\n");
            try err_out.flush();
            std.process.exit(failure_exit_code);
        }
        try out.writeAll("production image benchmark passed\n");
        try out.flush();
        return;
    }

    if (std.mem.eql(u8, command, "scan-private-material")) {
        var evidence_root: ?[]const u8 = null;
        var benchmark_root: ?[]const u8 = null;
        var index: usize = 0;
        while (index < rest.len) : (index += 1) {
            const argument = rest[index];
            if (optionValue(rest, &index, argument, "--evidence-root")) |value| {
                evidence_root = value;
            } else if (optionValue(rest, &index, argument, "--benchmark-root")) |value| {
                benchmark_root = value;
            } else {
                try err_out.writeAll(usage_text);
                try err_out.flush();
                std.process.exit(usage_exit_code);
            }
        }
        if (evidence_root == null or benchmark_root == null) {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        }
        scanPrivateMaterial(
            arena,
            io,
            evidence_root.?,
            benchmark_root.?,
            &context,
        ) catch |err| {
            context.adopt(err);
            try err_out.print("{s}\n", .{context.message()});
            try err_out.flush();
            std.process.exit(failure_exit_code);
        };
        try out.writeAll("no private material found in benchmark evidence\n");
        try out.flush();
        return;
    }

    try err_out.writeAll(usage_text);
    try err_out.flush();
    std.process.exit(usage_exit_code);
}
