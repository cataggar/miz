//! Publication contracts for the Azure Linux 4 release.
//!
//! Native replacement for every inline Python block in
//! `scripts/azurelinux4_publish.sh`. The publisher's job is to move four
//! exact files onto a GitHub release and prove, from the API's own answers,
//! that the release holds exactly those four and nothing else. Every block it
//! used to shell out to was one step of that proof.
//!
//! The expected-asset table is the pivot: `stage` writes the publish manifest,
//! this module renders it into the tab-separated table the shell loops over,
//! and every later check is against that same table. Rendering and checking
//! therefore live together, so the table cannot drift from its readers.

const std = @import("std");

const contracts = @import("contracts.zig");
const release = @import("../release/root.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const ObjectMap = contracts.ObjectMap;
const Value = contracts.Value;
const Writer = std.Io.Writer;
const contract = release.contract;
const digest_support = release.digest;
const file_support = release.file;

pub const Diagnostic = contract.Diagnostic;

/// Upper bound on the expected-asset table. Four rows of a name, a digest, and
/// a size.
pub const max_expected_bytes: u64 = 64 * 1024;

/// Upper bound on a published release asset that is downloaded back and
/// re-hashed.
pub const max_asset_bytes: u64 = 64 * 1024 * 1024 * 1024;

pub const PublishError = contracts.Error || error{
    InvalidManifest,
    DuplicateTagRefs,
    InvalidTagObject,
    InvalidExpectedTable,
    ReleaseAllowlistMismatch,
    ReleaseNotDraft,
    DownloadMismatch,
    CannotRead,
    NotAnObject,
    Io,
};

/// One published asset: the exact name, digest, and size the release must end
/// up holding.
pub const Expected = struct {
    name: []const u8,
    sha256: []const u8,
    bytes: u64,
};

// ---------------------------------------------------------------------------
// Expected-asset table
// ---------------------------------------------------------------------------

/// Renders `publish-manifest.json` into the tab-separated table the publisher
/// shell reads. Each field is re-validated on the way out, so a manifest that
/// lost its shape cannot become a table the shell then trusts.
pub fn writeExpected(
    manifest: *const ObjectMap,
    out: *Writer,
    diagnostic: *Diagnostic,
) PublishError!void {
    const assets = contracts.arrayOrNull(manifest.get("assets")) orelse
        return diagnostic.fail(
            error.InvalidManifest,
            "publish manifest has no asset list",
            .{},
        );
    if (assets.len != contracts.release_order.len) return diagnostic.fail(
        error.InvalidManifest,
        "publish manifest does not name exactly four assets",
        .{},
    );
    for (assets) |asset| {
        const fields = contracts.objectOrNull(asset) orelse return diagnostic.fail(
            error.InvalidManifest,
            "publish manifest asset record is invalid",
            .{},
        );
        const name = contracts.stringOrNull(fields.get("asset_name")) orelse "";
        if (name.len == 0 or std.mem.indexOfAny(u8, name, "\t\n/") != null) {
            return diagnostic.fail(
                error.InvalidManifest,
                "publish manifest asset name is invalid",
                .{},
            );
        }
        const sha256 = try contract.requireSha256(
            fields.get("sha256"),
            "publish manifest asset digest",
            diagnostic,
        );
        const bytes = contracts.integerOrNull(fields.get("bytes")) orelse -1;
        if (bytes < 0) return diagnostic.fail(
            error.InvalidManifest,
            "publish manifest asset size is invalid",
            .{},
        );
        out.print("{s}\t{s}\t{d}\n", .{ name, sha256, bytes }) catch return error.Io;
    }
}

/// Parses the table back. The shell writes it, re-reads it in three separate
/// loops, and passes it to every remaining check; parsing it in exactly one
/// place is what keeps those readers agreeing.
pub fn parseExpected(
    allocator: Allocator,
    text: []const u8,
    diagnostic: *Diagnostic,
) PublishError![]Expected {
    var rows: std.ArrayList(Expected) = .empty;
    errdefer rows.deinit(allocator);
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse "";
        const sha256 = fields.next() orelse "";
        const size = fields.next() orelse "";
        if (fields.next() != null or name.len == 0 or
            !contract.isSha256Hex(sha256))
        {
            return diagnostic.fail(
                error.InvalidExpectedTable,
                "expected asset table row is invalid: {s}",
                .{line},
            );
        }
        const bytes = std.fmt.parseInt(u64, size, 10) catch return diagnostic.fail(
            error.InvalidExpectedTable,
            "expected asset table row is invalid: {s}",
            .{line},
        );
        for (rows.items) |row| {
            if (std.mem.eql(u8, row.name, name)) return diagnostic.fail(
                error.InvalidExpectedTable,
                "expected asset table names {s} twice",
                .{name},
            );
        }
        try rows.append(allocator, .{
            .name = name,
            .sha256 = sha256,
            .bytes = bytes,
        });
    }
    if (rows.items.len != contracts.release_order.len) return diagnostic.fail(
        error.InvalidExpectedTable,
        "expected asset table does not name exactly four assets",
        .{},
    );
    return rows.toOwnedSlice(allocator);
}

fn findExpected(rows: []const Expected, name: []const u8) ?Expected {
    for (rows) |row| {
        if (std.mem.eql(u8, row.name, name)) return row;
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tag references
// ---------------------------------------------------------------------------

pub const TagObject = struct {
    kind: []const u8,
    sha: []const u8,
};

/// The object an exact `refs/tags/<tag>` match points at, or nothing when the
/// tag does not exist yet. More than one exact match means the API answered
/// with something this publisher will not reason about.
pub fn writeTagRef(
    refs: Value,
    tag: []const u8,
    out: *Writer,
    diagnostic: *Diagnostic,
) PublishError!void {
    var buffer: [256]u8 = undefined;
    const expected = std.fmt.bufPrint(&buffer, "refs/tags/{s}", .{tag}) catch
        return diagnostic.fail(
            error.InvalidTagObject,
            "release tag name is too long: {s}",
            .{tag},
        );
    const items = contracts.arrayOrNull(refs) orelse return diagnostic.fail(
        error.InvalidTagObject,
        "matching tag refs are not a list",
        .{},
    );
    var match: ?Value = null;
    var matches: usize = 0;
    for (items) |item| {
        const fields = contracts.objectOrNull(item) orelse continue;
        if (!contracts.isString(fields.get("ref"), expected)) continue;
        matches += 1;
        match = fields.get("object") orelse Value{ .null = {} };
    }
    if (matches > 1) return diagnostic.fail(
        error.DuplicateTagRefs,
        "duplicate exact tag refs",
        .{},
    );
    if (matches == 0) return;
    const object = try tagObject(match.?, diagnostic);
    out.print("{s}\n{s}\n", .{ object.kind, object.sha }) catch return error.Io;
}

/// The object a peeled annotated tag points at.
pub fn writeTagObject(
    document: *const ObjectMap,
    out: *Writer,
    diagnostic: *Diagnostic,
) PublishError!void {
    const object = try tagObject(
        document.get("object") orelse Value{ .null = {} },
        diagnostic,
    );
    out.print("{s}\n{s}\n", .{ object.kind, object.sha }) catch return error.Io;
}

fn tagObject(value: Value, diagnostic: *Diagnostic) PublishError!TagObject {
    const fields = contracts.objectOrNull(value) orelse return diagnostic.fail(
        error.InvalidTagObject,
        "tag object is absent",
        .{},
    );
    const kind = contracts.stringOrNull(fields.get("type")) orelse "";
    const sha = contracts.stringOrNull(fields.get("sha")) orelse "";
    // The shell compares both against literals and a commit SHA; a value that
    // could be mistaken for a shell word is refused before it is printed.
    if (kind.len == 0 or !isTagObjectKind(kind) or !contract.isCommitHex(sha)) {
        return diagnostic.fail(
            error.InvalidTagObject,
            "tag object identity is invalid",
            .{},
        );
    }
    return .{ .kind = kind, .sha = sha };
}

fn isTagObjectKind(kind: []const u8) bool {
    for ([_][]const u8{ "commit", "tag", "tree", "blob" }) |allowed| {
        if (std.mem.eql(u8, kind, allowed)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Remote release state
// ---------------------------------------------------------------------------

/// Asset IDs the release holds that the expected table does not name. The
/// publisher deletes exactly these, so anything it cannot identify as an
/// integer ID is a failure rather than a skipped row.
pub fn writeStaleAssetIds(
    release_document: *const ObjectMap,
    expected: []const Expected,
    out: *Writer,
    diagnostic: *Diagnostic,
) PublishError!void {
    const assets = contracts.arrayOrNull(release_document.get("assets")) orelse
        return diagnostic.fail(
            error.ReleaseAllowlistMismatch,
            "release has no asset list",
            .{},
        );
    for (assets) |asset| {
        const fields = contracts.objectOrNull(asset) orelse return diagnostic.fail(
            error.ReleaseAllowlistMismatch,
            "release asset record is invalid",
            .{},
        );
        const name = contracts.stringOrNull(fields.get("name")) orelse
            return diagnostic.fail(
                error.ReleaseAllowlistMismatch,
                "release asset record is invalid",
                .{},
            );
        if (findExpected(expected, name) != null) continue;
        const id = contracts.integerOrNull(fields.get("id")) orelse -1;
        if (id < 0) return diagnostic.fail(
            error.ReleaseAllowlistMismatch,
            "release asset record is invalid",
            .{},
        );
        out.print("{d}\n", .{id}) catch return error.Io;
    }
}

pub const ReleaseState = enum { draft, published };

/// The remote release must hold exactly the four expected assets. While the
/// release is still a draft the sizes are compared too; once published, the
/// name set is what the final check re-proves, together with the draft flag
/// having been cleared.
pub fn checkReleaseAssets(
    allocator: Allocator,
    release_document: *const ObjectMap,
    expected: []const Expected,
    state: ReleaseState,
    diagnostic: *Diagnostic,
) PublishError!void {
    const assets = contracts.arrayOrNull(release_document.get("assets")) orelse &.{};
    const draft = release_document.get("draft");
    if (draft == null or draft.? != .bool) return diagnostic.fail(
        error.ReleaseNotDraft,
        "release draft state is absent",
        .{},
    );

    switch (state) {
        .draft => {
            var actual = try actualAssetSizes(allocator, assets, diagnostic);
            defer actual.deinit(allocator);
            var matches = assets.len == expected.len and
                actual.count() == expected.len;
            if (matches) {
                for (expected) |row| {
                    const size = actual.get(row.name) orelse {
                        matches = false;
                        break;
                    };
                    if (size != row.bytes) {
                        matches = false;
                        break;
                    }
                }
            }
            if (!matches) {
                const repr = try assetSizeRepr(allocator, assets);
                defer allocator.free(repr);
                return diagnostic.fail(
                    error.ReleaseAllowlistMismatch,
                    "remote release asset allowlist/size mismatch: {s}",
                    .{repr},
                );
            }
            if (!draft.?.bool) return diagnostic.fail(
                error.ReleaseNotDraft,
                "release stopped being a draft before verification",
                .{},
            );
        },
        .published => {
            var names: std.StringHashMapUnmanaged(void) = .empty;
            defer names.deinit(allocator);
            for (assets) |asset| {
                const fields = contracts.objectOrNull(asset) orelse
                    return diagnostic.fail(
                        error.ReleaseAllowlistMismatch,
                        "published release did not retain the exact final allowlist",
                        .{},
                    );
                const name = contracts.stringOrNull(fields.get("name")) orelse
                    return diagnostic.fail(
                        error.ReleaseAllowlistMismatch,
                        "published release did not retain the exact final allowlist",
                        .{},
                    );
                try names.put(allocator, name, {});
            }
            var matches = !draft.?.bool and
                assets.len == expected.len and
                names.count() == expected.len;
            if (matches) {
                for (expected) |row| {
                    if (!names.contains(row.name)) {
                        matches = false;
                        break;
                    }
                }
            }
            if (!matches) return diagnostic.fail(
                error.ReleaseAllowlistMismatch,
                "published release did not retain the exact final allowlist",
                .{},
            );
        },
    }
}

fn actualAssetSizes(
    allocator: Allocator,
    assets: []const Value,
    diagnostic: *Diagnostic,
) PublishError!std.StringHashMapUnmanaged(u64) {
    var sizes: std.StringHashMapUnmanaged(u64) = .empty;
    errdefer sizes.deinit(allocator);
    for (assets) |asset| {
        const fields = contracts.objectOrNull(asset) orelse return diagnostic.fail(
            error.ReleaseAllowlistMismatch,
            "release asset record is invalid",
            .{},
        );
        const name = contracts.stringOrNull(fields.get("name")) orelse
            return diagnostic.fail(
                error.ReleaseAllowlistMismatch,
                "release asset record is invalid",
                .{},
            );
        const size = contracts.integerOrNull(fields.get("size")) orelse -1;
        if (size < 0) return diagnostic.fail(
            error.ReleaseAllowlistMismatch,
            "release asset record is invalid",
            .{},
        );
        try sizes.put(allocator, name, @intCast(size));
    }
    return sizes;
}

/// `{asset["name"]: asset["size"]}` as Python would have printed it, so the
/// failure repeats what the API actually returned.
fn assetSizeRepr(allocator: Allocator, assets: []const Value) Allocator.Error![]u8 {
    var map: ObjectMap = .empty;
    defer map.deinit(allocator);
    for (assets) |asset| {
        const fields = contracts.objectOrNull(asset) orelse continue;
        const name = contracts.stringOrNull(fields.get("name")) orelse continue;
        try map.put(allocator, name, fields.get("size") orelse Value{ .null = {} });
    }
    return contracts.pythonReprAlloc(allocator, Value{ .object = map });
}

// ---------------------------------------------------------------------------
// Downloaded release
// ---------------------------------------------------------------------------

/// The release downloaded back from GitHub must be exactly the four expected
/// files, at the expected sizes, hashing to the expected digests. This is the
/// only check performed on bytes that made a round trip through the service.
pub fn checkDownloads(
    allocator: Allocator,
    io: Io,
    directory_path: []const u8,
    expected: []const Expected,
    diagnostic: *Diagnostic,
) PublishError!void {
    var directory = std.Io.Dir.cwd().openDir(io, directory_path, .{
        .iterate = true,
    }) catch |err| return diagnostic.fail(
        error.CannotRead,
        "cannot read {s}: {s}",
        .{ directory_path, @errorName(err) },
    );
    defer directory.close(io);

    var present: std.ArrayList([]const u8) = .empty;
    defer {
        for (present.items) |name| allocator.free(name);
        present.deinit(allocator);
    }
    var iterator = directory.iterate();
    while (iterator.next(io) catch |err| return diagnostic.fail(
        error.CannotRead,
        "cannot read {s}: {s}",
        .{ directory_path, @errorName(err) },
    )) |entry| {
        if (entry.kind != .file) continue;
        try present.append(allocator, try allocator.dupe(u8, entry.name));
    }

    var exact = present.items.len == expected.len;
    if (exact) {
        for (present.items) |name| {
            if (findExpected(expected, name) == null) {
                exact = false;
                break;
            }
        }
    }
    if (!exact) {
        const repr = try nameSetRepr(allocator, present.items);
        defer allocator.free(repr);
        return diagnostic.fail(
            error.DownloadMismatch,
            "downloaded release allowlist mismatch: {s}",
            .{repr},
        );
    }

    for (expected) |row| {
        const path = try std.fs.path.join(allocator, &.{ directory_path, row.name });
        defer allocator.free(path);
        const result = digest_support.hashFile(
            io,
            path,
            max_asset_bytes,
        ) catch |err| return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        );
        if (result.size != row.bytes) return diagnostic.fail(
            error.DownloadMismatch,
            "{s}: downloaded size mismatch",
            .{row.name},
        );
        if (!std.mem.eql(u8, &result.hex, row.sha256)) return diagnostic.fail(
            error.DownloadMismatch,
            "{s}: downloaded digest mismatch",
            .{row.name},
        );
    }
}

/// A Python `set` repr: braces, sorted here so the text is deterministic.
fn nameSetRepr(allocator: Allocator, names: []const []const u8) Allocator.Error![]u8 {
    if (names.len == 0) return allocator.dupe(u8, "set()");
    const sorted = try allocator.dupe([]const u8, names);
    defer allocator.free(sorted);
    std.mem.sort([]const u8, sorted, {}, struct {
        fn lessThan(_: void, left: []const u8, right: []const u8) bool {
            return std.mem.lessThan(u8, left, right);
        }
    }.lessThan);
    var text: Writer.Allocating = .init(allocator);
    errdefer text.deinit();
    var list: std.json.Array = .init(allocator);
    defer list.deinit();
    for (sorted) |name| try list.append(contracts.str(name));
    contracts.writePythonRepr(&text.writer, .{ .array = list }) catch
        return error.OutOfMemory;
    const rendered = try text.toOwnedSlice();
    defer allocator.free(rendered);
    return std.fmt.allocPrint(allocator, "{{{s}}}", .{rendered[1 .. rendered.len - 1]});
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

pub fn readExpected(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) PublishError![]Expected {
    const text = file_support.readBounded(
        allocator,
        io,
        path,
        max_expected_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    return parseExpected(allocator, text, diagnostic);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const TempTree = @import("../release/testing.zig").TempTree;

fn parse(text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, std.testing.allocator, text, .{});
}

const manifest_json =
    \\{"assets": [
    \\ {"asset_name": "AzureLinux-4.0-x86_64.qcow2",
    \\  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
    \\  "bytes": 11},
    \\ {"asset_name": "AzureLinux-4.0-aarch64.qcow2",
    \\  "sha256": "2222222222222222222222222222222222222222222222222222222222222222",
    \\  "bytes": 22},
    \\ {"asset_name": "AzureLinux-4.0-x86_64.core.qcow2",
    \\  "sha256": "3333333333333333333333333333333333333333333333333333333333333333",
    \\  "bytes": 33},
    \\ {"asset_name": "AzureLinux-4.0-aarch64.core.qcow2",
    \\  "sha256": "4444444444444444444444444444444444444444444444444444444444444444",
    \\  "bytes": 44}]}
;

const expected_table = "AzureLinux-4.0-x86_64.qcow2\t" ++ "1" ** 64 ++ "\t11\n" ++
    "AzureLinux-4.0-aarch64.qcow2\t" ++ "2" ** 64 ++ "\t22\n" ++
    "AzureLinux-4.0-x86_64.core.qcow2\t" ++ "3" ** 64 ++ "\t33\n" ++
    "AzureLinux-4.0-aarch64.core.qcow2\t" ++ "4" ** 64 ++ "\t44\n";

test "the expected asset table round-trips the publish manifest" {
    var diagnostic: Diagnostic = .{};
    var manifest = try parse(manifest_json);
    defer manifest.deinit();

    var text: Writer.Allocating = .init(std.testing.allocator);
    defer text.deinit();
    try writeExpected(&manifest.value.object, &text.writer, &diagnostic);
    try std.testing.expectEqualStrings(expected_table, text.written());

    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const rows = try parseExpected(arena.allocator(), text.written(), &diagnostic);
    try std.testing.expectEqual(@as(usize, 4), rows.len);
    try std.testing.expectEqualStrings("AzureLinux-4.0-x86_64.qcow2", rows[0].name);
    try std.testing.expectEqual(@as(u64, 11), rows[0].bytes);
    try std.testing.expectEqualStrings("4" ** 64, rows[3].sha256);
}

test "a manifest that lost its shape never becomes a table" {
    var diagnostic: Diagnostic = .{};
    var text: Writer.Allocating = .init(std.testing.allocator);
    defer text.deinit();

    var short = try parse(
        \\{"assets": [{"asset_name": "a", "sha256": "0", "bytes": 1}]}
    );
    defer short.deinit();
    try std.testing.expectError(error.InvalidManifest, writeExpected(
        &short.value.object,
        &text.writer,
        &diagnostic,
    ));

    var tabbed = try parse(
        \\{"assets": [
        \\ {"asset_name": "a\tb",
        \\  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\  "bytes": 1},
        \\ {"asset_name": "b",
        \\  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\  "bytes": 1},
        \\ {"asset_name": "c",
        \\  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\  "bytes": 1},
        \\ {"asset_name": "d",
        \\  "sha256": "1111111111111111111111111111111111111111111111111111111111111111",
        \\  "bytes": 1}]}
    );
    defer tabbed.deinit();
    try std.testing.expectError(error.InvalidManifest, writeExpected(
        &tabbed.value.object,
        &text.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "publish manifest asset name is invalid",
        diagnostic.message(),
    );

    var unhashed = try parse(
        \\{"assets": [
        \\ {"asset_name": "a", "sha256": "nope", "bytes": 1},
        \\ {"asset_name": "b", "sha256": "nope", "bytes": 1},
        \\ {"asset_name": "c", "sha256": "nope", "bytes": 1},
        \\ {"asset_name": "d", "sha256": "nope", "bytes": 1}]}
    );
    defer unhashed.deinit();
    try std.testing.expectError(error.InvalidSha256, writeExpected(
        &unhashed.value.object,
        &text.writer,
        &diagnostic,
    ));
}

test "the expected table refuses malformed and duplicate rows" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    try std.testing.expectError(error.InvalidExpectedTable, parseExpected(
        allocator,
        "only-two\tfields\n",
        &diagnostic,
    ));
    try std.testing.expectError(error.InvalidExpectedTable, parseExpected(
        allocator,
        "name\t" ++ "1" ** 64 ++ "\tnot-a-number\n",
        &diagnostic,
    ));
    try std.testing.expectError(error.InvalidExpectedTable, parseExpected(
        allocator,
        "name\t" ++ "1" ** 64 ++ "\t1\n",
        &diagnostic,
    ));
    const duplicated = "a\t" ++ "1" ** 64 ++ "\t1\n" ++
        "a\t" ++ "1" ** 64 ++ "\t1\n" ++
        "c\t" ++ "1" ** 64 ++ "\t1\n" ++
        "d\t" ++ "1" ** 64 ++ "\t1\n";
    try std.testing.expectError(error.InvalidExpectedTable, parseExpected(
        allocator,
        duplicated,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "expected asset table names a twice",
        diagnostic.message(),
    );
}

test "an exact tag ref is reported and a duplicate is refused" {
    var diagnostic: Diagnostic = .{};
    var text: Writer.Allocating = .init(std.testing.allocator);
    defer text.deinit();

    var refs = try parse(
        \\[{"ref": "refs/tags/AzureLinux-4.0-20260814",
        \\  "object": {"type": "commit",
        \\   "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
        \\ {"ref": "refs/tags/AzureLinux-4.0-20260814-rc1",
        \\  "object": {"type": "commit",
        \\   "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]
    );
    defer refs.deinit();
    try writeTagRef(refs.value, "AzureLinux-4.0-20260814", &text.writer, &diagnostic);
    try std.testing.expectEqualStrings("commit\n" ++ "a" ** 40 ++ "\n", text.written());

    text.clearRetainingCapacity();
    var absent = try parse("[]");
    defer absent.deinit();
    try writeTagRef(absent.value, "AzureLinux-4.0-20260814", &text.writer, &diagnostic);
    try std.testing.expectEqual(@as(usize, 0), text.written().len);

    var duplicated = try parse(
        \\[{"ref": "refs/tags/t", "object": {"type": "commit",
        \\   "sha": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}},
        \\ {"ref": "refs/tags/t", "object": {"type": "tag",
        \\   "sha": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}}]
    );
    defer duplicated.deinit();
    try std.testing.expectError(error.DuplicateTagRefs, writeTagRef(
        duplicated.value,
        "t",
        &text.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings("duplicate exact tag refs", diagnostic.message());
}

test "a peeled tag object must name a real object identity" {
    var diagnostic: Diagnostic = .{};
    var text: Writer.Allocating = .init(std.testing.allocator);
    defer text.deinit();

    var annotated = try parse(
        \\{"object": {"type": "commit",
        \\  "sha": "cccccccccccccccccccccccccccccccccccccccc"}}
    );
    defer annotated.deinit();
    try writeTagObject(&annotated.value.object, &text.writer, &diagnostic);
    try std.testing.expectEqualStrings("commit\n" ++ "c" ** 40 ++ "\n", text.written());

    var injected = try parse(
        \\{"object": {"type": "commit; rm -rf /", "sha": "x"}}
    );
    defer injected.deinit();
    try std.testing.expectError(error.InvalidTagObject, writeTagObject(
        &injected.value.object,
        &text.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "tag object identity is invalid",
        diagnostic.message(),
    );
}

const release_json =
    \\{"draft": true, "assets": [
    \\ {"id": 1, "name": "AzureLinux-4.0-x86_64.qcow2", "size": 11},
    \\ {"id": 2, "name": "AzureLinux-4.0-aarch64.qcow2", "size": 22},
    \\ {"id": 3, "name": "AzureLinux-4.0-x86_64.core.qcow2", "size": 33},
    \\ {"id": 4, "name": "AzureLinux-4.0-aarch64.core.qcow2", "size": 44}]}
;

test "the remote release must hold exactly the expected four" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    const expected = try parseExpected(allocator, expected_table, &diagnostic);

    var draft = try parse(release_json);
    defer draft.deinit();
    try checkReleaseAssets(allocator, &draft.value.object, expected, .draft, &diagnostic);
    try std.testing.expectError(error.ReleaseAllowlistMismatch, checkReleaseAssets(
        allocator,
        &draft.value.object,
        expected,
        .published,
        &diagnostic,
    ));

    var published = try parse(
        \\{"draft": false, "assets": [
        \\ {"id": 1, "name": "AzureLinux-4.0-x86_64.qcow2", "size": 11},
        \\ {"id": 2, "name": "AzureLinux-4.0-aarch64.qcow2", "size": 22},
        \\ {"id": 3, "name": "AzureLinux-4.0-x86_64.core.qcow2", "size": 33},
        \\ {"id": 4, "name": "AzureLinux-4.0-aarch64.core.qcow2", "size": 44}]}
    );
    defer published.deinit();
    try checkReleaseAssets(
        allocator,
        &published.value.object,
        expected,
        .published,
        &diagnostic,
    );
    try std.testing.expectError(error.ReleaseNotDraft, checkReleaseAssets(
        allocator,
        &published.value.object,
        expected,
        .draft,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "release stopped being a draft before verification",
        diagnostic.message(),
    );

    var resized = try parse(
        \\{"draft": true, "assets": [
        \\ {"id": 1, "name": "AzureLinux-4.0-x86_64.qcow2", "size": 12},
        \\ {"id": 2, "name": "AzureLinux-4.0-aarch64.qcow2", "size": 22},
        \\ {"id": 3, "name": "AzureLinux-4.0-x86_64.core.qcow2", "size": 33},
        \\ {"id": 4, "name": "AzureLinux-4.0-aarch64.core.qcow2", "size": 44}]}
    );
    defer resized.deinit();
    try std.testing.expectError(error.ReleaseAllowlistMismatch, checkReleaseAssets(
        allocator,
        &resized.value.object,
        expected,
        .draft,
        &diagnostic,
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        diagnostic.message(),
        "remote release asset allowlist/size mismatch: {'AzureLinux-4.0-x86_64.qcow2': 12",
    ));

    var sidecar = try parse(
        \\{"draft": true, "assets": [
        \\ {"id": 1, "name": "AzureLinux-4.0-x86_64.qcow2", "size": 11},
        \\ {"id": 2, "name": "AzureLinux-4.0-aarch64.qcow2", "size": 22},
        \\ {"id": 3, "name": "AzureLinux-4.0-x86_64.core.qcow2", "size": 33},
        \\ {"id": 4, "name": "AzureLinux-4.0-aarch64.core.qcow2", "size": 44},
        \\ {"id": 5, "name": "AzureLinux-4.0-x86_64.qcow2.sha256", "size": 65}]}
    );
    defer sidecar.deinit();
    try std.testing.expectError(error.ReleaseAllowlistMismatch, checkReleaseAssets(
        allocator,
        &sidecar.value.object,
        expected,
        .draft,
        &diagnostic,
    ));

    var stale: Writer.Allocating = .init(allocator);
    try writeStaleAssetIds(&sidecar.value.object, expected, &stale.writer, &diagnostic);
    try std.testing.expectEqualStrings("5\n", stale.written());
}

test "downloaded assets are re-hashed against the expected table" {
    const io = std.testing.io;
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    var tree = TempTree.create();
    defer tree.deinit();
    var root_buffer: [TempTree.max_path_len]u8 = undefined;
    const root = tree.path(&root_buffer, "remote");
    try std.Io.Dir.cwd().createDirPath(io, root);

    var rows: std.ArrayList(Expected) = .empty;
    var name_buffer: [TempTree.max_path_len]u8 = undefined;
    for (contracts.release_order) |entry| {
        const data = entry.key;
        const path = try std.fmt.bufPrint(
            &name_buffer,
            "{s}/{s}",
            .{ root, entry.asset_name },
        );
        try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = path, .data = data });
        try rows.append(allocator, .{
            .name = entry.asset_name,
            .sha256 = try allocator.dupe(u8, &digest_support.hexBytes(data)),
            .bytes = data.len,
        });
    }
    try checkDownloads(allocator, io, root, rows.items, &diagnostic);

    // A byte that changed in transit.
    const tampered = try std.fmt.bufPrint(
        &name_buffer,
        "{s}/{s}",
        .{ root, contracts.release_order[0].asset_name },
    );
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = tampered, .data = "x86_64-fulL" });
    try std.testing.expectError(error.DownloadMismatch, checkDownloads(
        allocator,
        io,
        root,
        rows.items,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-x86_64.qcow2: downloaded digest mismatch",
        diagnostic.message(),
    );

    // A sidecar that was never published cannot appear in the download either.
    const extra = try std.fmt.bufPrint(
        &name_buffer,
        "{s}/{s}",
        .{ root, "AzureLinux-4.0-x86_64.qcow2.sha256" },
    );
    try std.Io.Dir.cwd().writeFile(io, .{ .sub_path = extra, .data = "0" });
    try std.testing.expectError(error.DownloadMismatch, checkDownloads(
        allocator,
        io,
        root,
        rows.items,
        &diagnostic,
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        diagnostic.message(),
        "downloaded release allowlist mismatch: {'AzureLinux-4.0-aarch64.core.qcow2'",
    ));
}
