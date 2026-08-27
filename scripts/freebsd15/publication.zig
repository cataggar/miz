//! The staged and published allowlists the FreeBSD 15.1 release shell enforces.
//!
//! Native port of the inline Python that `scripts/freebsd15_stage_release.sh`
//! and `scripts/freebsd15_publish.sh` used to embed as heredocs. The contract
//! is deliberately restated here rather than derived only from the release-set
//! table: a publication allowlist that came from the same table it is meant to
//! police would police nothing. The two statements are compared by
//! `tests/freebsd15_release.zig`.

const std = @import("std");
const profiles = @import("profiles.zig");
const document = @import("document.zig");
const candidate_support = @import("candidate.zig");
const staging = @import("staging.zig");
const support = @import("release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const Writer = std.Io.Writer;
const contract = support.contract;
const digest = support.digest;
const file_support = support.file;

pub const Context = document.Context;
pub const Error = document.Error;

pub const AllowedAsset = struct {
    variant: []const u8,
    asset_name: []const u8,
};

/// The exact four assets a combined ZFS dispatch may publish, spelled out so
/// the publisher refuses an incomplete or unexpected upload without consulting
/// the table that produced the upload.
pub const zfs_publication_allowlist = [_]AllowedAsset{
    .{ .variant = "aarch64-zfs-full", .asset_name = "FreeBSD-15.1-aarch64.qcow2" },
    .{ .variant = "x86_64-zfs-full", .asset_name = "FreeBSD-15.1-x86_64.qcow2" },
    .{ .variant = "aarch64-zfs-core", .asset_name = "FreeBSD-15.1-aarch64.core.qcow2" },
    .{ .variant = "x86_64-zfs-core", .asset_name = "FreeBSD-15.1-x86_64.core.qcow2" },
};

pub fn publicationAllowlist(
    context: *Context,
    release_set: []const u8,
) Error![]const AllowedAsset {
    if (!std.mem.eql(u8, release_set, "zfs")) return context.fail(
        "unsupported FreeBSD release set: {s}",
        .{release_set},
    );
    return &zfs_publication_allowlist;
}

/// One published asset: the three fields every downstream check compares.
pub const ExpectedAsset = struct {
    name: []const u8,
    sha256: []const u8,
    bytes: i64,
};

fn matchesAllowlist(
    allowlist: []const AllowedAsset,
    assets: std.json.Array,
) bool {
    if (assets.items.len != allowlist.len) return false;
    for (allowlist) |allowed| {
        var found = false;
        for (assets.items) |item| {
            const asset = document.objectOf(item) orelse return false;
            if (!document.eqlString(asset.get("variant"), allowed.variant)) continue;
            if (!document.eqlString(asset.get("asset_name"), allowed.asset_name)) {
                return false;
            }
            if (found) return false;
            found = true;
        }
        if (!found) return false;
    }
    return true;
}

/// Renders a name set the way a Python `repr` of the offending mapping did:
/// enough to identify what was actually there.
fn renderNames(writer: *Writer, names: []const []const u8) void {
    writer.writeByte('{') catch {};
    for (names, 0..) |name, index| {
        if (index > 0) writer.writeAll(", ") catch {};
        writer.print("'{s}'", .{name}) catch {};
    }
    writer.writeByte('}') catch {};
}

fn namesText(context: *Context, names: []const []const u8) Error![]const u8 {
    var out: Writer.Allocating = .init(context.arena);
    renderNames(&out.writer, names);
    return out.written();
}

fn sortedNames(names: [][]const u8) []const []const u8 {
    std.mem.sort([]const u8, names, {}, lessThanName);
    return names;
}

fn lessThanName(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn writeExpected(writer: *Writer, assets: []const ExpectedAsset) Error!void {
    for (assets) |asset| {
        writer.print("{s}\t{s}\t{d}\n", .{
            asset.name,
            asset.sha256,
            asset.bytes,
        }) catch return error.OutOfMemory;
    }
}

// ---- Staging: the release-set allowlist -----------------------------------

/// `freebsd15_stage_release.sh`'s first heredoc: prove the staged publish
/// manifest describes exactly the release set's allowlist, and emit the
/// `name<TAB>sha256<TAB>bytes` table the shell re-verifies against the files.
pub fn stagedExpected(
    context: *Context,
    manifest_path: []const u8,
    release_set: []const u8,
    writer: *Writer,
) Error!void {
    const allowlist = try publicationAllowlist(context, release_set);
    const manifest = try candidate_support.readObject(context, manifest_path);
    const root = manifest.object;
    if (!document.eqlString(root.get("release_set"), release_set)) return context.fail(
        "publish manifest release set mismatch",
        .{},
    );
    const assets = document.arrayOf(root.get("assets")) orelse return context.fail(
        "publish manifest assets are missing",
        .{},
    );
    if (!matchesAllowlist(allowlist, assets)) return context.fail(
        "ZFS publication allowlist mismatch: {s}",
        .{try assetNamesText(context, assets)},
    );
    const expected = try expectedAssets(context, assets);
    try writeExpected(writer, expected);
}

fn assetNamesText(context: *Context, assets: std.json.Array) Error![]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse continue;
        try names.append(
            context.arena,
            document.stringOf(asset.get("variant")) orelse "<invalid>",
        );
    }
    return namesText(context, sortedNames(names.items));
}

/// The `name`, `sha256`, and `bytes` of every asset, refusing anything that is
/// not a bare file name, a lowercase digest, and a positive size.
fn expectedAssets(context: *Context, assets: std.json.Array) Error![]const ExpectedAsset {
    var expected: std.ArrayList(ExpectedAsset) = .empty;
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse return context.fail(
            "invalid publish manifest asset",
            .{},
        );
        const name = document.stringOf(asset.get("asset_name")) orelse
            return context.fail("invalid publish manifest asset", .{});
        const sha256 = document.stringOf(asset.get("sha256")) orelse
            return context.fail("invalid publish manifest asset", .{});
        const bytes = document.integerOf(asset.get("bytes")) orelse
            return context.fail("invalid publish manifest asset", .{});
        if (!candidate_support.isBareFileName(name) or
            !contract.isSha256Hex(sha256) or bytes <= 0)
        {
            return context.fail("invalid publish manifest asset", .{});
        }
        for (expected.items) |already| {
            if (std.mem.eql(u8, already.name, name)) return context.fail(
                "invalid publish manifest asset",
                .{},
            );
        }
        try expected.append(
            context.arena,
            .{ .name = name, .sha256 = sha256, .bytes = bytes },
        );
    }
    return expected.items;
}

// ---- Staging: the validation evidence tree --------------------------------

/// `freebsd15_stage_release.sh`'s second heredoc: copy exactly one Azure result
/// per published variant into the evidence tree, then prove the tree holds
/// exactly the expected files and nothing else.
pub fn stageEvidence(
    context: *Context,
    release_set: []const u8,
    manifest_path: []const u8,
    azure_root: []const u8,
    evidence_root: []const u8,
) Error!void {
    const allowlist = try publicationAllowlist(context, release_set);
    const manifest = try candidate_support.readObject(context, manifest_path);
    const assets = document.arrayOf(manifest.object.get("assets")) orelse
        return context.fail("publish manifest assets are missing", .{});

    var variants: std.ArrayList([]const u8) = .empty;
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse return context.fail(
            "invalid publish manifest asset",
            .{},
        );
        try variants.append(
            context.arena,
            document.stringOf(asset.get("variant")) orelse "<invalid>",
        );
    }
    var allowed: std.ArrayList([]const u8) = .empty;
    for (allowlist) |entry| try allowed.append(context.arena, entry.variant);
    if (!staging.sameKeySet(variants.items, allowed.items)) return context.fail(
        "unexpected ZFS variant allowlist: {s}",
        .{try namesText(context, sortedNames(variants.items))},
    );

    var expected: std.ArrayList([]const u8) = .empty;
    try expected.append(context.arena, "publish-manifest.json");
    try expected.append(context.arena, "release-notes.md");
    try expected.append(context.arena, "size-comparison.md");

    var copied: std.ArrayList([]const u8) = .empty;
    const sources = try staging.findManifests(context, azure_root, "azure-result.json");
    for (sources) |source| {
        const azure = try candidate_support.readObject(context, source);
        const variant = document.stringOf(azure.object.get("variant")) orelse
            return context.fail("unexpected or duplicate Azure evidence variant", .{});
        var known = false;
        for (variants.items) |claimed| {
            if (std.mem.eql(u8, claimed, variant)) known = true;
        }
        for (copied.items) |already| {
            if (std.mem.eql(u8, already, variant)) known = false;
        }
        if (!known) return context.fail(
            "unexpected or duplicate Azure evidence variant",
            .{},
        );
        const relative = try std.fmt.allocPrint(
            context.arena,
            "azure-results/{s}/azure-result.json",
            .{variant},
        );
        const destination = try std.fs.path.join(
            context.arena,
            &.{ evidence_root, relative },
        );
        Dir.cwd().copyFile(
            source,
            Dir.cwd(),
            destination,
            context.io,
            .{ .make_path = true, .replace = true },
        ) catch |err| return context.fail(
            "cannot stage {s}: {t}",
            .{ destination, err },
        );
        try copied.append(context.arena, variant);
        try expected.append(context.arena, relative);
    }
    if (!staging.sameKeySet(copied.items, variants.items)) return context.fail(
        "Azure evidence matrix is incomplete",
        .{},
    );

    const actual = try listTree(context, evidence_root);
    if (!staging.sameKeySet(actual, expected.items)) return context.fail(
        "validation evidence allowlist mismatch: {s}",
        .{try namesText(context, actual)},
    );
}

/// Every regular file under `root`, as sorted `root`-relative POSIX paths.
pub fn listTree(context: *Context, root: []const u8) Error![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    var directory = Dir.cwd().openDir(context.io, root, .{ .iterate = true }) catch |err|
        return context.fail("cannot read {s}: {t}", .{ root, err });
    defer directory.close(context.io);

    var walker = try directory.walk(context.gpa);
    defer walker.deinit();
    while (walker.next(context.io) catch |err|
        return context.fail("cannot read {s}: {t}", .{ root, err })) |entry|
    {
        if (entry.kind != .file) continue;
        if (found.items.len >= staging.max_staged_entries) return context.fail(
            "{s}: too many evidence files",
            .{root},
        );
        try found.append(context.arena, try context.arena.dupe(u8, entry.path));
    }
    return sortedNames(found.items);
}

/// Every regular file directly inside `root`, as sorted base names.
pub fn listDirectory(context: *Context, root: []const u8) Error![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    var directory = Dir.cwd().openDir(context.io, root, .{ .iterate = true }) catch |err|
        return context.fail("cannot read {s}: {t}", .{ root, err });
    defer directory.close(context.io);

    var iterator = directory.iterate();
    while (iterator.next(context.io) catch |err|
        return context.fail("cannot read {s}: {t}", .{ root, err })) |entry|
    {
        if (entry.kind != .file) continue;
        if (found.items.len >= staging.max_staged_entries) return context.fail(
            "{s}: too many staged files",
            .{root},
        );
        try found.append(context.arena, try context.arena.dupe(u8, entry.name));
    }
    return sortedNames(found.items);
}

// ---- Publication ----------------------------------------------------------

pub const PublishExpectedArguments = struct {
    manifest: []const u8,
    assets: []const u8,
    release_set: []const u8,
    release_tag: []const u8,
    source_commit: []const u8,
    asset_count: i64,
};

/// `freebsd15_publish.sh`'s first heredoc: bind the staged manifest to the
/// dispatch that produced it, prove the staged directory holds exactly the
/// publication allowlist, and emit the verification table.
pub fn publishExpected(
    context: *Context,
    arguments: PublishExpectedArguments,
    writer: *Writer,
) Error!void {
    const allowlist = try publicationAllowlist(context, arguments.release_set);
    const manifest = try candidate_support.readObject(context, arguments.manifest);
    const root = manifest.object;
    if (!document.eqlString(root.get("type"), candidate_support.release_type)) {
        return context.fail("unexpected publish manifest type", .{});
    }
    if (!document.eqlString(root.get("release_set"), arguments.release_set)) {
        return context.fail("publish manifest release set mismatch", .{});
    }
    if (!document.eqlString(root.get("release_tag"), arguments.release_tag)) {
        return context.fail("publish manifest release tag mismatch", .{});
    }
    if (!document.eqlString(root.get("source_commit"), arguments.source_commit)) {
        return context.fail("publish manifest source commit mismatch", .{});
    }
    const assets = document.arrayOf(root.get("assets")) orelse return context.fail(
        "publish manifest asset count mismatch",
        .{},
    );
    if (assets.items.len != @as(usize, @intCast(arguments.asset_count))) {
        return context.fail("publish manifest asset count mismatch", .{});
    }
    if (!matchesAllowlist(allowlist, assets)) return context.fail(
        "ZFS publication allowlist mismatch: {s}",
        .{try assetNamesText(context, assets)},
    );
    const expected = try expectedAssets(context, assets);
    try writeExpected(writer, expected);

    var wanted: std.ArrayList([]const u8) = .empty;
    for (expected) |asset| try wanted.append(context.arena, asset.name);
    try wanted.append(context.arena, "publish-manifest.json");
    const actual = try listDirectory(context, arguments.assets);
    if (!staging.sameKeySet(actual, wanted.items)) return context.fail(
        "staged release allowlist mismatch: {s}",
        .{try namesText(context, actual)},
    );
}

/// `freebsd15_publish.sh`'s tag-ref heredoc: the exact `refs/tags/<tag>` object
/// type and SHA, if the tag already exists, and nothing at all if it does not.
pub fn tagObject(
    context: *Context,
    refs_path: []const u8,
    tag: []const u8,
    writer: *Writer,
) Error!void {
    const bytes = file_support.readBounded(
        context.arena,
        context.io,
        refs_path,
        candidate_support.max_document_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ refs_path, err }),
    };
    const parsed = std.json.parseFromSlice(
        Value,
        context.arena,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ refs_path, err }),
    };
    const items = document.arrayOf(parsed.value) orelse return context.fail(
        "{s}: matching tag refs are not a list",
        .{refs_path},
    );
    const expected_ref = try std.fmt.allocPrint(context.arena, "refs/tags/{s}", .{tag});

    var match: ?std.json.ObjectMap = null;
    for (items.items) |item| {
        const entry = document.objectOf(item) orelse continue;
        if (!document.eqlString(entry.get("ref"), expected_ref)) continue;
        if (match != null) return context.fail("duplicate exact tag refs", .{});
        match = entry;
    }
    const found = match orelse return;
    const object = document.objectOf(found.get("object")) orelse return context.fail(
        "{s}: matching tag ref has no object",
        .{refs_path},
    );
    const kind = document.stringOf(object.get("type")) orelse return context.fail(
        "{s}: matching tag ref has no object type",
        .{refs_path},
    );
    const sha = document.stringOf(object.get("sha")) orelse return context.fail(
        "{s}: matching tag ref has no object SHA",
        .{refs_path},
    );
    writer.print("{s}\n{s}\n", .{ kind, sha }) catch return error.OutOfMemory;
}

/// Parses the `name<TAB>sha256<TAB>bytes` table the expectation heredocs emit.
pub fn readExpected(
    context: *Context,
    path: []const u8,
) Error![]const ExpectedAsset {
    const bytes = file_support.readBounded(
        context.arena,
        context.io,
        path,
        candidate_support.max_document_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ path, err }),
    };
    var expected: std.ArrayList(ExpectedAsset) = .empty;
    var lines = candidate_support.splitPythonLines(bytes);
    while (lines.next()) |line| {
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next() orelse return context.fail(
            "{s}: malformed expectation record",
            .{path},
        );
        const sha256 = fields.next() orelse return context.fail(
            "{s}: malformed expectation record",
            .{path},
        );
        const size = fields.next() orelse return context.fail(
            "{s}: malformed expectation record",
            .{path},
        );
        if (fields.next() != null) return context.fail(
            "{s}: malformed expectation record",
            .{path},
        );
        const parsed_size = std.fmt.parseInt(i64, size, 10) catch return context.fail(
            "{s}: malformed expectation record",
            .{path},
        );
        try expected.append(
            context.arena,
            .{ .name = name, .sha256 = sha256, .bytes = parsed_size },
        );
    }
    if (expected.items.len == 0) return context.fail(
        "{s}: no expected assets",
        .{path},
    );
    return expected.items;
}

/// `freebsd15_publish.sh`'s post-upload heredoc: the remote release carries
/// exactly the expected assets, with the expected digests and sizes, and is
/// still a draft.
pub fn verifyRemoteRelease(
    context: *Context,
    release_path: []const u8,
    expected_path: []const u8,
) Error!void {
    const expected = try readExpected(context, expected_path);
    const release = try candidate_support.readObject(context, release_path);
    const assets = document.arrayOf(release.object.get("assets")) orelse
        return context.fail("remote release asset mismatch: {s}", .{"<no assets>"});
    if (assets.items.len != expected.len) return context.fail(
        "remote release asset mismatch: {s}",
        .{try releaseAssetNamesText(context, assets)},
    );
    for (expected) |wanted| {
        const asset = findReleaseAsset(assets, wanted.name) orelse return context.fail(
            "remote release asset mismatch: {s}",
            .{try releaseAssetNamesText(context, assets)},
        );
        const raw = document.stringOf(asset.get("digest")) orelse "";
        const observed = if (std.mem.startsWith(u8, raw, "sha256:"))
            raw["sha256:".len..]
        else
            raw;
        if (!std.mem.eql(u8, observed, wanted.sha256) or
            document.integerOf(asset.get("size")) != wanted.bytes)
        {
            return context.fail("remote release asset mismatch: {s}", .{wanted.name});
        }
    }
    const draft = release.object.get("draft");
    if (draft == null or draft.? != .bool or !draft.?.bool) {
        return context.fail("release stopped being a draft before verification", .{});
    }
}

fn findReleaseAsset(assets: std.json.Array, name: []const u8) ?std.json.ObjectMap {
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse continue;
        if (document.eqlString(asset.get("name"), name)) return asset;
    }
    return null;
}

fn releaseAssetNamesText(context: *Context, assets: std.json.Array) Error![]const u8 {
    var names: std.ArrayList([]const u8) = .empty;
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse continue;
        try names.append(
            context.arena,
            document.stringOf(asset.get("name")) orelse "<invalid>",
        );
    }
    return namesText(context, sortedNames(names.items));
}

/// `freebsd15_publish.sh`'s download heredoc: what the release actually serves
/// is exactly what was staged, byte for byte.
pub fn verifyDownloadedRelease(
    context: *Context,
    directory: []const u8,
    expected_path: []const u8,
) Error!void {
    const expected = try readExpected(context, expected_path);
    const actual = try listDirectory(context, directory);
    var wanted: std.ArrayList([]const u8) = .empty;
    for (expected) |asset| try wanted.append(context.arena, asset.name);
    if (!staging.sameKeySet(actual, wanted.items)) return context.fail(
        "downloaded release allowlist mismatch: {s}",
        .{try namesText(context, actual)},
    );
    for (expected) |asset| {
        const path = try std.fs.path.join(context.arena, &.{ directory, asset.name });
        const size = try candidate_support.regularFileSize(context, path);
        if (size != @as(u64, @intCast(asset.bytes))) return context.fail(
            "{s}: downloaded size mismatch",
            .{asset.name},
        );
        const observed = try candidate_support.hashFile(context, path);
        if (!std.mem.eql(u8, &observed, asset.sha256)) return context.fail(
            "{s}: downloaded digest mismatch",
            .{asset.name},
        );
    }
}

/// `freebsd15_publish.sh`'s final heredoc: the published release is no longer a
/// draft and still carries exactly the final allowlist.
pub fn verifyPublishedRelease(
    context: *Context,
    release_path: []const u8,
    expected_path: []const u8,
) Error!void {
    const expected = try readExpected(context, expected_path);
    const release = try candidate_support.readObject(context, release_path);
    const assets = document.arrayOf(release.object.get("assets")) orelse
        return context.fail(
            "published release did not retain the exact final allowlist",
            .{},
        );
    var actual: std.ArrayList([]const u8) = .empty;
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse return context.fail(
            "published release did not retain the exact final allowlist",
            .{},
        );
        try actual.append(
            context.arena,
            document.stringOf(asset.get("name")) orelse "<invalid>",
        );
    }
    var wanted: std.ArrayList([]const u8) = .empty;
    for (expected) |asset| try wanted.append(context.arena, asset.name);
    const draft = release.object.get("draft");
    const is_draft = draft != null and draft.? == .bool and draft.?.bool;
    if (is_draft or !staging.sameKeySet(actual.items, wanted.items)) return context.fail(
        "published release did not retain the exact final allowlist",
        .{},
    );
}

test "the publication allowlist and the release-set table agree" {
    const selected = profiles.findReleaseSet("zfs").?;
    try std.testing.expectEqual(selected.variants.len, zfs_publication_allowlist.len);
    for (zfs_publication_allowlist) |allowed| {
        const variant = profiles.findVariant(allowed.variant).?;
        try std.testing.expectEqualStrings(variant.asset_name, allowed.asset_name);
        var claimed = false;
        for (selected.variants) |key| {
            if (std.mem.eql(u8, key, allowed.variant)) claimed = true;
        }
        try std.testing.expect(claimed);
    }
    // No published asset name carries the qualified ZFS spelling.
    for (zfs_publication_allowlist) |allowed| {
        try std.testing.expect(
            std.mem.indexOf(u8, allowed.asset_name, ".zfs.qcow2") == null,
        );
    }
}
