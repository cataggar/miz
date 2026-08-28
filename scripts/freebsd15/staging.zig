//! Staging, size comparison, and release notes for the FreeBSD 15.1 release.
//!
//! Native port of the staging half of `scripts/freebsd15_release.py`. A staged
//! release is exactly the assets one dispatch is allowed to publish: the
//! candidate matrix has to be complete and unsurprising, every Azure result
//! has to name the same artifacts and the same workflow run, the core flavor
//! has to have actually gotten smaller, and the notes and publish manifest
//! that come out are the only description of the release anything downstream
//! is allowed to trust.

const std = @import("std");
const profiles = @import("profiles.zig");
const document = @import("document.zig");
const candidate_support = @import("candidate.zig");
const support = @import("release");
const azure_vhd = support.azure_vhd_layout;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const Writer = std.Io.Writer;
const contract = support.contract;
const file_support = support.file;
const json_document = support.json_document;

pub const Context = document.Context;
pub const Error = document.Error;

/// A staged tree holds four assets and three documents; anything deeper or
/// wider is not the tree the release jobs produce.
pub const max_staged_entries = 4096;

// ---- Release assets -------------------------------------------------------

/// `candidate_release_asset`.
pub fn candidateReleaseAsset(
    context: *Context,
    candidate: Value,
) Error!Value {
    const root = document.objectOf(candidate) orelse
        return context.fail("candidate is not an object", .{});
    const packages = try recordedObject(context, root, "packages");
    var asset: std.json.ObjectMap = .empty;
    for ([_][]const u8{
        "variant",
        "architecture",
        "filesystem",
        "flavor",
        "asset_name",
    }) |field| {
        try asset.put(context.arena, field, root.get(field) orelse
            return context.fail("recorded {s} is missing", .{field}));
    }
    // `bytes` remains the publisher-facing download size field. Schema 3 also
    // names it explicitly so comparisons cannot confuse it with the qemu-img
    // allocated size.
    const compressed_size: Value = .{
        .integer = try recordedInteger(context, root, "compressed_size"),
    };
    try asset.put(context.arena, "bytes", compressed_size);
    try asset.put(context.arena, "compressed_size", compressed_size);
    try asset.put(context.arena, "allocated_size", .{
        .integer = try recordedInteger(context, root, "allocated_size"),
    });
    try asset.put(context.arena, "virtual_size", .{
        .integer = try recordedInteger(context, root, "virtual_size"),
    });
    try asset.put(context.arena, "sha256", .{
        .string = try recordedString(context, root, "asset_sha256"),
    });
    try asset.put(context.arena, "packages", .{
        .integer = try recordedInteger(context, packages, "count"),
    });
    try asset.put(context.arena, "package_manifest", .{ .object = packages });
    try asset.put(context.arena, "source", .{
        .object = try recordedObject(context, root, "source"),
    });
    return .{ .object = asset };
}

// ---- Full versus core pairing ---------------------------------------------

pub const Pair = struct {
    full: std.json.ObjectMap,
    core: std.json.ObjectMap,
};

fn assetInteger(
    context: *Context,
    asset: std.json.ObjectMap,
    field: []const u8,
) Error!i64 {
    return document.integerOf(asset.get(field)) orelse context.fail(
        "release asset {s} is missing or invalid",
        .{field},
    );
}

fn assetString(
    context: *Context,
    asset: std.json.ObjectMap,
    field: []const u8,
) Error![]const u8 {
    return document.stringOf(asset.get(field)) orelse context.fail(
        "release asset {s} is missing or invalid",
        .{field},
    );
}

/// Sub-document of a validated candidate or Azure result. Validation proves
/// every field the notes render, but the renderer reaches for them by name, so
/// it asks rather than asserts: a rendering bug must be a diagnosed exit 1, not
/// a panic that leaves a half-staged release behind.
fn recordedObject(
    context: *Context,
    owner: std.json.ObjectMap,
    field: []const u8,
) Error!std.json.ObjectMap {
    return document.objectOf(owner.get(field)) orelse context.fail(
        "recorded {s} is missing or not an object",
        .{field},
    );
}

fn recordedInteger(
    context: *Context,
    owner: std.json.ObjectMap,
    field: []const u8,
) Error!i64 {
    return document.integerOf(owner.get(field)) orelse context.fail(
        "recorded {s} is missing or not an integer",
        .{field},
    );
}

fn recordedString(
    context: *Context,
    owner: std.json.ObjectMap,
    field: []const u8,
) Error![]const u8 {
    return document.stringOf(owner.get(field)) orelse context.fail(
        "recorded {s} is missing or not a string",
        .{field},
    );
}

fn recordedArray(
    context: *Context,
    owner: std.json.ObjectMap,
    field: []const u8,
) Error!std.json.Array {
    return document.arrayOf(owner.get(field)) orelse context.fail(
        "recorded {s} is missing or not a list",
        .{field},
    );
}

/// `full_core_rows`: pair full and core assets for the selected release
/// filesystem, refusing any pairing whose identity or pinned source disagrees.
pub fn fullCoreRows(context: *Context, manifest: Value) Error![]const Pair {
    const root = manifest.object;
    const release_set_name = document.stringOf(root.get("release_set")) orelse
        return context.fail("unsupported FreeBSD release set: {s}", .{""});
    const selected = try candidate_support.requireReleaseSet(context, release_set_name);

    var filesystem: ?[]const u8 = null;
    for (selected.variants) |key| {
        const variant = profiles.findVariant(key).?;
        if (filesystem) |seen| {
            if (!std.mem.eql(u8, seen, variant.filesystem)) return context.fail(
                "size comparison requires one release filesystem",
                .{},
            );
        } else filesystem = variant.filesystem;
    }
    const release_filesystem = filesystem orelse return context.fail(
        "size comparison requires one release filesystem",
        .{},
    );
    var upper_buffer: [16]u8 = undefined;
    const upper = std.ascii.upperString(&upper_buffer, release_filesystem);

    const assets = document.arrayOf(root.get("assets")) orelse
        return context.fail("release assets are missing", .{});

    var rows: std.ArrayList(Pair) = .empty;
    for (selected.variants) |key| {
        const core_profile = profiles.findVariant(key).?;
        if (!std.mem.eql(u8, core_profile.flavor, "core")) continue;
        const core = findAsset(assets, key) orelse return context.fail(
            "no {s} core {s} asset",
            .{ core_profile.architecture, upper },
        );
        if (!identityMatches(core, core_profile)) return context.fail(
            "{s} core asset identity is invalid",
            .{key},
        );
        const expected_full = try std.fmt.allocPrint(
            context.arena,
            "{s}-{s}-full",
            .{ core_profile.architecture, release_filesystem },
        );
        const full = findAsset(assets, expected_full) orelse return context.fail(
            "no {s} full {s} asset",
            .{ core_profile.architecture, upper },
        );
        const full_profile = profiles.findVariant(expected_full).?;
        if (!document.eqlString(full.get("variant"), expected_full) or
            !identityMatches(full, full_profile))
        {
            return context.fail(
                "{s} paired asset identity is invalid",
                .{core_profile.architecture},
            );
        }
        if (!document.eqlString(core.get("variant"), key)) return context.fail(
            "{s} core asset identity is invalid",
            .{core_profile.architecture},
        );
        const full_source = full.get("source") orelse Value{ .null = {} };
        const core_source = core.get("source") orelse Value{ .null = {} };
        if (!document.valueEql(full_source, core_source)) return context.fail(
            "{s} full and core pinned sources differ",
            .{try assetString(context, core, "architecture")},
        );
        try rows.append(context.arena, .{ .full = full, .core = core });
    }
    return rows.items;
}

fn findAsset(assets: std.json.Array, key: []const u8) ?std.json.ObjectMap {
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse continue;
        if (document.eqlString(asset.get("variant"), key)) return asset;
    }
    return null;
}

fn identityMatches(
    asset: std.json.ObjectMap,
    variant: *const profiles.Variant,
) bool {
    return document.eqlString(asset.get("architecture"), variant.architecture) and
        document.eqlString(asset.get("filesystem"), variant.filesystem) and
        document.eqlString(asset.get("flavor"), variant.flavor);
}

/// `size_reduction_percent`.
pub fn sizeReductionPercent(baseline: i64, value: i64) f64 {
    const numerator: f64 = @floatFromInt(baseline - value);
    const denominator: f64 = @floatFromInt(baseline);
    return 100.0 * numerator / denominator;
}

/// `enforce_core_size_gate`.
pub fn enforceCoreSizeGate(
    context: *Context,
    rows: []const Pair,
    minimum_reduction_percent: i64,
) Error!void {
    const threshold = try document.requireReductionPercent(
        context,
        minimum_reduction_percent,
    );
    if (rows.len != 2) return context.fail(
        "core size gate requires both architectures",
        .{},
    );
    for (rows) |row| {
        const architecture = try assetString(context, row.core, "architecture");
        if (try assetInteger(context, row.core, "virtual_size") >
            try assetInteger(context, row.full, "virtual_size"))
        {
            return context.fail("{s} core virtual size regressed", .{architecture});
        }
        const fields = [_][2][]const u8{
            .{ "allocated_size", "allocated" },
            .{ "compressed_size", "compressed/download" },
        };
        for (fields) |pair| {
            const core = try assetInteger(context, row.core, pair[0]);
            const full = try assetInteger(context, row.full, pair[0]);
            // Integer cross-multiplication makes the inclusive threshold
            // boundary exact and keeps the direction visibly full -> core.
            if (core * 100 > full * (100 - threshold)) return context.fail(
                "{s} core {s} size reduction is below {d}%",
                .{ architecture, pair[1], threshold },
            );
        }
    }
}

// ---- Publish manifests ----------------------------------------------------

/// `load_publish_manifest`: everything the publisher is allowed to believe
/// about a staged release, re-derived from the pinned profile tables.
pub fn loadPublishManifest(context: *Context, path: []const u8) Error!Value {
    const value = try candidate_support.readObject(context, path);
    const root = value.object;

    if (!document.eqlString(root.get("type"), candidate_support.release_type)) {
        return context.fail("{s}: not a publish manifest", .{path});
    }
    if (document.integerOf(root.get("schema")) != profiles.candidate_schema) {
        return context.fail("{s}: unsupported schema", .{path});
    }
    const release_set_name = document.stringOf(root.get("release_set")) orelse
        return context.fail("{s}: unexpected release set", .{path});
    const selected = profiles.findReleaseSet(release_set_name) orelse
        return context.fail("{s}: unexpected release set", .{path});
    try candidate_support.validateReleaseTag(
        context,
        release_set_name,
        document.stringOf(root.get("release_tag")),
    );
    if (!contract.isCommitHex(document.stringOf(root.get("source_commit")) orelse "")) {
        return context.fail("{s}: invalid source commit", .{path});
    }
    const assets = document.arrayOf(root.get("assets")) orelse
        return context.fail("{s}: release assets are missing", .{path});
    if (assets.items.len == 0) return context.fail(
        "{s}: release assets are missing",
        .{path},
    );

    var seen: std.ArrayList([]const u8) = .empty;
    for (assets.items) |item| {
        const asset = document.objectOf(item) orelse return context.fail(
            "{s}: invalid release asset",
            .{path},
        );
        const key = document.stringOf(asset.get("variant")) orelse return context.fail(
            "{s}: unexpected or duplicate release variant",
            .{path},
        );
        const expected = profiles.findVariant(key) orelse return context.fail(
            "{s}: unexpected or duplicate release variant",
            .{path},
        );
        for (seen.items) |already| {
            if (std.mem.eql(u8, already, key)) return context.fail(
                "{s}: unexpected or duplicate release variant",
                .{path},
            );
        }
        try seen.append(context.arena, key);

        for (&profiles.profile_keys) |profile_key| {
            const wanted = profiles.profileField(expected, profile_key).?;
            if (!document.eqlString(asset.get(profile_key), wanted)) return context.fail(
                "{s}: {s} {s} does not match profile",
                .{ path, key, profile_key },
            );
        }
        const virtual_size = try document.requirePositiveInt(
            context,
            asset.get("virtual_size"),
            "{s}: {s} virtual size",
            .{ path, key },
        );
        if (virtual_size != @as(i64, @intCast(expected.virtual_size))) {
            return context.fail(
                "{s}: {s} virtual size does not match profile",
                .{ path, key },
            );
        }
        const allocated_size = try document.requirePositiveInt(
            context,
            asset.get("allocated_size"),
            "{s}: {s} allocated size",
            .{ path, key },
        );
        if (allocated_size > virtual_size) return context.fail(
            "{s}: {s} allocated size exceeds virtual size",
            .{ path, key },
        );
        const compressed_size = try document.requirePositiveInt(
            context,
            asset.get("compressed_size"),
            "{s}: {s} compressed size",
            .{ path, key },
        );
        if (document.integerOf(asset.get("bytes")) != compressed_size) {
            return context.fail("{s}: {s} download size does not match", .{ path, key });
        }
        if (!contract.isSha256Hex(document.stringOf(asset.get("sha256")) orelse "")) {
            return context.fail("{s}: {s} SHA-256 must be a lowercase SHA-256", .{
                path,
                key,
            });
        }
        const package_count = try document.requirePositiveInt(
            context,
            asset.get("packages"),
            "{s}: {s} package count",
            .{ path, key },
        );
        const record = document.objectOf(asset.get("package_manifest")) orelse
            return context.fail("{s}: {s} package manifest is missing", .{ path, key });
        const reviewed = profiles.packageManifest(
            expected.filesystem,
            expected.flavor,
        ).?;
        if (document.integerOf(record.get("manifest_revision")) != reviewed.revision) {
            return context.fail(
                "{s}: {s} package manifest revision mismatch",
                .{ path, key },
            );
        }
        if (document.integerOf(record.get("count")) != package_count) {
            return context.fail(
                "{s}: {s} package manifest count mismatch",
                .{ path, key },
            );
        }
        const names = document.arrayOf(record.get("names")) orelse
            return context.fail("{s}: {s} package names are incomplete", .{ path, key });
        if (names.items.len != @as(usize, @intCast(package_count))) {
            return context.fail("{s}: {s} package names are incomplete", .{ path, key });
        }
        var recorded: std.ArrayList([]const u8) = .empty;
        for (names.items) |name_value| {
            const name = document.stringOf(name_value) orelse return context.fail(
                "{s}: {s} package names are invalid or duplicate",
                .{ path, key },
            );
            if (name.len == 0) return context.fail(
                "{s}: {s} package names are invalid or duplicate",
                .{ path, key },
            );
            for (recorded.items) |already| {
                if (std.mem.eql(u8, already, name)) return context.fail(
                    "{s}: {s} package names are invalid or duplicate",
                    .{ path, key },
                );
            }
            try recorded.append(context.arena, name);
        }
        _ = try document.requirePositiveInt(
            context,
            record.get("installed_bytes"),
            "{s}: {s} installed package bytes",
            .{ path, key },
        );
        try candidate_support.verifyPackageManifest(
            context,
            expected.filesystem,
            expected.flavor,
            recorded.items,
        );
        const source = document.objectOf(asset.get("source")) orelse
            return context.fail("{s}: {s} source metadata is missing", .{ path, key });
        if (!document.eqlString(source.get("name"), expected.source_name)) {
            return context.fail("{s}: {s} source name does not match", .{ path, key });
        }
        if (!document.eqlString(source.get("sha256"), expected.source_sha256)) {
            return context.fail("{s}: {s} source sha256 does not match", .{ path, key });
        }
        var url_buffer: [profiles.max_source_url_len]u8 = undefined;
        if (!document.eqlString(source.get("url"), expected.sourceUrl(&url_buffer))) {
            return context.fail("{s}: {s} source URL does not match", .{ path, key });
        }
        _ = try document.requirePositiveInt(
            context,
            source.get("bytes"),
            "{s}: {s} source bytes",
            .{ path, key },
        );
    }
    if (!sameKeySet(seen.items, selected.variants)) return context.fail(
        "{s}: release asset matrix is incomplete or unexpected",
        .{path},
    );
    return value;
}

pub fn sameKeySet(seen: []const []const u8, wanted: []const []const u8) bool {
    if (seen.len != wanted.len) return false;
    for (wanted) |key| {
        var found = false;
        for (seen) |already| {
            if (std.mem.eql(u8, already, key)) found = true;
        }
        if (!found) return false;
    }
    return true;
}

// ---- Recursive manifest discovery -----------------------------------------

/// `Path.rglob(name)` followed by `sorted()`: every matching file under `root`,
/// in a stable order so a duplicate is always reported against the same first
/// occurrence.
pub fn findManifests(
    context: *Context,
    root: []const u8,
    name: []const u8,
) Error![]const []const u8 {
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
        if (!std.mem.eql(u8, std.fs.path.basename(entry.path), name)) continue;
        if (found.items.len >= max_staged_entries) return context.fail(
            "{s}: too many {s} manifests",
            .{ root, name },
        );
        try found.append(
            context.arena,
            try std.fs.path.join(context.arena, &.{ root, entry.path }),
        );
    }
    std.mem.sort([]const u8, found.items, {}, lessThanPath);
    return found.items;
}

fn lessThanPath(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

// ---- stage ----------------------------------------------------------------

pub const StageArguments = struct {
    release_set: []const u8,
    candidates: []const u8,
    source_commit: []const u8,
    release_tag: []const u8,
    release_date: ?[]const u8,
    azure_results: ?[]const u8,
    minimum_core_reduction_percent: i64,
    output: []const u8,
    notes: []const u8,
};

/// `stage_command`.
pub fn stageCommand(context: *Context, arguments: StageArguments) Error!void {
    if (!contract.isCommitHex(arguments.source_commit)) return context.fail(
        "source commit must be a lowercase 40-character SHA",
        .{},
    );
    const selected = try candidate_support.requireReleaseSet(
        context,
        arguments.release_set,
    );
    const identity = try candidate_support.releaseIdentity(
        context,
        arguments.release_set,
        arguments.release_date,
    );
    if (!std.mem.eql(u8, arguments.release_tag, identity.tag)) return context.fail(
        "{s} releases must be tagged {s}",
        .{ arguments.release_set, identity.tag },
    );
    const azure_results = arguments.azure_results orelse return context.fail(
        "{s} releases require --azure-results",
        .{arguments.release_set},
    );

    const wanted = selected.variants;
    const manifests = try findManifests(context, arguments.candidates, "candidate.json");
    if (manifests.len != wanted.len) return context.fail(
        "expected {d} candidate manifests",
        .{wanted.len},
    );

    var keys: std.ArrayList([]const u8) = .empty;
    var candidates: std.ArrayList(candidate_support.ValidatedCandidate) = .empty;
    for (manifests) |manifest_path| {
        const validated = try candidate_support.validateCandidate(
            context,
            manifest_path,
            arguments.source_commit,
        );
        for (keys.items) |already| {
            if (std.mem.eql(u8, already, validated.variant.key)) return context.fail(
                "duplicate {s} candidate",
                .{validated.variant.key},
            );
        }
        try keys.append(context.arena, validated.variant.key);
        try candidates.append(context.arena, validated);
    }
    if (!sameKeySet(keys.items, wanted)) return context.fail(
        "{s} candidate matrix is incomplete or unexpected",
        .{arguments.release_set},
    );

    const minimum_reduction = try document.requireReductionPercent(
        context,
        arguments.minimum_core_reduction_percent,
    );

    var ordered: std.ArrayList(candidate_support.ValidatedCandidate) = .empty;
    for (wanted) |key| try ordered.append(context.arena, findCandidate(candidates.items, key).?);

    var asset_values: std.json.Array = .init(context.arena);
    for (ordered.items) |validated| {
        try asset_values.append(try candidateReleaseAsset(context, validated.value));
    }
    var gate_manifest: std.json.ObjectMap = .empty;
    try gate_manifest.put(context.arena, "schema", .{ .integer = profiles.candidate_schema });
    try gate_manifest.put(context.arena, "type", .{ .string = candidate_support.release_type });
    try gate_manifest.put(context.arena, "release_set", .{ .string = arguments.release_set });
    try gate_manifest.put(context.arena, "release_tag", .{ .string = identity.tag });
    try gate_manifest.put(context.arena, "source_commit", .{ .string = arguments.source_commit });
    try gate_manifest.put(context.arena, "assets", .{ .array = asset_values });
    const rows = try fullCoreRows(context, .{ .object = gate_manifest });
    try enforceCoreSizeGate(context, rows, minimum_reduction);

    const azure_manifests = try findManifests(context, azure_results, "azure-result.json");
    if (azure_manifests.len != wanted.len) return context.fail(
        "expected {d} azure result manifests",
        .{wanted.len},
    );
    var azure_keys: std.ArrayList([]const u8) = .empty;
    var azure_documents: std.ArrayList(Value) = .empty;
    for (azure_manifests) |azure_path| {
        const azure = try validateAzureResult(
            context,
            azure_path,
            arguments.source_commit,
            wanted,
            azure_keys.items,
            candidates.items,
        );
        try azure_keys.append(
            context.arena,
            try recordedString(context, azure.object, "variant"),
        );
        try azure_documents.append(context.arena, azure);
    }
    if (!sameKeySet(azure_keys.items, wanted)) return context.fail(
        "{s} azure result matrix is incomplete or unexpected",
        .{arguments.release_set},
    );

    Dir.cwd().createDirPath(context.io, arguments.output) catch |err|
        return context.fail("cannot create {s}: {t}", .{ arguments.output, err });
    for (ordered.items) |validated| {
        const destination = try std.fs.path.join(context.arena, &.{
            arguments.output,
            validated.variant.asset_name,
        });
        // `replace = false` materializes through a link, so an existing staged
        // asset is refused rather than silently overwritten.
        Dir.cwd().copyFile(
            validated.asset_path,
            Dir.cwd(),
            destination,
            context.io,
            .{ .make_path = true, .replace = false },
        ) catch |err| switch (err) {
            error.PathAlreadyExists => return context.fail(
                "staged asset already exists: {s}",
                .{destination},
            ),
            else => return context.fail(
                "cannot stage {s}: {t}",
                .{ destination, err },
            ),
        };
        const staged = try candidate_support.hashFile(context, destination);
        if (!document.eqlString(validated.get("asset_sha256"), &staged)) {
            return context.fail("staged asset digest mismatch", .{});
        }
    }

    var manifest_assets: std.json.Array = .init(context.arena);
    for (ordered.items) |validated| {
        var asset = (try candidateReleaseAsset(context, validated.value)).object;
        const azure = findAzureResult(
            azure_documents.items,
            validated.variant.key,
        ).?.object;
        var azure_object: std.json.ObjectMap = .empty;
        try azure_object.put(context.arena, "location", azure.get("location").?);
        try azure_object.put(context.arena, "vm_size", azure.get("vm_size").?);
        try azure_object.put(context.arena, "derived_vhd_sha256", azure.get("derived_vhd_sha256").?);
        try azure_object.put(context.arena, "derived_vhd_bytes", azure.get("derived_vhd_bytes").?);
        try azure_object.put(
            context.arena,
            "derived_vhd_current_size",
            azure.get("derived_vhd_current_size").?,
        );
        try azure_object.put(context.arena, "contracts", azure.get("contracts").?);
        try asset.put(context.arena, "azure", .{ .object = azure_object });
        try manifest_assets.append(.{ .object = asset });
    }

    var manifest: std.json.ObjectMap = .empty;
    try manifest.put(context.arena, "schema", .{ .integer = profiles.candidate_schema });
    try manifest.put(context.arena, "type", .{ .string = candidate_support.release_type });
    try manifest.put(context.arena, "release_set", .{ .string = arguments.release_set });
    try manifest.put(context.arena, "release_tag", .{ .string = arguments.release_tag });
    try manifest.put(context.arena, "source_commit", .{ .string = arguments.source_commit });
    try manifest.put(context.arena, "assets", .{ .array = manifest_assets });

    const manifest_path = try std.fs.path.join(context.arena, &.{
        arguments.output,
        "publish-manifest.json",
    });
    try candidate_support.writeDocument(context, manifest_path, .{ .object = manifest });

    const notes = try releaseNotes(context, .{
        .selected = selected,
        .candidates = ordered.items,
        .source_commit = arguments.source_commit,
        .azure_results = azure_documents.items,
        .minimum_core_reduction_percent = minimum_reduction,
        .core_rows = rows,
    });
    try candidate_support.writeText(context, arguments.notes, notes);
}

fn findCandidate(
    candidates: []const candidate_support.ValidatedCandidate,
    key: []const u8,
) ?candidate_support.ValidatedCandidate {
    for (candidates) |validated| {
        if (std.mem.eql(u8, validated.variant.key, key)) return validated;
    }
    return null;
}

fn findAzureResult(documents: []const Value, key: []const u8) ?Value {
    for (documents) |value| {
        if (document.eqlString(value.object.get("variant"), key)) return value;
    }
    return null;
}

/// One `azure-result.json`, bound to the candidate it claims to have accepted.
fn validateAzureResult(
    context: *Context,
    path: []const u8,
    source_commit: []const u8,
    wanted: []const []const u8,
    seen: []const []const u8,
    candidates: []const candidate_support.ValidatedCandidate,
) Error!Value {
    const value = try candidate_support.readObject(context, path);
    const root = value.object;

    if (document.integerOf(root.get("schema")) != profiles.candidate_schema) {
        return context.fail("{s}: unsupported schema", .{path});
    }
    if (!document.eqlString(root.get("type"), candidate_support.azure_result_type)) {
        return context.fail("{s}: unexpected azure result type", .{path});
    }
    const key = document.stringOf(root.get("variant")) orelse return context.fail(
        "{s}: unexpected variant",
        .{path},
    );
    if (!containsKey(wanted, key)) return context.fail(
        "{s}: unexpected variant",
        .{path},
    );
    if (containsKey(seen, key)) return context.fail("duplicate {s} azure result", .{key});

    const candidate = findCandidate(candidates, key).?;
    const expected = candidate.variant;
    for (&profiles.profile_keys) |profile_key| {
        const value_wanted = profiles.profileField(expected, profile_key).?;
        if (!document.eqlString(root.get(profile_key), value_wanted)) return context.fail(
            "{s}: {s} does not match profile",
            .{ path, profile_key },
        );
    }
    if (!document.eqlString(root.get("source_commit"), source_commit)) {
        return context.fail("{s}: source commit mismatch", .{path});
    }
    if (!document.valueEql(
        root.get("qcow_sha256") orelse .{ .null = {} },
        candidate.get("asset_sha256").?,
    )) return context.fail("{s}: QCOW SHA-256 does not match candidate", .{path});

    const bindings = [_][2][]const u8{
        .{ "qcow_virtual_size", "virtual_size" },
        .{ "qcow_allocated_size", "allocated_size" },
        .{ "qcow_compressed_size", "compressed_size" },
    };
    for (bindings) |binding| {
        if (document.integerOf(root.get(binding[0])) !=
            document.integerOf(candidate.get(binding[1])))
        {
            return context.fail(
                "{s}: QCOW {s} does not match candidate",
                .{ path, binding[1] },
            );
        }
    }
    if (!document.eqlString(root.get("status"), "success")) return context.fail(
        "{s}: status is not success",
        .{path},
    );
    const derived_bytes = document.integerOf(root.get("derived_vhd_bytes"));
    const derived_current = document.integerOf(root.get("derived_vhd_current_size"));
    const alignment: i64 = @intCast(azure_vhd.alignment);
    const footer: i64 = @intCast(azure_vhd.footer_bytes);
    if (derived_bytes == null or derived_current == null or
        derived_current.? <= 0 or
        @mod(derived_current.?, alignment) != 0 or
        derived_bytes.? != derived_current.? + footer)
    {
        return context.fail("{s}: derived VHD size evidence is inconsistent", .{path});
    }
    try document.requireSha256(
        context,
        document.stringOf(root.get("derived_vhd_sha256")) orelse "",
        "derived VHD SHA-256",
    );
    _ = try document.requireNonEmpty(
        context,
        document.stringOf(root.get("location")) orelse "",
        "location",
    );
    _ = try document.requireNonEmpty(
        context,
        document.stringOf(root.get("vm_size")) orelse "",
        "vm_size",
    );
    _ = try document.requireNonEmpty(
        context,
        document.stringOf(root.get("resource_group")) orelse "",
        "resource_group",
    );
    if (!contractsEqual(
        root.get("contracts"),
        profiles.azureContracts(expected.filesystem).?,
    )) return context.fail(
        "{s}: contracts do not match required Azure contracts",
        .{path},
    );
    const workflow = document.objectOf(root.get("workflow")) orelse
        return context.fail("{s}: workflow is missing", .{path});
    const run_id = try document.requireNonEmpty(
        context,
        document.stringOf(workflow.get("run_id")) orelse "",
        "run_id",
    );
    const run_attempt = try document.requireNonEmpty(
        context,
        document.stringOf(workflow.get("run_attempt")) orelse "",
        "run_attempt",
    );
    const validation = try recordedObject(context, candidate.object(), "validation");
    if (!document.eqlString(validation.get("run_id"), run_id) or
        !document.eqlString(validation.get("run_attempt"), run_attempt))
    {
        return context.fail("{s}: workflow identity does not match candidate", .{path});
    }
    return value;
}

fn containsKey(keys: []const []const u8, wanted: []const u8) bool {
    for (keys) |key| if (std.mem.eql(u8, key, wanted)) return true;
    return false;
}

fn contractsEqual(value: ?Value, expected: []const []const u8) bool {
    const items = document.arrayOf(value) orelse return false;
    if (items.items.len != expected.len) return false;
    for (items.items, expected) |item, wanted| {
        if (!document.eqlString(item, wanted)) return false;
    }
    return true;
}

// ---- Release notes --------------------------------------------------------

pub const NotesArguments = struct {
    selected: *const profiles.ReleaseSet,
    candidates: []const candidate_support.ValidatedCandidate,
    source_commit: []const u8,
    azure_results: ?[]const Value,
    minimum_core_reduction_percent: i64,
    core_rows: ?[]const Pair,
};

/// `release_notes`.
pub fn releaseNotes(context: *Context, arguments: NotesArguments) Error![]const u8 {
    var out: Writer.Allocating = .init(context.arena);
    const writer = &out.writer;
    const first = arguments.candidates[0];
    const filesystem = first.variant.filesystem;
    var upper_buffer: [16]u8 = undefined;
    const upper = std.ascii.upperString(&upper_buffer, filesystem);

    line(writer, "{s}", .{arguments.selected.summary});
    line(writer, "", .{});
    line(writer, "## Highlights", .{});
    line(writer, "", .{});
    for (arguments.selected.highlights) |highlight| line(writer, "- {s}", .{highlight});
    line(writer, "- Both architectures passed dual-instance UEFI QEMU acceptance " ++
        "with NoCloud provisioning, key-only SSH, reboot, and identity " ++
        "separation.", .{});
    line(writer, "- Images include Azure Agent, generic and Hyper-V DHCP " ++
        "configuration, and FreeBSD's Azure serial-console settings.", .{});

    if (arguments.core_rows) |rows| {
        line(writer, "", .{});
        line(writer, "## Full {s} versus core evidence", .{upper});
        line(writer, "", .{});
        line(writer, "| Architecture | Full virtual | Core virtual | " ++
            "Virtual reduction | Full allocated | Core allocated | " ++
            "Allocated reduction | Full compressed/download | " ++
            "Core compressed/download | Compressed reduction | " ++
            "Full packages | Core packages | Full SHA-256 | " ++
            "Core SHA-256 |", .{});
        line(writer, "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: " ++
            "| ---: | ---: | ---: | ---: | --- | --- |", .{});
        for (rows) |row| {
            const full_virtual = try assetInteger(context, row.full, "virtual_size");
            const core_virtual = try assetInteger(context, row.core, "virtual_size");
            const full_allocated = try assetInteger(context, row.full, "allocated_size");
            const core_allocated = try assetInteger(context, row.core, "allocated_size");
            const full_compressed = try assetInteger(
                context,
                row.full,
                "compressed_size",
            );
            const core_compressed = try assetInteger(
                context,
                row.core,
                "compressed_size",
            );
            line(
                writer,
                "| {s} | {d} | {d} | {d:.1}% | {d} | {d} | {d:.1}% | {d} | {d} " ++
                    "| {d:.1}% | {d} | {d} | `{s}` | `{s}` |",
                .{
                    try assetString(context, row.core, "architecture"),
                    full_virtual,
                    core_virtual,
                    sizeReductionPercent(full_virtual, core_virtual),
                    full_allocated,
                    core_allocated,
                    sizeReductionPercent(full_allocated, core_allocated),
                    full_compressed,
                    core_compressed,
                    sizeReductionPercent(full_compressed, core_compressed),
                    try assetInteger(context, row.full, "packages"),
                    try assetInteger(context, row.core, "packages"),
                    try assetString(context, row.full, "sha256"),
                    try assetString(context, row.core, "sha256"),
                },
            );
        }
        line(writer, "", .{});
        line(writer, "Both architectures passed the staging gate requiring at " ++
            "least {d}% reduction in qemu-img allocated size and " ++
            "compressed/download size. Core virtual size may not exceed its " ++
            "matching same-source full {s} asset.", .{
            arguments.minimum_core_reduction_percent,
            upper,
        });
    }

    if (anyCore(arguments.candidates)) {
        const manifest = profiles.packageManifest(filesystem, "core").?;
        line(writer, "", .{});
        line(writer, "## Core package contract", .{});
        line(writer, "", .{});
        line(writer, "- Reviewed manifest revision: {d}", .{manifest.revision});
        line(writer, "- The core package set is dependency-closed and realized by " ++
            "`pkg`; it is not produced by ad hoc deletion from a full image.", .{});
        line(writer, "- Retained package roots:", .{});
        line(writer, "", .{});
        line(writer, "```", .{});
        for (manifest.required) |name| line(writer, "{s}", .{name});
        for (manifest.library_roots) |name| line(writer, "{s}", .{name});
        line(writer, "```", .{});
        line(writer, "", .{});
        line(writer, "- Reviewed package exclusions:", .{});
        line(writer, "", .{});
        line(writer, "```", .{});
        for (manifest.excluded) |name| line(writer, "{s}", .{name});
        line(writer, "```", .{});
        line(writer, "", .{});
        writer.writeAll("- Excluded FreeBSD pkgbase name classes: ") catch
            return error.OutOfMemory;
        for (manifest.excluded_classes, 0..) |name, index| {
            if (index > 0) writer.writeAll(", ") catch return error.OutOfMemory;
            writer.print("`{s}`", .{name}) catch return error.OutOfMemory;
        }
        writer.writeByte('\n') catch return error.OutOfMemory;
    }

    line(writer, "", .{});
    line(writer, "## Installed packages", .{});
    line(writer, "", .{});
    line(writer, "| Asset | Manifest revision | Packages | Installed bytes |", .{});
    line(writer, "| --- | ---: | ---: | ---: |", .{});
    for (arguments.candidates) |validated| {
        const packages = try recordedObject(context, validated.object(), "packages");
        line(writer, "| `{s}` | {d} | {d} | {d} |", .{
            validated.variant.asset_name,
            try recordedInteger(context, packages, "manifest_revision"),
            try recordedInteger(context, packages, "count"),
            try recordedInteger(context, packages, "installed_bytes"),
        });
    }
    for (arguments.candidates) |validated| {
        const packages = try recordedObject(context, validated.object(), "packages");
        line(writer, "", .{});
        line(writer, "<details><summary>{s} package manifest</summary>", .{
            validated.variant.asset_name,
        });
        line(writer, "", .{});
        line(writer, "```", .{});
        for ((try recordedArray(context, packages, "names")).items) |name| {
            line(writer, "{s}", .{document.stringOf(name) orelse return context.fail(
                "recorded package name is not a string",
                .{},
            )});
        }
        line(writer, "```", .{});
        line(writer, "", .{});
        line(writer, "</details>", .{});
    }

    line(writer, "", .{});
    line(writer, "## Provenance", .{});
    line(writer, "", .{});
    line(writer, "- Source commit: `{s}`", .{arguments.source_commit});
    for (arguments.candidates) |validated| {
        const source = try recordedObject(context, validated.object(), "source");
        const validation = try recordedObject(context, validated.object(), "validation");
        line(writer, "- {s} source: `{s}`", .{
            validated.variant.key,
            try recordedString(context, source, "name"),
        });
        line(writer, "  - URL: {s}", .{try recordedString(context, source, "url")});
        line(writer, "  - File size: {d} bytes", .{
            try recordedInteger(context, source, "bytes"),
        });
        line(writer, "  - SHA-256: `{s}`", .{
            try recordedString(context, source, "sha256"),
        });
        line(writer, "  - QEMU acceptance: `{s}` on `{s}`; passed dual-instance " ++
            "UEFI provisioning, SSH, reboot, identity separation, disk growth, " ++
            "and clean shutdown.", .{
            try recordedString(context, validation, "qemu_version"),
            try recordedString(context, validation, "runner"),
        });
    }
    if (arguments.core_rows != null) {
        line(writer, "- Full and core {s} candidates were built in this dispatch " ++
            "from the same source commit and the same architecture-specific " ++
            "pinned source name, URL, and SHA-256.", .{upper});
    }

    if (arguments.azure_results) |results| {
        line(writer, "", .{});
        line(writer, "## Azure validation", .{});
        line(writer, "", .{});
        line(writer, "- Exact-candidate matching-architecture Gen2 validation is " ++
            "complete for every published release asset.", .{});
        for (arguments.candidates) |validated| {
            const found = findAzureResult(results, validated.variant.key) orelse
                return context.fail(
                    "no Azure result for {s}",
                    .{validated.variant.key},
                );
            const azure = found.object;
            line(writer, "- {s}: `{s}` / `{s}`", .{
                validated.variant.key,
                try recordedString(context, azure, "location"),
                try recordedString(context, azure, "vm_size"),
            });
            line(writer, "  - Derived VHD SHA-256: `{s}`", .{
                try recordedString(context, azure, "derived_vhd_sha256"),
            });
            line(writer, "  - Derived VHD size: {d} bytes", .{
                try recordedInteger(context, azure, "derived_vhd_bytes"),
            });
            line(writer, "  - Derived VHD current size: {d} bytes", .{
                try recordedInteger(context, azure, "derived_vhd_current_size"),
            });
            writer.writeAll("  - Passed contracts: ") catch return error.OutOfMemory;
            const contracts = try recordedArray(context, azure, "contracts");
            for (contracts.items, 0..) |name, index| {
                if (index > 0) writer.writeAll(", ") catch return error.OutOfMemory;
                writer.print("`{s}`", .{document.stringOf(name) orelse
                    return context.fail("recorded contract is not a string", .{})}) catch
                    return error.OutOfMemory;
            }
            writer.writeByte('\n') catch return error.OutOfMemory;
        }
        line(writer, "", .{});
        line(writer, "The QCOW2 assets are not directly uploadable to Azure. " ++
            "Validation was completed on aligned fixed VHDs derived with " ++
            "`miz azure derive` from these exact release candidates.", .{});
    } else {
        line(writer, "", .{});
        line(writer, "The QCOW2 assets are not directly uploadable to Azure. " ++
            "Derive an aligned fixed VHD with `miz azure derive` before upload. " ++
            "The exact release candidates were validated under UEFI QEMU; this " ++
            "release does not claim exact-candidate Azure validation.", .{});
    }

    line(writer, "", .{});
    // `"\n".join(lines)` with a trailing empty element: every line above ends
    // with a newline and the document has no final blank line.
    line(writer, "No `.sha256` or package-manifest sidecar assets are published.", .{});
    return out.written();
}

fn anyCore(candidates: []const candidate_support.ValidatedCandidate) bool {
    for (candidates) |validated| {
        if (std.mem.eql(u8, validated.variant.flavor, "core")) return true;
    }
    return false;
}

fn line(writer: *Writer, comptime fmt: []const u8, args: anytype) void {
    writer.print(fmt ++ "\n", args) catch {};
}

// ---- compare --------------------------------------------------------------

/// `compare_command`: the full-versus-core size comparison within one staged
/// set, as a Markdown table.
pub fn compareReport(context: *Context, manifest_path: []const u8) Error![]const u8 {
    const manifest = try loadPublishManifest(context, manifest_path);
    const rows = try fullCoreRows(context, manifest);

    var out: Writer.Allocating = .init(context.arena);
    const writer = &out.writer;
    line(writer, "| Architecture | Full virtual | Core virtual | Virtual reduction | " ++
        "Full allocated | Core allocated | Allocated reduction | " ++
        "Full compressed/download | Core compressed/download | " ++
        "Compressed reduction | Full packages | Core packages |", .{});
    line(writer, "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: " ++
        "| ---: | ---: | ---: |", .{});
    for (rows) |row| {
        const full_virtual = try assetInteger(context, row.full, "virtual_size");
        const core_virtual = try assetInteger(context, row.core, "virtual_size");
        const full_allocated = try assetInteger(context, row.full, "allocated_size");
        const core_allocated = try assetInteger(context, row.core, "allocated_size");
        const full_compressed = try assetInteger(context, row.full, "compressed_size");
        const core_compressed = try assetInteger(context, row.core, "compressed_size");
        line(
            writer,
            "| {s} | {d} | {d} | {d:.1}% | {d} | {d} | {d:.1}% | {d} | {d} " ++
                "| {d:.1}% | {d} | {d} |",
            .{
                try assetString(context, row.core, "architecture"),
                full_virtual,
                core_virtual,
                sizeReductionPercent(full_virtual, core_virtual),
                full_allocated,
                core_allocated,
                sizeReductionPercent(full_allocated, core_allocated),
                full_compressed,
                core_compressed,
                sizeReductionPercent(full_compressed, core_compressed),
                try assetInteger(context, row.full, "packages"),
                try assetInteger(context, row.core, "packages"),
            },
        );
    }
    return out.written();
}

test "size reduction is rendered the way the Python f-string rendered it" {
    var buffer: [64]u8 = undefined;
    try std.testing.expectEqualStrings(
        "20.0",
        try std.fmt.bufPrint(&buffer, "{d:.1}", .{sizeReductionPercent(1000, 800)}),
    );
    try std.testing.expectEqualStrings(
        "10.0",
        try std.fmt.bufPrint(&buffer, "{d:.1}", .{sizeReductionPercent(1000, 900)}),
    );
    try std.testing.expectEqualStrings(
        "0.0",
        try std.fmt.bufPrint(&buffer, "{d:.1}", .{sizeReductionPercent(1000, 1000)}),
    );
    try std.testing.expectEqualStrings(
        "-0.1",
        try std.fmt.bufPrint(&buffer, "{d:.1}", .{sizeReductionPercent(1000, 1001)}),
    );
    try std.testing.expectEqualStrings(
        "72.3",
        try std.fmt.bufPrint(&buffer, "{d:.1}", .{sizeReductionPercent(1000, 277)}),
    );
}

test "key sets compare without regard to order" {
    const wanted = [_][]const u8{ "a", "b", "c" };
    try std.testing.expect(sameKeySet(&.{ "c", "a", "b" }, &wanted));
    try std.testing.expect(!sameKeySet(&.{ "c", "a" }, &wanted));
    try std.testing.expect(!sameKeySet(&.{ "c", "a", "d" }, &wanted));
}
