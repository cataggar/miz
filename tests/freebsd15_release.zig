//! The FreeBSD 15.1 release contract, replacing `tests/freebsd15_release_test.py`.
//!
//! Two kinds of check live here. The behavioural ones drive real candidate
//! trees through the release tooling and assert on what it produced or refused
//! -- a release helper that cannot reject a bad candidate is the whole risk
//! this suite exists to remove. The contract ones read the tracked tree and
//! assert that the pinned tables still agree with the Zig builder and the
//! reviewed package manifest, that the workflow and shell scripts still invoke
//! the tooling with the arguments it accepts, and that validation mode still
//! cannot reach a release mutation.

const std = @import("std");
const freebsd15 = @import("freebsd15");
const support = @import("support");

const Allocator = std.mem.Allocator;
const Value = std.json.Value;
const candidate_support = freebsd15.candidate;
const cli = freebsd15.cli;
const document = freebsd15.document;
const profiles = freebsd15.profiles;
const publication = freebsd15.publication;
const staging = freebsd15.staging;
const Context = freebsd15.Context;
const Tree = support.Tree;

const zfs_variants = [_][]const u8{
    "aarch64-zfs-full",
    "x86_64-zfs-full",
    "aarch64-zfs-core",
    "x86_64-zfs-core",
};

const StageOptions = struct {
    release_tag: ?[]const u8 = null,
    release_date: ?[]const u8 = support.release_date,
    azure_results: bool = true,
    minimum_core_reduction_percent: i64 = profiles.core_minimum_reduction_percent,
};

fn stage(
    tree: *Tree,
    context: *Context,
    release_set: []const u8,
    options: StageOptions,
) !void {
    const identity = candidate_support.releaseIdentity(
        context,
        release_set,
        support.release_date,
    ) catch |err| return err;
    return staging.stageCommand(context, .{
        .release_set = release_set,
        .candidates = try tree.path(&.{"candidates"}),
        .source_commit = support.source_commit,
        .release_tag = options.release_tag orelse identity.tag,
        .release_date = options.release_date,
        .azure_results = if (options.azure_results)
            try tree.path(&.{"azure-results"})
        else
            null,
        .minimum_core_reduction_percent = options.minimum_core_reduction_percent,
        .output = try tree.path(&.{"output"}),
        .notes = try tree.path(&.{"notes.md"}),
    });
}

const ZfsSizes = struct {
    full_allocated: u64 = 1000,
    full_compressed: u64 = 1000,
    core_allocated: u64 = 800,
    core_compressed: u64 = 800,
    azure: bool = true,
};

fn makeZfsCandidates(tree: *Tree, gpa: Allocator, sizes: ZfsSizes) !void {
    for (zfs_variants) |key| {
        const full = std.mem.eql(u8, profiles.findVariant(key).?.flavor, "full");
        _ = try support.makeCandidate(tree, gpa, key, .{
            .allocated_size = if (full) sizes.full_allocated else sizes.core_allocated,
            .compressed_size = if (full) sizes.full_compressed else sizes.core_compressed,
        });
        if (sizes.azure) _ = try support.makeAzureResult(tree, gpa, key);
    }
}

fn stagedZfsRelease(tree: *Tree, context: *Context, gpa: Allocator) !void {
    try makeZfsCandidates(tree, gpa, .{});
    try stage(tree, context, "zfs", .{});
}

fn expectFailure(context: *const Context, needle: []const u8) !void {
    try support.expectContains(context.message(), needle);
}

// ---- Candidate documents --------------------------------------------------

test "candidate records all three sizes from validated inputs" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const key = "aarch64-ufs-core";

    const path = try support.makeCandidate(&tree, gpa, key, .{
        .allocated_size = 700,
        .compressed_size = 123,
    });
    const raw = try tree.readAbsolute(path);
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    const root = parsed.value.object;

    try std.testing.expectEqual(@as(i64, 3), document.integerOf(root.get("schema")).?);
    try std.testing.expectEqual(
        @as(i64, @intCast(profiles.findVariant(key).?.virtual_size)),
        document.integerOf(root.get("virtual_size")).?,
    );
    try std.testing.expectEqual(
        @as(i64, 700),
        document.integerOf(root.get("allocated_size")).?,
    );
    try std.testing.expectEqual(
        @as(i64, 123),
        document.integerOf(root.get("compressed_size")).?,
    );
    const validation = root.get("validation").?.object;
    try std.testing.expectEqual(
        @as(i64, 700),
        document.integerOf(validation.get("qemu_image").?.object.get("allocated_size")).?,
    );
    const qemu_info = validation.get("qemu_info").?.object;
    try std.testing.expectEqualStrings(
        "aarch64-ufs-core-qemu-info.json",
        document.stringOf(qemu_info.get("name")).?,
    );
    var context = tree.context(gpa);
    const beside = try tree.path(&.{
        "candidates", key, "aarch64-ufs-core-qemu-info.json",
    });
    const digest = try candidate_support.hashFile(&context, beside);
    try std.testing.expectEqualStrings(&digest, document.stringOf(qemu_info.get("sha256")).?);
}

test "candidate refuses every unpinned source claim" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const key = "aarch64-zfs-full";
    const variant = profiles.findVariant(key).?;

    const asset_relative = try std.fmt.allocPrint(
        tree.allocator(),
        "loose/{s}",
        .{variant.asset_name},
    );
    const asset = try tree.write(asset_relative, "candidate\n");
    const package_manifest = try support.writePackageManifest(
        &tree,
        key,
        "loose",
        &.{},
        &.{},
    );
    const qemu_info = try support.writeQemuInfo(&tree, key, "loose", 800);
    var context = tree.context(gpa);
    const digest = try candidate_support.hashFile(&context, asset);
    var url_buffer: [profiles.max_source_url_len]u8 = undefined;
    const base: candidate_support.CandidateArguments = .{
        .architecture = variant.architecture,
        .filesystem = variant.filesystem,
        .flavor = variant.flavor,
        .package_manifest = package_manifest,
        .asset = asset,
        .validated_sha256 = try tree.allocator().dupe(u8, &digest),
        .virtual_size = @intCast(variant.virtual_size),
        .qemu_info = qemu_info,
        .source_name = variant.source_name,
        .source_url = try tree.allocator().dupe(u8, variant.sourceUrl(&url_buffer)),
        .source_sha256 = variant.source_sha256,
        .source_bytes = 123456789,
        .source_commit = support.source_commit,
        .qemu_version = "QEMU emulator version 10.0.2",
        .runner = variant.runner,
        .run_id = "5001",
        .run_attempt = "7",
        .output = try tree.path(&.{"candidate.json"}),
    };

    var bad_digest = base;
    bad_digest.source_sha256 = "0" ** 64;
    try std.testing.expectError(
        error.Invalid,
        candidate_support.candidateCommand(&context, bad_digest),
    );
    try expectFailure(&context, "source SHA-256 does not match");

    var bad_name = base;
    bad_name.source_name = profiles.findVariant("aarch64-ufs-full").?.source_name;
    try std.testing.expectError(
        error.Invalid,
        candidate_support.candidateCommand(&context, bad_name),
    );
    try expectFailure(&context, "source filename does not match");

    var bad_url = base;
    bad_url.source_url = "https://example.invalid/image.qcow2.xz";
    try std.testing.expectError(
        error.Invalid,
        candidate_support.candidateCommand(&context, bad_url),
    );
    try expectFailure(&context, "source URL does not match");

    var bad_size = base;
    bad_size.virtual_size = 1;
    try std.testing.expectError(
        error.Invalid,
        candidate_support.candidateCommand(&context, bad_size),
    );
    try expectFailure(&context, "virtual size does not match");

    var bad_validation = base;
    bad_validation.validated_sha256 = "0" ** 64;
    try std.testing.expectError(
        error.Invalid,
        candidate_support.candidateCommand(&context, bad_validation),
    );
    try expectFailure(&context, "validated SHA-256 does not match");

    // The unmodified arguments are accepted, so each rejection above is the
    // single claim it names and not an artefact of the fixture.
    try candidate_support.candidateCommand(&context, base);
}

test "candidate refuses a qemu-img document without an allocated size" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const key = "aarch64-ufs-core";
    const variant = profiles.findVariant(key).?;

    const asset_relative = try std.fmt.allocPrint(
        tree.allocator(),
        "loose/{s}",
        .{variant.asset_name},
    );
    const asset = try tree.write(asset_relative, "candidate\n");
    const qemu_info = try support.writeQemuInfo(&tree, key, "loose", 800);
    try support.mutateDocument(&tree, qemu_info, "actual-size", null);

    var context = tree.context(gpa);
    const digest = try candidate_support.hashFile(&context, asset);
    var url_buffer: [profiles.max_source_url_len]u8 = undefined;
    try std.testing.expectError(error.Invalid, candidate_support.candidateCommand(
        &context,
        .{
            .architecture = variant.architecture,
            .filesystem = variant.filesystem,
            .flavor = variant.flavor,
            .package_manifest = try support.writePackageManifest(
                &tree,
                key,
                "loose",
                &.{},
                &.{},
            ),
            .asset = asset,
            .validated_sha256 = try tree.allocator().dupe(u8, &digest),
            .virtual_size = @intCast(variant.virtual_size),
            .qemu_info = qemu_info,
            .source_name = variant.source_name,
            .source_url = try tree.allocator().dupe(u8, variant.sourceUrl(&url_buffer)),
            .source_sha256 = variant.source_sha256,
            .source_bytes = 123456789,
            .source_commit = support.source_commit,
            .qemu_version = "QEMU emulator version 10.0.2",
            .runner = variant.runner,
            .run_id = "5001",
            .run_attempt = "7",
            .output = try tree.path(&.{"candidate.json"}),
        },
    ));
    try expectFailure(&context, "qemu-img allocated size");
}

test "candidate refuses a cross-filesystem asset name" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const key = "aarch64-zfs-core";
    const wrong = profiles.findVariant("aarch64-zfs-full").?;

    const asset_relative = try std.fmt.allocPrint(
        tree.allocator(),
        "loose/{s}",
        .{wrong.asset_name},
    );
    const asset = try tree.write(asset_relative, "candidate\n");
    var context = tree.context(gpa);
    const digest = try candidate_support.hashFile(&context, asset);
    const variant = profiles.findVariant(key).?;
    var url_buffer: [profiles.max_source_url_len]u8 = undefined;
    try std.testing.expectError(error.Invalid, candidate_support.candidateCommand(
        &context,
        .{
            .architecture = variant.architecture,
            .filesystem = variant.filesystem,
            .flavor = variant.flavor,
            .package_manifest = try support.writePackageManifest(
                &tree,
                key,
                "loose",
                &.{},
                &.{},
            ),
            .asset = asset,
            .validated_sha256 = try tree.allocator().dupe(u8, &digest),
            .virtual_size = @intCast(variant.virtual_size),
            .qemu_info = try support.writeQemuInfo(&tree, key, "loose", 800),
            .source_name = variant.source_name,
            .source_url = try tree.allocator().dupe(u8, variant.sourceUrl(&url_buffer)),
            .source_sha256 = variant.source_sha256,
            .source_bytes = 123456789,
            .source_commit = support.source_commit,
            .qemu_version = "QEMU emulator version 10.0.2",
            .runner = variant.runner,
            .run_id = "5001",
            .run_attempt = "7",
            .output = try tree.path(&.{"candidate.json"}),
        },
    ));
    try expectFailure(&context, "asset must be");
}

test "core candidates refuse a manifest that broke the reviewed contract" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();

    const cases = [_]struct {
        key: []const u8,
        extra: []const []const u8,
        drop: []const []const u8,
        message: []const u8,
    }{
        .{
            .key = "aarch64-ufs-core",
            .extra = &.{},
            .drop = &.{"FreeBSD-ssh"},
            .message = "missing FreeBSD-ssh",
        },
        .{
            .key = "x86_64-ufs-core",
            .extra = &.{"FreeBSD-clang"},
            .drop = &.{},
            .message = "still carries FreeBSD-clang",
        },
    };
    for (cases, 0..) |case, index| {
        const variant = profiles.findVariant(case.key).?;
        const directory = try std.fmt.allocPrint(tree.allocator(), "case{d}", .{index});
        const asset_relative = try std.fmt.allocPrint(
            tree.allocator(),
            "{s}/{s}",
            .{ directory, variant.asset_name },
        );
        const asset = try tree.write(asset_relative, "candidate\n");
        var context = tree.context(gpa);
        const digest = try candidate_support.hashFile(&context, asset);
        var url_buffer: [profiles.max_source_url_len]u8 = undefined;
        try std.testing.expectError(error.Invalid, candidate_support.candidateCommand(
            &context,
            .{
                .architecture = variant.architecture,
                .filesystem = variant.filesystem,
                .flavor = variant.flavor,
                .package_manifest = try support.writePackageManifest(
                    &tree,
                    case.key,
                    directory,
                    case.extra,
                    case.drop,
                ),
                .asset = asset,
                .validated_sha256 = try tree.allocator().dupe(u8, &digest),
                .virtual_size = @intCast(variant.virtual_size),
                .qemu_info = try support.writeQemuInfo(&tree, case.key, directory, 800),
                .source_name = variant.source_name,
                .source_url = try tree.allocator().dupe(
                    u8,
                    variant.sourceUrl(&url_buffer),
                ),
                .source_sha256 = variant.source_sha256,
                .source_bytes = 123456789,
                .source_commit = support.source_commit,
                .qemu_version = "QEMU emulator version 10.0.2",
                .runner = variant.runner,
                .run_id = "5001",
                .run_attempt = "7",
                .output = try tree.path(&.{ directory, "candidate.json" }),
            },
        ));
        try expectFailure(&context, case.message);
    }
}

// ---- Staging --------------------------------------------------------------

test "staging produces exactly the four-asset ZFS release" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try stagedZfsRelease(&tree, &context, gpa);

    const manifest_path = try tree.path(&.{ "output", "publish-manifest.json" });
    const raw = try tree.readAbsolute(manifest_path);
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    const root = parsed.value.object;
    try std.testing.expectEqualStrings(
        "zfs",
        document.stringOf(root.get("release_set")).?,
    );
    try std.testing.expectEqualStrings(
        "FreeBSD-15.1-" ++ support.release_date,
        document.stringOf(root.get("release_tag")).?,
    );

    const assets = root.get("assets").?.array;
    try std.testing.expectEqual(@as(usize, 4), assets.items.len);
    for (assets.items) |item| {
        const asset = item.object;
        try std.testing.expectEqualStrings(
            "zfs",
            document.stringOf(asset.get("filesystem")).?,
        );
        const azure = asset.get("azure").?.object;
        try std.testing.expectEqualStrings(
            "eastus2",
            document.stringOf(azure.get("location")).?,
        );
        try std.testing.expectEqualStrings(
            "Standard_D2s_v5",
            document.stringOf(azure.get("vm_size")).?,
        );
        const derived_bytes = document.integerOf(azure.get("derived_vhd_bytes")).?;
        const derived_current = document.integerOf(
            azure.get("derived_vhd_current_size"),
        ).?;
        try std.testing.expect(derived_bytes > 0);
        try std.testing.expectEqual(derived_current + 512, derived_bytes);
        const contracts = azure.get("contracts").?.array;
        try std.testing.expectEqual(
            profiles.azure_contracts_default.len,
            contracts.items.len,
        );
        for (contracts.items, profiles.azure_contracts_default) |claimed, wanted| {
            try std.testing.expectEqualStrings(wanted, document.stringOf(claimed).?);
        }
    }

    // The staging tree is the exact publication allowlist.
    try support.expectNames(try tree.list("output"), &.{
        "FreeBSD-15.1-aarch64.qcow2",
        "FreeBSD-15.1-x86_64.qcow2",
        "FreeBSD-15.1-aarch64.core.qcow2",
        "FreeBSD-15.1-x86_64.core.qcow2",
        "publish-manifest.json",
    });

    const notes = try tree.read("notes.md");
    try support.expectContains(notes, "## Full ZFS versus core evidence");
    try support.expectContains(notes, "full and core ZFS");
    try support.expectContains(notes, "zpool_reguid");
    try support.expectContains(notes, "every published release asset");
    try support.expectContains(notes, "## Azure validation");
    try support.expectContains(
        notes,
        "Exact-candidate matching-architecture Gen2 validation",
    );
    try support.expectContains(notes, "eastus2");
    try support.expectContains(notes, "Standard_D2s_v5");
    try support.expectContains(
        notes,
        "No `.sha256` or package-manifest sidecar assets",
    );
    try support.expectContains(notes, support.source_commit);
    try support.expectAbsent(notes, "baseline package manifests");
    try support.expectAbsent(
        notes,
        "does not claim exact-candidate Azure validation",
    );
}

test "staging refuses an incomplete or unexpected candidate matrix" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    _ = try support.makeCandidate(&tree, gpa, "aarch64-zfs-full", .{});
    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
    try expectFailure(&context, "expected 4 candidate manifests");

    _ = try support.makeCandidate(&tree, gpa, "x86_64-zfs-full", .{});
    _ = try support.makeCandidate(&tree, gpa, "aarch64-zfs-core", .{});
    _ = try support.makeCandidate(&tree, gpa, "x86_64-ufs-full", .{});
    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
    try expectFailure(&context, "incomplete or unexpected");
}

test "staging refuses a tag belonging to another release" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{});

    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{
        .release_tag = "FreeBSD-15.1-20260724",
    }));
    try expectFailure(&context, "must be tagged");
}

test "staging requires Azure results" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{ .azure = false });

    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{
        .azure_results = false,
    }));
    try expectFailure(&context, "zfs releases require --azure-results");
}

test "staging refuses a changed or cross-commit candidate" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    try makeZfsCandidates(&tree, gpa, .{});
    _ = try tree.write(
        "candidates/x86_64-zfs-full/FreeBSD-15.1-x86_64.qcow2",
        "tampered candidate\n",
    );
    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
    try std.testing.expect(
        support.contains(context.message(), "candidate size mismatch") or
            support.contains(context.message(), "candidate digest mismatch"),
    );

    var second = try Tree.create(gpa);
    defer second.deinit();
    var second_context = second.context(gpa);
    for (zfs_variants) |key| {
        const cross = std.mem.eql(u8, key, "x86_64-zfs-full");
        _ = try support.makeCandidate(&second, gpa, key, .{
            .source_commit = if (cross) "b" ** 40 else support.source_commit,
        });
        _ = try support.makeAzureResult(&second, gpa, key);
    }
    try std.testing.expectError(
        error.Invalid,
        stage(&second, &second_context, "zfs", .{}),
    );
    try expectFailure(&second_context, "source commit mismatch");
}

test "staging refuses every corrupted candidate size claim" {
    const gpa = std.testing.allocator;
    const cases = [_]struct {
        key: []const u8,
        field: []const u8,
        value: ?[]const u8,
        message: []const u8,
    }{
        .{
            .key = "aarch64-zfs-core",
            .field = "allocated_size",
            .value = null,
            .message = "allocated size",
        },
        .{
            .key = "x86_64-zfs-core",
            .field = "allocated_size",
            .value = "801",
            .message = "qemu-img size metadata mismatch",
        },
        .{
            .key = "aarch64-zfs-core",
            .field = "schema",
            .value = "2",
            .message = "unsupported schema",
        },
    };
    for (cases) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var context = tree.context(gpa);
        try makeZfsCandidates(&tree, gpa, .{});
        const manifest = try tree.path(&.{ "candidates", case.key, "candidate.json" });
        try support.mutateDocument(&tree, manifest, case.field, case.value);
        try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
        try expectFailure(&context, case.message);
    }
}

test "staging refuses a tampered qemu-img validation input" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{});

    const qemu_info = try tree.path(&.{
        "candidates",
        "aarch64-zfs-core",
        "aarch64-zfs-core-qemu-info.json",
    });
    try support.mutateDocument(&tree, qemu_info, "actual-size", "801");
    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
    try expectFailure(&context, "qemu-img validation input mismatch");
}

test "staging refuses a candidate whose recorded manifest was edited" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{});

    const manifest = try tree.path(&.{
        "candidates", "x86_64-zfs-core", "candidate.json",
    });
    try support.appendToDocumentArray(
        &tree,
        manifest,
        "packages.names",
        "\"FreeBSD-tests\"",
    );
    const raw = try tree.readAbsolute(manifest);
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    const count = document.integerOf(
        parsed.value.object.get("packages").?.object.get("count"),
    ).?;
    const bumped = try std.fmt.allocPrint(tree.allocator(), "{d}", .{count + 1});
    try support.mutateDocument(&tree, manifest, "packages.count", bumped);

    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
    try expectFailure(&context, "still carries FreeBSD-tests");
}

// ---- Azure results --------------------------------------------------------

const AzureResultOptions = struct {
    key: []const u8 = "x86_64-zfs-full",
    contracts: ?[]const u8 = null,
    vhd_sha256: []const u8 = "f" ** 64,
    location: []const u8 = "westus3",
    manifest_key: ?[]const u8 = null,
};

fn runAzureResult(
    tree: *Tree,
    context: *Context,
    gpa: Allocator,
    options: AzureResultOptions,
) !Value {
    const manifest_key = options.manifest_key orelse options.key;
    const manifest = try tree.path(&.{
        "candidates", manifest_key, "candidate.json",
    });
    if (!candidate_support.isRegularFile(std.testing.io, manifest)) {
        _ = try support.makeCandidate(tree, gpa, manifest_key, .{});
    }
    const variant = profiles.findVariant(manifest_key).?;
    const asset = try tree.path(&.{ "candidates", manifest_key, variant.asset_name });
    const output = try std.fmt.allocPrint(
        tree.allocator(),
        "{s}-azure-result.json",
        .{options.key},
    );
    const output_path = try tree.path(&.{output});

    var contracts_text: std.Io.Writer.Allocating = .init(tree.allocator());
    for (profiles.azureContracts(variant.filesystem).?, 0..) |name, index| {
        if (index > 0) try contracts_text.writer.writeByte(',');
        try contracts_text.writer.writeAll(name);
    }
    try candidate_support.azureResultCommand(context, .{
        .manifest = manifest,
        .asset = asset,
        .key = options.key,
        .source_commit = support.source_commit,
        .vhd_sha256 = options.vhd_sha256,
        .vhd_bytes = 1024 * 1024 + 512,
        .vhd_current_size = 1024 * 1024,
        .contracts = options.contracts orelse contracts_text.written(),
        .location = options.location,
        .vm_size = "Standard_D4s_v5",
        .resource_group = "rg-acceptance",
        .run_id = "5001",
        .run_attempt = "7",
        .output = output_path,
    });
    const raw = try tree.readAbsolute(output_path);
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    return parsed.value;
}

test "azure-result emits a complete, candidate-bound document" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const candidate_path = try support.makeCandidate(
        &tree,
        gpa,
        "x86_64-zfs-full",
        .{},
    );
    const candidate_raw = try tree.readAbsolute(candidate_path);
    const candidate = (try std.json.parseFromSlice(
        Value,
        tree.allocator(),
        candidate_raw,
        .{},
    )).value.object;

    const value = try runAzureResult(&tree, &context, gpa, .{});
    const root = value.object;
    try std.testing.expectEqual(
        profiles.candidate_schema,
        document.integerOf(root.get("schema")).?,
    );
    try std.testing.expectEqualStrings(
        "miz-freebsd15-azure-acceptance",
        document.stringOf(root.get("type")).?,
    );
    try std.testing.expectEqualStrings(
        "x86_64-zfs-full",
        document.stringOf(root.get("variant")).?,
    );
    try std.testing.expectEqualStrings(
        "x86_64",
        document.stringOf(root.get("architecture")).?,
    );
    try std.testing.expectEqualStrings(
        "zfs",
        document.stringOf(root.get("filesystem")).?,
    );
    try std.testing.expectEqualStrings(
        "full",
        document.stringOf(root.get("flavor")).?,
    );
    try std.testing.expectEqualStrings(
        profiles.findVariant("x86_64-zfs-full").?.asset_name,
        document.stringOf(root.get("asset_name")).?,
    );
    try std.testing.expectEqualStrings(
        support.source_commit,
        document.stringOf(root.get("source_commit")).?,
    );
    try std.testing.expectEqualStrings(
        document.stringOf(candidate.get("asset_sha256")).?,
        document.stringOf(root.get("qcow_sha256")).?,
    );
    for ([_][2][]const u8{
        .{ "qcow_virtual_size", "virtual_size" },
        .{ "qcow_allocated_size", "allocated_size" },
        .{ "qcow_compressed_size", "compressed_size" },
    }) |binding| {
        try std.testing.expectEqual(
            document.integerOf(candidate.get(binding[1])).?,
            document.integerOf(root.get(binding[0])).?,
        );
    }
    try std.testing.expect(root.get("azure_accepted_sha256") == null);
    try std.testing.expectEqualStrings(
        "f" ** 64,
        document.stringOf(root.get("derived_vhd_sha256")).?,
    );
    try std.testing.expectEqual(
        @as(i64, 1024 * 1024 + 512),
        document.integerOf(root.get("derived_vhd_bytes")).?,
    );
    try std.testing.expectEqual(
        @as(i64, 1024 * 1024),
        document.integerOf(root.get("derived_vhd_current_size")).?,
    );
    try std.testing.expectEqualStrings(
        "success",
        document.stringOf(root.get("status")).?,
    );
    try std.testing.expectEqualStrings(
        "westus3",
        document.stringOf(root.get("location")).?,
    );
    try std.testing.expectEqualStrings(
        "Standard_D4s_v5",
        document.stringOf(root.get("vm_size")).?,
    );
    try std.testing.expectEqualStrings(
        "rg-acceptance",
        document.stringOf(root.get("resource_group")).?,
    );
    const workflow = root.get("workflow").?.object;
    try std.testing.expectEqualStrings("5001", document.stringOf(workflow.get("run_id")).?);
    try std.testing.expectEqualStrings(
        "7",
        document.stringOf(workflow.get("run_attempt")).?,
    );
}

test "azure-result supports the UFS full and core contract lists" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "x86_64-ufs-full", "aarch64-ufs-core" }) |key| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var context = tree.context(gpa);
        const value = try runAzureResult(&tree, &context, gpa, .{ .key = key });
        const root = value.object;
        try std.testing.expectEqualStrings(
            "ufs",
            document.stringOf(root.get("filesystem")).?,
        );
        const contracts = root.get("contracts").?.array;
        const expected = profiles.azureContracts("ufs").?;
        try std.testing.expectEqual(expected.len, contracts.items.len);
        for (contracts.items, expected) |claimed, wanted| {
            try std.testing.expectEqualStrings(wanted, document.stringOf(claimed).?);
        }
    }
}

test "azure-result refuses cross-filesystem contracts, a wrong key, and bad evidence" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    var zfs_contracts: std.Io.Writer.Allocating = .init(tree.allocator());
    for (profiles.azure_contracts_default, 0..) |name, index| {
        if (index > 0) try zfs_contracts.writer.writeByte(',');
        try zfs_contracts.writer.writeAll(name);
    }

    try std.testing.expectError(error.Invalid, runAzureResult(&tree, &context, gpa, .{
        .key = "x86_64-ufs-full",
        .contracts = zfs_contracts.written(),
    }));
    try expectFailure(&context, "contracts");

    try std.testing.expectError(error.Invalid, runAzureResult(&tree, &context, gpa, .{
        .key = "aarch64-zfs-full",
        .manifest_key = "x86_64-zfs-full",
    }));
    try expectFailure(&context, "variant");

    try std.testing.expectError(error.Invalid, runAzureResult(&tree, &context, gpa, .{
        .vhd_sha256 = "not-a-sha",
    }));
    try expectFailure(&context, "VHD SHA-256");

    try std.testing.expectError(error.Invalid, runAzureResult(&tree, &context, gpa, .{
        .contracts = "key-only-ssh,agent-ready",
    }));
    try expectFailure(&context, "contracts");

    try std.testing.expectError(error.Invalid, runAzureResult(&tree, &context, gpa, .{
        .location = "",
    }));
    try expectFailure(&context, "location");
}

test "staging binds every Azure result to its candidate and workflow" {
    const gpa = std.testing.allocator;
    const cases = [_]struct {
        key: []const u8,
        field: []const u8,
        value: ?[]const u8,
        message: []const u8,
    }{
        .{
            .key = "x86_64-zfs-core",
            .field = "schema",
            .value = "2",
            .message = "unsupported schema",
        },
        .{
            .key = "x86_64-zfs-full",
            .field = "qcow_sha256",
            .value = "\"" ++ "0" ** 64 ++ "\"",
            .message = "QCOW SHA-256",
        },
        .{
            .key = "x86_64-zfs-core",
            .field = "qcow_allocated_size",
            .value = "801",
            .message = "does not match candidate",
        },
        .{
            .key = "x86_64-zfs-core",
            .field = "qcow_compressed_size",
            .value = "999",
            .message = "does not match candidate",
        },
        .{
            .key = "x86_64-zfs-full",
            .field = "source_commit",
            .value = "\"" ++ "b" ** 40 ++ "\"",
            .message = "source commit mismatch",
        },
        .{
            .key = "x86_64-zfs-core",
            .field = "contracts",
            .value = "[\"matching-architecture-gen2\"]",
            .message = "contracts",
        },
        .{
            .key = "x86_64-zfs-full",
            .field = "derived_vhd_current_size",
            .value = "8388608",
            .message = "size evidence",
        },
        .{
            .key = "x86_64-zfs-full",
            .field = "workflow.run_attempt",
            .value = "\"8\"",
            .message = "workflow identity",
        },
        .{
            .key = "x86_64-zfs-full",
            .field = "status",
            .value = "\"failed\"",
            .message = "status is not success",
        },
    };
    for (cases) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var context = tree.context(gpa);
        try makeZfsCandidates(&tree, gpa, .{});
        const path = try tree.path(&.{
            "azure-results", case.key, "azure-result.json",
        });
        try support.mutateDocument(&tree, path, case.field, case.value);
        try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
        try expectFailure(&context, case.message);
    }
}

test "staging refuses a missing or duplicated Azure result" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{});
    try tree.remove("azure-results/aarch64-zfs-full");
    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
    try expectFailure(&context, "expected 4 azure result");

    var second = try Tree.create(gpa);
    defer second.deinit();
    var second_context = second.context(gpa);
    try makeZfsCandidates(&second, gpa, .{});
    const path = try second.path(&.{
        "azure-results", "x86_64-zfs-core", "azure-result.json",
    });
    try support.mutateDocument(&second, path, "variant", "\"aarch64-zfs-full\"");
    try std.testing.expectError(
        error.Invalid,
        stage(&second, &second_context, "zfs", .{}),
    );
    try expectFailure(&second_context, "duplicate aarch64-zfs-full");
}

// ---- Size gate, pairing, and comparison -----------------------------------

test "the core size gate accepts the threshold boundary on both architectures" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{
        .core_allocated = 900,
        .core_compressed = 900,
    });
    try stage(&tree, &context, "zfs", .{ .minimum_core_reduction_percent = 10 });

    const raw = try tree.read("output/publish-manifest.json");
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    var saw_full = false;
    var saw_core = false;
    for (parsed.value.object.get("assets").?.array.items) |item| {
        const flavor = document.stringOf(item.object.get("flavor")).?;
        if (std.mem.eql(u8, flavor, "full")) saw_full = true;
        if (std.mem.eql(u8, flavor, "core")) saw_core = true;
    }
    try std.testing.expect(saw_full and saw_core);
}

test "the core size gate refuses a regression on either measured size" {
    const gpa = std.testing.allocator;

    var allocated = try Tree.create(gpa);
    defer allocated.deinit();
    var allocated_context = allocated.context(gpa);
    try makeZfsCandidates(&allocated, gpa, .{
        .core_allocated = 900,
        .core_compressed = 900,
    });
    _ = try support.makeCandidate(&allocated, gpa, "x86_64-zfs-core", .{
        .allocated_size = 901,
        .compressed_size = 900,
    });
    _ = try support.makeAzureResult(&allocated, gpa, "x86_64-zfs-core");
    try std.testing.expectError(error.Invalid, stage(
        &allocated,
        &allocated_context,
        "zfs",
        .{ .minimum_core_reduction_percent = 10 },
    ));
    try expectFailure(
        &allocated_context,
        "x86_64 core allocated size reduction is below 10%",
    );

    var compressed = try Tree.create(gpa);
    defer compressed.deinit();
    var compressed_context = compressed.context(gpa);
    try makeZfsCandidates(&compressed, gpa, .{
        .core_allocated = 900,
        .core_compressed = 900,
    });
    _ = try support.makeCandidate(&compressed, gpa, "aarch64-zfs-core", .{
        .allocated_size = 900,
        .compressed_size = 901,
    });
    _ = try support.makeAzureResult(&compressed, gpa, "aarch64-zfs-core");
    try std.testing.expectError(error.Invalid, stage(
        &compressed,
        &compressed_context,
        "zfs",
        .{ .minimum_core_reduction_percent = 10 },
    ));
    try expectFailure(
        &compressed_context,
        "aarch64 core compressed/download size reduction is below 10%",
    );
}

test "the core size gate honours a reviewed threshold override" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{
        .core_allocated = 850,
        .core_compressed = 850,
    });
    try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{
        .minimum_core_reduction_percent = 20,
    }));
    try expectFailure(&context, "below 20%");
}

test "the core size gate refuses a zero or no-op threshold" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    for ([_]i64{ 0, 100 }) |threshold| {
        try std.testing.expectError(
            error.Invalid,
            document.requireReductionPercent(&context, threshold),
        );
        try expectFailure(&context, "from 1 to 99");
    }
}

test "full and core pairing refuses a source or identity mismatch" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try stagedZfsRelease(&tree, &context, gpa);
    const manifest_path = try tree.path(&.{ "output", "publish-manifest.json" });

    const raw = try tree.readAbsolute(manifest_path);
    var parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    for (parsed.value.object.get("assets").?.array.items) |item| {
        if (!document.eqlString(item.object.get("variant"), "aarch64-zfs-core")) continue;
        const source = item.object.getPtr("source").?;
        const bytes = document.integerOf(source.object.get("bytes")).?;
        try source.object.put(tree.allocator(), "bytes", .{ .integer = bytes + 1 });
    }
    try std.testing.expectError(
        error.Invalid,
        staging.fullCoreRows(&context, parsed.value),
    );
    try expectFailure(&context, "pinned sources differ");

    var again = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    for (again.value.object.get("assets").?.array.items) |item| {
        if (!document.eqlString(item.object.get("variant"), "aarch64-zfs-core")) continue;
        var asset = item.object;
        try asset.put(tree.allocator(), "architecture", .{ .string = "x86_64" });
    }
    try std.testing.expectError(
        error.Invalid,
        staging.fullCoreRows(&context, again.value),
    );
    try expectFailure(&context, "identity is invalid");
}

test "compare reports every size for both architectures" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try stagedZfsRelease(&tree, &context, gpa);

    const manifest_path = try tree.path(&.{ "output", "publish-manifest.json" });
    const report = try staging.compareReport(&context, manifest_path);
    try support.expectContains(report, "| aarch64 |");
    try support.expectContains(report, "| x86_64 |");
    try support.expectContains(report, "Full virtual");
    try support.expectContains(report, "Full allocated");
    try support.expectContains(report, "Full compressed/download");
    try support.expectContains(report, "| 1000 | 800 | 20.0%");
    try support.expectContains(report, "6477643776");
    try support.expectContains(report, "6477840384");

    try support.mutateDocument(&tree, manifest_path, "schema", "2");
    try std.testing.expectError(
        error.Invalid,
        staging.compareReport(&context, manifest_path),
    );
    try expectFailure(&context, "unsupported schema");
}

// ---- Matrices, describe, and release identity -----------------------------

fn renderCommand(
    context: *Context,
    comptime handler: anytype,
    args: anytype,
) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(context.arena);
    try @call(.auto, handler, args ++ .{&out.writer});
    return out.written();
}

test "the build matrix covers exactly the release assets" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const text = try renderCommand(&context, cli.matrixCommand, .{ &context, "zfs" });
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), text, .{});
    const include = parsed.value.object.get("include").?.array;
    const selected = profiles.findReleaseSet("zfs").?;
    try std.testing.expectEqual(selected.variants.len, include.items.len);
    for (include.items, selected.variants) |item, key| {
        const entry = item.object;
        const variant = profiles.findVariant(key).?;
        try std.testing.expectEqualStrings(key, document.stringOf(entry.get("variant")).?);
        try std.testing.expectEqualStrings(
            variant.asset_name,
            document.stringOf(entry.get("asset_name")).?,
        );
        try std.testing.expectEqualStrings(
            variant.source_sha256,
            document.stringOf(entry.get("source_sha256")).?,
        );
        try std.testing.expectEqual(
            @as(i64, @intCast(variant.virtual_size)),
            document.integerOf(entry.get("virtual_size")).?,
        );
        const url = document.stringOf(entry.get("source_url")).?;
        try std.testing.expect(std.mem.startsWith(u8, url, profiles.source_url_prefix));
        const suffix = try std.fmt.allocPrint(
            tree.allocator(),
            "/{s}",
            .{document.stringOf(entry.get("source_name")).?},
        );
        try std.testing.expect(std.mem.endsWith(u8, url, suffix));
        try std.testing.expectEqualStrings(
            "release",
            document.stringOf(entry.get("release_role")).?,
        );
    }

    var count: std.Io.Writer.Allocating = .init(tree.allocator());
    try cli.includeCountCommand(&context, text, &count.writer);
    try std.testing.expectEqualStrings("4\n", count.written());
}

test "the Azure matrix is exact for the gated release set" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const text = try renderCommand(
        &context,
        cli.azureMatrixCommand,
        .{ &context, "zfs" },
    );
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), text, .{});
    const include = parsed.value.object.get("include").?.array;
    const selected = profiles.findReleaseSet("zfs").?;
    try std.testing.expectEqual(selected.variants.len, include.items.len);
    for (include.items, selected.variants) |item, key| {
        const entry = item.object;
        const variant = profiles.findVariant(key).?;
        try std.testing.expectEqualStrings(key, document.stringOf(entry.get("key")).?);
        try std.testing.expectEqualStrings(
            variant.architecture,
            document.stringOf(entry.get("architecture")).?,
        );
        try std.testing.expectEqualStrings(
            variant.filesystem,
            document.stringOf(entry.get("filesystem")).?,
        );
        try std.testing.expectEqualStrings(
            variant.flavor,
            document.stringOf(entry.get("flavor")).?,
        );
        try std.testing.expectEqualStrings(
            variant.asset_name,
            document.stringOf(entry.get("asset_name")).?,
        );
        const arm64 = std.mem.eql(u8, variant.architecture, "aarch64");
        try std.testing.expectEqualStrings(
            if (arm64) "AZURE_LOCATION_ARM64" else "AZURE_LOCATION_X64",
            document.stringOf(entry.get("location_variable")).?,
        );
        try std.testing.expectEqualStrings(
            if (arm64) "AZURE_VM_SIZE_ARM64" else "AZURE_VM_SIZE_X64",
            document.stringOf(entry.get("size_variable")).?,
        );
    }

    var count: std.Io.Writer.Allocating = .init(tree.allocator());
    try cli.includeCountCommand(&context, text, &count.writer);
    try std.testing.expectEqualStrings("4\n", count.written());
}

test "describe reports the selected release set and its gate" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    var out: std.Io.Writer.Allocating = .init(tree.allocator());
    try cli.describeCommand(&context, "zfs", support.release_date, &out.writer);
    try support.expectContains(
        out.written(),
        "release_tag=FreeBSD-15.1-" ++ support.release_date ++ "\n",
    );
    try support.expectContains(
        out.written(),
        "release_title=FreeBSD 15.1 - " ++ support.release_date ++ "\n",
    );
    try support.expectContains(out.written(), "asset_count=4\n");
    try support.expectContains(out.written(), "core_minimum_reduction_percent=10\n");

    for ([_]?[]const u8{ null, "", "2026073", "20260230" }) |value| {
        var scratch: std.Io.Writer.Allocating = .init(tree.allocator());
        try std.testing.expectError(
            error.Invalid,
            cli.describeCommand(&context, "zfs", value, &scratch.writer),
        );
        try expectFailure(&context, "release date");
    }
}

test "reserved historical tags are refused as release identities" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    try std.testing.expectError(
        error.Invalid,
        candidate_support.releaseIdentity(&context, "zfs", "20260724"),
    );
    try expectFailure(&context, "belongs to historical full UFS release");

    try std.testing.expectError(
        error.Invalid,
        candidate_support.validateReleaseTag(&context, "zfs", "FreeBSD-15.1-20260724"),
    );
    try expectFailure(&context, "belongs to historical full UFS release");

    try std.testing.expect(profiles.reservedTag("FreeBSD-15.1-zfs-20260729") != null);
    try std.testing.expectError(error.Invalid, candidate_support.validateReleaseTag(
        &context,
        "zfs",
        "FreeBSD-15.1-zfs-20260729",
    ));
    try expectFailure(&context, "release date");
}

test "release sets partition every published variant exactly once" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    var claimed: std.ArrayList([]const u8) = .empty;
    var tags: std.ArrayList([]const u8) = .empty;
    var names: std.ArrayList([]const u8) = .empty;
    for (profiles.release_sets) |selected| {
        for (selected.variants) |key| {
            const variant = profiles.findVariant(key).?;
            try std.testing.expectEqualStrings("zfs", variant.filesystem);
            for (claimed.items) |already| {
                try std.testing.expect(!std.mem.eql(u8, already, key));
            }
            try claimed.append(tree.allocator(), key);
            for (names.items) |already| {
                try std.testing.expect(!std.mem.eql(u8, already, variant.asset_name));
            }
            try names.append(tree.allocator(), variant.asset_name);
        }
        const identity = try candidate_support.releaseIdentity(
            &context,
            selected.name,
            support.release_date,
        );
        for (tags.items) |already| {
            try std.testing.expect(!std.mem.eql(u8, already, identity.tag));
        }
        try tags.append(tree.allocator(), identity.tag);
    }
    try std.testing.expectEqual(profiles.release_sets.len, tags.items.len);
}

test "unsupported variant combinations fail closed" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    for ([_][3][]const u8{
        .{ "riscv64", "ufs", "core" },
        .{ "x86_64", "ufs", "minimal" },
    }) |triple| {
        try std.testing.expectError(error.Invalid, candidate_support.requireVariant(
            &context,
            triple[0],
            triple[1],
            triple[2],
        ));
        try expectFailure(&context, "unsupported");
    }
}

// ---- The reviewed package contract ----------------------------------------

test "recorded package manifests parse exactly the builder's grammar" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    for ([_][]const u8{ "", "FreeBSD-runtime 15.1\n", "a 1 x\n", "a 1 2\na 2 3\n" }) |text| {
        const path = try tree.write("packages.txt", text);
        try std.testing.expectError(
            error.Invalid,
            candidate_support.parsePackageManifest(&context, path),
        );
    }
    const path = try tree.write("packages.txt", "FreeBSD-runtime 15.1 2048\n");
    const packages = try candidate_support.parsePackageManifest(&context, path);
    try std.testing.expectEqual(@as(usize, 1), packages.len);
    try std.testing.expectEqualStrings("FreeBSD-runtime", packages[0].name);
    try std.testing.expectEqualStrings("15.1", packages[0].version);
    try std.testing.expectEqual(@as(i64, 2048), packages[0].installed_bytes);
}

test "the retained contract covers every required capability" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    // Each entry is a capability the retain-at-minimum list names and the
    // package that must still deliver it in a core image.
    const contract = [_][2][]const u8{
        .{ "UEFI boot", "FreeBSD-bootloader" },
        .{ "release kernel", "FreeBSD-kernel-generic" },
        .{ "virtio and Hyper-V", "FreeBSD-hyperv-tools" },
        .{ "rc", "FreeBSD-rc" },
        .{ "sysrc configuration", "FreeBSD-bsdconfig" },
        .{ "user and account management", "FreeBSD-runtime" },
        .{ "DNS", "FreeBSD-resolvconf" },
        .{ "DHCP", "FreeBSD-dhclient" },
        .{ "certificates", "FreeBSD-caroot" },
        .{ "entropy and time", "FreeBSD-ntp" },
        .{ "key-only OpenSSH", "FreeBSD-ssh" },
        .{ "recovery tools", "FreeBSD-rescue" },
        .{ "nuageinit provisioning", "FreeBSD-nuageinit" },
        .{ "pkg", "pkg" },
        .{ "FreeBSD-base updates", "FreeBSD-pkg-bootstrap" },
        .{ "Azure Agent", "azure-agent" },
    };
    for (contract) |clause| {
        const package = clause[1];
        var shared = false;
        for (profiles.shared_required_packages) |name| {
            if (std.mem.eql(u8, name, package)) shared = true;
        }
        try std.testing.expect(shared);
        for (profiles.package_manifests) |manifest| {
            var required = false;
            for (manifest.required) |name| {
                if (std.mem.eql(u8, name, package)) required = true;
            }
            try std.testing.expect(required);
            for (manifest.excluded) |name| {
                try std.testing.expect(!std.mem.eql(u8, name, package));
            }

            var without: std.ArrayList([]const u8) = .empty;
            for (manifest.required) |name| {
                if (std.mem.eql(u8, name, package)) continue;
                try without.append(tree.allocator(), name);
            }
            try std.testing.expectError(
                error.Invalid,
                candidate_support.verifyPackageManifest(
                    &context,
                    manifest.filesystem,
                    manifest.flavor,
                    without.items,
                ),
            );
            const expected = try std.fmt.allocPrint(
                tree.allocator(),
                "missing {s}",
                .{package},
            );
            try expectFailure(&context, expected);
        }
    }

    for ([_]struct { filesystem: []const u8, own: [2][]const u8, other: [2][]const u8 }{
        .{
            .filesystem = "ufs",
            .own = .{ "FreeBSD-ufs", "FreeBSD-ufs-lib" },
            .other = .{ "FreeBSD-zfs", "FreeBSD-zfs-lib" },
        },
        .{
            .filesystem = "zfs",
            .own = .{ "FreeBSD-zfs", "FreeBSD-zfs-lib" },
            .other = .{ "FreeBSD-ufs", "FreeBSD-ufs-lib" },
        },
    }) |case| {
        for ([_][]const u8{ "full", "core" }) |flavor| {
            const manifest = profiles.packageManifest(case.filesystem, flavor).?;
            for (case.own) |package| {
                var found = false;
                for (manifest.required) |name| {
                    if (std.mem.eql(u8, name, package)) found = true;
                }
                try std.testing.expect(found);
            }
            for (case.other) |package| {
                for (manifest.required) |name| {
                    try std.testing.expect(!std.mem.eql(u8, name, package));
                }
            }
        }
    }
}

test "core retains the exact sysrc provider without the broad sets" {
    const core = profiles.packageManifest("zfs", "core").?;
    try std.testing.expectEqual(@as(i64, 3), profiles.package_manifest_revision);
    var found = false;
    for (core.required) |name| {
        if (std.mem.eql(u8, name, "FreeBSD-bsdconfig")) found = true;
    }
    try std.testing.expect(found);
    for ([_][]const u8{
        "FreeBSD-set-base",
        "FreeBSD-set-devel",
        "FreeBSD-set-optional",
    }) |broad| {
        for (core.required) |name| {
            try std.testing.expect(!std.mem.eql(u8, name, broad));
        }
        var excluded = false;
        for (core.excluded) |name| {
            if (std.mem.eql(u8, name, broad)) excluded = true;
        }
        try std.testing.expect(excluded);
    }
}

test "manifest verification refuses excluded content and excluded classes" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const required = profiles.packageManifest("zfs", "core").?.required;
    try candidate_support.verifyPackageManifest(&context, "zfs", "core", required);

    for ([_][]const u8{
        "FreeBSD-clang",
        "FreeBSD-runtime-dbg",
        "FreeBSD-clibs-dev",
    }) |name| {
        var carried: std.ArrayList([]const u8) = .empty;
        try carried.appendSlice(tree.allocator(), required);
        try carried.append(tree.allocator(), name);
        try std.testing.expectError(
            error.Invalid,
            candidate_support.verifyPackageManifest(
                &context,
                "zfs",
                "core",
                carried.items,
            ),
        );
        try expectFailure(&context, "still carries");
    }

    // A third-party package that merely ends in an excluded class is not a
    // pkgbase family member, and the full flavor excludes nothing.
    var third_party: std.ArrayList([]const u8) = .empty;
    try third_party.appendSlice(tree.allocator(), required);
    try third_party.append(tree.allocator(), "py312-dev");
    try candidate_support.verifyPackageManifest(
        &context,
        "zfs",
        "core",
        third_party.items,
    );

    var full: std.ArrayList([]const u8) = .empty;
    try full.appendSlice(tree.allocator(), required);
    try full.append(tree.allocator(), "FreeBSD-clang");
    try candidate_support.verifyPackageManifest(&context, "zfs", "full", full.items);
}

// ---- Agreement with the Zig builder and the reviewed manifest --------------

/// The quoted strings of a `pub const NAME = [_][]const u8{ ... };` literal.
fn zigStringList(
    allocator: Allocator,
    source: []const u8,
    name: []const u8,
) ![]const []const u8 {
    const header = try std.fmt.allocPrint(
        allocator,
        "pub const {s} = [_][]const u8{{",
        .{name},
    );
    defer allocator.free(header);
    const start = try support.indexOf(source, header);
    const end = try support.indexFrom(source, "\n};", start);
    return quotedStrings(allocator, source[start + header.len .. end]);
}

fn quotedStrings(allocator: Allocator, body: []const u8) ![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    var index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, body, index, '"')) |open| {
        const close = std.mem.indexOfScalarPos(u8, body, open + 1, '"') orelse break;
        try found.append(allocator, body[open + 1 .. close]);
        index = close + 1;
    }
    return found.items;
}

/// The value of a `.field = ` assignment starting at `from`, up to the comma
/// that ends it.
fn zigField(source: []const u8, field: []const u8, from: usize) !struct {
    value: []const u8,
    end: usize,
} {
    const marker = try std.fmt.allocPrint(
        std.testing.allocator,
        ".{s} = ",
        .{field},
    );
    defer std.testing.allocator.free(marker);
    const at = try support.indexFrom(source, marker, from);
    const start = at + marker.len;
    const end = try support.indexFrom(source, ",", start);
    return .{ .value = source[start..end], .end = end };
}

fn unquote(text: []const u8) []const u8 {
    if (text.len >= 2 and text[0] == '"' and text[text.len - 1] == '"') {
        return text[1 .. text.len - 1];
    }
    return text;
}

fn parseUnderscoredInt(text: []const u8) !u64 {
    var digits: [32]u8 = undefined;
    var length: usize = 0;
    for (text) |character| {
        if (character == '_') continue;
        digits[length] = character;
        length += 1;
    }
    return std.fmt.parseInt(u64, digits[0..length], 10);
}

test "the pinned variant table matches the Zig builder profiles" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const whole = try support.readSource(
        tree.allocator(),
        "scripts/build_generalized_freebsd15.zig",
    );
    // The declared profile table only; later files restate the same triples in
    // test data, which is not a second source of truth.
    const source = try support.between(whole, "const profiles = [_]Profile{", "\n};");

    var seen: std.ArrayList([]const u8) = .empty;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, ".architecture = .")) |at| {
        const architecture = try zigField(source, "architecture", at);
        const flavor = try zigField(source, "flavor", architecture.end);
        const storage = try zigField(source, "root_storage", flavor.end);
        const source_name = try zigField(source, "source_name", storage.end);
        const source_url = try zigField(source, "source_url", source_name.end);
        const source_sha256 = try zigField(source, "source_sha256", source_url.end);
        const virtual_size = try zigField(source, "virtual_size", source_sha256.end);
        const output = try zigField(source, "output", virtual_size.end);
        index = output.end;

        const storage_suffix = "_root_storage";
        try std.testing.expect(std.mem.endsWith(u8, storage.value, storage_suffix));
        const filesystem =
            storage.value[0 .. storage.value.len - storage_suffix.len];
        const variant = profiles.variantFor(
            architecture.value[1..],
            filesystem,
            flavor.value[1..],
        ).?;
        for (seen.items) |already| {
            try std.testing.expect(!std.mem.eql(u8, already, variant.key));
        }
        try seen.append(tree.allocator(), variant.key);

        try std.testing.expectEqualStrings(
            variant.source_name,
            unquote(source_name.value),
        );
        var url_buffer: [profiles.max_source_url_len]u8 = undefined;
        try std.testing.expectEqualStrings(
            variant.sourceUrl(&url_buffer),
            unquote(source_url.value),
        );
        try std.testing.expectEqualStrings(
            variant.source_sha256,
            unquote(source_sha256.value),
        );
        try std.testing.expectEqual(
            variant.virtual_size,
            try parseUnderscoredInt(virtual_size.value),
        );
        try std.testing.expectEqualStrings(variant.asset_name, unquote(output.value));
    }
    // Every builder profile is a release variant, and the builder covers at
    // least every variant the ZFS release set publishes.
    try std.testing.expectEqual(profiles.variants.len, seen.items.len);
}

test "the pinned package tables match the reviewed Zig manifest" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const allocator = tree.allocator();
    const source = try support.readSource(
        allocator,
        "scripts/freebsd15_package_manifest.zig",
    );

    // `.name = "X",` followed by `.source = .Y,` is one required package.
    var required: std.ArrayList([]const u8) = .empty;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, ".name = \"")) |at| {
        const start = at + ".name = \"".len;
        const close = try support.indexFrom(source, "\"", start);
        const name = source[start..close];
        const tail = source[close..@min(source.len, close + 64)];
        index = close + 1;
        if (std.mem.indexOf(u8, tail, ".source = .") == null) continue;
        try required.append(allocator, name);
    }

    const filesystem_packages = [_][]const u8{
        "FreeBSD-ufs",
        "FreeBSD-ufs-lib",
        "FreeBSD-zfs",
        "FreeBSD-zfs-lib",
    };
    var shared: std.ArrayList([]const u8) = .empty;
    for (required.items) |name| {
        var is_filesystem = false;
        for (filesystem_packages) |package| {
            if (std.mem.eql(u8, package, name)) is_filesystem = true;
        }
        if (is_filesystem) continue;
        try shared.append(allocator, name);
    }
    try std.testing.expectEqual(
        profiles.shared_required_packages.len,
        shared.items.len,
    );
    for (profiles.shared_required_packages, shared.items) |wanted, claimed| {
        try std.testing.expectEqualStrings(wanted, claimed);
    }
    for (filesystem_packages) |package| {
        const marker = try std.fmt.allocPrint(allocator, ".name = \"{s}\"", .{package});
        try support.expectContains(source, marker);
    }
    try std.testing.expectEqual(
        @as(usize, 2),
        profiles.ufs_required_packages.len + profiles.zfs_required_packages.len - 2,
    );

    for ([_][2][]const u8{
        .{ "library_roots", "library_roots" },
        .{ "core_excluded_packages", "core_excluded_packages" },
        .{ "core_excluded_classes", "core_excluded_classes" },
    }) |pair| {
        const claimed = try zigStringList(allocator, source, pair[1]);
        const wanted: []const []const u8 = if (std.mem.eql(u8, pair[0], "library_roots"))
            &profiles.library_roots
        else if (std.mem.eql(u8, pair[0], "core_excluded_packages"))
            &profiles.core_excluded_packages
        else
            &profiles.core_excluded_classes;
        try std.testing.expectEqual(wanted.len, claimed.len);
        for (wanted, claimed) |expected, actual| {
            try std.testing.expectEqualStrings(expected, actual);
        }
    }

    try std.testing.expectEqual(@as(i64, 3), profiles.package_manifest_revision);
    try support.expectContains(source, ".revision = 3,");
    const flavors = try support.between(source, "pub fn parse(", "}\n");
    try support.expectContains(flavors, "\"full\"");
    try support.expectContains(flavors, "\"core\"");

    var filesystems: usize = 0;
    for ([_][]const u8{ "ufs", "zfs" }) |filesystem| {
        if (profiles.hasFilesystem(filesystem)) filesystems += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), filesystems);
}

// ---- Publication helpers --------------------------------------------------

test "the staged expectation table is the exact publication allowlist" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try stagedZfsRelease(&tree, &context, gpa);
    const manifest_path = try tree.path(&.{ "output", "publish-manifest.json" });

    var out: std.Io.Writer.Allocating = .init(tree.allocator());
    try publication.stagedExpected(&context, manifest_path, "zfs", &out.writer);
    var lines: usize = 0;
    var iterator = std.mem.splitScalar(u8, out.written(), '\n');
    while (iterator.next()) |line| {
        if (line.len == 0) continue;
        lines += 1;
        var fields = std.mem.splitScalar(u8, line, '\t');
        const name = fields.next().?;
        const digest = fields.next().?;
        const size = fields.next().?;
        try std.testing.expect(fields.next() == null);
        try std.testing.expectEqual(@as(usize, 64), digest.len);
        try std.testing.expect(std.fmt.parseInt(u64, size, 10) catch 0 > 0);
        try std.testing.expect(std.mem.endsWith(u8, name, ".qcow2"));
    }
    try std.testing.expectEqual(@as(usize, 4), lines);

    // A manifest whose assets are not the allowlist is refused.
    try support.mutateDocument(&tree, manifest_path, "release_set", "\"ufs\"");
    var scratch: std.Io.Writer.Allocating = .init(tree.allocator());
    try std.testing.expectError(error.Invalid, publication.stagedExpected(
        &context,
        manifest_path,
        "zfs",
        &scratch.writer,
    ));
    try expectFailure(&context, "publish manifest release set mismatch");
}

test "validation evidence is exactly the plan and its Azure results" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try stagedZfsRelease(&tree, &context, gpa);

    const manifest_path = try tree.path(&.{ "output", "publish-manifest.json" });
    _ = try tree.write("evidence/publish-manifest.json", try tree.read(
        "output/publish-manifest.json",
    ));
    _ = try tree.write("evidence/release-notes.md", try tree.read("notes.md"));
    _ = try tree.write("evidence/size-comparison.md", "table\n");

    try publication.stageEvidence(
        &context,
        "zfs",
        manifest_path,
        try tree.path(&.{"azure-results"}),
        try tree.path(&.{"evidence"}),
    );
    const listed = try publication.listTree(&context, try tree.path(&.{"evidence"}));
    try support.expectNames(listed, &.{
        "publish-manifest.json",
        "release-notes.md",
        "size-comparison.md",
        "azure-results/aarch64-zfs-full/azure-result.json",
        "azure-results/x86_64-zfs-full/azure-result.json",
        "azure-results/aarch64-zfs-core/azure-result.json",
        "azure-results/x86_64-zfs-core/azure-result.json",
    });

    // An unexpected file in the evidence tree fails the allowlist.
    _ = try tree.write("evidence/stray.txt", "stray\n");
    try std.testing.expectError(error.Invalid, publication.stageEvidence(
        &context,
        "zfs",
        manifest_path,
        try tree.path(&.{"azure-results"}),
        try tree.path(&.{"evidence"}),
    ));
    try expectFailure(&context, "validation evidence allowlist mismatch");
}

test "the publish expectation binds the manifest to its dispatch" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try stagedZfsRelease(&tree, &context, gpa);
    const manifest_path = try tree.path(&.{ "output", "publish-manifest.json" });
    const assets = try tree.path(&.{"output"});
    const tag = "FreeBSD-15.1-" ++ support.release_date;

    var out: std.Io.Writer.Allocating = .init(tree.allocator());
    try publication.publishExpected(&context, .{
        .manifest = manifest_path,
        .assets = assets,
        .release_set = "zfs",
        .release_tag = tag,
        .source_commit = support.source_commit,
        .asset_count = 4,
    }, &out.writer);
    const expected_file = try tree.write("expected.tsv", out.written());

    const cases = [_]struct {
        tag: []const u8,
        commit: []const u8,
        count: i64,
        message: []const u8,
    }{
        .{
            .tag = "FreeBSD-15.1-20260724",
            .commit = support.source_commit,
            .count = 4,
            .message = "publish manifest release tag mismatch",
        },
        .{
            .tag = tag,
            .commit = "b" ** 40,
            .count = 4,
            .message = "publish manifest source commit mismatch",
        },
        .{
            .tag = tag,
            .commit = support.source_commit,
            .count = 3,
            .message = "publish manifest asset count mismatch",
        },
    };
    for (cases) |case| {
        var scratch: std.Io.Writer.Allocating = .init(tree.allocator());
        try std.testing.expectError(error.Invalid, publication.publishExpected(
            &context,
            .{
                .manifest = manifest_path,
                .assets = assets,
                .release_set = "zfs",
                .release_tag = case.tag,
                .source_commit = case.commit,
                .asset_count = case.count,
            },
            &scratch.writer,
        ));
        try expectFailure(&context, case.message);
    }

    // A stray file beside the staged assets is refused.
    _ = try tree.write("output/stray.txt", "stray\n");
    var stray: std.Io.Writer.Allocating = .init(tree.allocator());
    try std.testing.expectError(error.Invalid, publication.publishExpected(
        &context,
        .{
            .manifest = manifest_path,
            .assets = assets,
            .release_set = "zfs",
            .release_tag = tag,
            .source_commit = support.source_commit,
            .asset_count = 4,
        },
        &stray.writer,
    ));
    try expectFailure(&context, "staged release allowlist mismatch");
    _ = expected_file;
}

test "tag lookup reports one exact ref and refuses duplicates" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const absent = try tree.write("refs-absent.json",
        \\[{"ref": "refs/tags/FreeBSD-15.1-20260101",
        \\  "object": {"type": "commit", "sha": "b"}}]
    );
    var empty: std.Io.Writer.Allocating = .init(tree.allocator());
    try publication.tagObject(&context, absent, "FreeBSD-15.1-20260812", &empty.writer);
    try std.testing.expectEqualStrings("", empty.written());

    const present = try tree.write("refs.json",
        \\[{"ref": "refs/tags/FreeBSD-15.1-20260812-rc",
        \\  "object": {"type": "commit", "sha": "c"}},
        \\ {"ref": "refs/tags/FreeBSD-15.1-20260812",
        \\  "object": {"type": "commit", "sha": "aaaa"}}]
    );
    var found: std.Io.Writer.Allocating = .init(tree.allocator());
    try publication.tagObject(&context, present, "FreeBSD-15.1-20260812", &found.writer);
    try std.testing.expectEqualStrings("commit\naaaa\n", found.written());

    const duplicate = try tree.write("refs-duplicate.json",
        \\[{"ref": "refs/tags/FreeBSD-15.1-20260812",
        \\  "object": {"type": "commit", "sha": "a"}},
        \\ {"ref": "refs/tags/FreeBSD-15.1-20260812",
        \\  "object": {"type": "tag", "sha": "b"}}]
    );
    var scratch: std.Io.Writer.Allocating = .init(tree.allocator());
    try std.testing.expectError(error.Invalid, publication.tagObject(
        &context,
        duplicate,
        "FreeBSD-15.1-20260812",
        &scratch.writer,
    ));
    try expectFailure(&context, "duplicate exact tag refs");
}

test "remote, downloaded, and published releases must match the expectation" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const body = "release asset\n";
    const digest = "d0d9d5b1eb2d7b4f4c0ec2f7c0d3d2ef9b8e3f2b1a0c9d8e7f6a5b4c3d2e1f00";
    _ = try tree.write("remote/asset.qcow2", body);
    var real_context = tree.context(gpa);
    const real_digest = try candidate_support.hashFile(
        &real_context,
        try tree.path(&.{ "remote", "asset.qcow2" }),
    );
    _ = digest;

    const expected_path = try tree.write("expected.tsv", try std.fmt.allocPrint(
        tree.allocator(),
        "asset.qcow2\t{s}\t{d}\n",
        .{ &real_digest, body.len },
    ));

    const release_json = try std.fmt.allocPrint(tree.allocator(),
        \\{{"draft": true, "assets": [
        \\  {{"name": "asset.qcow2", "digest": "sha256:{s}", "size": {d}}}]}}
    , .{ &real_digest, body.len });
    const release_path = try tree.write("release.json", release_json);
    try publication.verifyRemoteRelease(&context, release_path, expected_path);
    try publication.verifyDownloadedRelease(
        &context,
        try tree.path(&.{"remote"}),
        expected_path,
    );

    try support.mutateDocument(&tree, release_path, "draft", "false");
    try std.testing.expectError(error.Invalid, publication.verifyRemoteRelease(
        &context,
        release_path,
        expected_path,
    ));
    try expectFailure(&context, "release stopped being a draft");
    try publication.verifyPublishedRelease(&context, release_path, expected_path);

    try support.mutateDocument(&tree, release_path, "draft", "true");
    try std.testing.expectError(error.Invalid, publication.verifyPublishedRelease(
        &context,
        release_path,
        expected_path,
    ));
    try expectFailure(&context, "published release did not leave the draft state");

    _ = try tree.write("remote/stray.qcow2", "stray\n");
    try std.testing.expectError(error.Invalid, publication.verifyDownloadedRelease(
        &context,
        try tree.path(&.{"remote"}),
        expected_path,
    ));
    try expectFailure(&context, "downloaded release allowlist mismatch");

    try tree.remove("remote/stray.qcow2");
    _ = try tree.write("remote/asset.qcow2", "tampered\n");
    try std.testing.expectError(error.Invalid, publication.verifyDownloadedRelease(
        &context,
        try tree.path(&.{"remote"}),
        expected_path,
    ));
    try std.testing.expect(
        support.contains(context.message(), "downloaded size mismatch") or
            support.contains(context.message(), "downloaded digest mismatch"),
    );
}

// ---- Workflow and script contracts ----------------------------------------

/// Long option names an invocation block passes, sorted, so the set can be
/// compared with what the parser declares. Only an option that opens a
/// continuation line counts: an inner command's own options -- `stat
/// --format`, for example -- are arguments to something else.
fn invokedOptions(allocator: Allocator, block: []const u8) ![]const []const u8 {
    var found: std.ArrayList([]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, block, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimStart(u8, raw, " \t");
        if (!std.mem.startsWith(u8, line, "--")) continue;
        var end: usize = 2;
        while (end < line.len and (std.ascii.isLower(line[end]) or
            std.ascii.isDigit(line[end]) or line[end] == '-')) end += 1;
        const name = line[2..end];
        if (name.len == 0) continue;
        var duplicate = false;
        for (found.items) |already| {
            if (std.mem.eql(u8, already, name)) duplicate = true;
        }
        if (duplicate) continue;
        try found.append(allocator, name);
    }
    std.mem.sort([]const u8, found.items, {}, lessThanText);
    return found.items;
}

fn lessThanText(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn expectSameOptions(actual: []const []const u8, command_name: []const u8) !void {
    const command = cli.findCommand(command_name).?;
    const sorted = try std.testing.allocator.dupe([]const u8, command.options);
    defer std.testing.allocator.free(sorted);
    std.mem.sort([]const u8, sorted, {}, lessThanText);
    try std.testing.expectEqual(sorted.len, actual.len);
    for (sorted, actual) |wanted, claimed| {
        try std.testing.expectEqualStrings(wanted, claimed);
    }
}

test "the acceptance harness invokes azure-result with exactly the parser's options" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15_azure_acceptance.sh",
    );
    const block = try support.between(
        source,
        "\"$release_tool\" azure-result \\",
        "\n\n",
    );
    try expectSameOptions(try invokedOptions(tree.allocator(), block), "azure-result");
}

test "the workflow invokes candidate with exactly the parser's options" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        ".github/workflows/freebsd15-release.yml",
    );
    const block = try support.between(
        source,
        "zig-out/bin/freebsd15_release candidate \\",
        "\n          {",
    );
    try expectSameOptions(try invokedOptions(tree.allocator(), block), "candidate");
    try support.expectContains(block, "--qemu-info");
}

test "the acceptance harness invokes candidate-binding with the parser's options" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15_azure_acceptance.sh",
    );
    const block = try support.between(
        source,
        "\"$release_tool\" candidate-binding \\",
        "\n}",
    );
    try expectSameOptions(
        try invokedOptions(tree.allocator(), block),
        "candidate-binding",
    );
}

test "the staging script binds Azure results and compares inside one manifest" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15_stage_release.sh",
    );
    try support.expectContains(source, "AZURE_RESULTS_DIR");
    try support.expectContains(source, "--azure-results");
    try support.expectAbsent(source, "BASELINE_CANDIDATES_DIR");
    try support.expectAbsent(source, "--baseline");
    try support.expectContains(
        source,
        "--minimum-core-reduction-percent \"$minimum_core_reduction\"",
    );
    try support.expectContains(
        source,
        "--candidate \"$assets_dir/publish-manifest.json\"",
    );
    // The staging script owns no interpreter of its own and no publication.
    try support.expectAbsent(source, support.interpreter_name);
    try support.expectAbsent(source, "freebsd15_publish.sh");
    try support.expectContains(source, "\"$release_tool\" stage \\");
    try support.expectContains(source, "\"$release_tool\" compare \\");
    try support.expectContains(source, "\"$release_tool\" stage-expected \\");
    try support.expectContains(source, "\"$release_tool\" stage-evidence \\");
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, "gh ")) |at| {
        index = at + 1;
        return error.StagingScriptTouchesTheRelease;
    }
}

test "the publish script requires a reviewed date and exact assets" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15_publish.sh",
    );
    try support.expectAbsent(source, "20260812");
    try support.expectContains(source, "explicit reviewed RELEASE_DATE");
    try support.expectContains(source, "--release-date \"$RELEASE_DATE\"");
    try support.expectContains(source, "gh release create \"$RELEASE_TAG\"");
    try support.expectContains(source, "gh release upload \"$RELEASE_TAG\"");
    try support.expectContains(source, "gh release edit \"$RELEASE_TAG\"");
    try support.expectContains(source, "gh release download \"$RELEASE_TAG\"");
    try support.expectContains(source, "--draft");
    try support.expectContains(source, "--latest=false");
    try support.expectContains(source, "git/matching-refs/tags/$RELEASE_TAG");
    try support.expectAbsent(source, "git/ref/tags/$RELEASE_TAG");
    try support.expectContains(source, "\"$release_tool\" tag-object");
    try support.expectContains(source, "\"$release_tool\" publish-expected \\");
    try support.expectContains(source, "\"$release_tool\" verify-remote-release \\");
    try support.expectContains(source, "\"$release_tool\" verify-downloaded-release \\");
    try support.expectContains(source, "\"$release_tool\" verify-published-release \\");
    try support.expectAbsent(source, support.interpreter_name);
    try support.expectAbsent(source, "*.sha256");
    try support.expectAbsent(source, "*.packages.txt");
}

test "the ported tooling owns the diagnostics the shell used to embed" {
    // The messages the removed heredocs produced are now the tool's, so the
    // fail-closed behaviour is still stated somewhere reviewable.
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const publication_source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15/publication.zig",
    );
    for ([_][]const u8{
        "duplicate exact tag refs",
        "downloaded release allowlist mismatch",
        "validation evidence allowlist mismatch",
        "staged release allowlist mismatch",
        "ZFS publication allowlist mismatch",
        "published release did not retain the exact final allowlist",
    }) |message| {
        try support.expectContains(publication_source, message);
    }
}

test "validation mode cannot reach a release mutation" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        ".github/workflows/freebsd15-release.yml",
    );
    const stage_block = try support.between(source, "\n  stage:\n", "\n  publish:\n");
    const publish_start = try support.indexOf(source, "\n  publish:\n");
    const publish_block = source[publish_start..];

    try support.expectContains(source, "validation_only:");
    try support.expectContains(source, "        type: boolean");
    try support.expectContains(source, "        required: true");
    try support.expectContains(source, "        default: false");
    try support.expectContains(source, "test \"$RELEASE_SET\" = zfs");
    try support.expectContains(stage_block, "needs: [prepare, build, azure_acceptance]");
    try support.expectContains(source, "environment: azurelinux4-release");
    try support.expectContains(stage_block, "scripts/freebsd15_stage_release.sh");
    try support.expectContains(stage_block, "if: inputs.validation_only");
    try support.expectContains(stage_block, "freebsd15-validation-evidence-");
    try support.expectContains(stage_block, "path: ${{ env.STAGING_ROOT }}/evidence/");
    try support.expectContains(stage_block, "retention-days: 1");
    try support.expectAbsent(stage_block, "contents: write");
    try support.expectAbsent(stage_block, "freebsd15_publish.sh");
    try support.expectContains(publish_block, "inputs.validation_only == false");
    try support.expectContains(publish_block, "needs.stage.result == 'success'");
    try support.expectContains(publish_block, "contents: write");
    try support.expectContains(publish_block, "scripts/freebsd15_stage_release.sh");
    try support.expectContains(publish_block, "scripts/freebsd15_publish.sh");
}

test "the release workflow runs no Python and builds the ported tooling" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        ".github/workflows/freebsd15-release.yml",
    );
    try support.expectAbsent(source, support.interpreter_name);
    try support.expectContains(source, "zig build freebsd15-release-tools");
    try support.expectContains(source, "\"$release_tool\" matrix \\");
    try support.expectContains(source, "\"$release_tool\" azure-matrix \\");
    try support.expectContains(source, "\"$release_tool\" include-count --matrix \"$matrix\"");
    try support.expectContains(
        source,
        "\"$release_tool\" include-count --matrix \"$azure_matrix\"",
    );
    try support.expectContains(source, "\"$release_tool\" describe \\");
    try support.expectContains(source, "zig-out/bin/freebsd15_release candidate \\");
}

test "no FreeBSD release file still executes Python" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    for ([_][]const u8{
        "scripts/freebsd15_stage_release.sh",
        "scripts/freebsd15_publish.sh",
        ".github/workflows/freebsd15-release.yml",
    }) |relative| {
        const source = try support.readSource(tree.allocator(), relative);
        try support.expectAbsent(source, support.interpreter_name);
    }
    // The acceptance harness names Python exactly once, in the guest-side
    // pattern that looks for a running Azure Agent process.
    const harness = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15_azure_acceptance.sh",
    );
    var mentions: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        harness,
        index,
        support.interpreter_name,
    )) |at| {
        mentions += 1;
        index = at + 1;
    }
    try std.testing.expectEqual(@as(usize, 1), mentions);
    try support.expectContains(harness, "pgrep -f 'python.*waagent'");
}

// ---- Provenance the notes render is proven before anything is staged ------

/// Whether anything exists at `relative` inside the tree, file or directory.
fn treeEntryExists(tree: *Tree, relative: []const u8) !bool {
    const full = try tree.path(&.{relative});
    _ = std.Io.Dir.cwd().statFile(std.testing.io, full, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

test "staging refuses provenance the notes would render, before any output" {
    const gpa = std.testing.allocator;
    // Each case is a claim `validate_candidate` never checked and the release
    // notes then rendered. Missing and wrongly typed are both refused, and a
    // numeric string is refused rather than rendered: the publish manifest
    // derived from the candidate has to carry a positive integer, so a string
    // could only ever have failed later, after the assets were staged.
    const cases = [_]struct {
        field: []const u8,
        value: ?[]const u8,
        message: []const u8,
    }{
        .{
            .field = "packages.installed_bytes",
            .value = null,
            .message = "installed package bytes must be a positive integer",
        },
        .{
            .field = "packages.installed_bytes",
            .value = "\"1024\"",
            .message = "installed package bytes must be a positive integer",
        },
        .{
            .field = "packages.installed_bytes",
            .value = "0",
            .message = "installed package bytes must be a positive integer",
        },
        .{
            .field = "packages.installed_bytes",
            .value = "true",
            .message = "installed package bytes must be a positive integer",
        },
        .{
            .field = "source.bytes",
            .value = null,
            .message = "source bytes must be a positive integer",
        },
        .{
            .field = "source.bytes",
            .value = "\"123456789\"",
            .message = "source bytes must be a positive integer",
        },
        .{
            .field = "source.bytes",
            .value = "null",
            .message = "source bytes must be a positive integer",
        },
        .{
            .field = "validation.qemu_version",
            .value = null,
            .message = "validation qemu_version must be recorded",
        },
        .{
            .field = "validation.qemu_version",
            .value = "5",
            .message = "validation qemu_version must be recorded",
        },
        .{
            .field = "validation.qemu_version",
            .value = "\"   \"",
            .message = "validation qemu_version must be recorded",
        },
        .{
            .field = "validation.runner",
            .value = null,
            .message = "validation runner must be recorded",
        },
        .{
            .field = "validation.runner",
            .value = "null",
            .message = "validation runner must be recorded",
        },
    };
    for (cases) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var context = tree.context(gpa);
        try makeZfsCandidates(&tree, gpa, .{});
        const manifest = try tree.path(&.{
            "candidates", "x86_64-zfs-core", "candidate.json",
        });
        try support.mutateDocument(&tree, manifest, case.field, case.value);

        try std.testing.expectError(error.Invalid, stage(&tree, &context, "zfs", .{}));
        try expectFailure(&context, case.message);
        // The rejection is ahead of every byte of output: no staged asset, no
        // publish manifest, and no release notes were left behind.
        try std.testing.expect(!try treeEntryExists(&tree, "output"));
        try std.testing.expect(!try treeEntryExists(&tree, "notes.md"));
    }
}

test "the release notes diagnose a malformed record instead of aborting" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);
    try makeZfsCandidates(&tree, gpa, .{});

    // Build the validated candidate set the notes renderer consumes, then
    // corrupt one rendered field behind validation's back. The renderer must
    // report it, not reach for a value that is not there.
    var candidates: std.ArrayList(candidate_support.ValidatedCandidate) = .empty;
    for (zfs_variants) |key| {
        const manifest = try tree.path(&.{ "candidates", key, "candidate.json" });
        try candidates.append(tree.allocator(), try candidate_support.validateCandidate(
            &context,
            manifest,
            support.source_commit,
        ));
    }
    const selected = profiles.findReleaseSet("zfs").?;
    const notes = try staging.releaseNotes(&context, .{
        .selected = selected,
        .candidates = candidates.items,
        .source_commit = support.source_commit,
        .azure_results = null,
        .minimum_core_reduction_percent = 10,
        .core_rows = null,
    });
    try support.expectContains(notes, "QEMU acceptance: `QEMU emulator version 10.0.2`");

    const validation = candidates.items[0].value.object.getPtr("validation").?;
    try validation.object.put(tree.allocator(), "runner", .{ .integer = 7 });
    try std.testing.expectError(error.Invalid, staging.releaseNotes(&context, .{
        .selected = selected,
        .candidates = candidates.items,
        .source_commit = support.source_commit,
        .azure_results = null,
        .minimum_core_reduction_percent = 10,
        .core_rows = null,
    }));
    try expectFailure(&context, "recorded runner is missing or not a string");
}

test "a published release must report leaving the draft state" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var context = tree.context(gpa);

    const body = "release asset\n";
    _ = try tree.write("remote/asset.qcow2", body);
    const digest = try candidate_support.hashFile(
        &context,
        try tree.path(&.{ "remote", "asset.qcow2" }),
    );
    const expected_path = try tree.write("expected.tsv", try std.fmt.allocPrint(
        tree.allocator(),
        "asset.qcow2\t{s}\t{d}\n",
        .{ &digest, body.len },
    ));

    // Only a present boolean `false` is a published release. Everything else,
    // including the falsy spellings a dynamic language would have accepted, is
    // refused -- the same shape the pre-publication gate requires of `true`.
    const refused = [_]?[]const u8{
        null,
        "true",
        "null",
        "\"false\"",
        "0",
        "[]",
    };
    for (refused) |draft| {
        const release_path = try tree.write("release.json", try std.fmt.allocPrint(
            tree.allocator(),
            \\{{{s}"assets": [
            \\  {{"name": "asset.qcow2", "digest": "sha256:{s}", "size": {d}}}]}}
        ,
            .{
                if (draft) |value| try std.fmt.allocPrint(
                    tree.allocator(),
                    "\"draft\": {s}, ",
                    .{value},
                ) else "",
                &digest,
                body.len,
            },
        ));
        try std.testing.expectError(error.Invalid, publication.verifyPublishedRelease(
            &context,
            release_path,
            expected_path,
        ));
        try expectFailure(&context, "published release did not leave the draft state");

        // The sibling gate is the mirror image: it requires a present boolean
        // `true`, so every one of these spellings fails there too, except the
        // one that really is a draft.
        const remote = publication.verifyRemoteRelease(
            &context,
            release_path,
            expected_path,
        );
        if (draft != null and std.mem.eql(u8, draft.?, "true")) {
            try remote;
        } else {
            try std.testing.expectError(error.Invalid, remote);
            try expectFailure(&context, "release stopped being a draft");
        }
    }

    const published = try tree.write("release.json", try std.fmt.allocPrint(
        tree.allocator(),
        \\{{"draft": false, "assets": [
        \\  {{"name": "asset.qcow2", "digest": "sha256:{s}", "size": {d}}}]}}
    ,
        .{ &digest, body.len },
    ));
    try publication.verifyPublishedRelease(&context, published, expected_path);

    // A non-draft release that lost or gained an asset is still refused, and
    // says so precisely.
    const wrong = try tree.write("release-wrong.json", try std.fmt.allocPrint(
        tree.allocator(),
        \\{{"draft": false, "assets": [
        \\  {{"name": "asset.qcow2", "digest": "sha256:{s}", "size": {d}}},
        \\  {{"name": "stray.qcow2", "digest": "sha256:{s}", "size": {d}}}]}}
    ,
        .{ &digest, body.len, &digest, body.len },
    ));
    try std.testing.expectError(error.Invalid, publication.verifyPublishedRelease(
        &context,
        wrong,
        expected_path,
    ));
    try expectFailure(
        &context,
        "published release did not retain the exact final allowlist",
    );
}
