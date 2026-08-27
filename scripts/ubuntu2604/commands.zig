//! The release commands that produce documents rather than only check them.
//!
//! `candidate` binds a freshly built QCOW2 to its provenance tree, and `stage`
//! turns two independently accepted candidates into the exact set of files a
//! GitHub release may carry. Staging is transactional on purpose: it builds
//! the asset directory and the release notes under temporary names and commits
//! both, so a failure part-way through leaves the publication inputs exactly
//! as they were rather than half-written.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const contracts = @import("contracts.zig");
const documents = @import("documents.zig");
const provenance = @import("provenance.zig");
const support = @import("support.zig");

const Builder = support.Builder;
const Diagnostic = support.Diagnostic;
const Error = support.Error;
const fail = support.fail;

/// `require_commit` applied to a command-line value rather than JSON.
pub fn requireCommitArgument(
    value: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error![]const u8 {
    if (!support.isCommit(value)) return fail(
        diagnostic,
        "{s} is not a full lowercase commit SHA",
        .{label},
    );
    return value;
}

/// `require_sha256` applied to a command-line value.
pub fn requireSha256Argument(
    value: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) Error![]const u8 {
    if (!support.isSha256(value)) return fail(
        diagnostic,
        "{s} is not a lowercase SHA-256",
        .{label},
    );
    return value;
}

/// `Path.resolve()`: an absolute, normalized spelling that does not require
/// the path to exist. The resolved form is what the Python prints in its
/// "missing" diagnostics.
pub fn resolvePath(allocator: Allocator, path: []const u8) Error![]u8 {
    return std.fs.path.resolve(allocator, &.{path}) catch error.OutOfMemory;
}

pub const CandidateOptions = struct {
    key: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset: []const u8,
    validated_sha256: []const u8,
    virtual_size: i64,
    source_commit: []const u8,
    provenance_dir: []const u8,
    runner: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    output: []const u8,
};

/// `candidate_command`.
pub fn candidate(
    allocator: Allocator,
    io: Io,
    options: CandidateOptions,
    diagnostic: *Diagnostic,
) Error!void {
    const asset = try resolvePath(allocator, options.asset);
    defer allocator.free(asset);
    if (!support.isRegularFile(io, asset)) return fail(
        diagnostic,
        "candidate asset is missing: {s}",
        .{asset},
    );
    const entry = contracts.lookup(options.key) orelse return fail(
        diagnostic,
        "unknown candidate key: {s}",
        .{options.key},
    );
    if (!std.mem.eql(u8, options.architecture, entry.architecture) or
        !std.mem.eql(u8, options.flavor, entry.flavor))
    {
        return fail(
            diagnostic,
            "{s}: architecture/flavor arguments do not match",
            .{options.key},
        );
    }
    const asset_basename = std.fs.path.basename(asset);
    if (!std.mem.eql(u8, asset_basename, entry.asset_name)) return fail(
        diagnostic,
        "{s}: expected asset {s}, got {s}",
        .{ options.key, entry.asset_name, asset_basename },
    );
    const source_commit = try requireCommitArgument(
        options.source_commit,
        "source_commit",
        diagnostic,
    );
    if (options.virtual_size <= 0) return fail(
        diagnostic,
        "virtual size must be positive",
        .{},
    );
    const flavor = contracts.parseFlavor(entry.flavor).?;

    const provenance_root = try resolvePath(allocator, options.provenance_dir);
    defer allocator.free(provenance_root);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());

    const records = try provenance.records(
        allocator,
        builder,
        io,
        provenance_root,
        diagnostic,
    );
    var ubuntu = try provenance.validateUbuntu(
        allocator,
        io,
        provenance_root,
        entry.architecture,
        flavor,
        options.virtual_size,
        diagnostic,
    );
    defer ubuntu.deinit();
    const signing = try provenance.validateSigning(
        allocator,
        builder,
        io,
        provenance_root,
        entry.architecture,
        flavor,
        diagnostic,
    );

    const asset_digest = support.hashArtifact(io, asset) catch return fail(
        diagnostic,
        "candidate asset is missing: {s}",
        .{asset},
    );
    var validated_label_buffer: [96]u8 = undefined;
    const validated = try requireSha256Argument(
        options.validated_sha256,
        std.fmt.bufPrint(
            &validated_label_buffer,
            "{s} validated digest",
            .{options.key},
        ) catch "validated digest",
        diagnostic,
    );
    if (!std.mem.eql(u8, validated, &asset_digest.hex)) return fail(
        diagnostic,
        "{s}: build validation digest does not match candidate bytes",
        .{options.key},
    );
    if (asset_digest.size == 0) return fail(
        diagnostic,
        "candidate asset must not be empty",
        .{},
    );
    const identities = [_]struct { label: []const u8, value: []const u8 }{
        .{ .label = "runner", .value = options.runner },
        .{ .label = "run ID", .value = options.run_id },
        .{ .label = "run attempt", .value = options.run_attempt },
    };
    for (identities) |identity| {
        if (identity.value.len == 0) return fail(
            diagnostic,
            "{s} is absent",
            .{identity.label},
        );
    }

    var build_validation = builder.object();
    try builder.putString(&build_validation, "status", "success");
    try builder.putString(&build_validation, "validated_sha256", validated);
    try builder.putString(&build_validation, "runner", options.runner);

    var provenance_value = builder.object();
    try builder.putString(
        &provenance_value,
        "digest",
        &try support.canonicalDigest(allocator, records),
    );
    try builder.put(&provenance_value, "files", records);

    var workflow = builder.object();
    try builder.putString(&workflow, "run_id", options.run_id);
    try builder.putString(&workflow, "run_attempt", options.run_attempt);

    var document = builder.object();
    try builder.putInteger(&document, "schema", 1);
    try builder.putString(&document, "type", documents.candidate_type);
    try builder.putString(&document, "key", options.key);
    try builder.putString(&document, "architecture", entry.architecture);
    try builder.putString(&document, "flavor", entry.flavor);
    try builder.putString(&document, "asset_name", entry.asset_name);
    try builder.putString(&document, "source_commit", source_commit);
    try builder.putString(&document, "sha256", &asset_digest.hex);
    try builder.putInteger(&document, "bytes", @intCast(asset_digest.size));
    try builder.putInteger(&document, "virtual_size", options.virtual_size);
    try builder.put(
        &document,
        "azure_contracts",
        try builder.strings(contracts.azureContracts(flavor)),
    );
    try builder.put(&document, "build_validation", .{ .object = build_validation });
    try builder.put(&document, "provenance", .{ .object = provenance_value });
    try builder.put(
        &document,
        "ubuntu_provenance",
        try builder.clone(ubuntu.value()),
    );
    try builder.put(&document, "uki_signing", signing.value);
    try builder.put(&document, "workflow", .{ .object = workflow });

    try support.writeDocument(
        allocator,
        io,
        options.output,
        .{ .object = document },
        diagnostic,
    );
}

pub const StageOptions = struct {
    candidates: []const u8,
    azure_results: []const u8,
    source_commit: []const u8,
    release_tag: []const u8,
    output: []const u8,
    notes: []const u8,
};

/// `RELEASE_TAG_RE`.
pub fn isReleaseTag(text: []const u8) bool {
    const prefix = "Ubuntu-26.04-";
    if (!std.mem.startsWith(u8, text, prefix)) return false;
    const rest = text[prefix.len..];
    if (rest.len != 8) return false;
    for (rest) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

/// One `find_documents` result: the manifest path plus its parsed document.
const Located = struct {
    path: []u8,
    document: support.json_document.Document,

    fn deinit(self: *Located, allocator: Allocator) void {
        self.document.deinit();
        allocator.free(self.path);
        self.* = undefined;
    }
};

/// `find_documents`: exactly one document per published key, keyed by the
/// `key` each document claims.
fn findDocuments(
    allocator: Allocator,
    io: Io,
    root: []const u8,
    filename: []const u8,
    diagnostic: *Diagnostic,
) Error![contracts.release_order.len]Located {
    const relative = support.listFilesNamed(
        allocator,
        io,
        root,
        filename,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "expected exactly {d} {s} files under {s}, found 0",
            .{ contracts.release_order.len, filename, root },
        ),
    };
    defer support.freePaths(allocator, relative);
    if (relative.len != contracts.release_order.len) return fail(
        diagnostic,
        "expected exactly {d} {s} files under {s}, found {d}",
        .{ contracts.release_order.len, filename, root, relative.len },
    );

    var found: [contracts.release_order.len]?Located = .{ null, null };
    errdefer for (&found) |*slot| {
        if (slot.*) |*located| located.deinit(allocator);
    };

    for (relative) |item| {
        const path = try support.joinPath(allocator, &.{ root, item });
        var located: Located = .{
            .path = path,
            .document = support.readObject(
                allocator,
                io,
                path,
                diagnostic,
            ) catch |err| {
                allocator.free(path);
                return err;
            },
        };
        errdefer located.deinit(allocator);
        const key = support.stringOf(located.document.get("key"));
        var index: ?usize = null;
        if (key) |text| {
            for (contracts.release_order, 0..) |candidate_key, position| {
                if (std.mem.eql(u8, candidate_key, text)) index = position;
            }
        }
        if (key == null or index == null or found[index.?] != null) {
            return fail(diagnostic, "duplicate or invalid key in {s}", .{path});
        }
        found[index.?] = located;
    }
    for (found) |slot| {
        if (slot == null) return fail(
            diagnostic,
            "{s} candidate set is not exact",
            .{filename},
        );
    }
    return .{ found[0].?, found[1].? };
}

/// Per-asset staging record, kept in publication order.
const Staged = struct {
    key: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset_name: []const u8,
    sha256: []const u8,
    bytes: i64,
    virtual_size: i64,
    build_runner: []const u8,
    provenance_digest: []const u8,
    certificate_sha256: []const u8,
    signing_certificate_sha256: []const u8,
    fallback_uki_sha256: []const u8,
    azure_location: []const u8,
    azure_vm_size: []const u8,
    azure_resource_group: []const u8,
    conversion: std.json.Value,
    derived_vhd_sha256: []const u8,
    derived_vhd_bytes: i64,
    derived_vhd_current_size: i64,
    azure_image_version_id: []const u8,
};

/// `_stage_into`.
fn stageInto(
    allocator: Allocator,
    io: Io,
    options: StageOptions,
    output: []const u8,
    notes: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const source_commit = try requireCommitArgument(
        options.source_commit,
        "source_commit",
        diagnostic,
    );
    if (!isReleaseTag(options.release_tag)) return fail(
        diagnostic,
        "release tag must be Ubuntu-26.04-YYYYMMDD",
        .{},
    );
    const candidates_root = try resolvePath(allocator, options.candidates);
    defer allocator.free(candidates_root);
    const azure_root = try resolvePath(allocator, options.azure_results);
    defer allocator.free(azure_root);

    for ([_][]const u8{ candidates_root, azure_root }) |root| {
        const sidecars = support.listFilesWithSuffix(
            allocator,
            io,
            root,
            ".sha256",
        ) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue,
        };
        defer support.freePaths(allocator, sidecars);
        if (sidecars.len != 0) return fail(
            diagnostic,
            "SHA-256 sidecar files are forbidden",
            .{},
        );
    }

    var candidate_documents = try findDocuments(
        allocator,
        io,
        candidates_root,
        "candidate.json",
        diagnostic,
    );
    defer for (&candidate_documents) |*located| located.deinit(allocator);
    var azure_documents = try findDocuments(
        allocator,
        io,
        azure_root,
        "azure-result.json",
        diagnostic,
    );
    defer for (&azure_documents) |*located| located.deinit(allocator);

    const qcow_paths = support.listFilesWithSuffix(
        allocator,
        io,
        candidates_root,
        ".qcow2",
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return fail(
            diagnostic,
            "expected exactly {d} candidate QCOW2 files, found 0",
            .{contracts.release_order.len},
        ),
    };
    defer support.freePaths(allocator, qcow_paths);
    if (qcow_paths.len != contracts.release_order.len) return fail(
        diagnostic,
        "expected exactly {d} candidate QCOW2 files, found {d}",
        .{ contracts.release_order.len, qcow_paths.len },
    );

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());

    var staged: [contracts.release_order.len]Staged = undefined;
    var release_certificate_sha256: ?[]const u8 = null;
    var release_signing_certificate_sha256: ?[]const u8 = null;
    var release_signing_provider: ?std.json.Value = null;

    for (contracts.release_order, 0..) |key, index| {
        const manifest = &candidate_documents[index];
        _ = try documents.validateIdentity(
            manifest.document.object(),
            documents.candidate_type,
            1,
            key,
            source_commit,
            diagnostic,
        );
        const entry = contracts.lookup(key).?;
        const manifest_parent = std.fs.path.dirname(manifest.path) orelse ".";
        const asset_path = try support.joinPath(
            allocator,
            &.{ manifest_parent, entry.asset_name },
        );
        defer allocator.free(asset_path);

        var verified = try documents.verifyCandidate(
            allocator,
            io,
            manifest.path,
            asset_path,
            key,
            source_commit,
            diagnostic,
        );
        defer verified.deinit();

        const azure_located = &azure_documents[index];
        var azure = try documents.validateAzureResult(
            allocator,
            io,
            &verified,
            azure_located.path,
            diagnostic,
        );
        defer azure.deinit();
        const azure_object = azure.object();
        _ = try documents.validateIdentity(
            azure_object,
            documents.azure_result_type,
            1,
            key,
            source_commit,
            diagnostic,
        );
        if (!documents.hasWorkflowIdentity(azure_object.get("workflow"))) {
            return fail(diagnostic, "{s}: Azure workflow identity is absent", .{key});
        }
        if (!support.stringIs(azure_object.get("status"), "success")) return fail(
            diagnostic,
            "{s}: Azure acceptance is not explicitly successful",
            .{key},
        );
        if (!support.stringIs(azure_object.get("qcow_sha256"), verified.sha256) or
            !support.stringIs(
                azure_object.get("azure_accepted_sha256"),
                verified.sha256,
            ))
        {
            return fail(
                diagnostic,
                "{s}: Azure acceptance did not validate published bytes",
                .{key},
            );
        }
        const signing = support.objectOf(verified.object().get("uki_signing")).?;
        const signing_provider = support.objectOf(signing.get("provider")) orelse
            return fail(
                diagnostic,
                "{s}: Artifact Signing provider identity is absent",
                .{key},
            );
        if (!support.stringIs(
            azure_object.get("certificate_sha256"),
            verified.certificate_sha256,
        ) or
            !support.stringIs(
                azure_object.get("signing_certificate_sha256"),
                verified.signing_certificate_sha256,
            ) or
            !support.stringIs(
                azure_object.get("fallback_uki_sha256"),
                verified.fallback_uki_sha256,
            ))
        {
            return fail(
                diagnostic,
                "{s}: Azure acceptance did not bind the signed UKI identity",
                .{key},
            );
        }
        try documents.validateAzureUefiSettings(
            allocator,
            azure_object.get("uefi_settings"),
            verified.certificate_sha256,
            diagnostic,
        );
        const image_version_id = support.stringOf(
            azure_object.get("image_version_id"),
        );
        if (image_version_id == null or
            !std.mem.startsWith(u8, image_version_id.?, "/subscriptions/"))
        {
            return fail(
                diagnostic,
                "{s}: Azure gallery image-version identity is absent",
                .{key},
            );
        }

        if (release_certificate_sha256) |shared| {
            if (!std.mem.eql(u8, shared, verified.certificate_sha256)) return fail(
                diagnostic,
                "release candidates do not share one UKI signing certificate",
                .{},
            );
        } else {
            release_certificate_sha256 = try arena.allocator().dupe(
                u8,
                verified.certificate_sha256,
            );
        }
        if (release_signing_certificate_sha256) |shared| {
            if (!std.mem.eql(u8, shared, verified.signing_certificate_sha256) or
                !support.jsonEqual(
                    release_signing_provider.?,
                    .{ .object = signing_provider },
                ))
            {
                return fail(
                    diagnostic,
                    "release candidates do not share one Artifact Signing identity",
                    .{},
                );
            }
        } else {
            release_signing_certificate_sha256 = try arena.allocator().dupe(
                u8,
                verified.signing_certificate_sha256,
            );
            release_signing_provider = try builder.clone(
                .{ .object = signing_provider },
            );
        }

        if (!support.jsonEqual(
            azure_object.get("contracts") orelse .null,
            verified.object().get("azure_contracts") orelse .null,
        )) {
            return fail(diagnostic, "{s}: Azure contract results are absent", .{key});
        }

        const conversion = try documents.validateConversionIdentity(
            azure_object.get("conversion"),
            key,
            diagnostic,
            "{s}: ",
        );
        try documents.validateConversionBindings(
            conversion,
            &verified,
            diagnostic,
            "{s}: ",
        );
        const derived_vhd_sha256 = try documents.validateConversionSizes(
            conversion,
            &verified,
            diagnostic,
            "{s}: ",
        );
        const conversion_result = support.objectOf(conversion.get("result")).?;

        const named = [_]struct { field: []const u8, label: []const u8 }{
            .{ .field = "location", .label = "location" },
            .{ .field = "vm_size", .label = "VM size" },
            .{ .field = "resource_group", .label = "resource group" },
        };
        for (named) |item| {
            const text = support.stringOf(azure_object.get(item.field));
            if (text == null or text.?.len == 0) return fail(
                diagnostic,
                "{s}: Azure {s} is absent",
                .{ key, item.label },
            );
        }

        const destination = try support.joinPath(
            allocator,
            &.{ output, entry.asset_name },
        );
        defer allocator.free(destination);
        Dir.cwd().hardLink(asset_path, Dir.cwd(), destination, io, .{}) catch {
            Dir.cwd().copyFile(
                asset_path,
                Dir.cwd(),
                destination,
                io,
                .{},
            ) catch return fail(
                diagnostic,
                "{s}: staging changed candidate bytes",
                .{key},
            );
        };
        const staged_digest = support.hashArtifact(io, destination) catch
            return fail(diagnostic, "{s}: staging changed candidate bytes", .{key});
        if (!std.mem.eql(u8, &staged_digest.hex, verified.sha256)) return fail(
            diagnostic,
            "{s}: staging changed candidate bytes",
            .{key},
        );

        const build_validation = support.objectOf(
            verified.object().get("build_validation"),
        ).?;
        const provenance_binding = support.objectOf(
            verified.object().get("provenance"),
        ).?;

        staged[index] = .{
            .key = key,
            .architecture = entry.architecture,
            .flavor = entry.flavor,
            .asset_name = entry.asset_name,
            .sha256 = try arena.allocator().dupe(u8, verified.sha256),
            .bytes = @intCast(staged_digest.size),
            .virtual_size = verified.virtual_size,
            .build_runner = try arena.allocator().dupe(
                u8,
                support.stringOf(build_validation.get("runner")).?,
            ),
            .provenance_digest = try arena.allocator().dupe(
                u8,
                support.stringOf(provenance_binding.get("digest")).?,
            ),
            .certificate_sha256 = try arena.allocator().dupe(
                u8,
                verified.certificate_sha256,
            ),
            .signing_certificate_sha256 = try arena.allocator().dupe(
                u8,
                verified.signing_certificate_sha256,
            ),
            .fallback_uki_sha256 = try arena.allocator().dupe(
                u8,
                verified.fallback_uki_sha256,
            ),
            .azure_location = try arena.allocator().dupe(
                u8,
                support.stringOf(azure_object.get("location")).?,
            ),
            .azure_vm_size = try arena.allocator().dupe(
                u8,
                support.stringOf(azure_object.get("vm_size")).?,
            ),
            .azure_resource_group = try arena.allocator().dupe(
                u8,
                support.stringOf(azure_object.get("resource_group")).?,
            ),
            .conversion = try builder.clone(azure_object.get("conversion").?),
            .derived_vhd_sha256 = try arena.allocator().dupe(u8, derived_vhd_sha256),
            .derived_vhd_bytes = support.integerOf(
                conversion_result.get("bytes"),
            ).?,
            .derived_vhd_current_size = support.integerOf(
                conversion_result.get("current_size"),
            ).?,
            .azure_image_version_id = try arena.allocator().dupe(
                u8,
                image_version_id.?,
            ),
        };
    }

    var assets = builder.array();
    for (staged) |item| {
        var record = builder.object();
        try builder.putString(&record, "key", item.key);
        try builder.putString(&record, "architecture", item.architecture);
        try builder.putString(&record, "flavor", item.flavor);
        try builder.putString(&record, "asset_name", item.asset_name);
        try builder.putString(&record, "sha256", item.sha256);
        try builder.putInteger(&record, "bytes", item.bytes);
        try builder.putInteger(&record, "virtual_size", item.virtual_size);
        try builder.putString(&record, "build_runner", item.build_runner);
        try builder.putString(&record, "provenance_digest", item.provenance_digest);
        try builder.putString(&record, "certificate_sha256", item.certificate_sha256);
        try builder.putString(
            &record,
            "signing_certificate_sha256",
            item.signing_certificate_sha256,
        );
        try builder.putString(
            &record,
            "fallback_uki_sha256",
            item.fallback_uki_sha256,
        );
        try builder.putString(&record, "azure_location", item.azure_location);
        try builder.putString(&record, "azure_vm_size", item.azure_vm_size);
        try builder.putString(
            &record,
            "azure_resource_group",
            item.azure_resource_group,
        );
        try builder.put(&record, "conversion", item.conversion);
        try builder.putString(&record, "derived_vhd_sha256", item.derived_vhd_sha256);
        try builder.putInteger(&record, "derived_vhd_bytes", item.derived_vhd_bytes);
        try builder.putInteger(
            &record,
            "derived_vhd_current_size",
            item.derived_vhd_current_size,
        );
        try builder.putString(
            &record,
            "azure_image_version_id",
            item.azure_image_version_id,
        );
        try assets.append(.{ .object = record });
    }

    var manifest = builder.object();
    try builder.putInteger(&manifest, "schema", 1);
    try builder.putString(&manifest, "type", "miz-ubuntu2604-release");
    try builder.putString(&manifest, "release_tag", options.release_tag);
    try builder.putString(&manifest, "source_commit", source_commit);
    try builder.putString(
        &manifest,
        "certificate_sha256",
        release_certificate_sha256.?,
    );
    try builder.putString(
        &manifest,
        "signing_certificate_sha256",
        release_signing_certificate_sha256.?,
    );
    try builder.put(&manifest, "signing_provider", release_signing_provider.?);
    try builder.put(&manifest, "assets", .{ .array = assets });

    const manifest_path = try support.joinPath(
        allocator,
        &.{ output, "publish-manifest.json" },
    );
    defer allocator.free(manifest_path);
    try support.writeDocument(
        allocator,
        io,
        manifest_path,
        .{ .object = manifest },
        diagnostic,
    );

    try writeNotes(
        allocator,
        io,
        notes,
        source_commit,
        release_certificate_sha256.?,
        release_signing_certificate_sha256.?,
        &staged,
        diagnostic,
    );
}

fn writeNotes(
    allocator: Allocator,
    io: Io,
    notes: []const u8,
    source_commit: []const u8,
    certificate_sha256: []const u8,
    signing_certificate_sha256: []const u8,
    staged: []const Staged,
    diagnostic: *Diagnostic,
) Error!void {
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    try text.print(allocator,
        \\Ubuntu Server 26.04 generalized Gen2 images built from the accepted source commit `{s}`. Every published QCOW2 passed hosted structural validation and protected-environment native validation on a matching Azure architecture.
        \\
        \\All UKIs are trusted through enrolled leaf SHA-256 `{s}`.
        \\Artifact Signing leaf certificate SHA-256: `{s}`.
        \\
        \\| Asset | SHA-256 | UKI SHA-256 | File size | Virtual size | Azure validation | Derived VHD evidence (not published) |
        \\| --- | --- | --- | ---: | ---: | --- | --- |
        \\
    , .{ source_commit, certificate_sha256, signing_certificate_sha256 });

    for (staged) |item| {
        try text.print(
            allocator,
            "| `{s}` | `{s}` | `{s}` | {s} | {s} | `{s}` / `{s}` | `{s}`; current {d} bytes; file {d} bytes |\n",
            .{
                item.asset_name,
                item.sha256,
                item.fallback_uki_sha256,
                formatMib(item.bytes).slice(),
                formatMib(item.virtual_size).slice(),
                item.azure_location,
                item.azure_vm_size,
                item.derived_vhd_sha256,
                item.derived_vhd_current_size,
                item.derived_vhd_bytes,
            },
        );
    }

    try text.appendSlice(allocator,
        \\
        \\Both server images boot systemd and use cloud-init for account/key provisioning, WALinuxAgent for Azure Ready/extensions, and `sshd.service`.
        \\
        \\Acceptance required signed UKIs, Azure Trusted Launch with Secure Boot and vTPM, the exact signer in UEFI db, kernel lockdown, module trust, key-only SSH, cloud-init provisioning, agent Ready, runtime Ubuntu release identity, root growth on an enlarged OS disk, managed-data-disk policy, and reboot/reconnect. Candidate and derived-VHD hashes were checked at every handoff; temporary VHDs and Azure resources were deleted.
        \\
        \\**No checksum sidecar assets are published**; SHA-256 digests are recorded only in these notes and the workflow job summary.
        \\
        \\Internal provenance bindings:
        \\
        \\
    );
    for (staged) |item| {
        try text.print(
            allocator,
            "- `{s}`: provenance `{s}`; hosted build on `{s}`\n",
            .{ item.asset_name, item.provenance_digest, item.build_runner },
        );
    }

    support.file_support.writeAtomic(io, notes, text.items) catch |err| return fail(
        diagnostic,
        "cannot write {s}: {s}",
        .{ notes, @errorName(err) },
    );
}

fn formatMib(byte_count: i64) @import("../release/contract.zig").MibText {
    return @import("../release/contract.zig").formatMib(@intCast(byte_count));
}

/// `stage_command`: build both outputs under temporary names and commit them,
/// so an interrupted run never leaves a partial publication input behind.
pub fn stage(
    allocator: Allocator,
    io: Io,
    options: StageOptions,
    diagnostic: *Diagnostic,
) Error!void {
    const output = try resolvePath(allocator, options.output);
    defer allocator.free(output);
    const notes = try resolvePath(allocator, options.notes);
    defer allocator.free(notes);

    var output_was_empty = false;
    if (support.pathExists(io, output)) {
        if (!support.isDirectory(io, output) or
            !try isEmptyDirectory(io, output, diagnostic))
        {
            return fail(diagnostic, "staging directory is not empty: {s}", .{output});
        }
        output_was_empty = true;
    }

    const output_parent = std.fs.path.dirname(output) orelse ".";
    const notes_parent = std.fs.path.dirname(notes) orelse ".";
    Dir.cwd().createDirPath(io, output_parent) catch {};
    Dir.cwd().createDirPath(io, notes_parent) catch {};

    const pid = std.os.linux.getpid();
    const temporary_output = try std.fmt.allocPrint(allocator, "{s}/.{s}.tmp-{d}", .{
        output_parent,
        std.fs.path.basename(output),
        pid,
    });
    defer allocator.free(temporary_output);
    const temporary_notes = try std.fmt.allocPrint(allocator, "{s}/.{s}.tmp-{d}", .{
        notes_parent,
        std.fs.path.basename(notes),
        pid,
    });
    defer allocator.free(temporary_notes);
    if (support.pathExists(io, temporary_output) or
        support.pathExists(io, temporary_notes))
    {
        return fail(diagnostic, "transactional staging path already exists", .{});
    }
    Dir.cwd().createDir(io, temporary_output, .default_dir) catch |err| return fail(
        diagnostic,
        "cannot create {s}: {s}",
        .{ temporary_output, @errorName(err) },
    );

    var output_committed = false;
    var committed = false;
    defer if (!committed) {
        Dir.cwd().deleteTree(io, temporary_output) catch {};
        Dir.cwd().deleteFile(io, temporary_notes) catch {};
        if (output_committed) {
            Dir.cwd().deleteTree(io, output) catch {};
            if (output_was_empty) {
                Dir.cwd().createDir(io, output, .default_dir) catch {};
            }
        }
    };

    try stageInto(
        allocator,
        io,
        options,
        temporary_output,
        temporary_notes,
        diagnostic,
    );
    if (support.pathExists(io, output)) {
        Dir.cwd().deleteDir(io, output) catch |err| return fail(
            diagnostic,
            "cannot replace {s}: {s}",
            .{ output, @errorName(err) },
        );
    }
    Dir.cwd().rename(
        temporary_output,
        Dir.cwd(),
        output,
        io,
    ) catch |err| return fail(
        diagnostic,
        "cannot replace {s}: {s}",
        .{ output, @errorName(err) },
    );
    output_committed = true;
    Dir.cwd().rename(
        temporary_notes,
        Dir.cwd(),
        notes,
        io,
    ) catch |err| return fail(
        diagnostic,
        "cannot replace {s}: {s}",
        .{ notes, @errorName(err) },
    );
    committed = true;
}

fn isEmptyDirectory(
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) Error!bool {
    var directory = Dir.cwd().openDir(io, path, .{ .iterate = true }) catch
        return fail(diagnostic, "staging directory is not empty: {s}", .{path});
    defer directory.close(io);
    var iterator = directory.iterate();
    const first = iterator.next(io) catch
        return fail(diagnostic, "staging directory is not empty: {s}", .{path});
    return first == null;
}

test "release tags accept only the dated Ubuntu spelling" {
    try std.testing.expect(isReleaseTag("Ubuntu-26.04-20260822"));
    try std.testing.expect(!isReleaseTag("Ubuntu-26.04-2026082"));
    try std.testing.expect(!isReleaseTag("Ubuntu-26.04-202608222"));
    try std.testing.expect(!isReleaseTag("Ubuntu-26.10-20260822"));
    try std.testing.expect(!isReleaseTag("ubuntu-26.04-20260822"));
    try std.testing.expect(!isReleaseTag("Ubuntu-26.04-2026082x"));
}

pub const AzureResultOptions = struct {
    manifest: []const u8,
    asset: []const u8,
    vhd: []const u8,
    vhd_info: []const u8,
    conversion_attestation: []const u8,
    key: []const u8,
    source_commit: []const u8,
    location: []const u8,
    vm_size: []const u8,
    resource_group: []const u8,
    image_version_id: []const u8,
    uefi_request: []const u8,
    uefi_response: []const u8,
    android_smoke_provenance_sha256: ?[]const u8,
    android_smoke_runtime_sha256: ?[]const u8,
    android_smoke_bundle_sha256: ?[]const u8,
    android_smoke_config_sha256: ?[]const u8,
    contracts: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    output: []const u8,
};

/// `azure_result_command`: records the Azure acceptance result only once the
/// candidate, the derived VHD, the conversion attestation, and the gallery's
/// own UEFI settings all agree with each other.
pub fn azureResult(
    allocator: Allocator,
    io: Io,
    options: AzureResultOptions,
    diagnostic: *Diagnostic,
) Error!void {
    var verified = try documents.verifyCandidate(
        allocator,
        io,
        options.manifest,
        options.asset,
        options.key,
        options.source_commit,
        diagnostic,
    );
    defer verified.deinit();
    const flavor = verified.flavor();

    const vhd = try resolvePath(allocator, options.vhd);
    defer allocator.free(vhd);
    if (!support.isRegularFile(io, vhd)) return fail(
        diagnostic,
        "derived VHD is missing: {s}",
        .{vhd},
    );

    var context: @import("../azure_vhd.zig").Context = .{};
    const inspection = @import("../azure_vhd.zig").inspect(
        allocator,
        io,
        options.vhd_info,
        vhd,
        &context,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => {
            diagnostic.set("{s}", .{context.message()});
            return error.Failed;
        },
    };

    var conversion = try documents.validateConversionAttestation(
        allocator,
        io,
        options.conversion_attestation,
        &verified,
        vhd,
        options.vhd_info,
        inspection,
        diagnostic,
    );
    defer conversion.deinit();

    var request = try support.readObject(
        allocator,
        io,
        options.uefi_request,
        diagnostic,
    );
    defer request.deinit();
    var response = try support.readObject(
        allocator,
        io,
        options.uefi_response,
        diagnostic,
    );
    defer response.deinit();
    const request_uefi = try documents.validateAzureGalleryUefiSettings(
        allocator,
        request.object(),
        response.object(),
        verified.certificate_sha256,
        diagnostic,
    );

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());

    var provided: std.ArrayList([]const u8) = .empty;
    defer provided.deinit(arena.allocator());
    var parts = std.mem.splitScalar(u8, options.contracts, ',');
    while (parts.next()) |part| {
        try provided.append(arena.allocator(), std.mem.trim(u8, part, " \t\n\r\x0b\x0c"));
    }
    const expected = contracts.azureContracts(flavor);
    var matches = provided.items.len == expected.len;
    if (matches) {
        for (provided.items, expected) |item, name| {
            if (!std.mem.eql(u8, item, name)) matches = false;
        }
    }
    if (!matches) return fail(
        diagnostic,
        "Azure contracts do not exactly match the candidate flavor",
        .{},
    );
    if (!support.isExactOrderedStrings(
        verified.object().get("azure_contracts"),
        provided.items,
    )) {
        return fail(diagnostic, "Azure contracts do not match candidate metadata", .{});
    }

    const identities = [_]struct { label: []const u8, value: []const u8 }{
        .{ .label = "Azure location", .value = options.location },
        .{ .label = "Azure VM size", .value = options.vm_size },
        .{ .label = "Azure resource group", .value = options.resource_group },
        .{ .label = "workflow run ID", .value = options.run_id },
        .{ .label = "workflow run attempt", .value = options.run_attempt },
    };
    for (identities) |identity| {
        if (identity.value.len == 0) return fail(
            diagnostic,
            "{s} is absent",
            .{identity.label},
        );
    }
    if (!std.mem.startsWith(u8, options.image_version_id, "/subscriptions/")) {
        return fail(
            diagnostic,
            "Azure gallery image-version identity is absent",
            .{},
        );
    }

    const android_arguments = [_]?[]const u8{
        options.android_smoke_provenance_sha256,
        options.android_smoke_runtime_sha256,
        options.android_smoke_bundle_sha256,
        options.android_smoke_config_sha256,
    };
    var android_smoke: ?std.json.Value = null;
    if (flavor == .core) {
        const labels = [_][]const u8{
            "android_smoke provenance digest",
            "android_smoke runtime digest",
            "android_smoke bundle digest",
            "android_smoke config digest",
        };
        const fields = [_][]const u8{
            "provenance_sha256",
            "runtime_sha256",
            "bundle_sha256",
            "config_sha256",
        };
        var value = builder.object();
        for (android_arguments, labels, fields) |argument, label, field| {
            const text = argument orelse return fail(
                diagnostic,
                "{s} is not a lowercase SHA-256",
                .{label},
            );
            try builder.putString(
                &value,
                field,
                try requireSha256Argument(text, label, diagnostic),
            );
        }
        try builder.putString(
            &value,
            "architecture",
            verified.identity.architecture,
        );
        try builder.putString(&value, "candidate_key", verified.identity.key);
        android_smoke = .{ .object = value };
    } else {
        for (android_arguments) |argument| {
            if (argument != null) return fail(
                diagnostic,
                "android_smoke provenance is only valid for the core flavor",
                .{},
            );
        }
    }

    const accepted = support.hashArtifact(io, options.asset) catch return fail(
        diagnostic,
        "{s}: exact candidate asset is missing",
        .{verified.identity.key},
    );

    var workflow = builder.object();
    try builder.putString(&workflow, "run_id", options.run_id);
    try builder.putString(&workflow, "run_attempt", options.run_attempt);

    var document = builder.object();
    try builder.putInteger(&document, "schema", switch (flavor) {
        .full => 1,
        .core => 2,
    });
    try builder.putString(&document, "type", documents.azure_result_type);
    try builder.putString(&document, "key", verified.identity.key);
    try builder.putString(
        &document,
        "architecture",
        verified.identity.architecture,
    );
    try builder.putString(&document, "flavor", verified.identity.flavor);
    try builder.putString(&document, "asset_name", verified.identity.asset_name);
    try builder.putString(
        &document,
        "source_commit",
        support.stringOf(verified.object().get("source_commit")).?,
    );
    try builder.putString(&document, "qcow_sha256", verified.sha256);
    try builder.putString(&document, "azure_accepted_sha256", &accepted.hex);
    try builder.put(
        &document,
        "conversion",
        try builder.clone(conversion.parsed.value),
    );
    try builder.putString(
        &document,
        "certificate_sha256",
        verified.certificate_sha256,
    );
    try builder.putString(
        &document,
        "signing_certificate_sha256",
        verified.signing_certificate_sha256,
    );
    try builder.putString(
        &document,
        "fallback_uki_sha256",
        verified.fallback_uki_sha256,
    );
    try builder.putString(&document, "image_version_id", options.image_version_id);
    try builder.put(&document, "uefi_settings", try builder.clone(request_uefi));
    try builder.putString(&document, "status", "success");
    try builder.putString(&document, "location", options.location);
    try builder.putString(&document, "vm_size", options.vm_size);
    try builder.putString(&document, "resource_group", options.resource_group);
    try builder.put(&document, "contracts", try builder.strings(provided.items));
    try builder.put(&document, "workflow", .{ .object = workflow });
    if (android_smoke) |value| {
        try builder.put(&document, "android_smoke", value);
    }

    try support.writeDocument(
        allocator,
        io,
        options.output,
        .{ .object = document },
        diagnostic,
    );
}
