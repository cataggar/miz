//! Candidate, native-acceptance, and Azure-acceptance document contracts.
//!
//! Every one of these checks is re-derived from files rather than read out of
//! a document: a candidate's digest is recomputed from the asset, its
//! provenance records are recomputed from the tree next to the manifest, and
//! an acceptance result is only accepted once the candidate it names has
//! itself been re-verified. That is what makes each handoff between workflow
//! jobs a binding rather than an assertion.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const azure_vhd = @import("../azure_vhd.zig");
const contracts = @import("contracts.zig");
const execution = @import("execution.zig");
const keys = @import("keys.zig");
const provenance = @import("provenance.zig");
const support = @import("support.zig");

const Builder = support.Builder;
const Diagnostic = support.Diagnostic;
const Error = support.Error;
const fail = support.fail;

pub const candidate_type = "ubuntu2604-candidate";
pub const azure_result_type = "ubuntu2604-azure-acceptance";
pub const native_result_type = "ubuntu2604-local-secure-boot-acceptance";

pub const Identity = struct {
    key: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset_name: []const u8,
    source_commit: []const u8,

    pub fn parsedFlavor(self: Identity) contracts.Flavor {
        return contracts.parseFlavor(self.flavor).?;
    }
};

/// `validate_identity`: schema, type, key, the exact top-level field set for
/// the document kind, and the identity triple the key implies.
pub fn validateIdentity(
    document: *const std.json.ObjectMap,
    expected_type: []const u8,
    expected_schema: i64,
    key: ?[]const u8,
    source_commit: ?[]const u8,
    diagnostic: *Diagnostic,
) Error!Identity {
    if (support.integerOf(document.get("schema")) != expected_schema or
        !support.stringIs(document.get("type"), expected_type))
    {
        return fail(diagnostic, "invalid {s} schema", .{expected_type});
    }
    const actual_key = support.stringOf(document.get("key"));
    if (actual_key == null or contracts.lookup(actual_key.?) == null) {
        if (actual_key) |text| return fail(
            diagnostic,
            "invalid candidate key: '{s}'",
            .{text},
        );
        return fail(diagnostic, "invalid candidate key: None", .{});
    }
    const entry = contracts.lookup(actual_key.?).?;
    const flavor = contracts.parseFlavor(entry.flavor).?;
    const expected_fields = if (std.mem.eql(u8, expected_type, candidate_type))
        &contracts.candidate_fields
    else if (std.mem.eql(u8, expected_type, native_result_type))
        contracts.nativeResultFields(flavor)
    else
        contracts.azureResultFields(flavor);
    if (!support.hasExactFields(document.*, expected_fields)) return fail(
        diagnostic,
        "invalid {s} fields",
        .{expected_type},
    );
    if (key) |expected| {
        if (!std.mem.eql(u8, actual_key.?, expected)) return fail(
            diagnostic,
            "candidate key mismatch: expected {s}, got {s}",
            .{ expected, actual_key.? },
        );
    }
    if (!support.stringIs(document.get("architecture"), entry.architecture)) {
        return fail(diagnostic, "{s}: architecture mismatch", .{actual_key.?});
    }
    if (!support.stringIs(document.get("flavor"), entry.flavor)) {
        return fail(diagnostic, "{s}: flavor mismatch", .{actual_key.?});
    }
    if (!support.stringIs(document.get("asset_name"), entry.asset_name)) {
        return fail(diagnostic, "{s}: asset name mismatch", .{actual_key.?});
    }
    const actual_commit = try support.requireCommit(
        document.get("source_commit"),
        "source_commit",
        diagnostic,
    );
    if (source_commit) |expected| {
        if (!std.mem.eql(u8, actual_commit, expected)) return fail(
            diagnostic,
            "{s}: source commit mismatch",
            .{actual_key.?},
        );
    }
    return .{
        .key = actual_key.?,
        .architecture = entry.architecture,
        .flavor = entry.flavor,
        .asset_name = entry.asset_name,
        .source_commit = actual_commit,
    };
}

/// A candidate manifest that has been re-verified against its asset and its
/// provenance tree.
pub const Candidate = struct {
    document: support.json_document.Document,
    identity: Identity,
    sha256: []const u8,
    bytes: i64,
    virtual_size: i64,
    certificate_sha256: []const u8,
    signing_certificate_sha256: []const u8,
    fallback_uki_sha256: []const u8,

    pub fn object(self: *const Candidate) *const std.json.ObjectMap {
        return self.document.object();
    }

    pub fn flavor(self: *const Candidate) contracts.Flavor {
        return self.identity.parsedFlavor();
    }

    pub fn deinit(self: *Candidate) void {
        self.document.deinit();
        self.* = undefined;
    }
};

/// `verify_candidate`.
pub fn verifyCandidate(
    allocator: Allocator,
    io: Io,
    manifest_path: []const u8,
    asset_path: []const u8,
    key: ?[]const u8,
    source_commit: ?[]const u8,
    diagnostic: *Diagnostic,
) Error!Candidate {
    var document = try support.readObject(allocator, io, manifest_path, diagnostic);
    errdefer document.deinit();
    const object = document.object();
    const identity = try validateIdentity(
        object,
        candidate_type,
        1,
        key,
        source_commit,
        diagnostic,
    );
    const flavor = identity.parsedFlavor();

    if (!std.mem.eql(u8, std.fs.path.basename(asset_path), identity.asset_name) or
        !support.isRegularFile(io, asset_path))
    {
        return fail(
            diagnostic,
            "{s}: exact candidate asset is missing",
            .{identity.key},
        );
    }
    var digest_label_buffer: [96]u8 = undefined;
    const sha256 = try support.requireSha256(
        object.get("sha256"),
        std.fmt.bufPrint(
            &digest_label_buffer,
            "{s} candidate digest",
            .{identity.key},
        ) catch "candidate digest",
        diagnostic,
    );
    const asset = support.hashArtifact(io, asset_path) catch return fail(
        diagnostic,
        "{s}: exact candidate asset is missing",
        .{identity.key},
    );
    if (!std.mem.eql(u8, &asset.hex, sha256)) return fail(
        diagnostic,
        "{s}: candidate bytes do not match the bound digest",
        .{identity.key},
    );
    const recorded_bytes = support.integerOf(object.get("bytes"));
    if (recorded_bytes == null or recorded_bytes.? != @as(i64, @intCast(asset.size))) {
        return fail(diagnostic, "{s}: candidate size mismatch", .{identity.key});
    }
    if (asset.size == 0) return fail(
        diagnostic,
        "{s}: candidate asset is empty",
        .{identity.key},
    );
    const virtual_size = support.integerOf(object.get("virtual_size"));
    if (virtual_size == null or virtual_size.? <= 0) return fail(
        diagnostic,
        "{s}: invalid virtual size",
        .{identity.key},
    );
    if (!support.isExactOrderedStrings(
        object.get("azure_contracts"),
        contracts.azureContracts(flavor),
    )) {
        return fail(
            diagnostic,
            "{s}: Azure acceptance contract binding is invalid",
            .{identity.key},
        );
    }

    const build_validation_fields = [_][]const u8{
        "runner",
        "status",
        "validated_sha256",
    };
    const build_validation = support.objectOf(object.get("build_validation"));
    if (build_validation == null or
        !support.hasExactFields(build_validation.?, &build_validation_fields) or
        !support.stringIs(build_validation.?.get("status"), "success"))
    {
        return fail(
            diagnostic,
            "{s}: build validation is not explicitly successful",
            .{identity.key},
        );
    }
    if (!support.stringIs(build_validation.?.get("validated_sha256"), sha256)) {
        return fail(
            diagnostic,
            "{s}: build validation did not validate published bytes",
            .{identity.key},
        );
    }
    const runner = support.stringOf(build_validation.?.get("runner"));
    if (runner == null or runner.?.len == 0) return fail(
        diagnostic,
        "{s}: build runner identity is absent",
        .{identity.key},
    );

    const provenance_fields = [_][]const u8{ "digest", "files" };
    const provenance_binding = support.objectOf(object.get("provenance"));
    if (provenance_binding == null or
        !support.hasExactFields(provenance_binding.?, &provenance_fields))
    {
        return fail(diagnostic, "{s}: provenance is absent", .{identity.key});
    }
    var provenance_digest_label_buffer: [96]u8 = undefined;
    _ = try support.requireSha256(
        provenance_binding.?.get("digest"),
        std.fmt.bufPrint(
            &provenance_digest_label_buffer,
            "{s} provenance digest",
            .{identity.key},
        ) catch "provenance digest",
        diagnostic,
    );
    const files = support.arrayOf(provenance_binding.?.get("files"));
    if (files == null or files.?.len == 0) return fail(
        diagnostic,
        "{s}: provenance file bindings are absent",
        .{identity.key},
    );

    const manifest_parent = std.fs.path.dirname(manifest_path) orelse ".";
    const provenance_root = try support.joinPath(
        allocator,
        &.{ manifest_parent, "internal-provenance" },
    );
    defer allocator.free(provenance_root);

    // A provenance tree that cannot be listed is an empty allowlist, exactly
    // as `rglob` on a missing directory is, so the file-set comparison below
    // rejects it rather than skipping the check.
    const actual_paths = support.listFiles(allocator, io, provenance_root) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => try allocator.alloc([]const u8, 0),
        };
    defer support.freePaths(allocator, actual_paths);

    var bound: std.StringHashMapUnmanaged(void) = .empty;
    defer bound.deinit(allocator);
    const record_fields = [_][]const u8{ "bytes", "path", "sha256" };
    for (files.?) |entry| {
        const record = support.objectOf(entry);
        if (record == null or !support.hasExactFields(record.?, &record_fields)) {
            return fail(
                diagnostic,
                "{s}: invalid provenance record",
                .{identity.key},
            );
        }
        const relative = support.stringOf(record.?.get("path"));
        if (relative == null or relative.?.len == 0 or
            std.fs.path.isAbsolute(relative.?) or
            hasParentComponent(relative.?) or
            bound.contains(relative.?))
        {
            return fail(diagnostic, "{s}: invalid provenance path", .{identity.key});
        }
        const path = try support.joinPath(
            allocator,
            &.{ provenance_root, relative.? },
        );
        defer allocator.free(path);

        if (support.isRegularFile(io, path)) {
            const contents = support.file_support.readBounded(
                allocator,
                io,
                path,
                support.artifact_max_bytes,
            ) catch |err| switch (err) {
                error.OutOfMemory => return error.OutOfMemory,
                else => return fail(
                    diagnostic,
                    "cannot read {s}: {s}",
                    .{ path, @errorName(err) },
                ),
            };
            defer allocator.free(contents);
            if (keys.containsPrivateKey(contents)) return fail(
                diagnostic,
                "{s}: private key material is forbidden in provenance",
                .{identity.key},
            );
            const recorded_size = support.integerOf(record.?.get("bytes"));
            if (recorded_size == null or
                recorded_size.? != @as(i64, @intCast(contents.len)))
            {
                return fail(
                    diagnostic,
                    "{s}: provenance file/size mismatch for {s}",
                    .{ identity.key, relative.? },
                );
            }
            if (!support.stringIs(
                record.?.get("sha256"),
                &support.digest.hexBytes(contents),
            )) {
                return fail(
                    diagnostic,
                    "{s}: provenance digest mismatch for {s}",
                    .{ identity.key, relative.? },
                );
            }
        } else {
            return fail(
                diagnostic,
                "{s}: provenance file/size mismatch for {s}",
                .{ identity.key, relative.? },
            );
        }
        try bound.put(allocator, relative.?, {});
    }
    if (bound.count() != actual_paths.len) return fail(
        diagnostic,
        "{s}: provenance file allowlist mismatch",
        .{identity.key},
    );
    for (actual_paths) |path| {
        if (!bound.contains(path)) return fail(
            diagnostic,
            "{s}: provenance file allowlist mismatch",
            .{identity.key},
        );
    }

    const aggregate = try support.canonicalDigest(
        allocator,
        provenance_binding.?.get("files").?,
    );
    if (!support.stringIs(provenance_binding.?.get("digest"), &aggregate)) {
        return fail(
            diagnostic,
            "{s}: aggregate provenance digest mismatch",
            .{identity.key},
        );
    }

    if (support.objectOf(object.get("ubuntu_provenance")) == null) return fail(
        diagnostic,
        "{s}: Ubuntu provenance binding is absent",
        .{identity.key},
    );
    var ubuntu = try provenance.validateUbuntu(
        allocator,
        io,
        provenance_root,
        identity.architecture,
        flavor,
        virtual_size.?,
        diagnostic,
    );
    defer ubuntu.deinit();
    if (!support.jsonEqual(object.get("ubuntu_provenance").?, ubuntu.value())) {
        return fail(
            diagnostic,
            "{s}: Ubuntu provenance binding does not match files",
            .{identity.key},
        );
    }

    if (support.objectOf(object.get("uki_signing")) == null) return fail(
        diagnostic,
        "{s}: UKI signing binding is absent",
        .{identity.key},
    );
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const signing = try provenance.validateSigning(
        allocator,
        Builder.init(arena.allocator()),
        io,
        provenance_root,
        identity.architecture,
        flavor,
        diagnostic,
    );
    if (!support.jsonEqual(object.get("uki_signing").?, signing.value)) {
        return fail(
            diagnostic,
            "{s}: UKI signing binding does not match provenance",
            .{identity.key},
        );
    }

    if (!hasWorkflowIdentity(object.get("workflow"))) return fail(
        diagnostic,
        "{s}: workflow identity is absent",
        .{identity.key},
    );

    const bound_signing = support.objectOf(object.get("uki_signing")).?;
    return .{
        .document = document,
        .identity = identity,
        .sha256 = sha256,
        .bytes = recorded_bytes.?,
        .virtual_size = virtual_size.?,
        .certificate_sha256 = support.stringOf(
            bound_signing.get("certificate_sha256"),
        ).?,
        .signing_certificate_sha256 = support.stringOf(
            bound_signing.get("signing_certificate_sha256"),
        ).?,
        .fallback_uki_sha256 = support.stringOf(
            bound_signing.get("fallback_uki_sha256"),
        ).?,
    };
}

fn hasParentComponent(relative: []const u8) bool {
    var parts = std.mem.splitScalar(u8, relative, '/');
    while (parts.next()) |part| {
        if (std.mem.eql(u8, part, "..")) return true;
    }
    return false;
}

/// `{"run_id": <positive decimal string>,
///   "run_attempt": <positive decimal string>}`.
pub fn hasWorkflowIdentity(value: ?std.json.Value) bool {
    const object = support.objectOf(value) orelse return false;
    const expected = [_][]const u8{ "run_attempt", "run_id" };
    if (!support.hasExactFields(object, &expected)) return false;
    for (expected) |field| {
        const text = support.stringOf(object.get(field)) orelse return false;
        if (!isPositiveDecimal(text)) return false;
    }
    return true;
}

pub fn workflowIdentityMatches(
    actual: ?std.json.Value,
    expected: ?std.json.Value,
) bool {
    if (!hasWorkflowIdentity(actual) or !hasWorkflowIdentity(expected)) {
        return false;
    }
    return support.jsonEqual(actual.?, expected.?);
}

fn isPositiveDecimal(value: []const u8) bool {
    if (value.len == 0 or value[0] == '0') return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    const parsed = std.fmt.parseInt(i64, value, 10) catch return false;
    return parsed > 0;
}

/// `validate_native_result`, given an already-verified candidate.
pub fn validateNativeResult(
    allocator: Allocator,
    io: Io,
    candidate: *const Candidate,
    result_path: []const u8,
    diagnostic: *Diagnostic,
) Error!support.json_document.Document {
    var result = try support.readObject(allocator, io, result_path, diagnostic);
    errdefer result.deinit();
    try validateNativeResultDocument(result.object(), candidate, diagnostic);
    return result;
}

pub fn nativeResultSchema(flavor: contracts.Flavor) i64 {
    return switch (flavor) {
        // Schema 4 binds the exact candidate workflow attempt in addition to
        // the QEMU execution and acceptance workflow identities.
        .full => 4,
        // Schema 9 carries the same candidate-attempt binding for core.
        .core => 9,
    };
}

fn validateQemuExecution(
    value: ?std.json.Value,
    architecture: []const u8,
    key: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const object = support.objectOf(value);
    const profile = execution.forName(architecture);
    if (object == null or profile == null or
        !support.hasExactFields(object.?, &execution.identity_fields))
    {
        return fail(
            diagnostic,
            "{s}: QEMU execution identity is malformed",
            .{key},
        );
    }
    const expected = profile.?;
    if (!support.stringIs(
        object.?.get("accelerator"),
        @tagName(expected.accelerator),
    ) or
        !support.stringIs(object.?.get("cpu"), expected.cpu) or
        !support.stringIs(object.?.get("emulator"), expected.emulator) or
        !support.stringIs(object.?.get("guest_architecture"), architecture) or
        !support.stringIs(object.?.get("machine"), expected.machine) or
        !support.stringIs(
            object.?.get("runner_architecture"),
            expected.runner_architecture,
        ))
    {
        return fail(
            diagnostic,
            "{s}: QEMU execution identity is invalid",
            .{key},
        );
    }
}

pub fn validateNativeResultDocument(
    result: *const std.json.ObjectMap,
    candidate: *const Candidate,
    diagnostic: *Diagnostic,
) Error!void {
    const flavor = candidate.flavor();
    const key = candidate.identity.key;
    _ = try validateIdentity(
        result,
        native_result_type,
        nativeResultSchema(flavor),
        key,
        candidate.identity.source_commit,
        diagnostic,
    );
    if (!support.stringIs(result.get("status"), "success")) return fail(
        diagnostic,
        "{s}: native acceptance is not explicitly successful",
        .{key},
    );
    if (!workflowIdentityMatches(
        result.get("candidate_workflow"),
        candidate.object().get("workflow"),
    )) {
        return fail(
            diagnostic,
            "{s}: native candidate workflow identity is invalid",
            .{key},
        );
    }
    if (support.integerOf(result.get("virtual_size")) != candidate.virtual_size or
        !support.stringIs(result.get("candidate_sha256"), candidate.sha256) or
        !support.stringIs(
            result.get("certificate_sha256"),
            candidate.certificate_sha256,
        ) or
        !support.stringIs(
            result.get("fallback_uki_sha256"),
            candidate.fallback_uki_sha256,
        ))
    {
        return fail(diagnostic, "{s}: native acceptance identity is invalid", .{key});
    }
    try validateQemuExecution(
        result.get("execution"),
        candidate.identity.architecture,
        key,
        diagnostic,
    );
    if (!hasWorkflowIdentity(result.get("workflow"))) return fail(
        diagnostic,
        "{s}: native workflow identity is absent",
        .{key},
    );
    if (!support.hasExactContracts(
        result.get("contracts"),
        contracts.nativeContracts(flavor),
    )) {
        return fail(
            diagnostic,
            "{s}: native acceptance contracts are invalid",
            .{key},
        );
    }
}

/// `validate_azure_uefi_settings`.
pub fn validateAzureUefiSettings(
    allocator: Allocator,
    settings: ?std.json.Value,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const expected_fields = [_][]const u8{
        "additionalSignatures",
        "signatureTemplateNames",
    };
    const object = support.objectOf(settings);
    if (object == null or !support.hasExactFields(object.?, &expected_fields)) {
        return fail(
            diagnostic,
            "Azure custom UEFI settings have an unexpected shape",
            .{},
        );
    }
    const templates = [_][]const u8{"MicrosoftUefiCertificateAuthorityTemplate"};
    if (!support.isExactOrderedStrings(
        object.?.get("signatureTemplateNames"),
        &templates,
    )) {
        return fail(
            diagnostic,
            "Azure custom UEFI settings do not retain the Microsoft template",
            .{},
        );
    }
    const additional_fields = [_][]const u8{"db"};
    const additional = support.objectOf(object.?.get("additionalSignatures"));
    if (additional == null or
        !support.hasExactFields(additional.?, &additional_fields))
    {
        return fail(
            diagnostic,
            "Azure custom UEFI additional signatures are invalid",
            .{},
        );
    }
    const db = support.arrayOf(additional.?.get("db"));
    if (db == null or db.?.len != 1) return fail(
        diagnostic,
        "Azure custom UEFI db signature is invalid",
        .{},
    );
    const entry_fields = [_][]const u8{ "type", "value" };
    const entry = support.objectOf(db.?[0]);
    if (entry == null or
        !support.stringIs(entry.?.get("type"), "x509") or
        !support.hasExactFields(entry.?, &entry_fields))
    {
        return fail(
            diagnostic,
            "Azure custom UEFI db signature is invalid",
            .{},
        );
    }
    const values = support.arrayOf(entry.?.get("value"));
    if (values == null or values.?.len != 1 or values.?[0] != .string) return fail(
        diagnostic,
        "Azure custom UEFI db signature is invalid",
        .{},
    );
    const certificate = provenance.decodeBase64(
        allocator,
        values.?[0].string,
    ) catch return fail(
        diagnostic,
        "Azure custom UEFI certificate is not canonical base64",
        .{},
    );
    defer allocator.free(certificate);
    if (!std.mem.eql(
        u8,
        &support.digest.hexBytes(certificate),
        certificate_sha256,
    )) {
        return fail(
            diagnostic,
            "Azure custom UEFI certificate fingerprint mismatch",
            .{},
        );
    }
}

/// `gallery_uefi_settings`.
pub fn galleryUefiSettings(document: *const std.json.ObjectMap) ?std.json.Value {
    const properties = support.objectOf(document.get("properties")) orelse return null;
    const security = support.objectOf(properties.get("securityProfile")) orelse
        return null;
    return security.get("uefiSettings");
}

/// `validate_azure_gallery_uefi_settings`.
pub fn validateAzureGalleryUefiSettings(
    allocator: Allocator,
    request: *const std.json.ObjectMap,
    response: *const std.json.ObjectMap,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const request_uefi = galleryUefiSettings(request);
    const response_uefi = galleryUefiSettings(response);
    if (request_uefi == null or support.objectOf(request_uefi) == null) return fail(
        diagnostic,
        "Azure gallery request omitted custom UEFI settings",
        .{},
    );
    if (response_uefi != null and
        !support.jsonEqual(request_uefi.?, response_uefi.?))
    {
        return fail(
            diagnostic,
            "Azure gallery version returned different custom UEFI settings",
            .{},
        );
    }
    try validateAzureUefiSettings(
        allocator,
        request_uefi,
        certificate_sha256,
        diagnostic,
    );
    return request_uefi.?;
}

pub const conversion_fields = [_][]const u8{
    "key",
    "operation",
    "parameters",
    "result",
    "schema",
    "source",
    "status",
    "tool",
    "type",
};

pub const conversion_result_fields = [_][]const u8{
    "bytes",
    "current_size",
    "qemu_info_sha256",
    "qemu_virtual_size",
    "sha256",
};

/// The 1 MiB-aligned size a derived VHD's footer must record for a candidate
/// of `virtual_size` bytes.
pub fn expectedVhdCurrentSize(virtual_size: i64) i64 {
    const alignment: i64 = @intCast(azure_vhd.alignment);
    return @divTrunc(virtual_size + alignment - 1, alignment) * alignment;
}

/// The parts of a conversion attestation that every consumer re-checks.
pub fn validateConversionIdentity(
    conversion: ?std.json.Value,
    key: []const u8,
    diagnostic: *Diagnostic,
    comptime prefix: []const u8,
) Error!std.json.ObjectMap {
    const object = support.objectOf(conversion);
    if (object == null or
        !support.hasExactFields(object.?, &conversion_fields) or
        support.integerOf(object.?.get("schema")) != 1 or
        !support.stringIs(object.?.get("type"), "miz-azure-vhd-conversion") or
        !support.stringIs(object.?.get("key"), key) or
        !support.stringIs(object.?.get("status"), "success") or
        !support.stringIs(object.?.get("tool"), "miz") or
        !support.stringIs(object.?.get("operation"), "azure derive"))
    {
        return fail(
            diagnostic,
            prefix ++ "Azure VHD conversion attestation is invalid",
            .{key},
        );
    }
    return object.?;
}

/// `source` and `parameters` bound to the candidate bytes.
pub fn validateConversionBindings(
    conversion: std.json.ObjectMap,
    candidate: *const Candidate,
    diagnostic: *Diagnostic,
    comptime prefix: []const u8,
) Error!void {
    const key = candidate.identity.key;
    const source_fields = [_][]const u8{
        "asset_name",
        "bytes",
        "sha256_after",
        "sha256_before",
        "virtual_size",
    };
    const source = support.objectOf(conversion.get("source"));
    if (source == null or
        !support.hasExactFields(source.?, &source_fields) or
        !support.stringIs(source.?.get("asset_name"), candidate.identity.asset_name) or
        !support.stringIs(source.?.get("sha256_before"), candidate.sha256) or
        !support.stringIs(source.?.get("sha256_after"), candidate.sha256) or
        support.integerOf(source.?.get("bytes")) != candidate.bytes or
        support.integerOf(source.?.get("virtual_size")) != candidate.virtual_size)
    {
        return fail(
            diagnostic,
            prefix ++ "Azure VHD conversion source binding is invalid",
            .{key},
        );
    }
    const parameter_fields = [_][]const u8{
        "expected_virtual_size",
        "input_sha256",
        "output_format",
        "vhd_alignment_bytes",
        "vhd_footer_bytes",
    };
    const parameters = support.objectOf(conversion.get("parameters"));
    if (parameters == null or
        !support.hasExactFields(parameters.?, &parameter_fields) or
        !support.stringIs(parameters.?.get("input_sha256"), candidate.sha256) or
        support.integerOf(parameters.?.get("expected_virtual_size")) !=
            candidate.virtual_size or
        !support.stringIs(parameters.?.get("output_format"), "vpc-fixed") or
        support.integerOf(parameters.?.get("vhd_alignment_bytes")) !=
            @as(i64, @intCast(azure_vhd.alignment)) or
        support.integerOf(parameters.?.get("vhd_footer_bytes")) !=
            @as(i64, @intCast(azure_vhd.footer_bytes)))
    {
        return fail(
            diagnostic,
            prefix ++ "Azure VHD conversion parameters are invalid",
            .{key},
        );
    }
}

/// `validate_conversion_attestation`: the harness-produced attestation must
/// agree with the VHD that was actually derived and validated.
pub fn validateConversionAttestation(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    candidate: *const Candidate,
    vhd_path: []const u8,
    vhd_info_path: []const u8,
    inspection: azure_vhd.Inspection,
    diagnostic: *Diagnostic,
) Error!support.json_document.Document {
    var document = try support.readObject(allocator, io, path, diagnostic);
    errdefer document.deinit();
    const object = document.object();
    const expected_fields = conversion_fields;
    if (!support.hasExactFields(object.*, &expected_fields)) return fail(
        diagnostic,
        "Azure VHD conversion attestation has unexpected fields",
        .{},
    );
    if (support.integerOf(object.get("schema")) != 1 or
        !support.stringIs(object.get("type"), "miz-azure-vhd-conversion") or
        !support.stringIs(object.get("key"), candidate.identity.key) or
        !support.stringIs(object.get("status"), "success") or
        !support.stringIs(object.get("tool"), "miz") or
        !support.stringIs(object.get("operation"), "azure derive"))
    {
        return fail(
            diagnostic,
            "Azure VHD conversion attestation identity is invalid",
            .{},
        );
    }

    const source_fields = [_][]const u8{
        "asset_name",
        "bytes",
        "sha256_after",
        "sha256_before",
        "virtual_size",
    };
    const source = support.objectOf(object.get("source"));
    if (source == null or !support.hasExactFields(source.?, &source_fields)) {
        return fail(
            diagnostic,
            "Azure VHD conversion source binding is invalid",
            .{},
        );
    }
    if (!support.stringIs(source.?.get("asset_name"), candidate.identity.asset_name) or
        !support.stringIs(source.?.get("sha256_before"), candidate.sha256) or
        !support.stringIs(source.?.get("sha256_after"), candidate.sha256) or
        support.integerOf(source.?.get("bytes")) != candidate.bytes or
        support.integerOf(source.?.get("virtual_size")) != candidate.virtual_size)
    {
        return fail(
            diagnostic,
            "Azure VHD conversion is not bound to the candidate bytes",
            .{},
        );
    }
    const parameter_fields = [_][]const u8{
        "expected_virtual_size",
        "input_sha256",
        "output_format",
        "vhd_alignment_bytes",
        "vhd_footer_bytes",
    };
    const parameters = support.objectOf(object.get("parameters"));
    if (parameters == null or
        !support.hasExactFields(parameters.?, &parameter_fields) or
        !support.stringIs(parameters.?.get("input_sha256"), candidate.sha256) or
        support.integerOf(parameters.?.get("expected_virtual_size")) !=
            candidate.virtual_size or
        !support.stringIs(parameters.?.get("output_format"), "vpc-fixed") or
        support.integerOf(parameters.?.get("vhd_alignment_bytes")) !=
            @as(i64, @intCast(azure_vhd.alignment)) or
        support.integerOf(parameters.?.get("vhd_footer_bytes")) !=
            @as(i64, @intCast(azure_vhd.footer_bytes)))
    {
        return fail(diagnostic, "Azure VHD conversion parameters are invalid", .{});
    }
    if (@as(i64, @intCast(inspection.current_size)) !=
        expectedVhdCurrentSize(candidate.virtual_size))
    {
        return fail(
            diagnostic,
            "derived VHD current size is not the aligned candidate virtual size",
            .{},
        );
    }

    const vhd_digest = support.hashArtifact(io, vhd_path) catch return fail(
        diagnostic,
        "Azure VHD conversion result does not match the validated VHD",
        .{},
    );
    const info_digest = support.hashArtifact(io, vhd_info_path) catch return fail(
        diagnostic,
        "Azure VHD conversion result does not match the validated VHD",
        .{},
    );
    const result = support.objectOf(object.get("result"));
    if (result == null or
        !support.hasExactFields(result.?, &conversion_result_fields) or
        !support.stringIs(result.?.get("sha256"), &vhd_digest.hex) or
        support.integerOf(result.?.get("bytes")) !=
            @as(i64, @intCast(inspection.file_size)) or
        support.integerOf(result.?.get("current_size")) !=
            @as(i64, @intCast(inspection.current_size)) or
        support.integerOf(result.?.get("qemu_virtual_size")) !=
            @as(i64, @intCast(inspection.qemu_virtual_size)) or
        !support.stringIs(result.?.get("qemu_info_sha256"), &info_digest.hex))
    {
        return fail(
            diagnostic,
            "Azure VHD conversion result does not match the validated VHD",
            .{},
        );
    }
    return document;
}

/// The derived-VHD size evidence a stored conversion result must carry.
pub fn validateConversionSizes(
    conversion: std.json.ObjectMap,
    candidate: *const Candidate,
    diagnostic: *Diagnostic,
    comptime prefix: []const u8,
) Error![]const u8 {
    const key = candidate.identity.key;
    const result = support.objectOf(conversion.get("result"));
    if (result == null or
        !support.hasExactFields(result.?, &conversion_result_fields))
    {
        return fail(
            diagnostic,
            prefix ++ "Azure VHD conversion result is invalid",
            .{key},
        );
    }
    var digest_label_buffer: [96]u8 = undefined;
    const vhd_sha256 = try support.requireSha256(
        result.?.get("sha256"),
        std.fmt.bufPrint(
            &digest_label_buffer,
            "{s} VHD digest",
            .{key},
        ) catch "VHD digest",
        diagnostic,
    );
    var info_label_buffer: [96]u8 = undefined;
    _ = try support.requireSha256(
        result.?.get("qemu_info_sha256"),
        std.fmt.bufPrint(
            &info_label_buffer,
            "{s} qemu VHD info digest",
            .{key},
        ) catch "qemu VHD info digest",
        diagnostic,
    );
    const derived_bytes = support.integerOf(result.?.get("bytes"));
    const derived_current = support.integerOf(result.?.get("current_size"));
    const qemu_virtual_size = support.integerOf(result.?.get("qemu_virtual_size"));
    if (derived_bytes == null or derived_current == null or
        qemu_virtual_size == null or
        derived_current.? <= 0 or
        derived_current.? != expectedVhdCurrentSize(candidate.virtual_size) or
        derived_bytes.? != derived_current.? +
            @as(i64, @intCast(azure_vhd.footer_bytes)) or
        qemu_virtual_size.? <= 0)
    {
        return fail(
            diagnostic,
            prefix ++ "derived VHD size binding is absent",
            .{key},
        );
    }
    return vhd_sha256;
}

/// `validate_azure_result`, given an already-verified candidate.
pub fn validateAzureResult(
    allocator: Allocator,
    io: Io,
    candidate: *const Candidate,
    result_path: []const u8,
    diagnostic: *Diagnostic,
) Error!support.json_document.Document {
    var result = try support.readObject(allocator, io, result_path, diagnostic);
    errdefer result.deinit();
    try validateAzureResultDocument(allocator, result.object(), candidate, diagnostic);
    return result;
}

pub fn validateAzureResultDocument(
    allocator: Allocator,
    result: *const std.json.ObjectMap,
    candidate: *const Candidate,
    diagnostic: *Diagnostic,
) Error!void {
    const flavor = candidate.flavor();
    const identity = try validateIdentity(
        result,
        azure_result_type,
        switch (flavor) {
            .full => 2,
            .core => 4,
        },
        candidate.identity.key,
        support.stringOf(candidate.object().get("source_commit")).?,
        diagnostic,
    );
    const key = identity.key;
    if (!support.stringIs(result.get("status"), "success")) return fail(
        diagnostic,
        "{s}: Azure acceptance is not explicitly successful",
        .{key},
    );
    if (!workflowIdentityMatches(
        result.get("candidate_workflow"),
        candidate.object().get("workflow"),
    )) {
        return fail(
            diagnostic,
            "{s}: Azure candidate workflow identity is invalid",
            .{key},
        );
    }
    if (!support.stringIs(result.get("qcow_sha256"), candidate.sha256) or
        !support.stringIs(result.get("azure_accepted_sha256"), candidate.sha256))
    {
        return fail(
            diagnostic,
            "{s}: Azure acceptance did not validate candidate bytes",
            .{key},
        );
    }
    if (!support.stringIs(
        result.get("certificate_sha256"),
        candidate.certificate_sha256,
    ) or
        !support.stringIs(
            result.get("signing_certificate_sha256"),
            candidate.signing_certificate_sha256,
        ) or
        !support.stringIs(
            result.get("fallback_uki_sha256"),
            candidate.fallback_uki_sha256,
        ))
    {
        return fail(
            diagnostic,
            "{s}: Azure acceptance did not bind the signed UKI identity",
            .{key},
        );
    }
    try validateAzureUefiSettings(
        allocator,
        result.get("uefi_settings"),
        candidate.certificate_sha256,
        diagnostic,
    );
    const image_version_id = support.stringOf(result.get("image_version_id"));
    if (image_version_id == null or
        !std.mem.startsWith(u8, image_version_id.?, "/subscriptions/"))
    {
        return fail(
            diagnostic,
            "{s}: Azure gallery image-version identity is absent",
            .{key},
        );
    }
    const named = [_]struct { field: []const u8, label: []const u8 }{
        .{ .field = "location", .label = "location" },
        .{ .field = "vm_size", .label = "VM size" },
        .{ .field = "resource_group", .label = "resource group" },
    };
    for (named) |entry| {
        const text = support.stringOf(result.get(entry.field));
        if (text == null or text.?.len == 0) return fail(
            diagnostic,
            "{s}: Azure {s} is absent",
            .{ key, entry.label },
        );
    }
    if (!hasWorkflowIdentity(result.get("workflow"))) return fail(
        diagnostic,
        "{s}: Azure workflow identity is absent",
        .{key},
    );
    const expected_contracts = contracts.azureContracts(flavor);
    if (!support.isExactOrderedStrings(
        candidate.object().get("azure_contracts"),
        expected_contracts,
    )) {
        return fail(
            diagnostic,
            "{s}: candidate Azure contract binding is invalid",
            .{key},
        );
    }
    if (!support.isExactOrderedStrings(result.get("contracts"), expected_contracts)) {
        return fail(
            diagnostic,
            "{s}: Azure contracts do not match candidate metadata",
            .{key},
        );
    }

    const conversion = try validateConversionIdentity(
        result.get("conversion"),
        key,
        diagnostic,
        "{s}: ",
    );
    try validateConversionBindings(conversion, candidate, diagnostic, "{s}: ");
    _ = try validateConversionSizes(conversion, candidate, diagnostic, "{s}: ");
}

test "workflow identity requires two positive decimal strings" {
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        std.testing.allocator,
        \\{"ok": {"run_id": "1", "run_attempt": "2"},
        \\ "empty": {"run_id": "", "run_attempt": "2"},
        \\ "typed": {"run_id": 1, "run_attempt": "2"},
        \\ "zero": {"run_id": "1", "run_attempt": "0"},
        \\ "text": {"run_id": "run", "run_attempt": "2"},
        \\ "extra": {"run_id": "1", "run_attempt": "2", "x": "3"},
        \\ "short": {"run_id": "1"}}
    ,
        .{},
    );
    defer parsed.deinit();
    const object = &parsed.value.object;
    try std.testing.expect(hasWorkflowIdentity(object.get("ok")));
    try std.testing.expect(!hasWorkflowIdentity(object.get("empty")));
    try std.testing.expect(!hasWorkflowIdentity(object.get("typed")));
    try std.testing.expect(!hasWorkflowIdentity(object.get("zero")));
    try std.testing.expect(!hasWorkflowIdentity(object.get("text")));
    try std.testing.expect(!hasWorkflowIdentity(object.get("extra")));
    try std.testing.expect(!hasWorkflowIdentity(object.get("short")));
    try std.testing.expect(!hasWorkflowIdentity(null));
}

test "provenance paths reject traversal and absolute spellings" {
    try std.testing.expect(hasParentComponent("a/../b"));
    try std.testing.expect(hasParentComponent(".."));
    try std.testing.expect(!hasParentComponent("a/b..c"));
    try std.testing.expect(!hasParentComponent("a/b"));
}

test "expectedVhdCurrentSize rounds up to the Azure alignment" {
    try std.testing.expectEqual(@as(i64, 1024 * 1024), expectedVhdCurrentSize(1));
    try std.testing.expectEqual(
        @as(i64, 1024 * 1024),
        expectedVhdCurrentSize(1024 * 1024),
    );
    try std.testing.expectEqual(
        @as(i64, 2 * 1024 * 1024),
        expectedVhdCurrentSize(1024 * 1024 + 1),
    );
}
