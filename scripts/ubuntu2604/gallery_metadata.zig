//! Portable Azure Compute Gallery metadata for Ubuntu 26.04 release images.
//!
//! The document contains only image-derived and release-derived values.
//! Subscription resources, regions, replication policy, and image-version
//! names remain explicit inputs when a consumer renders an Azure request.

const std = @import("std");
const miz = @import("miz");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const azure_vhd = @import("../azure_vhd.zig");
const contracts = @import("contracts.zig");
const documents = @import("documents.zig");
const provenance = @import("provenance.zig");
const support = @import("support.zig");

const Builder = support.Builder;
const Diagnostic = support.Diagnostic;
const Error = support.Error;
const fail = support.fail;
const trusted_launch = support.azure_trusted_launch;

pub const schema: i64 = 1;
pub const document_type = "miz-ubuntu2604-gallery-metadata";

const top_fields = [_][]const u8{
    "architecture",
    "conversion",
    "flavor",
    "image",
    "image_definition",
    "image_version",
    "key",
    "metadata_name",
    "provenance",
    "schema",
    "signing",
    "type",
};

const image_fields = [_][]const u8{
    "asset_name",
    "bytes",
    "sha256",
    "source_commit",
    "virtual_size",
};

const conversion_fields = [_][]const u8{
    "expected_virtual_size",
    "output_format",
    "source_format",
    "vhd_alignment_bytes",
    "vhd_footer_bytes",
};

const signing_fields = [_][]const u8{
    "artifact_signing",
    "fallback_uki",
    "uefi_db",
};

const artifact_signing_fields = [_][]const u8{
    "certificate_sha256",
    "provider",
};

const provider_fields = [_][]const u8{
    "account",
    "endpoint",
    "name",
    "profile",
};

const fallback_uki_fields = [_][]const u8{
    "path",
    "sha256",
};

const uefi_db_fields = [_][]const u8{
    "certificate_der_base64",
    "certificate_sha256",
    "issuer",
    "not_after",
    "not_before",
    "serial",
    "subject",
    "type",
};

const provenance_fields = [_][]const u8{
    "digest",
    "workflow",
};

const image_version_fields = [_][]const u8{"uefi_settings"};

pub const GenerateOptions = struct {
    manifest: []const u8,
    asset: []const u8,
    key: []const u8,
    source_commit: []const u8,
    output: []const u8,
};

pub const VerifyOptions = struct {
    metadata: []const u8,
    manifest: []const u8,
    asset: []const u8,
    key: []const u8,
    source_commit: []const u8,
};

pub const GalleryVersionRequestOptions = struct {
    metadata: []const u8,
    asset: []const u8,
    location: []const u8,
    disk_id: []const u8,
    replication_mode: []const u8,
    regional_replica_count: i64,
    storage_account_type: []const u8,
    output: []const u8,
};

fn detailValue(details: []const u8, prefix: []const u8) ?[]const u8 {
    var lines = std.mem.splitScalar(u8, details, '\n');
    while (lines.next()) |line| {
        if (std.mem.startsWith(u8, line, prefix)) return line[prefix.len..];
    }
    return null;
}

fn fallbackPath(architecture: []const u8) []const u8 {
    return if (std.mem.eql(u8, architecture, "x86_64"))
        "EFI/BOOT/BOOTX64.EFI"
    else
        "EFI/BOOT/BOOTAA64.EFI";
}

fn certificateDetails(
    allocator: Allocator,
    certificate_der: []const u8,
    diagnostic: *Diagnostic,
) Error![]u8 {
    miz.authenticode.validateX509CertificateDer(certificate_der) catch
        return fail(
            diagnostic,
            "gallery metadata UEFI db certificate is not valid X.509 DER",
            .{},
        );
    return miz.authenticode.describeCertificateAlloc(
        allocator,
        certificate_der,
    ) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => fail(
            diagnostic,
            "gallery metadata UEFI db certificate is not valid X.509 DER",
            .{},
        ),
    };
}

pub fn build(
    allocator: Allocator,
    builder: Builder,
    candidate: *const documents.Candidate,
    diagnostic: *Diagnostic,
) Error!std.json.Value {
    const entry = contracts.lookup(candidate.identity.key).?;
    const azure_architecture = contracts.azureArchitecture(
        entry.architecture,
    ).?;
    const signing = support.objectOf(
        candidate.object().get("uki_signing"),
    ).?;
    const encoded = support.stringOf(signing.get("certificate_der_base64")).?;
    const certificate_der = provenance.decodeBase64(allocator, encoded) catch
        return fail(
            diagnostic,
            "gallery metadata UEFI db certificate is not canonical base64",
            .{},
        );
    defer allocator.free(certificate_der);
    const details = try certificateDetails(
        allocator,
        certificate_der,
        diagnostic,
    );
    defer allocator.free(details);
    const not_before = detailValue(details, "notBefore=") orelse return fail(
        diagnostic,
        "gallery metadata UEFI db certificate validity is absent",
        .{},
    );
    const not_after = detailValue(details, "notAfter=") orelse return fail(
        diagnostic,
        "gallery metadata UEFI db certificate validity is absent",
        .{},
    );
    const subject = detailValue(details, "subject=") orelse return fail(
        diagnostic,
        "gallery metadata UEFI db certificate identity is absent",
        .{},
    );
    const issuer = detailValue(details, "issuer=") orelse return fail(
        diagnostic,
        "gallery metadata UEFI db certificate identity is absent",
        .{},
    );
    const serial = detailValue(details, "serial=") orelse return fail(
        diagnostic,
        "gallery metadata UEFI db certificate identity is absent",
        .{},
    );

    var image = builder.object();
    try builder.putString(&image, "asset_name", entry.asset_name);
    try builder.putString(&image, "sha256", candidate.sha256);
    try builder.putInteger(&image, "bytes", candidate.bytes);
    try builder.putInteger(&image, "virtual_size", candidate.virtual_size);
    try builder.putString(
        &image,
        "source_commit",
        candidate.identity.source_commit,
    );

    var conversion = builder.object();
    try builder.putString(&conversion, "source_format", "qcow2");
    try builder.putString(&conversion, "output_format", "vpc-fixed");
    try builder.putInteger(
        &conversion,
        "expected_virtual_size",
        candidate.virtual_size,
    );
    try builder.putInteger(
        &conversion,
        "vhd_alignment_bytes",
        @intCast(azure_vhd.alignment),
    );
    try builder.putInteger(
        &conversion,
        "vhd_footer_bytes",
        @intCast(azure_vhd.footer_bytes),
    );

    const definition = try trusted_launch.imageDefinitionContract(
        builder.arena,
        azure_architecture,
    );
    const uefi_settings = try trusted_launch.uefiSettings(
        builder.arena,
        certificate_der,
    );
    var image_version = builder.object();
    try builder.put(&image_version, "uefi_settings", uefi_settings);

    const provider = support.objectOf(signing.get("provider")).?;
    var artifact_signing = builder.object();
    try builder.putString(
        &artifact_signing,
        "certificate_sha256",
        candidate.signing_certificate_sha256,
    );
    try builder.put(
        &artifact_signing,
        "provider",
        try builder.clone(.{ .object = provider }),
    );

    var fallback_uki = builder.object();
    try builder.putString(
        &fallback_uki,
        "path",
        fallbackPath(entry.architecture),
    );
    try builder.putString(
        &fallback_uki,
        "sha256",
        candidate.fallback_uki_sha256,
    );

    var uefi_db = builder.object();
    try builder.putString(&uefi_db, "type", "x509");
    try builder.putString(
        &uefi_db,
        "certificate_sha256",
        candidate.certificate_sha256,
    );
    try builder.putString(
        &uefi_db,
        "certificate_der_base64",
        encoded,
    );
    try builder.putString(&uefi_db, "subject", subject);
    try builder.putString(&uefi_db, "issuer", issuer);
    try builder.putString(&uefi_db, "serial", serial);
    try builder.putString(&uefi_db, "not_before", not_before);
    try builder.putString(&uefi_db, "not_after", not_after);

    var signing_value = builder.object();
    try builder.put(
        &signing_value,
        "artifact_signing",
        .{ .object = artifact_signing },
    );
    try builder.put(
        &signing_value,
        "fallback_uki",
        .{ .object = fallback_uki },
    );
    try builder.put(&signing_value, "uefi_db", .{ .object = uefi_db });

    const provenance_binding = support.objectOf(
        candidate.object().get("provenance"),
    ).?;
    var provenance_value = builder.object();
    try builder.putString(
        &provenance_value,
        "digest",
        support.stringOf(provenance_binding.get("digest")).?,
    );
    try builder.put(
        &provenance_value,
        "workflow",
        try builder.clone(candidate.object().get("workflow").?),
    );

    var document = builder.object();
    try builder.putInteger(&document, "schema", schema);
    try builder.putString(&document, "type", document_type);
    try builder.putString(&document, "key", entry.key);
    try builder.putString(&document, "architecture", entry.architecture);
    try builder.putString(&document, "flavor", entry.flavor);
    try builder.putString(
        &document,
        "metadata_name",
        contracts.galleryMetadataName(entry.key).?,
    );
    try builder.put(&document, "image", .{ .object = image });
    try builder.put(&document, "image_definition", definition);
    try builder.put(
        &document,
        "image_version",
        .{ .object = image_version },
    );
    try builder.put(&document, "conversion", .{ .object = conversion });
    try builder.put(&document, "signing", .{ .object = signing_value });
    try builder.put(
        &document,
        "provenance",
        .{ .object = provenance_value },
    );
    return .{ .object = document };
}

pub fn validateDocument(
    allocator: Allocator,
    document: *const std.json.ObjectMap,
    diagnostic: *Diagnostic,
) Error!void {
    if (!support.hasExactFields(document.*, &top_fields) or
        support.integerOf(document.get("schema")) != schema or
        !support.stringIs(document.get("type"), document_type))
    {
        return fail(diagnostic, "unexpected gallery metadata schema", .{});
    }
    const key = support.stringOf(document.get("key")) orelse return fail(
        diagnostic,
        "gallery metadata candidate identity is invalid",
        .{},
    );
    const entry = contracts.lookup(key) orelse return fail(
        diagnostic,
        "gallery metadata candidate identity is invalid",
        .{},
    );
    const azure_architecture = contracts.azureArchitecture(
        entry.architecture,
    ).?;
    if (!support.stringIs(document.get("architecture"), entry.architecture) or
        !support.stringIs(document.get("flavor"), entry.flavor) or
        !support.stringIs(
            document.get("metadata_name"),
            contracts.galleryMetadataName(key).?,
        ))
    {
        return fail(diagnostic, "gallery metadata candidate identity is invalid", .{});
    }

    const image = support.objectOf(document.get("image")) orelse return fail(
        diagnostic,
        "gallery metadata image binding is invalid",
        .{},
    );
    const sha256 = support.stringOf(image.get("sha256"));
    const bytes = support.integerOf(image.get("bytes"));
    const virtual_size = support.integerOf(image.get("virtual_size"));
    if (!support.hasExactFields(image, &image_fields) or
        !support.stringIs(image.get("asset_name"), entry.asset_name) or
        sha256 == null or !support.isSha256(sha256.?) or
        bytes == null or bytes.? <= 0 or
        virtual_size == null or virtual_size.? <= 0)
    {
        return fail(diagnostic, "gallery metadata image binding is invalid", .{});
    }
    _ = support.requireCommit(
        image.get("source_commit"),
        "gallery metadata source commit",
        diagnostic,
    ) catch return fail(diagnostic, "gallery metadata image binding is invalid", .{});

    const definition = support.objectOf(
        document.get("image_definition"),
    ) orelse return fail(
        diagnostic,
        "gallery metadata image-definition contract is invalid",
        .{},
    );
    trusted_launch.validateImageDefinitionContract(
        &definition,
        azure_architecture,
        diagnostic,
    ) catch return fail(
        diagnostic,
        "gallery metadata image-definition contract is invalid",
        .{},
    );

    const conversion = support.objectOf(
        document.get("conversion"),
    ) orelse return fail(
        diagnostic,
        "gallery metadata conversion contract is invalid",
        .{},
    );
    if (!support.hasExactFields(conversion, &conversion_fields) or
        !support.stringIs(conversion.get("source_format"), "qcow2") or
        !support.stringIs(conversion.get("output_format"), "vpc-fixed") or
        support.integerOf(conversion.get("expected_virtual_size")) !=
            virtual_size.? or
        support.integerOf(conversion.get("vhd_alignment_bytes")) !=
            @as(i64, @intCast(azure_vhd.alignment)) or
        support.integerOf(conversion.get("vhd_footer_bytes")) !=
            @as(i64, @intCast(azure_vhd.footer_bytes)))
    {
        return fail(diagnostic, "gallery metadata conversion contract is invalid", .{});
    }

    const signing = support.objectOf(document.get("signing")) orelse
        return fail(diagnostic, "gallery metadata signing binding is invalid", .{});
    const artifact_signing = support.objectOf(
        signing.get("artifact_signing"),
    ) orelse return fail(
        diagnostic,
        "gallery metadata signing binding is invalid",
        .{},
    );
    const provider = support.objectOf(artifact_signing.get("provider")) orelse
        return fail(diagnostic, "gallery metadata signing binding is invalid", .{});
    const fallback_uki = support.objectOf(signing.get("fallback_uki")) orelse
        return fail(diagnostic, "gallery metadata signing binding is invalid", .{});
    const uefi_db = support.objectOf(signing.get("uefi_db")) orelse return fail(
        diagnostic,
        "gallery metadata signing binding is invalid",
        .{},
    );
    const certificate_sha256 = support.stringOf(
        uefi_db.get("certificate_sha256"),
    );
    const encoded = support.stringOf(uefi_db.get("certificate_der_base64"));
    if (!support.hasExactFields(signing, &signing_fields) or
        !support.hasExactFields(
            artifact_signing,
            &artifact_signing_fields,
        ) or
        !support.hasExactFields(provider, &provider_fields) or
        !support.stringIs(provider.get("name"), "azure-artifact-signing") or
        support.stringOf(provider.get("endpoint")) == null or
        support.stringOf(provider.get("account")) == null or
        support.stringOf(provider.get("profile")) == null or
        !support.hasExactFields(fallback_uki, &fallback_uki_fields) or
        !support.stringIs(
            fallback_uki.get("path"),
            fallbackPath(entry.architecture),
        ) or
        support.stringOf(fallback_uki.get("sha256")) == null or
        !support.isSha256(support.stringOf(fallback_uki.get("sha256")).?) or
        support.stringOf(artifact_signing.get("certificate_sha256")) == null or
        !support.isSha256(
            support.stringOf(
                artifact_signing.get("certificate_sha256"),
            ).?,
        ) or
        !support.hasExactFields(uefi_db, &uefi_db_fields) or
        !support.stringIs(uefi_db.get("type"), "x509") or
        certificate_sha256 == null or !support.isSha256(certificate_sha256.?) or
        encoded == null)
    {
        return fail(diagnostic, "gallery metadata signing binding is invalid", .{});
    }
    const certificate_der = provenance.decodeBase64(
        allocator,
        encoded.?,
    ) catch return fail(
        diagnostic,
        "gallery metadata UEFI db certificate is not canonical base64",
        .{},
    );
    defer allocator.free(certificate_der);
    const encoder = std.base64.standard.Encoder;
    const canonical = try allocator.alloc(
        u8,
        encoder.calcSize(certificate_der.len),
    );
    defer allocator.free(canonical);
    _ = encoder.encode(canonical, certificate_der);
    if (!std.mem.eql(u8, canonical, encoded.?) or
        !std.mem.eql(
            u8,
            &support.digest.hexBytes(certificate_der),
            certificate_sha256.?,
        ))
    {
        return fail(
            diagnostic,
            "gallery metadata UEFI db certificate fingerprint mismatch",
            .{},
        );
    }
    const details = try certificateDetails(
        allocator,
        certificate_der,
        diagnostic,
    );
    defer allocator.free(details);
    const not_before = detailValue(details, "notBefore=");
    const not_after = detailValue(details, "notAfter=");
    const subject = detailValue(details, "subject=");
    const issuer = detailValue(details, "issuer=");
    const serial = detailValue(details, "serial=");
    if (not_before == null or not_after == null or subject == null or
        issuer == null or serial == null or
        !support.stringIs(uefi_db.get("not_before"), not_before.?) or
        !support.stringIs(uefi_db.get("not_after"), not_after.?) or
        !support.stringIs(uefi_db.get("subject"), subject.?) or
        !support.stringIs(uefi_db.get("issuer"), issuer.?) or
        !support.stringIs(uefi_db.get("serial"), serial.?))
    {
        return fail(
            diagnostic,
            "gallery metadata UEFI db certificate validity mismatch",
            .{},
        );
    }

    const image_version = support.objectOf(
        document.get("image_version"),
    ) orelse return fail(
        diagnostic,
        "gallery metadata image-version contract is invalid",
        .{},
    );
    if (!support.hasExactFields(image_version, &image_version_fields)) {
        return fail(
            diagnostic,
            "gallery metadata image-version contract is invalid",
            .{},
        );
    }
    trusted_launch.validateUefiSettings(
        allocator,
        image_version.get("uefi_settings"),
        certificate_sha256.?,
        diagnostic,
    ) catch return fail(
        diagnostic,
        "gallery metadata image-version contract is invalid",
        .{},
    );

    const provenance_value = support.objectOf(
        document.get("provenance"),
    ) orelse return fail(
        diagnostic,
        "gallery metadata provenance binding is invalid",
        .{},
    );
    const provenance_digest = support.stringOf(provenance_value.get("digest"));
    if (!support.hasExactFields(provenance_value, &provenance_fields) or
        provenance_digest == null or !support.isSha256(provenance_digest.?) or
        !documents.hasWorkflowIdentity(provenance_value.get("workflow")))
    {
        return fail(diagnostic, "gallery metadata provenance binding is invalid", .{});
    }
}

fn verifyAsset(
    io: Io,
    document: *const std.json.ObjectMap,
    asset_path: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    const image = support.objectOf(document.get("image")).?;
    const expected_name = support.stringOf(image.get("asset_name")).?;
    const expected_sha256 = support.stringOf(image.get("sha256")).?;
    const expected_bytes = support.integerOf(image.get("bytes")).?;
    if (!std.mem.eql(u8, std.fs.path.basename(asset_path), expected_name)) {
        return fail(diagnostic, "gallery metadata image binding is invalid", .{});
    }
    const digest = support.hashArtifact(io, asset_path) catch return fail(
        diagnostic,
        "gallery metadata image binding is invalid",
        .{},
    );
    if (!std.mem.eql(u8, &digest.hex, expected_sha256) or
        @as(i64, @intCast(digest.size)) != expected_bytes)
    {
        return fail(diagnostic, "gallery metadata image binding is invalid", .{});
    }
}

pub fn generate(
    allocator: Allocator,
    io: Io,
    options: GenerateOptions,
    diagnostic: *Diagnostic,
) Error!void {
    var candidate = try documents.verifyCandidate(
        allocator,
        io,
        options.manifest,
        options.asset,
        options.key,
        options.source_commit,
        diagnostic,
    );
    defer candidate.deinit();
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const value = try build(
        allocator,
        Builder.init(arena.allocator()),
        &candidate,
        diagnostic,
    );
    try support.writeDocument(
        allocator,
        io,
        options.output,
        value,
        diagnostic,
    );
}

pub fn verify(
    allocator: Allocator,
    io: Io,
    options: VerifyOptions,
    diagnostic: *Diagnostic,
) Error!void {
    var candidate = try documents.verifyCandidate(
        allocator,
        io,
        options.manifest,
        options.asset,
        options.key,
        options.source_commit,
        diagnostic,
    );
    defer candidate.deinit();
    var metadata = try verifyCandidateFile(
        allocator,
        io,
        options.metadata,
        options.asset,
        &candidate,
        diagnostic,
    );
    metadata.deinit();
}

pub fn verifyCandidateFile(
    allocator: Allocator,
    io: Io,
    metadata_path: []const u8,
    asset_path: []const u8,
    candidate: *const documents.Candidate,
    diagnostic: *Diagnostic,
) Error!support.json_document.Document {
    var metadata = try support.readObject(
        allocator,
        io,
        metadata_path,
        diagnostic,
    );
    errdefer metadata.deinit();
    try validateDocument(allocator, metadata.object(), diagnostic);
    try verifyAsset(io, metadata.object(), asset_path, diagnostic);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const expected = try build(
        allocator,
        Builder.init(arena.allocator()),
        candidate,
        diagnostic,
    );
    if (!support.jsonEqual(metadata.parsed.value, expected)) return fail(
        diagnostic,
        "gallery metadata does not match the exact candidate",
        .{},
    );
    return metadata;
}

pub fn validateFile(
    allocator: Allocator,
    io: Io,
    metadata_path: []const u8,
    asset_path: ?[]const u8,
    diagnostic: *Diagnostic,
) Error!support.json_document.Document {
    var metadata = try support.readObject(
        allocator,
        io,
        metadata_path,
        diagnostic,
    );
    errdefer metadata.deinit();
    try validateDocument(allocator, metadata.object(), diagnostic);
    if (asset_path) |path| try verifyAsset(
        io,
        metadata.object(),
        path,
        diagnostic,
    );
    return metadata;
}

pub fn writeImageDefinition(
    allocator: Allocator,
    io: Io,
    metadata_path: []const u8,
    asset_path: []const u8,
    output: []const u8,
    diagnostic: *Diagnostic,
) Error!void {
    var metadata = try validateFile(
        allocator,
        io,
        metadata_path,
        asset_path,
        diagnostic,
    );
    defer metadata.deinit();
    try support.writeDocument(
        allocator,
        io,
        output,
        metadata.object().get("image_definition").?,
        diagnostic,
    );
}

fn validStorageAccountType(value: []const u8) bool {
    return std.mem.eql(u8, value, "Standard_LRS") or
        std.mem.eql(u8, value, "Standard_ZRS") or
        std.mem.eql(u8, value, "Premium_LRS");
}

pub fn writeGalleryVersionRequest(
    allocator: Allocator,
    io: Io,
    options: GalleryVersionRequestOptions,
    diagnostic: *Diagnostic,
) Error!void {
    if (options.location.len == 0 or
        !std.mem.startsWith(u8, options.disk_id, "/subscriptions/") or
        (options.replication_mode.len == 0 or
            (!std.mem.eql(u8, options.replication_mode, "Shallow") and
                !std.mem.eql(u8, options.replication_mode, "Full"))) or
        options.regional_replica_count <= 0 or
        !validStorageAccountType(options.storage_account_type))
    {
        return fail(
            diagnostic,
            "gallery image-version deployment parameters are invalid",
            .{},
        );
    }
    var metadata = try validateFile(
        allocator,
        io,
        options.metadata,
        options.asset,
        diagnostic,
    );
    defer metadata.deinit();
    const signing = support.objectOf(metadata.object().get("signing")).?;
    const uefi_db = support.objectOf(signing.get("uefi_db")).?;
    const certificate = provenance.decodeBase64(
        allocator,
        support.stringOf(uefi_db.get("certificate_der_base64")).?,
    ) catch return fail(
        diagnostic,
        "gallery metadata UEFI db certificate is not canonical base64",
        .{},
    );
    defer allocator.free(certificate);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const request = try trusted_launch.galleryVersionRequestWithOptions(
        arena.allocator(),
        .{
            .location = options.location,
            .disk_id = options.disk_id,
            .replication_mode = options.replication_mode,
            .regional_replica_count = options.regional_replica_count,
            .storage_account_type = options.storage_account_type,
        },
        certificate,
    );
    try support.writeDocument(
        allocator,
        io,
        options.output,
        request,
        diagnostic,
    );
}
