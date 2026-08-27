//! Azure acceptance contracts for the Azure Linux 4 release.
//!
//! Native replacement for every inline Python block in
//! `scripts/azurelinux4_azure_acceptance.sh` and the candidate-validation
//! block in `.github/workflows/azurelinux4-release.yml`. Each of those blocks
//! was one contract the acceptance shell could not express itself: reading a
//! field out of an Azure response, or refusing a response that does not say
//! what the release requires.
//!
//! They are collected here rather than left as separate one-off programs
//! because they are one contract set: the SKU the VM runs on, the gallery
//! version's custom UEFI settings, the VM's Trusted Launch profile, and the
//! signature the guest firmware actually holds all describe the same claim,
//! that the exact release signer is enrolled and enforced.
//!
//! Everything here fails closed. A document that cannot be read, a field with
//! the wrong type, and a field that is absent are all rejections, because the
//! shell reads these results as proof.

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
const json_document = release.json_document;

pub const Diagnostic = contract.Diagnostic;

/// Upper bound on a document produced by the Azure CLI or the Compute REST
/// API. A filtered SKU list is the largest of them and is kilobytes.
pub const max_document_bytes: u64 = 16 * 1024 * 1024;

/// Upper bound on the `db` variable read out of a guest's efivarfs. A real
/// `db` is a handful of certificates.
pub const max_uefi_db_bytes: u64 = 4 * 1024 * 1024;

/// Upper bound on the signing certificate a gallery version enrolls.
pub const max_certificate_bytes: u64 = 64 * 1024;

pub const AzureError = contracts.Error || error{
    InvalidOwnershipTags,
    MissingAccessSas,
    InvalidSku,
    InvalidGalleryResponse,
    InvalidSecurityProfile,
    InvalidUefiDb,
    InvalidCandidateInfo,
    InvalidSigningIdentity,
    CannotRead,
    NotAnObject,
    Io,
};

// ---------------------------------------------------------------------------
// Resource-group ownership
// ---------------------------------------------------------------------------

pub const Ownership = struct {
    run_id: []const u8,
    run_attempt: []const u8,
    candidate_key: []const u8,
};

/// The ownership tags a temporary resource group must carry before this
/// repository deletes it. `az group delete` is irreversible, so the tag set is
/// compared exactly: an extra tag means the group is not only ours.
pub fn checkGroupTags(
    allocator: Allocator,
    group: *const ObjectMap,
    ownership: Ownership,
    diagnostic: *Diagnostic,
) AzureError!void {
    // `json.load(...).get("tags") or {}`: absent, null, and an empty object
    // are the same starting point, and all three fail the comparison below.
    const tags = contracts.objectOrNull(group.get("tags")) orelse ObjectMap.empty;
    const matches = tags.count() == 4 and
        contracts.isString(tags.get("miz-owner"), "azurelinux4-release") and
        contracts.isString(tags.get("miz-run-id"), ownership.run_id) and
        contracts.isString(tags.get("miz-run-attempt"), ownership.run_attempt) and
        contracts.isString(tags.get("miz-candidate"), ownership.candidate_key);
    if (matches) return;

    const repr = try contracts.pythonReprAlloc(
        allocator,
        group.get("tags") orelse Value{ .object = ObjectMap.empty },
    );
    defer allocator.free(repr);
    return diagnostic.fail(
        error.InvalidOwnershipTags,
        "refusing to delete resource group with non-exact ownership tags: {s}",
        .{repr},
    );
}

// ---------------------------------------------------------------------------
// Disk write access
// ---------------------------------------------------------------------------

/// The SAS URL an accepted `beginGetAccess` returns, under either of the two
/// spellings the API has used. The shell re-checks the `https://` prefix; an
/// absent URL is reported here so the failure names the response.
pub fn writeDiskAccessSas(
    response: *const ObjectMap,
    out: *Writer,
    diagnostic: *Diagnostic,
) AzureError!void {
    const sas = contracts.stringOrNull(response.get("accessSAS")) orelse
        contracts.stringOrNull(response.get("accessSas")) orelse
        return diagnostic.fail(
            error.MissingAccessSas,
            "Azure disk access response omitted the SAS URL",
            .{},
        );
    out.print("{s}\n", .{sas}) catch return error.Io;
}

// ---------------------------------------------------------------------------
// VM SKU capabilities
// ---------------------------------------------------------------------------

/// Whether the SKU exposes a temporary resource disk. Arm64 SKUs legitimately
/// do not, and the guest acceptance branches on this answer.
pub const SkuResult = struct { has_resource_disk: bool };

/// `az vm list-skus` filtered to the configured size must name exactly one
/// SKU, in this location, at the requested architecture, supporting Gen2 and
/// Trusted Launch.
pub fn checkVmSku(
    allocator: Allocator,
    skus: Value,
    vm_size: []const u8,
    expected_architecture: []const u8,
    diagnostic: *Diagnostic,
) AzureError!SkuResult {
    const items = contracts.arrayOrNull(skus) orelse return diagnostic.fail(
        error.InvalidSku,
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        .{},
    );
    var match: ?ObjectMap = null;
    var matches: usize = 0;
    for (items) |item| {
        const sku = contracts.objectOrNull(item) orelse continue;
        if (!contracts.isString(sku.get("name"), vm_size)) continue;
        matches += 1;
        match = sku;
    }
    if (matches != 1) return diagnostic.fail(
        error.InvalidSku,
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        .{},
    );
    const sku = match.?;

    var restricted: std.json.Array = .init(allocator);
    defer restricted.deinit();
    for (contracts.arrayOrNull(sku.get("restrictions")) orelse &.{}) |restriction| {
        const fields = contracts.objectOrNull(restriction) orelse continue;
        if (contracts.isString(fields.get("type"), "Location")) {
            try restricted.append(restriction);
        }
    }
    if (restricted.items.len != 0) {
        const repr = try contracts.pythonReprAlloc(
            allocator,
            Value{ .array = restricted },
        );
        defer allocator.free(repr);
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure VM SKU is location-restricted: {s}",
            .{repr},
        );
    }

    const architecture = capability(sku, "CpuArchitectureType");
    if (!contracts.isString(architecture, expected_architecture)) {
        const repr = contracts.Repr.of(architecture);
        return diagnostic.fail(
            error.InvalidSku,
            "SKU architecture mismatch: {s}",
            .{repr.slice()},
        );
    }
    const generations = contracts.stringOrNull(capability(sku, "HyperVGenerations")) orelse "";
    var generation_names = std.mem.splitScalar(u8, generations, ',');
    var supports_gen2 = false;
    while (generation_names.next()) |name| {
        if (std.mem.eql(u8, name, "V2")) supports_gen2 = true;
    }
    if (!supports_gen2) return diagnostic.fail(
        error.InvalidSku,
        "configured Azure VM SKU does not support Gen2",
        .{},
    );
    if (contracts.isString(capability(sku, "TrustedLaunchDisabled"), "True")) {
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure VM SKU does not support Trusted Launch",
            .{},
        );
    }
    const resource_volume = capabilityInteger(
        capability(sku, "MaxResourceVolumeMB"),
    ) orelse return diagnostic.fail(
        error.InvalidSku,
        "configured Azure VM SKU reports an unreadable temporary resource disk size",
        .{},
    );
    const has_resource_disk = resource_volume > 0;
    if (std.mem.eql(u8, expected_architecture, "x64") and !has_resource_disk) {
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure VM SKU has no temporary resource disk",
            .{},
        );
    }
    return .{ .has_resource_disk = has_resource_disk };
}

fn capability(sku: ObjectMap, name: []const u8) ?Value {
    for (contracts.arrayOrNull(sku.get("capabilities")) orelse &.{}) |item| {
        const fields = contracts.objectOrNull(item) orelse continue;
        if (contracts.isString(fields.get("name"), name)) return fields.get("value");
    }
    return null;
}

/// `int(capabilities.get("MaxResourceVolumeMB", "0"))`: Azure spells these
/// numbers as strings, and an absent capability is zero.
fn capabilityInteger(value: ?Value) ?i64 {
    const present = value orelse return 0;
    return switch (present) {
        .integer => |number| number,
        .string => |text| std.fmt.parseInt(i64, text, 10) catch null,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Gallery image version
// ---------------------------------------------------------------------------

/// The gallery image-version request body: the exact document the release
/// publishes, with the release certificate in `additionalSignatures.db`
/// alongside the Microsoft template.
pub fn galleryRequest(
    allocator: Allocator,
    location: []const u8,
    disk_id: []const u8,
    certificate: []const u8,
) Allocator.Error!Value {
    const encoded = try contracts.encodeBase64Alloc(allocator, certificate);
    return contracts.object(allocator, &.{
        .{ "location", contracts.str(location) },
        .{ "properties", try contracts.object(allocator, &.{
            .{ "publishingProfile", try contracts.object(allocator, &.{
                .{ "replicationMode", contracts.str("Shallow") },
                .{ "targetRegions", try contracts.array(allocator, &.{
                    try contracts.object(allocator, &.{
                        .{ "name", contracts.str(location) },
                        .{ "regionalReplicaCount", contracts.int(1) },
                        .{ "storageAccountType", contracts.str("Standard_LRS") },
                    }),
                }) },
            }) },
            .{ "storageProfile", try contracts.object(allocator, &.{
                .{ "osDiskImage", try contracts.object(allocator, &.{
                    .{ "source", try contracts.object(allocator, &.{
                        .{ "id", contracts.str(disk_id) },
                    }) },
                }) },
            }) },
            .{ "securityProfile", try contracts.object(allocator, &.{
                .{ "uefiSettings", try contracts.object(allocator, &.{
                    .{ "signatureTemplateNames", try contracts.array(allocator, &.{
                        contracts.str(contracts.gallery_signature_template),
                    }) },
                    .{ "additionalSignatures", try contracts.object(allocator, &.{
                        .{ "db", try contracts.array(allocator, &.{
                            try contracts.object(allocator, &.{
                                .{ "type", contracts.str("x509") },
                                .{ "value", try contracts.array(allocator, &.{
                                    contracts.str(encoded),
                                }) },
                            }),
                        }) },
                    }) },
                }) },
            }) },
        }) },
    });
}

/// The create response must echo the exact custom UEFI settings that were
/// requested. Azure accepting a *different* set is the failure this catches.
pub fn checkGalleryAccepted(
    request: *const ObjectMap,
    response: *const ObjectMap,
    diagnostic: *Diagnostic,
) AzureError!void {
    const expected = contracts.galleryUefiSettings(request) orelse
        return diagnostic.fail(
            error.InvalidGalleryResponse,
            "Azure gallery request omitted custom UEFI settings",
            .{},
        );
    const actual = contracts.galleryUefiSettings(response) orelse
        return diagnostic.fail(
            error.InvalidGalleryResponse,
            "Azure did not accept the exact custom UEFI settings",
            .{},
        );
    if (!contracts.jsonEql(actual, expected)) return diagnostic.fail(
        error.InvalidGalleryResponse,
        "Azure did not accept the exact custom UEFI settings",
        .{},
    );
}

/// `properties.provisioningState`, or the empty string the polling loop reads
/// as "keep waiting".
pub fn writeGalleryState(
    response: *const ObjectMap,
    out: *Writer,
    diagnostic: *Diagnostic,
) AzureError!void {
    _ = diagnostic;
    const properties = contracts.objectOrNull(response.get("properties")) orelse
        ObjectMap.empty;
    const state = contracts.stringOrNull(properties.get("provisioningState")) orelse "";
    out.print("{s}\n", .{state}) catch return error.Io;
}

/// The final GET: the identity must be the version that was requested, any
/// settings it reports must be the ones that were accepted, and provisioning
/// must have succeeded.
///
/// A response that omits the settings entirely is allowed, and says so on
/// stdout: Azure has omitted them from a completed GET, and the authoritative
/// evidence is the certificate the booted guest reports in its own `db`.
pub fn checkGalleryFinal(
    allocator: Allocator,
    request: *const ObjectMap,
    response: *const ObjectMap,
    image_version_id: []const u8,
    out: *Writer,
    diagnostic: *Diagnostic,
) AzureError!void {
    const identity = contracts.stringOrNull(response.get("id")) orelse "";
    if (!std.ascii.eqlIgnoreCase(identity, image_version_id)) return diagnostic.fail(
        error.InvalidGalleryResponse,
        "Azure returned a different gallery image-version identity",
        .{},
    );
    const expected = contracts.galleryUefiSettings(request) orelse
        return diagnostic.fail(
            error.InvalidGalleryResponse,
            "Azure gallery request omitted custom UEFI settings",
            .{},
        );
    if (contracts.galleryUefiSettings(response)) |actual| {
        if (!contracts.jsonEql(actual, expected)) return diagnostic.fail(
            error.InvalidGalleryResponse,
            "Azure returned different custom UEFI settings after provisioning",
            .{},
        );
    } else {
        out.writeAll(
            "Azure omitted custom UEFI settings from the final GET; " ++
                "boot validation remains authoritative\n",
        ) catch return error.Io;
    }
    const properties = contracts.objectOrNull(response.get("properties")) orelse
        ObjectMap.empty;
    const state = properties.get("provisioningState");
    if (!contracts.isString(state, "Succeeded")) {
        const repr = try contracts.pythonReprAlloc(
            allocator,
            state orelse Value{ .null = {} },
        );
        defer allocator.free(repr);
        return diagnostic.fail(
            error.InvalidGalleryResponse,
            "gallery image-version provisioning did not succeed: {s}",
            .{repr},
        );
    }
}

// ---------------------------------------------------------------------------
// VM security profile
// ---------------------------------------------------------------------------

/// A deployed VM's security profile, as reported both by the resource and by
/// its instance view. Both must say Trusted Launch with Secure Boot and vTPM.
pub fn checkVmSecurity(
    profile: *const ObjectMap,
    label: []const u8,
    diagnostic: *Diagnostic,
) AzureError!void {
    if (!contracts.isString(profile.get("securityType"), "TrustedLaunch")) {
        return diagnostic.fail(
            error.InvalidSecurityProfile,
            "{s}: VM is not Trusted Launch",
            .{label},
        );
    }
    const settings = contracts.objectOrNull(profile.get("uefiSettings")) orelse
        ObjectMap.empty;
    if (!isTrue(settings.get("secureBootEnabled"))) return diagnostic.fail(
        error.InvalidSecurityProfile,
        "{s}: Secure Boot is not enabled",
        .{label},
    );
    if (!isTrue(settings.get("vTpmEnabled"))) return diagnostic.fail(
        error.InvalidSecurityProfile,
        "{s}: vTPM is not enabled",
        .{label},
    );
}

/// `is not True` in the Python: only the boolean itself passes, never a
/// truthy string or a 1.
fn isTrue(value: ?Value) bool {
    const present = value orelse return false;
    return present == .bool and present.bool;
}

// ---------------------------------------------------------------------------
// UEFI db
// ---------------------------------------------------------------------------

/// GUID of an `EFI_CERT_X509_GUID` signature list, little-endian as stored.
pub const efi_cert_x509_guid = [16]u8{
    0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
    0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
};

/// Bytes an efivarfs read prepends before the variable data itself.
const efivars_attribute_bytes = 4;

const signature_list_header_bytes = 28;

/// Whether the guest's UEFI `db` holds the exact release signing certificate.
///
/// The whole variable is walked rather than searched: a malformed signature
/// list is a rejection, because a `db` this code cannot parse is a `db` whose
/// contents it cannot claim to know.
pub fn checkUefiDb(
    data: []const u8,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) AzureError!void {
    var offset: usize = efivars_attribute_bytes;
    var found = false;
    while (offset < data.len) {
        if (data.len - offset < signature_list_header_bytes) return diagnostic.fail(
            error.InvalidUefiDb,
            "truncated EFI signature list",
            .{},
        );
        const list_size = std.mem.readInt(u32, data[offset + 16 ..][0..4], .little);
        const header_size = std.mem.readInt(u32, data[offset + 20 ..][0..4], .little);
        const signature_size = std.mem.readInt(u32, data[offset + 24 ..][0..4], .little);
        const is_x509 = std.mem.eql(u8, data[offset..][0..16], &efi_cert_x509_guid);
        if (list_size < signature_list_header_bytes or signature_size <= 16) {
            return diagnostic.fail(
                error.InvalidUefiDb,
                "invalid EFI signature list",
                .{},
            );
        }
        const end = offset + list_size;
        const signatures_start = offset + signature_list_header_bytes + header_size;
        if (end > data.len or signatures_start > end or
            (end - signatures_start) % signature_size != 0)
        {
            return diagnostic.fail(
                error.InvalidUefiDb,
                "invalid EFI signature-list bounds",
                .{},
            );
        }
        var signatures = signatures_start;
        while (signatures < end) : (signatures += signature_size) {
            const certificate = data[signatures + 16 .. signatures + signature_size];
            if (is_x509 and std.mem.eql(
                u8,
                &digest_support.hexBytes(certificate),
                certificate_sha256,
            )) found = true;
        }
        offset = end;
    }
    if (!found) return diagnostic.fail(
        error.InvalidUefiDb,
        "release signing certificate is absent from UEFI db",
        .{},
    );
}

// ---------------------------------------------------------------------------
// Candidate QCOW2 structure
// ---------------------------------------------------------------------------

/// The `qemu-img info` document of a freshly built candidate: exactly a
/// standalone zstd-compressed QCOW2 of the expected virtual size.
pub fn checkCandidateInfo(
    info: *const ObjectMap,
    virtual_size: i64,
    diagnostic: *Diagnostic,
) AzureError!void {
    if (!contracts.isString(info.get("format"), "qcow2")) return diagnostic.fail(
        error.InvalidCandidateInfo,
        "candidate is not QCOW2",
        .{},
    );
    if (!contracts.isInteger(info.get("virtual-size"), virtual_size)) {
        return diagnostic.fail(
            error.InvalidCandidateInfo,
            "candidate virtual size mismatch",
            .{},
        );
    }
    if (isTruthyString(info.get("backing-filename")) or
        isTruthyString(info.get("full-backing-filename")))
    {
        return diagnostic.fail(
            error.InvalidCandidateInfo,
            "candidate has a backing file",
            .{},
        );
    }
    const specific = contracts.objectOrNull(info.get("format-specific")) orelse
        ObjectMap.empty;
    const data = contracts.objectOrNull(specific.get("data")) orelse ObjectMap.empty;
    if (!contracts.isString(data.get("compression-type"), "zstd")) {
        return diagnostic.fail(
            error.InvalidCandidateInfo,
            "candidate does not use zstd cluster compression",
            .{},
        );
    }
}

/// Python's truthiness for the two backing-file fields: an empty string, a
/// null, and an absent key are all "no backing file".
fn isTruthyString(value: ?Value) bool {
    const present = value orelse return false;
    return switch (present) {
        .string => |text| text.len != 0,
        .null => false,
        .bool => |flag| flag,
        .integer => |number| number != 0,
        else => true,
    };
}

// ---------------------------------------------------------------------------
// Candidate signing identity
// ---------------------------------------------------------------------------

pub const SigningIdentity = struct {
    certificate_sha256: []const u8,
    fallback_uki_sha256: []const u8,
    certificate: []const u8,
};

/// The signing identity the acceptance run needs from a candidate manifest:
/// the enrolled leaf fingerprint, the fallback UKI digest, and the canonical
/// DER certificate itself, re-derived from the manifest's own base64 and
/// refused unless it hashes to the fingerprint the manifest claims.
pub fn signingIdentity(
    allocator: Allocator,
    manifest: *const ObjectMap,
    diagnostic: *Diagnostic,
) AzureError!SigningIdentity {
    const signing = contracts.objectOrNull(manifest.get("uki_signing")) orelse
        return diagnostic.fail(
            error.InvalidSigningIdentity,
            "candidate signing binding is absent",
            .{},
        );
    const certificate_sha256 = try contract.requireSha256(
        signing.get("certificate_sha256"),
        "UKI signing certificate fingerprint",
        diagnostic,
    );
    const fallback_uki_sha256 = try contract.requireSha256(
        signing.get("fallback_uki_sha256"),
        "fallback UKI digest",
        diagnostic,
    );
    const encoded = contracts.stringOrNull(signing.get("certificate_der_base64")) orelse
        return diagnostic.fail(
            error.InvalidSigningIdentity,
            "candidate signing certificate binding is invalid",
            .{},
        );
    const certificate = contracts.decodeBase64Alloc(
        allocator,
        encoded,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.InvalidSigningIdentity,
            "candidate signing certificate binding is invalid",
            .{},
        ),
    };
    if (certificate.len == 0 or !std.mem.eql(
        u8,
        &digest_support.hexBytes(certificate),
        certificate_sha256,
    )) return diagnostic.fail(
        error.InvalidSigningIdentity,
        "candidate signing certificate binding is invalid",
        .{},
    );
    return .{
        .certificate_sha256 = certificate_sha256,
        .fallback_uki_sha256 = fallback_uki_sha256,
        .certificate = certificate,
    };
}

// ---------------------------------------------------------------------------
// Reads
// ---------------------------------------------------------------------------

/// A whole JSON document of any top-level shape. `json_document.readObject`
/// covers the objects; a few Azure and GitHub endpoints answer with arrays.
pub fn readValue(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    max_bytes: u64,
    diagnostic: *Diagnostic,
) AzureError!std.json.Parsed(Value) {
    const bytes = file_support.readBounded(
        allocator,
        io,
        path,
        max_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
    defer allocator.free(bytes);
    if (!std.unicode.utf8ValidateSlice(bytes)) return diagnostic.fail(
        error.CannotRead,
        "cannot read {s}: {s}",
        .{ path, "InvalidUtf8" },
    );
    return std.json.parseFromSlice(Value, allocator, bytes, .{}) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return diagnostic.fail(
            error.CannotRead,
            "cannot read {s}: {s}",
            .{ path, @errorName(err) },
        ),
    };
}

pub fn readObject(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) AzureError!json_document.Document {
    return json_document.readObject(allocator, io, path, max_document_bytes, diagnostic);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

fn parse(text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, std.testing.allocator, text, .{});
}

fn collect(allocator: Allocator) Writer.Allocating {
    return .init(allocator);
}

test "group ownership tags are compared exactly before deletion" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    const ownership: Ownership = .{
        .run_id = "12",
        .run_attempt = "1",
        .candidate_key = "x86_64-full",
    };

    var owned = try parse(
        \\{"tags": {"miz-owner": "azurelinux4-release", "miz-run-id": "12",
        \\ "miz-run-attempt": "1", "miz-candidate": "x86_64-full"}}
    );
    defer owned.deinit();
    try checkGroupTags(allocator, &owned.value.object, ownership, &diagnostic);

    var extra = try parse(
        \\{"tags": {"miz-owner": "azurelinux4-release", "miz-run-id": "12",
        \\ "miz-run-attempt": "1", "miz-candidate": "x86_64-full", "other": "x"}}
    );
    defer extra.deinit();
    try std.testing.expectError(error.InvalidOwnershipTags, checkGroupTags(
        allocator,
        &extra.value.object,
        ownership,
        &diagnostic,
    ));
    try std.testing.expect(std.mem.startsWith(
        u8,
        diagnostic.message(),
        "refusing to delete resource group with non-exact ownership tags: ",
    ));

    var untagged = try parse("{}");
    defer untagged.deinit();
    try std.testing.expectError(error.InvalidOwnershipTags, checkGroupTags(
        allocator,
        &untagged.value.object,
        ownership,
        &diagnostic,
    ));

    var other_run = try parse(
        \\{"tags": {"miz-owner": "azurelinux4-release", "miz-run-id": "13",
        \\ "miz-run-attempt": "1", "miz-candidate": "x86_64-full"}}
    );
    defer other_run.deinit();
    try std.testing.expectError(error.InvalidOwnershipTags, checkGroupTags(
        allocator,
        &other_run.value.object,
        ownership,
        &diagnostic,
    ));
}

test "the disk access SAS is read under either spelling" {
    var diagnostic: Diagnostic = .{};
    var text = collect(std.testing.allocator);
    defer text.deinit();

    var upper = try parse(
        \\{"accessSAS": "https://example.blob.core.windows.net/x?sig=y"}
    );
    defer upper.deinit();
    try writeDiskAccessSas(&upper.value.object, &text.writer, &diagnostic);
    try std.testing.expectEqualStrings(
        "https://example.blob.core.windows.net/x?sig=y\n",
        text.written(),
    );

    text.clearRetainingCapacity();
    var lower = try parse(
        \\{"accessSas": "https://example.blob.core.windows.net/z"}
    );
    defer lower.deinit();
    try writeDiskAccessSas(&lower.value.object, &text.writer, &diagnostic);
    try std.testing.expectEqualStrings(
        "https://example.blob.core.windows.net/z\n",
        text.written(),
    );

    var absent = try parse(
        \\{"error": "denied"}
    );
    defer absent.deinit();
    try std.testing.expectError(error.MissingAccessSas, writeDiskAccessSas(
        &absent.value.object,
        &text.writer,
        &diagnostic,
    ));
}

fn skuJson(
    allocator: Allocator,
    architecture: []const u8,
    generations: []const u8,
    resource_volume: []const u8,
    extra: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator,
        \\[{{"name": "Standard_D2ds_v5", "capabilities": [
        \\  {{"name": "CpuArchitectureType", "value": "{s}"}},
        \\  {{"name": "HyperVGenerations", "value": "{s}"}},
        \\  {{"name": "MaxResourceVolumeMB", "value": "{s}"}}]{s}}}]
    , .{ architecture, generations, resource_volume, extra });
}

test "the configured VM SKU must be exact, Gen2, and Trusted Launch capable" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const good = try skuJson(allocator, "x64", "V1,V2", "76800", "");
    var parsed = try parse(good);
    defer parsed.deinit();
    const result = try checkVmSku(
        allocator,
        parsed.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    );
    try std.testing.expect(result.has_resource_disk);

    // Arm64 without a temporary resource disk is allowed, and says so.
    const arm = try skuJson(allocator, "Arm64", "V2", "0", "");
    var arm_parsed = try parse(arm);
    defer arm_parsed.deinit();
    const arm_result = try checkVmSku(
        allocator,
        arm_parsed.value,
        "Standard_D2ds_v5",
        "Arm64",
        &diagnostic,
    );
    try std.testing.expect(!arm_result.has_resource_disk);

    // x64 without one is not.
    const diskless = try skuJson(allocator, "x64", "V2", "0", "");
    var diskless_parsed = try parse(diskless);
    defer diskless_parsed.deinit();
    try std.testing.expectError(error.InvalidSku, checkVmSku(
        allocator,
        diskless_parsed.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "configured Azure VM SKU has no temporary resource disk",
        diagnostic.message(),
    );

    const gen1 = try skuJson(allocator, "x64", "V1", "76800", "");
    var gen1_parsed = try parse(gen1);
    defer gen1_parsed.deinit();
    try std.testing.expectError(error.InvalidSku, checkVmSku(
        allocator,
        gen1_parsed.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "configured Azure VM SKU does not support Gen2",
        diagnostic.message(),
    );

    const wrong_architecture = try skuJson(allocator, "Arm64", "V2", "76800", "");
    var wrong_parsed = try parse(wrong_architecture);
    defer wrong_parsed.deinit();
    try std.testing.expectError(error.InvalidSku, checkVmSku(
        allocator,
        wrong_parsed.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "SKU architecture mismatch: 'Arm64'",
        diagnostic.message(),
    );

    const trusted_launch_disabled =
        \\[{"name": "Standard_D2ds_v5", "capabilities": [
        \\  {"name": "CpuArchitectureType", "value": "x64"},
        \\  {"name": "HyperVGenerations", "value": "V2"},
        \\  {"name": "TrustedLaunchDisabled", "value": "True"},
        \\  {"name": "MaxResourceVolumeMB", "value": "76800"}]}]
    ;
    var disabled_parsed = try parse(trusted_launch_disabled);
    defer disabled_parsed.deinit();
    try std.testing.expectError(error.InvalidSku, checkVmSku(
        allocator,
        disabled_parsed.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "configured Azure VM SKU does not support Trusted Launch",
        diagnostic.message(),
    );

    const restricted = try skuJson(
        allocator,
        "x64",
        "V2",
        "76800",
        ", \"restrictions\": [{\"type\": \"Location\"}]",
    );
    var restricted_parsed = try parse(restricted);
    defer restricted_parsed.deinit();
    try std.testing.expectError(error.InvalidSku, checkVmSku(
        allocator,
        restricted_parsed.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "configured Azure VM SKU is location-restricted: [{'type': 'Location'}]",
        diagnostic.message(),
    );

    var empty = try parse("[]");
    defer empty.deinit();
    try std.testing.expectError(error.InvalidSku, checkVmSku(
        allocator,
        empty.value,
        "Standard_D2ds_v5",
        "x64",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        diagnostic.message(),
    );
}

test "the gallery request carries the template and the release certificate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const request = try galleryRequest(
        allocator,
        "eastus2",
        "/subscriptions/x/disks/miz-os",
        "miz test certificate DER",
    );
    const encoded = try json_document.canonicalAlloc(allocator, request, .document);
    try std.testing.expectEqualStrings(
        \\{
        \\  "location": "eastus2",
        \\  "properties": {
        \\    "publishingProfile": {
        \\      "replicationMode": "Shallow",
        \\      "targetRegions": [
        \\        {
        \\          "name": "eastus2",
        \\          "regionalReplicaCount": 1,
        \\          "storageAccountType": "Standard_LRS"
        \\        }
        \\      ]
        \\    },
        \\    "securityProfile": {
        \\      "uefiSettings": {
        \\        "additionalSignatures": {
        \\          "db": [
        \\            {
        \\              "type": "x509",
        \\              "value": [
        \\                "bWl6IHRlc3QgY2VydGlmaWNhdGUgREVS"
        \\              ]
        \\            }
        \\          ]
        \\        },
        \\        "signatureTemplateNames": [
        \\          "MicrosoftUefiCertificateAuthorityTemplate"
        \\        ]
        \\      }
        \\    },
        \\    "storageProfile": {
        \\      "osDiskImage": {
        \\        "source": {
        \\          "id": "/subscriptions/x/disks/miz-os"
        \\        }
        \\      }
        \\    }
        \\  }
        \\}
        \\
    , encoded);

    // The request the acceptance run writes is exactly what the release
    // contract then validates.
    var diagnostic: Diagnostic = .{};
    var request_document = try contracts.object(allocator, &.{
        .{ "properties", request.object.get("properties").? },
    });
    _ = try contracts.validateAzureGalleryUefiSettings(
        allocator,
        &request_document.object,
        &request_document.object,
        &digest_support.hexBytes("miz test certificate DER"),
        &diagnostic,
    );
}

test "gallery acceptance and the final GET are checked exactly" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};
    var text = collect(allocator);

    const identity = "/subscriptions/x/galleries/g/images/i/versions/1.0.0";
    var request = try parse(
        \\{"properties": {"securityProfile": {"uefiSettings":
        \\  {"signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"]}}}}
    );
    defer request.deinit();

    var accepted = try parse(
        \\{"id": "/SUBSCRIPTIONS/X/GALLERIES/G/IMAGES/I/VERSIONS/1.0.0",
        \\ "properties": {"provisioningState": "Succeeded", "securityProfile":
        \\  {"uefiSettings":
        \\   {"signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"]}}}}
    );
    defer accepted.deinit();
    try checkGalleryAccepted(&request.value.object, &accepted.value.object, &diagnostic);
    try checkGalleryFinal(
        allocator,
        &request.value.object,
        &accepted.value.object,
        identity,
        &text.writer,
        &diagnostic,
    );
    try std.testing.expectEqual(@as(usize, 0), text.written().len);

    var omitted = try parse(
        \\{"id": "/subscriptions/x/galleries/g/images/i/versions/1.0.0",
        \\ "properties": {"provisioningState": "Succeeded"}}
    );
    defer omitted.deinit();
    try checkGalleryFinal(
        allocator,
        &request.value.object,
        &omitted.value.object,
        identity,
        &text.writer,
        &diagnostic,
    );
    try std.testing.expectEqualStrings(
        "Azure omitted custom UEFI settings from the final GET; " ++
            "boot validation remains authoritative\n",
        text.written(),
    );
    try std.testing.expectError(error.InvalidGalleryResponse, checkGalleryAccepted(
        &request.value.object,
        &omitted.value.object,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "Azure did not accept the exact custom UEFI settings",
        diagnostic.message(),
    );

    var changed = try parse(
        \\{"id": "/subscriptions/x/galleries/g/images/i/versions/1.0.0",
        \\ "properties": {"provisioningState": "Succeeded", "securityProfile":
        \\  {"uefiSettings": {"signatureTemplateNames": []}}}}
    );
    defer changed.deinit();
    try std.testing.expectError(error.InvalidGalleryResponse, checkGalleryFinal(
        allocator,
        &request.value.object,
        &changed.value.object,
        identity,
        &text.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "Azure returned different custom UEFI settings after provisioning",
        diagnostic.message(),
    );

    var other = try parse(
        \\{"id": "/subscriptions/other/versions/1.0.0",
        \\ "properties": {"provisioningState": "Succeeded"}}
    );
    defer other.deinit();
    try std.testing.expectError(error.InvalidGalleryResponse, checkGalleryFinal(
        allocator,
        &request.value.object,
        &other.value.object,
        identity,
        &text.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "Azure returned a different gallery image-version identity",
        diagnostic.message(),
    );

    var failed = try parse(
        \\{"id": "/subscriptions/x/galleries/g/images/i/versions/1.0.0",
        \\ "properties": {"provisioningState": "Failed"}}
    );
    defer failed.deinit();
    try std.testing.expectError(error.InvalidGalleryResponse, checkGalleryFinal(
        allocator,
        &request.value.object,
        &failed.value.object,
        identity,
        &text.writer,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "gallery image-version provisioning did not succeed: 'Failed'",
        diagnostic.message(),
    );
}

test "the provisioning state is reported for the polling loop" {
    var diagnostic: Diagnostic = .{};
    var text = collect(std.testing.allocator);
    defer text.deinit();

    var creating = try parse(
        \\{"properties": {"provisioningState": "Creating"}}
    );
    defer creating.deinit();
    try writeGalleryState(&creating.value.object, &text.writer, &diagnostic);
    try std.testing.expectEqualStrings("Creating\n", text.written());

    text.clearRetainingCapacity();
    var silent = try parse("{}");
    defer silent.deinit();
    try writeGalleryState(&silent.value.object, &text.writer, &diagnostic);
    try std.testing.expectEqualStrings("\n", text.written());
}

test "a VM security profile must state Trusted Launch, Secure Boot, and vTPM" {
    var diagnostic: Diagnostic = .{};
    var good = try parse(
        \\{"securityType": "TrustedLaunch",
        \\ "uefiSettings": {"secureBootEnabled": true, "vTpmEnabled": true}}
    );
    defer good.deinit();
    try checkVmSecurity(&good.value.object, "vm-security.json", &diagnostic);

    var standard = try parse(
        \\{"securityType": "Standard"}
    );
    defer standard.deinit();
    try std.testing.expectError(error.InvalidSecurityProfile, checkVmSecurity(
        &standard.value.object,
        "vm-security.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "vm-security.json: VM is not Trusted Launch",
        diagnostic.message(),
    );

    // A truthy value that is not the boolean itself is still a rejection.
    var truthy = try parse(
        \\{"securityType": "TrustedLaunch",
        \\ "uefiSettings": {"secureBootEnabled": "true", "vTpmEnabled": true}}
    );
    defer truthy.deinit();
    try std.testing.expectError(error.InvalidSecurityProfile, checkVmSecurity(
        &truthy.value.object,
        "instance-security.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "instance-security.json: Secure Boot is not enabled",
        diagnostic.message(),
    );

    var no_vtpm = try parse(
        \\{"securityType": "TrustedLaunch",
        \\ "uefiSettings": {"secureBootEnabled": true, "vTpmEnabled": false}}
    );
    defer no_vtpm.deinit();
    try std.testing.expectError(error.InvalidSecurityProfile, checkVmSecurity(
        &no_vtpm.value.object,
        "vm-security.json",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "vm-security.json: vTPM is not enabled",
        diagnostic.message(),
    );
}

/// Builds an efivarfs `db` read holding `certificates` in one x509 signature
/// list, optionally preceded by a list of another type.
fn uefiDb(
    allocator: Allocator,
    certificates: []const []const u8,
    guid: [16]u8,
) ![]u8 {
    std.debug.assert(certificates.len > 0);
    for (certificates) |certificate| {
        std.debug.assert(certificate.len == certificates[0].len);
    }
    const signature_size: u32 = @intCast(16 + certificates[0].len);
    const list_size: u32 = @intCast(28 + signature_size * certificates.len);
    var bytes: std.ArrayList(u8) = .empty;
    errdefer bytes.deinit(allocator);
    try bytes.appendSlice(allocator, &.{ 0x07, 0x00, 0x00, 0x00 });
    try bytes.appendSlice(allocator, &guid);
    var header: [12]u8 = undefined;
    std.mem.writeInt(u32, header[0..4], list_size, .little);
    std.mem.writeInt(u32, header[4..8], 0, .little);
    std.mem.writeInt(u32, header[8..12], signature_size, .little);
    try bytes.appendSlice(allocator, &header);
    for (certificates) |certificate| {
        try bytes.appendSlice(allocator, &[_]u8{0xAB} ** 16);
        try bytes.appendSlice(allocator, certificate);
    }
    return bytes.toOwnedSlice(allocator);
}

test "the guest UEFI db must hold the exact release certificate" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const certificate = "miz test certificate DER";
    const fingerprint = digest_support.hexBytes(certificate);
    const enrolled = try uefiDb(
        allocator,
        &.{ "microsoft certificate DE", certificate },
        efi_cert_x509_guid,
    );
    try checkUefiDb(enrolled, &fingerprint, &diagnostic);

    const absent = try uefiDb(
        allocator,
        &.{"microsoft certificate DE"},
        efi_cert_x509_guid,
    );
    try std.testing.expectError(error.InvalidUefiDb, checkUefiDb(
        absent,
        &fingerprint,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "release signing certificate is absent from UEFI db",
        diagnostic.message(),
    );

    // The right bytes in a signature list of the wrong type do not count.
    const hashed = try uefiDb(
        allocator,
        &.{certificate},
        [_]u8{0x26} ++ [_]u8{0} ** 15,
    );
    try std.testing.expectError(error.InvalidUefiDb, checkUefiDb(
        hashed,
        &fingerprint,
        &diagnostic,
    ));

    try std.testing.expectError(error.InvalidUefiDb, checkUefiDb(
        enrolled[0 .. enrolled.len - 1],
        &fingerprint,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "invalid EFI signature-list bounds",
        diagnostic.message(),
    );

    try std.testing.expectError(error.InvalidUefiDb, checkUefiDb(
        enrolled[0..20],
        &fingerprint,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "truncated EFI signature list",
        diagnostic.message(),
    );

    var malformed = try allocator.dupe(u8, enrolled);
    std.mem.writeInt(u32, malformed[4 + 16 ..][0..4], 8, .little);
    try std.testing.expectError(error.InvalidUefiDb, checkUefiDb(
        malformed,
        &fingerprint,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings("invalid EFI signature list", diagnostic.message());
}

test "the built candidate must be a standalone zstd QCOW2 of the exact size" {
    var diagnostic: Diagnostic = .{};
    var good = try parse(
        \\{"format": "qcow2", "virtual-size": 5368709120,
        \\ "format-specific": {"type": "qcow2", "data": {"compression-type": "zstd"}}}
    );
    defer good.deinit();
    try checkCandidateInfo(&good.value.object, 5_368_709_120, &diagnostic);

    var raw = try parse(
        \\{"format": "raw", "virtual-size": 5368709120}
    );
    defer raw.deinit();
    try std.testing.expectError(error.InvalidCandidateInfo, checkCandidateInfo(
        &raw.value.object,
        5_368_709_120,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings("candidate is not QCOW2", diagnostic.message());

    try std.testing.expectError(error.InvalidCandidateInfo, checkCandidateInfo(
        &good.value.object,
        1_241_513_984,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "candidate virtual size mismatch",
        diagnostic.message(),
    );

    var backed = try parse(
        \\{"format": "qcow2", "virtual-size": 5368709120,
        \\ "backing-filename": "base.qcow2",
        \\ "format-specific": {"data": {"compression-type": "zstd"}}}
    );
    defer backed.deinit();
    try std.testing.expectError(error.InvalidCandidateInfo, checkCandidateInfo(
        &backed.value.object,
        5_368_709_120,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings("candidate has a backing file", diagnostic.message());

    var zlib = try parse(
        \\{"format": "qcow2", "virtual-size": 5368709120,
        \\ "format-specific": {"data": {"compression-type": "zlib"}}}
    );
    defer zlib.deinit();
    try std.testing.expectError(error.InvalidCandidateInfo, checkCandidateInfo(
        &zlib.value.object,
        5_368_709_120,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "candidate does not use zstd cluster compression",
        diagnostic.message(),
    );

    // An empty backing filename is Python-falsy and therefore allowed.
    var empty_backing = try parse(
        \\{"format": "qcow2", "virtual-size": 5368709120, "backing-filename": "",
        \\ "full-backing-filename": null,
        \\ "format-specific": {"data": {"compression-type": "zstd"}}}
    );
    defer empty_backing.deinit();
    try checkCandidateInfo(&empty_backing.value.object, 5_368_709_120, &diagnostic);
}

test "the candidate signing identity is re-derived, not trusted" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var diagnostic: Diagnostic = .{};

    const certificate = "miz test certificate DER";
    const fingerprint = digest_support.hexBytes(certificate);
    const encoded = try contracts.encodeBase64Alloc(allocator, certificate);
    const text = try std.fmt.allocPrint(allocator,
        \\{{"uki_signing": {{"certificate_sha256": "{s}",
        \\  "fallback_uki_sha256": "{s}", "certificate_der_base64": "{s}"}}}}
    , .{ &fingerprint, "3" ** 64, encoded });
    var manifest = try parse(text);
    defer manifest.deinit();
    const identity = try signingIdentity(allocator, &manifest.value.object, &diagnostic);
    try std.testing.expectEqualStrings(certificate, identity.certificate);
    try std.testing.expectEqualStrings("3" ** 64, identity.fallback_uki_sha256);

    const tampered = try std.fmt.allocPrint(allocator,
        \\{{"uki_signing": {{"certificate_sha256": "{s}",
        \\  "fallback_uki_sha256": "{s}", "certificate_der_base64": "{s}"}}}}
    , .{ &fingerprint, "3" ** 64, "ZGlmZmVyZW50" });
    var wrong = try parse(tampered);
    defer wrong.deinit();
    try std.testing.expectError(error.InvalidSigningIdentity, signingIdentity(
        allocator,
        &wrong.value.object,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "candidate signing certificate binding is invalid",
        diagnostic.message(),
    );

    var absent = try parse("{}");
    defer absent.deinit();
    try std.testing.expectError(error.InvalidSigningIdentity, signingIdentity(
        allocator,
        &absent.value.object,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "candidate signing binding is absent",
        diagnostic.message(),
    );
}
