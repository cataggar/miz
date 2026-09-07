//! Azure Trusted Launch image and VM contracts shared by release families.
//!
//! An image definition advertising `TrustedLaunchSupported`, an image version
//! carrying custom UEFI trust, and a VM deployed as `TrustedLaunch` are three
//! independent resources. Keeping their builders and validators together
//! prevents a release from treating any one of them as proof of the others.

const std = @import("std");

const azure_compute = @import("azure_compute.zig");
const contract = @import("contract.zig");
const digest = @import("digest.zig");
const json_document = @import("json_document.zig");

const Allocator = std.mem.Allocator;
const Diagnostic = contract.Diagnostic;
const ObjectMap = std.json.ObjectMap;
const Value = std.json.Value;

pub const image_security_type = "TrustedLaunchSupported";
pub const vm_security_type = "TrustedLaunch";
pub const signature_template = "MicrosoftUefiCertificateAuthorityTemplate";
pub const hyper_v_generation = azure_compute.hyper_v_generation;
pub const os_type = azure_compute.os_type;
pub const os_state = azure_compute.os_state;
pub const gallery_version_api = azure_compute.gallery_version_api;
pub const vm_api = azure_compute.vm_api;

pub const Coverage = struct {
    family: []const u8,
    architecture: []const u8,
    flavor: []const u8,
    asset_name: []const u8,
};

/// Image combinations for which a protected workflow boots the exact release
/// candidate on Azure. Documentation may claim no broader support than this.
pub const acceptance_coverage = [_]Coverage{
    .{ .family = "Azure Linux 4", .architecture = "x86_64", .flavor = "full", .asset_name = "AzureLinux-4.0-x86_64.qcow2" },
    .{ .family = "Azure Linux 4", .architecture = "aarch64", .flavor = "full", .asset_name = "AzureLinux-4.0-aarch64.qcow2" },
    .{ .family = "Azure Linux 4", .architecture = "x86_64", .flavor = "core", .asset_name = "AzureLinux-4.0-x86_64.core.qcow2" },
    .{ .family = "Azure Linux 4", .architecture = "aarch64", .flavor = "core", .asset_name = "AzureLinux-4.0-aarch64.core.qcow2" },
    .{ .family = "Ubuntu 26.04", .architecture = "x86_64", .flavor = "full", .asset_name = "Ubuntu-26.04-x86_64.qcow2" },
    .{ .family = "Ubuntu 26.04", .architecture = "aarch64", .flavor = "full", .asset_name = "Ubuntu-26.04-aarch64.qcow2" },
    .{ .family = "Ubuntu 26.04", .architecture = "x86_64", .flavor = "core", .asset_name = "Ubuntu-26.04-x86_64.core.qcow2" },
    .{ .family = "Ubuntu 26.04", .architecture = "aarch64", .flavor = "core", .asset_name = "Ubuntu-26.04-aarch64.core.qcow2" },
};

pub const Error = error{
    InvalidUefiSettings,
    OutOfMemory,
} || azure_compute.Error;
pub const UefiError = error{ InvalidUefiSettings, OutOfMemory };
pub const SecurityProfileError = azure_compute.SecurityProfileError;
pub const ManagedDiskError = azure_compute.ManagedDiskError;
pub const ImageDefinitionError = azure_compute.ImageDefinitionError;

const object = azure_compute.object;
const array = azure_compute.array;
const string = azure_compute.string;
const objectOf = azure_compute.objectOf;
const arrayOf = azure_compute.arrayOf;
const stringIs = azure_compute.stringIs;
const hasExactFields = azure_compute.hasExactFields;
const jsonEqual = azure_compute.jsonEqual;

pub fn imageDefinitionContract(
    allocator: Allocator,
    architecture: []const u8,
) !Value {
    return object(allocator, &.{
        .{ "osType", string(os_type) },
        .{ "osState", string(os_state) },
        .{ "hyperVGeneration", string(hyper_v_generation) },
        .{ "architecture", string(architecture) },
        .{ "features", try array(allocator, &.{
            try object(allocator, &.{
                .{ "name", string("SecurityType") },
                .{ "value", string(image_security_type) },
            }),
        }) },
    });
}

pub fn validateImageDefinitionContract(
    definition: *const ObjectMap,
    architecture: []const u8,
    diagnostic: *Diagnostic,
) ImageDefinitionError!void {
    if (!hasExactFields(definition.*, &.{
        "architecture",
        "features",
        "hyperVGeneration",
        "osState",
        "osType",
    }) or
        !stringIs(definition.get("osType"), os_type) or
        !stringIs(definition.get("osState"), os_state) or
        !stringIs(definition.get("hyperVGeneration"), hyper_v_generation) or
        !stringIs(definition.get("architecture"), architecture))
    {
        return diagnostic.fail(
            error.InvalidImageDefinition,
            "Azure gallery image-definition contract is invalid",
            .{},
        );
    }
    const features = arrayOf(definition.get("features")) orelse
        return diagnostic.fail(
            error.InvalidImageDefinition,
            "Azure gallery image-definition contract is invalid",
            .{},
        );
    if (features.len != 1) return diagnostic.fail(
        error.InvalidImageDefinition,
        "Azure gallery image-definition contract is invalid",
        .{},
    );
    const feature = objectOf(features[0]) orelse return diagnostic.fail(
        error.InvalidImageDefinition,
        "Azure gallery image-definition contract is invalid",
        .{},
    );
    if (!hasExactFields(feature, &.{ "name", "value" }) or
        !stringIs(feature.get("name"), "SecurityType") or
        !stringIs(feature.get("value"), image_security_type))
    {
        return diagnostic.fail(
            error.InvalidImageDefinition,
            "Azure gallery image-definition contract is invalid",
            .{},
        );
    }
}

pub fn uefiSettings(
    allocator: Allocator,
    certificate: []const u8,
) !Value {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(certificate.len));
    _ = encoder.encode(encoded, certificate);
    return object(allocator, &.{
        .{ "signatureTemplateNames", try array(allocator, &.{
            string(signature_template),
        }) },
        .{ "additionalSignatures", try object(allocator, &.{
            .{ "db", try array(allocator, &.{
                try object(allocator, &.{
                    .{ "type", string("x509") },
                    .{ "value", try array(allocator, &.{string(encoded)}) },
                }),
            }) },
        }) },
    });
}

/// Build the Compute Gallery image-version request used by both release
/// families. The Microsoft template remains present while the exact release
/// signer is appended to `db`.
pub fn galleryVersionRequest(
    allocator: Allocator,
    location: []const u8,
    disk_id: []const u8,
    certificate: []const u8,
) !Value {
    const security_profile = try object(allocator, &.{
        .{ "uefiSettings", try uefiSettings(allocator, certificate) },
    });
    return azure_compute.galleryVersionRequest(
        allocator,
        location,
        disk_id,
        security_profile,
    );
}

pub fn galleryVersionRequestWithOptions(
    allocator: Allocator,
    options: azure_compute.GalleryVersionOptions,
    certificate: []const u8,
) !Value {
    const security_profile = try object(allocator, &.{
        .{ "uefiSettings", try uefiSettings(allocator, certificate) },
    });
    return azure_compute.galleryVersionRequestWithOptions(
        allocator,
        options,
        security_profile,
    );
}

pub fn galleryUefiSettings(document: *const ObjectMap) ?Value {
    const properties = objectOf(document.get("properties")) orelse return null;
    const security = objectOf(properties.get("securityProfile")) orelse return null;
    return security.get("uefiSettings");
}

pub fn validateUefiSettings(
    allocator: Allocator,
    settings: ?Value,
    certificate_sha256: []const u8,
    diagnostic: *Diagnostic,
) UefiError!void {
    const map = objectOf(settings) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI settings have an unexpected shape",
        .{},
    );
    if (!hasExactFields(map, &.{ "additionalSignatures", "signatureTemplateNames" })) {
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI settings have an unexpected shape",
            .{},
        );
    }
    const templates = arrayOf(map.get("signatureTemplateNames")) orelse
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI settings do not retain the Microsoft template",
            .{},
        );
    if (templates.len != 1 or !stringIs(templates[0], signature_template)) {
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI settings do not retain the Microsoft template",
            .{},
        );
    }
    const additional = objectOf(map.get("additionalSignatures")) orelse
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI additional signatures are invalid",
            .{},
        );
    if (!hasExactFields(additional, &.{"db"})) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI additional signatures are invalid",
        .{},
    );
    const db = arrayOf(additional.get("db")) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI db signature is invalid",
        .{},
    );
    if (db.len != 1) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI db signature is invalid",
        .{},
    );
    const entry = objectOf(db[0]) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI db signature is invalid",
        .{},
    );
    if (!hasExactFields(entry, &.{ "type", "value" }) or
        !stringIs(entry.get("type"), "x509"))
    {
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI db signature is invalid",
            .{},
        );
    }
    const values = arrayOf(entry.get("value")) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI db signature is invalid",
        .{},
    );
    if (values.len != 1 or values[0] != .string) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI db signature is invalid",
        .{},
    );

    const decoder = std.base64.standard.Decoder;
    const size = decoder.calcSizeForSlice(values[0].string) catch
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI certificate is not canonical base64",
            .{},
        );
    const certificate = try allocator.alloc(u8, size);
    defer allocator.free(certificate);
    decoder.decode(certificate, values[0].string) catch return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI certificate is not canonical base64",
        .{},
    );
    const encoder = std.base64.standard.Encoder;
    const canonical = try allocator.alloc(u8, encoder.calcSize(certificate.len));
    defer allocator.free(canonical);
    _ = encoder.encode(canonical, certificate);
    if (!std.mem.eql(u8, canonical, values[0].string)) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure custom UEFI certificate is not canonical base64",
        .{},
    );
    if (!std.mem.eql(u8, &digest.hexBytes(certificate), certificate_sha256)) {
        return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure custom UEFI certificate fingerprint mismatch",
            .{},
        );
    }
}

/// Bind an image-version response to the request. A completed GET may omit
/// UEFI settings, but a response that reports them may not change them.
pub fn validateGalleryUefiSettings(
    allocator: Allocator,
    request: *const ObjectMap,
    response: *const ObjectMap,
    certificate_sha256: []const u8,
    require_response_settings: bool,
    diagnostic: *Diagnostic,
) UefiError!Value {
    const expected = galleryUefiSettings(request) orelse return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure gallery request omitted custom UEFI settings",
        .{},
    );
    const actual = galleryUefiSettings(response);
    if (require_response_settings and actual == null) return diagnostic.fail(
        error.InvalidUefiSettings,
        "Azure did not accept the exact custom UEFI settings",
        .{},
    );
    if (actual) |settings| {
        if (!jsonEqual(settings, expected)) return diagnostic.fail(
            error.InvalidUefiSettings,
            "Azure gallery version returned different custom UEFI settings",
            .{},
        );
    }
    try validateUefiSettings(
        allocator,
        expected,
        certificate_sha256,
        diagnostic,
    );
    return expected;
}

pub fn validateVmSecurityProfile(
    profile: *const ObjectMap,
    label: []const u8,
    diagnostic: *Diagnostic,
) SecurityProfileError!void {
    return azure_compute.validateVmSecurityProfile(
        profile,
        vm_security_type,
        "VM is not Trusted Launch",
        label,
        diagnostic,
    );
}

pub fn validateManagedDisk(
    disk: *const ObjectMap,
    architecture: []const u8,
    diagnostic: *Diagnostic,
) ManagedDiskError![]const u8 {
    return azure_compute.validateManagedDisk(disk, architecture, diagnostic);
}

pub fn validateImageDefinition(
    definition: *const ObjectMap,
    architecture: []const u8,
    diagnostic: *Diagnostic,
) ImageDefinitionError![]const u8 {
    return azure_compute.validateImageDefinition(
        definition,
        architecture,
        image_security_type,
        "Azure gallery image definition is not TrustedLaunchSupported",
        diagnostic,
    );
}

fn parse(allocator: Allocator, text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, allocator, text, .{});
}

test "gallery request appends the exact signer to the Microsoft template" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const certificate = "release certificate DER";
    const request = try galleryVersionRequest(
        allocator,
        "eastus2",
        "/subscriptions/test/disks/os",
        certificate,
    );
    var expected = try parse(allocator,
        \\{"location":"eastus2","properties":{"publishingProfile":{"replicationMode":"Shallow","targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS"}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/test/disks/os"}}},"securityProfile":{"uefiSettings":{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{"db":[{"type":"x509","value":["cmVsZWFzZSBjZXJ0aWZpY2F0ZSBERVI="]}]}}}}}
    );
    defer expected.deinit();
    const actual_json = try json_document.canonicalAlloc(allocator, request, .compact);
    const expected_json = try json_document.canonicalAlloc(
        allocator,
        expected.value,
        .compact,
    );
    try std.testing.expectEqualStrings(expected_json, actual_json);
    var diagnostic: Diagnostic = .{};
    const settings = galleryUefiSettings(&request.object).?;
    try validateUefiSettings(
        allocator,
        settings,
        &digest.hexBytes(certificate),
        &diagnostic,
    );
}

test "custom UEFI validation rejects every independently required property" {
    const certificate = "cert";
    const certificate_sha256 = digest.hexBytes(certificate);
    const invalid = [_][]const u8{
        \\null
        ,
        \\{"signatureTemplateNames":[],"additionalSignatures":{"db":[{"type":"x509","value":["Y2VydA=="]}]}}
        ,
        \\{"signatureTemplateNames":["Other"],"additionalSignatures":{"db":[{"type":"x509","value":["Y2VydA=="]}]}}
        ,
        \\{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{}}
        ,
        \\{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{"db":[]}}
        ,
        \\{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{"db":[{"type":"sha256","value":["Y2VydA=="]}]}}
        ,
        \\{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{"db":[{"type":"x509","value":[]}]}}
        ,
        \\{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{"db":[{"type":"x509","value":["Y2VydA"]}]}}
        ,
        \\{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"],"additionalSignatures":{"db":[{"type":"x509","value":["b3RoZXI="]}]}}
        ,
    };
    for (invalid) |text| {
        var settings = try parse(std.testing.allocator, text);
        defer settings.deinit();
        var diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidUefiSettings,
            validateUefiSettings(
                std.testing.allocator,
                settings.value,
                &certificate_sha256,
                &diagnostic,
            ),
        );
    }
}

test "managed disk validation rejects every independently required property" {
    const invalid = [_][]const u8{
        \\{"osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"Arm64"}}
        ,
        \\{"id":"disk","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"Arm64"}}
        ,
        \\{"id":"/subscriptions/test/disks/os","osType":"Windows","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"Arm64"}}
        ,
        \\{"id":"/subscriptions/test/disks/os","osType":"Linux","hyperVGeneration":"V1","supportedCapabilities":{"architecture":"Arm64"}}
        ,
        \\{"id":"/subscriptions/test/disks/os","osType":"Linux","hyperVGeneration":"V2"}
        ,
        \\{"id":"/subscriptions/test/disks/os","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"}}
        ,
    };
    for (invalid) |text| {
        var disk = try parse(std.testing.allocator, text);
        defer disk.deinit();
        var diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidManagedDisk,
            validateManagedDisk(&disk.value.object, "Arm64", &diagnostic),
        );
    }
}

test "image definition validation rejects every independently required property" {
    const invalid = [_][]const u8{
        \\{"osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"Arm64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Windows","osState":"Generalized","hyperVGeneration":"V2","architecture":"Arm64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Specialized","hyperVGeneration":"V2","architecture":"Arm64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V1","architecture":"Arm64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"Arm64"}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"Arm64","features":[{"name":"SecurityType","value":"TrustedLaunch"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"Arm64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"},{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
    };
    for (invalid) |text| {
        var definition = try parse(std.testing.allocator, text);
        defer definition.deinit();
        var diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidImageDefinition,
            validateImageDefinition(&definition.value.object, "Arm64", &diagnostic),
        );
    }
}

test "VM resource and instance profiles require three independent settings" {
    var profile = try parse(std.testing.allocator,
        \\{"securityType":"TrustedLaunch",
        \\"uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}}
    );
    defer profile.deinit();
    var diagnostic: Diagnostic = .{};
    try validateVmSecurityProfile(&profile.value.object, "vm.json", &diagnostic);
    const invalid = [_][]const u8{
        \\{"securityType":"TrustedLaunchSupported","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}}
        ,
        \\{"securityType":"TrustedLaunch"}
        ,
        \\{"securityType":"TrustedLaunch","uefiSettings":{"secureBootEnabled":false,"vTpmEnabled":true}}
        ,
        \\{"securityType":"TrustedLaunch","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":false}}
        ,
    };
    for (invalid) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidSecurityProfile,
            validateVmSecurityProfile(
                &candidate.value.object,
                "instance.json",
                &candidate_diagnostic,
            ),
        );
    }
}

test "real Azure acceptance coverage excludes Ubuntu bare metal" {
    try std.testing.expectEqual(@as(usize, 8), acceptance_coverage.len);
    for (acceptance_coverage) |entry| {
        try std.testing.expect(!std.mem.eql(u8, entry.flavor, "baremetal"));
    }
}
