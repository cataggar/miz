//! Azure Confidential VM image, SKU, gallery, and VM contracts.
//!
//! `ConfidentialVMSupported` describes a generalized image without VM Guest
//! State. A VM created from it must independently request `ConfidentialVM`,
//! `VMGuestStateOnly`, Secure Boot, and vTPM. The initial miz profile is x64
//! AMD SEV-SNP; accepting a Gen2 or Trusted Launch SKU is not sufficient.

const std = @import("std");

const azure_compute = @import("azure_compute.zig");
const azure_vhd = @import("azure_vhd_layout.zig");
const contract = @import("contract.zig");

const Allocator = std.mem.Allocator;
const Diagnostic = contract.Diagnostic;
const ObjectMap = std.json.ObjectMap;
const Value = std.json.Value;

pub const image_security_feature = "ConfidentialVMSupported";
pub const image_security_type = "ConfidentialVmSupported";
pub const vm_security_type = "ConfidentialVM";
pub const os_disk_security_encryption_type = "VMGuestStateOnly";
pub const architecture = "x64";
pub const confidential_computing_type = "SNP";
pub const hyper_v_generation = azure_compute.hyper_v_generation;
pub const os_type = azure_compute.os_type;
pub const os_state = azure_compute.os_state;
pub const gallery_version_api = azure_compute.gallery_version_api;
pub const vm_api = azure_compute.vm_api;

/// Azure documents the source VHD or managed image as strictly less than
/// 32 GiB for a `ConfidentialVMSupported` gallery definition.
pub const maximum_vhd_current_size: u64 = 32 * 1024 * 1024 * 1024;

pub const Error = azure_compute.Error || error{
    InvalidVhdSize,
    InvalidSku,
    InvalidManagedImage,
    InvalidDiskSecurityProfile,
    InvalidGalleryVersion,
};
pub const VhdSizeError = error{InvalidVhdSize};
pub const SkuError = error{InvalidSku};
pub const ManagedImageError = error{InvalidManagedImage};
pub const DiskSecurityProfileError = error{InvalidDiskSecurityProfile};
pub const GalleryVersionError = error{InvalidGalleryVersion};

pub const Sku = struct {
    name: []const u8,
    has_temporary_storage: bool,
};

pub fn galleryVersionRequest(
    allocator: Allocator,
    location: []const u8,
    managed_image_id: []const u8,
) !Value {
    const publishing = try azure_compute.object(allocator, &.{
        .{ "replicationMode", azure_compute.string("Shallow") },
        .{ "targetRegions", try azure_compute.array(allocator, &.{
            try azure_compute.object(allocator, &.{
                .{ "name", azure_compute.string(location) },
                .{ "regionalReplicaCount", azure_compute.integer(1) },
                .{ "storageAccountType", azure_compute.string("Standard_LRS") },
            }),
        }) },
    });
    const storage = try azure_compute.object(allocator, &.{
        .{ "source", try azure_compute.object(allocator, &.{
            .{ "id", azure_compute.string(managed_image_id) },
        }) },
    });
    return azure_compute.object(allocator, &.{
        .{ "location", azure_compute.string(location) },
        .{ "properties", try azure_compute.object(allocator, &.{
            .{ "publishingProfile", publishing },
            .{ "storageProfile", storage },
        }) },
    });
}

pub fn validateVhdSize(
    virtual_size: u64,
    current_size: u64,
    file_size: u64,
    diagnostic: *Diagnostic,
) VhdSizeError!void {
    const aligned_units = std.math.divCeil(
        u64,
        virtual_size,
        azure_vhd.alignment,
    ) catch return diagnostic.fail(
        error.InvalidVhdSize,
        "Confidential VM VHD size overflow",
        .{},
    );
    const expected_current = std.math.mul(
        u64,
        aligned_units,
        azure_vhd.alignment,
    ) catch return diagnostic.fail(
        error.InvalidVhdSize,
        "Confidential VM VHD size overflow",
        .{},
    );
    const expected_file = std.math.add(
        u64,
        current_size,
        azure_vhd.footer_bytes,
    ) catch return diagnostic.fail(
        error.InvalidVhdSize,
        "Confidential VM VHD size overflow",
        .{},
    );
    if (current_size != expected_current or
        file_size != expected_file)
    {
        return diagnostic.fail(
            error.InvalidVhdSize,
            "Confidential VM VHD geometry does not match the candidate",
            .{},
        );
    }
    if (current_size >= maximum_vhd_current_size) return diagnostic.fail(
        error.InvalidVhdSize,
        "Confidential VM VHD must be smaller than 32 GiB",
        .{},
    );
}

pub fn validateManagedDisk(
    disk: *const ObjectMap,
    diagnostic: *Diagnostic,
) azure_compute.ManagedDiskError![]const u8 {
    return azure_compute.validateManagedDisk(disk, architecture, diagnostic);
}

pub fn validateManagedImage(
    image: *const ObjectMap,
    disk_id: []const u8,
    diagnostic: *Diagnostic,
) ManagedImageError![]const u8 {
    const id = azure_compute.stringOf(image.get("id")) orelse
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image ID is absent",
            .{},
        );
    if (!azure_compute.stringIs(image.get("hyperVGeneration"), hyper_v_generation) or
        !azure_compute.stringIs(image.get("provisioningState"), "Succeeded"))
    {
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image is not a provisioned Gen2 image",
            .{},
        );
    }
    const storage = azure_compute.objectOf(image.get("storageProfile")) orelse
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image storage profile is absent",
            .{},
        );
    const os_disk = azure_compute.objectOf(storage.get("osDisk")) orelse
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image OS disk is absent",
            .{},
        );
    const managed_disk = azure_compute.objectOf(os_disk.get("managedDisk")) orelse
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image source disk is absent",
            .{},
        );
    if (!azure_compute.stringIs(os_disk.get("osType"), os_type) or
        !azure_compute.stringIs(os_disk.get("osState"), os_state) or
        !azure_compute.stringIs(managed_disk.get("id"), disk_id))
    {
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image does not bind the generalized Linux source disk",
            .{},
        );
    }
    const disk_size_gib = azure_compute.integerOf(os_disk.get("diskSizeGB")) orelse
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image OS disk size is absent",
            .{},
        );
    if (disk_size_gib <= 0 or disk_size_gib >= 32) {
        return diagnostic.fail(
            error.InvalidManagedImage,
            "Azure managed image OS disk is not smaller than 32 GiB",
            .{},
        );
    }
    return id;
}

pub fn validateImageDefinition(
    definition: *const ObjectMap,
    diagnostic: *Diagnostic,
) azure_compute.ImageDefinitionError![]const u8 {
    return azure_compute.validateImageDefinition(
        definition,
        architecture,
        image_security_type,
        "Azure gallery image definition is not ConfidentialVMSupported",
        diagnostic,
    );
}

pub fn validateVmSecurityProfile(
    profile: *const ObjectMap,
    label: []const u8,
    diagnostic: *Diagnostic,
) azure_compute.SecurityProfileError!void {
    return azure_compute.validateVmSecurityProfile(
        profile,
        vm_security_type,
        "VM is not Confidential",
        label,
        diagnostic,
    );
}

pub fn validateOsDiskSecurityProfile(
    profile: *const ObjectMap,
    label: []const u8,
    diagnostic: *Diagnostic,
) DiskSecurityProfileError!void {
    if (!azure_compute.stringIs(
        profile.get("securityEncryptionType"),
        os_disk_security_encryption_type,
    )) {
        return diagnostic.fail(
            error.InvalidDiskSecurityProfile,
            "{s}: OS disk encryption is not VMGuestStateOnly",
            .{label},
        );
    }
}

fn capability(
    sku: *const ObjectMap,
    name: []const u8,
    diagnostic: *Diagnostic,
) SkuError!?[]const u8 {
    const capabilities = azure_compute.arrayOf(sku.get("capabilities")) orelse
        return null;
    var value: ?[]const u8 = null;
    for (capabilities) |candidate| {
        const item = azure_compute.objectOf(candidate) orelse continue;
        if (!azure_compute.stringIs(item.get("name"), name)) continue;
        if (value != null) return diagnostic.fail(
            error.InvalidSku,
            "configured Azure VM SKU has ambiguous {s} capability",
            .{name},
        );
        value = azure_compute.stringOf(item.get("value")) orelse
            return diagnostic.fail(
                error.InvalidSku,
                "configured Azure VM SKU has malformed {s} capability",
                .{name},
            );
    }
    return value;
}

fn positiveCapability(
    sku: *const ObjectMap,
    name: []const u8,
    diagnostic: *Diagnostic,
) SkuError!bool {
    const text = try capability(sku, name, diagnostic) orelse return false;
    const value = std.fmt.parseInt(u64, text, 10) catch return diagnostic.fail(
        error.InvalidSku,
        "configured Azure VM SKU has malformed {s} capability",
        .{name},
    );
    return value > 0;
}

pub fn validateSku(
    sku: *const ObjectMap,
    expected_name: []const u8,
    diagnostic: *Diagnostic,
) SkuError!Sku {
    if (!azure_compute.stringIs(sku.get("name"), expected_name)) {
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure Confidential VM SKU identity mismatch",
            .{},
        );
    }
    if (azure_compute.arrayOf(sku.get("restrictions"))) |restrictions| {
        for (restrictions) |restriction| {
            const item = azure_compute.objectOf(restriction) orelse continue;
            if (azure_compute.stringIs(item.get("type"), "Location")) {
                return diagnostic.fail(
                    error.InvalidSku,
                    "configured Azure Confidential VM SKU is location-restricted",
                    .{},
                );
            }
        }
    }
    const cpu = try capability(sku, "CpuArchitectureType", diagnostic) orelse
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure Confidential VM SKU does not report x64",
            .{},
        );
    if (!std.mem.eql(u8, cpu, architecture)) return diagnostic.fail(
        error.InvalidSku,
        "configured Azure Confidential VM SKU does not report x64",
        .{},
    );
    const generations = try capability(sku, "HyperVGenerations", diagnostic) orelse
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure Confidential VM SKU does not support Gen2",
            .{},
        );
    var listed = std.mem.splitScalar(u8, generations, ',');
    var has_v2 = false;
    while (listed.next()) |generation| {
        if (std.mem.eql(u8, generation, hyper_v_generation)) has_v2 = true;
    }
    if (!has_v2) return diagnostic.fail(
        error.InvalidSku,
        "configured Azure Confidential VM SKU does not support Gen2",
        .{},
    );
    const tee = try capability(sku, "ConfidentialComputingType", diagnostic) orelse
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure VM SKU is not AMD SEV-SNP confidential compute",
            .{},
        );
    if (!std.mem.eql(u8, tee, confidential_computing_type)) {
        return diagnostic.fail(
            error.InvalidSku,
            "configured Azure VM SKU is not AMD SEV-SNP confidential compute",
            .{},
        );
    }
    return .{
        .name = azure_compute.stringOf(sku.get("name")).?,
        .has_temporary_storage = try positiveCapability(sku, "MaxResourceVolumeMB", diagnostic) or
            try positiveCapability(sku, "NvmeDiskSizeInMiB", diagnostic),
    };
}

fn gallerySourceId(document: *const ObjectMap) ?[]const u8 {
    const properties = azure_compute.objectOf(document.get("properties")) orelse
        return null;
    const storage = azure_compute.objectOf(properties.get("storageProfile")) orelse
        return null;
    const source = azure_compute.objectOf(storage.get("source")) orelse
        return null;
    return azure_compute.stringOf(source.get("id"));
}

fn hasCustomUefiSettings(document: *const ObjectMap) bool {
    const properties = azure_compute.objectOf(document.get("properties")) orelse
        return false;
    const security = azure_compute.objectOf(properties.get("securityProfile")) orelse
        return false;
    return security.contains("uefiSettings");
}

/// Bind a gallery version to the exact managed image while requiring the
/// stock Microsoft/Canonical UEFI trust chain. Custom UEFI keys are documented
/// only for different gallery security profiles and are rejected here.
pub fn validateGalleryVersion(
    request: *const ObjectMap,
    response: *const ObjectMap,
    image_version_id: []const u8,
    managed_image_id: []const u8,
    require_succeeded: bool,
    diagnostic: *Diagnostic,
) GalleryVersionError!void {
    if (gallerySourceId(request)) |source| {
        if (!std.mem.eql(u8, source, managed_image_id)) return diagnostic.fail(
            error.InvalidGalleryVersion,
            "Azure gallery request does not reference the accepted managed image",
            .{},
        );
    } else return diagnostic.fail(
        error.InvalidGalleryVersion,
        "Azure gallery request does not reference the accepted managed image",
        .{},
    );
    if (hasCustomUefiSettings(request)) return diagnostic.fail(
        error.InvalidGalleryVersion,
        "ConfidentialVMSupported gallery request must retain stock UEFI trust",
        .{},
    );
    const identity = azure_compute.stringOf(response.get("id")) orelse "";
    if (!std.ascii.eqlIgnoreCase(identity, image_version_id)) {
        return diagnostic.fail(
            error.InvalidGalleryVersion,
            "Azure returned a different gallery image-version identity",
            .{},
        );
    }
    if (gallerySourceId(response)) |source| {
        if (!std.ascii.eqlIgnoreCase(source, managed_image_id)) return diagnostic.fail(
            error.InvalidGalleryVersion,
            "Azure gallery version does not reference the accepted managed image",
            .{},
        );
    } else return diagnostic.fail(
        error.InvalidGalleryVersion,
        "Azure gallery version does not reference the accepted managed image",
        .{},
    );
    if (hasCustomUefiSettings(response)) return diagnostic.fail(
        error.InvalidGalleryVersion,
        "ConfidentialVMSupported gallery version changed stock UEFI trust",
        .{},
    );
    if (!require_succeeded) return;
    const properties = azure_compute.objectOf(response.get("properties")) orelse
        return diagnostic.fail(
            error.InvalidGalleryVersion,
            "gallery image-version provisioning did not succeed",
            .{},
        );
    if (!azure_compute.stringIs(properties.get("provisioningState"), "Succeeded")) {
        return diagnostic.fail(
            error.InvalidGalleryVersion,
            "gallery image-version provisioning did not succeed",
            .{},
        );
    }
}

fn parse(allocator: Allocator, text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, allocator, text, .{});
}

test "Confidential VM gallery request retains stock UEFI trust" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const request = try galleryVersionRequest(
        arena.allocator(),
        "eastus2",
        "/subscriptions/test/disks/os",
    );
    const properties = azure_compute.objectOf(
        request.object.get("properties"),
    ).?;
    try std.testing.expect(!properties.contains("securityProfile"));
}

test "Confidential VM VHD size is strictly below 32 GiB" {
    var diagnostic: Diagnostic = .{};
    const under = maximum_vhd_current_size - azure_vhd.alignment;
    try validateVhdSize(
        under,
        under,
        under + azure_vhd.footer_bytes,
        &diagnostic,
    );
    try std.testing.expectError(
        error.InvalidVhdSize,
        validateVhdSize(
            maximum_vhd_current_size,
            maximum_vhd_current_size,
            maximum_vhd_current_size + azure_vhd.footer_bytes,
            &diagnostic,
        ),
    );
    try std.testing.expectEqualStrings(
        "Confidential VM VHD must be smaller than 32 GiB",
        diagnostic.message(),
    );
}

test "Confidential VM SKU requires x64 Gen2 AMD SEV-SNP" {
    var parsed = try parse(std.testing.allocator,
        \\{"name":"Standard_DC2ads_v5","restrictions":[],"capabilities":[
        \\{"name":"CpuArchitectureType","value":"x64"},
        \\{"name":"HyperVGenerations","value":"V1,V2"},
        \\{"name":"ConfidentialComputingType","value":"SNP"},
        \\{"name":"MaxResourceVolumeMB","value":"76800"}]}
    );
    defer parsed.deinit();
    var diagnostic: Diagnostic = .{};
    const sku = try validateSku(
        &parsed.value.object,
        "Standard_DC2ads_v5",
        &diagnostic,
    );
    try std.testing.expect(sku.has_temporary_storage);

    parsed.value.object.getPtr("capabilities").?.array.items[2]
        .object.getPtr("value").?.* = .{ .string = "TDX" };
    try std.testing.expectError(
        error.InvalidSku,
        validateSku(
            &parsed.value.object,
            "Standard_DC2ads_v5",
            &diagnostic,
        ),
    );
}

test "Confidential VM resource requires security and VMGS-only encryption" {
    var profile = try parse(std.testing.allocator,
        \\{"securityType":"ConfidentialVM","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}}
    );
    defer profile.deinit();
    var disk = try parse(std.testing.allocator,
        \\{"securityEncryptionType":"VMGuestStateOnly"}
    );
    defer disk.deinit();
    var diagnostic: Diagnostic = .{};
    try validateVmSecurityProfile(&profile.value.object, "vm.json", &diagnostic);
    try validateOsDiskSecurityProfile(&disk.value.object, "disk.json", &diagnostic);

    disk.value.object.getPtr("securityEncryptionType").?.* =
        .{ .string = "DiskWithVMGuestState" };
    try std.testing.expectError(
        error.InvalidDiskSecurityProfile,
        validateOsDiskSecurityProfile(
            &disk.value.object,
            "disk.json",
            &diagnostic,
        ),
    );
}

test "Confidential image definition rejects every security-profile substitution" {
    const valid =
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"ConfidentialVmSupported"}]}
    ;
    var definition = try parse(std.testing.allocator, valid);
    defer definition.deinit();
    var diagnostic: Diagnostic = .{};
    _ = try validateImageDefinition(&definition.value.object, &diagnostic);

    const invalid = [_][]const u8{
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"TrustedLaunchSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"TrustedLaunchAndConfidentialVmSupported"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"ConfidentialVM"}]}
        ,
        \\{"id":"/subscriptions/test/galleries/g/images/i","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[]}
        ,
    };
    for (invalid) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidImageDefinition,
            validateImageDefinition(
                &candidate.value.object,
                &candidate_diagnostic,
            ),
        );
    }
}

test "managed image and gallery version bind their exact source" {
    var image = try parse(std.testing.allocator,
        \\{"id":"/subscriptions/test/resourceGroups/test/providers/Microsoft.Compute/images/os","hyperVGeneration":"V2","provisioningState":"Succeeded","storageProfile":{"osDisk":{"diskSizeGB":31,"managedDisk":{"id":"/subscriptions/test/disks/os"},"osState":"Generalized","osType":"Linux"}}}
    );
    defer image.deinit();
    var diagnostic: Diagnostic = .{};
    _ = try validateManagedImage(
        &image.value.object,
        "/subscriptions/test/disks/os",
        &diagnostic,
    );
    image.value.object.getPtr("hyperVGeneration").?.* = .{ .string = "V1" };
    try std.testing.expectError(
        error.InvalidManagedImage,
        validateManagedImage(
            &image.value.object,
            "/subscriptions/test/disks/os",
            &diagnostic,
        ),
    );

    var request = try parse(std.testing.allocator,
        \\{"properties":{"storageProfile":{"source":{"id":"/subscriptions/test/images/os"}}}}
    );
    defer request.deinit();
    var response = try parse(std.testing.allocator,
        \\{"id":"/subscriptions/test/galleries/g/images/i/versions/1.0.0","properties":{"provisioningState":"Succeeded","storageProfile":{"source":{"id":"/subscriptions/test/images/os"}}}}
    );
    defer response.deinit();
    diagnostic = .{};
    try validateGalleryVersion(
        &request.value.object,
        &response.value.object,
        "/subscriptions/test/galleries/g/images/i/versions/1.0.0",
        "/subscriptions/test/images/os",
        true,
        &diagnostic,
    );

    var custom = try parse(std.testing.allocator,
        \\{"properties":{"storageProfile":{"source":{"id":"/subscriptions/test/images/os"}},"securityProfile":{"uefiSettings":{"signatureTemplateNames":["MicrosoftUefiCertificateAuthorityTemplate"]}}}}
    );
    defer custom.deinit();
    try std.testing.expectError(
        error.InvalidGalleryVersion,
        validateGalleryVersion(
            &custom.value.object,
            &response.value.object,
            "/subscriptions/test/galleries/g/images/i/versions/1.0.0",
            "/subscriptions/test/images/os",
            true,
            &diagnostic,
        ),
    );
    try std.testing.expectEqualStrings(
        "ConfidentialVMSupported gallery request must retain stock UEFI trust",
        diagnostic.message(),
    );
}
