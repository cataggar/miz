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
pub const captured_image_security_type = "ConfidentialVM";
pub const vm_security_type = "ConfidentialVM";
pub const os_disk_security_encryption_type = "VMGuestStateOnly";
pub const managed_disk_security_type =
    "ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey";
pub const gallery_os_disk_encryption_type =
    "EncryptedVMGuestStateOnlyWithPmk";
pub const platform_disk_encryption_type = "EncryptionAtRestWithPlatformKey";
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
    InvalidCaptureVm,
    InvalidCaptureDisk,
    InvalidCaptureSnapshot,
    InvalidCapturedImageDefinition,
    InvalidCaptureGalleryVersion,
};
pub const VhdSizeError = error{InvalidVhdSize};
pub const SkuError = error{InvalidSku};
pub const ManagedImageError = error{InvalidManagedImage};
pub const DiskSecurityProfileError = error{InvalidDiskSecurityProfile};
pub const GalleryVersionError = error{InvalidGalleryVersion};
pub const CaptureVmError = error{InvalidCaptureVm};
pub const CaptureDiskError = error{InvalidCaptureDisk} ||
    azure_compute.ManagedDiskError;
pub const CaptureSnapshotError = error{InvalidCaptureSnapshot};
pub const CapturedImageDefinitionError = error{InvalidCapturedImageDefinition} ||
    azure_compute.ImageDefinitionError;
pub const CaptureGalleryVersionError = error{InvalidCaptureGalleryVersion};

pub const Sku = struct {
    name: []const u8,
    has_temporary_storage: bool,
};

pub const CaptureContract = struct {
    subscription_id: []const u8,
    location: []const u8,
    source_image_version_id: []const u8,
    vm_id: []const u8,
    disk_id: []const u8,
};

pub const CaptureGalleryContract = struct {
    subscription_id: []const u8,
    location: []const u8,
    source_id: []const u8,
    image_definition_id: []const u8,
    image_version_id: []const u8,
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

fn validGuid(text: []const u8) bool {
    if (text.len != 36) return false;
    for (text, 0..) |character, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (character != '-') return false;
        } else switch (character) {
            '0'...'9', 'a'...'f', 'A'...'F' => {},
            else => return false,
        }
    }
    return true;
}

fn exactResource(
    actual: ?Value,
    expected_id: []const u8,
    subscription_id: []const u8,
) bool {
    const id = azure_compute.stringOf(actual) orelse return false;
    return azure_compute.resourceIdIs(id, expected_id) and
        azure_compute.resourceIdHasSubscription(id, subscription_id);
}

fn exactLocation(document: *const ObjectMap, expected: []const u8) bool {
    return azure_compute.stringIsIgnoreCase(document.get("location"), expected);
}

fn validVmDiskSecurityProfile(profile: *const ObjectMap) bool {
    return azure_compute.stringIs(
        profile.get("securityEncryptionType"),
        os_disk_security_encryption_type,
    ) and !profile.contains("diskEncryptionSet");
}

fn validResourceDiskSecurityProfile(profile: *const ObjectMap) bool {
    return azure_compute.stringIs(
        profile.get("securityType"),
        managed_disk_security_type,
    ) and !profile.contains("secureVMDiskEncryptionSetId");
}

fn validPlatformEncryption(document: *const ObjectMap) bool {
    const encryption = azure_compute.objectOf(document.get("encryption")) orelse
        return false;
    return azure_compute.stringIs(
        encryption.get("type"),
        platform_disk_encryption_type,
    );
}

/// Validate the exact VM that will be generalized and captured. The accepted
/// VM must still bind the source image version and its managed OS disk.
pub fn validateCaptureVm(
    vm: *const ObjectMap,
    expected: CaptureContract,
    diagnostic: *Diagnostic,
) CaptureVmError!void {
    if (!exactResource(vm.get("id"), expected.vm_id, expected.subscription_id) or
        !exactLocation(vm, expected.location) or
        !azure_compute.stringIs(vm.get("provisioningState"), "Succeeded"))
    {
        return diagnostic.fail(
            error.InvalidCaptureVm,
            "Azure capture VM identity, subscription, location, or provisioning state is invalid",
            .{},
        );
    }
    const vm_id = azure_compute.stringOf(vm.get("vmId")) orelse "";
    if (!validGuid(vm_id)) return diagnostic.fail(
        error.InvalidCaptureVm,
        "Azure capture VM unique identity is invalid",
        .{},
    );
    const security = azure_compute.objectOf(vm.get("securityProfile")) orelse
        return diagnostic.fail(
            error.InvalidCaptureVm,
            "Azure capture VM security profile is absent",
            .{},
        );
    azure_compute.validateVmSecurityProfile(
        &security,
        vm_security_type,
        "VM is not Confidential",
        "Azure capture VM",
        diagnostic,
    ) catch return error.InvalidCaptureVm;

    const storage = azure_compute.objectOf(vm.get("storageProfile")) orelse
        return diagnostic.fail(
            error.InvalidCaptureVm,
            "Azure capture VM storage profile is absent",
            .{},
        );
    const image = azure_compute.objectOf(storage.get("imageReference")) orelse
        return diagnostic.fail(
            error.InvalidCaptureVm,
            "Azure capture VM image reference is absent",
            .{},
        );
    if (!exactResource(
        image.get("id"),
        expected.source_image_version_id,
        expected.subscription_id,
    )) return diagnostic.fail(
        error.InvalidCaptureVm,
        "Azure capture VM does not reference the accepted source image version",
        .{},
    );
    const os_disk = azure_compute.objectOf(storage.get("osDisk")) orelse
        return diagnostic.fail(
            error.InvalidCaptureVm,
            "Azure capture VM OS disk is absent",
            .{},
        );
    const managed_disk = azure_compute.objectOf(os_disk.get("managedDisk")) orelse
        return diagnostic.fail(
            error.InvalidCaptureVm,
            "Azure capture VM managed OS disk is absent",
            .{},
        );
    if (!exactResource(
        managed_disk.get("id"),
        expected.disk_id,
        expected.subscription_id,
    )) return diagnostic.fail(
        error.InvalidCaptureVm,
        "Azure capture VM managed OS disk identity is invalid",
        .{},
    );
    if (managed_disk.contains("diskEncryptionSet")) return diagnostic.fail(
        error.InvalidCaptureVm,
        "Azure capture VM unexpectedly uses a customer-managed disk encryption set",
        .{},
    );
    const disk_security = azure_compute.objectOf(
        managed_disk.get("securityProfile"),
    ) orelse return diagnostic.fail(
        error.InvalidCaptureVm,
        "Azure capture VM managed OS disk security profile is absent",
        .{},
    );
    if (!validVmDiskSecurityProfile(&disk_security)) return diagnostic.fail(
        error.InvalidCaptureVm,
        "Azure capture VM OS disk encryption is not VMGuestStateOnly without a CMK",
        .{},
    );
}

/// Validate the managed OS disk after deallocation/generalization and before it
/// is used directly or copied to a snapshot.
pub fn validateCaptureManagedDisk(
    disk: *const ObjectMap,
    expected: CaptureContract,
    diagnostic: *Diagnostic,
) CaptureDiskError![]const u8 {
    const id = try azure_compute.validateManagedDisk(
        disk,
        architecture,
        diagnostic,
    );
    if (!azure_compute.resourceIdIs(id, expected.disk_id) or
        !azure_compute.resourceIdHasSubscription(id, expected.subscription_id) or
        !exactLocation(disk, expected.location) or
        !azure_compute.stringIs(disk.get("provisioningState"), "Succeeded") or
        !exactResource(
            disk.get("managedBy"),
            expected.vm_id,
            expected.subscription_id,
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureDisk,
            "Azure capture OS disk identity, VM binding, location, or provisioning state is invalid",
            .{},
        );
    }
    const security = azure_compute.objectOf(disk.get("securityProfile")) orelse
        return diagnostic.fail(
            error.InvalidCaptureDisk,
            "Azure capture OS disk security profile is absent",
            .{},
        );
    if (!validResourceDiskSecurityProfile(&security) or
        !validPlatformEncryption(disk))
    {
        return diagnostic.fail(
            error.InvalidCaptureDisk,
            "Azure capture OS disk is not VMGuestStateOnly with platform-managed keys",
            .{},
        );
    }
    return id;
}

/// Validate a completed same-region snapshot copied from the accepted managed
/// OS disk. Confidential security metadata must survive the copy unchanged.
pub fn validateCaptureSnapshot(
    snapshot: *const ObjectMap,
    expected_snapshot_id: []const u8,
    expected: CaptureContract,
    diagnostic: *Diagnostic,
) CaptureSnapshotError![]const u8 {
    const id = azure_compute.stringOf(snapshot.get("id")) orelse "";
    if (!azure_compute.resourceIdIs(id, expected_snapshot_id) or
        !azure_compute.resourceIdHasSubscription(id, expected.subscription_id) or
        !exactLocation(snapshot, expected.location) or
        !azure_compute.stringIs(snapshot.get("provisioningState"), "Succeeded") or
        !azure_compute.stringIs(snapshot.get("osType"), os_type) or
        !azure_compute.stringIs(
            snapshot.get("hyperVGeneration"),
            hyper_v_generation,
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureSnapshot,
            "Azure capture snapshot identity, location, OS, generation, or provisioning state is invalid",
            .{},
        );
    }
    const capabilities = azure_compute.objectOf(
        snapshot.get("supportedCapabilities"),
    ) orelse return diagnostic.fail(
        error.InvalidCaptureSnapshot,
        "Azure capture snapshot architecture is absent",
        .{},
    );
    const creation = azure_compute.objectOf(snapshot.get("creationData")) orelse
        return diagnostic.fail(
            error.InvalidCaptureSnapshot,
            "Azure capture snapshot source is absent",
            .{},
        );
    if (!azure_compute.stringIs(capabilities.get("architecture"), architecture) or
        !azure_compute.stringIs(creation.get("createOption"), "Copy") or
        !exactResource(
            creation.get("sourceResourceId"),
            expected.disk_id,
            expected.subscription_id,
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureSnapshot,
            "Azure capture snapshot does not bind the accepted x64 OS disk",
            .{},
        );
    }
    const security = azure_compute.objectOf(snapshot.get("securityProfile")) orelse
        return diagnostic.fail(
            error.InvalidCaptureSnapshot,
            "Azure capture snapshot security profile is absent",
            .{},
        );
    if (!validResourceDiskSecurityProfile(&security) or
        !validPlatformEncryption(snapshot))
    {
        return diagnostic.fail(
            error.InvalidCaptureSnapshot,
            "Azure capture snapshot is not VMGuestStateOnly with platform-managed keys",
            .{},
        );
    }
    return id;
}

pub fn validateCapturedImageDefinition(
    definition: *const ObjectMap,
    expected: CaptureGalleryContract,
    diagnostic: *Diagnostic,
) CapturedImageDefinitionError![]const u8 {
    const id = try azure_compute.validateImageDefinition(
        definition,
        architecture,
        captured_image_security_type,
        "Azure gallery image definition is not ConfidentialVM",
        diagnostic,
    );
    if (!azure_compute.resourceIdIs(id, expected.image_definition_id) or
        !azure_compute.resourceIdHasSubscription(id, expected.subscription_id) or
        !exactLocation(definition, expected.location) or
        !azure_compute.stringIs(definition.get("provisioningState"), "Succeeded"))
    {
        return diagnostic.fail(
            error.InvalidCapturedImageDefinition,
            "Azure ConfidentialVM image-definition identity, subscription, location, or provisioning state is invalid",
            .{},
        );
    }
    return id;
}

pub fn captureGalleryVersionRequest(
    allocator: Allocator,
    location: []const u8,
    source_id: []const u8,
) !Value {
    const encryption = try azure_compute.object(allocator, &.{
        .{ "osDiskImage", try azure_compute.object(allocator, &.{
            .{ "securityProfile", try azure_compute.object(allocator, &.{
                .{
                    "confidentialVMEncryptionType",
                    azure_compute.string(gallery_os_disk_encryption_type),
                },
            }) },
        }) },
    });
    return azure_compute.object(allocator, &.{
        .{ "location", azure_compute.string(location) },
        .{ "properties", try azure_compute.object(allocator, &.{
            .{ "publishingProfile", try azure_compute.object(allocator, &.{
                .{ "replicationMode", azure_compute.string("Full") },
                .{ "targetRegions", try azure_compute.array(allocator, &.{
                    try azure_compute.object(allocator, &.{
                        .{ "name", azure_compute.string(location) },
                        .{ "regionalReplicaCount", azure_compute.integer(1) },
                        .{ "storageAccountType", azure_compute.string("Standard_LRS") },
                        .{ "encryption", encryption },
                    }),
                }) },
            }) },
            .{ "storageProfile", try azure_compute.object(allocator, &.{
                .{ "osDiskImage", try azure_compute.object(allocator, &.{
                    .{ "source", try azure_compute.object(allocator, &.{
                        .{ "id", azure_compute.string(source_id) },
                    }) },
                }) },
            }) },
        }) },
    });
}

fn captureGallerySourceId(document: *const ObjectMap) ?[]const u8 {
    const properties = azure_compute.objectOf(document.get("properties")) orelse
        return null;
    const storage = azure_compute.objectOf(properties.get("storageProfile")) orelse
        return null;
    const os_disk = azure_compute.objectOf(storage.get("osDiskImage")) orelse
        return null;
    const source = azure_compute.objectOf(os_disk.get("source")) orelse
        return null;
    return azure_compute.stringOf(source.get("id"));
}

fn validateCapturePublishingProfile(
    document: *const ObjectMap,
    location: []const u8,
    strict_request: bool,
    diagnostic: *Diagnostic,
) CaptureGalleryVersionError!void {
    const properties = azure_compute.objectOf(document.get("properties")) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery properties are absent",
            .{},
        );
    if (properties.contains("securityProfile")) return diagnostic.fail(
        error.InvalidCaptureGalleryVersion,
        "Azure ConfidentialVM gallery version must retain stock UEFI trust",
        .{},
    );
    const publishing = azure_compute.objectOf(
        properties.get("publishingProfile"),
    ) orelse return diagnostic.fail(
        error.InvalidCaptureGalleryVersion,
        "Azure ConfidentialVM gallery publishing profile is absent",
        .{},
    );
    if (strict_request and
        (!azure_compute.hasExactFields(
            properties,
            &.{ "publishingProfile", "storageProfile" },
        ) or
            !azure_compute.hasExactFields(
                publishing,
                &.{ "replicationMode", "targetRegions" },
            ) or
            !azure_compute.stringIs(publishing.get("replicationMode"), "Full")))
    {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery request contains unsupported properties",
            .{},
        );
    }
    const targets = azure_compute.arrayOf(publishing.get("targetRegions")) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery target region is absent",
            .{},
        );
    if (targets.len != 1) return diagnostic.fail(
        error.InvalidCaptureGalleryVersion,
        "Azure ConfidentialVM gallery request must have one regional replica and no cross-region targets",
        .{},
    );
    const target = azure_compute.objectOf(targets[0]) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery target region is invalid",
            .{},
        );
    if (!azure_compute.stringIsIgnoreCase(target.get("name"), location) or
        azure_compute.integerOf(target.get("regionalReplicaCount")) != 1 or
        !azure_compute.stringIs(
            target.get("storageAccountType"),
            "Standard_LRS",
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery target must be the source region with one Standard_LRS replica",
            .{},
        );
    }
    if (strict_request and !azure_compute.hasExactFields(
        target,
        &.{
            "encryption",
            "name",
            "regionalReplicaCount",
            "storageAccountType",
        },
    )) return diagnostic.fail(
        error.InvalidCaptureGalleryVersion,
        "Azure ConfidentialVM gallery target contains unsupported settings",
        .{},
    );
    const encryption = azure_compute.objectOf(target.get("encryption")) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery OS-disk encryption profile is absent",
            .{},
        );
    const os_disk = azure_compute.objectOf(encryption.get("osDiskImage")) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery OS-disk encryption profile is absent",
            .{},
        );
    const security = azure_compute.objectOf(os_disk.get("securityProfile")) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery OS-disk security profile is absent",
            .{},
        );
    if (!azure_compute.hasExactFields(encryption, &.{"osDiskImage"}) or
        !azure_compute.hasExactFields(os_disk, &.{"securityProfile"}) or
        !azure_compute.hasExactFields(
            security,
            &.{"confidentialVMEncryptionType"},
        ) or
        !azure_compute.stringIs(
            security.get("confidentialVMEncryptionType"),
            gallery_os_disk_encryption_type,
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery OS-disk encryption is not EncryptedVMGuestStateOnlyWithPmk",
            .{},
        );
    }
}

pub fn validateCaptureGalleryRequest(
    request: *const ObjectMap,
    expected: CaptureGalleryContract,
    diagnostic: *Diagnostic,
) CaptureGalleryVersionError!void {
    if (!exactLocation(request, expected.location)) return diagnostic.fail(
        error.InvalidCaptureGalleryVersion,
        "Azure ConfidentialVM gallery request location is invalid",
        .{},
    );
    const source_id = captureGallerySourceId(request) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery request source is absent",
            .{},
        );
    if (!azure_compute.resourceIdIs(source_id, expected.source_id) or
        !azure_compute.resourceIdHasSubscription(
            source_id,
            expected.subscription_id,
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery request does not reference the accepted disk or snapshot",
            .{},
        );
    }
    try validateCapturePublishingProfile(
        request,
        expected.location,
        true,
        diagnostic,
    );
}

pub fn validateCapturedGalleryVersion(
    response: *const ObjectMap,
    expected: CaptureGalleryContract,
    diagnostic: *Diagnostic,
) CaptureGalleryVersionError!void {
    if (!exactResource(
        response.get("id"),
        expected.image_version_id,
        expected.subscription_id,
    ) or !exactLocation(response, expected.location)) {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure returned a different ConfidentialVM gallery image-version identity or location",
            .{},
        );
    }
    const source_id = captureGallerySourceId(response) orelse
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery version source is absent",
            .{},
        );
    if (!azure_compute.resourceIdIs(source_id, expected.source_id) or
        !azure_compute.resourceIdHasSubscription(
            source_id,
            expected.subscription_id,
        ))
    {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery version does not reference the accepted disk or snapshot",
            .{},
        );
    }
    try validateCapturePublishingProfile(
        response,
        expected.location,
        false,
        diagnostic,
    );
    const properties = azure_compute.objectOf(response.get("properties")).?;
    if (!azure_compute.stringIs(properties.get("provisioningState"), "Succeeded")) {
        return diagnostic.fail(
            error.InvalidCaptureGalleryVersion,
            "Azure ConfidentialVM gallery image-version provisioning did not succeed",
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

const capture_contract: CaptureContract = .{
    .subscription_id = "sub",
    .location = "eastus2",
    .source_image_version_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/" ++
        "galleries/g/images/supported/versions/1.0.0",
    .vm_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/" ++
        "virtualMachines/capture",
    .disk_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/" ++
        "disks/capture-os",
};

const capture_gallery_contract: CaptureGalleryContract = .{
    .subscription_id = "sub",
    .location = "eastus2",
    .source_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/" ++
        "snapshots/capture-os",
    .image_definition_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/" ++
        "galleries/g/images/confidential",
    .image_version_id = "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/" ++
        "galleries/g/images/confidential/versions/1.0.0",
};

test "capture VM binds identity image and VMGuestStateOnly OS disk" {
    const valid =
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","vmId":"01234567-89ab-cdef-0123-456789abcdef","location":"eastus2","provisioningState":"Succeeded","securityProfile":{"securityType":"ConfidentialVM","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}},"storageProfile":{"imageReference":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/supported/versions/1.0.0"},"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","securityProfile":{"securityEncryptionType":"VMGuestStateOnly"}}}}}
    ;
    var vm = try parse(std.testing.allocator, valid);
    defer vm.deinit();
    var diagnostic: Diagnostic = .{};
    try validateCaptureVm(&vm.value.object, capture_contract, &diagnostic);

    const invalid = [_][]const u8{
        \\{"id":"/subscriptions/other/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","vmId":"01234567-89ab-cdef-0123-456789abcdef","location":"eastus2","provisioningState":"Succeeded","securityProfile":{"securityType":"ConfidentialVM","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}},"storageProfile":{"imageReference":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/supported/versions/1.0.0"},"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","securityProfile":{"securityEncryptionType":"VMGuestStateOnly"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","vmId":"01234567-89ab-cdef-0123-456789abcdef","location":"westus2","provisioningState":"Succeeded","securityProfile":{"securityType":"ConfidentialVM","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}},"storageProfile":{"imageReference":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/supported/versions/1.0.0"},"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","securityProfile":{"securityEncryptionType":"VMGuestStateOnly"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","vmId":"01234567-89ab-cdef-0123-456789abcdef","location":"eastus2","provisioningState":"Succeeded","securityProfile":{"securityType":"TrustedLaunch","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}},"storageProfile":{"imageReference":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/supported/versions/1.0.0"},"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","securityProfile":{"securityEncryptionType":"VMGuestStateOnly"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","vmId":"01234567-89ab-cdef-0123-456789abcdef","location":"eastus2","provisioningState":"Succeeded","securityProfile":{"securityType":"ConfidentialVM","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}},"storageProfile":{"imageReference":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/other/versions/1.0.0"},"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","securityProfile":{"securityEncryptionType":"VMGuestStateOnly"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","vmId":"01234567-89ab-cdef-0123-456789abcdef","location":"eastus2","provisioningState":"Succeeded","securityProfile":{"securityType":"ConfidentialVM","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}},"storageProfile":{"imageReference":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/supported/versions/1.0.0"},"osDisk":{"managedDisk":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","securityProfile":{"securityEncryptionType":"DiskWithVMGuestState"}}}}}
        ,
    };
    for (invalid) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidCaptureVm,
            validateCaptureVm(
                &candidate.value.object,
                capture_contract,
                &candidate_diagnostic,
            ),
        );
    }
}

test "capture disk and snapshot preserve source security in one region" {
    var disk = try parse(std.testing.allocator,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os","managedBy":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/capture","location":"eastus2","provisioningState":"Succeeded","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"},"securityProfile":{"securityType":"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey"},"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}
    );
    defer disk.deinit();
    var diagnostic: Diagnostic = .{};
    _ = try validateCaptureManagedDisk(
        &disk.value.object,
        capture_contract,
        &diagnostic,
    );
    disk.value.object.getPtr("securityProfile").?.object
        .getPtr("securityType").?.* = .{
        .string = "ConfidentialVM_DiskEncryptedWithPlatformKey",
    };
    try std.testing.expectError(
        error.InvalidCaptureDisk,
        validateCaptureManagedDisk(
            &disk.value.object,
            capture_contract,
            &diagnostic,
        ),
    );

    const valid_snapshot =
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os","location":"eastus2","provisioningState":"Succeeded","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"},"creationData":{"createOption":"Copy","sourceResourceId":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os"},"securityProfile":{"securityType":"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey"},"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}
    ;
    var snapshot = try parse(std.testing.allocator, valid_snapshot);
    defer snapshot.deinit();
    _ = try validateCaptureSnapshot(
        &snapshot.value.object,
        capture_gallery_contract.source_id,
        capture_contract,
        &diagnostic,
    );

    const invalid = [_][]const u8{
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os","location":"westus2","provisioningState":"Succeeded","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"},"creationData":{"createOption":"Copy","sourceResourceId":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os"},"securityProfile":{"securityType":"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey"},"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os","location":"eastus2","provisioningState":"Failed","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"},"creationData":{"createOption":"Copy","sourceResourceId":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os"},"securityProfile":{"securityType":"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey"},"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os","location":"eastus2","provisioningState":"Succeeded","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"},"creationData":{"createOption":"Copy","sourceResourceId":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/other"},"securityProfile":{"securityType":"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey"},"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}
        ,
        \\{"id":"/subscriptions/other/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os","location":"eastus2","provisioningState":"Succeeded","osType":"Linux","hyperVGeneration":"V2","supportedCapabilities":{"architecture":"x64"},"creationData":{"createOption":"Copy","sourceResourceId":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/disks/capture-os"},"securityProfile":{"securityType":"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey"},"encryption":{"type":"EncryptionAtRestWithPlatformKey"}}
        ,
    };
    for (invalid) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidCaptureSnapshot,
            validateCaptureSnapshot(
                &candidate.value.object,
                capture_gallery_contract.source_id,
                capture_contract,
                &candidate_diagnostic,
            ),
        );
    }
}

test "captured image definition is ConfidentialVM and provisioned" {
    const valid =
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential","location":"eastus2","provisioningState":"Succeeded","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"ConfidentialVM"}]}
    ;
    var definition = try parse(std.testing.allocator, valid);
    defer definition.deinit();
    var diagnostic: Diagnostic = .{};
    _ = try validateCapturedImageDefinition(
        &definition.value.object,
        capture_gallery_contract,
        &diagnostic,
    );

    var wrong_security = try parse(std.testing.allocator,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential","location":"eastus2","provisioningState":"Succeeded","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"ConfidentialVmSupported"}]}
    );
    defer wrong_security.deinit();
    try std.testing.expectError(
        error.InvalidImageDefinition,
        validateCapturedImageDefinition(
            &wrong_security.value.object,
            capture_gallery_contract,
            &diagnostic,
        ),
    );

    const invalid_resource = [_][]const u8{
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential","location":"westus2","provisioningState":"Succeeded","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"ConfidentialVM"}]}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential","location":"eastus2","provisioningState":"Failed","osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","features":[{"name":"SecurityType","value":"ConfidentialVM"}]}
        ,
    };
    for (invalid_resource) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidCapturedImageDefinition,
            validateCapturedImageDefinition(
                &candidate.value.object,
                capture_gallery_contract,
                &candidate_diagnostic,
            ),
        );
    }
}

test "capture gallery request and response are exact and fail closed" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const request = try captureGalleryVersionRequest(
        arena.allocator(),
        capture_gallery_contract.location,
        capture_gallery_contract.source_id,
    );
    var diagnostic: Diagnostic = .{};
    try validateCaptureGalleryRequest(
        &request.object,
        capture_gallery_contract,
        &diagnostic,
    );

    const response_text =
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential/versions/1.0.0","location":"eastus2","properties":{"provisioningState":"Succeeded","publishingProfile":{"replicationMode":"Full","targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}}}}
    ;
    var response = try parse(std.testing.allocator, response_text);
    defer response.deinit();
    try validateCapturedGalleryVersion(
        &response.value.object,
        capture_gallery_contract,
        &diagnostic,
    );

    const invalid_requests = [_][]const u8{
        \\{"location":"eastus2","properties":{"publishingProfile":{"replicationMode":"Full","targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}}}}
        ,
        \\{"location":"eastus2","properties":{"publishingProfile":{"replicationMode":"Full","targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/other"}}}}}
        ,
        \\{"location":"eastus2","properties":{"publishingProfile":{"replicationMode":"Full","targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}},{"name":"westus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}}}}
        ,
        \\{"location":"eastus2","properties":{"publishingProfile":{"replicationMode":"Full","targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}},"securityProfile":{"uefiSettings":{"signatureTemplateNames":["Custom"]}}}}
        ,
    };
    for (invalid_requests) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidCaptureGalleryVersion,
            validateCaptureGalleryRequest(
                &candidate.value.object,
                capture_gallery_contract,
                &candidate_diagnostic,
            ),
        );
    }

    const invalid_responses = [_][]const u8{
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential/versions/2.0.0","location":"eastus2","properties":{"provisioningState":"Succeeded","publishingProfile":{"targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential/versions/1.0.0","location":"eastus2","properties":{"provisioningState":"Succeeded","publishingProfile":{"targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/other"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential/versions/1.0.0","location":"eastus2","properties":{"provisioningState":"Succeeded","publishingProfile":{"targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}}}}
        ,
        \\{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/galleries/g/images/confidential/versions/1.0.0","location":"eastus2","properties":{"provisioningState":"Failed","publishingProfile":{"targetRegions":[{"name":"eastus2","regionalReplicaCount":1,"storageAccountType":"Standard_LRS","encryption":{"osDiskImage":{"securityProfile":{"confidentialVMEncryptionType":"EncryptedVMGuestStateOnlyWithPmk"}}}}]},"storageProfile":{"osDiskImage":{"source":{"id":"/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Compute/snapshots/capture-os"}}}}}
        ,
    };
    for (invalid_responses) |text| {
        var candidate = try parse(std.testing.allocator, text);
        defer candidate.deinit();
        var candidate_diagnostic: Diagnostic = .{};
        try std.testing.expectError(
            error.InvalidCaptureGalleryVersion,
            validateCapturedGalleryVersion(
                &candidate.value.object,
                capture_gallery_contract,
                &candidate_diagnostic,
            ),
        );
    }
}
