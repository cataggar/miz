//! Azure Compute resource contracts shared by secure image profiles.
//!
//! Trusted Launch and Confidential VM releases use different image and VM
//! security types, but the surrounding Gen2 Linux resources are identical.
//! This module owns that common shape so a profile cannot quietly weaken the
//! managed-disk, gallery-definition, Secure Boot, or vTPM checks.

const std = @import("std");

const contract = @import("contract.zig");

const Allocator = std.mem.Allocator;
const Diagnostic = contract.Diagnostic;
const ObjectMap = std.json.ObjectMap;
const Value = std.json.Value;

pub const hyper_v_generation = "V2";
pub const os_type = "Linux";
pub const os_state = "Generalized";
pub const gallery_version_api = "2025-03-03";
pub const vm_api = "2024-11-01";

pub const Error = error{
    InvalidSecurityProfile,
    InvalidManagedDisk,
    InvalidImageDefinition,
    OutOfMemory,
};
pub const SecurityProfileError = error{InvalidSecurityProfile};
pub const ManagedDiskError = error{InvalidManagedDisk};
pub const ImageDefinitionError = error{InvalidImageDefinition};

pub fn object(
    allocator: Allocator,
    pairs: []const struct { []const u8, Value },
) !Value {
    var map: ObjectMap = .empty;
    try map.ensureTotalCapacity(allocator, pairs.len);
    for (pairs) |pair| map.putAssumeCapacity(pair[0], pair[1]);
    return .{ .object = map };
}

pub fn array(allocator: Allocator, items: []const Value) !Value {
    var values: std.json.Array = .init(allocator);
    try values.ensureTotalCapacity(items.len);
    for (items) |item| values.appendAssumeCapacity(item);
    return .{ .array = values };
}

pub fn string(text: []const u8) Value {
    return .{ .string = text };
}

pub fn integer(number: i64) Value {
    return .{ .integer = number };
}

pub fn objectOf(value: ?Value) ?ObjectMap {
    const present = value orelse return null;
    return switch (present) {
        .object => |map| map,
        else => null,
    };
}

pub fn arrayOf(value: ?Value) ?[]const Value {
    const present = value orelse return null;
    return switch (present) {
        .array => |items| items.items,
        else => null,
    };
}

pub fn stringOf(value: ?Value) ?[]const u8 {
    const present = value orelse return null;
    return switch (present) {
        .string => |text| text,
        else => null,
    };
}

pub fn integerOf(value: ?Value) ?i64 {
    const present = value orelse return null;
    return switch (present) {
        .integer => |number| number,
        else => null,
    };
}

pub fn stringIs(value: ?Value, expected: []const u8) bool {
    const actual = stringOf(value) orelse return false;
    return std.mem.eql(u8, actual, expected);
}

pub fn isTrue(value: ?Value) bool {
    const present = value orelse return false;
    return present == .bool and present.bool;
}

pub fn hasExactFields(map: ObjectMap, fields: []const []const u8) bool {
    if (map.count() != fields.len) return false;
    for (fields) |field| {
        if (!map.contains(field)) return false;
    }
    return true;
}

pub fn jsonEqual(left: Value, right: Value) bool {
    return switch (left) {
        .null => right == .null,
        .bool => |flag| right == .bool and right.bool == flag,
        .integer => |number| right == .integer and right.integer == number,
        .float => |number| right == .float and right.float == number,
        .number_string => |text| right == .number_string and
            std.mem.eql(u8, right.number_string, text),
        .string => |text| right == .string and std.mem.eql(u8, right.string, text),
        .array => |items| blk: {
            if (right != .array or items.items.len != right.array.items.len) {
                break :blk false;
            }
            for (items.items, right.array.items) |item, other| {
                if (!jsonEqual(item, other)) break :blk false;
            }
            break :blk true;
        },
        .object => |map| blk: {
            if (right != .object or map.count() != right.object.count()) {
                break :blk false;
            }
            var iterator = map.iterator();
            while (iterator.next()) |entry| {
                const other = right.object.get(entry.key_ptr.*) orelse
                    break :blk false;
                if (!jsonEqual(entry.value_ptr.*, other)) break :blk false;
            }
            break :blk true;
        },
    };
}

pub const GalleryVersionOptions = struct {
    location: []const u8,
    disk_id: []const u8,
    replication_mode: []const u8 = "Shallow",
    regional_replica_count: i64 = 1,
    storage_account_type: []const u8 = "Standard_LRS",
};

/// Build the image-version request shared by secure gallery profiles.
/// `security_profile` is null for profiles that retain the source image's
/// stock UEFI trust and a JSON object for profiles that customize it.
pub fn galleryVersionRequestWithOptions(
    allocator: Allocator,
    options: GalleryVersionOptions,
    security_profile: ?Value,
) !Value {
    const publishing = try object(allocator, &.{
        .{ "replicationMode", string(options.replication_mode) },
        .{ "targetRegions", try array(allocator, &.{
            try object(allocator, &.{
                .{ "name", string(options.location) },
                .{ "regionalReplicaCount", integer(options.regional_replica_count) },
                .{ "storageAccountType", string(options.storage_account_type) },
            }),
        }) },
    });
    const storage = try object(allocator, &.{
        .{ "osDiskImage", try object(allocator, &.{
            .{ "source", try object(allocator, &.{
                .{ "id", string(options.disk_id) },
            }) },
        }) },
    });
    const properties = if (security_profile) |security|
        try object(allocator, &.{
            .{ "publishingProfile", publishing },
            .{ "storageProfile", storage },
            .{ "securityProfile", security },
        })
    else
        try object(allocator, &.{
            .{ "publishingProfile", publishing },
            .{ "storageProfile", storage },
        });
    return object(allocator, &.{
        .{ "location", string(options.location) },
        .{ "properties", properties },
    });
}

pub fn galleryVersionRequest(
    allocator: Allocator,
    location: []const u8,
    disk_id: []const u8,
    security_profile: ?Value,
) !Value {
    return galleryVersionRequestWithOptions(
        allocator,
        .{ .location = location, .disk_id = disk_id },
        security_profile,
    );
}

pub fn validateVmSecurityProfile(
    profile: *const ObjectMap,
    expected_security_type: []const u8,
    security_type_message: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) SecurityProfileError!void {
    if (!stringIs(profile.get("securityType"), expected_security_type)) {
        return diagnostic.fail(
            error.InvalidSecurityProfile,
            "{s}: {s}",
            .{ label, security_type_message },
        );
    }
    const settings = objectOf(profile.get("uefiSettings")) orelse
        return diagnostic.fail(
            error.InvalidSecurityProfile,
            "{s}: Secure Boot is not enabled",
            .{label},
        );
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

pub fn validateManagedDisk(
    disk: *const ObjectMap,
    architecture: []const u8,
    diagnostic: *Diagnostic,
) ManagedDiskError![]const u8 {
    const id = stringOf(disk.get("id")) orelse return diagnostic.fail(
        error.InvalidManagedDisk,
        "Azure managed disk identity is absent",
        .{},
    );
    if (!std.mem.startsWith(u8, id, "/subscriptions/")) return diagnostic.fail(
        error.InvalidManagedDisk,
        "Azure managed disk identity is absent",
        .{},
    );
    if (!stringIs(disk.get("osType"), os_type)) return diagnostic.fail(
        error.InvalidManagedDisk,
        "Azure managed disk is not a Linux OS disk",
        .{},
    );
    if (!stringIs(disk.get("hyperVGeneration"), hyper_v_generation)) {
        return diagnostic.fail(
            error.InvalidManagedDisk,
            "Azure managed disk is not Hyper-V generation V2",
            .{},
        );
    }
    const capabilities = objectOf(disk.get("supportedCapabilities")) orelse
        return diagnostic.fail(
            error.InvalidManagedDisk,
            "Azure managed disk architecture mismatch",
            .{},
        );
    if (!stringIs(capabilities.get("architecture"), architecture)) {
        return diagnostic.fail(
            error.InvalidManagedDisk,
            "Azure managed disk architecture mismatch",
            .{},
        );
    }
    return id;
}

pub fn validateImageDefinition(
    definition: *const ObjectMap,
    architecture: []const u8,
    expected_security_type: []const u8,
    security_type_message: []const u8,
    diagnostic: *Diagnostic,
) ImageDefinitionError![]const u8 {
    const id = stringOf(definition.get("id")) orelse return diagnostic.fail(
        error.InvalidImageDefinition,
        "Azure gallery image-definition identity is absent",
        .{},
    );
    if (!std.mem.startsWith(u8, id, "/subscriptions/")) return diagnostic.fail(
        error.InvalidImageDefinition,
        "Azure gallery image-definition identity is absent",
        .{},
    );
    if (!stringIs(definition.get("osType"), os_type) or
        !stringIs(definition.get("osState"), os_state))
    {
        return diagnostic.fail(
            error.InvalidImageDefinition,
            "Azure gallery image definition is not generalized Linux",
            .{},
        );
    }
    if (!stringIs(definition.get("hyperVGeneration"), hyper_v_generation)) {
        return diagnostic.fail(
            error.InvalidImageDefinition,
            "Azure gallery image definition is not Hyper-V generation V2",
            .{},
        );
    }
    if (!stringIs(definition.get("architecture"), architecture)) {
        return diagnostic.fail(
            error.InvalidImageDefinition,
            "Azure gallery image-definition architecture mismatch",
            .{},
        );
    }
    const features = arrayOf(definition.get("features")) orelse &.{};
    var matches: usize = 0;
    for (features) |feature| {
        const fields = objectOf(feature) orelse continue;
        if (!stringIs(fields.get("name"), "SecurityType")) continue;
        matches += 1;
        if (!stringIs(fields.get("value"), expected_security_type)) {
            return diagnostic.fail(
                error.InvalidImageDefinition,
                "{s}",
                .{security_type_message},
            );
        }
    }
    if (matches != 1) return diagnostic.fail(
        error.InvalidImageDefinition,
        "{s}",
        .{security_type_message},
    );
    return id;
}

fn parse(allocator: Allocator, text: []const u8) !std.json.Parsed(Value) {
    return std.json.parseFromSlice(Value, allocator, text, .{});
}

test "gallery request omits an absent security profile" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const request = try galleryVersionRequest(
        allocator,
        "eastus2",
        "/subscriptions/test/disks/os",
        null,
    );
    const properties = objectOf(request.object.get("properties")).?;
    try std.testing.expect(!properties.contains("securityProfile"));
    try std.testing.expect(stringIs(request.object.get("location"), "eastus2"));
}

test "profile-independent validators reject the wrong security types" {
    var profile = try parse(std.testing.allocator,
        \\{"securityType":"TrustedLaunch","uefiSettings":{"secureBootEnabled":true,"vTpmEnabled":true}}
    );
    defer profile.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(
        error.InvalidSecurityProfile,
        validateVmSecurityProfile(
            &profile.value.object,
            "ConfidentialVM",
            "VM is not Confidential",
            "vm.json",
            &diagnostic,
        ),
    );
    try std.testing.expectEqualStrings(
        "vm.json: VM is not Confidential",
        diagnostic.message(),
    );
}
