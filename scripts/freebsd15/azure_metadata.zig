//! Azure resource metadata validation for the FreeBSD 15.1 acceptance harness.
//!
//! Native port of `scripts/freebsd15_azure_metadata.py` together with the
//! inline Python `scripts/freebsd15_azure_acceptance.sh` used to embed. Every
//! check answers the same question the harness has to answer before it trusts
//! an Azure resource: is this the exact resource this run created, in the
//! resource group this run owns, with the shape the release contract requires?
//! A field Azure sometimes omits is allowed to be absent, but a field that is
//! present and disagrees is always a failure.

const std = @import("std");
const document = @import("document.zig");
const support = @import("release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const Value = std.json.Value;
const Writer = std.Io.Writer;
const file_support = support.file;
const json_document = support.json_document;

pub const Context = document.Context;
pub const Error = document.Error;

pub const gib: i64 = 1024 * 1024 * 1024;

/// Azure metadata documents are a few kilobytes; a location listing is the
/// largest and stays far inside this bound.
pub const max_document_bytes: u64 = 8 * 1024 * 1024;
/// A serial console response is a boot log. Azure caps them well below this.
pub const max_serial_console_bytes: u64 = 64 * 1024 * 1024;

// ---- Shared helpers -------------------------------------------------------

/// `same`: a present string that matches case-insensitively.
pub fn same(value: ?Value, expected: []const u8) bool {
    const text = document.stringOf(value) orelse return false;
    return std.ascii.eqlIgnoreCase(text, expected);
}

/// `value_at`: dotted-path lookup that distinguishes absent from null.
pub fn valueAt(root: Value, path: []const u8) ?Value {
    var current = root;
    var components = std.mem.splitScalar(u8, path, '.');
    while (components.next()) |component| {
        const object = document.objectOf(current) orelse return null;
        current = object.get(component) orelse return null;
    }
    return current;
}

pub fn loadDocument(context: *Context, path: []const u8) Error!Value {
    const parsed = json_document.readObject(
        context.arena,
        context.io,
        path,
        max_document_bytes,
        &context.diagnostic,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Invalid,
    };
    return parsed.parsed.value;
}

/// `json.dumps(value, sort_keys=True)`: sorted keys and the default `", "` and
/// `": "` separators the operator-facing diagnostics were written against.
pub fn writeSpacedJson(
    allocator: Allocator,
    writer: *Writer,
    value: Value,
) Error!void {
    switch (value) {
        .null => writer.writeAll("null") catch return error.OutOfMemory,
        .bool => |flag| writer.writeAll(if (flag) "true" else "false") catch
            return error.OutOfMemory,
        .integer => |number| writer.print("{d}", .{number}) catch
            return error.OutOfMemory,
        .float => |number| writer.print("{d}", .{number}) catch
            return error.OutOfMemory,
        .number_string => |text| writer.writeAll(text) catch return error.OutOfMemory,
        .string => |text| try writeJsonString(writer, text),
        .array => |items| {
            writer.writeByte('[') catch return error.OutOfMemory;
            for (items.items, 0..) |item, index| {
                if (index > 0) writer.writeAll(", ") catch return error.OutOfMemory;
                try writeSpacedJson(allocator, writer, item);
            }
            writer.writeByte(']') catch return error.OutOfMemory;
        },
        .object => |map| {
            const keys = try allocator.dupe([]const u8, map.keys());
            defer allocator.free(keys);
            std.mem.sort([]const u8, keys, {}, lessThanKey);
            writer.writeByte('{') catch return error.OutOfMemory;
            for (keys, 0..) |key, index| {
                if (index > 0) writer.writeAll(", ") catch return error.OutOfMemory;
                try writeJsonString(writer, key);
                writer.writeAll(": ") catch return error.OutOfMemory;
                try writeSpacedJson(allocator, writer, map.get(key).?);
            }
            writer.writeByte('}') catch return error.OutOfMemory;
        },
    }
}

fn lessThanKey(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn writeJsonString(writer: *Writer, text: []const u8) Error!void {
    var stringify: std.json.Stringify = .{
        .writer = writer,
        .options = .{ .escape_unicode = true },
    };
    stringify.write(text) catch return error.OutOfMemory;
}

/// `json.dumps(value, ensure_ascii=True, separators=(",", ":"))`.
pub fn compactJson(context: *Context, value: Value) Error![]const u8 {
    return json_document.canonicalAlloc(context.arena, value, .compact) catch |err|
        switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => return context.fail("unsupported diagnostic value", .{}),
        };
}

// ---- Size validation ------------------------------------------------------

pub const SizeCheck = struct {
    scope: []const u8,
    expected_size_gib: i64,
    byte_paths: []const []const u8,
    gib_paths: []const []const u8,
    allow_missing: bool = false,
};

/// `validate_size`: any size field Azure does expose has to agree exactly, and
/// at least one has to be exposed unless the caller allows none.
pub fn validateSize(context: *Context, root: Value, check: SizeCheck) Error!void {
    const expected_bytes = check.expected_size_gib * gib;

    var observed: std.json.ObjectMap = .empty;
    var mismatches: std.ArrayList([]const u8) = .empty;
    var represented: usize = 0;

    for ([_]bool{ true, false }) |bytes_pass| {
        const paths = if (bytes_pass) check.byte_paths else check.gib_paths;
        const expected = if (bytes_pass) expected_bytes else check.expected_size_gib;
        for (paths) |path| {
            const value = valueAt(root, path) orelse continue;
            try observed.put(context.arena, path, value);
            if (value == .null) continue;
            represented += 1;
            if (document.integerOf(value) != expected) {
                try mismatches.append(context.arena, path);
            }
        }
    }

    if (mismatches.items.len > 0) {
        var out: Writer.Allocating = .init(context.arena);
        try writeSpacedJson(context.gpa, &out.writer, .{ .object = observed });
        var fields: Writer.Allocating = .init(context.arena);
        for (mismatches.items, 0..) |path, index| {
            if (index > 0) fields.writer.writeAll(", ") catch return error.OutOfMemory;
            fields.writer.writeAll(path) catch return error.OutOfMemory;
        }
        return context.fail(
            "{s} size mismatch: expected {d} GiB ({d} bytes); observed {s}; " ++
                "mismatched fields {s}",
            .{
                check.scope,
                check.expected_size_gib,
                expected_bytes,
                out.written(),
                fields.written(),
            },
        );
    }
    if (represented == 0 and !check.allow_missing) {
        var out: Writer.Allocating = .init(context.arena);
        try writeSpacedJson(context.gpa, &out.writer, .{ .object = observed });
        var keys: Writer.Allocating = .init(context.arena);
        try writeSortedKeys(context, &keys.writer, root);
        return context.fail(
            "{s} size metadata is missing: expected {d} GiB ({d} bytes); " ++
                "observed {s}; object keys {s}",
            .{
                check.scope,
                check.expected_size_gib,
                expected_bytes,
                out.written(),
                keys.written(),
            },
        );
    }
}

/// `sorted(document)` rendered as the Python list repr the diagnostic showed.
fn writeSortedKeys(context: *Context, writer: *Writer, value: Value) Error!void {
    const object = document.objectOf(value) orelse {
        writer.writeAll("<non-object>") catch return error.OutOfMemory;
        return;
    };
    const keys = try context.gpa.dupe([]const u8, object.keys());
    defer context.gpa.free(keys);
    std.mem.sort([]const u8, keys, {}, lessThanKey);
    writer.writeByte('[') catch return error.OutOfMemory;
    for (keys, 0..) |key, index| {
        if (index > 0) writer.writeAll(", ") catch return error.OutOfMemory;
        writer.print("'{s}'", .{key}) catch return error.OutOfMemory;
    }
    writer.writeByte(']') catch return error.OutOfMemory;
}

const disk_byte_paths = [_][]const u8{ "diskSizeBytes", "sizeInBytes" };
const disk_gib_paths = [_][]const u8{
    "diskSizeGb",
    "diskSizeGB",
    "sizeInGB",
    "sizeInGb",
};

fn requireSizeGib(context: *Context, text: []const u8) Error!i64 {
    return std.fmt.parseInt(i64, text, 10) catch context.fail(
        "expected size in GiB is not an integer: {s}",
        .{text},
    );
}

// ---- managed-disk ---------------------------------------------------------

pub const ManagedDiskArguments = struct {
    path: []const u8,
    expected_id: []const u8,
    expected_name: []const u8,
    expected_group: []const u8,
    expected_location: []const u8,
    expected_architecture: []const u8,
    expected_size_gib: []const u8,
};

pub fn validateManagedDisk(
    context: *Context,
    arguments: ManagedDiskArguments,
    writer: *Writer,
) Error!void {
    const value = try loadDocument(context, arguments.path);
    const root = value.object;

    if (!same(root.get("id"), arguments.expected_id)) return context.fail(
        "Azure returned a different managed disk identity",
        .{},
    );
    if (!document.eqlString(root.get("name"), arguments.expected_name)) {
        return context.fail("Azure returned a different managed disk name", .{});
    }
    const resource_group = root.get("resourceGroup");
    if (!document.isAbsentOrEmpty(resource_group) and
        !same(resource_group, arguments.expected_group))
    {
        return context.fail(
            "managed disk is outside the owned temporary resource group",
            .{},
        );
    }
    if (!same(root.get("location"), arguments.expected_location)) return context.fail(
        "managed disk location mismatch",
        .{},
    );
    if (!same(root.get("type"), "Microsoft.Compute/disks")) return context.fail(
        "Azure returned a non-disk resource",
        .{},
    );
    if (!document.eqlString(root.get("osType"), "Linux")) return context.fail(
        "managed disk OS type mismatch",
        .{},
    );
    if (!document.eqlString(root.get("hyperVGeneration"), "V2")) return context.fail(
        "managed disk is not Gen2",
        .{},
    );
    const supported = document.objectOf(root.get("supportedCapabilities"));
    const architecture = if (supported) |present|
        present.get("architecture")
    else
        null;
    if (supported == null or
        !document.eqlString(architecture, arguments.expected_architecture))
    {
        return context.fail("managed disk architecture mismatch", .{});
    }
    if (!document.eqlString(root.get("diskState"), "Unattached")) return context.fail(
        "managed disk is not safely detached after upload",
        .{},
    );
    if (!document.eqlString(root.get("provisioningState"), "Succeeded")) {
        return context.fail("managed disk provisioning did not succeed", .{});
    }
    try validateSize(context, value, .{
        .scope = "managed disk expansion",
        .expected_size_gib = try requireSizeGib(context, arguments.expected_size_gib),
        .byte_paths = &disk_byte_paths,
        .gib_paths = &disk_gib_paths,
    });
    writer.print("{s}\n", .{document.stringOf(root.get("id")).?}) catch
        return error.OutOfMemory;
}

// ---- gallery --------------------------------------------------------------

pub const GalleryArguments = struct {
    path: []const u8,
    expected_id: []const u8,
    expected_name: []const u8,
    expected_group: []const u8,
    expected_location: []const u8,
};

pub fn validateGallery(context: *Context, arguments: GalleryArguments) Error!void {
    const value = try loadDocument(context, arguments.path);
    const root = value.object;

    if (!same(root.get("id"), arguments.expected_id)) return context.fail(
        "Azure returned a different gallery identity",
        .{},
    );
    if (!document.eqlString(root.get("name"), arguments.expected_name)) {
        return context.fail("Azure returned a different gallery name", .{});
    }
    const resource_group = root.get("resourceGroup");
    if (!document.isAbsentOrEmpty(resource_group) and
        !same(resource_group, arguments.expected_group))
    {
        return context.fail("gallery is outside the owned temporary resource group", .{});
    }
    if (!same(root.get("location"), arguments.expected_location)) return context.fail(
        "gallery location mismatch",
        .{},
    );
    if (!same(root.get("type"), "Microsoft.Compute/galleries")) return context.fail(
        "Azure returned a non-gallery resource",
        .{},
    );
    if (!document.eqlString(root.get("provisioningState"), "Succeeded")) {
        return context.fail("temporary gallery provisioning did not succeed", .{});
    }

    const sharing_value = root.get("sharingProfile");
    if (sharing_value == null or sharing_value.? == .null) return;
    const sharing = document.objectOf(sharing_value) orelse return context.fail(
        "temporary gallery sharing metadata is invalid",
        .{},
    );
    const permissions = sharing.get("permissions");
    if (permissions != null and permissions.? != .null and
        !same(permissions, "Private"))
    {
        return context.fail("temporary gallery is not private", .{});
    }
    for ([_][]const u8{ "groups", "communityGalleryInfo" }) |field| {
        if (!isEmptyExposure(sharing.get(field))) return context.fail(
            "temporary gallery exposes shared metadata",
            .{},
        );
    }
}

/// `value not in (None, "", [], {})`, inverted.
fn isEmptyExposure(value: ?Value) bool {
    const present = value orelse return true;
    return switch (present) {
        .null => true,
        .string => |text| text.len == 0,
        .array => |items| items.items.len == 0,
        .object => |map| map.count() == 0,
        else => false,
    };
}

// ---- gallery-image-definition ---------------------------------------------

pub const GalleryImageDefinitionArguments = struct {
    path: []const u8,
    expected_id: []const u8,
    expected_name: []const u8,
    expected_group: []const u8,
    expected_location: []const u8,
    expected_architecture: []const u8,
    expected_publisher: []const u8,
    expected_offer: []const u8,
    expected_sku: []const u8,
};

pub fn validateGalleryImageDefinition(
    context: *Context,
    arguments: GalleryImageDefinitionArguments,
) Error!void {
    const value = try loadDocument(context, arguments.path);
    const root = value.object;

    if (!same(root.get("id"), arguments.expected_id)) return context.fail(
        "Azure returned a different gallery image-definition identity",
        .{},
    );
    if (!document.eqlString(root.get("name"), arguments.expected_name)) {
        return context.fail(
            "Azure returned a different gallery image-definition name",
            .{},
        );
    }
    const resource_group = root.get("resourceGroup");
    if (!document.isAbsentOrEmpty(resource_group) and
        !same(resource_group, arguments.expected_group))
    {
        return context.fail(
            "image definition is outside the owned temporary resource group",
            .{},
        );
    }
    if (!same(root.get("location"), arguments.expected_location)) return context.fail(
        "gallery image-definition location mismatch",
        .{},
    );
    if (!same(root.get("type"), "Microsoft.Compute/galleries/images")) {
        return context.fail(
            "Azure returned a non-gallery-image-definition resource",
            .{},
        );
    }
    if (!document.eqlString(root.get("provisioningState"), "Succeeded")) {
        return context.fail(
            "gallery image-definition provisioning did not succeed",
            .{},
        );
    }
    if (!document.eqlString(root.get("architecture"), arguments.expected_architecture)) {
        return context.fail("gallery image-definition architecture mismatch", .{});
    }
    if (!document.eqlString(root.get("hyperVGeneration"), "V2")) return context.fail(
        "gallery image definition is not Gen2",
        .{},
    );
    if (!document.eqlString(root.get("osType"), "Linux")) return context.fail(
        "gallery image-definition OS type mismatch",
        .{},
    );
    if (!document.eqlString(root.get("osState"), "Generalized")) return context.fail(
        "gallery image definition is not generalized",
        .{},
    );
    const identifier = document.objectOf(root.get("identifier")) orelse
        return context.fail("gallery image-definition identifier mismatch", .{});
    if (identifier.count() != 3 or
        !document.eqlString(identifier.get("publisher"), arguments.expected_publisher) or
        !document.eqlString(identifier.get("offer"), arguments.expected_offer) or
        !document.eqlString(identifier.get("sku"), arguments.expected_sku))
    {
        return context.fail("gallery image-definition identifier mismatch", .{});
    }
}

// ---- gallery-image-version ------------------------------------------------

pub const GalleryImageVersionArguments = struct {
    path: []const u8,
    expected_id: []const u8,
    expected_name: []const u8,
    expected_group: []const u8,
    expected_location: []const u8,
    expected_location_display_name: []const u8,
    expected_disk_id: []const u8,
    expected_size_gib: []const u8,
};

pub fn validateGalleryImageVersion(
    context: *Context,
    arguments: GalleryImageVersionArguments,
) Error!void {
    const value = try loadDocument(context, arguments.path);
    const root = value.object;

    if (!same(root.get("id"), arguments.expected_id)) return context.fail(
        "Azure returned a different gallery image-version identity",
        .{},
    );
    if (!document.eqlString(root.get("name"), arguments.expected_name)) {
        return context.fail(
            "Azure returned a different gallery image-version name",
            .{},
        );
    }
    const resource_group = root.get("resourceGroup");
    if (!document.isAbsentOrEmpty(resource_group) and
        !same(resource_group, arguments.expected_group))
    {
        return context.fail(
            "image version is outside the owned temporary resource group",
            .{},
        );
    }
    if (!same(root.get("location"), arguments.expected_location)) return context.fail(
        "gallery image-version location mismatch",
        .{},
    );
    if (!same(root.get("type"), "Microsoft.Compute/galleries/images/versions")) {
        return context.fail(
            "Azure returned a non-gallery-image-version resource",
            .{},
        );
    }
    if (!document.eqlString(root.get("provisioningState"), "Succeeded")) {
        return context.fail(
            "gallery image-version provisioning did not succeed",
            .{},
        );
    }

    const storage_value = root.get("storageProfile");
    const storage = document.objectOf(storage_value) orelse return context.fail(
        "gallery image-version storage profile is missing",
        .{},
    );
    const os_disk_value = storage.get("osDiskImage");
    const os_disk = document.objectOf(os_disk_value) orelse return context.fail(
        "gallery image-version OS disk metadata is missing",
        .{},
    );

    var source_ids: std.json.ObjectMap = .empty;
    const candidates = [_]struct { path: []const u8, source: ?Value }{
        .{
            .path = "storageProfile.osDiskImage.source",
            .source = os_disk.get("source"),
        },
        .{ .path = "storageProfile.source", .source = storage.get("source") },
    };
    for (candidates) |entry| {
        const source_value = entry.source orelse continue;
        if (source_value == .null) continue;
        const source = document.objectOf(source_value) orelse return context.fail(
            "gallery image-version source metadata is invalid at {s}",
            .{entry.path},
        );
        const source_id = source.get("id");
        if (document.isAbsentOrEmpty(source_id)) continue;
        const key = try std.fmt.allocPrint(context.arena, "{s}.id", .{entry.path});
        try source_ids.put(context.arena, key, source_id.?);
        if (!same(source_id, arguments.expected_disk_id)) {
            var out: Writer.Allocating = .init(context.arena);
            try writeSpacedJson(context.gpa, &out.writer, .{ .object = source_ids });
            return context.fail(
                "gallery image version is not sourced from the exact managed " ++
                    "disk: expected '{s}'; observed {s}",
                .{ arguments.expected_disk_id, out.written() },
            );
        }
    }
    if (source_ids.count() == 0) {
        var storage_keys: Writer.Allocating = .init(context.arena);
        try writeSortedKeys(context, &storage_keys.writer, storage_value.?);
        var os_disk_keys: Writer.Allocating = .init(context.arena);
        try writeSortedKeys(context, &os_disk_keys.writer, os_disk_value.?);
        return context.fail(
            "gallery image version does not expose the exact managed disk " ++
                "source: expected '{s}'; storageProfile keys {s}; " ++
                "osDiskImage keys {s}",
            .{
                arguments.expected_disk_id,
                storage_keys.written(),
                os_disk_keys.written(),
            },
        );
    }

    try validateSize(context, os_disk_value.?, .{
        .scope = "gallery image-version OS disk",
        .expected_size_gib = try requireSizeGib(context, arguments.expected_size_gib),
        .byte_paths = &disk_byte_paths,
        .gib_paths = &disk_gib_paths,
        .allow_missing = true,
    });
    const data_disks = storage.get("dataDiskImages");
    if (!(data_disks == null or data_disks.? == .null or
        (data_disks.? == .array and data_disks.?.array.items.len == 0)))
    {
        return context.fail(
            "gallery image version unexpectedly contains data disks",
            .{},
        );
    }

    const publishing = document.objectOf(root.get("publishingProfile")) orelse
        return context.fail(
            "gallery image-version publishing profile is missing",
            .{},
        );
    if (!document.eqlString(publishing.get("replicationMode"), "Shallow")) {
        return context.fail("gallery image-version replication mode mismatch", .{});
    }
    const target_regions = document.arrayOf(publishing.get("targetRegions")) orelse
        return context.fail(
            "gallery image-version target region is missing or ambiguous",
            .{},
        );
    if (target_regions.items.len != 1) return context.fail(
        "gallery image-version target region is missing or ambiguous",
        .{},
    );
    const target = document.objectOf(target_regions.items[0]) orelse
        return context.fail("gallery image-version target location mismatch", .{});
    if (!same(target.get("name"), arguments.expected_location) and
        !same(target.get("name"), arguments.expected_location_display_name))
    {
        return context.fail("gallery image-version target location mismatch", .{});
    }
    const replica_count = target.get("regionalReplicaCount");
    if (!(replica_count == null or replica_count.? == .null or
        document.integerOf(replica_count) == 1))
    {
        return context.fail("gallery image-version replica count mismatch", .{});
    }
    const storage_account = target.get("storageAccountType");
    if (!(storage_account == null or storage_account.? == .null or
        document.eqlString(storage_account, "Standard_LRS")))
    {
        return context.fail(
            "gallery image-version storage account type mismatch",
            .{},
        );
    }
}

// ---- vm -------------------------------------------------------------------

pub const VmArguments = struct {
    path: []const u8,
    expected_id: []const u8,
    expected_name: []const u8,
    expected_group: []const u8,
    expected_location: []const u8,
    expected_size: []const u8,
    expected_image_version_id: []const u8,
    expected_admin: []const u8,
    expected_architecture: []const u8,
    expected_size_gib: []const u8,
};

const vm_byte_paths = [_][]const u8{
    "diskSizeBytes",
    "sizeInBytes",
    "managedDisk.diskSizeBytes",
    "managedDisk.sizeInBytes",
};
const vm_gib_paths = [_][]const u8{
    "diskSizeGb",
    "diskSizeGB",
    "sizeInGB",
    "sizeInGb",
    "managedDisk.diskSizeGb",
    "managedDisk.diskSizeGB",
    "managedDisk.sizeInGB",
    "managedDisk.sizeInGb",
};

pub fn validateVm(
    context: *Context,
    arguments: VmArguments,
    writer: *Writer,
) Error!void {
    const value = try loadDocument(context, arguments.path);
    const root = value.object;

    if (!same(root.get("id"), arguments.expected_id)) return context.fail(
        "Azure returned a different VM identity",
        .{},
    );
    if (!document.eqlString(root.get("name"), arguments.expected_name)) {
        return context.fail("Azure returned a different VM name", .{});
    }
    const resource_group = root.get("resourceGroup");
    if (!document.isAbsentOrEmpty(resource_group) and
        !same(resource_group, arguments.expected_group))
    {
        return context.fail("VM is outside the owned temporary resource group", .{});
    }
    if (!same(root.get("location"), arguments.expected_location)) return context.fail(
        "VM location mismatch",
        .{},
    );
    if (!same(root.get("type"), "Microsoft.Compute/virtualMachines")) {
        return context.fail("Azure returned a non-VM resource", .{});
    }
    if (!document.eqlString(root.get("provisioningState"), "Succeeded")) {
        return context.fail("VM provisioning did not succeed", .{});
    }
    if (!isUuid(document.stringOf(root.get("vmId")) orelse "")) return context.fail(
        "Azure returned an invalid VM instance identity",
        .{},
    );

    const hardware_value = root.get("hardwareProfile");
    const hardware = document.objectOf(hardware_value);
    if (hardware == null or
        !document.eqlString(hardware.?.get("vmSize"), arguments.expected_size))
    {
        return context.fail("VM size mismatch", .{});
    }
    const storage = document.objectOf(root.get("storageProfile")) orelse
        return context.fail("VM storage profile is missing", .{});
    const image_reference = document.objectOf(storage.get("imageReference"));
    if (image_reference == null or
        !same(image_reference.?.get("id"), arguments.expected_image_version_id))
    {
        return context.fail("VM is not bound to the exact gallery image version", .{});
    }
    const os_disk_value = storage.get("osDisk");
    const os_disk = document.objectOf(os_disk_value) orelse return context.fail(
        "VM OS disk metadata is missing",
        .{},
    );
    if (!document.eqlString(os_disk.get("osType"), "Linux") or
        !document.eqlString(os_disk.get("createOption"), "FromImage"))
    {
        return context.fail("VM OS disk was not created as Linux from the image", .{});
    }
    try validateSize(context, os_disk_value.?, .{
        .scope = "VM OS disk",
        .expected_size_gib = try requireSizeGib(context, arguments.expected_size_gib),
        .byte_paths = &vm_byte_paths,
        .gib_paths = &vm_gib_paths,
    });

    const managed_disk = document.objectOf(os_disk.get("managedDisk"));
    const vm_os_disk_id = if (managed_disk) |present|
        document.stringOf(present.get("id"))
    else
        null;
    const disk_prefix = try providerPrefix(
        context,
        arguments.expected_id,
        "Microsoft.Compute/disks/",
    );
    if (vm_os_disk_id == null or
        !startsWithIgnoreCase(vm_os_disk_id.?, disk_prefix))
    {
        return context.fail(
            "VM OS disk is outside the owned temporary resource group",
            .{},
        );
    }

    const os_profile = document.objectOf(root.get("osProfile"));
    if (os_profile == null or
        !document.eqlString(os_profile.?.get("adminUsername"), arguments.expected_admin))
    {
        return context.fail("VM administrator identity mismatch", .{});
    }
    const linux = document.objectOf(os_profile.?.get("linuxConfiguration")) orelse
        return context.fail("VM Linux provisioning policy is missing", .{});
    if (!isExactlyTrue(linux.get("disablePasswordAuthentication"))) return context.fail(
        "VM does not require key-only authentication",
        .{},
    );
    if (!isExactlyFalse(linux.get("provisionVMAgent"))) return context.fail(
        "VM agent policy mismatch",
        .{},
    );

    const security = document.objectOf(root.get("securityProfile"));
    const security_type = if (security) |present|
        present.get("securityType")
    else
        null;
    if (!(security_type == null or security_type.? == .null or
        document.eqlString(security_type, "Standard")))
    {
        return context.fail("VM security type mismatch", .{});
    }
    const diagnostics = document.objectOf(root.get("diagnosticsProfile"));
    const boot = if (diagnostics) |present|
        document.objectOf(present.get("bootDiagnostics"))
    else
        null;
    const enabled = if (boot) |present| present.get("enabled") else null;
    const storage_uri = if (boot) |present| present.get("storageUri") else null;
    if (!isExactlyTrue(enabled) or !(storage_uri == null or storage_uri.? == .null)) {
        return context.fail("VM managed boot diagnostics policy mismatch", .{});
    }
    const network = document.objectOf(root.get("networkProfile"));
    const interfaces = if (network) |present|
        document.arrayOf(present.get("networkInterfaces"))
    else
        null;
    if (interfaces == null or interfaces.?.items.len != 1) return context.fail(
        "VM network interface metadata is missing or ambiguous",
        .{},
    );
    const nic_prefix = try providerPrefix(
        context,
        arguments.expected_id,
        "Microsoft.Network/networkInterfaces/",
    );
    const nic = document.objectOf(interfaces.?.items[0]);
    const nic_id = if (nic) |present|
        document.stringOf(present.get("id")) orelse ""
    else
        "";
    if (nic_id.len < nic_prefix.len or
        !std.ascii.eqlIgnoreCase(nic_id[0..nic_prefix.len], nic_prefix))
    {
        return context.fail(
            "VM network interface is outside the owned temporary resource group",
            .{},
        );
    }

    for ([_]?std.json.ObjectMap{ root, hardware, os_disk }) |owner| {
        const present = owner orelse continue;
        const architecture = present.get("architecture");
        if (document.isAbsentOrEmpty(architecture)) continue;
        if (!document.eqlString(architecture, arguments.expected_architecture)) {
            return context.fail("VM architecture mismatch", .{});
        }
    }
    writer.print("{s}\n", .{document.stringOf(root.get("id")).?}) catch
        return error.OutOfMemory;
}

fn isExactlyTrue(value: ?Value) bool {
    const present = value orelse return false;
    return present == .bool and present.bool;
}

fn isExactlyFalse(value: ?Value) bool {
    const present = value orelse return false;
    return present == .bool and !present.bool;
}

fn startsWithIgnoreCase(text: []const u8, prefix: []const u8) bool {
    if (text.len < prefix.len) return false;
    return std.ascii.eqlIgnoreCase(text[0..prefix.len], prefix);
}

/// `expected_id.rsplit("/providers/", 1)[0] + "/providers/" + provider`.
fn providerPrefix(
    context: *Context,
    expected_id: []const u8,
    provider: []const u8,
) Error![]const u8 {
    const scope = if (std.mem.lastIndexOf(u8, expected_id, "/providers/")) |at|
        expected_id[0..at]
    else
        expected_id;
    return std.fmt.allocPrint(context.arena, "{s}/providers/{s}", .{ scope, provider });
}

pub fn isUuid(text: []const u8) bool {
    if (text.len != 36) return false;
    const groups = [_]usize{ 8, 4, 4, 4, 12 };
    var index: usize = 0;
    for (groups, 0..) |length, group| {
        if (group > 0) {
            if (text[index] != '-') return false;
            index += 1;
        }
        for (0..length) |_| {
            if (index >= text.len or !std.ascii.isHex(text[index])) return false;
            index += 1;
        }
    }
    return index == text.len;
}

// ---- Harness helpers ------------------------------------------------------

/// The resource-group ownership tags the cleanup path refuses to act without.
pub fn validateGroupTags(
    context: *Context,
    path: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    candidate_key: []const u8,
) Error!void {
    const value = try loadDocument(context, path);
    const tags_value = value.object.get("tags");
    const tags = if (tags_value == null or tags_value.? == .null)
        std.json.ObjectMap.empty
    else
        document.objectOf(tags_value) orelse std.json.ObjectMap.empty;

    const expected = [_][2][]const u8{
        .{ "miz-owner", "freebsd15-release" },
        .{ "miz-run-id", run_id },
        .{ "miz-run-attempt", run_attempt },
        .{ "miz-candidate", candidate_key },
    };
    var matches = tags.count() == expected.len;
    if (matches) {
        for (expected) |pair| {
            if (!document.eqlString(tags.get(pair[0]), pair[1])) matches = false;
        }
    }
    if (!matches) {
        var out: Writer.Allocating = .init(context.arena);
        try writeSpacedJson(context.gpa, &out.writer, .{ .object = tags });
        return context.fail(
            "refusing to delete resource group with non-exact ownership tags: {s}",
            .{out.written()},
        );
    }
}

/// The write SAS the disk-access grant returns, under either spelling.
pub fn diskAccessSas(
    context: *Context,
    path: []const u8,
    writer: *Writer,
) Error!void {
    const value = try loadDocument(context, path);
    const root = value.object;
    const sas = document.stringOf(root.get("accessSAS")) orelse
        document.stringOf(root.get("accessSas")) orelse "";
    writer.print("{s}\n", .{sas}) catch return error.OutOfMemory;
}

/// The one exact canonical Azure location match and its display name.
pub fn locationDisplayName(
    context: *Context,
    path: []const u8,
    expected: []const u8,
    writer: *Writer,
) Error!void {
    const bytes = file_support.readBounded(
        context.arena,
        context.io,
        path,
        max_document_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ path, err }),
    };
    const parsed = std.json.parseFromSlice(
        Value,
        context.arena,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ path, err }),
    };
    const locations = document.arrayOf(parsed.value) orelse return context.fail(
        "Azure location metadata is not a list",
        .{},
    );
    var matches: usize = 0;
    var display_name: ?[]const u8 = null;
    for (locations.items) |item| {
        const location = document.objectOf(item) orelse continue;
        const name = document.stringOf(location.get("name")) orelse continue;
        if (!std.ascii.eqlIgnoreCase(name, expected)) continue;
        matches += 1;
        display_name = document.stringOf(location.get("displayName"));
    }
    if (matches != 1) return context.fail(
        "Azure location metadata contains {d} exact canonical matches for '{s}'",
        .{ matches, expected },
    );
    const resolved = display_name orelse return context.fail(
        "Azure location '{s}' has no display name",
        .{expected},
    );
    if (resolved.len == 0) return context.fail(
        "Azure location '{s}' has no display name",
        .{expected},
    );
    writer.print("{s}\n", .{resolved}) catch return error.OutOfMemory;
}

/// The configured VM SKU exists exactly once, is unrestricted here, and offers
/// the matching architecture and Gen2.
pub fn validateVmSku(
    context: *Context,
    path: []const u8,
    vm_size: []const u8,
    expected_architecture: []const u8,
) Error!void {
    const bytes = file_support.readBounded(
        context.arena,
        context.io,
        path,
        max_document_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ path, err }),
    };
    const parsed = std.json.parseFromSlice(
        Value,
        context.arena,
        bytes,
        .{},
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ path, err }),
    };
    const items = document.arrayOf(parsed.value) orelse return context.fail(
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        .{},
    );
    var matched: ?std.json.ObjectMap = null;
    var matches: usize = 0;
    for (items.items) |item| {
        const sku = document.objectOf(item) orelse continue;
        if (!document.eqlString(sku.get("name"), vm_size)) continue;
        matches += 1;
        matched = sku;
    }
    if (matches != 1) return context.fail(
        "configured Azure VM SKU is absent or ambiguous in the configured location",
        .{},
    );
    const sku = matched.?;
    if (document.arrayOf(sku.get("restrictions"))) |restrictions| {
        for (restrictions.items) |item| {
            const restriction = document.objectOf(item) orelse continue;
            if (document.eqlString(restriction.get("type"), "Location")) {
                return context.fail(
                    "configured Azure VM SKU is location-restricted",
                    .{},
                );
            }
        }
    }
    var architecture: ?[]const u8 = null;
    var generations: []const u8 = "";
    if (document.arrayOf(sku.get("capabilities"))) |capabilities| {
        for (capabilities.items) |item| {
            const capability = document.objectOf(item) orelse continue;
            const name = document.stringOf(capability.get("name")) orelse continue;
            const raw = document.stringOf(capability.get("value")) orelse continue;
            if (std.mem.eql(u8, name, "CpuArchitectureType")) architecture = raw;
            if (std.mem.eql(u8, name, "HyperVGenerations")) generations = raw;
        }
    }
    if (architecture == null or
        !std.mem.eql(u8, architecture.?, expected_architecture))
    {
        return context.fail(
            "SKU architecture mismatch: '{s}'",
            .{architecture orelse "None"},
        );
    }
    var supports_gen2 = false;
    var generation_parts = std.mem.splitScalar(u8, generations, ',');
    while (generation_parts.next()) |generation| {
        if (std.mem.eql(u8, generation, "V2")) supports_gen2 = true;
    }
    if (!supports_gen2) return context.fail(
        "configured Azure VM SKU does not support Gen2",
        .{},
    );
}

/// One managed boot diagnostics observation: `ready`, or a `pending:` reason
/// the caller retries on. Anything else is a failure, not a retry.
pub fn bootDiagnosticsObservation(
    context: *Context,
    path: []const u8,
    writer: *Writer,
) Error!void {
    const value = try loadDocument(context, path);
    const root = value.object;
    const profile = root.get("diagnosticsProfile");
    if (profile == null or profile.? == .null) {
        writer.writeAll("pending: diagnosticsProfile is absent or null\n") catch
            return error.OutOfMemory;
        return;
    }
    const diagnostics = document.objectOf(profile) orelse return context.fail(
        "VM diagnosticsProfile is not an object",
        .{},
    );
    const boot_value = diagnostics.get("bootDiagnostics");
    if (boot_value == null or boot_value.? == .null) {
        writer.writeAll("pending: bootDiagnostics is absent or null\n") catch
            return error.OutOfMemory;
        return;
    }
    const boot = document.objectOf(boot_value) orelse return context.fail(
        "VM bootDiagnostics is not an object",
        .{},
    );
    const storage_uri = boot.get("storageUri");
    if (!(storage_uri == null or storage_uri.? == .null)) {
        var out: Writer.Allocating = .init(context.arena);
        try writeSpacedJson(context.gpa, &out.writer, storage_uri.?);
        return context.fail(
            "managed boot diagnostics storageUri must be absent or null, not {s}",
            .{out.written()},
        );
    }
    const enabled = boot.get("enabled");
    if (isExactlyTrue(enabled)) {
        writer.writeAll("ready\n") catch return error.OutOfMemory;
        return;
    }
    if (enabled == null or enabled.? == .null) {
        writer.writeAll("pending: bootDiagnostics.enabled is None\n") catch
            return error.OutOfMemory;
        return;
    }
    if (isExactlyFalse(enabled)) {
        writer.writeAll("pending: bootDiagnostics.enabled is False\n") catch
            return error.OutOfMemory;
        return;
    }
    var out: Writer.Allocating = .init(context.arena);
    try writeSpacedJson(context.gpa, &out.writer, enabled.?);
    return context.fail(
        "VM bootDiagnostics.enabled has invalid value {s}",
        .{out.written()},
    );
}

/// The unit separator the harness reads the replication observation back with.
pub const replication_separator = "\x1f";

/// The target region's replication state, aggregate state, and the opaque
/// progress and detail values, for one exact region.
pub fn replicationObservation(
    context: *Context,
    path: []const u8,
    expected_region: []const u8,
    expected_region_display_name: []const u8,
    writer: *Writer,
) Error!void {
    const value = try loadDocument(context, path);
    const replication = document.objectOf(value.object.get("replicationStatus")) orelse
        return context.fail("image version replicationStatus is missing", .{});
    const summary = document.arrayOf(replication.get("summary")) orelse
        return context.fail(
            "image version regional replication summary is missing",
            .{},
        );

    var matches: usize = 0;
    var target: ?std.json.ObjectMap = null;
    var reported: std.ArrayList([]const u8) = .empty;
    for (summary.items) |item| {
        const entry = document.objectOf(item) orelse continue;
        const region = document.stringOf(entry.get("region")) orelse continue;
        try reported.append(context.arena, region);
        if (!std.ascii.eqlIgnoreCase(region, expected_region) and
            !std.ascii.eqlIgnoreCase(region, expected_region_display_name)) continue;
        matches += 1;
        target = entry;
    }
    if (matches == 0) {
        var out: Writer.Allocating = .init(context.arena);
        out.writer.writeByte('[') catch return error.OutOfMemory;
        for (reported.items, 0..) |region, index| {
            if (index > 0) out.writer.writeAll(", ") catch return error.OutOfMemory;
            out.writer.print("'{s}'", .{region}) catch return error.OutOfMemory;
        }
        out.writer.writeByte(']') catch return error.OutOfMemory;
        return context.fail(
            "replication status does not include target region '{s}'; " ++
                "reported regions: {s}",
            .{ expected_region, out.written() },
        );
    }
    if (matches != 1) return context.fail(
        "replication status includes target region '{s}' {d} times",
        .{ expected_region, matches },
    );

    const entry = target.?;
    const state = document.stringOf(entry.get("state")) orelse return context.fail(
        "target region replication state is missing",
        .{},
    );
    if (state.len == 0) return context.fail(
        "target region replication state is missing",
        .{},
    );
    const aggregate_value = replication.get("aggregatedState");
    var aggregate: []const u8 = "";
    if (aggregate_value) |present| {
        if (present != .null) {
            aggregate = document.stringOf(present) orelse return context.fail(
                "aggregated replication state is invalid",
                .{},
            );
        }
    }
    const progress = try compactJson(context, entry.get("progress") orelse .{ .null = {} });
    const details = try compactJson(context, entry.get("details") orelse .{ .null = {} });
    writer.print("{s}" ++ replication_separator ++ "{s}" ++ replication_separator ++
        "{s}" ++ replication_separator ++ "{s}\n", .{
        state,
        aggregate,
        progress,
        details,
    }) catch return error.OutOfMemory;
}

// ---- Serial console normalization -----------------------------------------

/// What one serial console response turned out to be. The numeric values are
/// the exit codes `require_serial_console_log` dispatches on.
pub const SerialConsoleResult = enum(u8) {
    content = 0,
    blob_not_found = 10,
    empty = 11,
    structured_error = 12,
};

/// `normalize_serial_console_response`: unwrap the JSON string Azure sometimes
/// wraps a boot log in, classify the structured errors it returns instead of
/// one, and write only real serial content to `output_path`.
pub fn normalizeSerialConsole(
    context: *Context,
    raw_path: []const u8,
    output_path: []const u8,
) Error!SerialConsoleResult {
    const raw = file_support.readBounded(
        context.arena,
        context.io,
        raw_path,
        max_serial_console_bytes,
    ) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return context.fail("cannot read {s}: {t}", .{ raw_path, err }),
    };
    Dir.cwd().deleteFile(context.io, output_path) catch {};

    var candidate: []const u8 = raw;
    if (std.unicode.utf8ValidateSlice(raw)) {
        if (std.json.parseFromSlice(Value, context.arena, raw, .{})) |parsed| {
            switch (parsed.value) {
                .string => |text| candidate = text,
                else => return .structured_error,
            }
        } else |_| {}
    }

    if (document.trim(candidate).len == 0) return .empty;

    const stripped = std.mem.trimStart(u8, candidate, document.ascii_whitespace);
    if (stripped.len > 0 and stripped[0] == '<') {
        switch (classifyXml(stripped)) {
            .not_error => {},
            .blob_not_found => return .blob_not_found,
            .other_error => return .structured_error,
            .unparsed => {
                if (std.mem.startsWith(u8, stripped, "<?xml") or
                    std.mem.startsWith(u8, stripped, "<Error") or
                    std.mem.startsWith(u8, stripped, "<error")) return .structured_error;
            },
        }
    }

    file_support.writeAtomic(context.io, output_path, candidate) catch |err|
        return context.fail("cannot write {s}: {t}", .{ output_path, err });
    return .content;
}

const XmlClass = enum { not_error, blob_not_found, other_error, unparsed };

/// Enough XML to answer the one question the harness asks of it: is this an
/// Azure `<Error>` document, and if so does it carry `BlobNotFound`?
fn classifyXml(text: []const u8) XmlClass {
    var rest = text;
    while (true) {
        rest = std.mem.trimStart(u8, rest, document.ascii_whitespace);
        if (std.mem.startsWith(u8, rest, "<?")) {
            const close = std.mem.indexOf(u8, rest, "?>") orelse return .unparsed;
            rest = rest[close + 2 ..];
            continue;
        }
        if (std.mem.startsWith(u8, rest, "<!--")) {
            const close = std.mem.indexOf(u8, rest, "-->") orelse return .unparsed;
            rest = rest[close + 3 ..];
            continue;
        }
        if (std.mem.startsWith(u8, rest, "<!")) {
            const close = std.mem.indexOfScalar(u8, rest, '>') orelse return .unparsed;
            rest = rest[close + 1 ..];
            continue;
        }
        break;
    }
    if (rest.len == 0 or rest[0] != '<') return .unparsed;
    const root_end = std.mem.indexOfScalar(u8, rest, '>') orelse return .unparsed;
    const root_tag = localName(rest[1..root_end]);
    if (!std.ascii.eqlIgnoreCase(root_tag, "error")) return .not_error;

    var body = rest[root_end + 1 ..];
    while (std.mem.indexOfScalar(u8, body, '<')) |open| {
        body = body[open..];
        if (std.mem.startsWith(u8, body, "</")) break;
        const name_end = std.mem.indexOfScalar(u8, body, '>') orelse return .unparsed;
        const child = localName(body[1..name_end]);
        const child_body = body[name_end + 1 ..];
        const close = std.mem.indexOfScalar(u8, child_body, '<') orelse
            return .other_error;
        if (std.ascii.eqlIgnoreCase(child, "code")) {
            const code = document.trim(child_body[0..close]);
            if (std.ascii.eqlIgnoreCase(code, "blobnotfound")) return .blob_not_found;
            return .other_error;
        }
        body = child_body[close..];
        const child_close = std.mem.indexOfScalar(u8, body, '>') orelse return .unparsed;
        body = body[child_close + 1 ..];
    }
    return .other_error;
}

/// `tag.rsplit("}", 1)[-1]` after the element's attributes are dropped: the
/// local name of a possibly namespaced tag, in either the resolved `{uri}name`
/// spelling ElementTree produces or the `prefix:name` spelling on the wire.
fn localName(start_tag: []const u8) []const u8 {
    const trimmed = std.mem.trimEnd(u8, start_tag, "/ \t\r\n");
    const name_end = std.mem.indexOfAny(u8, trimmed, " \t\r\n") orelse trimmed.len;
    var name = trimmed[0..name_end];
    if (std.mem.lastIndexOfScalar(u8, name, '}')) |at| name = name[at + 1 ..];
    if (std.mem.lastIndexOfScalar(u8, name, ':')) |at| name = name[at + 1 ..];
    return name;
}

test "dotted paths distinguish absent from null" {
    var parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        \\{"a": {"b": {"c": 1}, "d": null}}
    ,
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqual(@as(i64, 1), valueAt(parsed.value, "a.b.c").?.integer);
    try std.testing.expect(valueAt(parsed.value, "a.d").? == .null);
    try std.testing.expectEqual(@as(?Value, null), valueAt(parsed.value, "a.b.z"));
    try std.testing.expectEqual(@as(?Value, null), valueAt(parsed.value, "a.b.c.d"));
}

test "spaced JSON matches json.dumps with sorted keys" {
    var parsed = try std.json.parseFromSlice(
        Value,
        std.testing.allocator,
        \\{"diskSizeGb": 8, "diskSizeBytes": 9663676416, "nested": {"b": [1, 2]}}
    ,
        .{},
    );
    defer parsed.deinit();
    var out: std.Io.Writer.Allocating = .init(std.testing.allocator);
    defer out.deinit();
    try writeSpacedJson(std.testing.allocator, &out.writer, parsed.value);
    try std.testing.expectEqualStrings(
        \\{"diskSizeBytes": 9663676416, "diskSizeGb": 8, "nested": {"b": [1, 2]}}
    ,
        out.written(),
    );
}

test "UUIDs are accepted only in the canonical grouping" {
    try std.testing.expect(isUuid("12345678-1234-1234-1234-123456789abc"));
    try std.testing.expect(isUuid("ABCDEF01-2345-6789-ABCD-EF0123456789"));
    try std.testing.expect(!isUuid("12345678-1234-1234-1234-123456789ab"));
    try std.testing.expect(!isUuid("12345678123412341234123456789abc"));
    try std.testing.expect(!isUuid(""));
    try std.testing.expect(!isUuid("12345678-1234-1234-1234-123456789abg"));
}

test "XML classification finds the Azure blob error and nothing else" {
    try std.testing.expectEqual(XmlClass.blob_not_found, classifyXml(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?>" ++
            "<Error><Code>BlobNotFound</Code>" ++
            "<Message>The specified blob does not exist.</Message></Error>",
    ));
    try std.testing.expectEqual(XmlClass.blob_not_found, classifyXml(
        "<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>BlobNotFound</Code></Error>",
    ));
    try std.testing.expectEqual(XmlClass.other_error, classifyXml(
        "<Error><Code>ServerBusy</Code></Error>",
    ));
    try std.testing.expectEqual(XmlClass.other_error, classifyXml(
        "<Error><Message>no code</Message></Error>",
    ));
    try std.testing.expectEqual(XmlClass.not_error, classifyXml(
        "<html><body>hello</body></html>",
    ));
    try std.testing.expectEqual(XmlClass.blob_not_found, classifyXml(
        "<x:Error xmlns:x=\"urn:test\"><x:Code> BlobNotFound </x:Code></x:Error>",
    ));
    try std.testing.expectEqual(XmlClass.unparsed, classifyXml("<Error"));
}
