//! Target-specific provenance for promoting an accepted Ubuntu 24.04
//! `ConfidentialVMSupported` image through Azure capture to `ConfidentialVM`.

const std = @import("std");
const release = @import("release/root.zig");

const Allocator = std.mem.Allocator;
const Diagnostic = release.contract.Diagnostic;
const ObjectMap = std.json.ObjectMap;
const Value = std.json.Value;

pub const schema: i64 = 1;
pub const result_type = "miz-ubuntu2404-confidential-azure-capture";
pub const source_acceptance_type =
    "miz-ubuntu2404-confidential-azure-acceptance";
pub const repository = "cataggar/miz";

pub const Artifact = struct {
    qcow_sha256: []const u8,
    qcow_size: u64,
    vhd_sha256: []const u8,
    vhd_size: u64,
    virtual_size: u64,
};

pub const SourceExpected = struct {
    commit: []const u8,
    location: []const u8,
    vm_size: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    acceptance_sha256: []const u8,
    artifact: Artifact,
};

pub const Expected = struct {
    source: SourceExpected,
    subscription_id: []const u8,
    location: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    capture_vm_id: []const u8,
    capture_disk_id: []const u8,
    snapshot_id: []const u8,
    image_definition_id: []const u8,
    image_version_id: []const u8,
    final_vm_id: []const u8,
    final_disk_id: []const u8,
};

pub const Documents = struct {
    source_acceptance: *const ObjectMap,
    capture_vm: *const ObjectMap,
    capture_disk: *const ObjectMap,
    snapshot: *const ObjectMap,
    image_definition: *const ObjectMap,
    gallery_request: *const ObjectMap,
    gallery_response: *const ObjectMap,
    final_vm: *const ObjectMap,
};

pub const Attestation = struct {
    vm_id: []const u8,
    issuer: []const u8,
    nonce_sha256: []const u8,
    token_sha256: []const u8,
};

pub const Source = struct {
    gallery_image_version_id: []const u8,
};

fn invalid(
    diagnostic: *Diagnostic,
    comptime message: []const u8,
    args: anytype,
) error{InvalidDocument} {
    return diagnostic.fail(error.InvalidDocument, message, args);
}

fn exact(map: ObjectMap, fields: []const []const u8) bool {
    return release.azure_compute.hasExactFields(map, fields);
}

fn object(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !ObjectMap {
    return release.azure_compute.objectOf(parent.get(name)) orelse
        invalid(diagnostic, "{s} is not an object", .{label});
}

fn string(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) ![]const u8 {
    return release.json_document.requireString(parent, name, label, diagnostic);
}

fn integer(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !i64 {
    return release.json_document.requireInteger(parent, name, label, diagnostic);
}

fn equal(
    actual: []const u8,
    expected: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        return invalid(diagnostic, "{s} mismatch", .{label});
    }
}

fn equalIgnoreCase(
    actual: []const u8,
    expected: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!std.ascii.eqlIgnoreCase(actual, expected)) {
        return invalid(diagnostic, "{s} mismatch", .{label});
    }
}

fn positive(value: i64, label: []const u8, diagnostic: *Diagnostic) !u64 {
    if (value <= 0) return invalid(diagnostic, "{s} is invalid", .{label});
    return @intCast(value);
}

fn validDecimal(text: []const u8) bool {
    if (text.len == 0 or text[0] == '0') return false;
    for (text) |character| if (character < '0' or character > '9') return false;
    return true;
}

fn validCommit(text: []const u8) bool {
    if (text.len != 40) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
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

fn validEndpoint(text: []const u8) bool {
    const prefix = "https://";
    const suffix = ".attest.azure.net";
    if (!std.mem.startsWith(u8, text, prefix) or
        !std.mem.endsWith(u8, text, suffix))
    {
        return false;
    }
    const host = text[prefix.len .. text.len - suffix.len];
    if (host.len == 0) return false;
    for (host) |character| switch (character) {
        'a'...'z', '0'...'9', '-', '.' => {},
        else => return false,
    };
    return true;
}

const ResourceKind = enum {
    virtual_machine,
    disk,
    snapshot,
    image_definition,
    image_version,
};

fn azureResourceId(
    id: []const u8,
    subscription_id: []const u8,
    kind: ResourceKind,
) bool {
    var segments: [16][]const u8 = undefined;
    var count: usize = 0;
    var split = std.mem.splitScalar(u8, id, '/');
    while (split.next()) |segment| {
        if (count == segments.len) return false;
        segments[count] = segment;
        count += 1;
    }
    const nested = kind == .image_definition or kind == .image_version;
    const expected_count: usize = if (kind == .image_version) 13 else if (nested) 11 else 9;
    if (count != expected_count or
        segments[0].len != 0 or
        !std.ascii.eqlIgnoreCase(segments[1], "subscriptions") or
        !std.ascii.eqlIgnoreCase(segments[2], subscription_id) or
        !std.ascii.eqlIgnoreCase(segments[3], "resourceGroups") or
        segments[4].len == 0 or
        !std.ascii.eqlIgnoreCase(segments[5], "providers") or
        !std.ascii.eqlIgnoreCase(segments[6], "Microsoft.Compute"))
    {
        return false;
    }
    const first_type = switch (kind) {
        .virtual_machine => "virtualMachines",
        .disk => "disks",
        .snapshot => "snapshots",
        .image_definition, .image_version => "galleries",
    };
    if (!std.ascii.eqlIgnoreCase(segments[7], first_type) or
        segments[8].len == 0)
    {
        return false;
    }
    if (nested and
        (!std.ascii.eqlIgnoreCase(segments[9], "images") or
            segments[10].len == 0))
    {
        return false;
    }
    return kind != .image_version or
        (std.ascii.eqlIgnoreCase(segments[11], "versions") and
            segments[12].len != 0);
}

pub fn validateSourceVersionId(
    id: []const u8,
    subscription_id: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!azureResourceId(id, subscription_id, .image_version)) {
        return invalid(
            diagnostic,
            "source gallery image-version ID is malformed or cross-subscription",
            .{},
        );
    }
}

fn resourceGroup(id: []const u8) ?[]const u8 {
    var split = std.mem.splitScalar(u8, id, '/');
    if (!std.mem.eql(u8, split.next() orelse return null, "") or
        !std.ascii.eqlIgnoreCase(split.next() orelse return null, "subscriptions"))
    {
        return null;
    }
    _ = split.next() orelse return null;
    if (!std.ascii.eqlIgnoreCase(
        split.next() orelse return null,
        "resourceGroups",
    )) return null;
    const group = split.next() orelse return null;
    return if (group.len == 0) null else group;
}

fn versionBelongsToDefinition(version_id: []const u8, definition_id: []const u8) bool {
    if (version_id.len <= definition_id.len or
        !std.ascii.eqlIgnoreCase(version_id[0..definition_id.len], definition_id))
    {
        return false;
    }
    const suffix = version_id[definition_id.len..];
    if (!std.ascii.startsWithIgnoreCase(suffix, "/versions/")) return false;
    const name = suffix["/versions/".len..];
    return name.len != 0 and std.mem.indexOfScalar(u8, name, '/') == null;
}

fn captureResourceGroup(
    allocator: Allocator,
    run_id: []const u8,
    run_attempt: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "miz-u2404-cvm-capture-{s}-{s}",
        .{ run_id, run_attempt },
    );
}

fn validateExpected(
    allocator: Allocator,
    expected: Expected,
    diagnostic: *Diagnostic,
) !void {
    if (!validCommit(expected.source.commit) or
        !validDecimal(expected.source.run_id) or
        !validDecimal(expected.source.run_attempt) or
        !validDecimal(expected.run_id) or
        !validDecimal(expected.run_attempt))
    {
        return invalid(diagnostic, "capture workflow identity is invalid", .{});
    }
    _ = release.digest.parseHex(expected.source.acceptance_sha256) catch
        return invalid(diagnostic, "source acceptance SHA-256 is invalid", .{});
    _ = release.digest.parseHex(expected.source.artifact.qcow_sha256) catch
        return invalid(diagnostic, "source QCOW2 SHA-256 is invalid", .{});
    _ = release.digest.parseHex(expected.source.artifact.vhd_sha256) catch
        return invalid(diagnostic, "source VHD SHA-256 is invalid", .{});
    if (expected.source.artifact.qcow_size == 0 or
        expected.source.artifact.vhd_size == 0 or
        expected.source.artifact.virtual_size == 0 or
        !std.ascii.eqlIgnoreCase(expected.source.location, expected.location))
    {
        return invalid(diagnostic, "capture source artifact or location is invalid", .{});
    }
    const ids = [_]struct { []const u8, ResourceKind }{
        .{ expected.capture_vm_id, .virtual_machine },
        .{ expected.capture_disk_id, .disk },
        .{ expected.snapshot_id, .snapshot },
        .{ expected.image_definition_id, .image_definition },
        .{ expected.image_version_id, .image_version },
        .{ expected.final_vm_id, .virtual_machine },
        .{ expected.final_disk_id, .disk },
    };
    for (ids) |entry| {
        if (!azureResourceId(entry[0], expected.subscription_id, entry[1])) {
            return invalid(diagnostic, "capture Azure resource ID is malformed", .{});
        }
    }
    if (!versionBelongsToDefinition(
        expected.image_version_id,
        expected.image_definition_id,
    )) return invalid(
        diagnostic,
        "capture gallery version is outside the exact image definition",
        .{},
    );
    const group = try captureResourceGroup(
        allocator,
        expected.run_id,
        expected.run_attempt,
    );
    defer allocator.free(group);
    const ephemeral = [_][]const u8{
        expected.capture_vm_id,
        expected.capture_disk_id,
        expected.snapshot_id,
        expected.final_vm_id,
        expected.final_disk_id,
    };
    for (ephemeral) |id| {
        if (!std.ascii.eqlIgnoreCase(resourceGroup(id) orelse "", group)) {
            return invalid(
                diagnostic,
                "capture resource is outside the workflow-owned resource group",
                .{},
            );
        }
    }
}

pub fn validateSourceAcceptance(
    root: *const ObjectMap,
    expected: Expected,
    diagnostic: *Diagnostic,
) !Source {
    if (!exact(root.*, &.{ "artifact", "attestation", "azure", "schema", "source_commit", "type" }) or
        try integer(root, "schema", "source acceptance schema", diagnostic) != 1)
    {
        return invalid(diagnostic, "source acceptance result shape is invalid", .{});
    }
    try equal(
        try string(root, "type", "source acceptance type", diagnostic),
        source_acceptance_type,
        "source acceptance type",
        diagnostic,
    );
    try equal(
        try string(root, "source_commit", "source acceptance commit", diagnostic),
        expected.source.commit,
        "source acceptance commit",
        diagnostic,
    );
    const artifact = try object(root, "artifact", "source artifact", diagnostic);
    if (!exact(artifact, &.{
        "qcow_sha256",
        "qcow_size",
        "vhd_sha256",
        "vhd_size",
        "virtual_size",
    })) return invalid(diagnostic, "source artifact shape is invalid", .{});
    try equal(
        try string(&artifact, "qcow_sha256", "source QCOW2 SHA-256", diagnostic),
        expected.source.artifact.qcow_sha256,
        "source QCOW2 SHA-256",
        diagnostic,
    );
    try equal(
        try string(&artifact, "vhd_sha256", "source VHD SHA-256", diagnostic),
        expected.source.artifact.vhd_sha256,
        "source VHD SHA-256",
        diagnostic,
    );
    const sizes = [_]struct { []const u8, u64 }{
        .{ "qcow_size", expected.source.artifact.qcow_size },
        .{ "vhd_size", expected.source.artifact.vhd_size },
        .{ "virtual_size", expected.source.artifact.virtual_size },
    };
    for (sizes) |entry| {
        if (try positive(
            try integer(&artifact, entry[0], entry[0], diagnostic),
            entry[0],
            diagnostic,
        ) != entry[1]) return invalid(
            diagnostic,
            "source artifact size mismatch",
            .{},
        );
    }
    const azure = try object(root, "azure", "source Azure evidence", diagnostic);
    if (!exact(azure, &.{
        "gallery_image_version_id",
        "location",
        "managed_disk_id",
        "managed_image_id",
        "resource_group",
        "vm_id",
        "vm_resource_id",
        "vm_size",
    })) return invalid(diagnostic, "source Azure evidence shape is invalid", .{});
    try equal(
        try string(&azure, "location", "source location", diagnostic),
        expected.source.location,
        "source location",
        diagnostic,
    );
    try equal(
        try string(&azure, "vm_size", "source VM size", diagnostic),
        expected.source.vm_size,
        "source VM size",
        diagnostic,
    );
    var group_buffer: [128]u8 = undefined;
    const expected_group = std.fmt.bufPrint(
        &group_buffer,
        "miz-u2404-cvm-{s}-{s}",
        .{ expected.source.run_id, expected.source.run_attempt },
    ) catch return invalid(diagnostic, "source workflow identity is invalid", .{});
    try equal(
        try string(&azure, "resource_group", "source resource group", diagnostic),
        expected_group,
        "source resource group",
        diagnostic,
    );
    const version_id = try string(
        &azure,
        "gallery_image_version_id",
        "source gallery image version",
        diagnostic,
    );
    try validateSourceVersionId(version_id, expected.subscription_id, diagnostic);
    return .{ .gallery_image_version_id = version_id };
}

fn vmUniqueId(vm: *const ObjectMap, diagnostic: *Diagnostic) ![]const u8 {
    const id = try string(vm, "vmId", "Azure VM unique identity", diagnostic);
    if (!validGuid(id)) return invalid(
        diagnostic,
        "Azure VM unique identity is invalid",
        .{},
    );
    return id;
}

fn cloneValue(allocator: Allocator, value: Value) !Value {
    return switch (value) {
        .null, .bool, .integer, .float => value,
        .number_string => |text| .{ .number_string = try allocator.dupe(u8, text) },
        .string => |text| .{ .string = try allocator.dupe(u8, text) },
        .array => |items| blk: {
            var list: std.json.Array = .init(allocator);
            try list.ensureTotalCapacity(items.items.len);
            for (items.items) |item| list.appendAssumeCapacity(
                try cloneValue(allocator, item),
            );
            break :blk .{ .array = list };
        },
        .object => |map| blk: {
            var copy: ObjectMap = .empty;
            var iterator = map.iterator();
            while (iterator.next()) |entry| try copy.put(
                allocator,
                try allocator.dupe(u8, entry.key_ptr.*),
                try cloneValue(allocator, entry.value_ptr.*),
            );
            break :blk .{ .object = copy };
        },
    };
}

fn workflowValue(
    allocator: Allocator,
    run_id: []const u8,
    run_attempt: []const u8,
) !Value {
    return release.azure_compute.object(allocator, &.{
        .{ "repository", release.azure_compute.string(repository) },
        .{ "run_id", release.azure_compute.string(run_id) },
        .{ "run_attempt", release.azure_compute.string(run_attempt) },
    });
}

fn attestationValue(allocator: Allocator, evidence: Attestation) !Value {
    return release.azure_compute.object(allocator, &.{
        .{ "compliance", release.azure_compute.string("azure-compliant-cvm") },
        .{ "debuggable", .{ .bool = false } },
        .{ "issuer", release.azure_compute.string(evidence.issuer) },
        .{ "nonce_sha256", release.azure_compute.string(evidence.nonce_sha256) },
        .{ "secure_boot", .{ .bool = true } },
        .{ "tee", release.azure_compute.string("AMD SEV-SNP") },
        .{ "token_sha256", release.azure_compute.string(evidence.token_sha256) },
        .{ "vm_id", release.azure_compute.string(evidence.vm_id) },
        .{ "vtpm", .{ .bool = true } },
    });
}

pub fn result(
    allocator: Allocator,
    documents: Documents,
    expected: Expected,
    attestation: Attestation,
    diagnostic: *Diagnostic,
) !Value {
    try validateExpected(allocator, expected, diagnostic);
    const source = try validateSourceAcceptance(
        documents.source_acceptance,
        expected,
        diagnostic,
    );
    const capture_contract: release.azure_confidential_vm.CaptureContract = .{
        .subscription_id = expected.subscription_id,
        .location = expected.location,
        .source_image_version_id = source.gallery_image_version_id,
        .vm_id = expected.capture_vm_id,
        .disk_id = expected.capture_disk_id,
    };
    try release.azure_confidential_vm.validateCaptureVm(
        documents.capture_vm,
        capture_contract,
        diagnostic,
    );
    _ = try release.azure_confidential_vm.validateCaptureManagedDisk(
        documents.capture_disk,
        capture_contract,
        diagnostic,
    );
    _ = try release.azure_confidential_vm.validateCaptureSnapshot(
        documents.snapshot,
        expected.snapshot_id,
        capture_contract,
        diagnostic,
    );
    const gallery_contract: release.azure_confidential_vm.CaptureGalleryContract = .{
        .subscription_id = expected.subscription_id,
        .location = expected.location,
        .source_id = expected.snapshot_id,
        .image_definition_id = expected.image_definition_id,
        .image_version_id = expected.image_version_id,
    };
    _ = try release.azure_confidential_vm.validateCapturedImageDefinition(
        documents.image_definition,
        gallery_contract,
        diagnostic,
    );
    try release.azure_confidential_vm.validateCaptureGalleryRequest(
        documents.gallery_request,
        gallery_contract,
        diagnostic,
    );
    try release.azure_confidential_vm.validateCapturedGalleryVersion(
        documents.gallery_response,
        gallery_contract,
        diagnostic,
    );
    const final_contract: release.azure_confidential_vm.CaptureContract = .{
        .subscription_id = expected.subscription_id,
        .location = expected.location,
        .source_image_version_id = expected.image_version_id,
        .vm_id = expected.final_vm_id,
        .disk_id = expected.final_disk_id,
    };
    try release.azure_confidential_vm.validateCapturedVm(
        documents.final_vm,
        final_contract,
        diagnostic,
    );
    const capture_vm_id = try vmUniqueId(documents.capture_vm, diagnostic);
    const final_vm_id = try vmUniqueId(documents.final_vm, diagnostic);
    if (!std.ascii.eqlIgnoreCase(attestation.vm_id, final_vm_id) or
        !validEndpoint(attestation.issuer))
    {
        return invalid(
            diagnostic,
            "final attestation identity or issuer is invalid",
            .{},
        );
    }
    _ = release.digest.parseHex(attestation.nonce_sha256) catch
        return invalid(diagnostic, "final attestation nonce SHA-256 is invalid", .{});
    _ = release.digest.parseHex(attestation.token_sha256) catch
        return invalid(diagnostic, "final attestation token SHA-256 is invalid", .{});

    const source_artifact = try release.azure_compute.object(allocator, &.{
        .{ "qcow_sha256", release.azure_compute.string(expected.source.artifact.qcow_sha256) },
        .{ "qcow_size", release.azure_compute.integer(@intCast(expected.source.artifact.qcow_size)) },
        .{ "vhd_sha256", release.azure_compute.string(expected.source.artifact.vhd_sha256) },
        .{ "vhd_size", release.azure_compute.integer(@intCast(expected.source.artifact.vhd_size)) },
        .{ "virtual_size", release.azure_compute.integer(@intCast(expected.source.artifact.virtual_size)) },
    });
    const source_acceptance = try release.azure_compute.object(allocator, &.{
        .{ "schema", release.azure_compute.integer(1) },
        .{ "sha256", release.azure_compute.string(expected.source.acceptance_sha256) },
        .{ "type", release.azure_compute.string(source_acceptance_type) },
        .{ "workflow", try workflowValue(
            allocator,
            expected.source.run_id,
            expected.source.run_attempt,
        ) },
    });
    const source_value = try release.azure_compute.object(allocator, &.{
        .{ "acceptance", source_acceptance },
        .{ "artifact", source_artifact },
        .{ "commit", release.azure_compute.string(expected.source.commit) },
        .{ "gallery_image_version_id", release.azure_compute.string(source.gallery_image_version_id) },
        .{ "release", release.azure_compute.string("24.04") },
    });
    const vm_value = try release.azure_compute.object(allocator, &.{
        .{ "image_reference_id", release.azure_compute.string(source.gallery_image_version_id) },
        .{ "managed_os_disk_id", release.azure_compute.string(expected.capture_disk_id) },
        .{ "os_disk_encryption_type", release.azure_compute.string(release.azure_confidential_vm.os_disk_security_encryption_type) },
        .{ "resource_id", release.azure_compute.string(expected.capture_vm_id) },
        .{ "security_type", release.azure_compute.string(release.azure_confidential_vm.vm_security_type) },
        .{ "vm_id", release.azure_compute.string(capture_vm_id) },
    });
    const disk_value = try release.azure_compute.object(allocator, &.{
        .{ "encryption_type", release.azure_compute.string(release.azure_confidential_vm.platform_disk_encryption_type) },
        .{ "id", release.azure_compute.string(expected.capture_disk_id) },
        .{ "location", release.azure_compute.string(expected.location) },
        .{ "managed_by", release.azure_compute.string(expected.capture_vm_id) },
        .{ "provisioning_state", release.azure_compute.string("Succeeded") },
        .{ "security_type", release.azure_compute.string(release.azure_confidential_vm.managed_disk_security_type) },
    });
    const snapshot_value = try release.azure_compute.object(allocator, &.{
        .{ "create_option", release.azure_compute.string("Copy") },
        .{ "encryption_type", release.azure_compute.string(release.azure_confidential_vm.platform_disk_encryption_type) },
        .{ "id", release.azure_compute.string(expected.snapshot_id) },
        .{ "location", release.azure_compute.string(expected.location) },
        .{ "provisioning_state", release.azure_compute.string("Succeeded") },
        .{ "security_type", release.azure_compute.string(release.azure_confidential_vm.managed_disk_security_type) },
        .{ "source_disk_id", release.azure_compute.string(expected.capture_disk_id) },
    });
    const translation = try release.azure_compute.object(allocator, &.{
        .{ "gallery", release.azure_compute.string(release.azure_confidential_vm.gallery_os_disk_encryption_type) },
        .{ "resource", release.azure_compute.string(release.azure_confidential_vm.managed_disk_security_type) },
        .{ "vm", release.azure_compute.string(release.azure_confidential_vm.os_disk_security_encryption_type) },
    });
    const capture_value = try release.azure_compute.object(allocator, &.{
        .{ "encryption_translation", translation },
        .{ "managed_os_disk", disk_value },
        .{ "snapshot", snapshot_value },
        .{ "vm", vm_value },
    });
    const definition_value = try release.azure_compute.object(allocator, &.{
        .{ "id", release.azure_compute.string(expected.image_definition_id) },
        .{ "security_type", release.azure_compute.string(release.azure_confidential_vm.captured_image_security_type) },
    });
    const version_value = try release.azure_compute.object(allocator, &.{
        .{ "encryption_type", release.azure_compute.string(release.azure_confidential_vm.gallery_os_disk_encryption_type) },
        .{ "id", release.azure_compute.string(expected.image_version_id) },
        .{ "replication_mode", release.azure_compute.string("Full") },
        .{ "request", try cloneValue(allocator, .{ .object = documents.gallery_request.* }) },
        .{ "response", try cloneValue(allocator, .{ .object = documents.gallery_response.* }) },
        .{ "source_snapshot_id", release.azure_compute.string(expected.snapshot_id) },
    });
    const gallery = try release.azure_compute.object(allocator, &.{
        .{ "definition", definition_value },
        .{ "version", version_value },
    });
    const final_vm = try release.azure_compute.object(allocator, &.{
        .{ "image_reference_id", release.azure_compute.string(expected.image_version_id) },
        .{ "managed_os_disk_id", release.azure_compute.string(expected.final_disk_id) },
        .{ "os_disk_encryption_type", release.azure_compute.string(release.azure_confidential_vm.os_disk_security_encryption_type) },
        .{ "resource_id", release.azure_compute.string(expected.final_vm_id) },
        .{ "security_type", release.azure_compute.string(release.azure_confidential_vm.vm_security_type) },
        .{ "vm_id", release.azure_compute.string(final_vm_id) },
    });
    const final_acceptance = try release.azure_compute.object(allocator, &.{
        .{ "attestation", try attestationValue(allocator, attestation) },
        .{ "vm", final_vm },
    });
    return release.azure_compute.object(allocator, &.{
        .{ "architecture", release.azure_compute.string("x64") },
        .{ "capture", capture_value },
        .{ "final_acceptance", final_acceptance },
        .{ "gallery", gallery },
        .{ "location", release.azure_compute.string(expected.location) },
        .{ "release", release.azure_compute.string("24.04") },
        .{ "schema", release.azure_compute.integer(schema) },
        .{ "source", source_value },
        .{ "subscription_id", release.azure_compute.string(expected.subscription_id) },
        .{ "type", release.azure_compute.string(result_type) },
        .{ "workflow", try workflowValue(allocator, expected.run_id, expected.run_attempt) },
    });
}

fn validateWorkflow(
    value: ObjectMap,
    run_id: []const u8,
    run_attempt: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!exact(value, &.{ "repository", "run_attempt", "run_id" })) {
        return invalid(diagnostic, "{s} shape is invalid", .{label});
    }
    try equal(
        try string(&value, "repository", label, diagnostic),
        repository,
        label,
        diagnostic,
    );
    try equal(try string(&value, "run_id", label, diagnostic), run_id, label, diagnostic);
    try equal(
        try string(&value, "run_attempt", label, diagnostic),
        run_attempt,
        label,
        diagnostic,
    );
}

fn validateAttestation(
    value: ObjectMap,
    vm_id: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!exact(value, &.{
        "compliance",
        "debuggable",
        "issuer",
        "nonce_sha256",
        "secure_boot",
        "tee",
        "token_sha256",
        "vm_id",
        "vtpm",
    })) return invalid(diagnostic, "final attestation shape is invalid", .{});
    try equal(
        try string(&value, "compliance", "final attestation compliance", diagnostic),
        "azure-compliant-cvm",
        "final attestation compliance",
        diagnostic,
    );
    if (value.get("debuggable") == null or value.get("debuggable").? != .bool or
        value.get("debuggable").?.bool or
        !release.azure_compute.isTrue(value.get("secure_boot")) or
        !release.azure_compute.isTrue(value.get("vtpm")))
    {
        return invalid(diagnostic, "final attestation security claims are invalid", .{});
    }
    try equal(
        try string(&value, "tee", "final attestation TEE", diagnostic),
        "AMD SEV-SNP",
        "final attestation TEE",
        diagnostic,
    );
    try equalIgnoreCase(
        try string(&value, "vm_id", "final attestation VM ID", diagnostic),
        vm_id,
        "final attestation VM ID",
        diagnostic,
    );
    if (!validEndpoint(try string(&value, "issuer", "final attestation issuer", diagnostic))) {
        return invalid(diagnostic, "final attestation issuer is invalid", .{});
    }
    _ = release.digest.parseHex(try string(
        &value,
        "nonce_sha256",
        "final attestation nonce SHA-256",
        diagnostic,
    )) catch return invalid(diagnostic, "final attestation nonce SHA-256 is invalid", .{});
    _ = release.digest.parseHex(try string(
        &value,
        "token_sha256",
        "final attestation token SHA-256",
        diagnostic,
    )) catch return invalid(diagnostic, "final attestation token SHA-256 is invalid", .{});
}

pub fn validateResult(
    allocator: Allocator,
    root: *const ObjectMap,
    source_acceptance: *const ObjectMap,
    expected: Expected,
    diagnostic: *Diagnostic,
) !void {
    try validateExpected(allocator, expected, diagnostic);
    const accepted_source = try validateSourceAcceptance(
        source_acceptance,
        expected,
        diagnostic,
    );
    if (!exact(root.*, &.{
        "architecture",
        "capture",
        "final_acceptance",
        "gallery",
        "location",
        "release",
        "schema",
        "source",
        "subscription_id",
        "type",
        "workflow",
    }) or try integer(root, "schema", "capture schema", diagnostic) != schema) {
        return invalid(diagnostic, "capture result shape is invalid", .{});
    }
    try equal(try string(root, "type", "capture type", diagnostic), result_type, "capture type", diagnostic);
    try equal(try string(root, "release", "capture release", diagnostic), "24.04", "capture release", diagnostic);
    try equal(try string(root, "architecture", "capture architecture", diagnostic), "x64", "capture architecture", diagnostic);
    try equalIgnoreCase(try string(root, "location", "capture location", diagnostic), expected.location, "capture location", diagnostic);
    try equalIgnoreCase(try string(root, "subscription_id", "capture subscription", diagnostic), expected.subscription_id, "capture subscription", diagnostic);
    try validateWorkflow(
        try object(root, "workflow", "capture workflow", diagnostic),
        expected.run_id,
        expected.run_attempt,
        "capture workflow",
        diagnostic,
    );

    const source = try object(root, "source", "capture source", diagnostic);
    if (!exact(source, &.{ "acceptance", "artifact", "commit", "gallery_image_version_id", "release" })) {
        return invalid(diagnostic, "capture source shape is invalid", .{});
    }
    try equal(try string(&source, "commit", "capture source commit", diagnostic), expected.source.commit, "capture source commit", diagnostic);
    try equal(try string(&source, "release", "capture source release", diagnostic), "24.04", "capture source release", diagnostic);
    try equalIgnoreCase(
        try string(&source, "gallery_image_version_id", "capture source version", diagnostic),
        accepted_source.gallery_image_version_id,
        "capture source version",
        diagnostic,
    );
    const acceptance = try object(&source, "acceptance", "capture source acceptance", diagnostic);
    if (!exact(acceptance, &.{ "schema", "sha256", "type", "workflow" }) or
        try integer(&acceptance, "schema", "source acceptance schema", diagnostic) != 1)
    {
        return invalid(diagnostic, "capture source acceptance shape is invalid", .{});
    }
    try equal(try string(&acceptance, "type", "source acceptance type", diagnostic), source_acceptance_type, "source acceptance type", diagnostic);
    try equal(try string(&acceptance, "sha256", "source acceptance SHA-256", diagnostic), expected.source.acceptance_sha256, "source acceptance SHA-256", diagnostic);
    try validateWorkflow(
        try object(&acceptance, "workflow", "source acceptance workflow", diagnostic),
        expected.source.run_id,
        expected.source.run_attempt,
        "source acceptance workflow",
        diagnostic,
    );
    const artifact = try object(&source, "artifact", "capture source artifact", diagnostic);
    if (!exact(artifact, &.{ "qcow_sha256", "qcow_size", "vhd_sha256", "vhd_size", "virtual_size" })) {
        return invalid(diagnostic, "capture source artifact shape is invalid", .{});
    }
    try equal(try string(&artifact, "qcow_sha256", "capture QCOW2 SHA-256", diagnostic), expected.source.artifact.qcow_sha256, "capture QCOW2 SHA-256", diagnostic);
    try equal(try string(&artifact, "vhd_sha256", "capture VHD SHA-256", diagnostic), expected.source.artifact.vhd_sha256, "capture VHD SHA-256", diagnostic);
    const result_sizes = [_]struct { []const u8, u64 }{
        .{ "qcow_size", expected.source.artifact.qcow_size },
        .{ "vhd_size", expected.source.artifact.vhd_size },
        .{ "virtual_size", expected.source.artifact.virtual_size },
    };
    for (result_sizes) |entry| if (try positive(
        try integer(&artifact, entry[0], entry[0], diagnostic),
        entry[0],
        diagnostic,
    ) != entry[1]) return invalid(diagnostic, "capture source artifact size mismatch", .{});

    const capture = try object(root, "capture", "capture evidence", diagnostic);
    if (!exact(capture, &.{ "encryption_translation", "managed_os_disk", "snapshot", "vm" })) {
        return invalid(diagnostic, "capture evidence shape is invalid", .{});
    }
    const vm = try object(&capture, "vm", "capture VM", diagnostic);
    if (!exact(vm, &.{ "image_reference_id", "managed_os_disk_id", "os_disk_encryption_type", "resource_id", "security_type", "vm_id" })) {
        return invalid(diagnostic, "capture VM evidence shape is invalid", .{});
    }
    try equalIgnoreCase(try string(&vm, "resource_id", "capture VM resource ID", diagnostic), expected.capture_vm_id, "capture VM resource ID", diagnostic);
    try equalIgnoreCase(try string(&vm, "image_reference_id", "capture VM image reference", diagnostic), accepted_source.gallery_image_version_id, "capture VM image reference", diagnostic);
    try equalIgnoreCase(try string(&vm, "managed_os_disk_id", "capture VM disk", diagnostic), expected.capture_disk_id, "capture VM disk", diagnostic);
    try equal(try string(&vm, "security_type", "capture VM security type", diagnostic), release.azure_confidential_vm.vm_security_type, "capture VM security type", diagnostic);
    try equal(try string(&vm, "os_disk_encryption_type", "capture VM encryption", diagnostic), release.azure_confidential_vm.os_disk_security_encryption_type, "capture VM encryption", diagnostic);
    if (!validGuid(try string(&vm, "vm_id", "capture VM ID", diagnostic))) return invalid(diagnostic, "capture VM ID is invalid", .{});

    const disk = try object(&capture, "managed_os_disk", "capture disk", diagnostic);
    if (!exact(disk, &.{ "encryption_type", "id", "location", "managed_by", "provisioning_state", "security_type" })) {
        return invalid(diagnostic, "capture disk evidence shape is invalid", .{});
    }
    try equalIgnoreCase(try string(&disk, "id", "capture disk ID", diagnostic), expected.capture_disk_id, "capture disk ID", diagnostic);
    try equalIgnoreCase(try string(&disk, "managed_by", "capture disk VM", diagnostic), expected.capture_vm_id, "capture disk VM", diagnostic);
    try equalIgnoreCase(try string(&disk, "location", "capture disk location", diagnostic), expected.location, "capture disk location", diagnostic);
    try equal(try string(&disk, "provisioning_state", "capture disk state", diagnostic), "Succeeded", "capture disk state", diagnostic);
    try equal(try string(&disk, "security_type", "capture disk security", diagnostic), release.azure_confidential_vm.managed_disk_security_type, "capture disk security", diagnostic);
    try equal(try string(&disk, "encryption_type", "capture disk encryption", diagnostic), release.azure_confidential_vm.platform_disk_encryption_type, "capture disk encryption", diagnostic);

    const snapshot = try object(&capture, "snapshot", "capture snapshot", diagnostic);
    if (!exact(snapshot, &.{ "create_option", "encryption_type", "id", "location", "provisioning_state", "security_type", "source_disk_id" })) {
        return invalid(diagnostic, "capture snapshot evidence shape is invalid", .{});
    }
    try equalIgnoreCase(try string(&snapshot, "id", "snapshot ID", diagnostic), expected.snapshot_id, "snapshot ID", diagnostic);
    try equalIgnoreCase(try string(&snapshot, "source_disk_id", "snapshot source disk", diagnostic), expected.capture_disk_id, "snapshot source disk", diagnostic);
    try equalIgnoreCase(try string(&snapshot, "location", "snapshot location", diagnostic), expected.location, "snapshot location", diagnostic);
    try equal(try string(&snapshot, "create_option", "snapshot create option", diagnostic), "Copy", "snapshot create option", diagnostic);
    try equal(try string(&snapshot, "provisioning_state", "snapshot state", diagnostic), "Succeeded", "snapshot state", diagnostic);
    try equal(try string(&snapshot, "security_type", "snapshot security", diagnostic), release.azure_confidential_vm.managed_disk_security_type, "snapshot security", diagnostic);
    try equal(try string(&snapshot, "encryption_type", "snapshot encryption", diagnostic), release.azure_confidential_vm.platform_disk_encryption_type, "snapshot encryption", diagnostic);
    const translation = try object(&capture, "encryption_translation", "encryption translation", diagnostic);
    if (!exact(translation, &.{ "gallery", "resource", "vm" })) return invalid(diagnostic, "encryption translation shape is invalid", .{});
    try equal(try string(&translation, "vm", "VM encryption translation", diagnostic), release.azure_confidential_vm.os_disk_security_encryption_type, "VM encryption translation", diagnostic);
    try equal(try string(&translation, "resource", "resource encryption translation", diagnostic), release.azure_confidential_vm.managed_disk_security_type, "resource encryption translation", diagnostic);
    try equal(try string(&translation, "gallery", "gallery encryption translation", diagnostic), release.azure_confidential_vm.gallery_os_disk_encryption_type, "gallery encryption translation", diagnostic);

    const gallery = try object(root, "gallery", "capture gallery", diagnostic);
    if (!exact(gallery, &.{ "definition", "version" })) return invalid(diagnostic, "capture gallery shape is invalid", .{});
    const definition = try object(&gallery, "definition", "capture definition", diagnostic);
    if (!exact(definition, &.{ "id", "security_type" })) return invalid(diagnostic, "capture definition shape is invalid", .{});
    try equalIgnoreCase(try string(&definition, "id", "capture definition ID", diagnostic), expected.image_definition_id, "capture definition ID", diagnostic);
    try equal(try string(&definition, "security_type", "capture definition security", diagnostic), release.azure_confidential_vm.captured_image_security_type, "capture definition security", diagnostic);
    const version = try object(&gallery, "version", "capture version", diagnostic);
    if (!exact(version, &.{ "encryption_type", "id", "replication_mode", "request", "response", "source_snapshot_id" })) {
        return invalid(diagnostic, "capture version shape is invalid", .{});
    }
    try equalIgnoreCase(try string(&version, "id", "capture version ID", diagnostic), expected.image_version_id, "capture version ID", diagnostic);
    try equalIgnoreCase(try string(&version, "source_snapshot_id", "capture version source", diagnostic), expected.snapshot_id, "capture version source", diagnostic);
    try equal(try string(&version, "replication_mode", "capture replication mode", diagnostic), "Full", "capture replication mode", diagnostic);
    try equal(try string(&version, "encryption_type", "capture gallery encryption", diagnostic), release.azure_confidential_vm.gallery_os_disk_encryption_type, "capture gallery encryption", diagnostic);
    const gallery_contract: release.azure_confidential_vm.CaptureGalleryContract = .{
        .subscription_id = expected.subscription_id,
        .location = expected.location,
        .source_id = expected.snapshot_id,
        .image_definition_id = expected.image_definition_id,
        .image_version_id = expected.image_version_id,
    };
    const request = try object(&version, "request", "capture gallery request", diagnostic);
    const response = try object(&version, "response", "capture gallery response", diagnostic);
    try release.azure_confidential_vm.validateCaptureGalleryRequest(&request, gallery_contract, diagnostic);
    try release.azure_confidential_vm.validateCapturedGalleryVersion(&response, gallery_contract, diagnostic);

    const final = try object(root, "final_acceptance", "final acceptance", diagnostic);
    if (!exact(final, &.{ "attestation", "vm" })) return invalid(diagnostic, "final acceptance shape is invalid", .{});
    const final_vm = try object(&final, "vm", "final VM", diagnostic);
    if (!exact(final_vm, &.{ "image_reference_id", "managed_os_disk_id", "os_disk_encryption_type", "resource_id", "security_type", "vm_id" })) {
        return invalid(diagnostic, "final VM shape is invalid", .{});
    }
    try equalIgnoreCase(try string(&final_vm, "resource_id", "final VM resource ID", diagnostic), expected.final_vm_id, "final VM resource ID", diagnostic);
    try equalIgnoreCase(try string(&final_vm, "managed_os_disk_id", "final VM disk", diagnostic), expected.final_disk_id, "final VM disk", diagnostic);
    try equalIgnoreCase(try string(&final_vm, "image_reference_id", "final VM image reference", diagnostic), expected.image_version_id, "final VM image reference", diagnostic);
    try equal(try string(&final_vm, "security_type", "final VM security", diagnostic), release.azure_confidential_vm.vm_security_type, "final VM security", diagnostic);
    try equal(try string(&final_vm, "os_disk_encryption_type", "final VM encryption", diagnostic), release.azure_confidential_vm.os_disk_security_encryption_type, "final VM encryption", diagnostic);
    const final_vm_unique_id = try string(&final_vm, "vm_id", "final VM ID", diagnostic);
    if (!validGuid(final_vm_unique_id)) return invalid(diagnostic, "final VM ID is invalid", .{});
    try validateAttestation(
        try object(&final, "attestation", "final attestation", diagnostic),
        final_vm_unique_id,
        diagnostic,
    );
}

test "Azure capture resource IDs are structural and exact" {
    const subscription = "00000000-0000-0000-0000-000000000000";
    const definition =
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gallery/providers/Microsoft.Compute/galleries/g/images/ubuntu";
    try std.testing.expect(azureResourceId(definition, subscription, .image_definition));
    try std.testing.expect(azureResourceId(
        definition ++ "/versions/1.0.0",
        subscription,
        .image_version,
    ));
    try std.testing.expect(versionBelongsToDefinition(
        definition ++ "/versions/1.0.0",
        definition,
    ));
    try std.testing.expect(!versionBelongsToDefinition(
        definition ++ "-evil/versions/1.0.0",
        definition,
    ));
    try std.testing.expect(!azureResourceId(
        definition ++ "/versions/1.0.0/extra",
        subscription,
        .image_version,
    ));
}

const test_subscription = "00000000-0000-0000-0000-000000000000";
const test_group = "miz-u2404-cvm-capture-456-2";
const test_prefix = "/subscriptions/" ++ test_subscription ++
    "/resourceGroups/" ++ test_group ++ "/providers/Microsoft.Compute/";
const test_source_version = "/subscriptions/" ++ test_subscription ++
    "/resourceGroups/miz-u2404-cvm-123-1/providers/Microsoft.Compute/" ++
    "galleries/source/images/ubuntu/versions/1.0.0";
const test_capture_vm = test_prefix ++ "virtualMachines/capture";
const test_capture_disk = test_prefix ++ "disks/capture-os";
const test_snapshot = test_prefix ++ "snapshots/capture-os";
const test_definition = "/subscriptions/" ++ test_subscription ++
    "/resourceGroups/gallery/providers/Microsoft.Compute/" ++
    "galleries/release/images/ubuntu-confidential";
const test_version = test_definition ++ "/versions/2.0.0";
const test_final_vm = test_prefix ++ "virtualMachines/final";
const test_final_disk = test_prefix ++ "disks/final-os";
const test_capture_vm_id = "11111111-1111-1111-1111-111111111111";
const test_final_vm_id = "22222222-2222-2222-2222-222222222222";

fn testExpected() Expected {
    return .{
        .source = .{
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .location = "eastus2",
            .vm_size = "Standard_DC2as_v5",
            .run_id = "123",
            .run_attempt = "1",
            .acceptance_sha256 = "a" ** 64,
            .artifact = .{
                .qcow_sha256 = "1" ** 64,
                .qcow_size = 1024,
                .vhd_sha256 = "2" ** 64,
                .vhd_size = 4096,
                .virtual_size = 3584,
            },
        },
        .subscription_id = test_subscription,
        .location = "eastus2",
        .run_id = "456",
        .run_attempt = "2",
        .capture_vm_id = test_capture_vm,
        .capture_disk_id = test_capture_disk,
        .snapshot_id = test_snapshot,
        .image_definition_id = test_definition,
        .image_version_id = test_version,
        .final_vm_id = test_final_vm,
        .final_disk_id = test_final_disk,
    };
}

test "capture expectations reject malformed cross-scope identities" {
    var diagnostic: Diagnostic = .{};
    var expected = testExpected();
    expected.image_version_id = test_definition ++ "-evil/versions/2.0.0";
    try std.testing.expectError(
        error.InvalidDocument,
        validateExpected(std.testing.allocator, expected, &diagnostic),
    );

    diagnostic = .{};
    expected = testExpected();
    expected.capture_disk_id =
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/" ++
        test_group ++ "/providers/Microsoft.Compute/disks/capture-os";
    try std.testing.expectError(
        error.InvalidDocument,
        validateExpected(std.testing.allocator, expected, &diagnostic),
    );

    diagnostic = .{};
    expected = testExpected();
    expected.final_vm_id = test_prefix ++ "virtualMachines/final/extra";
    try std.testing.expectError(
        error.InvalidDocument,
        validateExpected(std.testing.allocator, expected, &diagnostic),
    );

    diagnostic = .{};
    expected = testExpected();
    expected.run_attempt = "3";
    try std.testing.expectError(
        error.InvalidDocument,
        validateExpected(std.testing.allocator, expected, &diagnostic),
    );
}

const test_source_acceptance =
    "{\"artifact\":{\"qcow_sha256\":\"" ++ "1" ** 64 ++
    "\",\"qcow_size\":1024,\"vhd_sha256\":\"" ++ "2" ** 64 ++
    "\",\"vhd_size\":4096,\"virtual_size\":3584}," ++
    "\"attestation\":{},\"azure\":{\"gallery_image_version_id\":\"" ++
    test_source_version ++ "\",\"location\":\"eastus2\"," ++
    "\"managed_disk_id\":\"unused\",\"managed_image_id\":\"unused\"," ++
    "\"resource_group\":\"miz-u2404-cvm-123-1\"," ++
    "\"vm_id\":\"00000000-0000-0000-0000-000000000000\"," ++
    "\"vm_resource_id\":\"unused\",\"vm_size\":\"Standard_DC2as_v5\"}," ++
    "\"schema\":1,\"source_commit\":\"0123456789abcdef0123456789abcdef01234567\"," ++
    "\"type\":\"" ++ source_acceptance_type ++ "\"}";

const test_capture_vm_document =
    "{\"id\":\"" ++ test_capture_vm ++ "\",\"vmId\":\"" ++
    test_capture_vm_id ++ "\",\"location\":\"eastus2\"," ++
    "\"provisioningState\":\"Succeeded\",\"securityProfile\":{\"securityType\":" ++
    "\"ConfidentialVM\",\"uefiSettings\":{\"secureBootEnabled\":true," ++
    "\"vTpmEnabled\":true}},\"storageProfile\":{\"imageReference\":{\"id\":\"" ++
    test_source_version ++ "\"},\"osDisk\":{\"managedDisk\":{\"id\":\"" ++
    test_capture_disk ++ "\",\"diskEncryptionSet\":null,\"securityProfile\":" ++
    "{\"securityEncryptionType\":\"VMGuestStateOnly\",\"diskEncryptionSet\":null}}}}}";

const test_capture_disk_document =
    "{\"id\":\"" ++ test_capture_disk ++ "\",\"managedBy\":\"" ++
    test_capture_vm ++ "\",\"location\":\"eastus2\",\"provisioningState\":" ++
    "\"Succeeded\",\"osType\":\"Linux\",\"hyperVGeneration\":\"V2\"," ++
    "\"supportedCapabilities\":{\"architecture\":\"x64\"},\"securityProfile\":" ++
    "{\"securityType\":\"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey\"," ++
    "\"secureVMDiskEncryptionSetId\":null},\"encryption\":" ++
    "{\"type\":\"EncryptionAtRestWithPlatformKey\"}}";

const test_snapshot_document =
    "{\"id\":\"" ++ test_snapshot ++ "\",\"location\":\"eastus2\"," ++
    "\"provisioningState\":\"Succeeded\",\"osType\":\"Linux\"," ++
    "\"hyperVGeneration\":\"V2\",\"supportedCapabilities\":{\"architecture\":\"x64\"}," ++
    "\"creationData\":{\"createOption\":\"Copy\",\"sourceResourceId\":\"" ++
    test_capture_disk ++ "\"},\"securityProfile\":{\"securityType\":" ++
    "\"ConfidentialVM_VMGuestStateOnlyEncryptedWithPlatformKey\"," ++
    "\"secureVMDiskEncryptionSetId\":null},\"encryption\":" ++
    "{\"type\":\"EncryptionAtRestWithPlatformKey\"}}";

const test_definition_document =
    "{\"id\":\"" ++ test_definition ++ "\",\"location\":\"eastus2\"," ++
    "\"provisioningState\":\"Succeeded\",\"osType\":\"Linux\"," ++
    "\"osState\":\"Generalized\",\"hyperVGeneration\":\"V2\"," ++
    "\"architecture\":\"x64\",\"features\":[{\"name\":\"SecurityType\"," ++
    "\"value\":\"ConfidentialVM\"}]}";

const test_gallery_response =
    "{\"id\":\"" ++ test_version ++ "\",\"location\":\"eastus2\"," ++
    "\"properties\":{\"provisioningState\":\"Succeeded\",\"replicationStatus\":" ++
    "{\"aggregatedState\":\"Completed\",\"summary\":[{\"region\":\"eastus2\"," ++
    "\"state\":\"Completed\"}]},\"publishingProfile\":{\"replicationMode\":\"Full\"," ++
    "\"targetRegions\":[{\"name\":\"eastus2\",\"regionalReplicaCount\":1," ++
    "\"storageAccountType\":\"Standard_LRS\",\"encryption\":{\"osDiskImage\":" ++
    "{\"securityProfile\":{\"confidentialVMEncryptionType\":" ++
    "\"EncryptedVMGuestStateOnlyWithPmk\"}}}}]},\"storageProfile\":" ++
    "{\"osDiskImage\":{\"source\":{\"id\":\"" ++ test_snapshot ++ "\"}}}}}";

const test_final_vm_document =
    "{\"id\":\"" ++ test_final_vm ++ "\",\"vmId\":\"" ++ test_final_vm_id ++
    "\",\"location\":\"eastus2\",\"provisioningState\":\"Succeeded\"," ++
    "\"securityProfile\":{\"securityType\":\"ConfidentialVM\",\"uefiSettings\":" ++
    "{\"secureBootEnabled\":true,\"vTpmEnabled\":true}},\"storageProfile\":" ++
    "{\"imageReference\":{\"id\":\"" ++ test_version ++ "\"},\"osDisk\":" ++
    "{\"managedDisk\":{\"id\":\"" ++ test_final_disk ++
    "\",\"diskEncryptionSet\":null,\"securityProfile\":" ++
    "{\"securityEncryptionType\":\"VMGuestStateOnly\",\"diskEncryptionSet\":null}}}}}";

fn expectTamper(
    allocator: Allocator,
    valid: []const u8,
    needle: []const u8,
    replacement: []const u8,
    source_acceptance: *const ObjectMap,
) !void {
    const occurrences = std.mem.count(u8, valid, needle);
    if (occurrences != 1) {
        std.debug.print("capture tamper pattern occurrences={d}: {s}\n", .{
            occurrences,
            needle,
        });
    }
    try std.testing.expectEqual(@as(usize, 1), occurrences);
    const changed = try std.mem.replaceOwned(
        u8,
        allocator,
        valid,
        needle,
        replacement,
    );
    var parsed = try std.json.parseFromSlice(Value, allocator, changed, .{});
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, validateResult(
        allocator,
        &parsed.value.object,
        source_acceptance,
        testExpected(),
        &diagnostic,
    ));
}

test "capture result independently rejects provenance substitutions" {
    var arena: std.heap.ArenaAllocator = .init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var source = try std.json.parseFromSlice(
        Value,
        allocator,
        test_source_acceptance,
        .{},
    );
    var capture_vm = try std.json.parseFromSlice(
        Value,
        allocator,
        test_capture_vm_document,
        .{},
    );
    var capture_disk = try std.json.parseFromSlice(
        Value,
        allocator,
        test_capture_disk_document,
        .{},
    );
    var snapshot = try std.json.parseFromSlice(
        Value,
        allocator,
        test_snapshot_document,
        .{},
    );
    var definition = try std.json.parseFromSlice(
        Value,
        allocator,
        test_definition_document,
        .{},
    );
    const request = try release.azure_confidential_vm.captureGalleryVersionRequest(
        allocator,
        "eastus2",
        test_snapshot,
    );
    var response = try std.json.parseFromSlice(
        Value,
        allocator,
        test_gallery_response,
        .{},
    );
    var final_vm = try std.json.parseFromSlice(
        Value,
        allocator,
        test_final_vm_document,
        .{},
    );
    var diagnostic: Diagnostic = .{};
    const valid_value = try result(
        allocator,
        .{
            .source_acceptance = &source.value.object,
            .capture_vm = &capture_vm.value.object,
            .capture_disk = &capture_disk.value.object,
            .snapshot = &snapshot.value.object,
            .image_definition = &definition.value.object,
            .gallery_request = &request.object,
            .gallery_response = &response.value.object,
            .final_vm = &final_vm.value.object,
        },
        testExpected(),
        .{
            .vm_id = test_final_vm_id,
            .issuer = "https://test.attest.azure.net",
            .nonce_sha256 = "3" ** 64,
            .token_sha256 = "4" ** 64,
        },
        &diagnostic,
    );
    try validateResult(
        allocator,
        &valid_value.object,
        &source.value.object,
        testExpected(),
        &diagnostic,
    );
    const valid = try std.json.Stringify.valueAlloc(allocator, valid_value, .{});

    const substitutions = [_][2][]const u8{
        .{
            "\"qcow_sha256\":\"" ++ "1" ** 64 ++ "\"",
            "\"qcow_sha256\":\"" ++ "9" ** 64 ++ "\"",
        },
        .{
            "\"gallery_image_version_id\":\"" ++ test_source_version ++ "\"",
            "\"gallery_image_version_id\":\"" ++ test_version ++ "\"",
        },
        .{
            "\"image_reference_id\":\"" ++ test_source_version ++ "\"",
            "\"image_reference_id\":\"" ++ test_version ++ "\"",
        },
        .{
            "\"managed_by\":\"" ++ test_capture_vm ++ "\"",
            "\"managed_by\":\"" ++ test_final_vm ++ "\"",
        },
        .{
            "\"source_disk_id\":\"" ++ test_capture_disk ++ "\"",
            "\"source_disk_id\":\"" ++ test_final_disk ++ "\"",
        },
        .{
            "\"subscription_id\":\"" ++ test_subscription ++ "\"",
            "\"subscription_id\":\"11111111-1111-1111-1111-111111111111\"",
        },
        .{
            "\"location\":\"eastus2\",\"release\":\"24.04\"",
            "\"location\":\"westus2\",\"release\":\"24.04\"",
        },
        .{
            "\"security_type\":\"ConfidentialVM\",\"vm_id\":\"" ++ test_capture_vm_id ++ "\"",
            "\"security_type\":\"TrustedLaunch\",\"vm_id\":\"" ++ test_capture_vm_id ++ "\"",
        },
        .{
            "\"id\":\"" ++ test_version ++ "\",\"replication_mode\":\"Full\"",
            "\"id\":\"" ++ test_definition ++ "-evil/versions/2.0.0\",\"replication_mode\":\"Full\"",
        },
        .{
            "\"image_reference_id\":\"" ++ test_version ++ "\"",
            "\"image_reference_id\":\"" ++ test_source_version ++ "\"",
        },
        .{
            "\"vm_id\":\"" ++ test_final_vm_id ++ "\",\"vtpm\":true",
            "\"vm_id\":\"33333333-3333-3333-3333-333333333333\",\"vtpm\":true",
        },
        .{
            "\"run_id\":\"456\"",
            "\"run_id\":\"457\"",
        },
        .{
            "\"architecture\":\"x64\",\"capture\"",
            "\"unknown\":true,\"architecture\":\"x64\",\"capture\"",
        },
        .{
            "\"gallery\":\"EncryptedVMGuestStateOnlyWithPmk\"",
            "\"gallery\":\"EncryptedWithPmk\"",
        },
    };
    for (substitutions) |substitution| try expectTamper(
        allocator,
        valid,
        substitution[0],
        substitution[1],
        &source.value.object,
    );
}
