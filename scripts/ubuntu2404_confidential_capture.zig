//! Target-specific provenance for promoting an accepted Ubuntu 24.04
//! `ConfidentialVMSupported` image through Azure capture to `ConfidentialVM`.
//!
//! The protected workflow must freshly retrieve Azure ARM, OpenID, and JWKS
//! evidence over HTTPS/OIDC immediately before invoking this offline validator.
//! This module validates the complete contents and binds their raw SHA-256
//! digests; it does not authenticate the transport origin of supplied files.

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
    repository: []const u8,
    commit: []const u8,
    location: []const u8,
    vm_size: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    artifact: Artifact,
};

pub const Expected = struct {
    source: SourceExpected,
    repository: []const u8,
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
    attestation_endpoint: []const u8,
};

pub const Documents = struct {
    source_acceptance: *const ObjectMap,
    capture_vm: *const ObjectMap,
    capture_vm_instance: *const ObjectMap,
    capture_disk: *const ObjectMap,
    snapshot: *const ObjectMap,
    image_definition: *const ObjectMap,
    gallery_request: *const ObjectMap,
    gallery_response: *const ObjectMap,
    final_vm: *const ObjectMap,
    final_vm_instance: *const ObjectMap,
};

pub const Attestation = struct {
    vm_id: []const u8,
    issuer: []const u8,
};

pub const Evidence = struct {
    source_acceptance_sha256: release.digest.Hex,
    source_provenance_sha256: release.digest.Hex,
    capture_vm_sha256: release.digest.Hex,
    capture_vm_instance_sha256: release.digest.Hex,
    capture_disk_sha256: release.digest.Hex,
    snapshot_sha256: release.digest.Hex,
    image_definition_sha256: release.digest.Hex,
    gallery_request_sha256: release.digest.Hex,
    gallery_response_sha256: release.digest.Hex,
    final_vm_sha256: release.digest.Hex,
    final_vm_instance_sha256: release.digest.Hex,
    token_sha256: release.digest.Hex,
    openid_sha256: release.digest.Hex,
    jwks_sha256: release.digest.Hex,
    nonce_sha256: release.digest.Hex,
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

fn validResourceName(name: []const u8) bool {
    if (name.len == 0 or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, ".."))
    {
        return false;
    }
    for (name) |character| switch (character) {
        'a'...'z', 'A'...'Z', '0'...'9', '-', '_', '.', '(', ')' => {},
        else => return false,
    };
    return true;
}

fn validVersionName(name: []const u8) bool {
    var components = std.mem.splitScalar(u8, name, '.');
    var count: usize = 0;
    while (components.next()) |component| {
        count += 1;
        if (count > 3 or component.len == 0) return false;
        for (component) |character| {
            if (character < '0' or character > '9') return false;
        }
        const number = std.fmt.parseInt(u32, component, 10) catch return false;
        if (number > std.math.maxInt(i32)) return false;
    }
    return count == 3;
}

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
    if (!validGuid(subscription_id) or
        count != expected_count or
        segments[0].len != 0 or
        !std.ascii.eqlIgnoreCase(segments[1], "subscriptions") or
        !std.ascii.eqlIgnoreCase(segments[2], subscription_id) or
        !std.ascii.eqlIgnoreCase(segments[3], "resourceGroups") or
        !validResourceName(segments[4]) or
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
        !validResourceName(segments[8]))
    {
        return false;
    }
    if (nested and
        (!std.ascii.eqlIgnoreCase(segments[9], "images") or
            !validResourceName(segments[10])))
    {
        return false;
    }
    return kind != .image_version or
        (std.ascii.eqlIgnoreCase(segments[11], "versions") and
            validVersionName(segments[12]));
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

pub fn validateSnapshotId(
    id: []const u8,
    subscription_id: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!azureResourceId(id, subscription_id, .snapshot)) {
        return invalid(
            diagnostic,
            "capture snapshot ID is malformed, mistyped, or cross-subscription",
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
        !std.mem.eql(u8, version_id[0..definition_id.len], definition_id))
    {
        return false;
    }
    const suffix = version_id[definition_id.len..];
    if (!std.mem.startsWith(u8, suffix, "/versions/")) return false;
    const name = suffix["/versions/".len..];
    return validVersionName(name);
}

pub fn validateCaptureGalleryIds(
    definition_id: []const u8,
    version_id: []const u8,
    subscription_id: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!azureResourceId(
        definition_id,
        subscription_id,
        .image_definition,
    ) or !azureResourceId(
        version_id,
        subscription_id,
        .image_version,
    )) {
        return invalid(
            diagnostic,
            "capture gallery definition or version ID is malformed or cross-subscription",
            .{},
        );
    }
    if (!versionBelongsToDefinition(version_id, definition_id)) {
        return invalid(
            diagnostic,
            "capture gallery version is outside the exact image definition",
            .{},
        );
    }
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
    if (!std.mem.eql(u8, expected.source.repository, repository) or
        !std.mem.eql(u8, expected.repository, repository) or
        !validCommit(expected.source.commit) or
        !validDecimal(expected.source.run_id) or
        !validDecimal(expected.source.run_attempt) or
        !validDecimal(expected.run_id) or
        !validDecimal(expected.run_attempt))
    {
        return invalid(diagnostic, "capture workflow identity is invalid", .{});
    }
    _ = release.digest.parseHex(expected.source.artifact.qcow_sha256) catch
        return invalid(diagnostic, "source QCOW2 SHA-256 is invalid", .{});
    _ = release.digest.parseHex(expected.source.artifact.vhd_sha256) catch
        return invalid(diagnostic, "source VHD SHA-256 is invalid", .{});
    if (expected.source.artifact.qcow_size == 0 or
        expected.source.artifact.vhd_size == 0 or
        expected.source.artifact.virtual_size == 0 or
        !std.ascii.eqlIgnoreCase(expected.source.location, expected.location) or
        !validEndpoint(expected.attestation_endpoint))
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
    try validateCaptureGalleryIds(
        expected.image_definition_id,
        expected.image_version_id,
        expected.subscription_id,
        diagnostic,
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

pub fn vmUniqueId(vm: *const ObjectMap, diagnostic: *Diagnostic) ![]const u8 {
    const id = try string(vm, "vmId", "Azure VM unique identity", diagnostic);
    if (!validGuid(id)) return invalid(
        diagnostic,
        "Azure VM unique identity is invalid",
        .{},
    );
    return id;
}

fn validateVmInstance(
    instance: *const ObjectMap,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    release.azure_confidential_vm.validateVmSecurityProfile(
        instance,
        label,
        diagnostic,
    ) catch return error.InvalidDocument;
}

pub fn validateFinalVmEvidence(
    vm: *const ObjectMap,
    instance: *const ObjectMap,
    expected: Expected,
    diagnostic: *Diagnostic,
) ![]const u8 {
    const final_contract: release.azure_confidential_vm.CaptureContract = .{
        .subscription_id = expected.subscription_id,
        .location = expected.location,
        .source_image_version_id = expected.image_version_id,
        .vm_id = expected.final_vm_id,
        .disk_id = expected.final_disk_id,
    };
    release.azure_confidential_vm.validateCapturedVm(
        vm,
        final_contract,
        diagnostic,
    ) catch return error.InvalidDocument;
    try validateVmInstance(instance, "Azure final VM instance view", diagnostic);
    return vmUniqueId(vm, diagnostic);
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
    workflow_repository: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
) !Value {
    return release.azure_compute.object(allocator, &.{
        .{ "repository", release.azure_compute.string(workflow_repository) },
        .{ "run_id", release.azure_compute.string(run_id) },
        .{ "run_attempt", release.azure_compute.string(run_attempt) },
    });
}

fn attestationValue(allocator: Allocator, evidence: Attestation) !Value {
    return release.azure_compute.object(allocator, &.{
        .{ "compliance", release.azure_compute.string("azure-compliant-cvm") },
        .{ "debuggable", .{ .bool = false } },
        .{ "issuer", release.azure_compute.string(evidence.issuer) },
        .{ "secure_boot", .{ .bool = true } },
        .{ "tee", release.azure_compute.string("AMD SEV-SNP") },
        .{ "vm_id", release.azure_compute.string(evidence.vm_id) },
        .{ "vtpm", .{ .bool = true } },
    });
}

fn evidenceValue(allocator: Allocator, evidence: Evidence) !Value {
    return release.azure_compute.object(allocator, &.{
        .{ "capture_disk_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.capture_disk_sha256)) },
        .{ "capture_vm_instance_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.capture_vm_instance_sha256)) },
        .{ "capture_vm_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.capture_vm_sha256)) },
        .{ "final_vm_instance_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.final_vm_instance_sha256)) },
        .{ "final_vm_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.final_vm_sha256)) },
        .{ "gallery_request_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.gallery_request_sha256)) },
        .{ "gallery_response_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.gallery_response_sha256)) },
        .{ "image_definition_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.image_definition_sha256)) },
        .{ "jwks_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.jwks_sha256)) },
        .{ "nonce_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.nonce_sha256)) },
        .{ "openid_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.openid_sha256)) },
        .{ "snapshot_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.snapshot_sha256)) },
        .{ "source_acceptance_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.source_acceptance_sha256)) },
        .{ "source_provenance_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.source_provenance_sha256)) },
        .{ "token_sha256", release.azure_compute.string(try allocator.dupe(u8, &evidence.token_sha256)) },
    });
}

pub fn result(
    allocator: Allocator,
    documents: Documents,
    expected: Expected,
    attestation: Attestation,
    evidence: Evidence,
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
    try validateVmInstance(
        documents.capture_vm_instance,
        "Azure capture VM instance view",
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
    const final_vm_id = try validateFinalVmEvidence(
        documents.final_vm,
        documents.final_vm_instance,
        expected,
        diagnostic,
    );
    const capture_vm_id = try vmUniqueId(documents.capture_vm, diagnostic);
    if (!std.ascii.eqlIgnoreCase(attestation.vm_id, final_vm_id) or
        !std.mem.eql(u8, attestation.issuer, expected.attestation_endpoint))
    {
        return invalid(
            diagnostic,
            "final attestation identity or issuer is invalid",
            .{},
        );
    }
    const source_artifact = try release.azure_compute.object(allocator, &.{
        .{ "qcow_sha256", release.azure_compute.string(expected.source.artifact.qcow_sha256) },
        .{ "qcow_size", release.azure_compute.integer(@intCast(expected.source.artifact.qcow_size)) },
        .{ "vhd_sha256", release.azure_compute.string(expected.source.artifact.vhd_sha256) },
        .{ "vhd_size", release.azure_compute.integer(@intCast(expected.source.artifact.vhd_size)) },
        .{ "virtual_size", release.azure_compute.integer(@intCast(expected.source.artifact.virtual_size)) },
    });
    const source_acceptance = try release.azure_compute.object(allocator, &.{
        .{ "schema", release.azure_compute.integer(1) },
        .{ "type", release.azure_compute.string(source_acceptance_type) },
        .{ "workflow", try workflowValue(
            allocator,
            expected.source.repository,
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
        .{ "evidence", try evidenceValue(allocator, evidence) },
        .{ "final_acceptance", final_acceptance },
        .{ "gallery", gallery },
        .{ "location", release.azure_compute.string(expected.location) },
        .{ "release", release.azure_compute.string("24.04") },
        .{ "schema", release.azure_compute.integer(schema) },
        .{ "source", source_value },
        .{ "subscription_id", release.azure_compute.string(expected.subscription_id) },
        .{ "type", release.azure_compute.string(result_type) },
        .{ "workflow", try workflowValue(
            allocator,
            expected.repository,
            expected.run_id,
            expected.run_attempt,
        ) },
    });
}

fn jsonEqual(left: Value, right: Value) bool {
    if (std.meta.activeTag(left) != std.meta.activeTag(right)) return false;
    return switch (left) {
        .null => true,
        .bool => |value| value == right.bool,
        .integer => |value| value == right.integer,
        .float => |value| value == right.float,
        .number_string => |value| std.mem.eql(u8, value, right.number_string),
        .string => |value| std.mem.eql(u8, value, right.string),
        .array => |items| blk: {
            if (items.items.len != right.array.items.len) break :blk false;
            for (items.items, right.array.items) |left_item, right_item| {
                if (!jsonEqual(left_item, right_item)) break :blk false;
            }
            break :blk true;
        },
        .object => |map| blk: {
            if (map.count() != right.object.count()) break :blk false;
            var iterator = map.iterator();
            while (iterator.next()) |entry| {
                const right_value = right.object.get(entry.key_ptr.*) orelse
                    break :blk false;
                if (!jsonEqual(entry.value_ptr.*, right_value)) break :blk false;
            }
            break :blk true;
        },
    };
}

pub fn validateResult(
    allocator: Allocator,
    root: *const ObjectMap,
    documents: Documents,
    expected: Expected,
    attestation: Attestation,
    evidence: Evidence,
    diagnostic: *Diagnostic,
) !void {
    const independently_derived = try result(
        allocator,
        documents,
        expected,
        attestation,
        evidence,
        diagnostic,
    );
    if (!jsonEqual(.{ .object = root.* }, independently_derived)) return invalid(
        diagnostic,
        "capture result does not match independently validated external evidence",
        .{},
    );
}

test "Azure capture resource IDs are structural and exact" {
    const subscription = "00000000-0000-0000-0000-000000000000";
    const snapshot =
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/capture/providers/Microsoft.Compute/snapshots/os";
    const definition =
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gallery/providers/Microsoft.Compute/galleries/g/images/ubuntu";
    var diagnostic: Diagnostic = .{};
    try validateSnapshotId(snapshot, subscription, &diagnostic);
    const invalid_snapshots = [_][]const u8{
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/capture/providers/Microsoft.Compute/disks/os",
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/capture/providers/Microsoft.Network/virtualNetworks/os",
        "subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/capture/providers/Microsoft.Compute/snapshots/os",
        "prefix" ++ snapshot,
        snapshot ++ "/extra",
        "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/capture/providers/Microsoft.Compute/snapshots/os",
        "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/capture/providers/Microsoft.Compute/snapshotsEvil/os",
    };
    for (invalid_snapshots) |invalid_snapshot| {
        diagnostic = .{};
        try std.testing.expectError(
            error.InvalidDocument,
            validateSnapshotId(invalid_snapshot, subscription, &diagnostic),
        );
    }
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

    const invalid_pairs = [_][2][]const u8{
        .{
            definition,
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gallery/providers/Microsoft.Compute/galleries/other/images/ubuntu/versions/1.0.0",
        },
        .{
            definition,
            "/subscriptions/11111111-1111-1111-1111-111111111111/resourceGroups/gallery/providers/Microsoft.Compute/galleries/g/images/ubuntu/versions/1.0.0",
        },
        .{ definition, definition ++ "/versions/1.0" },
        .{ definition, definition ++ "/versions/1.0.0/extra" },
        .{ definition, definition ++ "-evil/versions/1.0.0" },
        .{
            definition,
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gallery/providers/Microsoft.Compute/galleries/g/images/Ubuntu/versions/1.0.0",
        },
    };
    for (invalid_pairs) |pair| {
        diagnostic = .{};
        try std.testing.expectError(error.InvalidDocument, validateCaptureGalleryIds(
            pair[0],
            pair[1],
            subscription,
            &diagnostic,
        ));
    }
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
            .repository = repository,
            .commit = "0123456789abcdef0123456789abcdef01234567",
            .location = "eastus2",
            .vm_size = "Standard_DC2as_v5",
            .run_id = "123",
            .run_attempt = "1",
            .artifact = .{
                .qcow_sha256 = "1" ** 64,
                .qcow_size = 1024,
                .vhd_sha256 = "2" ** 64,
                .vhd_size = 4096,
                .virtual_size = 3584,
            },
        },
        .repository = repository,
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
        .attestation_endpoint = "https://test.attest.azure.net",
    };
}

fn testEvidence() Evidence {
    return .{
        .source_acceptance_sha256 = release.digest.hexBytes("source acceptance"),
        .source_provenance_sha256 = release.digest.hexBytes("source provenance"),
        .capture_vm_sha256 = release.digest.hexBytes("capture VM"),
        .capture_vm_instance_sha256 = release.digest.hexBytes("capture VM instance"),
        .capture_disk_sha256 = release.digest.hexBytes("capture disk"),
        .snapshot_sha256 = release.digest.hexBytes("snapshot"),
        .image_definition_sha256 = release.digest.hexBytes("image definition"),
        .gallery_request_sha256 = release.digest.hexBytes("gallery request"),
        .gallery_response_sha256 = release.digest.hexBytes("gallery response"),
        .final_vm_sha256 = release.digest.hexBytes("final VM"),
        .final_vm_instance_sha256 = release.digest.hexBytes("final VM instance"),
        .token_sha256 = release.digest.hexBytes("MAA token"),
        .openid_sha256 = release.digest.hexBytes("OpenID configuration"),
        .jwks_sha256 = release.digest.hexBytes("JWKS"),
        .nonce_sha256 = release.digest.hexBytes("nonce"),
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

const test_vm_instance_document =
    "{\"securityType\":\"ConfidentialVM\",\"uefiSettings\":" ++
    "{\"secureBootEnabled\":true,\"vTpmEnabled\":true}}";

fn expectTamper(
    allocator: Allocator,
    valid: []const u8,
    needle: []const u8,
    replacement: []const u8,
    documents: Documents,
    attestation: Attestation,
    evidence: Evidence,
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
        documents,
        testExpected(),
        attestation,
        evidence,
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
    var capture_vm_instance = try std.json.parseFromSlice(
        Value,
        allocator,
        test_vm_instance_document,
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
    var final_vm_instance = try std.json.parseFromSlice(
        Value,
        allocator,
        test_vm_instance_document,
        .{},
    );
    const documents: Documents = .{
        .source_acceptance = &source.value.object,
        .capture_vm = &capture_vm.value.object,
        .capture_vm_instance = &capture_vm_instance.value.object,
        .capture_disk = &capture_disk.value.object,
        .snapshot = &snapshot.value.object,
        .image_definition = &definition.value.object,
        .gallery_request = &request.object,
        .gallery_response = &response.value.object,
        .final_vm = &final_vm.value.object,
        .final_vm_instance = &final_vm_instance.value.object,
    };
    const attestation: Attestation = .{
        .vm_id = test_final_vm_id,
        .issuer = "https://test.attest.azure.net",
    };
    const evidence = testEvidence();
    var diagnostic: Diagnostic = .{};
    const valid_value = try result(
        allocator,
        documents,
        testExpected(),
        attestation,
        evidence,
        &diagnostic,
    );
    try validateResult(
        allocator,
        &valid_value.object,
        documents,
        testExpected(),
        attestation,
        evidence,
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
        documents,
        attestation,
        evidence,
    );

    const digest_needle = try std.fmt.allocPrint(
        allocator,
        "\"capture_vm_sha256\":\"{s}\"",
        .{&evidence.capture_vm_sha256},
    );
    const digest_replacement = try std.fmt.allocPrint(
        allocator,
        "\"capture_vm_sha256\":\"{s}\"",
        .{&release.digest.hexBytes("substituted capture VM digest")},
    );
    try expectTamper(
        allocator,
        valid,
        digest_needle,
        digest_replacement,
        documents,
        attestation,
        evidence,
    );

    var changed_file_evidence = evidence;
    changed_file_evidence.capture_vm_sha256 =
        release.digest.hexBytes("changed capture VM file");
    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, validateResult(
        allocator,
        &valid_value.object,
        documents,
        testExpected(),
        attestation,
        changed_file_evidence,
        &diagnostic,
    ));

    const coordinated_final = try std.mem.replaceOwned(
        u8,
        allocator,
        valid,
        test_final_vm_id,
        "33333333-3333-3333-3333-333333333333",
    );
    try std.testing.expectEqual(
        @as(usize, 2),
        std.mem.count(u8, valid, test_final_vm_id),
    );
    var coordinated = try std.json.parseFromSlice(
        Value,
        allocator,
        coordinated_final,
        .{},
    );
    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, validateResult(
        allocator,
        &coordinated.value.object,
        documents,
        testExpected(),
        attestation,
        evidence,
        &diagnostic,
    ));

    const replaced_final_document = try std.mem.replaceOwned(
        u8,
        allocator,
        test_final_vm_document,
        test_final_vm_id,
        "33333333-3333-3333-3333-333333333333",
    );
    var replaced_final_vm = try std.json.parseFromSlice(
        Value,
        allocator,
        replaced_final_document,
        .{},
    );
    var replaced_documents = documents;
    replaced_documents.final_vm = &replaced_final_vm.value.object;
    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, validateResult(
        allocator,
        &coordinated.value.object,
        replaced_documents,
        testExpected(),
        attestation,
        evidence,
        &diagnostic,
    ));

    const substituted_final_resource =
        test_prefix ++ "virtualMachines/substituted-final";
    const substituted_result = try std.mem.replaceOwned(
        u8,
        allocator,
        valid,
        test_final_vm,
        substituted_final_resource,
    );
    var substituted_result_document = try std.json.parseFromSlice(
        Value,
        allocator,
        substituted_result,
        .{},
    );
    const substituted_final_vm_document = try std.mem.replaceOwned(
        u8,
        allocator,
        test_final_vm_document,
        test_final_vm,
        substituted_final_resource,
    );
    var substituted_final_vm = try std.json.parseFromSlice(
        Value,
        allocator,
        substituted_final_vm_document,
        .{},
    );
    var substituted_documents = documents;
    substituted_documents.final_vm = &substituted_final_vm.value.object;
    var substituted_evidence = evidence;
    substituted_evidence.final_vm_sha256 =
        release.digest.hexBytes(substituted_final_vm_document);
    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, validateResult(
        allocator,
        &substituted_result_document.value.object,
        substituted_documents,
        testExpected(),
        attestation,
        substituted_evidence,
        &diagnostic,
    ));

    try expectTamper(
        allocator,
        valid,
        test_capture_vm_id,
        "44444444-4444-4444-4444-444444444444",
        documents,
        attestation,
        evidence,
    );
}
