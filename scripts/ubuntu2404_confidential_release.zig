//! Validate and bind Ubuntu 24.04 Confidential VM acceptance artifacts.
//!
//! The acceptance runner does not trust a decoded JWT or Azure resource
//! metadata in isolation. This tool re-hashes the built image, validates the
//! derived fixed VHD, checks every Confidential VM resource contract, verifies
//! the nonce-bound MAA JWT against the endpoint's HTTPS-fetched JWKS, and emits
//! one acceptance result binding the complete chain.

const std = @import("std");
const miz = @import("miz");
const release = @import("release/root.zig");
const azure_vhd = @import("azure_vhd.zig");
const capture = @import("ubuntu2404_confidential_capture.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;
const Dir = std.Io.Dir;
const Writer = std.Io.Writer;
const Diagnostic = release.contract.Diagnostic;
const ObjectMap = std.json.ObjectMap;
const Value = std.json.Value;
const Sha256 = std.crypto.hash.sha2.Sha256;
const rsa = std.crypto.Certificate.rsa;

const usage_exit_code = 2;
const failure_exit_code = 1;
const document_max_bytes = 1024 * 1024;
const token_max_bytes = 256 * 1024;
const artifact_max_bytes = release.azure_confidential_vm.maximum_vhd_current_size +
    azure_vhd.footer_bytes;
const expected_build_type = "miz-ubuntu2404-confidential-build-provenance";
const conversion_type = "miz-ubuntu2404-confidential-vhd-conversion";
const acceptance_type = "miz-ubuntu2404-confidential-azure-acceptance";

const usage_text =
    \\usage: ubuntu2404_confidential_release <command> [--option value]...
    \\
    \\Ubuntu 24.04 Confidential VM acceptance:
    \\  verify-build           verify the QCOW2 against build provenance
    \\  verify-vhd             validate and bind the derived fixed VHD
    \\  check-sku              require an exact x64 AMD SEV-SNP VM SKU
    \\  check-managed-disk     require the uploaded Linux Gen2 managed disk
    \\  check-managed-image    bind a Gen2 managed image to the uploaded disk
    \\  check-image-definition require ConfidentialVMSupported
    \\  gallery-request        write the stock-trust gallery-version request
    \\  gallery-state          print a gallery version's provisioning state
    \\  check-gallery          bind the gallery version to the managed disk
    \\  check-vm               require ConfidentialVM, VMGuestStateOnly, Secure Boot, and vTPM
    \\  acceptance-result      verify MAA attestation and write the bound result
    \\  verify-acceptance      revalidate the exact protected acceptance result for publication
    \\  check-capture-vm       bind a fresh capture VM to the accepted source version
    \\  check-capture-disk     validate the capture VM managed OS disk
    \\  check-capture-snapshot validate the immutable same-region disk snapshot
    \\  check-capture-definition require the exact full ConfidentialVM definition
    \\  capture-gallery-request write the full ConfidentialVM gallery-version request
    \\  capture-gallery-state  print capture gallery provisioning/replication state
    \\  check-capture-gallery  validate the exact completed full gallery version
    \\  check-captured-vm      validate inherited security on a VM from the full version
    \\  capture-result         write durable source-to-capture provenance with signed MAA evidence
    \\  verify-capture         independently revalidate protected capture provenance
    \\
    \\verify-capture requires independently supplied workflow identities and every
    \\raw evidence file. Azure ARM, OpenID, and JWKS file authenticity must come
    \\from fresh HTTPS/OIDC retrieval by the protected workflow immediately before
    \\invocation; this CLI validates and tamper-evidently binds file contents but
    \\does not authenticate their transport origin.
    \\
;

const ArgumentError = error{Usage};

const Options = struct {
    const capacity = 40;

    names: [capacity][]const u8 = undefined,
    values: [capacity][]const u8 = undefined,
    count: usize = 0,

    fn get(self: *const Options, name: []const u8) ?[]const u8 {
        for (self.names[0..self.count], self.values[0..self.count]) |actual, value| {
            if (std.mem.eql(u8, actual, name)) return value;
        }
        return null;
    }

    fn require(self: *const Options, name: []const u8) ArgumentError![]const u8 {
        return self.get(name) orelse error.Usage;
    }

    fn requireInteger(self: *const Options, name: []const u8) ArgumentError!i64 {
        return std.fmt.parseInt(i64, try self.require(name), 10) catch error.Usage;
    }
};

fn parseOptions(
    argv: []const []const u8,
    allowed: []const []const u8,
) ArgumentError!Options {
    var options: Options = .{};
    var index: usize = 0;
    while (index < argv.len) : (index += 1) {
        const argument = argv[index];
        if (!std.mem.startsWith(u8, argument, "--")) return error.Usage;
        const body = argument[2..];
        const separator = std.mem.indexOfScalar(u8, body, '=');
        const name = if (separator) |at| body[0..at] else body;
        var accepted = false;
        for (allowed) |candidate| {
            if (std.mem.eql(u8, name, candidate)) accepted = true;
        }
        if (!accepted or options.count == Options.capacity) return error.Usage;
        const value = if (separator) |at| body[at + 1 ..] else blk: {
            index += 1;
            if (index >= argv.len) return error.Usage;
            break :blk argv[index];
        };
        options.names[options.count] = name;
        options.values[options.count] = value;
        options.count += 1;
    }
    return options;
}

const Context = struct {
    allocator: Allocator,
    io: Io,
    out: *Writer,
    diagnostic: *Diagnostic,
};

const Command = struct {
    name: []const u8,
    handler: *const fn (Context, []const []const u8) anyerror!void,
};

const command_table = [_]Command{
    .{ .name = "verify-build", .handler = runVerifyBuild },
    .{ .name = "verify-vhd", .handler = runVerifyVhd },
    .{ .name = "check-sku", .handler = runCheckSku },
    .{ .name = "check-managed-disk", .handler = runCheckManagedDisk },
    .{ .name = "check-managed-image", .handler = runCheckManagedImage },
    .{ .name = "check-image-definition", .handler = runCheckImageDefinition },
    .{ .name = "gallery-request", .handler = runGalleryRequest },
    .{ .name = "gallery-state", .handler = runGalleryState },
    .{ .name = "check-gallery", .handler = runCheckGallery },
    .{ .name = "check-vm", .handler = runCheckVm },
    .{ .name = "acceptance-result", .handler = runAcceptanceResult },
    .{ .name = "verify-acceptance", .handler = runVerifyAcceptance },
    .{ .name = "check-capture-vm", .handler = runCheckCaptureVm },
    .{ .name = "check-capture-disk", .handler = runCheckCaptureDisk },
    .{ .name = "check-capture-snapshot", .handler = runCheckCaptureSnapshot },
    .{ .name = "check-capture-definition", .handler = runCheckCaptureDefinition },
    .{ .name = "capture-gallery-request", .handler = runCaptureGalleryRequest },
    .{ .name = "capture-gallery-state", .handler = runCaptureGalleryState },
    .{ .name = "check-capture-gallery", .handler = runCheckCaptureGallery },
    .{ .name = "check-captured-vm", .handler = runCheckCapturedVm },
    .{ .name = "capture-result", .handler = runCaptureResult },
    .{ .name = "verify-capture", .handler = runVerifyCapture },
};

fn run(context: Context, argv: []const []const u8) !void {
    if (argv.len == 0) return error.Usage;
    for (command_table) |command| {
        if (std.mem.eql(u8, command.name, argv[0])) {
            return command.handler(context, argv[1..]);
        }
    }
    return error.Usage;
}

fn invalid(
    diagnostic: *Diagnostic,
    comptime message: []const u8,
    args: anytype,
) error{InvalidDocument} {
    return diagnostic.fail(error.InvalidDocument, message, args);
}

fn readObject(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) !release.json_document.Document {
    return release.json_document.readObject(
        allocator,
        io,
        path,
        document_max_bytes,
        diagnostic,
    );
}

fn requireObject(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !ObjectMap {
    return release.azure_compute.objectOf(parent.get(name)) orelse
        invalid(diagnostic, "{s} is not an object", .{label});
}

fn requireArray(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) ![]const Value {
    return release.azure_compute.arrayOf(parent.get(name)) orelse
        invalid(diagnostic, "{s} is not an array", .{label});
}

fn requireString(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) ![]const u8 {
    return release.json_document.requireString(parent, name, label, diagnostic);
}

fn requireInteger(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !i64 {
    return release.json_document.requireInteger(parent, name, label, diagnostic);
}

fn requireTrue(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!release.azure_compute.isTrue(parent.get(name))) {
        return invalid(diagnostic, "{s} is not true", .{label});
    }
}

fn requireFalse(
    parent: *const ObjectMap,
    name: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    const value = parent.get(name) orelse
        return invalid(diagnostic, "{s} is absent", .{label});
    if (value != .bool or value.bool) {
        return invalid(diagnostic, "{s} is not false", .{label});
    }
}

fn requireEqual(
    actual: []const u8,
    expected: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!std.mem.eql(u8, actual, expected)) {
        return invalid(diagnostic, "{s} mismatch", .{label});
    }
}

fn positiveU64(
    value: i64,
    label: []const u8,
    diagnostic: *Diagnostic,
) !u64 {
    if (value <= 0) return invalid(diagnostic, "{s} is invalid", .{label});
    return @intCast(value);
}

const BuildEvidence = struct {
    qcow_sha256: release.digest.Hex,
    qcow_size: u64,
    virtual_size: u64,
};

fn verifyBuild(
    allocator: Allocator,
    io: Io,
    provenance_path: []const u8,
    qcow_path: []const u8,
    diagnostic: *Diagnostic,
) !BuildEvidence {
    var document = try readObject(allocator, io, provenance_path, diagnostic);
    defer document.deinit();
    const root = document.object();
    if (try requireInteger(root, "schema", "build provenance schema", diagnostic) != 1) {
        return invalid(diagnostic, "build provenance schema is invalid", .{});
    }
    try requireEqual(
        try requireString(root, "type", "build provenance type", diagnostic),
        expected_build_type,
        "build provenance type",
        diagnostic,
    );
    try requireEqual(
        try requireString(root, "release", "build release", diagnostic),
        "24.04",
        "build release",
        diagnostic,
    );
    try requireEqual(
        try requireString(root, "architecture", "build architecture", diagnostic),
        "x86_64",
        "build architecture",
        diagnostic,
    );
    try requireEqual(
        try requireString(root, "tee", "build TEE", diagnostic),
        "AMD SEV-SNP",
        "build TEE",
        diagnostic,
    );
    const publication = try requireObject(
        root,
        "publication",
        "build publication",
        diagnostic,
    );
    try requireTrue(
        &publication,
        "sha256sums_signature_verified",
        "Canonical publication signature",
        diagnostic,
    );
    const guest = try requireObject(root, "guest_contract", "guest contract", diagnostic);
    try requireTrue(&guest, "generalized", "generalized guest contract", diagnostic);
    const candidate = try requireObject(root, "candidate", "build candidate", diagnostic);
    try requireEqual(
        try requireString(&candidate, "format", "candidate format", diagnostic),
        "standalone-qcow2",
        "candidate format",
        diagnostic,
    );

    const expected_sha = try requireString(
        &candidate,
        "sha256",
        "candidate SHA-256",
        diagnostic,
    );
    _ = release.digest.parseHex(expected_sha) catch
        return invalid(diagnostic, "candidate SHA-256 is invalid", .{});
    const expected_size = try positiveU64(
        try requireInteger(&candidate, "size", "candidate size", diagnostic),
        "candidate size",
        diagnostic,
    );
    const virtual_size = try positiveU64(
        try requireInteger(
            &candidate,
            "virtual_size",
            "candidate virtual size",
            diagnostic,
        ),
        "candidate virtual size",
        diagnostic,
    );
    if (virtual_size >= release.azure_confidential_vm.maximum_vhd_current_size) {
        return invalid(
            diagnostic,
            "candidate virtual size is not eligible for ConfidentialVMSupported",
            .{},
        );
    }
    const observed = try release.digest.hashFile(io, qcow_path, artifact_max_bytes);
    if (observed.size != expected_size or
        !std.mem.eql(u8, &observed.hex, expected_sha))
    {
        return invalid(
            diagnostic,
            "QCOW2 does not match its signed-source build provenance",
            .{},
        );
    }
    return .{
        .qcow_sha256 = observed.hex,
        .qcow_size = observed.size,
        .virtual_size = virtual_size,
    };
}

fn runVerifyBuild(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "provenance", "qcow" });
    const evidence = try verifyBuild(
        context.allocator,
        context.io,
        try options.require("provenance"),
        try options.require("qcow"),
        context.diagnostic,
    );
    try context.out.print("{s}\n{d}\n{d}\n", .{
        &evidence.qcow_sha256,
        evidence.qcow_size,
        evidence.virtual_size,
    });
}

const VhdEvidence = struct {
    qcow_sha256: release.digest.Hex,
    vhd_sha256: release.digest.Hex,
    virtual_size: u64,
    vhd_size: u64,
};

fn verifyVhd(
    allocator: Allocator,
    io: Io,
    provenance_path: []const u8,
    qcow_path: []const u8,
    vhd_path: []const u8,
    info_path: []const u8,
    diagnostic: *Diagnostic,
) !VhdEvidence {
    const build = try verifyBuild(
        allocator,
        io,
        provenance_path,
        qcow_path,
        diagnostic,
    );
    var vhd_context: azure_vhd.Context = .{};
    const inspection = azure_vhd.inspect(
        allocator,
        io,
        info_path,
        vhd_path,
        &vhd_context,
    ) catch |err| {
        if (vhd_context.message().len != 0) {
            diagnostic.set("{s}", .{vhd_context.message()});
        }
        return err;
    };
    try release.azure_confidential_vm.validateVhdSize(
        build.virtual_size,
        inspection.current_size,
        inspection.file_size,
        diagnostic,
    );
    const observed = try release.digest.hashFile(io, vhd_path, artifact_max_bytes);
    if (observed.size != inspection.file_size) {
        return invalid(diagnostic, "derived VHD changed during validation", .{});
    }
    return .{
        .qcow_sha256 = build.qcow_sha256,
        .vhd_sha256 = observed.hex,
        .virtual_size = inspection.current_size,
        .vhd_size = inspection.file_size,
    };
}

fn conversionDocument(
    allocator: Allocator,
    evidence: VhdEvidence,
) !Value {
    return release.azure_compute.object(allocator, &.{
        .{ "qcow_sha256", release.azure_compute.string(&evidence.qcow_sha256) },
        .{ "schema", release.azure_compute.integer(1) },
        .{ "type", release.azure_compute.string(conversion_type) },
        .{ "vhd_sha256", release.azure_compute.string(&evidence.vhd_sha256) },
        .{ "vhd_size", release.azure_compute.integer(@intCast(evidence.vhd_size)) },
        .{ "virtual_size", release.azure_compute.integer(@intCast(evidence.virtual_size)) },
    });
}

fn runVerifyVhd(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(
        argv,
        &.{ "provenance", "qcow", "vhd", "info", "output" },
    );
    const evidence = try verifyVhd(
        context.allocator,
        context.io,
        try options.require("provenance"),
        try options.require("qcow"),
        try options.require("vhd"),
        try options.require("info"),
        context.diagnostic,
    );
    const document = try conversionDocument(context.allocator, evidence);
    try release.json_document.writeDocument(
        context.allocator,
        context.io,
        try options.require("output"),
        document,
    );
    try context.out.print("{d}\n{d}\n{s}\n", .{
        evidence.virtual_size,
        evidence.vhd_size,
        &evidence.vhd_sha256,
    });
}

fn selectedSku(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    vm_size: []const u8,
    diagnostic: *Diagnostic,
) !release.azure_confidential_vm.Sku {
    const bytes = try release.file.readBounded(
        allocator,
        io,
        path,
        document_max_bytes,
    );
    defer allocator.free(bytes);
    var parsed = std.json.parseFromSlice(Value, allocator, bytes, .{}) catch
        return invalid(diagnostic, "Azure SKU response is invalid JSON", .{});
    defer parsed.deinit();
    if (parsed.value != .array) {
        return invalid(diagnostic, "Azure SKU response is not an array", .{});
    }
    var match: ?release.azure_confidential_vm.Sku = null;
    for (parsed.value.array.items) |entry| {
        if (entry != .object or
            !release.azure_compute.stringIs(entry.object.get("name"), vm_size))
        {
            continue;
        }
        if (match != null) {
            return invalid(diagnostic, "Azure SKU response is ambiguous", .{});
        }
        match = try release.azure_confidential_vm.validateSku(
            &entry.object,
            vm_size,
            diagnostic,
        );
    }
    return match orelse invalid(
        diagnostic,
        "configured Azure Confidential VM SKU is unavailable",
        .{},
    );
}

fn runCheckSku(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "sku", "vm-size" });
    const sku = try selectedSku(
        context.allocator,
        context.io,
        try options.require("sku"),
        try options.require("vm-size"),
        context.diagnostic,
    );
    try context.out.print("{s}\n", .{
        if (sku.has_temporary_storage) "true" else "false",
    });
}

fn managedDiskId(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) ![]u8 {
    var document = try readObject(allocator, io, path, diagnostic);
    defer document.deinit();
    const id = try release.azure_confidential_vm.validateManagedDisk(
        document.object(),
        diagnostic,
    );
    return allocator.dupe(u8, id);
}

fn runCheckManagedDisk(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"disk"});
    const id = try managedDiskId(
        context.allocator,
        context.io,
        try options.require("disk"),
        context.diagnostic,
    );
    defer context.allocator.free(id);
    try context.out.print("{s}\n", .{id});
}

fn managedImageId(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    disk_id: []const u8,
    diagnostic: *Diagnostic,
) ![]u8 {
    var document = try readObject(allocator, io, path, diagnostic);
    defer document.deinit();
    const id = try release.azure_confidential_vm.validateManagedImage(
        document.object(),
        disk_id,
        diagnostic,
    );
    return allocator.dupe(u8, id);
}

fn runCheckManagedImage(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "image", "disk-id" });
    const id = try managedImageId(
        context.allocator,
        context.io,
        try options.require("image"),
        try options.require("disk-id"),
        context.diagnostic,
    );
    defer context.allocator.free(id);
    try context.out.print("{s}\n", .{id});
}

fn imageDefinitionId(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    diagnostic: *Diagnostic,
) ![]u8 {
    var document = try readObject(allocator, io, path, diagnostic);
    defer document.deinit();
    const id = try release.azure_confidential_vm.validateImageDefinition(
        document.object(),
        diagnostic,
    );
    return allocator.dupe(u8, id);
}

fn runCheckImageDefinition(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"definition"});
    const id = try imageDefinitionId(
        context.allocator,
        context.io,
        try options.require("definition"),
        context.diagnostic,
    );
    defer context.allocator.free(id);
    try context.out.print("{s}\n", .{id});
}

fn runGalleryRequest(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{ "output", "location", "source-id" });
    const request = try release.azure_confidential_vm.galleryVersionRequest(
        context.allocator,
        try options.require("location"),
        try options.require("source-id"),
    );
    try release.json_document.writeDocument(
        context.allocator,
        context.io,
        try options.require("output"),
        request,
    );
}

fn runGalleryState(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"response"});
    var response = try readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer response.deinit();
    const properties = release.azure_compute.objectOf(
        response.object().get("properties"),
    ) orelse {
        try context.out.writeByte('\n');
        return;
    };
    try context.out.print("{s}\n", .{
        release.azure_compute.stringOf(properties.get("provisioningState")) orelse "",
    });
}

fn checkGallery(
    allocator: Allocator,
    io: Io,
    request_path: []const u8,
    response_path: []const u8,
    image_version_id: []const u8,
    disk_id: []const u8,
    diagnostic: *Diagnostic,
) !void {
    var request = try readObject(allocator, io, request_path, diagnostic);
    defer request.deinit();
    var response = try readObject(allocator, io, response_path, diagnostic);
    defer response.deinit();
    try release.azure_confidential_vm.validateGalleryVersion(
        request.object(),
        response.object(),
        image_version_id,
        disk_id,
        true,
        diagnostic,
    );
}

fn runCheckGallery(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(
        argv,
        &.{ "request", "response", "image-version-id", "source-id" },
    );
    try checkGallery(
        context.allocator,
        context.io,
        try options.require("request"),
        try options.require("response"),
        try options.require("image-version-id"),
        try options.require("source-id"),
        context.diagnostic,
    );
}

const VmEvidence = struct {
    resource_id: []u8,
    vm_id: []u8,

    fn deinit(self: *VmEvidence, allocator: Allocator) void {
        allocator.free(self.resource_id);
        allocator.free(self.vm_id);
        self.* = undefined;
    }
};

fn checkVm(
    allocator: Allocator,
    io: Io,
    resource_path: []const u8,
    instance_path: []const u8,
    image_version_id: []const u8,
    diagnostic: *Diagnostic,
) !VmEvidence {
    var resource = try readObject(allocator, io, resource_path, diagnostic);
    defer resource.deinit();
    var instance = try readObject(allocator, io, instance_path, diagnostic);
    defer instance.deinit();

    const security = try requireObject(
        resource.object(),
        "securityProfile",
        "VM resource security profile",
        diagnostic,
    );
    try release.azure_confidential_vm.validateVmSecurityProfile(
        &security,
        "VM resource",
        diagnostic,
    );
    try release.azure_confidential_vm.validateVmSecurityProfile(
        instance.object(),
        "VM instance view",
        diagnostic,
    );
    const disk_security = try requireObject(
        resource.object(),
        "osDiskSecurityProfile",
        "OS disk security profile",
        diagnostic,
    );
    try release.azure_confidential_vm.validateOsDiskSecurityProfile(
        &disk_security,
        "VM resource",
        diagnostic,
    );
    const image = try requireObject(
        resource.object(),
        "imageReference",
        "VM image reference",
        diagnostic,
    );
    const actual_image = try requireString(
        &image,
        "id",
        "VM image-version ID",
        diagnostic,
    );
    if (!std.ascii.eqlIgnoreCase(actual_image, image_version_id)) {
        return invalid(
            diagnostic,
            "VM does not reference the accepted gallery image version",
            .{},
        );
    }
    const resource_id = try requireString(
        resource.object(),
        "id",
        "VM resource ID",
        diagnostic,
    );
    const vm_id = try requireString(
        resource.object(),
        "vmId",
        "Azure VM ID",
        diagnostic,
    );
    if (!validGuid(vm_id)) return invalid(diagnostic, "Azure VM ID is invalid", .{});
    return .{
        .resource_id = try allocator.dupe(u8, resource_id),
        .vm_id = try allocator.dupe(u8, vm_id),
    };
}

fn runCheckVm(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(
        argv,
        &.{ "resource", "instance", "image-version-id" },
    );
    var evidence = try checkVm(
        context.allocator,
        context.io,
        try options.require("resource"),
        try options.require("instance"),
        try options.require("image-version-id"),
        context.diagnostic,
    );
    defer evidence.deinit(context.allocator);
    try context.out.print("{s}\n{s}\n", .{ evidence.resource_id, evidence.vm_id });
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

fn validCommit(text: []const u8) bool {
    if (text.len != 40) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

fn validEndpoint(endpoint: []const u8) bool {
    const prefix = "https://";
    const suffix = ".attest.azure.net";
    if (!std.mem.startsWith(u8, endpoint, prefix) or
        !std.mem.endsWith(u8, endpoint, suffix))
    {
        return false;
    }
    const host = endpoint[prefix.len .. endpoint.len - suffix.len];
    if (host.len == 0) return false;
    for (host) |character| switch (character) {
        'a'...'z', '0'...'9', '-', '.' => {},
        else => return false,
    };
    return true;
}

fn validPositiveDecimal(text: []const u8) bool {
    if (text.len == 0 or text[0] == '0') return false;
    for (text) |character| switch (character) {
        '0'...'9' => {},
        else => return false,
    };
    return true;
}

fn decodeUrlAlloc(
    allocator: Allocator,
    encoded: []const u8,
    max_bytes: usize,
) ![]u8 {
    const size = std.base64.url_safe_no_pad.Decoder.calcSizeForSlice(encoded) catch
        return error.InvalidJwt;
    if (size == 0 or size > max_bytes) return error.InvalidJwt;
    const decoded = try allocator.alloc(u8, size);
    errdefer allocator.free(decoded);
    std.base64.url_safe_no_pad.Decoder.decode(decoded, encoded) catch
        return error.InvalidJwt;
    return decoded;
}

fn decodeStandardAlloc(
    allocator: Allocator,
    encoded: []const u8,
    max_bytes: usize,
) ![]u8 {
    const size = std.base64.standard.Decoder.calcSizeForSlice(encoded) catch
        return error.InvalidJwt;
    if (size == 0 or size > max_bytes) return error.InvalidJwt;
    const decoded = try allocator.alloc(u8, size);
    errdefer allocator.free(decoded);
    std.base64.standard.Decoder.decode(decoded, encoded) catch
        return error.InvalidJwt;
    return decoded;
}

const AttestationEvidence = struct {
    token_sha256: release.digest.Hex,
    nonce_sha256: release.digest.Hex,
    issuer: []const u8,
};

fn verifyJwtSignature(
    allocator: Allocator,
    header_segment: []const u8,
    payload_segment: []const u8,
    signature_segment: []const u8,
    header: *const ObjectMap,
    jwks: *const ObjectMap,
    diagnostic: *Diagnostic,
) !void {
    try requireEqual(
        try requireString(header, "alg", "JWT algorithm", diagnostic),
        "RS256",
        "JWT algorithm",
        diagnostic,
    );
    const kid = try requireString(header, "kid", "JWT key ID", diagnostic);
    const keys = try requireArray(jwks, "keys", "MAA JWKS keys", diagnostic);
    var selected: ?ObjectMap = null;
    for (keys) |entry| {
        if (entry != .object or
            !release.azure_compute.stringIs(entry.object.get("kid"), kid))
        {
            continue;
        }
        if (selected != null) {
            return invalid(diagnostic, "MAA JWKS key ID is ambiguous", .{});
        }
        selected = entry.object;
    }
    const key = selected orelse
        return invalid(diagnostic, "MAA JWT signing key was not found", .{});
    try requireEqual(
        try requireString(&key, "alg", "JWK algorithm", diagnostic),
        "RS256",
        "JWK algorithm",
        diagnostic,
    );
    try requireEqual(
        try requireString(&key, "kty", "JWK key type", diagnostic),
        "RSA",
        "JWK key type",
        diagnostic,
    );
    try requireEqual(
        try requireString(&key, "use", "JWK use", diagnostic),
        "sig",
        "JWK use",
        diagnostic,
    );
    const modulus = try decodeUrlAlloc(
        allocator,
        try requireString(&key, "n", "JWK modulus", diagnostic),
        512,
    );
    defer allocator.free(modulus);
    const exponent = try decodeUrlAlloc(
        allocator,
        try requireString(&key, "e", "JWK exponent", diagnostic),
        8,
    );
    defer allocator.free(exponent);
    const signature = try decodeUrlAlloc(allocator, signature_segment, 512);
    defer allocator.free(signature);
    if (modulus.len < 256 or signature.len != modulus.len) {
        return invalid(diagnostic, "MAA JWT RSA key or signature size is invalid", .{});
    }
    const public_key = rsa.PublicKey.fromBytes(exponent, modulus) catch
        return invalid(diagnostic, "MAA JWT RSA public key is invalid", .{});
    inline for (.{ 256, 384, 512 }) |candidate| {
        if (signature.len == candidate) {
            var buffer: [candidate]u8 = undefined;
            @memcpy(&buffer, signature);
            rsa.PKCS1v1_5Signature.concatVerify(
                candidate,
                buffer,
                &.{ header_segment, ".", payload_segment },
                public_key,
                Sha256,
            ) catch return invalid(diagnostic, "MAA JWT signature is invalid", .{});
            return;
        }
    }
    return invalid(diagnostic, "MAA JWT RSA signature size is unsupported", .{});
}

fn verifyAttestationClaims(
    allocator: Allocator,
    root: *const ObjectMap,
    endpoint: []const u8,
    nonce: []const u8,
    vm_id: []const u8,
    now: i64,
    diagnostic: *Diagnostic,
) !void {
    try requireEqual(
        try requireString(root, "iss", "MAA JWT issuer", diagnostic),
        endpoint,
        "MAA JWT issuer",
        diagnostic,
    );
    const runtime = try requireObject(
        root,
        "x-ms-runtime",
        "MAA runtime claims",
        diagnostic,
    );
    const client_payload = try requireObject(
        &runtime,
        "client-payload",
        "MAA client payload",
        diagnostic,
    );
    const encoded_nonce = try requireString(
        &client_payload,
        "nonce",
        "MAA JWT nonce",
        diagnostic,
    );
    const attested_nonce = decodeStandardAlloc(
        allocator,
        encoded_nonce,
        128,
    ) catch return invalid(diagnostic, "MAA JWT nonce encoding is invalid", .{});
    defer allocator.free(attested_nonce);
    if (!std.mem.eql(u8, attested_nonce, nonce)) {
        return invalid(diagnostic, "MAA JWT nonce mismatch", .{});
    }
    const issued = try requireInteger(root, "iat", "MAA JWT issued time", diagnostic);
    const not_before = try requireInteger(root, "nbf", "MAA JWT not-before time", diagnostic);
    const expires = try requireInteger(root, "exp", "MAA JWT expiry", diagnostic);
    if (issued > now + 300 or not_before > now + 300 or expires < now or
        expires <= issued or expires - issued > 24 * 60 * 60)
    {
        return invalid(diagnostic, "MAA JWT validity interval is invalid", .{});
    }
    const token_vm_id = try requireString(
        root,
        "x-ms-azurevm-vmid",
        "attested Azure VM ID",
        diagnostic,
    );
    if (!std.ascii.eqlIgnoreCase(token_vm_id, vm_id)) {
        return invalid(diagnostic, "attested Azure VM identity mismatch", .{});
    }
    try requireTrue(root, "secureboot", "attested Secure Boot state", diagnostic);
    try requireFalse(
        root,
        "x-ms-azurevm-bootdebug-enabled",
        "attested boot-debug state",
        diagnostic,
    );
    try requireTrue(
        root,
        "x-ms-azurevm-debuggersdisabled",
        "attested debugger-disabled state",
        diagnostic,
    );
    const tee = try requireObject(
        root,
        "x-ms-isolation-tee",
        "MAA isolation TEE claims",
        diagnostic,
    );
    try requireEqual(
        try requireString(&tee, "x-ms-attestation-type", "TEE type", diagnostic),
        "sevsnpvm",
        "TEE type",
        diagnostic,
    );
    try requireEqual(
        try requireString(&tee, "x-ms-compliance-status", "TEE compliance", diagnostic),
        "azure-compliant-cvm",
        "TEE compliance",
        diagnostic,
    );
    try requireFalse(
        &tee,
        "x-ms-sevsnpvm-is-debuggable",
        "SEV-SNP debuggable state",
        diagnostic,
    );
    try requireFalse(
        &tee,
        "x-ms-sevsnpvm-migration-allowed",
        "SEV-SNP migration state",
        diagnostic,
    );
    if (try requireInteger(&tee, "x-ms-sevsnpvm-vmpl", "SEV-SNP VMPL", diagnostic) != 0) {
        return invalid(diagnostic, "SEV-SNP VMPL is not zero", .{});
    }
    const tee_runtime = try requireObject(
        &tee,
        "x-ms-runtime",
        "TEE runtime claims",
        diagnostic,
    );
    const configuration = try requireObject(
        &tee_runtime,
        "vm-configuration",
        "attested VM configuration",
        diagnostic,
    );
    try requireTrue(
        &configuration,
        "secure-boot",
        "attested VM Secure Boot configuration",
        diagnostic,
    );
    try requireTrue(
        &configuration,
        "tpm-enabled",
        "attested VM vTPM configuration",
        diagnostic,
    );
    const unique_id = try requireString(
        &configuration,
        "vmUniqueId",
        "attested VM unique ID",
        diagnostic,
    );
    if (!std.ascii.eqlIgnoreCase(unique_id, vm_id)) {
        return invalid(diagnostic, "attested VM configuration identity mismatch", .{});
    }
}

fn verifyAttestation(
    allocator: Allocator,
    io: Io,
    token_path: []const u8,
    openid_path: []const u8,
    jwks_path: []const u8,
    endpoint: []const u8,
    nonce: []const u8,
    vm_id: []const u8,
    now: i64,
    diagnostic: *Diagnostic,
) !AttestationEvidence {
    if (!validEndpoint(endpoint)) {
        return invalid(diagnostic, "MAA endpoint is not an Azure Attestation endpoint", .{});
    }
    if (nonce.len < 32 or nonce.len > 128) {
        return invalid(diagnostic, "attestation nonce length is invalid", .{});
    }
    if (!validGuid(vm_id) or now <= 0) {
        return invalid(diagnostic, "attestation identity or time is invalid", .{});
    }
    const token_bytes = try release.file.readBounded(
        allocator,
        io,
        token_path,
        token_max_bytes,
    );
    defer allocator.free(token_bytes);
    const token = std.mem.trim(u8, token_bytes, " \t\r\n");
    if (token.len != token_bytes.len) {
        return invalid(diagnostic, "MAA token contains surrounding whitespace", .{});
    }
    var segments = std.mem.splitScalar(u8, token, '.');
    const header_segment = segments.next() orelse return error.InvalidJwt;
    const payload_segment = segments.next() orelse return error.InvalidJwt;
    const signature_segment = segments.next() orelse return error.InvalidJwt;
    if (segments.next() != null) return error.InvalidJwt;

    const header_bytes = try decodeUrlAlloc(allocator, header_segment, token_max_bytes);
    defer allocator.free(header_bytes);
    const payload_bytes = try decodeUrlAlloc(allocator, payload_segment, token_max_bytes);
    defer allocator.free(payload_bytes);
    var header = std.json.parseFromSlice(Value, allocator, header_bytes, .{}) catch
        return invalid(diagnostic, "MAA JWT header is invalid", .{});
    defer header.deinit();
    var claims = std.json.parseFromSlice(Value, allocator, payload_bytes, .{}) catch
        return invalid(diagnostic, "MAA JWT claims are invalid", .{});
    defer claims.deinit();
    if (header.value != .object or claims.value != .object) {
        return invalid(diagnostic, "MAA JWT header or claims are not objects", .{});
    }

    var openid = try readObject(allocator, io, openid_path, diagnostic);
    defer openid.deinit();
    try requireEqual(
        try requireString(openid.object(), "issuer", "OpenID issuer", diagnostic),
        endpoint,
        "OpenID issuer",
        diagnostic,
    );
    const expected_jwks = try std.fmt.allocPrint(allocator, "{s}/certs", .{endpoint});
    defer allocator.free(expected_jwks);
    try requireEqual(
        try requireString(openid.object(), "jwks_uri", "OpenID JWKS URI", diagnostic),
        expected_jwks,
        "OpenID JWKS URI",
        diagnostic,
    );
    var jwks = try readObject(allocator, io, jwks_path, diagnostic);
    defer jwks.deinit();
    try verifyJwtSignature(
        allocator,
        header_segment,
        payload_segment,
        signature_segment,
        &header.value.object,
        jwks.object(),
        diagnostic,
    );

    try verifyAttestationClaims(
        allocator,
        &claims.value.object,
        endpoint,
        nonce,
        vm_id,
        now,
        diagnostic,
    );
    return .{
        .token_sha256 = release.digest.hexBytes(token),
        .nonce_sha256 = release.digest.hexBytes(nonce),
        .issuer = endpoint,
    };
}

fn readConversion(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    build: BuildEvidence,
    diagnostic: *Diagnostic,
) !VhdEvidence {
    var document = try readObject(allocator, io, path, diagnostic);
    defer document.deinit();
    const root = document.object();
    if (root.count() != 6 or
        try requireInteger(root, "schema", "conversion schema", diagnostic) != 1)
    {
        return invalid(diagnostic, "VHD conversion document shape is invalid", .{});
    }
    try requireEqual(
        try requireString(root, "type", "conversion type", diagnostic),
        conversion_type,
        "conversion type",
        diagnostic,
    );
    const qcow_sha = try requireString(root, "qcow_sha256", "QCOW2 SHA-256", diagnostic);
    const vhd_sha = try requireString(root, "vhd_sha256", "VHD SHA-256", diagnostic);
    _ = release.digest.parseHex(qcow_sha) catch
        return invalid(diagnostic, "conversion QCOW2 SHA-256 is invalid", .{});
    _ = release.digest.parseHex(vhd_sha) catch
        return invalid(diagnostic, "conversion VHD SHA-256 is invalid", .{});
    if (!std.mem.eql(u8, qcow_sha, &build.qcow_sha256)) {
        return invalid(diagnostic, "conversion does not bind the accepted QCOW2", .{});
    }
    const virtual_size = try positiveU64(
        try requireInteger(root, "virtual_size", "conversion virtual size", diagnostic),
        "conversion virtual size",
        diagnostic,
    );
    const vhd_size = try positiveU64(
        try requireInteger(root, "vhd_size", "conversion VHD size", diagnostic),
        "conversion VHD size",
        diagnostic,
    );
    try release.azure_confidential_vm.validateVhdSize(
        build.virtual_size,
        virtual_size,
        vhd_size,
        diagnostic,
    );
    return .{
        .qcow_sha256 = build.qcow_sha256,
        .vhd_sha256 = release.digest.hex(
            try release.digest.parseHex(vhd_sha),
        ),
        .virtual_size = virtual_size,
        .vhd_size = vhd_size,
    };
}

fn runAcceptanceResult(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "provenance",
        "qcow",
        "conversion",
        "sku",
        "vm-size",
        "disk",
        "managed-image",
        "definition",
        "gallery-request",
        "gallery-response",
        "image-version-id",
        "vm-resource",
        "vm-instance",
        "token",
        "openid",
        "jwks",
        "endpoint",
        "nonce",
        "now",
        "guest-vm-id",
        "source-commit",
        "location",
        "resource-group",
        "output",
    });
    const source_commit = try options.require("source-commit");
    if (!validCommit(source_commit)) return error.Usage;
    const location = try options.require("location");
    const resource_group = try options.require("resource-group");
    const vm_size = try options.require("vm-size");
    const image_version_id = try options.require("image-version-id");
    const guest_vm_id = try options.require("guest-vm-id");

    const build = try verifyBuild(
        context.allocator,
        context.io,
        try options.require("provenance"),
        try options.require("qcow"),
        context.diagnostic,
    );
    const conversion = try readConversion(
        context.allocator,
        context.io,
        try options.require("conversion"),
        build,
        context.diagnostic,
    );
    _ = try selectedSku(
        context.allocator,
        context.io,
        try options.require("sku"),
        vm_size,
        context.diagnostic,
    );
    const disk_id = try managedDiskId(
        context.allocator,
        context.io,
        try options.require("disk"),
        context.diagnostic,
    );
    defer context.allocator.free(disk_id);
    const managed_image_id = try managedImageId(
        context.allocator,
        context.io,
        try options.require("managed-image"),
        disk_id,
        context.diagnostic,
    );
    defer context.allocator.free(managed_image_id);
    const definition_id = try imageDefinitionId(
        context.allocator,
        context.io,
        try options.require("definition"),
        context.diagnostic,
    );
    defer context.allocator.free(definition_id);
    if (!std.mem.startsWith(u8, image_version_id, definition_id) or
        image_version_id.len <= definition_id.len or
        image_version_id[definition_id.len] != '/')
    {
        return invalid(
            context.diagnostic,
            "gallery image version is outside the accepted image definition",
            .{},
        );
    }
    try checkGallery(
        context.allocator,
        context.io,
        try options.require("gallery-request"),
        try options.require("gallery-response"),
        image_version_id,
        managed_image_id,
        context.diagnostic,
    );
    var vm = try checkVm(
        context.allocator,
        context.io,
        try options.require("vm-resource"),
        try options.require("vm-instance"),
        image_version_id,
        context.diagnostic,
    );
    defer vm.deinit(context.allocator);
    if (!std.ascii.eqlIgnoreCase(vm.vm_id, guest_vm_id)) {
        return invalid(context.diagnostic, "guest IMDS VM identity mismatch", .{});
    }
    const attestation = try verifyAttestation(
        context.allocator,
        context.io,
        try options.require("token"),
        try options.require("openid"),
        try options.require("jwks"),
        try options.require("endpoint"),
        try options.require("nonce"),
        vm.vm_id,
        try options.requireInteger("now"),
        context.diagnostic,
    );

    const attestation_value = try release.azure_compute.object(context.allocator, &.{
        .{ "compliance", release.azure_compute.string("azure-compliant-cvm") },
        .{ "debuggable", .{ .bool = false } },
        .{ "issuer", release.azure_compute.string(attestation.issuer) },
        .{ "nonce_sha256", release.azure_compute.string(&attestation.nonce_sha256) },
        .{ "secure_boot", .{ .bool = true } },
        .{ "tee", release.azure_compute.string("AMD SEV-SNP") },
        .{ "token_sha256", release.azure_compute.string(&attestation.token_sha256) },
        .{ "vtpm", .{ .bool = true } },
    });
    const artifact = try release.azure_compute.object(context.allocator, &.{
        .{ "qcow_sha256", release.azure_compute.string(&build.qcow_sha256) },
        .{ "qcow_size", release.azure_compute.integer(@intCast(build.qcow_size)) },
        .{ "vhd_sha256", release.azure_compute.string(&conversion.vhd_sha256) },
        .{ "vhd_size", release.azure_compute.integer(@intCast(conversion.vhd_size)) },
        .{ "virtual_size", release.azure_compute.integer(@intCast(conversion.virtual_size)) },
    });
    const azure = try release.azure_compute.object(context.allocator, &.{
        .{ "gallery_image_version_id", release.azure_compute.string(image_version_id) },
        .{ "location", release.azure_compute.string(location) },
        .{ "managed_disk_id", release.azure_compute.string(disk_id) },
        .{ "managed_image_id", release.azure_compute.string(managed_image_id) },
        .{ "resource_group", release.azure_compute.string(resource_group) },
        .{ "vm_id", release.azure_compute.string(vm.vm_id) },
        .{ "vm_resource_id", release.azure_compute.string(vm.resource_id) },
        .{ "vm_size", release.azure_compute.string(vm_size) },
    });
    const result = try release.azure_compute.object(context.allocator, &.{
        .{ "artifact", artifact },
        .{ "attestation", attestation_value },
        .{ "azure", azure },
        .{ "schema", release.azure_compute.integer(1) },
        .{ "source_commit", release.azure_compute.string(source_commit) },
        .{ "type", release.azure_compute.string(acceptance_type) },
    });
    try release.json_document.writeDocument(
        context.allocator,
        context.io,
        try options.require("output"),
        result,
    );
}

fn requireBoundAzureId(
    allocator: Allocator,
    id: []const u8,
    resource_group: []const u8,
    resource_type: []const u8,
    label: []const u8,
    diagnostic: *Diagnostic,
) !void {
    if (!std.mem.startsWith(u8, id, "/subscriptions/")) {
        return invalid(diagnostic, "{s} is not an Azure resource ID", .{label});
    }
    const group_segment = try std.fmt.allocPrint(
        allocator,
        "/resourceGroups/{s}/providers/Microsoft.Compute/",
        .{resource_group},
    );
    defer allocator.free(group_segment);
    if (std.mem.indexOf(u8, id, group_segment) == null or
        std.mem.indexOf(u8, id, resource_type) == null)
    {
        return invalid(
            diagnostic,
            "{s} is outside the accepted resource group or has the wrong type",
            .{label},
        );
    }
}

fn verifyAcceptanceResult(
    allocator: Allocator,
    io: Io,
    result_path: []const u8,
    provenance_path: []const u8,
    qcow_path: []const u8,
    source_commit: []const u8,
    location: []const u8,
    vm_size: []const u8,
    run_id: []const u8,
    run_attempt: []const u8,
    diagnostic: *Diagnostic,
) !BuildEvidence {
    if (!validCommit(source_commit) or
        !validPositiveDecimal(run_id) or
        !validPositiveDecimal(run_attempt))
    {
        return error.Usage;
    }
    const build = try verifyBuild(
        allocator,
        io,
        provenance_path,
        qcow_path,
        diagnostic,
    );
    var document = try readObject(allocator, io, result_path, diagnostic);
    defer document.deinit();
    const root = document.object();
    if (root.count() != 6 or
        try requireInteger(root, "schema", "acceptance schema", diagnostic) != 1)
    {
        return invalid(diagnostic, "acceptance result shape is invalid", .{});
    }
    try requireEqual(
        try requireString(root, "type", "acceptance type", diagnostic),
        acceptance_type,
        "acceptance type",
        diagnostic,
    );
    try requireEqual(
        try requireString(root, "source_commit", "acceptance source commit", diagnostic),
        source_commit,
        "acceptance source commit",
        diagnostic,
    );

    const artifact = try requireObject(root, "artifact", "accepted artifact", diagnostic);
    if (artifact.count() != 5) {
        return invalid(diagnostic, "accepted artifact shape is invalid", .{});
    }
    const qcow_sha = try requireString(
        &artifact,
        "qcow_sha256",
        "accepted QCOW2 SHA-256",
        diagnostic,
    );
    _ = release.digest.parseHex(qcow_sha) catch
        return invalid(diagnostic, "accepted QCOW2 SHA-256 is invalid", .{});
    try requireEqual(
        qcow_sha,
        &build.qcow_sha256,
        "accepted QCOW2 SHA-256",
        diagnostic,
    );
    const qcow_size = try positiveU64(
        try requireInteger(&artifact, "qcow_size", "accepted QCOW2 size", diagnostic),
        "accepted QCOW2 size",
        diagnostic,
    );
    if (qcow_size != build.qcow_size) {
        return invalid(diagnostic, "accepted QCOW2 size mismatch", .{});
    }
    const virtual_size = try positiveU64(
        try requireInteger(&artifact, "virtual_size", "accepted virtual size", diagnostic),
        "accepted virtual size",
        diagnostic,
    );
    const vhd_size = try positiveU64(
        try requireInteger(&artifact, "vhd_size", "accepted VHD size", diagnostic),
        "accepted VHD size",
        diagnostic,
    );
    _ = release.digest.parseHex(try requireString(
        &artifact,
        "vhd_sha256",
        "accepted VHD SHA-256",
        diagnostic,
    )) catch return invalid(diagnostic, "accepted VHD SHA-256 is invalid", .{});
    try release.azure_confidential_vm.validateVhdSize(
        build.virtual_size,
        virtual_size,
        vhd_size,
        diagnostic,
    );

    const attestation = try requireObject(
        root,
        "attestation",
        "accepted attestation",
        diagnostic,
    );
    if (attestation.count() != 8) {
        return invalid(diagnostic, "accepted attestation shape is invalid", .{});
    }
    try requireEqual(
        try requireString(&attestation, "compliance", "attestation compliance", diagnostic),
        "azure-compliant-cvm",
        "attestation compliance",
        diagnostic,
    );
    try requireFalse(&attestation, "debuggable", "attestation debuggable state", diagnostic);
    const issuer = try requireString(
        &attestation,
        "issuer",
        "attestation issuer",
        diagnostic,
    );
    if (!validEndpoint(issuer)) {
        return invalid(diagnostic, "attestation issuer is invalid", .{});
    }
    _ = release.digest.parseHex(try requireString(
        &attestation,
        "nonce_sha256",
        "attestation nonce SHA-256",
        diagnostic,
    )) catch return invalid(diagnostic, "attestation nonce SHA-256 is invalid", .{});
    try requireTrue(&attestation, "secure_boot", "attested Secure Boot state", diagnostic);
    try requireEqual(
        try requireString(&attestation, "tee", "attestation TEE", diagnostic),
        "AMD SEV-SNP",
        "attestation TEE",
        diagnostic,
    );
    _ = release.digest.parseHex(try requireString(
        &attestation,
        "token_sha256",
        "attestation token SHA-256",
        diagnostic,
    )) catch return invalid(diagnostic, "attestation token SHA-256 is invalid", .{});
    try requireTrue(&attestation, "vtpm", "attested vTPM state", diagnostic);

    const azure = try requireObject(root, "azure", "accepted Azure resources", diagnostic);
    if (azure.count() != 8) {
        return invalid(diagnostic, "accepted Azure resource shape is invalid", .{});
    }
    try requireEqual(
        try requireString(&azure, "location", "accepted Azure location", diagnostic),
        location,
        "accepted Azure location",
        diagnostic,
    );
    try requireEqual(
        try requireString(&azure, "vm_size", "accepted Azure VM size", diagnostic),
        vm_size,
        "accepted Azure VM size",
        diagnostic,
    );
    const expected_group = try std.fmt.allocPrint(
        allocator,
        "miz-u2404-cvm-{s}-{s}",
        .{ run_id, run_attempt },
    );
    defer allocator.free(expected_group);
    try requireEqual(
        try requireString(&azure, "resource_group", "accepted resource group", diagnostic),
        expected_group,
        "accepted resource group",
        diagnostic,
    );
    try requireBoundAzureId(
        allocator,
        try requireString(&azure, "managed_disk_id", "accepted managed disk", diagnostic),
        expected_group,
        "/disks/",
        "accepted managed disk",
        diagnostic,
    );
    try requireBoundAzureId(
        allocator,
        try requireString(&azure, "managed_image_id", "accepted managed image", diagnostic),
        expected_group,
        "/images/",
        "accepted managed image",
        diagnostic,
    );
    try requireBoundAzureId(
        allocator,
        try requireString(
            &azure,
            "gallery_image_version_id",
            "accepted gallery image version",
            diagnostic,
        ),
        expected_group,
        "/galleries/",
        "accepted gallery image version",
        diagnostic,
    );
    try requireBoundAzureId(
        allocator,
        try requireString(&azure, "vm_resource_id", "accepted VM resource", diagnostic),
        expected_group,
        "/virtualMachines/",
        "accepted VM resource",
        diagnostic,
    );
    if (!validGuid(try requireString(&azure, "vm_id", "accepted VM ID", diagnostic))) {
        return invalid(diagnostic, "accepted VM ID is invalid", .{});
    }
    return build;
}

fn runVerifyAcceptance(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "result",
        "provenance",
        "qcow",
        "source-commit",
        "location",
        "vm-size",
        "run-id",
        "run-attempt",
    });
    const build = try verifyAcceptanceResult(
        context.allocator,
        context.io,
        try options.require("result"),
        try options.require("provenance"),
        try options.require("qcow"),
        try options.require("source-commit"),
        try options.require("location"),
        try options.require("vm-size"),
        try options.require("run-id"),
        try options.require("run-attempt"),
        context.diagnostic,
    );
    try context.out.print("{s}\n{d}\n{d}\n", .{
        &build.qcow_sha256,
        build.qcow_size,
        build.virtual_size,
    });
}

fn captureContract(options: *const Options) !release.azure_confidential_vm.CaptureContract {
    return .{
        .subscription_id = try options.require("subscription-id"),
        .location = try options.require("location"),
        .source_image_version_id = try options.require("source-version-id"),
        .vm_id = try options.require("vm-id"),
        .disk_id = try options.require("disk-id"),
    };
}

fn verifiedSourceVersion(
    context: Context,
    options: *const Options,
) ![]u8 {
    try requireEqual(
        try options.require("repository"),
        capture.repository,
        "source workflow repository",
        context.diagnostic,
    );
    _ = try verifyAcceptanceResult(
        context.allocator,
        context.io,
        try options.require("source-acceptance"),
        try options.require("provenance"),
        try options.require("qcow"),
        try options.require("source-commit"),
        try options.require("location"),
        try options.require("vm-size"),
        try options.require("run-id"),
        try options.require("run-attempt"),
        context.diagnostic,
    );
    var acceptance = try readObject(
        context.allocator,
        context.io,
        try options.require("source-acceptance"),
        context.diagnostic,
    );
    defer acceptance.deinit();
    const azure = try requireObject(
        acceptance.object(),
        "azure",
        "source acceptance Azure evidence",
        context.diagnostic,
    );
    const version_id = try requireString(
        &azure,
        "gallery_image_version_id",
        "source gallery image version",
        context.diagnostic,
    );
    try capture.validateSourceVersionId(
        version_id,
        try options.require("subscription-id"),
        context.diagnostic,
    );
    return context.allocator.dupe(u8, version_id);
}

fn runCheckCaptureVm(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "vm",
        "source-acceptance",
        "provenance",
        "qcow",
        "source-commit",
        "vm-size",
        "run-id",
        "run-attempt",
        "repository",
        "subscription-id",
        "location",
        "vm-id",
        "disk-id",
    });
    const source_version_id = try verifiedSourceVersion(context, &options);
    defer context.allocator.free(source_version_id);
    var document = try readObject(
        context.allocator,
        context.io,
        try options.require("vm"),
        context.diagnostic,
    );
    defer document.deinit();
    try release.azure_confidential_vm.validateCaptureVm(
        document.object(),
        .{
            .subscription_id = try options.require("subscription-id"),
            .location = try options.require("location"),
            .source_image_version_id = source_version_id,
            .vm_id = try options.require("vm-id"),
            .disk_id = try options.require("disk-id"),
        },
        context.diagnostic,
    );
    try context.out.print("{s}\n{s}\n", .{
        try requireString(document.object(), "id", "capture VM ID", context.diagnostic),
        try requireString(document.object(), "vmId", "capture VM identity", context.diagnostic),
    });
}

fn runCheckCaptureDisk(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "disk",
        "subscription-id",
        "location",
        "source-version-id",
        "vm-id",
        "disk-id",
    });
    var document = try readObject(
        context.allocator,
        context.io,
        try options.require("disk"),
        context.diagnostic,
    );
    defer document.deinit();
    const id = try release.azure_confidential_vm.validateCaptureManagedDisk(
        document.object(),
        try captureContract(&options),
        context.diagnostic,
    );
    try context.out.print("{s}\n", .{id});
}

fn runCheckCaptureSnapshot(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "snapshot",
        "snapshot-id",
        "subscription-id",
        "location",
        "source-version-id",
        "vm-id",
        "disk-id",
    });
    var document = try readObject(
        context.allocator,
        context.io,
        try options.require("snapshot"),
        context.diagnostic,
    );
    defer document.deinit();
    const id = try release.azure_confidential_vm.validateCaptureSnapshot(
        document.object(),
        try options.require("snapshot-id"),
        try captureContract(&options),
        context.diagnostic,
    );
    try context.out.print("{s}\n", .{id});
}

fn captureGalleryContract(
    options: *const Options,
    diagnostic: *Diagnostic,
) !release.azure_confidential_vm.CaptureGalleryContract {
    const contract: release.azure_confidential_vm.CaptureGalleryContract = .{
        .subscription_id = try options.require("subscription-id"),
        .location = try options.require("location"),
        .source_id = try options.require("snapshot-id"),
        .image_definition_id = try options.require("definition-id"),
        .image_version_id = try options.require("version-id"),
    };
    try capture.validateSnapshotId(
        contract.source_id,
        contract.subscription_id,
        diagnostic,
    );
    try capture.validateCaptureGalleryIds(
        contract.image_definition_id,
        contract.image_version_id,
        contract.subscription_id,
        diagnostic,
    );
    return contract;
}

fn runCheckCaptureDefinition(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "definition",
        "subscription-id",
        "location",
        "snapshot-id",
        "definition-id",
        "version-id",
    });
    var document = try readObject(
        context.allocator,
        context.io,
        try options.require("definition"),
        context.diagnostic,
    );
    defer document.deinit();
    const id = try release.azure_confidential_vm.validateCapturedImageDefinition(
        document.object(),
        try captureGalleryContract(&options, context.diagnostic),
        context.diagnostic,
    );
    try context.out.print("{s}\n", .{id});
}

fn runCaptureGalleryRequest(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "output",
        "subscription-id",
        "location",
        "snapshot-id",
        "definition-id",
        "version-id",
    });
    const contract = try captureGalleryContract(&options, context.diagnostic);
    const request = try release.azure_confidential_vm.captureGalleryVersionRequest(
        context.allocator,
        try options.require("location"),
        try options.require("snapshot-id"),
    );
    try release.azure_confidential_vm.validateCaptureGalleryRequest(
        &request.object,
        contract,
        context.diagnostic,
    );
    try release.json_document.writeDocument(
        context.allocator,
        context.io,
        try options.require("output"),
        request,
    );
}

fn runCaptureGalleryState(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{"response"});
    var document = try readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer document.deinit();
    const properties = release.azure_compute.objectOf(
        document.object().get("properties"),
    );
    const provisioning = if (properties) |map|
        release.azure_compute.stringOf(map.get("provisioningState")) orelse ""
    else
        "";
    const replication = if (properties) |map| blk: {
        const status = release.azure_compute.objectOf(
            map.get("replicationStatus"),
        ) orelse break :blk "";
        break :blk release.azure_compute.stringOf(
            status.get("aggregatedState"),
        ) orelse "";
    } else "";
    try context.out.print("{s}\n{s}\n", .{ provisioning, replication });
}

fn runCheckCaptureGallery(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "request",
        "response",
        "subscription-id",
        "location",
        "snapshot-id",
        "definition-id",
        "version-id",
    });
    var request = try readObject(
        context.allocator,
        context.io,
        try options.require("request"),
        context.diagnostic,
    );
    defer request.deinit();
    var response = try readObject(
        context.allocator,
        context.io,
        try options.require("response"),
        context.diagnostic,
    );
    defer response.deinit();
    const contract = try captureGalleryContract(&options, context.diagnostic);
    try release.azure_confidential_vm.validateCaptureGalleryRequest(
        request.object(),
        contract,
        context.diagnostic,
    );
    try release.azure_confidential_vm.validateCapturedGalleryVersion(
        response.object(),
        contract,
        context.diagnostic,
    );
}

fn runCheckCapturedVm(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &.{
        "vm",
        "subscription-id",
        "location",
        "version-id",
        "vm-id",
        "disk-id",
    });
    var document = try readObject(
        context.allocator,
        context.io,
        try options.require("vm"),
        context.diagnostic,
    );
    defer document.deinit();
    try release.azure_confidential_vm.validateCapturedVm(
        document.object(),
        .{
            .subscription_id = try options.require("subscription-id"),
            .location = try options.require("location"),
            .source_image_version_id = try options.require("version-id"),
            .vm_id = try options.require("vm-id"),
            .disk_id = try options.require("disk-id"),
        },
        context.diagnostic,
    );
    try context.out.print("{s}\n{s}\n", .{
        try requireString(document.object(), "id", "final VM ID", context.diagnostic),
        try requireString(document.object(), "vmId", "final VM identity", context.diagnostic),
    });
}

const capture_result_options = [_][]const u8{
    "source-acceptance",
    "provenance",
    "qcow",
    "source-commit",
    "source-location",
    "source-vm-size",
    "source-run-id",
    "source-run-attempt",
    "source-repository",
    "subscription-id",
    "location",
    "repository",
    "run-id",
    "run-attempt",
    "capture-vm-id",
    "capture-disk-id",
    "snapshot-id",
    "definition-id",
    "version-id",
    "final-vm-id",
    "final-disk-id",
    "capture-vm",
    "capture-vm-instance",
    "capture-disk",
    "snapshot",
    "definition",
    "gallery-request",
    "gallery-response",
    "final-vm",
    "final-vm-instance",
    "token",
    "openid",
    "jwks",
    "endpoint",
    "nonce",
    "now",
    "guest-vm-id",
    "output",
};

const capture_verify_options = [_][]const u8{
    "source-acceptance",
    "provenance",
    "qcow",
    "source-commit",
    "source-location",
    "source-vm-size",
    "source-run-id",
    "source-run-attempt",
    "source-repository",
    "subscription-id",
    "location",
    "repository",
    "run-id",
    "run-attempt",
    "capture-vm-id",
    "capture-disk-id",
    "snapshot-id",
    "definition-id",
    "version-id",
    "final-vm-id",
    "final-disk-id",
    "capture-vm",
    "capture-vm-instance",
    "capture-disk",
    "snapshot",
    "definition",
    "gallery-request",
    "gallery-response",
    "final-vm",
    "final-vm-instance",
    "token",
    "openid",
    "jwks",
    "endpoint",
    "nonce",
    "now",
    "result",
};

fn captureExpected(
    options: *const Options,
    build: BuildEvidence,
    source_acceptance: *const ObjectMap,
    diagnostic: *Diagnostic,
) !capture.Expected {
    try requireEqual(
        try options.require("source-repository"),
        capture.repository,
        "source workflow repository",
        diagnostic,
    );
    try requireEqual(
        try options.require("repository"),
        capture.repository,
        "capture workflow repository",
        diagnostic,
    );
    const artifact = try requireObject(
        source_acceptance,
        "artifact",
        "accepted source artifact",
        diagnostic,
    );
    const qcow_size = try positiveU64(
        try requireInteger(&artifact, "qcow_size", "source QCOW2 size", diagnostic),
        "source QCOW2 size",
        diagnostic,
    );
    if (qcow_size != build.qcow_size) {
        return invalid(diagnostic, "source QCOW2 size mismatch", .{});
    }
    return .{
        .source = .{
            .repository = try options.require("source-repository"),
            .commit = try options.require("source-commit"),
            .location = try options.require("source-location"),
            .vm_size = try options.require("source-vm-size"),
            .run_id = try options.require("source-run-id"),
            .run_attempt = try options.require("source-run-attempt"),
            .artifact = .{
                .qcow_sha256 = &build.qcow_sha256,
                .qcow_size = qcow_size,
                .vhd_sha256 = try requireString(
                    &artifact,
                    "vhd_sha256",
                    "source VHD SHA-256",
                    diagnostic,
                ),
                .vhd_size = try positiveU64(
                    try requireInteger(&artifact, "vhd_size", "source VHD size", diagnostic),
                    "source VHD size",
                    diagnostic,
                ),
                .virtual_size = try positiveU64(
                    try requireInteger(
                        &artifact,
                        "virtual_size",
                        "source virtual size",
                        diagnostic,
                    ),
                    "source virtual size",
                    diagnostic,
                ),
            },
        },
        .repository = try options.require("repository"),
        .subscription_id = try options.require("subscription-id"),
        .location = try options.require("location"),
        .run_id = try options.require("run-id"),
        .run_attempt = try options.require("run-attempt"),
        .capture_vm_id = try options.require("capture-vm-id"),
        .capture_disk_id = try options.require("capture-disk-id"),
        .snapshot_id = try options.require("snapshot-id"),
        .image_definition_id = try options.require("definition-id"),
        .image_version_id = try options.require("version-id"),
        .final_vm_id = try options.require("final-vm-id"),
        .final_disk_id = try options.require("final-disk-id"),
        .attestation_endpoint = try options.require("endpoint"),
    };
}

fn verifiedCaptureInputs(
    context: Context,
    options: *const Options,
) !struct {
    build: BuildEvidence,
    acceptance_sha256: release.digest.Hex,
} {
    const build = try verifyAcceptanceResult(
        context.allocator,
        context.io,
        try options.require("source-acceptance"),
        try options.require("provenance"),
        try options.require("qcow"),
        try options.require("source-commit"),
        try options.require("source-location"),
        try options.require("source-vm-size"),
        try options.require("source-run-id"),
        try options.require("source-run-attempt"),
        context.diagnostic,
    );
    const acceptance_hash = try release.digest.hashFile(
        context.io,
        try options.require("source-acceptance"),
        document_max_bytes,
    );
    return .{
        .build = build,
        .acceptance_sha256 = acceptance_hash.hex,
    };
}

fn captureEvidence(
    context: Context,
    options: *const Options,
    source_acceptance_sha256: release.digest.Hex,
    attestation: AttestationEvidence,
) !capture.Evidence {
    return .{
        .source_acceptance_sha256 = source_acceptance_sha256,
        .source_provenance_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("provenance"),
            document_max_bytes,
        )).hex,
        .capture_vm_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("capture-vm"),
            document_max_bytes,
        )).hex,
        .capture_vm_instance_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("capture-vm-instance"),
            document_max_bytes,
        )).hex,
        .capture_disk_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("capture-disk"),
            document_max_bytes,
        )).hex,
        .snapshot_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("snapshot"),
            document_max_bytes,
        )).hex,
        .image_definition_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("definition"),
            document_max_bytes,
        )).hex,
        .gallery_request_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("gallery-request"),
            document_max_bytes,
        )).hex,
        .gallery_response_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("gallery-response"),
            document_max_bytes,
        )).hex,
        .final_vm_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("final-vm"),
            document_max_bytes,
        )).hex,
        .final_vm_instance_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("final-vm-instance"),
            document_max_bytes,
        )).hex,
        .token_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("token"),
            token_max_bytes,
        )).hex,
        .openid_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("openid"),
            document_max_bytes,
        )).hex,
        .jwks_sha256 = (try release.digest.hashFile(
            context.io,
            try options.require("jwks"),
            document_max_bytes,
        )).hex,
        .nonce_sha256 = attestation.nonce_sha256,
    };
}

fn runCaptureResult(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &capture_result_options);
    const verified = try verifiedCaptureInputs(context, &options);
    var source_acceptance = try readObject(
        context.allocator,
        context.io,
        try options.require("source-acceptance"),
        context.diagnostic,
    );
    defer source_acceptance.deinit();
    const expected = try captureExpected(
        &options,
        verified.build,
        source_acceptance.object(),
        context.diagnostic,
    );
    var capture_vm = try readObject(context.allocator, context.io, try options.require("capture-vm"), context.diagnostic);
    defer capture_vm.deinit();
    var capture_vm_instance = try readObject(context.allocator, context.io, try options.require("capture-vm-instance"), context.diagnostic);
    defer capture_vm_instance.deinit();
    var capture_disk = try readObject(context.allocator, context.io, try options.require("capture-disk"), context.diagnostic);
    defer capture_disk.deinit();
    var snapshot = try readObject(context.allocator, context.io, try options.require("snapshot"), context.diagnostic);
    defer snapshot.deinit();
    var definition = try readObject(context.allocator, context.io, try options.require("definition"), context.diagnostic);
    defer definition.deinit();
    var gallery_request = try readObject(context.allocator, context.io, try options.require("gallery-request"), context.diagnostic);
    defer gallery_request.deinit();
    var gallery_response = try readObject(context.allocator, context.io, try options.require("gallery-response"), context.diagnostic);
    defer gallery_response.deinit();
    var final_vm = try readObject(context.allocator, context.io, try options.require("final-vm"), context.diagnostic);
    defer final_vm.deinit();
    var final_vm_instance = try readObject(context.allocator, context.io, try options.require("final-vm-instance"), context.diagnostic);
    defer final_vm_instance.deinit();
    const guest_vm_id = try options.require("guest-vm-id");
    const attestation = try verifyAttestation(
        context.allocator,
        context.io,
        try options.require("token"),
        try options.require("openid"),
        try options.require("jwks"),
        try options.require("endpoint"),
        try options.require("nonce"),
        guest_vm_id,
        try options.requireInteger("now"),
        context.diagnostic,
    );
    const evidence = try captureEvidence(
        context,
        &options,
        verified.acceptance_sha256,
        attestation,
    );
    const result_document = try capture.result(
        context.allocator,
        .{
            .source_acceptance = source_acceptance.object(),
            .capture_vm = capture_vm.object(),
            .capture_vm_instance = capture_vm_instance.object(),
            .capture_disk = capture_disk.object(),
            .snapshot = snapshot.object(),
            .image_definition = definition.object(),
            .gallery_request = gallery_request.object(),
            .gallery_response = gallery_response.object(),
            .final_vm = final_vm.object(),
            .final_vm_instance = final_vm_instance.object(),
        },
        expected,
        .{
            .vm_id = guest_vm_id,
            .issuer = attestation.issuer,
        },
        evidence,
        context.diagnostic,
    );
    try release.json_document.writeDocument(
        context.allocator,
        context.io,
        try options.require("output"),
        result_document,
    );
}

fn runVerifyCapture(context: Context, argv: []const []const u8) !void {
    const options = try parseOptions(argv, &capture_verify_options);
    const verified = try verifiedCaptureInputs(context, &options);
    var source_acceptance = try readObject(
        context.allocator,
        context.io,
        try options.require("source-acceptance"),
        context.diagnostic,
    );
    defer source_acceptance.deinit();
    const expected = try captureExpected(
        &options,
        verified.build,
        source_acceptance.object(),
        context.diagnostic,
    );
    var result_document = try readObject(
        context.allocator,
        context.io,
        try options.require("result"),
        context.diagnostic,
    );
    defer result_document.deinit();
    var capture_vm = try readObject(context.allocator, context.io, try options.require("capture-vm"), context.diagnostic);
    defer capture_vm.deinit();
    var capture_vm_instance = try readObject(context.allocator, context.io, try options.require("capture-vm-instance"), context.diagnostic);
    defer capture_vm_instance.deinit();
    var capture_disk = try readObject(context.allocator, context.io, try options.require("capture-disk"), context.diagnostic);
    defer capture_disk.deinit();
    var snapshot = try readObject(context.allocator, context.io, try options.require("snapshot"), context.diagnostic);
    defer snapshot.deinit();
    var definition = try readObject(context.allocator, context.io, try options.require("definition"), context.diagnostic);
    defer definition.deinit();
    var gallery_request = try readObject(context.allocator, context.io, try options.require("gallery-request"), context.diagnostic);
    defer gallery_request.deinit();
    var gallery_response = try readObject(context.allocator, context.io, try options.require("gallery-response"), context.diagnostic);
    defer gallery_response.deinit();
    var final_vm = try readObject(context.allocator, context.io, try options.require("final-vm"), context.diagnostic);
    defer final_vm.deinit();
    var final_vm_instance = try readObject(context.allocator, context.io, try options.require("final-vm-instance"), context.diagnostic);
    defer final_vm_instance.deinit();
    const final_guest_vm_id = try capture.validateFinalVmEvidence(
        final_vm.object(),
        final_vm_instance.object(),
        expected,
        context.diagnostic,
    );
    const attestation = try verifyAttestation(
        context.allocator,
        context.io,
        try options.require("token"),
        try options.require("openid"),
        try options.require("jwks"),
        try options.require("endpoint"),
        try options.require("nonce"),
        final_guest_vm_id,
        try options.requireInteger("now"),
        context.diagnostic,
    );
    const evidence = try captureEvidence(
        context,
        &options,
        verified.acceptance_sha256,
        attestation,
    );
    try capture.validateResult(
        context.allocator,
        result_document.object(),
        .{
            .source_acceptance = source_acceptance.object(),
            .capture_vm = capture_vm.object(),
            .capture_vm_instance = capture_vm_instance.object(),
            .capture_disk = capture_disk.object(),
            .snapshot = snapshot.object(),
            .image_definition = definition.object(),
            .gallery_request = gallery_request.object(),
            .gallery_response = gallery_response.object(),
            .final_vm = final_vm.object(),
            .final_vm_instance = final_vm_instance.object(),
        },
        expected,
        .{
            .vm_id = final_guest_vm_id,
            .issuer = attestation.issuer,
        },
        evidence,
        context.diagnostic,
    );
    try context.out.print("{s}\n{s}\n", .{
        expected.image_version_id,
        &verified.acceptance_sha256,
    });
}

pub fn main(init: std.process.Init) !void {
    const io = init.io;
    var arena: std.heap.ArenaAllocator = .init(init.gpa);
    defer arena.deinit();
    const allocator = arena.allocator();
    const argv = try init.minimal.args.toSlice(allocator);

    var stdout_buffer: [16 * 1024]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;
    var stderr_buffer: [4096]u8 = undefined;
    var stderr_writer: std.Io.File.Writer = .init(.stderr(), io, &stderr_buffer);
    const err_out = &stderr_writer.interface;

    for (argv[1..]) |argument| {
        if (std.mem.eql(u8, argument, "-h") or std.mem.eql(u8, argument, "--help")) {
            try out.writeAll(usage_text);
            try out.flush();
            return;
        }
    }

    var diagnostic: Diagnostic = .{};
    run(.{
        .allocator = allocator,
        .io = io,
        .out = out,
        .diagnostic = &diagnostic,
    }, argv[1..]) catch |err| switch (err) {
        error.Usage => {
            try err_out.writeAll(usage_text);
            try err_out.flush();
            std.process.exit(usage_exit_code);
        },
        error.OutOfMemory => return err,
        else => {
            if (diagnostic.message().len != 0) {
                try err_out.print("{s}\n", .{diagnostic.message()});
            } else {
                try err_out.print("{s}\n", .{@errorName(err)});
            }
            try err_out.flush();
            std.process.exit(failure_exit_code);
        },
    };
    try out.flush();
}

test "command surface is exact and rejects incomplete invocations" {
    const names = [_][]const u8{
        "verify-build",
        "verify-vhd",
        "check-sku",
        "check-managed-disk",
        "check-managed-image",
        "check-image-definition",
        "gallery-request",
        "gallery-state",
        "check-gallery",
        "check-vm",
        "acceptance-result",
        "verify-acceptance",
        "check-capture-vm",
        "check-capture-disk",
        "check-capture-snapshot",
        "check-capture-definition",
        "capture-gallery-request",
        "capture-gallery-state",
        "check-capture-gallery",
        "check-captured-vm",
        "capture-result",
        "verify-capture",
    };
    try std.testing.expectEqual(names.len, command_table.len);
    var discard: Writer.Discarding = .init(&.{});
    var diagnostic: Diagnostic = .{};
    const context: Context = .{
        .allocator = std.testing.allocator,
        .io = std.testing.io,
        .out = &discard.writer,
        .diagnostic = &diagnostic,
    };
    for (command_table, names) |command, name| {
        try std.testing.expectEqualStrings(name, command.name);
        try std.testing.expect(std.mem.indexOf(u8, usage_text, name) != null);
        try std.testing.expectError(error.Usage, run(context, &.{name}));
    }
}

test "capture evidence digests track raw file bytes" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const path = try testFixturePath(allocator, &tmp.sub_path, "evidence.json");
    defer allocator.free(path);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = "{\"version\":1}\n",
    });
    const argv = [_][]const u8{
        "--provenance",          path,
        "--capture-vm",          path,
        "--capture-vm-instance", path,
        "--capture-disk",        path,
        "--snapshot",            path,
        "--definition",          path,
        "--gallery-request",     path,
        "--gallery-response",    path,
        "--final-vm",            path,
        "--final-vm-instance",   path,
        "--token",               path,
        "--openid",              path,
        "--jwks",                path,
    };
    const options = try parseOptions(&argv, &capture_verify_options);
    var discard: Writer.Discarding = .init(&.{});
    var diagnostic: Diagnostic = .{};
    const context: Context = .{
        .allocator = allocator,
        .io = std.testing.io,
        .out = &discard.writer,
        .diagnostic = &diagnostic,
    };
    const attestation: AttestationEvidence = .{
        .token_sha256 = release.digest.hexBytes("token"),
        .nonce_sha256 = release.digest.hexBytes("nonce"),
        .issuer = "https://test.attest.azure.net",
    };
    const first = try captureEvidence(
        context,
        &options,
        release.digest.hexBytes("source acceptance"),
        attestation,
    );
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = "{\"version\":2}\n",
    });
    const second = try captureEvidence(
        context,
        &options,
        release.digest.hexBytes("source acceptance"),
        attestation,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.capture_vm_sha256,
        &second.capture_vm_sha256,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.openid_sha256,
        &second.openid_sha256,
    ));
}

test "attestation endpoint commit and VM identities are strict" {
    try std.testing.expect(validEndpoint(
        "https://sharedeus2.eus2.attest.azure.net",
    ));
    try std.testing.expect(!validEndpoint(
        "http://sharedeus2.eus2.attest.azure.net",
    ));
    try std.testing.expect(!validEndpoint(
        "https://sharedeus2.eus2.attest.azure.net/other",
    ));
    try std.testing.expect(validGuid("2DEDC52A-6832-46CE-9910-E8C9980BF5A7"));
    try std.testing.expect(!validGuid("2DEDC52A-6832-46CE-9910"));
    try std.testing.expect(validCommit("0123456789abcdef0123456789abcdef01234567"));
    try std.testing.expect(!validCommit("0123456789ABCDEF0123456789ABCDEF01234567"));
}

test "publication revalidates the protected acceptance binding" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const candidate_path = try testFixturePath(allocator, &tmp.sub_path, "candidate.qcow2");
    defer allocator.free(candidate_path);
    const provenance_path = try testFixturePath(allocator, &tmp.sub_path, "provenance.json");
    defer allocator.free(provenance_path);
    const result_path = try testFixturePath(allocator, &tmp.sub_path, "acceptance.json");
    defer allocator.free(result_path);
    const candidate = "publication candidate fixture\n";
    const qcow_sha = release.digest.hexBytes(candidate);
    const commit = "0123456789abcdef0123456789abcdef01234567";
    const virtual_size = 4 * 1024 * 1024;
    const vhd_size = virtual_size + azure_vhd.footer_bytes;
    const provenance = try std.fmt.allocPrint(
        allocator,
        "{{\"schema\":1,\"type\":\"{s}\",\"release\":\"24.04\"," ++
            "\"architecture\":\"x86_64\",\"tee\":\"AMD SEV-SNP\"," ++
            "\"publication\":{{\"sha256sums_signature_verified\":true}}," ++
            "\"guest_contract\":{{\"generalized\":true}}," ++
            "\"candidate\":{{\"format\":\"standalone-qcow2\"," ++
            "\"sha256\":\"{s}\",\"size\":{d},\"virtual_size\":{d}}}}}",
        .{ expected_build_type, &qcow_sha, candidate.len, virtual_size },
    );
    defer allocator.free(provenance);
    const result = try std.fmt.allocPrint(
        allocator,
        "{{\"artifact\":{{\"qcow_sha256\":\"{s}\",\"qcow_size\":{d}," ++
            "\"vhd_sha256\":\"{s}\",\"vhd_size\":{d},\"virtual_size\":{d}}}," ++
            "\"attestation\":{{\"compliance\":\"azure-compliant-cvm\"," ++
            "\"debuggable\":false,\"issuer\":\"https://test.attest.azure.net\"," ++
            "\"nonce_sha256\":\"{s}\",\"secure_boot\":true," ++
            "\"tee\":\"AMD SEV-SNP\",\"token_sha256\":\"{s}\",\"vtpm\":true}}," ++
            "\"azure\":{{\"gallery_image_version_id\":\"{s}/galleries/g/images/i/versions/1\"," ++
            "\"location\":\"westeurope\",\"managed_disk_id\":\"{s}/disks/os\"," ++
            "\"managed_image_id\":\"{s}/images/base\"," ++
            "\"resource_group\":\"miz-u2404-cvm-123-4\"," ++
            "\"vm_id\":\"2dedc52a-6832-46ce-9910-e8c9980bf5a7\"," ++
            "\"vm_resource_id\":\"{s}/virtualMachines/vm\"," ++
            "\"vm_size\":\"Standard_DC2as_v5\"}},\"schema\":1," ++
            "\"source_commit\":\"{s}\",\"type\":\"{s}\"}}",
        .{
            &qcow_sha,
            candidate.len,
            "1" ** 64,
            vhd_size,
            virtual_size,
            "2" ** 64,
            "3" ** 64,
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/miz-u2404-cvm-123-4/providers/Microsoft.Compute",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/miz-u2404-cvm-123-4/providers/Microsoft.Compute",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/miz-u2404-cvm-123-4/providers/Microsoft.Compute",
            "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/miz-u2404-cvm-123-4/providers/Microsoft.Compute",
            commit,
            acceptance_type,
        },
    );
    defer allocator.free(result);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = candidate_path,
        .data = candidate,
    });
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = provenance_path,
        .data = provenance,
    });
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = result_path,
        .data = result,
    });

    var diagnostic: Diagnostic = .{};
    const accepted = try verifyAcceptanceResult(
        allocator,
        std.testing.io,
        result_path,
        provenance_path,
        candidate_path,
        commit,
        "westeurope",
        "Standard_DC2as_v5",
        "123",
        "4",
        &diagnostic,
    );
    try std.testing.expectEqualStrings(&qcow_sha, &accepted.qcow_sha256);

    const insecure = try std.mem.replaceOwned(
        u8,
        allocator,
        result,
        "\"secure_boot\":true",
        "\"secure_boot\":false",
    );
    defer allocator.free(insecure);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = result_path,
        .data = insecure,
    });
    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, verifyAcceptanceResult(
        allocator,
        std.testing.io,
        result_path,
        provenance_path,
        candidate_path,
        commit,
        "westeurope",
        "Standard_DC2as_v5",
        "123",
        "4",
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "attested Secure Boot state is not true",
        diagnostic.message(),
    );
}

const test_attestation_endpoint = "https://test.attest.azure.net";
const test_attestation_nonce =
    "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
const test_attestation_vm_id = "2dedc52a-6832-46ce-9910-e8c9980bf5a7";
const test_jwt_header = "eyJhbGciOiJSUzI1NiIsImtpZCI6InRlc3Qta2V5In0";
const test_jwt_payload =
    "eyJpc3MiOiJodHRwczovL3Rlc3QuYXR0ZXN0LmF6dXJlLm5ldCIsIngtbXMtcnVudGltZSI6eyJjbGllbnQtcGF5bG9hZCI6eyJub25jZSI6Ik1ERXlNelExTmpjNE9XRmlZMlJsWmpBeE1qTTBOVFkzT0RsaFltTmtaV1l3TVRJek5EVTJOemc1WVdKalpHVm1NREV5TXpRMU5qYzRPV0ZpWTJSbFpnPT0ifX0sImlhdCI6MTk5OTk5OTk0MCwibmJmIjoxOTk5OTk5OTQwLCJleHAiOjIwMDAwMDAwNjAsIngtbXMtYXp1cmV2bS12bWlkIjoiMmRlZGM1MmEtNjgzMi00NmNlLTk5MTAtZThjOTk4MGJmNWE3Iiwic2VjdXJlYm9vdCI6dHJ1ZSwieC1tcy1henVyZXZtLWJvb3RkZWJ1Zy1lbmFibGVkIjpmYWxzZSwieC1tcy1henVyZXZtLWRlYnVnZ2Vyc2Rpc2FibGVkIjp0cnVlLCJ4LW1zLWlzb2xhdGlvbi10ZWUiOnsieC1tcy1hdHRlc3RhdGlvbi10eXBlIjoic2V2c25wdm0iLCJ4LW1zLWNvbXBsaWFuY2Utc3RhdHVzIjoiYXp1cmUtY29tcGxpYW50LWN2bSIsIngtbXMtc2V2c25wdm0taXMtZGVidWdnYWJsZSI6ZmFsc2UsIngtbXMtc2V2c25wdm0tbWlncmF0aW9uLWFsbG93ZWQiOmZhbHNlLCJ4LW1zLXNldnNucHZtLXZtcGwiOjAsIngtbXMtcnVudGltZSI6eyJ2bS1jb25maWd1cmF0aW9uIjp7InNlY3VyZS1ib290Ijp0cnVlLCJ0cG0tZW5hYmxlZCI6dHJ1ZSwidm1VbmlxdWVJZCI6IjJkZWRjNTJhLTY4MzItNDZjZS05OTEwLWU4Yzk5ODBiZjVhNyJ9fX19";
const test_jwt_signature =
    "hHxIKU1QeOGc9iKXA-7yGzHHrrGydw30nEneRj47UcPK5M7n6ul8WtOol2N5twEFNuaTskGNPW7nsuiKa3JOoNXWwmnmaQJhs-HL8YIw50WLGOaitsWQISeGIjHKxwqU4oAQI6foce5m2yllJchXvj_tJlKsA2EaIveitSr-bOQzH_wV8rkuFPPlJNwDOSMHrol3sx_rzmH04NsOdfrlIexyFtZMVFAIRvr2yRhR93hiGATO0aYJalQ534Tt42cjXkCze0Tr69XOWqTjJfS6z4KuvNatM6422PXjLaQPecdke0nNb-hEPtaTq7bcPBxqtDkm9g8Z5jKTzDOonYHNKA";
const test_jwk_modulus =
    "-2XxXV320pe3bM-aJBMz2aCE3YdBveYuyyu1XVddm9T1Meh5spJ29cPjeBg4vM-5KDePqAZhPDmAMdvAabIz5MW92p3soyFYlnmQgd1AdwvpEM9U_MzItvrheYQ_Y5qdv_Aahyelf4obb42MvQ4GC9ujnoYyDV1OJFbF_EjyWPXsLH12vHqYBlHRLQ5sy5lrVWyvqTnNA3hBAx5q2lOyACGTGE05Bgw7rhY-3cNIVVNBBw_m9Vi_TvJOo31FcpRZADL_pw3Oq71fHCT7UASH23vFbCHXcGN4Fsh8fiXn-NUlx3GmUioI36yHpP30Sr91H777hQzVpVkHZgeiXBcHwQ";
const test_claims_json =
    \\{"iss":"https://test.attest.azure.net","x-ms-runtime":{"client-payload":{"nonce":"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg=="}},"iat":1999999940,"nbf":1999999940,"exp":2000000060,"x-ms-azurevm-vmid":"2dedc52a-6832-46ce-9910-e8c9980bf5a7","secureboot":true,"x-ms-azurevm-bootdebug-enabled":false,"x-ms-azurevm-debuggersdisabled":true,"x-ms-isolation-tee":{"x-ms-attestation-type":"sevsnpvm","x-ms-compliance-status":"azure-compliant-cvm","x-ms-sevsnpvm-is-debuggable":false,"x-ms-sevsnpvm-migration-allowed":false,"x-ms-sevsnpvm-vmpl":0,"x-ms-runtime":{"vm-configuration":{"secure-boot":true,"tpm-enabled":true,"vmUniqueId":"2dedc52a-6832-46ce-9910-e8c9980bf5a7"}}}}
;

fn testFixturePath(
    allocator: Allocator,
    sub_path: []const u8,
    name: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        ".zig-cache/tmp/{s}/{s}",
        .{ sub_path, name },
    );
}

test "valid RS256 JWT and JWKS verify cryptographically" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const token_path = try testFixturePath(allocator, &tmp.sub_path, "token.jwt");
    defer allocator.free(token_path);
    const openid_path = try testFixturePath(allocator, &tmp.sub_path, "openid.json");
    defer allocator.free(openid_path);
    const jwks_path = try testFixturePath(allocator, &tmp.sub_path, "jwks.json");
    defer allocator.free(jwks_path);
    const token = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}.{s}",
        .{ test_jwt_header, test_jwt_payload, test_jwt_signature },
    );
    defer allocator.free(token);
    const openid = try std.fmt.allocPrint(
        allocator,
        "{{\"issuer\":\"{s}\",\"jwks_uri\":\"{s}/certs\"}}",
        .{ test_attestation_endpoint, test_attestation_endpoint },
    );
    defer allocator.free(openid);
    const jwks = try std.fmt.allocPrint(
        allocator,
        "{{\"keys\":[{{\"kid\":\"test-key\",\"kty\":\"RSA\",\"use\":\"sig\",\"alg\":\"RS256\",\"n\":\"{s}\",\"e\":\"AQAB\"}}]}}",
        .{test_jwk_modulus},
    );
    defer allocator.free(jwks);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = token_path,
        .data = token,
    });
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = openid_path,
        .data = openid,
    });
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = jwks_path,
        .data = jwks,
    });
    var diagnostic: Diagnostic = .{};
    const evidence = verifyAttestation(
        allocator,
        std.testing.io,
        token_path,
        openid_path,
        jwks_path,
        test_attestation_endpoint,
        test_attestation_nonce,
        test_attestation_vm_id,
        2_000_000_000,
        &diagnostic,
    ) catch |err| {
        std.debug.print("{s}: {s}\n", .{ @errorName(err), diagnostic.message() });
        return err;
    };
    try std.testing.expectEqualStrings(
        test_attestation_endpoint,
        evidence.issuer,
    );

    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, verifyAttestation(
        allocator,
        std.testing.io,
        token_path,
        openid_path,
        jwks_path,
        test_attestation_endpoint,
        "1123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
        test_attestation_vm_id,
        2_000_000_000,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "MAA JWT nonce mismatch",
        diagnostic.message(),
    );

    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, verifyAttestation(
        allocator,
        std.testing.io,
        token_path,
        openid_path,
        jwks_path,
        "https://other.attest.azure.net",
        test_attestation_nonce,
        test_attestation_vm_id,
        2_000_000_000,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "OpenID issuer mismatch",
        diagnostic.message(),
    );

    var bad_signature = try allocator.dupe(u8, test_jwt_signature);
    defer allocator.free(bad_signature);
    bad_signature[0] = if (bad_signature[0] == 'a') 'b' else 'a';
    const invalid_token = try std.fmt.allocPrint(
        allocator,
        "{s}.{s}.{s}",
        .{ test_jwt_header, test_jwt_payload, bad_signature },
    );
    defer allocator.free(invalid_token);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = token_path,
        .data = invalid_token,
    });
    diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, verifyAttestation(
        allocator,
        std.testing.io,
        token_path,
        openid_path,
        jwks_path,
        test_attestation_endpoint,
        test_attestation_nonce,
        test_attestation_vm_id,
        2_000_000_000,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(
        "MAA JWT signature is invalid",
        diagnostic.message(),
    );
}

fn expectInvalidClaim(
    needle: []const u8,
    replacement: []const u8,
    message: []const u8,
) !void {
    const allocator = std.testing.allocator;
    try std.testing.expectEqual(
        @as(usize, 1),
        std.mem.count(u8, test_claims_json, needle),
    );
    const modified = try std.mem.replaceOwned(
        u8,
        allocator,
        test_claims_json,
        needle,
        replacement,
    );
    defer allocator.free(modified);
    var claims = try std.json.parseFromSlice(Value, allocator, modified, .{});
    defer claims.deinit();
    var diagnostic: Diagnostic = .{};
    try std.testing.expectError(error.InvalidDocument, verifyAttestationClaims(
        allocator,
        &claims.value.object,
        test_attestation_endpoint,
        test_attestation_nonce,
        test_attestation_vm_id,
        2_000_000_000,
        &diagnostic,
    ));
    try std.testing.expectEqualStrings(message, diagnostic.message());
}

test "attestation rejects identity and security claim substitutions" {
    try expectInvalidClaim(
        "\"nonce\":\"MDEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg==\"",
        "\"nonce\":\"MTEyMzQ1Njc4OWFiY2RlZjAxMjM0NTY3ODlhYmNkZWYwMTIzNDU2Nzg5YWJjZGVmMDEyMzQ1Njc4OWFiY2RlZg==\"",
        "MAA JWT nonce mismatch",
    );
    try expectInvalidClaim(
        "\"x-ms-azurevm-vmid\":\"2dedc52a-6832-46ce-9910-e8c9980bf5a7\"",
        "\"x-ms-azurevm-vmid\":\"3dedc52a-6832-46ce-9910-e8c9980bf5a7\"",
        "attested Azure VM identity mismatch",
    );
    try expectInvalidClaim(
        "\"x-ms-compliance-status\":\"azure-compliant-cvm\"",
        "\"x-ms-compliance-status\":\"non-compliant\"",
        "TEE compliance mismatch",
    );
    try expectInvalidClaim(
        "\"x-ms-sevsnpvm-is-debuggable\":false",
        "\"x-ms-sevsnpvm-is-debuggable\":true",
        "SEV-SNP debuggable state is not false",
    );
    try expectInvalidClaim(
        "\"secureboot\":true",
        "\"secureboot\":false",
        "attested Secure Boot state is not true",
    );
    try expectInvalidClaim(
        "\"tpm-enabled\":true",
        "\"tpm-enabled\":false",
        "attested VM vTPM configuration is not true",
    );
}

test {
    _ = miz;
}
