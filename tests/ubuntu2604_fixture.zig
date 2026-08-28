//! Builds complete Ubuntu 26.04 candidate and Azure acceptance bundles.
//!
//! Every behavioral test of the release tooling needs the same thing first: a
//! provenance tree that actually satisfies the contract, a candidate manifest
//! produced from it by the real `candidate` command, a structurally valid
//! derived VHD, and an Azure acceptance result produced from those by the real
//! `azure-result` command. Building that once, here, is what lets each test be
//! about the one thing it changes -- a mutated field, a tampered file, a
//! missing document -- rather than about fixture construction.

const std = @import("std");

const release = @import("ubuntu2604_release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const contracts = release.contracts;
const support = release.support;
const miz = @import("miz");

pub const Builder = support.Builder;
pub const Diagnostic = support.Diagnostic;

pub const source_commit = "a" ** 40;
pub const certificate_der = "miz Ubuntu test certificate";
pub const signing_certificate_sha256 = "4" ** 64;
pub const operation_id = "00000000-0000-4000-8000-000000000001";
/// Two aligned MiB: large enough to exercise the VHD footer geometry, small
/// enough that every fixture is written in one go.
pub const virtual_size: i64 = 2 * 1024 * 1024;

pub fn certificateSha256() [64]u8 {
    return support.digest.hexBytes(certificate_der);
}

/// A private tree holding one test's candidates, Azure results, and staging
/// outputs, with paths spelled relative to the working directory so the tools
/// under test resolve them exactly as production callers do.
pub const Tree = struct {
    tmp: std.testing.TmpDir,
    allocator: Allocator,
    io: Io,
    root: []u8,

    pub fn create(allocator: Allocator, io: Io) !Tree {
        const tmp = std.testing.tmpDir(.{});
        const root = try std.fmt.allocPrint(
            allocator,
            ".zig-cache/tmp/{s}",
            .{tmp.sub_path},
        );
        return .{ .tmp = tmp, .allocator = allocator, .io = io, .root = root };
    }

    pub fn deinit(self: *Tree) void {
        self.allocator.free(self.root);
        self.tmp.cleanup();
        self.* = undefined;
    }

    /// A path inside this tree. Caller owns the result.
    pub fn path(self: *const Tree, comptime fmt: []const u8, args: anytype) ![]u8 {
        const relative = try std.fmt.allocPrint(self.allocator, fmt, args);
        defer self.allocator.free(relative);
        return std.fs.path.join(self.allocator, &.{ self.root, relative });
    }

    pub fn candidates(self: *const Tree) ![]u8 {
        return self.path("candidates", .{});
    }

    pub fn azure(self: *const Tree) ![]u8 {
        return self.path("azure", .{});
    }

    pub fn native(self: *const Tree) ![]u8 {
        return self.path("native", .{});
    }

    pub fn candidateDir(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("candidates/{s}", .{key});
    }

    pub fn azureDir(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("azure/{s}", .{key});
    }

    pub fn nativeDir(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("native/{s}", .{key});
    }

    pub fn manifestPath(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("candidates/{s}/candidate.json", .{key});
    }

    pub fn assetPath(self: *const Tree, key: []const u8) ![]u8 {
        return self.path(
            "candidates/{s}/{s}",
            .{ key, contracts.lookup(key).?.asset_name },
        );
    }

    pub fn provenanceDir(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("candidates/{s}/internal-provenance", .{key});
    }

    pub fn azureResultPath(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("azure/{s}/azure-result.json", .{key});
    }

    pub fn nativeResultPath(self: *const Tree, key: []const u8) ![]u8 {
        return self.path("native/{s}/native-result.json", .{key});
    }

    pub fn removeBundle(self: *const Tree, key: []const u8) !void {
        const candidate_dir = try self.candidateDir(key);
        defer self.allocator.free(candidate_dir);
        const azure_dir = try self.azureDir(key);
        defer self.allocator.free(azure_dir);
        try Dir.cwd().deleteTree(self.io, candidate_dir);
        try Dir.cwd().deleteTree(self.io, azure_dir);
    }
};

pub const Options = struct {
    /// Overridden to prove the staging gate refuses two candidates that were
    /// signed by different certificates.
    certificate: []const u8 = certificate_der,
    signing_certificate_sha256: []const u8 = signing_certificate_sha256,
    asset_bytes: ?[]const u8 = null,
};

pub const NativeResultOptions = struct {
    source_commit: []const u8 = source_commit,
    status: []const u8 = "success",
    run_id: []const u8 = "100",
    run_attempt: []const u8 = "1",
};

/// Builds the provenance tree, the candidate, the derived VHD, and the Azure
/// acceptance result for `key`, using the production commands throughout.
pub fn makeBundle(tree: *const Tree, key: []const u8, options: Options) !void {
    const allocator = tree.allocator;
    const io = tree.io;
    const entry = contracts.lookup(key).?;
    const flavor = contracts.parseFlavor(entry.flavor).?;

    const candidate_dir = try tree.candidateDir(key);
    defer allocator.free(candidate_dir);
    try Dir.cwd().createDirPath(io, candidate_dir);

    const asset = try tree.assetPath(key);
    defer allocator.free(asset);
    const default_asset_bytes = try std.fmt.allocPrint(allocator, "{s}\n", .{key});
    defer allocator.free(default_asset_bytes);
    try Dir.cwd().writeFile(io, .{
        .sub_path = asset,
        .data = options.asset_bytes orelse default_asset_bytes,
    });

    const provenance = try tree.provenanceDir(key);
    defer allocator.free(provenance);
    try Dir.cwd().createDirPath(io, provenance);
    try writeProvenance(tree, key, provenance, options);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();

    const manifest = try tree.manifestPath(key);
    defer allocator.free(manifest);
    const asset_digest = try support.hashArtifact(io, asset);
    const runner = try std.fmt.allocPrint(
        allocator,
        "ubuntu-{s}",
        .{entry.architecture},
    );
    defer allocator.free(runner);

    var diagnostic: Diagnostic = .{};
    try release.commands.candidate(allocator, io, .{
        .key = key,
        .architecture = entry.architecture,
        .flavor = entry.flavor,
        .asset = asset,
        .validated_sha256 = &asset_digest.hex,
        .virtual_size = virtual_size,
        .source_commit = source_commit,
        .provenance_dir = provenance,
        .runner = runner,
        .run_id = "100",
        .run_attempt = "1",
        .output = manifest,
    }, &diagnostic);

    const azure_dir = try tree.azureDir(key);
    defer allocator.free(azure_dir);
    try Dir.cwd().createDirPath(io, azure_dir);

    const vhd = try tree.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);
    try writeFixedVhd(io, vhd, @intCast(virtual_size));

    const vhd_info = try tree.path("azure/{s}/vhd-info.json", .{key});
    defer allocator.free(vhd_info);
    const info_text = try std.fmt.allocPrint(
        allocator,
        "{{\"format\": \"vpc\", \"virtual-size\": {d}}}",
        .{virtual_size},
    );
    defer allocator.free(info_text);
    try Dir.cwd().writeFile(io, .{ .sub_path = vhd_info, .data = info_text });

    const conversion = try tree.path("azure/{s}/conversion-attestation.json", .{key});
    defer allocator.free(conversion);
    const vhd_digest = try support.hashArtifact(io, vhd);
    try release.workflow.conversionAttestation(allocator, io, .{
        .output = conversion,
        .key = key,
        .asset_name = entry.asset_name,
        .qcow_sha256 = &asset_digest.hex,
        .qcow_bytes = @intCast(asset_digest.size),
        .virtual_size = virtual_size,
        .vhd_sha256 = &vhd_digest.hex,
        .vhd_bytes = @intCast(vhd_digest.size),
        .vhd_current_size = virtual_size,
        .info = vhd_info,
    }, &diagnostic);

    const request = try tree.path("azure/{s}/request.json", .{key});
    defer allocator.free(request);
    const response = try tree.path("azure/{s}/response.json", .{key});
    defer allocator.free(response);
    const gallery = try galleryDocument(allocator, options.certificate);
    defer allocator.free(gallery);
    try Dir.cwd().writeFile(io, .{ .sub_path = request, .data = gallery });
    try Dir.cwd().writeFile(io, .{ .sub_path = response, .data = gallery });

    const output = try tree.azureResultPath(key);
    defer allocator.free(output);
    const resource_group = try std.fmt.allocPrint(allocator, "ubuntu-{s}", .{key});
    defer allocator.free(resource_group);
    const image_version_id = try std.fmt.allocPrint(
        allocator,
        "/subscriptions/test/gallery/ubuntu/{s}/versions/1.0.0",
        .{key},
    );
    defer allocator.free(image_version_id);
    const contract_list = try joinContracts(allocator, contracts.azureContracts(flavor));
    defer allocator.free(contract_list);

    try release.commands.azureResult(allocator, io, azureResultOptions(.{
        .manifest = manifest,
        .asset = asset,
        .vhd = vhd,
        .vhd_info = vhd_info,
        .conversion = conversion,
        .key = key,
        .request = request,
        .response = response,
        .contracts = contract_list,
        .resource_group = resource_group,
        .image_version_id = image_version_id,
        .output = output,
        .flavor = flavor,
    }), &diagnostic);
}

pub fn makeNativeResult(
    tree: *const Tree,
    key: []const u8,
    options: NativeResultOptions,
) !void {
    const allocator = tree.allocator;
    const io = tree.io;
    const entry = contracts.lookup(key).?;
    const flavor = contracts.parseFlavor(entry.flavor).?;
    const qemu = release.execution.forName(entry.architecture).?;

    const manifest = try tree.manifestPath(key);
    defer allocator.free(manifest);
    var candidate = try read(allocator, io, manifest);
    defer candidate.deinit();
    const object = candidate.value.object;
    const signing = object.get("uki_signing").?.object;

    const native_dir = try tree.nativeDir(key);
    defer allocator.free(native_dir);
    try Dir.cwd().createDirPath(io, native_dir);
    const output = try tree.nativeResultPath(key);
    defer allocator.free(output);

    const value = switch (flavor) {
        .full => try std.json.Stringify.valueAlloc(
            allocator,
            .{
                .schema = release.documents.nativeResultSchema(flavor),
                .type = release.documents.native_result_type,
                .key = key,
                .architecture = entry.architecture,
                .flavor = entry.flavor,
                .asset_name = entry.asset_name,
                .source_commit = options.source_commit,
                .virtual_size = object.get("virtual_size").?.integer,
                .candidate_sha256 = object.get("sha256").?.string,
                .certificate_sha256 = signing.get("certificate_sha256").?.string,
                .fallback_uki_sha256 = signing.get("fallback_uki_sha256").?.string,
                .status = options.status,
                .execution = .{
                    .accelerator = @tagName(qemu.accelerator),
                    .cpu = qemu.cpu,
                    .emulator = qemu.emulator,
                    .guest_architecture = entry.architecture,
                    .machine = qemu.machine,
                    .runner_architecture = qemu.runner_architecture,
                },
                .contracts = contracts.full_native_contracts,
                .workflow = .{
                    .run_id = options.run_id,
                    .run_attempt = options.run_attempt,
                },
            },
            .{ .whitespace = .indent_2 },
        ),
        .core => try std.json.Stringify.valueAlloc(
            allocator,
            .{
                .schema = release.documents.nativeResultSchema(flavor),
                .type = release.documents.native_result_type,
                .key = key,
                .architecture = entry.architecture,
                .flavor = entry.flavor,
                .asset_name = entry.asset_name,
                .source_commit = options.source_commit,
                .virtual_size = object.get("virtual_size").?.integer,
                .candidate_sha256 = object.get("sha256").?.string,
                .certificate_sha256 = signing.get("certificate_sha256").?.string,
                .fallback_uki_sha256 = signing.get("fallback_uki_sha256").?.string,
                .status = options.status,
                .execution = .{
                    .accelerator = @tagName(qemu.accelerator),
                    .cpu = qemu.cpu,
                    .emulator = qemu.emulator,
                    .guest_architecture = entry.architecture,
                    .machine = qemu.machine,
                    .runner_architecture = qemu.runner_architecture,
                },
                .contracts = contracts.core_native_contracts,
                .workflow = .{
                    .run_id = options.run_id,
                    .run_attempt = options.run_attempt,
                },
                .android_smoke = .{
                    .provenance_sha256 = android_provenance_sha256,
                    .runtime_sha256 = android_runtime_sha256,
                    .bundle_sha256 = android_bundle_sha256,
                    .config_sha256 = android_config_sha256,
                    .architecture = entry.architecture,
                    .candidate_key = key,
                },
            },
            .{ .whitespace = .indent_2 },
        ),
    };
    defer allocator.free(value);
    try Dir.cwd().writeFile(io, .{ .sub_path = output, .data = value });
}

/// The argument set the Azure acceptance harness passes, with the Android
/// smoke digests present only for the core flavor.
pub const AzureResultInputs = struct {
    manifest: []const u8,
    asset: []const u8,
    vhd: []const u8,
    vhd_info: []const u8,
    conversion: []const u8,
    key: []const u8,
    request: []const u8,
    response: []const u8,
    contracts: []const u8,
    resource_group: []const u8,
    image_version_id: []const u8,
    output: []const u8,
    flavor: contracts.Flavor,
};

pub const android_provenance_sha256 = "5" ** 64;
pub const android_runtime_sha256 = "6" ** 64;
pub const android_bundle_sha256 = "7" ** 64;
pub const android_config_sha256 = "8" ** 64;

pub fn azureResultOptions(
    inputs: AzureResultInputs,
) release.commands.AzureResultOptions {
    const core = inputs.flavor == .core;
    return .{
        .manifest = inputs.manifest,
        .asset = inputs.asset,
        .vhd = inputs.vhd,
        .vhd_info = inputs.vhd_info,
        .conversion_attestation = inputs.conversion,
        .key = inputs.key,
        .source_commit = source_commit,
        .location = "eastus2",
        .vm_size = "Standard_D2ds_v5",
        .resource_group = inputs.resource_group,
        .image_version_id = inputs.image_version_id,
        .uefi_request = inputs.request,
        .uefi_response = inputs.response,
        .android_smoke_provenance_sha256 = if (core) android_provenance_sha256 else null,
        .android_smoke_runtime_sha256 = if (core) android_runtime_sha256 else null,
        .android_smoke_bundle_sha256 = if (core) android_bundle_sha256 else null,
        .android_smoke_config_sha256 = if (core) android_config_sha256 else null,
        .contracts = inputs.contracts,
        .run_id = "100",
        .run_attempt = "1",
        .output = inputs.output,
    };
}

pub fn joinContracts(allocator: Allocator, list: []const []const u8) ![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(allocator);
    for (list, 0..) |item, index| {
        if (index != 0) try out.append(allocator, ',');
        try out.appendSlice(allocator, item);
    }
    return out.toOwnedSlice(allocator);
}

/// A structurally valid fixed VHD: `current_size` zero bytes followed by the
/// footer `miz azure derive` would have written for them.
pub fn writeFixedVhd(io: Io, path: []const u8, current_size: u64) !void {
    const file = try Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    const footer = miz.vhd.Footer.forFixedDisk(
        current_size,
        .{
            0x8d, 0x1f, 0x2a, 0x3b, 0x4c, 0x5d, 0x6e, 0x7f,
            0x80, 0x91, 0xa2, 0xb3, 0xc4, 0xd5, 0xe6, 0xf7,
        },
        1_700_000_000,
    ).encode();
    const zeros = try std.testing.allocator.alloc(u8, 64 * 1024);
    defer std.testing.allocator.free(zeros);
    @memset(zeros, 0);
    var offset: u64 = 0;
    while (offset < current_size) {
        const length: usize = @intCast(@min(current_size - offset, zeros.len));
        try file.writePositionalAll(io, zeros[0..length], offset);
        offset += length;
    }
    try file.writePositionalAll(io, &footer, current_size);
}

fn galleryDocument(allocator: Allocator, certificate: []const u8) ![]u8 {
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(u8, encoder.calcSize(certificate.len));
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, certificate);
    return std.fmt.allocPrint(allocator,
        \\{{"properties": {{"securityProfile": {{"uefiSettings": {{
        \\"signatureTemplateNames": ["MicrosoftUefiCertificateAuthorityTemplate"],
        \\"additionalSignatures": {{"db": [{{"type": "x509", "value": ["{s}"]}}]}}
        \\}}}}}}}}
    , .{encoded});
}

/// Writes the complete internal provenance tree: the Canonical source
/// bindings, the architecture-specific disk layout, the debz closure locks and
/// transaction results, and the UKI signing record.
fn writeProvenance(
    tree: *const Tree,
    key: []const u8,
    provenance: []const u8,
    options: Options,
) !void {
    const allocator = tree.allocator;
    const io = tree.io;
    const entry = contracts.lookup(key).?;
    const flavor = contracts.parseFlavor(entry.flavor).?;
    const source_architecture = contracts.sourceArchitecture(entry.architecture).?;

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = Builder.init(arena.allocator());

    const prefix = try std.fmt.allocPrint(
        arena.allocator(),
        "ubuntu-26.04-server-cloudimg-{s}",
        .{source_architecture},
    );
    const image_name = try std.fmt.allocPrint(arena.allocator(), "{s}.img", .{prefix});
    const manifest_name = try std.fmt.allocPrint(
        arena.allocator(),
        "{s}.manifest",
        .{prefix},
    );

    const manifest_path = try std.fs.path.join(
        allocator,
        &.{ provenance, manifest_name },
    );
    defer allocator.free(manifest_path);
    const manifest_text = try std.fmt.allocPrint(
        allocator,
        "image_manifest for {s}\n",
        .{key},
    );
    defer allocator.free(manifest_text);
    try Dir.cwd().writeFile(io, .{
        .sub_path = manifest_path,
        .data = manifest_text,
    });
    const manifest_digest = support.digest.hexBytes(manifest_text);
    const image_digest = "5" ** 64;

    const checksums = try std.fmt.allocPrint(
        allocator,
        "{s}  {s}\n{s}  {s}\n",
        .{ image_digest, image_name, &manifest_digest, manifest_name },
    );
    defer allocator.free(checksums);
    const checksum_path = try std.fs.path.join(
        allocator,
        &.{ provenance, "SHA256SUMS" },
    );
    defer allocator.free(checksum_path);
    try Dir.cwd().writeFile(io, .{ .sub_path = checksum_path, .data = checksums });

    const signature_path = try std.fs.path.join(
        allocator,
        &.{ provenance, "SHA256SUMS.gpg" },
    );
    defer allocator.free(signature_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = signature_path,
        .data = "detached signature",
    });

    var transactions = builder.array();
    for (contracts.debzPackages(flavor), 0..) |package, index| {
        // `format(7 + index, "x")` in the Python fixture: the digits continue
        // into the hex letters rather than running off the end of ASCII.
        const lock_digest = try repeatHex(
            arena.allocator(),
            std.fmt.digitToChar(@intCast(7 + index), .lower),
        );
        const lock_name = try std.fmt.allocPrint(
            arena.allocator(),
            "debz-exact-lock-{s}-{s}.json",
            .{ package, source_architecture },
        );
        const package_records = if (flavor == .core and index == 0)
            try std.fmt.allocPrint(
                allocator,
                \\  {{"name": "{s}", "version": "1", "architecture": "{s}",
                \\    "retention": "requested"}}
            ,
                .{ package, source_architecture },
            )
        else
            try std.fmt.allocPrint(
                allocator,
                \\  {{"name": "base-files", "version": "1", "architecture": "{s}",
                \\    "retention": "retained"}},
                \\  {{"name": "{s}", "version": "1", "architecture": "{s}",
                \\    "retention": "requested"}}
            ,
                .{ source_architecture, package, source_architecture },
            );
        defer allocator.free(package_records);
        const lock_text = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/exact-closure-lock-v1",
            \\"version": 1, "target_architecture": "{s}",
            \\"request_sha256": "{s}", "policy_sha256": "{s}",
            \\"repositories": [{{"fixture": true}}],
            \\"packages": [
            \\{s}],
            \\"digest_sha256": "{s}"}}
        , .{
            source_architecture,
            "1" ** 64,
            "2" ** 64,
            package_records,
            lock_digest,
        });
        defer allocator.free(lock_text);
        const lock_path = try std.fs.path.join(allocator, &.{ provenance, lock_name });
        defer allocator.free(lock_path);
        try Dir.cwd().writeFile(io, .{ .sub_path = lock_path, .data = lock_text });

        const transaction_digest = try repeatHex(
            arena.allocator(),
            'a' + @as(u8, @intCast(index)),
        );
        const transaction_name = try std.fmt.allocPrint(
            arena.allocator(),
            "debz-transaction-provenance-{s}-{s}.json",
            .{ package, source_architecture },
        );
        const transaction_text = try std.fmt.allocPrint(allocator,
            \\{{"schema": "https://debz.dev/schema/transaction-result-v1",
            \\"version": 1, "target_architecture": "{s}", "lock_sha256": "{s}",
            \\"outcome": "succeeded",
            \\"final_verification": {{"status": "exact_match"}},
            \\"digest_sha256": "{s}"}}
        , .{ source_architecture, lock_digest, transaction_digest });
        defer allocator.free(transaction_text);
        const transaction_path = try std.fs.path.join(
            allocator,
            &.{ provenance, transaction_name },
        );
        defer allocator.free(transaction_path);
        try Dir.cwd().writeFile(io, .{
            .sub_path = transaction_path,
            .data = transaction_text,
        });

        var exact_lock = builder.object();
        try builder.putString(&exact_lock, "filename", lock_name);
        try builder.putString(
            &exact_lock,
            "sha256",
            &support.digest.hexBytes(lock_text),
        );
        try builder.putString(&exact_lock, "digest_sha256", lock_digest);

        var transaction_provenance = builder.object();
        try builder.putString(&transaction_provenance, "filename", transaction_name);
        try builder.putString(
            &transaction_provenance,
            "sha256",
            &support.digest.hexBytes(transaction_text),
        );
        try builder.putString(
            &transaction_provenance,
            "digest_sha256",
            transaction_digest,
        );
        try builder.putString(&transaction_provenance, "lock_sha256", lock_digest);

        var record = builder.object();
        try builder.putString(&record, "package", package);
        try builder.put(&record, "exact_lock", .{ .object = exact_lock });
        try builder.put(
            &record,
            "transaction_provenance",
            .{ .object = transaction_provenance },
        );
        try transactions.append(.{ .object = record });
    }

    var artifacts = builder.object();
    try builder.put(&artifacts, "sha256sums", try fileBinding(
        builder,
        "SHA256SUMS",
        &support.digest.hexBytes(checksums),
        null,
    ));
    try builder.put(&artifacts, "sha256sums_signature", try fileBinding(
        builder,
        "SHA256SUMS.gpg",
        &support.digest.hexBytes("detached signature"),
        null,
    ));
    try builder.put(&artifacts, "source_image", try fileBinding(
        builder,
        image_name,
        image_digest,
        if (flavor == .core) "signed-gpt-esp-substrate" else null,
    ));
    try builder.put(&artifacts, "image_manifest", try fileBinding(
        builder,
        manifest_name,
        &manifest_digest,
        null,
    ));

    var baseline = builder.object();
    try builder.putString(&baseline, "source", switch (flavor) {
        .core => "empty-debz-root",
        .full => "canonical-image-dpkg-status",
    });
    try builder.putString(&baseline, "enforcement", "exact-final-closure");

    var debz = builder.object();
    try builder.putString(&debz, "api_commit", contracts.debz_api_commit);
    try builder.put(&debz, "baseline", .{ .object = baseline });
    try builder.put(&debz, "transactions", .{ .array = transactions });
    if (flavor == .core) {
        try builder.put(
            &debz,
            "package_roots",
            try builder.strings(&contracts.core_debz_packages),
        );
    }

    var snapshot = builder.object();
    try builder.putString(&snapshot, "id", "release-20260731");
    try builder.putString(
        &snapshot,
        "base_url",
        "https://cloud-images.ubuntu.com/releases/26.04/release-20260731/",
    );

    var document = builder.object();
    try builder.putInteger(&document, "schema", 1);
    try builder.putString(&document, "type", "miz-ubuntu2604-build-provenance");
    try builder.putString(&document, "architecture", entry.architecture);
    try builder.putString(&document, "release", "26.04");
    try builder.put(&document, "snapshot", .{ .object = snapshot });
    try builder.putString(&document, "canonical_key_fingerprint", "c" ** 40);
    try builder.put(&document, "sha256sums_signature_verified", .{ .bool = true });
    try builder.put(
        &document,
        "artifacts",
        .{ .object = artifacts },
    );
    try builder.put(
        &document,
        "disk_layout",
        try diskLayout(builder, entry.architecture),
    );
    try builder.put(&document, "debz", .{ .object = debz });
    if (flavor == .core) {
        try builder.putString(&document, "flavor", "core");
        try builder.putInteger(&document, "virtual_size", virtual_size);
        try builder.putInteger(&document, "minimum_root_free_bytes", 1024 * 1024);
        try builder.putInteger(&document, "validated_root_free_bytes", 1024 * 1024);
    }

    const provenance_path = try std.fs.path.join(
        allocator,
        &.{ provenance, contracts.ubuntu_provenance_filename },
    );
    defer allocator.free(provenance_path);
    var diagnostic: Diagnostic = .{};
    try support.writeDocument(
        allocator,
        io,
        provenance_path,
        .{ .object = document },
        &diagnostic,
    );

    try writeSigning(tree, key, provenance, options);
}

fn repeatHex(allocator: Allocator, character: u8) ![]u8 {
    const text = try allocator.alloc(u8, 64);
    @memset(text, character);
    return text;
}

fn fileBinding(
    builder: Builder,
    filename: []const u8,
    sha256: []const u8,
    role: ?[]const u8,
) !std.json.Value {
    var binding = builder.object();
    try builder.putString(&binding, "filename", filename);
    try builder.putString(&binding, "sha256", sha256);
    if (role) |value| try builder.putString(&binding, "role", value);
    return .{ .object = binding };
}

fn diskLayout(builder: Builder, architecture: []const u8) !std.json.Value {
    var layout = builder.object();
    try builder.putString(&layout, "source", "canonical-gen2-gpt");
    if (std.mem.eql(u8, architecture, "x86_64")) {
        try builder.putString(&layout, "transform", "preserved");
        return .{ .object = layout };
    }
    try builder.putString(&layout, "transform", "arm64-esp-rebuild-v1");

    var esp = builder.object();
    try builder.putInteger(&esp, "table_index", 14);
    try builder.putInteger(&esp, "first_lba", 2048);
    try builder.putInteger(&esp, "last_lba", 1_050_623);
    try builder.putInteger(&esp, "size_bytes", 512 * 1024 * 1024);
    try builder.putString(&esp, "fat32", "reformatted-preserve-volume-id");
    try builder.putString(&esp, "content", "signed-fallback-only");
    try builder.put(&layout, "esp", .{ .object = esp });

    var retired = builder.object();
    try builder.putInteger(&retired, "table_index", 12);
    try builder.put(&retired, "cleared", .{ .bool = true });
    try builder.put(&layout, "retired_xbootldr", .{ .object = retired });
    return .{ .object = layout };
}

fn writeSigning(
    tree: *const Tree,
    key: []const u8,
    provenance: []const u8,
    options: Options,
) !void {
    const allocator = tree.allocator;
    const entry = contracts.lookup(key).?;
    const encoder = std.base64.standard.Encoder;
    const encoded = try allocator.alloc(
        u8,
        encoder.calcSize(options.certificate.len),
    );
    defer allocator.free(encoded);
    _ = encoder.encode(encoded, options.certificate);
    const fingerprint = support.digest.hexBytes(options.certificate);
    const fallback = if (std.mem.eql(u8, entry.architecture, "x86_64"))
        "EFI/BOOT/BOOTX64.EFI"
    else
        "EFI/BOOT/BOOTAA64.EFI";

    const text = try std.fmt.allocPrint(allocator,
        \\{{"schema": 1, "type": "miz-uki-signing",
        \\"architecture": "{s}", "flavor": "{s}",
        \\"signer_mode": "external-command",
        \\"certificate_sha256": "{s}",
        \\"certificate_der_base64": "{s}",
        \\"certificate_details": "subject=CN=miz Ubuntu test signer",
        \\"provider": {{"name": "azure-artifact-signing",
        \\  "endpoint": "https://wus.codesigning.azure.net",
        \\  "account": "cataggar", "profile": "miz-uki",
        \\  "signing_certificate_sha256": "{s}"}},
        \\"signature_verification": "success",
        \\"files": [{{"path": "{s}", "unsigned_sha256": "{s}",
        \\  "signed_sha256": "{s}", "finalized_sha256": "{s}",
        \\  "signed_bytes": 4096, "signing_operation_id": "{s}",
        \\  "signing_certificate_sha256": "{s}"}}]}}
    , .{
        entry.architecture,
        entry.flavor,
        &fingerprint,
        encoded,
        options.signing_certificate_sha256,
        fallback,
        "2" ** 64,
        "3" ** 64,
        "3" ** 64,
        operation_id,
        options.signing_certificate_sha256,
    });
    defer allocator.free(text);

    const name = try std.fmt.allocPrint(
        allocator,
        "uki-signing-{s}-{s}.json",
        .{ entry.flavor, entry.architecture },
    );
    defer allocator.free(name);
    const path = try std.fs.path.join(allocator, &.{ provenance, name });
    defer allocator.free(path);
    try Dir.cwd().writeFile(tree.io, .{ .sub_path = path, .data = text });
}

/// One step of a path into a JSON document.
pub const Step = union(enum) {
    key: []const u8,
    index: usize,
};

pub const Change = union(enum) {
    set: std.json.Value,
    remove,
    /// Reverses an array in place, which is how "stably ordered" contracts are
    /// probed.
    reverse,
    /// Drops the last element of an array.
    pop,
};

/// Reads `path`, applies `change` at `steps`, and writes the document back.
/// This is the Zig spelling of the Python suite's `rewrite(path, mutate)`: it
/// is what lets a test state exactly one deviation from a valid fixture.
pub fn patch(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    steps: []const Step,
    change: Change,
) !void {
    const text = try Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(8 * 1024 * 1024),
    );
    defer allocator.free(text);
    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, text, .{});
    defer parsed.deinit();

    var current = &parsed.value;
    for (steps[0 .. steps.len - 1]) |step| {
        current = switch (step) {
            .key => |name| current.object.getPtr(name).?,
            .index => |index| &current.array.items[index],
        };
    }
    const last = steps[steps.len - 1];
    switch (change) {
        .set => |value| switch (last) {
            .key => |name| try current.object.put(parsed.arena.allocator(), name, value),
            .index => |index| current.array.items[index] = value,
        },
        .remove => switch (last) {
            .key => |name| _ = current.object.orderedRemove(name),
            .index => |index| _ = current.array.orderedRemove(index),
        },
        .reverse => {
            const target = switch (last) {
                .key => |name| current.object.getPtr(name).?,
                .index => |index| &current.array.items[index],
            };
            std.mem.reverse(std.json.Value, target.array.items);
        },
        .pop => {
            const target = switch (last) {
                .key => |name| current.object.getPtr(name).?,
                .index => |index| &current.array.items[index],
            };
            _ = target.array.pop();
        },
    }

    const bytes = try support.json_document.canonicalAlloc(
        allocator,
        parsed.value,
        .compact,
    );
    defer allocator.free(bytes);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = bytes });
}

/// Convenience for the common "replace a string field" mutation.
pub fn patchString(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    steps: []const Step,
    value: []const u8,
) !void {
    try patch(allocator, io, path, steps, .{ .set = .{ .string = value } });
}

pub fn patchInteger(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    steps: []const Step,
    value: i64,
) !void {
    try patch(allocator, io, path, steps, .{ .set = .{ .integer = value } });
}

/// Reads `path` as a JSON document. Caller owns the parsed value.
pub fn read(
    allocator: Allocator,
    io: Io,
    path: []const u8,
) !std.json.Parsed(std.json.Value) {
    const text = try Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(8 * 1024 * 1024),
    );
    defer allocator.free(text);
    return std.json.parseFromSlice(std.json.Value, allocator, text, .{});
}
