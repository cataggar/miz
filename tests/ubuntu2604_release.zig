//! Behavioral coverage of the Ubuntu 26.04 release tooling.
//!
//! Every test here builds a complete, valid bundle and then changes exactly
//! one thing, because that is the property the release contract actually has:
//! a candidate, an acceptance result, and a staged release are accepted only
//! when every binding still agrees with the bytes on disk. Replaces
//! `tests/ubuntu2604_release_test.py`.

const std = @import("std");

const fixture = @import("ubuntu2604_fixture.zig");
const release = @import("ubuntu2604_release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Step = fixture.Step;
const Tree = fixture.Tree;
const commands = release.commands;
const contracts = release.contracts;
const documents = release.documents;
const provenance = release.provenance;
const support = release.support;

const allocator = std.testing.allocator;
const io = std.testing.io;

fn tree() !Tree {
    return Tree.create(allocator, io);
}

/// `verify_candidate` against the bundle's own asset.
fn verify(subject: *const Tree, key: []const u8) !documents.Candidate {
    const manifest = try subject.manifestPath(key);
    defer allocator.free(manifest);
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    var diagnostic: support.Diagnostic = .{};
    return documents.verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        key,
        fixture.source_commit,
        &diagnostic,
    );
}

/// `validate_azure_result` against the bundle's own result.
fn validateAzure(subject: *const Tree, key: []const u8) !void {
    var candidate = try verify(subject, key);
    defer candidate.deinit();
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);
    var diagnostic: support.Diagnostic = .{};
    var result = try documents.validateAzureResult(
        allocator,
        io,
        &candidate,
        result_path,
        &diagnostic,
    );
    result.deinit();
}

fn expectAzureRejected(subject: *const Tree, key: []const u8) !void {
    try std.testing.expectError(error.Failed, validateAzure(subject, key));
}

/// `stage` into the tree's own staging paths.
fn stage(subject: *const Tree, release_tag: []const u8) !void {
    const candidates = try subject.candidates();
    defer allocator.free(candidates);
    const azure = try subject.azure();
    defer allocator.free(azure);
    const output = try subject.path("staged", .{});
    defer allocator.free(output);
    const notes = try subject.path("release-notes.md", .{});
    defer allocator.free(notes);
    var diagnostic: support.Diagnostic = .{};
    try commands.stage(allocator, io, .{
        .candidates = candidates,
        .azure_results = azure,
        .source_commit = fixture.source_commit,
        .release_tag = release_tag,
        .output = output,
        .notes = notes,
    }, &diagnostic);
}

fn expectStageRejected(subject: *const Tree) !void {
    try std.testing.expectError(error.Failed, stage(subject, "Ubuntu-26.04-20260822"));
}

fn makeAll(subject: *const Tree) !void {
    for (contracts.release_order) |key| {
        try fixture.makeBundle(subject, key, .{});
    }
}

fn remake(subject: *const Tree, key: []const u8) !void {
    try subject.removeBundle(key);
    try fixture.makeBundle(subject, key, .{});
}

test "a successful stage publishes exactly the two full-flavor assets" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    try stage(&subject, "Ubuntu-26.04-20260822");

    const manifest_path = try subject.path("staged/publish-manifest.json", .{});
    defer allocator.free(manifest_path);
    var manifest = try fixture.read(allocator, io, manifest_path);
    defer manifest.deinit();
    const document = manifest.value.object;

    try std.testing.expectEqualStrings(
        "miz-ubuntu2604-release",
        document.get("type").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.source_commit,
        document.get("source_commit").?.string,
    );
    try std.testing.expectEqualStrings(
        &fixture.certificateSha256(),
        document.get("certificate_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.signing_certificate_sha256,
        document.get("signing_certificate_sha256").?.string,
    );

    const assets = document.get("assets").?.array.items;
    try std.testing.expectEqual(contracts.release_order.len, assets.len);
    for (assets, contracts.release_order) |asset, key| {
        try std.testing.expectEqualStrings(
            contracts.lookup(key).?.asset_name,
            asset.object.get("asset_name").?.string,
        );
        const staged = try subject.path(
            "staged/{s}",
            .{contracts.lookup(key).?.asset_name},
        );
        defer allocator.free(staged);
        try std.testing.expect(support.isRegularFile(io, staged));
    }

    const notes_path = try subject.path("release-notes.md", .{});
    defer allocator.free(notes_path);
    const notes = try Dir.cwd().readFileAlloc(
        io,
        notes_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(notes);
    try std.testing.expect(std.mem.indexOf(u8, notes, "Ubuntu Server 26.04") != null);
    try std.testing.expect(std.mem.indexOf(
        u8,
        notes,
        "No checksum sidecar assets are published",
    ) != null);
    // Publication never mentions the appliance flavor, in any casing.
    const lowered = try allocator.alloc(u8, notes.len);
    defer allocator.free(lowered);
    try std.testing.expect(std.mem.indexOf(
        u8,
        std.ascii.lowerString(lowered, notes),
        "core",
    ) == null);
}

test "the candidate and Azure result schemas bind the published bytes" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});

    const manifest_path = try subject.manifestPath("x86_64-full");
    defer allocator.free(manifest_path);
    var candidate = try fixture.read(allocator, io, manifest_path);
    defer candidate.deinit();
    const result_path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(result_path);
    var azure = try fixture.read(allocator, io, result_path);
    defer azure.deinit();

    const candidate_object = candidate.value.object;
    const azure_object = azure.value.object;
    try std.testing.expectEqualStrings(
        "ubuntu2604-candidate",
        candidate_object.get("type").?.string,
    );
    try std.testing.expectEqualStrings(
        "ubuntu2604-azure-acceptance",
        azure_object.get("type").?.string,
    );
    const digest = candidate_object.get("sha256").?.string;
    try std.testing.expectEqualStrings(
        digest,
        azure_object.get("qcow_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        digest,
        azure_object.get("azure_accepted_sha256").?.string,
    );
    const conversion = azure_object.get("conversion").?.object;
    try std.testing.expectEqualStrings(
        digest,
        conversion.get("source").?.object.get("sha256_before").?.string,
    );
    try std.testing.expectEqual(
        candidate_object.get("virtual_size").?.integer,
        conversion.get("parameters").?.object.get("expected_virtual_size").?.integer,
    );
    try std.testing.expect(support.isExactOrderedStrings(
        azure_object.get("contracts"),
        &contracts.full_azure_contracts,
    ));
    try std.testing.expect(support.isExactOrderedStrings(
        candidate_object.get("azure_contracts"),
        &contracts.full_azure_contracts,
    ));
}

test "the core candidate and result bind flavor metadata and contracts" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-core";
    try fixture.makeBundle(&subject, key, .{});
    try validateAzure(&subject, key);

    const manifest_path = try subject.manifestPath(key);
    defer allocator.free(manifest_path);
    var candidate = try fixture.read(allocator, io, manifest_path);
    defer candidate.deinit();
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);
    var azure = try fixture.read(allocator, io, result_path);
    defer azure.deinit();

    const candidate_object = candidate.value.object;
    const azure_object = azure.value.object;
    try std.testing.expectEqualStrings("core", candidate_object.get("flavor").?.string);
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.core.qcow2",
        candidate_object.get("asset_name").?.string,
    );
    try std.testing.expect(support.isExactOrderedStrings(
        candidate_object.get("azure_contracts"),
        &contracts.core_azure_contracts,
    ));
    for ([_][]const u8{
        "source_commit",
        "architecture",
        "flavor",
        "asset_name",
    }) |field| {
        try std.testing.expectEqualStrings(
            candidate_object.get(field).?.string,
            azure_object.get(field).?.string,
        );
    }
    const signing = candidate_object.get("uki_signing").?.object;
    try std.testing.expectEqualStrings(
        candidate_object.get("sha256").?.string,
        azure_object.get("qcow_sha256").?.string,
    );
    for ([_][]const u8{
        "certificate_sha256",
        "signing_certificate_sha256",
        "fallback_uki_sha256",
    }) |field| {
        try std.testing.expectEqualStrings(
            signing.get(field).?.string,
            azure_object.get(field).?.string,
        );
    }
    try std.testing.expect(support.jsonEqual(
        azure_object.get("contracts").?,
        candidate_object.get("azure_contracts").?,
    ));
}

/// The native acceptance result the core validation workflow produces.
fn writeNativeResult(
    subject: *const Tree,
    key: []const u8,
    candidate: *const std.json.ObjectMap,
) ![]u8 {
    const path = try subject.path("candidates/{s}/native-result.json", .{key});
    errdefer allocator.free(path);
    const signing = candidate.get("uki_signing").?.object;
    const contract_list = try fixture.joinContracts(
        allocator,
        &contracts.core_native_contracts,
    );
    defer allocator.free(contract_list);
    var quoted: std.ArrayList(u8) = .empty;
    defer quoted.deinit(allocator);
    for (contracts.core_native_contracts, 0..) |item, index| {
        if (index != 0) try quoted.appendSlice(allocator, ", ");
        try quoted.print(allocator, "\"{s}\"", .{item});
    }
    const text = try std.fmt.allocPrint(allocator,
        \\{{"schema": 5, "type": "ubuntu2604-local-secure-boot-acceptance",
        \\"architecture": "{s}", "flavor": "{s}", "virtual_size": {d},
        \\"candidate_sha256": "{s}", "certificate_sha256": "{s}",
        \\"fallback_uki_sha256": "{s}", "contracts": [{s}],
        \\"android_smoke": {{"provenance_sha256": "{s}", "runtime_sha256": "{s}",
        \\  "bundle_sha256": "{s}", "config_sha256": "{s}",
        \\  "architecture": "{s}", "candidate_key": "{s}"}}}}
    , .{
        candidate.get("architecture").?.string,
        candidate.get("flavor").?.string,
        candidate.get("virtual_size").?.integer,
        candidate.get("sha256").?.string,
        signing.get("certificate_sha256").?.string,
        signing.get("fallback_uki_sha256").?.string,
        quoted.items,
        fixture.android_provenance_sha256,
        fixture.android_runtime_sha256,
        fixture.android_bundle_sha256,
        fixture.android_config_sha256,
        candidate.get("architecture").?.string,
        key,
    });
    defer allocator.free(text);
    try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = text });
    return path;
}

fn validateNative(subject: *const Tree, key: []const u8, path: []const u8) !void {
    var candidate = try verify(subject, key);
    defer candidate.deinit();
    var diagnostic: support.Diagnostic = .{};
    var result = try documents.validateNativeResult(
        allocator,
        io,
        &candidate,
        path,
        &diagnostic,
    );
    result.deinit();
}

test "the core native result binds the candidate identity and contracts" {
    var subject = try tree();
    defer subject.deinit();
    const key = "aarch64-core";
    try fixture.makeBundle(&subject, key, .{});

    const manifest_path = try subject.manifestPath(key);
    defer allocator.free(manifest_path);
    var candidate = try fixture.read(allocator, io, manifest_path);
    defer candidate.deinit();
    const native_path = try writeNativeResult(&subject, key, &candidate.value.object);
    defer allocator.free(native_path);
    try validateNative(&subject, key, native_path);

    var result = try fixture.read(allocator, io, native_path);
    defer result.deinit();
    try std.testing.expectEqualStrings(
        "aarch64",
        result.value.object.get("architecture").?.string,
    );
    try std.testing.expectEqualStrings(
        "core",
        result.value.object.get("flavor").?.string,
    );
    try std.testing.expect(support.hasExactContracts(
        result.value.object.get("contracts"),
        &contracts.core_native_contracts,
    ));

    const virtual_size = candidate.value.object.get("virtual_size").?.integer;
    const mutations = [_]struct {
        steps: []const Step,
        change: fixture.Change,
    }{
        .{ .steps = &.{.{ .key = "schema" }}, .change = .{ .set = .{ .integer = 1 } } },
        .{
            .steps = &.{.{ .key = "architecture" }},
            .change = .{ .set = .{ .string = "x86_64" } },
        },
        .{
            .steps = &.{.{ .key = "virtual_size" }},
            .change = .{ .set = .{ .integer = virtual_size + 1 } },
        },
        .{
            .steps = &.{.{ .key = "candidate_sha256" }},
            .change = .{ .set = .{ .string = "0" ** 64 } },
        },
        .{ .steps = &.{.{ .key = "contracts" }}, .change = .pop },
        .{
            .steps = &.{ .{ .key = "android_smoke" }, .{ .key = "architecture" } },
            .change = .{ .set = .{ .string = "x86_64" } },
        },
        .{
            .steps = &.{ .{ .key = "android_smoke" }, .{ .key = "candidate_key" } },
            .change = .{ .set = .{ .string = "x86_64-core" } },
        },
        .{
            .steps = &.{ .{ .key = "android_smoke" }, .{ .key = "runtime_sha256" } },
            .change = .{ .set = .{ .string = "F" ** 64 } },
        },
    };
    for (mutations) |mutation| {
        try fixture.patch(allocator, io, native_path, mutation.steps, mutation.change);
        try std.testing.expectError(
            error.Failed,
            validateNative(&subject, key, native_path),
        );
        allocator.free(try writeNativeResult(&subject, key, &candidate.value.object));
    }
}

test "the contract sets cover the acceptance each flavor actually performs" {
    // Full Azure acceptance: Trusted Launch, the enrolled signer, and the
    // cloud-init/WALinuxAgent server contract.
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "agent-ready",
            "cloud-init-provisioning",
            "kernel-lockdown",
            "key-only-ssh",
            "managed-data-disk",
            "matching-architecture-gen2",
            "module-signatures",
            "reboot-reconnect",
            "root-growth",
            "runtime-release-identity",
            "secure-boot",
            "signed-uki",
            "trusted-launch",
            "uefi-db-signer",
            "vtpm",
        },
        &contracts.full_azure_contracts,
    );
    // Core Azure acceptance: the appliance contract, plus the Binder and
    // Android container smoke evidence the appliance exists to provide.
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "agent-ready",
            "android-container-abi-matched",
            "android-container-boot-completed",
            "android-container-graceful-stop",
            "android-smoke-provenance-bound",
            "azagent-provisioning",
            "binder-devices-usable",
            "binder-module-signed",
            "binderfs-mounted",
            "identity-persistence",
            "kernel-lockdown",
            "key-only-ssh",
            "managed-data-disk-mount-only",
            "matching-architecture-gen2",
            "mizinit-pid1",
            "module-signatures",
            "no-anbox-evidence",
            "no-cloud-init",
            "no-dkms-binder-module",
            "no-systemd-service-manager",
            "no-walinuxagent",
            "pid1-supervised-sshd",
            "reboot-reconnect",
            "resource-disk",
            "root-growth",
            "runtime-release-identity",
            "secure-boot",
            "signed-uki",
            "sshd-restart-reconnect",
            "trusted-launch",
            "uefi-db-signer",
            "vtpm",
        },
        &contracts.core_azure_contracts,
    );
    try std.testing.expectEqualDeep(
        &[_][]const u8{
            "android-container-abi-match",
            "android-container-boot-completed",
            "android-smoke-artifact-provenance",
            "android-smoke-graceful-stop",
            "azagent-provisioning",
            "binder-boot-required",
            "binder-device-usability",
            "binderfs-dynamic-devices",
            "clean-service-health",
            "generalized-identity",
            "gpt-layout",
            "kernel-lockdown",
            "key-only-ssh",
            "local-ovf-azagent-skip-ready",
            "matching-architecture-native-kvm",
            "mizinit-pid1",
            "mizinit-sshd-supervision",
            "module-signatures",
            "no-cloud-init",
            "no-walinuxagent",
            "persistent-provisioned-state",
            "reboot-reconnect",
            "root-growth",
            "secure-boot",
            "signed-binder-module",
            "signed-uki",
            "sshd-restart",
            "standalone-zstd-qcow2",
            "tampered-uki-rejected",
            "uefi-db-signer",
            "vtpm",
        },
        &contracts.core_native_contracts,
    );
}

test "Azure root growth is measured from the original root geometry" {
    var script = try @import("ubuntu2604_source.zig").Source.open(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer script.deinit();
    try script.expectContains("x86_64) root_first_lba=2324480");
    try script.expectContains("aarch64) root_first_lba=2099200");
    try script.expectContains(
        "original_root_size=$(((last_usable_lba - root_first_lba + 1) * gpt_sector_size))",
    );
    try script.expectContains(
        "minimum_grown_root_size=$((original_root_size + 1073741824))",
    );
    try script.expectContains("test \"$root_size\" -gt \"$minimum_grown_root_size\"");
    try script.expectOmits("test \"$root_size\" -gt $((original_size + 1073741824))");

    // The growth threshold has to be reachable from the enlarged disk and
    // unreachable from the source disk, for both architectures.
    const source_disk_size: u64 = 5 * 1024 * 1024 * 1024;
    const expanded_disk_size: u64 = 7 * 1024 * 1024 * 1024;
    const gibibyte: u64 = 1024 * 1024 * 1024;
    for ([_]u64{ 2324480, 2099200 }) |first_lba| {
        const original = rootSize(source_disk_size, first_lba);
        const maximum = rootSize(expanded_disk_size, first_lba);
        try std.testing.expect(maximum < source_disk_size + gibibyte);
        try std.testing.expect(maximum > original + gibibyte);
    }
}

fn rootSize(disk_size: u64, first_lba: u64) u64 {
    const sector_size: u64 = 512;
    const partition_array_sectors: u64 = 32;
    const last_usable_lba = disk_size / sector_size - 2 - partition_array_sectors;
    return (last_usable_lba - first_lba + 1) * sector_size;
}

test "the full Azure service contract matches Ubuntu 26.04" {
    var script = try @import("ubuntu2604_source.zig").Source.open(
        allocator,
        "scripts/ubuntu2604_azure_acceptance.sh",
    );
    defer script.deinit();
    try script.expectContains("cloud-init-network.service");
    try script.expectOmits("cloud-init.service");
    try script.expectContains(
        "check network-online systemctl is-active --quiet network-online.target",
    );
    try script.expectOmits("networkctl is-online");
    try script.expectContains("FAIL %s (exit %s)");
    try script.expectContains("failed_units=$(systemctl --failed --no-legend --plain)");
    try script.expectContains("check no-failed-units test -z");
    try script.expectContains(
        "check conventional-resource-disk-policy validate_conventional_resource_disk",
    );
    try script.expectOmits(
        "check conventional-resource-disk-not-mounted not_mountpoint /mnt",
    );
    try script.expectContains("instanceView.bootDiagnostics.serialConsoleLogBlobUri");
}

test "an Azure result whose contracts are not the candidate's is rejected" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-core";
    try fixture.makeBundle(&subject, key, .{});
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = support.Builder.init(arena.allocator());
    try fixture.patch(
        allocator,
        io,
        result_path,
        &.{.{ .key = "contracts" }},
        .{ .set = try builder.strings(&contracts.full_azure_contracts) },
    );
    try expectAzureRejected(&subject, key);
}

test "the core Azure result rejects every candidate binding change" {
    const key = "x86_64-core";
    const mutations = [_]struct { field: []const u8, replacement: []const u8 }{
        .{ .field = "source_commit", .replacement = "b" ** 40 },
        .{ .field = "architecture", .replacement = "aarch64" },
        .{
            .field = "asset_name",
            .replacement = "Ubuntu-26.04-aarch64.core.qcow2",
        },
        .{ .field = "qcow_sha256", .replacement = "0" ** 64 },
        .{ .field = "certificate_sha256", .replacement = "1" ** 64 },
        .{ .field = "signing_certificate_sha256", .replacement = "2" ** 64 },
        .{ .field = "fallback_uki_sha256", .replacement = "9" ** 64 },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, key, .{});
        const result_path = try subject.azureResultPath(key);
        defer allocator.free(result_path);
        try fixture.patchString(
            allocator,
            io,
            result_path,
            &.{.{ .key = mutation.field }},
            mutation.replacement,
        );
        try expectAzureRejected(&subject, key);
    }
}

test "the core Azure result binds Android smoke provenance at schema 2" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-core";
    try fixture.makeBundle(&subject, key, .{});
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);

    var result = try fixture.read(allocator, io, result_path);
    defer result.deinit();
    try std.testing.expectEqual(@as(i64, 2), result.value.object.get("schema").?.integer);
    const smoke = result.value.object.get("android_smoke").?.object;
    try std.testing.expectEqualStrings(
        fixture.android_provenance_sha256,
        smoke.get("provenance_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.android_runtime_sha256,
        smoke.get("runtime_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.android_bundle_sha256,
        smoke.get("bundle_sha256").?.string,
    );
    try std.testing.expectEqualStrings(
        fixture.android_config_sha256,
        smoke.get("config_sha256").?.string,
    );
    try std.testing.expectEqualStrings("x86_64", smoke.get("architecture").?.string);
    try std.testing.expectEqualStrings(key, smoke.get("candidate_key").?.string);
    try validateAzure(&subject, key);

    // Schema 1 is the shape from before this binding existed and can never
    // satisfy the current core contract set.
    try fixture.patchInteger(allocator, io, result_path, &.{.{ .key = "schema" }}, 1);
    try expectAzureRejected(&subject, key);
}

test "a full-flavor Azure result never carries Android smoke provenance" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const result_path = try subject.azureResultPath(key);
    defer allocator.free(result_path);

    var result = try fixture.read(allocator, io, result_path);
    defer result.deinit();
    try std.testing.expect(result.value.object.get("android_smoke") == null);
    result.deinit();
    result = try fixture.read(allocator, io, result_path);

    // The full field set is exact, so injecting the binding is rejected.
    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const builder = support.Builder.init(arena.allocator());
    var smoke = builder.object();
    try builder.putString(&smoke, "provenance_sha256", fixture.android_provenance_sha256);
    try builder.putString(&smoke, "runtime_sha256", fixture.android_runtime_sha256);
    try builder.putString(&smoke, "bundle_sha256", fixture.android_bundle_sha256);
    try builder.putString(&smoke, "config_sha256", fixture.android_config_sha256);
    try builder.putString(&smoke, "architecture", "x86_64");
    try builder.putString(&smoke, "candidate_key", key);
    try fixture.patch(
        allocator,
        io,
        result_path,
        &.{.{ .key = "android_smoke" }},
        .{ .set = .{ .object = smoke } },
    );
    try expectAzureRejected(&subject, key);
}

/// Re-runs `azure-result` with one option changed, which is how the command's
/// own argument contract is probed.
fn rerunAzureResult(
    subject: *const Tree,
    key: []const u8,
    mutate: *const fn (*commands.AzureResultOptions) void,
) !void {
    const entry = contracts.lookup(key).?;
    const flavor = contracts.parseFlavor(entry.flavor).?;
    const manifest = try subject.manifestPath(key);
    defer allocator.free(manifest);
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    const vhd = try subject.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);
    const vhd_info = try subject.path("azure/{s}/vhd-info.json", .{key});
    defer allocator.free(vhd_info);
    const conversion = try subject.path(
        "azure/{s}/conversion-attestation.json",
        .{key},
    );
    defer allocator.free(conversion);
    const request = try subject.path("azure/{s}/request.json", .{key});
    defer allocator.free(request);
    const response = try subject.path("azure/{s}/response.json", .{key});
    defer allocator.free(response);
    const output = try subject.path("azure/{s}/rerun.json", .{key});
    defer allocator.free(output);
    const resource_group = try std.fmt.allocPrint(allocator, "ubuntu-{s}", .{key});
    defer allocator.free(resource_group);
    const image_version_id = try std.fmt.allocPrint(
        allocator,
        "/subscriptions/test/gallery/ubuntu/{s}/versions/1.0.0",
        .{key},
    );
    defer allocator.free(image_version_id);
    const contract_list = try fixture.joinContracts(
        allocator,
        contracts.azureContracts(flavor),
    );
    defer allocator.free(contract_list);

    var options = fixture.azureResultOptions(.{
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
    });
    mutate(&options);
    var diagnostic: support.Diagnostic = .{};
    return commands.azureResult(allocator, io, options, &diagnostic);
}

fn addSmokeToFull(options: *commands.AzureResultOptions) void {
    options.android_smoke_provenance_sha256 = fixture.android_provenance_sha256;
}

fn clearProvenanceDigest(options: *commands.AzureResultOptions) void {
    options.android_smoke_provenance_sha256 = null;
}

fn clearRuntimeDigest(options: *commands.AzureResultOptions) void {
    options.android_smoke_runtime_sha256 = null;
}

fn clearBundleDigest(options: *commands.AzureResultOptions) void {
    options.android_smoke_bundle_sha256 = null;
}

fn clearConfigDigest(options: *commands.AzureResultOptions) void {
    options.android_smoke_config_sha256 = null;
}

fn useFullContracts(options: *commands.AzureResultOptions) void {
    options.contracts = "agent-ready,cloud-init-provisioning,kernel-lockdown," ++
        "key-only-ssh,managed-data-disk,matching-architecture-gen2," ++
        "module-signatures,reboot-reconnect,root-growth," ++
        "runtime-release-identity,secure-boot,signed-uki,trusted-launch," ++
        "uefi-db-signer,vtpm";
}

test "azure-result rejects Android smoke arguments for the full flavor" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, "x86_64-full", addSmokeToFull),
    );
}

test "azure-result requires every Android smoke argument for the core flavor" {
    const mutators = [_]*const fn (*commands.AzureResultOptions) void{
        clearProvenanceDigest,
        clearRuntimeDigest,
        clearBundleDigest,
        clearConfigDigest,
    };
    for (mutators) |mutate| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, "x86_64-core", .{});
        try std.testing.expectError(
            error.Failed,
            rerunAzureResult(&subject, "x86_64-core", mutate),
        );
    }
}

test "azure-result rejects a non-canonical contract argument" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-core", .{});
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, "x86_64-core", useFullContracts),
    );
}

test "the core Azure result rejects Android smoke provenance mismatches" {
    const mutations = [_]struct { field: []const u8, replacement: []const u8 }{
        .{ .field = "provenance_sha256", .replacement = "not-a-digest" },
        .{ .field = "runtime_sha256", .replacement = "F" ** 64 },
        .{ .field = "bundle_sha256", .replacement = "not-a-digest" },
        .{ .field = "architecture", .replacement = "aarch64" },
        .{ .field = "candidate_key", .replacement = "aarch64-core" },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        const key = "x86_64-core";
        try fixture.makeBundle(&subject, key, .{});
        const result_path = try subject.azureResultPath(key);
        defer allocator.free(result_path);
        try fixture.patchString(
            allocator,
            io,
            result_path,
            &.{ .{ .key = "android_smoke" }, .{ .key = mutation.field } },
            mutation.replacement,
        );
        try expectAzureRejected(&subject, key);
    }
}

test "an unknown flavor has no Azure contract set" {
    try std.testing.expect(contracts.parseFlavor("minimal") == null);
    try std.testing.expect(contracts.parseFlavor("") == null);
}

test "candidate rejects a build-validation digest that is not the asset's" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const entry = contracts.lookup(key).?;
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    const provenance_dir = try subject.provenanceDir(key);
    defer allocator.free(provenance_dir);
    const output = try subject.path("candidates/{s}/rejected.json", .{key});
    defer allocator.free(output);

    var diagnostic: support.Diagnostic = .{};
    try std.testing.expectError(error.Failed, commands.candidate(allocator, io, .{
        .key = key,
        .architecture = entry.architecture,
        .flavor = entry.flavor,
        .asset = asset,
        .validated_sha256 = "0" ** 64,
        .virtual_size = fixture.virtual_size,
        .source_commit = fixture.source_commit,
        .provenance_dir = provenance_dir,
        .runner = "runner",
        .run_id = "1",
        .run_attempt = "1",
        .output = output,
    }, &diagnostic));
    try std.testing.expectEqualStrings(
        "x86_64-full: build validation digest does not match candidate bytes",
        diagnostic.message(),
    );
}

test "verify rejects tampered candidate bytes" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const asset = try subject.assetPath(key);
    defer allocator.free(asset);
    try Dir.cwd().writeFile(io, .{ .sub_path = asset, .data = "tampered" });

    const manifest = try subject.manifestPath(key);
    defer allocator.free(manifest);
    var diagnostic: support.Diagnostic = .{};
    try std.testing.expectError(error.Failed, documents.verifyCandidate(
        allocator,
        io,
        manifest,
        asset,
        null,
        null,
        &diagnostic,
    ));
}

test "stage rejects a missing or duplicated candidate document" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const manifest = try subject.manifestPath("aarch64-full");
    defer allocator.free(manifest);
    try Dir.cwd().deleteFile(io, manifest);
    try expectStageRejected(&subject);

    try remake(&subject, "aarch64-full");
    const extra = try subject.path("candidates/unexpected", .{});
    defer allocator.free(extra);
    try Dir.cwd().createDirPath(io, extra);
    const source_manifest = try subject.manifestPath("x86_64-full");
    defer allocator.free(source_manifest);
    const extra_manifest = try subject.path(
        "candidates/unexpected/candidate.json",
        .{},
    );
    defer allocator.free(extra_manifest);
    try Dir.cwd().copyFile(source_manifest, Dir.cwd(), extra_manifest, io, .{});
    try expectStageRejected(&subject);
}

test "stage requires exactly two Azure results" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const result_path = try subject.azureResultPath("aarch64-full");
    defer allocator.free(result_path);
    try Dir.cwd().deleteFile(io, result_path);
    try expectStageRejected(&subject);
}

test "stage never expands publication to the core assets" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    try fixture.makeBundle(&subject, "x86_64-core", .{});
    try expectStageRejected(&subject);
    try std.testing.expectEqual(@as(usize, 2), contracts.release_order.len);
    for (contracts.release_order) |key| {
        try std.testing.expectEqualStrings("full", contracts.lookup(key).?.flavor);
    }
}

test "stage rejects an extra QCOW2 and a checksum sidecar" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const extra = try subject.path("candidates/extra.qcow2", .{});
    defer allocator.free(extra);
    try Dir.cwd().writeFile(io, .{ .sub_path = extra, .data = "extra" });
    try expectStageRejected(&subject);
    try Dir.cwd().deleteFile(io, extra);

    const sidecar = try subject.path("azure/forbidden.sha256", .{});
    defer allocator.free(sidecar);
    try Dir.cwd().writeFile(io, .{ .sub_path = sidecar, .data = "0" ** 64 });
    try expectStageRejected(&subject);
}

test "stage rejects source commit and identity changes" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const manifest = try subject.manifestPath("x86_64-full");
    defer allocator.free(manifest);

    try fixture.patchString(
        allocator,
        io,
        manifest,
        &.{.{ .key = "source_commit" }},
        "b" ** 40,
    );
    try expectStageRejected(&subject);

    try fixture.patchString(
        allocator,
        io,
        manifest,
        &.{.{ .key = "source_commit" }},
        fixture.source_commit,
    );
    try fixture.patchString(
        allocator,
        io,
        manifest,
        &.{.{ .key = "asset_name" }},
        "other.qcow2",
    );
    try expectStageRejected(&subject);
}

test "stage rejects tampered or unbound provenance" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const manifest_file = try subject.path(
        "candidates/x86_64-full/internal-provenance/ubuntu-26.04-server-cloudimg-amd64.manifest",
        .{},
    );
    defer allocator.free(manifest_file);
    try Dir.cwd().writeFile(io, .{ .sub_path = manifest_file, .data = "tampered" });
    try expectStageRejected(&subject);

    try remake(&subject, "x86_64-full");
    const unbound = try subject.path(
        "candidates/x86_64-full/internal-provenance/unbound.log",
        .{},
    );
    defer allocator.free(unbound);
    try Dir.cwd().writeFile(io, .{ .sub_path = unbound, .data = "new" });
    try expectStageRejected(&subject);
}

fn validateUbuntu(
    subject: *const Tree,
    key: []const u8,
    architecture: []const u8,
    flavor: contracts.Flavor,
    virtual_size: ?i64,
) !void {
    const root = try subject.provenanceDir(key);
    defer allocator.free(root);
    var diagnostic: support.Diagnostic = .{};
    var document = try provenance.validateUbuntu(
        allocator,
        io,
        root,
        architecture,
        flavor,
        virtual_size,
        &diagnostic,
    );
    document.deinit();
}

fn expectUbuntuRejected(
    subject: *const Tree,
    key: []const u8,
    architecture: []const u8,
    flavor: contracts.Flavor,
    virtual_size: ?i64,
) !void {
    try std.testing.expectError(
        error.Failed,
        validateUbuntu(subject, key, architecture, flavor, virtual_size),
    );
}

test "Ubuntu provenance requires immutable, signed snapshot inputs" {
    const mutations = [_]struct { steps: []const Step, change: fixture.Change }{
        .{
            .steps = &.{ .{ .key = "snapshot" }, .{ .key = "base_url" } },
            .change = .{
                .set = .{
                    .string = "https://cloud-images.ubuntu.com/releases/26.04/current/",
                },
            },
        },
        .{
            .steps = &.{.{ .key = "canonical_key_fingerprint" }},
            .change = .{ .set = .{ .string = "not-a-fingerprint" } },
        },
        .{
            .steps = &.{.{ .key = "sha256sums_signature_verified" }},
            .change = .{ .set = .{ .bool = false } },
        },
        .{
            .steps = &.{ .{ .key = "artifacts" }, .{ .key = "source_image" } },
            .change = .remove,
        },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, "x86_64-full", .{});
        const path = try subject.path(
            "candidates/x86_64-full/internal-provenance/{s}",
            .{contracts.ubuntu_provenance_filename},
        );
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
    }
}

test "Ubuntu provenance requires the exact architecture disk layout" {
    for ([_][2][]const u8{
        .{ "x86_64-full", "x86_64" },
        .{ "aarch64-full", "aarch64" },
    }) |entry| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, entry[0], .{});
        try validateUbuntu(&subject, entry[0], entry[1], .full, null);
    }
}

test "Ubuntu provenance rejects disk layout changes" {
    const mutations = [_]struct { steps: []const Step, change: fixture.Change }{
        .{
            .steps = &.{ .{ .key = "disk_layout" }, .{ .key = "transform" } },
            .change = .{ .set = .{ .string = "preserved" } },
        },
        .{
            .steps = &.{
                .{ .key = "disk_layout" },
                .{ .key = "esp" },
                .{ .key = "last_lba" },
            },
            .change = .{ .set = .{ .integer = 1_050_622 } },
        },
        .{
            .steps = &.{
                .{ .key = "disk_layout" },
                .{ .key = "esp" },
                .{ .key = "table_index" },
            },
            .change = .{ .set = .{ .bool = true } },
        },
        .{
            .steps = &.{
                .{ .key = "disk_layout" },
                .{ .key = "retired_xbootldr" },
                .{ .key = "cleared" },
            },
            .change = .{ .set = .{ .bool = false } },
        },
        .{
            .steps = &.{ .{ .key = "disk_layout" }, .{ .key = "unexpected" } },
            .change = .{ .set = .{ .string = "value" } },
        },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, "aarch64-full", .{});
        const path = try subject.path(
            "candidates/aarch64-full/internal-provenance/{s}",
            .{contracts.ubuntu_provenance_filename},
        );
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        try expectUbuntuRejected(&subject, "aarch64-full", "aarch64", .full, null);
    }
}

test "Ubuntu provenance binds the source image and manifest checksums" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const root = try subject.provenanceDir("x86_64-full");
    defer allocator.free(root);
    const checksum_path = try std.fs.path.join(allocator, &.{ root, "SHA256SUMS" });
    defer allocator.free(checksum_path);

    const original = try Dir.cwd().readFileAlloc(
        io,
        checksum_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(original);
    // Drop the last binding, then re-bind the truncated file so only the
    // SHA256SUMS content itself is different.
    var lines = std.mem.splitScalar(u8, std.mem.trimEnd(u8, original, "\n"), '\n');
    var truncated: std.ArrayList(u8) = .empty;
    defer truncated.deinit(allocator);
    var kept: usize = 0;
    const total = std.mem.count(u8, std.mem.trimEnd(u8, original, "\n"), "\n") + 1;
    while (lines.next()) |line| : (kept += 1) {
        if (kept + 1 == total) break;
        try truncated.appendSlice(allocator, line);
        try truncated.append(allocator, '\n');
    }
    try Dir.cwd().writeFile(io, .{
        .sub_path = checksum_path,
        .data = truncated.items,
    });

    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    const digest = support.digest.hexBytes(truncated.items);
    try fixture.patchString(
        allocator,
        io,
        path,
        &.{
            .{ .key = "artifacts" },
            .{ .key = "sha256sums" },
            .{ .key = "sha256" },
        },
        &digest,
    );
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "Ubuntu provenance binds the debz lock and transaction together" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patchString(allocator, io, path, &.{
        .{ .key = "debz" },
        .{ .key = "transactions" },
        .{ .index = 0 },
        .{ .key = "transaction_provenance" },
        .{ .key = "lock_sha256" },
    }, "0" ** 64);
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "Ubuntu provenance requires a locked baseline for both architectures" {
    for ([_][2][]const u8{
        .{ "x86_64-full", "x86_64" },
        .{ "aarch64-full", "aarch64" },
    }) |entry| {
        var subject = try tree();
        defer subject.deinit();
        try fixture.makeBundle(&subject, entry[0], .{});
        const root = try subject.provenanceDir(entry[0]);
        defer allocator.free(root);
        const metadata = try std.fs.path.join(
            allocator,
            &.{ root, contracts.ubuntu_provenance_filename },
        );
        defer allocator.free(metadata);

        var document = try fixture.read(allocator, io, metadata);
        defer document.deinit();
        const transaction = document.value.object
            .get("debz").?.object
            .get("transactions").?.array.items[0].object;
        const lock_name = transaction
            .get("exact_lock").?.object
            .get("filename").?.string;
        const lock_path = try std.fs.path.join(allocator, &.{ root, lock_name });
        defer allocator.free(lock_path);

        // Removing every retained package leaves a lock that proves no closure.
        try fixture.patch(
            allocator,
            io,
            lock_path,
            &.{ .{ .key = "packages" }, .{ .index = 0 } },
            .remove,
        );
        const lock_bytes = try Dir.cwd().readFileAlloc(
            io,
            lock_path,
            allocator,
            .limited(64 * 1024),
        );
        defer allocator.free(lock_bytes);
        const digest = support.digest.hexBytes(lock_bytes);
        try fixture.patchString(allocator, io, metadata, &.{
            .{ .key = "debz" },
            .{ .key = "transactions" },
            .{ .index = 0 },
            .{ .key = "exact_lock" },
            .{ .key = "sha256" },
        }, &digest);
        try expectUbuntuRejected(&subject, entry[0], entry[1], .full, null);
    }
}

test "Ubuntu provenance requires the explicit baseline contract" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patchString(
        allocator,
        io,
        path,
        &.{ .{ .key = "debz" }, .{ .key = "baseline" }, .{ .key = "enforcement" } },
        "transaction-actions-only",
    );
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "Ubuntu provenance requires stably ordered debz transactions" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    const path = try subject.path(
        "candidates/x86_64-full/internal-provenance/{s}",
        .{contracts.ubuntu_provenance_filename},
    );
    defer allocator.free(path);
    try fixture.patch(
        allocator,
        io,
        path,
        &.{ .{ .key = "debz" }, .{ .key = "transactions" } },
        .reverse,
    );
    try expectUbuntuRejected(&subject, "x86_64-full", "x86_64", .full, null);
}

test "core Ubuntu provenance matches the builder contract" {
    var subject = try tree();
    defer subject.deinit();
    const key = "aarch64-core";
    try fixture.makeBundle(&subject, key, .{});
    try validateUbuntu(&subject, key, "aarch64", .core, fixture.virtual_size);

    const path = try subject.path(
        "candidates/{s}/internal-provenance/{s}",
        .{ key, contracts.ubuntu_provenance_filename },
    );
    defer allocator.free(path);
    var document = try fixture.read(allocator, io, path);
    defer document.deinit();
    try std.testing.expectEqualStrings(
        "core",
        document.value.object.get("flavor").?.string,
    );
    try std.testing.expectEqualStrings(
        "signed-gpt-esp-substrate",
        document.value.object
            .get("artifacts").?.object
            .get("source_image").?.object
            .get("role").?.string,
    );
    try std.testing.expect(support.isExactOrderedStrings(
        document.value.object.get("debz").?.object.get("package_roots"),
        &contracts.core_debz_packages,
    ));
    const transactions = document.value.object
        .get("debz").?.object
        .get("transactions").?.array.items;
    try std.testing.expectEqual(contracts.core_debz_packages.len, transactions.len);
    for (transactions, contracts.core_debz_packages) |item, package| {
        try std.testing.expectEqualStrings(
            package,
            item.object.get("package").?.string,
        );
    }
}

test "core Ubuntu provenance rejects contract changes" {
    const mutations = [_]struct { steps: []const Step, change: fixture.Change }{
        .{
            .steps = &.{.{ .key = "flavor" }},
            .change = .{ .set = .{ .string = "full" } },
        },
        .{
            .steps = &.{
                .{ .key = "artifacts" },
                .{ .key = "source_image" },
                .{ .key = "role" },
            },
            .change = .{ .set = .{ .string = "root-filesystem" } },
        },
        .{
            .steps = &.{ .{ .key = "debz" }, .{ .key = "package_roots" } },
            .change = .reverse,
        },
        .{
            .steps = &.{
                .{ .key = "debz" },
                .{ .key = "baseline" },
                .{ .key = "source" },
            },
            .change = .{ .set = .{ .string = "canonical-image-dpkg-status" } },
        },
        .{
            .steps = &.{.{ .key = "validated_root_free_bytes" }},
            .change = .{ .set = .{ .integer = 0 } },
        },
        .{
            .steps = &.{.{ .key = "virtual_size" }},
            .change = .{ .set = .{ .integer = 3 * 1024 * 1024 } },
        },
    };
    for (mutations) |mutation| {
        var subject = try tree();
        defer subject.deinit();
        const key = "x86_64-core";
        try fixture.makeBundle(&subject, key, .{});
        const path = try subject.path(
            "candidates/{s}/internal-provenance/{s}",
            .{ key, contracts.ubuntu_provenance_filename },
        );
        defer allocator.free(path);
        try fixture.patch(allocator, io, path, mutation.steps, mutation.change);
        try expectUbuntuRejected(&subject, key, "x86_64", .core, fixture.virtual_size);
    }
}

test "stage refuses PEM, DER, and embedded private key material" {
    const payloads = [_][]const u8{
        "-----BEGIN PRIVATE KEY-----\nsecret\n",
        "-----BEGIN DSA PRIVATE KEY-----\nsecret\n",
        &[_]u8{ 0x30, 0x82, 0x00, 0x08, 0x02, 0x01, 0x00, 0x30, 0x00, 0x00, 0x00, 0x00 },
        "prefix\n" ++ &[_]u8{
            0x30, 0x0c, 0x30, 0x07, 0x06, 0x03, 0x2a, 0x03,
            0x04, 0x05, 0x00, 0x04, 0x01, 0x00,
        },
        "binary-prefix\x00openssh-key-v1\x00binary-private-key",
    };
    for (payloads) |payload| {
        var subject = try tree();
        defer subject.deinit();
        try makeAll(&subject);
        const path = try subject.path(
            "candidates/x86_64-full/internal-provenance/ubuntu-26.04-server-cloudimg-amd64.manifest",
            .{},
        );
        defer allocator.free(path);
        try Dir.cwd().writeFile(io, .{ .sub_path = path, .data = payload });
        try expectStageRejected(&subject);
    }
}

test "stage rejects acceptance digest and contract changes" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(path);

    try fixture.patchString(
        allocator,
        io,
        path,
        &.{.{ .key = "azure_accepted_sha256" }},
        "0" ** 64,
    );
    try expectStageRejected(&subject);

    try remake(&subject, "x86_64-full");
    try fixture.patch(allocator, io, path, &.{.{ .key = "contracts" }}, .pop);
    try expectStageRejected(&subject);
}

test "stage rejects acceptance status and derived VHD evidence changes" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(path);

    try fixture.patchString(allocator, io, path, &.{.{ .key = "status" }}, "failure");
    try expectStageRejected(&subject);

    try remake(&subject, "x86_64-full");
    try fixture.patchInteger(allocator, io, path, &.{
        .{ .key = "conversion" },
        .{ .key = "result" },
        .{ .key = "current_size" },
    }, fixture.virtual_size + 1024 * 1024);
    try expectStageRejected(&subject);
}

test "azure-result rejects a malformed derived VHD structure" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const vhd = try subject.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);

    const file = try Dir.cwd().openFile(io, vhd, .{ .mode = .read_write });
    defer file.close(io);
    const size = (try file.stat(io)).size;
    const zeros = [_]u8{0} ** 512;
    try file.writePositionalAll(io, &zeros, size - zeros.len);
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

fn keepOptions(_: *commands.AzureResultOptions) void {}

test "azure-result rejects a malformed qemu VHD info document" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const info = try subject.path("azure/{s}/vhd-info.json", .{key});
    defer allocator.free(info);
    try Dir.cwd().writeFile(io, .{
        .sub_path = info,
        .data = "{\"format\": \"raw\", \"virtual-size\": 2097152}",
    });
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

test "azure-result rejects an unrelated but structurally valid VHD" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const vhd = try subject.path("azure/{s}/temporary.vhd", .{key});
    defer allocator.free(vhd);

    const file = try Dir.cwd().openFile(io, vhd, .{ .mode = .read_write });
    defer file.close(io);
    try file.writePositionalAll(io, "unrelated", 0);
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

test "azure-result rejects a conversion parameter mismatch" {
    var subject = try tree();
    defer subject.deinit();
    const key = "x86_64-full";
    try fixture.makeBundle(&subject, key, .{});
    const attestation = try subject.path(
        "azure/{s}/conversion-attestation.json",
        .{key},
    );
    defer allocator.free(attestation);
    try fixture.patchString(
        allocator,
        io,
        attestation,
        &.{ .{ .key = "parameters" }, .{ .key = "input_sha256" } },
        "0" ** 64,
    );
    try std.testing.expectError(
        error.Failed,
        rerunAzureResult(&subject, key, keepOptions),
    );
}

test "stage rejects mixed UKI and Artifact Signing identities" {
    var subject = try tree();
    defer subject.deinit();
    try fixture.makeBundle(&subject, "x86_64-full", .{});
    try fixture.makeBundle(&subject, "aarch64-full", .{
        .certificate = "different certificate",
    });
    try expectStageRejected(&subject);

    try subject.removeBundle("aarch64-full");
    try fixture.makeBundle(&subject, "aarch64-full", .{
        .signing_certificate_sha256 = "5" ** 64,
    });
    try expectStageRejected(&subject);
}

test "stage rejects a changed Azure signing binding" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const path = try subject.azureResultPath("aarch64-full");
    defer allocator.free(path);
    try fixture.patchString(
        allocator,
        io,
        path,
        &.{.{ .key = "certificate_sha256" }},
        "0" ** 64,
    );
    try expectStageRejected(&subject);
}

test "stage rejects a release tag that is not a date" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    try std.testing.expectError(
        error.Failed,
        stage(&subject, "Ubuntu-26.04-latest"),
    );
}

test "a failed stage leaves the destination and notes untouched" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);

    const output = try subject.path("staged", .{});
    defer allocator.free(output);
    try Dir.cwd().createDirPath(io, output);
    const notes = try subject.path("release-notes.md", .{});
    defer allocator.free(notes);
    try Dir.cwd().writeFile(io, .{ .sub_path = notes, .data = "existing notes\n" });

    const result_path = try subject.azureResultPath("x86_64-full");
    defer allocator.free(result_path);
    try fixture.patch(allocator, io, result_path, &.{.{ .key = "contracts" }}, .pop);
    try expectStageRejected(&subject);

    var directory = try Dir.cwd().openDir(io, output, .{ .iterate = true });
    defer directory.close(io);
    var iterator = directory.iterate();
    try std.testing.expect(try iterator.next(io) == null);

    const remaining = try Dir.cwd().readFileAlloc(
        io,
        notes,
        allocator,
        .limited(1024),
    );
    defer allocator.free(remaining);
    try std.testing.expectEqualStrings("existing notes\n", remaining);

    // No transactional staging path survives the failure.
    var root_directory = try Dir.cwd().openDir(io, subject.root, .{ .iterate = true });
    defer root_directory.close(io);
    var root_iterator = root_directory.iterate();
    while (try root_iterator.next(io)) |item| {
        try std.testing.expect(
            !std.mem.startsWith(u8, item.name, ".staged.tmp-"),
        );
        try std.testing.expect(
            !std.mem.startsWith(u8, item.name, ".release-notes.md.tmp-"),
        );
    }
}

test "stage refuses a non-empty destination" {
    var subject = try tree();
    defer subject.deinit();
    try makeAll(&subject);
    const output = try subject.path("staged", .{});
    defer allocator.free(output);
    try Dir.cwd().createDirPath(io, output);
    const sentinel = try subject.path("staged/do-not-replace", .{});
    defer allocator.free(sentinel);
    try Dir.cwd().writeFile(io, .{ .sub_path = sentinel, .data = "sentinel" });

    try expectStageRejected(&subject);
    try std.testing.expect(support.isRegularFile(io, sentinel));
}

test "the production builder is native, qemu-free, and GnuPG-free" {
    const Source = @import("ubuntu2604_source.zig").Source;
    var builder = try Source.open(
        allocator,
        "scripts/build_generalized_ubuntu2604.zig",
    );
    defer builder.deinit();
    const production = try builder.section("", "test \"profiles pin");

    const source = @import("ubuntu2604_source.zig");
    if (source.findForbiddenProductionTool(production)) |match| {
        std.debug.print("builder uses {s}\n", .{match});
        return error.ForbiddenText;
    }
    // Issue #476: Ubuntu finalization emits the compressed release image
    // natively, so qemu tooling no longer appears in the builder at all.
    try source.expectOmitsIn(production, "\"qemu-img\"", "builder");
    try source.expectOmitsIn(production, "\"qemu-utils\"", "builder");
    try source.expectContainsIn(
        production,
        "miz.qcow2.writeStandaloneCompressed",
        "builder",
    );

    // The package root is imported and exported through the native mountless
    // ext4 path, never through an external image tool.
    const native = [_][]const u8{
        "miz.ext4_mountless.FileSystem.open",
        "exportHostTree",
        "importHostTree",
        "native_root.finish()",
        "cloudimg-rootfs",
        "materializeTrustedKeyring(allocator, io, trusted_keyring, external_keyring)",
        "const absolute_keyring = trusted.path",
        "realPathFileAlloc(io, destination",
        "assertTrustedKeyringUnchanged",
        // Arm64 UKIs are assembled from a normalized EFI kernel payload.
        "uki_kernel_payload.normalize(",
        ".linux = kernel_payload.bytes",
        // Canonical's signature is verified natively.
        "@embedFile(\"fixtures/canonical-ubuntu-cloud-image-key.asc\")",
        "verifyOpenPgpDetachedSignature",
        "PKCS1v1_5Signature.concatVerify",
        "NativeHttpsDownloader.init",
        "artifact_pipeline.acquireVerified",
    };
    for (native) |needle| try source.expectContainsIn(production, needle, "builder");
    const forbidden = [_][]const u8{
        "/dev/sda4",
        "/dev/sda3",
        "virt-tar-out",
        "virt-tar-in",
        "\"guestfish\"",
        "\"tar\"",
        "\"cp\"",
        "realPathFileAlloc(io, trusted_keyring",
        ".linux = kernel_bytes",
        "\"gpg\"",
        "\"curl\"",
    };
    for (forbidden) |needle| try source.expectOmitsIn(production, needle, "builder");

    var root_tree = try Source.open(allocator, "packages/miz/src/root_tree.zig");
    defer root_tree.deinit();
    try root_tree.expectContains("path_index: std.StringHashMap(usize)");
    try root_tree.expectContains("append_only_import = true");
    var ext4 = try Source.open(allocator, "packages/miz/src/ext4_mountless.zig");
    defer ext4.deinit();
    try ext4.expectContains("readFileAllocAt");

    var workflow = try Source.open(
        allocator,
        ".github/workflows/ubuntu2604-release.yml",
    );
    defer workflow.deinit();
    try workflow.expectOmits("gnupg");
    try workflow.expectOmits("curl");
    try workflow.expectOmits("ukify");
    try workflow.expectContains("test -f \"$uki_stub\"");
}

test "the publisher is draft-first, allowlisted, and fail-safe" {
    const Source = @import("ubuntu2604_source.zig").Source;
    const source = @import("ubuntu2604_source.zig");
    var script = try Source.open(allocator, "scripts/ubuntu2604_publish.sh");
    defer script.deinit();

    try script.expectContains("test \"$(wc -l <\"$expected_file\")\" -eq 2");
    // The published allowlist is derived by the release tooling from the
    // staged manifest, and the shell only consumes the result.
    try script.expectContains("\"$RELEASE_TOOL\" publish-expected");
    try script.expectContains("--assets-dir \"$assets_dir\"");
    try script.expectContains("--draft");
    try script.expectContains("stale-asset-ids");
    try script.expectContains("retaining $RELEASE_TAG as a draft");
    try script.expectContains("gh release download \"$RELEASE_TAG\"");
    try script.expectContains("\"$RELEASE_TOOL\" github-release-downloaded");
    try source.expectOrder(
        script.text,
        "gh release create \"$RELEASE_TAG\"",
        "gh release upload \"$RELEASE_TAG\"",
        "publish",
    );
    const download_index = try script.indexOf("\"$RELEASE_TOOL\" github-release-downloaded");
    const remainder = script.text[download_index..];
    try source.expectContainsIn(
        remainder,
        "gh release edit \"$RELEASE_TAG\"",
        "publish",
    );
    // Publication depends on no interpreter.
    try script.expectOmits(source.interpreter);
}
