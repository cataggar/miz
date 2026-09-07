//! Source and cleanup guards for Ubuntu 24.04 Confidential VM acceptance.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const script_path = "scripts/ubuntu2404_confidential_azure_acceptance.sh";
const release_path = "scripts/ubuntu2404_confidential_release.zig";
const library_path = "scripts/azure_confidential_vm_lib.sh";
const guest_library_path = "scripts/ubuntu2404_confidential_guest_acceptance_lib.sh";
const max_source_bytes = 4 * 1024 * 1024;
const max_output_bytes = 1024 * 1024;

fn rootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_UBUNTU2404_CONFIDENTIAL_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

fn readTracked(allocator: Allocator, relative: []const u8) ![]u8 {
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, relative });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(
        std.testing.io,
        path,
        allocator,
        .limited(max_source_bytes),
    );
}

fn expectContains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) != null) return;
    std.debug.print("missing required text:\n{s}\n", .{needle});
    return error.RequiredTextMissing;
}

fn expectAbsent(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) return;
    std.debug.print("forbidden text is present:\n{s}\n", .{needle});
    return error.ForbiddenTextPresent;
}

test "acceptance deploys and attests the exact Confidential VM contract" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const release_tool = try readTracked(allocator, release_path);
    defer allocator.free(release_tool);
    const library = try readTracked(allocator, library_path);
    defer allocator.free(library);
    const guest_library = try readTracked(allocator, guest_library_path);
    defer allocator.free(guest_library);

    for ([_][]const u8{
        "azure_confidential_vm_sku_list_args",
        "azure_confidential_vm_image_definition_create_args",
        "azure_confidential_vm_vm_create_args",
        "verify-build",
        "verify-vhd",
        "--input-sha256 \"$qcow_sha256\"",
        "--expected-virtual-size \"$virtual_size\"",
        "qemu-img info -f vpc",
        "--blob-type PageBlob",
        "check-managed-disk",
        "check-managed-image",
        "check-image-definition",
        "check-gallery",
        "check-vm",
        "ubuntu2404_confidential_guest_final_acceptance",
        "guest-imds.json",
        "attestation.jwt",
        "openid-configuration.json",
        "jwks.json",
        "attestation-client.stderr",
        "azure-result.json",
        "acceptance-result",
    }) |needle| try expectContains(script, needle);
    for ([_][]const u8{
        "ubuntu2404_confidential_guest_configure_ssh",
        "ubuntu2404_confidential_guest_wait_for_ssh",
        "ubuntu2404_confidential_guest_check_readiness",
        "ubuntu2404_confidential_guest_collect_identity",
        "ubuntu2404_confidential_guest_pre_capture_check",
        "ubuntu2404_confidential_guest_collect_attestation",
        "ubuntu2404_confidential_guest_validate_persistent_data_disk",
        "ubuntu2404_confidential_guest_cleanup_validation_files",
        "ubuntu2404_confidential_guest_final_acceptance",
        "sudo -n mokutil --sb-state",
        "test -c /dev/tpmrm0",
        "cloud-init status --wait",
        "walinuxagent.service",
        "metadata/instance?api-version=2025-04-07",
        "az vm disk attach",
        "sudo -n reboot",
        "sudo -n rm -f /tmp/azguestattestation1.deb /tmp/AttestationClient",
    }) |needle| try expectContains(guest_library, needle);
    try expectContains(script, "beginGetAccess?api-version=2025-01-02");
    for ([_][]const u8{
        "--features SecurityType=ConfidentialVMSupported",
        "--security-type ConfidentialVM",
        "--os-disk-security-encryption-type VMGuestStateOnly",
        "--enable-secure-boot true",
        "--enable-vtpm true",
    }) |needle| try expectContains(library, needle);

    for ([_][]const u8{
        "x-ms-isolation-tee",
        "sevsnpvm",
        "azure-compliant-cvm",
        "x-ms-sevsnpvm-is-debuggable",
        "x-ms-sevsnpvm-migration-allowed",
        "x-ms-sevsnpvm-vmpl",
        "x-ms-azurevm-vmid",
        "x-ms-azurevm-bootdebug-enabled",
        "x-ms-azurevm-debuggersdisabled",
        "secure-boot",
        "tpm-enabled",
        "PKCS1v1_5Signature.concatVerify",
        "MAA JWT nonce",
        "MAA JWT signature is invalid",
    }) |needle| try expectContains(release_tool, needle);

    try expectContains(guest_library, "09bc7bd670d52321760e640486ab5d556b6b5285");
    try expectContains(guest_library, "azguestattestation1_1.0.5_amd64.deb");
    try expectContains(
        guest_library,
        "791dd441f84fca9ad3f9c46263a919ce50c987cfc4a80faf2f9d6bfc94d71815",
    );
    try expectContains(
        guest_library,
        "e046f80a571d73d59494a0c76b3c6277d5b04fc35cf6822901c20052d0487c2f",
    );
    try expectContains(
        guest_library,
        "a2aef93976948443ac981e18a260c2ae9f736368f8713b875916703ab37e9bc6",
    );
    try expectAbsent(script, "eval ");
    try expectAbsent(guest_library, "eval ");
    try expectAbsent(script, "az disk grant-access");
    try expectAbsent(script, "TrustedLaunchSupported");
    try expectAbsent(script, "--certificate");
    try expectAbsent(script, "cat \"$attestation_token\"");
}

test "pre-capture guest check is non-mutating and final acceptance is explicit" {
    const allocator = std.testing.allocator;
    const guest_library = try readTracked(allocator, guest_library_path);
    defer allocator.free(guest_library);
    const pre_capture_start = std.mem.indexOf(
        u8,
        guest_library,
        "ubuntu2404_confidential_guest_pre_capture_check() {",
    ) orelse return error.RequiredTextMissing;
    const pre_capture_tail = guest_library[pre_capture_start..];
    const pre_capture_end = std.mem.indexOf(
        u8,
        pre_capture_tail,
        "\n}\n\nubuntu2404_confidential_guest_prepare_attestation_client()",
    ) orelse return error.RequiredTextMissing;
    const pre_capture = pre_capture_tail[0..pre_capture_end];
    for ([_][]const u8{
        "ubuntu2404_confidential_guest_wait_for_ssh",
        "ubuntu2404_confidential_guest_check_readiness",
        "ubuntu2404_confidential_guest_collect_identity",
    }) |needle| try expectContains(pre_capture, needle);
    for ([_][]const u8{
        "dpkg",
        "AttestationClient",
        "az disk",
        "mkfs",
        "reboot",
        "rm -f",
    }) |needle| try expectAbsent(pre_capture, needle);

    const final_start = std.mem.indexOf(
        u8,
        guest_library,
        "ubuntu2404_confidential_guest_final_acceptance() {",
    ) orelse return error.RequiredTextMissing;
    const final_acceptance = guest_library[final_start..];
    for ([_][]const u8{
        "ubuntu2404_confidential_guest_wait_for_ssh",
        "ubuntu2404_confidential_guest_check_readiness",
        "ubuntu2404_confidential_guest_collect_attestation",
        "ubuntu2404_confidential_guest_collect_identity",
        "ubuntu2404_confidential_guest_validate_persistent_data_disk",
        "ubuntu2404_confidential_guest_cleanup_validation_files",
    }) |needle| try expectContains(final_acceptance, needle);
}

test "acceptance scripts are valid shell and runner is executable" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, script_path });
    defer allocator.free(path);
    const stat = try Dir.cwd().statFile(std.testing.io, path, .{});
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);
    const guest_library = try std.fs.path.join(
        allocator,
        &.{ root, guest_library_path },
    );
    defer allocator.free(guest_library);
    for ([_][]const u8{ path, guest_library }) |shell_path| {
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{ "bash", "-n", shell_path },
            .stdout_limit = .limited(max_output_bytes),
            .stderr_limit = .limited(max_output_bytes),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        try std.testing.expectEqual(@as(?u8, 0), switch (result.term) {
            .exited => |code| code,
            else => null,
        });
    }
}

const Result = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,

    fn deinit(self: Result, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
    }

    fn succeeded(self: Result) bool {
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }
};

fn runCleanup(
    allocator: Allocator,
    root: []const u8,
    state: []const u8,
    ownership: []const u8,
    marker: []const u8,
) !Result {
    const repository = try rootAlloc(allocator);
    defer allocator.free(repository);
    const script = try std.fs.path.join(allocator, &.{ repository, script_path });
    defer allocator.free(script);
    const existing_path = std.process.Environ.getAlloc(
        std.testing.environ,
        allocator,
        "PATH",
    ) catch try allocator.dupe(u8, "/usr/bin:/bin");
    defer allocator.free(existing_path);

    var environment = try std.process.Environ.createMap(
        std.testing.environ,
        allocator,
    );
    defer environment.deinit();
    const path_value = try std.fmt.allocPrint(
        allocator,
        "{s}/bin:{s}",
        .{ root, existing_path },
    );
    defer allocator.free(path_value);
    try environment.put("PATH", path_value);
    try environment.put("STATE_FILE", state);
    try environment.put("GITHUB_RUN_ID", "123");
    try environment.put("GITHUB_RUN_ATTEMPT", "4");
    try environment.put("MOCK_OWNER", ownership);
    try environment.put("DELETE_MARKER", marker);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ script, "cleanup" },
        .cwd = .{ .path = repository },
        .environ_map = &environment,
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    return .{
        .term = result.term,
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

test "cleanup deletes only the exact owned resource group" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const repository = try rootAlloc(allocator);
    defer allocator.free(repository);
    const root = try std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ repository, tmp.sub_path },
    );
    defer allocator.free(root);
    const bin = try std.fmt.allocPrint(allocator, "{s}/bin", .{root});
    defer allocator.free(bin);
    try Dir.cwd().createDirPath(std.testing.io, bin);
    const az = try std.fmt.allocPrint(allocator, "{s}/az", .{bin});
    defer allocator.free(az);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = az,
        .data =
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\case "$1 $2" in
        \\  "group exists") echo true ;;
        \\  "group show") printf '%s\n' "$MOCK_OWNER" | tr '\t' '\n' ;;
        \\  "group delete") printf 'deleted\n' >"$DELETE_MARKER" ;;
        \\  *) echo "unexpected az arguments: $*" >&2; exit 1 ;;
        \\esac
        \\
        ,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const state = try std.fmt.allocPrint(allocator, "{s}/state", .{root});
    defer allocator.free(state);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = state,
        .data = "miz-u2404-cvm-123-4\n",
    });
    const marker = try std.fmt.allocPrint(allocator, "{s}/deleted", .{root});
    defer allocator.free(marker);

    const accepted = try runCleanup(
        allocator,
        root,
        state,
        "ubuntu2404-confidential-acceptance\t123\t4",
        marker,
    );
    defer accepted.deinit(allocator);
    try std.testing.expect(accepted.succeeded());
    _ = try Dir.cwd().statFile(std.testing.io, marker, .{});

    try Dir.cwd().deleteFile(std.testing.io, marker);
    const refused = try runCleanup(
        allocator,
        root,
        state,
        "ubuntu2404-confidential-acceptance\t123\t5",
        marker,
    );
    defer refused.deinit(allocator);
    try std.testing.expect(!refused.succeeded());
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(std.testing.io, marker, .{}),
    );
}
