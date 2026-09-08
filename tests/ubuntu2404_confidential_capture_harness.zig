//! Structural and executable guards for the ConfidentialVM capture harness.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const script_path = "scripts/ubuntu2404_confidential_capture.sh";
const library_path = "scripts/azure_confidential_vm_lib.sh";
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

fn indexOf(text: []const u8, needle: []const u8) !usize {
    return std.mem.indexOf(u8, text, needle) orelse
        error.RequiredTextMissing;
}

fn section(text: []const u8, start: []const u8, end: []const u8) ![]const u8 {
    const start_index = try indexOf(text, start);
    const tail = text[start_index..];
    const end_index = std.mem.indexOf(u8, tail, end) orelse
        return error.RequiredTextMissing;
    return tail[0..end_index];
}

test "capture harness is fail closed and never evaluates or prints secrets" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);

    for ([_][]const u8{
        "usage: $0 run|cleanup",
        "EXPECTED_REPOSITORY=cataggar/miz",
        "EXPECTED_REF=refs/heads/main",
        "EXPECTED_ENVIRONMENT=ubuntu2404-confidential-capture",
        "Protected capture workflow identity is invalid",
        "Capture source, target, and validation region or SKU differ",
        "Target resource group subscription, location, or durable ownership is invalid",
        "Target gallery subscription, location, or durable ownership is invalid",
        "Refusing to reuse temporary resource group",
        "Capture cleanup state is unavailable",
        "Azure login is unavailable during cleanup",
        "miz-repository=$GITHUB_REPOSITORY",
        "miz-source-commit=$SOURCE_COMMIT",
        "az \"${AZURE_CONFIDENTIAL_VM_ARGS[@]}\"",
        "az \"${AZURE_TRUSTED_LAUNCH_ARGS[@]}\"",
    }) |needle| try expectContains(script, needle);
    for ([_][]const u8{
        "eval ",
        "set -x",
        "cat \"$final_token\"",
        "cat \"$source_token\"",
        "echo \"$final_nonce\"",
        "echo \"$source_nonce\"",
        "BASH_COMMAND",
    }) |needle| try expectAbsent(script, needle);
}

test "exact accepted bytes are staged and validated before capture generalization" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);

    for ([_][]const u8{
        "\"$RELEASE_TOOL\" verify-acceptance",
        "\"$MIZ\" azure derive",
        "\"$RELEASE_TOOL\" verify-vhd",
        "Re-derived VHD does not exactly match the released accepted artifact",
        "miz-source-acceptance-sha256",
        "--staging-disk \"$upload_disk_json\"",
        "--staging-managed-image \"$managed_image_json\"",
        "--staging-gallery-request \"$staging_request\"",
        "--staging-gallery-response \"$staging_response\"",
        "ubuntu2404_confidential_guest_final_acceptance",
        "\"$RELEASE_TOOL\" verify-attestation",
        "ubuntu2404_confidential_guest_pre_capture_check",
        "sudo -n waagent -deprovision+user -force",
        "PowerState/stopped",
        "PowerState/deallocated",
        "azure_confidential_vm_generalize_args",
        "check-capture-snapshot",
    }) |needle| try expectContains(script, needle);

    const verify_source = try indexOf(script, "\"$RELEASE_TOOL\" verify-acceptance");
    const derive = try indexOf(script, "\"$MIZ\" azure derive");
    const capture_validate = try indexOf(
        script,
        "run_capture_vm_check \"$capture_vm_resource\"",
    );
    const pre_capture = try indexOf(
        script,
        "ubuntu2404_confidential_guest_pre_capture_check",
    );
    const deallocate = try indexOf(script, "azure_confidential_vm_deallocate_args");
    const generalize = try indexOf(script, "azure_confidential_vm_generalize_args");
    const snapshot = try indexOf(script, "azure_confidential_vm_snapshot_create_args");
    const version = try indexOf(
        script,
        "azure_confidential_vm_capture_gallery_version_put_args",
    );
    const final_acceptance = std.mem.lastIndexOf(
        u8,
        script,
        "ubuntu2404_confidential_guest_final_acceptance",
    ) orelse return error.RequiredTextMissing;
    const fresh_maa = std.mem.lastIndexOf(
        u8,
        script,
        "refresh_maa_metadata \"$final_openid\" \"$final_jwks\"",
    ) orelse return error.RequiredTextMissing;
    const result = try indexOf(script, "\"$RELEASE_TOOL\" capture-result");
    const verify_result = try indexOf(script, "\"$RELEASE_TOOL\" verify-capture");
    try std.testing.expect(verify_source < derive);
    try std.testing.expect(derive < capture_validate);
    try std.testing.expect(capture_validate < pre_capture);
    try std.testing.expect(pre_capture < deallocate);
    try std.testing.expect(deallocate < generalize);
    try std.testing.expect(generalize < snapshot);
    try std.testing.expect(snapshot < version);
    try std.testing.expect(version < final_acceptance);
    try std.testing.expect(final_acceptance < fresh_maa);
    try std.testing.expect(fresh_maa < result);
    try std.testing.expect(result < verify_result);
}

test "persistent version is immutable fully replicated and final VM inherits security" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const library = try readTracked(allocator, library_path);
    defer allocator.free(library);

    for ([_][]const u8{
        "Target gallery version already exists; refusing update or overwrite",
        "capture-gallery-request",
        "provisioning\" == Succeeded && \"$replication\" == Completed",
        "Gallery full replication did not complete before the deadline",
        "check-capture-gallery",
        "azure_confidential_vm_captured_vm_create_args",
        "collect_vm_contract \"$final_vm_name\"",
    }) |needle| try expectContains(script, needle);
    try expectContains(library, "api-version=2025-03-03");
    try expectContains(library, "--headers 'If-None-Match=*'");
    const captured_builder = try section(
        library,
        "azure_confidential_vm_captured_vm_create_args() {",
        "azure_confidential_vm_vm_resource_args() {",
    );
    for ([_][]const u8{
        "--security-type",
        "--os-disk-security-encryption-type",
        "--enable-secure-boot",
        "--enable-vtpm",
    }) |needle| try expectAbsent(captured_builder, needle);

    const refusal = try indexOf(
        script,
        "Target gallery version already exists; refusing update or overwrite",
    );
    const created = try indexOf(script, "state_replace '.target.version_created = true'");
    const put = try indexOf(
        script,
        "azure_confidential_vm_capture_gallery_version_put_args",
    );
    try std.testing.expect(refusal < created);
    try std.testing.expect(created < put);
}

test "cleanup is ordered exact and never targets durable containers broadly" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const cleanup = try section(
        script,
        "cleanup_resources() {",
        "if [[ \"$command_name\" == cleanup ]]",
    );
    const version = try indexOf(cleanup, "delete_created_version");
    const definition = try indexOf(cleanup, "delete_created_definition");
    const group = try indexOf(cleanup, "delete_temporary_group");
    try std.testing.expect(version < definition);
    try std.testing.expect(definition < group);
    for ([_][]const u8{
        "az group delete --name \"$TARGET_RESOURCE_GROUP\"",
        "az sig delete",
        "az resource delete",
        "--resource-group '*'",
        "--name '*'",
    }) |needle| try expectAbsent(script, needle);
    for ([_][]const u8{
        "Refusing to delete target version without exact run ownership tags",
        "Refusing to delete target definition without exact run ownership tags",
        "Refusing to delete a non-empty target image definition",
        "Refusing to delete temporary resource group without exact ownership tags",
    }) |needle| try expectContains(script, needle);
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

fn writeCleanupFixture(
    allocator: Allocator,
    root: []const u8,
    succeeded: bool,
) !struct { state: []u8, log: []u8 } {
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
        \\printf '%s\n' "$*" >>"$MOCK_LOG"
        \\case "$1 $2" in
        \\  "account show") exit 0 ;;
        \\  "group exists") echo true ;;
        \\  "group show")
        \\    printf '{"tags":{"miz-owner":"%s","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"0123456789abcdef0123456789abcdef01234567"}}\n' "$MOCK_GROUP_OWNER"
        \\    ;;
        \\  "group delete") exit 0 ;;
        \\  "sig image-version")
        \\    case "$3" in
        \\      show)
        \\        printf '{"tags":{"miz-owner":"%s","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"0123456789abcdef0123456789abcdef01234567"}}\n' "$MOCK_VERSION_OWNER"
        \\        ;;
        \\      delete) exit 0 ;;
        \\      list) printf '%s\n' "$MOCK_VERSION_LIST" ;;
        \\      *) exit 71 ;;
        \\    esac
        \\    ;;
        \\  "sig image-definition")
        \\    case "$3" in
        \\      show)
        \\        printf '{"tags":{"miz-owner":"durable-owner","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"0123456789abcdef0123456789abcdef01234567"}}\n'
        \\        ;;
        \\      delete) exit 0 ;;
        \\      *) exit 72 ;;
        \\    esac
        \\    ;;
        \\  *) echo "unexpected Azure CLI arguments: $*" >&2; exit 73 ;;
        \\esac
        \\
        ,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const state = try std.fmt.allocPrint(allocator, "{s}/state.json", .{root});
    errdefer allocator.free(state);
    const state_json = try std.fmt.allocPrint(
        allocator,
        \\{{"schema":1,"repository":"cataggar/miz","run_id":"123","run_attempt":"4",
        \\"source_commit":"0123456789abcdef0123456789abcdef01234567",
        \\"temporary_resource_group":"miz-u2404-cvm-capture-123-4",
        \\"temporary_group_created":true,
        \\"run_succeeded":{s},"target":{{"owner_tag":"durable-owner",
        \\"resource_group":"gallery","gallery":"release","image_definition":"ubuntu",
        \\"definition_id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gallery/providers/Microsoft.Compute/galleries/release/images/ubuntu",
        \\"version_id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/gallery/providers/Microsoft.Compute/galleries/release/images/ubuntu/versions/1.2.3",
        \\"definition_created":true,"version_created":true}}}}
    ,
        .{if (succeeded) "true" else "false"},
    );
    defer allocator.free(state_json);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = state,
        .data = state_json,
    });
    return .{
        .state = state,
        .log = try std.fmt.allocPrint(allocator, "{s}/az.log", .{root}),
    };
}

fn runCleanup(
    allocator: Allocator,
    root: []const u8,
    state: []const u8,
    log: []const u8,
    version_owner: []const u8,
    group_owner: []const u8,
    version_list: []const u8,
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
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}/bin:{s}",
        .{ root, existing_path },
    );
    defer allocator.free(path);
    try environment.put("PATH", path);
    try environment.put("STATE_FILE", state);
    try environment.put("GITHUB_REPOSITORY", "cataggar/miz");
    try environment.put("GITHUB_RUN_ID", "123");
    try environment.put("GITHUB_RUN_ATTEMPT", "4");
    try environment.put(
        "SOURCE_COMMIT",
        "0123456789abcdef0123456789abcdef01234567",
    );
    try environment.put("MOCK_LOG", log);
    try environment.put("MOCK_VERSION_OWNER", version_owner);
    try environment.put("MOCK_GROUP_OWNER", group_owner);
    try environment.put("MOCK_VERSION_LIST", version_list);
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

test "mocked cleanup deletes only exact-owned resources in dependency order" {
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
    const fixture = try writeCleanupFixture(allocator, root, false);
    defer allocator.free(fixture.state);
    defer allocator.free(fixture.log);
    const result = try runCleanup(
        allocator,
        root,
        fixture.state,
        fixture.log,
        "ubuntu2404-confidential-capture",
        "ubuntu2404-confidential-capture",
        "[]",
    );
    defer result.deinit(allocator);
    if (!result.succeeded()) {
        std.debug.print("cleanup failed:\n{s}\n{s}\n", .{ result.stdout, result.stderr });
        return error.CleanupFailed;
    }
    const log = try Dir.cwd().readFileAlloc(
        std.testing.io,
        fixture.log,
        allocator,
        .limited(max_output_bytes),
    );
    defer allocator.free(log);
    const version_delete = try indexOf(log, "sig image-version delete");
    const definition_delete = try indexOf(log, "sig image-definition delete");
    const group_delete = try indexOf(log, "group delete");
    try std.testing.expect(version_delete < definition_delete);
    try std.testing.expect(definition_delete < group_delete);
}

test "mocked cleanup refuses mismatched target and group ownership" {
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
    const fixture = try writeCleanupFixture(allocator, root, false);
    defer allocator.free(fixture.state);
    defer allocator.free(fixture.log);
    const result = try runCleanup(
        allocator,
        root,
        fixture.state,
        fixture.log,
        "different-owner",
        "different-owner",
        "[{}]",
    );
    defer result.deinit(allocator);
    try std.testing.expect(!result.succeeded());
    const log = try Dir.cwd().readFileAlloc(
        std.testing.io,
        fixture.log,
        allocator,
        .limited(max_output_bytes),
    );
    defer allocator.free(log);
    try expectAbsent(log, "sig image-version delete");
    try expectAbsent(log, "sig image-definition delete");
    try expectAbsent(log, "group delete");
}

test "successful-run cleanup retains persistent target and deletes exact temp group" {
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
    const fixture = try writeCleanupFixture(allocator, root, true);
    defer allocator.free(fixture.state);
    defer allocator.free(fixture.log);
    const result = try runCleanup(
        allocator,
        root,
        fixture.state,
        fixture.log,
        "different-owner",
        "ubuntu2404-confidential-capture",
        "[{}]",
    );
    defer result.deinit(allocator);
    try std.testing.expect(result.succeeded());
    const log = try Dir.cwd().readFileAlloc(
        std.testing.io,
        fixture.log,
        allocator,
        .limited(max_output_bytes),
    );
    defer allocator.free(log);
    try expectAbsent(log, "sig image-version");
    try expectAbsent(log, "sig image-definition");
    try expectContains(log, "group delete");
}

test "mocked run refuses a pre-existing target version before artifact work" {
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
    const log = try std.fmt.allocPrint(allocator, "{s}/az.log", .{root});
    defer allocator.free(log);
    const exists_count = try std.fmt.allocPrint(
        allocator,
        "{s}/exists-count",
        .{root},
    );
    defer allocator.free(exists_count);
    const az = try std.fmt.allocPrint(allocator, "{s}/az", .{bin});
    defer allocator.free(az);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = az,
        .data =
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\printf '%s\n' "$*" >>"$MOCK_LOG"
        \\case "$1 $2" in
        \\  "account show")
        \\    if [[ "$*" == *"--query id"* ]]; then
        \\      echo 00000000-0000-0000-0000-000000000000
        \\    fi
        \\    ;;
        \\  "group exists")
        \\    count=0
        \\    test -f "$MOCK_EXISTS_COUNT" && count=$(cat "$MOCK_EXISTS_COUNT")
        \\    count=$((count + 1))
        \\    echo "$count" >"$MOCK_EXISTS_COUNT"
        \\    if (( count == 1 )); then echo false; else echo true; fi
        \\    ;;
        \\  "group create") exit 0 ;;
        \\  "group show")
        \\    if [[ "$*" == *"--name target-rg"* ]]; then
        \\      printf '{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/target-rg","location":"eastus2","tags":{"miz-owner":"durable-owner","miz-repository":"cataggar/miz"}}\n'
        \\    else
        \\      printf '{"tags":{"miz-owner":"ubuntu2404-confidential-capture","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"0123456789abcdef0123456789abcdef01234567"}}\n'
        \\    fi
        \\    ;;
        \\  "group delete") exit 0 ;;
        \\  "sig show")
        \\    printf '{"id":"/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release","location":"eastus2","tags":{"miz-owner":"durable-owner","miz-repository":"cataggar/miz"}}\n'
        \\    ;;
        \\  "sig image-version")
        \\    test "$3" = show
        \\    printf '{"id":"already-exists"}\n'
        \\    ;;
        \\  *) echo "unexpected Azure CLI arguments: $*" >&2; exit 74 ;;
        \\esac
        \\
        ,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    for ([_][]const u8{
        "azcopy",
        "curl",
        "openssl",
        "qemu-img",
        "scp",
        "sha256sum",
        "ssh",
        "ssh-keygen",
        "unzip",
    }) |name| {
        const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ bin, name });
        defer allocator.free(path);
        try Dir.cwd().writeFile(std.testing.io, .{
            .sub_path = path,
            .data = "#!/usr/bin/env bash\nexit 75\n",
            .flags = .{ .permissions = .fromMode(0o755) },
        });
    }
    const marker = try std.fmt.allocPrint(allocator, "{s}/artifact-work", .{root});
    defer allocator.free(marker);
    const executable = try std.fmt.allocPrint(allocator, "{s}/tool", .{root});
    defer allocator.free(executable);
    const tool_source = try std.fmt.allocPrint(
        allocator,
        "#!/usr/bin/env bash\n: >'{s}'\nexit 76\n",
        .{marker},
    );
    defer allocator.free(tool_source);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = executable,
        .data = tool_source,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const candidate = try std.fmt.allocPrint(allocator, "{s}/candidate.qcow2", .{root});
    defer allocator.free(candidate);
    const provenance = try std.fmt.allocPrint(allocator, "{s}/provenance.json", .{root});
    defer allocator.free(provenance);
    const acceptance = try std.fmt.allocPrint(allocator, "{s}/acceptance.json", .{root});
    defer allocator.free(acceptance);
    for ([_][]const u8{ candidate, provenance, acceptance }) |path| {
        try Dir.cwd().writeFile(std.testing.io, .{
            .sub_path = path,
            .data = "{}\n",
        });
    }
    const state = try std.fmt.allocPrint(allocator, "{s}/state.json", .{root});
    defer allocator.free(state);
    const result_dir = try std.fmt.allocPrint(allocator, "{s}/result", .{root});
    defer allocator.free(result_dir);
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
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}:{s}",
        .{ bin, existing_path },
    );
    defer allocator.free(path);
    const entries = [_][2][]const u8{
        .{ "PATH", path },
        .{ "STATE_FILE", state },
        .{ "GITHUB_REPOSITORY", "cataggar/miz" },
        .{ "GITHUB_RUN_ID", "123" },
        .{ "GITHUB_RUN_ATTEMPT", "4" },
        .{ "GITHUB_REF", "refs/heads/main" },
        .{ "PROTECTED_ENVIRONMENT", "ubuntu2404-confidential-capture" },
        .{ "SOURCE_COMMIT", "0123456789abcdef0123456789abcdef01234567" },
        .{ "CANDIDATE", candidate },
        .{ "PROVENANCE", provenance },
        .{ "SOURCE_ACCEPTANCE", acceptance },
        .{ "SOURCE_LOCATION", "eastus2" },
        .{ "SOURCE_VM_SIZE", "Standard_DC2as_v5" },
        .{ "SOURCE_RUN_ID", "12" },
        .{ "SOURCE_RUN_ATTEMPT", "1" },
        .{ "SOURCE_REPOSITORY", "cataggar/miz" },
        .{ "AZURE_SUBSCRIPTION_ID", "00000000-0000-0000-0000-000000000000" },
        .{ "AZURE_LOCATION", "eastus2" },
        .{ "AZURE_VM_SIZE", "Standard_DC2as_v5" },
        .{ "TARGET_RESOURCE_GROUP", "target-rg" },
        .{ "TARGET_GALLERY", "release" },
        .{ "TARGET_IMAGE_DEFINITION", "ubuntu-confidential" },
        .{ "TARGET_IMAGE_VERSION", "1.2.3" },
        .{ "TARGET_LOCATION", "eastus2" },
        .{ "TARGET_OWNER_TAG", "durable-owner" },
        .{ "RESULT_DIR", result_dir },
        .{ "MIZ", executable },
        .{ "UBUNTU2404_CONFIDENTIAL_RELEASE_TOOL", executable },
        .{ "MOCK_LOG", log },
        .{ "MOCK_EXISTS_COUNT", exists_count },
    };
    for (entries) |entry| try environment.put(entry[0], entry[1]);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ script, "run" },
        .cwd = .{ .path = repository },
        .environ_map = &environment,
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expect(switch (result.term) {
        .exited => |code| code != 0,
        else => true,
    });
    try expectContains(
        result.stderr,
        "Target gallery version already exists; refusing update or overwrite",
    );
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(std.testing.io, marker, .{}),
    );
    const azure_log = try Dir.cwd().readFileAlloc(
        std.testing.io,
        log,
        allocator,
        .limited(max_output_bytes),
    );
    defer allocator.free(azure_log);
    try expectAbsent(azure_log, "sig image-version delete");
    try expectContains(azure_log, "group delete");
}

test "capture harness is executable valid shell" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, script_path });
    defer allocator.free(path);
    const stat = try Dir.cwd().statFile(std.testing.io, path, .{});
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", "-n", path },
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
