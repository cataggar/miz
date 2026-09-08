//! Structural and executable guards for the ConfidentialVM capture harness.

const std = @import("std");
const confidential_release = @import("ubuntu2404_confidential_release");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const script_path = "scripts/ubuntu2404_confidential_capture.sh";
const library_path = "scripts/azure_confidential_vm_lib.sh";
const guest_library_path =
    "scripts/ubuntu2404_confidential_guest_acceptance_lib.sh";
const max_source_bytes = 4 * 1024 * 1024;
const max_output_bytes = 1024 * 1024;
const group_name =
    "miz-u2404-cvm-capture-123-4-00112233445566778899aabbccddeeff";
const subscription = "00000000-0000-0000-0000-000000000000";
const commit = "0123456789abcdef0123456789abcdef01234567";
const principal = "11111111-1111-1111-1111-111111111111";
const capture_principal = "22222222-2222-2222-2222-222222222222";
const publication_lock = "ubuntu2404-confidential-cvm-target-version";

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

const CaptureArguments = struct {
    argv: [128][]const u8 = undefined,
    names: [64][]const u8 = undefined,
    argv_len: usize = 0,
    names_len: usize = 0,

    fn appendLine(self: *CaptureArguments, line: []const u8) !void {
        const trimmed = std.mem.trim(u8, line, " \t\r\\");
        if (!std.mem.startsWith(u8, trimmed, "--")) return;
        const separator = std.mem.indexOfAny(u8, trimmed, " \t") orelse
            return error.MissingArgumentValue;
        const value = std.mem.trim(u8, trimmed[separator..], " \t");
        if (value.len == 0 or
            self.argv_len + 2 > self.argv.len or
            self.names_len == self.names.len)
        {
            return error.InvalidArgumentArray;
        }
        self.argv[self.argv_len] = trimmed[0..separator];
        self.argv[self.argv_len + 1] = value;
        self.argv_len += 2;
        self.names[self.names_len] = trimmed[2..separator];
        self.names_len += 1;
    }

    fn appendLines(self: *CaptureArguments, text: []const u8) !void {
        var lines = std.mem.splitScalar(u8, text, '\n');
        while (lines.next()) |line| try self.appendLine(line);
    }
};

fn captureArguments(
    script: []const u8,
    command: []const u8,
    invocation_end: []const u8,
) !CaptureArguments {
    var arguments: CaptureArguments = .{};
    const common = try section(
        script,
        "capture_common_args=(\n",
        ")\nverify_capture_evidence_revisions",
    );
    try arguments.appendLines(common);

    var command_marker_buffer: [96]u8 = undefined;
    const command_marker = try std.fmt.bufPrint(
        &command_marker_buffer,
        "\"$RELEASE_TOOL\" {s} \\\n",
        .{command},
    );
    const invocation = try section(script, command_marker, invocation_end);
    try arguments.appendLines(invocation);
    return arguments;
}

fn expectArgumentSchema(
    actual: CaptureArguments,
    expected: []const []const u8,
) !void {
    try std.testing.expectEqual(expected.len, actual.names_len);
    for (actual.names[0..actual.names_len], expected) |name, expected_name| {
        try std.testing.expectEqualStrings(expected_name, name);
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

fn fixtureRoot(allocator: Allocator, tmp: std.testing.TmpDir) ![]u8 {
    const repository = try rootAlloc(allocator);
    defer allocator.free(repository);
    return std.fmt.allocPrint(
        allocator,
        "{s}/.zig-cache/tmp/{s}",
        .{ repository, tmp.sub_path },
    );
}

fn runShellSource(
    allocator: Allocator,
    root: []const u8,
    name: []const u8,
    source: []const u8,
) !Result {
    const path = try std.fmt.allocPrint(allocator, "{s}/{s}", .{ root, name });
    defer allocator.free(path);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = path,
        .data = source,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", path },
        .cwd = .{ .path = root },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    return .{
        .term = result.term,
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

fn writeState(
    allocator: Allocator,
    root: []const u8,
    group_status: []const u8,
    publication_status: []const u8,
    run_succeeded: bool,
    resources: []const u8,
) ![]u8 {
    const state = try std.fmt.allocPrint(allocator, "{s}/state.json", .{root});
    errdefer allocator.free(state);
    const text = try std.fmt.allocPrint(
        allocator,
        \\{{"schema":3,"repository":"cataggar/miz","run_id":"123",
        \\"run_attempt":"4","source_commit":"{s}",
        \\"subscription_id":"{s}",
        \\"temporary_resource_group":"{s}",
        \\"temporary_group_create":{{"status":"{s}",
        \\"resource_id":"/subscriptions/{s}/resourceGroups/{s}",
        \\"resource_name":"{s}",
        \\"owner_tag":"ubuntu2404-confidential-capture",
        \\"repository":"cataggar/miz","run_id":"123","run_attempt":"4",
        \\"source_commit":"{s}"}},
        \\"temporary_resources":{s},"run_succeeded":{s},
        \\"outstanding_write_access":null,
        \\"target":{{"owner_tag":"durable-owner","resource_group":"target-rg",
        \\"gallery":"release","image_definition":"ubuntu-confidential",
        \\"definition_id":"/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release/images/ubuntu-confidential",
        \\"version_id":"/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release/images/ubuntu-confidential/versions/1.2.3",
        \\"publication":{{"lock_id":"{s}",
        \\"principal_client_id":"{s}","status":"{s}"}}}}}}
    ,
        .{
            commit,
            subscription,
            group_name,
            group_status,
            subscription,
            group_name,
            group_name,
            commit,
            resources,
            if (run_succeeded) "true" else "false",
            subscription,
            subscription,
            publication_lock,
            principal,
            publication_status,
        },
    );
    defer allocator.free(text);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = state,
        .data = text,
        .flags = .{ .permissions = .fromMode(0o600) },
    });
    return state;
}

fn shellIdentityPreamble(allocator: Allocator, state: []const u8) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        \\STATE_FILE='{s}'
        \\EXPECTED_PUBLICATION_LOCK={s}
        \\OWNER=ubuntu2404-confidential-capture
        \\GITHUB_REPOSITORY=cataggar/miz
        \\GITHUB_RUN_ID=123
        \\GITHUB_RUN_ATTEMPT=4
        \\SOURCE_COMMIT={s}
        \\AZURE_SUBSCRIPTION_ID={s}
        \\AZURE_LOCATION=eastus2
        \\TARGET_OWNER_TAG=durable-owner
        \\PUBLICATION_PRINCIPAL_CLIENT_ID={s}
        \\fail() {{ printf '%s\n' "$*" >&2; return 1; }}
        \\
    ,
        .{ state, publication_lock, commit, subscription, principal },
    );
}

test "harness encodes durable parent and serialized publication trust boundaries" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);

    for ([_][]const u8{
        "EXPECTED_PUBLICATION_LOCK=ubuntu2404-confidential-cvm-target-version",
        "PUBLICATION_AZURE_CONFIG_DIR",
        "CAPTURE_PRINCIPAL_CLIENT_ID",
        "PUBLICATION_PRINCIPAL_CLIENT_ID",
        "Capture and publication principals must be distinct",
        "stable,\n# non-canceling concurrency group",
        "no version delete or parent",
        "cannot prove RBAC or defend against a\n# malicious subscription Owner",
        "validate_target_parents",
        "Pre-provisioned target resource group is missing or unavailable",
        "Pre-provisioned target gallery is missing or unavailable",
        "Pre-provisioned target ConfidentialVM image definition is missing or unavailable",
        "publisher: $publisher",
        "offer: $offer",
        "sku: $sku",
        "name: \"SecurityType\", value: \"ConfidentialVM\"",
        "stock UEFI boundary",
        "require_target_version_absent startup",
        "require_target_version_absent pre-put",
        "Target gallery version already exists; refusing update or overwrite",
    }) |needle| try expectContains(script, needle);

    const first_validation = try indexOf(script, "validate_target_parents\n");
    const initial_absence = try indexOf(
        script,
        "require_target_version_absent startup",
    );
    const temporary_create = try indexOf(script, "create_temporary_group\n");
    const final_validation = std.mem.lastIndexOf(
        u8,
        script,
        "validate_target_parents\n",
    ) orelse return error.RequiredTextMissing;
    const final_absence = try indexOf(
        script,
        "require_target_version_absent pre-put",
    );
    const publication = try indexOf(script, "publish_target_version_once\n");
    try std.testing.expect(first_validation < initial_absence);
    try std.testing.expect(initial_absence < temporary_create);
    try std.testing.expect(temporary_create < final_validation);
    try std.testing.expect(final_validation < final_absence);
    try std.testing.expect(final_absence < publication);
}

test "unsupported conditional headers and target parent mutations are absent" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const library = try readTracked(allocator, library_path);
    defer allocator.free(library);

    for ([_][]const u8{
        "If-None-Match",
        "conditional_create",
        "create_target_definition",
        "delete_created_version",
        "delete_created_definition",
        "sig image-version delete",
        "sig image-definition delete",
        "tag_group_resources",
    }) |needle| {
        try expectAbsent(script, needle);
        try expectAbsent(library, needle);
    }
    try expectAbsent(
        script,
        "azure_confidential_vm_capture_image_definition_create_args \\\n  \"$TARGET_RESOURCE_GROUP\"",
    );
    try expectContains(
        library,
        "azure_confidential_vm_resource_group_create_args()",
    );
    try expectContains(library, "api-version=2022-09-01");
    try expectContains(library, "api-version=2025-03-03");
}

test "temporary resources use random group names explicit networking and allowlists" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const library = try readTracked(allocator, library_path);
    defer allocator.free(library);
    const guest = try readTracked(allocator, guest_library_path);
    defer allocator.free(guest);

    for ([_][]const u8{
        "random_group_suffix=$(openssl rand -hex 16)",
        "[[ \"$random_group_suffix\" =~ ^[0-9a-f]{32}$ ]]",
        "resource_group=\"miz-u2404-cvm-capture-${name_seed}-${random_group_suffix}\"",
        "temporary_group_create: {\n      status: \"expected\"",
        "group_exists=$(az group exists",
        "azure_confidential_vm_resource_group_create_args",
        "confirmed_created",
        "create_common_network",
        "az network vnet create",
        "az network nsg create",
        "az network public-ip create",
        "az network nic create",
        "source_os_disk_name=",
        "capture_os_disk_name=",
        "final_os_disk_name=",
        "record_expected_resource",
        "temporary_resources",
        "scratch-resource-inventory.json",
        "--scratch-resource-group \"$resource_group\"",
        "--scratch-inventory \"$scratch_inventory\"",
        "--target-resource-group \"$TARGET_RESOURCE_GROUP\"",
        "Could not freshly inventory the temporary resource group",
        "unknown, mismatched, or untagged resource",
    }) |needle| try expectContains(script, needle);
    try expectContains(library, "--nics \"$nic_id\"");
    try expectContains(library, "--os-disk-name \"$os_disk_name\"");
    try expectContains(
        guest,
        "ubuntu2404_confidential_guest_record_created_data_disk",
    );

    const state = try indexOf(script, "temporary_group_create: {");
    const absence = try indexOf(script, "group_exists=$(az group exists");
    const create = try indexOf(script, "create_temporary_group\n");
    try std.testing.expect(state < absence);
    try std.testing.expect(absence < create);
}

test "publication dispatch is one upsert and ambiguity is quarantined" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const publication_source = try section(
        script,
        "quarantine_target_publication() {",
        "\nwait_source_gallery_version() {",
    );
    const owned_source = try section(
        script,
        "owned_tags_match() {",
        "\nexact_owned_tags_match() {",
    );
    const state_source = try section(
        script,
        "state_replace() {",
        "\nowned_tags_match() {",
    );
    try expectContains(
        publication_source,
        ".target.publication.status = \"pending\"",
    );
    try expectContains(
        publication_source,
        ".target.publication.status = \"quarantined\"",
    );
    try expectContains(
        publication_source,
        ".target.publication.status = \"published\"",
    );
    try expectContains(publication_source, "Do not retry this upsert");
    const put_calls = std.mem.count(
        u8,
        publication_source,
        "publication_az \"${AZURE_CONFIDENTIAL_VM_ARGS[@]}\"",
    );
    try std.testing.expectEqual(@as(usize, 1), put_calls);

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const state = try writeState(
        allocator,
        root,
        "confirmed_created",
        "not_dispatched",
        false,
        "[]",
    );
    defer allocator.free(state);
    const preamble = try shellIdentityPreamble(allocator, state);
    defer allocator.free(preamble);
    const release_tool = try std.fmt.allocPrint(allocator, "{s}/release", .{root});
    defer allocator.free(release_tool);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = release_tool,
        .data = "#!/usr/bin/env bash\nexit 0\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const fixture_source = try std.fmt.allocPrint(
        allocator,
        \\#!/usr/bin/env bash
        \\set -Eeuo pipefail
        \\{s}
        \\RESULT_DIR='{s}'
        \\RELEASE_TOOL='{s}'
        \\TARGET_LOCATION=eastus2
        \\target_version_id=/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release/images/ubuntu-confidential/versions/1.2.3
        \\snapshot_id=/subscriptions/{s}/resourceGroups/{s}/providers/Microsoft.Compute/snapshots/capture
        \\target_definition_id=/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release/images/ubuntu-confidential
        \\target_request='{s}/request.json'
        \\target_response='{s}/response.json'
        \\AZURE_CONFIDENTIAL_VM_ARGS=()
        \\MOCK_MODE=ambiguous
        \\PUT_COUNT=0
        \\azure_confidential_vm_capture_gallery_version_put_args() {{
        \\  AZURE_CONFIDENTIAL_VM_ARGS=(rest --method put --uri "$1")
        \\}}
        \\publication_az() {{
        \\  PUT_COUNT=$((PUT_COUNT + 1))
        \\  printf '%s\n' "$*" >>'{s}/publication.log'
        \\  if [[ "$MOCK_MODE" == ambiguous ]]; then return 52; fi
        \\  printf '%s\n' '{{"id":"'"$target_version_id"'","name":"1.2.3","type":"Microsoft.Compute/galleries/images/versions","location":"eastus2","tags":{{"miz-owner":"ubuntu2404-confidential-capture","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"{s}"}}}}'
        \\}}
        \\wait_gallery_version() {{ return 0; }}
        \\{s}
        \\{s}
        \\{s}
        \\if publish_target_version_once; then exit 90; fi
        \\jq -e '.target.publication.status == "quarantined"' "$STATE_FILE" >/dev/null
        \\[[ "$PUT_COUNT" == 1 ]]
        \\jq '.target.publication.status = "not_dispatched"' "$STATE_FILE" >"$STATE_FILE.reset"
        \\mv "$STATE_FILE.reset" "$STATE_FILE"
        \\chmod 0600 "$STATE_FILE"
        \\MOCK_MODE=success
        \\publish_target_version_once
        \\jq -e '.target.publication.status == "published"' "$STATE_FILE" >/dev/null
        \\[[ "$PUT_COUNT" == 2 ]]
        \\
    ,
        .{
            preamble,
            root,
            release_tool,
            subscription,
            subscription,
            group_name,
            subscription,
            root,
            root,
            root,
            commit,
            state_source,
            owned_source,
            publication_source,
        },
    );
    defer allocator.free(fixture_source);
    const result = try runShellSource(
        allocator,
        root,
        "publication-fixture.sh",
        fixture_source,
    );
    defer result.deinit(allocator);
    if (!result.succeeded()) {
        std.debug.print(
            "publication fixture failed:\nstdout:\n{s}\nstderr:\n{s}\n",
            .{ result.stdout, result.stderr },
        );
    }
    try std.testing.expect(result.succeeded());
    try expectContains(result.stderr, "failed ambiguously");
}

test "parent missing and drift fail before any mutation" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const identity_source = try section(
        script,
        "validate_target_definition_identity() {",
        "\nvalidate_created_resource_document() {",
    );
    const parent_source = try section(
        script,
        "validate_target_parents() {",
        "\nrequire_target_version_absent() {",
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const release_tool = try std.fmt.allocPrint(allocator, "{s}/release", .{root});
    defer allocator.free(release_tool);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = release_tool,
        .data = "#!/usr/bin/env bash\nexit 0\n",
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const fixture_source = try std.fmt.allocPrint(
        allocator,
        \\#!/usr/bin/env bash
        \\set -Eeuo pipefail
        \\TARGET_RESOURCE_GROUP=target-rg
        \\TARGET_GALLERY=release
        \\TARGET_IMAGE_DEFINITION=ubuntu-confidential
        \\TARGET_LOCATION=eastus2
        \\TARGET_OWNER_TAG=durable-owner
        \\TARGET_PUBLISHER=miz
        \\TARGET_OFFER=ubuntu2404
        \\TARGET_SKU=confidential-x64
        \\AZURE_SUBSCRIPTION_ID={s}
        \\GITHUB_REPOSITORY=cataggar/miz
        \\target_definition_id=/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release/images/ubuntu-confidential
        \\target_version_id="$target_definition_id/versions/1.2.3"
        \\snapshot_id=/subscriptions/{s}/resourceGroups/scratch/providers/Microsoft.Compute/snapshots/capture
        \\target_group_json='{s}/group.json'
        \\target_gallery_json='{s}/gallery.json'
        \\target_definition_json='{s}/definition.json'
        \\RELEASE_TOOL='{s}'
        \\MODE=valid
        \\fail() {{ printf '%s\n' "$*" >&2; return 1; }}
        \\publication_az() {{
        \\  printf '%s\n' "$*" >>'{s}/target.log'
        \\  case "$1 $2" in
        \\    "group show")
        \\      [[ "$MODE" != missing-group ]] || return 44
        \\      location=eastus2
        \\      [[ "$MODE" != drift-group ]] || location=westus
        \\      printf '{{"id":"/subscriptions/{s}/resourceGroups/target-rg","name":"target-rg","type":"Microsoft.Resources/resourceGroups","location":"%s","tags":{{"miz-owner":"durable-owner","miz-repository":"cataggar/miz"}}}}\n' "$location"
        \\      ;;
        \\    "sig show")
        \\      [[ "$MODE" != missing-gallery ]] || return 47
        \\      owner=durable-owner
        \\      [[ "$MODE" != drift-gallery ]] || owner=other
        \\      printf '{{"id":"/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release","name":"release","type":"Microsoft.Compute/galleries","location":"eastus2","tags":{{"miz-owner":"%s","miz-repository":"cataggar/miz"}}}}\n' "$owner"
        \\      ;;
        \\    "sig image-definition")
        \\      [[ "$MODE" != missing-definition ]] || return 45
        \\      publisher=miz
        \\      [[ "$MODE" != drift-definition ]] || publisher=other
        \\      printf '{{"id":"%s","name":"ubuntu-confidential","type":"Microsoft.Compute/galleries/images","location":"eastus2","tags":{{"miz-owner":"durable-owner","miz-repository":"cataggar/miz"}},"identifier":{{"publisher":"%s","offer":"ubuntu2404","sku":"confidential-x64"}},"osType":"Linux","osState":"Generalized","hyperVGeneration":"V2","architecture":"x64","provisioningState":"Succeeded","features":[{{"name":"SecurityType","value":"ConfidentialVM"}}]}}\n' "$target_definition_id" "$publisher"
        \\      ;;
        \\    *) return 46 ;;
        \\  esac
        \\}}
        \\{s}
        \\{s}
        \\validate_target_parents
        \\for mode in missing-group missing-gallery missing-definition \
        \\    drift-group drift-gallery drift-definition; do
        \\  MODE=$mode
        \\  if validate_target_parents; then exit 90; fi
        \\done
        \\! grep -Eq '(^| )put( |$)|create|delete|tag update' '{s}/target.log'
        \\
    ,
        .{
            subscription,
            subscription,
            subscription,
            root,
            root,
            root,
            release_tool,
            root,
            subscription,
            subscription,
            identity_source,
            parent_source,
            root,
        },
    );
    defer allocator.free(fixture_source);
    const result = try runShellSource(
        allocator,
        root,
        "parent-fixture.sh",
        fixture_source,
    );
    defer result.deinit(allocator);
    if (!result.succeeded()) {
        std.debug.print("parent fixture failed:\n{s}\n{s}\n", .{
            result.stdout,
            result.stderr,
        });
    }
    try std.testing.expect(result.succeeded());
    try expectContains(result.stderr, "Pre-provisioned target resource group");
    try expectContains(result.stderr, "Pre-provisioned target gallery");
    try expectContains(result.stderr, "Pre-provisioned target ConfidentialVM");
    try expectContains(result.stderr, "Target resource group subscription");
    try expectContains(result.stderr, "Target gallery subscription");
    try expectContains(result.stderr, "Target image definition contract");
}

test "preexisting target version and second-check race are hard conflicts" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const absent_source = try section(
        script,
        "require_target_version_absent() {",
        "\nquarantine_temporary_group_create() {",
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const fixture_source = try std.fmt.allocPrint(
        allocator,
        \\#!/usr/bin/env bash
        \\set -Eeuo pipefail
        \\RESULT_DIR='{s}'
        \\target_version_id=/subscriptions/{s}/resourceGroups/target-rg/providers/Microsoft.Compute/galleries/release/images/ubuntu-confidential/versions/1.2.3
        \\CALLS=0
        \\MODE=preexisting
        \\fail() {{ printf '%s\n' "$*" >&2; return 1; }}
        \\publication_az() {{
        \\  CALLS=$((CALLS + 1))
        \\  if [[ "$MODE" == race && "$CALLS" == 1 ]]; then
        \\    printf 'ResourceNotFound\n' >&2
        \\    return 3
        \\  fi
        \\  printf '%s\n' '{{"id":"'"$target_version_id"'","tags":{{"miz-owner":"ubuntu2404-confidential-capture","miz-run-id":"123"}}}}'
        \\}}
        \\{s}
        \\if require_target_version_absent startup; then exit 90; fi
        \\[[ "$CALLS" == 1 ]]
        \\CALLS=0
        \\MODE=race
        \\require_target_version_absent startup
        \\if require_target_version_absent pre-put; then
        \\  echo PUT >>'{s}/mutation.log'
        \\  exit 91
        \\fi
        \\[[ "$CALLS" == 2 ]]
        \\[[ ! -e '{s}/mutation.log' ]]
        \\
    ,
        .{ root, subscription, absent_source, root, root },
    );
    defer allocator.free(fixture_source);
    const result = try runShellSource(
        allocator,
        root,
        "version-race-fixture.sh",
        fixture_source,
    );
    defer result.deinit(allocator);
    if (!result.succeeded()) {
        std.debug.print("version race fixture failed:\n{s}\n{s}\n", .{
            result.stdout,
            result.stderr,
        });
    }
    try std.testing.expect(result.succeeded());
    try expectContains(
        result.stderr,
        "Target gallery version already exists; refusing update or overwrite",
    );
}

test "ambiguous temporary group creation is quarantined and never deleted" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const state_source = try section(
        script,
        "state_replace() {",
        "\nowned_tags_match() {",
    );
    const ownership_source = try section(
        script,
        "owned_tags_match() {",
        "\nvalidate_write_access_identity() {",
    );
    const create_source = try section(
        script,
        "persist_temporary_group_create() {",
        "\ncreate_common_network() {",
    );
    const cleanup_source = try section(
        script,
        "delete_temporary_group() {",
        "\ncleanup_resources() {",
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const state = try writeState(
        allocator,
        root,
        "expected",
        "not_dispatched",
        false,
        "[]",
    );
    defer allocator.free(state);
    const preamble = try shellIdentityPreamble(allocator, state);
    defer allocator.free(preamble);
    const fixture_source = try std.fmt.allocPrint(
        allocator,
        \\#!/usr/bin/env bash
        \\set -Eeuo pipefail
        \\{s}
        \\RESULT_DIR='{s}'
        \\resource_group={s}
        \\temporary_group_id=/subscriptions/{s}/resourceGroups/{s}
        \\temporary_group_request='{s}/group-request.json'
        \\temporary_group_response='{s}/group-response.json'
        \\temporary_group_json='{s}/group.json'
        \\AZURE_CONFIDENTIAL_VM_ARGS=()
        \\azure_confidential_vm_resource_group_create_args() {{
        \\  AZURE_CONFIDENTIAL_VM_ARGS=(rest --method put --uri "$1")
        \\}}
        \\az() {{
        \\  printf '%s\n' "$*" >>'{s}/az.log'
        \\  return 52
        \\}}
        \\{s}
        \\{s}
        \\{s}
        \\{s}
        \\if create_temporary_group; then exit 90; fi
        \\jq -e '.temporary_group_create.status == "quarantined"' "$STATE_FILE" >/dev/null
        \\if delete_temporary_group; then exit 91; fi
        \\! grep -q 'group delete' '{s}/az.log'
        \\
    ,
        .{
            preamble,
            root,
            group_name,
            subscription,
            group_name,
            root,
            root,
            root,
            root,
            state_source,
            ownership_source,
            create_source,
            cleanup_source,
            root,
        },
    );
    defer allocator.free(fixture_source);
    const result = try runShellSource(
        allocator,
        root,
        "temporary-create-fixture.sh",
        fixture_source,
    );
    defer result.deinit(allocator);
    try std.testing.expect(result.succeeded());
    try expectContains(result.stderr, "create failed ambiguously");
    try expectContains(result.stderr, "requires manual review");
}

test "exact allowlist records resources and unknown inventory blocks group deletion" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const state_source = try section(
        script,
        "state_replace() {",
        "\nowned_tags_match() {",
    );
    const ownership_source = try section(
        script,
        "owned_tags_match() {",
        "\nvalidate_write_access_identity() {",
    );
    const cleanup_source = try section(
        script,
        "delete_temporary_group() {",
        "\ncleanup_resources() {",
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const disk_id = "/subscriptions/" ++ subscription ++ "/resourceGroups/" ++
        group_name ++ "/providers/Microsoft.Compute/disks/upload";
    const state = try writeState(
        allocator,
        root,
        "confirmed_created",
        "not_dispatched",
        false,
        "[]",
    );
    defer allocator.free(state);
    const preamble = try shellIdentityPreamble(allocator, state);
    defer allocator.free(preamble);
    const fixture_source = try std.fmt.allocPrint(
        allocator,
        \\#!/usr/bin/env bash
        \\set -Eeuo pipefail
        \\{s}
        \\resource_group={s}
        \\MOCK_UNKNOWN=true
        \\az() {{
        \\  printf '%s\n' "$*" >>'{s}/az.log'
        \\  case "$1 $2" in
        \\    "group show")
        \\      printf '{{"id":"/subscriptions/{s}/resourceGroups/{s}","name":"{s}","type":"Microsoft.Resources/resourceGroups","location":"eastus2","tags":{{"miz-owner":"ubuntu2404-confidential-capture","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"{s}"}}}}\n'
        \\      ;;
        \\    "resource list")
        \\      if [[ "$MOCK_UNKNOWN" == true ]]; then
        \\        printf '[{{"id":"{s}","name":"upload","type":"Microsoft.Compute/disks","tags":{{"miz-owner":"ubuntu2404-confidential-capture","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"{s}"}}}},{{"id":"/subscriptions/{s}/resourceGroups/{s}/providers/Microsoft.Compute/disks/unknown","name":"unknown","type":"Microsoft.Compute/disks","tags":{{}}}}]\n'
        \\      else
        \\        printf '[{{"id":"{s}","name":"upload","type":"Microsoft.Compute/disks","tags":{{"miz-owner":"ubuntu2404-confidential-capture","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"{s}"}}}}]\n'
        \\      fi
        \\      ;;
        \\    "group delete") return 0 ;;
        \\    *) return 73 ;;
        \\  esac
        \\}}
        \\{s}
        \\{s}
        \\{s}
        \\printf '{{"id":"{s}","name":"upload","type":"Microsoft.Compute/disks","location":"eastus2","tags":{{"miz-owner":"ubuntu2404-confidential-capture","miz-repository":"cataggar/miz","miz-run-id":"123","miz-run-attempt":"4","miz-source-commit":"{s}"}}}}\n' >'{s}/disk.json'
        \\record_expected_resource '{s}/disk.json' '{s}' Microsoft.Compute/disks upload
        \\jq -e '.temporary_resources == [{{"id":"{s}","name":"upload","type":"Microsoft.Compute/disks"}}]' "$STATE_FILE" >/dev/null
        \\if delete_temporary_group; then exit 90; fi
        \\! grep -q 'group delete' '{s}/az.log'
        \\MOCK_UNKNOWN=false
        \\delete_temporary_group
        \\grep -q 'group delete' '{s}/az.log'
        \\jq -e '.temporary_group_create == null and .temporary_resources == []' "$STATE_FILE" >/dev/null
        \\
    ,
        .{
            preamble,
            group_name,
            root,
            subscription,
            group_name,
            group_name,
            commit,
            disk_id,
            commit,
            subscription,
            group_name,
            disk_id,
            commit,
            state_source,
            ownership_source,
            cleanup_source,
            disk_id,
            commit,
            root,
            root,
            disk_id,
            disk_id,
            root,
            root,
        },
    );
    defer allocator.free(fixture_source);
    const result = try runShellSource(
        allocator,
        root,
        "inventory-fixture.sh",
        fixture_source,
    );
    defer result.deinit(allocator);
    if (!result.succeeded()) {
        std.debug.print("inventory fixture failed:\n{s}\n{s}\n", .{
            result.stdout,
            result.stderr,
        });
    }
    try std.testing.expect(result.succeeded());
    try expectContains(result.stderr, "unknown, mismatched, or untagged");
}

test "state replacement remains atomic" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const state_source = try section(
        script,
        "state_replace() {",
        "\nowned_tags_match() {",
    );
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const state = try writeState(
        allocator,
        root,
        "expected",
        "not_dispatched",
        false,
        "[]",
    );
    defer allocator.free(state);
    const preamble = try shellIdentityPreamble(allocator, state);
    defer allocator.free(preamble);
    const bin = try std.fmt.allocPrint(allocator, "{s}/bin", .{root});
    defer allocator.free(bin);
    try Dir.cwd().createDirPath(std.testing.io, bin);
    const jq_mock = try std.fmt.allocPrint(allocator, "{s}/jq", .{bin});
    defer allocator.free(jq_mock);
    try Dir.cwd().writeFile(std.testing.io, .{
        .sub_path = jq_mock,
        .data =
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\for arg in "$@"; do
        \\  if [[ "$arg" == '.run_succeeded = true' &&
        \\      "${MOCK_JQ_FAIL:-false}" == true ]]; then
        \\    printf '{"partial":'
        \\    exit 71
        \\  fi
        \\done
        \\exec "$REAL_JQ" "$@"
        \\
        ,
        .flags = .{ .permissions = .fromMode(0o755) },
    });
    const fixture_source = try std.fmt.allocPrint(
        allocator,
        \\#!/usr/bin/env bash
        \\set -Eeuo pipefail
        \\{s}
        \\REAL_JQ=$(command -v jq)
        \\export REAL_JQ
        \\cp "$STATE_FILE" '{s}/original.json'
        \\PATH='{s}':"$PATH"
        \\export PATH MOCK_JQ_FAIL=true
        \\{s}
        \\if state_replace '.run_succeeded = true'; then exit 90; fi
        \\cmp -s "$STATE_FILE" '{s}/original.json'
        \\[[ ! -e "$STATE_FILE.next" ]]
        \\MOCK_JQ_FAIL=false
        \\old_inode=$(stat -c %i "$STATE_FILE")
        \\state_replace '.run_succeeded = true'
        \\jq -e '.run_succeeded == true' "$STATE_FILE" >/dev/null
        \\[[ $(stat -c %i "$STATE_FILE") != "$old_inode" ]]
        \\[[ ! -e "$STATE_FILE.next" ]]
        \\
    ,
        .{ preamble, root, bin, state_source, root },
    );
    defer allocator.free(fixture_source);
    const result = try runShellSource(
        allocator,
        root,
        "state-fixture.sh",
        fixture_source,
    );
    defer result.deinit(allocator);
    try std.testing.expect(result.succeeded());
}

test "prior fail-closed capture sequencing remains intact" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);
    const guest = try readTracked(allocator, guest_library_path);
    defer allocator.free(guest);

    for ([_][]const u8{
        "'.outstanding_write_access = {\n      status: \"pending\"",
        "--request POST",
        "'.outstanding_write_access.status = \"active\"'",
        "revoke_outstanding_disk_write_access || cleanup_status=1",
        "deprovision_and_schedule_shutdown",
        "waagent -deprovision+user -force >/dev/null; shutdown -h +1 >/dev/null",
        "shutdown_power_state=$(az vm get-instance-view",
        "PowerState/stopped",
        "PowerState/deallocated",
        "azure_confidential_vm_generalize_args",
        "# Refresh every live Azure document and both public MAA documents",
        "refresh_maa_metadata \"$final_openid\" \"$final_jwks\"",
        "verify_capture_evidence_revisions",
        "\"$RELEASE_TOOL\" check-capture-disk",
        "\"$RELEASE_TOOL\" check-capture-snapshot",
        "\"$RELEASE_TOOL\" check-capture-definition",
        "\"$RELEASE_TOOL\" check-capture-gallery",
        "\"$RELEASE_TOOL\" check-captured-vm",
    }) |needle| try expectContains(script, needle);
    try expectContains(
        guest,
        "if (( validation_status != 0 )); then\n    return \"$validation_status\"",
    );
    try expectAbsent(script, ">/dev/null 2>&1 || true");

    const pending = try indexOf(
        script,
        "'.outstanding_write_access = {\n      status: \"pending\"",
    );
    const sas_request = try indexOf(script, "--request POST");
    const active = try indexOf(
        script,
        "'.outstanding_write_access.status = \"active\"'",
    );
    const deprovision = try indexOf(
        script,
        "deprovision_and_schedule_shutdown\n",
    );
    const shutdown_state = try indexOf(
        script,
        "shutdown_power_state=$(az vm get-instance-view",
    );
    const deallocate = try indexOf(
        script,
        "azure_confidential_vm_deallocate_args",
    );
    const generalize = try indexOf(
        script,
        "azure_confidential_vm_generalize_args",
    );
    try std.testing.expect(pending < sas_request);
    try std.testing.expect(sas_request < active);
    try std.testing.expect(deprovision < shutdown_state);
    try std.testing.expect(shutdown_state < deallocate);
    try std.testing.expect(deallocate < generalize);
}

test "invalid stable publication lock is rejected before Azure or artifact work" {
    const allocator = std.testing.allocator;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const root = try fixtureRoot(allocator, tmp);
    defer allocator.free(root);
    const repository = try rootAlloc(allocator);
    defer allocator.free(repository);
    const script = try std.fs.path.join(allocator, &.{ repository, script_path });
    defer allocator.free(script);
    var environment = try std.process.Environ.createMap(
        std.testing.environ,
        allocator,
    );
    defer environment.deinit();
    const entries = [_][2][]const u8{
        .{ "STATE_FILE", "state.json" },
        .{ "GITHUB_REPOSITORY", "cataggar/miz" },
        .{ "GITHUB_RUN_ID", "123" },
        .{ "GITHUB_RUN_ATTEMPT", "4" },
        .{ "GITHUB_REF", "refs/heads/main" },
        .{ "PROTECTED_ENVIRONMENT", "ubuntu2404-confidential-capture" },
        .{ "SOURCE_COMMIT", commit },
        .{ "CANDIDATE", "candidate" },
        .{ "PROVENANCE", "provenance" },
        .{ "SOURCE_ACCEPTANCE", "acceptance" },
        .{ "SOURCE_LOCATION", "eastus2" },
        .{ "SOURCE_VM_SIZE", "Standard_DC2as_v5" },
        .{ "SOURCE_RUN_ID", "12" },
        .{ "SOURCE_RUN_ATTEMPT", "1" },
        .{ "SOURCE_REPOSITORY", "cataggar/miz" },
        .{ "AZURE_SUBSCRIPTION_ID", subscription },
        .{ "AZURE_LOCATION", "eastus2" },
        .{ "AZURE_VM_SIZE", "Standard_DC2as_v5" },
        .{ "TARGET_RESOURCE_GROUP", "target-rg" },
        .{ "TARGET_GALLERY", "release" },
        .{ "TARGET_IMAGE_DEFINITION", "ubuntu-confidential" },
        .{ "TARGET_IMAGE_VERSION", "1.2.3" },
        .{ "TARGET_LOCATION", "eastus2" },
        .{ "TARGET_OWNER_TAG", "durable-owner" },
        .{ "PUBLICATION_LOCK_ID", "run-specific-lock" },
        .{ "CAPTURE_PRINCIPAL_CLIENT_ID", capture_principal },
        .{ "PUBLICATION_PRINCIPAL_CLIENT_ID", principal },
        .{ "PUBLICATION_AZURE_CONFIG_DIR", root },
        .{ "RESULT_DIR", "result" },
        .{ "MIZ", "miz" },
    };
    for (entries) |entry| try environment.put(entry[0], entry[1]);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ script, "run" },
        .cwd = .{ .path = root },
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
    try expectContains(result.stderr, "Protected publication lock identity is invalid");
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

test "capture result and verification arguments match their CLI schemas" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, script_path);
    defer allocator.free(script);

    const result_arguments = try captureArguments(
        script,
        "capture-result",
        "\nverify_capture_evidence_revisions\n",
    );
    try expectArgumentSchema(
        result_arguments,
        &confidential_release.capture_result_option_schema,
    );
    try confidential_release.parseCaptureCommandArguments(
        "capture-result",
        result_arguments.argv[0..result_arguments.argv_len],
    );

    const verify_arguments = try captureArguments(
        script,
        "verify-capture",
        "\n\njq -e \\\n",
    );
    try expectArgumentSchema(
        verify_arguments,
        &confidential_release.capture_verify_option_schema,
    );
    try confidential_release.parseCaptureCommandArguments(
        "verify-capture",
        verify_arguments.argv[0..verify_arguments.argv_len],
    );
}
