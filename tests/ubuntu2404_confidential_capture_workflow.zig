//! Structural guards for the protected full ConfidentialVM capture workflow.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const workflow_path =
    ".github/workflows/ubuntu2404-confidential-capture.yml";
const harness_path = "scripts/ubuntu2404_confidential_capture.sh";
const guide_path = "doc/azure-confidential-vm.md";
const max_source_bytes = 4 * 1024 * 1024;

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

fn expectCount(text: []const u8, needle: []const u8, expected: usize) !void {
    const actual = std.mem.count(u8, text, needle);
    if (actual == expected) return;
    std.debug.print(
        "expected {d} occurrence(s) of \"{s}\", found {d}\n",
        .{ expected, needle, actual },
    );
    return error.UnexpectedOccurrenceCount;
}

fn indexOf(text: []const u8, needle: []const u8) !usize {
    return std.mem.indexOf(u8, text, needle) orelse
        error.RequiredTextMissing;
}

fn section(text: []const u8, start: []const u8, end: ?[]const u8) ![]const u8 {
    const start_index = try indexOf(text, start);
    const tail = text[start_index + start.len ..];
    const marker = end orelse return tail;
    const end_index = std.mem.indexOf(u8, tail, marker) orelse
        return error.RequiredTextMissing;
    return tail[0..end_index];
}

fn isHexSha(text: []const u8) bool {
    if (text.len != 40) return false;
    for (text) |character| switch (character) {
        '0'...'9', 'a'...'f' => {},
        else => return false,
    };
    return true;
}

test "capture workflow is dispatch-only guarded and fully pinned" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);

    try expectCount(workflow, "workflow_dispatch:", 1);
    try expectAbsent(workflow, "\n  push:");
    try expectAbsent(workflow, "\n  pull_request:");
    try expectContains(
        workflow,
        "if: github.repository == 'cataggar/miz' && github.ref == 'refs/heads/main'",
    );
    try expectContains(
        workflow,
        "group: ubuntu2404-confidential-cvm-target-version\n  cancel-in-progress: false",
    );
    try expectCount(
        workflow,
        "environment: ubuntu2404-confidential-capture",
        2,
    );
    try expectCount(workflow, "id-token: write", 1);
    try expectAbsent(workflow, "uses: actions/checkout@v");
    try expectAbsent(workflow, "uses: azure/login@v");

    var lines = std.mem.splitScalar(u8, workflow, '\n');
    while (lines.next()) |line| {
        const trimmed = std.mem.trim(u8, line, " \t\r");
        if (!std.mem.startsWith(u8, trimmed, "uses: ")) continue;
        const at = std.mem.lastIndexOfScalar(u8, trimmed, '@') orelse
            return error.UnpinnedAction;
        const suffix = trimmed[at + 1 ..];
        const sha = suffix[0 .. std.mem.indexOfScalar(u8, suffix, ' ') orelse suffix.len];
        try std.testing.expect(isHexSha(sha));
    }
}

test "immutable source release and provenance identities fail closed" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const prepare = try section(workflow, "\n  prepare:\n", "\n  capture:\n");
    try expectContains(workflow, "source_release_tag:");
    try expectContains(workflow, "target_gallery_version:");

    for ([_][]const u8{
        "^Ubuntu-24\\.04-confidential-[0-9]{8}$",
        "TARGET_GALLERY_VERSION\" =~ ^(0|[1-9][0-9]{0,9})",
        "target_major != 0 || 10#$target_minor != 0 || 10#$target_patch != 0",
        "git ls-remote origin refs/heads/main",
        "refs/tags/$SOURCE_RELEASE_TAG^{}",
        "provenance_release_tag=\"Ubuntu-24.04-confidential-cvm-$TARGET_GALLERY_VERSION\"",
        "test \"$provenance_commit\" = \"$tool_commit\"",
        ".draft == false",
        ".prerelease == false",
        "(.assets | type == \"array\" and length == 3)",
        "Provenance release already exists; refusing reuse",
        "grep -Eq 'HTTP 404|Not Found'",
    }) |needle| try expectContains(prepare, needle);
}

test "source acquisition is exact and validated before Azure" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const capture_job = try section(
        workflow,
        "\n  capture:\n",
        "\n  publish_provenance:\n",
    );

    for ([_][]const u8{
        "Ubuntu-24.04-x86_64.confidential.qcow2",
        "Ubuntu-24.04-x86_64.confidential.qcow2.provenance.json",
        "Ubuntu-24.04-x86_64.confidential.azure-acceptance.json",
        "releases/assets/$SOURCE_QCOW_ASSET_ID",
        "releases/assets/$SOURCE_PROVENANCE_ASSET_ID",
        "releases/assets/$SOURCE_ACCEPTANCE_ASSET_ID",
        "test \"$(find \"$CANDIDATE_DIR\" -maxdepth 1 -type f | wc -l)\" -eq 3",
        "\"$RELEASE_TOOL\" verify-build",
        "\"$RELEASE_TOOL\" verify-acceptance",
        "source_group\" =~ ^miz-u2404-cvm-",
    }) |needle| try expectContains(capture_job, needle);
    try expectAbsent(capture_job, "gh release download");
    try expectAbsent(capture_job, "path: ${{ env.RESULT_DIR }}\n");

    const validate_source = try indexOf(
        capture_job,
        "- name: Validate source shape hashes and protected source identity",
    );
    const first_login = try indexOf(
        capture_job,
        "- name: Log in capture principal with protected-environment OIDC",
    );
    try std.testing.expect(validate_source < first_login);
}

test "dual OIDC contexts and staged freshness ordering are fixed" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const harness = try readTracked(allocator, harness_path);
    defer allocator.free(harness);
    const capture_job = try section(
        workflow,
        "\n  capture:\n",
        "\n  publish_provenance:\n",
    );

    for ([_][]const u8{
        "AZURE_CONFIG_DIR: ${{ github.workspace }}/.capture/azure/capture",
        "PUBLICATION_AZURE_CONFIG_DIR: ${{ github.workspace }}/.capture/azure/publication",
        "secrets.AZURE_CAPTURE_CLIENT_ID",
        "secrets.AZURE_PUBLICATION_CLIENT_ID",
        "scripts/ubuntu2404_confidential_capture.sh prepare",
        "scripts/ubuntu2404_confidential_capture.sh publish",
        "if: always()\n        uses: azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5",
        "steps.cleanup_login.outcome == 'success'",
        "Fresh cleanup login failed; retaining quarantined scratch state",
        "scripts/ubuntu2404_confidential_capture.sh cleanup",
    }) |needle| try expectContains(capture_job, needle);
    try expectContains(harness, "require_capture_account");
    try expectContains(harness, "require_publication_account");
    try expectContains(harness, "tenantId");
    try expectContains(harness, "Capture and publication principals must be distinct");

    const prepare = try indexOf(capture_job, "capture.sh prepare");
    const publisher_login = try indexOf(
        capture_job,
        "Log in exclusive publication principal only when prepared",
    );
    const capture_refresh = try indexOf(
        capture_job,
        "Refresh capture OIDC immediately before publication validation",
    );
    const publish = try indexOf(capture_job, "capture.sh publish");
    const cleanup_refresh = try indexOf(
        capture_job,
        "Refresh capture OIDC for unconditional exact cleanup",
    );
    const cleanup = try indexOf(capture_job, "capture.sh cleanup");
    try std.testing.expect(prepare < publisher_login);
    try std.testing.expect(publisher_login < capture_refresh);
    try std.testing.expect(capture_refresh < publish);
    try std.testing.expect(publish < cleanup_refresh);
    try std.testing.expect(cleanup_refresh < cleanup);
}

test "publication boundary uploads one sanitized result and never deletes target" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const harness = try readTracked(allocator, harness_path);
    defer allocator.free(harness);
    const publication = try section(
        workflow,
        "\n  publish_provenance:\n",
        null,
    );

    try expectCount(workflow, "gh release upload", 1);
    for ([_][]const u8{
        "path: ${{ env.RESULT_DIR }}/capture-result.json",
        "verify-capture-publication",
        "--expected-result-sha256 \"$EXPECTED_RESULT_SHA256\"",
        "(.assets | length == 1)",
        ".draft == true",
        "gh release edit \"$PROVENANCE_RELEASE_TAG\"",
        "--draft=false",
    }) |needle| try expectContains(workflow, needle);
    try expectAbsent(workflow, "attestation.jwt");
    try expectAbsent(workflow, "openid-configuration.json");
    try expectAbsent(workflow, "jwks.json");
    try expectAbsent(workflow, "id_ed25519");
    try expectAbsent(publication, "azure/login@");
    try expectAbsent(harness, "sig image-version delete");
    try expectAbsent(harness, "sig image-definition delete");
    try expectAbsent(harness, "delete_created_version");
    try expectAbsent(harness, "delete_created_definition");
    try expectCount(
        harness,
        "publication_az \"${AZURE_CONFIDENTIAL_VM_ARGS[@]}\" \\\n      >\"$target_response\"",
        1,
    );
}

test "operator guide fixes prerequisites RBAC and quarantine boundary" {
    const allocator = std.testing.allocator;
    const guide = try readTracked(allocator, guide_path);
    defer allocator.free(guide);
    for ([_][]const u8{
        "Azure creates the captured VM Guest State",
        "`SecurityType=ConfidentialVM`",
        "`VMGuestStateOnly`",
        "`EncryptedVMGuestStateOnlyWithPmk`",
        "Replication is\n`Full`",
        "durable target resource group, private gallery",
        "`AZURE_CAPTURE_CLIENT_ID`",
        "`AZURE_PUBLICATION_CLIENT_ID`",
        "require at least one designated release reviewer",
        "disable self-review",
        "no version delete permission",
        "outside what the workflow or harness can\nprove",
        "stable, non-canceling concurrency group",
        "quarantined",
        "manual",
        "live Azure qualification run",
    }) |needle| try expectContains(guide, needle);
}
