//! Structural guards for the protected Ubuntu 24.04 Confidential VM release.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const workflow_path = ".github/workflows/ubuntu2404-confidential-release.yml";
const publisher_path = "scripts/ubuntu2404_confidential_publish.sh";
const guide_path = "doc/azure-confidential-vm.md";
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

fn expectCount(text: []const u8, needle: []const u8, expected: usize) !void {
    const actual = std.mem.count(u8, text, needle);
    if (actual == expected) return;
    std.debug.print(
        "expected {d} occurrence(s) of \"{s}\", found {d}\n",
        .{ expected, needle, actual },
    );
    return error.UnexpectedOccurrenceCount;
}

fn section(text: []const u8, start: []const u8, end: ?[]const u8) ![]const u8 {
    const start_index = std.mem.indexOf(u8, text, start) orelse
        return error.MissingSection;
    const rest = text[start_index + start.len ..];
    const marker = end orelse return rest;
    const end_index = std.mem.indexOf(u8, rest, marker) orelse
        return error.MissingSection;
    return rest[0..end_index];
}

fn indexOf(text: []const u8, needle: []const u8) !usize {
    return std.mem.indexOf(u8, text, needle) orelse
        error.RequiredTextMissing;
}

test "workflow dispatch and protected identity are fail closed" {
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
        "RELEASE_TAG: Ubuntu-24.04-confidential-20260907",
    );
    try expectContains(workflow, "test \"$tag_commit\" = \"$commit\"");
    try expectCount(workflow, "environment: ubuntu2404-confidential-release", 2);
    try expectCount(workflow, "id-token: write", 1);
    try expectContains(
        workflow,
        "repo:cataggar/miz:environment:ubuntu2404-confidential-release",
    );
    for ([_][]const u8{
        "secrets.AZURE_CLIENT_ID",
        "secrets.AZURE_TENANT_ID",
        "secrets.AZURE_SUBSCRIPTION_ID",
        "vars.AZURE_LOCATION",
        "vars.AZURE_VM_SIZE",
        "test \"$AZURE_LOCATION\" = westeurope",
        "test \"$AZURE_VM_SIZE\" = Standard_DC2as_v5",
    }) |needle| try expectContains(workflow, needle);
    try expectCount(
        workflow,
        "azure/login@a457da9ea143d694b1b9c7c869ebb04ebe844ef5",
        2,
    );
    try expectAbsent(workflow, "uses: azure/login@v");
    try expectAbsent(workflow, "uses: actions/checkout@v");
    try expectAbsent(workflow, "persist-credentials: true");
}

test "build uploads only the exact authenticated candidate and provenance" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const build = try section(workflow, "\n  build:\n", "\n  azure_acceptance:\n");

    for ([_][]const u8{
        "needs: prepare",
        "ref: ${{ needs.prepare.outputs.source_commit }}",
        "generalized-ubuntu2404-confidential --",
        "--work-dir \"$GITHUB_WORKSPACE/$WORK_DIR\"",
        "--output \"$GITHUB_WORKSPACE/$CANDIDATE\"",
        "--provenance \"$GITHUB_WORKSPACE/$PROVENANCE\"",
        "\"$RELEASE_TOOL\" verify-build",
        "qemu-img check \"$CANDIDATE\"",
        "name: ubuntu2404-confidential-candidate-${{ needs.prepare.outputs.source_commit }}-${{ github.run_attempt }}",
        "${{ env.CANDIDATE }}\n            ${{ env.PROVENANCE }}",
        "compression-level: 0",
        "if-no-files-found: error",
        "rm -rf -- \"$BUNDLE_DIR\" \"$WORK_DIR/extracted\" \"$WORK_DIR/gnupg\"",
    }) |needle| try expectContains(build, needle);
    try expectContains(
        build,
        "ubuntu2404-confidential-canonical-20260826-843d243792abb05b50e1a7f5e614e1184d8fc7195c119747cbb3038520258a22",
    );
}

test "acceptance uses the exact artifact OIDC and unconditional owned cleanup" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const acceptance = try section(
        workflow,
        "\n  azure_acceptance:\n",
        "\n  publish:\n",
    );

    for ([_][]const u8{
        "needs: [prepare, build]",
        "environment: ubuntu2404-confidential-release",
        "name: ubuntu2404-confidential-candidate-${{ needs.prepare.outputs.source_commit }}-${{ github.run_attempt }}",
        "install-miz install-ubuntu2404-confidential-release",
        "scripts/ubuntu2404_confidential_azure_acceptance.sh run",
        "- name: Refresh Azure OIDC credential for unconditional cleanup\n        if: always()",
        "- name: Delete only exact ownership-tagged Azure resources\n        if: always()",
        "scripts/ubuntu2404_confidential_azure_acceptance.sh cleanup",
        "name: ubuntu2404-confidential-azure-${{ needs.prepare.outputs.source_commit }}-${{ github.run_attempt }}",
        "path: ${{ env.RESULT_DIR }}/azure-result.json",
    }) |needle| try expectContains(acceptance, needle);

    const login = try indexOf(acceptance, "- name: Log in to Azure with protected-environment OIDC");
    const run_acceptance = try indexOf(
        acceptance,
        "- name: Run exact-digest Confidential VM acceptance",
    );
    const refresh = try indexOf(
        acceptance,
        "- name: Refresh Azure OIDC credential for unconditional cleanup",
    );
    const cleanup = try indexOf(
        acceptance,
        "- name: Delete only exact ownership-tagged Azure resources",
    );
    const upload = try indexOf(
        acceptance,
        "- name: Upload exact Confidential VM acceptance result",
    );
    try std.testing.expect(login < run_acceptance);
    try std.testing.expect(run_acceptance < refresh);
    try std.testing.expect(refresh < cleanup);
    try std.testing.expect(cleanup < upload);
}

test "publication revalidates both artifacts before a three-asset release" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);
    const publish = try section(workflow, "\n  publish:\n", null);
    const publisher = try readTracked(allocator, publisher_path);
    defer allocator.free(publisher);

    for ([_][]const u8{
        "needs: [prepare, build, azure_acceptance]",
        "needs.prepare.result == 'success'",
        "needs.build.result == 'success'",
        "needs.azure_acceptance.result == 'success'",
        "environment: ubuntu2404-confidential-release",
        "contents: write",
        "Download exact build candidate and provenance",
        "Download exact protected acceptance result",
        "scripts/ubuntu2404_confidential_publish.sh",
    }) |needle| try expectContains(publish, needle);
    for ([_][]const u8{
        "\"$RELEASE_TOOL\" verify-acceptance",
        "--source-commit \"$SOURCE_COMMIT\"",
        "--run-id \"$GITHUB_RUN_ID\"",
        "--run-attempt \"$GITHUB_RUN_ATTEMPT\"",
        "test \"$(wc -l <\"$expected_file\")\" -eq 3",
        "--json isDraft",
        "Final release $RELEASE_TAG is immutable",
        "\"$RELEASE_TOOL\" check-release-metadata",
        "--target \"$SOURCE_COMMIT\"",
        "check-draft-assets",
        "check_release_assets exact",
        "check_release_assets subset",
        "https://uploads.github.com/repos/$REPOSITORY/releases/$release_id/assets?name=$asset_name",
        "gh release download",
        "check_release_assets published",
        "Ubuntu-24.04-x86_64.confidential.qcow2",
        "provenance_name=$candidate_name.provenance.json",
        "Ubuntu-24.04-x86_64.confidential.azure-acceptance.json",
        "release_published=true",
        "quarantine and inspect immutable release",
    }) |needle| try expectContains(publisher, needle);
    try expectAbsent(publisher, "gh release upload");
    try expectAbsent(publisher, "--clobber");
    try expectAbsent(publisher, "\njq ");
    try expectAbsent(publisher, "eval ");
    try expectAbsent(publisher, "--draft >/dev/null 2>&1 || true");
}

test "publisher is executable valid shell and documents the exact support boundary" {
    const allocator = std.testing.allocator;
    const root = try rootAlloc(allocator);
    defer allocator.free(root);
    const publisher = try std.fs.path.join(allocator, &.{ root, publisher_path });
    defer allocator.free(publisher);
    const stat = try Dir.cwd().statFile(std.testing.io, publisher, .{});
    try std.testing.expect(stat.permissions.toMode() & 0o111 != 0);
    const result = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", "-n", publisher },
        .stdout_limit = .limited(max_output_bytes),
        .stderr_limit = .limited(max_output_bytes),
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    try std.testing.expectEqual(@as(?u8, 0), switch (result.term) {
        .exited => |code| code,
        else => null,
    });

    const guide = try readTracked(allocator, guide_path);
    defer allocator.free(guide);
    for ([_][]const u8{
        ".github/workflows/ubuntu2404-confidential-release.yml",
        "Ubuntu 24.04 LTS x86_64 and AMD SEV-SNP only",
        "`westeurope` / `Standard_DC2as_v5`",
        "`VMGuestStateOnly`",
        "Canonical's stock Microsoft/Canonical Secure Boot trust",
        "nonce-bound Microsoft Azure Attestation",
        "`repo:cataggar/miz:environment:ubuntu2404-confidential-release`",
        "`AZURE_CLIENT_ID`",
        "`AZURE_TENANT_ID`",
        "`AZURE_SUBSCRIPTION_ID`",
    }) |needle| try expectContains(guide, needle);
}
