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

fn runShellFixture(
    allocator: Allocator,
    name: []const u8,
    source: []const u8,
) !void {
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    const repository = try rootAlloc(allocator);
    defer allocator.free(repository);
    const root = try allocator.print(
        "{s}/.zig-cache/tmp/{s}",
        .{ repository, tmp.sub_path },
    );
    defer allocator.free(root);
    const path = try allocator.print(
        "{s}/{s}",
        .{ root, name },
    );
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
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| {
            if (code == 0) return;
            std.debug.print("fixture failed:\n{s}\n{s}\n", .{
                result.stdout,
                result.stderr,
            });
            return error.ShellFixtureFailed;
        },
        else => return error.ShellFixtureFailed,
    }
}

test "workflow dispatch and protected identity are fail closed" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, workflow_path);
    defer allocator.free(workflow);

    try expectCount(workflow, "workflow_dispatch:", 1);
    try expectContains(workflow, "validation_only:");
    try expectContains(workflow, "default: false\n        type: boolean");
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
    try expectContains(workflow, "if [[ \"$VALIDATION_ONLY\" != true ]]; then");
    try expectContains(workflow, "test \"$tag_commit\" = \"$commit\"");
    try expectContains(workflow, "echo \"Mode: \\`validation_only\\`\" >> \"$GITHUB_STEP_SUMMARY\"");
    try expectCount(workflow, "environment: ubuntu2604-release", 2);
    try expectAbsent(workflow, "environment: ubuntu2404-confidential-release");
    try expectCount(workflow, "id-token: write", 1);
    try expectContains(
        workflow,
        "repo:cataggar/miz:environment:ubuntu2604-release",
    );
    for ([_][]const u8{
        "secrets.AZURE_CLIENT_ID",
        "secrets.AZURE_TENANT_ID",
        "secrets.AZURE_SUBSCRIPTION_ID",
        "vars.AZURE_LOCATION",
        "vars.AZURE_VM_SIZE",
        "[[ \"$AZURE_LOCATION\" =~ ^[a-z0-9-]+$ ]]",
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
        "environment: ubuntu2604-release",
        "name: ubuntu2404-confidential-candidate-${{ needs.prepare.outputs.source_commit }}-${{ github.run_attempt }}",
        "install-miz install-ubuntu2404-confidential-release",
        "id: azure_login",
        "scripts/ubuntu2404_confidential_azure_acceptance.sh run",
        "- name: Refresh Azure OIDC credential for unconditional cleanup\n        if: always() && steps.azure_login.outcome == 'success'",
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
        "environment: ubuntu2604-release",
        "contents: write",
        "Download exact build candidate and provenance",
        "Download exact protected acceptance result",
        "- name: Stage and verify release bundle (validation-only)",
        "VALIDATION_ONLY: ${{ inputs.validation_only && 'true' || 'false' }}",
        "if: inputs.validation_only != true",
        "scripts/ubuntu2404_confidential_publish.sh",
    }) |needle| try expectContains(publish, needle);
    for ([_][]const u8{
        "[[ \"$AZURE_LOCATION\" =~ ^[a-z0-9-]+$ ]]",
        "VALIDATION_ONLY=${VALIDATION_ONLY:-false}",
        "if [[ \"$VALIDATION_ONLY\" == true ]]; then",
        "### Ubuntu 24.04 Confidential VM release bundle verified (validation-only)",
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

test "publisher supports both validation_only and normal publication" {
    try runShellFixture(std.testing.allocator, "publisher-validation-and-publish-fixture.sh",
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\mkdir -p bin input scripts/release
        \\printf 'qcow-bytes' >input/Ubuntu-24.04-x86_64.confidential.qcow2
        \\printf '{"schema":1}' >input/Ubuntu-24.04-x86_64.confidential.qcow2.provenance.json
        \\printf '{"accepted":true}' >input/azure-result.json
        \\qcow_sha=$(sha256sum input/Ubuntu-24.04-x86_64.confidential.qcow2 | awk '{print $1}')
        \\qcow_size=$(stat --format='%s' input/Ubuntu-24.04-x86_64.confidential.qcow2)
        \\export MOCK_QCOW_SHA="$qcow_sha"
        \\export MOCK_QCOW_SIZE="$qcow_size"
        \\cat >bin/release_tool <<'EOF'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\cmd=${1:?}
        \\shift
        \\case "$cmd" in
        \\  verify-acceptance)
        \\    printf '%s\n%s\n%s\n' "$MOCK_QCOW_SHA" "$MOCK_QCOW_SIZE" 32212254720
        \\    ;;
        \\  check-release-metadata|check-release-policy)
        \\    ;;
        \\  check-draft-assets)
        \\    mode=
        \\    while (($#)); do
        \\      if [[ "$1" == "--mode" ]]; then
        \\        mode=$2
        \\        shift 2
        \\      else
        \\        shift
        \\      fi
        \\    done
        \\    if [[ "$mode" == asset ]]; then
        \\      printf 'upload\n'
        \\    fi
        \\    ;;
        \\  *)
        \\    exit 99
        \\    ;;
        \\esac
        \\EOF
        \\chmod +x bin/release_tool
        \\cat >scripts/release/check_repository_release_policy.sh <<'POLICY'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\printf 'policy:%s:%s\n' "$1" "${GH_TOKEN:-}" >>"$CALL_LOG"
        \\POLICY
        \\chmod +x scripts/release/check_repository_release_policy.sh
        \\cat >bin/git <<'GIT'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\printf 'git:%s\n' "$*" >>"$CALL_LOG"
        \\if [[ "$*" == *"^{}"* ]]; then
        \\  exit 0
        \\fi
        \\printf '%s\trefs/tags/%s\n' "$SOURCE_COMMIT" "$RELEASE_TAG"
        \\GIT
        \\chmod +x bin/git
        \\cat >bin/gh <<'GH'
        \\#!/usr/bin/env bash
        \\set -euo pipefail
        \\printf 'gh:%s\n' "$*" >>"$CALL_LOG"
        \\if [[ "$1" == release && "$2" == view ]]; then
        \\  if [[ "$*" == *isDraft* ]]; then
        \\    exit 1
        \\  fi
        \\  printf '42\n'
        \\  exit 0
        \\fi
        \\if [[ "$1" == release && "$2" == create ]]; then
        \\  exit 0
        \\fi
        \\if [[ "$1" == release && "$2" == download ]]; then
        \\  dir=
        \\  while (($#)); do
        \\    if [[ "$1" == "--dir" ]]; then
        \\      dir=$2
        \\      shift 2
        \\    else
        \\      shift
        \\    fi
        \\  done
        \\  cp "$STAGING_ROOT"/assets/* "$dir/"
        \\  exit 0
        \\fi
        \\if [[ "$1" == api ]]; then
        \\  printf '{"id":42}\n'
        \\  exit 0
        \\fi
        \\exit 98
        \\GH
        \\chmod +x bin/gh
        \\export PATH="$PWD/bin:$PATH"
        \\export CANDIDATE="$PWD/input/Ubuntu-24.04-x86_64.confidential.qcow2"
        \\export PROVENANCE="$PWD/input/Ubuntu-24.04-x86_64.confidential.qcow2.provenance.json"
        \\export ACCEPTANCE_RESULT="$PWD/input/azure-result.json"
        \\export SOURCE_COMMIT=0123456789abcdef0123456789abcdef01234567
        \\export AZURE_LOCATION=swedencentral
        \\export AZURE_VM_SIZE=Standard_DC2as_v5
        \\export RELEASE_TAG=Ubuntu-24.04-confidential-20260907
        \\export RELEASE_TITLE='Ubuntu 24.04 Confidential VM - 20260907'
        \\export REPOSITORY=cataggar/miz
        \\export GITHUB_RUN_ID=12345
        \\export GITHUB_RUN_ATTEMPT=1
        \\export UBUNTU2404_CONFIDENTIAL_RELEASE_TOOL="$PWD/bin/release_tool"
        \\publisher="$MIZ_UBUNTU2404_CONFIDENTIAL_ROOT/scripts/ubuntu2404_confidential_publish.sh"
        \\
        \\export STAGING_ROOT="$PWD/staging-validation"
        \\export GITHUB_STEP_SUMMARY="$PWD/summary-validation.md"
        \\export CALL_LOG="$PWD/calls-validation.log"
        \\: >"$CALL_LOG"
        \\: >"$GITHUB_STEP_SUMMARY"
        \\if VALIDATION_ONLY=invalid "$publisher" >/dev/null 2>&1; then
        \\  exit 90
        \\fi
        \\VALIDATION_ONLY=true "$publisher"
        \\test ! -s "$CALL_LOG"
        \\test "$(wc -l <"$STAGING_ROOT/expected.tsv")" -eq 3
        \\test -s "$STAGING_ROOT/release-notes.md"
        \\grep -F '### Ubuntu 24.04 Confidential VM release bundle verified (validation-only)' "$GITHUB_STEP_SUMMARY" >/dev/null
        \\grep -F 'Validation-only run completed; no GitHub release or tag was mutated.' "$GITHUB_STEP_SUMMARY" >/dev/null
        \\
        \\export STAGING_ROOT="$PWD/staging-publish"
        \\export GITHUB_STEP_SUMMARY="$PWD/summary-publish.md"
        \\export CALL_LOG="$PWD/calls-publish.log"
        \\: >"$CALL_LOG"
        \\: >"$GITHUB_STEP_SUMMARY"
        \\RELEASE_POLICY_GH_TOKEN=policy-tok GH_TOKEN=pub-tok VALIDATION_ONLY=false "$publisher"
        \\grep -F 'policy:' "$CALL_LOG" >/dev/null
        \\grep -F 'gh:release create' "$CALL_LOG" >/dev/null
        \\grep -F '### Ubuntu 24.04 Confidential VM release published' "$GITHUB_STEP_SUMMARY" >/dev/null
        \\
    );
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
        "`repo:cataggar/miz:environment:ubuntu2604-release`",
        "`AZURE_CLIENT_ID`",
        "`AZURE_TENANT_ID`",
        "`AZURE_SUBSCRIPTION_ID`",
        "validation_only=true",
    }) |needle| try expectContains(guide, needle);
}
