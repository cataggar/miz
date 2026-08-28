//! Workflow, shell, and documentation contracts of the Azure Linux 4 release.
//!
//! Replaces the half of `tests/azurelinux4_release_test.py` whose subject is
//! not a function but a tracked file: the release workflow's job graph and
//! artifact naming, the acceptance and publication shell, the pinned
//! dependency manifest, and the guides that describe what the release
//! publishes.
//!
//! These checks exist because the release path cannot be exercised in CI. A
//! four-hour protected-environment run against real Azure is the only way to
//! find out that a workflow lost its OIDC permissions or that the publisher
//! stopped verifying downloads -- unless something reads the files and says
//! so first. That is what this does.
//!
//! The business contracts these files call into are tested where they live:
//! `scripts/azurelinux4/*.zig` for the release tool, `scripts/azure_vhd.zig`
//! for VHD geometry, and `scripts/release/*.zig` for the shared foundation.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

/// No tracked file this reads is anywhere near this size.
const max_file_bytes = 4 * 1024 * 1024;

const workflow_path = ".github/workflows/azurelinux4-release.yml";
const ci_workflow_path = ".github/workflows/ci.yml";
const acceptance_path = "scripts/azurelinux4_azure_acceptance.sh";
const publish_path = "scripts/azurelinux4_publish.sh";
const runner_probe_path = "scripts/check_azurelinux4_release_runner.sh";
const azure_module_path = "scripts/azurelinux4/azure.zig";
const commands_module_path = "scripts/azurelinux4/commands.zig";

/// The tree to read. `build.zig` names the build root outright, so the checks
/// do not depend on which directory the test binary was started in, matching
/// the stale brand guard and the Python inventory next to it.
fn repositoryRootAlloc(allocator: Allocator) ![]u8 {
    return std.testing.environ.getAlloc(
        allocator,
        "MIZ_AZURELINUX4_CONTRACT_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => allocator.dupe(u8, "."),
        else => return err,
    };
}

fn readTracked(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    const full = try std.fs.path.join(allocator, &.{ root, path });
    defer allocator.free(full);
    return Dir.cwd().readFileAlloc(io, full, allocator, .limited(max_file_bytes));
}

fn expectContains(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) != null) return;
    std.debug.print("\nmissing required text:\n{s}\n", .{needle});
    return error.RequiredTextMissing;
}

fn expectAbsent(text: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, text, needle) == null) return;
    std.debug.print("\nforbidden text is present:\n{s}\n", .{needle});
    return error.ForbiddenTextPresent;
}

fn count(text: []const u8, needle: []const u8) usize {
    if (needle.len == 0) return 0;
    var found: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, text, index, needle)) |at| {
        found += 1;
        index = at + needle.len;
    }
    return found;
}

fn expectCount(text: []const u8, needle: []const u8, expected: usize) !void {
    const actual = count(text, needle);
    if (actual == expected) return;
    std.debug.print(
        "\nexpected {d} occurrence(s) of:\n{s}\nfound {d}\n",
        .{ expected, needle, actual },
    );
    return error.UnexpectedOccurrenceCount;
}

/// Everything after `start`, which is how the Python read one section out of
/// a document.
fn sectionToEnd(text: []const u8, start: []const u8) ![]const u8 {
    const begin = std.mem.indexOf(u8, text, start) orelse return error.SectionMissing;
    return text[begin + start.len ..];
}

/// The slice of `text` between `start` and the following `end`, which is how
/// the Python read one job out of a workflow.
fn section(text: []const u8, start: []const u8, end: []const u8) ![]const u8 {
    const body = try sectionToEnd(text, start);
    const finish = std.mem.indexOf(u8, body, end) orelse body.len;
    return body[0..finish];
}

fn lines(text: []const u8) std.mem.SplitIterator(u8, .scalar) {
    return std.mem.splitScalar(u8, text, '\n');
}

fn trimmed(line: []const u8) []const u8 {
    return std.mem.trim(u8, std.mem.trimEnd(u8, line, "\r"), " \t");
}

// ---------------------------------------------------------------------------
// Release workflow
// ---------------------------------------------------------------------------

test "release artifacts use visible, attempt-bound staging" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);

    // Staging directories are visible: an artifact upload cannot pick up a
    // path whose components a shell glob would skip.
    var staging: usize = 0;
    var iterator = lines(workflow);
    while (iterator.next()) |raw| {
        const line = trimmed(raw);
        for ([_][]const u8{ "BUNDLE_DIR:", "RESULT_DIR:" }) |name| {
            if (!std.mem.startsWith(u8, line, name)) continue;
            staging += 1;
            const value = std.mem.trim(u8, line[name.len..], " \t");
            var components = std.mem.splitScalar(u8, value, '/');
            while (components.next()) |component| {
                try std.testing.expect(component.len == 0 or component[0] != '.');
            }
        }
    }
    try std.testing.expectEqual(@as(usize, 2), staging);

    // Every artifact reference is bound to the accepted source commit, and to
    // the attempt of the run that produced it.
    var references: usize = 0;
    var candidates: usize = 0;
    var azure_results: usize = 0;
    iterator = lines(workflow);
    while (iterator.next()) |raw| {
        const line = trimmed(raw);
        const is_reference = (std.mem.startsWith(u8, line, "name: azurelinux4-") or
            std.mem.startsWith(u8, line, "pattern: azurelinux4-")) and
            (std.mem.indexOf(u8, line, "azurelinux4-candidate-") != null or
                std.mem.indexOf(u8, line, "azurelinux4-azure-") != null);
        if (!is_reference) continue;
        references += 1;
        try expectContains(line, "${{ needs.prepare.outputs.source_commit }}");
        if (std.mem.indexOf(u8, line, "azurelinux4-candidate-") != null) {
            candidates += 1;
            if (std.mem.indexOf(u8, line, "${{ matrix.key }}") == null) {
                try expectContains(
                    line,
                    "${{ needs.prepare.outputs.candidate_run_attempt }}",
                );
            }
        } else {
            azure_results += 1;
            try expectContains(line, "${{ github.run_attempt }}");
        }
    }
    try std.testing.expectEqual(@as(usize, 6), references);
    try std.testing.expectEqual(@as(usize, 3), candidates);
    try std.testing.expectEqual(@as(usize, 3), azure_results);
}

test "release reuse is bound to completed, successful candidates" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);

    try expectContains(workflow, "candidate_run_id:");
    try expectContains(workflow, "test \"$(jq -r .status <<<\"$run\")\" = completed");
    try expectContains(workflow, ".conclusion == \"success\"");
    try expectContains(workflow, ".expired == false");
    try expectContains(
        workflow,
        "test \"$(git ls-remote origin \"refs/tags/$RELEASE_TAG\"",
    );
    try expectCount(
        workflow,
        "run-id: ${{ needs.prepare.outputs.candidate_run_id }}",
        2,
    );
}

test "azure acceptance uses protected-environment OIDC and keeps no secret" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);
    const acceptance = try section(workflow, "  azure_acceptance:", "\n  publish:");

    try expectContains(acceptance, "id-token: write");
    try expectCount(acceptance, "client-id: ${{ secrets.AZURE_CLIENT_ID }}", 2);
    try expectCount(acceptance, "tenant-id: ${{ secrets.AZURE_TENANT_ID }}", 2);
    try expectCount(
        acceptance,
        "subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}",
        2,
    );
    try expectAbsent(acceptance, "clientSecret");
    try expectAbsent(acceptance, "AZURE_CLIENT_SECRET");
    try expectContains(acceptance, "Upload failed Azure acceptance diagnostics");
    try expectAbsent(acceptance, "AZURE_CORE_OUTPUT");

    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);
    try expectContains(script, "set -Eeuo pipefail");
    try expectContains(script, "Azure acceptance failed at line");
    try expectContains(script, "guest acceptance failed at line");
    try expectContains(script, "sshd_config=$(sudo -n /usr/sbin/sshd -T)");
    try expectAbsent(script, "/usr/sbin/sshd -T | grep");
    try expectContains(script, "az vm boot-diagnostics get-boot-log");
    try expectAbsent(script, "az disk grant-access");
    try expectContains(script, "/beginGetAccess?api-version=2025-01-02");
    try expectContains(script, "tolower($1) == \"location\"");
    try expectContains(
        script,
        "\"$release_tool\" disk-access-sas --response \"$response_body\"",
    );
    try std.testing.expect(count(script, "--output json >/dev/null") >= 9);
    try expectContains(script, "gallery-version-create-response.json");
    try expectContains(script, "check-gallery-accepted");
    try expectContains(script, "check-gallery-final");

    // The contracts those subcommands enforce, in the module that now owns
    // them and tests them directly.
    const azure_module = try readTracked(allocator, std.testing.io, azure_module_path);
    defer allocator.free(azure_module);
    try expectContains(azure_module, "\"accessSAS\"");
    try expectContains(azure_module, "\"accessSas\"");
    try expectContains(
        azure_module,
        "Azure did not accept the exact custom UEFI settings",
    );
    try expectContains(azure_module, "boot validation remains authoritative");
}

test "azure acceptance uses the current harness with the accepted-source tool" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);
    const acceptance = try section(workflow, "  azure_acceptance:", "\n  publish:");

    try expectContains(acceptance, "name: Check out acceptance harness");
    try expectContains(acceptance, "ref: ${{ github.sha }}");
    try expectContains(acceptance, "path: release-source");
    try expectContains(acceptance, "working-directory: release-source");
    try expectAbsent(acceptance, "vendor/zig-bzip2");
    try expectAbsent(acceptance, "--build-file");
    try expectContains(
        acceptance,
        "MIZ: ${{ github.workspace }}/release-source/zig-out/bin/miz",
    );

    const manifest = try readTracked(allocator, std.testing.io, "build.zig.zon");
    defer allocator.free(manifest);
    try expectContains(
        manifest,
        "git+https://github.com/cataggar/bzip2z" ++
            "#05f6d4e34df2da2729490aee2a5bbe43b5ce94f6",
    );
    try expectContains(
        manifest,
        "bzip2z-0.1.0-m5NdlhNXCwC5mTHdg2pgMytHjahuQP6nImdle78Pb9kO",
    );
    try expectAbsent(manifest, "mirrors.kernel.org/sourceware/bzip2");

    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    const vendored = try std.fs.path.join(allocator, &.{ root, "vendor/zig-bzip2" });
    defer allocator.free(vendored);
    try std.testing.expectError(
        error.FileNotFound,
        Dir.cwd().statFile(std.testing.io, vendored, .{}),
    );
}

test "build manifest dependencies are git-pinned to a full commit" {
    const allocator = std.testing.allocator;
    const manifest = try readTracked(allocator, std.testing.io, "build.zig.zon");
    defer allocator.free(manifest);

    const names = [_][]const u8{ "bzip2z", "tls", "debz", "rpmz", "zstd" };
    try expectCount(manifest, ".url = \"git+https://", names.len);
    for (names) |name| {
        const declaration = try std.fmt.allocPrint(allocator, ".{s} = .{{", .{name});
        defer allocator.free(declaration);
        const body = try section(manifest, declaration, "},");
        const url = try section(body, ".url = \"", "\"");
        try std.testing.expect(std.mem.startsWith(u8, url, "git+https://"));
        const separator = std.mem.lastIndexOfScalar(u8, url, '#') orelse
            return error.DependencyIsNotPinned;
        const commit = url[separator + 1 ..];
        try std.testing.expectEqual(@as(usize, 40), commit.len);
        for (commit) |character| switch (character) {
            '0'...'9', 'a'...'f' => {},
            else => return error.DependencyIsNotPinned,
        };
        const hash = try section(body, ".hash = \"", "\"");
        const prefix = try std.fmt.allocPrint(allocator, "{s}-", .{name});
        defer allocator.free(prefix);
        try std.testing.expect(std.mem.startsWith(u8, hash, prefix));
    }
    try expectContains(
        manifest,
        "git+https://github.com/cataggar/zstd" ++
            "#45b6dfcd9d0ffdba99fb653c66b233179b9f7229",
    );

    const build = try readTracked(allocator, std.testing.io, "build.zig");
    defer allocator.free(build);
    const zstd_dependency = try section(build, "fn zstdDependency(", "\n}\n");
    try expectContains(zstd_dependency, ".tools = false");
    try expectContains(zstd_dependency, ".shared = false");
    try expectContains(zstd_dependency, ".multithread = false");
}

test "azure acceptance allows Arm64 without a temporary resource disk" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);
    try expectContains(script, "\"$release_tool\" check-vm-sku \\");
    try expectContains(script, "--architecture \"$expected_azure_architecture\"");
    try expectContains(script, "if mountpoint -q /d; then");
    try expectContains(script, "test \"$has_resource_disk\" = false");

    const azure_module = try readTracked(allocator, std.testing.io, azure_module_path);
    defer allocator.free(azure_module);
    try expectContains(azure_module, "\"Location\"");
    try expectContains(azure_module, "configured Azure VM SKU is location-restricted");
    try expectContains(azure_module, "TrustedLaunchDisabled");
    try expectContains(
        azure_module,
        "configured Azure VM SKU has no temporary resource disk",
    );
}

test "azure acceptance identifies the attached data disk by exact size" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);
    try expectContains(script, "data_disk_size_gib=4");
    try expectContains(
        script,
        "expected_data_disk_size=$((data_disk_size_gib * 1073741824))",
    );
    try expectContains(script, "blockdev --getsize64 \"/dev/$name\"");
    try expectContains(script, "\"$size\" -eq \"$expected_size\"");
    try expectAbsent(script, "test -z \"${first_sector//0/}\"");
    try expectAbsent(script, "/usr/sbin/mkfs.ext4");
    try expectAbsent(script, "/usr/sbin/partprobe");
    try expectAbsent(script, "MSFT NVMe Accelerator");
    try expectContains(
        script,
        "Azure managed boot diagnostics did not return a serial log",
    );
    try expectContains(
        script,
        "[[ -n \"$boot_id\" && \"$boot_id\" != \"$old_boot_id\" ]]",
    );
    try expectAbsent(script, "saw_disconnect");
}

test "fixed VHD validation is structural and bound to the derived size" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);
    try expectAbsent(script, "qemu-img check -f vpc");
    try expectContains(script, "qemu-img info -f vpc --output=json \"$vhd\"");
    try expectContains(script, "\"$release_tool\" verify-vhd \\");
    try expectContains(script, "vhd_current_size=${vhd_geometry[0]}");
    try expectContains(script, "test \"$vhd_bytes\" -eq \"$((vhd_current_size + 512))\"");
    try expectContains(
        script,
        "expanded_size_gib=$(((vhd_current_size + 1073741823) / 1073741824 + 2))",
    );
    try expectContains(script, "--vhd-current-size \"$vhd_current_size\"");
}

test "the publisher verifies drafts by release id" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, std.testing.io, publish_path);
    defer allocator.free(script);
    try expectContains(script, "--json databaseId");
    try expectContains(script, "release_api=\"repos/$REPOSITORY/releases/$release_id\"");
    try expectCount(script, "gh api \"$release_api\"", 3);
    try expectAbsent(script, "releases/tags/$RELEASE_TAG");
    // Every remote state check goes through the one tool that parses the
    // expected-asset table, in the order the publication requires.
    try expectContains(script, "\"$release_tool\" release-stale-assets \\");
    try expectContains(script, "--state draft");
    try expectContains(script, "\"$release_tool\" check-downloads \\");
    try expectContains(script, "--state published");
    const draft = std.mem.indexOf(u8, script, "--state draft").?;
    const downloads = std.mem.indexOf(u8, script, "check-downloads").?;
    const published = std.mem.indexOf(u8, script, "--state published").?;
    try std.testing.expect(draft < downloads);
    try std.testing.expect(downloads < published);
}

test "the release workflow uses hosted architecture runners" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);
    try expectAbsent(
        workflow,
        "scripts/check_azurelinux4_release_runner.sh \"$ARCHITECTURE\"",
    );
    try expectAbsent(workflow, "self-hosted");
    try expectCount(workflow, "runner: ubuntu-24.04\n", 2);
    try expectCount(workflow, "runner: ubuntu-24.04-arm\n", 2);
    try expectContains(workflow, "max-parallel: 2");
    try expectAbsent(workflow, "test-azurelinux4-acceptance");
    try expectContains(workflow, "scripts/azurelinux4_azure_acceptance.sh run");
}

test "the release workflow requires built-in signing and Secure Boot" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);

    try expectContains(workflow, "environment: azurelinux4-signing");
    try expectAbsent(workflow, "AZURELINUX4_UKI_SIGN_COMMAND");
    try expectContains(
        workflow,
        "UKI_SIGN_COMMAND: ${{ github.workspace }}/zig-out/bin/miz",
    );
    try expectContains(workflow, "zig build install-miz");
    try expectContains(workflow, "tests/efi_signing_probe.zig");
    try expectContains(workflow, "\"$UKI_SIGN_COMMAND\" sign");
    try expectContains(
        workflow,
        "actual=$(\"$UKI_SIGN_COMMAND\" uki fingerprint \"$certificate\")",
    );
    try expectContains(
        workflow,
        "\"$UKI_SIGN_COMMAND\" uki verify " ++
            "--certificate \"$UKI_SIGNING_CERTIFICATE\" \"$signed\"",
    );
    try expectContains(workflow, "Upload failed signing probe");
    try expectContains(
        workflow,
        "SIGNING_PROBE_DIR: ${{ github.workspace }}/signing-probe-",
    );
    try expectAbsent(workflow, "/.signing-probe-");
    try expectContains(workflow, "--uki-sign-command \"$UKI_SIGN_COMMAND\"");
    try expectContains(workflow, "--uki-sign-command-arg sign");
    for ([_][]const u8{
        "MIZ_AZURE_TENANT_ID",
        "MIZ_AZURE_CLIENT_ID",
        "MIZ_ARTIFACT_SIGNING_ENDPOINT",
        "MIZ_ARTIFACT_SIGNING_ACCOUNT",
        "MIZ_ARTIFACT_SIGNING_PROFILE",
    }) |name| try expectContains(workflow, name);
    try expectAbsent(workflow, "MIZ_AZURE_KEY_ID");
    try expectAbsent(workflow, "--uki-signing-key");
    // Signing, fingerprinting, Secure Boot verification, and UEFI variable
    // enrollment are all native; no external OpenSSL, sbsigntool, or
    // virt-firmware toolchain appears in the production release workflow.
    try expectAbsent(workflow, "sbsigntool");
    try expectAbsent(workflow, "sbverify");
    try expectAbsent(workflow, "openssl");
    try expectAbsent(workflow, "virt-firmware");
    try expectAbsent(workflow, "virt-fw-vars");

    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);
    try expectContains(script, "api-version=2025-03-03");
    try expectContains(script, "--security-type TrustedLaunch");
    try expectContains(script, "--enable-secure-boot true");
    try expectContains(script, "--enable-vtpm true");

    // The gallery request body is built by the release tool, which is where
    // the Microsoft template it must retain is now spelled.
    const azure_module = try readTracked(allocator, std.testing.io, azure_module_path);
    defer allocator.free(azure_module);
    try expectContains(azure_module, "gallery_signature_template");
    const contracts_module = try readTracked(
        allocator,
        std.testing.io,
        "scripts/azurelinux4/contracts.zig",
    );
    defer allocator.free(contracts_module);
    try expectContains(contracts_module, "MicrosoftUefiCertificateAuthorityTemplate");
}

test "resource-group state precedes create and cleanup is guarded" {
    const allocator = std.testing.allocator;
    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);

    const persist = std.mem.indexOf(
        u8,
        script,
        "printf '%s\\n' \"$resource_group\" >\"$STATE_FILE\"",
    ) orelse return error.RequiredTextMissing;
    const create = std.mem.indexOf(u8, script, "if ! az group create") orelse
        return error.RequiredTextMissing;
    try std.testing.expect(persist < create);
    try expectContains(
        script,
        "[[ \"$resource_group\" == \"$expected_resource_group\" ]]",
    );

    const guard = std.mem.indexOf(u8, script, "\"$release_tool\" check-group-tags") orelse
        return error.RequiredTextMissing;
    const delete = std.mem.indexOf(u8, script, "if ! az group delete") orelse
        return error.RequiredTextMissing;
    try std.testing.expect(guard < delete);
}

// ---------------------------------------------------------------------------
// The release tool the workflow and shell call
// ---------------------------------------------------------------------------

test "every job that calls the release tool builds and names it" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, workflow_path);
    defer allocator.free(workflow);

    // The build job, the acceptance job, and the publisher each build the
    // tool from their own checkout and point at it by absolute path.
    try expectCount(
        workflow,
        "AZURELINUX4_RELEASE: ${{ github.workspace }}/zig-out/bin/azurelinux4_release",
        3,
    );
    try expectCount(workflow, "zig build install-azurelinux4-release", 2);
    try expectContains(workflow, "zig build install-miz install-azurelinux4-release");
    try expectCount(workflow, "test -x \"$AZURELINUX4_RELEASE\"", 3);
    try expectContains(workflow, "\"$AZURELINUX4_RELEASE\" check-candidate-info \\");
    try expectContains(workflow, "\"$AZURELINUX4_RELEASE\" candidate \\");
    try expectContains(workflow, "\"$AZURELINUX4_RELEASE\" verify-candidate \\");

    // Both shell callers fail closed when the tool is absent rather than
    // falling back to anything.
    for ([_][]const u8{ acceptance_path, publish_path }) |path| {
        const script = try readTracked(allocator, std.testing.io, path);
        defer allocator.free(script);
        try expectContains(
            script,
            "release_tool=${AZURELINUX4_RELEASE:-zig-out/bin/azurelinux4_release}",
        );
        try expectContains(script, "[[ -x \"$release_tool\" ]]");
    }

    const script = try readTracked(allocator, std.testing.io, acceptance_path);
    defer allocator.free(script);
    try expectContains(
        script,
        "echo \"::error::Azure Linux release tool is unavailable during cleanup\"",
    );
}

/// Spelled in halves so this guard's own bytes carry no interpreter name:
/// `tests/python_inventory.zig` reads a quoted interpreter token as an
/// invocation site, and this file must not become one.
const interpreter = "py" ++ "thon";

test "no repository-owned Python remains in the Azure Linux release path" {
    const allocator = std.testing.allocator;
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);

    for ([_][]const u8{
        "scripts/azurelinux4_release.py",
        "tests/azurelinux4_release_test.py",
    }) |path| {
        const full = try std.fs.path.join(allocator, &.{ root, path });
        defer allocator.free(full);
        try std.testing.expectError(
            error.FileNotFound,
            Dir.cwd().statFile(std.testing.io, full, .{}),
        );
    }

    // Not one spelling survives anywhere on this path: the last of them was a
    // package name, and native UEFI variable enrollment removed that too.
    for ([_][]const u8{ workflow_path, acceptance_path, publish_path }) |path| {
        const text = try readTracked(allocator, std.testing.io, path);
        defer allocator.free(text);
        if (std.mem.indexOf(u8, text, interpreter)) |at| {
            std.debug.print("\n{s}: an interpreter survives at byte {d}\n", .{
                path,
                at,
            });
            return error.InterpreterSurvives;
        }
    }
}

test "every Azure Linux release shell script parses under bash" {
    const allocator = std.testing.allocator;
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);

    for ([_][]const u8{ acceptance_path, publish_path, runner_probe_path }) |path| {
        const full = try std.fs.path.join(allocator, &.{ root, path });
        defer allocator.free(full);
        const result = try std.process.run(allocator, std.testing.io, .{
            .argv = &.{ "bash", "-n", full },
            .stdout_limit = .limited(64 * 1024),
        });
        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);
        if (result.term != .exited or result.term.exited != 0) {
            std.debug.print("\n{s}: bash -n failed\n{s}\n", .{ path, result.stderr });
            return error.ShellSyntaxError;
        }
    }
}

test "the runner probe answers help and refuses an unknown architecture" {
    const allocator = std.testing.allocator;
    const root = try repositoryRootAlloc(allocator);
    defer allocator.free(root);
    const script = try std.fs.path.join(allocator, &.{ root, runner_probe_path });
    defer allocator.free(script);

    const help = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", script, "--help" },
        .stdout_limit = .limited(64 * 1024),
    });
    defer allocator.free(help.stdout);
    defer allocator.free(help.stderr);
    try std.testing.expectEqual(@as(u8, 0), help.term.exited);

    const unknown = try std.process.run(allocator, std.testing.io, .{
        .argv = &.{ "bash", script, "riscv64" },
        .stdout_limit = .limited(64 * 1024),
    });
    defer allocator.free(unknown.stdout);
    defer allocator.free(unknown.stderr);
    try std.testing.expectEqual(@as(u8, 2), unknown.term.exited);

    const text = try readTracked(allocator, std.testing.io, runner_probe_path);
    defer allocator.free(text);
    try expectContains(text, "timeout --signal=TERM --kill-after=2s 2s");
    try expectAbsent(text, "-daemonize");
    try expectAbsent(text, "-pidfile");
}

// ---------------------------------------------------------------------------
// CI workflow
// ---------------------------------------------------------------------------

test "CI actions are pinned to audited commits" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, ci_workflow_path);
    defer allocator.free(workflow);

    const allowed = [_][]const u8{
        "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5 # v4",
        "cataggar/ghr/actions/install@" ++
            "7d8c3ef0886dd428a97727fce3b74909d6eace78 # v0.6.6",
        "actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830 # v4",
    };
    var found: usize = 0;
    var iterator = lines(workflow);
    while (iterator.next()) |raw| {
        const line = trimmed(raw);
        const body = if (std.mem.startsWith(u8, line, "- uses:"))
            std.mem.trim(u8, line["- uses:".len..], " \t")
        else if (std.mem.startsWith(u8, line, "uses:"))
            std.mem.trim(u8, line["uses:".len..], " \t")
        else
            continue;
        found += 1;
        var matched = false;
        for (allowed) |candidate| {
            if (std.mem.eql(u8, body, candidate)) matched = true;
        }
        if (!matched) {
            std.debug.print("\nunpinned or unaudited action: {s}\n", .{body});
            return error.UnauditedAction;
        }
    }
    try std.testing.expectEqual(@as(usize, 13), found);
}

test "CI heavy phases are independent jobs" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, ci_workflow_path);
    defer allocator.free(workflow);

    for ([_][]const u8{
        "quality",
        "zig-tests",
        "vm-backend",
        "windows",
        "unsafe-chroot",
        "vm-boot",
    }) |job| {
        const heading = try std.fmt.allocPrint(allocator, "  {s}:\n", .{job});
        defer allocator.free(heading);
        try expectContains(workflow, heading);
    }
    try expectAbsent(workflow, "\n    needs:");
    try expectCount(workflow, "fail-fast: false", 2);
    try expectCount(workflow, "name: build + test", 1);
    try expectContains(
        workflow,
        "grep -n 'std\\.process\\.spawn' packages/miz/src/package_family.zig",
    );
    try expectContains(
        workflow,
        "zig build check-ci-production-entrypoints test-package-family test-ci \\\n" ++
            "            -Doptimize=Debug --summary all",
    );
    try expectAbsent(workflow, "run: zig build -Doptimize=Debug");
    try expectCount(workflow, "zig build test-ci", 0);
    try expectCount(
        workflow,
        "run: zig build test-vm-backend -Doptimize=Debug --summary all",
        1,
    );
    try expectCount(
        workflow,
        "run: zig build test-device-write-integration -Doptimize=Debug --summary all",
        1,
    );
    try expectCount(
        workflow,
        "run: zig build test-unsafe-chroot-integration -Doptimize=Debug --summary all",
        1,
    );
    try expectCount(workflow, "zig build test-vm-real-boot", 3);
    try expectCount(workflow, "-Doptimize=${{ matrix.optimize }} --summary all", 3);
    try expectCount(workflow, "optimize: Debug", 2);
    try expectCount(workflow, "optimize: ReleaseSafe", 1);
    try expectContains(workflow, "cancel-in-progress: true");
}

test "CI no longer runs an Azure Linux Python suite" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(allocator, std.testing.io, ci_workflow_path);
    defer allocator.free(workflow);
    try expectAbsent(workflow, "azurelinux4_release_test");
    try expectAbsent(workflow, "Azure Linux release workflow unit tests");
}

// ---------------------------------------------------------------------------
// Documentation
// ---------------------------------------------------------------------------

test "the QEMU guide distinguishes default full and core output" {
    const allocator = std.testing.allocator;
    const guide = try readTracked(allocator, std.testing.io, "doc/qemu.md");
    defer allocator.free(guide);
    const body = try sectionToEnd(guide, "## Booting the release image with QEMU");
    try expectContains(body, "full image's systemd startup and login prompt");
    try expectContains(
        body,
        "only when a core image is selected with `--model core` or\nan explicit " ++
            "`*.core.qcow2` path",
    );
    try expectAbsent(
        body,
        "default secure command line, a successful local boot reaches\n" ++
            "the PID 1 readiness marker",
    );
}

test "the Azure Linux guide distinguishes full and core images" {
    const allocator = std.testing.allocator;
    const guide = try readTracked(allocator, std.testing.io, "doc/azure-linux.md");
    defer allocator.free(guide);
    try expectContains(guide, "| PID 1 | systemd | `mizinit` |");
    try expectContains(guide, "| Default virtual size | 5 GiB | 1184 MiB |");
    try expectContains(guide, "released Azure core images use `mizinit.mode=persistent`");
    try expectContains(
        guide,
        "| Azure extensions | Standard WALinuxAgent extension support | " ++
            "No general WALinuxAgent extension stack |",
    );
}

test "the Azure Linux guide names the release tool the workflow runs" {
    const allocator = std.testing.allocator;
    const guide = try readTracked(allocator, std.testing.io, "doc/azure-linux.md");
    defer allocator.free(guide);
    try expectContains(guide, "zig build install-azurelinux4-release");
    try expectContains(guide, "zig-out/bin/azurelinux4_release");
    try expectContains(guide, "zig build test-azurelinux4-release");
}

test "the root README is a short documentation landing page" {
    const allocator = std.testing.allocator;
    const readme = try readTracked(allocator, std.testing.io, "README.md");
    defer allocator.free(readme);

    var headings: usize = 0;
    var total: usize = 0;
    const expected = [_][]const u8{ "# miz", "## Install", "## Documentation" };
    var iterator = lines(readme);
    while (iterator.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        total += 1;
        if (!std.mem.startsWith(u8, line, "#")) continue;
        try std.testing.expect(headings < expected.len);
        try std.testing.expectEqualStrings(expected[headings], line);
        headings += 1;
    }
    try std.testing.expectEqual(expected.len, headings);
    // `splitScalar` reports a trailing element after the final newline, which
    // Python's `splitlines()` does not.
    try std.testing.expect(total - 1 < 60);
    try expectContains(readme, "[Documentation index](doc/readme.md)");
}

test "getting started documents linked zstd requirements" {
    const allocator = std.testing.allocator;
    const guide = try readTracked(allocator, std.testing.io, "doc/getting-started.md");
    defer allocator.free(guide);
    try expectContains(guide, "`zig build` compiles the pinned static libzstd dependency");
    try expectContains(guide, "`zig build test` additionally requires the `zstd` CLI");
    try expectContains(guide, "no system libzstd development package is needed");
    try expectContains(guide, "sudo apt-get install -y --no-install-recommends zstd");
}

test "zstd docs and comments avoid private-subset wording" {
    const allocator = std.testing.allocator;
    const development = try readTracked(allocator, std.testing.io, "doc/development.md");
    defer allocator.free(development);
    try expectContains(
        development,
        "zstd.zig               # zstd support shared by COSI, SquashFS,",
    );
    try expectContains(development, "and streaming raw.zst output");
    try expectAbsent(development, "minimal private raw-block zstd codec");

    const package_family = try readTracked(
        allocator,
        std.testing.io,
        "doc/debian-package-family.md",
    );
    defer allocator.free(package_family);
    try expectContains(package_family, "pinned static\nlibzstd dependency");
    try expectContains(package_family, "debz's\nliblzma/libzstd dependencies");

    const cosi = try readTracked(allocator, std.testing.io, "packages/miz/src/cosi.zig");
    defer allocator.free(cosi);
    try expectContains(cosi, "standard `.raw.zst` members");
    try expectAbsent(cosi, "small built-in encoder");

    const output = try readTracked(
        allocator,
        std.testing.io,
        "packages/miz/src/output.zig",
    );
    defer allocator.free(output);
    try expectContains(output, "`zstd` emits a standard");
    try expectAbsent(output, "in-tree\n/// encoder");
    try expectAbsent(output, "much smaller encoder");
}

test "the development guide records the release tooling layout" {
    const allocator = std.testing.allocator;
    const development = try readTracked(allocator, std.testing.io, "doc/development.md");
    defer allocator.free(development);
    try expectContains(development, "azurelinux4_release.zig");
    try expectContains(development, "azurelinux4/");
}

test "the CLI release packages documentation" {
    const allocator = std.testing.allocator;
    const workflow = try readTracked(
        allocator,
        std.testing.io,
        ".github/workflows/release.yml",
    );
    defer allocator.free(workflow);
    try expectContains(workflow, "test -f doc/readme.md");
    try expectContains(workflow, "cp -R doc \"$package/\"");
}

test "the staging transaction and its rollback are documented where they run" {
    const allocator = std.testing.allocator;
    const module = try readTracked(allocator, std.testing.io, commands_module_path);
    defer allocator.free(module);
    try expectContains(module, "StagingTransaction");
    try expectContains(module, "fn rollback(");
}
