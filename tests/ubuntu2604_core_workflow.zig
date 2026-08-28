//! Guards for `.github/workflows/ubuntu2604-core-validation.yml`.
//!
//! The core-validation workflow proves the appliance flavor end to end and
//! publishes nothing. Its safety is structural in the same way the release
//! workflow's is -- exact matrices, complete acceptance sets, least-privilege
//! permissions -- plus one thing the release workflow does not have: the
//! Android container smoke inputs, whose private identity must never reach a
//! workflow value. Replaces `tests/ubuntu2604_core_workflow_test.py`.

const std = @import("std");

const source = @import("ubuntu2604_source.zig");

const Source = source.Source;
const workflow_path = ".github/workflows/ubuntu2604-core-validation.yml";

fn open() !Source {
    return Source.open(std.testing.allocator, workflow_path);
}

fn job(workflow: *const Source, name: []const u8, following: ?[]const u8) ![]const u8 {
    var start_buffer: [64]u8 = undefined;
    const start = try std.fmt.bufPrint(&start_buffer, "\n  {s}:\n", .{name});
    if (following) |next| {
        var end_buffer: [64]u8 = undefined;
        const end = try std.fmt.bufPrint(&end_buffer, "\n  {s}:\n", .{next});
        return workflow.section(start, end);
    }
    return workflow.section(start, null);
}

test "only the exact core keys and assets are accepted" {
    var workflow = try open();
    defer workflow.deinit();

    const boundaries = [_][2][]const u8{
        .{ "build", "native_qemu" },
        .{ "native_qemu", "azure_acceptance" },
        .{ "azure_acceptance", "validate" },
    };
    for (boundaries) |boundary| {
        const section = try job(&workflow, boundary[0], boundary[1]);
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, section, "- key: x86_64-core"),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, section, "- key: aarch64-core"),
        );
        try source.expectOmitsIn(section, "- key: x86_64-full", boundary[0]);
        try source.expectOmitsIn(section, "- key: aarch64-full", boundary[0]);
        try source.expectContainsIn(
            section,
            "asset_name: Ubuntu-26.04-x86_64.core.qcow2",
            boundary[0],
        );
        try source.expectContainsIn(
            section,
            "asset_name: Ubuntu-26.04-aarch64.core.qcow2",
            boundary[0],
        );
    }

    // The gate's key/asset allowlist and its exactness diagnostics now live in
    // the release tooling, which the gate job runs against the downloaded set.
    const gate = try job(&workflow, "validate", null);
    try source.expectContainsIn(gate, "\"$RELEASE_TOOL\" core-gate", workflow_path);
    try source.expectContainsIn(gate, "--candidates \"$CANDIDATES_DIR\"", workflow_path);
    try source.expectContainsIn(
        gate,
        "--native-results \"$NATIVE_RESULTS_DIR\"",
        workflow_path,
    );
    try source.expectContainsIn(
        gate,
        "--azure-results \"$AZURE_RESULTS_DIR\"",
        workflow_path,
    );
    try source.expectContainsIn(
        gate,
        "--output \"$BUNDLE_DIR/validation.json\"",
        workflow_path,
    );
}

test "complete build and acceptance matrices are required" {
    var workflow = try open();
    defer workflow.deinit();
    const gate = try job(&workflow, "validate", null);
    try source.expectContainsIn(
        gate,
        "needs: [prepare, build, native_qemu, azure_acceptance]",
        workflow_path,
    );
    try source.expectContainsIn(gate, "needs.native_qemu.result == 'success'", workflow_path);
    try source.expectContainsIn(
        gate,
        "needs.azure_acceptance.result == 'success'",
        workflow_path,
    );
    try source.expectContainsIn(gate, "pattern: ubuntu2604-core-native-*", workflow_path);
    try source.expectContainsIn(gate, "pattern: ubuntu2604-core-azure-*", workflow_path);
}

test "the workflow is validation-only" {
    var workflow = try open();
    defer workflow.deinit();
    const forbidden = [_][]const u8{
        "\n  publish:\n",
        "scripts/ubuntu2604_publish.sh",
        "gh release",
        "RELEASE_TAG",
        "refs/tags/",
        "contents: write",
        "release create",
        "release upload",
    };
    for (forbidden) |needle| try workflow.expectOmits(needle);
}

test "candidate reuse is bound to the exact source, run, and attempt" {
    var workflow = try open();
    defer workflow.deinit();
    const prepare = try job(&workflow, "prepare", "build");
    try source.expectContainsIn(
        prepare,
        ".path <<<\"$run\")\" = \".github/workflows/ubuntu2604-core-validation.yml\"",
        workflow_path,
    );
    try source.expectContainsIn(prepare, "/attempts/$candidate_run_attempt/jobs", workflow_path);
    try source.expectContainsIn(prepare, "jq --arg name \"build/native $key\"", workflow_path);
    try source.expectContainsIn(
        prepare,
        "ubuntu2604-core-candidate-$key-$commit-$candidate_run_attempt",
        workflow_path,
    );
    try source.expectContainsIn(prepare, ".expired == false and .size_in_bytes > 0", workflow_path);
    try source.expectContainsIn(prepare, "git ls-remote origin \"refs/heads/main\"", workflow_path);

    const gate = try job(&workflow, "validate", null);
    try source.expectContainsIn(gate, "--candidate-run-id \"$CANDIDATE_RUN_ID\"", workflow_path);
    try source.expectContainsIn(
        gate,
        "--candidate-run-attempt \"$CANDIDATE_RUN_ATTEMPT\"",
        workflow_path,
    );
    try source.expectContainsIn(gate, "--run-id \"$RUN_ID_VALUE\"", workflow_path);
    try source.expectContainsIn(gate, "--run-attempt \"$RUN_ATTEMPT_VALUE\"", workflow_path);
}

test "permissions and protected environments are least privilege" {
    var workflow = try open();
    defer workflow.deinit();
    const header = try workflow.section("", "\njobs:\n");
    try source.expectContainsIn(
        header,
        "permissions:\n  actions: read\n  contents: read",
        workflow_path,
    );
    try workflow.expectCount("environment: ubuntu2604-signing", 1);
    try workflow.expectCount("environment: ubuntu2604-release", 1);
    try workflow.expectCount("id-token: write", 2);
    try workflow.expectOmits("packages: write");
    try workflow.expectOmits("security-events: write");
    try workflow.expectContains("repo:cataggar/miz:environment:ubuntu2604-signing");
    try workflow.expectContains("repo:cataggar/miz:environment:ubuntu2604-release");
}

test "core build and acceptance contracts are explicit" {
    var workflow = try open();
    defer workflow.deinit();

    const build = try job(&workflow, "build", "native_qemu");
    try source.expectContainsIn(build, "FLAVOR: core", workflow_path);
    try source.expectContainsIn(build, "VIRTUAL_SIZE: 3758096384", workflow_path);
    try source.expectContainsIn(build, "-Dubuntu2604-flavor=\"$FLAVOR\"", workflow_path);
    try source.expectContainsIn(build, "--virtual-size-label \"3584 MiB\"", workflow_path);
    if (source.findForbiddenProductionTool(build)) |match| {
        std.debug.print("{s}: build job uses {s}\n", .{ workflow_path, match });
        return error.ForbiddenText;
    }

    const native = try job(&workflow, "native_qemu", "azure_acceptance");
    const native_needles = [_][]const u8{
        "-Dubuntu2604-flavor=\"$FLAVOR\"",
        "runner: ubuntu-24.04",
        "runner: [self-hosted, Linux, ARM64, kvm]",
        "if [[ ! -c /dev/kvm ]]",
        "sudo -n chown \"$(id -u):$(id -g)\" /dev/kvm",
        "test -r /dev/kvm",
        "test -w /dev/kvm",
        // The stable KVM ABI check is a release-tooling subcommand now, run
        // once the accepted-source tooling exists.
        "\"$RELEASE_TOOL\" kvm-api-version",
        "qemu-efi-aarch64 qemu-system-arm",
        "qemu=qemu-system-aarch64",
        "/usr/share/AAVMF/AAVMF_CODE.ms.fd",
        "/usr/share/AAVMF/AAVMF_VARS.ms.fd",
        "MIZ_UBUNTU2604_UEFI_CODE=",
        "MIZ_UBUNTU2604_UEFI_VARS=",
        "test -f \"$uefi_code\"",
        "test -f \"$uefi_vars\"",
        "verify-native-result",
    };
    for (native_needles) |needle| try source.expectContainsIn(native, needle, workflow_path);
    for ([_][]const u8{ "force_tcg", "accel=tcg", "MIZ_VM_ACCEL=software" }) |needle| {
        try source.expectOmitsIn(native, needle, workflow_path);
    }
    const capability_start = try source.indexOfIn(
        native,
        "- name: Require matching native KVM runner",
        workflow_path,
    );
    const capability_end = try source.indexOfIn(
        native,
        "- name: Check out accepted source",
        workflow_path,
    );
    const capability = native[capability_start..capability_end];
    try source.expectContainsIn(
        capability,
        "test \"$(uname -m)\" = \"$expected_uname\"",
        workflow_path,
    );
    try source.expectContainsIn(
        capability,
        "test \"$(dpkg --print-architecture)\" = \"$expected_deb\"",
        workflow_path,
    );
    try source.expectOrder(
        native,
        "sudo apt-get install -y --no-install-recommends \"${packages[@]}\"",
        "uefi_code=$(readlink -f -- \"$uefi_code\")",
        workflow_path,
    );
    try source.expectOrder(
        native,
        "uefi_code=$(readlink -f -- \"$uefi_code\")",
        "echo \"MIZ_UBUNTU2604_UEFI_CODE=$uefi_code\"",
        workflow_path,
    );
    try source.expectOrder(
        native,
        "uefi_vars=$(readlink -f -- \"$uefi_vars\")",
        "echo \"MIZ_UBUNTU2604_UEFI_CODE=$uefi_code\"",
        workflow_path,
    );
    // The KVM ABI check depends on the accepted-source tooling, so it may not
    // precede the build that produces it.
    try source.expectOrder(
        native,
        "- name: Build accepted-source release tooling",
        "- name: Require the stable KVM API version",
        workflow_path,
    );

    const azure = try job(&workflow, "azure_acceptance", "validate");
    try source.expectContainsIn(azure, "FLAVOR: core", workflow_path);
    try source.expectContainsIn(azure, "ubuntu2604_azure_acceptance.sh run", workflow_path);
    try source.expectOrder(
        azure,
        "- name: Build accepted-source miz",
        "- name: Fetch and verify digest-bound Android container smoke inputs",
        workflow_path,
    );
    try source.expectOrder(
        azure,
        "- name: Fetch and verify digest-bound Android container smoke inputs",
        "- name: Log in to Azure with protected-environment OIDC",
        workflow_path,
    );
    try source.expectOrder(
        azure,
        "- name: Log in to Azure with protected-environment OIDC",
        "- name: Run exact-digest Azure Trusted Launch core acceptance",
        workflow_path,
    );
}

test "the Binder probe is built for the matching guest architecture" {
    var workflow = try open();
    defer workflow.deinit();
    const azure = try job(&workflow, "azure_acceptance", "validate");
    try source.expectContainsIn(
        azure,
        "BINDER_PROBE: ${{ github.workspace }}/zig-out/bin/binder-probe-${{ matrix.key }}",
        workflow_path,
    );
    const probe_start = try source.indexOfIn(
        azure,
        "- name: Build Binder device usability probe",
        workflow_path,
    );
    const probe_end = try source.indexOfIn(azure, "- name: Run exact-digest", workflow_path);
    const build_probe = azure[probe_start..probe_end];
    const needles = [_][]const u8{
        "-target \"$ARCHITECTURE-linux\"",
        "-static",
        "tests/binder_probe.zig",
        "-femit-bin=\"$BINDER_PROBE\"",
        "test -x \"$BINDER_PROBE\"",
    };
    for (needles) |needle| try source.expectContainsIn(build_probe, needle, workflow_path);
    try source.expectOrder(
        azure,
        "Build Binder device usability probe",
        "Run exact-digest Azure Trusted Launch core acceptance",
        workflow_path,
    );
}

test "Android smoke inputs are architecture-specific and stay private" {
    var workflow = try open();
    defer workflow.deinit();

    const scopes = [_]struct {
        name: []const u8,
        following: []const u8,
        private_root: []const u8,
    }{
        .{
            .name = "native_qemu",
            .following = "azure_acceptance",
            .private_root = ".validation/native",
        },
        .{
            .name = "azure_acceptance",
            .following = "validate",
            .private_root = ".validation/azure",
        },
    };
    for (scopes) |scope| {
        const section = try job(&workflow, scope.name, scope.following);
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, section, "android_smoke_secret: ANDROID_SMOKE_X86_64_JSON"),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, section, "android_smoke_secret: ANDROID_SMOKE_AARCH64_JSON"),
        );
        const download_start = try source.indexOfIn(
            section,
            "- name: Fetch and verify digest-bound Android container smoke inputs",
            workflow_path,
        );
        const rest = section[download_start..];
        const download = rest[0 .. std.mem.indexOfPos(
            u8,
            rest,
            1,
            "\n      - name:",
        ) orelse rest.len];
        try source.expectContainsIn(
            download,
            "ANDROID_SMOKE_INPUT_VALUE: ${{ secrets[matrix.android_smoke_secret] }}",
            workflow_path,
        );
        try source.expectContainsIn(download, "set +x", workflow_path);
        try source.expectContainsIn(download, "prepare-android-smoke-inputs", workflow_path);
        try source.expectContainsIn(download, "--architecture \"$ARCHITECTURE\"", workflow_path);
        try source.expectContainsIn(download, scope.private_root, workflow_path);
        try source.expectOmitsIn(download, "$RESULT_DIR/android", workflow_path);
        const forbidden = [_][]const u8{
            "ANDROID_RUNTIME_SOURCE_COMMIT",
            "ANDROID_RUNTIME_URL",
            "ANDROID_BUNDLE_URL",
            "--oauth2-bearer",
        };
        for (forbidden) |needle| try source.expectOmitsIn(section, needle, scope.name);
    }
}

test "the core size contract is aligned across builder, acceptance, and workflow" {
    var workflow = try open();
    defer workflow.deinit();
    var builder = try Source.open(
        std.testing.allocator,
        "scripts/build_generalized_ubuntu2604.zig",
    );
    defer builder.deinit();
    var acceptance = try Source.open(
        std.testing.allocator,
        "tests/ubuntu2604_acceptance.zig",
    );
    defer acceptance.deinit();

    try builder.expectContains("const core_virtual_size: u64 = 3584 * 1024 * 1024;");
    try acceptance.expectContains(".virtual_size = 3584 * mib");
    try workflow.expectContains("VIRTUAL_SIZE: 3758096384");
}

test "artifacts are commit, attempt, and digest bound" {
    var workflow = try open();
    defer workflow.deinit();
    const prefixes = [_][]const u8{
        "ubuntu2604-core-candidate-",
        "ubuntu2604-core-native-",
        "ubuntu2604-core-azure-",
        "ubuntu2604-core-validation-",
    };
    for (prefixes) |prefix| try workflow.expectContains(prefix);
    const gate = try job(&workflow, "validate", null);
    try source.expectContainsIn(gate, "\"$RELEASE_TOOL\" core-gate", workflow_path);
    try source.expectContainsIn(
        gate,
        "path: ${{ env.BUNDLE_DIR }}/validation.json",
        workflow_path,
    );
}

test "cleanup is unconditional and reports its own failures" {
    var workflow = try open();
    defer workflow.deinit();

    const build = try job(&workflow, "build", "native_qemu");
    try source.expectContainsIn(
        build,
        "- name: Clean privileged build state\n        if: always()",
        workflow_path,
    );
    try source.expectContainsIn(build, "set -uo pipefail", workflow_path);
    try source.expectContainsIn(
        build,
        "sudo rm -rf -- \"$WORK_DIR\" \"$BUNDLE_DIR\" || status=1",
        workflow_path,
    );
    try source.expectContainsIn(build, "exit \"$status\"", workflow_path);

    const native = try job(&workflow, "native_qemu", "azure_acceptance");
    try source.expectContainsIn(
        native,
        "- name: Remove candidate and local acceptance state\n        if: always()",
        workflow_path,
    );
    try source.expectContainsIn(native, "rm -rf -- \"$RESULT_DIR\" || status=1", workflow_path);

    const azure = try job(&workflow, "azure_acceptance", "validate");
    try source.expectContainsIn(
        azure,
        "- name: Refresh Azure OIDC credential for unconditional cleanup\n        if: always()",
        workflow_path,
    );
    try source.expectContainsIn(
        azure,
        "- name: Delete only ownership-tagged temporary Azure resources\n        if: always()",
        workflow_path,
    );
    try source.expectContainsIn(
        azure,
        "- name: Remove derived VHD and local credentials\n        if: always()",
        workflow_path,
    );
}

test "the workflow runs no Python at all" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectOmits(source.interpreter ++ " scripts/");
    try workflow.expectOmits(source.interpreter ++ " - ");
    try workflow.expectOmits("<<'PY'");
    // Native UEFI variable enrollment removed the last host package naming the
    // interpreter, so the core workflow carries no spelling of it either.
    try workflow.expectCount(source.interpreter, 0);
    try workflow.expectOmits("virt-fw-vars");
}
