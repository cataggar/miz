//! Guards for `.github/workflows/ubuntu2604-core-validation.yml`.
//!
//! The core-validation workflow proves the appliance flavor end to end and
//! publishes nothing. Its safety is structural in the same way the release
//! workflow's is -- exact matrices, complete acceptance sets, least-privilege
//! permissions, self-contained core inputs, and no publication path. Replaces
//! `tests/ubuntu2604_core_workflow_test.py`.

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

test "the core build job re-validates the size inventory it measured" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try job(&workflow, "build", "native_qemu");
    try source.expectOrder(
        build_job,
        "- name: Validate standalone zstd QCOW2 and exact 3584 MiB size",
        "- name: Verify the reproducible size inventory",
        workflow_path,
    );
    try source.expectOrder(
        build_job,
        "- name: Verify the reproducible size inventory",
        "- name: Create and verify exact core candidate bundle",
        workflow_path,
    );
    const start = try source.indexOfIn(
        build_job,
        "- name: Verify the reproducible size inventory",
        workflow_path,
    );
    const rest = build_job[start..];
    const step = rest[0 .. std.mem.indexOfPos(
        u8,
        rest,
        "- name: Verify".len,
        "- name:",
    ) orelse rest.len];
    try source.expectContainsIn(step, "size-inventory-verify", workflow_path);
    try source.expectContainsIn(
        step,
        "--require-phase root_build,image_build,publication",
        workflow_path,
    );
}

test "the core build job re-validates the runtime contract it published" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try job(&workflow, "build", "native_qemu");
    try source.expectOrder(
        build_job,
        "- name: Verify the reproducible size inventory",
        "- name: Verify the explicit runtime contract",
        workflow_path,
    );
    try source.expectOrder(
        build_job,
        "- name: Verify the explicit runtime contract",
        "- name: Create and verify exact core candidate bundle",
        workflow_path,
    );
    try source.expectContainsIn(build_job, "runtime-contract-verify", workflow_path);
    try source.expectContainsIn(
        build_job,
        "ubuntu2604-runtime-contract-$FLAVOR-$ARCHITECTURE.json",
        workflow_path,
    );
}

test "core QEMU acceptance measures and re-validates the first-boot inventory" {
    var workflow = try open();
    defer workflow.deinit();
    const native = try job(&workflow, "native_qemu", "azure_acceptance");
    // The bound inventory is an input; the measured phase goes to a separate
    // document, so the build provenance digest still describes the file it was
    // computed over.
    try source.expectContainsIn(native, "MIZ_UBUNTU2604_SIZE_INVENTORY=", workflow_path);
    try source.expectContainsIn(
        native,
        "MIZ_UBUNTU2604_FIRST_BOOT_INVENTORY=",
        workflow_path,
    );
    try source.expectOrder(
        native,
        "- name: Run same-architecture Secure Boot QEMU core acceptance",
        "- name: Verify the measured first-boot size inventory",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "--require-phase root_build,image_build,publication,first_boot",
        workflow_path,
    );
    try source.expectContainsIn(native, "*.first-boot.json", workflow_path);
}

test "core Azure acceptance builds the runtime contract probe from the build graph" {
    var workflow = try open();
    defer workflow.deinit();
    const azure = try job(&workflow, "azure_acceptance", null);
    try source.expectContainsIn(azure, "RUNTIME_CONTRACT_PROBE:", workflow_path);
    try source.expectContainsIn(
        azure,
        "zig build install-ubuntu2604-runtime-contract-probes",
        workflow_path,
    );
    try source.expectOrder(
        azure,
        "- name: Build the guest runtime contract probe",
        "- name: Run exact-digest Azure Trusted Launch core acceptance",
        workflow_path,
    );
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
    try workflow.expectContains(
        "MIZ_UBUNTU2604_CANDIDATE_RUN_ATTEMPT=$CANDIDATE_RUN_ATTEMPT",
    );
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
        "name: same-architecture QEMU (${{ matrix.accelerator }})",
        "timeout-minutes: ${{ matrix.timeout_minutes }}",
        "MIZ_UBUNTU2604_QEMU: ${{ matrix.emulator }}",
        "MIZ_UBUNTU2604_QEMU_ACCELERATOR: ${{ matrix.accelerator }}",
        "MIZ_UBUNTU2604_QEMU_ACCELERATOR_ARGUMENT: ${{ matrix.accelerator_argument }}",
        "MIZ_UBUNTU2604_QEMU_CPU: ${{ matrix.cpu }}",
        "MIZ_UBUNTU2604_QEMU_MACHINE: ${{ matrix.machine }}",
        "MIZ_UBUNTU2604_QEMU_JOB_TIMEOUT_MINUTES: ${{ matrix.timeout_minutes }}",
        "MIZ_UBUNTU2604_RUNNER_ARCHITECTURE: ${{ matrix.runner_architecture }}",
        "if [[ ! -c /dev/kvm ]]",
        "sudo -n chown \"$(id -u):$(id -g)\" /dev/kvm",
        "test -r /dev/kvm",
        "test -w /dev/kvm",
        // The stable KVM ABI check is a release-tooling subcommand now, run
        // once the accepted-source tooling exists.
        "\"$RELEASE_TOOL\" kvm-api-version",
        "qemu-efi-aarch64 qemu-system-arm",
        "qemu=qemu-system-aarch64",
        "test \"$(command -v \"$qemu\")\" = \"$MIZ_UBUNTU2604_QEMU\"",
        "/usr/share/AAVMF/AAVMF_CODE.ms.fd",
        "/usr/share/AAVMF/AAVMF_VARS.ms.fd",
        "MIZ_UBUNTU2604_UEFI_CODE=",
        "MIZ_UBUNTU2604_UEFI_VARS=",
        "test -f \"$uefi_code\"",
        "test -f \"$uefi_vars\"",
        "verify-native-result",
        "MIZ_UBUNTU2604_SOURCE_COMMIT=",
        "MIZ_UBUNTU2604_ACCEPTANCE_RUN_ID=",
        "MIZ_UBUNTU2604_ACCEPTANCE_RUN_ATTEMPT=",
    };
    for (native_needles) |needle| try source.expectContainsIn(native, needle, workflow_path);
    for ([_][]const u8{
        "[self-hosted, Linux, ARM64, kvm]",
        "force_tcg",
        "accel=auto",
        "MIZ_VM_ACCEL=software",
    }) |needle| {
        try source.expectOmitsIn(native, needle, workflow_path);
    }
    const x86_row =
        \\runner: ubuntu-24.04
        \\            runner_architecture: x86_64
        \\            debian_architecture: amd64
        \\            accelerator: kvm
        \\            accelerator_argument: kvm
        \\            emulator: /usr/bin/qemu-system-x86_64
        \\            machine: q35
        \\            cpu: host
        \\            timeout_minutes: 180
    ;
    const arm_row =
        \\runner: ubuntu-24.04-arm
        \\            runner_architecture: aarch64
        \\            debian_architecture: arm64
        \\            accelerator: tcg
        \\            accelerator_argument: tcg,thread=multi
        \\            emulator: /usr/bin/qemu-system-aarch64
        \\            machine: virt
        \\            cpu: max
        \\            timeout_minutes: 360
    ;
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, native, x86_row));
    try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, native, arm_row));

    const x86_start = try source.indexOfIn(
        native,
        "- name: Require x86_64 KVM runner",
        workflow_path,
    );
    const arm_start = try source.indexOfIn(
        native,
        "- name: Require hosted Arm64 TCG runner",
        workflow_path,
    );
    const checkout_start = try source.indexOfIn(
        native,
        "- name: Check out accepted source",
        workflow_path,
    );
    const x86_capability = native[x86_start..arm_start];
    const arm_capability = native[arm_start..checkout_start];
    for ([_][]const u8{
        "if: matrix.architecture == 'x86_64'",
        "test \"$MIZ_UBUNTU2604_QEMU_ACCELERATOR\" = kvm",
        "test \"$MIZ_UBUNTU2604_QEMU_ACCELERATOR_ARGUMENT\" = kvm",
        "test \"$MIZ_UBUNTU2604_QEMU_CPU\" = host",
        "test \"$MIZ_UBUNTU2604_QEMU_MACHINE\" = q35",
        "test \"$MIZ_UBUNTU2604_QEMU_JOB_TIMEOUT_MINUTES\" = 180",
        "test \"$MIZ_UBUNTU2604_QEMU\" = /usr/bin/qemu-system-x86_64",
        "test \"$(uname -m)\" = \"$expected_uname\"",
        "test \"$(dpkg --print-architecture)\" = \"$expected_deb\"",
        "if [[ ! -c /dev/kvm ]]",
        "sudo -n chown \"$(id -u):$(id -g)\" /dev/kvm",
        "test -r /dev/kvm",
        "test -w /dev/kvm",
    }) |needle| try source.expectContainsIn(x86_capability, needle, workflow_path);
    for ([_][]const u8{
        "if: matrix.architecture == 'aarch64'",
        "test \"$ARCHITECTURE\" = aarch64",
        "test \"$MIZ_UBUNTU2604_QEMU_ACCELERATOR_ARGUMENT\" = tcg,thread=multi",
        "test \"$MIZ_UBUNTU2604_QEMU_CPU\" = max",
        "test \"$MIZ_UBUNTU2604_QEMU_MACHINE\" = virt",
        "test \"$MIZ_UBUNTU2604_QEMU_JOB_TIMEOUT_MINUTES\" = 360",
        "test \"$MIZ_UBUNTU2604_QEMU\" = /usr/bin/qemu-system-aarch64",
        "test \"$(uname -m)\" = aarch64",
        "test \"$(dpkg --print-architecture)\" = arm64",
    }) |needle| try source.expectContainsIn(arm_capability, needle, workflow_path);
    for ([_][]const u8{ "/dev/kvm", "kvm-api-version", "fallback", "auto" }) |needle| {
        try source.expectOmitsIn(arm_capability, needle, workflow_path);
    }

    var execution_source = try Source.open(
        std.testing.allocator,
        "scripts/ubuntu2604/execution.zig",
    );
    defer execution_source.deinit();
    try execution_source.expectContains(".initial_guest_launch = .concurrent");
    try execution_source.expectContains(
        ".initial_guest_launch = .serial_until_ready",
    );

    var acceptance = try Source.open(
        std.testing.allocator,
        "tests/ubuntu2604_acceptance.zig",
    );
    defer acceptance.deinit();
    try acceptance.expectContains(
        "configured_execution.profile.initial_guest_launch",
    );
    try acceptance.expectContains(
        ".serial_until_ready => .{\n            .start_first,\n            .first_ready,\n            .start_second",
    );
    try acceptance.expectContains(
        ".concurrent => .{\n            .start_first,\n            .start_second,\n            .first_ready",
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
    const kvm_api_start = try source.indexOfIn(
        native,
        "- name: Require the stable KVM API version",
        workflow_path,
    );
    const fixture_start = try source.indexOfIn(
        native,
        "- name: Provision privileged offline-root containment fixture",
        workflow_path,
    );
    try source.expectContainsIn(
        native[kvm_api_start..fixture_start],
        "if: matrix.architecture == 'x86_64'",
        workflow_path,
    );

    const azure = try job(&workflow, "azure_acceptance", "validate");
    try source.expectContainsIn(azure, "FLAVOR: core", workflow_path);
    try source.expectContainsIn(azure, "ubuntu2604_azure_acceptance.sh run", workflow_path);
    try source.expectOrder(
        azure,
        "- name: Build accepted-source miz",
        "- name: Build Binder device usability probe",
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

test "the workflow has no external secret-bound smoke input dependency" {
    var workflow = try open();
    defer workflow.deinit();

    const scopes = [_]struct {
        name: []const u8,
        following: []const u8,
    }{
        .{
            .name = "native_qemu",
            .following = "azure_acceptance",
        },
        .{
            .name = "azure_acceptance",
            .following = "validate",
        },
    };
    for (scopes) |scope| {
        const section = try job(&workflow, scope.name, scope.following);
        for ([_][]const u8{
            "ANDROID" ++ "_",
            "android_" ++ "smoke_secret",
            "prepare-" ++ "android",
            "/android-" ++ "smoke",
            "artifact_url",
        }) |needle| {
            try source.expectOmitsIn(section, needle, scope.name);
        }
        if (std.mem.eql(u8, scope.name, "native_qemu")) {
            try source.expectOmitsIn(
                section,
                "ca-certificates curl openssh-client",
                scope.name,
            );
        } else {
            const binder = [_][]const u8{
                "Build Binder device usability probe",
                "tests/binder_probe.zig",
                "test -x \"$BINDER_PROBE\"",
            };
            for (binder) |needle| try source.expectContainsIn(section, needle, scope.name);
        }
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
