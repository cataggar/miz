//! Guards for `.github/workflows/ubuntu2604-release.yml`.
//!
//! The release workflow is the only path that publishes Ubuntu images, and
//! almost everything that makes it safe is structural: which matrices exist,
//! which jobs the publication gate needs, which tools the image builder may
//! install, and which order steps run in. None of that is visible to a unit
//! test of the release tooling, so it is asserted here, against the workflow
//! source itself. Replaces `tests/ubuntu2604_workflow_test.py`.

const std = @import("std");

const source = @import("ubuntu2604_source.zig");

const Source = source.Source;
const workflow_path = ".github/workflows/ubuntu2604-release.yml";

fn open() !Source {
    return Source.open(std.testing.allocator, workflow_path);
}

test "each matrix carries exactly the published full-flavor candidates" {
    var workflow = try open();
    defer workflow.deinit();

    const boundaries = [_][2][]const u8{
        .{ "build", "native_qemu" },
        .{ "native_qemu", "azure_acceptance" },
        .{ "azure_acceptance", "publish" },
    };
    for (boundaries) |boundary| {
        var start_buffer: [64]u8 = undefined;
        var end_buffer: [64]u8 = undefined;
        const start = try std.fmt.bufPrint(&start_buffer, "\n  {s}:\n", .{boundary[0]});
        const end = try std.fmt.bufPrint(&end_buffer, "\n  {s}:\n", .{boundary[1]});
        const section = try workflow.section(start, end);

        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, section, "- key: x86_64-full"),
        );
        try std.testing.expectEqual(
            @as(usize, 1),
            std.mem.count(u8, section, "- key: aarch64-full"),
        );
        try source.expectOmitsIn(section, "-core", boundary[0]);
        try source.expectContainsIn(
            section,
            "asset_name: Ubuntu-26.04-x86_64.qcow2",
            boundary[0],
        );
        try source.expectContainsIn(
            section,
            "asset_name: Ubuntu-26.04-aarch64.qcow2",
            boundary[0],
        );
    }
}

test "candidate reuse is bound to one attempt, job, and artifact" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectContains("/attempts/$candidate_run_attempt/jobs");
    try workflow.expectContains("jq --arg name \"build/native $key\"");
    try workflow.expectContains(".expired == false and .size_in_bytes > 0");
    try workflow.expectContains(
        "ubuntu2604-candidate-$key-$commit-$candidate_run_attempt",
    );
}

test "publication fails closed across all three matrices" {
    var workflow = try open();
    defer workflow.deinit();
    const publish = try workflow.section("  publish:", null);
    try source.expectContainsIn(
        publish,
        "needs: [prepare, build, native_qemu, azure_acceptance]",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "needs.native_qemu.result == 'success'",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "needs.azure_acceptance.result == 'success'",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "scripts/ubuntu2604_publish.sh",
        workflow_path,
    );
    // The gate itself now lives in the release tooling, so the workflow's job
    // is to run it against exactly the three downloaded result sets.
    try source.expectContainsIn(publish, "\"$RELEASE_TOOL\" release-gate", workflow_path);
    try source.expectContainsIn(publish, "--candidates \"$CANDIDATES_DIR\"", workflow_path);
    try source.expectContainsIn(
        publish,
        "--native-results \"$NATIVE_RESULTS_DIR\"",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "--azure-results \"$AZURE_RESULTS_DIR\"",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "--candidate-run-id \"$CANDIDATE_RUN_ID\"",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "--candidate-run-attempt \"$CANDIDATE_RUN_ATTEMPT\"",
        workflow_path,
    );
    try source.expectContainsIn(publish, "--run-id \"$RUN_ID_VALUE\"", workflow_path);
    try source.expectContainsIn(
        publish,
        "--run-attempt \"$RUN_ATTEMPT_VALUE\"",
        workflow_path,
    );
}

test "protected environments and OIDC subjects are explicit" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectCount("environment: ubuntu2604-signing", 1);
    try workflow.expectCount("environment: ubuntu2604-release", 2);
    try workflow.expectContains("id-token: write");
    try workflow.expectContains("github.repository == 'cataggar/miz'");
    try workflow.expectContains("repo:cataggar/miz:environment:ubuntu2604-signing");
    try workflow.expectContains("repo:cataggar/miz:environment:ubuntu2604-release");
}

test "the image builder installs only its complete native dependencies" {
    var workflow = try open();
    defer workflow.deinit();
    const install = try workflow.section(
        "- name: Install complete Ubuntu image-builder dependencies",
        "- name: Build built-in Artifact Signing client",
    );
    // Native miz UKI assembly replaces systemd-ukify and its builder
    // dependency stack, so none of them may be installed.
    const removed = [_][]const u8{
        "systemd-ukify",
        "binutils",
        "python3-pefile",
        "linux-image-generic",
        "util-linux",
        "liblzma-dev",
        "libzstd-dev",
        "cpio",
        "xz-utils",
        " zstd",
        "qemu-utils",
        "qemu-img",
        // The kernel and initrd are extracted natively, so the host /boot
        // kernel and its chmod fixup are gone.
        "/boot/vmlinuz",
        // The offline-root executor builds its sandbox with direct syscalls.
        "mount",
        "mknod",
        "chroot",
        "setsid",
        "timeout",
        "unshare",
        // Native UKI assembly replaces the ukify subprocess entirely.
        "ukify",
        "command -v",
        // Native X.509/Authenticode signing replaces these utilities.
        "openssl",
        "sbsigntool",
        "sbverify",
        "libguestfs",
        "guestfish",
        "supermin",
        "virt-customize",
        "virt-copy-in",
        "virt-copy-out",
        "virt-ls",
        "virt-cat",
        "sudo chmod 0666 /dev/kvm",
        "LIBGUESTFS_BACKEND_SETTINGS",
        "force_tcg",
        // The document checks the build job runs are native, so the builder
        // step installs no interpreter for them either.
        source.interpreter,
    };
    for (removed) |needle| {
        try source.expectOmitsIn(install, needle, "image-builder dependencies");
    }
    // systemd-boot-efi supplies the PE/COFF stub the native assembler appends
    // the UKI sections onto; the arch-correct stub is the sole external input
    // and must be verified present after install.
    try source.expectContainsIn(install, "systemd-boot-efi", workflow_path);
    try source.expectContainsIn(
        install,
        "/usr/lib/systemd/boot/efi/linuxx64.efi.stub",
        workflow_path,
    );
    try source.expectContainsIn(
        install,
        "/usr/lib/systemd/boot/efi/linuxaa64.efi.stub",
        workflow_path,
    );
    try source.expectOrder(
        install,
        "sudo apt-get install -y --no-install-recommends \"${packages[@]}\"",
        "test -f \"$uki_stub\"",
        workflow_path,
    );
}

test "privileged build outputs are removed with privilege and failures surface" {
    var workflow = try open();
    defer workflow.deinit();
    const cleanup = try workflow.section(
        "- name: Clean privileged build state",
        "\n  native_qemu:",
    );
    try source.expectContainsIn(
        cleanup,
        "sudo rm -rf -- \"$WORK_DIR\" \"$BUNDLE_DIR\"",
        workflow_path,
    );
    try source.expectOmitsIn(cleanup, "rm -rf -- \"$BUNDLE_DIR\"", workflow_path);
    // Cleanup must attempt every removal and surface failures without masking
    // the original build failure.
    try source.expectContainsIn(cleanup, "set -uo pipefail", workflow_path);
    try source.expectContainsIn(cleanup, "status=0", workflow_path);
    try source.expectContainsIn(
        cleanup,
        "sudo rm -rf -- \"$WORK_DIR\" \"$BUNDLE_DIR\" || status=1",
        workflow_path,
    );
    try source.expectContainsIn(cleanup, "exit \"$status\"", workflow_path);
    try source.expectContainsIn(
        cleanup,
        "rm -rf -- \"$SIGNING_PROBE_DIR\" || status=1",
        workflow_path,
    );
    try source.expectContainsIn(
        cleanup,
        "rm -f -- \"${UKI_SIGNING_CERTIFICATE:-}\" || status=1",
        workflow_path,
    );
    // Ownership is normalized with a targeted chown in the build step, never
    // with a broad chmod here.
    try source.expectOmitsIn(cleanup, "chmod", workflow_path);
}

test "the release identifier uses one calendar date everywhere" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectContains("group: ubuntu2604-release-20260822");
    try workflow.expectContains("RELEASE_TAG: Ubuntu-26.04-20260822");
    try workflow.expectContains("RELEASE_TITLE: Ubuntu Server 26.04 - 20260822");
    try workflow.expectContains("create or retarget RELEASE_TAG");
}

test "forbidden image tools appear only in explicitly optional oracle jobs" {
    var workflow = try open();
    defer workflow.deinit();

    var covered: usize = 0;
    var total: usize = 0;
    var scan: []const u8 = workflow.text;
    while (source.findForbiddenProductionTool(scan)) |match| {
        total += 1;
        const offset = @intFromPtr(match.ptr) - @intFromPtr(scan.ptr);
        scan = scan[offset + match.len ..];
    }

    const publish = try workflow.section("\n  publish:\n", null);
    var jobs = jobIterator(workflow.text);
    while (jobs.next()) |job| {
        var occurrences: usize = 0;
        var section = job.body;
        while (source.findForbiddenProductionTool(section)) |match| {
            occurrences += 1;
            const offset = @intFromPtr(match.ptr) - @intFromPtr(section.ptr);
            section = section[offset + match.len ..];
        }
        if (occurrences == 0) continue;
        if (!std.mem.startsWith(u8, job.name, "optional_oracle_")) {
            std.debug.print(
                "{s}: {s} contains a forbidden production tool\n",
                .{ workflow_path, job.name },
            );
            return error.ForbiddenText;
        }
        try source.expectContainsIn(job.body, "continue-on-error: true", job.name);
        try source.expectOmitsIn(job.body, "\n    outputs:", job.name);
        try source.expectOmitsIn(job.body, "actions/upload-artifact", job.name);
        try source.expectOmitsIn(job.body, "actions/download-artifact", job.name);
        const publish_needs = publish[0 .. std.mem.indexOf(
            u8,
            publish,
            "\n    if:",
        ) orelse publish.len];
        try source.expectOmitsIn(publish_needs, job.name, "publish needs");
        covered += occurrences;
    }
    try std.testing.expectEqual(total, covered);

    // UEFI Secure Boot variable enrollment is native (miz.efi_varstore), so
    // even the firmware-variable tooling that was never an image tool is gone.
    try workflow.expectOmits(source.firmware_package);
    try workflow.expectOmits("virt-fw-vars");
}

const Job = struct {
    name: []const u8,
    body: []const u8,
};

const JobIterator = struct {
    text: []const u8,
    cursor: usize,

    fn next(self: *JobIterator) ?Job {
        while (self.cursor < self.text.len) {
            const start = self.cursor;
            const line_end = std.mem.indexOfScalarPos(
                u8,
                self.text,
                start,
                '\n',
            ) orelse self.text.len;
            const line = self.text[start..line_end];
            self.cursor = line_end + 1;
            const name = jobName(line) orelse continue;
            var end = self.cursor;
            while (end < self.text.len) {
                const next_end = std.mem.indexOfScalarPos(
                    u8,
                    self.text,
                    end,
                    '\n',
                ) orelse self.text.len;
                if (jobName(self.text[end..next_end]) != null) break;
                end = next_end + 1;
            }
            const body_end = @min(end, self.text.len);
            self.cursor = body_end;
            return .{ .name = name, .body = self.text[start..body_end] };
        }
        return null;
    }
};

/// `^  ([a-z][a-z0-9_]*):$`, which is how a job header is spelled.
fn jobName(line: []const u8) ?[]const u8 {
    if (!std.mem.startsWith(u8, line, "  ")) return null;
    if (line.len < 4 or line[2] == ' ') return null;
    if (!std.ascii.isLower(line[2])) return null;
    if (line[line.len - 1] != ':') return null;
    const name = line[2 .. line.len - 1];
    for (name) |byte| {
        if (!std.ascii.isLower(byte) and !std.ascii.isDigit(byte) and byte != '_') {
            return null;
        }
    }
    return name;
}

fn jobIterator(text: []const u8) JobIterator {
    return .{ .text = text, .cursor = 0 };
}

test "the build log pipeline prepares its directory and propagates failures" {
    var workflow = try open();
    defer workflow.deinit();
    const build = try workflow.section(
        "- name: Build exact finalized Ubuntu QCOW2",
        "- name: Validate standalone zstd QCOW2 and exact 5 GiB size",
    );
    try source.expectOrder(build, "set -euo pipefail", "2>&1 | tee \"$build_log\"", workflow_path);
    try source.expectOrder(
        build,
        "mkdir -p \"$GITHUB_WORKSPACE/$WORK_DIR\"",
        "build_log=\"$GITHUB_WORKSPACE/$WORK_DIR/build.log\"",
        workflow_path,
    );
    try source.expectOrder(
        build,
        "build_log=\"$GITHUB_WORKSPACE/$WORK_DIR/build.log\"",
        "2>&1 | tee \"$build_log\"",
        workflow_path,
    );
    try source.expectContainsIn(build, "sudo -E \"$(command -v zig)\" build", workflow_path);
    try source.expectContainsIn(build, "sudo chown -R \"$(id -u):$(id -g)\"", workflow_path);
}

test "storage diagnostics are ordered and never mask the build failure" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try workflow.section("\n  build:\n", "\n  native_qemu:\n");
    try source.expectOrder(
        build_job,
        "- name: Record host filesystem capacity before image build",
        "- name: Build exact finalized Ubuntu QCOW2",
        workflow_path,
    );
    try source.expectOrder(
        build_job,
        "- name: Build exact finalized Ubuntu QCOW2",
        "- name: Diagnose storage after image build failure",
        workflow_path,
    );
    try source.expectOrder(
        build_job,
        "- name: Diagnose storage after image build failure",
        "- name: Clean privileged build state",
        workflow_path,
    );

    const capacity_start = try source.indexOfIn(
        build_job,
        "- name: Record host filesystem capacity before image build",
        workflow_path,
    );
    const build_start = try source.indexOfIn(
        build_job,
        "- name: Build exact finalized Ubuntu QCOW2",
        workflow_path,
    );
    const capacity = build_job[capacity_start..build_start];
    try source.expectContainsIn(capacity, "continue-on-error: true", workflow_path);
    try source.expectContainsIn(
        capacity,
        "df -hT -- \"$GITHUB_WORKSPACE\" \"$RUNNER_TEMP\"",
        workflow_path,
    );
    try source.expectOmitsIn(capacity, "sudo", workflow_path);

    const diagnostic_start = try source.indexOfIn(
        build_job,
        "- name: Diagnose storage after image build failure",
        workflow_path,
    );
    const cleanup_start = try source.indexOfIn(
        build_job,
        "- name: Clean privileged build state",
        workflow_path,
    );
    const diagnostic = build_job[diagnostic_start..cleanup_start];
    try source.expectContainsIn(diagnostic, "if: failure()", workflow_path);
    try source.expectContainsIn(diagnostic, "continue-on-error: true", workflow_path);
    try source.expectContainsIn(
        diagnostic,
        "df -hT -- \"$GITHUB_WORKSPACE\" \"$RUNNER_TEMP\"",
        workflow_path,
    );
    try source.expectContainsIn(diagnostic, "sudo -n du -x -h --max-depth=1", workflow_path);
    try source.expectContainsIn(diagnostic, "\"$GITHUB_WORKSPACE/$WORK_DIR\"", workflow_path);
    try source.expectContainsIn(diagnostic, "\"$GITHUB_WORKSPACE/$BUNDLE_DIR\"", workflow_path);
    try source.expectContainsIn(diagnostic, "tail -n 30", workflow_path);
    try source.expectOmitsIn(diagnostic, "sudo -n df", workflow_path);
}

test "the build job validates the QCOW2 and publishes its metadata natively" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try workflow.section("\n  build:\n", "\n  native_qemu:\n");
    const validate_start = try source.indexOfIn(
        build_job,
        "- name: Validate standalone zstd QCOW2 and exact 5 GiB size",
        workflow_path,
    );
    const rest = build_job[validate_start..];
    const validate = rest[0 .. std.mem.indexOfPos(
        u8,
        rest,
        "- name: Validate".len,
        "- name:",
    ) orelse rest.len];

    // The build job emits and validates the release image entirely with miz;
    // qemu tooling must not appear anywhere in it (issue #476).
    try source.expectOmitsIn(build_job, "qemu-img", workflow_path);
    try source.expectOmitsIn(build_job, "qemu-utils", workflow_path);
    try source.expectContainsIn(validate, "\"$miz\" check \"$asset\"", workflow_path);
    try source.expectContainsIn(validate, "\"$miz\" info --output=json \"$asset\"", workflow_path);
    try source.expectContainsIn(
        validate,
        "miz=\"$GITHUB_WORKSPACE/zig-out/bin/miz\"",
        workflow_path,
    );
    // Native metadata is the publication input the candidate provenance binds
    // and the exactness gate parses, and it is now judged by the release
    // tooling rather than an inline interpreter.
    try source.expectContainsIn(validate, "image-info.json", workflow_path);
    try source.expectContainsIn(validate, "\"$RELEASE_TOOL\" verify-image-info", workflow_path);
    try source.expectContainsIn(validate, "--virtual-size-label \"5 GiB\"", workflow_path);
    try source.expectOmitsIn(build_job, source.interpreter, workflow_path);
}

test "native acceptance cannot silently skip" {
    var workflow = try open();
    defer workflow.deinit();
    const native = try workflow.section("  native_qemu:", "  azure_acceptance:");
    const needles = [_][]const u8{
        "runner: ubuntu-24.04",
        "runner: [self-hosted, Linux, ARM64, kvm]",
        "FLAVOR: full",
        "if [[ ! -c /dev/kvm ]]",
        "sudo -n chown \"$(id -u):$(id -g)\" /dev/kvm",
        "test -r /dev/kvm",
        "test -w /dev/kvm",
        "test \"$(uname -m)\" = \"$expected_uname\"",
        "test \"$(dpkg --print-architecture)\" = \"$expected_deb\"",
        "\"$RELEASE_TOOL\" kvm-api-version",
        "qemu-efi-aarch64 qemu-system-arm",
        "qemu=qemu-system-aarch64",
        "OVMF_CODE_4M.ms.fd",
        "OVMF_VARS_4M.ms.fd",
        "AAVMF_CODE.ms.fd",
        "AAVMF_VARS.ms.fd",
        "MIZ_UBUNTU2604_UEFI_CODE=",
        "MIZ_UBUNTU2604_UEFI_VARS=",
        "test -f \"$uefi_code\"",
        "test -f \"$uefi_vars\"",
        "MIZ_UBUNTU2604_IMAGE=",
        "test -s \"$MIZ_UBUNTU2604_ACCEPTANCE_RESULT\"",
        "Provision privileged offline-root containment fixture",
        "sudo -E \"$(command -v zig)\" test packages/miz/src/offline_root.zig",
        "sudo rm -rf -- \"$fixture\"",
        "ldd \"$binary\"",
        "while read -r library",
        "MIZ_UBUNTU2604_SOURCE_COMMIT=",
        "MIZ_UBUNTU2604_ACCEPTANCE_RUN_ID=",
        "MIZ_UBUNTU2604_ACCEPTANCE_RUN_ATTEMPT=",
        "-Dubuntu2604-flavor=\"$FLAVOR\"",
    };
    for (needles) |needle| try source.expectContainsIn(native, needle, workflow_path);
    try source.expectOmitsIn(native, "/usr/bin/coreutils", workflow_path);
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
        "Unsupported native acceptance architecture",
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
        "sudo apt-get install -y --no-install-recommends \"${packages[@]}\"",
        "uefi_vars=$(readlink -f -- \"$uefi_vars\")",
        workflow_path,
    );
    try source.expectOrder(
        native,
        "uefi_vars=$(readlink -f -- \"$uefi_vars\")",
        "echo \"MIZ_UBUNTU2604_UEFI_CODE=$uefi_code\"",
        workflow_path,
    );
    try source.expectOrder(
        native,
        "- name: Build accepted-source release tooling",
        "- name: Require the stable KVM API version",
        workflow_path,
    );
    // The workflow uses the canonical candidate-aware document validator,
    // not the retired weaker manifest-only verifier.
    try source.expectContainsIn(native, "\"$RELEASE_TOOL\" verify-native-result", workflow_path);
    try source.expectOmitsIn(native, "verify-native-evidence", workflow_path);
    try source.expectContainsIn(
        native,
        "--manifest \"$CANDIDATE_DIR/candidate.json\"",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "--asset \"$CANDIDATE_DIR/$ASSET_NAME\"",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "--result \"$RESULT_DIR/native-result.json\"",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "--key \"$CANDIDATE_KEY\"",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "--source-commit \"$SOURCE_COMMIT\"",
        workflow_path,
    );
}

test "Azure OIDC login is fresh for acceptance" {
    var workflow = try open();
    defer workflow.deinit();
    const azure = try workflow.section("  azure_acceptance:", "  publish:");
    try source.expectOrder(
        azure,
        "- name: Build accepted-source miz",
        "- name: Log in to Azure with protected-environment OIDC",
        workflow_path,
    );
    try source.expectOrder(
        azure,
        "- name: Log in to Azure with protected-environment OIDC",
        "- name: Run exact-digest Azure Trusted Launch acceptance",
        workflow_path,
    );
}

test "every job that runs the release tooling builds it from the accepted source" {
    var workflow = try open();
    defer workflow.deinit();
    // The tooling is a build product of the checked-out commit, never a
    // pre-existing binary on the runner.
    try workflow.expectContains(
        "RELEASE_TOOL: ${{ github.workspace }}/zig-out/bin/ubuntu2604_release",
    );
    try workflow.expectContains("zig build install-miz install-ubuntu2604-release");
    const publish = try workflow.section("\n  publish:\n", null);
    try source.expectContainsIn(publish, "- name: Install Zig via ghr", workflow_path);
    try source.expectOrder(
        publish,
        "- name: Build accepted-source release tooling",
        "- name: Validate exact two-architecture release gate",
        workflow_path,
    );
    try source.expectContainsIn(publish, "test -x \"$RELEASE_TOOL\"", workflow_path);
}

test "the workflow runs no Python at all" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectOmits(source.interpreter ++ " scripts/");
    try workflow.expectOmits(source.interpreter ++ " - ");
    try workflow.expectOmits("<<'PY'");
    // Not one spelling of the interpreter survives: the release schema and
    // every document check are native, and so is Secure Boot variable
    // enrollment, which was the last host package that named it.
    try workflow.expectCount(source.interpreter, 0);
}
