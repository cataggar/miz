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

test "all release dependency prefetches use the bounded retry helper" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectOmits("zig build --fetch");
    try workflow.expectCount("bash scripts/zig_fetch_retry.sh", 5);

    var retry = try Source.open(
        std.testing.allocator,
        "scripts/zig_fetch_retry.sh",
    );
    defer retry.deinit();
    try retry.expectContains("readonly max_attempts=4");
    try retry.expectContains("NameServerFailure");
    try retry.expectContains("if ! grep -Eq \"$retryable_errors\"");
}

test "each matrix carries the exact four published candidates" {
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

        const rows = [_]struct {
            key: []const u8,
            architecture: []const u8,
            flavor: []const u8,
            asset_name: []const u8,
        }{
            .{
                .key = "x86_64-full",
                .architecture = "x86_64",
                .flavor = "full",
                .asset_name = "Ubuntu-26.04-x86_64.qcow2",
            },
            .{
                .key = "aarch64-full",
                .architecture = "aarch64",
                .flavor = "full",
                .asset_name = "Ubuntu-26.04-aarch64.qcow2",
            },
            .{
                .key = "x86_64-core",
                .architecture = "x86_64",
                .flavor = "core",
                .asset_name = "Ubuntu-26.04-x86_64.core.qcow2",
            },
            .{
                .key = "aarch64-core",
                .architecture = "aarch64",
                .flavor = "core",
                .asset_name = "Ubuntu-26.04-aarch64.core.qcow2",
            },
        };
        for (rows) |row| {
            var key_buffer: [64]u8 = undefined;
            const key = try std.fmt.bufPrint(&key_buffer, "- key: {s}", .{row.key});
            try std.testing.expectEqual(@as(usize, 1), std.mem.count(u8, section, key));
            var row_buffer: [256]u8 = undefined;
            const identity = try std.fmt.bufPrint(
                &row_buffer,
                "- key: {s}\n            architecture: {s}\n            flavor: {s}",
                .{ row.key, row.architecture, row.flavor },
            );
            try source.expectContainsIn(section, identity, boundary[0]);
            var asset_buffer: [128]u8 = undefined;
            const asset = try std.fmt.bufPrint(
                &asset_buffer,
                "asset_name: {s}",
                .{row.asset_name},
            );
            try source.expectContainsIn(section, asset, boundary[0]);
        }
    }
}

test "candidate and acceptance artifacts are resolved independently by key" {
    var workflow = try open();
    defer workflow.deinit();
    const candidates = try workflow.section(
        "\n  resolve_candidates:\n",
        "\n  native_qemu:\n",
    );
    try source.expectContainsIn(
        candidates,
        "needs: [prepare, build]",
        workflow_path,
    );
    try source.expectContainsIn(
        candidates,
        "bash scripts/ubuntu2604_resolve_artifacts.sh \\\n            candidate",
        workflow_path,
    );
    try source.expectContainsIn(
        candidates,
        "selection: ${{ steps.resolve.outputs.selection }}",
        workflow_path,
    );
    const results = try workflow.section("\n  publish:\n", null);
    try source.expectContainsIn(
        results,
        "- name: Resolve exact publication inputs",
        workflow_path,
    );
    try source.expectContainsIn(
        results,
        "native \"$RUN_ID_VALUE\" \"$SOURCE_COMMIT\"",
        workflow_path,
    );
    try source.expectContainsIn(
        results,
        "azure \"$RUN_ID_VALUE\" \"$SOURCE_COMMIT\"",
        workflow_path,
    );
    try source.expectContainsIn(
        results,
        "candidate \"$CANDIDATE_RUN_ID\" \"$SOURCE_COMMIT\"",
        workflow_path,
    );
    try workflow.expectContains(
        "fromJSON(needs.resolve_candidates.outputs.selection).artifacts[matrix.key].run_attempt",
    );
    try workflow.expectContains(
        "MIZ_UBUNTU2604_CANDIDATE_RUN_ATTEMPT=$CANDIDATE_RUN_ATTEMPT",
    );
    try workflow.expectCount("artifact-ids:", 5);
    try workflow.expectCount("merge-multiple: true", 2);
    try workflow.expectOmits("needs.prepare.outputs.candidate_run_attempt");
    try workflow.expectOmits("pattern: ubuntu2604-candidate-");
    try workflow.expectOmits("pattern: ubuntu2604-native-");
    try workflow.expectOmits("pattern: ubuntu2604-azure-");

    var resolver = try Source.open(
        std.testing.allocator,
        "scripts/ubuntu2604_resolve_artifacts.sh",
    );
    defer resolver.deinit();
    try resolver.expectContains(
        "/actions/runs/$run_id/attempts/$attempt/jobs?filter=all&per_page=100",
    );
    try resolver.expectContains(
        "\"$RELEASE_TOOL\" resolve-artifacts",
    );
    try resolver.expectContains("temporary_directory=\"${output}.inputs\"");
    try resolver.expectOmits("mktemp");
}

test "publication fails closed across all three matrices" {
    var workflow = try open();
    defer workflow.deinit();
    const publish = try workflow.section("  publish:", null);
    try source.expectContainsIn(
        publish,
        "needs: [prepare, build, resolve_candidates, native_qemu, azure_acceptance]",
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
        "--candidate-selection \"$SELECTIONS_DIR/candidates.json\"",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "--native-selection \"$SELECTIONS_DIR/native.json\"",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "--azure-selection \"$SELECTIONS_DIR/azure.json\"",
        workflow_path,
    );
    try source.expectContainsIn(publish, "--run-id \"$RUN_ID_VALUE\"", workflow_path);
    try source.expectContainsIn(
        publish,
        "artifact-ids: ${{ steps.artifacts.outputs.candidate_ids }}",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "artifact-ids: ${{ steps.artifacts.outputs.native_ids }}",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "artifact-ids: ${{ steps.artifacts.outputs.azure_ids }}",
        workflow_path,
    );
    try source.expectContainsIn(
        publish,
        "- name: Publish exactly four accepted Ubuntu assets",
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

test "a failed build publishes the measurement it failed on" {
    // Issue #677 step 6 makes failures attributable, and a budget or inventory
    // rejection is only attributable with the document that produced it. The
    // privileged cleanup removes the bundle, so the provenance is copied out
    // and uploaded on the failure path, before that cleanup runs.
    var workflow = try open();
    defer workflow.deinit();
    const build = try workflow.section(
        "  build:",
        "\n  resolve_candidates:",
    );
    try source.expectContainsIn(
        build,
        "FAILED_PROVENANCE_DIR: artifact-staging/failed-provenance/${{ matrix.key }}",
        workflow_path,
    );
    try source.expectContainsIn(
        build,
        "- name: Preserve the measurement that failed the build\n        if: failure()",
        workflow_path,
    );
    try source.expectContainsIn(
        build,
        "- name: Upload the measurement that failed the build\n        if: failure()",
        workflow_path,
    );
    try source.expectContainsIn(
        build,
        "name: ubuntu2604-failed-provenance-",
        workflow_path,
    );
    try source.expectContainsIn(
        build,
        "path: ${{ env.FAILED_PROVENANCE_DIR }}/",
        workflow_path,
    );
    // Evidence has to be captured before the privileged cleanup deletes the
    // bundle it is copied from.
    const preserve = std.mem.indexOf(
        u8,
        build,
        "- name: Preserve the measurement that failed the build",
    ).?;
    const cleanup = std.mem.indexOf(
        u8,
        build,
        "- name: Clean privileged build state",
    ).?;
    try std.testing.expect(preserve < cleanup);
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
        "sudo rm -rf -- \"$WORK_DIR\" \"$BUNDLE_DIR\" \"$FAILED_PROVENANCE_DIR\" || status=1",
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

test "native and Azure cleanup is unconditional for every matrix leg" {
    var workflow = try open();
    defer workflow.deinit();

    const native = try workflow.section("\n  native_qemu:\n", "\n  azure_acceptance:\n");
    try source.expectContainsIn(
        native,
        "- name: Remove candidate and local acceptance state\n        if: always()",
        workflow_path,
    );
    try source.expectContainsIn(native, "set -uo pipefail", workflow_path);
    try source.expectContainsIn(
        native,
        "rm -rf -- \".release/native/$CANDIDATE_KEY\" || status=1",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "rm -rf -- \"$RESULT_DIR\" || status=1",
        workflow_path,
    );
    try source.expectContainsIn(native, "exit \"$status\"", workflow_path);

    const azure = try workflow.section("\n  azure_acceptance:\n", "\n  publish:\n");
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
    try source.expectContainsIn(
        azure,
        "rm -rf -- \".release/azure/$CANDIDATE_KEY\" || status=1",
        workflow_path,
    );
    try source.expectContainsIn(
        azure,
        "rm -rf -- \"$RESULT_DIR\" || status=1",
        workflow_path,
    );
}

test "the release identifier uses one calendar date everywhere" {
    var workflow = try open();
    defer workflow.deinit();
    try workflow.expectContains("group: ubuntu2604-release-20260905");
    try workflow.expectContains("RELEASE_TAG: Ubuntu-26.04-20260905");
    try workflow.expectContains("RELEASE_TITLE: Ubuntu 26.04 full and core - 20260905");
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
        "- name: Validate standalone zstd QCOW2 and exact flavor size",
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

test "the release workflow publishes and re-checks the core runtime contract" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try workflow.section("\n  build:\n", "\n  native_qemu:\n");
    try source.expectOrder(
        build_job,
        "- name: Verify the reproducible size inventory",
        "- name: Verify the explicit runtime contract",
        workflow_path,
    );
    try source.expectContainsIn(build_job, "runtime-contract-verify", workflow_path);
    // Issue #677 step 4: the same job re-checks that the build tooling stayed
    // out of the guest, and that gate is core-only for the same reason the
    // contract is.
    try source.expectOrder(
        build_job,
        "- name: Verify the explicit runtime contract",
        "- name: Verify the build/runtime separation",
        workflow_path,
    );
    try source.expectContainsIn(build_job, "build-runtime-split-verify", workflow_path);
    {
        const split_start = try source.indexOfIn(
            build_job,
            "- name: Verify the build/runtime separation",
            workflow_path,
        );
        const split_rest = build_job[split_start..];
        const split_step = split_rest[0 .. std.mem.indexOfPos(
            u8,
            split_rest,
            "- name: Verify".len,
            "- name:",
        ) orelse split_rest.len];
        try source.expectContainsIn(split_step, "if [ \"$FLAVOR\" != core ]", workflow_path);
    }
    // Only core carries the contract, so the step must be flavor-gated rather
    // than failing every full candidate on a document that does not exist.
    const start = try source.indexOfIn(
        build_job,
        "- name: Verify the explicit runtime contract",
        workflow_path,
    );
    const rest = build_job[start..];
    const step = rest[0 .. std.mem.indexOfPos(
        u8,
        rest,
        "- name: Verify".len,
        "- name:",
    ) orelse rest.len];
    try source.expectContainsIn(step, "if: matrix.flavor == 'core'", workflow_path);

    const native = try workflow.section("\n  native_qemu:\n", "\n  azure_acceptance:\n");
    try source.expectContainsIn(
        native,
        "MIZ_UBUNTU2604_FIRST_BOOT_INVENTORY=",
        workflow_path,
    );
    try source.expectContainsIn(
        native,
        "--require-phase root_build,image_build,publication,first_boot",
        workflow_path,
    );

    const azure = try workflow.section("\n  azure_acceptance:\n", null);
    try source.expectContainsIn(azure, "RUNTIME_CONTRACT_PROBE:", workflow_path);
    try source.expectContainsIn(
        azure,
        "zig build install-ubuntu2604-runtime-contract-probes",
        workflow_path,
    );
}

test "the build job re-validates the size inventory it measured" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try workflow.section("\n  build:\n", "\n  native_qemu:\n");
    try source.expectOrder(
        build_job,
        "- name: Validate standalone zstd QCOW2 and exact flavor size",
        "- name: Verify the reproducible size inventory",
        workflow_path,
    );
    try source.expectOrder(
        build_job,
        "- name: Verify the reproducible size inventory",
        "- name: Create and verify exact candidate bundle",
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
    // The candidate has been built, finalized, and published by this point,
    // so every phase up to publication must be present rather than optional.
    try source.expectContainsIn(
        step,
        "--require-phase root_build,image_build,publication",
        workflow_path,
    );
    // Issue #677 step 3: core is assembled from an exact closure, so its
    // unowned remainder is gated at zero. The full flavor inherits Canonical's
    // server root and is measured rather than gated, which is why the bound is
    // applied per flavor rather than unconditionally.
    try source.expectContainsIn(step, "--max-unexpected-unowned 0", workflow_path);
    try source.expectContainsIn(step, "if [ \"$FLAVOR\" = core ]; then", workflow_path);
    try source.expectContainsIn(step, "set -euo pipefail", workflow_path);
}

test "publication is gated on a reviewed size and content budget" {
    // Issue #677 step 6. Two independent enforcement points, because they
    // answer different questions: the per-candidate step re-derives the verdict
    // this build published, and the release gate refuses to publish any core
    // candidate whose architecture has only a recorded baseline.
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try workflow.section("\n  build:\n", "\n  native_qemu:\n");
    try source.expectOrder(
        build_job,
        "- name: Enforce the reviewed size and content budget",
        "- name: Create and verify exact candidate bundle",
        workflow_path,
    );
    const start = try source.indexOfIn(
        build_job,
        "- name: Enforce the reviewed size and content budget",
        workflow_path,
    );
    const rest = build_job[start..];
    const step = rest[0 .. std.mem.indexOfPos(
        u8,
        rest,
        "- name: Enforce".len,
        "- name:",
    ) orelse rest.len];
    try source.expectContainsIn(step, "size-budget-verify", workflow_path);
    try source.expectContainsIn(step, "--require-status enforced", workflow_path);
    try source.expectContainsIn(step, "ubuntu2604-size-budget-", workflow_path);
    try source.expectContainsIn(step, "if: matrix.flavor == 'core'", workflow_path);
    try source.expectContainsIn(step, "set -euo pipefail", workflow_path);

    const publish_job = try workflow.section("\n  publish:\n", null);
    try source.expectContainsIn(publish_job, "release-gate", workflow_path);
    try source.expectContainsIn(
        publish_job,
        "--require-size-budget enforced",
        workflow_path,
    );
    // The gate runs before anything is staged or published, which is the only
    // ordering that makes it a gate.
    try source.expectOrder(
        publish_job,
        "--require-size-budget enforced",
        "- name: Publish exactly four accepted Ubuntu assets",
        workflow_path,
    );
}

test "the build job validates the QCOW2 and publishes its metadata natively" {
    var workflow = try open();
    defer workflow.deinit();
    const build_job = try workflow.section("\n  build:\n", "\n  native_qemu:\n");
    const validate_start = try source.indexOfIn(
        build_job,
        "- name: Validate standalone zstd QCOW2 and exact flavor size",
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
    try source.expectContainsIn(
        validate,
        "--virtual-size-label \"$VIRTUAL_SIZE_LABEL\"",
        workflow_path,
    );
    try source.expectContainsIn(
        build_job,
        "-Dubuntu2604-flavor=\"$FLAVOR\"",
        workflow_path,
    );
    try source.expectContainsIn(build_job, "virtual_size: 5368709120", workflow_path);
    try source.expectContainsIn(build_job, "virtual_size_label: 5 GiB", workflow_path);
    // #677 step 5: the core rows carry no size. Their planned geometry is
    // published by the build and bound afterwards, so a size in the matrix
    // would be a second, unchecked source of truth.
    try source.expectContainsIn(build_job, "virtual_size: \"\"", workflow_path);
    try source.expectContainsIn(build_job, "virtual_size_label: \"\"", workflow_path);
    try source.expectOmitsIn(build_job, "3758096384", workflow_path);
    try source.expectContainsIn(
        build_job,
        "- name: Bind this flavor's virtual size",
        workflow_path,
    );
    try source.expectContainsIn(build_job, "disk-geometry-verify", workflow_path);
    try source.expectContainsIn(build_job, "FLAVOR: ${{ matrix.flavor }}", workflow_path);
    try source.expectOmitsIn(build_job, source.interpreter, workflow_path);
}

test "QEMU acceptance pins x86 KVM and hosted Arm TCG without fallback" {
    var workflow = try open();
    defer workflow.deinit();
    const native = try workflow.section("  native_qemu:", "  azure_acceptance:");
    const needles = [_][]const u8{
        "name: same-architecture QEMU (${{ matrix.accelerator }})",
        "timeout-minutes: ${{ matrix.timeout_minutes }}",
        "FLAVOR: ${{ matrix.flavor }}",
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
        "test \"$(uname -m)\" = \"$expected_uname\"",
        "test \"$(dpkg --print-architecture)\" = \"$expected_deb\"",
        "\"$RELEASE_TOOL\" kvm-api-version",
        "qemu-efi-aarch64 qemu-system-arm",
        "qemu=qemu-system-aarch64",
        "test \"$(command -v \"$qemu\")\" = \"$MIZ_UBUNTU2604_QEMU\"",
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
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, native, x86_row));
    try std.testing.expectEqual(@as(usize, 2), std.mem.count(u8, native, arm_row));

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

    var execution_source = try Source.open(
        std.testing.allocator,
        "scripts/ubuntu2604/execution.zig",
    );
    defer execution_source.deinit();
    try execution_source.expectContains(
        ".accelerator_argument = \"tcg,thread=multi\"",
    );
    try execution_source.expectContains(".cpu = \"max\"");
    try execution_source.expectContains(".job_minutes = 360");
    try execution_source.expectContains(
        ".initial_guest_launch = .serial_until_ready",
    );
    try execution_source.expectContains(".initial_guest_launch = .concurrent");
    try execution_source.expectOmits("accel=auto");

    var acceptance = try Source.open(
        std.testing.allocator,
        "tests/ubuntu2604_acceptance.zig",
    );
    defer acceptance.deinit();
    try acceptance.expectContains("\"q35,accel=kvm,smm=on\"");
    try acceptance.expectContains(
        "if (instance.execution_profile.accelerator == .tcg)",
    );
    try acceptance.expectContains("\"-accel\"");
    try acceptance.expectContains(
        "instance.execution_profile.accelerator_argument",
    );
    try acceptance.expectContains(
        "configured_execution.profile.initial_guest_launch",
    );
    try acceptance.expectContains(
        ".serial_until_ready => .{\n            .start_first,\n            .first_ready,\n            .start_second",
    );
    try acceptance.expectContains(
        ".concurrent => .{\n            .start_first,\n            .start_second,\n            .first_ready",
    );
    try acceptance.expectOmits("\"virt,accel=kvm\"");
    try acceptance.expectOmits("accel=auto");

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
    for ([_][]const u8{
        "ANDROID" ++ "_",
        "android_" ++ "smoke_secret",
        "prepare-" ++ "android",
        "/android-" ++ "smoke",
    }) |needle| try source.expectOmitsIn(native, needle, workflow_path);
}

test "Azure acceptance conditionally adds core Binder validation" {
    var workflow = try open();
    defer workflow.deinit();
    const azure = try workflow.section("  azure_acceptance:", "  publish:");
    const needles = [_][]const u8{
        "FLAVOR: ${{ matrix.flavor }}",
        "BINDER_PROBE: ${{ github.workspace }}/zig-out/bin/binder-probe-${{ matrix.key }}",
        "-target \"$ARCHITECTURE-linux\"",
        "-static",
        "tests/binder_probe.zig",
        "-femit-bin=\"$BINDER_PROBE\"",
        "test -x \"$BINDER_PROBE\"",
        "if: matrix.flavor == 'core'",
        "scripts/ubuntu2604_azure_acceptance.sh run",
    };
    for (needles) |needle| try source.expectContainsIn(azure, needle, workflow_path);
    for ([_][]const u8{
        "ANDROID" ++ "_",
        "android_" ++ "smoke_secret",
        "prepare-" ++ "android",
        "/android-" ++ "smoke",
    }) |needle| try source.expectOmitsIn(azure, needle, workflow_path);
    try source.expectOrder(
        azure,
        "- name: Build accepted-source miz",
        "- name: Build Binder device usability probe",
        workflow_path,
    );
    try source.expectOrder(
        azure,
        "- name: Build Binder device usability probe",
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
        "- name: Validate exact four-candidate release gate",
        workflow_path,
    );
    try source.expectContainsIn(publish, "test -x \"$RELEASE_TOOL\"", workflow_path);
}

test "Ubuntu documentation states the intentional Arm TCG contract" {
    var document = try Source.open(std.testing.allocator, "doc/ubuntu.md");
    defer document.deinit();
    for ([_][]const u8{
        "x86_64 KVM and AArch64 TCG",
        "exact GitHub-hosted `ubuntu-24.04-arm`",
        "`uname -m == aarch64`",
        "`arm64`, then install",
        "`-accel tcg,thread=multi`",
        "`-cpu max`",
        "never examines or changes `/dev/kvm`",
        "never calls the\nKVM API check",
        "neither GitHub-hosted Arm\nrunners nor an Azure-hosted CI alternative supplies Arm64 KVM",
        "Azure Trusted\nLaunch acceptance remains mandatory for all four candidates",
        "[#626](https://github.com/cataggar/miz/issues/626)",
        "[#627](https://github.com/cataggar/miz/issues/627)",
        "first Arm TCG guest\nreaches and passes",
        "before the second guest is launched",
        "KVM rows continue to launch both\ninitial guests concurrently",
        "`udisks2` remains installed and D-Bus activatable",
        "`graphical.target.wants/udisks2.service`",
    }) |needle| try document.expectContains(needle);
    try document.expectOmits("[self-hosted, Linux, ARM64, kvm]");
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
