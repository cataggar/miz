//! Contract tests for the dispatch-only Ubuntu 26.04 image benchmark workflow.
//!
//! Port of `tests/ubuntu2604_image_benchmark_workflow_test.py`. The workflow
//! is the only place the production benchmark protocol is spelled out for a
//! hosted runner, and several of its properties are security properties rather
//! than conveniences: it is manual and `main`-only, it holds no secrets and no
//! write permissions, its actions are pinned by commit, the measured runs are
//! sealed in a network namespace, and no private key material is ever inside
//! the uploaded artifact. Each of those is asserted here against the workflow's
//! own bytes, and the whole file is required to invoke no Python at all.

const std = @import("std");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const workflow_path = ".github/workflows/ubuntu2604-image-benchmark.yml";

/// The workflow is a few hundred lines; reaching this bound means the file
/// being read is not the workflow.
const max_workflow_bytes = 256 * 1024;

/// The exact actions the workflow may use, in order of appearance, each pinned
/// to a full commit SHA.
const pinned_actions = [_][]const u8{
    "actions/checkout@34e114876b0b11c390a56381ad16ebd13914f8d5",
    "cataggar/ghr/actions/install@7d8c3ef0886dd428a97727fce3b74909d6eace78",
    "actions/upload-artifact@ea165f8d65b6e75b540449e92b4886f43607fa02",
};

fn workflowSource(allocator: Allocator, io: Io) ![]u8 {
    const root = std.testing.environ.getAlloc(
        allocator,
        "MIZ_REPOSITORY_ROOT",
    ) catch |err| switch (err) {
        error.EnvironmentVariableMissing => try allocator.dupe(u8, "."),
        else => return err,
    };
    defer allocator.free(root);
    const path = try std.fs.path.join(allocator, &.{ root, workflow_path });
    defer allocator.free(path);
    return Dir.cwd().readFileAlloc(io, path, allocator, .limited(max_workflow_bytes));
}

fn section(source: []const u8, start: []const u8, end: ?[]const u8) ![]const u8 {
    const start_index = std.mem.indexOf(u8, source, start) orelse {
        std.debug.print("\nworkflow has no section starting at: {s}\n", .{start});
        return error.TestMissingSection;
    };
    const tail = source[start_index + start.len ..];
    const stop = end orelse return tail;
    const end_index = std.mem.indexOf(u8, tail, stop) orelse {
        std.debug.print("\nworkflow has no section ending at: {s}\n", .{stop});
        return error.TestMissingSection;
    };
    return tail[0..end_index];
}

fn expectContains(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) == null) {
        std.debug.print("\nworkflow is missing: {s}\n", .{needle});
        return error.TestExpectedContains;
    }
}

fn expectExcludes(haystack: []const u8, needle: []const u8) !void {
    if (std.mem.indexOf(u8, haystack, needle) != null) {
        std.debug.print("\nworkflow unexpectedly contains: {s}\n", .{needle});
        return error.TestExpectedExcludes;
    }
}

fn count(haystack: []const u8, needle: []const u8) usize {
    var found: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, index, needle)) |at| {
        found += 1;
        index = at + needle.len;
    }
    return found;
}

/// One job step, as the workflow declares it. The tests below reason about
/// step order and reachability, which is the only way to state the contract
/// that a failure early in the job still produces uploadable evidence.
const Step = struct {
    index: usize,
    name: []const u8,
    id: ?[]const u8,
    condition: ?[]const u8,
    body: []const u8,

    /// GitHub runs a step whose condition begins with `always()` even after an
    /// earlier step failed.
    fn runsAfterFailure(self: Step) bool {
        const condition = self.condition orelse return false;
        return std.mem.startsWith(u8, condition, "always()");
    }
};

const step_marker = "\n      - name: ";

fn parseSteps(allocator: Allocator, source: []const u8) ![]Step {
    var steps: std.ArrayList(Step) = .empty;
    errdefer steps.deinit(allocator);
    var search: usize = 0;
    while (std.mem.indexOfPos(u8, source, search, step_marker)) |at| {
        const name_start = at + step_marker.len;
        const name_end = std.mem.indexOfScalarPos(u8, source, name_start, '\n') orelse
            source.len;
        const body_end = std.mem.indexOfPos(u8, source, name_end, step_marker) orelse
            source.len;
        const body = source[name_end..body_end];
        try steps.append(allocator, .{
            .index = steps.items.len,
            .name = source[name_start..name_end],
            .id = fieldValue(body, "\n        id: "),
            .condition = fieldValue(body, "\n        if: "),
            .body = body,
        });
        search = name_end;
    }
    return steps.toOwnedSlice(allocator);
}

fn fieldValue(body: []const u8, marker: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, body, marker) orelse return null;
    const start = at + marker.len;
    const end = std.mem.indexOfScalarPos(u8, body, start, '\n') orelse body.len;
    return body[start..end];
}

fn requireStep(steps: []const Step, name: []const u8) !Step {
    for (steps) |step| {
        if (std.mem.eql(u8, step.name, name)) return step;
    }
    std.debug.print("\nworkflow has no step named: {s}\n", .{name});
    return error.TestMissingStep;
}

const build_step = "Build the benchmark tool and the miz CLI";

/// The only steps allowed to run before the benchmark tool exists. Each is
/// either the checkout itself or a precondition of building at all, and a
/// failure in any of them means there is no benchmark evidence to report.
const steps_before_the_tool = [_][]const u8{
    "Check out exact main source",
    "Bind the benchmark to current main",
    "Reclaim disposable hosted-runner tools",
    "Install Zig via ghr",
};

/// Steps whose failure must still produce an uploaded artifact. Every one of
/// them therefore has to run after the tool the gate and the evidence scan
/// invoke has been built.
const evidence_preserving_failures = [_][]const u8{
    "Preflight the staging disk",
    "Install benchmark host dependencies",
    "Prepare one fixed non-secret test identity",
    "Verify the test signer",
    "Stage verified publication inputs, exact locks, and warm debz cache",
    "Run one warm-up and three measured builds without networking",
};

const staging_step =
    "- name: Stage verified publication inputs, exact locks, and warm debz cache";
const measured_step =
    "- name: Run one warm-up and three measured builds without networking";
const gate_step = "- name: Record and enforce the production non-regression gate";
const private_step = "- name: Prove upload evidence excludes private key material";
const upload_step = "- name: Upload benchmark timing, provenance, and logs";
const cleanup_step = "- name: Remove benchmark state and private material";
const identity_step = "- name: Prepare one fixed non-secret test identity";
const signer_step = "- name: Verify the test signer";
const tool_step = "- name: " ++ build_step;

test "the benchmark workflow is manual, main-only, and native aarch64" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);

    const header = try section(source, "", "\njobs:\n");
    try expectContains(header, "workflow_dispatch:");
    try expectExcludes(header, "pull_request:");
    try expectExcludes(header, "push:");
    try expectContains(source, "github.ref == 'refs/heads/main'");
    try expectContains(source, "runs-on: ubuntu-24.04-arm");
    try expectContains(source, "timeout-minutes: 240");
    try expectContains(source, "test \"$(uname -m)\" = aarch64");
}

test "permissions and actions are minimal and pinned" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);

    const header = try section(source, "", "\njobs:\n");
    try expectContains(header, "permissions:\n  contents: read");
    try expectExcludes(source, "id-token: write");
    try expectExcludes(source, "environment:");
    try expectExcludes(source, "secrets.");

    var used: std.ArrayList([]const u8) = .empty;
    defer used.deinit(allocator);
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, "uses: ")) |at| {
        const rest = source[at + "uses: ".len ..];
        const length = std.mem.indexOfAny(u8, rest, " \t\r\n") orelse rest.len;
        try used.append(allocator, rest[0..length]);
        index = at + "uses: ".len + length;
    }
    try std.testing.expectEqual(pinned_actions.len, used.items.len);
    for (pinned_actions, used.items) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
        const separator = std.mem.lastIndexOfScalar(u8, actual, '@').?;
        const revision = actual[separator + 1 ..];
        try std.testing.expectEqual(@as(usize, 40), revision.len);
        for (revision) |character| switch (character) {
            '0'...'9', 'a'...'f' => {},
            else => return error.TestExpectedPinnedAction,
        };
    }
}

test "staging uses the production builder and verified exact inputs" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);
    const stage = try section(source, staging_step, measured_step);

    try expectContains(stage, "generalized-ubuntu2604 --");
    try expectContains(stage, "-Doptimize=ReleaseSafe");
    try expectContains(stage, "-Dubuntu2604-arch=aarch64");
    try expectContains(stage, "-Dubuntu2604-flavor=baremetal");
    try expectContains(stage, "--debz-cache \"$cache\"");
    try expectContains(stage, "cache=\"$INPUT_ROOT/debz-cache\"");
    try expectContains(stage, "debz_inputs=\"$INPUT_ROOT/debz-inputs\"");
    try expectContains(stage, "--debz-input-dir \"$debz_inputs\"");
    // The warm cache is used where it is staged: moving it would change the
    // Signed-By path the cache identity binds.
    try expectExcludes(stage, "mv \"$cache\"");
    try expectExcludes(stage, "--debz-lock-dir");
    try expectContains(stage, "debz-exact-lock-*-arm64.json");
    try expectContains(stage, "verify-staging --input-root \"$INPUT_ROOT\"");
    try expectContains(stage, "ubuntu-26.04-server-cloudimg-arm64.img");
    try expectContains(stage, "SHA256SUMS.gpg");
}

test "the measured protocol is offline and uses warm inputs" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);
    const measured = try section(source, measured_step, gate_step);

    try expectContains(measured, "/usr/bin/unshare --net --");
    try std.testing.expectEqual(
        @as(usize, 1),
        count(measured, "/usr/bin/unshare --net --"),
    );
    try expectContains(measured, "sudo -E /usr/bin/unshare --net --");
    try expectContains(measured, "\"$BENCHMARK_TOOL\" run");
    try expectContains(measured, "--debz-cache \"$INPUT_ROOT/debz-cache\"");
    try expectContains(measured, "--debz-input-dir \"$INPUT_ROOT/debz-inputs\"");
    try expectContains(measured, "--debz-lock-dir \"$INPUT_ROOT/locks\"");
    try expectContains(measured, "--signing-key \"$SIGNING_KEY\"");
    try expectExcludes(measured, "--keep-images");
    try expectExcludes(measured, "--acceptance-command");
    try expectContains(source, "NON_REGRESSION_CEILING_NS: \"530000000000\"");
}

test "the gate and the evidence scan are driven by the benchmark tool" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);

    // One stable, absolute path known before any step runs, rather than a
    // value handed forward through `$GITHUB_ENV` by a step that may not have
    // run yet.
    try expectContains(
        source,
        "BENCHMARK_TOOL: ${{ github.workspace }}/zig-out/bin/ubuntu2604-image-benchmark",
    );
    try expectExcludes(source, "BENCHMARK_BIN");

    const tool = try section(source, tool_step, "- name: Preflight the staging disk");
    try expectContains(tool, "install-ubuntu2604-image-benchmark");
    try expectContains(tool, "install-miz");
    try expectContains(tool, "test -x \"$BENCHMARK_TOOL\"");

    const gate = try section(source, gate_step, private_step);
    try expectContains(gate, "if: always()");
    try expectContains(gate, "\"$BENCHMARK_TOOL\" gate");
    try expectContains(gate, "--summary \"$BENCHMARK_OUTPUT/benchmark-summary.json\"");
    try expectContains(gate, "--status \"$BENCHMARK_OUTPUT/benchmark-status.json\"");
    try expectContains(gate, "--output \"$EVIDENCE_ROOT/non-regression-gate.json\"");
    try expectContains(gate, "--step-summary \"$GITHUB_STEP_SUMMARY\"");
    try expectContains(gate, "--ceiling-ns \"$NON_REGRESSION_CEILING_NS\"");

    const private = try section(source, private_step, upload_step);
    try expectContains(private, "id: private-material-check");
    try expectContains(private, "if: always()");
    try expectContains(private, "\"$BENCHMARK_TOOL\" scan-private-material");
    try expectContains(private, "--evidence-root \"$EVIDENCE_ROOT\"");
    try expectContains(private, "--benchmark-root \"$BENCHMARK_OUTPUT\"");
}

test "the benchmark tool is built before every step whose failure is reported" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);
    const steps = try parseSteps(allocator, source);
    defer allocator.free(steps);

    // A closed list, so a new failure-prone step cannot be added ahead of the
    // build without this test being updated to say why that is acceptable.
    try std.testing.expect(steps.len > steps_before_the_tool.len);
    for (steps_before_the_tool, 0..) |expected, index| {
        try std.testing.expectEqualStrings(expected, steps[index].name);
    }
    const tool = try requireStep(steps, build_step);
    try std.testing.expectEqual(steps_before_the_tool.len, tool.index);

    for (evidence_preserving_failures) |name| {
        const step = try requireStep(steps, name);
        try std.testing.expect(tool.index < step.index);
    }

    // Nothing before the build may already depend on the binary it produces.
    for (steps[0..tool.index]) |step| {
        try expectExcludes(step.body, "$BENCHMARK_TOOL");
    }
}

test "an early failure still reaches the gate, the scan, and the upload" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);
    const steps = try parseSteps(allocator, source);
    defer allocator.free(steps);

    const tool = try requireStep(steps, build_step);
    const gate = try requireStep(
        steps,
        "Record and enforce the production non-regression gate",
    );
    const scan = try requireStep(
        steps,
        "Prove upload evidence excludes private key material",
    );
    const upload = try requireStep(steps, "Upload benchmark timing, provenance, and logs");
    const cleanup = try requireStep(steps, "Remove benchmark state and private material");

    // Simulate each early failure: the job stops there, and GitHub then runs
    // only the `always()` steps. Each of those must be able to run the tool,
    // which means the build must already have happened.
    for (evidence_preserving_failures) |name| {
        const failed = try requireStep(steps, name);
        try std.testing.expect(tool.index < failed.index);
        for ([_]Step{ gate, scan, upload, cleanup }) |reachable| {
            try std.testing.expect(reachable.runsAfterFailure());
            try std.testing.expect(failed.index < reachable.index);
        }
        // The upload is still gated on the scan actually having succeeded.
        try std.testing.expectEqualStrings(
            "always() && steps.private-material-check.outcome == 'success'",
            upload.condition.?,
        );
    }

    // Partial evidence survives a disk failure because the reclaim step wrote
    // it before the threshold is ever tested.
    const reclaim = try requireStep(steps, "Reclaim disposable hosted-runner tools");
    try expectContains(reclaim.body, "disk-before-cleanup.txt");
    try expectContains(reclaim.body, "disk-after-cleanup.txt");
    try expectExcludes(reclaim.body, "STAGING_MINIMUM_FREE_BYTES");
    const preflight = try requireStep(steps, "Preflight the staging disk");
    try expectContains(preflight.body, "staging-disk-preflight.txt");
    try expectContains(
        preflight.body,
        "test \"$available\" -ge \"$STAGING_MINIMUM_FREE_BYTES\"",
    );
    try expectContains(upload.body, "${{ env.EVIDENCE_ROOT }}/");
    try expectContains(upload.body, "if-no-files-found: warn");
}

test "disk and artifact failure evidence are explicit" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);

    try expectContains(source, "STAGING_MINIMUM_FREE_BYTES: \"38654705664\"");
    try expectContains(source, "MEASURED_MINIMUM_FREE_BYTES: \"32212254720\"");
    const upload = try section(source, upload_step, cleanup_step);
    try expectContains(
        upload,
        "if: always() && steps.private-material-check.outcome == 'success'",
    );
    try expectContains(upload, "benchmark-status.json");
    try expectContains(upload, "benchmark-summary.json");
    try expectContains(upload, "run-*/evidence/");
    try expectContains(source, "staging-build.log");
}

test "the test signer is fixed and private material is not uploaded" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);

    const identity = try section(source, identity_step, signer_step);
    try expectContains(
        identity,
        "tests/fixtures/ubuntu2604-local-signing/signing-key.pem",
    );
    try expectContains(identity, "install -m 0600");
    try expectContains(identity, "ssh-keygen -q -t ed25519");
    try expectContains(
        source,
        "TEST_CERTIFICATE_SHA256: " ++
            "\"8ca3b80b1a2272a4f3a6d13246a65cfdd89764eb83beb8a0709e3cf591490279\"",
    );

    const upload = try section(source, upload_step, cleanup_step);
    try expectExcludes(upload, "SIGNING_ROOT");
    try expectExcludes(upload, "signing-key.pem");

    const cleanup = try section(source, cleanup_step, null);
    try expectContains(cleanup, "if: always()");
    try expectContains(cleanup, "\"$SIGNING_ROOT\"");
}

/// Spelled in halves so this test's own bytes are not counted as an
/// interpreter invocation by the Python inventory guard next to it.
const interpreter_name = "pyt" ++ "hon";

test "the benchmark workflow invokes no Python" {
    const allocator = std.testing.allocator;
    const source = try workflowSource(allocator, std.testing.io);
    defer allocator.free(source);
    const lowered = try std.ascii.allocLowerString(allocator, source);
    defer allocator.free(lowered);
    try expectExcludes(lowered, interpreter_name);
}
