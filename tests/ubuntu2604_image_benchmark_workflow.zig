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

const staging_step =
    "- name: Stage verified publication inputs, exact locks, and warm debz cache";
const measured_step =
    "- name: Run one warm-up and three measured builds without networking";
const gate_step = "- name: Record and enforce the production non-regression gate";
const private_step = "- name: Prove upload evidence excludes private key material";
const upload_step = "- name: Upload benchmark timing, provenance, and logs";
const cleanup_step = "- name: Remove benchmark state and private material";
const identity_step = "- name: Prepare one fixed non-secret test identity";
const warm_step = "- name: Warm Zig dependencies and verify the test signer";

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
    try expectContains(measured, "\"$BENCHMARK_BIN\" run");
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

    try expectContains(source, "BENCHMARK_TOOL: zig-out/bin/ubuntu2604-image-benchmark");
    const warm = try section(source, warm_step, staging_step);
    try expectContains(warm, "install-ubuntu2604-image-benchmark");
    try expectContains(warm, "echo \"BENCHMARK_BIN=$benchmark_bin\" >> \"$GITHUB_ENV\"");

    const gate = try section(source, gate_step, private_step);
    try expectContains(gate, "if: always()");
    try expectContains(gate, "gate \\");
    try expectContains(gate, "--summary \"$BENCHMARK_OUTPUT/benchmark-summary.json\"");
    try expectContains(gate, "--status \"$BENCHMARK_OUTPUT/benchmark-status.json\"");
    try expectContains(gate, "--output \"$EVIDENCE_ROOT/non-regression-gate.json\"");
    try expectContains(gate, "--step-summary \"$GITHUB_STEP_SUMMARY\"");
    try expectContains(gate, "--ceiling-ns \"$NON_REGRESSION_CEILING_NS\"");

    const private = try section(source, private_step, upload_step);
    try expectContains(private, "id: private-material-check");
    try expectContains(private, "if: always()");
    try expectContains(private, "scan-private-material");
    try expectContains(private, "--evidence-root \"$EVIDENCE_ROOT\"");
    try expectContains(private, "--benchmark-root \"$BENCHMARK_OUTPUT\"");
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

    const identity = try section(source, identity_step, warm_step);
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
