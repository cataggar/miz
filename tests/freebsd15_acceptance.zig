//! The FreeBSD 15.1 Azure acceptance harness contract, replacing
//! `tests/freebsd15_azure_acceptance_test.py`.
//!
//! The harness itself only runs against real Azure, so what can be tested here
//! is everything around that: the shell parses, fails closed on an unsupported
//! candidate, orders its gates so a VM is never created from an unreplicated
//! image, bounds every poll, and hands its metadata decisions to the ported
//! validator -- which is driven directly, against recorded Azure documents,
//! including every shape that must be refused.

const std = @import("std");
const freebsd15 = @import("freebsd15");
const support = @import("support");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Value = std.json.Value;
const Tree = support.Tree;

const script_path = "scripts/freebsd15_azure_acceptance.sh";
const workflow_path = ".github/workflows/freebsd15-release.yml";

fn harness(allocator: Allocator) ![]u8 {
    return support.readSource(allocator, script_path);
}

fn workflow(allocator: Allocator) ![]u8 {
    return support.readSource(allocator, workflow_path);
}

fn toolPath(allocator: Allocator, name: []const u8) ![]u8 {
    return std.testing.environ.getAlloc(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableMissing => error.MissingToolPath,
        else => return err,
    };
}

/// The three ported tools the harness resolves, spelled as shell assignments a
/// generated fragment can prepend.
fn toolEnvironment(allocator: Allocator) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        \\export MIZ_FREEBSD15_RELEASE_TOOL={s}
        \\export MIZ_FREEBSD15_AZURE_METADATA_TOOL={s}
        \\export MIZ_AZURE_VHD_TOOL={s}
        \\
    ,
        .{
            try toolPath(allocator, "MIZ_FREEBSD15_RELEASE_TOOL"),
            try toolPath(allocator, "MIZ_FREEBSD15_AZURE_METADATA_TOOL"),
            try toolPath(allocator, "MIZ_AZURE_VHD_TOOL"),
        },
    );
}

// ---- The script itself ----------------------------------------------------

test "the harness exists, is executable, and is valid bash" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const path = try support.sourcePath(tree.allocator(), script_path);

    const stat = try Dir.cwd().statFile(std.testing.io, path, .{});
    try std.testing.expectEqual(std.Io.File.Kind.file, stat.kind);
    try std.testing.expect(stat.permissions.toMode() & 0o100 != 0);

    var run = try support.runProcess(gpa, &.{ "bash", "-n", path });
    defer run.deinit(gpa);
    try std.testing.expectEqual(@as(u8, 0), run.code);
    try std.testing.expectEqualStrings("", run.stderr);
}

test "the harness runs under strict mode and has exactly two modes" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    try support.expectContains(source, "set -Eeuo pipefail");
    try support.expectContains(source, "\"$command_name\" == cleanup");
    try support.expectContains(source, "\"$command_name\" != run");
}

/// Runs the harness with an invalid mode so only the preflight identity checks
/// execute: a supported candidate reaches the usage exit, an unsupported one
/// is refused before anything else happens.
fn preflight(gpa: Allocator, tree: *Tree, candidate_key: []const u8) !u8 {
    const path = try support.sourcePath(tree.allocator(), script_path);
    const state_file = try tree.path(&.{"unused-state"});
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\{s}
        \\export STATE_FILE={s}
        \\export GITHUB_RUN_ID=123
        \\export GITHUB_RUN_ATTEMPT=1
        \\export CANDIDATE_KEY={s}
        \\{s} invalid-mode
    , .{
        try toolEnvironment(tree.allocator()),
        state_file,
        candidate_key,
        path,
    });
    var run = try support.runShell(gpa, "bash", script);
    defer run.deinit(gpa);
    return run.code;
}

test "the candidate key accepts every supported profile" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    for ([_][]const u8{ "x86_64", "aarch64" }) |architecture| {
        for ([_][]const u8{ "ufs-full", "ufs-core", "zfs-full", "zfs-core" }) |profile| {
            const key = try std.fmt.allocPrint(
                tree.allocator(),
                "{s}-{s}",
                .{ architecture, profile },
            );
            try std.testing.expectEqual(@as(u8, 2), try preflight(gpa, &tree, key));
        }
    }
}

test "the candidate key refuses unsupported profiles before anything runs" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    for ([_][]const u8{ "x86_64-ufs-minimal", "riscv64-ufs-core" }) |key| {
        try std.testing.expectEqual(@as(u8, 1), try preflight(gpa, &tree, key));
    }
}

test "the harness refuses to run without the ported tooling" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const path = try support.sourcePath(tree.allocator(), script_path);
    const absent = try tree.path(&.{"absent-tool"});
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\export MIZ_FREEBSD15_RELEASE_TOOL={s}
        \\export MIZ_FREEBSD15_AZURE_METADATA_TOOL={s}
        \\export MIZ_AZURE_VHD_TOOL={s}
        \\export STATE_FILE={s}
        \\export GITHUB_RUN_ID=123
        \\export GITHUB_RUN_ATTEMPT=1
        \\export CANDIDATE_KEY=x86_64-zfs-full
        \\{s} invalid-mode
    , .{ absent, absent, absent, absent, path });
    var run = try support.runShell(gpa, "bash", script);
    defer run.deinit(gpa);
    try std.testing.expectEqual(@as(u8, 1), run.code);
    try support.expectContains(run.stdout, "is unavailable");
}

// ---- Candidate binding and result contracts -------------------------------

test "the candidate manifest is validated canonically and re-validated" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());

    try support.expectContains(source, "\"$release_tool\" candidate-binding \\");
    for ([_][]const u8{
        "--manifest \"$manifest\"",
        "--asset \"$asset\"",
        "--key \"$CANDIDATE_KEY\"",
        "--source-commit \"$SOURCE_COMMIT\"",
        "--architecture \"$ARCHITECTURE\"",
        "--filesystem \"$FILESYSTEM\"",
        "--flavor \"$FLAVOR\"",
        "--asset-name \"$ASSET_NAME\"",
        "--run-id \"$GITHUB_RUN_ID\"",
        "--run-attempt \"$GITHUB_RUN_ATTEMPT\"",
    }) |argument| try support.expectContains(source, argument);

    var occurrences: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, "validate_candidate_binding")) |at| {
        occurrences += 1;
        index = at + 1;
    }
    try std.testing.expect(occurrences >= 3);
    try support.expectContains(source, "readarray -t result_candidate");
    try support.expectContains(
        source,
        "test \"${result_candidate[0]}\" = \"$qcow_sha256\"",
    );
    try support.expectContains(
        source,
        "test \"${result_candidate[1]}\" = \"$qcow_bytes\"",
    );
    try support.expectContains(
        source,
        "test \"${result_candidate[2]}\" = \"$qcow_allocated_size\"",
    );
    try support.expectContains(
        source,
        "test \"${result_candidate[3]}\" = \"$virtual_size\"",
    );
    try support.expectContains(
        source,
        "test \"${result_candidate[4]}\" = \"$candidate_architecture\"",
    );
}

test "the binding validator states every claim it refuses" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15/candidate.zig",
    );
    for ([_][]const u8{
        "candidate asset path does not match manifest",
        "candidate asset name mismatch",
        "candidate variant mismatch: expected {s}",
        "candidate architecture mismatch",
        "candidate filesystem mismatch",
        "candidate flavor mismatch",
        "unsupported candidate filesystem/flavor combination",
        "candidate compressed size is missing or invalid",
        "candidate allocated size is missing or invalid",
        "candidate virtual size is missing or invalid",
        "candidate source size is missing or invalid",
        "candidate package manifest is missing",
        "candidate package installed size is missing or invalid",
        "candidate package manifest content does not match",
        "candidate package manifest count does not match",
        "candidate package manifest installed size does not match",
        "candidate validation metadata is missing",
        "candidate validation runner does not match profile",
        "candidate validation workflow identity mismatch",
    }) |message| try support.expectContains(source, message);
    try support.expectContains(source, "{s}.packages.txt");
    try support.expectContains(source, "parsePackageManifest(context, manifest_file)");
    try support.expectContains(source, "verifyPackageManifest(");
}

test "ownership, resource naming, and the contract set are stable" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    try support.expectContains(source, "miz-owner=freebsd15-release");
    try support.expectContains(source, "miz-fb15-${GITHUB_RUN_ID}");
    try support.expectContains(
        source,
        "shared_contracts_before_storage=\"matching-architecture-gen2," ++
            "key-only-ssh,agent-ready,hn0-dhcp,serial-console\"",
    );
    try support.expectContains(
        source,
        "shared_contracts_after_storage=\"root-growth,gpt-healthy," ++
            "reboot-reconnect,instance-identity\"",
    );
    try support.expectContains(source, "filesystem_contracts=\"zfs-root,zpool-healthy\"");
    try support.expectContains(
        source,
        "filesystem_contracts=\"ufs-root,ufs-root-partition-growth," ++
            "ufs-root-filesystem-growth,no-os-disk-swap\"",
    );
    try support.expectContains(
        source,
        "contracts=\"$shared_contracts_before_storage,$filesystem_contracts," ++
            "$shared_contracts_after_storage\"",
    );

    // The established ZFS result contract is byte-for-byte what it was.
    const before = "matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp," ++
        "serial-console";
    const storage = "zfs-root,zpool-healthy";
    const after = "root-growth,gpt-healthy,reboot-reconnect,instance-identity";
    const expected = before ++ "," ++ storage ++ "," ++ after;
    try std.testing.expectEqualStrings(
        "matching-architecture-gen2,key-only-ssh,agent-ready,hn0-dhcp," ++
            "serial-console,zfs-root,zpool-healthy,root-growth,gpt-healthy," ++
            "reboot-reconnect,instance-identity",
        expected,
    );
    var writers: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(u8, source, index, "\"$release_tool\" azure-result")) |at| {
        writers += 1;
        index = at + 1;
    }
    try std.testing.expectEqual(@as(usize, 1), writers);
    try support.expectAbsent(source, "UFS result writer");
    try support.expectContains(source, "qcow_allocated_size");
    try support.expectContains(source, "qcow_bytes");
}

// ---- The serial console gate ----------------------------------------------

const SerialMetrics = struct {
    status: i64,
    attempts: i64,
    sleeps: i64,
    clock: i64,
};

fn parseMetrics(text: []const u8) !SerialMetrics {
    var metrics: SerialMetrics = .{
        .status = -1,
        .attempts = -1,
        .sleeps = -1,
        .clock = -1,
    };
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const split = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        const key = line[0..split];
        const value = try std.fmt.parseInt(i64, line[split + 1 ..], 10);
        if (std.mem.eql(u8, key, "status")) metrics.status = value;
        if (std.mem.eql(u8, key, "attempts")) metrics.attempts = value;
        if (std.mem.eql(u8, key, "sleeps")) metrics.sleeps = value;
        if (std.mem.eql(u8, key, "clock")) metrics.clock = value;
    }
    return metrics;
}

const SerialCase = struct {
    mode: []const u8,
    timeout_seconds: u32 = 3,
    delay_seconds: u32 = 1,
};

const SerialOutcome = struct {
    metrics: SerialMetrics,
    stderr: []u8,
    boot_log: ?[]u8,
    raw_log: ?[]u8,
};

fn runSerialConsoleCase(
    gpa: Allocator,
    tree: *Tree,
    case: SerialCase,
) !SerialOutcome {
    const source = try harness(tree.allocator());
    const blob_not_found =
        \\"<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>BlobNotFound</Code><Message>The specified blob does not exist.</Message></Error>"
    ;
    _ = try tree.write("serial/blob.json", blob_not_found ++ "\n");
    _ = try tree.write(
        "serial/valid.json",
        "\"FreeBSD 15.1-RELEASE kernel boot\\n\"",
    );
    _ = try tree.write(
        "serial/error.json",
        "{\"error\": {\"code\": \"UnexpectedAzureError\"}}",
    );
    const root = try tree.path(&.{"serial"});

    const script = try std.fmt.allocPrint(tree.allocator(),
        \\{s}
        \\set -u -o pipefail
        \\azure_metadata_tool=$MIZ_FREEBSD15_AZURE_METADATA_TOOL
        \\attempts=0
        \\sleeps=0
        \\clock=0
        \\SERIAL_ROOT={s}
        \\SERIAL_MODE={s}
        \\az() {{
        \\  attempts=$((attempts + 1))
        \\  case "$SERIAL_MODE" in
        \\    missing) return 1 ;;
        \\    empty) return 0 ;;
        \\    blob-then-valid)
        \\      if [[ "$attempts" -eq 1 ]]; then
        \\        cat "$SERIAL_ROOT/blob.json"
        \\      else
        \\        cat "$SERIAL_ROOT/valid.json"
        \\      fi
        \\      ;;
        \\    persistent-blob) cat "$SERIAL_ROOT/blob.json" ;;
        \\    structured-error) cat "$SERIAL_ROOT/error.json" ;;
        \\    no-marker) printf 'UEFI firmware initialized\nlogin: ' ;;
        \\    valid-json) cat "$SERIAL_ROOT/valid.json" ;;
        \\    valid-raw) printf 'FreeBSD 15.1-RELEASE kernel boot\n' ;;
        \\    *) return 2 ;;
        \\  esac
        \\}}
        \\sleep() {{
        \\  sleeps=$((sleeps + 1))
        \\  clock=$((clock + $1))
        \\}}
        \\boot_log=$SERIAL_ROOT/boot.log
        \\boot_log_candidate=$SERIAL_ROOT/boot.log.candidate
        \\boot_log_raw=$SERIAL_ROOT/boot.log.raw
        \\boot_log_stderr=$SERIAL_ROOT/boot.log.stderr
        \\resource_group=rg-test
        \\vm_name=vm-test
        \\{s}
        \\serial_console_epoch_seconds() {{
        \\  printf '%s\n' "$clock"
        \\}}
        \\set +e
        \\require_serial_console_log {d} {d}
        \\status=$?
        \\set -e
        \\printf 'status=%s\nattempts=%s\nsleeps=%s\nclock=%s\n' \
        \\  "$status" "$attempts" "$sleeps" "$clock"
    , .{
        try toolEnvironment(tree.allocator()),
        root,
        case.mode,
        try support.shellFunctionRun(
            tree.allocator(),
            source,
            "normalize_serial_console_response",
            4,
        ),
        case.timeout_seconds,
        case.delay_seconds,
    });

    var run = try support.runShell(gpa, "bash", script);
    errdefer run.deinit(gpa);
    const metrics = try parseMetrics(run.stdout);
    const boot_log = tree.read("serial/boot.log") catch null;
    const raw_log = tree.read("serial/boot.log.raw") catch null;
    gpa.free(run.stdout);
    return .{
        .metrics = metrics,
        .stderr = run.stderr,
        .boot_log = boot_log,
        .raw_log = raw_log,
    };
}

test "a blob that appears on retry succeeds without extra polling" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runSerialConsoleCase(gpa, &tree, .{ .mode = "blob-then-valid" });
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 0,
        .attempts = 2,
        .sleeps = 1,
        .clock = 1,
    }, outcome.metrics);
    try std.testing.expectEqualStrings(
        "FreeBSD 15.1-RELEASE kernel boot\n",
        outcome.boot_log.?,
    );
    try support.expectContains(outcome.raw_log.?, "FreeBSD 15.1-RELEASE kernel boot");
    try std.testing.expectEqualStrings("", outcome.stderr);
}

test "a persistently missing blob fails closed without inventing content" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runSerialConsoleCase(gpa, &tree, .{ .mode = "persistent-blob" });
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 1,
        .attempts = 3,
        .sleeps = 3,
        .clock = 3,
    }, outcome.metrics);
    try std.testing.expect(outcome.boot_log == null);
    try support.expectContains(outcome.raw_log.?, "BlobNotFound");
    try support.expectContains(
        outcome.stderr,
        "did not return real serial content after 3s and 3 attempts",
    );
    try support.expectContains(outcome.stderr, "blob is not available yet");
}

test "both JSON-quoted and raw FreeBSD serial logs are accepted" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "valid-json", "valid-raw" }) |mode| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const outcome = try runSerialConsoleCase(gpa, &tree, .{ .mode = mode });
        defer gpa.free(outcome.stderr);
        try std.testing.expectEqual(SerialMetrics{
            .status = 0,
            .attempts = 1,
            .sleeps = 0,
            .clock = 0,
        }, outcome.metrics);
        try std.testing.expectEqualStrings(
            "FreeBSD 15.1-RELEASE kernel boot\n",
            outcome.boot_log.?,
        );
        try std.testing.expect(outcome.raw_log.?.len > 0);
        try std.testing.expectEqualStrings("", outcome.stderr);
    }
}

test "real content without a FreeBSD marker fails closed" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runSerialConsoleCase(gpa, &tree, .{ .mode = "no-marker" });
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 1,
        .attempts = 3,
        .sleeps = 3,
        .clock = 3,
    }, outcome.metrics);
    try std.testing.expectEqualStrings(
        "UEFI firmware initialized\nlogin: ",
        outcome.boot_log.?,
    );
    try support.expectContains(
        outcome.stderr,
        "serial log is missing expected FreeBSD output",
    );
}

test "a structured Azure error is never mistaken for serial content" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runSerialConsoleCase(gpa, &tree, .{ .mode = "structured-error" });
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 1,
        .attempts = 3,
        .sleeps = 3,
        .clock = 3,
    }, outcome.metrics);
    try std.testing.expect(outcome.boot_log == null);
    try support.expectContains(outcome.raw_log.?, "UnexpectedAzureError");
    try support.expectContains(
        outcome.stderr,
        "structured error instead of serial content",
    );
}

test "a missing or empty serial log fails after bounded retries" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "missing", "empty" }) |mode| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const outcome = try runSerialConsoleCase(gpa, &tree, .{ .mode = mode });
        defer gpa.free(outcome.stderr);
        try std.testing.expectEqual(SerialMetrics{
            .status = 1,
            .attempts = 3,
            .sleeps = 3,
            .clock = 3,
        }, outcome.metrics);
        try std.testing.expect(outcome.boot_log == null);
        try support.expectContains(
            outcome.stderr,
            "did not return real serial content after 3s and 3 attempts",
        );
    }
}

test "the serial log timeout configuration requires positive integers" {
    const gpa = std.testing.allocator;
    for ([_][2]u32{ .{ 0, 1 }, .{ 3, 0 } }) |pair| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const outcome = try runSerialConsoleCase(gpa, &tree, .{
            .mode = "valid-raw",
            .timeout_seconds = pair[0],
            .delay_seconds = pair[1],
        });
        defer gpa.free(outcome.stderr);
        try std.testing.expectEqual(SerialMetrics{
            .status = 1,
            .attempts = 0,
            .sleeps = 0,
            .clock = 0,
        }, outcome.metrics);
        try support.expectContains(
            outcome.stderr,
            "Invalid Azure serial log timeout configuration",
        );
    }
}

test "failure-time collection preserves an existing serial log" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const existing = "FreeBSD existing useful serial log\n";
    _ = try tree.write("cleanup/boot.log", existing);
    const root = try tree.path(&.{"cleanup"});

    const script = try std.fmt.allocPrint(tree.allocator(),
        \\{s}
        \\set -u -o pipefail
        \\azure_metadata_tool=$MIZ_FREEBSD15_AZURE_METADATA_TOOL
        \\az() {{
        \\  printf '%s\n' '"<?xml version=\"1.0\" encoding=\"utf-8\"?><Error><Code>BlobNotFound</Code></Error>"'
        \\}}
        \\boot_log={s}/boot.log
        \\cleanup_boot_log={s}/boot.log.cleanup
        \\cleanup_boot_log_raw={s}/boot.log.cleanup.raw
        \\cleanup_boot_log_stderr={s}/boot.log.cleanup.stderr
        \\resource_group=rg-test
        \\vm_name=vm-test
        \\{s}
        \\collect_failure_boot_log
    , .{
        try toolEnvironment(tree.allocator()),
        root,
        root,
        root,
        root,
        try support.shellFunctionRun(
            tree.allocator(),
            source,
            "normalize_serial_console_response",
            2,
        ),
    });
    var run = try support.runShell(gpa, "bash", script);
    defer run.deinit(gpa);
    try std.testing.expectEqual(@as(u8, 0), run.code);
    try std.testing.expectEqualStrings("", run.stderr);
    try std.testing.expectEqualStrings(existing, try tree.read("cleanup/boot.log"));
    try support.expectContains(
        try tree.read("cleanup/boot.log.cleanup.raw"),
        "BlobNotFound",
    );
}

test "failed acceptance retains the raw serial console responses" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try workflow(tree.allocator());
    try support.expectContains(source, "${{ env.RESULT_DIR }}/boot.log*");
}

// ---- Image replication and boot diagnostics gates -------------------------

/// The four functions between the replication clock and the location lookup:
/// the two clocks and the two bounded waits.
fn replicationFunctions(allocator: Allocator, source: []const u8) ![]const u8 {
    _ = allocator;
    return support.between(
        source,
        "replication_epoch_seconds() {",
        "\nazure_location_display_name=$(",
    );
}

fn bootDiagnosticsFunctions(allocator: Allocator, source: []const u8) ![]const u8 {
    _ = allocator;
    return support.between(
        source,
        "boot_diagnostics_epoch_seconds() {",
        "\nwait_for_image_version_replication() {",
    );
}

const TextMetrics = struct {
    entries: []const [2][]const u8,

    fn get(self: TextMetrics, key: []const u8) []const u8 {
        for (self.entries) |entry| {
            if (std.mem.eql(u8, entry[0], key)) return entry[1];
        }
        return "<missing>";
    }
};

fn parseTextMetrics(allocator: Allocator, text: []const u8) !TextMetrics {
    var entries: std.ArrayList([2][]const u8) = .empty;
    var lines = std.mem.splitScalar(u8, text, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        const split = std.mem.indexOfScalar(u8, line, '=') orelse continue;
        try entries.append(allocator, .{
            try allocator.dupe(u8, line[0..split]),
            try allocator.dupe(u8, line[split + 1 ..]),
        });
    }
    return .{ .entries = entries.items };
}

fn runReplicationCase(
    gpa: Allocator,
    tree: *Tree,
    mode: []const u8,
    timeout_seconds: u32,
) !struct { metrics: TextMetrics, stderr: []u8 } {
    const source = try harness(tree.allocator());
    const fixtures = try support.sourcePath(
        tree.allocator(),
        "tests/fixtures/freebsd15_azure_replication",
    );
    const result = try tree.path(&.{"replication.json"});
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\{s}
        \\set -u -o pipefail
        \\azure_metadata_tool=$MIZ_FREEBSD15_AZURE_METADATA_TOOL
        \\attempts=0
        \\sleeps=0
        \\clock=0
        \\events=
        \\delays=
        \\FIXTURE_DIR={s}
        \\REPLICATION_MODE={s}
        \\az() {{
        \\  if [[ "$1 $2 ${{3:-}}" == "sig image-version show" ]]; then
        \\    case " $* " in
        \\      *" --expand ReplicationStatus "*) ;;
        \\      *) return 9 ;;
        \\    esac
        \\    attempts=$((attempts + 1))
        \\    events="${{events:+$events,}}show"
        \\    case "$REPLICATION_MODE" in
        \\      pending-completed)
        \\        if [[ "$attempts" -eq 1 ]]; then
        \\          fixture=replicating.json
        \\        else
        \\          fixture=completed.json
        \\        fi
        \\        ;;
        \\      failed) fixture=failed.json ;;
        \\      missing-region) fixture=missing-region.json ;;
        \\      whitespace-mismatch) fixture=whitespace-mismatch.json ;;
        \\      timeout) fixture=replicating.json ;;
        \\      *) return 8 ;;
        \\    esac
        \\    cat "$FIXTURE_DIR/$fixture"
        \\    return
        \\  fi
        \\  if [[ "$1 $2" == "vm create" ]]; then
        \\    events="${{events:+$events,}}vm"
        \\    return
        \\  fi
        \\  return 7
        \\}}
        \\sleep() {{
        \\  sleeps=$((sleeps + 1))
        \\  delays="${{delays:+$delays,}}$1"
        \\  clock=$((clock + $1))
        \\}}
        \\{s}
        \\replication_epoch_seconds() {{
        \\  printf '%s\n' "$clock"
        \\}}
        \\resource_group=rg-test
        \\gallery_name=gallery-test
        \\image_definition_name=image-test
        \\image_version=1.0.0
        \\AZURE_LOCATION=westus2
        \\azure_location_display_name="West US 2"
        \\image_replication_json={s}
        \\wait_for_image_version_replication {d} 1 2
        \\status=$?
        \\if [[ "$status" -eq 0 ]]; then
        \\  az vm create
        \\fi
        \\printf 'status=%s\nattempts=%s\nsleeps=%s\nclock=%s\n' \
        \\  "$status" "$attempts" "$sleeps" "$clock"
        \\printf 'delays=%s\nevents=%s\n' "$delays" "$events"
    , .{
        try toolEnvironment(tree.allocator()),
        fixtures,
        mode,
        try replicationFunctions(tree.allocator(), source),
        result,
        timeout_seconds,
    });

    var run = try support.runShell(gpa, "bash", script);
    errdefer run.deinit(gpa);
    const metrics = try parseTextMetrics(tree.allocator(), run.stdout);
    gpa.free(run.stdout);
    return .{ .metrics = metrics, .stderr = run.stderr };
}

test "replication must complete before a VM is created" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runReplicationCase(gpa, &tree, "pending-completed", 5);
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqualStrings("0", outcome.metrics.get("status"));
    try std.testing.expectEqualStrings("2", outcome.metrics.get("attempts"));
    try std.testing.expectEqualStrings("1", outcome.metrics.get("sleeps"));
    try std.testing.expectEqualStrings("1", outcome.metrics.get("clock"));
    try std.testing.expectEqualStrings("1", outcome.metrics.get("delays"));
    try std.testing.expectEqualStrings("show,show,vm", outcome.metrics.get("events"));
    try std.testing.expectEqualStrings("", outcome.stderr);
}

test "a failed or missing replication region blocks the VM with diagnostics" {
    const gpa = std.testing.allocator;
    const cases = [_]struct {
        mode: []const u8,
        needles: []const []const u8,
    }{
        .{
            .mode = "failed",
            .needles = &.{ "replication to westus2 failed", "Replica copy failed" },
        },
        .{
            .mode = "missing-region",
            .needles = &.{
                "does not include target region 'westus2'",
                "invalid regional image replication status",
            },
        },
        .{
            .mode = "whitespace-mismatch",
            .needles = &.{
                "'West  US 2'",
                "does not include target region 'westus2'",
            },
        },
    };
    for (cases) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const outcome = try runReplicationCase(gpa, &tree, case.mode, 5);
        defer gpa.free(outcome.stderr);
        try std.testing.expectEqualStrings("1", outcome.metrics.get("status"));
        try std.testing.expectEqualStrings("show", outcome.metrics.get("events"));
        try std.testing.expectEqualStrings("0", outcome.metrics.get("sleeps"));
        for (case.needles) |needle| try support.expectContains(outcome.stderr, needle);
    }
}

test "the replication wait uses bounded exponential backoff" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runReplicationCase(gpa, &tree, "timeout", 3);
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqualStrings("1", outcome.metrics.get("status"));
    try std.testing.expectEqualStrings("2", outcome.metrics.get("attempts"));
    try std.testing.expectEqualStrings("2", outcome.metrics.get("sleeps"));
    try std.testing.expectEqualStrings("3", outcome.metrics.get("clock"));
    try std.testing.expectEqualStrings("1,2", outcome.metrics.get("delays"));
    try std.testing.expectEqualStrings("show,show", outcome.metrics.get("events"));
    try support.expectContains(outcome.stderr, "Timed out after 3s");
    try support.expectContains(outcome.stderr, "last state=Replicating");
}

fn runBootDiagnosticsCase(
    gpa: Allocator,
    tree: *Tree,
    mode: []const u8,
    timeout_seconds: u32,
) !struct { metrics: SerialMetrics, stderr: []u8 } {
    const source = try harness(tree.allocator());
    _ = try tree.write("diagnostics/pending.json", "{\"diagnosticsProfile\": null}");
    _ = try tree.write("diagnostics/ready.json",
        \\{"diagnosticsProfile": {"bootDiagnostics": {"enabled": true, "storageUri": null}}}
    );
    _ = try tree.write("diagnostics/custom.json",
        \\{"diagnosticsProfile": {"bootDiagnostics": {"enabled": true,
        \\ "storageUri": "https://custom.blob.core.windows.net/"}}}
    );
    _ = try tree.write("diagnostics/malformed.json",
        \\{"diagnosticsProfile": {"bootDiagnostics": []}}
    );
    const root = try tree.path(&.{"diagnostics"});

    const script = try std.fmt.allocPrint(tree.allocator(),
        \\{s}
        \\set -u -o pipefail
        \\azure_metadata_tool=$MIZ_FREEBSD15_AZURE_METADATA_TOOL
        \\attempts=0
        \\sleeps=0
        \\clock=0
        \\BOOT_DIAGNOSTICS_ROOT={s}
        \\BOOT_DIAGNOSTICS_MODE={s}
        \\az() {{
        \\  [[ "$1 $2" == "vm show" ]] || return 8
        \\  attempts=$((attempts + 1))
        \\  case "$BOOT_DIAGNOSTICS_MODE" in
        \\    pending-ready)
        \\      if [[ "$attempts" -eq 1 ]]; then fixture=pending.json; else fixture=ready.json; fi
        \\      ;;
        \\    timeout) fixture=pending.json ;;
        \\    custom-storage) fixture=custom.json ;;
        \\    malformed) fixture=malformed.json ;;
        \\    api-failure)
        \\      printf 'synthetic Azure API failure\n' >&2
        \\      return 1
        \\      ;;
        \\    *) return 7 ;;
        \\  esac
        \\  cat "$BOOT_DIAGNOSTICS_ROOT/$fixture"
        \\}}
        \\sleep() {{
        \\  sleeps=$((sleeps + 1))
        \\  clock=$((clock + $1))
        \\}}
        \\{s}
        \\boot_diagnostics_epoch_seconds() {{
        \\  printf '%s\n' "$clock"
        \\}}
        \\resource_group=rg-test
        \\vm_name=vm-test
        \\vm_json=$BOOT_DIAGNOSTICS_ROOT/vm.json
        \\vm_show_stderr=$BOOT_DIAGNOSTICS_ROOT/vm-show.stderr
        \\wait_for_managed_boot_diagnostics {d} 1
        \\status=$?
        \\printf 'status=%s\nattempts=%s\nsleeps=%s\nclock=%s\n' \
        \\  "$status" "$attempts" "$sleeps" "$clock"
    , .{
        try toolEnvironment(tree.allocator()),
        root,
        mode,
        try bootDiagnosticsFunctions(tree.allocator(), source),
        timeout_seconds,
    });

    var run = try support.runShell(gpa, "bash", script);
    errdefer run.deinit(gpa);
    const metrics = try parseMetrics(run.stdout);
    gpa.free(run.stdout);
    return .{ .metrics = metrics, .stderr = run.stderr };
}

test "managed boot diagnostics become ready without extra polling" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runBootDiagnosticsCase(gpa, &tree, "pending-ready", 3);
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 0,
        .attempts = 2,
        .sleeps = 1,
        .clock = 1,
    }, outcome.metrics);
    try std.testing.expectEqualStrings("", outcome.stderr);
}

test "the managed boot diagnostics wait is bounded and reports what it saw" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runBootDiagnosticsCase(gpa, &tree, "timeout", 3);
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 1,
        .attempts = 3,
        .sleeps = 3,
        .clock = 3,
    }, outcome.metrics);
    try support.expectContains(outcome.stderr, "Timed out after 3s and 3 attempts");
    try support.expectContains(outcome.stderr, "\"diagnosticsProfile\": null");
}

test "custom or malformed boot diagnostics metadata fails closed" {
    const gpa = std.testing.allocator;
    for ([_][2][]const u8{
        .{ "custom-storage", "storageUri must be absent or null" },
        .{ "malformed", "bootDiagnostics is not an object" },
    }) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const outcome = try runBootDiagnosticsCase(gpa, &tree, case[0], 3);
        defer gpa.free(outcome.stderr);
        try std.testing.expectEqual(SerialMetrics{
            .status = 1,
            .attempts = 1,
            .sleeps = 0,
            .clock = 0,
        }, outcome.metrics);
        try support.expectContains(outcome.stderr, case[1]);
        try support.expectContains(
            outcome.stderr,
            "invalid managed boot diagnostics metadata",
        );
    }
}

test "a boot diagnostics timeout reports the latest API failure" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const outcome = try runBootDiagnosticsCase(gpa, &tree, "api-failure", 3);
    defer gpa.free(outcome.stderr);
    try std.testing.expectEqual(SerialMetrics{
        .status = 1,
        .attempts = 3,
        .sleeps = 3,
        .clock = 3,
    }, outcome.metrics);
    try support.expectContains(
        outcome.stderr,
        "Latest Azure VM metadata API diagnostics",
    );
    try support.expectContains(outcome.stderr, "synthetic Azure API failure");
}

test "the Azure location display name resolves exactly once" {
    const gpa = std.testing.allocator;
    const cases = [_]struct {
        mode: []const u8,
        location: []const u8,
        status: []const u8,
        display_name: []const u8,
        needle: ?[]const u8,
    }{
        .{
            .mode = "success",
            .location = "swedencentral",
            .status = "0",
            .display_name = "Sweden Central",
            .needle = null,
        },
        .{
            .mode = "success",
            .location = "swedencentral2",
            .status = "1",
            .display_name = "",
            .needle = "0 exact canonical matches for 'swedencentral2'",
        },
        .{
            .mode = "query-failure",
            .location = "swedencentral",
            .status = "1",
            .display_name = "",
            .needle = "Could not query Azure location metadata",
        },
    };
    for (cases) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const source = try harness(tree.allocator());
        const fixture = try support.sourcePath(
            tree.allocator(),
            "tests/fixtures/freebsd15_azure_locations.json",
        );
        const script = try std.fmt.allocPrint(tree.allocator(),
            \\{s}
            \\set -u -o pipefail
            \\azure_metadata_tool=$MIZ_FREEBSD15_AZURE_METADATA_TOOL
            \\LOCATION_MODE={s}
            \\az() {{
            \\  [[ "$*" == "account list-locations --output json" ]] || return 8
            \\  [[ "$LOCATION_MODE" != query-failure ]] || return 1
            \\  cat {s}
            \\}}
            \\{s}
            \\display_name=$(
            \\  resolve_azure_location_display_name {s} {s}
            \\)
            \\status=$?
            \\printf 'status=%s\ndisplay_name=%s\n' "$status" "$display_name"
        , .{
            try toolEnvironment(tree.allocator()),
            case.mode,
            fixture,
            try support.shellFunction(
                tree.allocator(),
                source,
                "resolve_azure_location_display_name",
            ),
            try tree.path(&.{"locations.json"}),
            case.location,
        });
        var run = try support.runShell(gpa, "bash", script);
        defer run.deinit(gpa);
        const metrics = try parseTextMetrics(tree.allocator(), run.stdout);
        try std.testing.expectEqualStrings(case.status, metrics.get("status"));
        try std.testing.expectEqualStrings(
            case.display_name,
            metrics.get("display_name"),
        );
        if (case.needle) |needle| {
            try support.expectContains(run.stderr, needle);
        } else {
            try std.testing.expectEqualStrings("", run.stderr);
        }
    }
}

// ---- Azure resource metadata validation -----------------------------------

fn jsonText(allocator: Allocator, value: Value) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    var stringify: std.json.Stringify = .{ .writer = &out.writer, .options = .{} };
    try stringify.write(value);
    return out.written();
}

/// Materializes one recorded fixture case: the base Azure document with the
/// case's removals and replacements applied.
fn fixtureCase(
    tree: *Tree,
    fixture_relative: []const u8,
    case_name: []const u8,
) ![]const u8 {
    const raw = try support.readSource(tree.allocator(), fixture_relative);
    const parsed = try std.json.parseFromSlice(Value, tree.allocator(), raw, .{});
    const base = parsed.value.object.get("base").?;
    const path = try tree.write("metadata.json", try jsonText(tree.allocator(), base));

    const case = parsed.value.object.get("cases").?.object.get(case_name).?.object;
    if (case.get("remove")) |removals| {
        for (removals.array.items) |item| {
            try support.mutateDocument(tree, path, item.string, null);
        }
    }
    if (case.get("set")) |assignments| {
        var entries = assignments.object.iterator();
        while (entries.next()) |entry| {
            try support.mutateDocument(
                tree,
                path,
                entry.key_ptr.*,
                try jsonText(tree.allocator(), entry.value_ptr.*),
            );
        }
    }
    return path;
}

const disk_id = "/subscriptions/test/resourceGroups/rg-test/providers/" ++
    "Microsoft.Compute/disks/disk-test";
const image_version_id = "/subscriptions/test/resourceGroups/rg-test/providers/" ++
    "Microsoft.Compute/galleries/gallery-test/images/image-test/versions/1.0.0";
const vm_id = "/subscriptions/test/resourceGroups/rg-test/providers/" ++
    "Microsoft.Compute/virtualMachines/vm-test";

fn runMetadata(
    gpa: Allocator,
    tree: *Tree,
    arguments: []const []const u8,
) !support.Run {
    const tool = try toolPath(tree.allocator(), "MIZ_FREEBSD15_AZURE_METADATA_TOOL");
    var argv: std.ArrayList([]const u8) = .empty;
    try argv.append(tree.allocator(), tool);
    try argv.appendSlice(tree.allocator(), arguments);
    return support.runProcess(gpa, argv.items);
}

fn runSizeCase(
    gpa: Allocator,
    tree: *Tree,
    command: []const u8,
    fixture_relative: []const u8,
    case_name: []const u8,
) !support.Run {
    const path = try fixtureCase(tree, fixture_relative, case_name);
    if (std.mem.eql(u8, command, "managed-disk")) {
        return runMetadata(gpa, tree, &.{
            "managed-disk", path,            disk_id, "disk-test",
            "rg-test",      "swedencentral", "x64",   "9",
        });
    }
    if (std.mem.eql(u8, command, "gallery-image-version")) {
        return runMetadata(gpa, tree, &.{
            "gallery-image-version", path,
            image_version_id,        "1.0.0",
            "rg-test",               "swedencentral",
            "Sweden Central",        disk_id,
            "9",
        });
    }
    return runMetadata(gpa, tree, &.{
        "vm",        path,            vm_id,             "vm-test",
        "rg-test",   "swedencentral", "Standard_D2s_v5", image_version_id,
        "azureuser", "x64",           "9",
    });
}

test "managed disk size metadata is accepted in every shape Azure reports" {
    const gpa = std.testing.allocator;
    const fixture = "tests/fixtures/freebsd15_azure_managed_disk_sizes.json";
    for ([_][]const u8{ "bytes-only", "gib-only", "both-consistent" }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "managed-disk", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expectEqual(@as(u8, 0), run.code);
        try std.testing.expectEqualStrings("", run.stderr);
        try support.expectContains(run.stdout, disk_id);
    }
    for ([_][]const u8{ "both-inconsistent", "missing", "wrong-size" }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "managed-disk", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expect(run.code != 0);
        try support.expectContains(run.stderr, "managed disk expansion size");
        try support.expectContains(run.stderr, "expected 9 GiB (9663676416 bytes)");
    }

    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var inconsistent = try runSizeCase(
        gpa,
        &tree,
        "managed-disk",
        fixture,
        "both-inconsistent",
    );
    defer inconsistent.deinit(gpa);
    try support.expectContains(inconsistent.stderr, "\"diskSizeBytes\": 9663676416");
    try support.expectContains(inconsistent.stderr, "\"diskSizeGb\": 8");
}

test "gallery image-version size and exact managed-disk source are bound" {
    const gpa = std.testing.allocator;
    const fixture = "tests/fixtures/freebsd15_azure_gallery_sizes.json";
    for ([_][]const u8{
        "bytes-only",
        "gib-only",
        "both-consistent",
        "missing",
    }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "gallery-image-version", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expectEqual(@as(u8, 0), run.code);
        try std.testing.expectEqualStrings("", run.stderr);
    }
    for ([_][]const u8{ "both-inconsistent", "wrong-size" }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "gallery-image-version", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expect(run.code != 0);
        try support.expectContains(
            run.stderr,
            "gallery image-version OS disk size mismatch",
        );
        try support.expectContains(run.stderr, "expected 9 GiB (9663676416 bytes)");
    }

    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var missing = try runSizeCase(
        gpa,
        &tree,
        "gallery-image-version",
        fixture,
        "missing-size-and-source",
    );
    defer missing.deinit(gpa);
    try std.testing.expect(missing.code != 0);
    try support.expectContains(
        missing.stderr,
        "does not expose the exact managed disk source",
    );
    try support.expectContains(missing.stderr, "osDiskImage keys");
}

test "VM OS disk size metadata is accepted in every shape Azure reports" {
    const gpa = std.testing.allocator;
    const fixture = "tests/fixtures/freebsd15_azure_vm_sizes.json";
    for ([_][]const u8{ "bytes-only", "gib-only", "both-consistent" }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "vm", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expectEqual(@as(u8, 0), run.code);
        try std.testing.expectEqualStrings("", run.stderr);
        try support.expectContains(run.stdout, vm_id);
    }
    for ([_][]const u8{ "both-inconsistent", "missing", "wrong-size" }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "vm", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expect(run.code != 0);
        try support.expectContains(run.stderr, "VM OS disk size");
        try support.expectContains(run.stderr, "expected 9 GiB (9663676416 bytes)");
    }

    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var wrong = try runSizeCase(gpa, &tree, "vm", fixture, "wrong-size");
    defer wrong.deinit(gpa);
    try support.expectContains(
        wrong.stderr,
        "\"managedDisk.sizeInBytes\": 8589934592",
    );
}

test "VM managed boot diagnostics policy fails closed" {
    const gpa = std.testing.allocator;
    const fixture = "tests/fixtures/freebsd15_azure_vm_sizes.json";
    for ([_][]const u8{
        "boot-storage-empty",
        "boot-storage-custom",
        "boot-disabled",
        "boot-profile-missing",
    }) |case_name| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runSizeCase(gpa, &tree, "vm", fixture, case_name);
        defer run.deinit(gpa);
        try std.testing.expect(run.code != 0);
        try support.expectContains(
            run.stderr,
            "VM managed boot diagnostics policy mismatch",
        );
    }
}

fn runGalleryCase(
    gpa: Allocator,
    tree: *Tree,
    sharing_text: ?[]const u8,
) !support.Run {
    const gallery_id = "/subscriptions/test/resourceGroups/rg-test/providers/" ++
        "Microsoft.Compute/galleries/gallery-test";
    const sharing = if (sharing_text) |text|
        try std.fmt.allocPrint(tree.allocator(), ", \"sharingProfile\": {s}", .{text})
    else
        "";
    const document_text = try std.fmt.allocPrint(tree.allocator(),
        \\{{"id": "{s}", "name": "gallery-test", "resourceGroup": "rg-test",
        \\ "location": "swedencentral", "type": "Microsoft.Compute/galleries",
        \\ "provisioningState": "Succeeded"{s}}}
    , .{ gallery_id, sharing });
    const path = try tree.write("gallery.json", document_text);
    return runMetadata(gpa, tree, &.{
        "gallery", path, gallery_id, "gallery-test", "rg-test", "swedencentral",
    });
}

test "a default private gallery may omit its sharing metadata" {
    const gpa = std.testing.allocator;
    for ([_]?[]const u8{
        null,
        "null",
        "{}",
        "{\"permissions\": \"Private\"}",
    }) |sharing| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runGalleryCase(gpa, &tree, sharing);
        defer run.deinit(gpa);
        try std.testing.expectEqual(@as(u8, 0), run.code);
        try std.testing.expectEqualStrings("", run.stderr);
    }
}

test "a shared gallery fails closed" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{
        "\"Private\"",
        "{\"permissions\": \"Groups\"}",
        "{\"permissions\": \"Community\"}",
        "{\"permissions\": \"Shared\"}",
        "{\"permissions\": \"Private\", \"groups\": [{\"type\": \"Subscriptions\"}]}",
        "{\"permissions\": \"Private\", \"communityGalleryInfo\": {\"published\": true}}",
    }) |sharing| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runGalleryCase(gpa, &tree, sharing);
        defer run.deinit(gpa);
        try std.testing.expect(run.code != 0);
        try support.expectContains(run.stderr, "temporary gallery");
    }
}

test "the harness delegates gallery image-version validation to the tool" {
    const gpa = std.testing.allocator;
    for ([_][2][]const u8{
        .{ "tests/fixtures/freebsd15_azure_image_version.json", "" },
        .{
            "tests/fixtures/freebsd15_azure_image_version_mismatch.json",
            "gallery image-version target location mismatch",
        },
    }) |case| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        const source = try harness(tree.allocator());
        const fixture = try support.sourcePath(tree.allocator(), case[0]);
        const script = try std.fmt.allocPrint(tree.allocator(),
            \\{s}
            \\set -u -o pipefail
            \\azure_metadata_tool=$MIZ_FREEBSD15_AZURE_METADATA_TOOL
            \\{s}
            \\validate_gallery_image_version_metadata \
            \\  {s} "{s}" 1.0.0 rg-test swedencentral "Sweden Central" "{s}" 8
            \\status=$?
            \\printf 'status=%s\n' "$status"
        , .{
            try toolEnvironment(tree.allocator()),
            try support.shellFunction(
                tree.allocator(),
                source,
                "validate_gallery_image_version_metadata",
            ),
            fixture,
            image_version_id,
            disk_id,
        });
        var run = try support.runShell(gpa, "bash", script);
        defer run.deinit(gpa);
        if (case[1].len == 0) {
            try support.expectContains(run.stdout, "status=0");
            try std.testing.expectEqualStrings("", run.stderr);
        } else {
            try support.expectContains(run.stdout, "status=1");
            try support.expectContains(run.stderr, case[1]);
        }
    }
}

// ---- Gate ordering and resource ownership ---------------------------------

test "the serial console gate follows reconnect and precedes the result" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());

    const definition = try support.indexOf(source, "require_serial_console_log() {");
    const invocation = try support.indexFrom(
        source,
        "\nrequire_serial_console_log\n",
        definition,
    );
    const reboot = try support.indexFrom(
        source,
        "\nreboot_and_reconnect\n",
        invocation - 200,
    );
    const pre_identity = try support.indexOf(source, "pre_reboot_hostkey=");
    const post_identity = try support.indexFrom(
        source,
        "post_reboot_hostkey=",
        invocation,
    );
    const result_writer = try support.indexFrom(
        source,
        "\"$release_tool\" azure-result",
        invocation,
    );
    const cleanup_trap = try support.indexOf(source, "trap cleanup_on_exit EXIT");
    try std.testing.expect(cleanup_trap < pre_identity);
    try std.testing.expect(pre_identity < reboot);
    try std.testing.expect(reboot < invocation);
    try std.testing.expect(invocation < post_identity);
    try std.testing.expect(invocation < result_writer);
    try support.expectContains(source, "if ! cleanup_group; then");
    try support.expectAbsent(source, "::warning::Azure managed boot diagnostics");
}

test "the derived VHD is validated from its footer and never retained" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    try support.expectContains(source, "rm -f -- \"$vhd\"");
    try support.expectContains(source, "\"$azure_vhd_tool\" verify \\");
    try support.expectContains(source, "vhd_current_size=${vhd_geometry[0]}");
    try support.expectContains(
        source,
        "test \"$vhd_bytes\" -eq \"$((vhd_current_size + 512))\"",
    );
    try support.expectAbsent(source, "f.seek(virtual_size)");
    try support.expectAbsent(source, "file size == virtual size + 512");
    try support.expectContains(
        source,
        "expanded_size_gib=$(((vhd_current_size + 1073741823) / 1073741824 + 2))",
    );
    try support.expectContains(source, "--vhd-current-size \"$vhd_current_size\"");
    try support.expectContains(source, "--hyper-v-generation V2");
    try support.expectContains(source, "az disk update");
    try support.expectContains(source, "--size-gb");
}

test "the architecture profile maps exactly for the gallery definition" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const mapping = try support.shellFunction(
        tree.allocator(),
        source,
        "set_architecture_profile",
    );
    try support.expectContains(mapping,
        \\aarch64)
        \\      short_arch=arm64
        \\      expected_azure_architecture=Arm64
        \\      runtime_architecture=aarch64
        \\      azure_image_architecture=Arm64
    );
    try support.expectContains(mapping,
        \\x86_64)
        \\      short_arch=x64
        \\      expected_azure_architecture=x64
        \\      runtime_architecture=amd64
        \\      azure_image_architecture=x64
    );

    const script = try std.fmt.allocPrint(tree.allocator(),
        \\set -u
        \\{s}
        \\for architecture in aarch64 x86_64; do
        \\  set_architecture_profile "$architecture"
        \\  printf '%s:%s:%s:%s:%s\n' "$architecture" "$short_arch" \
        \\    "$expected_azure_architecture" "$runtime_architecture" \
        \\    "$azure_image_architecture"
        \\done
    , .{mapping});
    var run = try support.runShell(gpa, "/bin/sh", script);
    defer run.deinit(gpa);
    try std.testing.expectEqualStrings(
        "aarch64:arm64:Arm64:aarch64:Arm64\nx86_64:x64:x64:amd64:x64\n",
        run.stdout,
    );
}

test "the gallery definition and version precede the provisioned VM" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());

    const disk_validation = try support.indexOf(
        source,
        "# Validate the imported disk identity and matching architecture",
    );
    const gallery_create = try support.indexOf(source, "az sig create");
    const definition_create = try support.indexFrom(
        source,
        "az sig image-definition create",
        gallery_create,
    );
    const version_create = try support.indexFrom(
        source,
        "az sig image-version create",
        definition_create,
    );
    const version_wait = try support.indexFrom(
        source,
        "az sig image-version wait",
        version_create,
    );
    const version_show = try support.indexFrom(
        source,
        "az sig image-version show",
        version_wait,
    );
    const replication_wait = try support.indexFrom(
        source,
        "\nwait_for_image_version_replication \\",
        version_show,
    );
    const vm_create = try support.indexFrom(source, "az vm create", replication_wait);
    try std.testing.expect(disk_validation < gallery_create);
    try std.testing.expect(gallery_create < definition_create);
    try std.testing.expect(definition_create < version_create);
    try std.testing.expect(version_create < version_wait);
    try std.testing.expect(version_wait < version_show);
    try std.testing.expect(version_show < replication_wait);
    try std.testing.expect(replication_wait < vm_create);

    const definition_block = source[definition_create..version_create];
    const version_block = source[version_create..version_wait];
    const vm_end = try support.indexFrom(source, "\nexpected_vm_id=", vm_create);
    const vm_block = source[vm_create..vm_end];
    const boot_diagnostics_enable = try support.indexFrom(
        source,
        "az vm boot-diagnostics enable",
        vm_create,
    );
    const boot_diagnostics_wait = try support.indexFrom(
        source,
        "\nwait_for_managed_boot_diagnostics \\",
        boot_diagnostics_enable,
    );
    const vm_validation = try support.indexFrom(
        source,
        "\"$azure_metadata_tool\" vm \\",
        boot_diagnostics_wait,
    );

    try support.expectContains(source, "image_publisher=miz");
    try support.expectContains(source, "image_offer=freebsd15");
    try support.expectContains(source, "image_sku=\"${short_arch}-${FILESYSTEM}-${FLAVOR}\"");
    try support.expectAbsent(source[gallery_create..definition_create], "--permissions");
    for ([_][]const u8{
        "--publisher \"$image_publisher\"",
        "--offer \"$image_offer\"",
        "--sku \"$image_sku\"",
        "--os-type Linux",
        "--os-state Generalized",
        "--hyper-v-generation V2",
        "--architecture \"$azure_image_architecture\"",
    }) |needle| try support.expectContains(definition_block, needle);
    for ([_][]const u8{
        "--os-snapshot \"$disk_id\"",
        "--replication-mode Shallow",
        "--no-wait",
    }) |needle| try support.expectContains(version_block, needle);
    try support.expectContains(source[version_wait..version_show], "--created");
    try support.expectContains(
        version_block,
        "  --storage-account-type Standard_LRS \\\n" ++
            "  --target-regions \"$AZURE_LOCATION=1=standard_lrs\" \\\n",
    );

    const replication_function = try replicationFunctions(tree.allocator(), source);
    try support.expectContains(replication_function, "--expand ReplicationStatus");
    try support.expectContains(replication_function, "\"$azure_location_display_name\"");
    try support.expectContains(replication_function, "if [[ \"${state,,}\" == completed ]]");
    try support.expectContains(replication_function, "Timed out after ${elapsed}s");
    try support.expectContains(source, "az account list-locations --output json");

    for ([_][]const u8{
        "--image \"$image_version_id\"",
        "--admin-username \"$admin_username\"",
        "--authentication-type ssh",
        "--ssh-key-values \"$private_key.pub\"",
        "--enable-agent false",
        "--security-type Standard",
        "--size \"$AZURE_VM_SIZE\"",
        "--location \"$AZURE_LOCATION\"",
        "--public-ip-sku Standard",
        "--nsg-rule SSH",
    }) |needle| try support.expectContains(vm_block, needle);
    try support.expectAbsent(vm_block, "--boot-diagnostics-storage");
    try support.expectAbsent(vm_block, "--specialized");
    try support.expectContains(vm_block, "AZURE_BOOT_DIAGNOSTICS_TIMEOUT_SECONDS:-180");
    try support.expectContains(vm_block, "AZURE_BOOT_DIAGNOSTICS_POLL_SECONDS:-5");

    const enable_block = source[boot_diagnostics_enable..boot_diagnostics_wait];
    try support.expectAbsent(enable_block, "--storage");
    try support.expectContains(
        enable_block,
        "Could not enable Azure managed boot diagnostics",
    );
    try std.testing.expect(vm_create < boot_diagnostics_enable);
    try std.testing.expect(boot_diagnostics_enable < boot_diagnostics_wait);
    try std.testing.expect(boot_diagnostics_wait < vm_validation);
    try support.expectAbsent(source, "az image create");
    try support.expectAbsent(source, "az image show");
    try support.expectAbsent(source, "--attach-os-disk");
}

test "the replication gate keeps owned resource-group cleanup active" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const cleanup_function = try support.indexOf(source, "cleanup_on_exit() {");
    const cleanup_trap = try support.indexOf(source, "trap cleanup_on_exit EXIT");
    const replication_wait = try support.indexOf(
        source,
        "\nwait_for_image_version_replication \\",
    );
    const vm_create = try support.indexFrom(source, "az vm create", replication_wait);
    try std.testing.expect(cleanup_trap < replication_wait);
    try std.testing.expect(replication_wait < vm_create);
    try support.expectContains(
        source[cleanup_function..cleanup_trap],
        "if ! cleanup_group; then",
    );
}

test "every Azure identity is bound to the exact resource this run created" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const validator = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15/azure_metadata.zig",
    );

    for ([_][]const u8{
        "expected_disk_id=\"/subscriptions/$subscription_id/",
        "test \"${disk_id,,}\" = \"${expected_disk_id,,}\"",
        "expected_gallery_id=\"/subscriptions/$subscription_id/",
        "expected_image_definition_id=\"$expected_gallery_id/images/",
        "image_version_id=\"$expected_image_definition_id/versions/",
        "expected_vm_id=\"/subscriptions/$subscription_id/",
        "test \"${vm_id,,}\" = \"${expected_vm_id,,}\"",
        "\"$azure_metadata_tool\" managed-disk \\",
        "\"$azure_metadata_tool\" gallery \\",
        "\"$azure_metadata_tool\" gallery-image-definition \\",
        "\"$azure_metadata_tool\" gallery-image-version",
        "\"$azure_metadata_tool\" vm \\",
    }) |needle| try support.expectContains(source, needle);

    for ([_][]const u8{
        "managed disk architecture mismatch",
        "gallery image-definition architecture mismatch",
        "gallery image definition is not Gen2",
        "gallery image definition is not generalized",
        "gallery image-definition identifier mismatch",
        "is not sourced from the exact managed",
        "gallery image-version provisioning did not succeed",
        "gallery image-version OS disk",
        "VM is not bound to the exact gallery image version",
        "VM OS disk",
        "size mismatch",
        "VM architecture mismatch",
    }) |needle| try support.expectContains(validator, needle);

    var qcow_checks: usize = 0;
    var index: usize = 0;
    const qcow_needle = "test \"$(sha256sum \"$asset\" | awk '{print $1}')\" = \"$qcow_sha256\"";
    while (std.mem.indexOfPos(u8, source, index, qcow_needle)) |at| {
        qcow_checks += 1;
        index = at + 1;
    }
    try std.testing.expect(qcow_checks >= 3);

    var vhd_checks: usize = 0;
    index = 0;
    const vhd_needle = "test \"$(sha256sum \"$vhd\" | awk '{print $1}')\" = \"$vhd_sha256\"";
    while (std.mem.indexOfPos(u8, source, index, vhd_needle)) |at| {
        vhd_checks += 1;
        index = at + 1;
    }
    try std.testing.expectEqual(@as(usize, 2), vhd_checks);
}

test "owned resource-group cleanup is the only deletion path" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    for ([_][]const u8{
        "az disk create",
        "az sig create",
        "az sig image-definition create",
        "az sig image-version create",
        "az vm create",
    }) |command| {
        const start = try support.indexOf(source, command);
        const end = try support.indexFrom(source, "--output", start);
        try support.expectContains(
            source[start..end],
            "--resource-group \"$resource_group\"",
        );
    }
    try support.expectContains(
        source,
        "name_seed=\"${GITHUB_RUN_ID}${GITHUB_RUN_ATTEMPT}" ++
            "${short_arch}${FILESYSTEM}${FLAVOR}\"",
    );
    try support.expectContains(source, "gallery_name=\"mizfb15${name_seed}\"");
    try support.expectContains(
        source,
        "image_definition_name=\"mizfb15${short_arch}${FILESYSTEM}${FLAVOR}\"",
    );
    try support.expectContains(source, "image_version=1.0.0");
    try support.expectContains(source, "trap cleanup_on_exit EXIT");
    try support.expectContains(source, "az group delete --name \"$resource_group\" --yes");
    try support.expectContains(
        source,
        "Owned temporary resource group still exists after deletion",
    );
    for ([_][]const u8{
        "az sig delete",
        "az sig image-definition delete",
        "az sig image-version delete",
        "az disk delete",
        "az vm delete",
    }) |forbidden| try support.expectAbsent(source, forbidden);
}

test "the reboot, shutdown, and account policies are asserted" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    try support.expectContains(source, "reboot_and_reconnect");
    try support.expectContains(source, "pre_reboot_hostkey");
    try support.expectContains(source, "post_reboot_hostkey");
    try support.expectContains(source, "wait_for_poweroff");
    try support.expectContains(source, "PowerState/stopped|PowerState/deallocated");
    try support.expectContains(source, "! id freebsd");
    try support.expectContains(source, "root account is not locked");
}

// ---- The guest contract ---------------------------------------------------

/// The guest-side script the harness pipes to `/bin/sh` over SSH.
fn guestContractScript(allocator: Allocator, source: []const u8) ![]const u8 {
    _ = allocator;
    const marker = "  \"/bin/sh -s -- '$vhd_current_size' " ++
        "'$runtime_architecture' '$FILESYSTEM'\" <<'GUEST'";
    const at = try support.indexOf(source, marker);
    const start = try support.indexFrom(source, "\n", at) + 1;
    const end = try support.indexFrom(source, "\nGUEST\n", start);
    return source[start..end];
}

/// Several guest fragments are POSIX shell that leans on `awk`, which the
/// FreeBSD guest always has but a host toolchain need not. Where it is absent
/// the fragment cannot be exercised at all, so the test says so rather than
/// asserting on the behaviour of a missing tool.
fn requireHostTool(gpa: Allocator, tree: *Tree, name: []const u8) !void {
    const script = try std.fmt.allocPrint(
        tree.allocator(),
        "command -v {s} >/dev/null",
        .{name},
    );
    var run = try support.runShell(gpa, "/bin/sh", script);
    defer run.deinit(gpa);
    if (run.code != 0) return error.SkipZigTest;
}

fn guestStorageFunctions(
    allocator: Allocator,
    source: []const u8,
    names: []const []const u8,
) ![]const u8 {
    var out: std.Io.Writer.Allocating = .init(allocator);
    for (names) |name| {
        try out.writer.writeAll(try support.shellFunction(allocator, source, name));
        try out.writer.writeByte('\n');
    }
    return out.written();
}

test "a guest contract failure names its phase and fails closed" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const script = try guestContractScript(tree.allocator(), source);
    const path = try tree.write("guest.sh", script);

    var run = try support.runProcess(gpa, &.{
        "/bin/sh",
        path,
        "1",
        "not-the-local-architecture",
        "ufs",
    });
    defer run.deinit(gpa);
    try std.testing.expect(run.code != 0);
    try support.expectContains(
        run.stderr,
        "guest contract failed: phase=runtime-architecture",
    );
    try support.expectContains(run.stderr, "check=read hw.machine_arch");
    try support.expectContains(run.stderr, "remote_line=");
}

test "a post-root failure observes the UFS root device it resolved" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    try requireHostTool(gpa, &tree, "awk");
    const source = try harness(tree.allocator());
    const functions = try guestStorageFunctions(tree.allocator(), source, &.{
        "privileged_diskinfo",
        "privileged_gpart",
        "privileged_glabel_status",
        "privileged_mdconfig",
        "partition_disk_for_provider",
        "resolve_guest_provider",
        "guest_observation",
        "guest_contract_diagnostics",
        "guest_contract_exit",
    });
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\set -u
        \\sudo() {{
        \\  printf 'sudo-call:%s\n' "$*" >&2
        \\  case "$*" in
        \\    "-n diskinfo /dev/da0p3") printf 'da0p3 512 4294967296\n' ;;
        \\    "-n gpart show da0") printf '=> 40 8388528 da0 GPT\n' ;;
        \\    "-n gpart status -s da0") printf 'da0p3 OK da0\n' ;;
        \\    "-n mdconfig -lv") : ;;
        \\  esac
        \\}}
        \\{s}
        \\original_size=2147483648
        \\root_device=/dev/gpt/rootfs
        \\rootfs=ufs
        \\root_provider=da0p3
        \\disk=da0
        \\root_partition_size=4294967296
        \\root_filesystem_kib=4194304
        \\root_pool=
        \\pool_size=
        \\guest_phase=gpt-health
        \\guest_check="require every GPT provider status to be OK"
        \\post_root_failure() {{
        \\  return 23
        \\}}
        \\post_root_failure
        \\guest_contract_exit
    , .{functions});
    var run = try support.runShell(gpa, "/bin/sh", script);
    defer run.deinit(gpa);
    try std.testing.expectEqual(@as(u8, 23), run.code);
    try support.expectContains(run.stderr, "guest contract failed: phase=gpt-health");
    try support.expectContains(
        run.stderr,
        "--- guest observation: root-device (first 40 lines) ---",
    );
    try support.expectContains(run.stderr, "sudo-call:-n diskinfo /dev/da0p3");
    try support.expectAbsent(run.stderr, "sudo-call:-n glabel status");
}

test "guest contract capture preserves status files and bounds its output" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const stdout_path = try tree.path(&.{"guest-contract.stdout"});
    const stderr_path = try tree.path(&.{"guest-contract.stderr"});
    try Dir.cwd().createDirPath(std.testing.io, tree.root);

    const script = try std.fmt.allocPrint(tree.allocator(),
        \\set -u -o pipefail
        \\guest_output_line_limit=5
        \\ssh_options=()
        \\ssh_target=guest-test
        \\ssh() {{
        \\  for number in {{1..12}}; do
        \\    printf 'stdout-line-%s\n' "$number"
        \\    printf 'stderr-line-%s\n' "$number" >&2
        \\  done
        \\  return 37
        \\}}
        \\{s}
        \\{s}
        \\set +e
        \\run_guest_contract {s} {s} /bin/sh -s
        \\status=$?
        \\set -e
        \\printf 'status=%s\n' "$status"
    , .{
        try support.shellFunction(tree.allocator(), source, "print_bounded_guest_file"),
        try support.shellFunction(tree.allocator(), source, "run_guest_contract"),
        stdout_path,
        stderr_path,
    });
    var run = try support.runShell(gpa, "bash", script);
    defer run.deinit(gpa);
    try std.testing.expectEqualStrings("status=37\n", run.stdout);
    const captured_stdout = try tree.read("guest-contract.stdout");
    const captured_stderr = try tree.read("guest-contract.stderr");
    try std.testing.expect(std.mem.startsWith(u8, captured_stdout, "stdout-line-1\n"));
    try std.testing.expect(std.mem.endsWith(u8, captured_stdout, "stdout-line-12\n"));
    try std.testing.expect(std.mem.startsWith(u8, captured_stderr, "stderr-line-1\n"));
    try std.testing.expect(std.mem.endsWith(u8, captured_stderr, "stderr-line-12\n"));
    try support.expectContains(
        run.stderr,
        "Remote guest contract SSH failed with status 37",
    );
    try support.expectContains(run.stderr, "stdout-line-5");
    try support.expectContains(run.stderr, "stderr-line-5");
    try support.expectAbsent(run.stderr, "stdout-line-6");
    try support.expectAbsent(run.stderr, "stderr-line-6");
    var truncations: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        run.stderr,
        index,
        "[truncated: 12 total lines]",
    )) |at| {
        truncations += 1;
        index = at + 1;
    }
    try std.testing.expectEqual(@as(usize, 2), truncations);
}

test "guest contract failure artefacts and observations are bounded" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const flow = try workflow(tree.allocator());
    const failure_upload = try support.between(
        flow,
        "      - name: Upload failed Azure acceptance diagnostics",
        "      - name: Upload exact Azure acceptance result",
    );
    try support.expectContains(flow, "${{ env.RESULT_DIR }}/guest-contract.stdout");
    try support.expectContains(flow, "${{ env.RESULT_DIR }}/guest-contract.stderr");
    try support.expectAbsent(failure_upload, "id_ed25519");
    try support.expectContains(source, "guest_output_line_limit=200");
    try support.expectContains(
        source,
        "guest observation: $observation (first 40 lines)",
    );
    for ([_][]const u8{
        "architecture",
        "sshd-settings",
        "agent-processes",
        "agent-service",
        "network-interfaces",
        "mounts",
        "root-device",
        "gpart-status",
        "swapinfo",
        "mdconfig",
    }) |observation| {
        const needle = try std.fmt.allocPrint(
            tree.allocator(),
            "guest_observation {s}",
            .{observation},
        );
        try support.expectContains(source, needle);
    }
}

fn runProviderResolution(
    gpa: Allocator,
    tree: *Tree,
    provider: []const u8,
    glabel_output: []const u8,
) !support.Run {
    const source = try harness(tree.allocator());
    const functions = try guestStorageFunctions(tree.allocator(), source, &.{
        "privileged_glabel_status",
        "partition_disk_for_provider",
        "resolve_guest_provider",
    });
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\set -u
        \\GLABEL_OUTPUT='{s}'
        \\sudo() {{
        \\  printf 'sudo-call:%s\n' "$*" >&2
        \\  test "$1" = -n
        \\  test "$2" = glabel
        \\  test "$3" = status
        \\  printf '%s' "$GLABEL_OUTPUT"
        \\}}
        \\{s}
        \\set +e
        \\resolved=$(resolve_guest_provider '{s}')
        \\status=$?
        \\set -e
        \\printf 'status=%s\nresolved=%s\n' "$status" "$resolved"
    , .{ glabel_output, functions, provider });
    return support.runShell(gpa, "/bin/sh", script);
}

test "the guest provider resolver keeps a direct provider without glabel" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    var run = try runProviderResolution(gpa, &tree, "/dev/da0p3", "");
    defer run.deinit(gpa);
    try std.testing.expectEqualStrings("status=0\nresolved=da0p3\n", run.stdout);
    try std.testing.expectEqualStrings("", run.stderr);
}

test "the guest provider resolver resolves exact GEOM labels with sudo -n" {
    const gpa = std.testing.allocator;
    for ([_][]const u8{ "gpt/rootfs", "label/resource-swap", "ufs/rootfs" }) |label| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        try requireHostTool(gpa, &tree, "awk");
        const fixture = try std.fmt.allocPrint(tree.allocator(),
            \\Name Status Components
            \\gpt/efi N/A da0p1
            \\{s} N/A da0p3
            \\
        , .{label});
        const provider = try std.fmt.allocPrint(tree.allocator(), "/dev/{s}", .{label});
        var run = try runProviderResolution(gpa, &tree, provider, fixture);
        defer run.deinit(gpa);
        try std.testing.expectEqualStrings("status=0\nresolved=da0p3\n", run.stdout);
        try std.testing.expectEqualStrings("sudo-call:-n glabel status\n", run.stderr);
    }
}

test "the guest provider resolver refuses missing, ambiguous, or malformed labels" {
    const gpa = std.testing.allocator;
    const fixtures = [_][]const u8{
        "Name Status Components\ngpt/efi N/A da0p1\n",
        "Name Status Components\ngpt/rootfs N/A da0p3\ngpt/rootfs N/A da1p3\n",
        "Name Status Components\ngpt/rootfs N/A da0\n",
        "unexpected header\ngpt/rootfs N/A da0p3\n",
        "Name Status Components\nmalformed-row\ngpt/rootfs N/A da0p3\n",
    };
    for (fixtures) |fixture| {
        var tree = try Tree.create(gpa);
        defer tree.deinit();
        var run = try runProviderResolution(gpa, &tree, "/dev/gpt/rootfs", fixture);
        defer run.deinit(gpa);
        try std.testing.expectEqualStrings("status=1\nresolved=\n", run.stdout);
        try support.expectContains(run.stderr, "sudo-call:-n glabel status\n");
        try support.expectContains(run.stderr, "GEOM label");
    }
}

test "privileged storage commands use exact non-interactive sudo invocations" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const functions = try guestStorageFunctions(tree.allocator(), source, &.{
        "privileged_diskinfo",
        "privileged_gpart",
        "privileged_glabel_status",
        "privileged_mdconfig",
    });
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\set -u
        \\sudo() {{
        \\  printf '%s\n' "$*"
        \\}}
        \\{s}
        \\privileged_diskinfo /dev/da0p3
        \\privileged_gpart status -s da0
        \\privileged_glabel_status
        \\privileged_mdconfig -lv -u 0
    , .{functions});
    var run = try support.runShell(gpa, "/bin/sh", script);
    defer run.deinit(gpa);
    try std.testing.expectEqualStrings(
        "-n diskinfo /dev/da0p3\n-n gpart status -s da0\n-n glabel status\n" ++
            "-n mdconfig -lv -u 0\n",
        run.stdout,
    );
}

test "swap must be backed by a resource-disk partition, never the OS disk" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    const functions = try guestStorageFunctions(tree.allocator(), source, &.{
        "privileged_diskinfo",
        "partition_disk_for_provider",
        "require_resource_disk_provider",
    });
    const script = try std.fmt.allocPrint(tree.allocator(),
        \\set -u
        \\sudo_call=
        \\sudo() {{
        \\  sudo_call=$*
        \\}}
        \\{s}
        \\disk=da0
        \\require_resource_disk_provider da1p1
        \\printf 'resource_status=%s\nsudo_call=%s\n' "$?" "$sudo_call"
        \\set +e
        \\require_resource_disk_provider da0p2
        \\printf 'os_status=%s\n' "$?"
        \\require_resource_disk_provider da1
        \\printf 'whole_disk_status=%s\n' "$?"
    , .{functions});
    var run = try support.runShell(gpa, "/bin/sh", script);
    defer run.deinit(gpa);
    try std.testing.expectEqualStrings(
        "resource_status=0\nsudo_call=-n diskinfo /dev/da1\nos_status=1\n" ++
            "whole_disk_status=1\n",
        run.stdout,
    );
    try support.expectContains(
        run.stderr,
        "swap is not backed by a resource-disk partition: da0p2",
    );
    try support.expectContains(
        run.stderr,
        "provider is not an exact partition provider: da1",
    );
}

test "the mdconfig and resource-disk parsers read only the fields they claim" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    try requireHostTool(gpa, &tree, "awk");

    for ([_][2][]const u8{
        .{
            "md0\tvnode\t 2.0G\t/swapfile\troot-swap\tasync,cache,compress\n",
            "/swapfile",
        },
        .{
            "md7\tvnode\t 1.0G\t/mnt/resource/swap file\tazure swap\t" ++
                "cache,readonly,verify\n",
            "/mnt/resource/swap file",
        },
    }) |case| {
        const input = try tree.write("mdconfig.txt", case[0]);
        const script = try std.fmt.allocPrint(
            tree.allocator(),
            "awk -F '\\t' '$2 == \"vnode\" {{ print $4; exit }}' {s}",
            .{input},
        );
        var run = try support.runShell(gpa, "/bin/sh", script);
        defer run.deinit(gpa);
        try std.testing.expectEqualStrings(case[1], std.mem.trimEnd(u8, run.stdout, "\n"));
    }

    for ([_][2][]const u8{
        .{ "da1p1", "da1" },
        .{ "nda2p3", "nda2" },
        .{ "da1s1", "da1" },
        .{ "ada2s4", "ada2" },
    }) |case| {
        const script = try std.fmt.allocPrint(
            tree.allocator(),
            "printf '{s}\\n' | sed -E 's/(p|s)[0-9]+$//'",
            .{case[0]},
        );
        var run = try support.runShell(gpa, "/bin/sh", script);
        defer run.deinit(gpa);
        try std.testing.expectEqualStrings(case[1], std.mem.trimEnd(u8, run.stdout, "\n"));
    }

    const source = try harness(tree.allocator());
    try support.expectContains(source, "sed -E 's/(p|s)[0-9]+$//'");
    try support.expectContains(source, "*p[0-9]*|*s[0-9]*)");
}

test "the guest phase names and storage contracts are stable" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const source = try harness(tree.allocator());
    for ([_][]const u8{
        "runtime-architecture",
        "sshd-policy",
        "account-policy",
        "azure-agent-ready",
        "network-dhcp",
        "root-filesystem",
        "ufs-root-growth",
        "zfs-root-health",
        "gpt-health",
        "swap-policy",
    }) |phase| {
        const needle = try std.fmt.allocPrint(
            tree.allocator(),
            "begin_guest_phase {s} ",
            .{phase},
        );
        try support.expectContains(source, needle);
    }

    try support.expectContains(source, "zpool status -x \"$root_pool\"");
    try support.expectContains(source, "zpool get -H -o value autoexpand \"$root_pool\"");
    try support.expectContains(source, "pre_reboot_storage_identity");
    try support.expectContains(source, "post_reboot_storage_identity");

    const ufs_checks = try support.between(
        source,
        "    # ufs-root and UFS growth:",
        "\n    ;;",
    );
    try support.expectAbsent(ufs_checks, "mount -p");
    try support.expectContains(ufs_checks, "diskinfo");
    try support.expectContains(ufs_checks, "df -k /");
    try support.expectContains(ufs_checks, "root_partition_size");
    try support.expectContains(ufs_checks, "root_filesystem_kib");
    try support.expectAbsent(ufs_checks, "zpool");
    try support.expectAbsent(ufs_checks, "zfs ");

    try support.expectContains(
        source,
        "! privileged_gpart show \"$disk\" | grep -q CORRUPT",
    );
    try support.expectContains(source, "privileged_gpart status -s \"$disk\"");
    try support.expectContains(source, "require_resource_disk_provider");
    try support.expectContains(source, "[ \"$resource_disk\" = \"$disk\" ]");
    try support.expectContains(
        source,
        "swap provider is not positively identified as resource-disk-backed",
    );

    const md_checks = try support.between(source, "    md[0-9]*)", "\n      ;;");
    try support.expectContains(md_checks, "privileged_mdconfig -lv -u \"$md_unit\"");
    try support.expectContains(md_checks, "$2 == \"vnode\" { print $4; exit }");
    try support.expectContains(md_checks, "md_backing_mount=$(df -k \"$md_backing\"");
    try support.expectContains(md_checks, "md_backing_device=$(df -k \"$md_backing\"");
    try support.expectContains(md_checks, "[ \"$md_backing_mount\" = / ]");
    try support.expectContains(
        md_checks,
        "swap vnode is backed by the OS/root filesystem",
    );
    try support.expectContains(
        md_checks,
        "require_resource_disk_provider \"$md_backing_provider\"",
    );
}

// ---- Workflow integration -------------------------------------------------

fn azureSection(allocator: Allocator, flow: []const u8) ![]const u8 {
    _ = allocator;
    return support.between(flow, "azure_acceptance:", "\n  stage:");
}

test "the Azure acceptance job runs for the release set's whole matrix" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const flow = try workflow(tree.allocator());
    const section = try azureSection(tree.allocator(), flow);

    try support.expectContains(flow, "azure_acceptance:");
    try support.expectContains(section, "needs.build.result == 'success'");
    try support.expectAbsent(section, "inputs.release_set ==");
    try support.expectContains(section, "fromJSON(needs.prepare.outputs.azure_matrix)");
    try support.expectContains(section, "CANDIDATE_KEY: ${{ matrix.key }}");
    try support.expectContains(
        section,
        "AZURE_LOCATION: ${{ vars[matrix.location_variable] }}",
    );
    try support.expectContains(
        section,
        "AZURE_VM_SIZE: ${{ vars[matrix.size_variable] }}",
    );
    try support.expectContains(section, "scripts/freebsd15_azure_acceptance.sh run");
    try support.expectContains(section, "scripts/freebsd15_azure_acceptance.sh cleanup");
}

test "only the Azure acceptance job reaches the protected configuration" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const flow = try workflow(tree.allocator());
    const section = try azureSection(tree.allocator(), flow);
    const start = try support.indexOf(flow, "azure_acceptance:");
    const end = try support.indexFrom(flow, "\n  stage:", start);
    const outside = try std.fmt.allocPrint(
        tree.allocator(),
        "{s}{s}",
        .{ flow[0..start], flow[end..] },
    );

    try support.expectContains(section, "id-token: write");
    try support.expectContains(section, "azure/login@");
    try support.expectContains(section, "environment: azurelinux4-release");
    for ([_][]const u8{
        "secrets.AZURE_CLIENT_ID",
        "secrets.AZURE_TENANT_ID",
        "secrets.AZURE_SUBSCRIPTION_ID",
    }) |secret| {
        var occurrences: usize = 0;
        var index: usize = 0;
        while (std.mem.indexOfPos(u8, section, index, secret)) |at| {
            occurrences += 1;
            index = at + 1;
        }
        try std.testing.expectEqual(@as(usize, 4), occurrences);
    }
    const refresh = try support.indexOf(
        section,
        "Refresh Azure OIDC credential before acceptance",
    );
    const acceptance = try support.indexOf(section, "Run exact-artifact Azure acceptance");
    try std.testing.expect(refresh < acceptance);
    try support.expectAbsent(section, "AZURE_CLIENT_SECRET");
    try support.expectAbsent(section, "client-secret:");

    var environments: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        flow,
        index,
        "environment: azurelinux4-release",
    )) |at| {
        environments += 1;
        index = at + 1;
    }
    try std.testing.expectEqual(@as(usize, 1), environments);
    try support.expectAbsent(flow, "environment: freebsd15-release");
    try support.expectAbsent(outside, "secrets.AZURE_");
    try support.expectAbsent(outside, "vars[matrix.location_variable]");
    try support.expectAbsent(outside, "vars[matrix.size_variable]");
}

test "staging depends on Azure and publication depends on staging" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const flow = try workflow(tree.allocator());
    const stage_block = try support.between(flow, "\n  stage:", "\n  publish:");
    const publish_start = try support.indexOf(flow, "\n  publish:");
    const publish_block = flow[publish_start..];

    try support.expectContains(stage_block, "needs: [prepare, build, azure_acceptance]");
    try support.expectContains(publish_block, "needs: [prepare, stage]");
    try support.expectContains(
        stage_block,
        "needs.azure_acceptance.result == 'success'",
    );
    try support.expectAbsent(stage_block, "inputs.release_set == 'zfs'");
    try support.expectContains(stage_block, "test \"$AZURE_RESULT\" = success");
    try support.expectContains(
        stage_block,
        "test \"$count\" -eq \"$EXPECTED_ASSET_COUNT\"",
    );
    try support.expectContains(
        stage_block,
        "AZURE_RESULTS_DIR: .release/freebsd15/azure-results",
    );
    try support.expectContains(publish_block, "freebsd15-azure-*");
    try support.expectContains(publish_block, "AZURE_RESULTS_DIR");
    try support.expectAbsent(publish_block, "inputs.release_set == 'core'");
    try support.expectContains(publish_block, "inputs.validation_only == false");
    try support.expectContains(publish_block, "github.repository == 'cataggar/miz'");
    try support.expectContains(publish_block, "github.ref == 'refs/heads/main'");
}

test "the workflow persists the exact qemu-img document and one candidate matrix" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const flow = try workflow(tree.allocator());

    try support.expectContains(
        flow,
        "qemu-img info --output=json \"$asset\" > \"$image_info\"",
    );
    try support.expectContains(flow, "--qemu-info \"$CANDIDATE_DIR/qemu-img-info.json\"");
    try support.expectContains(
        flow,
        "jq -r '.\"actual-size\"' \"$CANDIDATE_DIR/qemu-img-info.json\"",
    );
    try support.expectAbsent(flow, "BASELINE_CANDIDATES_DIR");
    try support.expectContains(flow, "Download every build-validated candidate");
    try support.expectContains(flow, "freebsd15-candidate-*");
    try support.expectContains(flow, "merge-multiple: false");
    try support.expectContains(flow, "default: zfs");
    try support.expectAbsent(flow, "          - ufs");
    try support.expectContains(flow, "test \"$RELEASE_SET\" = zfs");

    var counts: usize = 0;
    var index: usize = 0;
    while (std.mem.indexOfPos(
        u8,
        flow,
        index,
        "\"$release_tool\" include-count --matrix",
    )) |at| {
        counts += 1;
        index = at + 1;
    }
    try std.testing.expectEqual(@as(usize, 2), counts);
}

test "the reviewed release date is explicit and every artefact names the commit" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const flow = try workflow(tree.allocator());

    try support.expectContains(flow, "release_date:");
    try support.expectContains(flow, "Explicit reviewed YYYYMMDD");
    const release_date_block = try support.between(
        flow,
        "      release_date:",
        "      validation_only:",
    );
    try support.expectContains(release_date_block, "required: true");
    try support.expectAbsent(release_date_block, "default:");
    try support.expectContains(flow, "RELEASE_DATE");
    try support.expectContains(flow, "--release-date");
    try support.expectAbsent(flow, "20260730");

    var lines = std.mem.splitScalar(u8, flow, '\n');
    while (lines.next()) |raw| {
        const line = std.mem.trimStart(u8, raw, " ");
        const is_reference = std.mem.startsWith(u8, line, "name: freebsd15-candidate-") or
            std.mem.startsWith(u8, line, "name: freebsd15-azure-") or
            std.mem.startsWith(u8, line, "pattern: freebsd15-candidate-") or
            std.mem.startsWith(u8, line, "pattern: freebsd15-azure-");
        if (!is_reference) continue;
        try support.expectContains(line, "source_commit");
    }
}

test "the staged ZFS allowlist is unqualified and complete" {
    const gpa = std.testing.allocator;
    var tree = try Tree.create(gpa);
    defer tree.deinit();
    const publication_source = try support.readSource(
        tree.allocator(),
        "scripts/freebsd15/publication.zig",
    );
    const allowlist = try support.between(
        publication_source,
        "pub const zfs_publication_allowlist = [_]AllowedAsset{",
        "\n};",
    );
    for ([_][]const u8{
        "FreeBSD-15.1-aarch64.qcow2",
        "FreeBSD-15.1-x86_64.qcow2",
        "FreeBSD-15.1-aarch64.core.qcow2",
        "FreeBSD-15.1-x86_64.core.qcow2",
        "aarch64-zfs-core",
        "x86_64-zfs-core",
    }) |needle| try support.expectContains(allowlist, needle);
    // The published names are the unqualified spelling, never the qualified
    // one an earlier ZFS release used.
    try support.expectAbsent(allowlist, ".zfs.qcow2");
}
