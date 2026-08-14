//! Opt-in QEMU acceptance for generalized FreeBSD 15.1 release images.
//! Set `ZVMI_FREEBSD15_IMAGE`, `ZVMI_FREEBSD15_ARCHITECTURE`,
//! `ZVMI_FREEBSD15_FILESYSTEM`, and `ZVMI_FREEBSD15_FLAVOR` to run it.

const std = @import("std");
const builtin = @import("builtin");
const qemu_host = @import("qemu_host");
const qmp = @import("qmp");
const packages = @import("packages");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;
const serial_limit: usize = 2 * 1024 * 1024;
const serial_tail_size: usize = 256 * 1024;
const boot_timeout_seconds: i64 = 10 * 60;
const ssh_diagnostic_limit_bytes: usize = 64 * 1024;

/// Every release image is pinned to roughly 6.04 GiB, so each acceptance
/// overlay is created at 12 GiB to prove first-boot growth. The size stays
/// under growfs(8)'s 15 GB threshold for volunteering a swap partition, so a
/// guest that grew and a guest that also gained swap remain distinguishable.
const expanded_virtual_size: u64 = 12 * 1024 * 1024 * 1024;

/// Lower bound the grown root storage must clear. The upstream root partition
/// is 5 GiB, so anything at or above this proves the last GPT partition was
/// resized and the filesystem or pool followed it.
const minimum_grown_root_bytes: u64 = 8 * 1024 * 1024 * 1024;

const Architecture = enum {
    aarch64,
    x86_64,

    fn parse(text: []const u8) ?Architecture {
        if (std.mem.eql(u8, text, "aarch64")) return .aarch64;
        if (std.mem.eql(u8, text, "x86_64")) return .x86_64;
        return null;
    }

    fn guestArchitecture(self: Architecture) qemu_host.GuestArchitecture {
        return switch (self) {
            .aarch64 => .aarch64,
            .x86_64 => .x86_64,
        };
    }

    fn machineArg(self: Architecture) []const u8 {
        return switch (self) {
            .aarch64 => "virt,accel=tcg",
            .x86_64 => "q35,accel=tcg",
        };
    }

    fn cpuArg(self: Architecture) []const u8 {
        return switch (self) {
            .aarch64 => "max",
            .x86_64 => "qemu64",
        };
    }

    fn qemuName(self: Architecture) []const u8 {
        return qemu_host.qemuSystemName(self.guestArchitecture());
    }
};

const Firmware = qemu_host.FirmwarePair;

/// Root filesystem of the image under acceptance. The generalized guest
/// contract is identical for both, but the way each one grows, records swap,
/// and carries per-instance identity is not, so the checks stay separate.
const RootFilesystem = enum {
    ufs,
    zfs,

    fn parse(text: []const u8) ?RootFilesystem {
        if (std.mem.eql(u8, text, "ufs")) return .ufs;
        if (std.mem.eql(u8, text, "zfs")) return .zfs;
        return null;
    }
};

/// Content flavor of the image under acceptance. Every flavor must satisfy
/// the same retained contract; the core flavor additionally has to prove the
/// reviewed exclusions are really gone from a booted image rather than only
/// from the manifest the builder recorded.
const Flavor = packages.Flavor;

fn optionalEnvAlloc(
    allocator: Allocator,
    comptime name: []const u8,
) !?[]u8 {
    return std.testing.environ.getAlloc(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
}

fn architectureFromEnvironment(allocator: Allocator) !Architecture {
    const value = try optionalEnvAlloc(
        allocator,
        "ZVMI_FREEBSD15_ARCHITECTURE",
    ) orelse return .aarch64;
    defer allocator.free(value);
    return Architecture.parse(value) orelse error.InvalidArchitecture;
}

fn rootFilesystemFromEnvironment(allocator: Allocator) !RootFilesystem {
    const value = try optionalEnvAlloc(
        allocator,
        "ZVMI_FREEBSD15_FILESYSTEM",
    ) orelse return .zfs;
    defer allocator.free(value);
    return RootFilesystem.parse(value) orelse error.InvalidRootFilesystem;
}

fn flavorFromEnvironment(allocator: Allocator) !Flavor {
    const value = try optionalEnvAlloc(
        allocator,
        "ZVMI_FREEBSD15_FLAVOR",
    ) orelse return .full;
    defer allocator.free(value);
    return Flavor.parse(value) orelse error.InvalidFlavor;
}

fn requireImageAlloc(
    allocator: Allocator,
    io: Io,
    architecture: Architecture,
) ![]u8 {
    const path = try optionalEnvAlloc(
        allocator,
        "ZVMI_FREEBSD15_IMAGE",
    ) orelse {
        std.debug.print(
            "skipping FreeBSD {s} boot acceptance: set " ++
                "ZVMI_FREEBSD15_IMAGE to a generalized QCOW2\n",
            .{@tagName(architecture)},
        );
        return error.SkipZigTest;
    };
    errdefer allocator.free(path);
    if (!try qemu_host.pathAccessible(io, path, .{ .read = true })) {
        std.debug.print(
            "ZVMI_FREEBSD15_IMAGE is not readable: {s}\n",
            .{path},
        );
        return error.AcceptanceImageNotReadable;
    }
    return path;
}

fn requireToolAlloc(
    allocator: Allocator,
    io: Io,
    name: []const u8,
    architecture: Architecture,
) ![]u8 {
    return try qemu_host.findExecutableInPathAlloc(
        allocator,
        io,
        std.testing.environ,
        name,
    ) orelse {
        std.debug.print(
            "skipping FreeBSD {s} boot acceptance: {s} is not in PATH\n",
            .{ @tagName(architecture), name },
        );
        return error.SkipZigTest;
    };
}

fn requireToolOverrideAlloc(
    allocator: Allocator,
    io: Io,
    comptime environment_name: []const u8,
    default_name: []const u8,
    architecture: Architecture,
) ![]u8 {
    if (try optionalEnvAlloc(allocator, environment_name)) |path| {
        errdefer allocator.free(path);
        if (!try qemu_host.pathAccessible(io, path, .{ .execute = true })) {
            return error.ToolOverrideNotExecutable;
        }
        return path;
    }
    return requireToolAlloc(allocator, io, default_name, architecture);
}

fn resolveFirmwareAlloc(
    allocator: Allocator,
    io: Io,
    architecture: Architecture,
    qemu_path: []const u8,
) !Firmware {
    const explicit_code = try optionalEnvAlloc(
        allocator,
        "ZVMI_FREEBSD15_UEFI_CODE",
    );
    defer if (explicit_code) |path| allocator.free(path);
    const explicit_vars = try optionalEnvAlloc(
        allocator,
        "ZVMI_FREEBSD15_UEFI_VARS",
    );
    defer if (explicit_vars) |path| allocator.free(path);
    if ((explicit_code == null) != (explicit_vars == null)) {
        return error.IncompleteFirmwareOverride;
    }
    if (try qemu_host.findFirmwarePairAlloc(allocator, io, .{
        .architecture = architecture.guestArchitecture(),
        .explicit_code_path = explicit_code,
        .explicit_vars_path = explicit_vars,
        .qemu_path = qemu_path,
    })) |firmware| return firmware;
    std.debug.print(
        "skipping FreeBSD {s} boot acceptance: matching UEFI firmware was not found; " ++
            "set ZVMI_FREEBSD15_UEFI_CODE and ZVMI_FREEBSD15_UEFI_VARS\n",
        .{@tagName(architecture)},
    );
    return error.SkipZigTest;
}

fn runCommand(io: Io, argv: []const []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    defer child.kill(io);
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

const SshOperation = enum {
    readiness,
    identity,
    static_contract,
    update_contract,
    package_lifecycle,
    power,

    fn description(self: SshOperation) []const u8 {
        return switch (self) {
            .readiness => "SSH readiness",
            .identity => "guest identity",
            .static_contract => "static guest contract",
            .update_contract => "package update contract",
            .package_lifecycle => "package lifecycle contract",
            .power => "guest power command",
        };
    }

    fn timeoutSeconds(self: SshOperation) u32 {
        return switch (self) {
            .readiness, .identity => 15,
            .static_contract => 2 * 60,
            .update_contract => 10 * 60,
            .package_lifecycle => 5 * 60,
            .power => 30,
        };
    }
};

const SshCommandResult = struct {
    operation: SshOperation,
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,
    timeout_evidence: TimeoutEvidence,

    fn deinit(self: *SshCommandResult, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }

    fn succeeded(self: SshCommandResult) bool {
        if (self.timeout_evidence.timedOut(self.term)) return false;
        if (self.timeout_evidence.completed_status != 0) return false;
        return switch (self.term) {
            .exited => |code| code == 0,
            else => false,
        };
    }

    fn timedOut(self: SshCommandResult) bool {
        return self.timeout_evidence.timedOut(self.term);
    }
};

const ssh_capture_script =
    "exec \"$@\" > >(/usr/bin/tail -c 65536) " ++
    "2> >(/usr/bin/tail -c 65536 >&2)";

const timeout_wrapper_script =
    "completion_file=$1; started_file=$2; timeout_file=$3; shift 3; " ++
    ": > \"$started_file\" || exit 125; timed_out=; " ++
    "trap 'timed_out=1; : > \"$timeout_file\"' TERM; " ++
    "\"$@\"; status=$?; trap - TERM; " ++
    "if [ -z \"$timed_out\" ]; then " ++
    "printf '%s\\n' \"$status\" > \"$completion_file\" || exit 125; fi; " ++
    "exit \"$status\"";

const TimeoutEvidence = struct {
    wrapper_started: bool,
    timeout_marked: bool,
    completed_status: ?u8,

    fn completed(status: u8) TimeoutEvidence {
        return .{
            .wrapper_started = true,
            .timeout_marked = false,
            .completed_status = status,
        };
    }

    fn timedOut(self: TimeoutEvidence, term: std.process.Child.Term) bool {
        if (self.completed_status) |status| {
            if (shellStatus(term) == status) return false;
        }
        if (self.timeout_marked) return true;
        if (!self.wrapper_started) return false;
        const status = shellStatus(term) orelse return false;
        return status == 124 or status == 137;
    }
};

fn shellStatus(term: std.process.Child.Term) ?u8 {
    return switch (term) {
        .exited => |code| code,
        .signal => |signal| std.math.add(
            u8,
            128,
            @intCast(@intFromEnum(signal)),
        ) catch null,
        else => null,
    };
}

fn readMarkerExists(io: Io, dir: Dir, name: []const u8) !bool {
    dir.access(io, name, .{}) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    return true;
}

fn readCompletionStatus(
    allocator: Allocator,
    io: Io,
    dir: Dir,
) !?u8 {
    const raw = dir.readFileAlloc(
        io,
        "completed",
        allocator,
        .limited(16),
    ) catch |err| switch (err) {
        error.FileNotFound => return null,
        else => return err,
    };
    defer allocator.free(raw);
    const text = std.mem.trim(u8, raw, " \t\r\n");
    if (text.len == 0) return error.InvalidTimeoutCompletionStatus;
    return std.fmt.parseInt(u8, text, 10) catch
        return error.InvalidTimeoutCompletionStatus;
}

fn runTimedCommandAlloc(
    allocator: Allocator,
    io: Io,
    operation: SshOperation,
    timeout_text: []const u8,
    kill_after_text: []const u8,
    command_argv: []const []const u8,
) !SshCommandResult {
    var marker_dir = std.testing.tmpDir(.{});
    defer marker_dir.cleanup();
    var marker_path_buffer: [Dir.max_path_bytes]u8 = undefined;
    const marker_path_length = try marker_dir.dir.realPath(
        io,
        &marker_path_buffer,
    );
    const marker_path = marker_path_buffer[0..marker_path_length];
    const completion_path = try std.fs.path.join(
        allocator,
        &.{ marker_path, "completed" },
    );
    defer allocator.free(completion_path);
    const started_path = try std.fs.path.join(
        allocator,
        &.{ marker_path, "started" },
    );
    defer allocator.free(started_path);
    const timeout_path = try std.fs.path.join(
        allocator,
        &.{ marker_path, "timed-out" },
    );
    defer allocator.free(timeout_path);
    const kill_after_arg = try std.fmt.allocPrint(
        allocator,
        "--kill-after={s}",
        .{kill_after_text},
    );
    defer allocator.free(kill_after_arg);

    var argv: std.ArrayList([]const u8) = .empty;
    defer argv.deinit(allocator);
    try argv.appendSlice(allocator, &.{
        "/bin/bash",
        "-c",
        ssh_capture_script,
        "zvmi-ssh-capture",
        "/usr/bin/timeout",
        kill_after_arg,
        timeout_text,
        "/bin/bash",
        "-c",
        timeout_wrapper_script,
        "zvmi-timeout-wrapper",
        completion_path,
        started_path,
        timeout_path,
    });
    try argv.appendSlice(allocator, command_argv);
    const result = try std.process.run(allocator, io, .{
        .argv = argv.items,
        .stdout_limit = .limited(ssh_diagnostic_limit_bytes),
        .stderr_limit = .limited(ssh_diagnostic_limit_bytes),
    });
    errdefer allocator.free(result.stdout);
    errdefer allocator.free(result.stderr);
    return .{
        .operation = operation,
        .term = result.term,
        .stdout = result.stdout,
        .stderr = result.stderr,
        .timeout_evidence = .{
            .wrapper_started = try readMarkerExists(
                io,
                marker_dir.dir,
                "started",
            ),
            .timeout_marked = try readMarkerExists(
                io,
                marker_dir.dir,
                "timed-out",
            ),
            .completed_status = try readCompletionStatus(
                allocator,
                io,
                marker_dir.dir,
            ),
        },
    };
}

fn runSshCommandAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    operation: SshOperation,
    command: []const u8,
) !SshCommandResult {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_text);
    const timeout_text = try std.fmt.allocPrint(
        allocator,
        "{d}s",
        .{operation.timeoutSeconds()},
    );
    defer allocator.free(timeout_text);
    return runTimedCommandAlloc(
        allocator,
        io,
        operation,
        timeout_text,
        "5s",
        &.{
            ssh_path,
            "-i",
            key_path,
            "-p",
            port_text,
            "-o",
            "BatchMode=yes",
            "-o",
            "ConnectTimeout=5",
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            "zvmitest@127.0.0.1",
            command,
        },
    );
}

fn diagnosticTail(bytes: []const u8) []const u8 {
    const start = bytes.len - @min(bytes.len, ssh_diagnostic_limit_bytes);
    return bytes[start..];
}

fn appendDiagnosticStream(
    writer: *std.Io.Writer,
    name: []const u8,
    bytes: []const u8,
) !void {
    const tail = diagnosticTail(bytes);
    try writer.print(
        "{s} tail ({d} byte{s}):\n",
        .{ name, tail.len, if (tail.len == 1) "" else "s" },
    );
    if (tail.len == 0) {
        try writer.writeAll("<empty>\n");
    } else {
        try writer.print("{s}\n", .{tail});
    }
}

fn sshFailureDiagnosticAlloc(
    allocator: Allocator,
    result: SshCommandResult,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    if (result.timedOut()) {
        try output.writer.print(
            "FreeBSD acceptance {s} timed out after {d} seconds\n",
            .{ result.operation.description(), result.operation.timeoutSeconds() },
        );
    } else switch (result.term) {
        .exited => |code| try output.writer.print(
            "FreeBSD acceptance {s} failed with exit code {d}\n",
            .{ result.operation.description(), code },
        ),
        .signal => |signal| try output.writer.print(
            "FreeBSD acceptance {s} ended by signal {d}\n",
            .{ result.operation.description(), @intFromEnum(signal) },
        ),
        .stopped => |signal| try output.writer.print(
            "FreeBSD acceptance {s} stopped by signal {d}\n",
            .{ result.operation.description(), @intFromEnum(signal) },
        ),
        .unknown => |status| try output.writer.print(
            "FreeBSD acceptance {s} ended with unknown status {d}\n",
            .{ result.operation.description(), status },
        ),
    }
    try appendDiagnosticStream(&output.writer, "stdout", result.stdout);
    try appendDiagnosticStream(&output.writer, "stderr", result.stderr);
    return output.toOwnedSlice();
}

fn printSshFailure(
    allocator: Allocator,
    result: SshCommandResult,
) !void {
    const diagnostic = try sshFailureDiagnosticAlloc(allocator, result);
    defer allocator.free(diagnostic);
    std.debug.print("{s}", .{diagnostic});
}

fn sshSucceeded(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    operation: SshOperation,
    command: []const u8,
) !bool {
    var result = try runSshCommandAlloc(
        allocator,
        io,
        ssh_path,
        key_path,
        port,
        operation,
        command,
    );
    defer result.deinit(allocator);
    return result.succeeded();
}

fn sshOutputAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    operation: SshOperation,
    command: []const u8,
) ![]u8 {
    var result = try runSshCommandAlloc(
        allocator,
        io,
        ssh_path,
        key_path,
        port,
        operation,
        command,
    );
    if (!result.succeeded()) {
        defer result.deinit(allocator);
        try printSshFailure(allocator, result);
        return error.SshCommandFailed;
    }
    allocator.free(result.stderr);
    return result.stdout;
}

fn requireSshSuccess(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    operation: SshOperation,
    command: []const u8,
) !void {
    std.debug.print(
        "FreeBSD acceptance: running {s} (timeout {d}s)\n",
        .{ operation.description(), operation.timeoutSeconds() },
    );
    var result = try runSshCommandAlloc(
        allocator,
        io,
        ssh_path,
        key_path,
        port,
        operation,
        command,
    );
    defer result.deinit(allocator);
    if (result.succeeded()) return;
    try printSshFailure(allocator, result);
    return error.SshCommandFailed;
}

fn qemuRunning(
    client: *qmp.Client,
    deadline: Io.Timestamp,
) !bool {
    return client.queryRunningUntil(deadline);
}

fn waitForSerialMarker(
    allocator: Allocator,
    io: Io,
    client: *qmp.Client,
    serial_path: []const u8,
    marker: []const u8,
    failure_marker: []const u8,
) !void {
    const deadline = Io.Clock.awake.now(io).addDuration(
        .fromSeconds(boot_timeout_seconds),
    );
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        const serial = Dir.cwd().readFileAlloc(
            io,
            serial_path,
            allocator,
            .limited(serial_limit),
        ) catch |err| switch (err) {
            error.FileNotFound => try allocator.alloc(u8, 0),
            else => return err,
        };
        defer allocator.free(serial);
        if (std.mem.indexOf(u8, serial, marker) != null) return;
        if (std.mem.indexOf(u8, serial, failure_marker) != null) {
            return error.GuestReadinessFailed;
        }
        if (!try qemuRunning(client, deadline)) {
            return error.QemuExitedEarly;
        }
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.BootTimedOut;
}

fn printSerialTail(
    allocator: Allocator,
    io: Io,
    serial_path: []const u8,
) void {
    const serial = Dir.cwd().readFileAlloc(
        io,
        serial_path,
        allocator,
        .limited(serial_limit),
    ) catch return;
    defer allocator.free(serial);
    const start = serial.len - @min(serial.len, serial_tail_size);
    std.debug.print(
        "FreeBSD acceptance serial output tail:\n{s}\n",
        .{serial[start..]},
    );
}

fn countOccurrences(haystack: []const u8, needle: []const u8) usize {
    var count: usize = 0;
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, haystack, offset, needle)) |index| {
        count += 1;
        offset = index + needle.len;
    }
    return count;
}

fn serialMarkerCount(
    allocator: Allocator,
    io: Io,
    serial_path: []const u8,
    marker: []const u8,
) !usize {
    const serial = try Dir.cwd().readFileAlloc(
        io,
        serial_path,
        allocator,
        .limited(serial_limit),
    );
    defer allocator.free(serial);
    return countOccurrences(serial, marker);
}

fn waitForAdditionalSerialMarker(
    allocator: Allocator,
    io: Io,
    client: *qmp.Client,
    serial_path: []const u8,
    marker: []const u8,
    initial_count: usize,
) !void {
    const deadline = Io.Clock.awake.now(io).addDuration(
        .fromSeconds(boot_timeout_seconds),
    );
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (try serialMarkerCount(
            allocator,
            io,
            serial_path,
            marker,
        ) > initial_count) return;
        if (!try qemuRunning(client, deadline)) {
            return error.QemuExitedEarly;
        }
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.RebootTimedOut;
}

fn waitForSshState(
    allocator: Allocator,
    io: Io,
    client: *qmp.Client,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    wanted: bool,
) !void {
    const deadline = Io.Clock.awake.now(io).addDuration(
        .fromSeconds(boot_timeout_seconds),
    );
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        const connected = try sshSucceeded(
            allocator,
            io,
            ssh_path,
            key_path,
            port,
            .readiness,
            "true",
        );
        if (connected == wanted) return;
        if (!try qemuRunning(client, deadline)) {
            return error.QemuExitedEarly;
        }
        try Io.sleep(io, .fromSeconds(2), .awake);
    }
    return error.SshTimedOut;
}

fn waitForQemuExit(
    io: Io,
    spawned: *qmp.Spawned,
) !std.process.Child.Term {
    const deadline = Io.Clock.awake.now(io).addDuration(
        .fromSeconds(boot_timeout_seconds),
    );
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        const running = try spawned.client.queryRunningUntil(deadline);
        if (!running) {
            var reply = try spawned.client.executeUntil(
                "quit",
                null,
                deadline,
            );
            defer reply.deinit();
            if (reply.err != null) return error.QemuQuitFailed;
            return spawned.waitUntil(deadline);
        }
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.QemuShutdownTimedOut;
}

/// The generalized guest contract, which every profile must satisfy
/// identically. Anything that depends on how the root is stored belongs in
/// the per-filesystem checks instead.
const shared_remote_checks =
    \\set -eu
    \\test "$(/usr/sbin/sysrc -n waagent_enable)" = YES
    \\test "$(/usr/sbin/sysrc -n sshd_enable)" = YES
    \\test "$(/usr/sbin/sysrc -n nuageinit_enable)" = YES
    \\test "$(/usr/sbin/sysrc -n growfs_enable)" = YES
    \\test "$(/usr/sbin/sysrc -n growfs_swap_size)" = 0
    \\test "$(/usr/sbin/sysrc -n ifconfig_DEFAULT)" = "SYNCDHCP accept_rtadv"
    \\test "$(/usr/sbin/sysrc -n ifconfig_hn0)" = SYNCDHCP
    \\test "$(/usr/sbin/sysrc -n firstboot_pkg_upgrade_enable)" = NO
    \\/usr/local/sbin/pkg info -e azure-agent
    \\! /usr/sbin/pw usershow freebsd >/dev/null 2>&1
    \\/usr/local/bin/sudo -n /usr/bin/awk -F: '$1 == "root" && $2 == "*LOCKED*" { ok=1 } END { exit !ok }' /etc/master.passwd
    \\test -s /etc/ssh/ssh_host_ed25519_key
    \\test -s /home/zvmitest/.ssh/authorized_keys
    \\test ! -e /firstboot
    \\test ! -e /firstboot-reboot
    \\test ! -e /root/zvmi-generalize.sh
    \\test ! -e /etc/rc.d/zvmi_generalize
    \\! /usr/bin/grep -Eq '^[^#].*[[:space:]]swap[[:space:]]' /etc/fstab
    \\test "$(/usr/sbin/swapinfo -k | /usr/bin/wc -l | /usr/bin/tr -d ' ')" = 1
    \\/usr/bin/grep -Fx 'Provisioning.Agent=auto' /usr/local/etc/waagent.conf
    \\/usr/bin/grep -Fx 'ResourceDisk.SwapSizeMB=2048' /usr/local/etc/waagent.conf
    \\disk=$(/sbin/gpart show | /usr/bin/awk '$1 == "=>" { print $4; exit }')
    \\test -n "${disk}"
    \\! /sbin/gpart show | /usr/bin/grep -q CORRUPT
    \\test "$(/sbin/gpart status -s "${disk}" | /usr/bin/awk '{ print $2 }' | /usr/bin/sort -u)" = OK
;

/// UFS-specific state. The root is named in /etc/fstab and grows with
/// growfs(8), so df(1) reports the enlarged filesystem directly.
const ufs_remote_checks =
    \\test "$(/sbin/mount -p | /usr/bin/awk '$2 == "/" { print $3 }')" = ufs
    \\/usr/bin/grep -Eq '^[^#]+[[:space:]]+/[[:space:]]+ufs[[:space:]]' /etc/fstab
    \\test "$(($(/bin/df -k / | /usr/bin/awk 'END { print $2 }') * 1024))" -ge @MINIMUM_ROOT_BYTES@
;

/// ZFS-specific state. The root has no fstab entry and grows by onlining the
/// enlarged vdev, so the pool - not the dataset - is what must have grown.
/// The pool must also be healthy, carry autoexpand for later enlargements,
/// and be re-GUIDed on every boot so two clones stay distinguishable.
const zfs_remote_checks =
    \\test "$(/sbin/mount -p | /usr/bin/awk '$2 == "/" { print $3 }')" = zfs
    \\root_pool=$(/sbin/mount -p | /usr/bin/awk '$2 == "/" { print $1 }' | /usr/bin/sed 's|/.*||')
    \\test "${root_pool}" = zroot
    \\test "$(/sbin/zpool status -x "${root_pool}")" = "pool '${root_pool}' is healthy"
    \\test "$(/usr/sbin/sysrc -n zfs_enable)" = YES
    \\test "$(/usr/sbin/sysrc -n zpool_reguid)" = "${root_pool}"
    \\test "$(/sbin/zpool get -H -o value autoexpand "${root_pool}")" = on
    \\test "$(/sbin/zpool list -Hp -o size "${root_pool}")" -ge @MINIMUM_ROOT_BYTES@
    \\test -z "$(/sbin/zfs list -H -o name,org.freebsd:swap -t volume | /usr/bin/awk '$2 == "on" { print $1 }')"
    \\! /usr/bin/grep -Eq '[[:space:]]ufs[[:space:]]' /etc/fstab
;

fn replaceTokenAlloc(
    allocator: Allocator,
    template: []const u8,
    token: []const u8,
    value: []const u8,
) ![]u8 {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    var offset: usize = 0;
    while (std.mem.indexOfPos(u8, template, offset, token)) |index| {
        try output.writer.writeAll(template[offset..index]);
        try output.writer.writeAll(value);
        offset = index + token.len;
    }
    try output.writer.writeAll(template[offset..]);
    return output.toOwnedSlice();
}

/// The retained package contract, checked against a booted image. Generating
/// this from the manifest rather than restating it is what makes the
/// contract enforceable: a package removed from the manifest stops being
/// required here in the same diff, and nothing else can quietly drop one.
fn staticPackageRemoteChecksAlloc(
    allocator: Allocator,
    root_filesystem: RootFilesystem,
    flavor: Flavor,
) ![]u8 {
    const manifest = packages.forProfile(
        switch (root_filesystem) {
            .ufs => .ufs,
            .zfs => .zfs,
        },
        flavor,
    );
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    for (manifest.required) |package| {
        try output.writer.print("/usr/local/sbin/pkg info -e {s}\n", .{package.name});
    }
    for (manifest.library_roots) |library| {
        try output.writer.print("/usr/local/sbin/pkg info -e {s}\n", .{library});
    }
    for (manifest.excluded) |excluded| {
        try output.writer.print("! /usr/local/sbin/pkg info -e {s}\n", .{excluded});
    }
    for (manifest.excluded_classes) |class| {
        try output.writer.print(
            "! /usr/local/sbin/pkg query -a '%n' | " ++
                "/usr/bin/grep -Eq '^FreeBSD-.*-{s}$'\n",
            .{class},
        );
    }
    try output.writer.print(
        "! /usr/local/sbin/pkg info -e {s}\n",
        .{packages.representative_package},
    );
    return output.toOwnedSlice();
}

/// Refresh both catalogues and exercise the pkgbase solver without applying
/// an update. This is intentionally separate from the static guest contract:
/// finalized images carry neither catalogues nor package archives, so the
/// first refresh is a bounded network operation rather than an SSH probe.
fn updateRemoteChecksAlloc(
    allocator: Allocator,
    root_filesystem: RootFilesystem,
    flavor: Flavor,
) ![]u8 {
    const manifest = packages.forProfile(
        switch (root_filesystem) {
            .ufs => .ufs,
            .zfs => .zfs,
        },
        flavor,
    );
    return std.fmt.allocPrint(
        allocator,
        "set -eu\n" ++
            "package_state_before=$(/usr/local/sbin/pkg query -a '%n %v %a' | " ++
            "/usr/bin/sort | /sbin/sha256 -q)\n" ++
            "/usr/local/bin/sudo -n /usr/local/sbin/pkg update -f\n" ++
            "/usr/local/bin/sudo -n /usr/local/sbin/pkg update -f -r {s}\n" ++
            "/usr/local/sbin/pkg rquery -r {s} '%n-%v' FreeBSD-runtime >/dev/null\n" ++
            "/usr/local/bin/sudo -n /usr/local/sbin/pkg upgrade -n -U -r {s}\n" ++
            "test \"$(/usr/local/sbin/pkg query -a '%n %v %a' | " ++
            "/usr/bin/sort | /sbin/sha256 -q)\" = " ++
            "\"${{package_state_before}}\"\n",
        .{
            manifest.base_repository,
            manifest.base_repository,
            manifest.base_repository,
        },
    );
}

/// Prove a ports package can be resolved, installed, removed, and cleaned
/// without changing the shipped package set. No assertion requires an update
/// to exist; the lifecycle only requires the current catalogue to be usable.
fn packageLifecycleRemoteChecksAlloc(allocator: Allocator) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "set -eu\n" ++
            "! /usr/local/sbin/pkg info -e {s}\n" ++
            "/usr/local/sbin/pkg rquery '%n-%v' {s} >/dev/null\n" ++
            "package_state_before=$(/usr/local/sbin/pkg query -a '%n %v %a' | " ++
            "/usr/bin/sort | /sbin/sha256 -q)\n" ++
            "/usr/local/bin/sudo -n /usr/local/sbin/pkg install -y {s}\n" ++
            "/usr/local/sbin/pkg info -e {s}\n" ++
            "/usr/local/bin/sudo -n /usr/local/sbin/pkg delete -y {s}\n" ++
            "! /usr/local/sbin/pkg info -e {s}\n" ++
            "test \"$(/usr/local/sbin/pkg query -a '%n %v %a' | " ++
            "/usr/bin/sort | /sbin/sha256 -q)\" = " ++
            "\"${{package_state_before}}\"\n" ++
            "/usr/local/bin/sudo -n /usr/local/sbin/pkg clean -ay\n" ++
            "test -z \"$(/usr/bin/find /var/cache/pkg -type f)\"\n",
        .{
            packages.representative_package,
            packages.representative_package,
            packages.representative_package,
            packages.representative_package,
            packages.representative_package,
            packages.representative_package,
        },
    );
}

fn staticRemoteChecksAlloc(
    allocator: Allocator,
    root_filesystem: RootFilesystem,
    flavor: Flavor,
) ![]u8 {
    const specific = switch (root_filesystem) {
        .ufs => ufs_remote_checks,
        .zfs => zfs_remote_checks,
    };
    const minimum = try std.fmt.allocPrint(
        allocator,
        "{d}",
        .{minimum_grown_root_bytes},
    );
    defer allocator.free(minimum);
    const rendered = try replaceTokenAlloc(
        allocator,
        specific,
        "@MINIMUM_ROOT_BYTES@",
        minimum,
    );
    defer allocator.free(rendered);
    const contract = try staticPackageRemoteChecksAlloc(
        allocator,
        root_filesystem,
        flavor,
    );
    defer allocator.free(contract);
    return std.fmt.allocPrint(
        allocator,
        "{s}\n{s}\n{s}",
        .{ shared_remote_checks, rendered, contract },
    );
}

const shared_identity_command =
    \\/usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256 |
    \\  /usr/bin/awk '{ print $2 }'
    \\/sbin/sysctl -n kern.hostuuid
;

/// A ZFS root carries a third per-instance identifier that UFS has no
/// equivalent for: the pool GUID, which `zpool_reguid` re-randomizes on every
/// boot. Two clones sharing it would collide on simultaneous import.
const zfs_identity_command =
    \\/sbin/zpool get -H -o value guid zroot
;

fn identityCommandAlloc(
    allocator: Allocator,
    root_filesystem: RootFilesystem,
) ![]u8 {
    return switch (root_filesystem) {
        .ufs => allocator.dupe(u8, shared_identity_command),
        .zfs => std.fmt.allocPrint(
            allocator,
            "{s}\n{s}",
            .{ shared_identity_command, zfs_identity_command },
        ),
    };
}

const GuestIdentity = struct {
    ssh_fingerprint: []u8,
    host_uuid: []u8,
    /// Present only for a ZFS root.
    pool_guid: ?[]u8,

    fn deinit(self: *GuestIdentity, allocator: Allocator) void {
        allocator.free(self.ssh_fingerprint);
        allocator.free(self.host_uuid);
        if (self.pool_guid) |guid| allocator.free(guid);
        self.* = undefined;
    }
};

fn readGuestIdentityAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    root_filesystem: RootFilesystem,
) !GuestIdentity {
    const command = try identityCommandAlloc(allocator, root_filesystem);
    defer allocator.free(command);
    const output = try sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        key_path,
        port,
        .identity,
        command,
    );
    defer allocator.free(output);
    var lines = std.mem.splitScalar(u8, output, '\n');
    const fingerprint = std.mem.trim(
        u8,
        lines.next() orelse return error.InvalidGuestIdentity,
        " \t\r",
    );
    const host_uuid = std.mem.trim(
        u8,
        lines.next() orelse return error.InvalidGuestIdentity,
        " \t\r",
    );
    if (fingerprint.len == 0 or host_uuid.len == 0) {
        return error.InvalidGuestIdentity;
    }
    const pool_guid = switch (root_filesystem) {
        .ufs => null,
        .zfs => blk: {
            const value = std.mem.trim(
                u8,
                lines.next() orelse return error.InvalidGuestIdentity,
                " \t\r",
            );
            if (value.len == 0) return error.InvalidGuestIdentity;
            break :blk value;
        },
    };
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len != 0) {
            return error.InvalidGuestIdentity;
        }
    }
    const owned_fingerprint = try allocator.dupe(u8, fingerprint);
    errdefer allocator.free(owned_fingerprint);
    const owned_host_uuid = try allocator.dupe(u8, host_uuid);
    errdefer allocator.free(owned_host_uuid);
    const owned_pool_guid = if (pool_guid) |guid|
        try allocator.dupe(u8, guid)
    else
        null;
    return .{
        .ssh_fingerprint = owned_fingerprint,
        .host_uuid = owned_host_uuid,
        .pool_guid = owned_pool_guid,
    };
}

/// Compare the parts of two guest identities that must differ between two
/// independently provisioned instances.
fn expectDistinctIdentities(first: GuestIdentity, second: GuestIdentity) !void {
    try std.testing.expect(!std.mem.eql(
        u8,
        first.ssh_fingerprint,
        second.ssh_fingerprint,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        first.host_uuid,
        second.host_uuid,
    ));
    if (first.pool_guid) |first_guid| {
        const second_guid = second.pool_guid orelse
            return error.InconsistentIdentityShape;
        try std.testing.expect(!std.mem.eql(u8, first_guid, second_guid));
    } else if (second.pool_guid != null) {
        return error.InconsistentIdentityShape;
    }
}

test "guest identities compare every per-instance value" {
    var first = GuestIdentity{
        .ssh_fingerprint = try std.testing.allocator.dupe(u8, "SHA256:a"),
        .host_uuid = try std.testing.allocator.dupe(u8, "uuid-a"),
        .pool_guid = try std.testing.allocator.dupe(u8, "1"),
    };
    defer first.deinit(std.testing.allocator);
    var second = GuestIdentity{
        .ssh_fingerprint = try std.testing.allocator.dupe(u8, "SHA256:b"),
        .host_uuid = try std.testing.allocator.dupe(u8, "uuid-b"),
        .pool_guid = try std.testing.allocator.dupe(u8, "1"),
    };
    defer second.deinit(std.testing.allocator);

    // A shared pool GUID must fail even when every other value differs.
    try std.testing.expectError(
        error.TestUnexpectedResult,
        expectDistinctIdentities(first, second),
    );
    std.testing.allocator.free(second.pool_guid.?);
    second.pool_guid = try std.testing.allocator.dupe(u8, "2");
    try expectDistinctIdentities(first, second);

    // A UFS guest compared against a ZFS guest is a harness mistake, not a
    // passing acceptance run.
    std.testing.allocator.free(second.pool_guid.?);
    second.pool_guid = null;
    try std.testing.expectError(
        error.InconsistentIdentityShape,
        expectDistinctIdentities(first, second),
    );
}

fn expectCommandBefore(
    command: []const u8,
    first: []const u8,
    second: []const u8,
) !void {
    const first_index = std.mem.indexOf(u8, command, first) orelse
        return error.ExpectedCommandMissing;
    const second_index = std.mem.indexOf(u8, command, second) orelse
        return error.ExpectedCommandMissing;
    try std.testing.expect(first_index < second_index);
}

const BootPhase = enum {
    initial,
    after_reboot,
};

/// The builder already exercises the update and package lifecycle for every
/// image. QEMU repeats that expensive network contract once against a clean,
/// finalized clone; both clones and both boots still repeat the static and
/// identity contracts that provide the dual-instance and reboot evidence.
fn shouldRunExpensivePackageContract(
    instance_index: usize,
    boot_phase: BootPhase,
) bool {
    return instance_index == 0 and boot_phase == .initial;
}

test "static remote checks stay filesystem-specific" {
    const allocator = std.testing.allocator;
    const ufs = try staticRemoteChecksAlloc(allocator, .ufs, .full);
    defer allocator.free(ufs);
    const zfs = try staticRemoteChecksAlloc(allocator, .zfs, .full);
    defer allocator.free(zfs);

    for ([_][]const u8{ ufs, zfs }) |checks| {
        try std.testing.expect(std.mem.indexOf(u8, checks, "@") == null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            checks,
            "pkg info -e azure-agent",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            checks,
            "! /sbin/gpart show | /usr/bin/grep -q CORRUPT",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            checks,
            "8589934592",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            checks,
            "/usr/sbin/sysrc -n waagent_enable",
        ) != null);
        try std.testing.expect(std.mem.indexOf(u8, checks, ". /etc/rc.conf") == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, ufs, "zpool") == null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "zpool list -Hp -o size") != null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "df -k /") == null);
}

test "static remote checks enforce each filesystem and flavor contract" {
    const allocator = std.testing.allocator;
    for (std.enums.values(RootFilesystem)) |filesystem| {
        for (std.enums.values(Flavor)) |flavor| {
            const checks = try staticRemoteChecksAlloc(
                allocator,
                filesystem,
                flavor,
            );
            defer allocator.free(checks);
            const manifest = packages.forProfile(
                switch (filesystem) {
                    .ufs => .ufs,
                    .zfs => .zfs,
                },
                flavor,
            );
            for (manifest.required) |package| {
                const line = try std.fmt.allocPrint(
                    allocator,
                    "\n/usr/local/sbin/pkg info -e {s}\n",
                    .{package.name},
                );
                defer allocator.free(line);
                try std.testing.expect(std.mem.indexOf(u8, checks, line) != null);
            }
            try std.testing.expect(std.mem.indexOf(
                u8,
                checks,
                "! /usr/local/sbin/pkg info -e tree",
            ) != null);
            try std.testing.expect(std.mem.indexOf(u8, checks, "pkg update") == null);
            try std.testing.expect(std.mem.indexOf(u8, checks, "pkg install") == null);
        }
    }

    const full = try staticRemoteChecksAlloc(allocator, .zfs, .full);
    defer allocator.free(full);
    const core = try staticRemoteChecksAlloc(allocator, .zfs, .core);
    defer allocator.free(core);
    for (packages.core_excluded_packages) |excluded| {
        const line = try std.fmt.allocPrint(
            allocator,
            "! /usr/local/sbin/pkg info -e {s}\n",
            .{excluded},
        );
        defer allocator.free(line);
        try std.testing.expect(std.mem.indexOf(u8, core, line) != null);
        try std.testing.expect(std.mem.indexOf(u8, full, line) == null);
    }
    for (packages.library_roots) |library| {
        const line = try std.fmt.allocPrint(
            allocator,
            "/usr/local/sbin/pkg info -e {s}\n",
            .{library},
        );
        defer allocator.free(line);
        try std.testing.expect(std.mem.indexOf(u8, core, line) != null);
    }
    try std.testing.expect(std.mem.indexOf(
        u8,
        core,
        "'^FreeBSD-.*-dbg$'",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, core, "FreeBSD-zfs\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, core, "FreeBSD-zfs-lib\n") != null);
}

test "package contract phases preserve update and lifecycle ordering" {
    const allocator = std.testing.allocator;
    const update = try updateRemoteChecksAlloc(allocator, .zfs, .core);
    defer allocator.free(update);
    const lifecycle = try packageLifecycleRemoteChecksAlloc(allocator);
    defer allocator.free(lifecycle);

    try expectCommandBefore(
        update,
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg update -f\n",
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg update -f -r FreeBSD-base",
    );
    try expectCommandBefore(
        update,
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg update -f -r FreeBSD-base",
        "/usr/local/sbin/pkg rquery -r FreeBSD-base",
    );
    try expectCommandBefore(
        update,
        "/usr/local/sbin/pkg rquery -r FreeBSD-base",
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg upgrade -n -U -r FreeBSD-base",
    );
    try std.testing.expect(std.mem.indexOf(
        u8,
        update,
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg upgrade -n -U -r FreeBSD-base",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, update, "pkg install") == null);

    try expectCommandBefore(
        lifecycle,
        "/usr/local/sbin/pkg rquery '%n-%v' tree",
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg install -y tree",
    );
    try expectCommandBefore(
        lifecycle,
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg install -y tree",
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg delete -y tree",
    );
    try expectCommandBefore(
        lifecycle,
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg delete -y tree",
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg clean -ay",
    );
    try expectCommandBefore(
        lifecycle,
        "/usr/local/bin/sudo -n /usr/local/sbin/pkg clean -ay",
        "/usr/bin/find /var/cache/pkg -type f",
    );
}

test "SSH operations use phase-appropriate bounded timeouts" {
    try std.testing.expectEqual(@as(u32, 15), SshOperation.readiness.timeoutSeconds());
    try std.testing.expectEqual(@as(u32, 15), SshOperation.identity.timeoutSeconds());
    try std.testing.expectEqual(@as(u32, 120), SshOperation.static_contract.timeoutSeconds());
    try std.testing.expectEqual(@as(u32, 600), SshOperation.update_contract.timeoutSeconds());
    try std.testing.expectEqual(@as(u32, 300), SshOperation.package_lifecycle.timeoutSeconds());
    try std.testing.expectEqual(@as(u32, 30), SshOperation.power.timeoutSeconds());
    try std.testing.expect(
        SshOperation.readiness.timeoutSeconds() <
            SshOperation.update_contract.timeoutSeconds(),
    );
}

test "SSH failure diagnostics identify exit and timeout with bounded streams" {
    const allocator = std.testing.allocator;
    var exited = SshCommandResult{
        .operation = .static_contract,
        .term = .{ .exited = 7 },
        .stdout = try allocator.dupe(u8, "static stdout"),
        .stderr = try allocator.dupe(u8, "static stderr"),
        .timeout_evidence = .completed(7),
    };
    defer exited.deinit(allocator);
    const exit_diagnostic = try sshFailureDiagnosticAlloc(allocator, exited);
    defer allocator.free(exit_diagnostic);
    try std.testing.expect(std.mem.indexOf(
        u8,
        exit_diagnostic,
        "static guest contract failed with exit code 7",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, exit_diagnostic, "static stdout") != null);
    try std.testing.expect(std.mem.indexOf(u8, exit_diagnostic, "static stderr") != null);

    var timed_out = SshCommandResult{
        .operation = .update_contract,
        .term = .{ .exited = 124 },
        .stdout = try allocator.alloc(u8, ssh_diagnostic_limit_bytes + 4),
        .stderr = try allocator.dupe(u8, "update stderr"),
        .timeout_evidence = .{
            .wrapper_started = true,
            .timeout_marked = true,
            .completed_status = null,
        },
    };
    defer timed_out.deinit(allocator);
    @memset(timed_out.stdout, 'x');
    @memcpy(timed_out.stdout[0..4], "drop");
    @memcpy(timed_out.stdout[timed_out.stdout.len - 4 ..], "keep");
    const timeout_diagnostic = try sshFailureDiagnosticAlloc(allocator, timed_out);
    defer allocator.free(timeout_diagnostic);
    try std.testing.expect(std.mem.indexOf(
        u8,
        timeout_diagnostic,
        "package update contract timed out after 600 seconds",
    ) != null);
    try std.testing.expect(std.mem.indexOf(u8, timeout_diagnostic, "drop") == null);
    try std.testing.expect(std.mem.indexOf(u8, timeout_diagnostic, "keep") != null);
    try std.testing.expect(std.mem.indexOf(u8, timeout_diagnostic, "update stderr") != null);
}

test "timeout wrapper distinguishes completion, expiry, and SIGKILL escalation" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var completed = try runTimedCommandAlloc(
        allocator,
        io,
        .readiness,
        "2s",
        "1s",
        &.{ "/bin/bash", "-c", "exit 0" },
    );
    defer completed.deinit(allocator);
    try std.testing.expect(completed.succeeded());
    try std.testing.expect(!completed.timedOut());
    try std.testing.expectEqual(@as(?u8, 0), completed.timeout_evidence.completed_status);

    for ([_]u8{ 124, 137 }) |child_status| {
        const command = try std.fmt.allocPrint(
            allocator,
            "exit {d}",
            .{child_status},
        );
        defer allocator.free(command);
        var child_exit = try runTimedCommandAlloc(
            allocator,
            io,
            .readiness,
            "2s",
            "1s",
            &.{ "/bin/bash", "-c", command },
        );
        defer child_exit.deinit(allocator);
        try std.testing.expect(!child_exit.succeeded());
        try std.testing.expect(!child_exit.timedOut());
        try std.testing.expectEqual(
            @as(?u8, child_status),
            child_exit.timeout_evidence.completed_status,
        );
        const diagnostic = try sshFailureDiagnosticAlloc(
            allocator,
            child_exit,
        );
        defer allocator.free(diagnostic);
        try std.testing.expect(std.mem.indexOf(
            u8,
            diagnostic,
            "timed out",
        ) == null);
        if (child_status == 137) {
            try std.testing.expect(std.mem.indexOf(
                u8,
                diagnostic,
                "failed with exit code 137",
            ) != null);
        }
    }

    var expired = try runTimedCommandAlloc(
        allocator,
        io,
        .readiness,
        "0.1s",
        "1s",
        &.{ "/bin/sleep", "10" },
    );
    defer expired.deinit(allocator);
    try std.testing.expect(expired.timedOut());
    try std.testing.expect(expired.timeout_evidence.completed_status == null);
    try std.testing.expectEqual(
        std.process.Child.Term{ .exited = 124 },
        expired.term,
    );
    const expired_diagnostic = try sshFailureDiagnosticAlloc(
        allocator,
        expired,
    );
    defer allocator.free(expired_diagnostic);
    try std.testing.expect(std.mem.indexOf(
        u8,
        expired_diagnostic,
        "timed out after 15 seconds",
    ) != null);

    var escalated = try runTimedCommandAlloc(
        allocator,
        io,
        .readiness,
        "0.1s",
        "0.1s",
        &.{
            "/bin/bash",
            "-c",
            "trap '' TERM; while :; do /bin/sleep 1; done",
        },
    );
    defer escalated.deinit(allocator);
    try std.testing.expect(escalated.timedOut());
    try std.testing.expect(escalated.timeout_evidence.completed_status == null);
    try std.testing.expectEqual(@as(?u8, 137), shellStatus(escalated.term));
    const escalated_diagnostic = try sshFailureDiagnosticAlloc(
        allocator,
        escalated,
    );
    defer allocator.free(escalated_diagnostic);
    try std.testing.expect(std.mem.indexOf(
        u8,
        escalated_diagnostic,
        "timed out after 15 seconds",
    ) != null);
}

test "expensive package contract runs once while static evidence repeats" {
    try std.testing.expect(shouldRunExpensivePackageContract(0, .initial));
    try std.testing.expect(!shouldRunExpensivePackageContract(0, .after_reboot));
    try std.testing.expect(!shouldRunExpensivePackageContract(1, .initial));
    try std.testing.expect(!shouldRunExpensivePackageContract(1, .after_reboot));
}

test "the flavor selector accepts only known flavors" {
    try std.testing.expectEqual(Flavor.core, Flavor.parse("core").?);
    try std.testing.expectEqual(Flavor.full, Flavor.parse("full").?);
    try std.testing.expect(Flavor.parse("Core") == null);
    try std.testing.expect(Flavor.parse("") == null);
}

test "generalized FreeBSD image boots, provisions SSH, and survives reboot" {
    const allocator = std.testing.allocator;
    const architecture = try architectureFromEnvironment(allocator);
    const root_filesystem = try rootFilesystemFromEnvironment(allocator);
    const flavor = try flavorFromEnvironment(allocator);
    if (builtin.os.tag != .linux) {
        std.debug.print(
            "skipping FreeBSD {s} {s} {s} boot acceptance: QEMU is Linux-only\n",
            .{
                @tagName(architecture),
                @tagName(root_filesystem),
                @tagName(flavor),
            },
        );
        return error.SkipZigTest;
    }

    const io = std.testing.io;
    const static_remote_checks = try staticRemoteChecksAlloc(
        allocator,
        root_filesystem,
        flavor,
    );
    defer allocator.free(static_remote_checks);
    const update_remote_checks = try updateRemoteChecksAlloc(
        allocator,
        root_filesystem,
        flavor,
    );
    defer allocator.free(update_remote_checks);
    const package_lifecycle_remote_checks =
        try packageLifecycleRemoteChecksAlloc(allocator);
    defer allocator.free(package_lifecycle_remote_checks);
    const image_path = try requireImageAlloc(allocator, io, architecture);
    defer allocator.free(image_path);
    const absolute_image = try Dir.cwd().realPathFileAlloc(
        io,
        image_path,
        allocator,
    );
    defer allocator.free(absolute_image);
    const backing_format: []const u8 = if (std.mem.endsWith(
        u8,
        absolute_image,
        ".vhd",
    ))
        "vpc"
    else
        "qcow2";

    const qemu_path = try requireToolOverrideAlloc(
        allocator,
        io,
        "ZVMI_FREEBSD15_QEMU",
        architecture.qemuName(),
        architecture,
    );
    defer allocator.free(qemu_path);
    const qemu_img_path = try requireToolAlloc(
        allocator,
        io,
        "qemu-img",
        architecture,
    );
    defer allocator.free(qemu_img_path);
    const xorriso_path = try requireToolAlloc(
        allocator,
        io,
        "xorriso",
        architecture,
    );
    defer allocator.free(xorriso_path);
    const ssh_keygen_path = try requireToolAlloc(
        allocator,
        io,
        "ssh-keygen",
        architecture,
    );
    defer allocator.free(ssh_keygen_path);
    const ssh_path = try requireToolAlloc(allocator, io, "ssh", architecture);
    defer allocator.free(ssh_path);
    var firmware = try resolveFirmwareAlloc(
        allocator,
        io,
        architecture,
        qemu_path,
    );
    defer firmware.deinit(allocator);

    var identities: [2]GuestIdentity = undefined;
    var identity_count: usize = 0;
    defer for (identities[0..identity_count]) |*identity| {
        identity.deinit(allocator);
    };
    for (0..2) |instance_index| {
        var temporary = std.testing.tmpDir(.{});
        defer temporary.cleanup();
        var temporary_path_buffer: [Dir.max_path_bytes]u8 = undefined;
        const temporary_path_length = try temporary.dir.realPath(
            io,
            &temporary_path_buffer,
        );
        const temporary_path = temporary_path_buffer[0..temporary_path_length];
        const overlay_path = try std.fs.path.join(
            allocator,
            &.{ temporary_path, "overlay.qcow2" },
        );
        defer allocator.free(overlay_path);
        const vars_path = try std.fs.path.join(
            allocator,
            &.{ temporary_path, "vars.fd" },
        );
        defer allocator.free(vars_path);
        const seed_dir = try std.fs.path.join(
            allocator,
            &.{ temporary_path, "seed" },
        );
        defer allocator.free(seed_dir);
        const seed_path = try std.fs.path.join(
            allocator,
            &.{ temporary_path, "seed.iso" },
        );
        defer allocator.free(seed_path);
        const private_key_path = try std.fs.path.join(
            allocator,
            &.{ temporary_path, "id_ed25519" },
        );
        defer allocator.free(private_key_path);
        const public_key_path = try std.fmt.allocPrint(
            allocator,
            "{s}.pub",
            .{private_key_path},
        );
        defer allocator.free(public_key_path);
        const serial_path = try std.fs.path.join(
            allocator,
            &.{ temporary_path, "serial.log" },
        );
        defer allocator.free(serial_path);
        errdefer printSerialTail(allocator, io, serial_path);

        // Create the overlay larger than its backing image so first-boot
        // growth has somewhere to expand into. This proves the release image
        // grows on a bigger disk without ever rewriting the release asset.
        const expanded_size_text = try std.fmt.allocPrint(
            allocator,
            "{d}",
            .{expanded_virtual_size},
        );
        defer allocator.free(expanded_size_text);
        try runCommand(io, &.{
            qemu_img_path,
            "create",
            "-q",
            "-f",
            "qcow2",
            "-F",
            backing_format,
            "-b",
            absolute_image,
            overlay_path,
            expanded_size_text,
        });
        try Dir.copyFileAbsolute(firmware.vars_path, vars_path, io, .{
            .replace = false,
        });
        try runCommand(io, &.{
            ssh_keygen_path,
            "-q",
            "-t",
            "ed25519",
            "-N",
            "",
            "-f",
            private_key_path,
        });

        const public_key_file = try Dir.cwd().readFileAlloc(
            io,
            public_key_path,
            allocator,
            .limited(16 * 1024),
        );
        defer allocator.free(public_key_file);
        const public_key = std.mem.trim(u8, public_key_file, " \t\r\n");
        var nonce_bytes: [16]u8 = undefined;
        Io.random(io, &nonce_bytes);
        const nonce = std.fmt.bytesToHex(nonce_bytes, .lower);
        const ready_marker = try std.fmt.allocPrint(
            allocator,
            "ZVMI_FREEBSD_ACCEPTANCE_READY {s}",
            .{&nonce},
        );
        defer allocator.free(ready_marker);
        const failure_marker = try std.fmt.allocPrint(
            allocator,
            "ZVMI_FREEBSD_ACCEPTANCE_FAILED {s}",
            .{&nonce},
        );
        defer allocator.free(failure_marker);

        try Dir.cwd().createDir(io, seed_dir, .default_dir);
        const metadata = try std.fmt.allocPrint(
            allocator,
            "instance-id: zvmi-acceptance-{s}\n" ++
                "local-hostname: zvmi-acceptance\n",
            .{&nonce},
        );
        defer allocator.free(metadata);
        const user_data = try std.fmt.allocPrint(
            allocator,
            \\#cloud-config
            \\hostname: zvmi-acceptance
            \\ssh_pwauth: false
            \\users:
            \\  - name: zvmitest
            \\    groups: wheel
            \\    shell: /bin/sh
            \\    ssh_authorized_keys:
            \\      - {s}
            \\write_files:
            \\  - path: /usr/local/etc/sudoers.d/zvmitest
            \\    permissions: "0440"
            \\    content: |
            \\      zvmitest ALL=(ALL) NOPASSWD: ALL
            \\  - path: /root/zvmi-acceptance-ready.sh
            \\    permissions: "0700"
            \\    content: |
            \\      #!/bin/sh
            \\      sleep 30
            \\      if [ -s /etc/ssh/ssh_host_ed25519_key ] &&
            \\          [ -s /home/zvmitest/.ssh/authorized_keys ] &&
            \\          /usr/bin/id zvmitest >/dev/null 2>&1 &&
            \\          /usr/sbin/service sshd onestatus >/dev/null 2>&1 &&
            \\          /sbin/ifconfig vtnet0 | /usr/bin/grep -q 'inet '; then
            \\          printf 'ZVMI_FREEBSD_ACCEPTANCE_READY {s}\n' >/dev/console
            \\      else
            \\          printf 'ZVMI_FREEBSD_ACCEPTANCE_FAILED {s}\n' >/dev/console
            \\          /sbin/ifconfig -a >/dev/console 2>&1 || true
            \\          /usr/sbin/service sshd onestatus >/dev/console 2>&1 || true
            \\          /usr/bin/id zvmitest >/dev/console 2>&1 || true
            \\          /usr/bin/stat -f '%Sp %Su:%Sg %z %N' \
            \\              /home/zvmitest /home/zvmitest/.ssh \
            \\              /home/zvmitest/.ssh/authorized_keys \
            \\              >/dev/console 2>&1 || true
            \\      fi
            \\runcmd:
            \\  - /usr/sbin/daemon -cf /root/zvmi-acceptance-ready.sh
            \\
        ,
            .{ public_key, &nonce, &nonce },
        );
        defer allocator.free(user_data);
        const metadata_path = try std.fs.path.join(
            allocator,
            &.{ seed_dir, "meta-data" },
        );
        defer allocator.free(metadata_path);
        const user_data_path = try std.fs.path.join(
            allocator,
            &.{ seed_dir, "user-data" },
        );
        defer allocator.free(user_data_path);
        try Dir.cwd().writeFile(io, .{
            .sub_path = metadata_path,
            .data = metadata,
        });
        try Dir.cwd().writeFile(io, .{
            .sub_path = user_data_path,
            .data = user_data,
        });
        try runCommand(io, &.{
            xorriso_path,
            "-as",
            "mkisofs",
            "-quiet",
            "-V",
            "cidata",
            "-J",
            "-r",
            "-o",
            seed_path,
            seed_dir,
        });

        var port_bytes: [2]u8 = undefined;
        Io.random(io, &port_bytes);
        const port: u16 = 20_000 +
            (@as(u16, port_bytes[0]) << 8 | port_bytes[1]) % 20_000;
        const hostfwd = try std.fmt.allocPrint(
            allocator,
            "user,id=net0,hostfwd=tcp:127.0.0.1:{d}-:22",
            .{port},
        );
        defer allocator.free(hostfwd);
        const serial_arg = try std.fmt.allocPrint(
            allocator,
            "file:{s}",
            .{serial_path},
        );
        defer allocator.free(serial_arg);
        const code_drive = try std.fmt.allocPrint(
            allocator,
            "if=pflash,format=raw,readonly=on,file={s}",
            .{firmware.code_path},
        );
        defer allocator.free(code_drive);
        const vars_drive = try std.fmt.allocPrint(
            allocator,
            "if=pflash,format=raw,file={s}",
            .{vars_path},
        );
        defer allocator.free(vars_drive);
        const image_drive = try std.fmt.allocPrint(
            allocator,
            "file={s},format=qcow2,if=virtio",
            .{overlay_path},
        );
        defer allocator.free(image_drive);
        const seed_drive = try std.fmt.allocPrint(
            allocator,
            "file={s},format=raw,if=virtio,readonly=on",
            .{seed_path},
        );
        defer allocator.free(seed_drive);

        var spawned = try qmp.spawnAndConnect(allocator, io, .{
            .binary = qemu_path,
            .extra_args = &.{
                "-machine",
                architecture.machineArg(),
                "-cpu",
                architecture.cpuArg(),
                "-smp",
                "2",
                "-m",
                "2048",
                "-display",
                "none",
                "-no-shutdown",
                "-monitor",
                "none",
                "-serial",
                serial_arg,
                "-drive",
                code_drive,
                "-drive",
                vars_drive,
                "-drive",
                image_drive,
                "-drive",
                seed_drive,
                "-netdev",
                hostfwd,
                "-device",
                "virtio-net-pci,netdev=net0,romfile=",
                "-device",
                "virtio-rng-pci",
            },
            .stdout = .ignore,
            .stderr = .inherit,
        });
        var child_waited = false;
        defer {
            if (!child_waited) spawned.kill();
            spawned.deinit();
        }

        try waitForSerialMarker(
            allocator,
            io,
            spawned.client,
            serial_path,
            ready_marker,
            failure_marker,
        );
        try waitForSshState(
            allocator,
            io,
            spawned.client,
            ssh_path,
            private_key_path,
            port,
            true,
        );
        try requireSshSuccess(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            .static_contract,
            static_remote_checks,
        );
        if (shouldRunExpensivePackageContract(instance_index, .initial)) {
            try requireSshSuccess(
                allocator,
                io,
                ssh_path,
                private_key_path,
                port,
                .update_contract,
                update_remote_checks,
            );
            try requireSshSuccess(
                allocator,
                io,
                ssh_path,
                private_key_path,
                port,
                .package_lifecycle,
                package_lifecycle_remote_checks,
            );
        }
        var identity_before_reboot = try readGuestIdentityAlloc(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            root_filesystem,
        );
        var identity_owned = true;
        errdefer if (identity_owned) identity_before_reboot.deinit(allocator);

        const kernel_marker = "FreeBSD 15.1-RELEASE releng/15.1";
        const initial_boot_count = try serialMarkerCount(
            allocator,
            io,
            serial_path,
            kernel_marker,
        );
        try std.testing.expect(initial_boot_count > 0);
        _ = try sshSucceeded(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            .power,
            "sudo -n /sbin/shutdown -r now",
        );
        try waitForAdditionalSerialMarker(
            allocator,
            io,
            spawned.client,
            serial_path,
            kernel_marker,
            initial_boot_count,
        );
        try waitForSshState(
            allocator,
            io,
            spawned.client,
            ssh_path,
            private_key_path,
            port,
            true,
        );
        try requireSshSuccess(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            .static_contract,
            static_remote_checks,
        );
        var identity_after_reboot = try readGuestIdentityAlloc(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            root_filesystem,
        );
        defer identity_after_reboot.deinit(allocator);
        try std.testing.expectEqualStrings(
            identity_before_reboot.ssh_fingerprint,
            identity_after_reboot.ssh_fingerprint,
        );
        try std.testing.expectEqualStrings(
            identity_before_reboot.host_uuid,
            identity_after_reboot.host_uuid,
        );
        // zpoolreguid is a firstboot script, so a ZFS guest's pool GUID must
        // stay put across a reboot just like its host UUID.
        if (identity_before_reboot.pool_guid) |before| {
            try std.testing.expectEqualStrings(
                before,
                identity_after_reboot.pool_guid orelse
                    return error.InconsistentIdentityShape,
            );
        }
        identities[instance_index] = identity_before_reboot;
        identity_count += 1;
        identity_owned = false;

        _ = try sshSucceeded(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            .power,
            "sudo -n /sbin/shutdown -p now",
        );
        const term = try waitForQemuExit(io, &spawned);
        child_waited = true;
        switch (term) {
            .exited => |code| try std.testing.expectEqual(@as(u8, 0), code),
            else => return error.QemuDidNotExitCleanly,
        }
    }
    try expectDistinctIdentities(identities[0], identities[1]);
}
