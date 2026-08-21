//! Native, offline operations on an Ubuntu root directory.
//!
//! The directory is a bounded staging view produced by `ext4_mountless`; it
//! is never treated as a general host path.  Filesystem changes are explicit
//! operations and guest processes can only be selected from `Command`. The
//! executor follows the existing `unsafe_chroot` namespace contract: private
//! mounts, a private PID/network namespace, an exact environment, bounded
//! output, and teardown before the caller can publish the root.

const std = @import("std");
const builtin = @import("builtin");

const Allocator = std.mem.Allocator;
const Io = std.Io;

pub const Architecture = enum {
    x86_64,
    aarch64,

    pub fn host() Architecture {
        return switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => .x86_64,
        };
    }
};

pub const NetworkPolicy = enum { disabled };
pub const DevicePolicy = enum { minimal };
pub const PidfdMode = enum { auto, force_unavailable, force_blocked, force_fd_exhaustion, force_unexpected };
pub const PidfdOpenFn = *const fn (pid: i32) usize;
const cleanup_timeout_ms: u64 = 90 * 1000;

pub const Limits = struct {
    max_file_bytes: u64 = 256 * 1024 * 1024,
    max_entries: usize = 16 * 1024,
};

pub const FileSource = union(enum) {
    inline_bytes: []const u8,
    host_path: []const u8,
};

pub const WriteFile = struct {
    path: []const u8,
    source: FileSource,
    mode: u32 = 0o644,
};

pub const CreateDirectory = struct {
    path: []const u8,
    mode: u32 = 0o755,
};

pub const ReplaceSymlink = struct {
    path: []const u8,
    target: []const u8,
};

pub const Cleanup = struct {
    directory: []const u8,
    /// A single `*` is supported and matches any basename.  The pattern is
    /// intentionally not a shell glob and never leaves `directory`.
    pattern: []const u8,
};

pub const Operation = union(enum) {
    write_file: WriteFile,
    create_directory: CreateDirectory,
    replace_symlink: ReplaceSymlink,
    remove: []const u8,
    cleanup: Cleanup,
};

pub const FoundEntry = struct {
    path: []u8,
    directory: bool,
};

pub const Inspection = struct {
    path: []u8,
    kind: Kind,
    size: u64,
};

pub const Kind = enum { file, directory, symlink, other };

const ParentDirectory = struct {
    dir: Io.Dir,
    name: []const u8,
};

pub const Command = union(enum) {
    update_initramfs: []const u8,
    dpkg_query,
    cloud_init_clean: struct { logs: bool = true },
};

pub const CommandOutcome = enum { succeeded, failed, timed_out };

pub const CommandRecord = struct {
    tool: []const u8,
    arguments: []const []const u8,
    outcome: CommandOutcome,
    exit_code: ?u8,
};

pub const CommandResult = struct {
    outcome: CommandOutcome,
    exit_code: ?u8,
    stdout: []u8,
    stderr: []u8,

    pub fn deinit(self: *CommandResult, allocator: Allocator) void {
        allocator.free(self.stdout);
        allocator.free(self.stderr);
        self.* = undefined;
    }
};

pub const ExecutorOptions = struct {
    root: *const Root,
    architecture: Architecture,
    timeout_ms: u64 = 30 * 60 * 1000,
    network: NetworkPolicy = .disabled,
    devices: DevicePolicy = .minimal,
    /// The executor requires a privileged mount namespace.  Callers may
    /// disable this only for a test runner supplied through `run_fn`.
    require_privileged_namespace: bool = true,
    pre_chroot_delay_ms: u64 = 0,
    supervisor_timeout_ms_override: ?u64 = null,
    pidfd_mode: PidfdMode = .auto,
    pidfd_open_fn: ?PidfdOpenFn = null,
    run_fn: ?*const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        argv: []const []const u8,
        timeout_ms: u64,
    ) anyerror!CommandResult = null,
    run_context: ?*anyopaque = null,
};

pub const Executor = struct {
    allocator: Allocator,
    io: Io,
    options: ExecutorOptions,
    root_dir: Io.Dir,
    root_inode: Io.File.INode,
    root_dir_owned: bool = true,
    records: std.array_list.Managed(CommandRecord),

    pub fn init(allocator: Allocator, io: Io, options: ExecutorOptions) !Executor {
        if (options.architecture != Architecture.host()) return error.ArchitectureMismatch;
        if (options.network != .disabled) return error.NetworkPolicyViolation;
        if (options.devices != .minimal) return error.DevicePolicyViolation;
        if (options.require_privileged_namespace and
            (builtin.os.tag != .linux or std.os.linux.geteuid() != 0))
        {
            return error.PrivilegedNamespaceRequired;
        }
        const root_dir = try options.root.duplicateDir();
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
            .root_dir = root_dir,
            .root_inode = options.root.root_inode,
            .records = .init(allocator),
        };
    }

    pub fn deinit(self: *Executor) void {
        for (self.records.items) |record| {
            self.allocator.free(record.tool);
            for (record.arguments) |argument| self.allocator.free(argument);
            self.allocator.free(record.arguments);
        }
        self.records.deinit();
        if (self.root_dir_owned) self.root_dir.close(self.io);
        self.* = undefined;
    }

    pub fn commandRecords(self: *const Executor) []const CommandRecord {
        return self.records.items;
    }

    pub fn execute(self: *Executor, command: Command) !CommandResult {
        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try self.appendCommand(&argv, command);
        const timeout_ms = @min(self.options.timeout_ms, commandTimeoutMs(command));
        const result = if (self.options.run_fn) |run_fn|
            try run_fn(
                self.options.run_context,
                self.allocator,
                self.io,
                argv.items,
                timeout_ms,
            )
        else
            try self.runIsolated(argv.items, timeout_ms);
        errdefer {
            var discard = result;
            discard.deinit(self.allocator);
        }

        const normalized_result = result;
        const outcome = normalized_result.outcome;
        const exit_code = normalized_result.exit_code;
        const tool = try self.allocator.dupe(u8, argv.items[argv.items.len - commandArgCount(command)]);
        const arguments = self.allocator.alloc([]const u8, argv.items.len) catch |err| {
            self.allocator.free(tool);
            return err;
        };
        var arguments_owned = true;
        defer if (arguments_owned) {
            self.allocator.free(tool);
            for (arguments) |argument| if (argument.len != 0) self.allocator.free(argument);
            self.allocator.free(arguments);
        };
        for (arguments) |*argument| argument.* = &.{};
        for (argv.items, 0..) |argument, index| {
            arguments[index] = try self.allocator.dupe(u8, argument);
        }
        try self.records.append(.{
            .tool = tool,
            .arguments = arguments,
            .outcome = outcome,
            .exit_code = exit_code,
        });
        std.debug.print(
            "offline-root: {s} outcome={s} exit={any}\n",
            .{ tool, @tagName(outcome), exit_code },
        );

        arguments_owned = false;

        if (outcome == .timed_out) {
            return error.CommandTimeout;
        }
        if (outcome == .failed) {
            return error.CommandFailed;
        }
        return normalized_result;
    }

    fn appendCommand(self: *Executor, argv: *std.array_list.Managed([]const u8), command: Command) !void {
        _ = self;
        switch (command) {
            .update_initramfs => |release| {
                try validateToken(release, error.InvalidKernelRelease);
                try argv.append("/usr/sbin/update-initramfs");
                try argv.append("-c");
                try argv.append("-k");
                try argv.append(release);
            },
            .dpkg_query => {
                try argv.append("/usr/bin/dpkg-query");
                try argv.append("-W");
                try argv.append("-f=${binary:Package}\t${Version}\t${Architecture}\n");
            },
            .cloud_init_clean => |options| {
                try argv.append("/usr/bin/cloud-init");
                try argv.append("clean");
                if (options.logs) try argv.append("--logs");
            },
        }
    }

    fn runIsolated(
        self: *Executor,
        guest_argv: []const []const u8,
        timeout_ms: u64,
    ) !CommandResult {
        if (builtin.os.tag != .linux) return error.UnsupportedHost;
        // The namespace's first child is chrooted before this script can
        // mount /proc or run guest code. The host-side `std.process.run`
        // timeout supervises the whole unshare process; the in-namespace
        // setpriv/timeout pair drops capabilities before guest code starts,
        // supplies a shorter command deadline, and kills its process group
        // before the reverse unmount trap runs.
        const inner_script =
            \\set -eu
            \\timeout_seconds="$1"
            \\shift
            \\cd /
            \\cleanup() { status=$?; umount -n /tmp 2>/dev/null || umount -n -l /tmp 2>/dev/null || { echo tmp-cleanup-failed >&2; status=125; }; umount -n /run 2>/dev/null || umount -n -l /run 2>/dev/null || { echo run-cleanup-failed >&2; status=125; }; umount -n /sys 2>/dev/null || umount -n -l /sys 2>/dev/null || { echo sys-cleanup-failed >&2; status=125; }; umount -n /proc 2>/dev/null || umount -n -l /proc 2>/dev/null || { echo proc-cleanup-failed >&2; status=125; }; umount -n /dev 2>/dev/null || umount -n -l /dev 2>/dev/null || true; exit "$status"; }
            \\trap cleanup EXIT
            \\mount -t proc -o nosuid,nodev,noexec proc /proc
            \\mount -t sysfs -o ro,nosuid,nodev,noexec sysfs /sys
            \\mount -t tmpfs -o mode=0755,nosuid tmpfs /dev
            \\mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs /run
            \\mount -t tmpfs -o mode=1777,nosuid,nodev,noexec tmpfs /tmp
            \\mknod -m 666 /dev/null c 1 3
            \\mknod -m 666 /dev/zero c 1 5
            \\mknod -m 666 /dev/random c 1 8
            \\mknod -m 666 /dev/urandom c 1 9
            \\chmod 666 /dev/null /dev/zero /dev/random /dev/urandom
            \\set +e
            \\setpriv --inh-caps=-all --ambient-caps=-all --bounding-set=-all -- timeout --signal=TERM --kill-after=5s "$timeout_seconds" "$@"
            \\status=$?
            \\set -e
            \\if [ "$status" -eq 124 ] || [ "$status" -eq 137 ]; then kill -KILL -1 2>/dev/null || true; for i in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16; do wait 2>/dev/null || break; done; fi
            \\exit "$status"
        ;
        const unshare_script =
            \\set -eu
            \\root_fd="$1"
            \\shift
            \\inner_script="$1"
            \\shift
            \\mountpoint="$1"
            \\shift
            \\pre_chroot_seconds="$1"
            \\shift
            \\case "$root_fd" in *[!0-9]*|'') exit 125;; esac
            \\if [ "$pre_chroot_seconds" != "0" ]; then sleep "$pre_chroot_seconds"; fi
            \\mount --bind "/proc/self/fd/$root_fd" "$mountpoint"
            \\for fd_path in /proc/self/fd/*; do fd="${fd_path##*/}"; case "$fd" in 0|1|2) ;; *) eval "exec ${fd}>&-" 2>/dev/null || true ;; esac; done
            \\exec chroot "$mountpoint" /bin/sh -c "$inner_script" vmiz-offline-root "$@"
        ;
        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try argv.append("setsid");
        try argv.append("unshare");
        try argv.append("--mount");
        try argv.append("--net");
        try argv.append("--pid");
        try argv.append("--fork");
        try argv.append("--kill-child");
        try argv.append("--propagation");
        try argv.append("private");
        try argv.append("--");
        try argv.append("/bin/sh");
        try argv.append("-c");
        try argv.append(unshare_script);
        try argv.append("vmiz-unshare");
        const root_fd_text = try std.fmt.allocPrint(
            self.allocator,
            "{d}",
            .{self.root_dir.handle},
        );
        try argv.append(root_fd_text);
        try argv.append(inner_script);
        const mountpoint = try std.fmt.allocPrint(
            self.allocator,
            "/run/vmiz-offline-root-{d}-{d}",
            .{ std.os.linux.getpid(), self.root_dir.handle },
        );
        try argv.append(mountpoint);
        const pre_chroot_seconds = try std.fmt.allocPrint(
            self.allocator,
            "{d}",
            .{std.math.divCeil(u64, self.options.pre_chroot_delay_ms, 1000) catch return error.TimeoutOutOfRange},
        );
        try argv.append(pre_chroot_seconds);
        const timeout_seconds = try std.fmt.allocPrint(
            self.allocator,
            "{d}s",
            .{std.math.divCeil(u64, timeout_ms, 1000) catch return error.TimeoutOutOfRange},
        );
        try argv.append(timeout_seconds);
        try argv.appendSlice(guest_argv);
        defer self.allocator.free(root_fd_text);
        defer self.allocator.free(pre_chroot_seconds);
        defer self.allocator.free(timeout_seconds);
        defer self.allocator.free(mountpoint);
        try Io.Dir.createDirAbsolute(self.io, mountpoint, .fromMode(0o700));
        defer Io.Dir.deleteDirAbsolute(self.io, mountpoint) catch {};

        var environment = std.process.Environ.Map.init(self.allocator);
        defer environment.deinit();
        try environment.put("HOME", "/root");
        try environment.put("LANG", "C");
        try environment.put("LC_ALL", "C");
        try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        try environment.put("TERM", "dumb");
        try environment.put("DEBIAN_FRONTEND", "noninteractive");
        const result = try self.runSupervised(argv.items, &environment, timeout_ms);
        return result;
    }

    fn runSupervised(
        self: *Executor,
        argv: []const []const u8,
        environment: *std.process.Environ.Map,
        timeout_ms: u64,
    ) !CommandResult {
        var child = try std.process.spawn(self.io, .{
            .argv = argv,
            .environ_map = environment,
            .stdin = .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
        var multi_reader: Io.File.MultiReader = undefined;
        multi_reader.init(
            self.allocator,
            self.io,
            multi_reader_buffer.toStreams(),
            &.{ child.stdout.?, child.stderr.? },
        );
        defer multi_reader.deinit();
        const stdout_reader = multi_reader.reader(0);
        const stderr_reader = multi_reader.reader(1);
        const host_timeout_ms = self.options.supervisor_timeout_ms_override orelse
            (std.math.add(u64, timeout_ms, cleanup_timeout_ms) catch return error.TimeoutOutOfRange);
        const timeout: Io.Timeout = .{ .duration = .{
            .raw = std.Io.Duration.fromMilliseconds(
                std.math.cast(i64, host_timeout_ms) orelse return error.TimeoutOutOfRange,
            ),
            .clock = .awake,
        } };
        const deadline = timeout.toDeadline(self.io);
        while (multi_reader.fill(64, deadline)) |_| {
            if (stdout_reader.buffered().len > 4 * 1024 * 1024 or
                stderr_reader.buffered().len > 4 * 1024 * 1024)
            {
                killProcessGroup(&child);
                child.kill(self.io);
                return error.StreamTooLong;
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            error.Timeout => {
                killProcessGroup(&child);
                child.kill(self.io);
                return .{
                    .outcome = .timed_out,
                    .exit_code = null,
                    .stdout = &.{},
                    .stderr = &.{},
                };
            },
            else => |read_err| {
                killProcessGroup(&child);
                child.kill(self.io);
                return read_err;
            },
        }
        try multi_reader.checkAnyError();
        const term = waitUntilDeadline(
            self.io,
            &child,
            deadline,
            self.options.pidfd_mode,
            self.options.pidfd_open_fn,
        ) catch |err| {
            killProcessGroup(&child);
            child.kill(self.io);
            if (err == error.Timeout) {
                return .{
                    .outcome = .timed_out,
                    .exit_code = null,
                    .stdout = &.{},
                    .stderr = &.{},
                };
            }
            return err;
        };
        const stdout = try multi_reader.toOwnedSlice(0);
        errdefer self.allocator.free(stdout);
        const stderr = try multi_reader.toOwnedSlice(1);
        const exit_code: ?u8 = switch (term) {
            .exited => |code| std.math.cast(u8, code),
            else => null,
        };
        return .{
            .outcome = if (exit_code == 0)
                .succeeded
            else if (exit_code == 124 or exit_code == 137)
                .timed_out
            else
                .failed,
            .exit_code = exit_code,
            .stdout = stdout,
            .stderr = stderr,
        };
    }
};

fn killProcessGroup(child: *std.process.Child) void {
    if (comptime builtin.os.tag != .linux) return;
    const pid = child.id orelse return;
    _ = std.os.linux.kill(-@as(i32, @intCast(pid)), .TERM);
    _ = std.os.linux.kill(-@as(i32, @intCast(pid)), .KILL);
}

fn waitUntilDeadline(
    io: Io,
    child: *std.process.Child,
    deadline: Io.Timeout,
    mode: PidfdMode,
    pidfd_open_fn: ?PidfdOpenFn,
) !std.process.Child.Term {
    if (comptime builtin.os.tag != .linux) return child.wait(io);
    const pid = child.id orelse return error.Timeout;
    if (mode == .force_unexpected) return error.PidfdSetupFailed;
    if (mode != .auto) return waitpidFallback(io, child, pid, deadline);
    const opened = if (pidfd_open_fn) |open_fn|
        open_fn(@intCast(pid))
    else
        std.os.linux.pidfd_open(pid, 0);
    if (std.os.linux.errno(opened) != .SUCCESS) switch (std.os.linux.errno(opened)) {
        .NOSYS, .INVAL, .PERM, .MFILE, .NFILE => return waitpidFallback(io, child, pid, deadline),
        else => return error.PidfdSetupFailed,
    };
    const pidfd: i32 = @intCast(opened);
    defer _ = std.os.linux.close(pidfd);
    while (true) {
        const remaining = deadline.toDurationFromNow(io) orelse return child.wait(io);
        if (remaining.raw.nanoseconds <= 0) return error.Timeout;
        var fds = [_]std.os.linux.pollfd{.{
            .fd = pidfd,
            .events = std.os.linux.POLL.IN,
            .revents = 0,
        }};
        const milliseconds = @max(@as(i64, 1), remaining.raw.toMilliseconds());
        const poll_result = std.os.linux.poll(&fds, fds.len, @intCast(@min(milliseconds, std.math.maxInt(i32))));
        switch (std.os.linux.errno(poll_result)) {
            .SUCCESS => if (poll_result != 0) return child.wait(io),
            .INTR => {},
            else => return waitpidFallback(io, child, pid, deadline),
        }
    }
}

fn waitpidFallback(
    io: Io,
    child: *std.process.Child,
    pid: std.os.linux.pid_t,
    deadline: Io.Timeout,
) !std.process.Child.Term {
    while (true) {
        const remaining = deadline.toDurationFromNow(io) orelse {
            var status: u32 = undefined;
            _ = std.os.linux.waitpid(pid, &status, 0);
            clearReapedChild(io, child);
            return waitStatusTerm(status);
        };
        if (remaining.raw.nanoseconds <= 0) return error.Timeout;
        var status: u32 = undefined;
        const result = std.os.linux.waitpid(pid, &status, std.os.linux.W.NOHANG);
        switch (std.os.linux.errno(result)) {
            .SUCCESS => {
                if (result != 0) {
                    clearReapedChild(io, child);
                    return waitStatusTerm(status);
                }
            },
            .INTR => continue,
            else => return error.WaitpidFailed,
        }
        const sleep_ns = @min(
            remaining.raw.nanoseconds,
            @as(i96, 10 * std.time.ns_per_ms),
        );
        try Io.sleep(io, Io.Duration.fromNanoseconds(sleep_ns), .awake);
    }
}

fn clearReapedChild(io: Io, child: *std.process.Child) void {
    if (child.stdin) |file| file.close(io);
    if (child.stdout) |file| file.close(io);
    if (child.stderr) |file| file.close(io);
    child.stdin = null;
    child.stdout = null;
    child.stderr = null;
    child.id = null;
}

fn waitStatusTerm(status: u32) std.process.Child.Term {
    const signal = status & 0x7f;
    if (signal == 0) return .{ .exited = @intCast((status >> 8) & 0xff) };
    if (signal == 0x7f) return .{ .stopped = @enumFromInt(@as(u8, @intCast((status >> 8) & 0xff))) };
    return .{ .signal = @enumFromInt(@as(u8, @intCast(signal))) };
}

pub const Root = struct {
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    root_dir: Io.Dir,
    root_inode: Io.File.INode,
    limits: Limits = .{},

    pub fn init(allocator: Allocator, io: Io, root_path: []const u8, limits: Limits) !Root {
        if (!std.fs.path.isAbsolute(root_path)) return error.RootPathMustBeAbsolute;
        var root_dir = try openRootPathNoFollow(io, root_path);
        errdefer root_dir.close(io);
        const stat = try root_dir.stat(io);
        if (stat.kind != .directory) return error.RootNotDirectory;
        return .{
            .allocator = allocator,
            .io = io,
            .root_path = root_path,
            .root_dir = root_dir,
            .root_inode = stat.inode,
            .limits = limits,
        };
    }

    pub fn deinit(self: *Root) void {
        self.root_dir.close(self.io);
        self.* = undefined;
    }

    pub fn apply(self: *Root, operations: []const Operation) !void {
        for (operations) |operation| try self.applyOne(operation);
    }

    pub fn applyOne(self: *Root, operation: Operation) !void {
        switch (operation) {
            .write_file => |file| try self.writeFile(file),
            .create_directory => |directory| try self.createDirectory(directory.path, directory.mode),
            .replace_symlink => |link| try self.replaceSymlink(link.path, link.target),
            .remove => |path| self.remove(path, true) catch |err| switch (err) {
                error.PathNotFound => {},
                else => return err,
            },
            .cleanup => |cleanup_op| try self.cleanup(cleanup_op.directory, cleanup_op.pattern),
        }
    }

    pub fn writeFile(self: *Root, file: WriteFile) !void {
        const relative = try normalizeGuestPath(file.path);
        var bytes: []u8 = undefined;
        var owned = false;
        switch (file.source) {
            .inline_bytes => |value| {
                if (value.len > self.limits.max_file_bytes) return error.FileLimitExceeded;
                bytes = @constCast(value);
            },
            .host_path => |source| {
                bytes = try Io.Dir.cwd().readFileAlloc(self.io, source, self.allocator, .limited(self.limits.max_file_bytes));
                owned = true;
            },
        }
        defer if (owned) self.allocator.free(bytes);
        var parent = try self.openParentDirectory(relative, true);
        defer parent.dir.close(self.io);
        const existing = parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false }) catch null;
        if (existing) |stat| {
            if (stat.kind == .directory) return error.NotRegularFile;
            try parent.dir.deleteFile(self.io, parent.name);
        }
        try parent.dir.writeFile(self.io, .{
            .sub_path = parent.name,
            .data = bytes,
            .flags = .{
                .exclusive = true,
                .permissions = .fromMode(file.mode),
                .resolve_beneath = true,
            },
        });
    }

    pub fn createDirectory(self: *Root, guest_path: []const u8, mode: u32) !void {
        const relative = try normalizeGuestPath(guest_path);
        var directory = try self.openDirectoryPath(relative, true);
        defer directory.close(self.io);
        try directory.setPermissions(self.io, .fromMode(mode));
    }

    pub fn replaceSymlink(self: *Root, guest_path: []const u8, target: []const u8) !void {
        if (target.len == 0 or std.mem.indexOfScalar(u8, target, 0) != null) return error.InvalidSymlinkTarget;
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, true);
        defer parent.dir.close(self.io);
        if (parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .directory) return error.NotRegularFile;
            try parent.dir.deleteFile(self.io, parent.name);
        } else |_| {}
        try parent.dir.symLink(self.io, target, parent.name, .{});
    }

    pub fn remove(self: *Root, guest_path: []const u8, recursive: bool) !void {
        const relative = try normalizeGuestPath(guest_path);
        var parent = self.openParentDirectory(relative, false) catch |err| switch (err) {
            error.FileNotFound => return error.PathNotFound,
            else => return err,
        };
        defer parent.dir.close(self.io);
        const stat = parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false }) catch
            return error.PathNotFound;
        if (stat.kind == .directory and recursive) {
            try parent.dir.deleteTree(self.io, parent.name);
        } else {
            try parent.dir.deleteFile(self.io, parent.name);
        }
    }

    pub fn cleanup(self: *Root, guest_directory: []const u8, pattern: []const u8) !void {
        const entries = self.discover(guest_directory, pattern) catch |err| switch (err) {
            error.FileNotFound => return,
            else => return err,
        };
        defer self.freeFound(entries);
        for (entries) |entry| try self.remove(entry.path, true);
    }

    pub fn discover(self: *Root, guest_directory: []const u8, pattern: []const u8) ![]FoundEntry {
        if (std.mem.count(u8, pattern, "*") > 1) return error.InvalidDiscoveryPattern;
        const relative = try normalizeGuestPath(guest_directory);
        var dir = try self.openDirectoryPath(relative, false);
        defer dir.close(self.io);
        var iterator = dir.iterate();
        var entries = std.array_list.Managed(FoundEntry).init(self.allocator);
        errdefer {
            for (entries.items) |entry| self.allocator.free(entry.path);
            entries.deinit();
        }
        while (try iterator.next(self.io)) |entry| {
            if (entries.items.len >= self.limits.max_entries) return error.EntryLimitExceeded;
            if (!wildcardMatch(pattern, entry.name)) continue;
            const path = if (std.mem.eql(u8, guest_directory, "/"))
                try std.fmt.allocPrint(self.allocator, "/{s}", .{entry.name})
            else
                try std.fmt.allocPrint(self.allocator, "{s}/{s}", .{ guest_directory, entry.name });
            try entries.append(.{ .path = path, .directory = entry.kind == .directory });
        }
        return entries.toOwnedSlice();
    }

    pub fn freeFound(self: *Root, entries: []const FoundEntry) void {
        for (entries) |entry| self.allocator.free(entry.path);
        self.allocator.free(entries);
    }

    pub fn inspect(self: *Root, guest_path: []const u8) !Inspection {
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, false);
        defer parent.dir.close(self.io);
        const stat = parent.dir.statFile(self.io, parent.name, .{ .follow_symlinks = false }) catch |err| switch (err) {
            error.FileNotFound => return error.PathNotFound,
            else => return err,
        };
        return .{
            .path = try self.allocator.dupe(u8, guest_path),
            .kind = switch (stat.kind) {
                .file => .file,
                .directory => .directory,
                .sym_link => .symlink,
                else => .other,
            },
            .size = stat.size,
        };
    }

    pub fn readFile(self: *Root, guest_path: []const u8) ![]u8 {
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, false);
        defer parent.dir.close(self.io);
        var file = try parent.dir.openFile(self.io, parent.name, .{
            .mode = .read_only,
            .follow_symlinks = false,
            .resolve_beneath = true,
        });
        defer file.close(self.io);
        const stat = try file.stat(self.io);
        if (stat.kind != .file) return error.NotRegularFile;
        if (stat.size > self.limits.max_file_bytes) return error.FileLimitExceeded;
        const bytes = try self.allocator.alloc(u8, @intCast(stat.size));
        errdefer self.allocator.free(bytes);
        _ = try file.readPositionalAll(self.io, bytes, 0);
        return bytes;
    }

    pub fn readLink(self: *Root, guest_path: []const u8) ![]u8 {
        const relative = try normalizeGuestPath(guest_path);
        var parent = try self.openParentDirectory(relative, false);
        defer parent.dir.close(self.io);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try parent.dir.readLink(self.io, parent.name, &buffer);
        return self.allocator.dupe(u8, buffer[0..length]);
    }

    pub fn validateArchitecture(self: *Root, architecture: Architecture) !void {
        const shell = self.readFile("/usr/bin/dash") catch return error.GuestArchitectureUnknown;
        defer self.allocator.free(shell);
        if (shell.len < 20 or !std.mem.eql(u8, shell[0..4], "\x7fELF")) {
            return error.GuestArchitectureUnknown;
        }
        const machine = std.mem.readInt(u16, shell[18..20], .little);
        const expected: u16 = switch (architecture) {
            .x86_64 => 62,
            .aarch64 => 183,
        };
        if (machine != expected) return error.ArchitectureMismatch;
    }

    pub fn extract(self: *Root, guest_path: []const u8, host_path: []const u8) !void {
        const bytes = try self.readFile(guest_path);
        defer self.allocator.free(bytes);
        try Io.Dir.cwd().writeFile(self.io, .{ .sub_path = host_path, .data = bytes });
    }

    pub fn insert(self: *Root, host_path: []const u8, guest_path: []const u8, mode: u32) !void {
        try self.writeFile(.{ .path = guest_path, .source = .{ .host_path = host_path }, .mode = mode });
    }

    pub fn activeKernelRelease(self: *Root) ![]u8 {
        const target = try self.readLink("/boot/vmlinuz");
        defer self.allocator.free(target);
        const name = std.fs.path.basename(target);
        if (!std.mem.startsWith(u8, name, "vmlinuz-") or !std.mem.endsWith(u8, name, "-azure"))
            return error.AzureKernelMissing;
        return self.allocator.dupe(u8, name["vmlinuz-".len..]);
    }

    pub fn duplicateDir(self: *const Root) !Io.Dir {
        const duplicate = if (comptime builtin.os.tag == .linux) blk: {
            const result = std.os.linux.fcntl(
                self.root_dir.handle,
                std.os.linux.F.DUPFD,
                128,
            );
            if (@as(isize, @bitCast(result)) < 0) return error.RootFdDupFailed;
            break :blk Io.Dir{ .handle = @intCast(result) };
        } else try self.root_dir.openDir(self.io, ".", .{
            .access_sub_paths = true,
            .iterate = true,
            .follow_symlinks = false,
        });
        const stat = duplicate.stat(self.io) catch |err| {
            duplicate.close(self.io);
            return err;
        };
        if (stat.kind != .directory or stat.inode != self.root_inode) {
            duplicate.close(self.io);
            return error.RootDescriptorChanged;
        }
        return duplicate;
    }

    fn openDirectoryPath(self: *Root, relative: []const u8, create_missing: bool) !Io.Dir {
        var current = try self.duplicateDir();
        if (relative.len == 0) return current;
        var components = std.mem.splitScalar(u8, relative, '/');
        while (components.next()) |component| {
            const stat = current.statFile(self.io, component, .{ .follow_symlinks = false }) catch |err| switch (err) {
                error.FileNotFound => if (create_missing) blk: {
                    try current.createDir(self.io, component, .default_dir);
                    break :blk try current.statFile(self.io, component, .{ .follow_symlinks = false });
                } else {
                    current.close(self.io);
                    return err;
                },
                else => {
                    current.close(self.io);
                    return err;
                },
            };
            if (stat.kind != .directory) {
                current.close(self.io);
                return error.NotDirectory;
            }
            const next = current.openDir(self.io, component, .{
                .access_sub_paths = true,
                .iterate = true,
                .follow_symlinks = false,
            }) catch |err| {
                current.close(self.io);
                return err;
            };
            current.close(self.io);
            current = next;
        }
        return current;
    }

    fn openParentDirectory(self: *Root, relative: []const u8, create_missing: bool) !ParentDirectory {
        if (relative.len == 0) return error.InvalidGuestPath;
        const parent = std.fs.path.dirname(relative) orelse "";
        return .{
            .dir = try self.openDirectoryPath(parent, create_missing),
            .name = std.fs.path.basename(relative),
        };
    }
};

fn commandTimeoutMs(command: Command) u64 {
    return switch (command) {
        .update_initramfs => 300 * 1000,
        .dpkg_query => 60 * 1000,
        .cloud_init_clean => 30 * 1000,
    };
}

fn commandArgCount(command: Command) usize {
    return switch (command) {
        .update_initramfs => 4,
        .dpkg_query => 3,
        .cloud_init_clean => |options| 2 + @as(usize, @intFromBool(options.logs)),
    };
}

fn validateToken(value: []const u8, err: anyerror) !void {
    if (value.len == 0 or value.len > 128) return err;
    for (value) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and byte != '_' and byte != '+' and byte != '-' and byte != '@')
            return err;
    }
}

fn normalizeGuestPath(path: []const u8) ![]const u8 {
    if (path.len == 0 or path[0] != '/' or std.mem.indexOfScalar(u8, path, 0) != null)
        return error.InvalidGuestPath;
    if (std.mem.eql(u8, path, "/")) return path[1..];
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, ".."))
            return error.InvalidGuestPath;
    }
    return path[1..];
}

fn wildcardMatch(pattern: []const u8, value: []const u8) bool {
    if (std.mem.indexOfScalar(u8, pattern, '*')) |index| {
        return std.mem.startsWith(u8, value, pattern[0..index]) and
            std.mem.endsWith(u8, value, pattern[index + 1 ..]) and
            value.len >= pattern.len - 1;
    }
    return std.mem.eql(u8, pattern, value);
}

fn openRootPathNoFollow(io: Io, absolute_path: []const u8) !Io.Dir {
    var current = try Io.Dir.openDirAbsolute(io, "/", .{
        .access_sub_paths = true,
        .iterate = true,
        .follow_symlinks = false,
    });
    var components = std.mem.splitScalar(u8, absolute_path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0) continue;
        if (std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..")) {
            current.close(io);
            return error.InvalidRootPath;
        }
        const next = current.openDir(io, component, .{
            .access_sub_paths = true,
            .iterate = true,
            .follow_symlinks = false,
        }) catch |err| {
            current.close(io);
            return err;
        };
        current.close(io);
        current = next;
    }
    return current;
}

fn expectNoResidualOfflineMounts(io: Io) !void {
    var run_dir = try Io.Dir.openDirAbsolute(io, "/run", .{ .iterate = true });
    defer run_dir.close(io);
    var iterator = run_dir.iterate();
    while (try iterator.next(io)) |entry| {
        if (std.mem.startsWith(u8, entry.name, "vmiz-offline-root-"))
            return error.OfflineRootMountpointResidual;
    }
}

fn countOpenFds(io: Io) !usize {
    var fd_dir = try Io.Dir.openDirAbsolute(io, "/proc/self/fd", .{ .iterate = true });
    defer fd_dir.close(io);
    var iterator = fd_dir.iterate();
    var count: usize = 0;
    while (try iterator.next(io)) |_| count += 1;
    return count;
}

test "offline root rejects traversal and wildcard ambiguity" {
    try std.testing.expectError(error.InvalidGuestPath, normalizeGuestPath("/etc/../shadow"));
    try std.testing.expectError(error.InvalidDiscoveryPattern, blk: {
        var root = Root{
            .allocator = std.testing.allocator,
            .io = undefined,
            .root_path = "/",
            .root_dir = undefined,
            .root_inode = undefined,
        };
        break :blk root.discover("/", "a*b*c");
    });
}

test "offline command validation is fail closed" {
    try std.testing.expectError(error.InvalidKernelRelease, blk: {
        var executor = Executor{
            .allocator = std.testing.allocator,
            .io = undefined,
            .options = .{
                .root = undefined,
                .architecture = Architecture.host(),
                .require_privileged_namespace = false,
            },
            .root_dir = undefined,
            .root_inode = undefined,
            .root_dir_owned = false,
            .records = .init(std.testing.allocator),
        };
        defer executor.deinit();
        var args = std.array_list.Managed([]const u8).init(std.testing.allocator);
        defer args.deinit();
        break :blk executor.appendCommand(&args, .{ .update_initramfs = "../bad" });
    });
}

test "offline root initialization rejects a symlinked root path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const target = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-target" });
    defer allocator.free(target);
    const link = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-link" });
    defer allocator.free(link);
    Io.Dir.cwd().deleteTree(io, target) catch {};
    Io.Dir.cwd().deleteFile(io, link) catch {};
    defer Io.Dir.cwd().deleteTree(io, target) catch {};
    defer Io.Dir.cwd().deleteFile(io, link) catch {};
    try Io.Dir.cwd().createDirPath(io, target);
    try Io.Dir.cwd().symLink(io, target, link, .{});
    const opened = Root.init(allocator, io, link, .{}) catch |err| {
        try std.testing.expect(err == error.NotDir or err == error.SymLinkLoop or err == error.GuestSymlinkTraversal);
        return;
    };
    var accepted = opened;
    accepted.deinit();
    return error.RootSymlinkAccepted;
}

const RootInitRace = struct {
    link: []const u8,
    outside: []const u8,
    stop: *std.atomic.Value(bool),
    io: Io,

    fn run(self: *RootInitRace) void {
        while (!self.stop.load(.acquire)) {
            Io.Dir.cwd().deleteTree(self.io, self.link) catch {};
            Io.Dir.cwd().symLink(self.io, self.outside, self.link, .{}) catch {};
            Io.Dir.cwd().deleteFile(self.io, self.link) catch {};
            Io.Dir.cwd().createDirPath(self.io, self.link) catch {};
        }
    }
};

test "offline root init never follows a concurrently replaced root path" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const target = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-race-target" });
    defer allocator.free(target);
    const outside = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-race-outside" });
    defer allocator.free(outside);
    const link = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-init-race-link" });
    defer allocator.free(link);
    Io.Dir.cwd().deleteTree(io, target) catch {};
    Io.Dir.cwd().deleteTree(io, outside) catch {};
    Io.Dir.cwd().deleteTree(io, link) catch {};
    defer Io.Dir.cwd().deleteTree(io, target) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside) catch {};
    defer Io.Dir.cwd().deleteTree(io, link) catch {};
    try Io.Dir.cwd().createDirPath(io, target);
    try Io.Dir.cwd().createDirPath(io, outside);
    try Io.Dir.cwd().createDirPath(io, link);
    const outside_stat = try Io.Dir.cwd().statFile(io, outside, .{ .follow_symlinks = false });

    var stop = std.atomic.Value(bool).init(false);
    var race = RootInitRace{ .link = link, .outside = outside, .stop = &stop, .io = io };
    var thread = try std.Thread.spawn(.{}, RootInitRace.run, .{&race});
    for (0..128) |_| {
        if (Root.init(allocator, io, link, .{})) |opened| {
            var root = opened;
            if (root.root_inode == outside_stat.inode) {
                root.deinit();
                stop.store(true, .release);
                thread.join();
                return error.RootInitEscapedToOutside;
            }
            root.deinit();
        } else |_| {}
    }
    stop.store(true, .release);
    thread.join();
}

test "offline root applies structured operations and cleans up" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-operations" });
    defer allocator.free(path);
    Io.Dir.cwd().deleteTree(io, path) catch {};
    defer Io.Dir.cwd().deleteTree(io, path) catch {};
    const etc = try std.fs.path.join(allocator, &.{ path, "etc" });
    defer allocator.free(etc);
    const logs = try std.fs.path.join(allocator, &.{ path, "var/log" });
    defer allocator.free(logs);
    const stale = try std.fs.path.join(allocator, &.{ logs, "stale" });
    defer allocator.free(stale);
    try Io.Dir.cwd().createDirPath(io, etc);
    try Io.Dir.cwd().createDirPath(io, logs);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = stale, .data = "stale" });

    var root = try Root.init(allocator, io, path, .{});
    defer root.deinit();
    try root.apply(&.{
        .{ .create_directory = .{ .path = "/etc/vmiz", .mode = 0o755 } },
        .{ .write_file = .{ .path = "/etc/vmiz/config", .source = .{ .inline_bytes = "ok\n" } } },
        .{ .replace_symlink = .{ .path = "/etc/vmiz/current", .target = "/etc/vmiz/config" } },
    });
    const config = try root.readFile("/etc/vmiz/config");
    defer allocator.free(config);
    try std.testing.expectEqualStrings("ok\n", config);
    const link = try root.readLink("/etc/vmiz/current");
    defer allocator.free(link);
    try std.testing.expectEqualStrings("/etc/vmiz/config", link);
    const found = try root.discover("/etc/vmiz", "*");
    defer root.freeFound(found);
    try std.testing.expectEqual(@as(usize, 2), found.len);
    try root.cleanup("/var/log", "*");
    try std.testing.expectError(error.PathNotFound, root.inspect("/var/log/stale"));
}

test "offline root refuses intermediate symlink escapes" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-symlink-root" });
    defer allocator.free(root_path);
    const outside_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-symlink-outside" });
    defer allocator.free(outside_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    const safe_path = try std.fs.path.join(allocator, &.{ root_path, "safe" });
    defer allocator.free(safe_path);
    try Io.Dir.cwd().createDirPath(io, safe_path);
    try Io.Dir.cwd().createDirPath(io, outside_path);
    const sentinel = try std.fs.path.join(allocator, &.{ outside_path, "sentinel" });
    defer allocator.free(sentinel);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = sentinel, .data = "unchanged" });

    const etc_path = try std.fs.path.join(allocator, &.{ root_path, "etc" });
    defer allocator.free(etc_path);
    try Io.Dir.cwd().symLink(io, outside_path, etc_path, .{});
    const nested_path = try std.fs.path.join(allocator, &.{ root_path, "safe/nested" });
    defer allocator.free(nested_path);
    try Io.Dir.cwd().symLink(io, outside_path, nested_path, .{});

    var root = try Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    for ([_][]const u8{ "/etc/escape", "/safe/nested/escape" }) |guest_path| {
        root.writeFile(.{
            .path = guest_path,
            .source = .{ .inline_bytes = "must-not-write" },
        }) catch |err| {
            try std.testing.expect(
                err == error.NotDir or
                    err == error.NotDirectory or
                    err == error.GuestSymlinkTraversal or
                    err == error.SymLinkLoop,
            );
            continue;
        };
        return error.SymlinkEscapeAccepted;
    }
    const unchanged = try Io.Dir.cwd().readFileAlloc(io, sentinel, allocator, .limited(1024));
    defer allocator.free(unchanged);
    try std.testing.expectEqualStrings("unchanged", unchanged);
}

const SymlinkRace = struct {
    root_path: []const u8,
    outside_path: []const u8,
    stop: *std.atomic.Value(bool),
    io: Io,

    fn run(self: *SymlinkRace) void {
        while (!self.stop.load(.acquire)) {
            const nested = std.fs.path.join(std.heap.page_allocator, &.{ self.root_path, "safe/nested" }) catch return;
            defer std.heap.page_allocator.free(nested);
            Io.Dir.cwd().deleteTree(self.io, nested) catch {};
            Io.Dir.cwd().symLink(self.io, self.outside_path, nested, .{}) catch {};
            Io.Dir.cwd().deleteFile(self.io, nested) catch {};
            Io.Dir.cwd().createDirPath(self.io, nested) catch {};
        }
    }
};

test "offline root mutations and discovery survive concurrent symlink replacement" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const root_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-concurrent-root" });
    defer allocator.free(root_path);
    const outside_path = try std.fs.path.join(allocator, &.{ cwd, "test-offline-root-concurrent-outside" });
    defer allocator.free(outside_path);
    Io.Dir.cwd().deleteTree(io, root_path) catch {};
    Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, outside_path) catch {};
    const safe_path = try std.fs.path.join(allocator, &.{ root_path, "safe" });
    defer allocator.free(safe_path);
    try Io.Dir.cwd().createDirPath(io, safe_path);
    try Io.Dir.cwd().createDirPath(io, outside_path);

    var root = try Root.init(allocator, io, root_path, .{});
    defer root.deinit();
    var stop = std.atomic.Value(bool).init(false);
    var race = SymlinkRace{
        .root_path = root_path,
        .outside_path = outside_path,
        .stop = &stop,
        .io = io,
    };
    var thread = try std.Thread.spawn(.{}, SymlinkRace.run, .{&race});
    for (0..128) |_| {
        root.writeFile(.{
            .path = "/safe/nested/file",
            .source = .{ .inline_bytes = "inside" },
        }) catch {};
        root.createDirectory("/safe/nested/mkdir", 0o755) catch {};
        root.replaceSymlink("/safe/nested/link", "/safe/nested/file") catch {};
        root.remove("/safe/nested/file", false) catch {};
        const entries = root.discover("/safe/nested", "*") catch null;
        if (entries) |found| root.freeFound(found);
    }
    stop.store(true, .release);
    thread.join();

    const outside_file = try std.fs.path.join(allocator, &.{ outside_path, "file" });
    defer allocator.free(outside_file);
    const outside_mkdir = try std.fs.path.join(allocator, &.{ outside_path, "mkdir" });
    defer allocator.free(outside_mkdir);
    const outside_link = try std.fs.path.join(allocator, &.{ outside_path, "link" });
    defer allocator.free(outside_link);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, outside_file, .{ .follow_symlinks = false }));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, outside_mkdir, .{ .follow_symlinks = false }));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, outside_link, .{ .follow_symlinks = false }));
}

const FakeRunner = struct {
    outcome: CommandOutcome,
    exit_code: ?u8 = 0,
    saw_allowlisted: bool = false,
    timeout_ms: u64 = 0,

    fn run(
        context: ?*anyopaque,
        allocator: Allocator,
        _: Io,
        argv: []const []const u8,
        timeout_ms: u64,
    ) !CommandResult {
        const self: *FakeRunner = @ptrCast(@alignCast(context.?));
        if (argv.len == 0) return error.EmptyCommand;
        self.saw_allowlisted = std.mem.eql(u8, argv[0], "/usr/bin/dpkg-query");
        self.timeout_ms = timeout_ms;
        return .{
            .outcome = self.outcome,
            .exit_code = self.exit_code,
            .stdout = try allocator.dupe(u8, ""),
            .stderr = try allocator.dupe(u8, ""),
        };
    }
};

fn fakePidfdErrno(errno: std.os.linux.E) usize {
    return @bitCast(-@as(isize, @intCast(@intFromEnum(errno))));
}

fn fakePidfdEnosys(_: i32) usize {
    return fakePidfdErrno(.NOSYS);
}
fn fakePidfdInval(_: i32) usize {
    return fakePidfdErrno(.INVAL);
}
fn fakePidfdPerm(_: i32) usize {
    return fakePidfdErrno(.PERM);
}
fn fakePidfdMfile(_: i32) usize {
    return fakePidfdErrno(.MFILE);
}
fn fakePidfdNfile(_: i32) usize {
    return fakePidfdErrno(.NFILE);
}
fn fakePidfdUnexpected(_: i32) usize {
    return fakePidfdErrno(.BADF);
}

test "offline executor enforces architecture, allowlist, timeout, and failure" {
    const host = Architecture.host();
    const foreign: Architecture = if (host == .x86_64) .aarch64 else .x86_64;
    var test_root = try Root.init(std.testing.allocator, std.testing.io, "/", .{});
    defer test_root.deinit();
    try std.testing.expectError(error.ArchitectureMismatch, Executor.init(
        std.testing.allocator,
        std.testing.io,
        .{
            .root = &test_root,
            .architecture = foreign,
            .require_privileged_namespace = false,
        },
    ));

    var success = FakeRunner{ .outcome = .succeeded };
    var executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &success,
    });
    defer executor.deinit();
    var result = try executor.execute(.dpkg_query);
    defer result.deinit(std.testing.allocator);
    try std.testing.expect(success.saw_allowlisted);
    try std.testing.expectEqual(@as(u64, 60 * 1000), success.timeout_ms);

    var timeout = FakeRunner{ .outcome = .timed_out };
    var timeout_executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &timeout,
    });
    defer timeout_executor.deinit();
    try std.testing.expectError(error.CommandTimeout, timeout_executor.execute(.{ .cloud_init_clean = .{} }));
    try std.testing.expectEqual(@as(u64, 30 * 1000), timeout.timeout_ms);

    var failure = FakeRunner{ .outcome = .failed, .exit_code = 2 };
    var failure_executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root = &test_root,
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &failure,
    });
    defer failure_executor.deinit();
    try std.testing.expectError(error.CommandFailed, failure_executor.execute(.{ .update_initramfs = "6.0.0-azure" }));
    try std.testing.expectEqual(@as(u64, 300 * 1000), failure.timeout_ms);
}

test "privileged offline namespace contains PID1 and reaps descendants" {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0) {
        std.debug.print("skipping offline-root containment test: root Linux runner required\n", .{});
        return;
    }
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const cwd = try std.process.currentPathAlloc(io, allocator);
    defer allocator.free(cwd);
    const fixture = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-integration-root" });
    defer allocator.free(fixture);
    if (Io.Dir.cwd().statFile(io, fixture, .{ .follow_symlinks = false })) |_| {} else |_| {
        std.debug.print("skipping offline-root containment test: integration root fixture missing\n", .{});
        return;
    }
    var root = try Root.init(allocator, io, fixture, .{});
    defer root.deinit();
    const pinned = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-pinned" });
    defer allocator.free(pinned);
    Io.Dir.cwd().deleteTree(io, pinned) catch {};
    try Io.Dir.rename(Io.Dir.cwd(), fixture, Io.Dir.cwd(), pinned, io);
    try Io.Dir.cwd().symLink(io, cwd, fixture, .{});
    defer {
        Io.Dir.cwd().deleteFile(io, fixture) catch {};
        Io.Dir.rename(Io.Dir.cwd(), pinned, Io.Dir.cwd(), fixture, io) catch {};
    }
    const sentinel = try std.fs.path.join(allocator, &.{ cwd, ".scratch/offline-root-host-sentinel" });
    defer allocator.free(sentinel);
    const marker = try std.fs.path.join(allocator, &.{ pinned, "descendant-marker" });
    defer allocator.free(marker);
    Io.Dir.cwd().deleteFile(io, sentinel) catch {};
    Io.Dir.cwd().deleteFile(io, marker) catch {};
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = sentinel, .data = "unchanged" });
    defer Io.Dir.cwd().deleteFile(io, sentinel) catch {};

    var executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .timeout_ms = 5 * 1000,
    });
    defer executor.deinit();
    const probe = try executor.runIsolated(
        &.{ "/bin/sh", "-c", "printf escaped > \"/proc/1/root$1\"", "probe", sentinel },
        5 * 1000,
    );
    defer {
        var result = probe;
        result.deinit(allocator);
    }
    const sentinel_bytes = try Io.Dir.cwd().readFileAlloc(io, sentinel, allocator, .limited(1024));
    defer allocator.free(sentinel_bytes);
    try std.testing.expectEqualStrings("unchanged", sentinel_bytes);
    try expectNoResidualOfflineMounts(io);
    const root_fd_text = try std.fmt.allocPrint(allocator, "{d}", .{executor.root_dir.handle});
    defer allocator.free(root_fd_text);
    const fd_probe = try executor.runIsolated(
        &.{
            "/bin/sh",
            "-c",
            "if [ -e \"/proc/self/fd/$1\" ] || [ -e \"/proc/self/fd/$1/..\" ]; then printf escaped > \"$2\"; fi; for fd in /proc/self/fd/*; do n=\"${fd##*/}\"; if [ \"$n\" = \"$1\" ]; then printf escaped > \"$2\"; fi; done",
            "fd-probe",
            root_fd_text,
            sentinel,
        },
        5 * 1000,
    );
    defer {
        var result = fd_probe;
        result.deinit(allocator);
    }
    const fd_sentinel = try Io.Dir.cwd().readFileAlloc(io, sentinel, allocator, .limited(1024));
    defer allocator.free(fd_sentinel);
    try std.testing.expectEqualStrings("unchanged", fd_sentinel);
    try expectNoResidualOfflineMounts(io);

    const timed = try executor.runIsolated(
        &.{ "/bin/sh", "-c", "(sleep 10; printf alive > /descendant-marker) & sleep 10" },
        1 * 1000,
    );
    defer {
        var result = timed;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, timed.outcome);
    try Io.sleep(io, .fromSeconds(2), .real);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, marker, .{ .follow_symlinks = false }));
    try expectNoResidualOfflineMounts(io);
    for (0..2) |_| {
        const repeated = try executor.runIsolated(
            &.{ "/bin/sh", "-c", "exit 0" },
            5 * 1000,
        );
        defer {
            var result = repeated;
            result.deinit(allocator);
        }
        try std.testing.expectEqual(CommandOutcome.succeeded, repeated.outcome);
        try expectNoResidualOfflineMounts(io);
    }
    const fds_before_fallbacks = try countOpenFds(io);
    for ([_]PidfdMode{ .force_unavailable, .force_blocked, .force_fd_exhaustion }) |mode| {
        var fallback_executor = try Executor.init(allocator, io, .{
            .root = &root,
            .architecture = Architecture.host(),
            .pidfd_mode = mode,
        });
        const completed = try fallback_executor.runIsolated(
            &.{ "/bin/sh", "-c", "exit 0" },
            5 * 1000,
        );
        fallback_executor.deinit();
        var completed_result = completed;
        defer completed_result.deinit(allocator);
        try std.testing.expectEqual(CommandOutcome.succeeded, completed.outcome);
        try expectNoResidualOfflineMounts(io);
    }
    for ([_]PidfdOpenFn{
        fakePidfdEnosys,
        fakePidfdInval,
        fakePidfdPerm,
        fakePidfdMfile,
        fakePidfdNfile,
    }) |open_fn| {
        var injected_executor = try Executor.init(allocator, io, .{
            .root = &root,
            .architecture = Architecture.host(),
            .pidfd_open_fn = open_fn,
        });
        const completed = try injected_executor.runIsolated(
            &.{ "/bin/sh", "-c", "exit 0" },
            5 * 1000,
        );
        injected_executor.deinit();
        var completed_result = completed;
        defer completed_result.deinit(allocator);
        try std.testing.expectEqual(CommandOutcome.succeeded, completed.outcome);
        try expectNoResidualOfflineMounts(io);
    }
    var injected_unexpected_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .pidfd_open_fn = fakePidfdUnexpected,
    });
    try std.testing.expectError(
        error.PidfdSetupFailed,
        injected_unexpected_executor.runIsolated(&.{ "/bin/sh", "-c", "exit 0" }, 5 * 1000),
    );
    injected_unexpected_executor.deinit();
    try expectNoResidualOfflineMounts(io);
    var unexpected_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .pidfd_mode = .force_unexpected,
    });
    try std.testing.expectError(
        error.PidfdSetupFailed,
        unexpected_executor.runIsolated(&.{ "/bin/sh", "-c", "exit 0" }, 5 * 1000),
    );
    unexpected_executor.deinit();
    try expectNoResidualOfflineMounts(io);
    try std.testing.expectEqual(fds_before_fallbacks, try countOpenFds(io));
    var stalled_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .timeout_ms = 5 * 1000,
        .pre_chroot_delay_ms = 3 * 1000,
        .supervisor_timeout_ms_override = 1 * 1000,
    });
    defer stalled_executor.deinit();
    const stalled = try stalled_executor.runIsolated(
        &.{ "/bin/sh", "-c", "exit 0" },
        5 * 1000,
    );
    defer {
        var result = stalled;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, stalled.outcome);
    try expectNoResidualOfflineMounts(io);
    var chatty_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .timeout_ms = 5 * 1000,
        .supervisor_timeout_ms_override = 1 * 1000,
    });
    defer chatty_executor.deinit();
    const chatty = try chatty_executor.runIsolated(
        &.{ "/bin/sh", "-c", "while true; do printf x; sleep 0.1; done" },
        5 * 1000,
    );
    defer {
        var result = chatty;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, chatty.outcome);
    try expectNoResidualOfflineMounts(io);
    var quiet_executor = try Executor.init(allocator, io, .{
        .root = &root,
        .architecture = Architecture.host(),
        .pidfd_mode = .force_unavailable,
        .supervisor_timeout_ms_override = 1 * 1000,
    });
    defer quiet_executor.deinit();
    const quiet = try quiet_executor.runIsolated(
        &.{ "/bin/sh", "-c", "exec 1>&- 2>&-; sleep 10" },
        5 * 1000,
    );
    defer {
        var result = quiet;
        result.deinit(allocator);
    }
    try std.testing.expectEqual(CommandOutcome.timed_out, quiet.outcome);
    try expectNoResidualOfflineMounts(io);
    Io.Dir.cwd().access(io, fixture, .{ .read = true, .execute = true }) catch
        return error.OfflineRootTeardownIncomplete;
}
