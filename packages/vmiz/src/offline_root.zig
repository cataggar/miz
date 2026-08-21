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
    root_path: []const u8,
    architecture: Architecture,
    timeout_ms: u64 = 30 * 60 * 1000,
    network: NetworkPolicy = .disabled,
    devices: DevicePolicy = .minimal,
    /// The executor requires a privileged mount namespace.  Callers may
    /// disable this only for a test runner supplied through `run_fn`.
    require_privileged_namespace: bool = true,
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
    records: std.array_list.Managed(CommandRecord),

    pub fn init(allocator: Allocator, io: Io, options: ExecutorOptions) !Executor {
        if (!std.fs.path.isAbsolute(options.root_path)) return error.RootPathMustBeAbsolute;
        if (options.root_path.len == 0) return error.InvalidRootPath;
        if (options.architecture != Architecture.host()) return error.ArchitectureMismatch;
        if (options.network != .disabled) return error.NetworkPolicyViolation;
        if (options.devices != .minimal) return error.DevicePolicyViolation;
        if (options.require_privileged_namespace and
            (builtin.os.tag != .linux or std.os.linux.geteuid() != 0))
        {
            return error.PrivilegedNamespaceRequired;
        }
        return .{
            .allocator = allocator,
            .io = io,
            .options = options,
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
        const script =
            \\set -eu
            \\root="$1"
            \\shift
            \\timeout_seconds="$1"
            \\shift
            \\cleanup() { status=$?; umount "$root/tmp" 2>/dev/null || status=125; umount "$root/run" 2>/dev/null || status=125; umount "$root/sys" 2>/dev/null || status=125; umount "$root/proc" 2>/dev/null || status=125; umount "$root/dev" 2>/dev/null || status=125; exit "$status"; }
            \\trap cleanup EXIT
            \\mount --make-rprivate /
            \\mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$root/dev"
            \\mount -t proc -o nosuid,nodev,noexec proc "$root/proc"
            \\mount -t sysfs -o ro,nosuid,nodev,noexec sysfs "$root/sys"
            \\mount -t tmpfs -o mode=0755,nosuid,nodev tmpfs "$root/run"
            \\mount -t tmpfs -o mode=1777,nosuid,nodev,noexec tmpfs "$root/tmp"
            \\mknod -m 666 "$root/dev/null" c 1 3
            \\mknod -m 666 "$root/dev/zero" c 1 5
            \\mknod -m 666 "$root/dev/random" c 1 8
            \\mknod -m 666 "$root/dev/urandom" c 1 9
            \\exec timeout --signal=TERM --kill-after=5s "$timeout_seconds" setsid chroot "$root" "$@"
        ;
        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
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
        try argv.append(script);
        try argv.append("vmiz-offline-root");
        const timeout_seconds = try std.fmt.allocPrint(
            self.allocator,
            "{d}s",
            .{std.math.divCeil(u64, timeout_ms, 1000) catch return error.TimeoutOutOfRange},
        );
        try argv.append(timeout_seconds);
        try argv.append(self.options.root_path);
        try argv.appendSlice(guest_argv);
        defer self.allocator.free(timeout_seconds);

        var environment = std.process.Environ.Map.init(self.allocator);
        defer environment.deinit();
        try environment.put("HOME", "/root");
        try environment.put("LANG", "C");
        try environment.put("LC_ALL", "C");
        try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
        try environment.put("TERM", "dumb");
        try environment.put("DEBIAN_FRONTEND", "noninteractive");
        const result = std.process.run(self.allocator, self.io, .{
            .argv = argv.items,
            .environ_map = &environment,
            .stdout_limit = .limited(4 * 1024 * 1024),
            .stderr_limit = .limited(4 * 1024 * 1024),
            .timeout = .{ .duration = .{
                .raw = std.Io.Duration.fromMilliseconds(
                    std.math.cast(
                        i64,
                        std.math.add(u64, timeout_ms, cleanup_timeout_ms) catch return error.TimeoutOutOfRange,
                    ) orelse return error.TimeoutOutOfRange,
                ),
                .clock = .awake,
            } },
        }) catch |err| switch (err) {
            error.Timeout => return .{
                .outcome = .timed_out,
                .exit_code = null,
                .stdout = &.{},
                .stderr = &.{},
            },
            else => return err,
        };
        const exit_code: ?u8 = switch (result.term) {
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
            .stdout = result.stdout,
            .stderr = result.stderr,
        };
    }
};

pub const Root = struct {
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    limits: Limits = .{},

    pub fn init(allocator: Allocator, io: Io, root_path: []const u8, limits: Limits) !Root {
        if (!std.fs.path.isAbsolute(root_path)) return error.RootPathMustBeAbsolute;
        const stat = try Io.Dir.cwd().statFile(io, root_path, .{ .follow_symlinks = false });
        if (stat.kind != .directory) return error.RootNotDirectory;
        return .{ .allocator = allocator, .io = io, .root_path = root_path, .limits = limits };
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
        const path = try self.hostPath(file.path);
        defer self.allocator.free(path);
        try self.ensureParent(file.path);
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
        const existing = Io.Dir.cwd().statFile(self.io, path, .{ .follow_symlinks = false }) catch null;
        if (existing) |stat| {
            if (stat.kind == .directory) return error.NotRegularFile;
            Io.Dir.cwd().deleteFile(self.io, path) catch {};
        }
        try Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = bytes });
        try Io.Dir.cwd().setFilePermissions(self.io, path, .fromMode(file.mode), .{});
    }

    pub fn createDirectory(self: *Root, guest_path: []const u8, mode: u32) !void {
        const path = try self.hostPath(guest_path);
        defer self.allocator.free(path);
        try Io.Dir.cwd().createDirPath(self.io, path);
        try Io.Dir.cwd().setFilePermissions(self.io, path, .fromMode(mode), .{});
    }

    pub fn replaceSymlink(self: *Root, guest_path: []const u8, target: []const u8) !void {
        if (target.len == 0 or std.mem.indexOfScalar(u8, target, 0) != null) return error.InvalidSymlinkTarget;
        const path = try self.hostPath(guest_path);
        defer self.allocator.free(path);
        try self.ensureParent(guest_path);
        if (Io.Dir.cwd().statFile(self.io, path, .{ .follow_symlinks = false })) |stat| {
            if (stat.kind == .directory) return error.NotRegularFile;
            try Io.Dir.cwd().deleteFile(self.io, path);
        } else |_| {}
        try Io.Dir.cwd().symLink(self.io, target, path, .{});
    }

    pub fn remove(self: *Root, guest_path: []const u8, recursive: bool) !void {
        const path = try self.hostPath(guest_path);
        defer self.allocator.free(path);
        const stat = Io.Dir.cwd().statFile(self.io, path, .{ .follow_symlinks = false }) catch
            return error.PathNotFound;
        if (stat.kind == .directory and recursive) {
            try Io.Dir.cwd().deleteTree(self.io, path);
        } else {
            try Io.Dir.cwd().deleteFile(self.io, path);
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
        _ = try normalizeGuestPath(guest_directory);
        if (std.mem.count(u8, pattern, "*") > 1) return error.InvalidDiscoveryPattern;
        const directory = try self.hostPath(guest_directory);
        defer self.allocator.free(directory);
        var dir = try Io.Dir.cwd().openDir(self.io, directory, .{ .iterate = true });
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
        const path = try self.hostPath(guest_path);
        defer self.allocator.free(path);
        const stat = Io.Dir.cwd().statFile(self.io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
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
        const path = try self.hostPath(guest_path);
        defer self.allocator.free(path);
        return Io.Dir.cwd().readFileAlloc(self.io, path, self.allocator, .limited(self.limits.max_file_bytes));
    }

    pub fn readLink(self: *Root, guest_path: []const u8) ![]u8 {
        const path = try self.hostPath(guest_path);
        defer self.allocator.free(path);
        var buffer: [std.fs.max_path_bytes]u8 = undefined;
        const length = try Io.Dir.cwd().readLink(self.io, path, &buffer);
        return self.allocator.dupe(u8, buffer[0..length]);
    }

    pub fn validateArchitecture(self: *Root, architecture: Architecture) !void {
        const shell = self.readFile("/bin/sh") catch return error.GuestArchitectureUnknown;
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

    fn ensureParent(self: *Root, guest_path: []const u8) !void {
        const relative = try normalizeGuestPath(guest_path);
        const parent = std.fs.path.dirname(relative) orelse return;
        const path = try std.fs.path.join(self.allocator, &.{ self.root_path, parent });
        defer self.allocator.free(path);
        try Io.Dir.cwd().createDirPath(self.io, path);
    }

    fn hostPath(self: *Root, guest_path: []const u8) ![]u8 {
        const relative = try normalizeGuestPath(guest_path);
        return if (relative.len == 0)
            self.allocator.dupe(u8, self.root_path)
        else
            std.fs.path.join(self.allocator, &.{ self.root_path, relative });
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

test "offline root rejects traversal and wildcard ambiguity" {
    try std.testing.expectError(error.InvalidGuestPath, normalizeGuestPath("/etc/../shadow"));
    try std.testing.expectError(error.InvalidDiscoveryPattern, blk: {
        var root = Root{
            .allocator = std.testing.allocator,
            .io = undefined,
            .root_path = "/",
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
                .root_path = "/",
                .architecture = Architecture.host(),
                .require_privileged_namespace = false,
            },
            .records = .init(std.testing.allocator),
        };
        defer executor.deinit();
        var args = std.array_list.Managed([]const u8).init(std.testing.allocator);
        defer args.deinit();
        break :blk executor.appendCommand(&args, .{ .update_initramfs = "../bad" });
    });
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

test "offline executor enforces architecture, allowlist, timeout, and failure" {
    const host = Architecture.host();
    const foreign: Architecture = if (host == .x86_64) .aarch64 else .x86_64;
    try std.testing.expectError(error.ArchitectureMismatch, Executor.init(
        std.testing.allocator,
        std.testing.io,
        .{
            .root_path = "/",
            .architecture = foreign,
            .require_privileged_namespace = false,
        },
    ));

    var success = FakeRunner{ .outcome = .succeeded };
    var executor = try Executor.init(std.testing.allocator, std.testing.io, .{
        .root_path = "/",
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
        .root_path = "/",
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
        .root_path = "/",
        .architecture = host,
        .require_privileged_namespace = false,
        .run_fn = FakeRunner.run,
        .run_context = &failure,
    });
    defer failure_executor.deinit();
    try std.testing.expectError(error.CommandFailed, failure_executor.execute(.{ .update_initramfs = "6.0.0-azure" }));
    try std.testing.expectEqual(@as(u64, 300 * 1000), failure.timeout_ms);
}
