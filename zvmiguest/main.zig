//! In-VM guest agent for the `vm` customization backend.
//!
//! This runs as PID 1 in the image's own initramfs, reached by
//! `rdinit=/zvmi-guest-agent`, so the image's bootloader, firmware, and init
//! system never run. That is what makes cross-architecture customization
//! affordable: under software emulation the instructions this skips are
//! instructions that would otherwise be interpreted one at a time.
//!
//! It is deliberately libc-free, static, and syscall-only. It is the one piece
//! of zvmi that executes inside a guest whose contents it does not control, and
//! the smaller and more direct it is, the fewer ways that can go wrong.
//!
//! The agent never returns. PID 1 exiting panics the kernel, so every path —
//! including a control document it refuses to act on — ends by sealing a result
//! onto the result device and powering the machine off. A host that finds no
//! sealed result knows the guest died before it could answer, which is a
//! different fact from any answer it could have given.

const std = @import("std");
const control_mod = @import("vm_control");

const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const guest_root = "/mnt/root";
const max_capture_bytes = 1024 * 1024;
const repository_directory = "/run/zvmi-repos";
const tdnf_config = "/run/zvmi-tdnf.conf";
const resolver_path = "/etc/resolv.conf";
/// How long the target's block device is waited for, and how often it is
/// checked. Generous because software emulation stretches every wall-clock
/// interval a guest experiences.
const device_wait_ms: u32 = 60_000;
const device_poll_ms: u32 = 50;

var console_fd: i32 = -1;

pub fn main(init: std.process.Init.Minimal) noreturn {
    _ = init;
    mountIgnoreBusy("proc", "/proc", "proc");
    mountIgnoreBusy("sysfs", "/sys", "sysfs");
    mountIgnoreBusy("devtmpfs", "/dev", "devtmpfs");
    openConsole();
    log("[zvmi-guest] agent started\n");

    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    const allocator = arena.allocator();

    var session = Session{
        .allocator = allocator,
        .tools = .init(allocator),
        .installed_packages = .init(allocator),
    };
    const outcome = session.run();
    session.teardown();

    publish(allocator, session.result_device, .{
        .failure = outcome.failure,
        .tools = session.tools.items,
        .installed_packages = session.installed_packages.items,
    });
    powerOff();
}

const Outcome = struct {
    failure: ?control_mod.Failure = null,
};

fn fail(stage: []const u8, detail: []const u8) Outcome {
    return .{ .failure = .{ .stage = stage, .detail = detail } };
}

const Session = struct {
    allocator: Allocator,
    tools: std.array_list.Managed(control_mod.Tool),
    installed_packages: std.array_list.Managed([]const u8),

    /// Captured as soon as the control document parses, so that even a refusal
    /// to act on the rest of it still gets an answer home.
    result_device: []const u8 = "",
    last_exit_code: ?u8 = null,

    root_mounted: bool = false,
    dev_mounted: bool = false,
    proc_mounted: bool = false,
    sys_mounted: bool = false,
    run_mounted: bool = false,
    /// Original `/etc/resolv.conf`, held in memory so the image gets it back
    /// byte for byte. The guest's `/run` is a tmpfs that is gone by teardown,
    /// and a rename across filesystems would not have worked anyway.
    saved_resolver: ?[]const u8 = null,
    resolver_written: bool = false,
    repositories_written: []const control_mod.Repository = &.{},

    fn run(self: *Session) Outcome {
        const bytes = readFileAlloc(
            self.allocator,
            "/" ++ control_mod.control_path,
            control_mod.max_control_bytes,
        ) catch return fail("read-control", "control document unreadable");
        const parsed = control_mod.parseControl(self.allocator, bytes) catch |err| {
            return fail("parse-control", @errorName(err));
        };
        const control = parsed.value;
        self.result_device = control.result_device;

        // Before the network and before any device is waited for: a driver
        // that is not in the kernel yet is a device that will never appear,
        // and waiting for it would turn a knowable failure into a timeout.
        self.loadModules(control.modules) catch |err| {
            return fail("load-modules", @errorName(err));
        };

        switch (control.network) {
            .offline => {},
            .declared_repositories => |config| configureNetwork(self.allocator, config) catch {
                return fail("network", "static network configuration failed");
            },
        }

        self.mountTarget(control.root_device) catch |err| {
            return fail("mount-root", @errorName(err));
        };
        self.writeRepositoryFiles(control) catch |err| {
            return fail("repository-configuration", @errorName(err));
        };
        self.importTrust(control) catch |err| {
            return self.stageFailure("repository-trust", err);
        };
        for (control.actions) |action| {
            const executed = switch (action) {
                .install => |names| self.runTdnf("install", names, control.repositories),
                .remove => |names| self.runTdnf("remove", names, &.{}),
            };
            executed catch |err| return self.stageFailure("packages", err);
        }
        for (control.initramfs_kernels) |kernel| {
            self.regenerateInitramfs(kernel) catch |err| {
                return self.stageFailure("initramfs", err);
            };
        }
        self.loadInstalledPackages() catch |err| {
            return self.stageFailure("package-inventory", err);
        };
        return .{};
    }

    fn stageFailure(self: *Session, stage: []const u8, err: anyerror) Outcome {
        return .{ .failure = .{
            .stage = stage,
            .detail = @errorName(err),
            .exit_code = self.last_exit_code,
        } };
    }

    /// Inserts the modules the control document names, in the order it names
    /// them, which is the dependency order the host resolved out of the
    /// image's own `modules.dep`.
    ///
    /// `finit_module` rather than `init_module` because the bytes are already
    /// a file in rootfs: the kernel reads them itself instead of the agent
    /// buffering a copy. They were decompressed on the host, so this needs no
    /// decompressor and does not depend on the guest kernel having been built
    /// with `CONFIG_MODULE_DECOMPRESS`.
    fn loadModules(self: *Session, members: []const []const u8) !void {
        for (members) |member| {
            if (!control_mod.validModuleMember(member)) return error.InvalidModuleMember;
            const path = try self.allocator.dupeZ(u8, member);
            defer self.allocator.free(path);

            const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
            if (linux.errno(fd_rc) != .SUCCESS) return error.ModuleMemberMissing;
            const fd: i32 = @intCast(fd_rc);
            defer _ = linux.close(fd);

            const rc = linux.syscall3(.finit_module, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(""), 0);
            switch (linux.errno(rc)) {
                // Already in the kernel is the state this was asking for, and
                // a kernel that built the driver in reports it this way.
                .SUCCESS, .EXIST => {},
                else => return error.ModuleInsertFailed,
            }
        }
    }

    fn mountTarget(self: *Session, device: []const u8) !void {
        try mkdirPath("/mnt");
        try mkdirPath(guest_root);
        const device_z = try self.allocator.dupeZ(u8, device);
        // Block-device probing finishes on a kernel workqueue that can outlast
        // the jump to `rdinit`, so the node may not exist yet even though the
        // driver is built in and the disk is present.
        try waitForDevice(device_z);
        try mountChecked(device_z, guest_root, "ext4", linux.MS.NOSUID | linux.MS.NODEV);
        self.root_mounted = true;

        // A target missing these is not a root filesystem this backend can
        // safely operate on, and finding that out now beats finding it out
        // halfway through a package transaction.
        inline for (.{ "/dev", "/proc", "/sys", "/run", "/etc", "/usr" }) |required| {
            if (!isDirectory(guest_root ++ required)) return error.TargetRootIncomplete;
        }

        try mountChecked("devtmpfs", guest_root ++ "/dev", "devtmpfs", linux.MS.NOSUID);
        self.dev_mounted = true;
        try mountChecked(
            "proc",
            guest_root ++ "/proc",
            "proc",
            linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        );
        self.proc_mounted = true;
        try mountChecked(
            "sysfs",
            guest_root ++ "/sys",
            "sysfs",
            linux.MS.RDONLY | linux.MS.NOSUID | linux.MS.NODEV | linux.MS.NOEXEC,
        );
        self.sys_mounted = true;
        try mountChecked(
            "tmpfs",
            guest_root ++ "/run",
            "tmpfs",
            linux.MS.NOSUID | linux.MS.NODEV,
        );
        self.run_mounted = true;
    }

    fn writeRepositoryFiles(self: *Session, control: control_mod.Control) !void {
        if (control.repositories.len == 0) return;
        try mkdirPath(guest_root ++ repository_directory);
        try self.writeGuestFile(
            tdnf_config,
            "[main]\ngpgcheck=1\nreposdir=" ++ repository_directory ++ "\n",
        );

        for (control.repositories) |repository| {
            const path = try std.fmt.allocPrint(
                self.allocator,
                repository_directory ++ "/{s}.repo",
                .{repository.id},
            );
            try self.writeGuestFile(path, try renderRepositoryFile(self.allocator, repository));
        }
        self.repositories_written = control.repositories;

        switch (control.network) {
            .offline => {},
            .declared_repositories => |config| try self.installResolver(config),
        }
    }

    /// Replaces the image's resolver for the duration of the run and keeps the
    /// original so it can be put back. tdnf resolves names through whatever the
    /// target root says, and the target root has no reason to name a resolver
    /// that exists on this synthetic link.
    fn installResolver(self: *Session, config: control_mod.NetworkConfig) !void {
        if (readFileAlloc(self.allocator, guest_root ++ resolver_path, 64 * 1024)) |original| {
            self.saved_resolver = original;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const body = try renderResolver(self.allocator, config);
        try writeFileBytes(self.allocator, guest_root ++ resolver_path, body);
        self.resolver_written = true;
    }

    fn importTrust(self: *Session, control: control_mod.Control) !void {
        var index: usize = 0;
        for (control.repositories) |repository| {
            for (repository.trust_base64) |encoded| {
                const decoder = std.base64.standard.Decoder;
                const size = try decoder.calcSizeForSlice(encoded);
                const material = try self.allocator.alloc(u8, size);
                try decoder.decode(material, encoded);

                const guest_path = try std.fmt.allocPrint(
                    self.allocator,
                    "/run/zvmi-trust-{d}.asc",
                    .{index},
                );
                try self.writeGuestFile(guest_path, material);
                try self.runChroot(&.{ "/usr/bin/rpm", "--import", guest_path });
                self.deleteGuestFile(guest_path);
                index += 1;
            }
        }
    }

    fn runTdnf(
        self: *Session,
        verb: []const u8,
        names: []const []const u8,
        repositories: []const control_mod.Repository,
    ) !void {
        var argv: std.array_list.Managed([]const u8) = .init(self.allocator);
        try argv.appendSlice(&.{
            "/usr/bin/tdnf",
            "--config",
            tdnf_config,
            "--disablerepo=*",
        });
        for (repositories) |repository| {
            try argv.append(try std.fmt.allocPrint(
                self.allocator,
                "--enablerepo={s}",
                .{repository.id},
            ));
        }
        try argv.appendSlice(&.{ verb, "-y" });
        try argv.appendSlice(names);
        try self.runChroot(argv.items);
    }

    fn regenerateInitramfs(self: *Session, kernel: []const u8) !void {
        const temporary = "/run/zvmi-initramfs.img";
        try self.runChroot(&.{
            "/usr/bin/dracut",
            "--force",
            "--no-hostonly",
            "--tmpdir",
            "/run",
            "--kver",
            kernel,
            temporary,
        });
        // Built aside and copied into place so a dracut that fails partway
        // through cannot leave the image with a truncated initramfs.
        const final = try std.fmt.allocPrint(
            self.allocator,
            "/boot/initramfs-{s}.img",
            .{kernel},
        );
        try self.runChroot(&.{ "/usr/bin/cp", "--remove-destination", temporary, final });
        self.deleteGuestFile(temporary);
    }

    fn loadInstalledPackages(self: *Session) !void {
        const output = try self.captureChroot(&.{
            "/usr/bin/rpm",
            "-qa",
            "--qf",
            "%{NAME}-%{EPOCHNUM}:%{VERSION}-%{RELEASE}.%{ARCH}\n",
        });
        var lines = std.mem.tokenizeScalar(u8, output, '\n');
        while (lines.next()) |line| {
            if (line.len == 0 or std.mem.indexOfScalar(u8, line, 0) != null) {
                return error.InvalidInstalledPackageRecord;
            }
            try self.installed_packages.append(line);
        }
        std.mem.sort([]const u8, self.installed_packages.items, {}, lessThanBytes);
    }

    fn runChroot(self: *Session, argv: []const []const u8) !void {
        const version = self.probeVersion(argv[0]);
        const captured = try runInChroot(self.allocator, argv);
        try self.tools.append(.{
            .name = std.fs.path.basename(argv[0]),
            .version = version,
            .command = argv,
        });
        if (captured.exit_code != 0) {
            self.last_exit_code = captured.exit_code;
            log("[zvmi-guest] command failed: ");
            log(argv[0]);
            log("\n");
            log(captured.output);
            return error.GuestCommandFailed;
        }
    }

    /// Best-effort tool version for provenance. A probe that fails is not a run
    /// that failed, so it must not leave an exit code behind for a later stage
    /// to be blamed with.
    fn probeVersion(self: *Session, program: []const u8) []const u8 {
        const captured = runInChroot(self.allocator, &.{ program, "--version" }) catch
            return "";
        if (captured.exit_code != 0) return "";
        return std.mem.trim(u8, firstLine(captured.output), " \t\r");
    }

    fn captureChroot(self: *Session, argv: []const []const u8) ![]const u8 {
        const captured = try runInChroot(self.allocator, argv);
        if (captured.exit_code != 0) {
            self.last_exit_code = captured.exit_code;
            return error.GuestCommandFailed;
        }
        return captured.output;
    }

    fn writeGuestFile(self: *Session, guest_path: []const u8, bytes: []const u8) !void {
        const host_path = try std.fmt.allocPrint(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
        );
        try writeFileBytes(self.allocator, host_path, bytes);
    }

    fn deleteGuestFile(self: *Session, guest_path: []const u8) void {
        const host_path = std.fmt.allocPrintSentinel(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
            0,
        ) catch return;
        _ = linux.unlink(host_path);
    }

    /// Undoes everything the run put in place, in reverse, whatever the
    /// outcome was: a failed run must still leave the image as it found it,
    /// minus whatever the package manager itself already committed.
    fn teardown(self: *Session) void {
        self.removeRepositoryFiles();
        self.restoreResolver();
        if (self.run_mounted) unmount(guest_root ++ "/run");
        if (self.sys_mounted) unmount(guest_root ++ "/sys");
        if (self.proc_mounted) unmount(guest_root ++ "/proc");
        if (self.dev_mounted) unmount(guest_root ++ "/dev");
        if (self.root_mounted) {
            _ = linux.syscall0(.sync);
            unmount(guest_root);
        }
        _ = linux.syscall0(.sync);
    }

    fn removeRepositoryFiles(self: *Session) void {
        for (self.repositories_written) |repository| {
            const path = std.fmt.allocPrintSentinel(
                self.allocator,
                guest_root ++ repository_directory ++ "/{s}.repo",
                .{repository.id},
                0,
            ) catch continue;
            _ = linux.unlink(path);
        }
        if (self.repositories_written.len != 0) {
            _ = linux.unlink(guest_root ++ tdnf_config);
            _ = linux.rmdir(guest_root ++ repository_directory);
        }
    }

    fn restoreResolver(self: *Session) void {
        if (!self.resolver_written) return;
        if (self.saved_resolver) |original| {
            writeFileBytes(self.allocator, guest_root ++ resolver_path, original) catch {
                log("[zvmi-guest] could not restore the target resolver\n");
            };
        } else {
            _ = linux.unlink(guest_root ++ resolver_path);
        }
    }
};

/// The tdnf repository file the guest writes into the target root. Written by
/// hand rather than by a template so the grammar it has to satisfy — one
/// section, space-separated baseurls, gpgcheck on — is visible here.
fn renderRepositoryFile(
    allocator: Allocator,
    repository: control_mod.Repository,
) ![]const u8 {
    var body: std.array_list.Managed(u8) = .init(allocator);
    try body.appendSlice(try std.fmt.allocPrint(
        allocator,
        "[{s}]\nname=zvmi-{s}\nenabled=1\ngpgcheck=1\nbaseurl=",
        .{ repository.id, repository.id },
    ));
    for (repository.urls, 0..) |url, index| {
        if (index != 0) try body.append(' ');
        try body.appendSlice(url);
    }
    try body.append('\n');
    return body.items;
}

fn renderResolver(allocator: Allocator, config: control_mod.NetworkConfig) ![]const u8 {
    var body: std.array_list.Managed(u8) = .init(allocator);
    for (config.nameservers) |nameserver| {
        try body.appendSlice(try std.fmt.allocPrint(allocator, "nameserver {s}\n", .{nameserver}));
    }
    return body.items;
}

fn lessThanBytes(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

fn firstLine(text: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    return text[0..end];
}

const Captured = struct {
    exit_code: u8,
    output: []const u8,
};

/// Forks, enters the target root, and runs `argv` with stdout and stderr merged
/// into a pipe the parent drains to EOF before reaping. Draining first is what
/// keeps a command that writes more than one pipe buffer from deadlocking
/// against its own supervisor.
fn runInChroot(allocator: Allocator, argv: []const []const u8) !Captured {
    const argv_z = try allocator.allocSentinel(?[*:0]const u8, argv.len, null);
    for (argv, 0..) |argument, index| {
        argv_z[index] = (try allocator.dupeZ(u8, argument)).ptr;
    }
    const envp = [_:null]?[*:0]const u8{
        "HOME=/root",
        "LANG=C",
        "LC_ALL=C",
        "PATH=/usr/sbin:/usr/bin:/sbin:/bin",
        "TERM=dumb",
        null,
    };

    var fds: [2]i32 = undefined;
    if (linux.errno(linux.pipe2(&fds, .{})) != .SUCCESS) return error.PipeFailed;

    const pid_raw = linux.fork();
    if (linux.errno(pid_raw) != .SUCCESS) {
        _ = linux.close(fds[0]);
        _ = linux.close(fds[1]);
        return error.ForkFailed;
    }
    const pid: linux.pid_t = @intCast(pid_raw);
    if (pid == 0) {
        _ = linux.close(fds[0]);
        _ = linux.dup2(fds[1], 1);
        _ = linux.dup2(fds[1], 2);
        if (fds[1] > 2) _ = linux.close(fds[1]);
        if (linux.errno(linux.chroot(guest_root)) != .SUCCESS) linux.exit(126);
        if (linux.errno(linux.chdir("/")) != .SUCCESS) linux.exit(126);
        _ = linux.execve(argv_z[0].?, argv_z.ptr, &envp);
        linux.exit(127);
    }

    _ = linux.close(fds[1]);
    var output: std.array_list.Managed(u8) = .init(allocator);
    var buffer: [4096]u8 = undefined;
    while (true) {
        const rc = linux.read(fds[0], &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => break,
        }
        const count: usize = @intCast(rc);
        if (count == 0) break;
        if (output.items.len < max_capture_bytes) {
            const room = max_capture_bytes - output.items.len;
            try output.appendSlice(buffer[0..@min(count, room)]);
        }
    }
    _ = linux.close(fds[0]);

    var status: u32 = 0;
    while (true) {
        const rc = linux.wait4(pid, &status, 0, null);
        if (linux.errno(rc) != .INTR) break;
    }
    const exit_code: u8 = if (linux.W.IFEXITED(status))
        linux.W.EXITSTATUS(status)
    else
        // A signalled command has no exit status of its own; 128+n is the shell
        // convention and keeps the field meaningful rather than merely nonzero.
        @truncate(128 +% @intFromEnum(linux.W.TERMSIG(status)));
    return .{ .exit_code = exit_code, .output = output.items };
}

fn configureNetwork(allocator: Allocator, config: control_mod.NetworkConfig) !void {
    const socket_raw = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    if (linux.errno(socket_raw) != .SUCCESS) return error.SocketFailed;
    const socket: i32 = @intCast(socket_raw);
    defer _ = linux.close(socket);

    interfaceUp(socket, "lo");
    setInterfaceAddress(socket, config.interface, linux.SIOCSIFADDR, config.address);
    setInterfaceAddress(socket, config.interface, linux.SIOCSIFNETMASK, config.netmask);
    interfaceUp(socket, config.interface);
    try addDefaultRoute(allocator, socket, config.interface, config.gateway);
}

// struct rtentry (linux/route.h); a stable ABI that std.os.linux does not expose.
const rtentry = extern struct {
    rt_pad1: usize = 0,
    rt_dst: linux.sockaddr = std.mem.zeroes(linux.sockaddr),
    rt_gateway: linux.sockaddr = std.mem.zeroes(linux.sockaddr),
    rt_genmask: linux.sockaddr = std.mem.zeroes(linux.sockaddr),
    rt_flags: u16 = 0,
    rt_pad2: i16 = 0,
    rt_pad3: usize = 0,
    rt_pad4: ?*anyopaque = null,
    rt_metric: i16 = 0,
    rt_dev: ?[*:0]const u8 = null,
    rt_mtu: usize = 0,
    rt_window: usize = 0,
    rt_irtt: u16 = 0,
};

const rtf_up: u16 = 0x0001;
const rtf_gateway: u16 = 0x0002;

fn sockaddrIn(address: [4]u8) linux.sockaddr {
    const in: linux.sockaddr.in = .{ .port = 0, .addr = @bitCast(address) };
    return @bitCast(in);
}

fn interfaceUp(socket: i32, name: []const u8) void {
    var request: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(request.ifrn.name[0..name.len], name);
    _ = linux.ioctl(socket, linux.SIOCGIFFLAGS, @intFromPtr(&request));
    request.ifru.flags.UP = true;
    request.ifru.flags.RUNNING = true;
    _ = linux.ioctl(socket, linux.SIOCSIFFLAGS, @intFromPtr(&request));
}

fn setInterfaceAddress(socket: i32, name: []const u8, operation: u32, text: []const u8) void {
    const address = control_mod.parseIpv4(text) orelse return;
    var request: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(request.ifrn.name[0..name.len], name);
    request.ifru.addr = sockaddrIn(address);
    _ = linux.ioctl(socket, operation, @intFromPtr(&request));
}

fn addDefaultRoute(
    allocator: Allocator,
    socket: i32,
    interface: []const u8,
    gateway: []const u8,
) !void {
    const address = control_mod.parseIpv4(gateway) orelse return error.InvalidGateway;
    const interface_z = try allocator.dupeZ(u8, interface);
    var route: rtentry = .{
        .rt_dst = sockaddrIn(.{ 0, 0, 0, 0 }),
        .rt_genmask = sockaddrIn(.{ 0, 0, 0, 0 }),
        .rt_gateway = sockaddrIn(address),
        .rt_flags = rtf_up | rtf_gateway,
        .rt_dev = interface_z.ptr,
    };
    if (linux.errno(linux.ioctl(socket, linux.SIOCADDRT, @intFromPtr(&route))) != .SUCCESS) {
        return error.AddRouteFailed;
    }
}

fn publish(allocator: Allocator, device: []const u8, result: control_mod.Result) void {
    if (device.len == 0) {
        log("[zvmi-guest] no result device; the host will see no answer\n");
        return;
    }
    const sealed = control_mod.seal(allocator, result) catch {
        // Falling back to a bare failure keeps the host from having to read
        // "the result was too large to serialize" as "the guest vanished".
        const minimal = control_mod.seal(allocator, .{
            .failure = .{ .stage = "seal-result", .detail = "result could not be serialized" },
        }) catch return;
        writeDevice(allocator, device, minimal);
        return;
    };
    writeDevice(allocator, device, sealed);
}

fn writeDevice(allocator: Allocator, device: []const u8, bytes: []const u8) void {
    const device_z = allocator.dupeZ(u8, device) catch return;
    const fd_raw = linux.open(device_z, .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(fd_raw) != .SUCCESS) {
        log("[zvmi-guest] result device could not be opened\n");
        return;
    }
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + written, bytes.len - written);
        if (linux.errno(rc) != .SUCCESS) {
            log("[zvmi-guest] result device write failed\n");
            return;
        }
        const count: usize = @intCast(rc);
        if (count == 0) break;
        written += count;
    }
    _ = linux.fsync(fd);
}

fn powerOff() noreturn {
    _ = linux.syscall0(.sync);
    while (true) {
        _ = linux.reboot(.MAGIC1, .MAGIC2, .POWER_OFF, null);
        // A reboot that returns has failed. Halting is the only other way to
        // stop, and looping beats returning from PID 1 into a kernel panic.
        _ = linux.reboot(.MAGIC1, .MAGIC2, .HALT, null);
    }
}

fn openConsole() void {
    const rc = linux.open("/dev/console", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(rc) == .SUCCESS) console_fd = @intCast(rc);
}

fn log(text: []const u8) void {
    _ = linux.write(if (console_fd >= 0) console_fd else 2, text.ptr, text.len);
}

fn mountIgnoreBusy(source: [*:0]const u8, target: [*:0]const u8, filesystem: [*:0]const u8) void {
    _ = linux.mkdir(target, 0o755);
    _ = linux.mount(source, target, filesystem, 0, 0);
}

fn mountChecked(
    source: [*:0]const u8,
    target: [*:0]const u8,
    filesystem: [*:0]const u8,
    flags: u32,
) !void {
    if (linux.errno(linux.mount(source, target, filesystem, flags, 0)) != .SUCCESS) {
        return error.MountFailed;
    }
}

fn unmount(target: [*:0]const u8) void {
    if (linux.errno(linux.umount2(target, 0)) == .SUCCESS) return;
    // A lazy detach still flushes, and by this point the alternative is
    // powering off with the mount held.
    _ = linux.umount2(target, linux.MNT.DETACH);
}

fn mkdirPath(path: [*:0]const u8) !void {
    const err = linux.errno(linux.mkdir(path, 0o755));
    if (err != .SUCCESS and err != .EXIST) return error.MkdirFailed;
}

/// Opening with `O_DIRECTORY` answers the question without needing a `struct
/// stat` whose layout varies by architecture.
fn isDirectory(path: [*:0]const u8) bool {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Polls rather than waiting on uevents: a poll needs no netlink socket, no
/// parser, and no second failure mode, and the wait it replaces is measured in
/// milliseconds on every boot that is going to succeed at all.
fn waitForDevice(path: [*:0]const u8) !void {
    var waited_ms: u32 = 0;
    while (waited_ms < device_wait_ms) : (waited_ms += device_poll_ms) {
        const rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(rc) == .SUCCESS) {
            _ = linux.close(@intCast(rc));
            return;
        }
        sleepMilliseconds(device_poll_ms);
    }
    return error.RootDeviceAbsent;
}

fn sleepMilliseconds(milliseconds: u32) void {
    const request = linux.timespec{
        .sec = @intCast(milliseconds / 1000),
        .nsec = @intCast((milliseconds % 1000) * std.time.ns_per_ms),
    };
    _ = linux.nanosleep(&request, null);
}

fn readFileAlloc(allocator: Allocator, path: []const u8, limit: usize) ![]u8 {
    const path_z = try allocator.dupeZ(u8, path);
    const fd_raw = linux.open(path_z, .{ .ACCMODE = .RDONLY }, 0);
    switch (linux.errno(fd_raw)) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        else => return error.OpenFailed,
    }
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    var output: std.array_list.Managed(u8) = .init(allocator);
    var buffer: [8192]u8 = undefined;
    while (output.items.len <= limit) {
        const rc = linux.read(fd, &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        const count: usize = @intCast(rc);
        if (count == 0) return output.items;
        try output.appendSlice(buffer[0..count]);
    }
    return error.FileTooLarge;
}

fn writeFileBytes(allocator: Allocator, path: []const u8, bytes: []const u8) !void {
    const path_z = try allocator.dupeZ(u8, path);
    const fd_raw = linux.open(
        path_z,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        0o644,
    );
    if (linux.errno(fd_raw) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + written, bytes.len - written);
        if (linux.errno(rc) != .SUCCESS) return error.WriteFailed;
        const count: usize = @intCast(rc);
        if (count == 0) return error.WriteFailed;
        written += count;
    }
}

test "the generated repository file enables exactly the declared repository" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    const rendered = try renderRepositoryFile(arena.allocator(), .{
        .id = "azurelinux-base",
        .urls = &.{
            "https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64",
            "https://mirror.invalid/base",
        },
        .trust_base64 = &.{"a2V5"},
    });
    try std.testing.expectEqualStrings(
        \\[azurelinux-base]
        \\name=zvmi-azurelinux-base
        \\enabled=1
        \\gpgcheck=1
        \\baseurl=https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64 https://mirror.invalid/base
        \\
    , rendered);
}

test "the generated resolver names every declared nameserver" {
    const allocator = std.testing.allocator;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();

    try std.testing.expectEqualStrings(
        "nameserver 10.0.2.3\n",
        try renderResolver(arena.allocator(), control_mod.qemu_user_network),
    );
    try std.testing.expectEqualStrings(
        "nameserver 10.0.2.3\nnameserver 10.0.2.4\n",
        try renderResolver(arena.allocator(), .{
            .address = "10.0.2.15",
            .gateway = "10.0.2.2",
            .nameservers = &.{ "10.0.2.3", "10.0.2.4" },
        }),
    );
}

test "tool versions are reported as their first line only" {
    try std.testing.expectEqualStrings("tdnf 3.5.8", firstLine("tdnf 3.5.8\nlibsolv 0.7\n"));
    try std.testing.expectEqualStrings("dracut 059", firstLine("dracut 059"));
    try std.testing.expectEqualStrings("", firstLine(""));
}

test "a module member the agent will not open is refused before any syscall" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    var session = Session{
        .allocator = arena.allocator(),
        .tools = .init(arena.allocator()),
        .installed_packages = .init(arena.allocator()),
    };

    // The host validated this too, but a guest that trusts its control
    // document is a guest that can be driven anywhere by whoever wrote it.
    try std.testing.expectError(
        error.InvalidModuleMember,
        session.loadModules(&.{"/lib/modules/evil.ko"}),
    );
    // Nothing to insert is the case every image that builds its drivers in
    // presents, and it must reach the mount unchanged.
    try session.loadModules(&.{});
}
