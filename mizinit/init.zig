//! Minimal PID 1 replacement for a from-scratch Azure Linux container-image
//! VM. Responsibilities:
//!   - mount /proc /sys /dev /run (essential pseudo-filesystems)
//!   - mount the ESP at /boot/efi (best-effort, tries a few device-name
//!     conventions since the disk controller varies: virtio -> vdaN,
//!     SCSI/Azure -> sdaN, NVMe -> nvme0n1pN)
//!   - set the hostname
//!   - bring up loopback + run a small DHCP client on the first non-lo
//!     interface, then write /etc/resolv.conf
//!   - install SIGTERM/SIGINT handlers that cleanly power off/reboot, and
//!     double as /sbin/poweroff, /sbin/reboot, /sbin/shutdown (dispatched
//!     by argv[0]) so the kernel's orderly_poweroff() usermode-helper path
//!     (driven by Hyper-V's shutdown integration service) has something to
//!     exec.
//!   - supervise provisioning, foreground sshd, and an optional diagnostic
//!     serial shell as direct children, reaping every exited child
//!   - opt-in (`mizinit.binder=required`) signed Binder boot setup for a
//!     core Binder IPC workload: load binder_linux, mount binderfs, and
//!     create the binder/hwbinder/vndbinder control devices, failing closed
//!     (no service startup, no readiness announcement) if that fails
//! Root stays mounted read-only by default (matches the dm-verity/immutable
//! image philosophy elsewhere in this project). `mizinit.mode=persistent`
//! opts into a writable root for generalized VM images whose provisioned
//! accounts, SSH keys, host keys, and azagent sentinel must survive reboot.
const std = @import("std");
const provisioning_media = @import("provisioning_media");
const linux = std.os.linux;

var log_fd: i32 = -1;
var console_log_fd: i32 = -1;

fn openConsoleLog() void {
    const rc = linux.open("/dev/console", .{ .ACCMODE = .WRONLY }, 0);
    if (linux.errno(rc) == .SUCCESS) console_log_fd = @intCast(rc);
}

fn openDebugLog() void {
    const rc = linux.open("/run/mizinit.log", .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o644);
    const fd: i32 = @intCast(rc);
    if (linux.errno(rc) == .SUCCESS) log_fd = fd;
}

fn writeStr(s: []const u8) void {
    _ = linux.write(if (console_log_fd >= 0) console_log_fd else 2, s.ptr, s.len);
    if (log_fd >= 0) _ = linux.write(log_fd, s.ptr, s.len);
}

fn writeErrno(prefix: []const u8, e: linux.E) void {
    var buf: [96]u8 = undefined;
    const msg = std.fmt.bufPrint(&buf, "{s}: errno={d}\r\n", .{ prefix, @intFromEnum(e) }) catch "errno format failed\r\n";
    writeStr(msg);
}

fn forkProcess(error_prefix: []const u8) ?linux.pid_t {
    const rc = linux.fork();
    const e = linux.errno(rc);
    if (e != .SUCCESS) {
        writeErrno(error_prefix, e);
        return null;
    }
    return @intCast(rc);
}

fn mountIgnoreBusy(special: ?[*:0]const u8, dir: [*:0]const u8, fstype: ?[*:0]const u8, flags: u32) void {
    const rc = linux.mount(special, dir, fstype, flags, 0);
    const e = linux.errno(rc);
    if (e != .SUCCESS and e != .BUSY) {
        var buf: [80]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "mount {s} failed: errno={d}\r\n", .{ dir, @intFromEnum(e) }) catch "mount failed\r\n";
        writeStr(msg);
    }
}

fn mkdirIgnoreExists(path: [*:0]const u8) void {
    const rc = linux.mkdir(path, 0o755);
    const e = linux.errno(rc);
    if (e != .SUCCESS and e != .EXIST) {
        writeErrno("mkdir failed", e);
    }
}

// --- ESP mount: try a handful of common partition-1 device-name schemes ---
// Retries briefly since the kernel may not have finished creating the
// partition device nodes by the time we first try (a real race observed in
// testing). Passes an explicit iocharset=ascii to sidestep environments
// where the vfat driver's default iso8859-1 NLS table isn't built in.
fn tryMountEsp() void {
    mkdirIgnoreExists("/boot");
    mkdirIgnoreExists("/boot/efi");
    const candidates = [_][*:0]const u8{
        "/dev/sda1",
        "/dev/vda1",
        "/dev/xvda1",
        "/dev/nvme0n1p1",
    };
    var retry: u32 = 0;
    while (retry < 5) : (retry += 1) {
        for (candidates) |dev| {
            const rc = linux.mount(dev, "/boot/efi", "vfat", 0, @intFromPtr("iocharset=ascii"));
            const e = linux.errno(rc);
            if (e == .SUCCESS) {
                var buf: [64]u8 = undefined;
                const msg = std.fmt.bufPrint(&buf, "[mizinit] mounted {s} at /boot/efi\r\n", .{dev}) catch "[mizinit] mounted ESP\r\n";
                writeStr(msg);
                return;
            }
        }
        const req: linux.timespec = .{ .sec = 0, .nsec = 200_000_000 };
        _ = linux.nanosleep(&req, null);
    }
    writeStr("[mizinit] no ESP candidate device mounted (non-fatal)\r\n");
}

// --- signal-driven / argv0-driven shutdown ---
fn doReboot(cmd: linux.LINUX_REBOOT.CMD) noreturn {
    while (true) {
        _ = linux.syscall0(.sync);
        const rc = linux.reboot(.MAGIC1, .MAGIC2, cmd, null);
        writeErrno("[mizinit] reboot syscall failed; retrying", linux.errno(rc));
        const req: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&req, null);
    }
}

var shutdown_signal: u8 = 0;

fn onTermSignal(sig: linux.SIG) callconv(.c) void {
    shutdown_signal = if (sig == .INT) 2 else 1;
}

fn installShutdownHandlers() void {
    var sa: linux.Sigaction = .{
        .handler = .{ .handler = &onTermSignal },
        .mask = std.mem.zeroes(linux.sigset_t),
        .flags = 0,
    };
    _ = linux.sigaction(.TERM, &sa, null);
    _ = linux.sigaction(.INT, &sa, null);
}

fn requestPid1Shutdown(signal: linux.SIG, command: linux.LINUX_REBOOT.CMD) noreturn {
    if (isPid1(linux.getpid())) doReboot(command);
    const rc = linux.kill(1, signal);
    if (linux.errno(rc) != .SUCCESS) {
        writeErrno("[mizinit] failed to signal PID 1", linux.errno(rc));
        linux.exit(1);
    }
    linux.exit(0);
}

// --- hostname ---
fn setKernelHostname(name: []const u8) void {
    const rc = linux.syscall2(.sethostname, @intFromPtr(name.ptr), name.len);
    const e = linux.errno(rc);
    if (e != .SUCCESS) writeErrno("sethostname failed", e);
}

fn parsePersistedHostname(content: []const u8) ?[]const u8 {
    const name = std.mem.trim(u8, content, " \t\r\n");
    if (name.len == 0 or name.len > linux.HOST_NAME_MAX or std.mem.indexOfScalar(u8, name, 0) != null) return null;
    return name;
}

fn readPersistedHostname(buf: []u8) ?[]const u8 {
    const fd_rc = linux.open("/etc/hostname", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const read_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        const read_error = linux.errno(read_rc);
        if (read_error == .INTR) continue;
        if (read_error != .SUCCESS) {
            writeErrno("[mizinit] reading /etc/hostname failed", read_error);
            return null;
        }
        if (read_rc == 0) break;
        total += read_rc;
    }
    if (total == buf.len) {
        writeStr("[mizinit] /etc/hostname is too long; using default hostname\r\n");
        return null;
    }
    return parsePersistedHostname(buf[0..total]);
}

fn setHostname(mode: BootMode, persistent_root_ready: bool) void {
    if (mode == .persistent and persistent_root_ready) {
        var buf: [linux.HOST_NAME_MAX + 2]u8 = undefined;
        if (readPersistedHostname(&buf)) |name| {
            setKernelHostname(name);
            return;
        }
    }
    setKernelHostname("azurelinux");
}

fn isValidMachineId(content: []const u8) bool {
    const id = std.mem.trimEnd(u8, content, "\r\n");
    if (id.len != 32) return false;
    for (id) |c| {
        if (!std.ascii.isDigit(c) and !(c >= 'a' and c <= 'f')) return false;
    }
    return true;
}

fn formatMachineId(random: [16]u8) [33]u8 {
    const hex = "0123456789abcdef";
    var result: [33]u8 = undefined;
    for (random, 0..) |byte, index| {
        result[index * 2] = hex[byte >> 4];
        result[index * 2 + 1] = hex[byte & 0x0f];
    }
    result[32] = '\n';
    return result;
}

fn machineIdExists() bool {
    const fd_rc = linux.open("/etc/machine-id", .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return false;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var buf: [34]u8 = undefined;
    var total: usize = 0;
    while (total < buf.len) {
        const read_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        const read_error = linux.errno(read_rc);
        if (read_error == .INTR) continue;
        if (read_error != .SUCCESS) return false;
        if (read_rc == 0) break;
        total += read_rc;
    }
    return total < buf.len and isValidMachineId(buf[0..total]);
}

fn ensureMachineId() void {
    if (!etc_writable or machineIdExists()) return;

    var random: [16]u8 = undefined;
    var random_len: usize = 0;
    while (random_len < random.len) {
        const random_rc = linux.getrandom(random[random_len..].ptr, random.len - random_len, 0);
        const random_error = linux.errno(random_rc);
        if (random_error == .INTR) continue;
        if (random_error != .SUCCESS or random_rc == 0) {
            writeErrno("[mizinit] generating machine-id failed", random_error);
            return;
        }
        random_len += random_rc;
    }

    const content = formatMachineId(random);
    const fd_rc = linux.open("/etc/machine-id", .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o444);
    if (linux.errno(fd_rc) != .SUCCESS) {
        writeErrno("[mizinit] opening /etc/machine-id for writing failed", linux.errno(fd_rc));
        return;
    }
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var written: usize = 0;
    while (written < content.len) {
        const write_rc = linux.write(fd, content[written..].ptr, content.len - written);
        const write_error = linux.errno(write_rc);
        if (write_error == .INTR) continue;
        if (write_error != .SUCCESS or write_rc == 0) {
            writeErrno("[mizinit] writing /etc/machine-id failed", write_error);
            return;
        }
        written += write_rc;
    }
    _ = linux.fsync(fd);
    writeStr("[mizinit] generated /etc/machine-id\r\n");
}

const BootMode = enum {
    immutable,
    persistent,
};

const AzurePolicy = enum {
    auto,
    on,
    off,
};

/// Whether the signed Binder boot setup below (module load, binderfs mount,
/// binder/hwbinder/vndbinder device creation) is required for this boot.
/// Opt-in and disabled by default: only a core image with the matching kernel
/// and packaged module should ever set `required`.
const BinderPolicy = enum {
    disabled,
    required,
};

const BootConfig = struct {
    mode: BootMode = .immutable,
    azure_policy: AzurePolicy = .auto,
    shell_enabled: bool = false,
    binder_policy: BinderPolicy = .disabled,
    invalid_mode: ?[]const u8 = null,
    invalid_azure_policy: ?[]const u8 = null,
    invalid_shell: ?[]const u8 = null,
    invalid_binder_policy: ?[]const u8 = null,
};

fn parseBootConfig(cmdline: []const u8) BootConfig {
    var config: BootConfig = .{};
    var tokens = std.mem.tokenizeAny(u8, cmdline, " \t\r\n");
    while (tokens.next()) |token| {
        if (std.mem.startsWith(u8, token, "mizinit.mode=")) {
            const value = token["mizinit.mode=".len..];
            if (std.mem.eql(u8, value, "persistent")) {
                config.mode = .persistent;
                config.invalid_mode = null;
            } else if (std.mem.eql(u8, value, "immutable")) {
                config.mode = .immutable;
                config.invalid_mode = null;
            } else {
                config.mode = .immutable;
                config.invalid_mode = value;
            }
        } else if (std.mem.startsWith(u8, token, "mizinit.azure=")) {
            const value = token["mizinit.azure=".len..];
            if (std.mem.eql(u8, value, "auto")) {
                config.azure_policy = .auto;
                config.invalid_azure_policy = null;
            } else if (std.mem.eql(u8, value, "on")) {
                config.azure_policy = .on;
                config.invalid_azure_policy = null;
            } else if (std.mem.eql(u8, value, "off")) {
                config.azure_policy = .off;
                config.invalid_azure_policy = null;
            } else {
                config.azure_policy = .auto;
                config.invalid_azure_policy = value;
            }
        } else if (std.mem.startsWith(u8, token, "mizinit.shell=")) {
            const value = token["mizinit.shell=".len..];
            if (std.mem.eql(u8, value, "on")) {
                config.shell_enabled = true;
                config.invalid_shell = null;
            } else if (std.mem.eql(u8, value, "off")) {
                config.shell_enabled = false;
                config.invalid_shell = null;
            } else {
                config.shell_enabled = false;
                config.invalid_shell = value;
            }
        } else if (std.mem.startsWith(u8, token, "mizinit.binder=")) {
            const value = token["mizinit.binder=".len..];
            if (std.mem.eql(u8, value, "required")) {
                config.binder_policy = .required;
                config.invalid_binder_policy = null;
            } else if (std.mem.eql(u8, value, "disabled")) {
                config.binder_policy = .disabled;
                config.invalid_binder_policy = null;
            } else {
                config.binder_policy = .disabled;
                config.invalid_binder_policy = value;
            }
        }
    }
    return config;
}

fn readBootConfig() BootConfig {
    var fd_rc: usize = undefined;
    while (true) {
        fd_rc = linux.open("/proc/cmdline", .{ .ACCMODE = .RDONLY }, 0);
        if (linux.errno(fd_rc) != .INTR) break;
    }
    if (linux.errno(fd_rc) != .SUCCESS) {
        writeErrno("[mizinit] opening /proc/cmdline failed; using boot defaults", linux.errno(fd_rc));
        return .{};
    }
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var buf: [4097]u8 = undefined;
    var read_rc: usize = undefined;
    while (true) {
        read_rc = linux.read(fd, &buf, buf.len);
        if (linux.errno(read_rc) != .INTR) break;
    }
    if (linux.errno(read_rc) != .SUCCESS) {
        writeErrno("[mizinit] reading /proc/cmdline failed; using boot defaults", linux.errno(read_rc));
        return .{};
    }
    if (read_rc == buf.len) {
        writeStr("[mizinit] /proc/cmdline is too long; using boot defaults\r\n");
        return .{};
    }

    var config = parseBootConfig(buf[0..read_rc]);
    if (config.invalid_mode) |value| {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "[mizinit] invalid mizinit.mode={s}; using immutable mode\r\n", .{value}) catch "[mizinit] invalid mizinit.mode; using immutable mode\r\n";
        writeStr(msg);
        config.invalid_mode = null;
    }
    if (config.invalid_azure_policy) |value| {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "[mizinit] invalid mizinit.azure={s}; using auto\r\n", .{value}) catch "[mizinit] invalid mizinit.azure; using auto\r\n";
        writeStr(msg);
        config.invalid_azure_policy = null;
    }
    if (config.invalid_shell) |value| {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "[mizinit] invalid mizinit.shell={s}; keeping diagnostic shell off\r\n", .{value}) catch "[mizinit] invalid mizinit.shell; keeping diagnostic shell off\r\n";
        writeStr(msg);
        config.invalid_shell = null;
    }
    if (config.invalid_binder_policy) |value| {
        var msg_buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "[mizinit] invalid mizinit.binder={s}; keeping binder disabled\r\n", .{value}) catch "[mizinit] invalid mizinit.binder; keeping binder disabled\r\n";
        writeStr(msg);
        config.invalid_binder_policy = null;
    }
    return config;
}

fn isSerialConsoleName(name: []const u8) bool {
    const prefixes = [_][]const u8{
        "ttyS",
        "ttyAMA",
        "ttyUSB",
        "ttyACM",
        "ttymxc",
        "ttySC",
        "ttyFIQ",
        "hvc",
    };
    for (prefixes) |prefix| {
        if (std.mem.startsWith(u8, name, prefix) and name.len > prefix.len) return true;
    }
    return false;
}

fn serialConsoleFromCmdline(cmdline: []const u8) ?[]const u8 {
    var selected: ?[]const u8 = null;
    var tokens = std.mem.tokenizeAny(u8, cmdline, " \t\r\n");
    while (tokens.next()) |token| {
        if (!std.mem.startsWith(u8, token, "console=")) continue;
        const value = token["console=".len..];
        const name = value[0 .. std.mem.indexOfScalar(u8, value, ',') orelse value.len];
        if (isSerialConsoleName(name)) selected = name;
    }
    return selected;
}

fn serialConsoleFromActive(active: []const u8) ?[]const u8 {
    var selected: ?[]const u8 = null;
    var names = std.mem.tokenizeAny(u8, active, " \t\r\n");
    while (names.next()) |name| {
        if (isSerialConsoleName(name)) selected = name;
    }
    return selected;
}

fn selectSerialConsole(cmdline: []const u8, active: []const u8, arch: std.Target.Cpu.Arch) []const u8 {
    if (serialConsoleFromCmdline(cmdline)) |name| return name;
    if (serialConsoleFromActive(active)) |name| return name;
    return if (arch == .aarch64) "ttyAMA0" else "ttyS0";
}

fn discoverSerialConsolePath(path_buf: *[80:0]u8) [*:0]const u8 {
    var cmdline_buf: [4097]u8 = undefined;
    const cmdline = readBoundedFile("/proc/cmdline", &cmdline_buf) orelse "";
    var active_buf: [257]u8 = undefined;
    const active = readBoundedFile("/sys/class/tty/console/active", &active_buf) orelse "";
    const name = selectSerialConsole(cmdline, active, @import("builtin").cpu.arch);
    return std.fmt.bufPrintZ(path_buf, "/dev/{s}", .{name}) catch blk: {
        const fallback = if (@import("builtin").cpu.arch == .aarch64) "/dev/ttyAMA0" else "/dev/ttyS0";
        @memcpy(path_buf[0..fallback.len], fallback);
        path_buf[fallback.len] = 0;
        break :blk path_buf;
    };
}

const AzureDecision = enum {
    unknown,
    azure,
    local,
    non_azure,
};

const AzureEvidence = struct {
    dhcp_acknowledged: bool = false,
    saw_option_245: bool = false,
    media: provisioning_media.ProbeResult = .indeterminate,
};

fn resolveAzureDecision(policy: AzurePolicy, cached: ?AzureDecision, evidence: AzureEvidence) AzureDecision {
    return switch (policy) {
        .on => .azure,
        .off => .non_azure,
        .auto => if (evidence.saw_option_245 or evidence.media == .azure)
            .azure
        else if (evidence.media == .local)
            .local
        else if (cached) |decision|
            decision
        else
            .unknown,
    };
}

const environment_state_dir = "/var/lib/azagent";
const environment_state_path = environment_state_dir ++ "/azure-environment";
const environment_state_tmp_path = environment_state_path ++ ".tmp";
const provisioned_sentinel_path = environment_state_dir ++ "/provisioned";
const vm_identity_path = "/sys/class/dmi/id/product_uuid";

const EnvironmentState = struct {
    identity: [36]u8,
    decision: AzureDecision,
};

fn normalizeVmIdentity(content: []const u8) ?[36]u8 {
    const text = std.mem.trim(u8, content, " \t\r\n");
    if (text.len != 36) return null;

    var normalized: [36]u8 = undefined;
    var all_zero = true;
    for (text, 0..) |c, index| {
        if (index == 8 or index == 13 or index == 18 or index == 23) {
            if (c != '-') return null;
            normalized[index] = '-';
            continue;
        }
        if (!std.ascii.isHex(c)) return null;
        normalized[index] = std.ascii.toLower(c);
        if (c != '0') all_zero = false;
    }
    return if (all_zero) null else normalized;
}

fn parseEnvironmentState(content: []const u8) ?EnvironmentState {
    var tokens = std.mem.tokenizeAny(u8, content, " \t\r\n");
    if (!std.mem.eql(u8, tokens.next() orelse return null, "v1")) return null;
    const identity = normalizeVmIdentity(tokens.next() orelse return null) orelse return null;
    const decision_text = tokens.next() orelse return null;
    if (tokens.next() != null) return null;

    const decision: AzureDecision = if (std.mem.eql(u8, decision_text, "azure"))
        .azure
    else if (std.mem.eql(u8, decision_text, "non-azure"))
        .non_azure
    else
        return null;
    return .{ .identity = identity, .decision = decision };
}

fn renderEnvironmentState(buf: []u8, identity: [36]u8, decision: AzureDecision) ?[]const u8 {
    const decision_text = switch (decision) {
        .azure => "azure",
        .non_azure => "non-azure",
        .unknown, .local => return null,
    };
    return std.fmt.bufPrint(buf, "v1 {s} {s}\n", .{ &identity, decision_text }) catch null;
}

fn readBoundedFile(path: [*:0]const u8, buf: []u8) ?[]const u8 {
    const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var total: usize = 0;
    while (total < buf.len) {
        const read_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        const read_error = linux.errno(read_rc);
        if (read_error == .INTR) continue;
        if (read_error != .SUCCESS) return null;
        if (read_rc == 0) return buf[0..total];
        total += read_rc;
    }
    return null;
}

fn readVmIdentity() ?[36]u8 {
    var buf: [64]u8 = undefined;
    return normalizeVmIdentity(readBoundedFile(vm_identity_path, &buf) orelse return null);
}

fn cachedDecisionForIdentity(state: EnvironmentState, identity: [36]u8) ?AzureDecision {
    if (!std.mem.eql(u8, &state.identity, &identity)) return null;
    return state.decision;
}

fn readCachedAzureDecision(identity: [36]u8) ?AzureDecision {
    var buf: [128]u8 = undefined;
    const state = parseEnvironmentState(readBoundedFile(environment_state_path, &buf) orelse return null) orelse return null;
    return cachedDecisionForIdentity(state, identity);
}

fn writeAll(fd: i32, content: []const u8) bool {
    var written: usize = 0;
    while (written < content.len) {
        const write_rc = linux.write(fd, content[written..].ptr, content.len - written);
        const write_error = linux.errno(write_rc);
        if (write_error == .INTR) continue;
        if (write_error != .SUCCESS or write_rc == 0) return false;
        written += write_rc;
    }
    return true;
}

fn persistAzureDecision(identity: ?[36]u8, decision: AzureDecision) void {
    const vm_identity = identity orelse return;
    var content_buf: [64]u8 = undefined;
    const content = renderEnvironmentState(&content_buf, vm_identity, decision) orelse return;

    mkdirIgnoreExists(environment_state_dir);
    const fd_rc = linux.open(environment_state_tmp_path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    if (linux.errno(fd_rc) != .SUCCESS) {
        writeErrno("[mizinit] opening Azure environment state failed", linux.errno(fd_rc));
        return;
    }
    const fd: i32 = @intCast(fd_rc);
    if (!writeAll(fd, content)) {
        writeStr("[mizinit] writing Azure environment state failed\r\n");
        _ = linux.close(fd);
        _ = linux.unlink(environment_state_tmp_path);
        return;
    }
    const sync_rc = linux.fsync(fd);
    const sync_error = linux.errno(sync_rc);
    _ = linux.close(fd);
    if (sync_error != .SUCCESS) {
        writeErrno("[mizinit] syncing Azure environment state failed", sync_error);
        _ = linux.unlink(environment_state_tmp_path);
        return;
    }

    const rename_rc = linux.rename(environment_state_tmp_path, environment_state_path);
    if (linux.errno(rename_rc) != .SUCCESS) {
        writeErrno("[mizinit] replacing Azure environment state failed", linux.errno(rename_rc));
        _ = linux.unlink(environment_state_tmp_path);
        return;
    }

    const dir_fd_rc = linux.open(environment_state_dir, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(dir_fd_rc) == .SUCCESS) {
        const dir_fd: i32 = @intCast(dir_fd_rc);
        _ = linux.fsync(dir_fd);
        _ = linux.close(dir_fd);
    }
}

fn isProvisioned() bool {
    return linux.errno(linux.access(provisioned_sentinel_path, linux.F_OK)) == .SUCCESS;
}

fn probeProvisioningMedia() provisioning_media.ProbeResult {
    mkdirIgnoreExists("/run/mizinit");
    mkdirIgnoreExists("/run/mizinit/provision-media");
    return provisioning_media.probe(
        "/run/mizinit/provision-media",
        "/run/mizinit/provision-media/ovf-env.xml",
        "/run/mizinit/provision-media/" ++ provisioning_media.local_provisioning_marker,
    );
}

fn remountRootWritable() bool {
    const rc = linux.mount(null, "/", null, linux.MS.REMOUNT, 0);
    const e = linux.errno(rc);
    if (e != .SUCCESS) {
        writeErrno("[mizinit] remounting / read-write failed", e);
        return false;
    }
    writeStr("[mizinit] persistent mode: remounted / read-write\r\n");
    return true;
}

// --- writable paths on top of a read-only root ---
fn mountImmutableWritableOverlays() void {
    mountIgnoreBusy("tmpfs", "/var", "tmpfs", 0);
    mkdirIgnoreExists("/var/log");
    mkdirIgnoreExists("/var/cache");
    mkdirIgnoreExists("/var/lib");
    mkdirIgnoreExists("/var/tmp");
}

// /etc needs a handful of files written at runtime (resolv.conf, hostname,
// machine-id, ...) despite root staying read-only overall. Overlay a tmpfs
// upper layer on top of the existing (read-only) /etc content -- the
// standard pattern immutable-root distros use -- rather than punching a
// hole in the read-only design by making all of /etc a plain tmpfs (which
// would hide the real, pre-populated config files shipped by the image).
// Returns whether /etc ended up writable (the overlay filesystem isn't
// guaranteed to be built into every kernel).
var etc_writable: bool = false;

fn mountEtcOverlay() void {
    mkdirIgnoreExists("/run/etc-upper");
    mkdirIgnoreExists("/run/etc-work");
    const rc = linux.mount("overlay", "/etc", "overlay", 0, @intFromPtr("lowerdir=/etc,upperdir=/run/etc-upper,workdir=/run/etc-work"));
    const e = linux.errno(rc);
    if (e != .SUCCESS) {
        writeErrno("[mizinit] /etc overlay mount failed", e);
        etc_writable = false;
    } else {
        etc_writable = true;
    }
}

// ============================== module autoload ==============================
// Loads a small, fixed set of kernel modules explicitly at boot. There is no
// udev/mdev daemon in this appliance to drive the kernel's usual
// uevent-triggered request_module() -> /sbin/modprobe autoload path (and no
// modprobe/kmod binary is shipped either) -- see miz issue #88: build-image
// used to drop /lib/modules entirely, and even after that's fixed, something
// still has to actually call insmod. Since the exact drivers this appliance
// needs are known ahead of time (Hyper-V networking, overlayfs for immutable
// mode, XFS for the Azure resource disk, and the provisioning DVD's
// UDF/ISO9660 filesystems), loading them in dependency order with a raw
// init_module() syscall is simpler and more self-contained than shipping
// kmod: no MODALIAS matching and no extra shared-library dependencies
// (liblzma/libzstd/libcrypto) added to the image.

const max_module_file_size: usize = 4 * 1024 * 1024;

fn readWholeFileAlloc(gpa: std.mem.Allocator, path: [*:0]const u8) ?[]u8 {
    const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    const fd: i32 = @intCast(fd_rc);
    if (linux.errno(fd_rc) != .SUCCESS) return null;
    defer _ = linux.close(fd);

    const buf = gpa.alloc(u8, max_module_file_size) catch return null;
    var total: usize = 0;
    while (total < buf.len) {
        const n_rc = linux.read(fd, buf[total..].ptr, buf.len - total);
        const n: isize = @bitCast(n_rc);
        if (n <= 0) break;
        total += @intCast(n);
    }
    return buf[0..total];
}

fn decompressXzAlloc(gpa: std.mem.Allocator, compressed: []const u8) ?[]u8 {
    var input = std.Io.Reader.fixed(compressed);
    var decompressor = std.compress.xz.Decompress.init(&input, gpa, &.{}) catch {
        return null;
    };
    defer decompressor.deinit();
    return decompressor.reader.allocRemaining(gpa, .limited(max_module_file_size * 8)) catch null;
}

// `rel_path` is relative to /lib/modules/<kernel-release>/, e.g.
// "kernel/drivers/net/hyperv/hv_netvsc.ko.xz".
fn loadModuleAt(gpa: std.mem.Allocator, release: []const u8, rel_path: []const u8) void {
    var path_buf: [256:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/lib/modules/{s}/{s}", .{ release, rel_path }) catch return;

    const compressed = readWholeFileAlloc(gpa, path) orelse {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[mizinit] module {s} not found (non-fatal)\r\n", .{rel_path}) catch "[mizinit] module not found\r\n";
        writeStr(msg);
        return;
    };
    defer gpa.free(compressed);

    const image = decompressXzAlloc(gpa, compressed) orelse {
        var buf: [128]u8 = undefined;
        const msg = std.fmt.bufPrint(&buf, "[mizinit] module {s} decompress failed (non-fatal)\r\n", .{rel_path}) catch "[mizinit] module decompress failed\r\n";
        writeStr(msg);
        return;
    };
    defer gpa.free(image);

    const rc = linux.syscall3(.init_module, @intFromPtr(image.ptr), image.len, @intFromPtr(""));
    const e = linux.errno(rc);
    var buf: [160]u8 = undefined;
    if (e == .SUCCESS or e == .EXIST) {
        const msg = std.fmt.bufPrint(&buf, "[mizinit] loaded module {s}\r\n", .{rel_path}) catch "[mizinit] module loaded\r\n";
        writeStr(msg);
    } else {
        const msg = std.fmt.bufPrint(&buf, "[mizinit] init_module {s} failed: errno={d}\r\n", .{ rel_path, @intFromEnum(e) }) catch "[mizinit] init_module failed\r\n";
        writeStr(msg);
    }
}

fn loadBootModules(mode: BootMode) void {
    const gpa = std.heap.page_allocator;
    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) {
        writeStr("[mizinit] uname failed; skipping module autoload\r\n");
        return;
    }
    const release = std.mem.sliceTo(&uts.release, 0);

    if (mode == .immutable) {
        loadModuleAt(gpa, release, "kernel/fs/overlayfs/overlay.ko.xz");
    }
    loadModuleAt(gpa, release, "kernel/drivers/net/hyperv/hv_netvsc.ko.xz");
    loadModuleAt(gpa, release, "kernel/fs/xfs/xfs.ko.xz");
    loadModuleAt(gpa, release, "kernel/lib/crc/crc-itu-t.ko.xz");
    loadModuleAt(gpa, release, "kernel/fs/udf/udf.ko.xz");
    loadModuleAt(gpa, release, "kernel/fs/isofs/isofs.ko.xz");
}

// ============================== Binder boot setup ==============================
// Opt-in via `mizinit.binder=required` (default: disabled). A core image with
// the matching signed kernel module sets this so an in-guest Binder workload
// has a working IPC transport before any service starts: load binder_linux,
// mount binderfs, and create the binder/hwbinder/vndbinder control devices.
//
// This is deliberately not built on loadModuleAt() above: that path only
// ever handles a raw, uncompressed-after-decompress `.ko.xz` and a plain
// init_module(), which is fine for this appliance's own best-effort modules
// but wrong for a package-signed one. Ubuntu ships binder_linux compressed
// and signed as `binder_linux.ko.zst`; finit_module()'s
// MODULE_INIT_COMPRESSED_FILE flag asks the kernel itself to decompress the
// file (CONFIG_MODULE_DECOMPRESS) before running its normal
// signature-verified load path, so mizinit never touches -- and so never
// risks corrupting -- the signed bytes.
const binder_module_name = "binder_linux";
const binderfs_mount_point = "/dev/binderfs";
const binder_control_path = binderfs_mount_point ++ "/binder-control";

/// finit_module(2) flag telling the kernel the supplied file descriptor is
/// compressed and should be decompressed in-kernel before the normal
/// signature-verified module load path runs.
const MODULE_INIT_COMPRESSED_FILE: u32 = 4;

/// From <linux/android/binderfs.h>: BINDERFS_MAX_NAME is 255, so `name` holds
/// up to 255 bytes plus a trailing NUL.
const binderfs_max_name = 255;

/// Mirrors `struct binderfs_device` from <linux/android/binderfs.h>.
const BinderfsDevice = extern struct {
    name: [binderfs_max_name + 1]u8,
    major: u32,
    minor: u32,
};

/// `_IOWR('b', 1, struct binderfs_device)` per <linux/android/binderfs.h>,
/// computed the same way the kernel's own ioctl.h macros would rather than
/// hand-encoded, so it stays correct if `BinderfsDevice`'s layout ever
/// changes.
const binder_ctl_add: u32 = linux.IOCTL.IOWR('b', 1, BinderfsDevice);

const BinderDeviceName = enum {
    binder,
    hwbinder,
    vndbinder,

    fn asBytes(self: BinderDeviceName) []const u8 {
        return switch (self) {
            .binder => "binder",
            .hwbinder => "hwbinder",
            .vndbinder => "vndbinder",
        };
    }
};

/// Every binderfs-backed device this appliance's Binder workload needs.
const binder_devices = [_]BinderDeviceName{ .binder, .hwbinder, .vndbinder };

const BinderModuleCandidate = struct {
    rel_path: []const u8,
    flags: u32,
};

/// Candidates are tried in order: the compressed module Ubuntu actually
/// ships first (asking the kernel to decompress and verify it), then a
/// plain uncompressed `.ko` as a fallback for any kernel that ships
/// binder_linux that way instead.
fn binderModuleCandidates() [2]BinderModuleCandidate {
    return .{
        .{ .rel_path = "kernel/drivers/android/" ++ binder_module_name ++ ".ko.zst", .flags = MODULE_INIT_COMPRESSED_FILE },
        .{ .rel_path = "kernel/drivers/android/" ++ binder_module_name ++ ".ko", .flags = 0 },
    };
}

/// The state-machine decision, separated from the syscalls that produce
/// `linux.E` values so it can be tested on a build host: an `errno` result is
/// meaningless without knowing which value this particular step tolerates as
/// "already done".
fn binderStepResult(e: linux.E, already_done: linux.E) BinderStepResult {
    return if (e == .SUCCESS or e == already_done) .ok else .failed;
}

const BinderStepResult = enum { ok, failed };

const BinderSetupOutcome = enum {
    /// `mizinit.binder=required` was not set; nothing was attempted.
    not_requested,
    /// Module loaded, binderfs mounted, and all three control devices exist.
    ready,
    /// Required, but at least one step failed.
    failed,
};

/// Pure fail-closed policy: a disabled policy never blocks anything, and a
/// required policy is `.ready` only if every step succeeded (including
/// having already been done, e.g. a second call after the module was already
/// loaded), `.failed` otherwise.
fn binderSetupOutcome(
    policy: BinderPolicy,
    module: BinderStepResult,
    mount: BinderStepResult,
    devices: BinderStepResult,
) BinderSetupOutcome {
    if (policy != .required) return .not_requested;
    if (module == .failed or mount == .failed or devices == .failed) return .failed;
    return .ready;
}

/// Whether service startup (azagent, the access provider) should proceed
/// given the base gate already in effect (immutable mode, or persistent mode
/// with a writable root) and this boot's Binder setup outcome. A required
/// policy that failed always fails closed, regardless of the base gate.
fn servicesAllowedAfterBinderSetup(base_allowed: bool, outcome: BinderSetupOutcome) bool {
    return base_allowed and outcome != .failed;
}

fn binderModuleAlreadyLoaded() bool {
    return linux.errno(linux.access("/sys/module/" ++ binder_module_name, linux.F_OK)) == .SUCCESS;
}

fn finitModuleAt(release: []const u8, rel_path: []const u8, flags: u32) linux.E {
    var path_buf: [256:0]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/lib/modules/{s}/{s}", .{ release, rel_path }) catch return .NAMETOOLONG;

    const fd_rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
    const open_error = linux.errno(fd_rc);
    if (open_error != .SUCCESS) return open_error;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    const rc = linux.syscall3(.finit_module, @as(usize, @bitCast(@as(isize, fd))), @intFromPtr(""), @as(usize, flags));
    return linux.errno(rc);
}

fn loadBinderModule(release: []const u8) linux.E {
    if (binderModuleAlreadyLoaded()) return .EXIST;
    var last_error: linux.E = .NOENT;
    for (binderModuleCandidates()) |candidate| {
        const e = finitModuleAt(release, candidate.rel_path, candidate.flags);
        if (e == .SUCCESS or e == .EXIST) return e;
        last_error = e;
    }
    return last_error;
}

fn mountBinderfs() linux.E {
    return linux.errno(linux.mount("binder", binderfs_mount_point, "binder", 0, 0));
}

fn ensureBinderDevice(device: BinderDeviceName) linux.E {
    const fd_rc = linux.open(binder_control_path, .{ .ACCMODE = .RDONLY }, 0);
    const open_error = linux.errno(fd_rc);
    if (open_error != .SUCCESS) return open_error;
    const fd: i32 = @intCast(fd_rc);
    defer _ = linux.close(fd);

    var request: BinderfsDevice = std.mem.zeroes(BinderfsDevice);
    const name = device.asBytes();
    @memcpy(request.name[0..name.len], name);

    return linux.errno(linux.ioctl(fd, binder_ctl_add, @intFromPtr(&request)));
}

/// Runs once, after /proc, /sys, and /dev are mounted (main() mounts those
/// before this is reached) and the boot command line has been parsed. Every
/// step tolerates "already done" (module already loaded, binderfs already
/// mounted, a control device that already exists), so calling this more than
/// once -- or racing a kernel that already brought Binder up -- is a no-op
/// rather than a spurious failure.
fn configureBinder(policy: BinderPolicy) BinderSetupOutcome {
    if (policy != .required) return .not_requested;

    var uts: linux.utsname = undefined;
    if (linux.errno(linux.uname(&uts)) != .SUCCESS) {
        writeStr("[mizinit] binder required: uname failed\r\n");
        return .failed;
    }
    const release = std.mem.sliceTo(&uts.release, 0);

    const module = binderStepResult(loadBinderModule(release), .EXIST);
    if (module == .failed) writeStr("[mizinit] binder required: loading binder_linux failed\r\n");

    mkdirIgnoreExists(binderfs_mount_point);
    const mount = binderStepResult(mountBinderfs(), .BUSY);
    if (mount == .failed) writeStr("[mizinit] binder required: mounting binderfs failed\r\n");

    var devices: BinderStepResult = .ok;
    if (mount == .ok) {
        for (binder_devices) |device| {
            const e = ensureBinderDevice(device);
            if (binderStepResult(e, .EXIST) == .failed) {
                devices = .failed;
                writeErrno("[mizinit] binder required: BINDER_CTL_ADD failed", e);
            }
        }
    } else {
        devices = .failed;
    }

    const outcome = binderSetupOutcome(policy, module, mount, devices);
    if (outcome == .ready) {
        writeStr("[mizinit] binder ready: binderfs mounted, binder/hwbinder/vndbinder available\r\n");
    }
    return outcome;
}

// ============================== networking ==============================

// route.h flags; stable ABI, not exposed by std.os.linux.
const RTF_UP: u16 = 0x0001;
const RTF_GATEWAY: u16 = 0x0002;

// struct rtentry (linux/route.h); stable ABI, not exposed by std.os.linux.
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

fn ifUp(fd: i32, name: []const u8) void {
    var req: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(req.ifrn.name[0..name.len], name);

    _ = linux.ioctl(fd, linux.SIOCGIFFLAGS, @intFromPtr(&req));
    req.ifru.flags.UP = true;
    req.ifru.flags.RUNNING = true;
    _ = linux.ioctl(fd, linux.SIOCSIFFLAGS, @intFromPtr(&req));
}

fn sockaddrIn(addr_be: u32) linux.sockaddr {
    const in: linux.sockaddr.in = .{ .port = 0, .addr = addr_be };
    return @bitCast(in);
}

fn sockaddrInPort(addr_be: u32, port_be: u16) linux.sockaddr {
    const in: linux.sockaddr.in = .{ .port = port_be, .addr = addr_be };
    return @bitCast(in);
}

fn setIfaceAddr(fd: i32, name: []const u8, request: u32, addr_be: u32) void {
    var req: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(req.ifrn.name[0..name.len], name);
    req.ifru.addr = sockaddrIn(addr_be);
    _ = linux.ioctl(fd, request, @intFromPtr(&req));
}

/// The largest number of interfaces mizinit will consider for DHCP.
///
/// A cloud VM has one. A bare-metal accelerator node has dozens once its
/// fabric NICs bind — the machines this flavor targets bring up 38 — so the
/// bound is generous, and any interface past it is simply not considered.
const max_candidate_interfaces = 64;

/// How long to let links settle before concluding that none has carrier.
const carrier_settle_seconds: u32 = 5;

/// The non-loopback interfaces this machine currently has, in a stable order.
const InterfaceList = struct {
    names: [max_candidate_interfaces][linux.IFNAMESIZE]u8 = undefined,
    lens: [max_candidate_interfaces]u8 = [_]u8{0} ** max_candidate_interfaces,
    count: usize = 0,

    fn name(self: *const InterfaceList, index: usize) []const u8 {
        return self.names[index][0..self.lens[index]];
    }

    fn append(self: *InterfaceList, candidate: []const u8) void {
        if (self.count == max_candidate_interfaces) return;
        if (candidate.len == 0 or candidate.len > linux.IFNAMESIZE) return;
        @memcpy(self.names[self.count][0..candidate.len], candidate);
        self.lens[self.count] = @intCast(candidate.len);
        self.count += 1;
    }

    /// Sorted so that which interface a machine tries first does not depend on
    /// the order `getdents` happened to hand back.
    fn sort(self: *InterfaceList) void {
        var i: usize = 1;
        while (i < self.count) : (i += 1) {
            var j = i;
            while (j > 0 and std.mem.order(u8, self.name(j), self.name(j - 1)) == .lt) : (j -= 1) {
                const swap_name = self.names[j];
                self.names[j] = self.names[j - 1];
                self.names[j - 1] = swap_name;
                const swap_len = self.lens[j];
                self.lens[j] = self.lens[j - 1];
                self.lens[j - 1] = swap_len;
            }
        }
    }
};

/// Every non-loopback interface the kernel currently exposes.
fn collectInterfaces(list: *InterfaceList) void {
    const dir_fd_rc = linux.open("/sys/class/net", .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    const dir_fd: i32 = @intCast(dir_fd_rc);
    if (linux.errno(dir_fd_rc) != .SUCCESS) return;
    defer _ = linux.close(dir_fd);

    var dirent_buf: [2048]u8 align(8) = undefined;
    while (true) {
        const n_read_rc = linux.getdents64(dir_fd, &dirent_buf, dirent_buf.len);
        const n_read: isize = @bitCast(n_read_rc);
        if (n_read <= 0) break;
        var offset: usize = 0;
        while (offset < @as(usize, @intCast(n_read))) {
            const d: *align(1) linux.dirent64 = @ptrCast(&dirent_buf[offset]);
            const name_ptr: [*:0]const u8 = @ptrCast(&d.name);
            const entry = std.mem.span(name_ptr);
            const skip = std.mem.eql(u8, entry, "lo") or
                std.mem.eql(u8, entry, ".") or
                std.mem.eql(u8, entry, "..");
            if (!skip) list.append(entry);
            offset += d.reclen;
        }
    }
    list.sort();
}

/// `/sys/class/net/<iface>/carrier`, or null when the kernel declines to
/// answer: it fails with EINVAL while the link is administratively down, and
/// some synthetic NICs never report carrier at all.
fn readCarrier(iface: []const u8) ?bool {
    var path_buf: [linux.IFNAMESIZE + 32]u8 = undefined;
    const path = std.fmt.bufPrintZ(&path_buf, "/sys/class/net/{s}/carrier", .{iface}) catch return null;
    var value: [8]u8 = undefined;
    const contents = readBoundedFile(path.ptr, &value) orelse return null;
    if (contents.len == 0) return null;
    return contents[0] == '1';
}

/// Which interfaces are worth a DHCP attempt, in the order to try them.
///
/// Preferring carrier is what keeps a bare-metal node reachable. Exactly one
/// of its interfaces is cabled to the provisioning network, a DHCP attempt on
/// a dark fabric port burns fifteen seconds before it fails, and picking wrong
/// costs the machine its only way in. When nothing reports carrier — synthetic
/// NICs on some hypervisors never do — every interface is tried instead, which
/// is what this code did unconditionally before it could tell the difference.
fn dhcpCandidateOrder(carriers: []const ?bool, out: []u8) []const u8 {
    var count: usize = 0;
    for (carriers, 0..) |carrier, index| {
        if ((carrier orelse false) and count < out.len) {
            out[count] = @intCast(index);
            count += 1;
        }
    }
    if (count != 0) return out[0..count];
    for (carriers, 0..) |_, index| {
        if (count < out.len) {
            out[count] = @intCast(index);
            count += 1;
        }
    }
    return out[0..count];
}

const DhcpResult = struct {
    your_ip: u32, // network byte order
    subnet_mask: u32, // network byte order
    router: u32, // network byte order, 0 if absent
    dns: [2]u32, // network byte order, 0 if absent
};

const DhcpAttempt = struct {
    lease: ?DhcpResult = null,
    saw_option_245: bool = false,
};

const DHCP_MAGIC = [4]u8{ 0x63, 0x82, 0x53, 0x63 };

fn buildDhcpPacket(buf: []u8, xid: u32, mac: [6]u8, msg_type: u8, requested_ip: u32, server_ip: u32) usize {
    @memset(buf[0..240], 0);
    buf[0] = 1; // BOOTREQUEST
    buf[1] = 1; // htype ethernet
    buf[2] = 6; // hlen
    buf[3] = 0; // hops
    std.mem.writeInt(u32, buf[4..8], xid, .big);
    buf[10] = 0x80; // broadcast flag
    @memcpy(buf[28..34], &mac);
    @memcpy(buf[236..240], &DHCP_MAGIC);

    var pos: usize = 240;
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = msg_type;
    pos += 3;

    if (msg_type == 3) { // DHCPREQUEST: echo requested IP + server id
        buf[pos] = 50;
        buf[pos + 1] = 4;
        std.mem.writeInt(u32, buf[pos + 2 ..][0..4], requested_ip, .big);
        pos += 6;

        buf[pos] = 54;
        buf[pos + 1] = 4;
        std.mem.writeInt(u32, buf[pos + 2 ..][0..4], server_ip, .big);
        pos += 6;
    }

    buf[pos] = 55;
    buf[pos + 1] = 4;
    buf[pos + 2] = 1; // subnet mask
    buf[pos + 3] = 3; // router
    buf[pos + 4] = 6; // DNS
    buf[pos + 5] = 245; // Azure WireServer endpoint
    pos += 6;

    buf[pos] = 255; // end
    pos += 1;
    return pos;
}

const ParsedReply = struct {
    msg_type: u8,
    your_ip: u32,
    server_ip: u32,
    router: u32,
    mask: u32,
    dns: [2]u32,
    has_option_245: bool,
};

fn recordDhcpEvidence(attempt: *DhcpAttempt, reply: ParsedReply) void {
    attempt.saw_option_245 = attempt.saw_option_245 or reply.has_option_245;
}

fn parseDhcpReply(buf: []const u8, len: usize, expected_xid: u32) ?ParsedReply {
    if (len < 240) return null;
    if (buf[0] != 2) return null; // BOOTREPLY
    const xid = std.mem.readInt(u32, buf[4..8], .big);
    if (xid != expected_xid) return null;
    if (!std.mem.eql(u8, buf[236..240], &DHCP_MAGIC)) return null;

    const your_ip = std.mem.readInt(u32, buf[16..20], .big);
    var msg_type: u8 = 0;
    var server_ip: u32 = 0;
    var router: u32 = 0;
    var mask: u32 = 0;
    var dns: [2]u32 = .{ 0, 0 };
    var has_option_245 = false;

    var pos: usize = 240;
    while (pos < len) {
        const opt = buf[pos];
        if (opt == 255) break;
        if (opt == 0) {
            pos += 1;
            continue;
        }
        if (pos + 1 >= len) break;
        const opt_len = buf[pos + 1];
        const val_start = pos + 2;
        if (val_start + opt_len > len) break;
        switch (opt) {
            53 => if (opt_len >= 1) {
                msg_type = buf[val_start];
            },
            54 => if (opt_len >= 4) {
                server_ip = std.mem.readInt(u32, buf[val_start..][0..4], .big);
            },
            1 => if (opt_len >= 4) {
                mask = std.mem.readInt(u32, buf[val_start..][0..4], .big);
            },
            3 => if (opt_len >= 4) {
                router = std.mem.readInt(u32, buf[val_start..][0..4], .big);
            },
            6 => {
                if (opt_len >= 4) dns[0] = std.mem.readInt(u32, buf[val_start..][0..4], .big);
                if (opt_len >= 8) dns[1] = std.mem.readInt(u32, buf[val_start + 4 ..][0..4], .big);
            },
            245 => {
                has_option_245 = opt_len == 4;
            },
            else => {},
        }
        pos = val_start + opt_len;
    }
    return .{
        .msg_type = msg_type,
        .your_ip = your_ip,
        .server_ip = server_ip,
        .router = router,
        .mask = mask,
        .dns = dns,
        .has_option_245 = has_option_245,
    };
}

// --- raw packet socket receive path ---
// On Azure (unlike simpler local QEMU networking), DHCP replies sent to an
// interface that has no IP address configured yet get dropped by the
// kernel's normal IPv4 input path before they ever reach a recvfrom() on an
// AF_INET/SOCK_DGRAM socket: with no local route known for the interface,
// the reverse-path source check for the relay/server address fails and the
// packet is logged as "IPv4: martian source 255.255.255.255 from
// <relay-ip>, on dev ethN" and silently discarded. Real DHCP clients
// (dhclient/udhcpc/systemd-networkd) avoid this by receiving replies on a
// raw AF_PACKET socket bound to the interface, which taps the device's
// receive path *before* general IP routing/martian-source checks apply.
// Sending is unaffected (broadcast egress doesn't hit this check), so only
// the receive side needs to change.
const ETH_P_IP: u16 = 0x0800;

fn ifIndex(fd: i32, name: []const u8) ?i32 {
    var req: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(req.ifrn.name[0..name.len], name);
    const rc = linux.ioctl(fd, linux.SIOCGIFINDEX, @intFromPtr(&req));
    if (linux.errno(rc) != .SUCCESS) return null;
    return req.ifru.ivalue;
}

fn openRawIpRecvSocket(ctl_fd: i32, iface: []const u8) ?i32 {
    const index = ifIndex(ctl_fd, iface) orelse {
        writeStr("[mizinit] dhcp: SIOCGIFINDEX failed\r\n");
        return null;
    };

    const sock_rc = linux.socket(linux.AF.PACKET, linux.SOCK.DGRAM, std.mem.nativeToBig(u16, ETH_P_IP));
    const sock: i32 = @intCast(sock_rc);
    if (linux.errno(sock_rc) != .SUCCESS) {
        writeErrno("[mizinit] dhcp: AF_PACKET socket() failed", linux.errno(sock_rc));
        return null;
    }

    var addr: linux.sockaddr.ll = .{
        .protocol = std.mem.nativeToBig(u16, ETH_P_IP),
        .ifindex = index,
        .hatype = 0,
        .pkttype = 0,
        .halen = 0,
        .addr = std.mem.zeroes([8]u8),
    };
    const bind_rc = linux.bind(sock, @ptrCast(&addr), @sizeOf(linux.sockaddr.ll));
    if (linux.errno(bind_rc) != .SUCCESS) {
        writeErrno("[mizinit] dhcp: AF_PACKET bind failed", linux.errno(bind_rc));
        _ = linux.close(sock);
        return null;
    }
    return sock;
}

/// Extracts the UDP payload from a raw IPv4 packet captured on an
/// AF_PACKET/SOCK_DGRAM socket (Ethernet header already stripped by the
/// kernel, IP header is not). Returns null unless it's a well-formed UDP
/// packet addressed to `dest_port`.
fn extractUdpPayload(packet: []const u8, dest_port: u16) ?[]const u8 {
    if (packet.len < 20) return null;
    if (packet[0] >> 4 != 4) return null; // IPv4 only
    const ihl: usize = @as(usize, packet[0] & 0x0f) * 4;
    if (ihl < 20 or packet.len < ihl + 8) return null;
    if (packet[9] != 17) return null; // protocol == UDP
    const udp = packet[ihl..];
    if (std.mem.readInt(u16, udp[2..4], .big) != dest_port) return null;
    const udp_len = std.mem.readInt(u16, udp[4..6], .big);
    if (udp_len < 8 or ihl + udp_len > packet.len) return null;
    return udp[8..udp_len];
}

fn runDhcp(iface: []const u8) DhcpAttempt {
    var result: DhcpAttempt = .{};
    const ctl_fd_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    const ctl_fd: i32 = @intCast(ctl_fd_rc);
    if (linux.errno(ctl_fd_rc) != .SUCCESS) return result;
    defer _ = linux.close(ctl_fd);

    var hw_req: linux.ifreq = std.mem.zeroes(linux.ifreq);
    @memcpy(hw_req.ifrn.name[0..iface.len], iface);
    const hw_rc = linux.ioctl(ctl_fd, linux.SIOCGIFHWADDR, @intFromPtr(&hw_req));
    if (linux.errno(hw_rc) != .SUCCESS) writeErrno("[mizinit] dhcp: SIOCGIFHWADDR failed", linux.errno(hw_rc));
    var mac: [6]u8 = undefined;
    @memcpy(&mac, hw_req.ifru.hwaddr.data[0..6]);
    {
        var mbuf: [64]u8 = undefined;
        const m = std.fmt.bufPrint(&mbuf, "[mizinit] dhcp: mac={x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}:{x:0>2}\r\n", .{ mac[0], mac[1], mac[2], mac[3], mac[4], mac[5] }) catch "[mizinit] dhcp: mac read\r\n";
        writeStr(m);
    }

    ifUp(ctl_fd, iface);

    const sock_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    const sock: i32 = @intCast(sock_rc);
    if (linux.errno(sock_rc) != .SUCCESS) {
        writeErrno("[mizinit] dhcp: socket() failed", linux.errno(sock_rc));
        return result;
    }
    defer _ = linux.close(sock);

    var one: i32 = 1;
    _ = linux.setsockopt(sock, linux.SOL.SOCKET, linux.SO.BROADCAST, std.mem.asBytes(&one), @sizeOf(i32));
    const bindtodev_rc = linux.setsockopt(sock, linux.SOL.SOCKET, linux.SO.BINDTODEVICE, iface.ptr, @intCast(iface.len));
    if (linux.errno(bindtodev_rc) != .SUCCESS) writeErrno("[mizinit] dhcp: SO_BINDTODEVICE failed", linux.errno(bindtodev_rc));

    const bind_addr = sockaddrInPort(0, std.mem.nativeToBig(u16, 68));
    const bind_rc = linux.bind(sock, &bind_addr, @sizeOf(linux.sockaddr));
    if (linux.errno(bind_rc) != .SUCCESS) {
        writeErrno("[mizinit] dhcp bind failed", linux.errno(bind_rc));
        return result;
    }
    writeStr("[mizinit] dhcp: bound to udp/68\r\n");

    var recv_sock = sock;
    var recv_is_raw = false;
    if (openRawIpRecvSocket(ctl_fd, iface)) |raw_sock| {
        recv_sock = raw_sock;
        recv_is_raw = true;
    } else {
        writeStr("[mizinit] dhcp: falling back to udp recv (may miss replies on some networks)\r\n");
    }
    defer if (recv_is_raw) {
        _ = linux.close(recv_sock);
    };

    const dest_addr = sockaddrInPort(0xffffffff, std.mem.nativeToBig(u16, 67));

    var xid_buf: [4]u8 = undefined;
    _ = linux.getrandom(&xid_buf, xid_buf.len, 0);
    const xid = std.mem.readInt(u32, &xid_buf, .big);

    var packet: [512]u8 = undefined;
    var recv_buf: [1024]u8 = undefined;

    var send_len = buildDhcpPacket(&packet, xid, mac, 1, 0, 0);
    const send_rc = linux.sendto(sock, &packet, send_len, 0, &dest_addr, @sizeOf(linux.sockaddr));
    {
        var sbuf: [64]u8 = undefined;
        const smsg = std.fmt.bufPrint(&sbuf, "[mizinit] dhcp: sent DISCOVER, sendto_rc={d}\r\n", .{send_rc}) catch "[mizinit] dhcp: sent DISCOVER\r\n";
        writeStr(smsg);
    }

    var timeout: linux.timeval = .{ .sec = 5, .usec = 0 };
    _ = linux.setsockopt(recv_sock, linux.SOL.SOCKET, linux.SO.RCVTIMEO, std.mem.asBytes(&timeout), @sizeOf(linux.timeval));

    var offer_ip: u32 = 0;
    var offer_server: u32 = 0;
    var got_offer = false;
    var attempt: u32 = 0;
    while (attempt < 3 and !got_offer) : (attempt += 1) {
        const n_rc = linux.recvfrom(recv_sock, &recv_buf, recv_buf.len, 0, null, null);
        const n_signed: isize = @bitCast(n_rc);
        {
            var rbuf: [80]u8 = undefined;
            const rmsg = std.fmt.bufPrint(&rbuf, "[mizinit] dhcp: recvfrom attempt {d} -> {d}\r\n", .{ attempt, n_signed }) catch "[mizinit] dhcp: recv attempt\r\n";
            writeStr(rmsg);
        }
        const payload: ?[]const u8 = if (n_signed <= 0)
            null
        else if (recv_is_raw)
            extractUdpPayload(recv_buf[0..@intCast(n_signed)], 68)
        else
            recv_buf[0..@intCast(n_signed)];
        if (payload) |data| {
            if (parseDhcpReply(data, data.len, xid)) |reply| {
                recordDhcpEvidence(&result, reply);
                var pbuf: [64]u8 = undefined;
                const pmsg = std.fmt.bufPrint(&pbuf, "[mizinit] dhcp: parsed reply msg_type={d}\r\n", .{reply.msg_type}) catch "[mizinit] dhcp: parsed reply\r\n";
                writeStr(pmsg);
                if (reply.msg_type == 2) { // DHCPOFFER
                    offer_ip = reply.your_ip;
                    offer_server = reply.server_ip;
                    got_offer = true;
                }
            } else if (n_signed > 0) {
                writeStr("[mizinit] dhcp: recv'd packet failed to parse (xid/magic mismatch?)\r\n");
            }
        } else {
            send_len = buildDhcpPacket(&packet, xid, mac, 1, 0, 0);
            _ = linux.sendto(sock, &packet, send_len, 0, &dest_addr, @sizeOf(linux.sockaddr));
        }
    }
    if (!got_offer) {
        writeStr("[mizinit] dhcp: no offer received\r\n");
        return result;
    }

    send_len = buildDhcpPacket(&packet, xid, mac, 3, offer_ip, offer_server);
    _ = linux.sendto(sock, &packet, send_len, 0, &dest_addr, @sizeOf(linux.sockaddr));

    var got_ack: ?DhcpResult = null;
    attempt = 0;
    while (attempt < 3 and got_ack == null) : (attempt += 1) {
        const n_rc = linux.recvfrom(recv_sock, &recv_buf, recv_buf.len, 0, null, null);
        const n_signed: isize = @bitCast(n_rc);
        const payload: ?[]const u8 = if (n_signed <= 0)
            null
        else if (recv_is_raw)
            extractUdpPayload(recv_buf[0..@intCast(n_signed)], 68)
        else
            recv_buf[0..@intCast(n_signed)];
        if (payload) |data| {
            if (parseDhcpReply(data, data.len, xid)) |reply| {
                recordDhcpEvidence(&result, reply);
                if (reply.msg_type == 5) { // DHCPACK
                    got_ack = .{
                        .your_ip = std.mem.nativeToBig(u32, reply.your_ip),
                        .subnet_mask = if (reply.mask != 0) std.mem.nativeToBig(u32, reply.mask) else std.mem.nativeToBig(u32, 0xffffff00),
                        .router = std.mem.nativeToBig(u32, reply.router),
                        .dns = .{ std.mem.nativeToBig(u32, reply.dns[0]), std.mem.nativeToBig(u32, reply.dns[1]) },
                    };
                }
            }
        } else {
            send_len = buildDhcpPacket(&packet, xid, mac, 3, offer_ip, offer_server);
            _ = linux.sendto(sock, &packet, send_len, 0, &dest_addr, @sizeOf(linux.sockaddr));
        }
    }
    if (got_ack == null) writeStr("[mizinit] dhcp: no ack received\r\n");
    result.lease = got_ack;
    return result;
}

fn addDefaultRoute(iface: []const u8, gateway_be: u32) void {
    const sock_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    const sock: i32 = @intCast(sock_rc);
    if (linux.errno(sock_rc) != .SUCCESS) return;
    defer _ = linux.close(sock);

    var iface_buf: [linux.IFNAMESIZE:0]u8 = std.mem.zeroes([linux.IFNAMESIZE:0]u8);
    @memcpy(iface_buf[0..iface.len], iface);

    var route: rtentry = .{
        .rt_dst = sockaddrIn(0),
        .rt_genmask = sockaddrIn(0),
        .rt_gateway = sockaddrIn(gateway_be),
        .rt_flags = RTF_UP | RTF_GATEWAY,
        .rt_dev = @ptrCast(&iface_buf),
    };

    const rc = linux.ioctl(sock, linux.SIOCADDRT, @intFromPtr(&route));
    const e = linux.errno(rc);
    if (e != .SUCCESS) writeErrno("[mizinit] add default route failed", e);
}

fn writeResolvConf(dns: [2]u32) void {
    const path: [*:0]const u8 = if (etc_writable) "/etc/resolv.conf" else "/run/resolv.conf";
    const fd_rc = linux.open(path, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, 0o644);
    const fd: i32 = @intCast(fd_rc);
    if (linux.errno(fd_rc) != .SUCCESS) {
        writeErrno("[mizinit] writing resolv.conf failed", linux.errno(fd_rc));
        return;
    }
    defer _ = linux.close(fd);
    if (!etc_writable) writeStr("[mizinit] /etc not writable (no overlayfs); wrote /run/resolv.conf instead\r\n");

    var buf: [128]u8 = undefined;
    for (dns) |d| {
        if (d == 0) continue;
        const be_bytes = std.mem.asBytes(&d);
        const line = std.fmt.bufPrint(&buf, "nameserver {d}.{d}.{d}.{d}\n", .{ be_bytes[0], be_bytes[1], be_bytes[2], be_bytes[3] }) catch continue;
        _ = linux.write(fd, line.ptr, line.len);
    }
}

const NetworkResult = struct {
    dhcp_acknowledged: bool = false,
    saw_option_245: bool = false,
};

fn setupNetworking() NetworkResult {
    const lo_sock_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    const lo_sock: i32 = @intCast(lo_sock_rc);
    if (linux.errno(lo_sock_rc) == .SUCCESS) {
        ifUp(lo_sock, "lo");
        _ = linux.close(lo_sock);
    }

    var list: InterfaceList = .{};
    collectInterfaces(&list);
    if (list.count == 0) {
        writeStr("[mizinit] no non-lo network interface found\r\n");
        return .{};
    }

    const ctl_rc = linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0);
    const ctl: i32 = @intCast(ctl_rc);
    if (linux.errno(ctl_rc) != .SUCCESS) return .{};
    defer _ = linux.close(ctl);

    // Carrier only means anything once the link is administratively up, so
    // raise every candidate first, then let the slowest PHY settle instead of
    // judging the whole machine on one reading.
    var index: usize = 0;
    while (index < list.count) : (index += 1) ifUp(ctl, list.name(index));

    var carriers: [max_candidate_interfaces]?bool = [_]?bool{null} ** max_candidate_interfaces;
    var waited: u32 = 0;
    while (true) {
        var any_carrier = false;
        index = 0;
        while (index < list.count) : (index += 1) {
            carriers[index] = readCarrier(list.name(index));
            if (carriers[index] orelse false) any_carrier = true;
        }
        if (any_carrier or waited >= carrier_settle_seconds) break;
        const req: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&req, null);
        waited += 1;
    }

    var order_buf: [max_candidate_interfaces]u8 = undefined;
    const order = dhcpCandidateOrder(carriers[0..list.count], &order_buf);

    var network_result: NetworkResult = .{};
    for (order) |candidate| {
        const iface = list.name(candidate);
        var msg_buf: [96]u8 = undefined;
        const msg = std.fmt.bufPrint(&msg_buf, "[mizinit] running DHCP on {s}\r\n", .{iface}) catch "[mizinit] running DHCP\r\n";
        writeStr(msg);

        const attempt = runDhcp(iface);
        // Azure is identified by a DHCP option, and the interface that offers
        // it need not be the one that ends up leasing, so keep the evidence
        // from every attempt rather than only the successful one.
        network_result.saw_option_245 = network_result.saw_option_245 or attempt.saw_option_245;
        const lease = attempt.lease orelse continue;
        network_result.dhcp_acknowledged = true;

        setIfaceAddr(ctl, iface, linux.SIOCSIFADDR, lease.your_ip);
        setIfaceAddr(ctl, iface, linux.SIOCSIFNETMASK, lease.subnet_mask);
        ifUp(ctl, iface);

        if (lease.router != 0) addDefaultRoute(iface, lease.router);
        writeResolvConf(lease.dns);

        const ip_bytes = std.mem.asBytes(&lease.your_ip);
        var ok_buf: [96]u8 = undefined;
        const ok_msg = std.fmt.bufPrint(&ok_buf, "[mizinit] {s} configured: {d}.{d}.{d}.{d}\r\n", .{ iface, ip_bytes[0], ip_bytes[1], ip_bytes[2], ip_bytes[3] }) catch "[mizinit] network configured\r\n";
        writeStr(ok_msg);
        return network_result;
    }

    writeStr("[mizinit] dhcp: no interface accepted a lease\r\n");
    return network_result;
}

// ============================== managed children ==============================
const azagent_path = "/usr/sbin/azagent";
const sshd_path = "/usr/sbin/sshd";
/// An image may replace the default access provider by shipping this binary.
///
/// mizinit supervises exactly one program that makes the machine reachable.
/// By default that is OpenSSH. An appliance image whose way in is something
/// else — a mesh VPN, a console enrollment agent, a vendor control channel —
/// installs this path instead, and mizinit runs it *in place of* sshd rather
/// than alongside it. An image that does not ship it is unaffected.
const access_provider_path = "/usr/local/sbin/mizinit-access";
const provisioning_retry_seconds: u32 = 5;
const access_max_backoff_seconds: u32 = 30;

/// Which program makes this machine reachable.
const AccessProvider = enum {
    /// `/usr/sbin/sshd`, the default.
    sshd,
    /// `/usr/local/sbin/mizinit-access`, supplied by the image.
    override,

    fn path(provider: AccessProvider) [*:0]const u8 {
        return switch (provider) {
            .sshd => sshd_path,
            .override => access_provider_path,
        };
    }
};

/// The decision itself, separated from the probe so it can be tested on a
/// build host: `linux.access` is a raw Linux syscall and means nothing here.
fn accessProviderFor(override_present: bool) AccessProvider {
    if (override_present) return .override;
    return .sshd;
}

/// Resolved once per supervisor pass rather than cached, so an image that
/// installs the override during provisioning is picked up without a reboot.
fn selectAccessProvider() AccessProvider {
    return accessProviderFor(
        linux.errno(linux.access(access_provider_path, linux.F_OK)) == .SUCCESS,
    );
}

const AzagentLaunchMode = enum {
    azure,
    local,
};

fn azagentModeArgument(mode: AzagentLaunchMode) ?[*:0]const u8 {
    return if (mode == .local) "--skip-ready" else null;
}

fn attachChildLog() void {
    if (console_log_fd < 0) return;
    _ = linux.dup2(console_log_fd, 1);
    _ = linux.dup2(console_log_fd, 2);
}

fn spawnAzagent(mode: AzagentLaunchMode) ?linux.pid_t {
    if (linux.errno(linux.access(azagent_path, linux.F_OK)) != .SUCCESS) return null;
    writeStr("[mizinit] running azagent...\r\n");
    const pid = forkProcess("[mizinit] fork() for azagent failed") orelse return null;
    if (pid == 0) {
        attachChildLog();
        const argv = [_:null]?[*:0]const u8{
            azagent_path,
            azagentModeArgument(mode),
            null,
        };
        const envp = [_:null]?[*:0]const u8{
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            null,
        };
        _ = linux.execve(azagent_path, &argv, &envp);
        writeStr("[mizinit] execve(azagent) failed\r\n");
        linux.exit(127);
    }
    return pid;
}

fn spawnAccessProvider(provider: AccessProvider) ?linux.pid_t {
    const path = provider.path();
    if (linux.errno(linux.access(path, linux.F_OK)) != .SUCCESS) return null;
    switch (provider) {
        .sshd => {
            mkdirIgnoreExists("/run/sshd");
            writeStr("[mizinit] starting supervised sshd -D -e\r\n");
        },
        .override => writeStr("[mizinit] starting supervised " ++ access_provider_path ++ "\r\n"),
    }
    const pid = forkProcess("[mizinit] fork() for the access provider failed") orelse return null;
    if (pid == 0) {
        attachChildLog();
        const envp = [_:null]?[*:0]const u8{
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            null,
        };
        switch (provider) {
            .sshd => {
                const argv = [_:null]?[*:0]const u8{ sshd_path, "-D", "-e", null };
                _ = linux.execve(sshd_path, &argv, &envp);
            },
            .override => {
                // No arguments: everything the provider needs comes from the
                // image, so its configuration surface stays out of PID 1.
                const argv = [_:null]?[*:0]const u8{ path, null };
                _ = linux.execve(path, &argv, &envp);
            },
        }
        writeStr("[mizinit] execve(access provider) failed\r\n");
        linux.exit(127);
    }
    return pid;
}

fn spawnDiagnosticShell(console_path: [*:0]const u8) ?linux.pid_t {
    const tty_fd_raw = linux.open(console_path, .{ .ACCMODE = .RDWR }, 0);
    if (linux.errno(tty_fd_raw) != .SUCCESS) {
        writeErrno("[mizinit] opening diagnostic serial console failed", linux.errno(tty_fd_raw));
        return null;
    }
    const tty_fd: i32 = @intCast(tty_fd_raw);
    const pid = forkProcess("[mizinit] fork() for diagnostic shell failed") orelse {
        _ = linux.close(tty_fd);
        return null;
    };
    if (pid == 0) {
        _ = linux.setsid();
        _ = linux.ioctl(tty_fd, linux.T.IOCSCTTY, 0);
        _ = linux.dup2(tty_fd, 0);
        _ = linux.dup2(tty_fd, 1);
        _ = linux.dup2(tty_fd, 2);
        if (tty_fd > 2) _ = linux.close(tty_fd);

        const argv = [_:null]?[*:0]const u8{ "/usr/bin/bash", "--login", null };
        const envp = [_:null]?[*:0]const u8{
            "HOME=/root",
            "TERM=linux",
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            null,
        };
        _ = linux.execve("/usr/bin/bash", &argv, &envp);
        writeStr("[mizinit] execve(/usr/bin/bash) failed\r\n");
        linux.exit(127);
    }
    _ = linux.close(tty_fd);
    return pid;
}

fn azureEvidence(network: NetworkResult, media: provisioning_media.ProbeResult) AzureEvidence {
    return .{
        .dhcp_acknowledged = network.dhcp_acknowledged,
        .saw_option_245 = network.saw_option_245,
        .media = media,
    };
}

fn persistObservedAzureDecision(
    policy: AzurePolicy,
    identity: ?[36]u8,
    evidence: AzureEvidence,
) void {
    if (policy != .auto) return;
    if (automaticDecisionToPersist(evidence)) |decision| persistAzureDecision(identity, decision);
}

fn automaticDecisionToPersist(evidence: AzureEvidence) ?AzureDecision {
    return if (evidence.saw_option_245 or evidence.media == .azure) .azure else null;
}

fn logAzureDecision(decision: AzureDecision, policy: AzurePolicy, evidence: AzureEvidence, cached: ?AzureDecision) void {
    switch (policy) {
        .on => writeStr("[mizinit] Azure environment forced on by mizinit.azure=on\r\n"),
        .off => writeStr("[mizinit] Azure environment forced off by mizinit.azure=off\r\n"),
        .auto => switch (decision) {
            .azure => if (evidence.saw_option_245)
                writeStr("[mizinit] Azure environment detected from DHCP option 245\r\n")
            else if (evidence.media == .azure)
                writeStr("[mizinit] Azure environment detected from provisioning media\r\n")
            else if (cached == .azure)
                writeStr("[mizinit] Azure environment restored from persistent state\r\n")
            else
                writeStr("[mizinit] Azure environment detected\r\n"),
            .local => writeStr("[mizinit] explicit local provisioning media detected; WireServer Ready will be skipped\r\n"),
            .non_azure => if (cached == .non_azure)
                writeStr("[mizinit] non-Azure environment restored from persistent state; skipping azagent\r\n")
            else
                writeStr("[mizinit] non-Azure environment detected; skipping azagent\r\n"),
            .unknown => writeStr("[mizinit] Azure environment is unknown; retrying detection\r\n"),
        },
    }
}

const Supervisor = struct {
    policy: AzurePolicy,
    decision: AzureDecision,
    network: NetworkResult,
    media: provisioning_media.ProbeResult,
    identity: ?[36]u8,
    cached: ?AzureDecision,
    persist_detection: bool,
    services_allowed: bool,
    binder_setup_failed: bool,
    shell_enabled: bool,
    console_path: [*:0]const u8,

    azagent_pid: linux.pid_t = 0,
    azagent_done: bool = false,
    azagent_retry: u32 = 0,
    azagent_missing_logged: bool = false,
    access_pid: linux.pid_t = 0,
    access_retry: u32 = 0,
    access_backoff: u32 = 1,
    shell_pid: linux.pid_t = 0,
    shell_retry: u32 = 0,
    detection_retry: u32 = provisioning_retry_seconds,
};

fn nextAccessBackoff(current: u32) u32 {
    return @min(current * 2, access_max_backoff_seconds);
}

fn childSucceeded(status: u32) bool {
    return linux.W.IFEXITED(status) and linux.W.EXITSTATUS(status) == 0;
}

fn noteChildExit(supervisor: *Supervisor, pid: linux.pid_t, status: u32) void {
    if (pid == supervisor.azagent_pid) {
        supervisor.azagent_pid = 0;
        if (childSucceeded(status)) {
            supervisor.azagent_done = true;
            writeStr("[mizinit] azagent completed successfully\r\n");
        } else {
            supervisor.azagent_retry = provisioning_retry_seconds;
            writeStr("[mizinit] azagent failed; retrying in 5 seconds\r\n");
        }
    } else if (pid == supervisor.access_pid) {
        supervisor.access_pid = 0;
        supervisor.access_retry = supervisor.access_backoff;
        supervisor.access_backoff = nextAccessBackoff(supervisor.access_backoff);
        writeStr("[mizinit] access provider exited unexpectedly; scheduling restart\r\n");
    } else if (pid == supervisor.shell_pid) {
        supervisor.shell_pid = 0;
        supervisor.shell_retry = 1;
        writeStr("[mizinit] diagnostic shell exited; scheduling restart\r\n");
    } else {
        writeStr("[mizinit] reaped adopted child\r\n");
    }
}

fn reapChildren(supervisor: *Supervisor) void {
    while (true) {
        var status: u32 = 0;
        const wait_rc = linux.waitpid(-1, &status, linux.W.NOHANG);
        const wait_error = linux.errno(wait_rc);
        if (wait_error == .INTR) continue;
        if (wait_error == .CHILD or wait_rc == 0) return;
        if (wait_error != .SUCCESS) {
            writeErrno("[mizinit] waitpid() failed", wait_error);
            return;
        }
        noteChildExit(supervisor, @intCast(wait_rc), status);
    }
}

const ChildDrainState = enum {
    drained,
    remaining,
};

const ShutdownPhase = enum {
    term,
    kill,
    final_reap,
    reboot,
};

fn phaseAfterDrain(phase: ShutdownPhase, state: ChildDrainState) ShutdownPhase {
    return switch (phase) {
        .term => if (state == .drained) .reboot else .kill,
        .kill => if (state == .drained) .reboot else .final_reap,
        .final_reap => if (state == .drained) .reboot else .final_reap,
        .reboot => .reboot,
    };
}

fn drainExitedChildren(supervisor: *Supervisor) ChildDrainState {
    while (true) {
        var status: u32 = 0;
        const wait_rc = linux.waitpid(-1, &status, linux.W.NOHANG);
        const wait_error = linux.errno(wait_rc);
        if (wait_error == .INTR) continue;
        if (wait_error == .CHILD) return .drained;
        if (wait_rc == 0) return .remaining;
        if (wait_error != .SUCCESS) {
            writeErrno("[mizinit] shutdown waitpid() failed", wait_error);
            return .remaining;
        }
        noteChildExit(supervisor, @intCast(wait_rc), status);
    }
}

fn boundedChildDrain(supervisor: *Supervisor, attempts: u32) ChildDrainState {
    var attempt: u32 = 0;
    while (attempt < attempts) : (attempt += 1) {
        if (drainExitedChildren(supervisor) == .drained) return .drained;
        const req: linux.timespec = .{ .sec = 0, .nsec = 100_000_000 };
        _ = linux.nanosleep(&req, null);
    }
    return drainExitedChildren(supervisor);
}

fn reapUntilNoChildren(supervisor: *Supervisor) void {
    while (true) {
        var status: u32 = 0;
        const wait_rc = linux.waitpid(-1, &status, 0);
        const wait_error = linux.errno(wait_rc);
        if (wait_error == .INTR) continue;
        if (wait_error == .CHILD) return;
        if (wait_error == .SUCCESS) {
            noteChildExit(supervisor, @intCast(wait_rc), status);
            continue;
        }
        writeErrno("[mizinit] final shutdown waitpid() failed; retrying", wait_error);
        const req: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&req, null);
    }
}

fn isPid1(pid: linux.pid_t) bool {
    return pid == 1;
}

fn broadcastGuestSignal(signal: linux.SIG) void {
    if (!isPid1(linux.getpid())) {
        writeStr("[mizinit] refusing shutdown broadcast outside PID 1\r\n");
        linux.exit(1);
    }
    // Linux kill(-1, ...) excludes process 1 itself. As PID 1 this reaches
    // every permitted guest process, including adopted ssh session children.
    const rc = linux.kill(-1, signal);
    const signal_error = linux.errno(rc);
    if (signal_error != .SUCCESS and signal_error != .SRCH) {
        writeErrno("[mizinit] broadcast shutdown signal failed", signal_error);
    }
}

fn shutdownSupervisor(supervisor: *Supervisor) noreturn {
    writeStr("[mizinit] terminating all guest processes\r\n");
    var phase: ShutdownPhase = .term;
    broadcastGuestSignal(.TERM);
    phase = phaseAfterDrain(phase, boundedChildDrain(supervisor, 50));
    if (phase == .kill) {
        writeStr("[mizinit] forcing remaining guest processes to exit\r\n");
        broadcastGuestSignal(.KILL);
        phase = phaseAfterDrain(phase, boundedChildDrain(supervisor, 50));
    }
    if (phase == .final_reap) {
        writeStr("[mizinit] waiting for all killed children to be reaped\r\n");
        reapUntilNoChildren(supervisor);
        phase = phaseAfterDrain(phase, .drained);
    }
    std.debug.assert(phase == .reboot);
    doReboot(if (shutdown_signal == 2) .RESTART else .POWER_OFF);
}

fn updateDetection(supervisor: *Supervisor) void {
    if (!supervisor.network.dhcp_acknowledged) supervisor.network = setupNetworking();
    if (supervisor.decision != .unknown) return;

    supervisor.media = probeProvisioningMedia();
    const evidence = azureEvidence(supervisor.network, supervisor.media);
    const next_decision = resolveAzureDecision(supervisor.policy, supervisor.cached, evidence);
    if (supervisor.persist_detection) {
        persistObservedAzureDecision(supervisor.policy, supervisor.identity, evidence);
    }
    if (next_decision != .unknown) {
        supervisor.decision = next_decision;
        logAzureDecision(next_decision, supervisor.policy, evidence, supervisor.cached);
    }
}

fn initializeSupervisor(
    boot_config: BootConfig,
    network: NetworkResult,
    identity: ?[36]u8,
    cached: ?AzureDecision,
    persist_detection: bool,
    services_allowed: bool,
    binder_setup_failed: bool,
    console_path: [*:0]const u8,
) Supervisor {
    const media: provisioning_media.ProbeResult = if (boot_config.azure_policy == .auto and services_allowed)
        probeProvisioningMedia()
    else
        .indeterminate;
    const evidence = azureEvidence(network, media);
    const decision = resolveAzureDecision(boot_config.azure_policy, cached, evidence);
    if (persist_detection) {
        persistObservedAzureDecision(boot_config.azure_policy, identity, evidence);
    }
    logAzureDecision(decision, boot_config.azure_policy, evidence, cached);
    return .{
        .policy = boot_config.azure_policy,
        .decision = decision,
        .network = network,
        .media = media,
        .identity = identity,
        .cached = cached,
        .persist_detection = persist_detection,
        .services_allowed = services_allowed,
        .binder_setup_failed = binder_setup_failed,
        .shell_enabled = boot_config.shell_enabled,
        .console_path = console_path,
    };
}

fn decrementDelay(delay: *u32) void {
    if (delay.* > 0) delay.* -= 1;
}

fn azagentLaunchMode(decision: AzureDecision) ?AzagentLaunchMode {
    return switch (decision) {
        .azure => .azure,
        .local => .local,
        .unknown, .non_azure => null,
    };
}

fn shouldRunAzagent(supervisor: *const Supervisor) bool {
    return supervisor.services_allowed and azagentLaunchMode(supervisor.decision) != null and
        !supervisor.azagent_done and supervisor.azagent_pid == 0 and supervisor.azagent_retry == 0;
}

/// The default provider waits for the provisioning sentinel because
/// provisioning is what installs the administrator's authorized key: an sshd
/// started earlier is listening on an image nobody can authenticate to.
///
/// A replacement provider does not wait. It brings its own credential path —
/// it may well *be* what enrolls the machine — so the sentinel proves nothing
/// about it, and making it wait would mean a stalled provisioner takes the
/// machine's only remaining way in down with it. On an appliance whose kernel
/// command line is fixed at build time, that is unrecoverable.
fn shouldStartAccessProvider(
    provider: AccessProvider,
    services_allowed: bool,
    provisioned: bool,
    access_pid: linux.pid_t,
    retry: u32,
) bool {
    if (!services_allowed or access_pid != 0 or retry != 0) return false;
    return switch (provider) {
        .sshd => provisioned,
        .override => true,
    };
}

fn supervisorLoop(supervisor: *Supervisor) noreturn {
    if (!isPid1(linux.getpid())) {
        writeStr("[mizinit] fatal: supervisor must run as PID 1\r\n");
        linux.exit(1);
    }
    if (supervisor.shell_enabled) {
        var buf: [128]u8 = undefined;
        const path = std.mem.span(supervisor.console_path);
        const msg = std.fmt.bufPrint(&buf, "[mizinit] diagnostic root shell enabled on {s}\r\n", .{path}) catch "[mizinit] diagnostic root shell enabled\r\n";
        writeStr(msg);
    } else {
        writeStr("[mizinit] diagnostic root shell disabled\r\n");
    }
    // A required Binder policy that failed to come up stops readiness
    // rather than silently degrading like other best-effort boot steps:
    // the machine still runs (reaping children, honoring shutdown, and an
    // explicitly enabled diagnostic shell), but never announces itself
    // ready and never starts azagent or the access provider (see
    // services_allowed above).
    if (supervisor.binder_setup_failed) {
        writeStr("[mizinit] binder required but unavailable; supervisor loop active but not ready\r\n");
    } else {
        writeStr("[mizinit] MIZINIT_PID1_READY supervisor loop active\r\n");
    }

    while (true) {
        reapChildren(supervisor);
        if (shutdown_signal != 0) shutdownSupervisor(supervisor);

        if (shouldRunAzagent(supervisor)) {
            if (spawnAzagent(azagentLaunchMode(supervisor.decision).?)) |pid| {
                supervisor.azagent_pid = pid;
                supervisor.azagent_missing_logged = false;
            } else {
                if (!supervisor.azagent_missing_logged) {
                    writeStr("[mizinit] provisioning requires /usr/sbin/azagent; SSH remains gated\r\n");
                    supervisor.azagent_missing_logged = true;
                }
                supervisor.azagent_retry = provisioning_retry_seconds;
            }
        }

        const access_provider = selectAccessProvider();
        if (shouldStartAccessProvider(
            access_provider,
            supervisor.services_allowed,
            isProvisioned(),
            supervisor.access_pid,
            supervisor.access_retry,
        )) {
            if (spawnAccessProvider(access_provider)) |pid| {
                supervisor.access_pid = pid;
            } else {
                supervisor.access_retry = supervisor.access_backoff;
                supervisor.access_backoff = nextAccessBackoff(supervisor.access_backoff);
            }
        }

        if (supervisor.shell_enabled and supervisor.shell_pid == 0 and supervisor.shell_retry == 0) {
            if (spawnDiagnosticShell(supervisor.console_path)) |pid| {
                supervisor.shell_pid = pid;
            } else {
                supervisor.shell_retry = 1;
            }
        }

        const req: linux.timespec = .{ .sec = 1, .nsec = 0 };
        _ = linux.nanosleep(&req, null);
        decrementDelay(&supervisor.azagent_retry);
        decrementDelay(&supervisor.access_retry);
        decrementDelay(&supervisor.shell_retry);
        decrementDelay(&supervisor.detection_retry);
        if (supervisor.services_allowed and supervisor.detection_retry == 0) {
            updateDetection(supervisor);
            supervisor.detection_retry = provisioning_retry_seconds;
        }
    }
}

pub fn main(init: std.process.Init.Minimal) noreturn {
    const argv0 = if (init.args.vector.len > 0) std.mem.span(init.args.vector[0]) else "";
    if (std.mem.endsWith(u8, argv0, "poweroff") or std.mem.endsWith(u8, argv0, "shutdown")) {
        requestPid1Shutdown(.TERM, .POWER_OFF);
    }
    if (std.mem.endsWith(u8, argv0, "reboot")) {
        requestPid1Shutdown(.INT, .RESTART);
    }

    installShutdownHandlers();

    mountIgnoreBusy("proc", "/proc", "proc", 0);
    mountIgnoreBusy("sysfs", "/sys", "sysfs", 0);
    mountIgnoreBusy("devtmpfs", "/dev", "devtmpfs", 0);
    mountIgnoreBusy("tmpfs", "/run", "tmpfs", 0);
    openConsoleLog();
    openDebugLog();
    const boot_config = readBootConfig();
    var console_path_buf: [80:0]u8 = undefined;
    const console_path = discoverSerialConsolePath(&console_path_buf);
    const boot_mode = boot_config.mode;
    const persistent_root_ready = if (boot_mode == .persistent) remountRootWritable() else false;
    loadBootModules(boot_mode);
    const binder_outcome = configureBinder(boot_config.binder_policy);
    mountIgnoreBusy("tmpfs", "/tmp", "tmpfs", 0);
    if (boot_mode == .immutable) {
        mountImmutableWritableOverlays();
        mountEtcOverlay();
    } else {
        etc_writable = persistent_root_ready;
    }
    tryMountEsp();
    setHostname(boot_mode, persistent_root_ready);
    ensureMachineId();

    writeStr("\r\n[mizinit] base mounts ready; configuring network...\r\n");
    const network = setupNetworking();

    if (boot_mode == .persistent and !persistent_root_ready) {
        writeStr("[mizinit] persistent storage is unavailable; azagent and SSH will not start\r\n");
    }
    const persist_detection = boot_mode == .persistent and persistent_root_ready;
    const identity = if (persist_detection) readVmIdentity() else null;
    const cached = if (identity) |vm_identity| readCachedAzureDecision(vm_identity) else null;
    var supervisor = initializeSupervisor(
        boot_config,
        network,
        identity,
        cached,
        persist_detection,
        servicesAllowedAfterBinderSetup(boot_mode == .immutable or persistent_root_ready, binder_outcome),
        binder_outcome == .failed,
        console_path,
    );
    supervisorLoop(&supervisor);
}

test "parseBootConfig defaults to immutable automatic Azure detection and no shell" {
    const config = parseBootConfig("root=/dev/sda2 console=ttyS0");
    try std.testing.expectEqual(BootMode.immutable, config.mode);
    try std.testing.expectEqual(AzurePolicy.auto, config.azure_policy);
    try std.testing.expect(!config.shell_enabled);
}

test "parseBootConfig accepts boot modes Azure policies and explicit shell setting independently" {
    const persistent = parseBootConfig("root=/dev/sda2 mizinit.mode=persistent mizinit.azure=on mizinit.shell=on console=ttyS0");
    try std.testing.expectEqual(BootMode.persistent, persistent.mode);
    try std.testing.expectEqual(AzurePolicy.on, persistent.azure_policy);
    try std.testing.expect(persistent.shell_enabled);

    const immutable = parseBootConfig("mizinit.mode=immutable mizinit.azure=off mizinit.shell=off");
    try std.testing.expectEqual(BootMode.immutable, immutable.mode);
    try std.testing.expectEqual(AzurePolicy.off, immutable.azure_policy);
    try std.testing.expect(!immutable.shell_enabled);
}

test "parseBootConfig uses the last value for each setting" {
    const config = parseBootConfig("mizinit.mode=persistent mizinit.azure=off mizinit.shell=on mizinit.mode=immutable mizinit.azure=auto mizinit.shell=off");
    try std.testing.expectEqual(BootMode.immutable, config.mode);
    try std.testing.expectEqual(AzurePolicy.auto, config.azure_policy);
    try std.testing.expect(!config.shell_enabled);
    try std.testing.expectEqual(@as(?[]const u8, null), config.invalid_mode);
    try std.testing.expectEqual(@as(?[]const u8, null), config.invalid_azure_policy);
    try std.testing.expectEqual(@as(?[]const u8, null), config.invalid_shell);
}

test "parseBootConfig allows later valid values to replace invalid ones" {
    const config = parseBootConfig("mizinit.mode=invalid mizinit.azure=maybe mizinit.shell=yes mizinit.mode=persistent mizinit.azure=on mizinit.shell=on");
    try std.testing.expectEqual(BootMode.persistent, config.mode);
    try std.testing.expectEqual(AzurePolicy.on, config.azure_policy);
    try std.testing.expect(config.shell_enabled);
    try std.testing.expectEqual(@as(?[]const u8, null), config.invalid_mode);
    try std.testing.expectEqual(@as(?[]const u8, null), config.invalid_azure_policy);
    try std.testing.expectEqual(@as(?[]const u8, null), config.invalid_shell);
}

test "parseBootConfig rejects invalid values with safe defaults" {
    const config = parseBootConfig("mizinit.mode=writable mizinit.azure=maybe mizinit.shell=yes");
    try std.testing.expectEqual(BootMode.immutable, config.mode);
    try std.testing.expectEqual(AzurePolicy.auto, config.azure_policy);
    try std.testing.expect(!config.shell_enabled);
    try std.testing.expectEqualStrings("writable", config.invalid_mode.?);
    try std.testing.expectEqualStrings("maybe", config.invalid_azure_policy.?);
    try std.testing.expectEqualStrings("yes", config.invalid_shell.?);
}

test "parseBootConfig defaults binder policy to disabled and accepts required independently of other options" {
    const default_config = parseBootConfig("root=/dev/sda2 console=ttyS0");
    try std.testing.expectEqual(BinderPolicy.disabled, default_config.binder_policy);

    const required = parseBootConfig("mizinit.mode=persistent mizinit.azure=on mizinit.binder=required console=ttyS0");
    try std.testing.expectEqual(BinderPolicy.required, required.binder_policy);
    try std.testing.expectEqual(BootMode.persistent, required.mode);
    try std.testing.expectEqual(AzurePolicy.on, required.azure_policy);

    const explicit_disabled = parseBootConfig("mizinit.binder=disabled");
    try std.testing.expectEqual(BinderPolicy.disabled, explicit_disabled.binder_policy);
}

test "parseBootConfig uses the last binder value and rejects invalid ones with a safe default" {
    const last_wins = parseBootConfig("mizinit.binder=required mizinit.binder=disabled");
    try std.testing.expectEqual(BinderPolicy.disabled, last_wins.binder_policy);
    try std.testing.expectEqual(@as(?[]const u8, null), last_wins.invalid_binder_policy);

    const invalid = parseBootConfig("mizinit.binder=maybe");
    try std.testing.expectEqual(BinderPolicy.disabled, invalid.binder_policy);
    try std.testing.expectEqualStrings("maybe", invalid.invalid_binder_policy.?);

    const recovered = parseBootConfig("mizinit.binder=maybe mizinit.binder=required");
    try std.testing.expectEqual(BinderPolicy.required, recovered.binder_policy);
    try std.testing.expectEqual(@as(?[]const u8, null), recovered.invalid_binder_policy);
}

test "serial console discovery prefers the last serial cmdline entry then active console" {
    try std.testing.expectEqualStrings(
        "ttyAMA1",
        selectSerialConsole("console=tty0 console=ttyS0,115200 console=ttyAMA1,115200", "tty0 hvc0", .x86_64),
    );
    try std.testing.expectEqualStrings(
        "hvc0",
        selectSerialConsole("console=tty0", "tty0 hvc0", .x86_64),
    );
    try std.testing.expectEqualStrings("ttyS0", selectSerialConsole("", "tty0", .x86_64));
    try std.testing.expectEqualStrings("ttyAMA0", selectSerialConsole("", "", .aarch64));
}

test "access provider restart backoff is exponential and bounded" {
    try std.testing.expectEqual(@as(u32, 2), nextAccessBackoff(1));
    try std.testing.expectEqual(@as(u32, 16), nextAccessBackoff(8));
    try std.testing.expectEqual(access_max_backoff_seconds, nextAccessBackoff(16));
    try std.testing.expectEqual(access_max_backoff_seconds, nextAccessBackoff(access_max_backoff_seconds));
}

test "binder module candidates try kernel-decompressed .ko.zst before a plain .ko fallback" {
    const candidates = binderModuleCandidates();
    try std.testing.expectEqual(@as(usize, 2), candidates.len);
    try std.testing.expect(std.mem.endsWith(u8, candidates[0].rel_path, "binder_linux.ko.zst"));
    try std.testing.expectEqual(MODULE_INIT_COMPRESSED_FILE, candidates[0].flags);
    try std.testing.expect(std.mem.endsWith(u8, candidates[1].rel_path, "binder_linux.ko"));
    try std.testing.expect(!std.mem.endsWith(u8, candidates[1].rel_path, ".zst"));
    try std.testing.expectEqual(@as(u32, 0), candidates[1].flags);
}

test "binder devices are created in binder hwbinder vndbinder order" {
    try std.testing.expectEqual(@as(usize, 3), binder_devices.len);
    try std.testing.expectEqualStrings("binder", binder_devices[0].asBytes());
    try std.testing.expectEqualStrings("hwbinder", binder_devices[1].asBytes());
    try std.testing.expectEqualStrings("vndbinder", binder_devices[2].asBytes());
}

test "BINDER_CTL_ADD matches the kernel's binderfs_device layout and _IOWR encoding" {
    // struct binderfs_device { char name[256]; __u32 major; __u32 minor; };
    try std.testing.expectEqual(@as(usize, 264), @sizeOf(BinderfsDevice));
    // _IOWR('b', 1, struct binderfs_device) per <linux/android/binderfs.h>.
    try std.testing.expectEqual(@as(u32, 0xC1086201), binder_ctl_add);
}

test "binder step results tolerate exactly the already-done errno for that step" {
    try std.testing.expectEqual(BinderStepResult.ok, binderStepResult(.SUCCESS, .EXIST));
    try std.testing.expectEqual(BinderStepResult.ok, binderStepResult(.EXIST, .EXIST));
    try std.testing.expectEqual(BinderStepResult.failed, binderStepResult(.NOENT, .EXIST));
    try std.testing.expectEqual(BinderStepResult.failed, binderStepResult(.BUSY, .EXIST));

    try std.testing.expectEqual(BinderStepResult.ok, binderStepResult(.SUCCESS, .BUSY));
    try std.testing.expectEqual(BinderStepResult.ok, binderStepResult(.BUSY, .BUSY));
    try std.testing.expectEqual(BinderStepResult.failed, binderStepResult(.NODEV, .BUSY));
}

test "binder setup outcome is not_requested when disabled and fails closed on any required step failure" {
    try std.testing.expectEqual(BinderSetupOutcome.not_requested, binderSetupOutcome(.disabled, .failed, .failed, .failed));
    try std.testing.expectEqual(BinderSetupOutcome.not_requested, binderSetupOutcome(.disabled, .ok, .ok, .ok));

    try std.testing.expectEqual(BinderSetupOutcome.ready, binderSetupOutcome(.required, .ok, .ok, .ok));
    try std.testing.expectEqual(BinderSetupOutcome.failed, binderSetupOutcome(.required, .failed, .ok, .ok));
    try std.testing.expectEqual(BinderSetupOutcome.failed, binderSetupOutcome(.required, .ok, .failed, .ok));
    try std.testing.expectEqual(BinderSetupOutcome.failed, binderSetupOutcome(.required, .ok, .ok, .failed));
}

test "servicesAllowedAfterBinderSetup fails closed only on a failed required binder outcome" {
    try std.testing.expect(servicesAllowedAfterBinderSetup(true, .not_requested));
    try std.testing.expect(servicesAllowedAfterBinderSetup(true, .ready));
    try std.testing.expect(!servicesAllowedAfterBinderSetup(true, .failed));
    // A base gate that was already closed (e.g. persistent mode without a
    // writable root) stays closed regardless of the binder outcome.
    try std.testing.expect(!servicesAllowedAfterBinderSetup(false, .ready));
    try std.testing.expect(!servicesAllowedAfterBinderSetup(false, .not_requested));
}

test "service gates require provisionable media for azagent and sentinel for sshd" {
    var supervisor: Supervisor = undefined;
    supervisor.services_allowed = true;
    supervisor.decision = .azure;
    supervisor.azagent_done = false;
    supervisor.azagent_pid = 0;
    supervisor.azagent_retry = 0;
    try std.testing.expect(shouldRunAzagent(&supervisor));
    supervisor.decision = .local;
    try std.testing.expect(shouldRunAzagent(&supervisor));
    supervisor.decision = .non_azure;
    try std.testing.expect(!shouldRunAzagent(&supervisor));

    // The default provider is unchanged: it still waits for the sentinel.
    try std.testing.expect(!shouldStartAccessProvider(.sshd, true, false, 0, 0));
    try std.testing.expect(shouldStartAccessProvider(.sshd, true, true, 0, 0));
    try std.testing.expect(!shouldStartAccessProvider(.sshd, true, true, 42, 0));
    try std.testing.expect(!shouldStartAccessProvider(.sshd, true, true, 0, 1));
}

test "a replacement access provider starts without waiting for provisioning" {
    // The sentinel proves an authorized key was installed, which says nothing
    // about a provider that carries its own credentials. Waiting would let a
    // stalled provisioner remove the machine's last way in.
    try std.testing.expect(shouldStartAccessProvider(.override, true, false, 0, 0));
    try std.testing.expect(shouldStartAccessProvider(.override, true, true, 0, 0));

    // Everything else still gates it identically to sshd.
    try std.testing.expect(!shouldStartAccessProvider(.override, false, true, 0, 0));
    try std.testing.expect(!shouldStartAccessProvider(.override, true, true, 42, 0));
    try std.testing.expect(!shouldStartAccessProvider(.override, true, true, 0, 1));
}

test "each access provider runs its own binary" {
    // A provider is supervised as itself, never as sshd with different
    // arguments: the override takes none, and sshd needs -D -e to be
    // supervisable at all.
    try std.testing.expectEqualStrings(sshd_path, std.mem.span(AccessProvider.path(.sshd)));
    try std.testing.expectEqualStrings(access_provider_path, std.mem.span(AccessProvider.path(.override)));
    try std.testing.expect(!std.mem.eql(u8, sshd_path, access_provider_path));
}

test "an image with no override resolves to the default provider" {
    // The whole compatibility promise of this seam: an image that ships no
    // /usr/local/sbin/mizinit-access behaves exactly as it did before it
    // existed, on every architecture.
    try std.testing.expectEqual(AccessProvider.sshd, accessProviderFor(false));
    try std.testing.expectEqual(AccessProvider.override, accessProviderFor(true));
}

test "azagent launch selects skip-ready only for explicit local media" {
    try std.testing.expectEqual(AzagentLaunchMode.azure, azagentLaunchMode(.azure).?);
    try std.testing.expectEqual(@as(?[*:0]const u8, null), azagentModeArgument(.azure));
    try std.testing.expectEqual(AzagentLaunchMode.local, azagentLaunchMode(.local).?);
    try std.testing.expectEqualStrings("--skip-ready", std.mem.span(azagentModeArgument(.local).?));
    try std.testing.expectEqual(@as(?AzagentLaunchMode, null), azagentLaunchMode(.unknown));
    try std.testing.expectEqual(@as(?AzagentLaunchMode, null), azagentLaunchMode(.non_azure));
}

test "shutdown policy broadcasts only as PID 1 and escalates after bounded drain" {
    try std.testing.expect(isPid1(1));
    try std.testing.expect(!isPid1(2));
    try std.testing.expectEqual(ShutdownPhase.reboot, phaseAfterDrain(.term, .drained));
    try std.testing.expectEqual(ShutdownPhase.kill, phaseAfterDrain(.term, .remaining));
    try std.testing.expectEqual(ShutdownPhase.reboot, phaseAfterDrain(.kill, .drained));
    try std.testing.expectEqual(ShutdownPhase.final_reap, phaseAfterDrain(.kill, .remaining));
    try std.testing.expectEqual(ShutdownPhase.final_reap, phaseAfterDrain(.final_reap, .remaining));
    try std.testing.expectEqual(ShutdownPhase.reboot, phaseAfterDrain(.final_reap, .drained));
}

test "parsePersistedHostname trims line endings and rejects invalid content" {
    try std.testing.expectEqualStrings("generalized-vm", parsePersistedHostname("generalized-vm\n").?);
    try std.testing.expectEqual(@as(?[]const u8, null), parsePersistedHostname(" \r\n"));
    try std.testing.expectEqual(@as(?[]const u8, null), parsePersistedHostname("invalid\x00hostname"));

    const too_long = "a" ** (linux.HOST_NAME_MAX + 1);
    try std.testing.expectEqual(@as(?[]const u8, null), parsePersistedHostname(too_long));
}

test "machine-id validation accepts lowercase 128-bit hex only" {
    try std.testing.expect(isValidMachineId("0123456789abcdef0123456789abcdef\n"));
    try std.testing.expect(!isValidMachineId(""));
    try std.testing.expect(!isValidMachineId("0123456789ABCDEF0123456789ABCDEF\n"));
    try std.testing.expect(!isValidMachineId("0123456789abcdef0123456789abcdeg\n"));
}

test "formatMachineId emits lowercase hex and a newline" {
    try std.testing.expectEqualStrings(
        "000102030405060708090a0b0c0d0e0f\n",
        &formatMachineId(.{ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15 }),
    );
}

test "resolveAzureDecision honors overrides, positive evidence, cache, and fail-closed unknowns" {
    const none: AzureEvidence = .{ .media = .absent };
    try std.testing.expectEqual(AzureDecision.azure, resolveAzureDecision(.on, .non_azure, none));
    try std.testing.expectEqual(AzureDecision.azure, resolveAzureDecision(.on, null, .{ .media = .local }));
    try std.testing.expectEqual(AzureDecision.non_azure, resolveAzureDecision(.off, .azure, .{ .saw_option_245 = true }));

    try std.testing.expectEqual(
        AzureDecision.azure,
        resolveAzureDecision(.auto, .non_azure, .{ .saw_option_245 = true }),
    );
    try std.testing.expectEqual(
        AzureDecision.azure,
        resolveAzureDecision(.auto, .non_azure, .{ .media = .azure }),
    );
    try std.testing.expectEqual(
        AzureDecision.local,
        resolveAzureDecision(.auto, .non_azure, .{ .media = .local }),
    );
    try std.testing.expectEqual(
        AzureDecision.azure,
        resolveAzureDecision(.auto, null, .{ .saw_option_245 = true, .media = .local }),
    );
    try std.testing.expectEqual(AzureDecision.azure, resolveAzureDecision(.auto, .azure, none));
    try std.testing.expectEqual(AzureDecision.unknown, resolveAzureDecision(.auto, null, .{
        .dhcp_acknowledged = true,
        .media = .absent,
    }));
    try std.testing.expectEqual(AzureDecision.unknown, resolveAzureDecision(.auto, null, .{
        .dhcp_acknowledged = true,
        .media = .indeterminate,
    }));
    try std.testing.expectEqual(AzureDecision.unknown, resolveAzureDecision(.auto, null, none));
}

test "automatic persistence requires positive Azure evidence" {
    try std.testing.expectEqual(
        AzureDecision.azure,
        automaticDecisionToPersist(.{ .saw_option_245 = true }).?,
    );
    try std.testing.expectEqual(
        AzureDecision.azure,
        automaticDecisionToPersist(.{ .media = .azure }).?,
    );
    try std.testing.expectEqual(
        @as(?AzureDecision, null),
        automaticDecisionToPersist(.{ .dhcp_acknowledged = true, .media = .absent }),
    );
}

test "Azure environment state normalizes identities, round trips, and rejects mismatches" {
    const identity = normalizeVmIdentity("01234567-89AB-CDEF-0123-456789ABCDEF\n").?;
    try std.testing.expectEqualStrings("01234567-89ab-cdef-0123-456789abcdef", &identity);
    try std.testing.expectEqual(@as(?[36]u8, null), normalizeVmIdentity("00000000-0000-0000-0000-000000000000"));
    try std.testing.expectEqual(@as(?[36]u8, null), normalizeVmIdentity("not-a-uuid"));

    var buf: [64]u8 = undefined;
    const rendered = renderEnvironmentState(&buf, identity, .non_azure).?;
    try std.testing.expectEqualStrings(
        "v1 01234567-89ab-cdef-0123-456789abcdef non-azure\n",
        rendered,
    );

    const parsed = parseEnvironmentState(rendered).?;
    try std.testing.expectEqual(AzureDecision.non_azure, parsed.decision);
    try std.testing.expectEqualSlices(u8, &identity, &parsed.identity);
    try std.testing.expectEqual(AzureDecision.non_azure, cachedDecisionForIdentity(parsed, identity).?);

    const other_identity = normalizeVmIdentity("11234567-89ab-cdef-0123-456789abcdef").?;
    try std.testing.expectEqual(@as(?AzureDecision, null), cachedDecisionForIdentity(parsed, other_identity));
    try std.testing.expectEqual(@as(?EnvironmentState, null), parseEnvironmentState("v2 01234567-89ab-cdef-0123-456789abcdef azure"));
    try std.testing.expectEqual(@as(?EnvironmentState, null), parseEnvironmentState("v1 01234567-89ab-cdef-0123-456789abcdef unknown"));
}

test "DHCP requests include Azure option 245" {
    const expected = &[_]u8{ 55, 4, 1, 3, 6, 245, 255 };
    var packet: [512]u8 = undefined;
    const mac = [_]u8{ 0, 1, 2, 3, 4, 5 };

    const discover_len = buildDhcpPacket(&packet, 0x12345678, mac, 1, 0, 0);
    try std.testing.expect(std.mem.indexOf(u8, packet[240..discover_len], expected) != null);

    const request_len = buildDhcpPacket(&packet, 0x12345678, mac, 3, 0x0a000002, 0x0a000001);
    try std.testing.expect(std.mem.indexOf(u8, packet[240..request_len], expected) != null);
}

fn makeTestDhcpReply(buf: []u8, xid: u32, msg_type: u8, option_245: ?[]const u8) usize {
    @memset(buf, 0);
    buf[0] = 2;
    std.mem.writeInt(u32, buf[4..8], xid, .big);
    std.mem.writeInt(u32, buf[16..20], 0x0a000002, .big);
    @memcpy(buf[236..240], &DHCP_MAGIC);

    var pos: usize = 240;
    buf[pos] = 53;
    buf[pos + 1] = 1;
    buf[pos + 2] = msg_type;
    pos += 3;
    if (option_245) |value| {
        buf[pos] = 245;
        buf[pos + 1] = @intCast(value.len);
        @memcpy(buf[pos + 2 ..][0..value.len], value);
        pos += 2 + value.len;
    }
    buf[pos] = 255;
    return pos + 1;
}

test "DHCP parser retains valid option 245 evidence from OFFER or ACK" {
    const xid = 0x12345678;
    var buf: [512]u8 = undefined;
    const endpoint = [_]u8{ 168, 63, 129, 16 };

    const offer_len = makeTestDhcpReply(&buf, xid, 2, &endpoint);
    const offer = parseDhcpReply(&buf, offer_len, xid).?;
    try std.testing.expect(offer.has_option_245);

    var attempt: DhcpAttempt = .{};
    recordDhcpEvidence(&attempt, offer);
    const ack_len = makeTestDhcpReply(&buf, xid, 5, null);
    const ack = parseDhcpReply(&buf, ack_len, xid).?;
    recordDhcpEvidence(&attempt, ack);
    try std.testing.expect(attempt.saw_option_245);

    const ack_only_len = makeTestDhcpReply(&buf, xid, 5, &endpoint);
    try std.testing.expect(parseDhcpReply(&buf, ack_only_len, xid).?.has_option_245);
}

test "DHCP parser ignores malformed or truncated option 245" {
    const xid = 0x12345678;
    var buf: [512]u8 = undefined;

    const short_len = makeTestDhcpReply(&buf, xid, 2, &[_]u8{ 1, 2, 3 });
    try std.testing.expect(!parseDhcpReply(&buf, short_len, xid).?.has_option_245);

    const base_len = makeTestDhcpReply(&buf, xid, 2, null);
    buf[base_len - 1] = 245;
    buf[base_len] = 4;
    buf[base_len + 1] = 1;
    buf[base_len + 2] = 2;
    try std.testing.expect(!parseDhcpReply(&buf, base_len + 3, xid).?.has_option_245);
}

test "dhcp candidates prefer the interfaces reporting carrier" {
    var out: [8]u8 = undefined;

    // A bare-metal node: dark fabric ports either side of the one cabled NIC.
    const mixed = [_]?bool{ false, false, true, false };
    try std.testing.expectEqualSlices(u8, &.{2}, dhcpCandidateOrder(&mixed, &out));

    // More than one live link: both are tried, in the list's stable order.
    const several = [_]?bool{ true, false, true };
    try std.testing.expectEqualSlices(u8, &.{ 0, 2 }, dhcpCandidateOrder(&several, &out));

    // Nothing reports carrier, including interfaces that never answer at all.
    // Falling back to trying everything preserves the behavior this function
    // replaced, so a hypervisor with synthetic NICs still gets an address.
    const silent = [_]?bool{ null, false, null };
    try std.testing.expectEqualSlices(u8, &.{ 0, 1, 2 }, dhcpCandidateOrder(&silent, &out));

    // A machine with no interfaces at all must not produce a candidate.
    const none = [_]?bool{};
    try std.testing.expectEqual(@as(usize, 0), dhcpCandidateOrder(&none, &out).len);
}

test "interface order does not depend on readdir order" {
    var list: InterfaceList = .{};
    list.append("enxb4e9b8888d30");
    list.append("enP1p3s0f0np0");
    list.append("enx3eb3994d4bf7");
    list.sort();

    try std.testing.expectEqual(@as(usize, 3), list.count);
    try std.testing.expectEqualStrings("enP1p3s0f0np0", list.name(0));
    try std.testing.expectEqualStrings("enx3eb3994d4bf7", list.name(1));
    try std.testing.expectEqualStrings("enxb4e9b8888d30", list.name(2));
}

test "interface list is bounded and rejects unusable names" {
    var list: InterfaceList = .{};
    list.append("");
    try std.testing.expectEqual(@as(usize, 0), list.count);

    var added: usize = 0;
    while (added < max_candidate_interfaces + 8) : (added += 1) list.append("eth0");
    try std.testing.expectEqual(max_candidate_interfaces, list.count);
}
