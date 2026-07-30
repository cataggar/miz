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
    ) orelse return .ufs;
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

fn commandSucceeded(io: Io, argv: []const []const u8) bool {
    var child = std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    defer child.kill(io);
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn sshSucceeded(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    command: []const u8,
) !bool {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_text);
    return commandSucceeded(io, &.{
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
    });
}

fn sshOutputAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    key_path: []const u8,
    port: u16,
    command: []const u8,
) ![]u8 {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{port});
    defer allocator.free(port_text);
    const result = try std.process.run(allocator, io, .{
        .argv = &.{
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
        .stdout_limit = .limited(16 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(15),
            .clock = .awake,
        } },
    });
    allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }
    allocator.free(result.stdout);
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
    \\test "$(sysrc -n waagent_enable)" = YES
    \\test "$(sysrc -n sshd_enable)" = YES
    \\test "$(sysrc -n nuageinit_enable)" = YES
    \\test "$(sysrc -n growfs_enable)" = YES
    \\test "$(sysrc -n growfs_swap_size)" = 0
    \\test "$(sysrc -n ifconfig_DEFAULT)" = "SYNCDHCP accept_rtadv"
    \\test "$(sysrc -n ifconfig_hn0)" = SYNCDHCP
    \\test "$(sysrc -n firstboot_pkg_upgrade_enable)" = NO
    \\pkg info -e azure-agent
    \\! pw usershow freebsd >/dev/null 2>&1
    \\sudo -n awk -F: '$1 == "root" && $2 == "*LOCKED*" { ok=1 } END { exit !ok }' /etc/master.passwd
    \\test -s /etc/ssh/ssh_host_ed25519_key
    \\test -s /home/zvmitest/.ssh/authorized_keys
    \\test ! -e /firstboot
    \\test ! -e /firstboot-reboot
    \\test ! -e /root/zvmi-generalize.sh
    \\test ! -e /etc/rc.d/zvmi_generalize
    \\! grep -Eq '^[^#].*[[:space:]]swap[[:space:]]' /etc/fstab
    \\test "$(swapinfo -k | wc -l | tr -d ' ')" = 1
    \\grep -Fx 'Provisioning.Agent=auto' /usr/local/etc/waagent.conf
    \\grep -Fx 'ResourceDisk.SwapSizeMB=2048' /usr/local/etc/waagent.conf
    \\disk=$(gpart show | awk '$1 == "=>" { print $4; exit }')
    \\test -n "${disk}"
    \\! gpart show | grep -q CORRUPT
    \\test "$(gpart status -s "${disk}" | awk '{ print $2 }' | sort -u)" = OK
;

/// UFS-specific state. The root is named in /etc/fstab and grows with
/// growfs(8), so df(1) reports the enlarged filesystem directly.
const ufs_remote_checks =
    \\test "$(mount -p | awk '$2 == "/" { print $3 }')" = ufs
    \\grep -Eq '^[^#]+[[:space:]]+/[[:space:]]+ufs[[:space:]]' /etc/fstab
    \\test "$(($(df -k / | awk 'END { print $2 }') * 1024))" -ge @MINIMUM_ROOT_BYTES@
;

/// ZFS-specific state. The root has no fstab entry and grows by onlining the
/// enlarged vdev, so the pool - not the dataset - is what must have grown.
/// The pool must also be healthy, carry autoexpand for later enlargements,
/// and be re-GUIDed on every boot so two clones stay distinguishable.
const zfs_remote_checks =
    \\test "$(mount -p | awk '$2 == "/" { print $3 }')" = zfs
    \\root_pool=$(mount -p | awk '$2 == "/" { print $1 }' | sed 's|/.*||')
    \\test "${root_pool}" = zroot
    \\test "$(zpool status -x "${root_pool}")" = "pool '${root_pool}' is healthy"
    \\test "$(sysrc -n zfs_enable)" = YES
    \\test "$(sysrc -n zpool_reguid)" = "${root_pool}"
    \\test "$(zpool get -H -o value autoexpand "${root_pool}")" = on
    \\test "$(zpool list -Hp -o size "${root_pool}")" -ge @MINIMUM_ROOT_BYTES@
    \\test -z "$(zfs list -H -o name,org.freebsd:swap -t volume | awk '$2 == "on" { print $1 }')"
    \\! grep -Eq '[[:space:]]ufs[[:space:]]' /etc/fstab
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
fn contractRemoteChecksAlloc(
    allocator: Allocator,
    flavor: Flavor,
) ![]u8 {
    const manifest = packages.forFlavor(flavor);
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    for (manifest.required) |package| {
        try output.writer.print("pkg info -e {s}\n", .{package.name});
    }
    for (manifest.library_roots) |library| {
        try output.writer.print("pkg info -e {s}\n", .{library});
    }
    for (manifest.excluded) |excluded| {
        try output.writer.print("! pkg info -e {s}\n", .{excluded});
    }
    for (manifest.excluded_classes) |class| {
        try output.writer.print(
            "! pkg query -a '%n' | grep -Eq '^FreeBSD-.*-{s}$'\n",
            .{class},
        );
    }
    // The update path is the reason a core image stays supportable, so prove
    // both repositories still answer rather than trusting the build log.
    try output.writer.print(
        "pkg update -f\npkg update -f -r {s}\n" ++
            "pkg rquery -r {s} '%n-%v' FreeBSD-runtime >/dev/null\n",
        .{ manifest.base_repository, manifest.base_repository },
    );
    return output.toOwnedSlice();
}

fn remoteChecksAlloc(
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
    const contract = try contractRemoteChecksAlloc(allocator, flavor);
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
    \\sysctl -n kern.hostuuid
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

test "remote checks stay filesystem-specific" {
    const allocator = std.testing.allocator;
    const ufs = try remoteChecksAlloc(allocator, .ufs, .full);
    defer allocator.free(ufs);
    const zfs = try remoteChecksAlloc(allocator, .zfs, .full);
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
            "! gpart show | grep -q CORRUPT",
        ) != null);
        try std.testing.expect(std.mem.indexOf(
            u8,
            checks,
            "8589934592",
        ) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, ufs, "zpool") == null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "zpool list -Hp -o size") != null);
    try std.testing.expect(std.mem.indexOf(u8, zfs, "df -k /") == null);
}

test "remote checks enforce the retained contract for every flavor" {
    const allocator = std.testing.allocator;
    const full = try remoteChecksAlloc(allocator, .ufs, .full);
    defer allocator.free(full);
    const core = try remoteChecksAlloc(allocator, .ufs, .core);
    defer allocator.free(core);

    for ([_][]const u8{ full, core }) |checks| {
        // Every clause of the retain-at-minimum list is a package the booted
        // image must still carry, so losing one fails acceptance rather than
        // shipping.
        for (packages.required_packages) |package| {
            const line = try std.fmt.allocPrint(
                allocator,
                "\npkg info -e {s}\n",
                .{package.name},
            );
            defer allocator.free(line);
            try std.testing.expect(
                std.mem.indexOf(u8, checks, line) != null,
            );
        }
        // The base update path is what makes a published image supportable.
        try std.testing.expect(std.mem.indexOf(
            u8,
            checks,
            "pkg update -f -r FreeBSD-base",
        ) != null);
    }

    // Only the core flavor claims exclusions, so only it may assert them.
    for (packages.core_excluded_packages) |excluded| {
        const line = try std.fmt.allocPrint(
            allocator,
            "! pkg info -e {s}\n",
            .{excluded},
        );
        defer allocator.free(line);
        try std.testing.expect(std.mem.indexOf(u8, core, line) != null);
        try std.testing.expect(std.mem.indexOf(u8, full, line) == null);
    }
    for (packages.library_roots) |library| {
        const line = try std.fmt.allocPrint(
            allocator,
            "pkg info -e {s}\n",
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
    const remote_checks = try remoteChecksAlloc(
        allocator,
        root_filesystem,
        flavor,
    );
    defer allocator.free(remote_checks);
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
        try std.testing.expect(try sshSucceeded(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            remote_checks,
        ));
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
        try std.testing.expect(try sshSucceeded(
            allocator,
            io,
            ssh_path,
            private_key_path,
            port,
            remote_checks,
        ));
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
