//! `azagent`: minimal guest provisioning agent for first-boot Azure VM
//! setup. Native Zig replacement for the provisioning portion of Python
//! `waagent` (Microsoft Azure Linux Agent) -- see vmiz issue #112.
//!
//! Deliberately not named `waagent`: this project does not aim for
//! binary/config/CLI compatibility with the real Azure Linux Agent (no
//! `-deprovision` flag, no VM extension handling -- see the issue for the
//! full list of what's explicitly out of scope). `waagent_conf.zig` does
//! read `/etc/waagent.conf`, but only honors a small explicit whitelist of
//! keys (see issue #125) -- not full compatibility with that format's ~50
//! other settings.
const std = @import("std");
const wireserver = @import("wireserver");

pub const ovf = @import("ovf.zig");
pub const hostname = @import("hostname.zig");
pub const passwd = @import("passwd.zig");
pub const sudoers = @import("sudoers.zig");
pub const ssh_keys = @import("ssh_keys.zig");
pub const sentinel = @import("sentinel.zig");
pub const cdrom = @import("cdrom.zig");
pub const waagent_conf = @import("waagent_conf.zig");
pub const resource_disk = @import("resource_disk.zig");
pub const drive_mounts = @import("drive_mounts.zig");
pub const root_resize = @import("root_resize.zig");
pub const validation = @import("validation.zig");

/// Everything `provision` needs, injected rather than hardcoded, so it's
/// fully testable against a scoped temp directory instead of the real
/// `/etc`, `/home`, and `/var` (see the test at the bottom of this file).
pub const Deps = struct {
    allocator: std.mem.Allocator,
    io: std.Io,
    etc_dir: std.Io.Dir,
    home_parent_dir: std.Io.Dir,
    var_dir: std.Io.Dir,
    /// Already-read content of `ovf-env.xml` (fetching it off the
    /// provisioning CD-ROM is `main`'s job, via `cdrom.zig`, not
    /// `provision`'s -- keeps `provision` itself free of any real device
    /// I/O and therefore testable).
    ovf_env_xml: []const u8,
    now_unix_seconds: i64,
    delete_root_password: bool = true,
    /// `null` skips host key regeneration (used by tests, since it needs a
    /// real `/etc/ssh` and the `ssh-keygen` binary on `PATH`).
    ssh_dir: ?std.Io.Dir = null,
    /// Parsed `/etc/waagent.conf` (or its defaults if the file is absent
    /// -- see `waagent_conf.zig`). Not yet consulted anywhere here; the
    /// `resourcedisk_*` fields exist for #113 to read once implemented.
    /// (Deliberately does not include a `Provisioning.Enabled`-equivalent
    /// gate -- see `waagent_conf.zig`'s doc comment on why honoring that
    /// specific upstream key would be actively harmful here.)
    waagent_conf: waagent_conf.WaagentConf = .{},
};

/// Runs local first-boot provisioning and records its sentinel, independently
/// of Azure WireServer health acknowledgement. Existing sentinels skip only
/// these local account/key/identity mutations; normal invocations still
/// report Ready after this function returns.
pub fn provision(deps: Deps) !void {
    if (try isProvisioned(deps.allocator, deps.var_dir, deps.io)) return;

    const env = try ovf.OvfEnv.parse(deps.ovf_env_xml);

    try hostname.publish(deps.etc_dir, deps.io, env.hostname);

    const user = try passwd.createUserIfMissing(deps.allocator, deps.etc_dir, deps.home_parent_dir, deps.io, env.username, deps.now_unix_seconds);
    defer deps.allocator.free(user.home);

    {
        var home_dir = try deps.home_parent_dir.openDir(deps.io, env.username, .{ .iterate = true });
        defer home_dir.close(deps.io);

        var keys_buf: [ovf.OvfEnv.max_public_keys][]const u8 = undefined;
        var keys_len: usize = 0;
        for (env.publicKeys()) |pk| {
            keys_buf[keys_len] = pk.value;
            keys_len += 1;
        }
        try ssh_keys.deployAuthorizedKeys(deps.allocator, home_dir, deps.io, user.uid, user.gid, keys_buf[0..keys_len]);
    }

    try sudoers.configureSudoer(deps.allocator, deps.etc_dir, deps.io, env.username);

    if (deps.delete_root_password) {
        try passwd.lockRootPasswordInPlace(deps.allocator, deps.etc_dir, deps.io);
    }

    if (deps.ssh_dir) |ssh_dir| {
        try ssh_keys.regenerateHostKeys(deps.allocator, deps.io, ssh_dir);
    }

    try sentinel.writeSentinel(deps.var_dir, deps.io, env.hostname);
}

fn isProvisioned(allocator: std.mem.Allocator, var_dir: std.Io.Dir, io: std.Io) !bool {
    if (try sentinel.readSentinel(allocator, var_dir, io)) |existing| {
        allocator.free(existing);
        return true;
    }
    return false;
}

const ReadyMode = enum {
    azure,
    skip,
};

const Options = struct {
    ready_mode: ReadyMode = .azure,
};

fn parseOption(options: *Options, arg: []const u8) error{InvalidArgument}!void {
    if (std.mem.eql(u8, arg, "--skip-ready")) {
        options.ready_mode = .skip;
    } else {
        return error.InvalidArgument;
    }
}

fn parseOptions(args: []const []const u8) error{InvalidArgument}!Options {
    var options: Options = .{};
    for (args[1..]) |arg| try parseOption(&options, arg);
    return options;
}

const InvocationPlan = struct {
    provision_locally: bool,
    acknowledge_ready: bool,
};

fn invocationPlan(already_provisioned: bool, ready_mode: ReadyMode) InvocationPlan {
    return .{
        .provision_locally = !already_provisioned,
        .acknowledge_ready = ready_mode == .azure,
    };
}

fn reportHealth(allocator: std.mem.Allocator, client: *wireserver.Client) !void {
    const goal_state_xml = try client.fetchGoalState(allocator);
    defer allocator.free(goal_state_xml);
    const gs = try wireserver.GoalState.parse(goal_state_xml);
    try client.reportHealth(allocator, .{
        .incarnation = gs.incarnation,
        .container_id = gs.container_id,
        .role_instance_id = gs.role_instance_id,
        .state = .ready,
    });
}

fn acknowledgeReady(ready_mode: ReadyMode, reporter: anytype) !void {
    if (ready_mode == .azure) try reporter.report();
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    var options: Options = .{};
    for (init.minimal.args.vector[1..]) |arg| {
        const parsed = std.mem.span(arg);
        parseOption(&options, parsed) catch {
            std.debug.print("azagent: unknown argument: {s}\nusage: azagent [--skip-ready]\n", .{parsed});
            std.process.exit(2);
        };
    }

    if (std.os.linux.geteuid() != 0) {
        std.debug.print("azagent: must run as root\n", .{});
        std.process.exit(1);
    }

    var etc_dir = try std.Io.Dir.cwd().openDir(io, "/etc", .{});
    defer etc_dir.close(io);
    var var_dir = try std.Io.Dir.cwd().openDir(io, "/var", .{});
    defer var_dir.close(io);

    const waagent_conf_content = try waagent_conf.readWaagentConf(gpa, etc_dir, io);
    defer if (waagent_conf_content) |c| gpa.free(c);
    const parsed_waagent_conf = if (waagent_conf_content) |c| waagent_conf.WaagentConf.parse(c) else waagent_conf.WaagentConf{};

    const now = std.Io.Clock.real.now(io);
    const now_unix_seconds: i64 = @intCast(@divTrunc(now.nanoseconds, 1_000_000_000));

    const plan = invocationPlan(try isProvisioned(gpa, var_dir, io), options.ready_mode);
    if (plan.provision_locally) {
        const ovf_env_xml = cdrom.readOvfEnv(gpa, io) catch |err| {
            std.debug.print("azagent: failed to read ovf-env.xml from the provisioning media: {t}\n", .{err});
            std.process.exit(1);
        };
        defer gpa.free(ovf_env_xml);

        var home_parent_dir = try std.Io.Dir.cwd().openDir(io, "/home", .{});
        defer home_parent_dir.close(io);
        var ssh_dir = try etc_dir.openDir(io, "ssh", .{ .iterate = true });
        defer ssh_dir.close(io);
        try provision(.{
            .allocator = gpa,
            .io = io,
            .etc_dir = etc_dir,
            .home_parent_dir = home_parent_dir,
            .var_dir = var_dir,
            .ovf_env_xml = ovf_env_xml,
            .now_unix_seconds = now_unix_seconds,
            .ssh_dir = ssh_dir,
            .waagent_conf = parsed_waagent_conf,
        });
    }

    // Unlike `provision` above, disk activation runs on every boot: Azure
    // can reallocate the temporary disk or attach managed data disks across
    // a VM's lifetime. Failures remain best-effort so the OS stays usable.
    driveMountSetupBestEffort(gpa, io, now_unix_seconds, parsed_waagent_conf);

    // Same "every boot, best-effort" reasoning applies to growing the root
    // partition/filesystem (issue #130): the platform can deploy a larger
    // OS disk than the image was built at, and that's a redeploy-time
    // event, not a first-boot-only one. Not gated by any `waagent.conf`
    // toggle either -- real waagent has no growpart-equivalent conf key.
    rootResizeSetupBestEffort(gpa, io);

    if (plan.acknowledge_ready) {
        var client: wireserver.Client = .init(gpa, io);
        defer client.deinit();
        const Reporter = struct {
            allocator: std.mem.Allocator,
            client: *wireserver.Client,

            fn report(self: @This()) !void {
                try reportHealth(self.allocator, self.client);
            }
        };
        try acknowledgeReady(options.ready_mode, Reporter{ .allocator = gpa, .client = &client });
    }
}

/// Best-effort wrapper around `root_resize.setup` -- see its call site in
/// `main` for why failures here are logged rather than fatal.
fn rootResizeSetupBestEffort(allocator: std.mem.Allocator, io: std.Io) void {
    rootResizeSetup(allocator, io) catch |err| {
        std.debug.print("azagent: warning: failed to grow the root partition/filesystem: {t}\n", .{err});
    };
}

fn rootResizeSetup(allocator: std.mem.Allocator, io: std.Io) !void {
    var class_block_dir = try std.Io.Dir.cwd().openDir(io, "/sys/class/block", .{ .iterate = true });
    defer class_block_dir.close(io);

    try root_resize.setup(.{
        .allocator = allocator,
        .io = io,
        .class_block_dir = class_block_dir,
    });
}

fn driveMountSetupBestEffort(allocator: std.mem.Allocator, io: std.Io, now_unix_seconds: i64, conf: waagent_conf.WaagentConf) void {
    driveMountSetup(allocator, io, now_unix_seconds, conf) catch |err| {
        std.debug.print("azagent: warning: failed to enumerate non-OS disks: {t}\n", .{err});
    };
}

/// Resolves `ResourceDisk.Owner` to numeric ids against the live
/// `/etc/passwd`. An unset key means "leave it `root:root`". A set but
/// unknown account is a misconfiguration worth reporting, but not worth
/// failing the whole disk activation over -- the disk still mounts, just
/// root-owned, which is exactly what the default does.
fn resourceDiskOwner(allocator: std.mem.Allocator, io: std.Io, username: []const u8) ?resource_disk.Owner {
    if (username.len == 0) return null;

    const passwd_content = std.Io.Dir.cwd().readFileAlloc(io, "/etc/passwd", allocator, passwd.read_limit) catch |err| {
        std.debug.print("azagent: warning: cannot read /etc/passwd to resolve ResourceDisk.Owner={s}: {t}\n", .{ username, err });
        return null;
    };
    defer allocator.free(passwd_content);

    const ids = passwd.lookupIds(passwd_content, username) catch |err| {
        std.debug.print("azagent: warning: malformed /etc/passwd entry for ResourceDisk.Owner={s}: {t}\n", .{ username, err });
        return null;
    };
    if (ids) |resolved| return .{ .uid = resolved.uid, .gid = resolved.gid };

    std.debug.print("azagent: warning: ResourceDisk.Owner={s} is not an account; leaving the mount point root-owned\n", .{username});
    return null;
}

fn driveMountSetup(allocator: std.mem.Allocator, io: std.Io, now_unix_seconds: i64, conf: waagent_conf.WaagentConf) !void {
    if (!conf.resourcedisk_format and !conf.datadisk_mount) return;
    if (conf.resourcedisk_format and !std.mem.eql(u8, conf.resourcedisk_filesystem, "ext4")) {
        std.debug.print("azagent: warning: ResourceDisk.Filesystem={s} is not supported, using ext4 instead\n", .{conf.resourcedisk_filesystem});
    }

    var devices_dir = try std.Io.Dir.cwd().openDir(io, "/sys/bus/vmbus/devices", .{ .iterate = true });
    defer devices_dir.close(io);
    const resource_name = resource_disk.findResourceDiskName(allocator, devices_dir, io) catch |err| switch (err) {
        error.ResourceDiskNotFound => null,
        else => return err,
    };
    defer if (resource_name) |name| allocator.free(name);

    var class_block_dir = try std.Io.Dir.cwd().openDir(io, "/sys/class/block", .{ .iterate = true });
    defer class_block_dir.close(io);
    const proc_mounts = try root_resize.readProcMounts(allocator);
    defer allocator.free(proc_mounts);
    const root = root_resize.findRootDevice(allocator, io, proc_mounts, class_block_dir) catch |err| root: {
        std.debug.print(
            "azagent: warning: cannot resolve the physical root disk ({t}); managed data disks will not be mounted\n",
            .{err},
        );
        break :root null;
    };
    defer if (root) |device| {
        allocator.free(device.disk_name);
        allocator.free(device.partition_name);
    };

    try drive_mounts.setup(.{
        .allocator = allocator,
        .io = io,
        .class_block_dir = class_block_dir,
        .root_disk_name = if (root) |device| device.disk_name else null,
        .scsi_resource_disk_name = resource_name,
        .now_unix_seconds = now_unix_seconds,
        .resource_enabled = conf.resourcedisk_format,
        .resource_mount_point = conf.resourcedisk_mount_point,
        .resource_owner = resourceDiskOwner(allocator, io, conf.resourcedisk_owner),
        .resource_enable_swap = conf.resourcedisk_enable_swap,
        .resource_swap_size_mb = if (conf.resourcedisk_swap_size_mb > 0) conf.resourcedisk_swap_size_mb else resource_disk.default_swap_size_mb,
        .data_disks_enabled = conf.datadisk_mount and root != null,
    });
}

test {
    _ = ovf;
    _ = hostname;
    _ = passwd;
    _ = sudoers;
    _ = ssh_keys;
    _ = sentinel;
    _ = cdrom;
    _ = waagent_conf;
    _ = resource_disk;
    _ = drive_mounts;
    _ = root_resize;
    _ = validation;
}

test "provision runs the full sequence end to end against scoped temp directories" {
    if (std.os.linux.geteuid() != 0) {
        std.debug.print("skipping provision end-to-end test: not running as root, chown would fail\n", .{});
        return error.SkipZigTest;
    }

    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();

    try tmp.dir.writeFile(io, .{ .sub_path = "passwd", .data = "root:x:0:0::/root:/bin/bash\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "group", .data = "root:x:0:\n" });
    try tmp.dir.writeFile(io, .{ .sub_path = "shadow", .data = "root:$6$abc$def:19000:0:99999:7:::\n" });
    try tmp.dir.createDir(io, "home", .default_dir);
    try tmp.dir.createDir(io, "var", .default_dir);

    var etc_dir = try tmp.dir.openDir(io, ".", .{});
    defer etc_dir.close(io);
    var home_parent_dir = try tmp.dir.openDir(io, "home", .{});
    defer home_parent_dir.close(io);
    var var_dir = try tmp.dir.openDir(io, "var", .{});
    defer var_dir.close(io);

    const ovf_env_xml =
        \\<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1">
        \\  <wa:ProvisioningSection xmlns:wa="http://schemas.microsoft.com/windowsazure">
        \\    <LinuxProvisioningConfigurationSet xmlns="http://schemas.microsoft.com/windowsazure">
        \\      <HostName>test-host</HostName>
        \\      <UserName>azureuser</UserName>
        \\      <DisableSshPasswordAuthentication>true</DisableSshPasswordAuthentication>
        \\      <SSH><PublicKeys><PublicKey><Value>ssh-rsa AAAATEST== a@b</Value></PublicKey></PublicKeys></SSH>
        \\    </LinuxProvisioningConfigurationSet>
        \\  </wa:ProvisioningSection>
        \\</Environment>
    ;

    try provision(.{
        .allocator = allocator,
        .io = io,
        .etc_dir = etc_dir,
        .home_parent_dir = home_parent_dir,
        .var_dir = var_dir,
        .ovf_env_xml = ovf_env_xml,
        .now_unix_seconds = 19700 * 86_400,
    });

    const passwd_after = try tmp.dir.readFileAlloc(io, "passwd", allocator, .limited(4096));
    defer allocator.free(passwd_after);
    try std.testing.expect(std.mem.indexOf(u8, passwd_after, "azureuser:x:1000:1000::/home/azureuser:/bin/bash\n") != null);

    const shadow_after = try tmp.dir.readFileAlloc(io, "shadow", allocator, .limited(4096));
    defer allocator.free(shadow_after);
    try std.testing.expect(std.mem.indexOf(u8, shadow_after, "root:!$6$abc$def:") != null);

    const authorized_keys = try tmp.dir.readFileAlloc(io, "home/azureuser/.ssh/authorized_keys", allocator, .limited(4096));
    defer allocator.free(authorized_keys);
    try std.testing.expectEqualStrings("ssh-rsa AAAATEST== a@b\n", authorized_keys);

    const sudoers_drop_in = try tmp.dir.readFileAlloc(io, "sudoers.d/azagent", allocator, .limited(4096));
    defer allocator.free(sudoers_drop_in);
    try std.testing.expectEqualStrings("azureuser ALL=(ALL) NOPASSWD: ALL\n", sudoers_drop_in);

    const sentinel_content = try tmp.dir.readFileAlloc(io, "var/lib/azagent/provisioned", allocator, .limited(4096));
    defer allocator.free(sentinel_content);
    try std.testing.expectEqualStrings("test-host", sentinel_content);
    try std.testing.expect(try isProvisioned(allocator, var_dir, io));

    // A second call should be a no-op (sentinel present).
    try provision(.{
        .allocator = allocator,
        .io = io,
        .etc_dir = etc_dir,
        .home_parent_dir = home_parent_dir,
        .var_dir = var_dir,
        .ovf_env_xml = ovf_env_xml,
        .now_unix_seconds = 19700 * 86_400,
    });
}

test "options require explicit skip-ready and reject unknown arguments" {
    try std.testing.expectEqual(ReadyMode.azure, (try parseOptions(&.{"azagent"})).ready_mode);
    try std.testing.expectEqual(ReadyMode.skip, (try parseOptions(&.{ "azagent", "--skip-ready" })).ready_mode);
    try std.testing.expectError(error.InvalidArgument, parseOptions(&.{ "azagent", "--offline" }));
}

test "invocation plan separates local provisioning from Ready acknowledgement" {
    try std.testing.expectEqual(InvocationPlan{
        .provision_locally = true,
        .acknowledge_ready = true,
    }, invocationPlan(false, .azure));
    try std.testing.expectEqual(InvocationPlan{
        .provision_locally = false,
        .acknowledge_ready = true,
    }, invocationPlan(true, .azure));
    try std.testing.expectEqual(InvocationPlan{
        .provision_locally = false,
        .acknowledge_ready = false,
    }, invocationPlan(true, .skip));
}

test "Ready acknowledgement is skipped only explicitly and failures remain retriable" {
    const Reporter = struct {
        calls: *usize,
        fail: bool,

        fn report(self: @This()) !void {
            self.calls.* += 1;
            if (self.fail) return error.TransientReadyFailure;
        }
    };

    var calls: usize = 0;
    try acknowledgeReady(.skip, Reporter{ .calls = &calls, .fail = true });
    try std.testing.expectEqual(@as(usize, 0), calls);
    try std.testing.expectError(
        error.TransientReadyFailure,
        acknowledgeReady(.azure, Reporter{ .calls = &calls, .fail = true }),
    );
    try acknowledgeReady(.azure, Reporter{ .calls = &calls, .fail = false });
    try std.testing.expectEqual(@as(usize, 2), calls);
}

test "a local provisioning sentinel makes repeated invocation retry-safe" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    var tmp = std.testing.tmpDir(.{});
    defer tmp.cleanup();
    try tmp.dir.createDir(io, "var", .default_dir);
    var var_dir = try tmp.dir.openDir(io, "var", .{});
    defer var_dir.close(io);

    try sentinel.writeSentinel(var_dir, io, "host");
    try std.testing.expect(try isProvisioned(allocator, var_dir, io));
    const retry = invocationPlan(true, .azure);
    try std.testing.expect(!retry.provision_locally);
    try std.testing.expect(retry.acknowledge_ready);
}
