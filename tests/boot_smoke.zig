//! Opportunistic real-QEMU boot verification for images produced by
//! `miz.build_image.build()`. Skipped gracefully (not failed) whenever
//! `qemu-system-x86_64`, OVMF firmware, or the `MIZ_BOOT_TEST_ISO`/
//! `MIZ_BOOT_TEST_OCI` fixture env vars aren't available, matching the
//! opportunistic-external-tool pattern used elsewhere in this repo.
//!
//! Lives outside `packages/miz` (rather than inside
//! `packages/miz/src/build_image.zig`, where this test used to live)
//! because it needs both `miz` (to actually build an image) and `qmp`
//! (to drive the resulting QEMU process precisely -- see issue #99) --
//! two independent top-level components of this repo's single root
//! `build.zig`, not something either component's own module should
//! depend on for its non-test build.

const std = @import("std");
const Io = std.Io;
const miz = @import("miz");
const qmp = @import("qmp");
const qemu_host = @import("qemu_host");

const qemu_boot_smoke_timeout_seconds: i64 = 120;
const qemu_boot_smoke_serial_limit: usize = 256 * 1024;
const qemu_boot_smoke_disk_size: u64 = 4 * 1024 * miz.azure.one_mib;

pub const OvmfFirmwarePair = qemu_host.FirmwarePair;

const QemuBootSmokePrereqs = struct {
    qemu_path: []u8,
    iso_path: []u8,
    oci_path: []u8,

    fn deinit(self: *QemuBootSmokePrereqs, allocator: std.mem.Allocator) void {
        allocator.free(self.qemu_path);
        allocator.free(self.iso_path);
        allocator.free(self.oci_path);
        self.* = undefined;
    }
};

const IsoOciFixtures = struct {
    iso_path: []u8,
    oci_path: []u8,

    fn deinit(self: *IsoOciFixtures, allocator: std.mem.Allocator) void {
        allocator.free(self.iso_path);
        allocator.free(self.oci_path);
        self.* = undefined;
    }
};

pub const QemuBootSmokeResult = struct {
    timed_out: bool,
    quit_acknowledged: bool,
    serial_output: []u8,

    pub fn deinit(self: *QemuBootSmokeResult, allocator: std.mem.Allocator) void {
        allocator.free(self.serial_output);
        self.* = undefined;
    }
};

fn readOptionalFileAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    path: []const u8,
    limit: usize,
) ![]u8 {
    return Io.Dir.cwd().readFileAlloc(io, path, allocator, .limited(limit)) catch |err| switch (err) {
        error.FileNotFound => allocator.alloc(u8, 0),
        else => return err,
    };
}

fn getOptionalTestEnvPathAlloc(
    allocator: std.mem.Allocator,
    comptime key: []const u8,
) !?[]u8 {
    return std.testing.environ.getAlloc(allocator, key) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
}

fn requireProvisionedBootTestPathAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    comptime key: []const u8,
    what: []const u8,
) ![]u8 {
    const path = try getOptionalTestEnvPathAlloc(allocator, key) orelse {
        std.debug.print(
            "skipping build-image QEMU boot smoke test: set {s} to a real local {s}\n",
            .{ key, what },
        );
        return error.SkipZigTest;
    };
    errdefer allocator.free(path);

    if (!try qemu_host.pathAccessible(io, path, .{ .read = true })) {
        std.debug.print(
            "skipping build-image QEMU boot smoke test: {s} points to an unreadable path: {s}\n",
            .{ key, path },
        );
        return error.SkipZigTest;
    }

    return path;
}

/// Like `requireProvisionedBootTestPathAlloc`, but returns `null` instead of
/// `error.SkipZigTest` when the env var isn't set at all -- for optional
/// fixtures (e.g. a verity-capable container) that most dev/CI setups won't
/// have provisioned, where the calling test should skip just that one case
/// rather than the whole test.
fn optionalProvisionedBootTestPathAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    comptime key: []const u8,
) !?[]u8 {
    const path = try getOptionalTestEnvPathAlloc(allocator, key) orelse return null;
    errdefer allocator.free(path);

    if (!try qemu_host.pathAccessible(io, path, .{ .read = true })) {
        std.debug.print(
            "skipping: {s} points to an unreadable path: {s}\n",
            .{ key, path },
        );
        allocator.free(path);
        return null;
    }

    return path;
}

fn requireOvmfFirmwarePairAlloc(
    allocator: std.mem.Allocator,
    io: Io,
    qemu_path: []const u8,
) !OvmfFirmwarePair {
    const env_code = try getOptionalTestEnvPathAlloc(allocator, "MIZ_BOOT_TEST_OVMF_CODE");
    defer if (env_code) |path| allocator.free(path);
    const env_vars = try getOptionalTestEnvPathAlloc(allocator, "MIZ_BOOT_TEST_OVMF_VARS");
    defer if (env_vars) |path| allocator.free(path);

    if (env_code != null or env_vars != null) {
        if (env_code == null or env_vars == null) {
            std.debug.print(
                "skipping build-image QEMU boot smoke test: set both MIZ_BOOT_TEST_OVMF_CODE and MIZ_BOOT_TEST_OVMF_VARS together\n",
                .{},
            );
            return error.SkipZigTest;
        }

        return qemu_host.findFirmwarePairAlloc(allocator, io, .{
            .explicit_code_path = env_code,
            .explicit_vars_path = env_vars,
            .qemu_path = qemu_path,
        }) catch {
            std.debug.print(
                "skipping build-image QEMU boot smoke test: configured OVMF paths are unreadable ({s}, {s})\n",
                .{ env_code.?, env_vars.? },
            );
            return error.SkipZigTest;
        } orelse return error.SkipZigTest;
    }

    if (try qemu_host.findFirmwarePairAlloc(allocator, io, .{
        .qemu_path = qemu_path,
    })) |pair| return pair;

    std.debug.print(
        "skipping build-image QEMU boot smoke test: OVMF firmware not found; set MIZ_BOOT_TEST_OVMF_CODE and MIZ_BOOT_TEST_OVMF_VARS\n",
        .{},
    );
    return error.SkipZigTest;
}

fn requireIsoOciFixturesAlloc(
    allocator: std.mem.Allocator,
    io: Io,
) !IsoOciFixtures {
    const iso_path = try requireProvisionedBootTestPathAlloc(
        allocator,
        io,
        "MIZ_BOOT_TEST_ISO",
        "bootable ISO fixture",
    );
    errdefer allocator.free(iso_path);

    const oci_path = try requireProvisionedBootTestPathAlloc(
        allocator,
        io,
        "MIZ_BOOT_TEST_OCI",
        "OCI layout fixture",
    );
    errdefer allocator.free(oci_path);

    return .{
        .iso_path = iso_path,
        .oci_path = oci_path,
    };
}

fn requireQemuBootSmokePrereqs(
    allocator: std.mem.Allocator,
    io: Io,
) !QemuBootSmokePrereqs {
    const qemu_path = try qemu_host.findExecutableInPathAlloc(
        allocator,
        io,
        std.testing.environ,
        "qemu-system-x86_64",
    ) orelse {
        std.debug.print(
            "skipping build-image QEMU boot smoke test: qemu-system-x86_64 not found on PATH\n",
            .{},
        );
        return error.SkipZigTest;
    };
    errdefer allocator.free(qemu_path);

    var fixtures = try requireIsoOciFixturesAlloc(allocator, io);
    errdefer fixtures.deinit(allocator);

    return .{
        .qemu_path = qemu_path,
        .iso_path = fixtures.iso_path,
        .oci_path = fixtures.oci_path,
    };
}

fn copyFileToPath(
    allocator: std.mem.Allocator,
    io: Io,
    source_path: []const u8,
    output_path: []const u8,
) !void {
    const bytes = try Io.Dir.cwd().readFileAlloc(io, source_path, allocator, .limited(4 * 1024 * 1024));
    defer allocator.free(bytes);
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = output_path, .data = bytes });
}

/// Polling interval while waiting for the guest to reach the expected serial
/// output or for QEMU to stop running (see `runQemuBootSmoke`).
const qemu_boot_smoke_poll_interval_ms: u64 = 200;

/// Drives a QEMU boot over its QMP control socket (see issue #99): polls the
/// serial log for the expected kernel-boot marker *and* `query-status`
/// (bailing out early if QEMU stops running, e.g. a crash or guest
/// triple-fault) instead of a single blocking call with a fixed timeout, and
/// quits cleanly once the guest reaches the expected serial output.
///
/// `ovmf` is `null` for a Gen1/BIOS boot (SeaBIOS, no `-drive if=pflash`
/// entries at all -- the raw MBR disk's embedded GRUB boots directly); pass
/// a firmware pair (with `ovmf_vars_copy_path` pointing at a *writable copy*
/// of its vars file) for a Gen2/UEFI boot.
pub fn runQemuBootSmoke(
    allocator: std.mem.Allocator,
    io: Io,
    qemu_path: []const u8,
    ovmf: ?struct { firmware: OvmfFirmwarePair, vars_copy_path: []const u8 },
    image_path: []const u8,
    serial_output_path: []const u8,
    extra_wait_marker: ?[]const u8,
) !QemuBootSmokeResult {
    const serial_arg = try std.fmt.allocPrint(allocator, "file:{s}", .{serial_output_path});
    defer allocator.free(serial_arg);
    const image_drive = try std.fmt.allocPrint(
        allocator,
        "file={s},format=raw,if=virtio",
        .{image_path},
    );
    defer allocator.free(image_drive);

    var ovmf_code_drive: ?[]u8 = null;
    defer if (ovmf_code_drive) |d| allocator.free(d);
    var ovmf_vars_drive: ?[]u8 = null;
    defer if (ovmf_vars_drive) |d| allocator.free(d);
    if (ovmf) |firmware_pair| {
        ovmf_code_drive = try std.fmt.allocPrint(
            allocator,
            "if=pflash,format=raw,readonly=on,file={s}",
            .{firmware_pair.firmware.code_path},
        );
        ovmf_vars_drive = try std.fmt.allocPrint(
            allocator,
            "if=pflash,format=raw,file={s}",
            .{firmware_pair.vars_copy_path},
        );
    }

    var args = std.array_list.Managed([]const u8).init(allocator);
    defer args.deinit();
    try args.appendSlice(&.{
        "-M",         "q35",
        "-accel",     "tcg",
        "-m",         "2048",
        "-display",   "none",
        "-no-reboot", "-monitor",
        "none",       "-serial",
        serial_arg,
    });
    if (ovmf_code_drive) |d| try args.appendSlice(&.{ "-drive", d });
    if (ovmf_vars_drive) |d| try args.appendSlice(&.{ "-drive", d });
    try args.appendSlice(&.{ "-drive", image_drive });

    var spawned = try qmp.spawnAndConnect(allocator, io, .{
        .binary = qemu_path,
        .extra_args = args.items,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer spawned.deinit();

    return awaitQemuBoot(allocator, io, &spawned, serial_output_path, extra_wait_marker);
}

/// Polls an already-spawned QEMU (over QMP) until the guest reaches the
/// expected kernel-boot marker (and `extra_wait_marker`, if any) or QEMU
/// stops running, then quits it cleanly. Shared by the disk and ISO runners.
fn awaitQemuBoot(
    allocator: std.mem.Allocator,
    io: Io,
    spawned: anytype,
    serial_output_path: []const u8,
    extra_wait_marker: ?[]const u8,
) !QemuBootSmokeResult {
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(qemu_boot_smoke_timeout_seconds));
    var timed_out = true;

    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        const serial_output = try readOptionalFileAlloc(allocator, io, serial_output_path, qemu_boot_smoke_serial_limit);
        // The kernel starting to boot is enough for most callers, but a few
        // (e.g. the --verity real-boot test) need to keep polling until a
        // later milestone shows up too -- otherwise this would quit QEMU
        // the instant the kernel starts printing, long before systemd/
        // dm-verity ever run.
        const reached_boot = serialOutputShowsKernelBoot(serial_output) and
            (extra_wait_marker == null or std.mem.indexOf(u8, serial_output, extra_wait_marker.?) != null);
        allocator.free(serial_output);

        if (reached_boot) {
            timed_out = false;
            break;
        }

        // Bail out early (rather than waiting out the full timeout) if QEMU
        // has already stopped running, e.g. a crash or guest triple-fault.
        const still_running = blk: {
            var status = qmp.qapi.queryStatus(spawned.client, allocator) catch break :blk false;
            defer status.deinit();
            break :blk status.value.running;
        };
        if (!still_running) break;

        try Io.sleep(io, .fromMilliseconds(qemu_boot_smoke_poll_interval_ms), .awake);
    }

    var quit_acknowledged = false;
    if (!timed_out) {
        // Ask QEMU to exit cleanly. Tolerate the reply read racing the
        // connection closing (a known caveat documented in qmp/README.md's
        // "quit" notes) as long as the process actually exits below.
        if (spawned.client.execute("quit", null)) |reply| {
            reply.deinit();
            quit_acknowledged = true;
        } else |_| {}
        _ = spawned.wait() catch {};
    } else {
        spawned.kill();
    }

    const serial_output = try readOptionalFileAlloc(
        allocator,
        io,
        serial_output_path,
        qemu_boot_smoke_serial_limit,
    );
    errdefer allocator.free(serial_output);

    return .{
        .timed_out = timed_out,
        .quit_acknowledged = quit_acknowledged,
        .serial_output = serial_output,
    };
}

/// Boots a generated ISO as a UEFI CD-ROM under OVMF, using the same QMP-driven
/// poll as `runQemuBootSmoke`. Requires an OVMF firmware pair (an ISO is booted
/// through UEFI El Torito here).
pub fn runQemuIsoBootSmoke(
    allocator: std.mem.Allocator,
    io: Io,
    qemu_path: []const u8,
    ovmf: struct { firmware: OvmfFirmwarePair, vars_copy_path: []const u8 },
    iso_path: []const u8,
    serial_output_path: []const u8,
    extra_wait_marker: ?[]const u8,
) !QemuBootSmokeResult {
    const serial_arg = try std.fmt.allocPrint(allocator, "file:{s}", .{serial_output_path});
    defer allocator.free(serial_arg);
    const cdrom_drive = try std.fmt.allocPrint(
        allocator,
        "file={s},format=raw,if=none,media=cdrom,id=live-cd",
        .{iso_path},
    );
    defer allocator.free(cdrom_drive);
    const ovmf_code_drive = try std.fmt.allocPrint(
        allocator,
        "if=pflash,format=raw,readonly=on,file={s}",
        .{ovmf.firmware.code_path},
    );
    defer allocator.free(ovmf_code_drive);
    const ovmf_vars_drive = try std.fmt.allocPrint(
        allocator,
        "if=pflash,format=raw,file={s}",
        .{ovmf.vars_copy_path},
    );
    defer allocator.free(ovmf_vars_drive);

    var args = std.array_list.Managed([]const u8).init(allocator);
    defer args.deinit();
    try args.appendSlice(&.{
        "-M",                               "q35",
        "-accel",                           "tcg",
        "-m",                               "2048",
        "-display",                         "none",
        "-no-reboot",                       "-monitor",
        "none",                             "-serial",
        serial_arg,                         "-drive",
        ovmf_code_drive,                    "-drive",
        ovmf_vars_drive,                    "-drive",
        cdrom_drive,                        "-device",
        "ide-cd,drive=live-cd,bootindex=0",
    });

    var spawned = try qmp.spawnAndConnect(allocator, io, .{
        .binary = qemu_path,
        .extra_args = args.items,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    defer spawned.deinit();

    return awaitQemuBoot(allocator, io, &spawned, serial_output_path, extra_wait_marker);
}

fn serialOutputShowsKernelBoot(serial_output: []const u8) bool {
    return std.mem.indexOf(u8, serial_output, "Linux version ") != null or
        std.mem.indexOf(u8, serial_output, "Kernel command line:") != null;
}

test "build-image boot-smokes typed customization and generalization under Gen2 QEMU" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var prereqs = try requireQemuBootSmokePrereqs(allocator, io);
    defer prereqs.deinit(allocator);
    var ovmf = try requireOvmfFirmwarePairAlloc(allocator, io, prereqs.qemu_path);
    defer ovmf.deinit(allocator);

    const output_path = "test-build-image-qemu-gen2.raw";
    const ovmf_vars_copy_path = "test-build-image-qemu-gen2.OVMF_VARS.fd";
    const serial_output_path = "test-build-image-qemu-gen2.serial.log";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, ovmf_vars_copy_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, serial_output_path) catch {};

    const service_name = "miz-customization-smoke.service";
    const smoke_script =
        \\#!/bin/sh
        \\set -eu
        \\test "$(cat /etc/hostname)" = "miz-customized"
        \\grep -q '^miz-smoke:' /etc/passwd
        \\grep -q 'ssh-ed25519 AAAATEST miz-smoke' /home/miz-smoke/.ssh/authorized_keys
        \\test ! -e /var/lib/azagent/captured
        \\printf 'MIZ customization verified\n' >/dev/ttyS0
        \\
    ;
    const service_unit =
        \\[Unit]
        \\Description=Verify miz typed image customization
        \\After=local-fs.target
        \\
        \\[Service]
        \\Type=oneshot
        \\ExecStart=/usr/local/sbin/miz-customization-smoke
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    ;
    const filesystem = [_]miz.os_customization.FilesystemOperation{
        .{ .put_file = .{
            .path = "/usr/local/sbin/miz-customization-smoke",
            .source = .{ .inline_bytes = smoke_script },
            .metadata = .{ .mode = 0o755 },
        } },
        .{ .put_file = .{
            .path = "/usr/lib/systemd/system/" ++ service_name,
            .source = .{ .inline_bytes = service_unit },
        } },
        .{ .put_file = .{
            .path = "/var/lib/azagent/captured",
            .source = .{ .inline_bytes = "remove-me" },
        } },
    };
    const users = [_]miz.os_customization.User{.{
        .name = "miz-smoke",
        .ssh_authorized_keys = &.{"ssh-ed25519 AAAATEST miz-smoke"},
    }};
    const services = [_]miz.os_customization.Service{.{
        .name = service_name,
        .state = .enabled,
    }};
    var report = try miz.build_image.build(allocator, io, .{
        .iso_path = prereqs.iso_path,
        .container_path = prereqs.oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = qemu_boot_smoke_disk_size,
        .extra_kernel_options = "console=tty0 console=ttyS0,115200n8 selinux=0",
        .os = .{
            .filesystem = &filesystem,
            .hostname = "miz-customized",
            .users = &users,
            .services = &services,
        },
        .generalization = .{ .azure = .{ .reset_hostname = false } },
    });
    defer report.deinit(allocator);

    try copyFileToPath(allocator, io, ovmf.vars_path, ovmf_vars_copy_path);

    var qemu = try runQemuBootSmoke(
        allocator,
        io,
        prereqs.qemu_path,
        .{ .firmware = ovmf, .vars_copy_path = ovmf_vars_copy_path },
        output_path,
        serial_output_path,
        "MIZ customization verified",
    );
    defer qemu.deinit(allocator);

    if (!serialOutputShowsKernelBoot(qemu.serial_output) or
        std.mem.indexOf(u8, qemu.serial_output, "MIZ customization verified") == null)
    {
        std.debug.print(
            "QEMU customization boot smoke did not reach its marker (timed_out={}, quit_acknowledged={})\nserial output:\n{s}\n",
            .{ qemu.timed_out, qemu.quit_acknowledged, qemu.serial_output },
        );
    }
    try std.testing.expect(serialOutputShowsKernelBoot(qemu.serial_output));
    try std.testing.expect(std.mem.indexOf(u8, qemu.serial_output, "MIZ customization verified") != null);
}

test "native-edit boot-smokes a kernel argument appended to an already-built image" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var prereqs = try requireQemuBootSmokePrereqs(allocator, io);
    defer prereqs.deinit(allocator);
    var ovmf = try requireOvmfFirmwarePairAlloc(allocator, io, prereqs.qemu_path);
    defer ovmf.deinit(allocator);

    const base_path = "test-kernel-options-qemu-base.raw";
    const workspace_path = "test-kernel-options-qemu-work";
    const output_path = workspace_path ++ "/output.raw";
    const ovmf_vars_copy_path = "test-kernel-options-qemu.OVMF_VARS.fd";
    const serial_output_path = "test-kernel-options-qemu.serial.log";
    defer Io.Dir.cwd().deleteFile(io, base_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, ovmf_vars_copy_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, serial_output_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    // The image is built without the argument, so reaching the marker can only
    // mean the preserved-image edit put it on the command line afterwards.
    const service_name = "miz-kernel-options-smoke.service";
    const smoke_script =
        \\#!/bin/sh
        \\set -eu
        \\grep -q 'miz.smoke=applied' /proc/cmdline
        \\printf 'MIZ kernel option verified\n' >/dev/ttyS0
        \\
    ;
    const service_unit =
        \\[Unit]
        \\Description=Verify a miz kernel-argument change
        \\After=local-fs.target
        \\
        \\[Service]
        \\Type=oneshot
        \\ExecStart=/usr/local/sbin/miz-kernel-options-smoke
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    ;
    const filesystem = [_]miz.os_customization.FilesystemOperation{
        .{ .put_file = .{
            .path = "/usr/local/sbin/miz-kernel-options-smoke",
            .source = .{ .inline_bytes = smoke_script },
            .metadata = .{ .mode = 0o755 },
        } },
        .{ .put_file = .{
            .path = "/usr/lib/systemd/system/" ++ service_name,
            .source = .{ .inline_bytes = service_unit },
        } },
    };
    const services = [_]miz.os_customization.Service{.{
        .name = service_name,
        .state = .enabled,
    }};
    var build_report = try miz.build_image.build(allocator, io, .{
        .iso_path = prereqs.iso_path,
        .container_path = prereqs.oci_path,
        .output_path = base_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = qemu_boot_smoke_disk_size,
        .extra_kernel_options = "console=tty0 console=ttyS0,115200n8 selinux=0",
        .os = .{
            .filesystem = &filesystem,
            .services = &services,
        },
    });
    defer build_report.deinit(allocator);

    var request = miz.customize.Request{
        .target_architecture = .x86_64,
        .input = .{ .disk = .{ .path = base_path } },
        .output = .{
            .path = output_path,
            .format = .raw,
            .size_policy = .preserve_source,
        },
        .storage = .{ .preserve = .{ .root_partition = .{ .gpt_index = 2 } } },
        .execution = .{
            .workspace_path = workspace_path,
            .backend = .native_edit,
        },
        .boot_security = .{ .extra_kernel_options = "miz.smoke=applied" },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x5B} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
    var resolved = try miz.customize.resolve(
        allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(allocator);
    try std.testing.expect(!resolved.diagnostics.hasErrors());

    var outcome = try miz.customize.execute(
        allocator,
        io,
        &resolved.plan.?,
        miz.customize.Platform.system(),
        null,
    );
    defer outcome.deinit(allocator);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    const kernel_options = outcome.result.?.provenance.execution.preserved.?.kernel_options.?;
    try std.testing.expect(kernel_options.files_rewritten > 0);

    try copyFileToPath(allocator, io, ovmf.vars_path, ovmf_vars_copy_path);

    var qemu = try runQemuBootSmoke(
        allocator,
        io,
        prereqs.qemu_path,
        .{ .firmware = ovmf, .vars_copy_path = ovmf_vars_copy_path },
        output_path,
        serial_output_path,
        "MIZ kernel option verified",
    );
    defer qemu.deinit(allocator);

    if (!serialOutputShowsKernelBoot(qemu.serial_output) or
        std.mem.indexOf(u8, qemu.serial_output, "MIZ kernel option verified") == null)
    {
        std.debug.print(
            "QEMU kernel-option boot smoke did not reach its marker (timed_out={}, quit_acknowledged={})\nserial output:\n{s}\n",
            .{ qemu.timed_out, qemu.quit_acknowledged, qemu.serial_output },
        );
    }
    try std.testing.expect(serialOutputShowsKernelBoot(qemu.serial_output));
    try std.testing.expect(std.mem.indexOf(u8, qemu.serial_output, "MIZ kernel option verified") != null);
}

test "build-image opportunistically boot-smokes a provisioned Gen1 BIOS raw image under QEMU" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var prereqs = try requireQemuBootSmokePrereqs(allocator, io);
    defer prereqs.deinit(allocator);

    const output_path = "test-build-image-qemu-gen1.raw";
    const serial_output_path = "test-build-image-qemu-gen1.serial.log";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, serial_output_path) catch {};

    // Gen1/BIOS: MBR-partitioned, GRUB embedded in the post-MBR gap. No OVMF
    // needed -- QEMU's built-in SeaBIOS boots the raw disk's embedded GRUB
    // directly (see PR #82/#83 for the structural coverage this complements).
    var report = try miz.build_image.build(allocator, io, .{
        .iso_path = prereqs.iso_path,
        .container_path = prereqs.oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen1,
        .size = qemu_boot_smoke_disk_size,
        .extra_kernel_options = "console=tty0 console=ttyS0,115200n8",
    });
    defer report.deinit(allocator);

    var qemu = try runQemuBootSmoke(
        allocator,
        io,
        prereqs.qemu_path,
        null,
        output_path,
        serial_output_path,
        null,
    );
    defer qemu.deinit(allocator);

    if (!serialOutputShowsKernelBoot(qemu.serial_output)) {
        std.debug.print(
            "Gen1 QEMU boot smoke test did not reach kernel serial output (timed_out={}, quit_acknowledged={})\nserial output:\n{s}\n",
            .{ qemu.timed_out, qemu.quit_acknowledged, qemu.serial_output },
        );
    }
    try std.testing.expect(serialOutputShowsKernelBoot(qemu.serial_output));
}

test "build-image --boot-mode uki fails fast against a provisioned real ISO/OCI lacking a systemd EFI stub" {
    // Like --verity (see the test below), stock installer media -- including
    // the real Azure Linux 4.0 ISO this repo's own boot-smoke fixtures use --
    // typically doesn't ship the systemd-boot-unsigned package (or
    // equivalent) that provides the systemd EFI stub UKI generation needs,
    // so `build-image --boot-mode uki` fails fast with
    // `error.MissingUkiStub` against such media rather than silently
    // producing a broken image. No QEMU needed.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fixtures = try requireIsoOciFixturesAlloc(allocator, io);
    defer fixtures.deinit(allocator);

    const output_path = "test-build-image-uki-real-media.raw";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    try std.testing.expectError(error.MissingUkiStub, miz.build_image.build(allocator, io, .{
        .iso_path = fixtures.iso_path,
        .container_path = fixtures.oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .esp_size = 512 * miz.azure.one_mib,
        .size = qemu_boot_smoke_disk_size + 512 * miz.azure.one_mib,
        .boot_mode = .uki_only,
    }));
}

test "build-image --boot-mode uki opportunistically boot-smokes a provisioned stub-providing container under QEMU" {
    // Like the --verity positive case below, this needs an *extra*,
    // separately-provisioned fixture beyond the base ISO/OCI: a container
    // that adds a systemd EFI stub (e.g. linuxx64.efi.stub from the
    // systemd-boot-unsigned package) into the merged source tree. Skips
    // (not fails) when MIZ_BOOT_TEST_UKI_OCI isn't set.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var prereqs = try requireQemuBootSmokePrereqs(allocator, io);
    defer prereqs.deinit(allocator);
    var ovmf = try requireOvmfFirmwarePairAlloc(allocator, io, prereqs.qemu_path);
    defer ovmf.deinit(allocator);

    const uki_oci_path = try optionalProvisionedBootTestPathAlloc(allocator, io, "MIZ_BOOT_TEST_UKI_OCI") orelse {
        std.debug.print(
            "skipping build-image --boot-mode uki QEMU boot smoke test: set MIZ_BOOT_TEST_UKI_OCI to an OCI layout providing a systemd EFI stub\n",
            .{},
        );
        return error.SkipZigTest;
    };
    defer allocator.free(uki_oci_path);

    const output_path = "test-build-image-qemu-uki.raw";
    const ovmf_vars_copy_path = "test-build-image-qemu-uki.OVMF_VARS.fd";
    const serial_output_path = "test-build-image-qemu-uki.serial.log";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, ovmf_vars_copy_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, serial_output_path) catch {};

    var report = try miz.build_image.build(allocator, io, .{
        .iso_path = prereqs.iso_path,
        .container_path = uki_oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        // UKI mode stores the kernel/initrd inside the EFI binary itself, so
        // it needs a bigger ESP than BLS/GRUB mode -- see the UKI guidance
        // in doc/image-building.md.
        .esp_size = 512 * miz.azure.one_mib,
        .size = qemu_boot_smoke_disk_size + 512 * miz.azure.one_mib,
        .boot_mode = .uki_only,
        .extra_kernel_options = "console=tty0 console=ttyS0,115200n8",
    });
    defer report.deinit(allocator);

    try copyFileToPath(allocator, io, ovmf.vars_path, ovmf_vars_copy_path);

    var qemu = try runQemuBootSmoke(
        allocator,
        io,
        prereqs.qemu_path,
        .{ .firmware = ovmf, .vars_copy_path = ovmf_vars_copy_path },
        output_path,
        serial_output_path,
        null,
    );
    defer qemu.deinit(allocator);

    if (!serialOutputShowsKernelBoot(qemu.serial_output)) {
        std.debug.print(
            "UKI QEMU boot smoke test did not reach kernel serial output (timed_out={}, quit_acknowledged={})\nserial output:\n{s}\n",
            .{ qemu.timed_out, qemu.quit_acknowledged, qemu.serial_output },
        );
    }
    try std.testing.expect(serialOutputShowsKernelBoot(qemu.serial_output));
}

test "build-image --verity fails fast against a provisioned real ISO/OCI whose initramfs lacks verity tooling" {
    // Regression coverage for issue #77/#91: stock installer media
    // (including the real Azure Linux 4.0 ISO this repo's own boot-smoke
    // fixtures use) ships an initramfs built for the *installer*
    // environment, which has no need for -- and so typically lacks --
    // dm-verity userspace tooling. `build-image --verity` should fail fast
    // with `error.InitramfsMissingVerityTooling` against such media instead
    // of silently producing an image that hangs at boot. No QEMU needed:
    // this only exercises `miz.build_image.build()` itself.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var fixtures = try requireIsoOciFixturesAlloc(allocator, io);
    defer fixtures.deinit(allocator);

    const output_path = "test-build-image-verity-real-media.raw";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};

    try std.testing.expectError(error.InitramfsMissingVerityTooling, miz.build_image.build(allocator, io, .{
        .iso_path = fixtures.iso_path,
        .container_path = fixtures.oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = qemu_boot_smoke_disk_size,
        .verity = true,
    }));
}

test "build-image --verity opportunistically boot-smokes a provisioned verity-capable container under QEMU" {
    // Unlike the other tests in this file, this one needs an *extra*,
    // separately-provisioned fixture: an OCI container that overlays a
    // regenerated initramfs (built with e.g. `dracut --add veritysetup`)
    // at the same boot/initramfs-<kver>.img path the base ISO/squashfs
    // rootfs uses -- see "Producing a verity-capable initramfs" in
    // doc/image-building.md. Most dev/CI setups won't have this provisioned,
    // so this skips (not fails) when MIZ_BOOT_TEST_VERITY_OCI isn't set,
    // on top of the usual QEMU/OVMF/ISO prerequisites.
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    var prereqs = try requireQemuBootSmokePrereqs(allocator, io);
    defer prereqs.deinit(allocator);
    var ovmf = try requireOvmfFirmwarePairAlloc(allocator, io, prereqs.qemu_path);
    defer ovmf.deinit(allocator);

    const verity_oci_path = try optionalProvisionedBootTestPathAlloc(allocator, io, "MIZ_BOOT_TEST_VERITY_OCI") orelse {
        std.debug.print(
            "skipping build-image --verity QEMU boot smoke test: set MIZ_BOOT_TEST_VERITY_OCI to an OCI layout overlaying a verity-capable initramfs\n",
            .{},
        );
        return error.SkipZigTest;
    };
    defer allocator.free(verity_oci_path);

    const output_path = "test-build-image-qemu-verity.raw";
    const ovmf_vars_copy_path = "test-build-image-qemu-verity.OVMF_VARS.fd";
    const serial_output_path = "test-build-image-qemu-verity.serial.log";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, ovmf_vars_copy_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, serial_output_path) catch {};

    var report = try miz.build_image.build(allocator, io, .{
        .iso_path = prereqs.iso_path,
        .container_path = verity_oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        // The --force-drivers-regenerated verity-capable initramfs (see
        // scripts/ci/build-verity-initramfs-fixture.sh) is a bit bigger
        // than the stock one (it force-includes virtio storage + dm-verity
        // driver modules dracut's hostonly detection would otherwise miss,
        // seeing the CI runner's own hardware instead of the eventual QEMU
        // boot-smoke guest's). The default 96 MiB ESP has margin to spare
        // but this keeps it comfortably sized regardless.
        .esp_size = 512 * miz.azure.one_mib,
        .size = qemu_boot_smoke_disk_size + 512 * miz.azure.one_mib,
        .verity = true,
        .extra_kernel_options = "console=tty0 console=ttyS0,115200n8",
    });
    defer report.deinit(allocator);

    try copyFileToPath(allocator, io, ovmf.vars_path, ovmf_vars_copy_path);

    var qemu = try runQemuBootSmoke(
        allocator,
        io,
        prereqs.qemu_path,
        .{ .firmware = ovmf, .vars_copy_path = ovmf_vars_copy_path },
        output_path,
        serial_output_path,
        "Local Verity Protected Volumes",
    );
    defer qemu.deinit(allocator);

    // Reaching veritysetup.target (systemd's confirmation that the
    // dm-verity root device was set up and mounted -- see the real boot log
    // captured investigating #77; a kernel-boot-only check wouldn't
    // distinguish a hung/corrupted verity mount from success) is checked via
    // its unit description, "Local Verity Protected Volumes", rather than
    // the unit name itself, for two reasons: systemd's colorized
    // interactive status line renders the name as e.g. "Reached target
    // \x1b[0;1;39mveritysetup.target\x1b[0m - Local Verity Protected
    // Volumes.", with an ANSI escape sequence splitting "target" from
    // "veritysetup.target" so "Reached target veritysetup.target" never
    // appears as one contiguous substring; and plain "veritysetup.target"
    // alone would false-positive on the unrelated, always-reached
    // "remote-veritysetup.target" ("Remote Verity Protected Volumes"),
    // which is wanted by initrd-root-device.target regardless of whether
    // this image actually uses local dm-verity.
    const reached_verity_target = std.mem.indexOf(u8, qemu.serial_output, "Local Verity Protected Volumes") != null;
    if (!reached_verity_target) {
        std.debug.print(
            "--verity QEMU boot smoke test did not reach veritysetup.target (timed_out={}, quit_acknowledged={})\nserial output:\n{s}\n",
            .{ qemu.timed_out, qemu.quit_acknowledged, qemu.serial_output },
        );
    }
    try std.testing.expect(reached_verity_target);
}

test "build-iso opportunistically boot-smokes a regenerated LiveOS ISO as a UEFI CD-ROM under QEMU" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;

    const skip = try getOptionalTestEnvPathAlloc(
        allocator,
        "MIZ_BOOT_TEST_SKIP_BUILD_ISO",
    );
    defer if (skip) |value| allocator.free(value);
    if (skip != null) {
        std.debug.print(
            "skipping build-iso QEMU boot smoke test: MIZ_BOOT_TEST_SKIP_BUILD_ISO is set\n",
            .{},
        );
        return error.SkipZigTest;
    }

    // Gated on the same real fixtures as the build-image boot smokes plus
    // OVMF; skips cleanly (never fails) whenever qemu, OVMF, or the
    // MIZ_BOOT_TEST_ISO/MIZ_BOOT_TEST_OCI fixtures are unavailable. An ISO
    // is booted through UEFI El Torito here, so OVMF is required.
    var prereqs = try requireQemuBootSmokePrereqs(allocator, io);
    defer prereqs.deinit(allocator);
    var ovmf = try requireOvmfFirmwarePairAlloc(allocator, io, prereqs.qemu_path);
    defer ovmf.deinit(allocator);

    const output_path = "test-build-iso-qemu.iso";
    const ovmf_vars_copy_path = "test-build-iso-qemu.OVMF_VARS.fd";
    const serial_output_path = "test-build-iso-qemu.serial.log";
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, ovmf_vars_copy_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, serial_output_path) catch {};

    var report = try miz.build_iso.build(allocator, io, .{
        .iso_path = prereqs.iso_path,
        .container_path = prereqs.oci_path,
        .output_path = output_path,
        // Generous, since the fixture is a real LiveOS rootfs; a developer
        // supplying fixtures can size this from a --dry-run if it is too small.
        .rootfs_size = qemu_boot_smoke_disk_size,
    });
    defer report.deinit(allocator);

    try copyFileToPath(allocator, io, ovmf.vars_path, ovmf_vars_copy_path);

    var qemu = try runQemuIsoBootSmoke(
        allocator,
        io,
        prereqs.qemu_path,
        .{ .firmware = ovmf, .vars_copy_path = ovmf_vars_copy_path },
        output_path,
        serial_output_path,
        null,
    );
    defer qemu.deinit(allocator);

    if (!serialOutputShowsKernelBoot(qemu.serial_output)) {
        std.debug.print(
            "build-iso QEMU boot smoke did not reach kernel boot (timed_out={}, quit_acknowledged={})\nserial output:\n{s}\n",
            .{ qemu.timed_out, qemu.quit_acknowledged, qemu.serial_output },
        );
    }
    // A structural pipeline cannot honestly assert a full userspace boot; this
    // only claims the regenerated ISO's boot chain reaches the kernel, which is
    // the strongest claim a CD-ROM boot smoke can make without guest agents.
    try std.testing.expect(serialOutputShowsKernelBoot(qemu.serial_output));
}
