const std = @import("std");
const builtin = @import("builtin");
const qemu_host = @import("qemu_host");
const boot_smoke = @import("boot_smoke.zig");
const miz = @import("miz");

const Io = std.Io;
const Allocator = std.mem.Allocator;
const disk_size: u64 = 4 * 1024 * miz.azure.one_mib;
const smoke_marker = "MIZ real package customization verified";

const Config = struct {
    iso_path: []const u8,
    oci_path: []const u8,
    qemu_path: []const u8,
    ovmf_code_path: []const u8,
    ovmf_vars_path: []const u8,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(allocator);
    if (argv.len == 3 and std.mem.eql(u8, argv[1], "--unsafe-chroot-worker")) {
        return miz.unsafe_chroot.workerMain(init, argv[2]);
    }
    if (builtin.os.tag != .linux or builtin.cpu.arch != .x86_64) {
        std.debug.print(
            "skipping real unsafe-chroot boot integration: Linux x86_64 is required\n",
            .{},
        );
        return;
    }

    if (parsePrivilegedConfig(argv)) |config| {
        if (std.os.linux.geteuid() != 0) return error.PrivilegedModeRequiresRoot;
        return runIntegration(allocator, init.io, argv[0], config);
    }

    const requested = if (init.environ_map.get("MIZ_RUN_REAL_PACKAGE_BOOT")) |value|
        std.mem.eql(u8, value, "1")
    else
        false;
    if (!requested) {
        std.debug.print(
            "skipping real unsafe-chroot boot integration: set MIZ_RUN_REAL_PACKAGE_BOOT=1 to opt in\n",
            .{},
        );
        return;
    }

    const iso_path = init.environ_map.get("MIZ_BOOT_TEST_ISO") orelse
        return error.MissingIsoFixture;
    const oci_path = init.environ_map.get("MIZ_BOOT_TEST_OCI") orelse
        return error.MissingOciFixture;
    const qemu_path = try qemu_host.findExecutableInPathAlloc(
        allocator,
        init.io,
        init.minimal.environ,
        "qemu-system-x86_64",
    ) orelse return error.QemuUnavailable;
    const firmware = try qemu_host.findFirmwarePairAlloc(allocator, init.io, .{
        .explicit_code_path = init.environ_map.get("MIZ_BOOT_TEST_OVMF_CODE"),
        .explicit_vars_path = init.environ_map.get("MIZ_BOOT_TEST_OVMF_VARS"),
        .qemu_path = qemu_path,
    }) orelse return error.OvmfUnavailable;
    const config = Config{
        .iso_path = iso_path,
        .oci_path = oci_path,
        .qemu_path = qemu_path,
        .ovmf_code_path = firmware.code_path,
        .ovmf_vars_path = firmware.vars_path,
    };
    if (std.os.linux.geteuid() != 0) {
        return reexecWithSudo(allocator, init.io, argv[0], config);
    }
    try runIntegration(allocator, init.io, argv[0], config);
}

fn parsePrivilegedConfig(argv: []const []const u8) ?Config {
    if (argv.len == 7 and
        std.mem.eql(u8, argv[1], "--privileged"))
    {
        return .{
            .iso_path = argv[2],
            .oci_path = argv[3],
            .qemu_path = argv[4],
            .ovmf_code_path = argv[5],
            .ovmf_vars_path = argv[6],
        };
    }
    return null;
}

fn reexecWithSudo(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    config: Config,
) !void {
    const sudo = if (isExecutable(io, "/usr/bin/sudo"))
        "/usr/bin/sudo"
    else if (isExecutable(io, "/bin/sudo"))
        "/bin/sudo"
    else
        return error.SudoUnavailable;
    var argv = std.array_list.Managed([]const u8).init(allocator);
    defer argv.deinit();
    try argv.appendSlice(&.{
        sudo,
        "-n",
        self_exe,
        "--privileged",
        config.iso_path,
        config.oci_path,
        config.qemu_path,
        config.ovmf_code_path,
        config.ovmf_vars_path,
    });
    var child = try std.process.spawn(io, .{
        .argv = argv.items,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    });
    const term = try child.wait(io);
    switch (term) {
        .exited => |code| if (code != 0) return error.PrivilegedTestFailed,
        else => return error.PrivilegedTestFailed,
    }
}

fn runIntegration(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    config: Config,
) !void {
    if (miz.unsafe_chroot.available(io) != .available) {
        return error.UnsafeChrootHostUnavailable;
    }

    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    const work_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/miz-real-package-boot-{s}",
        .{&random_hex},
    );
    try Io.Dir.cwd().createDir(io, work_path, .default_dir);
    var completed = false;
    defer if (!completed) {
        std.debug.print(
            "real package boot integration retained failed workspace: {s}\n",
            .{work_path},
        );
    };

    const built_source_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "source.raw" },
    );
    const source_path = built_source_path;
    const root_offset = try buildSourceImage(
        allocator,
        io,
        config.iso_path,
        config.oci_path,
        source_path,
    );
    const output_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "customized.raw" },
    );
    const serial_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "serial.log" },
    );
    const vars_copy_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "OVMF_VARS.fd" },
    );

    const kernel = try findKernelRelease(allocator, io, source_path, root_offset);
    try ensureGuestPath(
        io,
        allocator,
        source_path,
        root_offset,
        "usr/lib/systemd/system/miz-real-package-smoke.service",
    );
    try ensureGuestPath(
        io,
        allocator,
        source_path,
        root_offset,
        "etc/systemd/system/multi-user.target.wants/miz-real-package-smoke.service",
    );
    const initramfs_path = try std.fmt.allocPrint(
        allocator,
        "boot/initramfs-{s}.img",
        .{kernel},
    );
    const trust = try readGuestFile(
        allocator,
        io,
        source_path,
        root_offset,
        "etc/pki/rpm-gpg/RPM-GPG-KEY-azurelinux-4.0-primary",
    );
    const source_digest = try miz.customize.hashSourcePath(
        allocator,
        io,
        source_path,
    );

    const actions = [_]miz.customize.PackageAction{
        .{ .install = &.{"nano"} },
    };
    // The hook writes what it can see rather than a fixed marker, so the file
    // it leaves behind states which phase it ran in and whether the package
    // actions had already happened -- an ordering claim a passing fake cannot
    // make on a real root.
    const after_packages_script =
        \\#!/bin/sh
        \\set -e
        \\test -x /usr/bin/nano
        \\echo "$1" > /etc/miz-hook-after-packages
        \\
    ;
    const finalize_script =
        \\#!/bin/sh
        \\set -e
        \\test -f /etc/miz-hook-after-packages
        \\ls /run/miz-hook-* > /etc/miz-hook-leftovers 2>/dev/null || true
        \\echo finalize > /etc/miz-hook-finalize
        \\
    ;
    const hooks = [_]miz.customize.Hook{
        .{
            .name = "after-packages",
            .phase = .after_packages,
            .source = .{ .inline_script = after_packages_script },
            .arguments = &.{"argument-reached-the-hook"},
        },
        .{
            .name = "finalize",
            .phase = .finalize,
            .source = .{ .inline_script = finalize_script },
        },
    };
    var after_packages_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(
        after_packages_script,
        &after_packages_digest,
        .{},
    );
    const repositories = [_]miz.customize.PackageRepository{.{
        .id = "azurelinux-base",
        .urls = &.{
            "https://packages.microsoft.com/azurelinux/4.0/beta/base/x86_64",
        },
        .trust = &.{.{ .inline_bytes = trust }},
    }};
    const request = miz.customize.Request{
        .target_architecture = .x86_64,
        .input = .{ .disk = .{ .path = source_path } },
        .output = .{
            .path = output_path,
            .format = .raw,
            .size_policy = .preserve_source,
        },
        .storage = .{ .preserve = .{
            .root_partition = .{ .gpt_index = 2 },
        } },
        .packages = .{
            .actions = &actions,
            .repositories = &repositories,
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{kernel},
        } },
        .hooks = &hooks,
        .execution = .{
            .workspace_path = work_path,
            .backend = .unsafe_chroot,
            .acknowledge_unsafe = true,
        },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x51} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
    var resolved = try miz.customize.resolve(allocator, &request, .{
        .host_architecture = .x86_64,
    });
    defer resolved.deinit(allocator);
    if (resolved.plan == null or resolved.diagnostics.hasErrors()) {
        return error.RealPackageResolutionFailed;
    }

    var context = RuntimeContext{ .self_exe = self_exe };
    var platform = miz.customize.Platform.system();
    platform.context = &context;
    platform.unsafeChrootCheckFn = checkUnsafeChroot;
    platform.unsafeChrootRunFn = runUnsafeChroot;
    var preflight = try miz.customize.preflight(
        allocator,
        io,
        &resolved.plan.?,
        platform,
    );
    defer preflight.deinit(allocator);
    if (!preflight.ready()) return error.RealPackagePreflightFailed;

    var outcome = try miz.customize.execute(
        allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(allocator);
    const result = outcome.result orelse return error.RealPackageExecutionFailed;
    if (outcome.diagnostics.hasErrors()) return error.RealPackageExecutionFailed;
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) {
            return error.RealPackageCleanupFailed;
        }
    }
    try validateProvenance(&result.provenance, kernel, after_packages_digest);
    const final_source_digest = try miz.customize.hashSourcePath(
        allocator,
        io,
        source_path,
    );
    try ensure(std.mem.eql(
        u8,
        &source_digest.bytes,
        &final_source_digest.bytes,
    ));
    try ensureGuestPath(io, allocator, output_path, root_offset, "usr/bin/nano");
    try ensureGuestPath(
        io,
        allocator,
        output_path,
        root_offset,
        "etc/miz-hook-after-packages",
    );
    try ensureGuestPath(io, allocator, output_path, root_offset, "etc/miz-hook-finalize");
    const hook_argument = try readGuestFile(
        allocator,
        io,
        output_path,
        root_offset,
        "etc/miz-hook-after-packages",
    );
    defer allocator.free(hook_argument);
    try ensure(std.mem.eql(
        u8,
        std.mem.trimEnd(u8, hook_argument, "\n"),
        "argument-reached-the-hook",
    ));
    // The finalize hook listed the private tmpfs from inside the chroot while
    // it was itself the running hook, so an empty listing is the strongest
    // statement available that no earlier hook's code is still there.
    const leftovers = try readGuestFile(
        allocator,
        io,
        output_path,
        root_offset,
        "etc/miz-hook-leftovers",
    );
    defer allocator.free(leftovers);
    try ensure(std.mem.indexOf(u8, leftovers, "miz-hook-0") == null);
    try ensureGuestPathAbsent(io, allocator, output_path, root_offset, "run/miz-hook-1");
    try ensureGuestFileNonempty(
        allocator,
        io,
        output_path,
        root_offset,
        initramfs_path,
    );
    try ensureBootEntryReferences(
        allocator,
        io,
        output_path,
        std.fs.path.basename(initramfs_path),
    );
    try ensurePathAbsent(io, resolved.plan.?.data.transaction_path);

    try copyFile(allocator, io, config.ovmf_vars_path, vars_copy_path);
    var qemu = try boot_smoke.runQemuBootSmoke(
        allocator,
        io,
        config.qemu_path,
        .{
            .firmware = .{
                .code_path = @constCast(config.ovmf_code_path),
                .vars_path = @constCast(config.ovmf_vars_path),
            },
            .vars_copy_path = vars_copy_path,
        },
        output_path,
        serial_path,
        smoke_marker,
    );
    defer qemu.deinit(allocator);
    if (qemu.timed_out or
        std.mem.indexOf(u8, qemu.serial_output, "Linux version") == null)
    {
        std.debug.print("real package boot serial output:\n{s}\n", .{qemu.serial_output});
        return error.RealPackageBootFailed;
    }

    try Io.Dir.cwd().deleteTree(io, work_path);
    completed = true;
    std.debug.print(
        "real unsafe-chroot package/dracut/QEMU integration passed ({s})\n",
        .{kernel},
    );
}

fn buildSourceImage(
    allocator: Allocator,
    io: Io,
    iso_path: []const u8,
    oci_path: []const u8,
    output_path: []const u8,
) !u64 {
    const script =
        \\#!/bin/sh
        \\set -eu
        \\rpm -q nano >/dev/null
        \\test -s "/boot/initramfs-$(uname -r).img"
        \\printf 'MIZ real package customization verified\n' >/dev/ttyS0
        \\
    ;
    const unit =
        \\[Unit]
        \\Description=Verify real miz package customization
        \\After=local-fs.target
        \\
        \\[Service]
        \\Type=oneshot
        \\ExecStart=/usr/local/sbin/miz-real-package-smoke
        \\
        \\[Install]
        \\WantedBy=multi-user.target
        \\
    ;
    const filesystem = [_]miz.os_customization.FilesystemOperation{
        .{ .put_file = .{
            .path = "/usr/local/sbin/miz-real-package-smoke",
            .source = .{ .inline_bytes = script },
            .metadata = .{ .mode = 0o755 },
        } },
        .{ .put_file = .{
            .path = "/usr/lib/systemd/system/miz-real-package-smoke.service",
            .source = .{ .inline_bytes = unit },
        } },
    };
    const services = [_]miz.os_customization.Service{.{
        .name = "miz-real-package-smoke.service",
        .state = .enabled,
    }};
    var report = try miz.build_image.build(allocator, io, .{
        .iso_path = iso_path,
        .container_path = oci_path,
        .output_path = output_path,
        .output_format = .raw,
        .generation = .gen2,
        .size = disk_size,
        .extra_kernel_options = "console=tty0 console=ttyS0,115200n8 selinux=0",
        .os = .{
            .filesystem = &filesystem,
            .services = &services,
        },
    });
    defer report.deinit(allocator);
    for (report.planned_partitions) |partition| {
        if (partition.planned.role == .root_x86_64) {
            return partition.planned.offset_bytes;
        }
    }
    return error.RootPartitionMissing;
}

fn findKernelRelease(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    root_offset: u64,
) ![]u8 {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
        .offset = root_offset,
    });
    defer reader.deinit();
    const entries = try reader.listDir(io, allocator, "usr/lib/modules");
    defer miz.ext4.freeDirEntries(allocator, entries);
    var kernel: ?[]u8 = null;
    for (entries) |entry| {
        if (entry.kind != .directory) continue;
        if (kernel != null) return error.MultipleKernelReleases;
        kernel = try allocator.dupe(u8, entry.name);
    }
    return kernel orelse error.KernelReleaseMissing;
}

fn readGuestFile(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    root_offset: u64,
    path: []const u8,
) ![]u8 {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
        .offset = root_offset,
    });
    defer reader.deinit();
    return reader.readFileAlloc(io, allocator, path);
}

fn ensureGuestFileNonempty(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    root_offset: u64,
    path: []const u8,
) !void {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
        .offset = root_offset,
    });
    defer reader.deinit();
    const stat = try reader.statPath(io, path);
    try ensure(stat.kind == .file and stat.size != 0);
}

fn ensureBootEntryReferences(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    initramfs_name: []const u8,
) !void {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    const parsed = try miz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    if (parsed.partitions.len < 2) return error.EspPartitionMissing;
    const esp_partition = parsed.partitions[0];
    var esp = try miz.fat32.open(&image, io, .{
        .offset = esp_partition.first_lba * miz.gpt.sector_size,
        .length = (esp_partition.last_lba - esp_partition.first_lba + 1) *
            miz.gpt.sector_size,
    });
    const entries = try esp.listDirAlloc(io, allocator, "loader/entries");
    defer miz.fat32.freeDirEntries(allocator, entries);
    for (entries) |entry| {
        if (entry.kind != .file or
            !std.mem.endsWith(u8, entry.name, ".conf"))
        {
            continue;
        }
        const path = try std.fmt.allocPrint(
            allocator,
            "loader/entries/{s}",
            .{entry.name},
        );
        const bytes = try esp.readFileAlloc(io, allocator, path);
        if (std.mem.indexOf(u8, bytes, initramfs_name) != null) return;
    }
    return error.InitramfsBootEntryMissing;
}

fn ensureGuestPath(
    io: Io,
    allocator: Allocator,
    image_path: []const u8,
    root_offset: u64,
    path: []const u8,
) !void {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
        .offset = root_offset,
    });
    defer reader.deinit();
    _ = try reader.statPath(io, path);
}

/// The counterpart to `ensureGuestPath`. A hook's script lives on a tmpfs the
/// executor unmounts before publishing, so this asserting nothing is only
/// meaningful together with the finalize hook's own listing from inside the
/// chroot -- one says the image is clean, the other says the run was.
fn ensureGuestPathAbsent(
    io: Io,
    allocator: Allocator,
    image_path: []const u8,
    root_offset: u64,
    path: []const u8,
) !void {
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
        .offset = root_offset,
    });
    defer reader.deinit();
    if (reader.statPath(io, path)) |_| {
        return error.GuestPathUnexpectedlyPresent;
    } else |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    }
}

fn validateProvenance(
    provenance: *const miz.customize.Provenance,
    kernel: []const u8,
    after_packages_digest: [32]u8,
) !void {
    const preserved = provenance.execution.preserved orelse
        return error.MissingPreservedProvenance;
    try ensure(preserved.hooks.len == 2);
    try ensure(std.mem.eql(u8, preserved.hooks[0].name, "after-packages"));
    try ensure(preserved.hooks[0].phase == .after_packages);
    try ensure(std.mem.eql(
        u8,
        &preserved.hooks[0].source_sha256.bytes,
        &after_packages_digest,
    ));
    try ensure(preserved.hooks[0].exit_code == 0);
    try ensure(std.mem.eql(u8, preserved.hooks[1].name, "finalize"));
    try ensure(preserved.hooks[1].phase == .finalize);
    var found_nano = false;
    for (preserved.installed_packages) |package| {
        if (std.mem.startsWith(u8, package, "nano-")) found_nano = true;
    }
    try ensure(found_nano);
    inline for (.{ "rpm", "tdnf", "dracut" }) |name| {
        var found = false;
        for (provenance.tools) |tool| {
            const version = tool.version orelse continue;
            if (std.mem.eql(u8, tool.name, name) and version.len != 0) {
                found = true;
            }
        }
        try ensure(found);
    }
    // A real run against a real host: the plumbing that staged the image is
    // recorded alongside the programs that customized it, and every record
    // names a command rather than a probe of one.
    inline for (.{ "unshare", "losetup", "mount", "umount", "sync" }) |name| {
        var found = false;
        for (provenance.tools) |tool| {
            if (std.mem.eql(u8, tool.name, name) and tool.context == .host) found = true;
        }
        try ensure(found);
    }
    for (provenance.tools) |tool| {
        for (tool.command) |argument| {
            try ensure(!std.mem.eql(u8, argument, "--version"));
        }
    }
    var found_dracut = false;
    var expected_output_buffer: [256]u8 = undefined;
    const expected_output = try std.fmt.bufPrint(
        &expected_output_buffer,
        "/boot/initramfs-{s}.img",
        .{kernel},
    );
    const expected_temporary = "/run/miz-initramfs.img";
    for (provenance.tools) |tool| {
        if (!std.mem.eql(u8, tool.name, "dracut") or
            tool.command.len != 8)
        {
            continue;
        }
        if (std.mem.eql(u8, tool.command[0], "/usr/bin/dracut") and
            std.mem.eql(u8, tool.command[1], "--force") and
            std.mem.eql(u8, tool.command[2], "--no-hostonly") and
            std.mem.eql(u8, tool.command[3], "--tmpdir") and
            std.mem.eql(u8, tool.command[4], "/run") and
            std.mem.eql(u8, tool.command[5], "--kver") and
            std.mem.eql(u8, tool.command[6], kernel) and
            std.mem.eql(u8, tool.command[7], expected_temporary))
        {
            found_dracut = true;
        }
    }
    try ensure(found_dracut);
    var found_publish = false;
    for (provenance.tools) |tool| {
        if (tool.command.len == 4 and
            std.mem.eql(u8, tool.name, "cp") and
            (tool.version orelse @as([]const u8, "")).len != 0 and
            std.mem.eql(u8, tool.command[0], "/usr/bin/cp") and
            std.mem.eql(u8, tool.command[1], "--remove-destination") and
            std.mem.eql(u8, tool.command[2], expected_temporary) and
            std.mem.eql(u8, tool.command[3], expected_output))
        {
            found_publish = true;
        }
    }
    try ensure(found_publish);
}

const RuntimeContext = struct {
    self_exe: []const u8,
};

fn checkUnsafeChroot(
    _: ?*anyopaque,
    io: Io,
    _: *const miz.customize.ResolvedPlan,
) miz.customize.CapabilityState {
    return miz.unsafe_chroot.available(io);
}

fn runUnsafeChroot(
    context_ptr: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    plan: *const miz.customize.ResolvedPlan,
    target: miz.preserved_image.RawMutationTarget,
    deadline: miz.customize.Deadline,
) !miz.customize.UnsafeChrootRuntimeReport {
    const context: *RuntimeContext = @ptrCast(@alignCast(context_ptr.?));
    return miz.unsafe_chroot.runParent(allocator, io, .{
        .deadline = deadline,
        .self_exe = context.self_exe,
        .transaction_path = plan.data.transaction_path,
        .plan = plan,
        .target = target,
    });
}

fn copyFile(
    allocator: Allocator,
    io: Io,
    source_path: []const u8,
    output_path: []const u8,
) !void {
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        source_path,
        allocator,
        .limited(8 * 1024 * 1024),
    );
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = output_path, .data = bytes });
}

fn ensurePathAbsent(io: Io, path: []const u8) !void {
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.UnexpectedPath;
}

fn isExecutable(io: Io, path: []const u8) bool {
    Io.Dir.accessAbsolute(io, path, .{ .execute = true }) catch return false;
    return true;
}

fn ensure(condition: bool) !void {
    if (!condition) return error.IntegrationExpectationFailed;
}
