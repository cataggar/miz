const std = @import("std");
const builtin = @import("builtin");
const zvmi = @import("zvmi");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const disk_size: u64 = 160 * 1024 * 1024;
const partition_first_lba: u32 = 2048;
const partition_sectors: u32 = 300 * 1024;
const partition_offset = @as(u64, partition_first_lba) * zvmi.mbr.sector_size;
const partition_length = @as(u64, partition_sectors) * zvmi.mbr.sector_size;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(allocator);
    const executable_name = std.fs.path.basename(argv[0]);
    if (std.mem.eql(u8, executable_name, "rpm")) {
        return runGuestRpm(init.io, argv[1..]);
    }
    if (std.mem.eql(u8, executable_name, "tdnf")) {
        return runGuestTdnf(init.io, argv[1..]);
    }
    if (std.mem.eql(u8, executable_name, "dracut")) {
        return runGuestDracut(init.io, argv[1..]);
    }
    if (std.mem.eql(u8, executable_name, "cp")) {
        return runGuestCp(init.io, argv[1..]);
    }
    if (std.mem.eql(u8, executable_name, "grub2-mkconfig")) {
        return runGuestGrubMkconfig(allocator, init.io, argv[1..]);
    }
    if (argv.len == 3 and
        std.mem.eql(u8, argv[1], "--unsafe-chroot-worker"))
    {
        return zvmi.unsafe_chroot.workerMain(init, argv[2]);
    }
    if (builtin.os.tag != .linux) {
        std.debug.print("skipping unsafe-chroot integration: Linux is required\n", .{});
        return;
    }
    const explicitly_requested = if (init.environ_map.get(
        "ZVMI_RUN_PRIVILEGED_TEST",
    )) |value|
        std.mem.eql(u8, value, "1")
    else
        false;
    const privileged_child = argv.len == 2 and
        std.mem.eql(u8, argv[1], "--privileged");
    if (!explicitly_requested and !privileged_child) {
        std.debug.print(
            "skipping unsafe-chroot integration: set ZVMI_RUN_PRIVILEGED_TEST=1 to opt in\n",
            .{},
        );
        return;
    }
    if (std.os.linux.geteuid() != 0) {
        return reexecWithSudo(init.io, argv[0]);
    }
    try runIntegration(allocator, init.io, argv[0]);
}

fn reexecWithSudo(io: Io, self_exe: []const u8) !void {
    const sudo = if (isExecutable(io, "/usr/bin/sudo"))
        "/usr/bin/sudo"
    else if (isExecutable(io, "/bin/sudo"))
        "/bin/sudo"
    else
        return error.SudoUnavailable;
    var child = try std.process.spawn(io, .{
        .argv = &.{ sudo, "-n", self_exe, "--privileged" },
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
) !void {
    if (zvmi.unsafe_chroot.available(io) != .available) {
        return error.UnsafeChrootHostUnavailable;
    }

    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    const work_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/zvmi-unsafe-chroot-integration-{s}",
        .{&random_hex},
    );
    const source_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "source.raw" },
    );
    const output_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "output.raw" },
    );
    const spool_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "root.spool" },
    );
    try Io.Dir.cwd().createDir(io, work_path, .default_dir);
    var completed = false;
    defer if (!completed) {
        std.debug.print(
            "unsafe-chroot integration retained failed workspace for recovery: {s}\n",
            .{work_path},
        );
    };

    try createSourceDisk(
        allocator,
        io,
        self_exe,
        source_path,
        spool_path,
    );

    const actions = [_]zvmi.customize.PackageAction{
        .{ .install = &.{"integration-package"} },
        .{ .remove = &.{"obsolete-package"} },
    };
    const repositories = [_]zvmi.customize.PackageRepository{.{
        .id = "integration",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "integration trust\n" }},
    }};
    const architecture: zvmi.customize.Architecture = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => return error.UnsupportedArchitecture,
    };
    // The identity the stub `rpm -qa` reports, so the run has a lock that can
    // actually hold. The install below is checked against the pinned spec
    // rather than the bare name, which is the observable difference between a
    // lock that is enforced and one that is merely recorded.
    const lock = [_]zvmi.customize.PackageVersionLock{.{
        .name = "integration-package",
        .evr = "0:1.0-1",
        .architecture = @tagName(builtin.cpu.arch),
    }};
    const request = zvmi.customize.Request{
        .target_architecture = architecture,
        .input = .{ .disk = .{ .path = source_path } },
        .output = .{
            .path = output_path,
            .format = .raw,
            .size_policy = .preserve_source,
        },
        .storage = .{ .preserve = .{
            .root_partition = .{ .mbr_index = 1 },
        } },
        .packages = .{
            .actions = &actions,
            .repositories = &repositories,
            .lock = .{ .exact = &lock },
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.0-integration"},
        } },
        .boot_security = .{ .extra_kernel_options = "console=ttyS0" },
        .execution = .{
            .workspace_path = work_path,
            .backend = .unsafe_chroot,
            .acknowledge_unsafe = true,
        },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x48} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
    var resolved = try zvmi.customize.resolve(allocator, &request, .{
        .host_architecture = architecture,
    });
    defer resolved.deinit(allocator);
    if (resolved.plan == null or resolved.diagnostics.hasErrors()) {
        return error.IntegrationResolutionFailed;
    }

    var context = RuntimeContext{ .self_exe = self_exe };
    var platform = zvmi.customize.Platform.system();
    platform.context = &context;
    platform.unsafeChrootCheckFn = checkUnsafeChroot;
    platform.unsafeChrootRunFn = runUnsafeChroot;
    var preflight = try zvmi.customize.preflight(
        allocator,
        io,
        &resolved.plan.?,
        platform,
    );
    defer preflight.deinit(allocator);
    if (!preflight.ready()) return error.IntegrationPreflightFailed;

    var outcome = try zvmi.customize.execute(
        allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(allocator);
    const result = outcome.result orelse
        return error.IntegrationExecutionFailed;
    if (outcome.diagnostics.hasErrors()) {
        return error.IntegrationExecutionFailed;
    }
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) {
            return error.IntegrationCleanupFailed;
        }
    }
    try ensure(result.provenance.tools.len == 6);
    const preserved = result.provenance.execution.preserved orelse
        return error.MissingPreservedProvenance;
    // The inventory is reported as rpm gives it, trust pseudo-packages and
    // all. What they are excluded from is the lock, not the record of what
    // the root holds.
    try ensure(preserved.installed_packages.len == 4);
    try ensure(std.mem.eql(
        u8,
        preserved.installed_packages[0],
        preexisting_nevra,
    ));
    try ensure(std.mem.eql(
        u8,
        preserved.installed_packages[1],
        declared_trust_nevra,
    ));
    try ensure(std.mem.eql(
        u8,
        preserved.installed_packages[2],
        transaction_trust_nevra,
    ));
    try ensure(std.mem.eql(
        u8,
        preserved.installed_packages[3],
        installed_nevra,
    ));

    // The emitted lock is the difference between the two inventories, so the
    // package the root already carried must not be in it even though it is in
    // the inventory beside it. Neither trust pseudo-package is in it either:
    // the declared key was imported before the baseline was read, and the one
    // the transaction imported is excluded by name. That this run completed
    // at all is the other half of the assertion -- it ran under an exact
    // lock, so a pseudo-package left in the delta would have failed it.
    try ensure(preserved.emitted_package_lock.len == 1);
    const emitted = preserved.emitted_package_lock[0];
    try ensure(std.mem.eql(u8, emitted.name, "integration-package"));
    try ensure(std.mem.eql(u8, emitted.evr, "0:1.0-1"));
    try ensure(std.mem.eql(u8, emitted.architecture, @tagName(builtin.cpu.arch)));

    // The generator ran as the target's own program, against the file this
    // run edited, and produced entries carrying the options.
    const boot_configuration = preserved.boot_configuration orelse
        return error.MissingBootConfigurationProvenance;
    try ensure(std.mem.eql(
        u8,
        boot_configuration.defaults_path,
        "/etc/default/grub",
    ));
    try ensure(std.mem.eql(
        u8,
        boot_configuration.generator_path,
        "/usr/sbin/grub2-mkconfig",
    ));
    try ensure(std.mem.eql(
        u8,
        boot_configuration.generated_path,
        "/boot/grub2/grub.cfg",
    ));
    try ensure(std.mem.eql(u8, boot_configuration.options, "console=ttyS0"));
    // Both the normal entry, where the options sit before
    // `GRUB_CMDLINE_LINUX_DEFAULT`, and the recovery entry, where they end
    // the line.
    try ensure(boot_configuration.entries == 2);
    try ensure(!boot_configuration.defaults_already_current);
    var generator_recorded = false;
    for (result.provenance.tools) |tool| {
        if (!std.mem.eql(u8, tool.name, "grub2-mkconfig")) continue;
        generator_recorded = true;
        try ensure(std.mem.eql(u8, tool.version, "grub2-mkconfig integration-1"));
        try ensure(tool.command.len == 3);
        try ensure(std.mem.eql(u8, tool.command[1], "-o"));
        try ensure(std.mem.eql(u8, tool.command[2], "/boot/grub2/grub.cfg"));
    }
    try ensure(generator_recorded);

    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/var/lib/zvmi-integration/trust",
        "trusted\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/var/lib/zvmi-integration/installed",
        installed_nevra ++ "\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/var/lib/zvmi-integration/removed",
        "obsolete-package\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/boot/initramfs-6.0-integration.img",
        "integration initramfs\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/etc/resolv.conf",
        "nameserver 192.0.2.1\n",
    );
    // The input the distro regenerates from carries the options, so the next
    // kernel package change reproduces them rather than dropping them.
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/etc/default/grub",
        "# integration defaults\n" ++
            "GRUB_TIMEOUT=5\n" ++
            "GRUB_CMDLINE_LINUX=\"rd.auto=1 console=ttyS0\"\n" ++
            "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/boot/grub2/grub.cfg",
        "menuentry 'integration' {\n" ++
            "\tlinux /vmlinuz-6.0-integration root=UUID=integration ro rd.auto=1 console=ttyS0 quiet\n" ++
            "}\n" ++
            "menuentry 'integration (recovery)' {\n" ++
            "\tlinux /vmlinuz-6.0-integration root=UUID=integration ro single rd.auto=1 console=ttyS0\n" ++
            "}\n",
    );
    try expectMissingFile(
        allocator,
        io,
        source_path,
        "/var/lib/zvmi-integration/installed",
    );

    try expectPathAbsent(io, resolved.plan.?.data.transaction_path);
    try Io.Dir.cwd().deleteTree(io, work_path);
    completed = true;
    std.debug.print("unsafe-chroot privileged integration passed\n", .{});
}

const integration_grub_defaults =
    "# integration defaults\n" ++
    "GRUB_TIMEOUT=5\n" ++
    "GRUB_CMDLINE_LINUX=\"rd.auto=1\"\n" ++
    "GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"\n";

const RuntimeContext = struct {
    self_exe: []const u8,
};

fn checkUnsafeChroot(
    _: ?*anyopaque,
    io: Io,
    _: *const zvmi.customize.ResolvedPlan,
) zvmi.customize.CapabilityState {
    return zvmi.unsafe_chroot.available(io);
}

fn runUnsafeChroot(
    context_ptr: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    plan: *const zvmi.customize.ResolvedPlan,
    target: zvmi.preserved_image.RawMutationTarget,
) !zvmi.customize.UnsafeChrootRuntimeReport {
    const context: *RuntimeContext = @ptrCast(@alignCast(context_ptr.?));
    return zvmi.unsafe_chroot.runParent(allocator, io, .{
        .self_exe = context.self_exe,
        .transaction_path = plan.data.transaction_path,
        .plan = plan,
        .target = target,
    });
}

fn createSourceDisk(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    source_path: []const u8,
    spool_path: []const u8,
) !void {
    const executable = try Io.Dir.cwd().readFileAlloc(
        io,
        self_exe,
        allocator,
        .limited(64 * 1024 * 1024),
    );
    defer allocator.free(executable);

    var image = try zvmi.Image.createExclusive(
        io,
        source_path,
        .raw,
        disk_size,
        .{},
    );
    defer image.close(io);
    const boot_record = zvmi.mbr.singleLinuxPartitionMbr(
        partition_first_lba,
        partition_sectors,
    ).encode();
    try image.pwrite(io, &boot_record, 0);

    var tree = try zvmi.root_tree.RootTree.init(
        allocator,
        io,
        spool_path,
        .{},
    );
    defer tree.deinit();
    inline for (.{
        "boot",
        "boot/grub2",
        "dev",
        "etc",
        "etc/default",
        "proc",
        "run",
        "sys",
        "usr",
        "usr/bin",
        "usr/sbin",
        "var",
        "var/lib",
        "var/lib/zvmi-integration",
    }) |path| {
        try tree.putDirectory(path, .{ .mode = 0o755 });
    }
    try tree.putFileBytes(
        "etc/resolv.conf",
        "nameserver 192.0.2.1\n",
        .{ .mode = 0o644 },
    );
    // A root-only fstab: the layout the chroot backend can regenerate for,
    // as opposed to one declaring a separate `/boot` it never mounted.
    try tree.putFileBytes(
        "etc/fstab",
        "UUID=integration /     ext4 defaults 0 1\n" ++
            "UUID=swap        none  swap defaults 0 0\n",
        .{ .mode = 0o644 },
    );
    // Two variables, as a distro ships: the generator puts
    // `GRUB_CMDLINE_LINUX_DEFAULT` *after* the variable this run edits on
    // the normal entry, so the options land mid-line there and last only on
    // the recovery entry.
    try tree.putFileBytes(
        "etc/default/grub",
        integration_grub_defaults,
        .{ .mode = 0o644 },
    );
    try tree.putFileBytes(
        "boot/grub2/grub.cfg",
        "menuentry 'stale' {\n" ++
            "\tlinux /vmlinuz-6.0-integration root=UUID=integration ro rd.auto=1\n" ++
            "}\n",
        .{ .mode = 0o644 },
    );
    try tree.putFileBytes(
        "usr/bin/rpm",
        executable,
        .{ .mode = 0o755 },
    );
    try tree.putSymlink("usr/bin/tdnf", "rpm", .{ .mode = 0o777 });
    try tree.putSymlink("usr/bin/dracut", "rpm", .{ .mode = 0o777 });
    try tree.putSymlink("usr/bin/cp", "rpm", .{ .mode = 0o777 });
    try tree.putSymlink("usr/sbin/grub2-mkconfig", "../bin/rpm", .{ .mode = 0o777 });
    _ = try zvmi.ext4.populate(
        io,
        image.file,
        allocator,
        try tree.ext4View(),
        .{
            .offset = partition_offset,
            .length = partition_length,
            .label = "unsafe-test",
            .uuid = [_]u8{0x48} ** 16,
            .timestamp = 1_735_689_600,
        },
    );
}

fn runGuestRpm(io: Io, args: []const []const u8) !void {
    if (containsArg(args, "--version")) {
        std.debug.print("RPM version integration-1\n", .{});
        return;
    }
    if (containsArg(args, "--import")) {
        const trust_path = argumentImmediatelyAfter(args, "--import") orelse
            return error.UnexpectedRpmInvocation;
        if (!std.mem.eql(u8, trust_path, "/run/zvmi-trust-0.asc")) {
            return error.UnexpectedTrustPath;
        }
        var trust_buffer: [64]u8 = undefined;
        const trust_file = try Io.Dir.cwd().openFile(io, trust_path, .{
            .mode = .read_only,
            .allow_directory = false,
            .follow_symlinks = false,
        });
        defer trust_file.close(io);
        const trust_size = (try trust_file.stat(io)).size;
        if (trust_size > trust_buffer.len) return error.UnexpectedTrustData;
        const trust_length: usize = @intCast(trust_size);
        const read = try trust_file.readPositionalAll(
            io,
            trust_buffer[0..trust_length],
            0,
        );
        if (read != trust_length or
            !std.mem.eql(u8, trust_buffer[0..read], "integration trust\n"))
        {
            return error.UnexpectedTrustData;
        }
        try writeGuestMarker(
            io,
            "/var/lib/zvmi-integration/trust",
            "trusted",
        );
        return;
    }
    if (containsArg(args, "-qa")) {
        // The inventory answers differently before and after the transaction,
        // because a stub that answered the same both times would let an
        // emitted lock built from the difference pass while being empty.
        std.debug.print("{s}\n", .{preexisting_nevra});
        // Real rpm records each imported key as a `gpg-pubkey` pseudo-package
        // and reports it here. The declared repository key appears once the
        // trust import has run, and a second key appears once the transaction
        // has run, standing for a key tdnf imports on its own under gpgcheck.
        // Neither belongs in a lock: `(none)` is not an architecture the pin
        // rules accept, so a lock naming one could never be restated.
        if (guestPathExists(io, "/var/lib/zvmi-integration/trust")) {
            std.debug.print("{s}\n", .{declared_trust_nevra});
        }
        if (guestPathExists(io, "/var/lib/zvmi-integration/installed")) {
            std.debug.print("{s}\n", .{installed_nevra});
            std.debug.print("{s}\n", .{transaction_trust_nevra});
        }
        return;
    }
    return error.UnexpectedRpmInvocation;
}

fn runGuestTdnf(io: Io, args: []const []const u8) !void {
    if (containsArg(args, "--version")) {
        std.debug.print("tdnf integration-1\n", .{});
        return;
    }
    if (argumentAfter(args, "install")) |package| {
        try writeGuestMarker(
            io,
            "/var/lib/zvmi-integration/installed",
            package,
        );
        return;
    }
    if (argumentAfter(args, "remove")) |package| {
        try writeGuestMarker(
            io,
            "/var/lib/zvmi-integration/removed",
            package,
        );
        return;
    }
    return error.UnexpectedTdnfInvocation;
}

fn runGuestDracut(io: Io, args: []const []const u8) !void {
    if (containsArg(args, "--version")) {
        std.debug.print("dracut integration-1\n", .{});
        return;
    }
    if (args.len == 0 or
        !containsArg(args, "--no-hostonly") or
        !std.mem.eql(
            u8,
            argumentImmediatelyAfter(args, "--tmpdir") orelse "",
            "/run",
        ))
    {
        return error.UnexpectedDracutInvocation;
    }
    try writeGuestMarker(
        io,
        args[args.len - 1],
        "integration initramfs",
    );
}

/// A stand-in for the target's own `grub2-mkconfig`: it regenerates the
/// configuration from `/etc/default/grub` the way a distro's generator does,
/// which is what makes editing that file rather than the output the durable
/// change. It deliberately reads the variable back out of the file instead of
/// taking the options on its command line, so the test fails if the edit
/// landed anywhere else.
fn runGuestGrubMkconfig(
    allocator: Allocator,
    io: Io,
    args: []const []const u8,
) !void {
    if (containsArg(args, "--version")) {
        std.debug.print("grub2-mkconfig integration-1\n", .{});
        return;
    }
    const output = argumentImmediatelyAfter(args, "-o") orelse
        return error.UnexpectedGrubMkconfigInvocation;
    const defaults = try Io.Dir.cwd().readFileAlloc(
        io,
        "/etc/default/grub",
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(defaults);
    // `/etc/grub.d/10_linux` composes the normal entry from both variables
    // in this order and the recovery entry from the first alone. Reproducing
    // that is what makes the test cover an option that is not the last word
    // on the line.
    const command_line = try guestVariable(defaults, "GRUB_CMDLINE_LINUX");
    const default_command_line = try guestVariable(
        defaults,
        "GRUB_CMDLINE_LINUX_DEFAULT",
    );
    var buffer: [1024]u8 = undefined;
    const generated = try std.fmt.bufPrint(
        &buffer,
        "menuentry 'integration' {{\n" ++
            "\tlinux /vmlinuz-6.0-integration root=UUID=integration ro {s} {s}\n" ++
            "}}\n" ++
            "menuentry 'integration (recovery)' {{\n" ++
            "\tlinux /vmlinuz-6.0-integration root=UUID=integration ro single {s}\n" ++
            "}}\n",
        .{ command_line, default_command_line, command_line },
    );
    const file = try Io.Dir.cwd().createFile(io, output, .{});
    defer file.close(io);
    try file.writePositionalAll(io, generated, 0);
}

fn guestVariable(defaults: []const u8, name: []const u8) ![]const u8 {
    var lines = std.mem.splitScalar(u8, defaults, '\n');
    while (lines.next()) |line| {
        if (!std.mem.startsWith(u8, line, name)) continue;
        const rest = line[name.len..];
        if (!std.mem.startsWith(u8, rest, "=\"")) continue;
        const value = rest[2..];
        const end = std.mem.indexOfScalar(u8, value, '"') orelse
            return error.UnterminatedGrubCommandLine;
        return value[0..end];
    }
    return error.MissingGrubCommandLine;
}

fn runGuestCp(io: Io, args: []const []const u8) !void {
    if (containsArg(args, "--version")) {
        std.debug.print("cp (GNU coreutils) integration-1\n", .{});
        return;
    }
    if (args.len != 3 or
        !std.mem.eql(u8, args[0], "--remove-destination"))
    {
        return error.UnexpectedCpInvocation;
    }
    var buffer: [64]u8 = undefined;
    const source = try Io.Dir.cwd().openFile(io, args[1], .{
        .mode = .read_only,
        .allow_directory = false,
    });
    defer source.close(io);
    const length = try source.readPositionalAll(io, &buffer, 0);
    Io.Dir.cwd().deleteFile(io, args[2]) catch |err| switch (err) {
        error.FileNotFound => {},
        else => return err,
    };
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = args[2],
        .data = buffer[0..length],
    });
}

fn writeGuestMarker(io: Io, path: []const u8, value: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, value, 0);
    try file.writePositionalAll(io, "\n", value.len);
}

/// The one package the stub `rpm -qa` reports as installed, in the same
/// `NAME-EPOCH:VERSION-RELEASE.ARCH` form the real command is asked for.
/// A constant rather than a function so the pinned spec the lock produces can
/// be spelled out at compile time beside it.
const installed_nevra = "integration-package-0:1.0-1." ++ @tagName(builtin.cpu.arch);

/// What the root already carried. Present in both inventories, so it must not
/// appear in the emitted lock: a lock naming what the run did not choose says
/// nothing about the run.
const preexisting_nevra = "base-files-0:2.0-3.azl3." ++ @tagName(builtin.cpu.arch);

/// The pseudo-package rpm records for the repository key this run declares,
/// reported from the moment `rpm --import` has run.
const declared_trust_nevra = "gpg-pubkey-0:3135ce90-5e6d6b3f.(none)";

/// The pseudo-package rpm records for a key the package transaction imported
/// on its own, which no caller declared and no lock could pin.
const transaction_trust_nevra = "gpg-pubkey-0:c1b39b60-5e6d6b40.(none)";

fn guestPathExists(io: Io, path: []const u8) bool {
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return true;
}

fn argumentAfter(
    args: []const []const u8,
    expected: []const u8,
) ?[]const u8 {
    for (args, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, expected) and index + 2 < args.len and
            std.mem.eql(u8, args[index + 1], "-y"))
        {
            return args[index + 2];
        }
    }
    return null;
}

fn argumentImmediatelyAfter(
    args: []const []const u8,
    expected: []const u8,
) ?[]const u8 {
    for (args, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, expected) and index + 1 < args.len) {
            return args[index + 1];
        }
    }
    return null;
}

fn containsArg(args: []const []const u8, expected: []const u8) bool {
    for (args) |arg| {
        if (std.mem.eql(u8, arg, expected)) return true;
    }
    return false;
}

fn expectOutputFile(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    guest_path: []const u8,
    expected: []const u8,
) !void {
    var image = try zvmi.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try zvmi.ext4.open(io, image.file, allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    const bytes = try reader.readFileAlloc(io, allocator, guest_path);
    defer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, expected)) {
        return error.UnexpectedGuestFile;
    }
}

fn expectMissingFile(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    guest_path: []const u8,
) !void {
    var image = try zvmi.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try zvmi.ext4.open(io, image.file, allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    _ = reader.statPath(io, guest_path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    return error.UnexpectedGuestFile;
}

fn isExecutable(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{ .execute = true }) catch return false;
    return true;
}

fn expectPathAbsent(io: Io, path: []const u8) !void {
    _ = Io.Dir.cwd().statFile(
        io,
        path,
        .{ .follow_symlinks = false },
    ) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.UnexpectedPath;
}

fn ensure(condition: bool) !void {
    if (!condition) return error.IntegrationAssertionFailed;
}
