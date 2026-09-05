const std = @import("std");
const builtin = @import("builtin");
const miz = @import("miz");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const disk_size: u64 = 160 * 1024 * 1024;
const fixture_executable_max_size: usize = 128 * 1024 * 1024;
const partition_first_lba: u32 = 2048;
const partition_sectors: u32 = 300 * 1024;
const partition_offset = @as(u64, partition_first_lba) * miz.mbr.sector_size;
const partition_length = @as(u64, partition_sectors) * miz.mbr.sector_size;

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
    // The interpreter the hanging hook names in its shebang. It never
    // returns, which is the only way to observe a bound that works.
    if (std.mem.eql(u8, executable_name, "hang")) {
        return runGuestHangingHook(init.io);
    }
    // The target's own labelling tool. It records the command it was given
    // rather than labelling anything: what is under test is that the run
    // invokes the target's tool, with the policy the target names, at the
    // point in the run where nothing else will write afterwards.
    if (std.mem.eql(u8, executable_name, "setfiles")) {
        return runGuestSetfiles(allocator, init.io, argv[1..]);
    }
    if (std.mem.eql(u8, executable_name, "grub2-mkconfig")) {
        return runGuestGrubMkconfig(allocator, init.io, argv[1..]);
    }
    if (argv.len == 3 and
        std.mem.eql(u8, argv[1], "--unsafe-chroot-worker"))
    {
        return miz.unsafe_chroot.workerMain(init, argv[2]);
    }
    if (builtin.os.tag != .linux) {
        std.debug.print("skipping unsafe-chroot integration: Linux is required\n", .{});
        return;
    }
    const explicitly_requested = if (init.environ_map.get(
        "MIZ_RUN_PRIVILEGED_TEST",
    )) |value|
        std.mem.eql(u8, value, "1")
    else
        false;
    const privileged_child = argv.len == 2 and
        std.mem.eql(u8, argv[1], "--privileged");
    if (!explicitly_requested and !privileged_child) {
        std.debug.print(
            "skipping unsafe-chroot integration: set MIZ_RUN_PRIVILEGED_TEST=1 to opt in\n",
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
    if (miz.unsafe_chroot.available(io) != .available) {
        return error.UnsafeChrootHostUnavailable;
    }

    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    const work_path = try std.fmt.allocPrint(
        allocator,
        "/tmp/miz-unsafe-chroot-integration-{s}",
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
    const offline_output_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "offline-output.raw" },
    );
    // Deliberately not created here: the populating run's whole claim is that
    // it produces the directory a later offline run reads.
    const cache_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "package-cache" },
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
        .{},
    );

    const actions = [_]miz.customize.PackageAction{
        .{ .install = &.{"integration-package"} },
        .{ .remove = &.{"obsolete-package"} },
    };
    const repositories = [_]miz.customize.PackageRepository{.{
        .id = "integration",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "integration trust\n" }},
    }};
    const architecture: miz.customize.Architecture = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => return error.UnsupportedArchitecture,
    };
    // The identity the stub `rpm -qa` reports, so the run has a lock that can
    // actually hold. The install below is checked against the pinned spec
    // rather than the bare name, which is the observable difference between a
    // lock that is enforced and one that is merely recorded.
    const lock = [_]miz.customize.PackageVersionLock{.{
        .name = "integration-package",
        .evr = "0:1.0-1",
        .architecture = @tagName(builtin.cpu.arch),
    }};
    // One request shape, two cache policies: the offline rebuild below differs
    // from this run only in where its packages came from, which is what makes
    // the comparison say something about the cache rather than about two
    // unrelated builds.
    var request = miz.customize.Request{
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
            .cache = .{ .online_populating = cache_path },
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.0-integration"},
        } },
        .boot_security = .{ .extra_kernel_options = "console=ttyS0" },
        .selinux = .relabel,
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
    var resolved = try miz.customize.resolve(allocator, &request, .{
        .host_architecture = architecture,
    });
    defer resolved.deinit(allocator);
    if (resolved.plan == null or resolved.diagnostics.hasErrors()) {
        return error.IntegrationResolutionFailed;
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
    if (!preflight.ready()) return error.IntegrationPreflightFailed;

    var outcome = try miz.customize.execute(
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
    // Every command the run spawned, in the order it spawned them. The count
    // is not pinned -- a mount added later is a real change to what the run
    // does, and a test that fails on it teaches nothing -- but the shape is:
    // the privileged plumbing that staged the image, the work done inside the
    // target root, and the teardown that released it, in that order.
    try ensure(std.mem.eql(u8, result.provenance.tools[0].name, "unshare"));
    try ensure(result.provenance.tools[0].context == .host);
    for ([_][]const u8{
        "losetup",
        "mount",
        "mknod",
        "rpm",
        "tdnf",
        "dracut",
        "cp",
        "grub2-mkconfig",
        "setfiles",
        "sync",
        "umount",
    }) |name| {
        try ensure(indexOfTool(result.provenance.tools, name) != null);
    }
    // Staging before customization before teardown. Before #308 the report
    // held only the middle of this, so an image could not be traced back to
    // the loop device and mounts it was built through.
    try ensure(
        indexOfTool(result.provenance.tools, "mount").? <
            indexOfTool(result.provenance.tools, "tdnf").?,
    );
    try ensure(
        indexOfTool(result.provenance.tools, "tdnf").? <
            indexOfTool(result.provenance.tools, "umount").?,
    );
    // The relabel is the case the optional version exists for: `setfiles`
    // takes no `--version`, and the fixed table this replaced recorded that
    // as an empty string, indistinguishable from a tool that answered blank.
    for (result.provenance.tools) |tool| {
        try ensure(tool.name.len != 0);
        try ensure(tool.command.len != 0);
        if (std.mem.eql(u8, tool.name, "setfiles")) try ensure(tool.version == null);
        // A probe is recorded as the version of the command it describes,
        // never as a command of its own.
        for (tool.command) |argument| {
            try ensure(!std.mem.eql(u8, argument, "--version"));
        }
    }
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
        try ensure(std.mem.eql(u8, tool.version orelse "", "grub2-mkconfig integration-1"));
        try ensure(tool.command.len == 3);
        try ensure(std.mem.eql(u8, tool.command[1], "-o"));
        try ensure(std.mem.eql(u8, tool.command[2], "/boot/grub2/grub.cfg"));
    }
    try ensure(generator_recorded);

    // The relabel ran the tool the target carries, against the policy the
    // target's own configuration names -- neither was supplied by the caller.
    // The recorded command is the audit trail the run publishes for it.
    var relabel_recorded = false;
    for (result.provenance.tools) |tool| {
        if (!std.mem.eql(u8, tool.name, "setfiles")) continue;
        relabel_recorded = true;
        try ensure(tool.command.len == integration_relabel_argv.len);
        for (tool.command, integration_relabel_argv) |actual, expected| {
            try ensure(std.mem.eql(u8, actual, expected));
        }
    }
    try ensure(relabel_recorded);
    // Written by the tool from inside the chroot, so this is the command as
    // the target saw it rather than as the parent composed it.
    try expectOutputFile(
        allocator,
        io,
        output_path,
        integration_relabel_marker,
        integration_relabel_command ++ "\n",
    );

    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/var/lib/miz-integration/trust",
        "trusted\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/var/lib/miz-integration/installed",
        installed_nevra ++ "\n",
    );
    try expectOutputFile(
        allocator,
        io,
        output_path,
        "/var/lib/miz-integration/removed",
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
        "/var/lib/miz-integration/installed",
    );

    try expectPathAbsent(io, resolved.plan.?.data.transaction_path);

    // The directory the run was told to fill exists on the host and holds
    // what the transaction put there: the bind carried writes outwards, so
    // the cache outlives the workspace the run mounted it into.
    const populated = preserved.package_cache orelse
        return error.MissingPackageCacheProvenance;
    try ensure(!populated.offline);
    try ensure(std.mem.eql(u8, populated.host_path, cache_path));
    try ensure(std.mem.eql(u8, populated.guest_path, "/run/miz-cache"));
    try expectHostFile(
        allocator,
        io,
        cache_path,
        integration_cache_download,
        integration_cache_payload ++ "\n",
    );

    // The same request again, reading the directory the first run filled and
    // reaching no network. Everything else is held constant, so a difference
    // in the result is a difference the cache policy made.
    request.output.path = offline_output_path;
    request.packages.cache = .{ .cache_only = cache_path };
    var offline_resolved = try miz.customize.resolve(allocator, &request, .{
        .host_architecture = architecture,
    });
    defer offline_resolved.deinit(allocator);
    if (offline_resolved.plan == null or offline_resolved.diagnostics.hasErrors()) {
        return error.IntegrationResolutionFailed;
    }
    // Where the packages came from is part of what the plan says, so two runs
    // that could have installed different bytes are not one plan.
    try ensure(!std.mem.eql(
        u8,
        &resolved.plan.?.data.plan_hash.bytes,
        &offline_resolved.plan.?.data.plan_hash.bytes,
    ));
    var offline_preflight = try miz.customize.preflight(
        allocator,
        io,
        &offline_resolved.plan.?,
        platform,
    );
    defer offline_preflight.deinit(allocator);
    if (!offline_preflight.ready()) return error.IntegrationPreflightFailed;

    var offline_outcome = try miz.customize.execute(
        allocator,
        io,
        &offline_resolved.plan.?,
        platform,
        null,
    );
    defer offline_outcome.deinit(allocator);
    const offline_result = offline_outcome.result orelse
        return error.IntegrationExecutionFailed;
    if (offline_outcome.diagnostics.hasErrors()) {
        return error.IntegrationExecutionFailed;
    }
    for (offline_outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) {
            return error.IntegrationCleanupFailed;
        }
    }
    const offline_preserved = offline_result.provenance.execution.preserved orelse
        return error.MissingPreservedProvenance;
    const consumed = offline_preserved.package_cache orelse
        return error.MissingPackageCacheProvenance;
    try ensure(consumed.offline);
    try ensure(std.mem.eql(u8, consumed.host_path, cache_path));
    try ensure(std.mem.eql(u8, consumed.guest_path, "/run/miz-cache"));

    // The run that read the cache installed the same package the run that
    // filled it did. The stub records what it was asked for, so this is the
    // transaction being reproduced rather than the image being copied.
    try expectOutputFile(
        allocator,
        io,
        offline_output_path,
        "/var/lib/miz-integration/installed",
        installed_nevra ++ "\n",
    );
    try ensure(offline_preserved.emitted_package_lock.len == 1);
    try ensure(std.mem.eql(
        u8,
        offline_preserved.emitted_package_lock[0].name,
        "integration-package",
    ));
    // The offline run's target is left with the resolver the image shipped,
    // untouched, because the run installed none over it.
    try expectOutputFile(
        allocator,
        io,
        offline_output_path,
        "/etc/resolv.conf",
        "nameserver 192.0.2.1\n",
    );
    // Read-only in, read-only out: nothing the offline run did reached the
    // directory it was reproducing from.
    try expectMissingHostFile(io, cache_path, "offline-write");

    try expectPathAbsent(io, offline_resolved.plan.?.data.transaction_path);

    try runDeadlineIntegration(
        allocator,
        io,
        platform,
        request,
        work_path,
        architecture,
    );

    try runForeignRootIntegration(
        allocator,
        io,
        self_exe,
        platform,
        request,
        work_path,
        architecture,
    );

    try Io.Dir.cwd().deleteTree(io, work_path);
    completed = true;
    std.debug.print("unsafe-chroot privileged integration passed\n", .{});
}

/// How long the hung hook is given before the run's budget stops it. Long
/// enough that the copy, the package transaction and the initramfs step ahead
/// of it are not the thing that expires -- the point is a run stopped inside a
/// command that would never return, not a budget that was too small to reach
/// one.
const deadline_integration_seconds: u32 = 20;

/// A run that hangs is stopped by its deadline, and stopped cleanly.
///
/// The hook here never returns. Nothing else in the suite can produce that:
/// every other stub finishes, and a backend that only ever ran finishing
/// commands would report a bounded run whether or not the bound worked. What
/// is asserted afterwards is the part that is easy to get wrong -- the host is
/// left holding nothing. The worker is killed mid-run, so its mounts, its loop
/// device and its transaction directory all have to be gone anyway.
fn runDeadlineIntegration(
    allocator: Allocator,
    io: Io,
    platform: miz.customize.Platform,
    base_request: miz.customize.Request,
    work_path: []const u8,
    architecture: miz.customize.Architecture,
) !void {
    const output_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "deadline-output.raw" },
    );
    const loops_before = try countAttachedLoops(allocator, io);

    // The hook names an interpreter this root does carry: the same test
    // binary the package stubs are, under a name that makes it sleep. The
    // script itself is never reached, which is the point -- what is being
    // bounded is a command that has started and will not finish.
    const hooks = [_]miz.customize.Hook{.{
        .name = "hang",
        .phase = .before_seal,
        .source = .{ .inline_script = "#!/usr/bin/hang\n" },
    }};
    var request = base_request;
    request.output.path = output_path;
    request.hooks = &hooks;
    // A hook paired with declared repositories is a network consumer even
    // when the package transaction was copied from a cache-only request. This
    // deadline test is about stopping the hook, not that mixed networking
    // policy, so let its package setup use the ordinary online path.
    request.packages.cache = .online;
    request.execution.deadline_seconds = deadline_integration_seconds;

    var resolved = try miz.customize.resolve(allocator, &request, .{
        .host_architecture = architecture,
    });
    defer resolved.deinit(allocator);
    if (resolved.plan == null or resolved.diagnostics.hasErrors()) {
        return error.IntegrationResolutionFailed;
    }
    try ensure(resolved.plan.?.data.execution.deadline_seconds.? ==
        deadline_integration_seconds);

    var outcome = try miz.customize.execute(
        allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(allocator);
    // A run that ran out of time publishes nothing and says why in the one
    // code that means "give it more time".
    if (outcome.result != null) return error.DeadlineRunProducedResult;
    var reported = false;
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) return error.IntegrationCleanupFailed;
        if (diagnostic.code != .deadline_exceeded) continue;
        reported = true;
    }
    if (!reported) {
        for (outcome.diagnostics.items) |diagnostic| {
            std.debug.print(
                "deadline run diagnostic: {s} {s}: {s}\n",
                .{ @tagName(diagnostic.code), diagnostic.configuration_path, diagnostic.message },
            );
        }
        return error.DeadlineNotReported;
    }

    try expectPathAbsent(io, output_path);
    // The transaction is removed rather than abandoned, which is the whole
    // difference between a deadline the worker enforced and a worker the
    // parent had to kill: only the first can finish its own teardown.
    try expectPathAbsent(io, resolved.plan.?.data.transaction_path);
    // Loop devices are global, so a worker killed while holding one would
    // leave it attached to a file this test is about to delete.
    try ensure(try countAttachedLoops(allocator, io) == loops_before);
}

/// A root with no `/usr/bin/tdnf` and an `/usr/bin/apt-get` instead is refused
/// by name, before the run writes anything into it.
///
/// This is the behaviour the documentation already claimed and the code did
/// not have: the tool paths were plain `runChroot` argv, so this root used to
/// fail with a generic non-zero exit from a chroot that could not exec a path,
/// partway through a run that had already placed credential-bearing repository
/// files in the image.
fn runForeignRootIntegration(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    platform: miz.customize.Platform,
    base_request: miz.customize.Request,
    work_path: []const u8,
    architecture: miz.customize.Architecture,
) !void {
    const foreign_source_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "foreign-source.raw" },
    );
    const foreign_spool_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "foreign-root.spool" },
    );
    const output_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "foreign-output.raw" },
    );
    try createSourceDisk(
        allocator,
        io,
        self_exe,
        foreign_source_path,
        foreign_spool_path,
        .{ .package_manager = false, .foreign_package_manager = true },
    );

    var request = base_request;
    request.input = .{ .disk = .{ .path = foreign_source_path } };
    request.output.path = output_path;
    // The cache policy of the base request names a directory the populating
    // run created. This run must fail before it would have been consulted.
    request.packages.cache = .online;

    var resolved = try miz.customize.resolve(allocator, &request, .{
        .host_architecture = architecture,
    });
    defer resolved.deinit(allocator);
    // The refusal is a run failure by design, not a plan-time one: for an
    // ISO+container input the root does not exist until the run assembles it,
    // so nothing before the run could have answered this.
    if (resolved.plan == null or resolved.diagnostics.hasErrors()) {
        return error.ForeignRootResolutionFailed;
    }

    var outcome = try miz.customize.execute(
        allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(allocator);
    if (outcome.result != null) return error.ForeignRootProducedResult;

    // The worker's own error name is not asserted here, and cannot be: the
    // privilege boundary is a status file carrying two tokens, so every
    // worker-side failure reaches the parent as `execution_failed`. What this
    // scenario establishes is that the root is refused rather than half
    // customized; that the refusal is `UnsupportedPackageManagerFamily`
    // rather than a generic exec failure is established by the unit tests
    // over `packages.toolVerdict` and by the guest agent, whose channel does
    // carry the name.
    var failed = false;
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) return error.IntegrationCleanupFailed;
        if (diagnostic.code == .execution_failed) failed = true;
    }
    if (!failed) return error.ForeignRootNotRefused;

    // Refused before anything was written: no output, and the transaction the
    // run would have built in is gone.
    try expectPathAbsent(io, output_path);
    try expectPathAbsent(io, resolved.plan.?.data.transaction_path);

    // The gating fence, and the part of this change most likely to break
    // something that worked: the *same* root, with a request that asks for no
    // package transaction and no trust, must still customize. A root with no
    // package manager is a legitimate thing to build from as long as nothing
    // needs one -- the rule `os_customization.applyServices` already follows
    // when it returns on an empty service list before refusing anything.
    const quiet_output_path = try std.fs.path.join(
        allocator,
        &.{ work_path, "foreign-quiet-output.raw" },
    );
    var quiet = base_request;
    quiet.input = .{ .disk = .{ .path = foreign_source_path } };
    quiet.output.path = quiet_output_path;
    quiet.packages = .{};
    quiet.initramfs = .unchanged;
    quiet.selinux = .unchanged;
    quiet.boot_security = .{};

    var quiet_resolved = try miz.customize.resolve(allocator, &quiet, .{
        .host_architecture = architecture,
    });
    defer quiet_resolved.deinit(allocator);
    if (quiet_resolved.plan == null or quiet_resolved.diagnostics.hasErrors()) {
        return error.QuietRootResolutionFailed;
    }

    var quiet_outcome = try miz.customize.execute(
        allocator,
        io,
        &quiet_resolved.plan.?,
        platform,
        null,
    );
    defer quiet_outcome.deinit(allocator);
    if (quiet_outcome.result == null) {
        for (quiet_outcome.diagnostics.items) |diagnostic| {
            std.debug.print(
                "quiet-root diagnostic: {s} {s}: {s}\n",
                .{ @tagName(diagnostic.code), diagnostic.configuration_path, diagnostic.message },
            );
        }
        return error.QuietRootRefused;
    }
}

fn countAttachedLoops(allocator: Allocator, io: Io) !usize {
    const result = std.process.run(allocator, io, .{
        .argv = &.{ "/usr/sbin/losetup", "--list", "--output", "NAME", "--noheadings" },
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
    }) catch return 0;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    var count: usize = 0;
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len != 0) count += 1;
    }
    return count;
}

/// What the populating run leaves in the cache directory and the offline run
/// finds there. Standing in for the downloaded packages `keepcache` keeps: the
/// point under test is that one run's writes are the other run's inputs, not
/// that the bytes are an RPM.
const integration_cache_download = "integration-package.rpm";
const integration_cache_payload = "integration cache payload";

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

/// How the staged root differs from the supported one.
///
/// Only ever used to build a root this backend must *refuse*: the supported
/// shape is the default and every existing scenario takes it.
const SourceDiskShape = struct {
    /// Stage `/usr/bin/tdnf`. A root without it is one no package transaction
    /// can run in.
    package_manager: bool = true,
    /// Stage `/usr/bin/apt-get` as well, so the root carries evidence of a
    /// family this project does not target.
    foreign_package_manager: bool = false,
};

fn createSourceDisk(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    source_path: []const u8,
    spool_path: []const u8,
    shape: SourceDiskShape,
) !void {
    const executable = try Io.Dir.cwd().readFileAlloc(
        io,
        self_exe,
        allocator,
        .limited(fixture_executable_max_size),
    );
    defer allocator.free(executable);

    var image = try miz.Image.createExclusive(
        io,
        source_path,
        .raw,
        disk_size,
        .{},
    );
    defer image.close(io);
    const boot_record = miz.mbr.singleLinuxPartitionMbr(
        partition_first_lba,
        partition_sectors,
    ).encode();
    try image.pwrite(io, &boot_record, 0);

    var tree = try miz.root_tree.RootTree.init(
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
        "etc/selinux",
        "etc/selinux/" ++ integration_selinux_policy,
        "etc/selinux/" ++ integration_selinux_policy ++ "/contexts",
        "etc/selinux/" ++ integration_selinux_policy ++ "/contexts/files",
        "proc",
        "run",
        "sys",
        "usr",
        "usr/bin",
        "usr/sbin",
        "var",
        "var/lib",
        "var/lib/miz-integration",
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
    if (shape.package_manager) {
        try tree.putSymlink("usr/bin/tdnf", "rpm", .{ .mode = 0o777 });
    }
    if (shape.foreign_package_manager) {
        try tree.putSymlink("usr/bin/apt-get", "rpm", .{ .mode = 0o777 });
    }
    try tree.putSymlink("usr/bin/dracut", "rpm", .{ .mode = 0o777 });
    try tree.putSymlink("usr/bin/cp", "rpm", .{ .mode = 0o777 });
    // The interpreter the deadline run's hook names. A hook has to name one,
    // and this root carries no shell.
    try tree.putSymlink("usr/bin/hang", "rpm", .{ .mode = 0o777 });
    try tree.putSymlink("usr/sbin/grub2-mkconfig", "../bin/rpm", .{ .mode = 0o777 });
    // The labelling tool and the policy it labels against, both carried by
    // the target the way a real SELinux-enabled image carries them. The
    // preflight probe reads these out of this disk before the run starts, so
    // a root missing any of them is refused rather than half-relabelled.
    try tree.putSymlink("usr/sbin/setfiles", "../bin/rpm", .{ .mode = 0o777 });
    try tree.putFileBytes(
        "etc/selinux/config",
        "SELINUX=enforcing\nSELINUXTYPE=" ++ integration_selinux_policy ++ "\n",
        .{ .mode = 0o644 },
    );
    try tree.putFileBytes(
        "etc/selinux/" ++ integration_selinux_policy ++ "/contexts/files/file_contexts",
        "/.*  system_u:object_r:default_t:s0\n",
        .{ .mode = 0o644 },
    );
    _ = try miz.ext4.populate(
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

/// The policy this target ships. Deliberately not `targeted`: the run has to
/// read the name out of the target's own configuration, and a name every real
/// image also uses would not tell a read apart from a default.
const integration_selinux_policy = "integration";

const integration_relabel_marker = "/var/lib/miz-integration/relabel";

const integration_relabel_argv = [_][]const u8{
    "/usr/sbin/setfiles",
    "-F",
    "-e",
    "/proc",
    "-e",
    "/sys",
    "-e",
    "/dev",
    "-e",
    "/run",
    "/etc/selinux/" ++ integration_selinux_policy ++ "/contexts/files/file_contexts",
    "/",
};

const integration_relabel_command = "/usr/sbin/setfiles -F " ++
    "-e /proc -e /sys -e /dev -e /run " ++
    "/etc/selinux/" ++ integration_selinux_policy ++ "/contexts/files/file_contexts /";

/// Stands in for the target's `setfiles`. It checks the file-contexts file it
/// was pointed at is one this root actually carries -- a relabel against a
/// policy that is not there is the failure the preflight probe exists to
/// prevent -- and records the command for the run to be checked against.
fn runGuestSetfiles(allocator: Allocator, io: Io, args: []const []const u8) !void {
    if (args.len < 3) return error.UnexpectedSetfilesInvocation;
    const contexts = args[args.len - 2];
    const contexts_file = Io.Dir.cwd().openFile(io, contexts, .{
        .mode = .read_only,
        .allow_directory = false,
    }) catch return error.MissingSelinuxFileContexts;
    contexts_file.close(io);
    if (!std.mem.eql(u8, args[args.len - 1], "/")) {
        return error.UnexpectedSetfilesInvocation;
    }
    const command = try std.mem.join(allocator, " ", args);
    defer allocator.free(command);
    const full = try std.fmt.allocPrint(
        allocator,
        "/usr/sbin/setfiles {s}",
        .{command},
    );
    defer allocator.free(full);
    try writeGuestMarker(io, integration_relabel_marker, full);
}

/// Sleeps far past any budget a test would set, in one call rather than a
/// loop, so the process is asleep in a syscall when it is killed -- which is
/// where a hung `tdnf` or `dracut` would be too.
fn runGuestHangingHook(io: Io) !void {
    try Io.sleep(io, Io.Duration.fromSeconds(3600), .awake);
}

fn runGuestRpm(io: Io, args: []const []const u8) !void {
    if (containsArg(args, "--version")) {
        std.debug.print("RPM version integration-1\n", .{});
        return;
    }
    if (containsArg(args, "--import")) {
        const trust_path = argumentImmediatelyAfter(args, "--import") orelse
            return error.UnexpectedRpmInvocation;
        if (!std.mem.eql(u8, trust_path, "/run/miz-trust-0.asc")) {
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
            "/var/lib/miz-integration/trust",
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
        if (guestPathExists(io, "/var/lib/miz-integration/trust")) {
            std.debug.print("{s}\n", .{declared_trust_nevra});
        }
        if (guestPathExists(io, "/var/lib/miz-integration/installed")) {
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
    // `--cacheonly` is what makes an offline run fail rather than fetch, so
    // the branch below is keyed on the same argument the real tdnf would act
    // on rather than on anything the test arranged separately.
    const offline = containsArg(args, "--cacheonly");
    try checkGuestCacheConfiguration(io);
    if (offline) {
        // The other run's download, seen from inside this one. This is the
        // whole claim of a declared cache: one build filled a host directory
        // and another read it.
        try expectGuestFile(
            io,
            "/run/miz-cache/" ++ integration_cache_download,
            integration_cache_payload ++ "\n",
        );
        // Bound read-only, so the run cannot change the input it is
        // reproducing from. Left behind on the host if it ever succeeds, so
        // the parent can say so rather than the failure being swallowed here.
        if (Io.Dir.cwd().createFile(
            io,
            "/run/miz-cache/offline-write",
            .{},
        )) |file| {
            file.close(io);
            return error.OfflineCacheWasWritable;
        } else |_| {}
        // No resolver at all rather than one that resolves nothing: with no
        // `/etc/resolv.conf` the target cannot reach a name server even if
        // something in it tried.
        if (guestPathExists(io, "/run/miz-resolv.conf")) {
            return error.OfflineRunCarriedResolver;
        }
    } else {
        if (!guestPathExists(io, "/run/miz-resolv.conf")) {
            return error.OnlineRunLackedResolver;
        }
        try writeGuestMarker(
            io,
            "/run/miz-cache/" ++ integration_cache_download,
            integration_cache_payload,
        );
    }
    if (argumentAfter(args, "install")) |package| {
        try writeGuestMarker(
            io,
            "/var/lib/miz-integration/installed",
            package,
        );
        return;
    }
    if (argumentAfter(args, "remove")) |package| {
        try writeGuestMarker(
            io,
            "/var/lib/miz-integration/removed",
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

/// The cache reaches tdnf as configuration rather than as a command-line
/// flag, because the tdnf the target images ship has no flag that names one.
/// Checked from inside the run, so the assertion is about what the package
/// manager was actually told.
fn checkGuestCacheConfiguration(io: Io) !void {
    var buffer: [512]u8 = undefined;
    const file = try Io.Dir.cwd().openFile(io, "/run/miz-tdnf.conf", .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    });
    defer file.close(io);
    const size = (try file.stat(io)).size;
    if (size > buffer.len) return error.UnexpectedTdnfConfiguration;
    const length: usize = @intCast(size);
    const read = try file.readPositionalAll(io, buffer[0..length], 0);
    const body = buffer[0..read];
    if (std.mem.indexOf(u8, body, "cachedir=/run/miz-cache\n") == null or
        std.mem.indexOf(u8, body, "keepcache=1\n") == null)
    {
        return error.UnexpectedTdnfConfiguration;
    }
}

fn expectGuestFile(io: Io, path: []const u8, expected: []const u8) !void {
    var buffer: [512]u8 = undefined;
    if (expected.len > buffer.len) return error.UnexpectedGuestFile;
    const file = Io.Dir.cwd().openFile(io, path, .{
        .mode = .read_only,
        .allow_directory = false,
        .follow_symlinks = false,
    }) catch return error.MissingGuestFile;
    defer file.close(io);
    const read = try file.readPositionalAll(io, buffer[0..expected.len], 0);
    if (!std.mem.eql(u8, buffer[0..read], expected)) {
        return error.UnexpectedGuestFile;
    }
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
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
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
    var image = try miz.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try miz.ext4.open(io, image.file, allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    _ = reader.statPath(io, guest_path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    return error.UnexpectedGuestFile;
}

/// The cache directory is on the host filesystem rather than inside an image,
/// which is the point: it is the one thing a build leaves behind for the next
/// one to read.
fn expectHostFile(
    allocator: Allocator,
    io: Io,
    directory: []const u8,
    name: []const u8,
    expected: []const u8,
) !void {
    const path = try std.fs.path.join(allocator, &.{ directory, name });
    defer allocator.free(path);
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, expected)) return error.UnexpectedHostFile;
}

fn expectMissingHostFile(io: Io, directory: []const u8, name: []const u8) !void {
    var buffer: [std.fs.max_path_bytes]u8 = undefined;
    const path = std.fmt.bufPrint(
        &buffer,
        "{s}/{s}",
        .{ directory, name },
    ) catch return error.UnexpectedHostFile;
    try expectPathAbsent(io, path);
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

/// Where a tool first appears in the run-ordered record of every command the
/// run spawned. Looked up by name rather than pinned to an index, because the
/// list now includes the host plumbing and its length is a detail of how many
/// mounts the policy needed.
fn indexOfTool(tools: []const miz.customize.ToolRecord, name: []const u8) ?usize {
    for (tools, 0..) |tool, index| {
        if (std.mem.eql(u8, tool.name, name)) return index;
    }
    return null;
}

fn ensure(condition: bool) !void {
    if (!condition) return error.IntegrationAssertionFailed;
}
