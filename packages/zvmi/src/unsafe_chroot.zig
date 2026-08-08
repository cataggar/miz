const std = @import("std");
const builtin = @import("builtin");
const boot_options = @import("boot_options.zig");
const credential_mod = @import("credential.zig");
const customize = @import("customize.zig");
const grub_defaults = @import("grub_defaults.zig");
const os_customization = @import("os_customization.zig");
const preserved_image = @import("preserved_image.zig");
const selinux_mod = @import("selinux.zig");
const transaction_guard = @import("transaction_guard.zig");
const vm_control = @import("vm_control.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const max_command_output = 1024 * 1024;
const loop_settle_attempts = 20;
const loop_settle_interval = std.Io.Duration.fromMilliseconds(100);
const worker_started_text = "worker-started\n";
const cleanup_complete_text = "cleanup-complete\n";
/// Written by a worker that stopped because the run's budget was spent, after
/// its cleanup finished. A separate token rather than a non-zero exit, because
/// the parent has to tell "the run ran out of time" from "a command failed"
/// and both leave the same exit status.
const deadline_exceeded_text = "deadline-exceeded\n";
/// What the worker's own teardown gets after the run stops, whether it stopped
/// by finishing, by failing or by running out of time. Shorter than the
/// parent's grace, so a worker that cannot finish its teardown still reports
/// that itself rather than being killed mid-report.
const cleanup_deadline_seconds: u32 = 90;
/// How much longer than the run's deadline the parent waits for the worker.
///
/// The worker enforces the deadline over its own children and then unmounts,
/// detaches the loop device and removes the guest root; that teardown starts
/// when the budget is already spent, so a parent that gave up at the same
/// instant would kill the only process that can finish it. The grace exists to
/// let the graceful path win, and the parent's own bound exists because a
/// worker wedged in that teardown must not hang the build either.
const worker_cleanup_grace_seconds: u32 = 120;

/// How much of the target's `/etc/selinux/config` is read to find the policy
/// name. The file is a handful of `KEY=value` lines in every distribution that
/// ships one, so anything past this is not the file this expects.
const max_selinux_config_bytes: usize = 64 * 1024;

pub const active_lease_basename = transaction_guard.active_lease_basename;
pub const activeLeasePath = transaction_guard.activeLeasePath;

pub const ParentOptions = struct {
    self_exe: []const u8,
    transaction_path: []const u8,
    plan: *const customize.ResolvedPlan,
    target: preserved_image.RawMutationTarget,
    /// Read only for the variables a declared credential names.
    environ: std.process.Environ = .empty,
    /// What is left of the run's budget. `.unbounded` is every caller that
    /// declared no deadline.
    deadline: customize.Deadline = .unbounded,
};

const Manifest = struct {
    raw_path: []const u8,
    root_path: []const u8,
    status_path: []const u8,
    report_path: []const u8,
    stage_inode: u64,
    virtual_size: u64,
    partition_offset: u64,
    partition_length: u64,
    packages: customize.PackagePolicy,
    initramfs: customize.InitramfsPolicy,
    kernel_modules: []const customize.KernelModule = &.{},
    /// Kernel command-line options to add to the target's own bootloader
    /// configuration. Empty means the run changes none.
    kernel_options: []const u8 = "",
    hooks: []const customize.Hook = &.{},
    /// Whether the run relabels the root filesystem before it is sealed.
    selinux: customize.SelinuxPolicy = .unchanged,
    /// What was left of the run's budget when the worker was spawned, in whole
    /// seconds. Passed as a remainder rather than as an absolute time because
    /// the worker is a separate process and only one of them owns the clock
    /// the budget started on. Absent means the run declared no deadline.
    deadline_seconds: ?u32 = null,
};

/// Where the distro's own bootloader tooling is looked for inside the target
/// root, in the order the two spellings of the same program are tried.
/// `grub2-` is the Red Hat family's rename, `grub-` is everyone else's.
const guest_generator_candidates = [_][]const u8{
    "/usr/sbin/grub2-mkconfig",
    "/usr/bin/grub2-mkconfig",
    "/sbin/grub2-mkconfig",
    "/usr/sbin/grub-mkconfig",
    "/usr/bin/grub-mkconfig",
    "/sbin/grub-mkconfig",
};

/// The configuration file the generator is asked to write, in the order the
/// two directory layouts are tried. A target has one or the other, never
/// both, and the one it has is where its bootloader reads from.
const guest_generated_candidates = [_][]const u8{
    "/boot/grub2/grub.cfg",
    "/boot/grub/grub.cfg",
};

/// Where a declared host cache directory is bound. Under the private `/run`
/// tmpfs, which is unmounted before anything is published, so the binding
/// cannot reach the image even if the transaction leaves the cache dirty.
const guest_cache_directory = "/run/zvmi-cache";

const guest_grub_defaults = "/etc/default/grub";
const guest_kernel_cmdline = "/etc/kernel/cmdline";
const guest_fstab = "/etc/fstab";

pub fn available(io: Io) customize.CapabilityState {
    if (builtin.os.tag != .linux or
        std.os.linux.geteuid() != 0 or
        !hasRequiredCapabilities() or
        !isCharacterDevice(io, "/dev/loop-control"))
    {
        return .missing;
    }
    inline for (.{
        unshare_candidates,
        losetup_candidates,
        mount_candidates,
        umount_candidates,
        chroot_candidates,
        mknod_candidates,
        sync_candidates,
        true_candidates,
    }) |candidates| {
        const tool = findTool(io, candidates) orelse return .missing;
        Io.Dir.cwd().access(io, tool, .{ .execute = true }) catch return .missing;
    }
    return if (probeUnshare(io)) .available else .missing;
}

pub fn runParent(
    allocator: Allocator,
    io: Io,
    options: ParentOptions,
) !customize.UnsafeChrootRuntimeReport {
    if (available(io) != .available) return error.UnsafeChrootHostUnavailable;
    const manifest_path = try std.fs.path.join(
        allocator,
        &.{ options.transaction_path, "unsafe-chroot.json" },
    );
    defer allocator.free(manifest_path);
    const root_path = try std.fs.path.join(
        allocator,
        &.{ options.transaction_path, "guest-root" },
    );
    defer allocator.free(root_path);
    const status_path = try std.fs.path.join(
        allocator,
        &.{ options.transaction_path, "unsafe-chroot.status" },
    );
    defer allocator.free(status_path);
    const report_path = try std.fs.path.join(
        allocator,
        &.{ options.transaction_path, "unsafe-chroot-report.json" },
    );
    defer allocator.free(report_path);

    var lease = try transaction_guard.acquire(io, options.transaction_path);
    var lease_active = true;
    defer if (lease_active) lease.abandon(io);
    errdefer if (lease_active) {
        lease.release(io) catch lease.abandon(io);
        lease_active = false;
    };

    Io.Dir.cwd().deleteFile(io, status_path) catch {};
    Io.Dir.cwd().deleteFile(io, report_path) catch {};

    const manifest = Manifest{
        .raw_path = options.target.raw_path,
        .root_path = root_path,
        .status_path = status_path,
        .report_path = report_path,
        .stage_inode = options.target.stage_inode,
        .virtual_size = options.target.virtual_size,
        .partition_offset = options.target.partition.offset,
        .partition_length = options.target.partition.length,
        .packages = options.plan.data.packages,
        .initramfs = options.plan.data.initramfs,
        .kernel_modules = options.plan.data.os.kernel_modules,
        .kernel_options = options.plan.data.boot_security.extra_kernel_options,
        .hooks = options.plan.data.hooks,
        .selinux = options.plan.data.selinux,
        // What is left of the budget at the moment the worker starts, not what
        // the run declared: the copy that produced the raw stage has already
        // been paid for out of the same budget.
        .deadline_seconds = options.deadline.remainingSeconds(io),
    };
    const json = try std.json.Stringify.valueAlloc(allocator, manifest, .{});
    defer allocator.free(json);
    try writeBytes(io, manifest_path, json);

    const unshare = findTool(io, unshare_candidates).?;
    const argv = [_][]const u8{
        unshare,
        "--mount",
        "--pid",
        "--fork",
        "--kill-child",
        "--mount-proc",
        "--propagation",
        "private",
        "--",
        options.self_exe,
        "--unsafe-chroot-worker",
        manifest_path,
    };
    var environment = try baseEnvironment(allocator);
    defer environment.deinit();
    // The worker's environment is built rather than inherited, so a declared
    // credential variable has to be forwarded by name. The exception is exactly
    // as wide as the plan says it is, and the plan hash covers the names. It
    // goes no further: the worker builds a fresh environment for every command
    // it runs, from `baseEnvironment` alone.
    try forwardCredentialVariables(allocator, options.environ, &environment, manifest);
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .environ_map = &environment,
        .stdin = .ignore,
        // Piped rather than inherited so the parent has somewhere to enforce
        // its own bound. `Child.wait` takes no deadline, so a parent that
        // handed the worker its own descriptors would have nothing left to do
        // but block forever on a worker that never returns.
        .stdout = .pipe,
        .stderr = .pipe,
    }) catch |err| {
        lease.release(io) catch {
            lease.abandon(io);
            lease_active = false;
            return error.MutationResourcesActive;
        };
        lease_active = false;
        return err;
    };
    const supervision = superviseWorker(
        allocator,
        io,
        &child,
        options.deadline.withGrace(worker_cleanup_grace_seconds),
    ) catch {
        lease.abandon(io);
        lease_active = false;
        return error.MutationResourcesActive;
    };

    switch (classifyWorkerOutcome(io, status_path, supervision.term)) {
        .never_started => {
            lease.release(io) catch {
                lease.abandon(io);
                lease_active = false;
                return error.MutationResourcesActive;
            };
            lease_active = false;
            return if (supervision.timed_out)
                error.ExecutionDeadlineExceeded
            else
                error.UnsafeChrootWorkerFailed;
        },
        .cleanup_uncertain => {
            // Deliberately not reported as the deadline it may also have been.
            // Something may still hold the staging image, and that is the fact
            // the caller has to act on: it decides whether the transaction can
            // be removed, where the deadline only decides what to say about
            // why the run stopped.
            lease.abandon(io);
            lease_active = false;
            return error.MutationResourcesActive;
        },
        .cleanup_complete_deadline => {
            try lease.release(io);
            lease_active = false;
            return error.ExecutionDeadlineExceeded;
        },
        .cleanup_complete_failed => {
            try lease.release(io);
            lease_active = false;
            return if (supervision.timed_out)
                error.ExecutionDeadlineExceeded
            else
                error.UnsafeChrootWorkerFailed;
        },
        .cleanup_complete_success => {
            try lease.release(io);
            lease_active = false;
        },
    }
    return loadParentReport(allocator, io, report_path, &argv);
}

pub fn workerMain(init: std.process.Init, manifest_path: []const u8) !void {
    if (builtin.os.tag != .linux or std.os.linux.geteuid() != 0) {
        return error.UnsafeChrootHostUnavailable;
    }
    const allocator = init.arena.allocator();
    const bytes = try Io.Dir.cwd().readFileAlloc(
        init.io,
        manifest_path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    const parsed = try std.json.parseFromSlice(
        Manifest,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false },
    );
    try writeBytes(init.io, parsed.value.status_path, worker_started_text);
    var executor = Executor.system(init.minimal.environ);
    // The remainder the parent measured, restarted here as this process's own
    // budget. One conversion, at the start, so every command the worker runs
    // shares the deadline instead of each getting the whole of what is left.
    executor.deadline = .start(init.io, parsed.value.deadline_seconds);
    const result = try executeManifest(
        allocator,
        init.io,
        parsed.value,
        executor,
    );
    if (result.cleanup_complete) {
        if (result.outcome == .succeeded) {
            const report_json = try std.json.Stringify.valueAlloc(
                allocator,
                result.report,
                .{},
            );
            defer allocator.free(report_json);
            try writeBytes(init.io, parsed.value.report_path, report_json);
        }
        // The deadline gets its own token, written only once the teardown it
        // triggered has finished. The parent reads it as "the run ran out of
        // time and nothing is still held", which no exit status can say.
        try writeBytes(init.io, parsed.value.status_path, switch (result.outcome) {
            .deadline_exceeded => deadline_exceeded_text,
            else => cleanup_complete_text,
        });
    }
    if (!result.cleanup_complete) return error.UnsafeChrootCleanupFailed;
    switch (result.outcome) {
        .succeeded => {},
        .failed => return error.UnsafeChrootOperationFailed,
        .deadline_exceeded => return error.ExecutionDeadlineExceeded,
    }
}

/// Why the worker stopped. `failed` and `deadline_exceeded` both leave nothing
/// published, but only one of them is answered by giving the run more time.
const RunOutcome = enum {
    succeeded,
    failed,
    deadline_exceeded,
};

const ExecutionResult = struct {
    outcome: RunOutcome,
    cleanup_complete: bool,
    report: WorkerReport,
};

const WorkerReport = struct {
    tools: []const customize.ToolRecord,
    installed_packages: []const []const u8,
    /// Every package this transaction added or changed, at the exact identity
    /// it settled on. This is the lock a later run can state to get the same
    /// closure, which is why it is emitted whether or not one was declared:
    /// the run that has nothing to verify is exactly the run you want a lock
    /// out of.
    package_lock: []const customize.PackageVersionLock = &.{},
    /// Trust rpm derived from what this run imported, as
    /// `gpg-pubkey-<keyid>-<timestamp>`. The declared trust is recorded as
    /// bytes or a path; this is the key rpm actually verified signatures
    /// against, and it is also where trust nobody declared shows up.
    imported_trust_keys: []const []const u8 = &.{},
    hooks: []const customize.HookRecord = &.{},
    boot_configuration: ?customize.BootConfigurationRecord = null,
    package_cache: ?customize.PackageCacheRecord = null,
    selinux_relabel: ?customize.SelinuxRelabelRecord = null,
    selinux_configure: ?customize.SelinuxConfigureRecord = null,
    initramfs: ?customize.InitramfsRecord = null,
    host_resolver: ?customize.HostResolverRecord = null,
};

fn classifyRunFailure(err: anyerror) RunOutcome {
    return if (err == error.ExecutionDeadlineExceeded)
        .deadline_exceeded
    else
        .failed;
}

/// Kills and reaps everything else in this PID namespace.
///
/// The worker is PID 1 under `unshare --mount --pid --fork`, which is what
/// makes this both possible and safe: a process can only signal processes in
/// its own PID namespace, so `kill(-1)` from here reaches every descendant --
/// including the grandchildren a scriptlet left behind, which killing the
/// direct child does not -- and nothing outside. The guard is the whole
/// safety argument, so it is checked rather than assumed: the same code runs
/// in-process under the unit tests, where this must do nothing at all.
///
/// Reaping matters as much as killing. A signalled process still holds its
/// mounts until it is gone, and the unmount that follows is what makes the
/// difference between a transaction that cleaned up and one the caller has to
/// be warned about.
fn reapNamespace() void {
    if (builtin.os.tag != .linux) return;
    if (std.os.linux.getpid() != 1) return;
    _ = std.os.linux.kill(-1, .KILL);
    while (true) {
        var status: u32 = undefined;
        const rc = std.os.linux.waitpid(-1, &status, 0);
        switch (std.os.linux.errno(rc)) {
            .SUCCESS => continue,
            .INTR => continue,
            // No children left, which is the point at which the namespace
            // holds nothing but this process.
            .CHILD => return,
            else => return,
        }
    }
}

fn executeManifest(
    allocator: Allocator,
    io: Io,
    manifest: Manifest,
    executor: Executor,
) !ExecutionResult {
    if (manifest.partition_length == 0) return error.InvalidPartitionBounds;
    // Before anything is created, mounted or written. Every field this refuses
    // is one the worker would otherwise act on as root: the declared resolver
    // is rendered into the target root during `open`, well before `runPolicy`
    // is reached, so a check deferred to there would run after the bytes it
    // guards had already been placed.
    //
    // Reported as a refusal with cleanup complete rather than propagated,
    // because propagating out of `workerMain` after the started marker is
    // written is read by the parent as `cleanup_uncertain`: the lease is
    // abandoned rather than released, the active marker stays, the staging raw
    // is left behind, and the run is reported as `MutationResourcesActive`.
    // Nothing has been created, mounted or attached at this point, so saying
    // resources may still be active would name something that never happened.
    validateManifestPolicy(manifest) catch {
        return .{
            .outcome = .failed,
            .cleanup_complete = true,
            .report = .{ .tools = &.{}, .installed_packages = &.{}, .hooks = &.{} },
        };
    };
    try prepareEmptyRoot(io, manifest.root_path);
    var session = Session{
        .allocator = allocator,
        .io = io,
        .executor = executor,
        .manifest = manifest,
        .tools = .init(allocator),
        .installed_packages = .init(allocator),
        .baseline_packages = .init(allocator),
        .emitted_lock = .init(allocator),
        .imported_trust_keys = .init(allocator),
        .preexisting_loops = .init(allocator),
        .hook_records = .init(allocator),
        .tool_versions = .init(allocator),
        .initramfs_images = .init(allocator),
        .skipped_kernels = .init(allocator),
    };
    const outcome = session.openAndRun();
    // Before the teardown, and only on this path. The command that ran out of
    // time was killed, but anything it spawned was re-parented to this process
    // -- the namespace's init -- and a scriptlet's surviving child holding the
    // target root open is exactly what would turn an unmount into a failure.
    // Nothing else in the run has orphans to collect: a command that returned
    // took its own children with it or left them to this same reaper on the
    // way out.
    if (outcome == .deadline_exceeded) reapNamespace();
    // Teardown gets a budget of its own rather than what is left of the run's,
    // which on the path that matters most is nothing at all. Unmounting,
    // detaching the loop device and removing the guest root are what keep the
    // host from being left holding the staging image, so they must not be
    // preempted by the very deadline that made them necessary -- while still
    // being bounded, because a wedged unmount would otherwise hang the build
    // in the one place there is nothing left to stop it.
    session.executor.deadline = .start(io, cleanup_deadline_seconds);
    const cleanup_complete = session.close();
    return .{
        .outcome = outcome,
        .cleanup_complete = cleanup_complete,
        .report = .{
            .tools = session.tools.items,
            .installed_packages = session.installed_packages.items,
            .package_lock = session.emitted_lock.items,
            .imported_trust_keys = session.imported_trust_keys.items,
            .hooks = session.hook_records.items,
            .boot_configuration = session.boot_configuration,
            .package_cache = session.package_cache,
            .selinux_relabel = session.selinux_relabel,
            .selinux_configure = session.selinux_configure,
            .host_resolver = session.host_resolver,
            .initramfs = if (session.initramfs_regenerated) .{
                .skipped_kernel_releases = session.skipped_kernels.items,
                .images = session.initramfs_images.items,
            } else null,
        },
    };
}

/// The payload of `customize.SelinuxPolicy.configure`, named once here so the
/// worker's signature follows the request type rather than restating it.
const SelinuxConfigure = @FieldType(customize.SelinuxPolicy, "configure");

/// What one read of the target's `/etc/selinux/config` yielded.
const DiscoveredSelinux = struct {
    /// Absent when the configuration names no policy this can use. A relabel
    /// fails on that; a mode-only `.configure` does not, so the read reports
    /// it rather than refusing on its caller's behalf.
    policy: ?[]const u8,
    mode: ?customize.SelinuxMode,
};

const Session = struct {
    allocator: Allocator,
    io: Io,
    executor: Executor,
    manifest: Manifest,
    raw_file: ?Io.File = null,
    loop_path: ?[]u8 = null,
    loop_attachment_uncertain: bool = false,
    loop_inventory_safe: bool = false,
    root_mounted: bool = false,
    dev_mounted: bool = false,
    proc_mounted: bool = false,
    sys_mounted: bool = false,
    run_mounted: bool = false,
    cache_mounted: bool = false,
    resolver_mounted: bool = false,
    resolver_replaced: bool = false,
    resolver_had_original: bool = false,
    tools: std.array_list.Managed(customize.ToolRecord),
    installed_packages: std.array_list.Managed([]const u8),
    /// The installed set as it stood before the package actions ran, in the
    /// same `NAME-EPOCH:VERSION-RELEASE.ARCH` form as `installed_packages`.
    /// Populated only under an exact lock, which is the only policy that has a
    /// question to ask of it: what this transaction added.
    baseline_packages: std.array_list.Managed([]const u8),
    emitted_lock: std.array_list.Managed(customize.PackageVersionLock),
    /// Trust rpm holds because of this run, collected from the same delta the
    /// emitted lock comes from and for the same reason: the input image's own
    /// keys are not this run's doing.
    imported_trust_keys: std.array_list.Managed([]const u8),
    preexisting_loops: std.array_list.Managed([]const u8),
    hook_records: std.array_list.Managed(customize.HookRecord),
    /// Versions already probed, keyed by the guest path that was probed.
    /// Probing is per program rather than per invocation, but the answer is
    /// still the answer for that program: what it replaced was a fixed table
    /// of five suffixes that returned an empty string for everything else, so
    /// `setfiles` -- the most recently added tool -- recorded no version at
    /// all.
    tool_versions: std.array_list.Managed(ProbedVersion),
    boot_configuration: ?customize.BootConfigurationRecord = null,
    package_cache: ?customize.PackageCacheRecord = null,
    selinux_relabel: ?customize.SelinuxRelabelRecord = null,
    selinux_configure: ?customize.SelinuxConfigureRecord = null,
    /// Set exactly when this run bound the build machine's own resolver into
    /// the target for the package transaction.
    host_resolver: ?customize.HostResolverRecord = null,
    /// Whether an initramfs regeneration was attempted at all, which is not
    /// the same as whether one produced an image: a derived regeneration that
    /// found no installed kernel is a successful run that regenerated nothing,
    /// and the entries it passed over are the only account of why.
    initramfs_regenerated: bool = false,
    initramfs_images: std.array_list.Managed(customize.InitramfsImageRecord),
    skipped_kernels: std.array_list.Managed(customize.SkippedKernelRelease),

    fn openAndRun(self: *Session) RunOutcome {
        self.open() catch |err| return classifyRunFailure(err);
        self.runPolicy() catch |err| return classifyRunFailure(err);
        self.loadInstalledPackages() catch |err| return classifyRunFailure(err);
        // After the rpm database has been read, and before `close` publishes
        // anything: a run whose lock did not hold must fail while the image is
        // still staging, not after it has been committed under a plan hash
        // that claims the versions were pinned.
        self.verifyPackageLock() catch |err| return classifyRunFailure(err);
        self.emitPackageLock() catch |err| return classifyRunFailure(err);
        return .succeeded;
    }

    fn open(self: *Session) !void {
        const raw_file = try Io.Dir.cwd().openFile(self.io, self.manifest.raw_path, .{
            .mode = .read_write,
            .allow_directory = false,
            .follow_symlinks = false,
        });
        self.raw_file = raw_file;
        const raw_stat = try raw_file.stat(self.io);
        if (raw_stat.kind != .file or
            raw_stat.inode != self.manifest.stage_inode or
            raw_stat.size != self.manifest.virtual_size or
            raw_stat.nlink != 1)
        {
            return error.RawStageIdentityMismatch;
        }
        try self.snapshotAssociatedLoops();

        const offset = try std.fmt.allocPrint(
            self.allocator,
            "{d}",
            .{self.manifest.partition_offset},
        );
        defer self.allocator.free(offset);
        const length = try std.fmt.allocPrint(
            self.allocator,
            "{d}",
            .{self.manifest.partition_length},
        );
        defer self.allocator.free(length);
        const losetup = findTool(self.io, losetup_candidates).?;
        self.loop_attachment_uncertain = true;
        self.loop_inventory_safe = false;
        const attach_argv = [_][]const u8{
            losetup,
            "--find",
            "--show",
            "--offset",
            offset,
            "--sizelimit",
            length,
            "/proc/self/fd/0",
        };
        var result = try self.executor.run(
            self.allocator,
            self.io,
            &attach_argv,
            true,
            raw_file,
        );
        defer result.deinit(self.allocator);
        try expectSuccess(result.term);
        try self.recordTool(.host, &attach_argv);
        const loop_path = try parseLoopPath(self.allocator, result.stdout);
        if (self.loopWasPreexisting(loop_path)) {
            self.allocator.free(loop_path);
            return error.UnexpectedLoopReuse;
        }
        self.loop_path = loop_path;
        self.loop_attachment_uncertain = false;

        try self.runSuccess(&.{
            findTool(self.io, mount_candidates).?,
            "-t",
            "ext4",
            "-o",
            "rw,nodev,nosuid",
            self.loop_path.?,
            self.manifest.root_path,
        });
        self.root_mounted = true;
        try validateGuestMountpoints(self.io, self.manifest.root_path);

        const dev_path = try joinGuest(self.allocator, self.manifest.root_path, "/dev");
        defer self.allocator.free(dev_path);
        try self.runSuccess(&.{
            findTool(self.io, mount_candidates).?,
            "-t",
            "tmpfs",
            "-o",
            "mode=0755,nosuid",
            "tmpfs",
            dev_path,
        });
        self.dev_mounted = true;
        try self.createDevices(dev_path);

        const proc_path = try joinGuest(self.allocator, self.manifest.root_path, "/proc");
        defer self.allocator.free(proc_path);
        try self.runSuccess(&.{
            findTool(self.io, mount_candidates).?,
            "-t",
            "proc",
            "-o",
            "nosuid,nodev,noexec",
            "proc",
            proc_path,
        });
        self.proc_mounted = true;

        const sys_path = try joinGuest(self.allocator, self.manifest.root_path, "/sys");
        defer self.allocator.free(sys_path);
        try self.runSuccess(&.{
            findTool(self.io, mount_candidates).?,
            "-t",
            "sysfs",
            "-o",
            "ro,nosuid,nodev,noexec",
            "sysfs",
            sys_path,
        });
        self.sys_mounted = true;

        const run_path = try joinGuest(self.allocator, self.manifest.root_path, "/run");
        defer self.allocator.free(run_path);
        try self.runSuccess(&.{
            findTool(self.io, mount_candidates).?,
            "-t",
            "tmpfs",
            "-o",
            "mode=0755,nosuid,nodev",
            "tmpfs",
            run_path,
        });
        self.run_mounted = true;
        try self.mountPackageCache();

        const resolver_path = try joinGuest(
            self.allocator,
            self.manifest.root_path,
            "/etc/resolv.conf",
        );
        defer self.allocator.free(resolver_path);
        // `host_resolver` installs nothing when the host has no resolver of
        // its own to lend; a declared list is always installable because it
        // does not depend on this machine. Either way a run with no package
        // actions gets none: this is the package transaction's resolver, and
        // a root that never resolves a name has no business carrying one.
        // An offline transaction reaches no network, so it gets no resolver
        // at all. That is not tidiness: with no `/etc/resolv.conf` the target
        // cannot resolve a name even if something in it tried, so "offline"
        // is a property of the run rather than a flag it was asked to honour.
        // It layers with `--cacheonly` rather than replacing it.
        const install_resolver = self.manifest.packages.actions.len != 0 and
            !customize.offlinePackageCache(self.manifest.packages.cache) and
            switch (self.manifest.packages.resolver) {
                .host_resolver => isRegularFileFollow(self.io, "/etc/resolv.conf"),
                .nameservers => true,
            };
        if (install_resolver) {
            const resolver_backup_path = try joinGuest(
                self.allocator,
                self.manifest.root_path,
                "/etc/.zvmi-resolv.conf",
            );
            defer self.allocator.free(resolver_backup_path);
            if (pathExistsNoFollow(self.io, resolver_backup_path)) {
                return error.ResolverBackupExists;
            }
            const resolver_run_path = try joinGuest(
                self.allocator,
                self.manifest.root_path,
                "/run/zvmi-resolv.conf",
            );
            defer self.allocator.free(resolver_run_path);
            switch (self.manifest.packages.resolver) {
                .host_resolver => {
                    // Digested before the bind, which is the only moment this
                    // backend has the host's own file open on its own account.
                    // The bytes, not their content: what they name is this
                    // machine's DNS topology, which the caller never declared.
                    try self.recordHostResolver("/etc/resolv.conf");
                    try writeBytesExclusive(self.io, resolver_run_path, "", default_repository_permissions);
                    try self.runSuccess(&.{
                        findTool(self.io, mount_candidates).?,
                        "--bind",
                        "/etc/resolv.conf",
                        resolver_run_path,
                    });
                    self.resolver_mounted = true;
                    try self.runSuccess(&.{
                        findTool(self.io, mount_candidates).?,
                        "-o",
                        "remount,bind,ro",
                        resolver_run_path,
                    });
                },
                // No bind mount, because there is no host file to follow: the
                // content is the request's, so it is simply written. `/run` is
                // the tmpfs mounted just above, so it leaves as it arrived.
                .nameservers => |nameservers| {
                    const body = try vm_control.renderResolverBody(
                        self.allocator,
                        nameservers,
                    );
                    defer self.allocator.free(body);
                    try writeBytesExclusive(self.io, resolver_run_path, body, default_repository_permissions);
                },
            }
            const resolver_stat = Io.Dir.cwd().statFile(
                self.io,
                resolver_path,
                .{ .follow_symlinks = false },
            );
            if (resolver_stat) |stat| {
                if (stat.kind != .file and stat.kind != .sym_link) {
                    return error.UnsupportedGuestResolver;
                }
                try Io.Dir.rename(
                    Io.Dir.cwd(),
                    resolver_path,
                    Io.Dir.cwd(),
                    resolver_backup_path,
                    self.io,
                );
                self.resolver_had_original = true;
            } else |err| switch (err) {
                error.FileNotFound => {},
                else => return err,
            }
            self.resolver_replaced = true;
            try Io.Dir.cwd().symLink(
                self.io,
                "/run/zvmi-resolv.conf",
                resolver_path,
                .{},
            );
        }
    }

    /// Digests the build machine's own resolver, streamed rather than read
    /// whole: nothing bounds a file this backend did not write.
    fn recordHostResolver(self: *Session, host_path: []const u8) !void {
        const file = try Io.Dir.cwd().openFile(self.io, host_path, .{});
        defer file.close(self.io);
        const size = (try file.stat(self.io)).size;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < size) {
            const length: usize = @intCast(@min(size - offset, buffer.len));
            const read = try file.readPositionalAll(self.io, buffer[0..length], offset);
            if (read != length) return error.ShortResolverRead;
            hash.update(buffer[0..length]);
            offset += length;
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        self.host_resolver = .{ .sha256 = .{ .bytes = digest }, .size = size };
    }

    fn runPolicy(self: *Session) !void {
        try self.writeRepositoryFiles();
        errdefer self.removeRepositoryFiles() catch {};
        // Before the trust import, so the baseline is the root exactly as it
        // arrived and every `gpg-pubkey-<keyid>-<timestamp>` pseudo-package in
        // the delta is trust this run added -- whether the request declared it
        // or a package transaction imported one of its own. The lock is
        // unaffected either way: both readers of the delta drop trust
        // pseudo-packages, because `(none)` is not an architecture the pin
        // rules accept and a lock must not pin a key.
        //
        // Read for any run with package actions, not only a locked one: the
        // emitted lock is the difference between the two inventories, and a
        // run that declares no lock is the one most likely to want one.
        if (self.manifest.packages.actions.len != 0) try self.loadBaselinePackages();
        try self.importTrust();
        for (self.manifest.packages.actions) |action| switch (action) {
            .install => |names| try self.runTdnfLocked("install", names),
            // The one verb a lock does not rewrite. A removal names what must
            // not be installed, and asking to remove one exact version would
            // silently leave any other in place.
            .remove => |names| try self.runTdnf("remove", names, false),
            .update_all => try self.runTdnf("update", &.{}, true),
            .update_selected => |names| try self.runTdnfLocked("update", names),
        };
        try self.removeRepositoryFiles();
        // After the packages, so a package that ships its own modprobe
        // configuration cannot land on top of the declared one, and before
        // the initramfs, so a generator that reads this configuration sees
        // the declared state rather than the one it replaced. Also before any
        // hook, so every hook sees the declared configuration rather than a
        // different one depending on which phase it asked for.
        try self.writeKernelModuleFiles();
        // The four phases, in the order `buildOperations` publishes them. A
        // run whose hooks fired in a different order from the one the plan
        // shows would make the plan a description of something else.
        try self.runHooks(.after_packages);
        try self.runHooks(.before_initramfs);
        switch (self.manifest.initramfs) {
            .unchanged => {},
            .regenerate => |regenerate| try self.regenerateInitramfs(regenerate),
            // `validateManifestPolicy` already refused this; repeated here
            // because the run itself must not treat an undecided policy as a
            // decision to do nothing.
            .when_needed => return error.UnresolvedInitramfsPolicy,
        }
        try self.runHooks(.before_seal);
        // In the phase the plan publishes as `bootloader_prepare`: after the
        // packages that could have installed a kernel and after the initramfs
        // the generator will reference, so the configuration it produces
        // describes the root as the run leaves it.
        try self.regenerateBootConfiguration();
        try self.runHooks(.finalize);
        // Last, in the phase the plan publishes last. Everything above this
        // line creates or rewrites files, and a relabel only describes the
        // tree as it stood when the tool walked it.
        try self.applySelinuxPolicy();
    }

    /// Carries out whichever SELinux operation the plan published, in the
    /// phase it published it in.
    fn applySelinuxPolicy(self: *Session) !void {
        switch (self.manifest.selinux) {
            .unchanged => {},
            .relabel => try self.relabelRoot(),
            .configure => |configure| try self.configureSelinux(configure),
        }
    }

    /// Relabels the target root with the policy the target itself carries.
    ///
    /// The policy is read from the target's own `/etc/selinux/config` here
    /// rather than taken from the plan, because a package action in this same
    /// run can have installed or replaced it -- the same reason kernel
    /// releases are discovered after the transaction rather than declared in
    /// advance. What it resolved to is auditable without a record of its own,
    /// because the full argv reaches provenance like every other tool.
    fn relabelRoot(self: *Session) !void {
        // Read once, for the policy the relabel needs and the mode the record
        // carries: a second read could see a different file, and provenance
        // would describe a configuration that never existed as a whole.
        const discovered = try self.readGuestSelinuxConfiguration();
        defer if (discovered.policy) |policy| self.allocator.free(policy);
        const policy = discovered.policy orelse return error.MissingSelinuxConfiguration;
        try self.runRelabel(policy);
        // After the tool succeeded, so the record describes a relabel that
        // happened rather than one that was attempted.
        self.selinux_relabel = .{
            .discovered_policy = try self.allocator.dupe(u8, policy),
            .target_mode = discovered.mode,
        };
    }

    /// Writes the declared mode and policy into the target's own
    /// `/etc/selinux/config`, and relabels when that change makes the labels
    /// the target already carries wrong.
    ///
    /// The before-state is read from the target rather than taken from the
    /// plan, for the same reason the relabel's policy is: a package action in
    /// this same run can have replaced the configuration. It is read once, so
    /// the recorded before-state is a configuration that existed as a whole.
    ///
    /// A policy the target does not carry fails the run rather than being
    /// installed. Installing a policy is a package action and the model
    /// already has one; a `.configure` that quietly ran a transaction would be
    /// doing something the plan did not say.
    ///
    /// `/.autorelabel` is deliberately not used, and this is the obvious
    /// shortcut so it is written down: it defers the labelling to the target's
    /// first boot, which means publishing an image whose first boot relabels
    /// and reboots. zvmi's position is that an image is finished when it is
    /// published, which is the same reason the relabel happens in the run.
    fn configureSelinux(self: *Session, configure: SelinuxConfigure) !void {
        if (configure.mode == null and configure.policy == null) {
            return error.EmptySelinuxConfiguration;
        }
        const path = try self.guestPath(selinux_mod.config_path);
        defer self.allocator.free(path);
        const before = Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(max_selinux_config_bytes),
        ) catch return error.MissingSelinuxConfiguration;
        defer self.allocator.free(before);
        const previous_mode = selinux_mod.parseConfiguredMode(before);
        const previous_policy = selinux_mod.parseConfiguredPolicy(before);

        // Refused before the file is rewritten, so a run that cannot finish
        // the operation has not half-finished it: the published image would
        // otherwise name a policy it does not carry, which is a root that
        // fails to load a policy at boot.
        if (configure.policy) |name| {
            var contexts_buffer: [selinux_mod.max_policy_name_bytes + 64]u8 = undefined;
            const contexts = selinux_mod.fileContextsPath(&contexts_buffer, name) catch
                return error.UnsupportedSelinuxPolicy;
            if (!try self.guestFileExists(contexts)) return error.MissingSelinuxPolicy;
        }

        const rendered = try self.allocator.alloc(
            u8,
            before.len + selinux_mod.max_policy_name_bytes + 32,
        );
        defer self.allocator.free(rendered);
        const text = selinux_mod.renderConfig(
            rendered,
            before,
            configure.mode,
            configure.policy,
        ) catch |err| switch (err) {
            error.MissingSelinuxSetting => return error.MissingSelinuxSetting,
            error.InvalidPolicy => return error.UnsupportedSelinuxPolicy,
            error.NoChangeRequested => return error.EmptySelinuxConfiguration,
            error.NoSpaceLeft => return error.MissingSelinuxConfiguration,
        };
        {
            // A truncating open keeps the existing file's mode, which is the
            // distro's own and not this run's to change.
            const file = try Io.Dir.cwd().createFile(self.io, path, .{});
            defer file.close(self.io);
            try file.writePositionalAll(self.io, text, 0);
        }

        const reason = selinux_mod.relabelReason(
            configure.relabel,
            previous_mode,
            previous_policy orelse "",
            configure.mode,
            configure.policy,
        );
        if (selinux_mod.relabels(reason)) {
            // Against the policy this just wrote, not the one it replaced:
            // the labels have to be the ones the published configuration
            // names.
            const policy = configure.policy orelse
                previous_policy orelse return error.MissingSelinuxConfiguration;
            try self.runRelabel(policy);
        }
        self.selinux_configure = .{
            .previous_mode = previous_mode,
            .previous_policy = if (previous_policy) |name|
                try self.allocator.dupe(u8, name)
            else
                null,
            .mode = configure.mode,
            .policy = if (configure.policy) |name|
                try self.allocator.dupe(u8, name)
            else
                null,
            .relabelled = selinux_mod.relabels(reason),
            .relabel_reason = reason,
        };
    }

    /// Walks the target root with its own labelling tool, against `policy`.
    ///
    /// `setfiles` rather than `restorecon`: it takes the file-contexts file as
    /// an argument instead of asking libselinux for the active policy, which
    /// needs a loaded policy and a mounted selinuxfs that an executor running
    /// its own kernel does not have.
    fn runRelabel(self: *Session, policy: []const u8) !void {
        const tool = try self.findGuestLabellingTool();
        var contexts_buffer: [selinux_mod.max_policy_name_bytes + 64]u8 = undefined;
        const contexts = selinux_mod.fileContextsPath(&contexts_buffer, policy) catch
            return error.UnsupportedSelinuxPolicy;
        if (!try self.guestFileExists(contexts)) return error.MissingSelinuxFileContexts;

        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try argv.append(tool);
        // Matches how the target's own installer labels a fresh root: reset
        // every context to what the policy says, rather than only those the
        // tool considers unset.
        try argv.append("-F");
        // Only the exclusions that exist. `setfiles` is given a directory it
        // could not walk otherwise, and an argv naming a path the target does
        // not have would describe a run that did not happen.
        for (selinux_mod.excluded_directories) |directory| {
            if (!try self.guestDirectoryExists(directory)) continue;
            try argv.append("-e");
            try argv.append(directory);
        }
        try argv.append(contexts);
        try argv.append("/");
        try self.runChroot(argv.items);
    }

    fn findGuestLabellingTool(self: *Session) ![]const u8 {
        for (selinux_mod.setfiles_candidates) |candidate| {
            if (try self.guestFileExists(candidate)) return candidate;
        }
        return error.MissingSelinuxLabellingTool;
    }

    /// What the target's own SELinux configuration says: the policy a relabel
    /// must use, and the mode it asks the target's kernel for.
    ///
    /// The policy is duplicated because the file it was parsed out of does not
    /// outlive this call.
    fn readGuestSelinuxConfiguration(self: *Session) !DiscoveredSelinux {
        const path = try self.guestPath(selinux_mod.config_path);
        defer self.allocator.free(path);
        const contents = Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(max_selinux_config_bytes),
        ) catch return error.MissingSelinuxConfiguration;
        defer self.allocator.free(contents);
        return .{
            .policy = if (selinux_mod.parseConfiguredPolicy(contents)) |policy|
                try self.allocator.dupe(u8, policy)
            else
                null,
            .mode = selinux_mod.parseConfiguredMode(contents),
        };
    }

    fn runHooks(self: *Session, phase: customize.HookPhase) !void {
        for (self.manifest.hooks, 0..) |hook, index| {
            if (hook.phase != phase) continue;
            try self.runHook(hook, index);
        }
    }

    /// Runs one hook and records what ran.
    ///
    /// What the hook gets is stated, not inherited. Its argument vector is the
    /// script followed by exactly the declared arguments. Its environment is
    /// the one every command in this worker gets -- built by `baseEnvironment`
    /// and containing nothing from the build machine, which matters more here
    /// than anywhere else because a hook is the only place a caller supplies
    /// code rather than configuration. Its standard input is closed; its
    /// output goes to the builder's own, unbuffered and uncaptured, because a
    /// hook's output is a build log rather than a value the run consumes.
    ///
    /// What it does not get is a wall clock. Nothing here is bounded in time,
    /// and a hook is no exception: package scriptlets and dracut modules are
    /// already target-supplied code running as root for as long as they like.
    /// A deadline belongs to the whole run rather than to this one command,
    /// and inventing one only for hooks would state a guarantee the backend
    /// does not have.
    fn runHook(self: *Session, hook: customize.Hook, index: usize) !void {
        const guest_path = try std.fmt.allocPrint(
            self.allocator,
            "/run/zvmi-hook-{d}",
            .{index},
        );
        defer self.allocator.free(guest_path);
        const host_path = try joinGuest(
            self.allocator,
            self.manifest.root_path,
            guest_path,
        );
        defer self.allocator.free(host_path);

        // Read here, on the host side of the chroot, and never opened from
        // inside the target root: a hook source resolved against the target
        // would let the image being customized choose the code that customizes
        // it.
        const script = try self.readHookScript(hook.source);
        defer self.allocator.free(script);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(script, &digest, .{});

        try writeExecutableExclusive(self.io, host_path, script);
        // Unconditional. The script lives on the private tmpfs at `<root>/run`
        // for exactly the command that runs it: the next hook, the initramfs
        // generator and anything a package scriptlet spawns must not find it,
        // and nothing published can contain it.
        defer Io.Dir.cwd().deleteFile(self.io, host_path) catch {};

        var argv = try std.array_list.Managed([]const u8).initCapacity(
            self.allocator,
            hook.arguments.len + 3,
        );
        defer argv.deinit();
        argv.appendAssumeCapacity(findTool(self.io, chroot_candidates).?);
        argv.appendAssumeCapacity(self.manifest.root_path);
        argv.appendAssumeCapacity(guest_path);
        argv.appendSliceAssumeCapacity(hook.arguments);

        var result = try self.executor.run(
            self.allocator,
            self.io,
            argv.items,
            false,
            null,
        );
        defer result.deinit(self.allocator);
        const exit_code: u8 = switch (result.term) {
            .exited => |code| std.math.cast(u8, code) orelse return error.HookFailed,
            // Killed by a signal, stopped, or whatever else a term can be.
            // None of them is a hook that finished, so none of them has an
            // exit code to record.
            else => return error.HookFailed,
        };
        if (exit_code != 0) return error.HookFailed;

        try self.hook_records.append(.{
            .name = try self.allocator.dupe(u8, hook.name),
            .phase = hook.phase,
            .source_sha256 = .{ .bytes = digest },
            .interpreter = try self.allocator.dupe(
                u8,
                customize.hookInterpreterLine(script),
            ),
            .exit_code = exit_code,
        });
    }

    fn readHookScript(self: *Session, source: customize.HookSource) ![]u8 {
        switch (source) {
            .inline_script => |script| {
                if (!validHookScript(script)) return error.HookScriptUnusable;
                return self.allocator.dupe(u8, script);
            },
            .host_path => |path| {
                const bytes = Io.Dir.cwd().readFileAlloc(
                    self.io,
                    path,
                    self.allocator,
                    .limited(customize.max_hook_script_bytes + 1),
                ) catch return error.HookSourceUnreadable;
                errdefer self.allocator.free(bytes);
                // The same rule the request validator applies to an inline
                // script, applied to bytes it could not see. A host path is
                // read here for the first time, so this is the first boundary
                // that can hold it to anything.
                if (!validHookScript(bytes)) return error.HookScriptUnusable;
                return bytes;
            },
        }
    }

    /// Runs a package verb whose names an exact lock has something to say
    /// about, substituting each name with the pinned identity.
    ///
    /// The substitution is what makes the lock a lock rather than a report:
    /// asking tdnf for `openssh` and checking afterwards that it happened to
    /// land on the pinned release would fail a build that could have succeeded
    /// by asking for the release in the first place. `validatePackageLock`
    /// has already refused any action naming a package the lock omits, so
    /// every name here resolves to exactly one pin.
    fn runTdnfLocked(
        self: *Session,
        verb: []const u8,
        names: []const []const u8,
    ) !void {
        const pins = switch (self.manifest.packages.lock) {
            .exact => |pins| pins,
            else => return self.runTdnf(verb, names, true),
        };
        var specs = std.array_list.Managed([]const u8).init(self.allocator);
        defer {
            for (specs.items) |spec| self.allocator.free(spec);
            specs.deinit();
        }
        for (names) |name| {
            // Every pin sharing the name, not the first one. A lock may pin
            // `glibc` at both `i686` and `x86_64`, and those are two packages
            // a multilib root holds at once: asking for whichever happened to
            // be listed first would install one and then fail verification on
            // the other.
            var matched = false;
            for (pins) |pin| {
                if (!std.mem.eql(u8, pin.name, name)) continue;
                matched = true;
                try specs.append(try std.fmt.allocPrint(
                    self.allocator,
                    "{s}-{s}.{s}",
                    .{ pin.name, pin.evr, pin.architecture },
                ));
            }
            if (!matched) return error.UnlockedPackageRequested;
        }
        try self.runTdnf(verb, specs.items, true);
    }

    /// Holds the finished root to the lock it was built under.
    ///
    /// Two questions, and both have to be asked. Every pin must name a package
    /// the rpm database actually holds at that exact identity, or the
    /// transaction resolved somewhere the request did not point. And every
    /// package this transaction added must be covered by a pin, or the lock
    /// pinned the packages the caller named and left their dependencies free
    /// -- which is an image pinned in one place and open in the others, built
    /// under a plan hash that says otherwise.
    ///
    /// The second question is why the baseline exists. Comparing the whole
    /// installed set against the lock would demand that a lock enumerate the
    /// hundreds of packages the input image already carried, none of which
    /// this run chose. The delta is the part the run is answerable for.
    fn verifyPackageLock(self: *Session) !void {
        const pins = switch (self.manifest.packages.lock) {
            .unlocked => return,
            // Refused before the root was opened; repeated so that a policy
            // this function cannot check can never be read as one it checked
            // and found satisfied.
            .snapshot => return error.UnsupportedPackagePolicy,
            .exact => |pins| pins,
        };
        for (pins) |pin| {
            const spec = try std.fmt.allocPrint(
                self.allocator,
                "{s}-{s}.{s}",
                .{ pin.name, pin.evr, pin.architecture },
            );
            defer self.allocator.free(spec);
            if (containsBytes(self.installed_packages.items, spec)) continue;
            // Distinguished because they are different failures: an absent
            // package means the transaction never installed what was pinned,
            // while a present one at another identity means it installed
            // something else under the same name. Compared by parsed name
            // rather than by string prefix, because `python3-libs` starts with
            // `python3-` and is a different package, not a different version of
            // one.
            for (self.installed_packages.items) |installed| {
                const record = customize.parseInstalledPackageRecord(installed) orelse continue;
                if (std.mem.eql(u8, record.name, pin.name)) {
                    return error.LockedPackageMismatch;
                }
            }
            return error.LockedPackageMissing;
        }
        for (self.installed_packages.items) |installed| {
            if (containsBytes(self.baseline_packages.items, installed)) continue;
            if (isTrustPseudoPackage(installed)) continue;
            if (!pinsCover(pins, installed)) return error.UnlockedPackageInstalled;
        }
    }

    /// Records what this transaction changed, as the lock that would reproduce
    /// it.
    ///
    /// The difference between the two inventories rather than the whole final
    /// one, because the whole final one is already recorded beside it and is
    /// mostly the input image: a lock naming the hundreds of packages the run
    /// did not choose would say nothing about the run. A record that parses as
    /// something other than rpm's own output is a refusal rather than a
    /// skipped entry -- an emitted lock with a hole in it is worse than none,
    /// because the next run would state it and believe it complete.
    fn emitPackageLock(self: *Session) !void {
        if (self.manifest.packages.actions.len == 0) return;
        for (self.installed_packages.items) |installed| {
            if (containsBytes(self.baseline_packages.items, installed)) continue;
            if (isTrustPseudoPackage(installed)) {
                try self.imported_trust_keys.append(
                    try self.allocator.dupe(u8, trustKeyIdentity(installed)),
                );
                continue;
            }
            const pin = customize.parseInstalledPackageRecord(installed) orelse
                return error.InvalidInstalledPackageRecord;
            try self.emitted_lock.append(pin);
        }
    }

    fn loadBaselinePackages(self: *Session) !void {
        try self.readInstalledPackages(&self.baseline_packages);
    }

    fn loadInstalledPackages(self: *Session) !void {
        try self.readInstalledPackages(&self.installed_packages);
    }

    fn readInstalledPackages(
        self: *Session,
        into: *std.array_list.Managed([]const u8),
    ) !void {
        const output = try self.runChrootCapture(&.{
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
            try into.append(try self.allocator.dupe(u8, line));
        }
        std.mem.sort([]const u8, into.items, {}, lessThanBytes);
    }

    fn close(self: *Session) bool {
        var complete = true;
        if (self.root_mounted) {
            const sync_argv = [_][]const u8{
                findTool(self.io, sync_candidates).?,
                "-f",
                self.manifest.root_path,
            };
            self.runSuccess(&sync_argv) catch {
                complete = false;
            };
        }
        const umount = findTool(self.io, umount_candidates).?;
        self.cleanupMount(
            umount,
            self.resolver_mounted,
            "/run/zvmi-resolv.conf",
            &complete,
        );
        self.restoreResolver(&complete);
        self.cleanupMount(umount, self.cache_mounted, guest_cache_directory, &complete);
        self.cleanupMount(umount, self.run_mounted, "/run", &complete);
        self.cleanupMount(umount, self.sys_mounted, "/sys", &complete);
        self.cleanupMount(umount, self.proc_mounted, "/proc", &complete);
        self.cleanupMount(umount, self.dev_mounted, "/dev", &complete);
        if (self.root_mounted) {
            self.runSuccess(&.{ umount, self.manifest.root_path }) catch {
                complete = false;
            };
        }
        if (self.loop_path) |loop_path| {
            const detach_succeeded = blk: {
                self.runSuccess(&.{
                    findTool(self.io, losetup_candidates).?,
                    "--detach",
                    loop_path,
                }) catch break :blk false;
                break :blk true;
            };
            const loop_clean = detach_succeeded and
                self.waitForOnlyPreexistingLoops();
            self.loop_inventory_safe = loop_clean;
            if (!loop_clean) {
                complete = false;
            }
            self.allocator.free(loop_path);
            self.loop_path = null;
        } else if (self.loop_attachment_uncertain) {
            const loop_clean = self.detachAssociatedLoops();
            self.loop_inventory_safe = loop_clean;
            if (!loop_clean) complete = false;
            self.loop_attachment_uncertain = false;
        }
        if (self.raw_file) |raw_file| {
            raw_file.close(self.io);
            self.raw_file = null;
        }
        if (!self.loop_inventory_safe) complete = false;
        if (complete) {
            Io.Dir.cwd().deleteTree(self.io, self.manifest.root_path) catch {
                complete = false;
            };
        }
        return complete;
    }

    fn restoreResolver(self: *Session, complete: *bool) void {
        if (!self.resolver_replaced) return;
        const resolver_path = joinGuest(
            self.allocator,
            self.manifest.root_path,
            "/etc/resolv.conf",
        ) catch {
            complete.* = false;
            return;
        };
        defer self.allocator.free(resolver_path);
        Io.Dir.cwd().deleteFile(self.io, resolver_path) catch |err| switch (err) {
            error.FileNotFound => {},
            else => complete.* = false,
        };
        if (self.resolver_had_original) {
            const resolver_backup_path = joinGuest(
                self.allocator,
                self.manifest.root_path,
                "/etc/.zvmi-resolv.conf",
            ) catch {
                complete.* = false;
                return;
            };
            defer self.allocator.free(resolver_backup_path);
            Io.Dir.rename(
                Io.Dir.cwd(),
                resolver_backup_path,
                Io.Dir.cwd(),
                resolver_path,
                self.io,
            ) catch {
                complete.* = false;
            };
        }
        self.resolver_replaced = false;
    }

    fn queryAssociatedLoops(self: *Session) !CommandResult {
        const raw_file = self.raw_file orelse
            return error.RawStageHandleUnavailable;
        const argv = [_][]const u8{
            findTool(self.io, losetup_candidates).?,
            "--associated",
            "/proc/self/fd/0",
            "--output",
            "NAME",
            "--noheadings",
        };
        const result = try self.executor.run(
            self.allocator,
            self.io,
            &argv,
            true,
            raw_file,
        );
        // Recorded on every call, including each attempt of the settle poll in
        // `waitForOnlyPreexistingLoops`. A run that had to ask twenty times
        // took two seconds to get its loop device back, which is a fact about
        // that run; collapsing the repeats would record the executor's
        // patience instead of what happened.
        try self.recordTool(.host, &argv);
        return result;
    }

    fn snapshotAssociatedLoops(self: *Session) !void {
        self.loop_inventory_safe = false;
        var result = try self.queryAssociatedLoops();
        defer result.deinit(self.allocator);
        try expectSuccess(result.term);
        var lines = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
        while (lines.next()) |line| {
            const loop_path = try parseLoopPath(self.allocator, line);
            try self.preexisting_loops.append(loop_path);
        }
        if (self.preexisting_loops.items.len != 0) {
            return error.RawStageAlreadyAttached;
        }
        self.loop_inventory_safe = true;
    }

    fn loopWasPreexisting(self: *const Session, loop_path: []const u8) bool {
        for (self.preexisting_loops.items) |existing| {
            if (std.mem.eql(u8, existing, loop_path)) return true;
        }
        return false;
    }

    fn waitForOnlyPreexistingLoops(self: *Session) bool {
        for (0..loop_settle_attempts) |attempt| {
            var result = self.queryAssociatedLoops() catch return false;
            defer result.deinit(self.allocator);
            expectSuccess(result.term) catch return false;
            var lines = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
            var found_new = false;
            while (lines.next()) |line| {
                const parsed = parseLoopPath(self.allocator, line) catch
                    return false;
                found_new = found_new or !self.loopWasPreexisting(parsed);
                self.allocator.free(parsed);
            }
            if (!found_new) return true;
            if (attempt + 1 != loop_settle_attempts) {
                Io.sleep(
                    self.io,
                    loop_settle_interval,
                    .awake,
                ) catch return false;
            }
        }
        return false;
    }

    fn detachAssociatedLoops(self: *Session) bool {
        var result = self.queryAssociatedLoops() catch return false;
        defer result.deinit(self.allocator);
        expectSuccess(result.term) catch return false;
        var lines = std.mem.tokenizeAny(u8, result.stdout, " \t\r\n");
        while (lines.next()) |line| {
            const loop_path = parseLoopPath(self.allocator, line) catch return false;
            defer self.allocator.free(loop_path);
            if (self.loopWasPreexisting(loop_path)) continue;
            self.runSuccess(&.{
                findTool(self.io, losetup_candidates).?,
                "--detach",
                loop_path,
            }) catch {
                return false;
            };
        }
        return self.waitForOnlyPreexistingLoops();
    }

    fn cleanupMount(
        self: *Session,
        umount: []const u8,
        mounted: bool,
        guest_path: []const u8,
        complete: *bool,
    ) void {
        if (!mounted) return;
        const path = joinGuest(
            self.allocator,
            self.manifest.root_path,
            guest_path,
        ) catch {
            complete.* = false;
            return;
        };
        defer self.allocator.free(path);
        self.runSuccess(&.{ umount, path }) catch {
            complete.* = false;
        };
    }

    /// Runs a command on the build machine and records it.
    ///
    /// Every host command the worker spawns goes through here, so the tool
    /// list is complete by construction rather than by remembering to append
    /// at each of the fourteen call sites. The mounts, the loop attachment and
    /// its detachment, the device nodes and the final `sync` are the run's
    /// derived work: which loop device, at which offset, over which length is
    /// decided while the run executes and is answerable nowhere else.
    fn runSuccess(self: *Session, argv: []const []const u8) !void {
        try self.runUnrecorded(argv);
        try self.recordTool(.host, argv);
    }

    /// The same, for a command whose record its caller appends instead:
    /// `runChroot` records the guest argv it wrapped, not the `chroot` call.
    fn runUnrecorded(self: *Session, argv: []const []const u8) !void {
        var result = try self.executor.run(
            self.allocator,
            self.io,
            argv,
            false,
            null,
        );
        defer result.deinit(self.allocator);
        try expectSuccess(result.term);
    }

    fn createDevices(self: *Session, dev_path: []const u8) !void {
        const devices = [_]struct {
            name: []const u8,
            major: []const u8,
            minor: []const u8,
        }{
            .{ .name = "null", .major = "1", .minor = "3" },
            .{ .name = "zero", .major = "1", .minor = "5" },
            .{ .name = "random", .major = "1", .minor = "8" },
            .{ .name = "urandom", .major = "1", .minor = "9" },
        };
        for (devices) |device| {
            const path = try std.fs.path.join(
                self.allocator,
                &.{ dev_path, device.name },
            );
            defer self.allocator.free(path);
            try self.runSuccess(&.{
                findTool(self.io, mknod_candidates).?,
                "-m",
                "666",
                path,
                "c",
                device.major,
                device.minor,
            });
        }
    }

    /// Binds the declared host cache directory into the target.
    ///
    /// A bind mount rather than a copy: the directory is what makes a later
    /// offline run possible, so it has to be the operator's own directory
    /// that this run fills, not a copy of it that disappears with the
    /// workspace. `cache_only` binds it read-only, so an offline run cannot
    /// change the input it was asked to reproduce from.
    fn mountPackageCache(self: *Session) !void {
        const cache = self.manifest.packages.cache;
        const host_directory = customize.packageCacheDirectory(cache) orelse return;
        // Re-checked here rather than trusted from the control document: this
        // process is root, and the path names what it is about to mount.
        try customize.validatePackageCacheDirectory(host_directory);
        const offline = customize.offlinePackageCache(cache);
        if (offline) {
            const stat = Io.Dir.cwd().statFile(self.io, host_directory, .{}) catch
                return error.MissingPackageCacheDirectory;
            if (stat.kind != .directory) return error.MissingPackageCacheDirectory;
        } else {
            // The populating mode declares the directory as this run's
            // output, so creating it is doing what was asked rather than
            // guessing.
            try Io.Dir.cwd().createDirPath(self.io, host_directory);
        }

        const guest_path = try joinGuest(
            self.allocator,
            self.manifest.root_path,
            guest_cache_directory,
        );
        defer self.allocator.free(guest_path);
        try Io.Dir.cwd().createDirPath(self.io, guest_path);
        const mount = findTool(self.io, mount_candidates).?;
        try self.runSuccess(&.{ mount, "--bind", host_directory, guest_path });
        self.cache_mounted = true;
        if (offline) {
            try self.runSuccess(&.{ mount, "-o", "remount,bind,ro", guest_path });
        }
        self.package_cache = .{
            .offline = offline,
            .host_path = host_directory,
            .guest_path = guest_cache_directory,
        };
    }

    fn writeRepositoryFiles(self: *Session) !void {
        const directory = try repositoryHostDirectory(
            self.allocator,
            self.manifest.root_path,
        );
        defer self.allocator.free(directory);
        try Io.Dir.cwd().createDirPath(self.io, directory);
        const config_path = try tdnfConfigHostPath(
            self.allocator,
            self.manifest.root_path,
        );
        defer self.allocator.free(config_path);
        // `cachedir` and `keepcache` are ordinary tdnf configuration keys
        // rather than command-line flags, which is what lets this work
        // against the tdnf 3.x the target images ship: the 4.0 flag that
        // would name a cache directory on the command line does not exist
        // there. `keepcache` is what makes a populating run leave the
        // downloaded packages behind for the offline run to install from;
        // without it tdnf discards them once the transaction commits.
        const config_body = if (customize.packageCacheDirectory(self.manifest.packages.cache)) |_|
            "[main]\ngpgcheck=1\nreposdir=/run/zvmi-repos\ncachedir=" ++
                guest_cache_directory ++ "\nkeepcache=1\n"
        else
            "[main]\ngpgcheck=1\nreposdir=/run/zvmi-repos\n";
        try writeBytesExclusive(
            self.io,
            config_path,
            config_body,
            default_repository_permissions,
        );
        for (self.manifest.packages.repositories) |repository| {
            const path = try repositoryHostPath(
                self.allocator,
                self.manifest.root_path,
                repository.id,
            );
            defer self.allocator.free(path);
            var material: ?vm_control.BasicMaterial = null;
            defer if (material) |resolved| {
                // The only copy this process makes of the material. tdnf reads
                // it back from the file, which lives on the private tmpfs at
                // <root>/run and is unmounted before anything is published.
                @memset(@constCast(resolved.password), 0);
                self.allocator.free(resolved.password);
            };
            if (repository.credential) |credential| {
                material = switch (credential) {
                    .basic => |basic| .{
                        .username = basic.username,
                        .password = try self.readCredentialMaterial(basic.password),
                    },
                };
            }
            const body = try vm_control.renderRepositoryBody(
                self.allocator,
                repository.id,
                repository.urls,
                material,
            );
            defer {
                @memset(body, 0);
                self.allocator.free(body);
            }
            try writeBytesExclusive(self.io, path, body, if (material == null)
                default_repository_permissions
            else
                credentialed_repository_permissions);
        }
    }

    /// Resolved here, in the worker, and never earlier: the material must not
    /// exist in the parent's address space, in the manifest, or in any argv.
    fn readCredentialMaterial(
        self: *Session,
        source: customize.CredentialSource,
    ) ![]u8 {
        // Scrubbing, because this worker is PID 1 in the namespace and mounts
        // a real `proc` inside the target root. See `credential.readMaterial`
        // for why that is a decision rather than a rule.
        return credential_mod.readMaterial(
            self.allocator,
            self.io,
            self.executor.environ,
            source,
            true,
        );
    }

    fn removeRepositoryFiles(self: *Session) !void {
        for (self.manifest.packages.repositories) |repository| {
            const path = try repositoryHostPath(
                self.allocator,
                self.manifest.root_path,
                repository.id,
            );
            defer self.allocator.free(path);
            try Io.Dir.cwd().deleteFile(self.io, path);
        }
        const config_path = try tdnfConfigHostPath(
            self.allocator,
            self.manifest.root_path,
        );
        defer self.allocator.free(config_path);
        try Io.Dir.cwd().deleteFile(self.io, config_path);
        const directory = try repositoryHostDirectory(
            self.allocator,
            self.manifest.root_path,
        );
        defer self.allocator.free(directory);
        if (std.fs.path.isAbsolute(directory)) {
            try Io.Dir.deleteDirAbsolute(self.io, directory);
        } else {
            try Io.Dir.cwd().deleteDir(self.io, directory);
        }
    }

    fn importTrust(self: *Session) !void {
        var trust_index: usize = 0;
        for (self.manifest.packages.repositories) |repository| {
            for (repository.trust) |trust| {
                const guest_path = try std.fmt.allocPrint(
                    self.allocator,
                    "/run/zvmi-trust-{d}.asc",
                    .{trust_index},
                );
                defer self.allocator.free(guest_path);
                const host_path = try joinGuest(
                    self.allocator,
                    self.manifest.root_path,
                    guest_path,
                );
                defer self.allocator.free(host_path);
                switch (trust) {
                    .inline_bytes => |bytes| try writeBytes(self.io, host_path, bytes),
                    .host_path => |path| try copyFile(
                        self.allocator,
                        self.io,
                        path,
                        host_path,
                    ),
                }
                try self.runChroot(&.{ "/usr/bin/rpm", "--import", guest_path });
                try Io.Dir.cwd().deleteFile(self.io, host_path);
                trust_index += 1;
            }
        }
    }

    fn runTdnf(
        self: *Session,
        verb: []const u8,
        names: []const []const u8,
        repositories: bool,
    ) !void {
        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try argv.appendSlice(&.{
            "/usr/bin/tdnf",
            "--config",
            "/run/zvmi-tdnf.conf",
            "--disablerepo=*",
        });
        // tdnf's own refusal to fetch. A package the declared cache does not
        // hold fails as `ERROR_TDNF_CACHE_DISABLED` rather than being
        // downloaded, which is what makes the offline claim checkable instead
        // of merely intended.
        if (customize.offlinePackageCache(self.manifest.packages.cache)) {
            try argv.append("--cacheonly");
        }
        if (repositories) {
            for (self.manifest.packages.repositories) |repository| {
                try argv.append(try std.fmt.allocPrint(
                    self.allocator,
                    "--enablerepo={s}",
                    .{repository.id},
                ));
            }
        }
        try argv.append(verb);
        try argv.append("-y");
        try argv.appendSlice(names);
        try self.runChroot(argv.items);
    }

    fn regenerateInitramfs(
        self: *Session,
        regenerate: @FieldType(customize.InitramfsPolicy, "regenerate"),
    ) !void {
        if (regenerate.generator) |generator| {
            if (!std.mem.eql(u8, generator, "dracut")) {
                return error.UnsupportedInitramfsGenerator;
            }
        }
        // Set before discovery, so a run that finds no usable kernel at all
        // still publishes the entries it passed over on the way to that
        // answer: under `nothing_to_regenerate` that is a successful run whose
        // provenance would otherwise say nothing happened.
        self.initramfs_regenerated = true;
        const kernels = if (regenerate.kernels.len > 0)
            regenerate.kernels
        else
            self.installedKernels() catch |err| switch (err) {
                // A derived regeneration asks a question the plan could not
                // answer, so a root with no kernel is the answer "nothing is
                // stale" rather than an unmet instruction.
                error.NoInstalledKernels => switch (regenerate.no_installed_kernels) {
                    .fail => return err,
                    .nothing_to_regenerate => return,
                },
                else => return err,
            };
        defer if (regenerate.kernels.len == 0) {
            for (kernels) |kernel| self.allocator.free(kernel);
            self.allocator.free(kernels);
        };
        for (kernels) |kernel| {
            const output = try std.fmt.allocPrint(
                self.allocator,
                "/boot/initramfs-{s}.img",
                .{kernel},
            );
            defer self.allocator.free(output);
            const temporary_output = "/run/zvmi-initramfs.img";
            try self.runChroot(&.{
                "/usr/bin/dracut",
                "--force",
                "--no-hostonly",
                "--tmpdir",
                "/run",
                "--kver",
                kernel,
                temporary_output,
            });
            try self.runChroot(&.{
                "/usr/bin/cp",
                "--remove-destination",
                temporary_output,
                output,
            });
            try self.recordInitramfsImage(kernel, output);
        }
    }

    /// Digests the initramfs `dracut` produced, where `cp` left it.
    ///
    /// Read from the mounted target rather than from the temporary, because
    /// what a reader can check is the file the published image carries, and
    /// the two are only the same file if the copy did what it said.
    fn recordInitramfsImage(
        self: *Session,
        kernel: []const u8,
        guest_path: []const u8,
    ) !void {
        const host_path = try self.guestPath(guest_path);
        defer self.allocator.free(host_path);
        const file = try Io.Dir.cwd().openFile(self.io, host_path, .{});
        defer file.close(self.io);
        const size = (try file.stat(self.io)).size;
        var hash = std.crypto.hash.sha2.Sha256.init(.{});
        var buffer: [64 * 1024]u8 = undefined;
        var offset: u64 = 0;
        while (offset < size) {
            const length: usize = @intCast(@min(size - offset, buffer.len));
            const read = try file.readPositionalAll(self.io, buffer[0..length], offset);
            if (read != length) return error.ShortInitramfsRead;
            hash.update(buffer[0..length]);
            offset += length;
        }
        var digest: [32]u8 = undefined;
        hash.final(&digest);
        try self.initramfs_images.append(.{
            .kernel_release = try self.allocator.dupe(u8, kernel),
            .image_path = try self.allocator.dupe(u8, guest_path),
            .size = size,
            .sha256 = .{ .bytes = digest },
        });
    }

    /// Kernel releases installed in the target root, sorted.
    ///
    /// Called after the package actions, which is the point of it: a kernel
    /// that `update_all` pulled in during this very run is found here, and
    /// its release string was not knowable when the plan was written.
    ///
    /// The rule is dracut's own. Its `--regenerate-all` iterates
    /// `/lib/modules/*` and skips any entry without a `modules.dep` or
    /// `modules.dep.bin`, which is what distinguishes an installed kernel
    /// from a directory that merely sits beside one -- a firmware drop, or
    /// the leftovers of a package that was removed. Copying that rule rather
    /// than inventing one means this and the tool it hands the answer to
    /// cannot disagree about what is installed.
    fn recordSkippedKernel(
        self: *Session,
        name: []const u8,
        reason: customize.SkippedKernelReason,
    ) !void {
        try self.skipped_kernels.append(.{
            .name = try self.allocator.dupe(u8, name),
            .reason = reason,
        });
    }

    fn installedKernels(self: *Session) ![]const []const u8 {
        const modules_path = try std.fs.path.join(
            self.allocator,
            &.{ self.manifest.root_path, "lib", "modules" },
        );
        defer self.allocator.free(modules_path);

        // No module tree at all is the one shape that honestly means no kernel
        // is installed. Every other failure -- a `/lib/modules` that is a
        // file, a symlink loop, EIO, a descriptor limit -- is a failure to
        // find out, and must not be reported as an answer: under
        // `nothing_to_regenerate` that answer is accepted, and the build would
        // ship the initramfs the package transaction just invalidated.
        var modules_dir = Io.Dir.cwd().openDir(
            self.io,
            modules_path,
            .{ .iterate = true },
        ) catch |err| switch (err) {
            error.FileNotFound => return error.NoInstalledKernels,
            else => return err,
        };
        defer modules_dir.close(self.io);

        var releases: std.array_list.Managed([]const u8) = .init(self.allocator);
        errdefer {
            for (releases.items) |release| self.allocator.free(release);
            releases.deinit();
        }

        var iterator = modules_dir.iterate();
        while (try iterator.next(self.io)) |entry| {
            // A release string the manifest would have been refused for
            // naming cannot become acceptable by being discovered instead.
            // This also excludes "." and "..".
            // Excluded by the same rule, and not worth reporting as kernels
            // a run passed over.
            if (std.mem.eql(u8, entry.name, ".") or
                std.mem.eql(u8, entry.name, "..")) continue;
            if (!validKernelRelease(entry.name)) {
                try self.recordSkippedKernel(entry.name, .invalid_release_name);
                continue;
            }

            // Deliberately no check on the entry kind: `d_type` is `unknown`
            // on filesystems that do not carry it, and a non-directory cannot
            // be opened as one anyway, so the marker below settles it.
            var release_dir = modules_dir.openDir(self.io, entry.name, .{}) catch |err| switch (err) {
                // Not a directory, or gone between the read and the open:
                // either way this entry is not an installed kernel. Every
                // other failure is a failure to find out, and skipping on one
                // reaches the same silent stale initramfs the guarded open
                // above refuses -- an empty discovered set is accepted as
                // "nothing is stale" under `nothing_to_regenerate`.
                error.NotDir, error.FileNotFound => {
                    try self.recordSkippedKernel(entry.name, .not_a_module_directory);
                    continue;
                },
                else => return err,
            };
            defer release_dir.close(self.io);
            if (!try hasDepmodOutput(self.io, release_dir)) {
                try self.recordSkippedKernel(entry.name, .no_module_dependency_index);
                continue;
            }

            try releases.append(try self.allocator.dupe(u8, entry.name));
        }

        // A request to regenerate every initramfs that regenerates none has
        // not done what it said, so it fails rather than reporting success.
        if (releases.items.len == 0) return error.NoInstalledKernels;
        std.mem.sort([]const u8, releases.items, {}, lessThanBytes);
        return releases.toOwnedSlice();
    }

    /// Places kernel-module configuration in the mounted target root.
    ///
    /// No chroot and no guest binary: these are inert configuration files, so
    /// writing them directly is both simpler and the only option that works
    /// on an image whose own tooling has not been made runnable yet.
    /// Creates a rendered file's directory, stating the mode on the
    /// components it actually creates and leaving alone the ones the image
    /// already had -- `/etc` belongs to the image, `/etc/modprobe.d` belongs
    /// to whoever made it.
    ///
    /// `mkdir` masks the mode it is given by the umask, which for this
    /// executor is the invoking shell's, so a stated mode is not enough on
    /// its own: under `umask 0` an unstated `/etc/modprobe.d` comes out
    /// `0o777`, and `modprobe` reads that directory as root at boot and
    /// honours `install` directives, which run a shell command. The other two
    /// backends are already deterministic here -- the guest is PID 1 under
    /// the kernel's own `0o022`, and a rebuild writes the mode into the
    /// filesystem with no umask in the picture -- so this is also what keeps
    /// one request producing one result whichever backend runs it.
    fn createConfigDirectory(self: *Session, directory: []const u8) !void {
        var index: usize = 0;
        while (std.mem.indexOfScalarPos(u8, directory, index + 1, '/')) |separator| {
            try self.createOneDirectory(directory[0..separator]);
            index = separator;
        }
        try self.createOneDirectory(directory);
    }

    fn createOneDirectory(self: *Session, path: []const u8) !void {
        Io.Dir.cwd().createDir(self.io, path, @enumFromInt(0o755)) catch |err| switch (err) {
            error.PathAlreadyExists => return,
            else => return err,
        };
        // `mkdir` masks the mode it was given, so it is set again here. The
        // handle has to be openable for `fchmod`, which an `O_PATH` one is
        // not -- `iterate` is what asks for a real descriptor.
        var opened = try Io.Dir.cwd().openDir(self.io, path, .{ .iterate = true });
        defer opened.close(self.io);
        try opened.setPermissions(self.io, @enumFromInt(0o755));
    }

    fn writeKernelModuleFiles(self: *Session) !void {
        const rendered = try os_customization.renderKernelModules(
            self.allocator,
            self.manifest.kernel_modules,
        );
        defer {
            for (rendered) |file| self.allocator.free(file.contents);
            self.allocator.free(rendered);
        }
        for (rendered) |file| {
            const path = try std.fs.path.join(
                self.allocator,
                &.{ self.manifest.root_path, file.path },
            );
            defer self.allocator.free(path);
            const directory = std.fs.path.dirname(path).?;
            try self.createConfigDirectory(directory);
            // The mode is stated rather than inherited. `createFile` defaults
            // to `0o666` masked by whatever umask the builder was invoked
            // with, and `modprobe` parses these as root at boot -- a
            // world-writable one is a way into the finished image. It would
            // also make the same request produce a different result here than
            // on the backends that state `0o644`. An existing file keeps its
            // own mode through a truncating open, so it is set afterwards
            // rather than only at creation.
            const target = try Io.Dir.cwd().createFile(self.io, path, .{
                .permissions = @enumFromInt(0o644),
            });
            defer target.close(self.io);
            try target.writePositionalAll(self.io, file.contents, 0);
            try target.setPermissions(self.io, @enumFromInt(0o644));
        }
    }

    /// Adds the declared kernel options to the target's own bootloader
    /// configuration by editing the input the distro's generator reads and
    /// then running that generator.
    ///
    /// `boot_options` edits the generated entries on the ESP directly, which
    /// is right for an image whose command line only zvmi ever writes. A
    /// distro-installed image regenerates its `grub.cfg` from
    /// `/etc/default/grub` whenever a kernel package changes, so an option
    /// written into the generated file there lasts until the next kernel
    /// update. This is the durable half, and it is the reason this path needs
    /// a chroot: only the target's own generator knows the target's menu.
    fn regenerateBootConfiguration(self: *Session) !void {
        const options = self.manifest.kernel_options;
        if (options.len == 0) return;

        // Re-checked against the file it is about to be spliced into, so the
        // rule and the write it guards are in the same function.
        try grub_defaults.validateOptions(options);
        try self.refuseSeparateBootFilesystem();
        const generator = try self.findGuestGenerator();
        const generated = try self.findGuestGeneratedConfiguration();

        const defaults_path = try self.guestPath(guest_grub_defaults);
        defer self.allocator.free(defaults_path);
        const before = Io.Dir.cwd().readFileAlloc(
            self.io,
            defaults_path,
            self.allocator,
            .limited(grub_defaults.max_file_bytes),
        ) catch return error.MissingBootloaderDefaults;
        defer self.allocator.free(before);

        const outcome = try grub_defaults.append(self.allocator, before, options);
        defer if (outcome.text) |text| self.allocator.free(text);
        if (outcome.text) |text| {
            // A truncating open keeps the existing file's mode, which is the
            // distro's own and not this run's to change.
            const file = try Io.Dir.cwd().createFile(self.io, defaults_path, .{});
            defer file.close(self.io);
            try file.writePositionalAll(self.io, text, 0);
        }

        try self.runChroot(&.{ generator, "-o", generated });

        // The generator is the target's program, run against the target's
        // scripts, so nothing before this point can promise what came out of
        // it. A configuration regenerated from a root with no kernel installed
        // is valid, empty, and unbootable; so is one whose distro scripts
        // ignore the variable this run edited. Both are caught here and only
        // here.
        const entries = try self.verifyGeneratedConfiguration(generated, options);
        self.boot_configuration = .{
            .defaults_path = guest_grub_defaults,
            .generator_path = generator,
            .generated_path = generated,
            .entries = entries,
            .defaults_already_current = outcome.already_current,
            .options = options,
        };
    }

    /// Refuses a target whose `/boot` is a filesystem of its own.
    ///
    /// This backend mounts the selected root partition and nothing else, so
    /// on such an image the `/boot` the generator would read and write is an
    /// empty stub directory: it would find no kernel, produce a configuration
    /// with no entries, and write it where nothing reads it. Naming the case
    /// beats regenerating into the void and reporting success.
    fn refuseSeparateBootFilesystem(self: *Session) !void {
        const path = try self.guestPath(guest_fstab);
        defer self.allocator.free(path);
        const contents = Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(grub_defaults.max_file_bytes),
            // No `/etc/fstab` at all is a root this check cannot speak about,
            // and the verification pass over the generated configuration is
            // what catches the layout being wrong anyway.
        ) catch return;
        defer self.allocator.free(contents);
        if (declaresSeparateBootFilesystem(contents)) {
            return error.SeparateBootFilesystem;
        }
    }

    fn findGuestGenerator(self: *Session) ![]const u8 {
        for (guest_generator_candidates) |candidate| {
            if (try self.guestFileExists(candidate)) return candidate;
        }
        // A systemd-managed target keeps its command line in
        // `/etc/kernel/cmdline` and regenerates through `kernel-install`,
        // whose verb needs a kernel version and image path this backend does
        // not model. Named separately so the message says what the image is
        // rather than only what it is not.
        if (try self.guestFileExists(guest_kernel_cmdline)) {
            return error.UnsupportedBootloaderGenerator;
        }
        return error.MissingBootloaderGenerator;
    }

    fn findGuestGeneratedConfiguration(self: *Session) ![]const u8 {
        for (guest_generated_candidates) |candidate| {
            if (try self.guestFileExists(candidate)) return candidate;
        }
        return error.MissingBootloaderConfiguration;
    }

    /// Reads back the regenerated configuration and counts the entries whose
    /// command line carries the options. Zero fails the run.
    fn verifyGeneratedConfiguration(
        self: *Session,
        generated: []const u8,
        options: []const u8,
    ) !usize {
        const path = try self.guestPath(generated);
        defer self.allocator.free(path);
        const contents = try Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .limited(boot_options.max_config_bytes),
        );
        defer self.allocator.free(contents);

        const defaults_path = try self.guestPath(guest_grub_defaults);
        defer self.allocator.free(defaults_path);
        const defaults = try Io.Dir.cwd().readFileAlloc(
            self.io,
            defaults_path,
            self.allocator,
            .limited(grub_defaults.max_file_bytes),
        );
        defer self.allocator.free(defaults);
        // The generator rewrites its own output but never its input, so an
        // input that lost the options means something else edited it during
        // the run.
        if (!try grub_defaults.carries(defaults, options)) return error.KernelOptionsNotApplied;

        const entries = boot_options.countGrubEntriesCarrying(contents, options);
        if (entries == 0) return error.KernelOptionsNotApplied;
        return entries;
    }

    /// Joins a guest-absolute path onto the mounted target root. Caller owns
    /// the result.
    fn guestPath(self: *Session, guest_absolute: []const u8) ![]u8 {
        return std.fs.path.join(
            self.allocator,
            &.{ self.manifest.root_path, guest_absolute[1..] },
        );
    }

    fn guestDirectoryExists(self: *Session, guest_absolute: []const u8) !bool {
        const path = try self.guestPath(guest_absolute);
        defer self.allocator.free(path);
        const stat = Io.Dir.cwd().statFile(self.io, path, .{}) catch return false;
        return stat.kind == .directory;
    }

    fn guestFileExists(self: *Session, guest_absolute: []const u8) !bool {
        const path = try self.guestPath(guest_absolute);
        defer self.allocator.free(path);
        const stat = Io.Dir.cwd().statFile(self.io, path, .{}) catch return false;
        return stat.kind == .file;
    }

    fn runChroot(self: *Session, guest_argv: []const []const u8) !void {
        var argv = try std.array_list.Managed([]const u8).initCapacity(
            self.allocator,
            guest_argv.len + 2,
        );
        defer argv.deinit();
        try argv.append(findTool(self.io, chroot_candidates).?);
        try argv.append(self.manifest.root_path);
        try argv.appendSlice(guest_argv);
        // The `chroot` wrapper is not recorded in its own right: the record
        // this appends says `target_root`, which is what the wrapper means.
        try self.runUnrecorded(argv.items);
        try self.recordTool(.target_root, guest_argv);
    }

    fn runChrootCapture(
        self: *Session,
        guest_argv: []const []const u8,
    ) ![]const u8 {
        const captured = try self.captureUnrecorded(guest_argv);
        errdefer self.allocator.free(captured);
        try self.recordTool(.target_root, guest_argv);
        return captured;
    }

    fn captureUnrecorded(
        self: *Session,
        guest_argv: []const []const u8,
    ) ![]const u8 {
        var argv = try std.array_list.Managed([]const u8).initCapacity(
            self.allocator,
            guest_argv.len + 2,
        );
        defer argv.deinit();
        try argv.append(findTool(self.io, chroot_candidates).?);
        try argv.append(self.manifest.root_path);
        try argv.appendSlice(guest_argv);
        var result = try self.executor.run(
            self.allocator,
            self.io,
            argv.items,
            true,
            null,
        );
        defer result.deinit(self.allocator);
        try expectSuccess(result.term);
        const bytes = if (std.mem.trim(u8, result.stdout, " \t\r\n").len != 0)
            result.stdout
        else
            result.stderr;
        return self.allocator.dupe(u8, std.mem.trim(u8, bytes, " \t\r\n"));
    }

    /// Appends the record for a command that has already run.
    ///
    /// A version probe is never recorded as a command of its own: it is
    /// recorded as the `version` of the record it produced. Recording both
    /// would say the run did more than it did, and the rule terminates,
    /// because a probe does not probe.
    fn recordTool(
        self: *Session,
        context: customize.ToolContext,
        argv: []const []const u8,
    ) !void {
        const version = switch (context) {
            .target_root => try self.toolVersion(argv[0]),
            // Nothing on the host is asked its version: these are the
            // executor's own plumbing, chosen by `findTool` from a fixed
            // candidate list, and the path they were chosen at is already the
            // first element of the recorded argv.
            .host => null,
        };
        const command = try self.allocator.alloc([]const u8, argv.len);
        errdefer self.allocator.free(command);
        for (argv, 0..) |argument, index| {
            command[index] = try self.allocator.dupe(u8, argument);
        }
        try self.tools.append(.{
            .name = try self.allocator.dupe(u8, std.fs.path.basename(argv[0])),
            .version = version,
            .command = command,
            .context = context,
        });
    }

    /// The reported version of a program inside the target root, probed once
    /// and remembered.
    ///
    /// Null when the program answered nothing: `setfiles` takes no
    /// `--version`, and a run has to be able to say so rather than record an
    /// empty string that reads like a blank version.
    fn toolVersion(self: *Session, guest_path: []const u8) !?[]const u8 {
        for (self.tool_versions.items) |probed| {
            if (std.mem.eql(u8, probed.guest_path, guest_path)) return probed.version;
        }
        const version = self.probeToolVersion(guest_path);
        errdefer if (version) |text| self.allocator.free(text);
        const owned_path = try self.allocator.dupe(u8, guest_path);
        errdefer self.allocator.free(owned_path);
        try self.tool_versions.append(.{
            .guest_path = owned_path,
            .version = version,
        });
        return version;
    }

    /// Best-effort, and deliberately not an error: a probe that fails is not a
    /// run that failed, and a tool that reports no version is still a tool
    /// that ran.
    fn probeToolVersion(self: *Session, guest_path: []const u8) ?[]const u8 {
        const captured = self.captureUnrecorded(&.{ guest_path, "--version" }) catch
            return null;
        const first = std.mem.trim(u8, firstLine(captured), " \t\r");
        if (first.len == 0) {
            self.allocator.free(captured);
            return null;
        }
        const owned = self.allocator.dupe(u8, first) catch {
            self.allocator.free(captured);
            return null;
        };
        self.allocator.free(captured);
        return owned;
    }
};

/// A program's reported version, remembered against the path it was probed at.
const ProbedVersion = struct {
    guest_path: []const u8,
    version: ?[]const u8,
};

fn firstLine(text: []const u8) []const u8 {
    const end = std.mem.indexOfScalar(u8, text, '\n') orelse text.len;
    return text[0..end];
}

/// Whether an `/etc/fstab` mounts anything at `/boot`.
///
/// Pure so the rule can be tested against the shapes real fstabs take --
/// comments, `/boot/efi` which is a different mount, a trailing slash --
/// without a privileged run to produce them.
fn declaresSeparateBootFilesystem(contents: []const u8) bool {
    var lines = std.mem.splitScalar(u8, contents, '\n');
    while (lines.next()) |line| {
        const body = std.mem.trim(u8, line, " \t\r");
        if (body.len == 0 or body[0] == '#') continue;
        var fields = std.mem.tokenizeAny(u8, body, " \t");
        _ = fields.next() orelse continue;
        const target = fields.next() orelse continue;
        const trimmed = if (target.len > 1 and target[target.len - 1] == '/')
            target[0 .. target.len - 1]
        else
            target;
        if (std.mem.eql(u8, trimmed, "/boot")) return true;
    }
    return false;
}

const CommandResult = struct {
    term: std.process.Child.Term,
    stdout: []u8,
    stderr: []u8,
    owned_output: bool = true,

    fn deinit(self: *CommandResult, allocator: Allocator) void {
        if (self.owned_output) {
            allocator.free(self.stdout);
            allocator.free(self.stderr);
        }
        self.* = undefined;
    }
};

const Executor = struct {
    context: ?*anyopaque = null,
    /// Reading a variable is reaching outside this process's declared inputs,
    /// exactly like running a command, so it belongs to the same seam. Tests
    /// get `.empty` and so cannot accidentally read the developer's shell.
    environ: std.process.Environ = .empty,
    /// The run's remaining budget, resolved once. Held here rather than passed
    /// at each call site because it is one budget for the whole worker: a
    /// deadline every command got a fresh copy of would bound nothing.
    deadline: customize.Deadline = .unbounded,
    runFn: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        argv: []const []const u8,
        capture_output: bool,
        stdin_file: ?Io.File,
        deadline: customize.Deadline,
    ) anyerror!CommandResult,

    fn system(environ: std.process.Environ) Executor {
        return .{ .runFn = runSystem, .environ = environ };
    }

    fn run(
        self: Executor,
        allocator: Allocator,
        io: Io,
        argv: []const []const u8,
        capture_output: bool,
        stdin_file: ?Io.File,
    ) !CommandResult {
        return self.runFn(
            self.context,
            allocator,
            io,
            argv,
            capture_output,
            stdin_file,
            self.deadline,
        );
    }
};

/// The environment the worker runs under, and the environment it hands to every
/// command it runs. Built rather than inherited in both directions. A credential
/// variable is forwarded into the first and deliberately not into the second:
/// the worker consumes it, and nothing it spawns -- least of all a package
/// scriptlet or a dracut module, which are target-supplied code running as root
/// against the image about to be published -- ever sees it. The repository file
/// is deleted before the initramfs is regenerated; a variable left in the
/// environment would have outlived the channel it was meant to travel on.
fn baseEnvironment(allocator: Allocator) !std.process.Environ.Map {
    var environment = std.process.Environ.Map.init(allocator);
    errdefer environment.deinit();
    try environment.put("HOME", "/root");
    try environment.put("LANG", "C");
    try environment.put("LC_ALL", "C");
    try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    try environment.put("TERM", "dumb");
    return environment;
}

/// Runs one command under the run's budget.
///
/// Every shape pipes, including the one whose output is not captured. An
/// inherited descriptor would leave the worker blocked in `Child.wait`, which
/// takes no deadline; reading is the only place the budget can be applied. So
/// uncaptured output is forwarded to the worker's own streams as it arrives
/// instead of being written to the builder's descriptors directly. It is still
/// unbuffered and still uncaptured -- a build log rather than a value -- but it
/// now passes through a process that can stop waiting for it.
fn runSystem(
    _: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
    capture_output: bool,
    stdin_file: ?Io.File,
    deadline: customize.Deadline,
) !CommandResult {
    var environment = try baseEnvironment(allocator);
    defer environment.deinit();
    if (!capture_output) {
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .environ_map = &environment,
            .stdin = if (stdin_file) |file| .{ .file = file } else .ignore,
            .stdout = .pipe,
            .stderr = .pipe,
        });
        const timed_out = forwardUntilEnd(
            allocator,
            io,
            child.stdout.?,
            child.stderr.?,
            deadline,
        ) catch |err| {
            child.kill(io);
            return err;
        };
        if (timed_out) {
            child.kill(io);
            return error.ExecutionDeadlineExceeded;
        }
        return .{
            .term = try waitBounded(io, &child, deadline),
            .stdout = &.{},
            .stderr = &.{},
            .owned_output = false,
        };
    }
    if (stdin_file) |file| {
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .environ_map = &environment,
            .stdin = .{ .file = file },
            .stdout = .pipe,
            .stderr = .pipe,
        });
        defer child.kill(io);

        var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
        var multi_reader: Io.File.MultiReader = undefined;
        multi_reader.init(
            allocator,
            io,
            multi_reader_buffer.toStreams(),
            &.{ child.stdout.?, child.stderr.? },
        );
        defer multi_reader.deinit();
        const stdout_reader = multi_reader.reader(0);
        const stderr_reader = multi_reader.reader(1);
        while (multi_reader.fill(64, deadline.timeout)) |_| {
            if (stdout_reader.buffered().len > max_command_output or
                stderr_reader.buffered().len > max_command_output)
            {
                return error.StreamTooLong;
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            error.Timeout => return error.ExecutionDeadlineExceeded,
            else => |read_err| return read_err,
        }
        try multi_reader.checkAnyError();
        const term = try waitBounded(io, &child, deadline);
        const stdout = try multi_reader.toOwnedSlice(0);
        errdefer allocator.free(stdout);
        const stderr = try multi_reader.toOwnedSlice(1);
        return .{
            .term = term,
            .stdout = stdout,
            .stderr = stderr,
        };
    }
    const result = std.process.run(allocator, io, .{
        .argv = argv,
        .environ_map = &environment,
        .stdout_limit = .limited(max_command_output),
        .stderr_limit = .limited(max_command_output),
        .timeout = deadline.timeout,
    }) catch |err| switch (err) {
        // `std.process.run` kills the child on its way out, so the name of
        // the failure is the only thing left to translate.
        error.Timeout => return error.ExecutionDeadlineExceeded,
        else => |run_err| return run_err,
    };
    return .{
        .term = result.term,
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
}

/// Reaps a child whose streams have already ended, without waiting past the
/// run's budget.
///
/// `Child.wait` takes no deadline, so a command that closed its descriptors
/// and then hung would block here until something outside gave up -- which is
/// the one case where the worker would stop being the process that reports its
/// own expiry. The exit is therefore waited for through a pidfd, which is
/// pollable, and only then reaped. On a kernel too old to open one the wait
/// falls back to the unbounded form, still backstopped by the parent.
fn waitBounded(
    io: Io,
    child: *std.process.Child,
    deadline: customize.Deadline,
) !std.process.Child.Term {
    if (deadline.expired(io)) {
        child.kill(io);
        return error.ExecutionDeadlineExceeded;
    }
    if (!try exitedWithinDeadline(io, child, deadline)) {
        // `kill` both signals and reaps, so nothing is left of the command
        // that ran out of time.
        child.kill(io);
        return error.ExecutionDeadlineExceeded;
    }
    return child.wait(io);
}

/// Whether the child ended before the budget did. True without waiting at all
/// when there is no budget, or when the exit cannot be watched for.
fn exitedWithinDeadline(
    io: Io,
    child: *std.process.Child,
    deadline: customize.Deadline,
) !bool {
    if (builtin.os.tag != .linux) return true;
    const pid = child.id orelse return true;
    const open_rc = std.os.linux.pidfd_open(pid, 0);
    if (std.os.linux.errno(open_rc) != .SUCCESS) return true;
    const pidfd: i32 = @intCast(open_rc);
    defer _ = std.os.linux.close(pidfd);
    while (true) {
        const remaining = deadline.remainingSeconds(io) orelse return true;
        if (remaining == 0) return false;
        var fds = [_]std.os.linux.pollfd{.{
            .fd = pidfd,
            .events = std.os.linux.POLL.IN,
            .revents = 0,
        }};
        // Woken every second rather than once for the whole remainder, so the
        // wait cannot outlive a budget measured on a clock this poll does not
        // share.
        const poll_rc = std.os.linux.poll(&fds, fds.len, 1000);
        switch (std.os.linux.errno(poll_rc)) {
            .SUCCESS => if (poll_rc != 0) return true,
            .INTR => {},
            // A pidfd that cannot be polled is not a reason to fail a command
            // that may well have finished; the unbounded wait still has the
            // parent behind it.
            else => return true,
        }
    }
}

fn expectSuccess(term: std.process.Child.Term) !void {
    switch (term) {
        .exited => |code| if (code != 0) return error.CommandFailed,
        else => return error.CommandFailed,
    }
}

fn parseLoopPath(allocator: Allocator, bytes: []const u8) ![]u8 {
    const path = std.mem.trim(u8, bytes, " \t\r\n");
    if (!std.mem.startsWith(u8, path, "/dev/loop") or path.len == "/dev/loop".len) {
        return error.InvalidLoopDevice;
    }
    for (path["/dev/loop".len..]) |byte| {
        if (!std.ascii.isDigit(byte)) return error.InvalidLoopDevice;
    }
    return allocator.dupe(u8, path);
}

fn prepareEmptyRoot(io: Io, path: []const u8) !void {
    const cwd = Io.Dir.cwd();
    try cwd.deleteTree(io, path);
    try cwd.createDir(io, path, .default_dir);
}

fn validateGuestMountpoints(io: Io, root_path: []const u8) !void {
    inline for (.{ "/dev", "/proc", "/sys", "/run", "/etc" }) |guest_path| {
        var buffer: [Io.Dir.max_path_bytes]u8 = undefined;
        const path = try std.fmt.bufPrint(
            &buffer,
            "{s}{s}",
            .{ root_path, guest_path },
        );
        const stat = try Io.Dir.cwd().statFile(
            io,
            path,
            .{ .follow_symlinks = false },
        );
        if (stat.kind != .directory) return error.UnsafeGuestMountpoint;
    }
}

fn repositoryHostPath(
    allocator: Allocator,
    root_path: []const u8,
    id: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(
        allocator,
        "{s}/run/zvmi-repos/{s}.repo",
        .{ root_path, id },
    );
}

fn repositoryHostDirectory(
    allocator: Allocator,
    root_path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/run/zvmi-repos", .{root_path});
}

fn tdnfConfigHostPath(
    allocator: Allocator,
    root_path: []const u8,
) ![]u8 {
    return std.fmt.allocPrint(allocator, "{s}/run/zvmi-tdnf.conf", .{root_path});
}

/// Whether an `rpm -qa` record is one of rpm's own trust pseudo-packages
/// rather than a package a transaction installed.
///
/// `rpm --import` records each trusted key as `gpg-pubkey-<keyid>-<timestamp>`
/// with `%{ARCH}` of `(none)`, and this backend imports the declared
/// repository trust before it runs anything. Ordering the baseline read after
/// the import already keeps the declared keys out of the delta; this is for
/// the ones a package transaction imports on its own, which no caller declared
/// and no lock could pin -- `(none)` is not an architecture the pin rules
/// accept, so a lock naming one could never be restated.
/// The key rpm derived from imported trust, without the constant `(none)`
/// architecture rpm gives every one of them.
fn trustKeyIdentity(record: []const u8) []const u8 {
    return record[0 .. record.len - ".(none)".len];
}

fn isTrustPseudoPackage(record: []const u8) bool {
    return std.mem.startsWith(u8, record, "gpg-pubkey-") and
        std.mem.endsWith(u8, record, ".(none)");
}

/// Finds the pin for a package name, or nothing.
///
/// Linear because a lock is the closure of one transaction rather than of a
/// distribution: tens of entries, walked a handful of times.
fn findPin(
    pins: []const customize.PackageVersionLock,
    name: []const u8,
) ?customize.PackageVersionLock {
    for (pins) |pin| {
        if (std.mem.eql(u8, pin.name, name)) return pin;
    }
    return null;
}

/// Whether any pin names the `NAME-EPOCH:VERSION-RELEASE.ARCH` record given.
///
/// Rebuilding the pin's own spec and comparing whole strings, rather than
/// matching the record's name and then its version, because the record is one
/// value with no delimiter that a name may not also contain: `foo-1:2-3.noarch`
/// could be package `foo` or package `foo-1`, and only an equality against a
/// candidate spec decides it without guessing.
fn pinsCover(
    pins: []const customize.PackageVersionLock,
    record: []const u8,
) bool {
    for (pins) |pin| {
        if (record.len != pin.name.len + 1 + pin.evr.len + 1 + pin.architecture.len) continue;
        if (!std.mem.startsWith(u8, record, pin.name)) continue;
        if (record[pin.name.len] != '-') continue;
        const rest = record[pin.name.len + 1 ..];
        if (!std.mem.startsWith(u8, rest, pin.evr)) continue;
        if (rest[pin.evr.len] != '.') continue;
        if (!std.mem.eql(u8, rest[pin.evr.len + 1 ..], pin.architecture)) continue;
        return true;
    }
    return false;
}

fn containsBytes(haystack: []const []const u8, needle: []const u8) bool {
    for (haystack) |candidate| {
        if (std.mem.eql(u8, candidate, needle)) return true;
    }
    return false;
}

/// The lock rules the worker enforces on its own side of the privilege
/// boundary.
///
/// `validate` already refused every lock that is not a complete identity, and
/// `unsafeChrootCapabilityState` already refused every one whose bytes this
/// backend could not put on a command line. Both ran in the parent. This
/// manifest arrives as JSON read after re-execing as root, so neither of those
/// checks covers the bytes actually in hand.
fn validManifestLock(lock: customize.PackageLockPolicy) bool {
    const pins = switch (lock) {
        .unlocked => return true,
        // Nothing in this root can be compared against a repository snapshot
        // id, so the worker must not accept one and then run as though the
        // policy had been honoured.
        .snapshot => return false,
        .exact => |pins| pins,
    };
    if (pins.len == 0) return false;
    for (pins, 0..) |pin, index| {
        if (!validPackageName(pin.name)) return false;
        if (!validLockEvr(pin.evr)) return false;
        if (!validKernelRelease(pin.architecture)) return false;
        for (pins[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, pin.name) and
                std.mem.eql(u8, previous.architecture, pin.architecture))
            {
                return false;
            }
        }
    }
    return true;
}

fn validLockEvr(evr: []const u8) bool {
    if (evr.len == 0 or !std.ascii.isAlphanumeric(evr[0])) return false;
    // The full `epoch:version-release`, for the reason `PackageVersionLock`
    // gives: a bare version is not a pin.
    if (std.mem.indexOfScalar(u8, evr, ':') == null) return false;
    if (std.mem.indexOfScalar(u8, evr, '-') == null) return false;
    for (evr[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~' and
            byte != '^' and
            byte != ':')
        {
            return false;
        }
    }
    return true;
}

fn validateManifestPolicy(manifest: Manifest) !void {
    if (!validManifestLock(manifest.packages.lock)) {
        return error.UnsupportedPackagePolicy;
    }
    // The parent validated this, and this process mounts what it names while
    // running as root, so it is re-checked rather than trusted.
    if (customize.packageCacheDirectory(manifest.packages.cache)) |directory| {
        customize.validatePackageCacheDirectory(directory) catch {
            return error.UnsupportedPackagePolicy;
        };
    }
    // A locked run rewrites these names into pinned specs, so one the lock
    // omits would silently run unpinned inside a transaction the plan hash
    // describes as pinned.
    if (manifest.packages.lock == .exact) {
        const pins = manifest.packages.lock.exact;
        // Pins describe a transaction; with no actions there is none, and the
        // coverage check would compare the whole installed set against an
        // empty baseline.
        if (manifest.packages.actions.len == 0) return error.UnsupportedPackagePolicy;
        for (manifest.packages.actions) |action| {
            const names: []const []const u8 = switch (action) {
                .install, .update_selected => |values| values,
                .remove => continue,
                // Its subject is whatever the repositories hold, which is the
                // question the lock exists to close.
                .update_all => return error.UnsupportedPackagePolicy,
            };
            for (names) |name| {
                if (findPin(pins, name) == null) return error.UnsupportedPackagePolicy;
            }
        }
    }
    for (manifest.packages.repositories) |repository| {
        if (!validRepositoryId(repository.id)) return error.InvalidRepositoryId;
        // The worker re-reads this manifest from JSON after re-execing as
        // root, so it checks the URLs on its own side of the boundary rather
        // than trusting the validator that already did. A userinfo component
        // is the case worth naming: it is a credential in the one field that
        // is hashed, published and kept in provenance verbatim.
        for (repository.urls) |url| {
            if (vm_control.hasUserinfo(url)) return error.RepositoryUrlCarriesCredential;
            if (!vm_control.validRepositoryUrl(url)) return error.InvalidRepositoryUrl;
            // Basic authentication puts the password on the wire, so a
            // credentialed repository has to be reached over TLS. Re-checked
            // here because the URL and the credential arrive together in a
            // document this side of the boundary did not write.
            if (repository.credential != null and
                !std.mem.startsWith(u8, url, "https://"))
            {
                return error.CredentialedRepositoryNotEncrypted;
            }
        }
        if (repository.credential) |credential| switch (credential) {
            .basic => |basic| {
                if (!validCredentialField(
                    basic.username,
                    customize.max_credential_field_bytes,
                )) {
                    return error.InvalidCredentialUsername;
                }
                switch (basic.password) {
                    .host_path => |path| if (!std.fs.path.isAbsolute(path) or
                        !validCredentialField(path, Io.Dir.max_path_bytes))
                    {
                        return error.InvalidCredentialSource;
                    },
                    .host_environment => |name| if (!validEnvironmentName(name)) {
                        return error.InvalidCredentialSource;
                    },
                }
            },
        };
    }
    var needs_repository = false;
    for (manifest.packages.actions) |action| {
        const names: []const []const u8 = switch (action) {
            .install, .update_selected => |values| blk: {
                needs_repository = true;
                break :blk values;
            },
            .remove => |values| values,
            // Naming nothing is what `update_all` means; every other action
            // must name at least one package.
            .update_all => {
                needs_repository = true;
                continue;
            },
        };
        if (names.len == 0) return error.EmptyPackageAction;
        for (names) |name| {
            if (!validPackageName(name)) return error.InvalidPackageName;
        }
    }
    // An update names no package to fail on: it resolves against whatever the
    // enabled repositories hold, so with none declared tdnf consults nothing
    // and exits successfully having done nothing. An install without
    // repositories fails loudly instead, but both are refused here rather than
    // letting a no-op be reported as a completed policy. The request validator
    // already requires this; the worker repeats it because it sits across the
    // privilege boundary and does not trust the manifest it is handed.
    if (needs_repository and manifest.packages.repositories.len == 0) {
        return error.PackageActionWithoutRepositories;
    }
    switch (manifest.initramfs) {
        .unchanged => {},
        .regenerate => |regenerate| {
            // An empty list means "every kernel release installed in the
            // target root", resolved at run time after the package actions.
            // It is not refused here; a run that then discovers none fails
            // with `NoInstalledKernels` rather than reporting a completed
            // policy for work it did not do.
            for (regenerate.kernels) |kernel| {
                if (!validKernelRelease(kernel)) {
                    return error.InvalidKernelRelease;
                }
            }
            if (regenerate.generator) |generator| {
                if (!std.mem.eql(u8, generator, "dracut")) {
                    return error.UnsupportedInitramfsGenerator;
                }
            }
        },
        // The host resolves this away before the plan is built, so a manifest
        // carrying it did not come from a plan this worker should run. Refused
        // by name rather than treated as either outcome: guessing here would
        // either skip work the caller asked for or do work it did not.
        .when_needed => return error.UnresolvedInitramfsPolicy,
    }
    // Re-checked on this side of the privilege boundary for the same reason
    // the package names are: the policy name reaches a path this worker builds
    // and an argument vector it runs as root, and the validator that already
    // checked it is on the other side. A `.configure` that names neither
    // setting is refused here too -- the host refuses it at validation, and a
    // manifest carrying it did not come from a plan this worker should run.
    switch (manifest.selinux) {
        .unchanged, .relabel => {},
        .configure => |configure| {
            if (configure.mode == null and configure.policy == null) {
                return error.EmptySelinuxConfiguration;
            }
            if (configure.policy) |name| {
                if (!selinux_mod.validPolicyName(name)) {
                    return error.UnsupportedSelinuxPolicy;
                }
            }
        },
    }
    // The option text is checked on this side of the privilege boundary for
    // the same reason the package names are: it ends up inside a shell
    // assignment in a file this worker writes as root into the target root,
    // and the validator that already checked it is on the other side.
    if (manifest.kernel_options.len != 0) {
        boot_options.validateOptions(manifest.kernel_options) catch {
            return error.InvalidKernelOptions;
        };
        try grub_defaults.validateOptions(manifest.kernel_options);
    }
    // A hook is caller-supplied code that this worker will run as root inside
    // the target root, so the manifest's account of it is re-checked on this
    // side of the privilege boundary rather than trusted. The phase order is
    // part of that: the plan published an operation list in this order, and a
    // worker that ran them in another would have executed something the plan
    // does not describe.
    var previous_phase: ?customize.HookPhase = null;
    for (manifest.hooks, 0..) |hook, index| {
        if (!validHookName(hook.name)) return error.InvalidHookName;
        for (manifest.hooks[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, hook.name)) return error.DuplicateHookName;
        }
        if (previous_phase) |phase| {
            if (@intFromEnum(hook.phase) < @intFromEnum(phase)) {
                return error.HookPhasesOutOfOrder;
            }
        }
        previous_phase = hook.phase;
        // Only the inline form can be checked here. A `host_path` source is
        // bytes this side has not read yet, and `readHookScript` holds it to
        // the same rule at the moment it becomes readable.
        switch (hook.source) {
            .inline_script => |script| if (!validHookScript(script)) {
                return error.HookScriptUnusable;
            },
            .host_path => |path| if (path.len == 0) return error.InvalidHookSource,
        }
        if (hook.arguments.len > customize.max_hook_arguments) {
            return error.TooManyHookArguments;
        }
        for (hook.arguments) |argument| {
            if (argument.len > customize.max_hook_argument_bytes) {
                return error.HookArgumentTooLong;
            }
            if (std.mem.indexOfScalar(u8, argument, 0) != null) {
                return error.InvalidHookArgument;
            }
        }
    }
    // The request validator already refused these, but the worker sits across
    // the privilege boundary and does not trust the manifest it is handed. A
    // name reaching the renderer unchecked would be a line of its own in a
    // modprobe configuration file.
    switch (manifest.packages.resolver) {
        .host_resolver => {},
        // Same reasoning one field over: each entry is written verbatim as a
        // `nameserver` line, so an unchecked value carrying a newline would
        // add directives of its own to the resolver the transaction runs
        // against. The guest agent re-validates the identical rule on its
        // side of the same boundary.
        .nameservers => |nameservers| try vm_control.validateNameservers(nameservers),
    }
    for (manifest.kernel_modules) |module| {
        if (!validKernelModuleName(module.name)) {
            return error.InvalidKernelModuleName;
        }
        if (module.load and module.disabled) {
            return error.ContradictoryKernelModule;
        }
        if (module.options) |options| {
            // `\\` joins this directive to the one rendered after it.
            if (std.mem.indexOfAny(u8, options, "\r\n\x00\\") != null) {
                return error.InvalidKernelModuleOptions;
            }
        }
    }
}

/// Mirrors `customize.validKernelModuleName`. An allowlist rather than a list
/// of refusals, because every way out of a `modules-load.d` line or a
/// `modprobe.d` directive's subject position is silent: whitespace retargets
/// the directive, a trailing `\` continues the line over the next one, and a
/// leading `#` or `;` comments the line out.
fn validKernelModuleName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '_' and byte != '-' and byte != '.')
        {
            return false;
        }
    }
    return true;
}

fn validRepositoryId(id: []const u8) bool {
    if (id.len == 0 or !std.ascii.isAlphanumeric(id[0])) return false;
    for (id[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '-')
        {
            return false;
        }
    }
    return true;
}

fn validPackageName(name: []const u8) bool {
    if (name.len == 0 or !std.ascii.isAlphanumeric(name[0])) return false;
    if (name.len >= 4 and
        std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".rpm"))
    {
        return false;
    }
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~' and
            byte != '^')
        {
            return false;
        }
    }
    return true;
}

fn lessThanBytes(_: void, left: []const u8, right: []const u8) bool {
    return std.mem.lessThan(u8, left, right);
}

/// Whether depmod left its output beside a release, which is what separates an
/// installed kernel from the firmware directories and stray names that share
/// `/lib/modules` with it.
///
/// An absent marker is an answer: this is not a kernel. A marker that cannot
/// be looked at is not, and returning `false` for one would drop a real kernel
/// from the discovered set -- a set that came up empty that way is accepted as
/// "nothing is stale" whenever the host derived the regeneration rather than
/// being asked for it, and the run would ship the initramfs it invalidated.
fn hasDepmodOutput(io: Io, release_dir: Io.Dir) !bool {
    for ([_][]const u8{ "modules.dep", "modules.dep.bin" }) |marker| {
        release_dir.access(io, marker, .{}) catch |err| switch (err) {
            error.FileNotFound => continue,
            else => return err,
        };
        return true;
    }
    return false;
}

fn validKernelRelease(kernel: []const u8) bool {
    if (kernel.len == 0 or !std.ascii.isAlphanumeric(kernel[0])) return false;
    for (kernel[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~')
        {
            return false;
        }
    }
    return true;
}

fn joinGuest(
    allocator: Allocator,
    root_path: []const u8,
    guest_path: []const u8,
) ![]u8 {
    if (guest_path.len == 0 or guest_path[0] != '/') return error.InvalidGuestPath;
    return std.fmt.allocPrint(allocator, "{s}{s}", .{ root_path, guest_path });
}

fn writeBytes(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{});
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

const default_repository_permissions: Io.File.Permissions = .default_file;
/// umask can only clear bits, so this is 0o600 or narrower however the caller's
/// process is configured. It can never come out more permissive.
const credentialed_repository_permissions: Io.File.Permissions = .fromMode(0o600);

/// tdnf reads a repository file as INI, so a newline or a NUL in the material
/// would end the `password=` line and let the rest be read as configuration.
/// `limit` rather than one constant, because a path and a user name are bounded
/// by different things. Both bounds are the request validator's, so this side of
/// the privilege boundary refuses exactly what that side refuses and no more: a
/// rule that is stricter here would accept a request and then fail it after the
/// workspace has been copied and the image staged.
fn validCredentialField(text: []const u8, limit: usize) bool {
    if (text.len == 0 or text.len > limit) return false;
    for (text) |byte| {
        if (byte < 0x20 or byte == 0x7f) return false;
    }
    return true;
}

fn validEnvironmentName(name: []const u8) bool {
    if (name.len == 0 or name.len > customize.max_credential_field_bytes) return false;
    if (std.ascii.isDigit(name[0])) return false;
    for (name) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    return true;
}

/// Overwrites a variable's value in the process's own environment block, in
/// place. The name is left behind because it is not a secret and is already in
/// the plan; only the material goes.
///
/// This narrows the window rather than making the backend safe. `unsafe_chroot`
/// runs package scriptlets as root against the host kernel and says so: code
/// that wants the credential can leave the chroot and read the file a
/// `host_path` credential names. The point is that a secret should not sit in a
/// process image for the length of a run when the run needed it once.
/// Copies the value of every variable a declared credential names into the
/// worker's environment, and refuses now rather than after the image has been
/// mounted and half mutated. An unset variable is a declaration the host cannot
/// honour, which is a refusal, not an empty password.
fn forwardCredentialVariables(
    allocator: Allocator,
    environ: std.process.Environ,
    map: *std.process.Environ.Map,
    manifest: Manifest,
) !void {
    for (manifest.packages.repositories) |repository| {
        const credential = repository.credential orelse continue;
        const name = switch (credential) {
            .basic => |basic| switch (basic.password) {
                .host_environment => |name| name,
                .host_path => continue,
            },
        };
        const value = std.process.Environ.getAlloc(environ, allocator, name) catch
            return error.CredentialSourceUnreadable;
        defer {
            @memset(value, 0);
            allocator.free(value);
        }
        if (!credential_mod.validMaterial(value)) return error.CredentialMaterialUnusable;
        try map.put(name, value);
    }
}

fn writeBytesExclusive(
    io: Io,
    path: []const u8,
    bytes: []const u8,
    permissions: Io.File.Permissions,
) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{
        .exclusive = true,
        .permissions = permissions,
    });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

/// A hook script, written where only this run can reach it and made executable
/// by an explicit mode rather than by whatever `umask` the builder inherited.
/// An owner-execute bit cleared by a stray umask would turn a declared hook
/// into an `ENOEXEC` several phases into a privileged run.
fn writeExecutableExclusive(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{
        .exclusive = true,
        .permissions = hook_script_permissions,
    });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
    try file.setPermissions(io, hook_script_permissions);
}

const hook_script_permissions: Io.File.Permissions = .fromMode(0o700);

/// Whether these bytes are a hook this worker will run: non-empty, within the
/// declared bound, and naming their own interpreter. The last is what makes an
/// unrunnable hook a named refusal rather than a `chroot` that exits nonzero
/// for a reason nothing recorded.
fn validHookScript(bytes: []const u8) bool {
    return bytes.len != 0 and
        bytes.len <= customize.max_hook_script_bytes and
        std.mem.startsWith(u8, bytes, "#!");
}

fn validHookName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255 or name[0] == '.') return false;
    return std.mem.indexOfAny(u8, name, "/\r\n\x00") == null;
}

fn copyFile(
    allocator: Allocator,
    io: Io,
    source_path: []const u8,
    destination_path: []const u8,
) !void {
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        source_path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    defer allocator.free(bytes);
    try writeBytes(io, destination_path, bytes);
}

fn isRegularFileFollow(io: Io, path: []const u8) bool {
    const stat = Io.Dir.cwd().statFile(
        io,
        path,
        .{ .follow_symlinks = true },
    ) catch return false;
    return stat.kind == .file;
}

fn pathExistsNoFollow(io: Io, path: []const u8) bool {
    _ = Io.Dir.cwd().statFile(
        io,
        path,
        .{ .follow_symlinks = false },
    ) catch return false;
    return true;
}

fn statusEquals(io: Io, path: []const u8, expected: []const u8) bool {
    var buffer: [64]u8 = undefined;
    const file = Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only }) catch
        return false;
    defer file.close(io);
    const count = file.readPositionalAll(io, &buffer, 0) catch return false;
    return std.mem.eql(u8, buffer[0..count], expected);
}

const WorkerOutcome = enum {
    never_started,
    cleanup_uncertain,
    cleanup_complete_failed,
    cleanup_complete_success,
    /// The worker stopped because the run's budget was spent, and finished its
    /// own teardown before saying so.
    cleanup_complete_deadline,
};

/// What the worker left behind, read from the status file rather than from its
/// exit status, because the exit status cannot distinguish a worker that tore
/// its own resources down from one that died holding them.
///
/// `term` is absent when the parent killed the worker on its own bound. That
/// says nothing new about cleanup, so the status file still decides; a killed
/// worker that had already written `cleanup-complete` really had.
fn classifyWorkerOutcome(
    io: Io,
    status_path: []const u8,
    term: ?std.process.Child.Term,
) WorkerOutcome {
    if (statusEquals(io, status_path, deadline_exceeded_text)) {
        return .cleanup_complete_deadline;
    }
    if (statusEquals(io, status_path, cleanup_complete_text)) {
        const exit_term = term orelse return .cleanup_complete_failed;
        return switch (exit_term) {
            .exited => |code| if (code == 0)
                .cleanup_complete_success
            else
                .cleanup_complete_failed,
            else => .cleanup_complete_failed,
        };
    }
    return if (statusEquals(io, status_path, worker_started_text))
        .cleanup_uncertain
    else
        .never_started;
}

const WorkerSupervision = struct {
    /// Absent when the parent gave up on the worker and killed it.
    term: ?std.process.Child.Term,
    timed_out: bool,
};

/// Runs the worker to completion, forwarding what it prints, and gives up on
/// it a fixed grace after the run's deadline.
///
/// The output is forwarded rather than captured because it is a build log
/// rather than a value the run consumes: a package transaction's progress and
/// a hook's output belong on the builder's own streams as they happen. It
/// travels through a pipe rather than an inherited descriptor only because
/// reading is the one place a wall clock can be applied -- `Child.wait` takes
/// no deadline.
fn superviseWorker(
    allocator: Allocator,
    io: Io,
    child: *std.process.Child,
    timeout: customize.Deadline,
) !WorkerSupervision {
    // Every path out of here that is not a clean exit leaves the worker
    // killed. A supervisor that returned an error while the process it was
    // supervising kept running would leave privileged target code executing
    // with nothing left watching it.
    errdefer child.kill(io);
    const timed_out = try forwardUntilEnd(
        allocator,
        io,
        child.stdout.?,
        child.stderr.?,
        timeout,
    );
    if (timed_out) {
        // Kills `unshare`. The worker holds `PR_SET_PDEATHSIG` from
        // `--kill-child`, so the PID namespace's init dies with its parent and
        // the kernel removes every process left inside the namespace. What it
        // cannot remove is anything global the worker had attached -- a loop
        // device outlives the namespace -- which is why this path reports
        // through the status file rather than as a clean stop.
        child.kill(io);
        return .{ .term = null, .timed_out = true };
    }
    return .{ .term = try child.wait(io), .timed_out = false };
}

/// Forwards a process's two output streams until both end, or until the
/// budget is spent -- which it reports rather than raises, because the caller
/// is the one that knows what the process it was reading is.
///
/// Its reader is torn down before it returns, so a caller that goes on to kill
/// the process owning these descriptors is not cancelling a read still in
/// flight against them.
fn forwardUntilEnd(
    allocator: Allocator,
    io: Io,
    stdout_file: Io.File,
    stderr_file: Io.File,
    deadline: customize.Deadline,
) !bool {
    var multi_reader_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: Io.File.MultiReader = undefined;
    multi_reader.init(
        allocator,
        io,
        multi_reader_buffer.toStreams(),
        &.{ stdout_file, stderr_file },
    );
    defer multi_reader.deinit();
    var timed_out = false;
    while (multi_reader.fill(4096, deadline.timeout)) |_| {
        forwardWorkerOutput(io, &multi_reader);
    } else |err| switch (err) {
        error.EndOfStream => {},
        error.Timeout => timed_out = true,
        else => |read_err| return read_err,
    }
    forwardWorkerOutput(io, &multi_reader);
    return timed_out;
}

/// Copies whatever has arrived to the builder's own streams and drops it, so
/// the forwarding buffer stays a window rather than a transcript.
fn forwardWorkerOutput(io: Io, multi_reader: *Io.File.MultiReader) void {
    forwardStream(io, multi_reader.reader(0), Io.File.stdout());
    forwardStream(io, multi_reader.reader(1), Io.File.stderr());
}

fn forwardStream(io: Io, reader: *Io.Reader, file: Io.File) void {
    const bytes = reader.buffered();
    if (bytes.len == 0) return;
    // A builder whose own stdout has gone away is not a reason to fail a
    // privileged run that is otherwise proceeding.
    file.writeStreamingAll(io, bytes) catch {};
    reader.toss(bytes.len);
}

/// Reads the worker's report and puts the parent's own spawn at the head of
/// it.
///
/// The `unshare` invocation is the only command the parent runs on the execute
/// path, and it is the one that decides which namespaces everything after it
/// ran in -- so it belongs first, before the mounts the worker made inside
/// them. The worker cannot record it, because the worker is its child.
fn loadParentReport(
    allocator: Allocator,
    io: Io,
    path: []const u8,
    worker_argv: []const []const u8,
) !customize.UnsafeChrootRuntimeReport {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const report_allocator = arena.allocator();
    const bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        path,
        report_allocator,
        .limited(16 * 1024 * 1024),
    );
    const parsed = try std.json.parseFromSlice(
        WorkerReport,
        report_allocator,
        bytes,
        .{ .ignore_unknown_fields = false },
    );
    const tools = try report_allocator.alloc(
        customize.ToolRecord,
        parsed.value.tools.len + 1,
    );
    const command = try report_allocator.alloc([]const u8, worker_argv.len);
    for (worker_argv, 0..) |argument, index| {
        command[index] = try report_allocator.dupe(u8, argument);
    }
    tools[0] = .{
        .name = try report_allocator.dupe(
            u8,
            std.fs.path.basename(worker_argv[0]),
        ),
        .version = null,
        .command = command,
        .context = .host,
    };
    @memcpy(tools[1..], parsed.value.tools);
    return .{
        .arena = arena,
        .tools = tools,
        .installed_packages = parsed.value.installed_packages,
        .imported_trust_keys = parsed.value.imported_trust_keys,
        .package_lock = parsed.value.package_lock,
        .hooks = parsed.value.hooks,
        .boot_configuration = parsed.value.boot_configuration,
        .package_cache = parsed.value.package_cache,
        .selinux_relabel = parsed.value.selinux_relabel,
        .host_resolver = parsed.value.host_resolver,
        .initramfs = parsed.value.initramfs,
    };
}

fn findTool(io: Io, candidates: []const []const u8) ?[]const u8 {
    for (candidates) |path| {
        const stat = Io.Dir.cwd().statFile(
            io,
            path,
            .{ .follow_symlinks = false },
        ) catch continue;
        if (stat.kind == .file) return path;
    }
    return null;
}

fn hasRequiredCapabilities() bool {
    if (builtin.os.tag != .linux) return false;
    var header = std.os.linux.cap_user_header_t{
        .version = 0x20080522,
        .pid = 0,
    };
    var data = [_]std.os.linux.cap_user_data_t{
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
        .{ .effective = 0, .permitted = 0, .inheritable = 0 },
    };
    if (std.os.linux.capget(&header, &data[0]) != 0) return false;
    inline for (.{ 18, 21, 27 }) |capability| {
        const index = capability / 32;
        const bit: u5 = @intCast(capability % 32);
        if (data[index].effective & (@as(u32, 1) << bit) == 0) return false;
    }
    return true;
}

fn isCharacterDevice(io: Io, path: []const u8) bool {
    const stat = Io.Dir.cwd().statFile(
        io,
        path,
        .{ .follow_symlinks = false },
    ) catch return false;
    return stat.kind == .character_device;
}

fn probeUnshare(io: Io) bool {
    const unshare = findTool(io, unshare_candidates) orelse return false;
    const true_exe = findTool(io, true_candidates) orelse return false;
    var child = std.process.spawn(io, .{
        .argv = &.{
            unshare,
            "--mount",
            "--pid",
            "--fork",
            "--kill-child",
            "--mount-proc",
            "--propagation",
            "private",
            "--",
            true_exe,
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    }) catch return false;
    const term = child.wait(io) catch return false;
    return switch (term) {
        .exited => |code| code == 0,
        else => false,
    };
}

const unshare_candidates = &.{ "/usr/bin/unshare", "/bin/unshare" };
const losetup_candidates = &.{ "/usr/sbin/losetup", "/sbin/losetup", "/usr/bin/losetup" };
const mount_candidates = &.{ "/usr/bin/mount", "/bin/mount" };
const umount_candidates = &.{ "/usr/bin/umount", "/bin/umount" };
const chroot_candidates = &.{ "/usr/sbin/chroot", "/usr/bin/chroot" };
const mknod_candidates = &.{ "/usr/bin/mknod", "/bin/mknod" };
const sync_candidates = &.{ "/usr/bin/sync", "/bin/sync" };
const true_candidates = &.{ "/usr/bin/true", "/bin/true" };

test "loop device parser rejects command injection" {
    const valid = try parseLoopPath(std.testing.allocator, " /dev/loop12\n");
    defer std.testing.allocator.free(valid);
    try std.testing.expectEqualStrings("/dev/loop12", valid);
    try std.testing.expectError(
        error.InvalidLoopDevice,
        parseLoopPath(std.testing.allocator, "/dev/loop1\n/dev/loop2"),
    );
    try std.testing.expectError(
        error.InvalidLoopDevice,
        parseLoopPath(std.testing.allocator, "/dev/loop1;touch /tmp/x"),
    );
}

test "worker policy identifiers are literal and package-only" {
    try std.testing.expect(validRepositoryId("base-1.0"));
    try std.testing.expect(!validRepositoryId("*"));
    try std.testing.expect(!validRepositoryId("base,updates"));
    try std.testing.expect(validPackageName("systemd-257.5-1.azl4"));
    try std.testing.expect(validPackageName("libstdc++"));
    try std.testing.expect(!validPackageName("payload.rpm"));
    try std.testing.expect(!validPackageName("https://example.invalid/x.rpm"));
    try std.testing.expect(!validPackageName("./x.rpm"));
    try std.testing.expect(!validPackageName("-y"));
    try std.testing.expect(validKernelRelease("6.12.0-1.azl4.aarch64"));
    try std.testing.expect(!validKernelRelease("../../etc/passwd"));
}

test "worker policy accepts updates and still refuses an unnamed selective update" {
    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const base = Manifest{
        .raw_path = "/tmp/stage.raw",
        .root_path = "/tmp/root",
        .status_path = "/tmp/status",
        .report_path = "/tmp/report",
        .stage_inode = 1,
        .virtual_size = 0,
        .partition_offset = 0,
        .partition_length = 0,
        .packages = .{},
        .initramfs = .unchanged,
    };

    var manifest = base;
    manifest.packages = .{
        .actions = &.{ .update_all, .{ .update_selected = &.{"kernel"} } },
        .repositories = &repositories,
    };
    try validateManifestPolicy(manifest);

    // An update consults repositories rather than named packages, so with none
    // declared it would succeed having done nothing.
    manifest.packages = .{ .actions = &.{.update_all} };
    try std.testing.expectError(
        error.PackageActionWithoutRepositories,
        validateManifestPolicy(manifest),
    );

    manifest.packages = .{ .actions = &.{.{ .install = &.{"dracut"} }} };
    try std.testing.expectError(
        error.PackageActionWithoutRepositories,
        validateManifestPolicy(manifest),
    );

    // Removal needs no repository, so it stays legal without one.
    manifest.packages = .{ .actions = &.{.{ .remove = &.{"obsolete"} }} };
    try validateManifestPolicy(manifest);

    // `update_all` is the only action that legitimately names nothing.
    manifest.packages = .{
        .actions = &.{.{ .update_selected = &.{} }},
        .repositories = &repositories,
    };
    try std.testing.expectError(error.EmptyPackageAction, validateManifestPolicy(manifest));

    manifest.packages = .{
        .actions = &.{.{ .update_selected = &.{"payload.rpm"} }},
        .repositories = &repositories,
    };
    try std.testing.expectError(error.InvalidPackageName, validateManifestPolicy(manifest));

    // A cache directory the parent could not have produced is refused on
    // this side of the privilege boundary too: this process mounts it.
    manifest.packages = .{
        .actions = &.{.{ .install = &.{"payload"} }},
        .repositories = &repositories,
        .cache = .{ .cache_only = "/var/cache/../../etc" },
    };
    try std.testing.expectError(error.UnsupportedPackagePolicy, validateManifestPolicy(manifest));

    manifest.packages = .{
        .actions = &.{.{ .install = &.{"payload"} }},
        .repositories = &repositories,
        .cache = .{ .online_populating = "relative/cache" },
    };
    try std.testing.expectError(error.UnsupportedPackagePolicy, validateManifestPolicy(manifest));

    manifest.packages = .{
        .actions = &.{.update_all},
        .repositories = &repositories,
        .lock = .{ .snapshot = "s1" },
    };
    try std.testing.expectError(error.UnsupportedPackagePolicy, validateManifestPolicy(manifest));
}

test "worker status distinguishes startup cleanup and operation outcomes" {
    const io = std.testing.io;
    const status_path = "test-unsafe-chroot.status";
    defer Io.Dir.cwd().deleteFile(io, status_path) catch {};
    try std.testing.expectEqual(
        WorkerOutcome.never_started,
        classifyWorkerOutcome(io, status_path, .{ .exited = 1 }),
    );
    try writeBytes(io, status_path, worker_started_text);
    try std.testing.expectEqual(
        WorkerOutcome.cleanup_uncertain,
        classifyWorkerOutcome(io, status_path, .{ .exited = 1 }),
    );
    try writeBytes(io, status_path, cleanup_complete_text);
    try std.testing.expectEqual(
        WorkerOutcome.cleanup_complete_failed,
        classifyWorkerOutcome(io, status_path, .{ .exited = 1 }),
    );
    try std.testing.expectEqual(
        WorkerOutcome.cleanup_complete_success,
        classifyWorkerOutcome(io, status_path, .{ .exited = 0 }),
    );
    // A worker the parent killed on its own bound reports no exit status. The
    // status file still decides, and cleanup it had already finished stays
    // finished.
    try std.testing.expectEqual(
        WorkerOutcome.cleanup_complete_failed,
        classifyWorkerOutcome(io, status_path, null),
    );
    try writeBytes(io, status_path, deadline_exceeded_text);
    try std.testing.expectEqual(
        WorkerOutcome.cleanup_complete_deadline,
        classifyWorkerOutcome(io, status_path, .{ .exited = 1 }),
    );
    try std.testing.expectEqual(
        WorkerOutcome.cleanup_complete_deadline,
        classifyWorkerOutcome(io, status_path, null),
    );
}

test "worker executes policy with strict reverse cleanup" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-root";
    const raw_path = "test-unsafe-chroot-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const actions = [_]customize.PackageAction{
        .{ .install = &.{"dracut"} },
        .{ .remove = &.{"obsolete"} },
    };
    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &actions,
            .repositories = &repositories,
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.12.0-test"},
        } },
    };
    var mismatched_manifest = manifest;
    mismatched_manifest.stage_inode +%= 1;
    var identity_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
    };
    const identity_mismatch = try executeManifest(
        allocator,
        io,
        mismatched_manifest,
        .{
            .context = &identity_context,
            .runFn = FakeExecutorContext.run,
        },
    );
    try std.testing.expectEqual(RunOutcome.failed, identity_mismatch.outcome);
    try std.testing.expect(!identity_mismatch.cleanup_complete);
    try std.testing.expectEqual(
        @as(usize, 0),
        identity_context.associated_queries,
    );

    var inventory_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .malformed_inventory = true,
    };
    const malformed_inventory = try executeManifest(
        allocator,
        io,
        manifest,
        .{
            .context = &inventory_context,
            .runFn = FakeExecutorContext.run,
        },
    );
    try std.testing.expectEqual(RunOutcome.failed, malformed_inventory.outcome);
    try std.testing.expect(!malformed_inventory.cleanup_complete);
    try std.testing.expectEqual(
        @as(usize, 1),
        inventory_context.associated_queries,
    );

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
    };
    const executor = Executor{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    };
    const result = try executeManifest(allocator, io, manifest, executor);
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expect(result.cleanup_complete);
    // Named rather than indexed: the report is every command the run issued,
    // in run order, so pinning a position would make any new mount a test
    // failure while saying nothing about what was recorded.
    try std.testing.expectEqualStrings(
        "RPM version 4.18.0",
        (try findToolRecord(result.report.tools, "rpm")).version.?,
    );
    try std.testing.expectEqualStrings(
        "tdnf 3.5.0",
        (try findToolRecord(result.report.tools, "tdnf")).version.?,
    );
    try std.testing.expectEqualStrings(
        "dracut 102",
        (try findToolRecord(result.report.tools, "dracut")).version.?,
    );
    try std.testing.expectEqualStrings(
        "cp (GNU coreutils) 9.4",
        (try findToolRecord(result.report.tools, "cp")).version.?,
    );
    // The privileged host commands the run performed on its own behalf. None
    // of these is implied by a package transaction, and before #308 none of
    // them was recorded at all: the report described what ran inside the
    // target root and stayed silent about what built the target root.
    for ([_][]const u8{ "losetup", "mount", "umount", "mknod", "sync" }) |name| {
        const tool = try findToolRecord(result.report.tools, name);
        try std.testing.expectEqual(customize.ToolContext.host, tool.context);
    }
    // Teardown is inside the published report: the worker writes the report
    // only after cleanup completes, so the unmounts that released the target
    // are recorded rather than lost to the write that preceded them.
    try std.testing.expect(
        lastToolIndex(result.report.tools, "umount").? >
            lastToolIndex(result.report.tools, "dracut").?,
    );
    // A version probe is never a command of its own. It is recorded as the
    // version of the command it describes, so `--version` must not appear as
    // an argv in its own right -- otherwise the report doubles in size and
    // reads as if the run had asked every tool to do nothing.
    for (result.report.tools) |tool| {
        try std.testing.expect(tool.name.len != 0);
        try std.testing.expect(tool.command.len != 0);
        for (tool.command) |argument| {
            try std.testing.expect(!std.mem.eql(u8, argument, "--version"));
        }
    }
    try std.testing.expectEqual(
        @as(usize, 2),
        result.report.installed_packages.len,
    );
    try std.testing.expectEqualStrings(
        "bash-0:5.2-1.aarch64",
        result.report.installed_packages[0],
    );
    try std.testing.expectEqualStrings(
        "zlib-0:1.3-2.aarch64",
        result.report.installed_packages[1],
    );
    // The one input a plan cannot carry. `host_resolver` is the default, so
    // this is the ordinary case: the transaction resolved its repository names
    // through whatever this machine happens to be pointed at, and the run
    // recorded nothing about it. Digest and size only -- what the file names
    // is this machine's DNS topology, which no caller declared and no
    // published image should carry.
    if (isRegularFileFollow(io, "/etc/resolv.conf")) {
        const resolver = result.report.host_resolver orelse
            return error.TestExpectedHostResolverRecord;
        const bytes = try Io.Dir.cwd().readFileAlloc(
            io,
            "/etc/resolv.conf",
            allocator,
            .limited(1 << 20),
        );
        var expected: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(bytes, &expected, .{});
        try std.testing.expectEqual(@as(u64, bytes.len), resolver.size);
        try std.testing.expectEqualSlices(u8, &expected, &resolver.sha256.bytes);
    } else {
        // A build machine with no resolver of its own lends none, and the
        // record says so rather than describing a bind that did not happen.
        try std.testing.expectEqual(
            @as(?customize.HostResolverRecord, null),
            result.report.host_resolver,
        );
    }

    try std.testing.expect(context.saw_rpm_import);
    try std.testing.expect(context.saw_tdnf_install);
    try std.testing.expect(context.saw_tdnf_remove);
    try std.testing.expect(context.saw_repository_isolation);
    try std.testing.expect(context.saw_dracut);
    try std.testing.expectEqual(@as(usize, 6), context.unmounts.items.len);
    const expected_unmounts = [_][]const u8{
        "/run/zvmi-resolv.conf",
        "/run",
        "/sys",
        "/proc",
        "/dev",
        "",
    };
    for (context.unmounts.items, expected_unmounts) |actual, suffix| {
        const expected = try std.fmt.allocPrint(
            allocator,
            "{s}{s}",
            .{ root_path, suffix },
        );
        try std.testing.expectEqualStrings(expected, actual);
    }
    try std.testing.expect(context.detached_loop);

    var failing_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .fail_tdnf = true,
    };
    const failed = try executeManifest(allocator, io, manifest, .{
        .context = &failing_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.failed, failed.outcome);
    try std.testing.expect(failed.cleanup_complete);
    try std.testing.expectEqual(@as(usize, 6), failing_context.unmounts.items.len);
    try std.testing.expect(failing_context.detached_loop);

    // A command that ran out of time is not a command that failed. The run
    // stops either way, but only this one is answered by more time -- and the
    // teardown still has to finish, because the deadline is the reason the run
    // stopped and not permission to leave the host holding a mount.
    var expired_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .deadline_on_command = "tdnf",
    };
    const expired = try executeManifest(allocator, io, manifest, .{
        .context = &expired_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.deadline_exceeded, expired.outcome);
    try std.testing.expect(expired.cleanup_complete);
    try std.testing.expectEqual(@as(usize, 6), expired_context.unmounts.items.len);
    try std.testing.expect(expired_context.detached_loop);

    var malformed_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .malformed_losetup = true,
    };
    const malformed = try executeManifest(allocator, io, manifest, .{
        .context = &malformed_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.failed, malformed.outcome);
    try std.testing.expect(malformed.cleanup_complete);
    try std.testing.expect(malformed_context.queried_associated_loops);
    try std.testing.expectEqual(@as(usize, 2), malformed_context.detached_loops);

    var preexisting_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .malformed_losetup = true,
        .preexisting_loop = true,
    };
    const preexisting = try executeManifest(allocator, io, manifest, .{
        .context = &preexisting_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.failed, preexisting.outcome);
    try std.testing.expect(!preexisting.cleanup_complete);
    try std.testing.expectEqual(
        @as(usize, 0),
        preexisting_context.detached_loops,
    );

    var cleanup_failure_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .fail_umount = true,
    };
    const cleanup_failure = try executeManifest(allocator, io, manifest, .{
        .context = &cleanup_failure_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, cleanup_failure.outcome);
    try std.testing.expect(!cleanup_failure.cleanup_complete);
    try std.testing.expectEqual(
        @as(usize, 6),
        cleanup_failure_context.unmounts.items.len,
    );
    try std.testing.expectEqual(
        @as(usize, 1),
        cleanup_failure_context.detached_loops,
    );

    var lazy_detach_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .associated_loop_stuck = true,
    };
    const lazy_detach = try executeManifest(allocator, io, manifest, .{
        .context = &lazy_detach_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, lazy_detach.outcome);
    try std.testing.expect(!lazy_detach.cleanup_complete);

    var symlink_resolver_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .resolver_layout = .symlink,
    };
    const symlink_resolver = try executeManifest(allocator, io, manifest, .{
        .context = &symlink_resolver_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, symlink_resolver.outcome);
    try std.testing.expect(symlink_resolver.cleanup_complete);

    var missing_resolver_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .resolver_layout = .missing,
    };
    const missing_resolver = try executeManifest(allocator, io, manifest, .{
        .context = &missing_resolver_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, missing_resolver.outcome);
    try std.testing.expect(missing_resolver.cleanup_complete);
}

test "hooks run where the plan says they run, and stop existing when they are done" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-hook-order-root";
    const raw_path = "test-unsafe-chroot-hook-order-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const first_script = "#!/bin/sh\necho after-packages\n";
    const hooks = [_]customize.Hook{
        .{
            .name = "packages",
            .phase = .after_packages,
            .source = .{ .inline_script = first_script },
            .arguments = &.{ "--mode", "one" },
        },
        .{
            .name = "initramfs",
            .phase = .before_initramfs,
            .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
        },
        .{
            .name = "seal",
            .phase = .before_seal,
            .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
        },
        .{
            .name = "final",
            .phase = .finalize,
            // A different interpreter from the rest, because the record is a
            // property of each hook rather than of the run.
            .source = .{ .inline_script = "#!/usr/bin/env python3\nexit(0)\n" },
        },
    };
    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.12.0-test"},
        } },
        .hooks = &hooks,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expect(result.cleanup_complete);

    // The order the plan publishes, and no other. `buildOperations` emits
    // packages, then the two pre-initramfs phases, then the initramfs, then
    // the two after it -- a run that fired them in a different order would
    // make the published operation list a description of something else.
    try std.testing.expectEqual(@as(usize, 6), context.timeline.items.len);
    const expected = [_][]const u8{
        "tdnf-install",
        "/run/zvmi-hook-0",
        "/run/zvmi-hook-1",
        "dracut",
        "/run/zvmi-hook-2",
        "/run/zvmi-hook-3",
    };
    for (expected, context.timeline.items) |want, got| {
        try std.testing.expectEqualStrings(want, got);
    }

    // The argument vector is the script and exactly the declared arguments.
    const argv = context.hook_argv orelse return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 5), argv.len);
    try std.testing.expectEqualStrings(root_path, argv[1]);
    try std.testing.expectEqualStrings("/run/zvmi-hook-0", argv[2]);
    try std.testing.expectEqualStrings("--mode", argv[3]);
    try std.testing.expectEqualStrings("one", argv[4]);

    // The bytes that ran are the bytes that were declared, in a file only
    // their owner can read or run.
    try std.testing.expectEqualStrings(
        first_script,
        context.hook_script_at_run orelse return error.TestUnexpectedResult,
    );
    try std.testing.expectEqual(@as(?u32, 0o700), context.hook_mode_at_run);

    // And they were gone by the time the initramfs generator ran, which runs
    // target-supplied module scripts as root against the image about to be
    // published.
    try std.testing.expect(!context.hook_visible_at_dracut);

    try std.testing.expectEqual(@as(usize, 4), result.report.hooks.len);
    var script_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(first_script, &script_digest, .{});
    try std.testing.expectEqualStrings("packages", result.report.hooks[0].name);
    try std.testing.expectEqual(customize.HookPhase.after_packages, result.report.hooks[0].phase);
    try std.testing.expectEqualSlices(u8, &script_digest, &result.report.hooks[0].source_sha256.bytes);
    try std.testing.expectEqual(@as(u8, 0), result.report.hooks[0].exit_code);
    try std.testing.expectEqualStrings("final", result.report.hooks[3].name);
    try std.testing.expectEqual(customize.HookPhase.finalize, result.report.hooks[3].phase);

    // What interpreted each hook. The `chroot` argv names the throwaway path
    // the script was written to and nothing else, and the script itself is
    // deleted before the image is sealed -- so without this the published
    // provenance cannot say whether a hook ran under the shell its author
    // wrote it for.
    try std.testing.expectEqualStrings("/bin/sh", result.report.hooks[0].interpreter);
    try std.testing.expectEqualStrings(
        "/usr/bin/env python3",
        result.report.hooks[3].interpreter,
    );

    // Nothing of the hook survives the run.
    const leftover = try joinGuest(allocator, root_path, "/run/zvmi-hook-0");
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, leftover, .{}),
    );
}

test "a hook that fails fails the run" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-hook-failure-root";
    const raw_path = "test-unsafe-chroot-hook-failure-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const hooks = [_]customize.Hook{
        .{
            .name = "failing",
            .phase = .after_packages,
            .source = .{ .inline_script = "#!/bin/sh\nexit 3\n" },
        },
        .{
            .name = "later",
            .phase = .finalize,
            .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
        },
    };
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{},
        .initramfs = .unchanged,
        .hooks = &hooks,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .fail_hook = "/run/zvmi-hook-0",
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    // A nonzero exit ends the run. Nothing is published, and the hook that
    // would have run afterwards never does -- a later phase that ran anyway
    // would be doing its work against a root an earlier phase abandoned.
    try std.testing.expectEqual(RunOutcome.failed, result.outcome);
    try std.testing.expect(result.cleanup_complete);
    try std.testing.expectEqual(@as(usize, 1), context.timeline.items.len);
    try std.testing.expectEqualStrings("/run/zvmi-hook-0", context.timeline.items[0]);

    // Even the failed run leaves nothing behind.
    const leftover = try joinGuest(allocator, root_path, "/run/zvmi-hook-0");
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, leftover, .{}),
    );
}

test "a hook source is read on the host, not from inside the target" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-hook-source-root";
    const raw_path = "test-unsafe-chroot-hook-source-stage.raw";
    const script_path = "test-unsafe-chroot-hook-source.sh";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, script_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const script = "#!/bin/sh\ntouch /etc/from-a-host-path\n";
    try Io.Dir.cwd().writeFile(io, .{ .sub_path = script_path, .data = script });

    const hooks = [_]customize.Hook{.{
        .name = "from-host",
        .phase = .after_packages,
        .source = .{ .host_path = script_path },
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{},
        .initramfs = .unchanged,
        .hooks = &hooks,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        // A decoy at the same relative path inside the target, holding
        // different bytes, kept present for the whole run. If the worker
        // opened the script through the chroot it would run this instead, and
        // the digest would say so.
        .plant_in_target = script_path,
        .plant_bytes = "#!/bin/sh\nfalse\n",
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expectEqualStrings(
        script,
        context.hook_script_at_run orelse return error.TestUnexpectedResult,
    );
    // The record names the bytes, not where they came from: an inline script
    // holding the same bytes would produce the same digest, and a host file
    // that changed between two runs would not.
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(script, &digest, .{});
    try std.testing.expectEqual(@as(usize, 1), result.report.hooks.len);
    try std.testing.expectEqualSlices(
        u8,
        &digest,
        &result.report.hooks[0].source_sha256.bytes,
    );
    // Read from the same host-side bytes as the digest, so a `host_path` hook
    // records its interpreter on the same terms an inline one does.
    try std.testing.expectEqualStrings("/bin/sh", result.report.hooks[0].interpreter);
}

test "the privilege boundary re-checks a hook it is handed" {
    const base = Manifest{
        .raw_path = "stage.raw",
        .root_path = "root",
        .status_path = "status",
        .report_path = "report.json",
        .stage_inode = 1,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{},
        .initramfs = .unchanged,
    };
    const runnable = "#!/bin/sh\nexit 0\n";
    const long_argument = "x" ** (customize.max_hook_argument_bytes + 1);
    var many_arguments: [customize.max_hook_arguments + 1][]const u8 = undefined;
    for (&many_arguments) |*slot| slot.* = "x";

    const cases = [_]struct {
        hooks: []const customize.Hook,
        expected: anyerror,
    }{
        .{
            .hooks = &.{.{ .name = "", .phase = .finalize, .source = .{ .inline_script = runnable } }},
            .expected = error.InvalidHookName,
        },
        .{
            .hooks = &.{.{ .name = "a/b", .phase = .finalize, .source = .{ .inline_script = runnable } }},
            .expected = error.InvalidHookName,
        },
        .{
            .hooks = &.{
                .{ .name = "same", .phase = .finalize, .source = .{ .inline_script = runnable } },
                .{ .name = "same", .phase = .finalize, .source = .{ .inline_script = runnable } },
            },
            .expected = error.DuplicateHookName,
        },
        .{
            .hooks = &.{
                .{ .name = "late", .phase = .finalize, .source = .{ .inline_script = runnable } },
                .{ .name = "early", .phase = .after_packages, .source = .{ .inline_script = runnable } },
            },
            .expected = error.HookPhasesOutOfOrder,
        },
        .{
            .hooks = &.{.{ .name = "no-interpreter", .phase = .finalize, .source = .{ .inline_script = "exit 0\n" } }},
            .expected = error.HookScriptUnusable,
        },
        .{
            .hooks = &.{.{ .name = "empty", .phase = .finalize, .source = .{ .inline_script = "" } }},
            .expected = error.HookScriptUnusable,
        },
        .{
            .hooks = &.{.{ .name = "nowhere", .phase = .finalize, .source = .{ .host_path = "" } }},
            .expected = error.InvalidHookSource,
        },
        .{
            .hooks = &.{.{
                .name = "wordy",
                .phase = .finalize,
                .source = .{ .inline_script = runnable },
                .arguments = &many_arguments,
            }},
            .expected = error.TooManyHookArguments,
        },
        .{
            .hooks = &.{.{
                .name = "long",
                .phase = .finalize,
                .source = .{ .inline_script = runnable },
                .arguments = &.{long_argument},
            }},
            .expected = error.HookArgumentTooLong,
        },
        .{
            .hooks = &.{.{
                .name = "truncating",
                .phase = .finalize,
                .source = .{ .inline_script = runnable },
                .arguments = &.{"one\x00two"},
            }},
            .expected = error.InvalidHookArgument,
        },
    };
    for (cases) |case| {
        var manifest = base;
        manifest.hooks = case.hooks;
        try std.testing.expectError(case.expected, validateManifestPolicy(manifest));
    }

    // The shape the request validator produces passes on this side too, or the
    // two boundaries would disagree about what a valid hook is.
    var accepted = base;
    accepted.hooks = &.{
        .{ .name = "first", .phase = .after_packages, .source = .{ .inline_script = runnable } },
        .{ .name = "second", .phase = .finalize, .source = .{ .host_path = "/opt/hook.sh" } },
    };
    try validateManifestPolicy(accepted);
}

test "a credential reaches tdnf without reaching anything that outlives the run" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-credential-root";
    const raw_path = "test-unsafe-chroot-credential-stage.raw";
    const secret_path = "test-unsafe-chroot-credential-secret";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, secret_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    // A trailing newline, because a secret in a file almost always has one and
    // sending it to the server would fail in a way nobody could read.
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = secret_path,
        .data = "s3cr3t-from-a-file\n",
    });
    var cwd_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const cwd_length = try std.process.currentPath(io, &cwd_buffer);
    const absolute_secret = try std.fs.path.join(
        allocator,
        &.{ cwd_buffer[0..cwd_length], secret_path },
    );

    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_path = absolute_secret },
        } },
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
        },
        .initramfs = .unchanged,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expect(result.cleanup_complete);

    // The material arrives, trimmed of the newline the file carried.
    const seen = context.repository_at_tdnf orelse return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings(
        "[base]\nname=zvmi-base\nenabled=1\ngpgcheck=1\n" ++
            "baseurl=https://packages.example.invalid\n" ++
            "username=builder\npassword=s3cr3t-from-a-file\n",
        seen,
    );
    // And arrives in a file only its owner can read, unlike every other
    // repository file, which carries nothing worth protecting.
    try std.testing.expectEqual(@as(?u32, 0o600), context.repository_mode_at_tdnf);

    // The one place a secret would be published: the report is what provenance
    // is built from, and every argv in it is recorded verbatim.
    for (result.report.tools) |tool| {
        for (tool.command) |argument| {
            try std.testing.expect(
                std.mem.indexOf(u8, argument, "s3cr3t-from-a-file") == null,
            );
        }
    }

    // Cleanup removed it. In a real run the tmpfs it sat on is unmounted too,
    // so the material never reached a block of the image being published.
    const leftover_path = try repositoryHostPath(allocator, root_path, "base");
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, leftover_path, .{ .follow_symlinks = false }),
    );
}

test "no credential material reaches anything the run publishes" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-sentinel-root";
    const raw_path = "test-unsafe-chroot-sentinel-stage.raw";
    const secret_path = "test-unsafe-chroot-sentinel-secret";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, secret_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    // Distinct per source, so a leak names which channel it came through
    // rather than leaving both under suspicion.
    const file_material = "zvmi-sentinel-from-a-file";
    const variable_material = "zvmi-sentinel-from-a-variable";
    try Io.Dir.cwd().writeFile(io, .{
        .sub_path = secret_path,
        .data = file_material ++ "\n",
    });
    var cwd_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const cwd_length = try std.process.currentPath(io, &cwd_buffer);
    const absolute_secret = try std.fs.path.join(
        allocator,
        &.{ cwd_buffer[0..cwd_length], secret_path },
    );

    const repositories = [_]customize.PackageRepository{
        .{
            .id = "base",
            .urls = &.{"https://packages.example.invalid"},
            .trust = &.{.{ .inline_bytes = "test key" }},
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_path = absolute_secret },
            } },
        },
        .{
            .id = "other",
            .urls = &.{"https://other.example.invalid"},
            .trust = &.{.{ .inline_bytes = "test key" }},
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_environment = "ZVMI_TEST_SENTINEL" },
            } },
        },
    };
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.12.0-test"},
        } },
        .selinux = .relabel,
    };

    const block = [_:null]?[*:0]const u8{
        "ZVMI_TEST_SENTINEL=" ++ variable_material,
    };
    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .plant_selinux = .targeted,
        .plant_trust_key = true,
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
        .environ = .{ .block = .{ .slice = &block } },
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);

    // Not a vacuous absence: both secrets were read and both reached the file
    // tdnf is pointed at, which is the only place either is supposed to go.
    // Without this the whole test would pass on a run that never resolved a
    // credential at all.
    const from_file = context.repository_at_tdnf orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(std.mem.indexOf(u8, from_file, file_material) != null);
    const from_variable = context.second_repository_at_tdnf orelse
        return error.TestUnexpectedResult;
    try std.testing.expect(
        std.mem.indexOf(u8, from_variable, variable_material) != null,
    );

    // The report is the whole of what provenance is built from, and this
    // backend now records every command it spawns rather than only the ones
    // that ran inside the target root -- so the surface a secret could reach
    // grew, and the assertion has to cover it as a document rather than field
    // by field.
    var document: Io.Writer.Allocating = .init(allocator);
    var stringify: std.json.Stringify = .{ .writer = &document.writer };
    try stringify.write(result.report);
    for ([_][]const u8{ file_material, variable_material }) |sentinel| {
        try std.testing.expect(
            std.mem.indexOf(u8, document.written(), sentinel) == null,
        );
        for (result.report.tools) |tool| {
            for (tool.command) |argument| {
                try std.testing.expect(
                    std.mem.indexOf(u8, argument, sentinel) == null,
                );
            }
        }
    }

    // And the absence above is an absence from something, not from nothing:
    // this run recorded the commands it spawned, including the ones that
    // handled the repository file the secrets were written into.
    try std.testing.expect(result.report.tools.len > 0);
    try std.testing.expect(
        std.mem.indexOf(u8, document.written(), "\"tools\"") != null,
    );
}

test "nothing the worker runs inherits the worker's environment" {
    // The credential is forwarded into the worker and stops there. Everything
    // the worker runs is target-supplied code executing as root against the
    // image about to be published -- package scriptlets, dracut modules -- and
    // the repository file is already deleted by the time the initramfs is
    // regenerated, so a variable left in the environment would outlive the
    // channel it was meant to travel on.
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    const env_tool = findTool(std.testing.io, &.{ "/usr/bin/env", "/bin/env" }) orelse
        return error.SkipZigTest;
    const stdin_path = "test-unsafe-chroot-environment-stdin";
    defer Io.Dir.cwd().deleteFile(std.testing.io, stdin_path) catch {};
    try Io.Dir.cwd().writeFile(std.testing.io, .{ .sub_path = stdin_path, .data = "" });

    // Both branches that can be observed: `runSystem` spawns three different
    // ways, and an environment supplied to one of them and not the others is
    // the shape this would most plausibly regress into.
    for ([_]?[]const u8{ null, stdin_path }) |stdin| {
        const stdin_file: ?Io.File = if (stdin) |path|
            try Io.Dir.cwd().openFile(std.testing.io, path, .{})
        else
            null;
        defer if (stdin_file) |file| file.close(std.testing.io);
        const result = try runSystem(
            null,
            allocator,
            std.testing.io,
            &.{env_tool},
            true,
            stdin_file,
            .unbounded,
        );
        try std.testing.expectEqual(@as(u8, 0), result.term.exited);

        // Compared as a set rather than a count: the assertion is that the
        // child's environment is the built one and nothing else, whatever the
        // process running these tests happens to carry.
        var names: std.array_list.Managed([]const u8) = .init(allocator);
        var lines = std.mem.splitScalar(
            u8,
            std.mem.trimEnd(u8, result.stdout, "\n"),
            '\n',
        );
        while (lines.next()) |line| {
            try names.append(line[0 .. std.mem.indexOfScalar(u8, line, '=') orelse line.len]);
        }
        std.mem.sort([]const u8, names.items, {}, struct {
            fn lessThan(_: void, a: []const u8, b: []const u8) bool {
                return std.mem.lessThan(u8, a, b);
            }
        }.lessThan);
        try std.testing.expectEqual(@as(usize, 5), names.items.len);
        inline for (.{ "HOME", "LANG", "LC_ALL", "PATH", "TERM" }, 0..) |expected, index| {
            try std.testing.expectEqualStrings(expected, names.items[index]);
        }
    }
}

test "a consumed credential variable stops existing" {
    if (builtin.os.tag == .windows) return error.SkipZigTest;
    var entry = "ZVMI_TEST_CREDENTIAL=s3cr3t-from-a-variable".*;
    var other = "PATH=/usr/bin".*;
    const block = [_:null]?[*:0]const u8{ &entry, &other };
    const environ = std.process.Environ{ .block = .{ .slice = &block } };

    try std.testing.expectEqualStrings(
        "s3cr3t-from-a-variable",
        std.process.Environ.getPosix(environ, "ZVMI_TEST_CREDENTIAL").?,
    );
    credential_mod.scrubEnvironmentValue(environ, "ZVMI_TEST_CREDENTIAL");

    // Gone from the block, and gone from the bytes the block points at, which
    // is what `/proc/<pid>/environ` reads.
    try std.testing.expectEqualStrings(
        "",
        std.process.Environ.getPosix(environ, "ZVMI_TEST_CREDENTIAL").?,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, &entry, "s3cr3t-from-a-variable") == null,
    );

    // And nothing else is disturbed: the worker still has to run commands.
    try std.testing.expectEqualStrings(
        "/usr/bin",
        std.process.Environ.getPosix(environ, "PATH").?,
    );
    credential_mod.scrubEnvironmentValue(environ, "ZVMI_NOT_DECLARED");
}

test "a credential the host cannot resolve is a refusal, not an empty password" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();

    var map = std.process.Environ.Map.init(allocator);
    defer map.deinit();

    const environment_credential = customize.RepositoryCredential{ .basic = .{
        .username = "builder",
        .password = .{ .host_environment = "ZVMI_TEST_CREDENTIAL" },
    } };
    var repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = environment_credential,
    }};
    const manifest = Manifest{
        .raw_path = "unused.raw",
        .root_path = "unused-root",
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = 0,
        .virtual_size = 0,
        .partition_offset = 0,
        .partition_length = 0,
        .packages = .{ .repositories = &repositories },
        .initramfs = .unchanged,
    };

    // The parent's environment is built, not inherited, so a variable it cannot
    // read is refused before the image is opened rather than forwarded as "".
    try std.testing.expectError(
        error.CredentialSourceUnreadable,
        forwardCredentialVariables(allocator, .empty, &map, manifest),
    );
    try std.testing.expect(map.get("ZVMI_TEST_CREDENTIAL") == null);

    const block = [_:null]?[*:0]const u8{
        "ZVMI_TEST_CREDENTIAL=s3cr3t-from-a-variable",
    };
    const environ = std.process.Environ{ .block = .{ .slice = &block } };
    try forwardCredentialVariables(allocator, environ, &map, manifest);
    try std.testing.expectEqualStrings(
        "s3cr3t-from-a-variable",
        map.get("ZVMI_TEST_CREDENTIAL").?,
    );

    // A newline would end the `password=` line and let whatever followed be
    // read back as repository configuration, so it is refused at the source.
    const injecting = [_:null]?[*:0]const u8{
        "ZVMI_TEST_CREDENTIAL=s3cr3t\nenabled=0",
    };
    var injecting_map = std.process.Environ.Map.init(allocator);
    defer injecting_map.deinit();
    try std.testing.expectError(
        error.CredentialMaterialUnusable,
        forwardCredentialVariables(
            allocator,
            .{ .block = .{ .slice = &injecting } },
            &injecting_map,
            manifest,
        ),
    );

    // A repository whose credential is a file needs nothing forwarded: the
    // worker reads the file itself, so nothing is put in the environment.
    var file_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_path = "/dev/null" },
        } },
    }};
    var file_manifest = manifest;
    file_manifest.packages = .{ .repositories = &file_repositories };
    var file_map = std.process.Environ.Map.init(allocator);
    defer file_map.deinit();
    try forwardCredentialVariables(allocator, .empty, &file_map, file_manifest);
    try std.testing.expectEqual(@as(usize, 0), file_map.count());
}

test "the privilege boundary re-checks a credential it is handed" {
    const base = Manifest{
        .raw_path = "unused.raw",
        .root_path = "unused-root",
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = 0,
        .virtual_size = 0,
        .partition_offset = 0,
        .partition_length = 0,
        .packages = .{},
        .initramfs = .unchanged,
    };
    const credential = customize.RepositoryCredential{ .basic = .{
        .username = "builder",
        .password = .{ .host_path = "/run/secrets/token" },
    } };

    var accepted = base;
    var accepted_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = credential,
    }};
    accepted.packages = .{ .repositories = &accepted_repositories };
    try validateManifestPolicy(accepted);

    // Basic authentication puts the password on the wire. A plaintext URL for a
    // credentialed repository is refused here as well as in the validator,
    // because this side re-reads the document from JSON.
    var plaintext = base;
    var plaintext_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"http://packages.example.invalid"},
        .trust = &.{},
        .credential = credential,
    }};
    plaintext.packages = .{ .repositories = &plaintext_repositories };
    try std.testing.expectError(
        error.CredentialedRepositoryNotEncrypted,
        validateManifestPolicy(plaintext),
    );

    // The bound on a credential path is the request validator's, not a tighter
    // one: a rule stricter here would accept a request and then fail it after
    // the workspace has been copied and the image staged.
    var long = base;
    var long_path: [Io.Dir.max_path_bytes]u8 = undefined;
    long_path[0] = '/';
    @memset(long_path[1..], 'a');
    var long_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_path = &long_path },
        } },
    }};
    long.packages = .{ .repositories = &long_repositories };
    try validateManifestPolicy(long);

    var relative = base;
    var relative_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_path = "secrets/token" },
        } },
    }};
    relative.packages = .{ .repositories = &relative_repositories };
    try std.testing.expectError(
        error.InvalidCredentialSource,
        validateManifestPolicy(relative),
    );

    var named = base;
    var named_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_environment = "TOKEN; rm -rf /" },
        } },
    }};
    named.packages = .{ .repositories = &named_repositories };
    try std.testing.expectError(
        error.InvalidCredentialSource,
        validateManifestPolicy(named),
    );

    var blank = base;
    var blank_repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{},
        .credential = .{ .basic = .{
            .username = "",
            .password = .{ .host_path = "/run/secrets/token" },
        } },
    }};
    blank.packages = .{ .repositories = &blank_repositories };
    try std.testing.expectError(
        error.InvalidCredentialUsername,
        validateManifestPolicy(blank),
    );
}

test "the key rpm derived from imported trust is recorded, and never pinned" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-trust-key-root";
    const raw_path = "test-unsafe-chroot-trust-key-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &.{.{ .install = &.{"zlib"} }},
            .repositories = &repositories,
        },
        .initramfs = .unchanged,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .plant_trust_key = true,
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expect(context.saw_rpm_import);

    // The `rpm --import` argv names a file on a tmpfs that no longer exists,
    // and the declared trust is recorded as bytes. Neither says which key rpm
    // derived from them and then verified every signature against.
    try std.testing.expectEqual(
        @as(usize, 1),
        result.report.imported_trust_keys.len,
    );
    try std.testing.expectEqualStrings(
        "gpg-pubkey-3135ce90-5e6d0f1e",
        result.report.imported_trust_keys[0],
    );

    // And it is still not a package. `(none)` is not an architecture the pin
    // rules accept, so an emitted lock carrying one could never be restated by
    // the run that reads it.
    for (result.report.package_lock) |pin| {
        try std.testing.expect(!std.mem.startsWith(u8, pin.name, "gpg-pubkey"));
    }
}

fn findSkippedKernel(
    entries: []const customize.SkippedKernelRelease,
    name: []const u8,
) ?customize.SkippedKernelReason {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.reason;
    }
    return null;
}

test "worker regenerates every installed kernel when the policy names none" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-discovery-root";
    const raw_path = "test-unsafe-chroot-discovery-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{},
        .initramfs = .{ .regenerate = .{ .generator = "dracut" } },
    };

    // Deliberately out of order, and salted with the two things that live
    // beside a kernel without being one: a firmware directory depmod never
    // touched, and a name no manifest would have been allowed to carry.
    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .installed_kernels = &.{
            .{ .release = "6.12.0-2.azl" },
            .{ .release = "6.12.0-10.azl", .marker = "modules.dep.bin" },
            .{ .release = "firmware", .marker = null },
            .{ .release = "6.12.0 spaced" },
        },
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expect(result.cleanup_complete);

    // The resolved releases are auditable because the recorded command is the
    // whole argv.
    var regenerated: std.array_list.Managed([]const u8) = .init(allocator);
    for (result.report.tools) |tool| {
        if (!std.mem.eql(u8, tool.name, "dracut")) continue;
        for (tool.command, 0..) |argument, index| {
            if (!std.mem.eql(u8, argument, "--kver")) continue;
            try regenerated.append(tool.command[index + 1]);
        }
    }
    // Sorted, so the same target produces the same run twice. Lexicographic
    // ordering puts 10 before 2; the guarantee is determinism, not version
    // order, and dracut is handed each release whatever the order.
    try std.testing.expectEqual(@as(usize, 2), regenerated.items.len);
    try std.testing.expectEqualStrings("6.12.0-10.azl", regenerated.items[0]);
    try std.testing.expectEqualStrings("6.12.0-2.azl", regenerated.items[1]);

    // What the argv cannot say is what discovery declined to hand it. Two
    // `--kver` arguments look the same whether the target had two kernels or
    // four, and the difference between those is a package transaction that
    // shipped a stale initramfs and one that did not.
    const initramfs = result.report.initramfs orelse
        return error.TestExpectedInitramfsRecord;
    const skipped = initramfs.skipped_kernel_releases;
    try std.testing.expectEqual(@as(usize, 2), skipped.len);
    try std.testing.expectEqual(
        customize.SkippedKernelReason.no_module_dependency_index,
        findSkippedKernel(skipped, "firmware").?,
    );
    try std.testing.expectEqual(
        customize.SkippedKernelReason.invalid_release_name,
        findSkippedKernel(skipped, "6.12.0 spaced").?,
    );

    // And what came out. The digest is of the file in the mounted target, so
    // it is checkable against the published image -- which is the only reason
    // to record it, the bytes having been produced by a tool this run does
    // not control.
    try std.testing.expectEqual(@as(usize, 2), initramfs.images.len);
    // The bytes `cp` left in the target, not the bytes `dracut` wrote to the
    // temporary: the two are the same file only if the copy did what it said,
    // and the published image carries the first. A fake that reported a
    // successful `cp` without writing anything would fail the run here rather
    // than publish a digest of a file that is not in the image.
    var expected_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash("fake initramfs bytes", &expected_digest, .{});
    for (initramfs.images) |image| {
        try std.testing.expectEqual(@as(u64, "fake initramfs bytes".len), image.size);
        try std.testing.expectEqualSlices(u8, &expected_digest, &image.sha256.bytes);
        // Named for the release it was built for, and where the `cp` argv put
        // it.
        try std.testing.expect(std.mem.indexOf(
            u8,
            image.image_path,
            image.kernel_release,
        ) != null);
    }
    try std.testing.expectEqualStrings(
        "/boot/initramfs-6.12.0-10.azl.img",
        initramfs.images[0].image_path,
    );

    // Regenerating every initramfs and regenerating none are different
    // outcomes, so a target with no installed kernel fails rather than
    // reporting a policy it did not carry out.
    var empty_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .installed_kernels = &.{.{ .release = "firmware", .marker = null }},
    };
    const empty = try executeManifest(allocator, io, manifest, .{
        .context = &empty_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.failed, empty.outcome);
    try std.testing.expect(!empty_context.saw_dracut);

    // Unless the host derived the regeneration rather than being asked for
    // it, in which case an empty module tree is the answer "nothing here is
    // stale". The same target, the same empty tree, the opposite outcome --
    // the difference is entirely in what the plan claimed.
    var derived_manifest = manifest;
    derived_manifest.initramfs = .{ .regenerate = .{
        .generator = "dracut",
        .no_installed_kernels = .nothing_to_regenerate,
    } };
    var derived_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .installed_kernels = &.{.{ .release = "firmware", .marker = null }},
    };
    const derived = try executeManifest(allocator, io, derived_manifest, .{
        .context = &derived_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, derived.outcome);
    try std.testing.expect(derived.cleanup_complete);
    try std.testing.expect(!derived_context.saw_dracut);

    // Tolerating "none installed" must not extend to tolerating "could not
    // find out". A `lib/modules` that cannot be read as a directory is not
    // evidence that nothing is stale, and accepting it as such would ship the
    // initramfs the package transaction had just invalidated -- silently, and
    // only on the derived path.
    // Its own root: the sub-cases above left a real `lib/modules` directory
    // behind, and writing the file over it would fail in the fake's setup
    // rather than in discovery -- the test would pass without proving
    // anything.
    const unreadable_root = "test-unsafe-chroot-unreadable-modules-root";
    defer Io.Dir.cwd().deleteTree(io, unreadable_root) catch {};
    var unreadable_manifest = derived_manifest;
    unreadable_manifest.root_path = unreadable_root;
    var unreadable_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = unreadable_root,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .modules_path_is_file = true,
    };
    const unreadable = try executeManifest(allocator, io, unreadable_manifest, .{
        .context = &unreadable_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.failed, unreadable.outcome);
    try std.testing.expect(!unreadable_context.saw_dracut);

    // The same distinction one level in: a release directory that cannot be
    // searched is not evidence that the kernel inside it has no modules. If
    // the probe skipped it the set would come up empty, and an empty set is
    // exactly what `nothing_to_regenerate` accepts.
    const locked_root = "test-unsafe-chroot-locked-release-root";
    defer Io.Dir.cwd().deleteTree(io, locked_root) catch {};
    var locked_manifest = derived_manifest;
    locked_manifest.root_path = locked_root;
    var locked_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = locked_root,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .installed_kernels = &.{
            .{ .release = "6.12.0-locked.azl", .marker_loops = true },
        },
    };
    const locked = try executeManifest(allocator, io, locked_manifest, .{
        .context = &locked_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.failed, locked.outcome);
    try std.testing.expect(!locked_context.saw_dracut);
}

test "worker places kernel-module configuration after packages and before dracut" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    // A permissive umask, restored afterwards, because the point of stating
    // the modes is that they do not depend on the builder's umask -- and a
    // test run under the default `0o022` cannot tell a stated mode from an
    // inherited one.
    const previous_umask = std.os.linux.syscall1(.umask, 0);
    defer _ = std.os.linux.syscall1(.umask, previous_umask);
    const root_path = "test-unsafe-chroot-modules-root";
    const raw_path = "test-unsafe-chroot-modules-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const actions = [_]customize.PackageAction{.{ .install = &.{"dracut"} }};
    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const modules = [_]customize.KernelModule{
        .{ .name = "overlay", .load = true },
        .{ .name = "floppy", .disabled = true },
        .{ .name = "i915", .options = "enable_guc=2" },
    };
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &actions,
            .repositories = &repositories,
        },
        .initramfs = .{ .regenerate = .{
            .generator = "dracut",
            .kernels = &.{"6.12.0-test"},
        } },
        .kernel_modules = &modules,
    };
    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);
    try std.testing.expect(result.cleanup_complete);

    // A package shipping its own modprobe configuration must not land on top
    // of the declared one, and a generator reading the configuration must see
    // the declared state -- so the write belongs strictly between the two.
    try std.testing.expect(context.saw_tdnf_install);
    try std.testing.expect(context.saw_dracut);
    try std.testing.expect(!context.modules_present_at_tdnf);

    const at_dracut = context.modules_at_dracut.?;
    try std.testing.expectEqualStrings("overlay\n", at_dracut[0]);
    try std.testing.expectEqualStrings("blacklist floppy\n", at_dracut[1]);
    try std.testing.expectEqualStrings("options i915 enable_guc=2\n", at_dracut[2]);

    // The modes are stated, not inherited. `mkdir` and `createFile` are both
    // masked by the invoking shell's umask, and `modprobe` reads these as
    // root at boot -- a world-writable `modprobe.d` lets any user in the
    // finished image run a command as root through an `install` directive.
    // The permissive umask is set here rather than assumed absent, since a
    // test that only passes under the developer's umask proves nothing.
    try std.testing.expectEqual(@as(u32, 0o644), context.file_mode_at_dracut.?);
    try std.testing.expectEqual(@as(u32, 0o755), context.directory_mode_at_dracut.?);
}

// A declared resolver has to reach the package transaction as bytes the
// request chose, with no host file involved and nothing left behind. The
// no-actions case is the other half of the same claim: the resolver belongs to
// the package transaction, so a run without one must not acquire a resolver at
// all -- least of all the build machine's.
test "worker installs the declared resolver and none without package actions" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-resolver-root";
    const raw_path = "test-unsafe-chroot-resolver-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const actions = [_]customize.PackageAction{.{ .install = &.{"dracut"} }};
    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const declared = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &actions,
            .repositories = &repositories,
            .resolver = .{ .nameservers = &.{ "192.0.2.1", "198.51.100.7" } },
        },
        .initramfs = .unchanged,
    };

    var declared_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        // The host has a resolver to lend. A declared list must not touch it.
        .resolver_layout = .regular,
    };
    const declared_result = try executeManifest(allocator, io, declared, .{
        .context = &declared_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, declared_result.outcome);
    try std.testing.expect(declared_result.cleanup_complete);
    try std.testing.expectEqualStrings(
        "nameserver 192.0.2.1\nnameserver 198.51.100.7\n",
        declared_context.resolver_at_tdnf.?,
    );
    // One fewer unmount than the `host_resolver` path: nothing was bound, so
    // there is nothing to unbind. The list is the evidence that the run really
    // took the other branch rather than writing over a bind mount.
    try std.testing.expectEqual(
        @as(usize, 5),
        declared_context.unmounts.items.len,
    );
    try std.testing.expect(!containsArg(
        declared_context.unmounts.items,
        root_path ++ "/run/zvmi-resolv.conf",
    ));

    var idle = declared;
    idle.packages = .{};
    var idle_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .resolver_layout = .regular,
    };
    const idle_result = try executeManifest(allocator, io, idle, .{
        .context = &idle_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, idle_result.outcome);
    try std.testing.expect(idle_result.cleanup_complete);
    try std.testing.expectEqual(@as(usize, 5), idle_context.unmounts.items.len);
    try std.testing.expect(!containsArg(
        idle_context.unmounts.items,
        root_path ++ "/run/zvmi-resolv.conf",
    ));

    // A manifest the worker will not honour is refused before it creates,
    // mounts or writes anything as root. The declared resolver is rendered into
    // the target root while the session is opened, so a check made when the
    // policy is *run* would arrive after the bytes it guards had been placed --
    // and an untouched root path is the only assertion that cannot pass by
    // accident, since every later refusal leaves one behind.
    const refused_root = "test-unsafe-chroot-resolver-refused-root";
    defer Io.Dir.cwd().deleteTree(io, refused_root) catch {};
    var refused = declared;
    refused.root_path = refused_root;
    refused.packages.resolver = .{ .nameservers = &.{"127.0.0.53"} };
    var refused_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = refused_root,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .resolver_layout = .regular,
    };
    const refused_result = try executeManifest(
        allocator,
        io,
        refused,
        .{ .context = &refused_context, .runFn = FakeExecutorContext.run },
    );
    try std.testing.expectEqual(RunOutcome.failed, refused_result.outcome);
    // Cleanup is complete because there was nothing to clean up. The parent
    // reads a propagated error here as "the worker may have left resources
    // attached" and abandons its lease, poisoning the transaction directory
    // for a run that touched nothing.
    try std.testing.expect(refused_result.cleanup_complete);
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, refused_root, .{}),
    );
    try std.testing.expectEqual(@as(usize, 0), refused_context.unmounts.items.len);
}

// A whitespace-carrying name reaching the renderer would silently retarget a
// `modprobe.d` directive at a different module, so the worker refuses it on
// its own side of the privilege boundary rather than trusting the request
// validator that already refused it.
test "worker refuses kernel module names it would render as two tokens" {
    const base = Manifest{
        .raw_path = "unused.raw",
        .root_path = "unused-root",
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = 0,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{},
        .initramfs = .unchanged,
    };

    // Same boundary, one field over: an unchecked nameserver carrying a
    // newline would add directives of its own to the resolver the transaction
    // runs against, and the worker re-reads this manifest from JSON after
    // re-execing as root rather than receiving it from the validator.
    var injected = base;
    injected.packages = .{ .resolver = .{
        .nameservers = &.{"192.0.2.1\nsearch attacker.invalid"},
    } };
    try std.testing.expectError(
        error.InvalidNetworkConfiguration,
        validateManifestPolicy(injected),
    );
    // Named apart from the malformed case, because a well-formed address that
    // means the build machine is a different mistake from one that is not an
    // address at all, and only the caller can tell them apart from the error.
    var loopback = base;
    loopback.packages = .{ .resolver = .{ .nameservers = &.{"127.0.0.53"} } };
    try std.testing.expectError(
        error.UnusableNameserver,
        validateManifestPolicy(loopback),
    );

    // Same boundary, same reasoning, one field further: the URL is the field
    // the plan hashes and provenance keeps verbatim, so a credential in its
    // authority is refused under its own name rather than as a malformed URL.
    var smuggled = base;
    smuggled.packages = .{ .repositories = &.{.{
        .id = "base",
        .urls = &.{"https://builder:hunter2@packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }} };
    try std.testing.expectError(
        error.RepositoryUrlCarriesCredential,
        validateManifestPolicy(smuggled),
    );
    var wrong_scheme = base;
    wrong_scheme.packages = .{ .repositories = &.{.{
        .id = "base",
        .urls = &.{"ftp://packages.example.invalid/base"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }} };
    try std.testing.expectError(
        error.InvalidRepositoryUrl,
        validateManifestPolicy(wrong_scheme),
    );

    var spaced = base;
    spaced.kernel_modules = &.{.{ .name = "overlay -f", .load = true }};
    try std.testing.expectError(
        error.InvalidKernelModuleName,
        validateManifestPolicy(spaced),
    );

    var contradictory = base;
    contradictory.kernel_modules = &.{
        .{ .name = "overlay", .load = true, .disabled = true },
    };
    try std.testing.expectError(
        error.ContradictoryKernelModule,
        validateManifestPolicy(contradictory),
    );

    var multiline = base;
    multiline.kernel_modules = &.{
        .{ .name = "i915", .options = "enable_guc=2\nblacklist floppy" },
    };
    try std.testing.expectError(
        error.InvalidKernelModuleOptions,
        validateManifestPolicy(multiline),
    );

    var accepted = base;
    accepted.kernel_modules = &.{.{ .name = "overlay", .load = true }};
    try validateManifestPolicy(accepted);
}

const FakeResolverLayout = enum { regular, symlink, missing };

/// A directory under `/lib/modules` in the fake target. The marker is what
/// separates an installed kernel from a directory that merely looks like one;
/// a null marker is a directory depmod never wrote to.
const FakeKernel = struct {
    release: []const u8,
    marker: ?[]const u8 = "modules.dep",
    /// Makes the depmod marker a symlink to itself, so probing it fails with
    /// `SymLinkLoop` rather than reporting it absent. This isolates the probe
    /// -- an unsearchable directory would fail the directory open instead,
    /// which is a different guard, and would also defeat cleanup.
    marker_loops: bool = false,
};

/// The first record for a tool, or a failure naming what was missing.
///
/// Tests look records up by name because the report is a run-ordered list of
/// every command issued, and an index into it is a statement about how many
/// mounts the run happened to need.
fn findToolRecord(
    tools: []const customize.ToolRecord,
    name: []const u8,
) !customize.ToolRecord {
    for (tools) |tool| {
        if (std.mem.eql(u8, tool.name, name)) return tool;
    }
    std.debug.print("no provenance record for tool '{s}'\n", .{name});
    return error.ToolNotRecorded;
}

/// Where a tool ran for the last time, used to assert ordering between stages
/// that each run more than once.
fn lastToolIndex(tools: []const customize.ToolRecord, name: []const u8) ?usize {
    var found: ?usize = null;
    for (tools, 0..) |tool, index| {
        if (std.mem.eql(u8, tool.name, name)) found = index;
    }
    return found;
}

const FakeExecutorContext = struct {
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    unmounts: std.array_list.Managed([]const u8) = undefined,
    saw_rpm_import: bool = false,
    /// Whether the target's rpm database gains a trust pseudo-package once
    /// this run has imported something into it.
    plant_trust_key: bool = false,
    inventory_reads: usize = 0,
    saw_tdnf_install: bool = false,
    saw_tdnf_remove: bool = false,
    saw_dracut: bool = false,
    installed_kernels: []const FakeKernel = &.{},
    /// Makes `lib/modules` a regular file, so discovery fails to read the tree
    /// rather than reading an empty one. The two must not arrive as the same
    /// answer once the host is willing to tolerate "none installed".
    modules_path_is_file: bool = false,
    detached_loop: bool = false,
    detached_loops: usize = 0,
    fail_tdnf: bool = false,
    fail_umount: bool = false,
    /// A run in which any command line mentioning this name never returns
    /// within the run's budget. Names a command rather than a duration because
    /// the fake has no clock: what a test is asserting about is the outcome of
    /// a command that ran out of time, not the timing that produced it.
    deadline_on_command: ?[]const u8 = null,
    malformed_losetup: bool = false,
    queried_associated_loops: bool = false,
    associated_loop_stuck: bool = false,
    associated_queries: usize = 0,
    preexisting_loop: bool = false,
    malformed_inventory: bool = false,
    resolver_layout: FakeResolverLayout = .regular,
    saw_repository_isolation: bool = false,
    /// Whether the declared kernel-module configuration was already in place
    /// when each of the neighbouring stages ran. Ordering is the whole
    /// contract here, and the finished tree cannot be inspected afterwards --
    /// cleanup unmounts and removes it -- so the evidence has to be taken
    /// while the run is still standing.
    modules_present_at_tdnf: bool = false,
    /// The resolver the package transaction actually saw, read while the run
    /// is still standing. Null means none was installed. Under
    /// `host_resolver` the fake never really bind-mounts, so this is the empty
    /// placeholder the real mount would have covered; under a declared list it
    /// is the rendered body itself.
    resolver_at_tdnf: ?[]const u8 = null,
    /// The repository file the package transaction actually saw, and its mode,
    /// read while the run is still standing. Cleanup deletes the file and
    /// unmounts the tmpfs it sat on, so this is the only moment the material a
    /// credential resolved to is observable at all.
    repository_at_tdnf: ?[]const u8 = null,
    /// A second declared repository's rendered file, for the cases that need
    /// two credentials resolved from two different sources in one run.
    second_repository_at_tdnf: ?[]const u8 = null,
    repository_mode_at_tdnf: ?u32 = null,
    modules_at_dracut: ?[]const []const u8 = null,
    file_mode_at_dracut: ?u32 = null,
    directory_mode_at_dracut: ?u32 = null,
    /// Every stage that can be ordered against another, in the order it
    /// happened. A hook's whole contract is when it runs, and the tree it ran
    /// against is unmounted and deleted by cleanup, so the order has to be
    /// recorded while the run is still standing.
    timeline: std.array_list.Managed([]const u8) = undefined,
    /// The argument vector the first hook was invoked with, and the script and
    /// mode it saw at that moment.
    hook_argv: ?[]const []const u8 = null,
    hook_script_at_run: ?[]const u8 = null,
    hook_mode_at_run: ?u32 = null,
    /// Whether any hook script was still present in the target root when the
    /// initramfs generator ran. dracut runs target-supplied module scripts as
    /// root, so a hook left behind is code from one phase reachable in another.
    hook_visible_at_dracut: bool = false,
    /// A guest hook path this fake refuses to run, so a failing hook can be
    /// told apart from a failing anything-else.
    fail_hook: ?[]const u8 = null,
    /// Written into the target root on every command, because the executor
    /// empties that root before it runs anything -- a decoy planted by the
    /// test would be gone before the hook it is meant to shadow.
    plant_in_target: ?[]const u8 = null,
    plant_bytes: []const u8 = "",
    /// Whether the target root looks like one carrying an SELinux policy.
    /// Planted on every command for the same reason `plant_in_target` is: the
    /// executor empties the root before it runs anything, so a tree the test
    /// laid down in advance would be gone before the relabel looked for it.
    plant_selinux: ?FakeSelinuxLayout = null,
    /// The argument vector `setfiles` was invoked with, without the `chroot`
    /// prefix, and whether it ran at all.
    relabel_argv: ?[]const []const u8 = null,

    fn plantSelinuxTree(self: *FakeExecutorContext, layout: FakeSelinuxLayout) !void {
        try self.writeTargetFile("etc/selinux/config", switch (layout) {
            .none => return,
            .no_policy_named => "SELINUX=enforcing\n",
            .targeted, .missing_contexts => "SELINUX=enforcing\nSELINUXTYPE=targeted\n",
            .targeted_permissive => "SELINUX=permissive\nSELINUXTYPE=targeted\n",
        });
        if (layout == .missing_contexts) return;
        try self.writeTargetFile(
            "etc/selinux/targeted/contexts/files/file_contexts",
            "/.*  system_u:object_r:default_t:s0\n",
        );
        try self.writeTargetFile("usr/sbin/setfiles", "");
    }

    fn writeTargetFile(
        self: *FakeExecutorContext,
        relative: []const u8,
        bytes: []const u8,
    ) !void {
        const path = try std.fs.path.join(self.allocator, &.{ self.root_path, relative });
        defer self.allocator.free(path);
        if (std.fs.path.dirname(path)) |parent| {
            try Io.Dir.cwd().createDirPath(self.io, parent);
        }
        try Io.Dir.cwd().writeFile(self.io, .{ .sub_path = path, .data = bytes });
    }

    fn readTargetFile(self: *FakeExecutorContext, relative: []const u8) ?[]const u8 {
        const path = std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.root_path, relative },
        ) catch return null;
        defer self.allocator.free(path);
        return Io.Dir.cwd().readFileAlloc(
            self.io,
            path,
            self.allocator,
            .unlimited,
        ) catch null;
    }

    fn modeOf(self: *FakeExecutorContext, relative: []const u8) ?u32 {
        const path = std.fmt.allocPrint(
            self.allocator,
            "{s}/{s}",
            .{ self.root_path, relative },
        ) catch return null;
        defer self.allocator.free(path);
        const status = Io.Dir.cwd().statFile(self.io, path, .{}) catch return null;
        return @intFromEnum(status.permissions) & 0o7777;
    }

    fn snapshotKernelModuleFiles(self: *FakeExecutorContext) ![]const []const u8 {
        const paths = [_][]const u8{
            os_customization.modules_load_path,
            os_customization.modprobe_blacklist_path,
            os_customization.modprobe_options_path,
        };
        const contents = try self.allocator.alloc([]const u8, paths.len);
        for (paths, contents) |relative, *slot| {
            slot.* = self.readTargetFile(relative) orelse "";
        }
        return contents;
    }

    /// What each program answers `--version` with. A program not listed
    /// answers nothing, which is how a real host behaves for the mount and
    /// loop utilities and for `setfiles`, none of which take the option, and
    /// is recorded as no version rather than an empty one.
    fn fakeVersion(
        self: *FakeExecutorContext,
        allocator: Allocator,
        argv: []const []const u8,
    ) !CommandResult {
        _ = self;
        const table = [_]struct { []const u8, []const u8 }{
            .{ "/usr/bin/rpm", "RPM version 4.18.0\n" },
            .{ "/usr/bin/tdnf", "tdnf 3.5.0\n" },
            .{ "/usr/bin/dracut", "dracut 102\n" },
            .{ "/usr/bin/cp", "cp (GNU coreutils) 9.4\n" },
            .{ "/usr/sbin/grub2-mkconfig", "grub2-mkconfig (GRUB) 2.06\n" },
        };
        for (table) |entry| {
            if (containsArg(argv, entry[0])) return fakeResult(allocator, entry[1], 0);
        }
        return fakeResult(allocator, "", 0);
    }

    fn run(
        context_ptr: ?*anyopaque,
        allocator: Allocator,
        _: Io,
        argv: []const []const u8,
        _: bool,
        _: ?Io.File,
        _: customize.Deadline,
    ) !CommandResult {
        const self: *FakeExecutorContext = @ptrCast(@alignCast(context_ptr.?));
        // Stands in for a command that outlived the run's budget, which is
        // what `runSystem` reports after it has killed the child.
        if (self.deadline_on_command) |name| {
            for (argv) |arg| {
                // Matched anywhere in the command line because the real ones
                // run through `chroot`, where the program that would have hung
                // is an argument rather than argv[0].
                if (std.mem.endsWith(u8, arg, name)) {
                    return error.ExecutionDeadlineExceeded;
                }
            }
        }
        // Version probes are answered before anything is observed, because a
        // probe is not a stage: a fake that let `setfiles --version` fall
        // through would record it as the relabel and a test would be asserting
        // against a command the run never used to label anything.
        if (containsArg(argv, "--version")) return self.fakeVersion(allocator, argv);
        if (self.plant_selinux) |layout| try self.plantSelinuxTree(layout);
        if (self.plant_in_target) |relative| {
            const path = try std.fs.path.join(
                self.allocator,
                &.{ self.root_path, relative },
            );
            defer self.allocator.free(path);
            if (std.fs.path.dirname(path)) |parent| {
                try Io.Dir.cwd().createDirPath(self.io, parent);
            }
            try Io.Dir.cwd().writeFile(self.io, .{
                .sub_path = path,
                .data = self.plant_bytes,
            });
        }
        if (std.mem.endsWith(u8, argv[0], "losetup") and
            containsArg(argv, "--associated"))
        {
            self.queried_associated_loops = true;
            self.associated_queries += 1;
            return fakeResult(
                allocator,
                if (self.associated_queries == 1)
                    if (self.malformed_inventory)
                        "unexpected\n"
                    else if (self.preexisting_loop)
                        "/dev/loop6\n"
                    else
                        ""
                else if (self.associated_loop_stuck)
                    "/dev/loop7\n"
                else if (self.detached_loops == 0 and self.malformed_losetup)
                    if (self.preexisting_loop)
                        "/dev/loop6\n/dev/loop7\n"
                    else
                        "/dev/loop7\n/dev/loop8\n"
                else if (self.preexisting_loop)
                    "/dev/loop6\n"
                else
                    "",
                0,
            );
        }
        if (std.mem.endsWith(u8, argv[0], "losetup") and
            !std.mem.eql(u8, argv[1], "--detach"))
        {
            return fakeResult(
                allocator,
                if (self.malformed_losetup)
                    "losetup: unexpected output\n"
                else
                    "/dev/loop7\n",
                0,
            );
        }
        if (std.mem.eql(u8, std.fs.path.basename(argv[0]), "mount") and
            argv.len >= 2 and
            std.mem.eql(u8, argv[argv.len - 1], self.root_path))
        {
            inline for (.{
                "/dev",
                "/proc",
                "/sys",
                "/run",
                "/etc/yum.repos.d",
                "/boot",
            }) |suffix| {
                const path = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}{s}",
                    .{ self.root_path, suffix },
                );
                try Io.Dir.cwd().createDirPath(self.io, path);
            }
            const resolver = try std.fmt.allocPrint(
                self.allocator,
                "{s}/etc/resolv.conf",
                .{self.root_path},
            );
            switch (self.resolver_layout) {
                .regular => try writeBytes(
                    self.io,
                    resolver,
                    "nameserver 127.0.0.1\n",
                ),
                .symlink => try Io.Dir.cwd().symLink(
                    self.io,
                    "/run/systemd/resolve/stub-resolv.conf",
                    resolver,
                    .{},
                ),
                .missing => {},
            }
            // Mounting is what makes the target root's contents visible, so
            // it is where a fake target grows its installed kernels.
            if (self.modules_path_is_file) {
                const lib = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/lib",
                    .{self.root_path},
                );
                try Io.Dir.cwd().createDirPath(self.io, lib);
                const modules = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/modules",
                    .{lib},
                );
                try writeBytes(self.io, modules, "");
            }
            for (self.installed_kernels) |kernel| {
                const directory = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/lib/modules/{s}",
                    .{ self.root_path, kernel.release },
                );
                try Io.Dir.cwd().createDirPath(self.io, directory);
                if (kernel.marker) |marker_name| {
                    const marker = try std.fmt.allocPrint(
                        self.allocator,
                        "{s}/{s}",
                        .{ directory, marker_name },
                    );
                    if (kernel.marker_loops) {
                        try Io.Dir.cwd().symLink(
                            self.io,
                            marker_name,
                            marker,
                            .{},
                        );
                    } else {
                        try writeBytes(self.io, marker, "");
                    }
                }
            }
        }
        // `cp` produces the file it was told to produce. A fake that reported
        // success without writing anything would let a run claim to have
        // published an initramfs that is not in the target root, which is the
        // one thing the digest recorded for it exists to catch.
        if (containsArg(argv, "/usr/bin/cp") and argv.len >= 2) {
            const destination = argv[argv.len - 1];
            if (std.mem.startsWith(u8, destination, "/")) {
                self.writeTargetFile(
                    destination[1..],
                    "fake initramfs bytes",
                ) catch {};
            }
        }
        if (std.mem.endsWith(u8, argv[0], "umount")) {
            try self.unmounts.append(try self.allocator.dupe(
                u8,
                argv[argv.len - 1],
            ));
            if (self.fail_umount) return fakeResult(allocator, "", 1);
        }
        if (std.mem.endsWith(u8, argv[0], "losetup") and
            argv.len >= 2 and
            std.mem.eql(u8, argv[1], "--detach"))
        {
            self.detached_loop = true;
            self.detached_loops += 1;
        }
        if (containsArg(argv, "/usr/bin/rpm") and containsArg(argv, "-qa")) {
            self.inventory_reads += 1;
            // The baseline is read first and before the trust import, so a key
            // rpm derived during this run is in the second reading and not the
            // first -- which is exactly what makes it a key this run added
            // rather than one the input image already carried.
            const trusted = self.plant_trust_key and self.inventory_reads > 1;
            return fakeResult(
                allocator,
                if (trusted)
                    "zlib-0:1.3-2.aarch64\nbash-0:5.2-1.aarch64\n" ++
                        "gpg-pubkey-3135ce90-5e6d0f1e.(none)\n"
                else
                    "zlib-0:1.3-2.aarch64\nbash-0:5.2-1.aarch64\n",
                0,
            );
        }
        if (containsArg(argv, "/usr/bin/rpm") and containsArg(argv, "--import")) {
            self.saw_rpm_import = true;
        }
        if (std.mem.eql(u8, std.fs.path.basename(argv[0]), "chroot") and
            argv.len >= 3 and
            std.mem.startsWith(u8, argv[2], "/run/zvmi-hook-"))
        {
            try self.timeline.append(try self.allocator.dupe(u8, argv[2]));
            if (self.hook_argv == null) {
                const command = try self.allocator.alloc([]const u8, argv.len);
                for (argv, command) |argument, *slot| {
                    slot.* = try self.allocator.dupe(u8, argument);
                }
                self.hook_argv = command;
                self.hook_script_at_run = self.readTargetFile(argv[2][1..]);
                self.hook_mode_at_run = self.modeOf(argv[2][1..]);
            }
            if (self.fail_hook) |failing| {
                if (std.mem.eql(u8, failing, argv[2])) {
                    return fakeResult(allocator, "", 3);
                }
            }
            return fakeResult(allocator, "", 0);
        }
        if (containsArg(argv, "/usr/bin/tdnf") and containsArg(argv, "install")) {
            try self.timeline.append("tdnf-install");
            self.saw_tdnf_install = true;
            self.modules_present_at_tdnf =
                self.readTargetFile(os_customization.modprobe_blacklist_path) != null;
            self.resolver_at_tdnf = self.readTargetFile("run/zvmi-resolv.conf");
            self.repository_at_tdnf = self.readTargetFile("run/zvmi-repos/base.repo");
            self.repository_mode_at_tdnf = self.modeOf("run/zvmi-repos/base.repo");
            self.second_repository_at_tdnf =
                self.readTargetFile("run/zvmi-repos/other.repo");
            self.saw_repository_isolation =
                containsArg(argv, "/run/zvmi-tdnf.conf") and
                containsArg(argv, "--disablerepo=*") and
                !containsArg(argv, "--");
            if (self.fail_tdnf) return fakeResult(allocator, "", 1);
        }
        if (containsArg(argv, "/usr/bin/tdnf") and containsArg(argv, "remove")) {
            self.saw_tdnf_remove = true;
        }
        if (containsArg(argv, "/usr/bin/dracut") and !containsArg(argv, "--version")) {
            try self.timeline.append("dracut");
            var index: usize = 0;
            while (index < 8) : (index += 1) {
                const relative = try std.fmt.allocPrint(
                    self.allocator,
                    "run/zvmi-hook-{d}",
                    .{index},
                );
                defer self.allocator.free(relative);
                if (self.modeOf(relative) != null) self.hook_visible_at_dracut = true;
            }
        }
        if (containsArg(argv, "/usr/bin/dracut")) {
            if (self.modules_at_dracut == null) {
                self.modules_at_dracut = try self.snapshotKernelModuleFiles();
                self.file_mode_at_dracut = self.modeOf(
                    os_customization.modprobe_blacklist_path,
                );
                self.directory_mode_at_dracut = self.modeOf(
                    std.fs.path.dirname(os_customization.modprobe_blacklist_path).?,
                );
            }
            self.saw_dracut = true;
        }
        if (containsArg(argv, "/usr/sbin/setfiles")) {
            const copied = try self.allocator.alloc([]const u8, argv.len - 2);
            for (argv[2..], copied) |argument, *slot| {
                slot.* = try self.allocator.dupe(u8, argument);
            }
            self.relabel_argv = copied;
            try self.timeline.append("setfiles");
        }
        return fakeResult(allocator, "", 0);
    }
};

/// What the target root looks like where SELinux is concerned.
const FakeSelinuxLayout = enum {
    none,
    targeted,
    /// A configuration that names no policy: `/etc/selinux/config` exists but
    /// has no usable `SELINUXTYPE`, so there is nothing to relabel against.
    no_policy_named,
    /// A configuration naming a policy whose file-contexts file is absent.
    missing_contexts,
    /// A relabelled target that will nonetheless not enforce what the labels
    /// say at boot. The relabel is identical; the resulting image is not.
    targeted_permissive,
};

fn fakeResult(
    allocator: Allocator,
    stdout: []const u8,
    exit_code: u8,
) !CommandResult {
    return .{
        .term = .{ .exited = exit_code },
        .stdout = try allocator.dupe(u8, stdout),
        .stderr = try allocator.dupe(u8, ""),
    };
}

fn containsArg(argv: []const []const u8, expected: []const u8) bool {
    for (argv) |arg| {
        if (std.mem.eql(u8, arg, expected)) return true;
    }
    return false;
}

test "a relabel runs last, with the policy the target names" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-relabel-root";
    const raw_path = "test-unsafe-chroot-relabel-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const hooks = [_]customize.Hook{.{
        .name = "final",
        .phase = .finalize,
        .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
        },
        .hooks = &hooks,
        .initramfs = .unchanged,
        .selinux = .relabel,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .plant_selinux = .targeted,
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);

    // The exact command, including the policy read out of the target's own
    // configuration rather than out of the manifest, and an exclusion for
    // every kernel filesystem the session mounted into the root -- those are
    // not part of the image, so labelling them would describe a run that did
    // not happen to the bytes being published.
    const argv = context.relabel_argv orelse return error.TestExpectedRelabel;
    const expected_argv = [_][]const u8{
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
        "/etc/selinux/targeted/contexts/files/file_contexts",
        "/",
    };
    try std.testing.expectEqual(expected_argv.len, argv.len);
    for (expected_argv, argv) |expected, actual| {
        try std.testing.expectEqualStrings(expected, actual);
    }

    // Last, after the finalize hook. Anything written after a relabel is a
    // file the relabel did not label.
    const timeline = context.timeline.items;
    try std.testing.expectEqualStrings("setfiles", timeline[timeline.len - 1]);
    try std.testing.expectEqualStrings("/run/zvmi-hook-0", timeline[timeline.len - 2]);

    // `setfiles` takes no `--version`, so its record carries none. The fixed
    // table this replaced had no entry for it either, but answered with an
    // empty string, which published as a tool whose version was blank rather
    // than a tool that was never able to give one.
    try std.testing.expectEqual(
        @as(?[]const u8, null),
        (try findToolRecord(result.report.tools, "setfiles")).version,
    );

    // What the argv cannot say. The policy name is in there, but only as a
    // path component of a file the run chose to pass -- indistinguishable, to
    // a reader, from a policy the request named. The record says it was read
    // out of the target. The mode is not in the argv at all: `setfiles` does
    // the same work whatever `/etc/selinux/config` says it should enforce, so
    // an image relabelled under `permissive` and one relabelled under
    // `enforcing` produce identical commands and boot differently.
    const relabel = result.report.selinux_relabel orelse
        return error.TestExpectedRelabelRecord;
    try std.testing.expectEqualStrings("targeted", relabel.discovered_policy);
    try std.testing.expectEqual(
        @as(?customize.SelinuxMode, .enforcing),
        relabel.target_mode,
    );
    // The policy in the record is the policy in the command, not a second
    // reading that could disagree with it.
    try std.testing.expect(std.mem.indexOf(
        u8,
        argv[argv.len - 2],
        relabel.discovered_policy,
    ) != null);
}

test "a relabel records the mode the target will boot under" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;
    const root_path = "test-unsafe-chroot-permissive-root";
    const raw_path = "test-unsafe-chroot-permissive-stage.raw";
    defer Io.Dir.cwd().deleteTree(io, root_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    const raw_file = try Io.Dir.cwd().createFile(io, raw_path, .{
        .exclusive = true,
        .read = true,
    });
    try raw_file.setLength(io, 8192);
    const raw_inode = (try raw_file.stat(io)).inode;
    raw_file.close(io);

    const repositories = [_]customize.PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const manifest = Manifest{
        .raw_path = raw_path,
        .root_path = root_path,
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = raw_inode,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
            // Declared, so this run inherits nothing from the build machine.
            .resolver = .{ .nameservers = &.{"192.0.2.1"} },
        },
        .initramfs = .unchanged,
        .selinux = .relabel,
    };

    var context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .timeline = .init(allocator),
        .plant_selinux = .targeted_permissive,
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expectEqual(RunOutcome.succeeded, result.outcome);

    // The same relabel, the same argv, a different image. Nothing else in the
    // provenance distinguishes the two runs.
    const relabel = result.report.selinux_relabel orelse
        return error.TestExpectedRelabelRecord;
    try std.testing.expectEqual(
        @as(?customize.SelinuxMode, .permissive),
        relabel.target_mode,
    );
    try std.testing.expectEqualStrings("targeted", relabel.discovered_policy);

    // Nothing was inherited, so nothing is recorded. Absent means the plan
    // already carries the answer -- it names the nameservers -- rather than
    // that the question went unasked.
    try std.testing.expectEqual(
        @as(?customize.HostResolverRecord, null),
        result.report.host_resolver,
    );
}

test "a relabel a target cannot satisfy fails the run rather than skipping it" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const allocator = arena_state.allocator();
    const io = std.testing.io;

    const cases = [_]struct {
        layout: FakeSelinuxLayout,
        root: []const u8,
        raw: []const u8,
    }{
        .{
            .layout = .none,
            .root = "test-unsafe-chroot-relabel-none-root",
            .raw = "test-unsafe-chroot-relabel-none-stage.raw",
        },
        .{
            .layout = .no_policy_named,
            .root = "test-unsafe-chroot-relabel-unnamed-root",
            .raw = "test-unsafe-chroot-relabel-unnamed-stage.raw",
        },
        .{
            .layout = .missing_contexts,
            .root = "test-unsafe-chroot-relabel-contexts-root",
            .raw = "test-unsafe-chroot-relabel-contexts-stage.raw",
        },
    };

    for (cases) |case| {
        defer Io.Dir.cwd().deleteTree(io, case.root) catch {};
        defer Io.Dir.cwd().deleteFile(io, case.raw) catch {};
        const raw_file = try Io.Dir.cwd().createFile(io, case.raw, .{
            .exclusive = true,
            .read = true,
        });
        try raw_file.setLength(io, 8192);
        const raw_inode = (try raw_file.stat(io)).inode;
        raw_file.close(io);

        const manifest = Manifest{
            .raw_path = case.raw,
            .root_path = case.root,
            .status_path = "unused.status",
            .report_path = "unused-report.json",
            .stage_inode = raw_inode,
            .virtual_size = 8192,
            .partition_offset = 1024,
            .partition_length = 4096,
            .packages = .{},
            .initramfs = .unchanged,
            .selinux = .relabel,
        };
        var context = FakeExecutorContext{
            .allocator = allocator,
            .io = io,
            .root_path = case.root,
            .unmounts = .init(allocator),
            .timeline = .init(allocator),
            .plant_selinux = case.layout,
        };
        const result = try executeManifest(allocator, io, manifest, .{
            .context = &context,
            .runFn = FakeExecutorContext.run,
        });
        // A relabel that could not run is a failed run: the alternative is an
        // image published as relabelled that is not.
        try std.testing.expectEqual(RunOutcome.failed, result.outcome);
        try std.testing.expect(context.relabel_argv == null);
    }
}

test "the worker re-checks a configuration change on its own side of the boundary" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();

    var manifest = Manifest{
        .raw_path = "unused.raw",
        .root_path = "unused-root",
        .status_path = "unused.status",
        .report_path = "unused-report.json",
        .stage_inode = 1,
        .virtual_size = 8192,
        .partition_offset = 1024,
        .partition_length = 4096,
        .packages = .{},
        .initramfs = .unchanged,
        // A change that names nothing is a request to change nothing spelled
        // as a request to change something. The host refuses it at
        // validation; refused again here because what arrives across a
        // privilege boundary is checked rather than trusted.
        .selinux = .{ .configure = .{} },
    };
    try std.testing.expectError(
        error.EmptySelinuxConfiguration,
        validateManifestPolicy(manifest),
    );
    // A policy name reaches a path this worker builds and an argv it runs as
    // root, so it is held to the same rule that builds the path.
    manifest.selinux = .{ .configure = .{ .policy = "../escape" } };
    try std.testing.expectError(
        error.UnsupportedSelinuxPolicy,
        validateManifestPolicy(manifest),
    );
    manifest.selinux = .{ .configure = .{ .mode = .permissive } };
    try validateManifestPolicy(manifest);
    manifest.selinux = .relabel;
    try validateManifestPolicy(manifest);
}

test "a separate /boot is recognized from fstab and /boot/efi is not" {
    try std.testing.expect(declaresSeparateBootFilesystem(
        "UUID=aaaa / ext4 defaults 0 1\n" ++
            "UUID=bbbb /boot ext4 defaults 0 2\n",
    ));
    // A trailing slash names the same mount point.
    try std.testing.expect(declaresSeparateBootFilesystem(
        "UUID=bbbb\t/boot/\text4\tdefaults\t0 2\n",
    ));
    // The ESP is mounted under `/boot` on most distro images and is not a
    // separate `/boot`: the generator still finds the kernels it needs.
    try std.testing.expect(!declaresSeparateBootFilesystem(
        "UUID=aaaa / ext4 defaults 0 1\n" ++
            "UUID=cccc /boot/efi vfat umask=0077 0 2\n",
    ));
    // A commented-out entry mounts nothing.
    try std.testing.expect(!declaresSeparateBootFilesystem(
        "# UUID=bbbb /boot ext4 defaults 0 2\n",
    ));
    // A device whose name contains the target is not a mount at it.
    try std.testing.expect(!declaresSeparateBootFilesystem(
        "/dev/disk/by-label/boot / ext4 defaults 0 1\n",
    ));
    try std.testing.expect(!declaresSeparateBootFilesystem(""));
}
