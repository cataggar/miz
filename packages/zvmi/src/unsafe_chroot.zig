const std = @import("std");
const builtin = @import("builtin");
const customize = @import("customize.zig");
const os_customization = @import("os_customization.zig");
const preserved_image = @import("preserved_image.zig");
const transaction_guard = @import("transaction_guard.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

const max_command_output = 1024 * 1024;
const loop_settle_attempts = 20;
const loop_settle_interval = std.Io.Duration.fromMilliseconds(100);
const worker_started_text = "worker-started\n";
const cleanup_complete_text = "cleanup-complete\n";

pub const active_lease_basename = transaction_guard.active_lease_basename;
pub const activeLeasePath = transaction_guard.activeLeasePath;

pub const ParentOptions = struct {
    self_exe: []const u8,
    transaction_path: []const u8,
    plan: *const customize.ResolvedPlan,
    target: preserved_image.RawMutationTarget,
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
};

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
    var environment = std.process.Environ.Map.init(allocator);
    defer environment.deinit();
    try environment.put("HOME", "/root");
    try environment.put("LANG", "C");
    try environment.put("LC_ALL", "C");
    try environment.put("PATH", "/usr/sbin:/usr/bin:/sbin:/bin");
    try environment.put("TERM", "dumb");
    var child = std.process.spawn(io, .{
        .argv = &argv,
        .environ_map = &environment,
        .stdin = .ignore,
        .stdout = .inherit,
        .stderr = .inherit,
    }) catch |err| {
        lease.release(io) catch {
            lease.abandon(io);
            lease_active = false;
            return error.MutationResourcesActive;
        };
        lease_active = false;
        return err;
    };
    const term = child.wait(io) catch {
        lease.abandon(io);
        lease_active = false;
        return error.MutationResourcesActive;
    };

    switch (classifyWorkerOutcome(io, status_path, term)) {
        .never_started => {
            lease.release(io) catch {
                lease.abandon(io);
                lease_active = false;
                return error.MutationResourcesActive;
            };
            lease_active = false;
            return error.UnsafeChrootWorkerFailed;
        },
        .cleanup_uncertain => {
            lease.abandon(io);
            lease_active = false;
            return error.MutationResourcesActive;
        },
        .cleanup_complete_failed => {
            try lease.release(io);
            lease_active = false;
            return error.UnsafeChrootWorkerFailed;
        },
        .cleanup_complete_success => {
            try lease.release(io);
            lease_active = false;
        },
    }
    return loadParentReport(allocator, io, report_path);
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
    const result = try executeManifest(
        allocator,
        init.io,
        parsed.value,
        Executor.system(),
    );
    if (result.cleanup_complete) {
        if (result.operation_succeeded) {
            const report_json = try std.json.Stringify.valueAlloc(
                allocator,
                result.report,
                .{},
            );
            defer allocator.free(report_json);
            try writeBytes(init.io, parsed.value.report_path, report_json);
        }
        try writeBytes(init.io, parsed.value.status_path, cleanup_complete_text);
    }
    if (!result.cleanup_complete) return error.UnsafeChrootCleanupFailed;
    if (!result.operation_succeeded) return error.UnsafeChrootOperationFailed;
}

const ExecutionResult = struct {
    operation_succeeded: bool,
    cleanup_complete: bool,
    report: WorkerReport,
};

const WorkerReport = struct {
    tools: []const customize.ToolRecord,
    installed_packages: []const []const u8,
};

fn executeManifest(
    allocator: Allocator,
    io: Io,
    manifest: Manifest,
    executor: Executor,
) !ExecutionResult {
    if (manifest.partition_length == 0) return error.InvalidPartitionBounds;
    try prepareEmptyRoot(io, manifest.root_path);
    var session = Session{
        .allocator = allocator,
        .io = io,
        .executor = executor,
        .manifest = manifest,
        .tools = .init(allocator),
        .installed_packages = .init(allocator),
        .preexisting_loops = .init(allocator),
    };
    const operation_result = session.openAndRun();
    const cleanup_complete = session.close();
    return .{
        .operation_succeeded = operation_result != null,
        .cleanup_complete = cleanup_complete,
        .report = .{
            .tools = session.tools.items,
            .installed_packages = session.installed_packages.items,
        },
    };
}

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
    resolver_mounted: bool = false,
    resolver_replaced: bool = false,
    resolver_had_original: bool = false,
    tools: std.array_list.Managed(customize.ToolRecord),
    installed_packages: std.array_list.Managed([]const u8),
    preexisting_loops: std.array_list.Managed([]const u8),
    rpm_version: []const u8 = "",
    tdnf_version: []const u8 = "",
    dracut_version: []const u8 = "",
    cp_version: []const u8 = "",

    fn openAndRun(self: *Session) ?void {
        self.open() catch return null;
        self.runPolicy() catch return null;
        self.loadInstalledPackages() catch return null;
        return {};
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
        var result = try self.executor.run(
            self.allocator,
            self.io,
            &.{
                losetup,
                "--find",
                "--show",
                "--offset",
                offset,
                "--sizelimit",
                length,
                "/proc/self/fd/0",
            },
            true,
            raw_file,
        );
        defer result.deinit(self.allocator);
        try expectSuccess(result.term);
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

        const resolver_path = try joinGuest(
            self.allocator,
            self.manifest.root_path,
            "/etc/resolv.conf",
        );
        defer self.allocator.free(resolver_path);
        if (isRegularFileFollow(self.io, "/etc/resolv.conf")) {
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
            try writeBytesExclusive(self.io, resolver_run_path, "");
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

    fn runPolicy(self: *Session) !void {
        try validateManifestPolicy(self.manifest);
        try self.writeRepositoryFiles();
        errdefer self.removeRepositoryFiles() catch {};
        try self.importTrust();
        for (self.manifest.packages.actions) |action| switch (action) {
            .install => |names| try self.runTdnf("install", names, true),
            .remove => |names| try self.runTdnf("remove", names, false),
            .update_all => try self.runTdnf("update", &.{}, true),
            .update_selected => |names| try self.runTdnf("update", names, true),
        };
        try self.removeRepositoryFiles();
        // After the packages, so a package that ships its own modprobe
        // configuration cannot land on top of the declared one, and before
        // the initramfs, so a generator that reads this configuration sees
        // the declared state rather than the one it replaced.
        try self.writeKernelModuleFiles();
        switch (self.manifest.initramfs) {
            .unchanged => {},
            .regenerate => |regenerate| try self.regenerateInitramfs(regenerate),
        }
    }

    fn loadInstalledPackages(self: *Session) !void {
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
            try self.installed_packages.append(
                try self.allocator.dupe(u8, line),
            );
        }
        std.mem.sort(
            []const u8,
            self.installed_packages.items,
            {},
            lessThanBytes,
        );
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
        return self.executor.run(
            self.allocator,
            self.io,
            &.{
                findTool(self.io, losetup_candidates).?,
                "--associated",
                "/proc/self/fd/0",
                "--output",
                "NAME",
                "--noheadings",
            },
            true,
            raw_file,
        );
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

    fn runSuccess(self: *Session, argv: []const []const u8) !void {
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
        try writeBytesExclusive(
            self.io,
            config_path,
            "[main]\ngpgcheck=1\nreposdir=/run/zvmi-repos\n",
        );
        for (self.manifest.packages.repositories) |repository| {
            const path = try repositoryHostPath(
                self.allocator,
                self.manifest.root_path,
                repository.id,
            );
            defer self.allocator.free(path);
            var output: Io.Writer.Allocating = .init(self.allocator);
            defer output.deinit();
            try output.writer.print(
                "[{s}]\nname=zvmi-{s}\nenabled=1\ngpgcheck=1\nbaseurl=",
                .{ repository.id, repository.id },
            );
            for (repository.urls, 0..) |url, index| {
                if (index != 0) try output.writer.writeByte(' ');
                try output.writer.writeAll(url);
            }
            try output.writer.writeByte('\n');
            try writeBytesExclusive(self.io, path, output.written());
        }
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
                self.rpm_version = try self.runChrootCapture(&.{
                    "/usr/bin/rpm",
                    "--version",
                });
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
        self.tdnf_version = try self.runChrootCapture(&.{
            "/usr/bin/tdnf",
            "--version",
        });
        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        defer argv.deinit();
        try argv.appendSlice(&.{
            "/usr/bin/tdnf",
            "--config",
            "/run/zvmi-tdnf.conf",
            "--disablerepo=*",
        });
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
        const kernels = if (regenerate.kernels.len > 0)
            regenerate.kernels
        else
            try self.installedKernels();
        defer if (regenerate.kernels.len == 0) {
            for (kernels) |kernel| self.allocator.free(kernel);
            self.allocator.free(kernels);
        };
        for (kernels) |kernel| {
            self.dracut_version = try self.runChrootCapture(&.{
                "/usr/bin/dracut",
                "--version",
            });
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
            self.cp_version = try self.runChrootCapture(&.{
                "/usr/bin/cp",
                "--version",
            });
            try self.runChroot(&.{
                "/usr/bin/cp",
                "--remove-destination",
                temporary_output,
                output,
            });
        }
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
    fn installedKernels(self: *Session) ![]const []const u8 {
        const modules_path = try std.fs.path.join(
            self.allocator,
            &.{ self.manifest.root_path, "lib", "modules" },
        );
        defer self.allocator.free(modules_path);

        var modules_dir = Io.Dir.cwd().openDir(
            self.io,
            modules_path,
            .{ .iterate = true },
        ) catch return error.NoInstalledKernels;
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
            if (!validKernelRelease(entry.name)) continue;

            // Deliberately no check on the entry kind: `d_type` is `unknown`
            // on filesystems that do not carry it, and a non-directory cannot
            // be opened as one anyway, so the marker below settles it.
            var release_dir = modules_dir.openDir(self.io, entry.name, .{}) catch continue;
            defer release_dir.close(self.io);
            release_dir.access(self.io, "modules.dep", .{}) catch
                release_dir.access(self.io, "modules.dep.bin", .{}) catch continue;

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

    fn runChroot(self: *Session, guest_argv: []const []const u8) !void {
        var argv = try std.array_list.Managed([]const u8).initCapacity(
            self.allocator,
            guest_argv.len + 2,
        );
        defer argv.deinit();
        try argv.append(findTool(self.io, chroot_candidates).?);
        try argv.append(self.manifest.root_path);
        try argv.appendSlice(guest_argv);
        try self.runSuccess(argv.items);
        const command = try self.allocator.alloc([]const u8, guest_argv.len);
        for (guest_argv, 0..) |argument, index| {
            command[index] = try self.allocator.dupe(u8, argument);
        }
        try self.tools.append(.{
            .name = try self.allocator.dupe(
                u8,
                std.fs.path.basename(guest_argv[0]),
            ),
            .version = try self.allocator.dupe(
                u8,
                self.toolVersion(guest_argv[0]),
            ),
            .command = command,
        });
    }

    fn runChrootCapture(
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

    fn toolVersion(self: *const Session, guest_path: []const u8) []const u8 {
        if (std.mem.endsWith(u8, guest_path, "/rpm")) return self.rpm_version;
        if (std.mem.endsWith(u8, guest_path, "/tdnf")) return self.tdnf_version;
        if (std.mem.endsWith(u8, guest_path, "/dracut")) return self.dracut_version;
        if (std.mem.endsWith(u8, guest_path, "/cp")) return self.cp_version;
        return "";
    }
};

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
    runFn: *const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        argv: []const []const u8,
        capture_output: bool,
        stdin_file: ?Io.File,
    ) anyerror!CommandResult,

    fn system() Executor {
        return .{ .runFn = runSystem };
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
        );
    }
};

fn runSystem(
    _: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
    capture_output: bool,
    stdin_file: ?Io.File,
) !CommandResult {
    if (!capture_output) {
        var child = try std.process.spawn(io, .{
            .argv = argv,
            .stdin = if (stdin_file) |file| .{ .file = file } else .ignore,
            .stdout = .inherit,
            .stderr = .inherit,
        });
        return .{
            .term = try child.wait(io),
            .stdout = &.{},
            .stderr = &.{},
            .owned_output = false,
        };
    }
    if (stdin_file) |file| {
        var child = try std.process.spawn(io, .{
            .argv = argv,
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
        while (multi_reader.fill(64, .none)) |_| {
            if (stdout_reader.buffered().len > max_command_output or
                stderr_reader.buffered().len > max_command_output)
            {
                return error.StreamTooLong;
            }
        } else |err| switch (err) {
            error.EndOfStream => {},
            else => |read_err| return read_err,
        }
        try multi_reader.checkAnyError();
        const term = try child.wait(io);
        const stdout = try multi_reader.toOwnedSlice(0);
        errdefer allocator.free(stdout);
        const stderr = try multi_reader.toOwnedSlice(1);
        return .{
            .term = term,
            .stdout = stdout,
            .stderr = stderr,
        };
    }
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(max_command_output),
        .stderr_limit = .limited(max_command_output),
    });
    return .{
        .term = result.term,
        .stdout = result.stdout,
        .stderr = result.stderr,
    };
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

fn validateManifestPolicy(manifest: Manifest) !void {
    if (manifest.packages.cache != .online or
        manifest.packages.lock != .unlocked)
    {
        return error.UnsupportedPackagePolicy;
    }
    for (manifest.packages.repositories) |repository| {
        if (!validRepositoryId(repository.id)) return error.InvalidRepositoryId;
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
    }
    // The request validator already refused these, but the worker sits across
    // the privilege boundary and does not trust the manifest it is handed. A
    // name reaching the renderer unchecked would be a line of its own in a
    // modprobe configuration file.
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

fn writeBytesExclusive(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{
        .exclusive = true,
    });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
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
};

fn classifyWorkerOutcome(
    io: Io,
    status_path: []const u8,
    term: std.process.Child.Term,
) WorkerOutcome {
    if (statusEquals(io, status_path, cleanup_complete_text)) {
        return switch (term) {
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

fn loadParentReport(
    allocator: Allocator,
    io: Io,
    path: []const u8,
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
    return .{
        .arena = arena,
        .tools = parsed.value.tools,
        .installed_packages = parsed.value.installed_packages,
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

    // Updating is now executable; pinning it still is not.
    manifest.packages = .{
        .actions = &.{.update_all},
        .repositories = &repositories,
        .cache = .cache_only,
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
    try std.testing.expect(!identity_mismatch.operation_succeeded);
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
    try std.testing.expect(!malformed_inventory.operation_succeeded);
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
    };
    const executor = Executor{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    };
    const result = try executeManifest(allocator, io, manifest, executor);
    try std.testing.expect(result.operation_succeeded);
    try std.testing.expect(result.cleanup_complete);
    try std.testing.expectEqual(@as(usize, 5), result.report.tools.len);
    try std.testing.expectEqualStrings(
        "RPM version 4.18.0",
        result.report.tools[0].version,
    );
    try std.testing.expectEqualStrings(
        "tdnf 3.5.0",
        result.report.tools[1].version,
    );
    try std.testing.expectEqualStrings(
        "dracut 102",
        result.report.tools[3].version,
    );
    try std.testing.expectEqualStrings(
        "cp (GNU coreutils) 9.4",
        result.report.tools[4].version,
    );
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
        .fail_tdnf = true,
    };
    const failed = try executeManifest(allocator, io, manifest, .{
        .context = &failing_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(!failed.operation_succeeded);
    try std.testing.expect(failed.cleanup_complete);
    try std.testing.expectEqual(@as(usize, 6), failing_context.unmounts.items.len);
    try std.testing.expect(failing_context.detached_loop);

    var malformed_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .malformed_losetup = true,
    };
    const malformed = try executeManifest(allocator, io, manifest, .{
        .context = &malformed_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(!malformed.operation_succeeded);
    try std.testing.expect(malformed.cleanup_complete);
    try std.testing.expect(malformed_context.queried_associated_loops);
    try std.testing.expectEqual(@as(usize, 2), malformed_context.detached_loops);

    var preexisting_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .malformed_losetup = true,
        .preexisting_loop = true,
    };
    const preexisting = try executeManifest(allocator, io, manifest, .{
        .context = &preexisting_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(!preexisting.operation_succeeded);
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
        .fail_umount = true,
    };
    const cleanup_failure = try executeManifest(allocator, io, manifest, .{
        .context = &cleanup_failure_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(cleanup_failure.operation_succeeded);
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
        .associated_loop_stuck = true,
    };
    const lazy_detach = try executeManifest(allocator, io, manifest, .{
        .context = &lazy_detach_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(lazy_detach.operation_succeeded);
    try std.testing.expect(!lazy_detach.cleanup_complete);

    var symlink_resolver_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .resolver_layout = .symlink,
    };
    const symlink_resolver = try executeManifest(allocator, io, manifest, .{
        .context = &symlink_resolver_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(symlink_resolver.operation_succeeded);
    try std.testing.expect(symlink_resolver.cleanup_complete);

    var missing_resolver_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .resolver_layout = .missing,
    };
    const missing_resolver = try executeManifest(allocator, io, manifest, .{
        .context = &missing_resolver_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(missing_resolver.operation_succeeded);
    try std.testing.expect(missing_resolver.cleanup_complete);
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
    try std.testing.expect(result.operation_succeeded);
    try std.testing.expect(result.cleanup_complete);

    // The resolved releases are auditable because the recorded command is the
    // whole argv, so discovery needs no provenance record of its own.
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

    // Regenerating every initramfs and regenerating none are different
    // outcomes, so a target with no installed kernel fails rather than
    // reporting a policy it did not carry out.
    var empty_context = FakeExecutorContext{
        .allocator = allocator,
        .io = io,
        .root_path = root_path,
        .unmounts = .init(allocator),
        .installed_kernels = &.{.{ .release = "firmware", .marker = null }},
    };
    const empty = try executeManifest(allocator, io, manifest, .{
        .context = &empty_context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(!empty.operation_succeeded);
    try std.testing.expect(!empty_context.saw_dracut);
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
    };
    const result = try executeManifest(allocator, io, manifest, .{
        .context = &context,
        .runFn = FakeExecutorContext.run,
    });
    try std.testing.expect(result.operation_succeeded);
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
};

const FakeExecutorContext = struct {
    allocator: Allocator,
    io: Io,
    root_path: []const u8,
    unmounts: std.array_list.Managed([]const u8) = undefined,
    saw_rpm_import: bool = false,
    saw_tdnf_install: bool = false,
    saw_tdnf_remove: bool = false,
    saw_dracut: bool = false,
    installed_kernels: []const FakeKernel = &.{},
    detached_loop: bool = false,
    detached_loops: usize = 0,
    fail_tdnf: bool = false,
    fail_umount: bool = false,
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
    modules_at_dracut: ?[]const []const u8 = null,
    file_mode_at_dracut: ?u32 = null,
    directory_mode_at_dracut: ?u32 = null,

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

    fn run(
        context_ptr: ?*anyopaque,
        allocator: Allocator,
        _: Io,
        argv: []const []const u8,
        _: bool,
        _: ?Io.File,
    ) !CommandResult {
        const self: *FakeExecutorContext = @ptrCast(@alignCast(context_ptr.?));
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
            for (self.installed_kernels) |kernel| {
                const directory = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/lib/modules/{s}",
                    .{ self.root_path, kernel.release },
                );
                try Io.Dir.cwd().createDirPath(self.io, directory);
                const marker_name = kernel.marker orelse continue;
                const marker = try std.fmt.allocPrint(
                    self.allocator,
                    "{s}/{s}",
                    .{ directory, marker_name },
                );
                try writeBytes(self.io, marker, "");
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
        if (containsArg(argv, "/usr/bin/rpm") and containsArg(argv, "--version")) {
            return fakeResult(allocator, "RPM version 4.18.0\n", 0);
        }
        if (containsArg(argv, "/usr/bin/tdnf") and containsArg(argv, "--version")) {
            return fakeResult(allocator, "tdnf 3.5.0\n", 0);
        }
        if (containsArg(argv, "/usr/bin/dracut") and containsArg(argv, "--version")) {
            return fakeResult(allocator, "dracut 102\n", 0);
        }
        if (containsArg(argv, "/usr/bin/cp") and containsArg(argv, "--version")) {
            return fakeResult(allocator, "cp (GNU coreutils) 9.4\n", 0);
        }
        if (containsArg(argv, "/usr/bin/rpm") and containsArg(argv, "-qa")) {
            return fakeResult(
                allocator,
                "zlib-0:1.3-2.aarch64\nbash-0:5.2-1.aarch64\n",
                0,
            );
        }
        if (containsArg(argv, "/usr/bin/rpm") and containsArg(argv, "--import")) {
            self.saw_rpm_import = true;
        }
        if (containsArg(argv, "/usr/bin/tdnf") and containsArg(argv, "install")) {
            self.saw_tdnf_install = true;
            self.modules_present_at_tdnf =
                self.readTargetFile(os_customization.modprobe_blacklist_path) != null;
            self.saw_repository_isolation =
                containsArg(argv, "/run/zvmi-tdnf.conf") and
                containsArg(argv, "--disablerepo=*") and
                !containsArg(argv, "--");
            if (self.fail_tdnf) return fakeResult(allocator, "", 1);
        }
        if (containsArg(argv, "/usr/bin/tdnf") and containsArg(argv, "remove")) {
            self.saw_tdnf_remove = true;
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
        return fakeResult(allocator, "", 0);
    }
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
