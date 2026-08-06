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
/// Where the image's own resolver is held while the transaction runs. Beside
/// the original rather than under `/run`, because `/run` in the target is a
/// separate mount and a rename cannot cross one.
const resolver_backup_path = "/etc/.zvmi-resolv.conf";
/// How long the target's block device is waited for, and how often it is
/// checked. Generous because software emulation stretches every wall-clock
/// interval a guest experiences.
const device_wait_ms: u32 = 60_000;
/// How much of the target's `/etc/selinux/config` is read to find the policy
/// name. It is a handful of `KEY=value` lines wherever it exists.
const max_selinux_config_bytes: usize = 64 * 1024;
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
        .baseline_packages = .init(allocator),
        .emitted_lock = .init(allocator),
        .hook_outcomes = .init(allocator),
        .initramfs_images = .init(allocator),
        .skipped_kernels = .init(allocator),
    };
    const outcome = session.run();
    session.teardown();

    publish(allocator, session.result_device, .{
        .failure = outcome.failure,
        .tools = session.tools.items,
        .installed_packages = session.installed_packages.items,
        .package_lock = session.emitted_lock.items,
        .hooks = session.hook_outcomes.items,
        .selinux_relabel = session.selinux_relabel,
        .initramfs = if (session.initramfs_regenerated) .{
            .skipped_kernel_releases = session.skipped_kernels.items,
            .images = session.initramfs_images.items,
        } else null,
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
    /// The installed set as it stood before the package actions ran. Read only
    /// under a pinned control document, which is the only one with a question
    /// to ask of it: what this transaction added.
    baseline_packages: std.array_list.Managed([]const u8),
    /// What the transaction added or changed, as the pins that would restate
    /// it. Sent home whether or not the control document declared any.
    emitted_lock: std.array_list.Managed(control_mod.PackagePin),
    /// What each hook did, in the order it ran.
    hook_outcomes: std.array_list.Managed(control_mod.HookOutcome),
    /// What the target's own SELinux configuration named, filled by a relabel
    /// that succeeded. The policy is in the `setfiles` argv too; the mode is
    /// nowhere else, and neither is marked as discovered without this.
    selinux_relabel: ?control_mod.SelinuxRelabel = null,
    /// Whether an initramfs regeneration was attempted at all, which is not
    /// the same as whether one produced an image.
    initramfs_regenerated: bool = false,
    initramfs_images: std.array_list.Managed(control_mod.InitramfsImage),
    skipped_kernels: std.array_list.Managed(control_mod.SkippedKernel),

    /// Captured as soon as the control document parses, so that even a refusal
    /// to act on the rest of it still gets an answer home.
    result_device: []const u8 = "",
    last_exit_code: ?u8 = null,

    root_mounted: bool = false,
    dev_mounted: bool = false,
    proc_mounted: bool = false,
    sys_mounted: bool = false,
    run_mounted: bool = false,
    /// What was done to the image's own `/etc/resolv.conf`. One value rather
    /// than a "replaced" flag beside a "had an original" flag, because the two
    /// are only ever meaningful read together and a pair that can be assigned
    /// separately can describe a filesystem that never existed -- which is
    /// exactly how a teardown comes to delete the file it was restoring.
    ///
    /// It is renamed aside rather than copied because a copy reads through a
    /// symlink and writes back a regular file: an image whose resolver links
    /// into `/run` -- which is most of them -- would come out of the
    /// transaction with the link replaced by a stale file. The same names and
    /// the same protocol as the chroot backend, so an image cannot tell which
    /// one ran.
    resolver_state: enum { untouched, replaced_nothing, replaced_original } = .untouched,
    repositories_written: []const control_mod.Repository = &.{},
    /// The bytes read off the credential device, held so teardown can overwrite
    /// them. Every password the run uses is a slice of this one buffer -- the
    /// blob is read in place rather than parsed into allocations -- so this is
    /// the only thing that has to be scrubbed.
    credential_bytes: ?[]u8 = null,

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

        // Read before the target root is mounted, so material that cannot be
        // obtained fails the run before the image has been touched.
        self.readCredentials(control) catch |err| {
            return fail("read-credentials", @errorName(err));
        };

        self.mountTarget(control.root_device) catch |err| {
            return fail("mount-root", @errorName(err));
        };
        self.writeRepositoryFiles(control) catch |err| {
            return fail("repository-configuration", @errorName(err));
        };
        self.importTrust(control) catch |err| {
            return self.stageFailure("repository-trust", err);
        };
        // Before the first action, so the baseline is the root as it arrived.
        // Read for any run with package actions, not only a pinned one: the
        // emitted lock is the difference between the two inventories, and the
        // run that declares no pins is the one most likely to want them.
        if (control.actions.len != 0) {
            self.readInstalledPackages(&self.baseline_packages) catch |err| {
                return self.stageFailure("package-baseline", err);
            };
        }
        for (control.actions) |action| {
            const executed = switch (action) {
                .install => |names| self.runTdnfPinned("install", names, control),
                // The one verb a pin does not rewrite: asking to remove one
                // exact version would silently leave any other in place.
                .remove => |names| self.runTdnf("remove", names, &.{}),
                .update_all => self.runTdnf("update", &.{}, control.repositories),
                .update_selected => |names| self.runTdnfPinned("update", names, control),
            };
            executed catch |err| return self.stageFailure("packages", err);
        }
        // After the packages, so a package that ships its own modprobe
        // configuration cannot land on top of the declared one, and before
        // the initramfs, so a generator that reads this configuration sees
        // the declared state rather than the one it replaced.
        self.writeKernelModuleFiles(control.kernel_module_files) catch |err| {
            return self.stageFailure("kernel-modules", err);
        };
        // The four phases, in the order `buildOperations` publishes them and
        // the order the chroot backend runs them. A run whose hooks fired in a
        // different order from the one the plan shows would make the plan a
        // description of something else.
        self.runHooks(control, .after_packages) catch |err| {
            return self.stageFailure("hooks", err);
        };
        self.runHooks(control, .before_initramfs) catch |err| {
            return self.stageFailure("hooks", err);
        };
        switch (control.initramfs) {
            .unchanged => {},
            .regenerate => |regenerate| {
                // Before discovery, so a run that finds no usable kernel still
                // publishes the entries it passed over on the way to that
                // answer.
                self.initramfs_regenerated = true;
                const kernels = if (regenerate.kernels.len > 0)
                    regenerate.kernels
                else
                    self.installedKernels() catch |err| blk: {
                        // A regeneration the host derived rather than was
                        // asked for treats an empty module tree as nothing to
                        // do; an explicit one still fails, because it named
                        // work it then did not carry out.
                        if (err == error.NoInstalledKernels and
                            regenerate.no_installed_kernels == .nothing_to_regenerate)
                        {
                            break :blk &.{};
                        }
                        return self.stageFailure("initramfs", err);
                    };
                for (kernels) |kernel| {
                    self.regenerateInitramfs(kernel) catch |err| {
                        return self.stageFailure("initramfs", err);
                    };
                }
            },
        }
        self.runHooks(control, .before_seal) catch |err| {
            return self.stageFailure("hooks", err);
        };
        // No bootloader step separates these two on this backend: the vm
        // backend refuses a non-default boot policy, so there is nothing
        // between sealing and finishing for a phase to sit either side of.
        // The phases stay distinct anyway, because which one a hook declared
        // is what the plan published.
        self.runHooks(control, .finalize) catch |err| {
            return self.stageFailure("hooks", err);
        };
        // Last, after every hook and every other change: a relabel is only
        // true of the tree as it stood when the tool walked it, so anything
        // written afterwards would be the unlabelled file it exists to
        // prevent. The same position the chroot backend relabels from, and
        // the phase the plan publishes last.
        if (control.selinux_relabel) {
            self.relabelRoot() catch |err| {
                return self.stageFailure("selinux", err);
            };
        }
        // After every hook, so a hook that installed a package is visible in
        // the inventory the result carries -- the same point the chroot
        // backend reads its own.
        self.loadInstalledPackages() catch |err| {
            return self.stageFailure("package-inventory", err);
        };
        // After the inventory and before the result is published: a run whose
        // pins did not hold must come home as a failure, not as a success
        // whose report happens to disagree with the plan that produced it.
        self.verifyPackagePins(control.package_pins) catch |err| {
            return self.stageFailure("package-lock", err);
        };
        self.emitPackageLock(control) catch |err| {
            return self.stageFailure("package-lock", err);
        };
        return .{};
    }

    /// Runs a package verb whose names the control document pins, substituting
    /// each name with its exact identity.
    ///
    /// Asking for the pinned release outright rather than asking for the name
    /// and complaining afterwards: the second would fail builds that could
    /// have succeeded by asking the right question first.
    fn runTdnfPinned(
        self: *Session,
        verb: []const u8,
        names: []const []const u8,
        control: control_mod.Control,
    ) !void {
        if (control.package_pins.len == 0) {
            return self.runTdnf(verb, names, control.repositories);
        }
        var specs: std.array_list.Managed([]const u8) = .init(self.allocator);
        for (names) |name| {
            // Every pin sharing the name, not the first one: a lock may pin
            // `glibc` at both `i686` and `x86_64`, and a multilib root holds
            // both at once.
            var matched = false;
            for (control.package_pins) |pin| {
                if (!std.mem.eql(u8, pin.name, name)) continue;
                matched = true;
                try specs.append(try std.fmt.allocPrint(
                    self.allocator,
                    "{s}-{s}.{s}",
                    .{ pin.name, pin.evr, pin.architecture },
                ));
            }
            if (!matched) return error.UnpinnedPackageAction;
        }
        try self.runTdnf(verb, specs.items, control.repositories);
    }

    /// Records what this transaction changed, as the pins that would reproduce
    /// it.
    ///
    /// The difference between the two inventories rather than the whole final
    /// one: the whole final one travels home beside it and is mostly the input
    /// image, so a lock naming it would say nothing about the run. A record
    /// that does not parse as rpm's own output fails the run rather than being
    /// dropped, because an emitted lock with a hole in it is worse than none.
    fn emitPackageLock(self: *Session, control: control_mod.Control) !void {
        if (control.actions.len == 0) return;
        for (self.installed_packages.items) |installed| {
            if (containsBytes(self.baseline_packages.items, installed)) continue;
            if (control_mod.isTrustPseudoPackage(installed)) continue;
            const pin = control_mod.parseInstalledPackageRecord(installed) orelse
                return error.InvalidInstalledPackageRecord;
            try self.emitted_lock.append(pin);
        }
    }

    /// Holds the finished root to the pins it was built under.
    ///
    /// Both directions, because each catches a different failure. A pin the rpm
    /// database does not hold at that identity means the transaction resolved
    /// somewhere the request did not point. A package this transaction added
    /// that no pin names means the dependencies of a pinned install were left
    /// free -- an image pinned in one place and open in the others, published
    /// under a plan hash that says otherwise.
    fn verifyPackagePins(
        self: *Session,
        pins: []const control_mod.PackagePin,
    ) !void {
        if (pins.len == 0) return;
        for (pins) |pin| {
            const spec = try std.fmt.allocPrint(
                self.allocator,
                "{s}-{s}.{s}",
                .{ pin.name, pin.evr, pin.architecture },
            );
            if (containsBytes(self.installed_packages.items, spec)) continue;
            for (self.installed_packages.items) |installed| {
                // Present under the pinned name at some other identity, which
                // is a different failure from never having been installed.
                // By parsed name rather than string prefix: `python3-libs` is
                // not another version of `python3`.
                const record = control_mod.parseInstalledPackageRecord(installed) orelse continue;
                if (std.mem.eql(u8, record.name, pin.name)) {
                    return error.LockedPackageMismatch;
                }
            }
            return error.LockedPackageMissing;
        }
        for (self.installed_packages.items) |installed| {
            if (containsBytes(self.baseline_packages.items, installed)) continue;
            if (control_mod.isTrustPseudoPackage(installed)) continue;
            if (!control_mod.pinsCoverRecord(pins, installed)) {
                return error.UnlockedPackageInstalled;
            }
        }
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

    /// Loads the credential device the control document named, if it named
    /// one.
    ///
    /// The device is a raw disk whose contents are framed and digested exactly
    /// like the result device, so a guest that is handed the wrong device --
    /// or a truncated one, or one written by something else -- refuses rather
    /// than rendering whatever bytes it found into a repository file and
    /// sending them to a server.
    fn readCredentials(self: *Session, control: control_mod.Control) !void {
        const device = control.credential_device orelse return;
        const bytes = try readDeviceAlloc(
            self.allocator,
            device,
            control_mod.credential_device_bytes,
        );
        self.credential_bytes = bytes;
        // Parsed once here so a malformed device fails before the image is
        // mounted rather than part-way through writing repository files.
        _ = try control_mod.parseCredentials(bytes);
    }

    /// The material for a repository, borrowed from the device buffer.
    fn credentialFor(
        self: *Session,
        repository: control_mod.Repository,
    ) !?control_mod.BasicMaterial {
        const declared = repository.credential orelse return null;
        const bytes = self.credential_bytes orelse return error.MissingCredentialDevice;
        const credentials = try control_mod.parseCredentials(bytes);
        return switch (declared) {
            .basic => |basic| control_mod.BasicMaterial{
                .username = basic.username,
                .password = try credentials.password(basic.password_index),
            },
        };
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
            const material = try self.credentialFor(repository);
            const body = try renderRepositoryFile(self.allocator, repository, material);
            // The rendered body holds the password, so it is overwritten as
            // soon as it has been written out. The file itself lives on the
            // private `/run` tmpfs, which is unmounted before anything is
            // published, and is readable only by the package manager's own
            // uid -- the same mode the chroot backend uses, for the same
            // reason.
            defer if (material != null) @memset(@constCast(body), 0);
            try self.writeGuestFileMode(path, body, if (material == null)
                0o644
            else
                0o600);
        }
        self.repositories_written = control.repositories;

        if (resolverConfigFor(control)) |config| try self.installResolver(config);
    }

    /// Replaces the image's resolver for the duration of the run and puts the
    /// original back afterwards. tdnf resolves names through whatever the
    /// target root says, and the target root has no reason to name a resolver
    /// that exists on this synthetic link.
    fn installResolver(self: *Session, config: control_mod.NetworkConfig) !void {
        const body = try renderResolver(self.allocator, config);
        // Nothing is recorded until this has succeeded. `replaceAside` puts
        // back whatever it moved on every one of its own error paths, so a
        // teardown that also acted on a flag set beforehand would either
        // delete an original that was never moved or undo the restore that
        // had already happened.
        const had_original = try replaceAside(
            self.allocator,
            guest_root ++ resolver_path,
            guest_root ++ resolver_backup_path,
            body,
        );
        self.resolver_state = if (had_original) .replaced_original else .replaced_nothing;
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

    /// Places kernel-module configuration the host rendered.
    ///
    /// The destinations are checked against the same closed set the host
    /// validated against, because a guest that trusts its control document is
    /// a guest that can be driven anywhere by whoever wrote it -- and this is
    /// the one instruction that names a path inside the target root.
    fn writeKernelModuleFiles(self: *Session, files: []const control_mod.TargetFile) !void {
        for (files) |file| {
            if (!control_mod.knownKernelModuleConfigPath(file.path)) {
                return error.UnknownTargetFile;
            }
            const path = try std.fmt.allocPrint(
                self.allocator,
                guest_root ++ "/{s}",
                .{file.path},
            );
            try mkdirParents(self.allocator, path);
            try writeFileBytes(self.allocator, path, file.contents, 0o644);
            // A truncating open leaves an existing file's mode alone, so the
            // `0o644` `writeFileBytes` asks for only applies when it creates
            // the file. `modprobe` parses these as root at boot, so a mode
            // inherited from whatever the image already had at this path is
            // not something to carry forward.
            try setMode(self.allocator, path, 0o644);
        }
    }

    /// Kernel releases installed in the target root, sorted.
    ///
    /// This runs after the package actions, which is the whole point: a
    /// kernel that `update_all` pulled in during this very run is found here,
    /// and its release string was not knowable when the plan was written.
    ///
    /// The rule is dracut's own. Its `--regenerate-all` iterates
    /// `/lib/modules/*` and skips any entry without a `modules.dep` or
    /// `modules.dep.bin` -- files `depmod` writes as a kernel package
    /// installs -- which is what separates an installed kernel from a
    /// directory that merely sits beside one. Copying that rule rather than
    /// inventing one means this and the tool it hands the answer to cannot
    /// disagree about what is installed.
    ///
    /// Finding none is an error rather than a quiet success, because a
    /// request to regenerate every initramfs that regenerates none has not
    /// done what it said.
    fn installedKernels(self: *Session) ![]const []const u8 {
        return discoverKernels(
            self.allocator,
            guest_root ++ "/lib/modules",
            &self.skipped_kernels,
        );
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
        // Digested where `cp` left it rather than where dracut built it: what
        // a reader can check is the file the published image carries, and the
        // two are only the same file if the copy did what it said.
        const measured = try measureGuestFile(self.allocator, final);
        try self.initramfs_images.append(.{
            .kernel_release = kernel,
            .image_path = final,
            .size = measured.size,
            .sha256 = measured.sha256,
        });
    }

    /// Relabels the target root with the policy the target itself carries.
    ///
    /// Reads the policy out of the target's own `/etc/selinux/config` while
    /// the run executes rather than taking it from the control document,
    /// because a package action in this same run can have installed or
    /// replaced it. The argv reaches provenance like every other tool, so what
    /// it resolved to needs no record of its own.
    fn relabelRoot(self: *Session) !void {
        const tool = for (control_mod.selinux.setfiles_candidates) |candidate| {
            if (self.guestFileExists(candidate)) break candidate;
        } else return error.MissingSelinuxLabellingTool;

        const config = self.readGuestFile(
            control_mod.selinux.config_path,
            max_selinux_config_bytes,
        ) catch return error.MissingSelinuxConfiguration;
        const policy = control_mod.selinux.parseConfiguredPolicy(config) orelse
            return error.MissingSelinuxConfiguration;
        // Taken from the same read as the policy, so the record describes one
        // configuration rather than two glimpses of a file.
        const mode = control_mod.selinux.parseConfiguredMode(config);
        var contexts_buffer: [control_mod.selinux.max_policy_name_bytes + 64]u8 = undefined;
        const contexts = control_mod.selinux.fileContextsPath(&contexts_buffer, policy) catch
            return error.UnsupportedSelinuxPolicy;
        if (!self.guestFileExists(contexts)) return error.MissingSelinuxFileContexts;

        var argv = std.array_list.Managed([]const u8).init(self.allocator);
        try argv.append(tool);
        // Reset every context to what the policy says, matching how the
        // target's own installer labels a fresh root.
        try argv.append("-F");
        // Only the exclusions that exist, so the argv describes the run that
        // happened. All four are mounted by this agent for the chroot, and
        // none of them is part of the image.
        for (control_mod.selinux.excluded_directories) |directory| {
            if (!self.guestDirectoryExists(directory)) continue;
            try argv.append("-e");
            try argv.append(directory);
        }
        // Duplicated because the buffer it was formatted into does not outlive
        // this function, and the argv is kept for provenance.
        try argv.append(try self.allocator.dupe(u8, contexts));
        try argv.append("/");
        try self.runChroot(argv.items);
        // After the tool succeeded, so the record describes a relabel that
        // happened. `policy` points into the configuration this session's
        // arena still holds, so it outlives the result it is published in.
        self.selinux_relabel = .{ .policy = policy, .mode = mode };
    }

    fn guestFileExists(self: *Session, guest_path: []const u8) bool {
        const host_path = std.fmt.allocPrintSentinel(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
            0,
        ) catch return false;
        return isRegularFile(host_path);
    }

    fn guestDirectoryExists(self: *Session, guest_path: []const u8) bool {
        const host_path = std.fmt.allocPrintSentinel(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
            0,
        ) catch return false;
        return isDirectory(host_path);
    }

    fn readGuestFile(self: *Session, guest_path: []const u8, limit: usize) ![]u8 {
        const host_path = try std.fmt.allocPrint(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
        );
        return readFileAlloc(self.allocator, host_path, limit);
    }

    fn loadInstalledPackages(self: *Session) !void {
        try self.readInstalledPackages(&self.installed_packages);
    }

    fn readInstalledPackages(
        self: *Session,
        into: *std.array_list.Managed([]const u8),
    ) !void {
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
            try into.append(line);
        }
        std.mem.sort([]const u8, into.items, {}, lessThanBytes);
    }

    fn containsBytes(haystack: []const []const u8, needle: []const u8) bool {
        for (haystack) |candidate| {
            if (std.mem.eql(u8, candidate, needle)) return true;
        }
        return false;
    }

    fn runHooks(
        self: *Session,
        control: control_mod.Control,
        phase: control_mod.HookPhase,
    ) !void {
        for (control.hooks, 0..) |hook, index| {
            if (hook.phase != phase) continue;
            try self.runHook(hook, index);
        }
    }

    /// Runs one hook and records that it ran.
    ///
    /// What the hook gets is stated, not inherited, and is the same on both
    /// backends: its argument vector is the script followed by exactly the
    /// declared arguments, its environment is the one every command this agent
    /// runs gets, and it executes inside the target root. Its output is a
    /// build log rather than a value the run consumes, so it goes to the
    /// console the host is already reading, bounded by the same capture limit
    /// every other command's output is bounded by.
    ///
    /// The script is written by this agent, at a path this agent chose from
    /// the hook's position, onto the private tmpfs mounted at `<root>/run`,
    /// and unlinked whatever happens. The control document names no
    /// destination, so there is none to get wrong: the next hook, the
    /// initramfs generator, and anything a package scriptlet spawns must not
    /// find it, and nothing published can contain it.
    ///
    /// What it does not get is a wall clock, for the reason the chroot backend
    /// does not give it one either: package scriptlets and dracut modules are
    /// already target-supplied code running as root here with no deadline, and
    /// bounding only the hook would state a guarantee this backend does not
    /// have. #312 covers the whole execution.
    fn runHook(self: *Session, hook: control_mod.Hook, index: usize) !void {
        const guest_path = try std.fmt.allocPrint(
            self.allocator,
            "/run/zvmi-hook-{d}",
            .{index},
        );
        const size = try control_mod.hookScriptSize(hook);
        const script = try self.allocator.alloc(u8, size);
        try control_mod.decodeHookScript(hook, script);
        // The rule the request validator and the control document's own
        // validator both applied, applied once more to the bytes rather than
        // to their encoding: this is the last point before they are made
        // executable.
        if (script.len < 2 or script[0] != '#' or script[1] != '!') {
            return error.HookScriptUnusable;
        }

        try self.writeExecutableGuestFile(guest_path, script);
        defer self.deleteGuestFile(guest_path);

        var argv = try std.array_list.Managed([]const u8).initCapacity(
            self.allocator,
            hook.arguments.len + 1,
        );
        argv.appendAssumeCapacity(guest_path);
        argv.appendSliceAssumeCapacity(hook.arguments);

        // Not `runChroot`: that probes `argv[0] --version` for provenance,
        // and a hook is caller-supplied code rather than a tool. Running it an
        // extra time, with an argument its declaration never named, is not
        // something a hook's contract permits.
        const captured = try runInChroot(self.allocator, argv.items);
        log("[zvmi-guest] hook ");
        log(hook.name);
        log("\n");
        log(captured.output);
        if (captured.exit_code != 0) {
            self.last_exit_code = captured.exit_code;
            return error.HookFailed;
        }
        try self.hook_outcomes.append(.{
            .index = @intCast(index),
            .exit_code = captured.exit_code,
        });
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
    ///
    /// Nothing, rather than an empty string, when the tool could not be asked:
    /// the host publishes this straight into provenance, where "not probed"
    /// and "answered with nothing" have to stay distinguishable.
    fn probeVersion(self: *Session, program: []const u8) ?[]const u8 {
        const captured = runInChroot(self.allocator, &.{ program, "--version" }) catch
            return null;
        if (captured.exit_code != 0) return null;
        const trimmed = std.mem.trim(u8, firstLine(captured.output), " \t\r");
        return if (trimmed.len == 0) null else trimmed;
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
        try self.writeGuestFileMode(guest_path, bytes, 0o644);
    }

    fn writeGuestFileMode(
        self: *Session,
        guest_path: []const u8,
        bytes: []const u8,
        mode: linux.mode_t,
    ) !void {
        const host_path = try std.fmt.allocPrint(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
        );
        try writeFileBytes(self.allocator, host_path, bytes, mode);
    }

    /// Writes a file the guest is about to execute.
    ///
    /// Created exclusively, so a path something else already put there is a
    /// failure rather than a file this agent silently adopts, and `0700` so
    /// nothing in the target that is not root can read the caller's code even
    /// for the moment it exists.
    fn writeExecutableGuestFile(
        self: *Session,
        guest_path: []const u8,
        bytes: []const u8,
    ) !void {
        const host_path = try std.fmt.allocPrint(
            self.allocator,
            guest_root ++ "{s}",
            .{guest_path},
        );
        const path_z = try self.allocator.dupeZ(u8, host_path);
        const fd_raw = linux.open(
            path_z,
            .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true },
            0o700,
        );
        if (linux.errno(fd_raw) != .SUCCESS) return error.OpenFailed;
        const fd: i32 = @intCast(fd_raw);
        defer _ = linux.close(fd);
        try writeAll(fd, bytes);
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
        // First, and unconditionally: whatever else fails to unwind, the
        // material must not still be in this process's memory afterwards.
        if (self.credential_bytes) |bytes| {
            @memset(bytes, 0);
            self.credential_bytes = null;
        }
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
        const had_original = switch (self.resolver_state) {
            .untouched => return,
            .replaced_nothing => false,
            .replaced_original => true,
        };
        self.resolver_state = .untouched;
        restoreAside(
            guest_root ++ resolver_path,
            guest_root ++ resolver_backup_path,
            had_original,
        ) catch {
            log("[zvmi-guest] could not restore the target resolver\n");
        };
    }
};

/// The tdnf repository file the guest writes into the target root. Written by
/// hand rather than by a template so the grammar it has to satisfy — one
/// section, space-separated baseurls, gpgcheck on — is visible here.
fn renderRepositoryFile(
    allocator: Allocator,
    repository: control_mod.Repository,
    credential: ?control_mod.BasicMaterial,
) ![]const u8 {
    // The same renderer the chroot backend calls, so the same declaration
    // produces the same bytes whichever backend carries it out.
    return control_mod.renderRepositoryBody(
        allocator,
        repository.id,
        repository.urls,
        credential,
    );
}

fn renderResolver(allocator: Allocator, config: control_mod.NetworkConfig) ![]const u8 {
    return control_mod.renderResolverBody(allocator, config.nameservers);
}

/// The directory scan behind `Session.installedKernels`, taking its path so a
/// test can point it at a tree it built rather than at the mounted target.
fn discoverKernels(
    allocator: Allocator,
    modules_path: []const u8,
    skipped: *std.array_list.Managed(control_mod.SkippedKernel),
) ![]const []const u8 {
    const modules_z = try allocator.dupeZ(u8, modules_path);
    defer allocator.free(modules_z);
    const fd_raw = linux.open(modules_z, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    switch (linux.errno(fd_raw)) {
        .SUCCESS => {},
        // Absent is an answer: nothing is installed. Anything else -- a
        // `/lib/modules` that is not a directory, a symlink loop, EIO -- is a
        // failure to find out, and the host may be tolerating "none found",
        // in which case reporting it as none would ship a stale initramfs.
        .NOENT => return error.NoInstalledKernels,
        else => return error.OpenFailed,
    }
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    var releases: std.array_list.Managed([]const u8) = .init(allocator);
    var buffer: [8192]u8 align(@alignOf(linux.dirent64)) = undefined;
    while (true) {
        const rc = linux.getdents64(fd, &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        const filled: usize = @intCast(rc);
        if (filled == 0) break;

        var offset: usize = 0;
        while (offset < filled) {
            const record = buffer[offset..];
            const entry: *align(1) const linux.dirent64 = @ptrCast(record.ptr);
            // Records are variable-length and self-describing, so the length
            // is read before the cursor moves past it.
            offset += entry.reclen;

            const name_ptr: [*:0]const u8 = @ptrCast(record.ptr + @offsetOf(linux.dirent64, "name"));
            const name = std.mem.sliceTo(name_ptr, 0);
            // A release string the control document would have been refused
            // for carrying cannot become acceptable by being discovered
            // instead. This also excludes "." and "..".
            // "." and ".." are excluded by the same rule, and are not worth
            // reporting as kernels a run passed over.
            if (std.mem.eql(u8, name, ".") or std.mem.eql(u8, name, "..")) continue;
            if (!control_mod.validKernelRelease(name)) {
                try skipped.append(.{
                    .name = try allocator.dupe(u8, name),
                    .reason = .invalid_release_name,
                });
                continue;
            }
            if (!try hasDepmodOutput(allocator, modules_path, name)) {
                try skipped.append(.{
                    .name = try allocator.dupe(u8, name),
                    .reason = .no_module_dependency_index,
                });
                continue;
            }

            try releases.append(try allocator.dupe(u8, name));
        }
    }
    if (releases.items.len == 0) return error.NoInstalledKernels;
    std.mem.sort([]const u8, releases.items, {}, lessThanBytes);
    return releases.items;
}

// Fallible rather than returning a bare `false`: running out of memory while
// building a path is not evidence that the kernel beside it has no modules,
// and dropping a release on that basis skips an initramfs the caller asked to
// have regenerated.
fn hasDepmodOutput(allocator: Allocator, modules_path: []const u8, release: []const u8) !bool {
    for ([_][]const u8{ "modules.dep", "modules.dep.bin" }) |marker| {
        const path = try std.fmt.allocPrintSentinel(
            allocator,
            "{s}/{s}/{s}",
            .{ modules_path, release, marker },
            0,
        );
        defer allocator.free(path);
        // Absent -- or reached through something that is not a directory --
        // means this entry is not a kernel. Every other errno means the run
        // does not know, and answering "not a kernel" would drop a real
        // kernel from the set; a set emptied that way is accepted as
        // "nothing is stale" under `nothing_to_regenerate`.
        const rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
        switch (linux.errno(rc)) {
            .SUCCESS => {
                _ = linux.close(@intCast(rc));
                return true;
            },
            .NOENT, .NOTDIR => continue,
            else => return error.OpenFailed,
        }
    }
    return false;
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

/// Sets a file's mode outright, which a truncating open does not do for a
/// file that already exists.
fn setMode(allocator: Allocator, path: []const u8, mode: linux.mode_t) !void {
    const path_z = try allocator.dupeZ(u8, path);
    defer allocator.free(path_z);
    const err = linux.errno(linux.chmod(path_z, mode));
    if (err != .SUCCESS) return error.ChmodFailed;
}

/// Creates every directory leading to `path`, which the destinations for
/// rendered configuration need: an image that never had a `modprobe.d` is
/// still an image the configuration belongs in.
fn mkdirParents(allocator: Allocator, path: []const u8) !void {
    var index: usize = 0;
    while (std.mem.indexOfScalarPos(u8, path, index + 1, '/')) |separator| {
        const directory = try allocator.dupeZ(u8, path[0..separator]);
        defer allocator.free(directory);
        try mkdirPath(directory);
        index = separator;
    }
}

/// Opening with `O_DIRECTORY` answers the question without needing a `struct
/// stat` whose layout varies by architecture.
fn isDirectory(path: [*:0]const u8) bool {
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// The mirror of `isDirectory` for a file: opening for reading answers the
/// question, and fails for a directory only after `O_DIRECTORY` has already
/// been ruled out -- so it is asked the other way round, by refusing anything
/// that opens as a directory.
fn isRegularFile(path: [*:0]const u8) bool {
    if (isDirectory(path)) return false;
    const rc = linux.open(path, .{ .ACCMODE = .RDONLY }, 0);
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

/// Reads a whole block device into one exact allocation.
///
/// Deliberately not `readFileAlloc`: that grows a list and reads through a
/// stack buffer, so a secret read with it would be left behind in the stack
/// frame and in every intermediate allocation the growth abandoned -- and this
/// agent's arena is never reset, so abandoned is not the same as gone. One
/// allocation read into directly is one thing to scrub.
fn readDeviceAlloc(allocator: Allocator, device: []const u8, size: u64) ![]u8 {
    const device_z = try allocator.dupeZ(u8, device);
    defer allocator.free(device_z);
    const fd_raw = linux.open(device_z, .{ .ACCMODE = .RDONLY }, 0);
    switch (linux.errno(fd_raw)) {
        .SUCCESS => {},
        else => return error.OpenFailed,
    }
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    const buffer = try allocator.alloc(u8, @intCast(size));
    errdefer {
        @memset(buffer, 0);
        allocator.free(buffer);
    }
    @memset(buffer, 0);
    var filled: usize = 0;
    while (filled < buffer.len) {
        const rc = linux.read(fd, buffer.ptr + filled, buffer.len - filled);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        const count: usize = @intCast(rc);
        // A device shorter than the host said it would be is not fatal on its
        // own: the frame carries its own length and digest, so a truncated
        // read fails there, by name.
        if (count == 0) break;
        filled += count;
    }
    return buffer;
}

/// The size and SHA-256 of a file inside the target root.
///
/// Streamed rather than read whole: an initramfs is tens of megabytes and this
/// runs in a guest sized for the transaction, not for a copy of its output.
fn measureGuestFile(allocator: Allocator, guest_path: []const u8) !MeasuredFile {
    const host_path = try std.fmt.allocPrintSentinel(
        allocator,
        guest_root ++ "{s}",
        .{guest_path},
        0,
    );
    defer allocator.free(host_path);
    return measureFile(host_path);
}

/// Streams a file already named from the agent's own root.
fn measureFile(host_path: [:0]const u8) !MeasuredFile {
    const fd_raw = linux.open(host_path, .{ .ACCMODE = .RDONLY }, 0);
    switch (linux.errno(fd_raw)) {
        .SUCCESS => {},
        .NOENT => return error.FileNotFound,
        else => return error.OpenFailed,
    }
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var size: u64 = 0;
    while (true) {
        const rc = linux.read(fd, &buffer, buffer.len);
        switch (linux.errno(rc)) {
            .SUCCESS => {},
            .INTR => continue,
            else => return error.ReadFailed,
        }
        const count: usize = @intCast(rc);
        if (count == 0) break;
        hash.update(buffer[0..count]);
        size += count;
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .size = size, .sha256 = digest };
}

const MeasuredFile = struct {
    size: u64,
    sha256: [32]u8,
};

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

/// The resolver configuration this transaction will actually use, or null if it
/// will resolve no names and so must leave the image's own resolver alone.
///
/// Both halves matter. An offline guest has no network to resolve over, and a
/// transaction with no package actions runs no package manager -- and replacing
/// the resolver in either case would touch a file the run has no reason to
/// touch, which is exactly what the chroot backend and the documentation both
/// say does not happen.
fn resolverConfigFor(control: control_mod.Control) ?control_mod.NetworkConfig {
    if (control.actions.len == 0) return null;
    return switch (control.network) {
        .offline => null,
        .declared_repositories => |config| config,
    };
}

/// Moves whatever is at `path` aside to `backup` and writes `bytes` in its
/// place, reporting whether there was anything to move.
///
/// A rename rather than a read-and-write-back because `/etc/resolv.conf` is a
/// symlink into `/run` on most images: reading through one and writing the
/// bytes back would leave a regular file where the link was, mutating the
/// published image to record a resolver that only existed while the build ran.
/// A rename moves the link itself, whatever it points at.
fn replaceAside(
    allocator: Allocator,
    path: [:0]const u8,
    backup: [:0]const u8,
    bytes: []const u8,
) !bool {
    // Refusing an occupied backup rather than clobbering it: the only thing
    // that puts a file there is an earlier run of this, and overwriting it
    // would destroy the image's own file while reporting success.
    if (pathExistsNoFollow(backup)) return error.BackupPathOccupied;

    // The rename is its own probe. It reports in one atomic step both that
    // something was there and that it has been moved, so there is no window in
    // which a stat has answered "present" and the file has since gone.
    var had_original = false;
    switch (linux.errno(linux.renameat(linux.AT.FDCWD, path, linux.AT.FDCWD, backup))) {
        .SUCCESS => had_original = true,
        .NOENT => {},
        else => return error.RenameFailed,
    }
    errdefer restoreAside(path, backup, had_original) catch {};

    // Exclusive: nothing can be at the path now, and if something is, it is not
    // what was just moved aside -- so this can never write through a symlink.
    try writeNewFileBytes(allocator, path, bytes);
    return had_original;
}

/// Undoes `replaceAside`. Removing the written file even when there was no
/// original, so an image that shipped without a resolver does not gain one.
fn restoreAside(path: [:0]const u8, backup: [:0]const u8, had_original: bool) !void {
    _ = linux.unlink(path);
    if (!had_original) return;
    const rc = linux.renameat(linux.AT.FDCWD, backup, linux.AT.FDCWD, path);
    if (linux.errno(rc) != .SUCCESS) return error.RenameFailed;
}

/// Whether anything exists at the path, without following a final symlink. The
/// `PATH` handle is what makes that possible: `NOFOLLOW` alone fails on a
/// symlink, which would report a dangling link as absent.
fn pathExistsNoFollow(path: [*:0]const u8) bool {
    const rc = linux.open(
        path,
        .{ .ACCMODE = .RDONLY, .NOFOLLOW = true, .PATH = true },
        0,
    );
    if (linux.errno(rc) != .SUCCESS) return false;
    _ = linux.close(@intCast(rc));
    return true;
}

/// Creates a file that must not already exist. `EXCL` refuses a symlink at the
/// path outright, so this cannot write through one into somewhere else.
fn writeNewFileBytes(allocator: Allocator, path: []const u8, bytes: []const u8) !void {
    const path_z = try allocator.dupeZ(u8, path);
    const fd_raw = linux.open(
        path_z,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .EXCL = true },
        0o644,
    );
    if (linux.errno(fd_raw) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);
    try writeAll(fd, bytes);
}

fn writeFileBytes(
    allocator: Allocator,
    path: []const u8,
    bytes: []const u8,
    mode: linux.mode_t,
) !void {
    const path_z = try allocator.dupeZ(u8, path);
    const fd_raw = linux.open(
        path_z,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true },
        mode,
    );
    if (linux.errno(fd_raw) != .SUCCESS) return error.OpenFailed;
    const fd: i32 = @intCast(fd_raw);
    defer _ = linux.close(fd);
    try writeAll(fd, bytes);
}

fn writeAll(fd: i32, bytes: []const u8) !void {
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
    }, null);
    try std.testing.expectEqualStrings(
        \\[azurelinux-base]
        \\name=zvmi-azurelinux-base
        \\enabled=1
        \\gpgcheck=1
        \\baseurl=https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64 https://mirror.invalid/base
        \\
    , rendered);

    // The same declaration with material resolved for it gains the two lines
    // tdnf reads and nothing else, so a credentialed repository differs from
    // an anonymous one only where it has to.
    const authenticated = try renderRepositoryFile(arena.allocator(), .{
        .id = "azurelinux-base",
        .urls = &.{"https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64"},
        .trust_base64 = &.{"a2V5"},
        .credential = .{ .basic = .{ .username = "builder", .password_index = 0 } },
    }, .{ .username = "builder", .password = "s3cr3t" });
    try std.testing.expectEqualStrings(
        \\[azurelinux-base]
        \\name=zvmi-azurelinux-base
        \\enabled=1
        \\gpgcheck=1
        \\baseurl=https://packages.microsoft.com/azurelinux/3.0/prod/base/x86_64
        \\username=builder
        \\password=s3cr3t
        \\
    , authenticated);
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
        .baseline_packages = .init(arena.allocator()),
        .emitted_lock = .init(arena.allocator()),
        .hook_outcomes = .init(arena.allocator()),
        .initramfs_images = .init(arena.allocator()),
        .skipped_kernels = .init(arena.allocator()),
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

test "an initramfs is measured by streaming it, not by reading it whole" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // Larger than the read buffer, so the incremental path is the one under
    // test. A guest sized for the transaction cannot afford to hold an
    // initramfs in its arena, so this must never become a whole-file read.
    const path = "test-zvmiguest-initramfs.img";
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    const body = try allocator.alloc(u8, 150 * 1024);
    for (body, 0..) |*byte, index| byte.* = @truncate(index * 31);
    try writeFileBytes(allocator, path, body, 0o644);

    const measured = try measureFile(path);
    try std.testing.expectEqual(@as(u64, body.len), measured.size);
    var expected: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(body, &expected, .{});
    try std.testing.expectEqualSlices(u8, &expected, &measured.sha256);

    // A regeneration that produced no file must fail rather than publish a
    // digest of nothing.
    try std.testing.expectError(error.FileNotFound, measureFile("test-zvmiguest-absent.img"));
}

fn findSkipped(
    entries: []const control_mod.SkippedKernel,
    name: []const u8,
) ?control_mod.SkippedKernelReason {
    for (entries) |entry| {
        if (std.mem.eql(u8, entry.name, name)) return entry.reason;
    }
    return null;
}

test "kernel discovery follows dracut's rule and refuses to find nothing" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    var skipped: std.array_list.Managed(control_mod.SkippedKernel) = .init(allocator);

    // Built with the agent's own primitives, so the scan is tested against a
    // tree made the way the agent makes trees.
    const modules_path = "test-zvmiguest-modules";
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, modules_path) catch {};
    try mkdirPath(modules_path);

    // Nothing installed at all, which is the case a run must fail on rather
    // than report as a policy it carried out.
    try std.testing.expectError(
        error.NoInstalledKernels,
        discoverKernels(allocator, modules_path, &skipped),
    );

    // Two installed kernels, deliberately out of order and distinguished by
    // which of depmod's two outputs they carry, beside the two things that
    // live in `/lib/modules` without being kernels: a directory depmod never
    // touched, and a name no control document would have been allowed to
    // carry.
    try mkdirPath(modules_path ++ "/6.12.0-2.azl");
    try writeFileBytes(allocator, modules_path ++ "/6.12.0-2.azl/modules.dep", "", 0o644);
    try mkdirPath(modules_path ++ "/6.12.0-10.azl");
    try writeFileBytes(allocator, modules_path ++ "/6.12.0-10.azl/modules.dep.bin", "", 0o644);
    try mkdirPath(modules_path ++ "/firmware");
    try mkdirPath(modules_path ++ "/6.12.0 spaced");
    try writeFileBytes(allocator, modules_path ++ "/6.12.0 spaced/modules.dep", "", 0o644);

    skipped.clearRetainingCapacity();
    const found = try discoverKernels(allocator, modules_path, &skipped);
    try std.testing.expectEqual(@as(usize, 2), found.len);
    // Sorted, so the same target produces the same run twice.
    try std.testing.expectEqualStrings("6.12.0-10.azl", found[0]);
    try std.testing.expectEqualStrings("6.12.0-2.azl", found[1]);

    // What the scan passed over reaches the host too. A run that regenerated
    // one kernel's initramfs and silently declined to regenerate another's is
    // indistinguishable, from the report alone, from a target that only ever
    // had the one -- and the second is a bootable image, while the first is a
    // package transaction that shipped a stale initramfs. `.` and `..` are
    // not reported: they fail the same rule, but no reader could mistake them
    // for a kernel.
    try std.testing.expectEqual(@as(usize, 2), skipped.items.len);
    try std.testing.expectEqual(
        control_mod.SkippedKernelReason.no_module_dependency_index,
        findSkipped(skipped.items, "firmware").?,
    );
    try std.testing.expectEqual(
        control_mod.SkippedKernelReason.invalid_release_name,
        findSkipped(skipped.items, "6.12.0 spaced").?,
    );

    // An absent module tree is the only shape that reads as nothing
    // installed. The host may be tolerating that answer -- a regeneration it
    // derived rather than was asked for treats "none found" as nothing stale
    // -- so a path that could not be read must not arrive as the same answer,
    // or a package transaction would ship the initramfs it invalidated.
    try std.testing.expectError(
        error.NoInstalledKernels,
        discoverKernels(allocator, modules_path ++ "/absent", &skipped),
    );
    try std.testing.expectError(
        error.OpenFailed,
        discoverKernels(allocator, "/dev/null", &skipped),
    );
    try std.testing.expectError(
        error.OpenFailed,
        discoverKernels(allocator, modules_path ++ "/6.12.0-2.azl/modules.dep", &skipped),
    );

    // The same distinction one level in. A release directory that cannot be
    // searched is not evidence that the kernel inside it has no modules, and
    // skipping it would drop a real kernel from the set -- an empty set is
    // accepted as "nothing is stale" whenever the host derived the
    // regeneration, so this has to reach the caller as a failure.
    try mkdirPath(modules_path ++ "/6.12.0-locked.azl");
    try writeFileBytes(allocator, modules_path ++ "/6.12.0-locked.azl/modules.dep", "", 0o644);
    try setMode(allocator, modules_path ++ "/6.12.0-locked.azl", 0o000);
    defer setMode(allocator, modules_path ++ "/6.12.0-locked.azl", 0o755) catch {};
    try std.testing.expectError(
        error.OpenFailed,
        discoverKernels(allocator, modules_path, &skipped),
    );
}

test "every directory leading to a rendered destination is created" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // An image that never had a `modprobe.d` is still an image the declared
    // configuration belongs in, so the walk has to create the whole chain --
    // and must stop at the last separator rather than making a directory
    // where the file goes.
    const base = "test-zvmiguest-parents";
    defer std.Io.Dir.cwd().deleteTree(std.testing.io, base) catch {};
    const path = base ++ "/etc/modprobe.d/zvmi-blacklist.conf";
    try mkdirParents(allocator, path);
    try writeFileBytes(allocator, path, "blacklist floppy\n", 0o644);

    try std.testing.expect(isDirectory(base ++ "/etc/modprobe.d"));
    try std.testing.expect(!isDirectory(path));

    // Running it again on a chain that already exists is not an error: the
    // three destinations share their leading directories.
    try mkdirParents(allocator, path);
}

test "the image's own resolver comes back the kind of file it was" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();
    const io = std.testing.io;
    const cwd = std.Io.Dir.cwd();

    const base = "test-zvmiguest-resolver";
    defer cwd.deleteTree(io, base) catch {};
    cwd.deleteTree(io, base) catch {};
    try cwd.createDirPath(io, base ++ "/etc");
    const path = base ++ "/etc/resolv.conf";
    const backup = base ++ "/etc/.zvmi-resolv.conf";
    const rendered = "nameserver 192.0.2.1\n";

    // A regular file is moved aside and comes back byte for byte.
    try cwd.writeFile(io, .{ .sub_path = path, .data = "nameserver 198.51.100.7\n" });
    try std.testing.expect(try replaceAside(allocator, path, backup, rendered));
    try std.testing.expectEqualStrings(
        rendered,
        try cwd.readFileAlloc(io, path, allocator, .unlimited),
    );
    try restoreAside(path, backup, true);
    try std.testing.expectEqualStrings(
        "nameserver 198.51.100.7\n",
        try cwd.readFileAlloc(io, path, allocator, .unlimited),
    );
    try std.testing.expectError(
        error.FileNotFound,
        cwd.statFile(io, backup, .{}),
    );

    // The case that matters: nearly every distribution ships
    // `/etc/resolv.conf` as a symlink into `/run`. Copying its bytes and
    // writing them back would publish an image whose link had been replaced by
    // a stale regular file naming a resolver that existed only during the
    // build, so the link itself has to move.
    try cwd.deleteFile(io, path);
    try cwd.symLink(io, "../run/systemd/resolve/stub-resolv.conf", path, .{});
    try std.testing.expect(try replaceAside(allocator, path, backup, rendered));
    try std.testing.expectEqualStrings(
        rendered,
        try cwd.readFileAlloc(io, path, allocator, .unlimited),
    );
    try restoreAside(path, backup, true);
    var link_buffer: [256]u8 = undefined;
    const link_length = try cwd.readLink(io, path, &link_buffer);
    try std.testing.expectEqualStrings(
        "../run/systemd/resolve/stub-resolv.conf",
        link_buffer[0..link_length],
    );
    try std.testing.expectError(
        error.FileNotFound,
        cwd.statFile(io, backup, .{}),
    );

    // An image with no resolver at all does not gain one from the transaction.
    try cwd.deleteFile(io, path);
    try std.testing.expect(!try replaceAside(allocator, path, backup, rendered));
    try restoreAside(path, backup, false);
    try std.testing.expectError(
        error.FileNotFound,
        cwd.statFile(io, path, .{}),
    );

    // An occupied backup is a previous run's original. Clobbering it would
    // destroy the image's own file while reporting success.
    try cwd.writeFile(io, .{ .sub_path = path, .data = "nameserver 203.0.113.9\n" });
    try cwd.writeFile(io, .{ .sub_path = backup, .data = "stale\n" });
    try std.testing.expectError(
        error.BackupPathOccupied,
        replaceAside(allocator, path, backup, rendered),
    );
    try std.testing.expectEqualStrings(
        "nameserver 203.0.113.9\n",
        try cwd.readFileAlloc(io, path, allocator, .unlimited),
    );
}

test "the image's resolver is touched only by a transaction that resolves names" {
    const config = control_mod.NetworkConfig{
        .address = "10.0.2.15",
        .netmask = "255.255.255.0",
        .gateway = "10.0.2.2",
        .nameservers = &.{"10.0.2.3"},
    };
    const actions = [_]control_mod.Action{.{ .install = &.{"dracut"} }};
    const base = control_mod.Control{
        .root_device = "/dev/vda2",
        .result_device = "/dev/vdb",
        .network = .{ .declared_repositories = config },
    };

    var working = base;
    working.actions = &actions;
    try std.testing.expect(resolverConfigFor(working) != null);

    // A run with repositories and no package action still starts no package
    // manager, so there is nothing to resolve for and nothing to replace.
    try std.testing.expect(resolverConfigFor(base) == null);

    // An offline guest has no network to resolve over whatever else it does.
    var offline = base;
    offline.actions = &actions;
    offline.network = .offline;
    try std.testing.expect(resolverConfigFor(offline) == null);
}
