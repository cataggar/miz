//! Exercises the whole host side of the `vm` backend against a stand-in
//! emulator.
//!
//! The stand-in is this same executable invoked under a `qemu-system-<arch>`
//! name. It reads the command line the backend built, opens the initramfs the
//! backend appended to, parses the control document out of it, and seals a
//! result onto the device the control document named. In other words it
//! honours exactly the contract a real guest honours, and nothing else.
//!
//! That makes this test the one place where the host's argv, its control
//! document, its payload extraction, its result framing, its provenance, and
//! its transaction cleanup are checked together — on any runner, with no
//! privileges, no KVM, and no minutes of software emulation. A real guest
//! boot proves different things and is tested separately.

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

const kernel_release = "6.12.0-1.integration";
const kernel_bytes = "integration-kernel-image\n";
const agent_bytes = "integration-guest-agent\n";

/// What the stand-in emulator does once it has checked the contract. Each
/// value is a distinct way a real run can end, and the host is required to
/// tell them apart.
const StubMode = enum {
    /// Seals a successful result, as a guest that finished the plan would.
    success,
    /// Seals a result naming the stage that gave up.
    guest_failure,
    /// Exits cleanly having written nothing, as a guest that panicked before
    /// it could answer would.
    silent,
    /// Exits non-zero, as an emulator that could not start would.
    emulator_failure,
};

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(allocator);
    const executable_name = std.fs.path.basename(argv[0]);
    if (std.mem.startsWith(u8, executable_name, "qemu-system-")) {
        return runStubEmulator(allocator, init.io, argv[0], argv[1..]);
    }
    if (builtin.os.tag != .linux) {
        std.debug.print("skipping vm backend integration: Linux is required\n", .{});
        return;
    }
    try runIntegration(allocator, init.io, argv[0]);
}

fn runIntegration(allocator: Allocator, io: Io, self_exe: []const u8) !void {
    const architecture: zvmi.customize.Architecture = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => {
            std.debug.print(
                "skipping vm backend integration: unsupported host architecture\n",
                .{},
            );
            return;
        },
    };

    try runSuccess(allocator, io, self_exe, architecture);
    try runGuestFailure(allocator, io, self_exe, architecture);
    try runSilentGuest(allocator, io, self_exe, architecture);
    try runEmulatorFailure(allocator, io, self_exe, architecture);
    try runHardwareRejected(allocator, io, self_exe, architecture);
    std.debug.print("vm backend integration passed\n", .{});
}

// ---------------------------------------------------------------------------
// Cases
// ---------------------------------------------------------------------------

fn runSuccess(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture);
    defer workspace.deinit(io);

    var outcome = try workspace.execute(allocator, io, .success, .software);
    defer outcome.deinit(allocator);

    const result = outcome.result orelse return error.ExecutionProducedNoResult;
    if (outcome.diagnostics.hasErrors()) return error.ExecutionReportedErrors;
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) return error.CleanupFailed;
    }

    try ensure(result.provenance.schema_version == 6);
    const vm = result.provenance.execution.vm orelse
        return error.MissingVmProvenance;
    try ensure(std.mem.eql(u8, vm.emulator_command, workspace.emulator_path));
    try ensure(std.mem.eql(u8, vm.emulator_version, "stub-emulator 1.0"));
    try ensure(vm.acceleration == .software);
    try ensure(vm.network == .declared_repositories);
    try ensure(std.mem.eql(u8, vm.root_device, "/dev/vda1"));
    try ensure(std.mem.eql(u8, vm.kernel_release, kernel_release));
    try ensure(vm.runner_architecture == architecture);
    try ensure(vm.memory_mib == 1024);
    try ensure(vm.vcpus == 2);
    try ensure(std.mem.eql(
        u8,
        vm.boot_origin.boot_directory.kernel_path,
        "boot/vmlinuz-" ++ kernel_release,
    ));
    // The kernel the guest booted is the one the staged image carried, and
    // provenance can be checked against the source without trusting the run.
    try ensure(std.mem.eql(u8, &vm.kernel_sha256.bytes, &sha256(kernel_bytes)));
    try ensure(!std.mem.eql(u8, &vm.initrd_sha256.bytes, &vm.control_sha256.bytes));

    // The guest's answer is recorded verbatim rather than re-derived.
    const preserved = result.provenance.execution.preserved orelse
        return error.MissingPreservedProvenance;
    try ensure(preserved.installed_packages.len == 1);
    try ensure(std.mem.eql(
        u8,
        preserved.installed_packages[0],
        "integration-package-0:1.0-1.noarch",
    ));
    var saw_tdnf = false;
    for (result.provenance.tools) |tool| {
        if (std.mem.eql(u8, tool.name, "tdnf")) {
            saw_tdnf = true;
            try ensure(std.mem.eql(u8, tool.version, "stub tdnf 4.0"));
        }
    }
    try ensure(saw_tdnf);

    try expectPathAbsent(io, workspace.transaction_path);
    try expectFileExists(io, workspace.output_path);
    try expectSourceUnchanged(io, &workspace);
    workspace.completed = true;
}

fn runGuestFailure(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture);
    defer workspace.deinit(io);

    var outcome = try workspace.execute(allocator, io, .guest_failure, .software);
    defer outcome.deinit(allocator);

    try expectFailedRun(io, &workspace, &outcome);
    workspace.completed = true;
}

fn runSilentGuest(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture);
    defer workspace.deinit(io);

    var outcome = try workspace.execute(allocator, io, .silent, .software);
    defer outcome.deinit(allocator);

    try expectFailedRun(io, &workspace, &outcome);
    workspace.completed = true;
}

fn runEmulatorFailure(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture);
    defer workspace.deinit(io);

    var outcome = try workspace.execute(allocator, io, .emulator_failure, .software);
    defer outcome.deinit(allocator);

    try expectFailedRun(io, &workspace, &outcome);
    workspace.completed = true;
}

/// Hardware acceleration is rejected before anything is copied when the
/// accelerator is not there, rather than quietly degrading to emulation and
/// recording an accelerator that never ran.
fn runHardwareRejected(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    if (accelerationDeviceUsable(io)) {
        std.debug.print(
            "skipping vm hardware-rejection case: this host has an accelerator\n",
            .{},
        );
        return;
    }
    var workspace = try Workspace.create(allocator, io, self_exe, architecture);
    defer workspace.deinit(io);

    var resolved = try workspace.resolve(allocator, .hardware);
    defer resolved.deinit(allocator);
    const plan = &(resolved.plan orelse return error.ResolutionProducedNoPlan);
    try workspace.rememberTransaction(plan);

    var report = try zvmi.customize.preflight(
        allocator,
        io,
        plan,
        zvmi.customize.Platform.system(),
    );
    defer report.deinit(allocator);
    if (report.ready()) return error.HardwareAccelerationWasNotRejected;

    try expectPathAbsent(io, workspace.output_path);
    try expectPathAbsent(io, workspace.transaction_path);
    try expectSourceUnchanged(io, &workspace);
    workspace.completed = true;
}

/// Every failing run must leave the same evidence: no output, no transaction,
/// and a source byte-for-byte as it started. The distinction between the
/// failures is the diagnostic, not the residue.
fn expectFailedRun(
    io: Io,
    workspace: *const Workspace,
    outcome: *const zvmi.customize.ExecutionOutcome,
) !void {
    if (outcome.result != null) return error.FailedRunProducedResult;
    if (!outcome.diagnostics.hasErrors()) return error.FailedRunReportedNoError;
    try expectPathAbsent(io, workspace.output_path);
    try expectPathAbsent(io, workspace.transaction_path);
    try expectSourceUnchanged(io, workspace);
}

// ---------------------------------------------------------------------------
// Workspace
// ---------------------------------------------------------------------------

const Workspace = struct {
    allocator: Allocator,
    path: []const u8,
    source_path: []const u8,
    output_path: []const u8,
    /// Derived by `resolve` from a hash of the plan, so it is only known once
    /// a plan exists. Recorded here because the checks that matter are about
    /// what is left behind after the plan is gone.
    transaction_path: []const u8 = "",
    emulator_path: []const u8,
    mode_path: []const u8,
    architecture: zvmi.customize.Architecture,
    source_digest: [32]u8,
    /// Set by a case that reached its last assertion. A workspace is only
    /// removed once that happens, so a failure leaves its source, its output,
    /// and its transaction exactly as they were for inspection.
    completed: bool = false,

    fn create(
        allocator: Allocator,
        io: Io,
        self_exe: []const u8,
        architecture: zvmi.customize.Architecture,
    ) !Workspace {
        var random: [8]u8 = undefined;
        Io.random(io, &random);
        const random_hex = std.fmt.bytesToHex(random, .lower);
        const path = try std.fmt.allocPrint(
            allocator,
            "/tmp/zvmi-vm-backend-{s}",
            .{&random_hex},
        );
        try Io.Dir.cwd().createDir(io, path, .default_dir);

        const source_path = try std.fs.path.join(allocator, &.{ path, "source.raw" });
        const output_path = try std.fs.path.join(allocator, &.{ path, "output.raw" });
        const spool_path = try std.fs.path.join(allocator, &.{ path, "root.spool" });
        const emulator_path = try std.fs.path.join(allocator, &.{
            path,
            try std.fmt.allocPrint(
                allocator,
                "qemu-system-{s}",
                .{@tagName(architecture)},
            ),
        });

        try createSourceDisk(allocator, io, source_path, spool_path);
        try copyExecutable(io, self_exe, emulator_path);

        return .{
            .allocator = allocator,
            .path = path,
            .source_path = source_path,
            .output_path = output_path,
            .emulator_path = emulator_path,
            .mode_path = try std.fmt.allocPrint(
                allocator,
                "{s}.mode",
                .{emulator_path},
            ),
            .architecture = architecture,
            .source_digest = try digestOfFile(io, source_path),
        };
    }

    fn deinit(self: *Workspace, io: Io) void {
        if (!self.completed) {
            std.debug.print(
                "vm backend integration retained failed workspace: {s}\n",
                .{self.path},
            );
            return;
        }
        Io.Dir.cwd().deleteTree(io, self.path) catch {};
    }

    fn resolve(
        self: *const Workspace,
        allocator: Allocator,
        acceleration: zvmi.customize.VmAcceleration,
    ) !zvmi.customize.ResolveOutcome {
        const actions = [_]zvmi.customize.PackageAction{
            .{ .install = &.{"integration-package"} },
        };
        const repositories = [_]zvmi.customize.PackageRepository{.{
            .id = "integration",
            .urls = &.{"https://packages.example.invalid/base"},
            .trust = &.{.{ .inline_bytes = "integration trust\n" }},
        }};
        const request = zvmi.customize.Request{
            .target_architecture = self.architecture,
            .input = .{ .disk = .{ .path = self.source_path } },
            .output = .{
                .path = self.output_path,
                .format = .raw,
                .size_policy = .preserve_source,
            },
            .storage = .{ .preserve = .{
                .root_partition = .{ .mbr_index = 1 },
            } },
            .packages = .{
                .actions = &actions,
                .repositories = &repositories,
            },
            .initramfs = .{ .regenerate = .{
                .generator = "dracut",
                .kernels = &.{kernel_release},
            } },
            .execution = .{
                .workspace_path = self.path,
                .backend = .vm,
                .vm = .{
                    .emulator_command = self.emulator_path,
                    .acceleration = acceleration,
                    .acknowledge_software_emulation = acceleration == .software,
                    .memory_mib = 1024,
                    .network = .declared_repositories,
                    .boot_timeout_seconds = 120,
                },
            },
            .reproducibility = .{
                .seed = .{ .bytes = [_]u8{0x56} ** 32 },
                .source_date_epoch = 1_735_689_600,
            },
        };
        return zvmi.customize.resolve(allocator, &request, .{
            .host_architecture = self.architecture,
        });
    }

    fn execute(
        self: *Workspace,
        allocator: Allocator,
        io: Io,
        mode: StubMode,
        acceleration: zvmi.customize.VmAcceleration,
    ) !zvmi.customize.ExecutionOutcome {
        // The backend controls every argument the emulator receives, so the
        // stand-in is told what to do through a file it finds beside itself.
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = self.mode_path,
            .data = @tagName(mode),
        });

        var resolved = try self.resolve(allocator, acceleration);
        defer resolved.deinit(allocator);
        const plan = &(resolved.plan orelse return error.ResolutionProducedNoPlan);
        if (resolved.diagnostics.hasErrors()) return error.ResolutionReportedErrors;
        try self.rememberTransaction(plan);

        var platform = zvmi.customize.Platform.system();
        platform.vmCheckFn = checkVm;
        platform.vmRunFn = runVm;

        var report = try zvmi.customize.preflight(allocator, io, plan, platform);
        defer report.deinit(allocator);
        if (!report.ready()) return error.PreflightRefusedTheRun;

        return zvmi.customize.execute(allocator, io, plan, platform, null);
    }

    fn rememberTransaction(
        self: *Workspace,
        plan: *const zvmi.customize.ResolvedPlan,
    ) !void {
        if (self.transaction_path.len != 0) {
            self.allocator.free(self.transaction_path);
        }
        self.transaction_path = try self.allocator.dupe(
            u8,
            plan.data.transaction_path,
        );
    }
};

fn checkVm(
    _: ?*anyopaque,
    io: Io,
    plan: *const zvmi.customize.ResolvedPlan,
) zvmi.customize.CapabilityState {
    return zvmi.vm_backend.available(io, plan);
}

fn runVm(
    _: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    plan: *const zvmi.customize.ResolvedPlan,
    target: zvmi.preserved_image.RawMutationTarget,
) !zvmi.customize.VmRuntimeReport {
    return zvmi.vm_backend.run(allocator, io, .{
        .plan = plan,
        .transaction_path = plan.data.transaction_path,
        .target = target,
        .agent = agent_bytes,
    });
}

// ---------------------------------------------------------------------------
// The stand-in emulator
// ---------------------------------------------------------------------------

fn runStubEmulator(
    allocator: Allocator,
    io: Io,
    self_path: []const u8,
    args: []const []const u8,
) !void {
    if (args.len == 1 and std.mem.eql(u8, args[0], "--version")) {
        var stdout_buffer: [64]u8 = undefined;
        var stdout = Io.File.stdout().writer(io, &stdout_buffer);
        try stdout.interface.writeAll("stub-emulator 1.0\n");
        try stdout.interface.flush();
        return;
    }
    const mode_path = try std.fmt.allocPrint(allocator, "{s}.mode", .{self_path});
    const mode_text = try Io.Dir.cwd().readFileAlloc(
        io,
        mode_path,
        allocator,
        .limited(64),
    );
    const mode = std.meta.stringToEnum(StubMode, mode_text) orelse
        return error.UnknownStubMode;
    if (mode == .emulator_failure) return error.StubEmulatorRefused;

    const kernel_path = valueAfter(args, "-kernel") orelse
        return error.MissingKernelArgument;
    const initrd_path = valueAfter(args, "-initrd") orelse
        return error.MissingInitrdArgument;
    const append = valueAfter(args, "-append") orelse
        return error.MissingAppendArgument;

    // The agent only ever runs as rdinit; anything else means the image's own
    // init would have run first and the guest would not be an appliance.
    if (std.mem.indexOf(u8, append, "rdinit=/zvmi-guest-agent") == null) {
        return error.UnexpectedKernelCommandLine;
    }
    if (std.mem.indexOf(u8, append, "panic=-1") == null) {
        return error.KernelWouldRebootOnPanic;
    }

    const kernel = try Io.Dir.cwd().readFileAlloc(
        io,
        kernel_path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    if (!std.mem.eql(u8, kernel, kernel_bytes)) return error.UnexpectedKernel;

    const initrd = try Io.Dir.cwd().readFileAlloc(
        io,
        initrd_path,
        allocator,
        .limited(64 * 1024 * 1024),
    );

    var agent: ?[]const u8 = null;
    var control_json: ?[]const u8 = null;
    var reader = zvmi.cpio.Reader.init(initrd);
    while (try reader.next()) |entry| {
        if (std.mem.eql(u8, entry.path, zvmi.vm_control.agent_path)) {
            agent = entry.content;
        } else if (std.mem.eql(u8, entry.path, zvmi.vm_control.control_path)) {
            control_json = entry.content;
        }
    }
    if (!std.mem.eql(u8, agent orelse return error.MissingAgentMember, agent_bytes)) {
        return error.UnexpectedAgent;
    }

    const parsed = try zvmi.vm_control.parseControl(
        allocator,
        control_json orelse return error.MissingControlMember,
    );
    defer parsed.deinit();
    const control = parsed.value;
    // The guest would refuse a document it cannot act on, so the stand-in does
    // too: a host that emits an invalid document must fail here, not in a real
    // guest weeks later.
    try control.validate();
    try expectStub(std.mem.eql(u8, control.root_device, "/dev/vda1"));
    try expectStub(std.mem.eql(u8, control.result_device, zvmi.vm_backend.result_device));
    try expectStub(control.repositories.len == 1);
    try expectStub(std.mem.eql(u8, control.repositories[0].id, "integration"));
    try expectStub(control.repositories[0].trust_base64.len == 1);
    try expectStub(control.actions.len == 1);
    try expectStub(control.initramfs_kernels.len == 1);
    try expectStub(std.mem.eql(u8, control.initramfs_kernels[0], kernel_release));
    try expectStub(control.network == .declared_repositories);

    // Which drive is which is positional, so the result must be written
    // through the same ordering the guest would see.
    const result_path = driveAt(args, 1) orelse return error.MissingResultDrive;
    const stage_path = driveAt(args, 0) orelse return error.MissingStageDrive;
    try expectStub(!std.mem.eql(u8, stage_path, result_path));
    if (mode == .silent) return;

    const result: zvmi.vm_control.Result = switch (mode) {
        .guest_failure => .{
            .failure = .{
                .stage = "packages",
                .detail = "the stand-in guest was told to fail",
                .exit_code = 1,
            },
        },
        else => .{
            .tools = &.{
                .{
                    .name = "tdnf",
                    .version = "stub tdnf 4.0",
                    .command = &.{ "tdnf", "--version" },
                },
                .{
                    .name = "dracut",
                    .version = "stub dracut 059",
                    .command = &.{ "dracut", "--version" },
                },
            },
            .installed_packages = &.{"integration-package-0:1.0-1.noarch"},
        },
    };
    const sealed = try zvmi.vm_control.seal(allocator, result);
    defer allocator.free(sealed);

    const file = try Io.Dir.cwd().openFile(io, result_path, .{ .mode = .write_only });
    defer file.close(io);
    try file.writePositionalAll(io, sealed, 0);
}

fn driveAt(args: []const []const u8, wanted: usize) ?[]const u8 {
    var seen: usize = 0;
    for (args, 0..) |arg, index| {
        if (!std.mem.eql(u8, arg, "-drive") or index + 1 >= args.len) continue;
        if (seen == wanted) {
            const value = args[index + 1];
            const prefix = "file=";
            if (!std.mem.startsWith(u8, value, prefix)) return null;
            const rest = value[prefix.len..];
            const end = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
            return rest[0..end];
        }
        seen += 1;
    }
    return null;
}

fn valueAfter(args: []const []const u8, name: []const u8) ?[]const u8 {
    for (args, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, name) and index + 1 < args.len) {
            return args[index + 1];
        }
    }
    return null;
}

fn expectStub(condition: bool) !void {
    if (!condition) return error.StubEmulatorContractViolated;
}

// ---------------------------------------------------------------------------
// Fixtures and helpers
// ---------------------------------------------------------------------------

fn createSourceDisk(
    allocator: Allocator,
    io: Io,
    source_path: []const u8,
    spool_path: []const u8,
) !void {
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

    var tree = try zvmi.root_tree.RootTree.init(allocator, io, spool_path, .{});
    defer tree.deinit();
    inline for (.{ "boot", "dev", "etc", "proc", "run", "sys", "usr", "var" }) |path| {
        try tree.putDirectory(path, .{ .mode = 0o755 });
    }
    try tree.putFileBytes(
        "boot/vmlinuz-" ++ kernel_release,
        kernel_bytes,
        .{ .mode = 0o644 },
    );
    try tree.putFileBytes(
        "boot/initramfs-" ++ kernel_release ++ ".img",
        cpio_trailer,
        .{ .mode = 0o600 },
    );
    _ = try zvmi.ext4.populate(io, image.file, allocator, try tree.ext4View(), .{
        .offset = partition_offset,
        .length = partition_length,
        .label = "vm-test",
        .uuid = [_]u8{0x56} ** 16,
        .timestamp = 1_735_689_600,
    });
}

/// A newc header for `TRAILER!!!`: 110 header bytes of constant fields, the
/// name, its NUL, and padding to a four-byte boundary.
const cpio_trailer =
    "070701" ++ // magic
    "00000000" ++ // ino
    "00000000" ++ // mode
    "00000000" ++ // uid
    "00000000" ++ // gid
    "00000001" ++ // nlink
    "00000000" ++ // mtime
    "00000000" ++ // filesize
    "00000000" ++ // devmajor
    "00000000" ++ // devminor
    "00000000" ++ // rdevmajor
    "00000000" ++ // rdevminor
    "0000000b" ++ // namesize, including the trailing NUL
    "00000000" ++ // check
    "TRAILER!!!\x00\x00\x00\x00";

/// Copies rather than links so the stand-in has its own inode: the emulator
/// name the backend invokes is part of what is under test, and the copy
/// inherits the source's executable permissions.
fn copyExecutable(io: Io, self_exe: []const u8, destination: []const u8) !void {
    const cwd = Io.Dir.cwd();
    try cwd.copyFile(self_exe, cwd, destination, io, .{});
}

/// Streamed rather than read whole: the source is large enough that hashing it
/// twice through a buffer is cheaper than holding it twice in memory.
fn digestOfFile(io: Io, path: []const u8) ![32]u8 {
    var buffer: [64 * 1024]u8 = undefined;
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var offset: u64 = 0;
    while (true) {
        const read = try file.readPositionalAll(io, &buffer, offset);
        if (read == 0) break;
        hasher.update(buffer[0..read]);
        offset += read;
        if (read < buffer.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
}

fn sha256(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

fn expectSourceUnchanged(io: Io, workspace: *const Workspace) !void {
    const digest = try digestOfFile(io, workspace.source_path);
    if (!std.mem.eql(u8, &digest, &workspace.source_digest)) {
        return error.SourceWasModified;
    }
}

fn expectPathAbsent(io: Io, path: []const u8) !void {
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.UnexpectedPath;
}

fn expectFileExists(io: Io, path: []const u8) !void {
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch
        return error.MissingPath;
}

fn accelerationDeviceUsable(io: Io) bool {
    Io.Dir.cwd().access(io, "/dev/kvm", .{ .read = true, .write = true }) catch
        return false;
    return true;
}

fn ensure(condition: bool) !void {
    if (!condition) return error.IntegrationAssertionFailed;
}
