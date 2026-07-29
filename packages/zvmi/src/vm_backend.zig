//! Host capability probe for the isolated `vm` customization backend.
//!
//! This module deliberately performs no discovery: the emulator is named
//! explicitly by `customize.VmPolicy`, so a run can never silently fall back
//! to a host-architecture emulator or to software emulation. Every check runs
//! before `preserved_image.transactRaw` copies anything, so a rejection leaves
//! the source and the output untouched.

const std = @import("std");
const builtin = @import("builtin");
const customize = @import("customize.zig");
const free_space = @import("free_space.zig");
const preserved_image = @import("preserved_image.zig");
const transaction_guard = @import("transaction_guard.zig");
const vm_control = @import("vm_control.zig");
const vm_payload = @import("vm_payload.zig");

const Allocator = std.mem.Allocator;
const Io = std.Io;

/// Extra free space required beyond the raw stage and the published output, to
/// cover the control and result disks and filesystem overhead.
pub const workspace_overhead_bytes: u64 = 512 * 1024 * 1024;

/// The guest sees the staged image as its first disk and the result device as
/// its second. Which names those are depends on the transport the image's own
/// kernel can drive, which is read out of the image rather than assumed.
pub const stage_disk_index: u8 = 0;
pub const result_disk_index: u8 = 1;

/// Trust material is embedded in the control document, so it is bounded well
/// below the control-document limit rather than by the host's patience.
pub const max_trust_bytes: usize = 1024 * 1024;

/// How much of the emulator's console is retained for diagnosis. A guest that
/// fails is diagnosed from the tail of this, so it must be generous enough to
/// hold a kernel panic and small enough that a chatty guest cannot exhaust
/// host memory.
pub const max_console_bytes: usize = 8 * 1024 * 1024;

/// Reported when the guest ran to completion but refused or failed its plan.
/// The specific stage and detail travel in the runtime report's diagnostics,
/// not in the error, because an error value cannot carry them.
pub const Error = error{
    VmPolicyMissing,
    VmHostUnavailable,
    UnsupportedPackageAction,
    UnsupportedRootPartition,
    VmBootTimedOut,
    VmEmulatorFailed,
    /// The result device still held zeroes: the guest never reached the point
    /// of sealing an answer, which is a different outcome from any answer.
    VmGuestSilent,
    VmGuestFailed,
};

/// Reports whether this host can run the plan's VM backend.
///
/// `.missing` means the host lacks a resource the plan requires and the
/// operator can install or free it. `.unsupported` means the plan itself is
/// not executable here.
pub fn available(io: Io, plan: *const customize.ResolvedPlan) customize.CapabilityState {
    const data = plan.data;
    const policy = data.execution.vm orelse return .unsupported;
    if (data.execution.backend != .vm) return .unsupported;

    if (!emulatorExecutable(io, policy.emulator_command)) return .missing;

    switch (policy.boot) {
        .direct_kernel => {},
        // Firmware boot is part of the policy surface so the configuration is
        // stable, but no backend brings a guest up through firmware yet.
        // Falling back to a direct-kernel boot would silently bypass the boot
        // chain the caller asked to exercise.
        .firmware => return .unsupported,
    }

    switch (policy.acceleration) {
        .hardware => {
            if (data.architectures.runner != data.architectures.host) return .unsupported;
            if (!hardwareAccelerationAvailable(io)) return .missing;
        },
        .software => {},
    }

    if (data.input != .disk) return .unsupported;
    if (!workspaceHasFreeSpace(io, data.execution.workspace_path, data.input.disk.path)) {
        return .missing;
    }
    return .available;
}

fn emulatorExecutable(io: Io, command: []const u8) bool {
    // Resolution of a bare name against `PATH` belongs to the caller that
    // builds the policy, so provenance records the exact binary that ran.
    if (!std.fs.path.isAbsolute(command)) return false;
    return pathExecutable(io, command);
}

fn pathExecutable(io: Io, path: []const u8) bool {
    const cwd = Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{}) catch return false;
    if (stat.kind != .file) return false;
    cwd.access(io, path, .{ .execute = true }) catch return false;
    return true;
}

fn hardwareAccelerationAvailable(io: Io) bool {
    return switch (builtin.os.tag) {
        .linux => blk: {
            Io.Dir.cwd().access(io, "/dev/kvm", .{ .read = true, .write = true }) catch
                break :blk false;
            break :blk true;
        },
        // Hardware acceleration on these platforms is provided by the
        // hypervisor framework rather than a device node, and cannot be
        // probed without launching the emulator.
        .macos, .windows => true,
        else => false,
    };
}

fn workspaceHasFreeSpace(io: Io, workspace_path: []const u8, source_path: []const u8) bool {
    const cwd = Io.Dir.cwd();
    const source = cwd.statFile(io, source_path, .{}) catch return false;
    const doubled = std.math.mul(u64, source.size, 2) catch return false;
    const required = std.math.add(u64, doubled, workspace_overhead_bytes) catch return false;

    // The workspace itself is created by execution, so when it is absent the
    // parent directory is what must have room.
    const probe_path = if (pathExists(io, workspace_path))
        workspace_path
    else
        std.fs.path.dirname(workspace_path) orelse ".";
    // A null probe means the host cannot answer, which must not fail the
    // preflight: unknown free space is not the same as too little.
    const free_bytes = free_space.availableBytes(probe_path) orelse return true;
    return free_bytes >= required;
}

fn pathExists(io: Io, path: []const u8) bool {
    Io.Dir.cwd().access(io, path, .{}) catch return false;
    return true;
}

// ---- Execution --------------------------------------------------------

pub const RunOptions = struct {
    plan: *const customize.ResolvedPlan,
    transaction_path: []const u8,
    target: preserved_image.RawMutationTarget,
    /// The guest agent built for the runner architecture. Supplied by the
    /// caller rather than discovered on disk, so the bytes that boot are the
    /// ones this build produced and provenance can say so.
    agent: []const u8,
    /// Receives the emulator console when, and only when, a run fails. A guest
    /// that dies before it can seal a result leaves its kernel's last words
    /// here and nowhere else.
    console: ?ConsoleSink = null,
};

/// Where a failed run's console goes. A sink rather than a writer because the
/// destination is usually a locked stream the caller must not have held open
/// for the minutes a software-emulated boot can take.
pub const ConsoleSink = struct {
    context: ?*anyopaque = null,
    writeFn: *const fn (context: ?*anyopaque, bytes: []const u8) void,

    fn write(self: ConsoleSink, bytes: []const u8) void {
        self.writeFn(self.context, bytes);
    }
};

/// Boots the staged image's own kernel in an isolated guest, applies the
/// plan's package and initramfs policy there, and returns what the guest
/// reported.
///
/// The host holds no loop devices, no mounts, and no namespaces for this
/// backend: its entire footprint is one child process that `std.process.run`
/// is contracted to reap on every path. That is why, unlike `unsafe_chroot`,
/// this never has to abandon a transaction because teardown is uncertain.
pub fn run(
    allocator: Allocator,
    io: Io,
    options: RunOptions,
) !customize.VmRuntimeReport {
    const data = options.plan.data;
    const policy = data.execution.vm orelse return error.VmPolicyMissing;
    if (available(io, options.plan) != .available) return error.VmHostUnavailable;

    var scratch = std.heap.ArenaAllocator.init(allocator);
    defer scratch.deinit();
    const work = scratch.allocator();

    var lease = try transaction_guard.acquire(io, options.transaction_path);
    var lease_active = true;
    defer if (lease_active) {
        lease.release(io) catch lease.abandon(io);
        lease_active = false;
    };

    // Read before anything is built: every device name the guest is given,
    // the modules it has to insert to see those devices at all, and the
    // emulator command line that produces them all follow from what the
    // image's kernel can actually drive.
    var drivers = try vm_payload.probeDrivers(work, io, .{
        .raw_path = options.target.raw_path,
        .root_partition_offset = options.target.partition.offset,
        .kernel_release = requestedKernelRelease(data.initramfs),
        .network_required = policy.network == .declared_repositories,
    });
    defer drivers.deinit(work);

    var stage_buffer: [16]u8 = undefined;
    var result_buffer: [16]u8 = undefined;
    const stage_device = drivers.disk.devicePath(&stage_buffer, stage_disk_index);
    const result_device = drivers.disk.devicePath(&result_buffer, result_disk_index);

    const root_device = try rootDevicePath(
        work,
        stage_device,
        data.storage.preserve.root_partition,
    );
    const control = try buildControl(work, io, options.plan, .{
        .root_device = root_device,
        .result_device = result_device,
    }, drivers.modules);
    // The host refuses to emit a document it would refuse to read, so a
    // rejection here is a host bug rather than a guest-side surprise.
    try control.validate();
    const control_json = try std.json.Stringify.valueAlloc(work, control, .{});

    // The agent and the control document first, so a module can never take
    // the name of either, then the modules in the order they are inserted.
    var members: std.array_list.Managed(vm_payload.Member) = .init(work);
    try members.appendSlice(&.{
        .{ .path = vm_control.agent_path, .bytes = options.agent },
        .{ .path = vm_control.control_path, .bytes = control_json, .mode = 0o100600 },
    });
    for (drivers.modules) |module| {
        try members.append(.{ .path = module.member_path, .bytes = module.bytes });
    }

    var payload = try vm_payload.extract(work, io, .{
        .raw_path = options.target.raw_path,
        .root_partition_offset = options.target.partition.offset,
        .members = members.items,
        .kernel_release = requestedKernelRelease(data.initramfs),
    });
    defer payload.deinit(work);

    const layout = Layout{
        .kernel_path = try std.fs.path.join(work, &.{ options.transaction_path, "vm-kernel" }),
        .initrd_path = try std.fs.path.join(work, &.{ options.transaction_path, "vm-initrd" }),
        .raw_path = options.target.raw_path,
        .result_path = try std.fs.path.join(work, &.{ options.transaction_path, "vm-result.raw" }),
    };
    const cwd = Io.Dir.cwd();
    try writeFileBytes(io, layout.kernel_path, payload.kernel);
    try writeFileBytes(io, layout.initrd_path, payload.initrd);
    try createResultDevice(io, layout.result_path);

    const argv = try buildArgv(work, .{
        .policy = policy,
        .architecture = data.architectures.runner,
        .layout = layout,
        .disk = drivers.disk,
    });
    const outcome = std.process.run(work, io, .{
        .argv = argv,
        .stdout_limit = .limited(max_console_bytes),
        .stderr_limit = .limited(max_console_bytes),
        .timeout = (Io.Timeout{ .duration = .{
            .raw = .fromSeconds(policy.boot_timeout_seconds),
            .clock = .awake,
        } }).toDeadline(io),
    }) catch |err| {
        return switch (err) {
            error.Timeout => error.VmBootTimedOut,
            else => err,
        };
    };

    // Freed before the transaction publishes, so the copy that follows does
    // not have to share the workspace with a kernel and an initramfs.
    cwd.deleteFile(io, layout.kernel_path) catch {};
    cwd.deleteFile(io, layout.initrd_path) catch {};

    const framed = try readResultDevice(work, io, layout.result_path);
    cwd.deleteFile(io, layout.result_path) catch {};

    const emulator_ok = switch (outcome.term) {
        .exited => |code| code == 0,
        else => false,
    };
    if (!emulator_ok or isZeroed(framed)) {
        reportConsole(work, options.console, outcome, null);
        return if (emulator_ok) error.VmGuestSilent else error.VmEmulatorFailed;
    }

    const parsed = vm_control.parseResult(work, framed) catch |err| {
        reportConsole(work, options.console, outcome, null);
        return err;
    };
    defer parsed.deinit();
    try parsed.value.validate();
    if (parsed.value.failure) |failure| {
        reportConsole(work, options.console, outcome, failure);
        return error.VmGuestFailed;
    }

    const version = probeEmulatorVersion(work, io, policy.emulator_command);
    return ownReport(allocator, .{
        .result = parsed.value,
        .policy = policy,
        .architecture = data.architectures.runner,
        .root_device = root_device,
        .control_json = control_json,
        .payload = &payload,
        .emulator_version = version,
        .modules = drivers.modules,
    });
}

const Layout = struct {
    kernel_path: []const u8,
    initrd_path: []const u8,
    raw_path: []const u8,
    result_path: []const u8,
};

/// The guest kernel scans the partition table itself, so it is handed a
/// partition device rather than an offset it would have to be told to honour.
fn rootDevicePath(
    allocator: Allocator,
    stage_device: []const u8,
    selector: customize.PartitionSelector,
) ![]const u8 {
    const index = switch (selector) {
        .gpt_index, .mbr_index => |value| value,
    };
    if (index == 0 or index > 128) return error.UnsupportedRootPartition;
    return std.fmt.allocPrint(allocator, "{s}{d}", .{ stage_device, index });
}

fn requestedKernelRelease(initramfs: customize.InitramfsPolicy) ?[]const u8 {
    return switch (initramfs) {
        .unchanged => null,
        .regenerate => |regenerate| if (regenerate.kernels.len == 0)
            null
        else
            regenerate.kernels[0],
    };
}

const Devices = struct {
    root_device: []const u8,
    result_device: []const u8,
};

fn buildControl(
    allocator: Allocator,
    io: Io,
    plan: *const customize.ResolvedPlan,
    devices: Devices,
    modules: []const vm_payload.Module,
) !vm_control.Control {
    const data = plan.data;
    const members = try allocator.alloc([]const u8, modules.len);
    for (modules, members) |module, *member| member.* = module.member_path;
    return controlFromPolicy(allocator, io, .{
        .packages = data.packages,
        .initramfs = data.initramfs,
        .network = data.execution.vm.?.network,
        .devices = devices,
        .modules = members,
    });
}

const ControlInput = struct {
    packages: customize.PackagePolicy,
    initramfs: customize.InitramfsPolicy,
    network: customize.VmNetworkPolicy,
    devices: Devices,
    modules: []const []const u8 = &.{},
};

fn controlFromPolicy(
    allocator: Allocator,
    io: Io,
    input: ControlInput,
) !vm_control.Control {
    const repositories = try allocator.alloc(
        vm_control.Repository,
        input.packages.repositories.len,
    );
    for (input.packages.repositories, repositories) |source, *target| {
        const trust = try allocator.alloc([]const u8, source.trust.len);
        for (source.trust, trust) |material, *encoded| {
            // The guest has no host filesystem, so a path is resolved here or
            // not at all.
            const bytes = switch (material) {
                .inline_bytes => |value| value,
                .host_path => |path| try Io.Dir.cwd().readFileAlloc(
                    io,
                    path,
                    allocator,
                    .limited(max_trust_bytes),
                ),
            };
            const size = std.base64.standard.Encoder.calcSize(bytes.len);
            const buffer = try allocator.alloc(u8, size);
            encoded.* = std.base64.standard.Encoder.encode(buffer, bytes);
        }
        target.* = .{
            .id = source.id,
            .urls = source.urls,
            .trust_base64 = trust,
        };
    }

    const actions = try allocator.alloc(vm_control.Action, input.packages.actions.len);
    for (input.packages.actions, actions) |source, *target| {
        target.* = switch (source) {
            .install => |names| .{ .install = names },
            .remove => |names| .{ .remove = names },
            // Preflight already refuses these; failing here too keeps the
            // guest from ever receiving an action it cannot perform.
            .update_all, .update_selected => return error.UnsupportedPackageAction,
        };
    }

    return .{
        .root_device = input.devices.root_device,
        .result_device = input.devices.result_device,
        .network = switch (input.network) {
            .offline => .offline,
            .declared_repositories => .{ .declared_repositories = vm_control.qemu_user_network },
        },
        .repositories = repositories,
        .actions = actions,
        .initramfs_kernels = switch (input.initramfs) {
            .unchanged => &.{},
            .regenerate => |regenerate| regenerate.kernels,
        },
        .modules = input.modules,
    };
}

const ArgvInput = struct {
    policy: customize.VmPolicy,
    architecture: customize.Architecture,
    layout: Layout,
    disk: vm_payload.DiskTransport,
};

fn buildArgv(allocator: Allocator, input: ArgvInput) ![]const []const u8 {
    const policy = input.policy;
    const architecture = input.architecture;
    const layout = input.layout;
    var argv: std.array_list.Managed([]const u8) = .init(allocator);
    errdefer argv.deinit();

    try argv.appendSlice(&.{
        policy.emulator_command,
        // A run must not inherit anything from the host's QEMU configuration,
        // or the same plan would boot differently on two machines.
        "-no-user-config",
        "-nodefaults",
        // A guest that reboots has failed; letting the emulator exit turns
        // that into a prompt failure instead of a wait for the deadline.
        "-no-reboot",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "stdio",
        "-rtc",
        "base=utc",
    });
    try argv.appendSlice(&.{ "-machine", try std.fmt.allocPrint(
        allocator,
        "{s},accel={s}",
        .{ machineName(policy, architecture), accelerationName(policy.acceleration) },
    ) });
    try argv.appendSlice(&.{ "-cpu", cpuName(policy, architecture) });
    try argv.appendSlice(&.{ "-smp", try std.fmt.allocPrint(allocator, "{d}", .{policy.vcpus}) });
    try argv.appendSlice(&.{ "-m", try std.fmt.allocPrint(allocator, "{d}", .{policy.memory_mib}) });
    try argv.appendSlice(&.{ "-kernel", layout.kernel_path });
    try argv.appendSlice(&.{ "-initrd", layout.initrd_path });
    try argv.appendSlice(&.{ "-append", try kernelCommandLine(allocator, architecture) });
    try appendDisks(allocator, &argv, input);
    switch (policy.network) {
        .offline => try argv.appendSlice(&.{ "-nic", "none" }),
        .declared_repositories => try argv.appendSlice(&.{
            "-netdev", "user,id=zvmi0",
            "-device", "virtio-net-pci,netdev=zvmi0",
        }),
    }
    return argv.toOwnedSlice();
}

/// Attaches the stage and the result device in that order.
///
/// The names the guest sees are positional either way: `if=virtio` enumerates
/// in argv order, and `virtio-scsi` enumerates by SCSI id. Both are stated
/// explicitly here and again in the control document, so neither side has to
/// infer the other's ordering.
fn appendDisks(
    allocator: Allocator,
    argv: *std.array_list.Managed([]const u8),
    input: ArgvInput,
) !void {
    const paths = [_][]const u8{ input.layout.raw_path, input.layout.result_path };
    switch (input.disk) {
        .virtio_blk => for (paths) |path| {
            try argv.appendSlice(&.{ "-drive", try std.fmt.allocPrint(
                allocator,
                "file={s},format=raw,if=virtio,cache=writeback",
                .{path},
            ) });
        },
        .virtio_scsi => {
            try argv.appendSlice(&.{ "-device", "virtio-scsi-pci,id=zvmiscsi" });
            for (paths, 0..) |path, index| {
                try argv.appendSlice(&.{ "-drive", try std.fmt.allocPrint(
                    allocator,
                    "file={s},format=raw,if=none,id=zvmidisk{d},cache=writeback",
                    .{ path, index },
                ) });
                try argv.appendSlice(&.{ "-device", try std.fmt.allocPrint(
                    allocator,
                    "scsi-hd,drive=zvmidisk{d},bus=zvmiscsi.0,channel=0,scsi-id={d},lun=0",
                    .{ index, index },
                ) });
            }
        },
    }
}

fn machineName(policy: customize.VmPolicy, architecture: customize.Architecture) []const u8 {
    if (policy.machine) |machine| return machine;
    return switch (architecture) {
        .x86_64 => "q35",
        .aarch64 => "virt",
    };
}

fn cpuName(policy: customize.VmPolicy, architecture: customize.Architecture) []const u8 {
    if (policy.cpu) |cpu| return cpu;
    return switch (policy.acceleration) {
        // Passing the host model through is both the fastest and the most
        // faithful option, and it is only expressible when the guest and the
        // host are the same architecture — which hardware acceleration
        // already requires.
        .hardware => "host",
        .software => switch (architecture) {
            .x86_64 => "qemu64",
            .aarch64 => "max",
        },
    };
}

fn accelerationName(acceleration: customize.VmAcceleration) []const u8 {
    return switch (acceleration) {
        .hardware => "kvm",
        .software => "tcg",
    };
}

/// The agent replaces init outright: nothing between the kernel and it gets a
/// chance to run, which is what keeps a software-emulated boot affordable.
fn kernelCommandLine(
    allocator: Allocator,
    architecture: customize.Architecture,
) ![]const u8 {
    return std.fmt.allocPrint(
        allocator,
        "console={s},115200n8 rdinit=/{s} panic=-1 loglevel=4",
        .{ consoleDevice(architecture), vm_control.agent_path },
    );
}

fn consoleDevice(architecture: customize.Architecture) []const u8 {
    return switch (architecture) {
        .x86_64 => "ttyS0",
        .aarch64 => "ttyAMA0",
    };
}

fn writeFileBytes(io: Io, path: []const u8, bytes: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    var writer = file.writer(io, &.{});
    try writer.interface.writeAll(bytes);
    try writer.interface.flush();
}

/// A freshly created sparse file reads as zeroes, which is exactly the "no
/// answer yet" state the frame check depends on.
fn createResultDevice(io: Io, path: []const u8) !void {
    const file = try Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.setLength(io, vm_control.result_device_bytes);
}

fn readResultDevice(allocator: Allocator, io: Io, path: []const u8) ![]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    const wanted = vm_control.frame_header_size + vm_control.max_result_bytes;
    const buffer = try allocator.alloc(u8, wanted);
    const filled = try file.readPositionalAll(io, buffer, 0);
    return buffer[0..filled];
}

fn isZeroed(bytes: []const u8) bool {
    const window = @min(bytes.len, vm_control.frame_magic.len);
    for (bytes[0..window]) |byte| {
        if (byte != 0) return false;
    }
    return true;
}

/// Best effort: losing the console costs diagnosis, but refusing to report the
/// original failure because the report itself failed costs the diagnosis and
/// the failure.
fn reportConsole(
    allocator: Allocator,
    console: ?ConsoleSink,
    outcome: std.process.RunResult,
    failure: ?vm_control.Failure,
) void {
    const sink = console orelse return;
    if (failure) |value| {
        const summary = describeFailure(allocator, value) catch "guest failed\n";
        sink.write(summary);
    }
    sink.write(outcome.stdout);
    sink.write(outcome.stderr);
}

fn describeFailure(allocator: Allocator, failure: vm_control.Failure) ![]const u8 {
    var text: std.array_list.Managed(u8) = .init(allocator);
    errdefer text.deinit();
    try text.appendSlice(try std.fmt.allocPrint(
        allocator,
        "guest failed at stage '{s}'",
        .{failure.stage},
    ));
    if (failure.exit_code) |code| {
        try text.appendSlice(try std.fmt.allocPrint(allocator, " (exit {d})", .{code}));
    }
    if (failure.detail.len != 0) {
        try text.appendSlice(try std.fmt.allocPrint(allocator, ": {s}", .{failure.detail}));
    }
    try text.append('\n');
    return text.toOwnedSlice();
}

/// Best effort: a missing version string is worth recording as unknown, but is
/// not worth discarding a completed customization over.
fn probeEmulatorVersion(allocator: Allocator, io: Io, command: []const u8) []const u8 {
    const outcome = std.process.run(allocator, io, .{
        .argv = &.{ command, "--version" },
        .stdout_limit = .limited(64 * 1024),
        .stderr_limit = .limited(64 * 1024),
        .timeout = .{ .duration = .{ .raw = .fromSeconds(30), .clock = .awake } },
    }) catch return "unknown";
    switch (outcome.term) {
        .exited => |code| if (code != 0) return "unknown",
        else => return "unknown",
    }
    var lines = std.mem.splitScalar(u8, outcome.stdout, '\n');
    const first = lines.next() orelse return "unknown";
    const trimmed = std.mem.trim(u8, first, " \t\r");
    return if (trimmed.len == 0) "unknown" else trimmed;
}

const ReportInput = struct {
    result: vm_control.Result,
    policy: customize.VmPolicy,
    architecture: customize.Architecture,
    root_device: []const u8,
    control_json: []const u8,
    payload: *const vm_payload.Payload,
    emulator_version: []const u8,
    modules: []const vm_payload.Module,
};

fn ownReport(allocator: Allocator, input: ReportInput) !customize.VmRuntimeReport {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = arena.allocator();

    const tools = try owned.alloc(customize.ToolRecord, input.result.tools.len);
    for (input.result.tools, tools) |tool, *record| {
        const command = try owned.alloc([]const u8, tool.command.len);
        for (tool.command, command) |argument, *slot| slot.* = try owned.dupe(u8, argument);
        record.* = .{
            .name = try owned.dupe(u8, tool.name),
            .version = try owned.dupe(u8, tool.version),
            .command = command,
        };
    }

    const packages = try owned.alloc([]const u8, input.result.installed_packages.len);
    for (input.result.installed_packages, packages) |name, *slot| {
        slot.* = try owned.dupe(u8, name);
    }

    const modules = try owned.alloc(customize.VmModuleRecord, input.modules.len);
    for (input.modules, modules) |module, *record| {
        record.* = .{
            .name = try owned.dupe(u8, module.name),
            .image_path = try owned.dupe(u8, module.image_path),
            .sha256 = .{ .bytes = module.sha256 },
        };
    }

    return .{
        .arena = arena,
        .tools = tools,
        .installed_packages = packages,
        .execution = .{
            .emulator_command = try owned.dupe(u8, input.policy.emulator_command),
            .emulator_version = try owned.dupe(u8, input.emulator_version),
            .machine = try owned.dupe(u8, machineName(input.policy, input.architecture)),
            .cpu = try owned.dupe(u8, cpuName(input.policy, input.architecture)),
            .acceleration = input.policy.acceleration,
            .network = input.policy.network,
            .memory_mib = input.policy.memory_mib,
            .vcpus = input.policy.vcpus,
            .runner_architecture = input.architecture,
            .root_device = try owned.dupe(u8, input.root_device),
            .kernel_release = try owned.dupe(u8, input.payload.kernel_release orelse ""),
            .kernel_sha256 = .{ .bytes = digestOf(input.payload.kernel) },
            .initrd_sha256 = .{ .bytes = digestOf(input.payload.initrd) },
            .control_sha256 = .{ .bytes = digestOf(input.control_json) },
            .boot_origin = switch (input.payload.origin) {
                .boot_directory => |boot| .{ .boot_directory = .{
                    .kernel_path = try owned.dupe(u8, boot.kernel_path),
                    .initrd_path = try owned.dupe(u8, boot.initrd_path),
                } },
                .unified_kernel => |unified| .{ .unified_kernel = .{
                    .esp_path = try owned.dupe(u8, unified.esp_path),
                } },
            },
            .modules = modules,
        },
    };
}

fn digestOf(bytes: []const u8) [32]u8 {
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &digest, .{});
    return digest;
}

test "an emulator command must be an absolute path to an executable file" {
    const io = std.testing.io;
    try std.testing.expect(!emulatorExecutable(io, ""));
    try std.testing.expect(!emulatorExecutable(io, "qemu-system-x86_64"));
    try std.testing.expect(!emulatorExecutable(io, "/nonexistent/qemu-system-x86_64"));
    // A directory is not an emulator even though the path resolves.
    try std.testing.expect(!emulatorExecutable(io, "/tmp"));
}

fn indexOfArgument(argv: []const []const u8, name: []const u8) ?usize {
    for (argv, 0..) |argument, index| {
        if (std.mem.eql(u8, argument, name)) return index;
    }
    return null;
}

fn valueOfArgument(argv: []const []const u8, name: []const u8) ?[]const u8 {
    const index = indexOfArgument(argv, name) orelse return null;
    if (index + 1 >= argv.len) return null;
    return argv[index + 1];
}

const test_layout = Layout{
    .kernel_path = "work/vm-kernel",
    .initrd_path = "work/vm-initrd",
    .raw_path = "work/stage.raw",
    .result_path = "work/vm-result.raw",
};

test "a software-emulated x86_64 guest is offline and boots the extracted kernel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = try buildArgv(allocator, .{
        .policy = .{
            .emulator_command = "/opt/qemu/bin/qemu-system-x86_64",
            .acceleration = .software,
            .acknowledge_software_emulation = true,
            .memory_mib = 3072,
            .vcpus = 4,
            .network = .offline,
        },
        .architecture = .x86_64,
        .layout = test_layout,
        .disk = .virtio_blk,
    });

    try std.testing.expectEqualStrings("/opt/qemu/bin/qemu-system-x86_64", argv[0]);
    try std.testing.expectEqualStrings("q35,accel=tcg", valueOfArgument(argv, "-machine").?);
    try std.testing.expectEqualStrings("qemu64", valueOfArgument(argv, "-cpu").?);
    try std.testing.expectEqualStrings("3072", valueOfArgument(argv, "-m").?);
    try std.testing.expectEqualStrings("4", valueOfArgument(argv, "-smp").?);
    try std.testing.expectEqualStrings("work/vm-kernel", valueOfArgument(argv, "-kernel").?);
    try std.testing.expectEqualStrings("work/vm-initrd", valueOfArgument(argv, "-initrd").?);
    try std.testing.expectEqualStrings(
        "console=ttyS0,115200n8 rdinit=/zvmi-guest-agent panic=-1 loglevel=4",
        valueOfArgument(argv, "-append").?,
    );
    try std.testing.expectEqualStrings("none", valueOfArgument(argv, "-nic").?);
    try std.testing.expect(indexOfArgument(argv, "-netdev") == null);
    // Nothing about the host's QEMU configuration may reach the guest.
    try std.testing.expect(indexOfArgument(argv, "-no-user-config") != null);
    try std.testing.expect(indexOfArgument(argv, "-nodefaults") != null);
    try std.testing.expect(indexOfArgument(argv, "-no-reboot") != null);
}

test "drive order gives the stage vda and the result device vdb" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = try buildArgv(allocator, .{
        .policy = .{
            .emulator_command = "/opt/qemu/bin/qemu-system-x86_64",
            .acceleration = .software,
            .acknowledge_software_emulation = true,
        },
        .architecture = .x86_64,
        .layout = test_layout,
        .disk = .virtio_blk,
    });

    const first = indexOfArgument(argv, "-drive").?;
    try std.testing.expectEqualStrings(
        "file=work/stage.raw,format=raw,if=virtio,cache=writeback",
        argv[first + 1],
    );
    try std.testing.expectEqualStrings(
        "file=work/vm-result.raw,format=raw,if=virtio,cache=writeback",
        argv[first + 3],
    );

    var buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/dev/vdb",
        vm_payload.DiskTransport.virtio_blk.devicePath(&buffer, result_disk_index),
    );
}

test "a kernel with no built-in virtio-blk gets its disks over virtio-scsi" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = try buildArgv(allocator, .{
        .policy = .{
            .emulator_command = "/opt/qemu/bin/qemu-system-aarch64",
            .acceleration = .software,
            .acknowledge_software_emulation = true,
        },
        .architecture = .aarch64,
        .layout = test_layout,
        .disk = .virtio_scsi,
    });

    // A single controller with the stage at target 0 and the result device at
    // target 1, which is what makes them sda and sdb.
    try std.testing.expect(indexOfArgument(argv, "-drive") != null);
    var saw_controller = false;
    var saw_stage = false;
    var saw_result = false;
    for (argv) |argument| {
        if (std.mem.eql(u8, argument, "virtio-scsi-pci,id=zvmiscsi")) saw_controller = true;
        if (std.mem.eql(
            u8,
            argument,
            "scsi-hd,drive=zvmidisk0,bus=zvmiscsi.0,channel=0,scsi-id=0,lun=0",
        )) saw_stage = true;
        if (std.mem.eql(
            u8,
            argument,
            "scsi-hd,drive=zvmidisk1,bus=zvmiscsi.0,channel=0,scsi-id=1,lun=0",
        )) saw_result = true;
        // `if=virtio` would silently attach a disk the kernel cannot see.
        try std.testing.expect(std.mem.indexOf(u8, argument, "if=virtio") == null);
    }
    try std.testing.expect(saw_controller and saw_stage and saw_result);

    var buffer: [16]u8 = undefined;
    try std.testing.expectEqualStrings(
        "/dev/sda",
        vm_payload.DiskTransport.virtio_scsi.devicePath(&buffer, stage_disk_index),
    );
    try std.testing.expectEqualStrings(
        "/dev/sdb",
        vm_payload.DiskTransport.virtio_scsi.devicePath(&buffer, result_disk_index),
    );
}

test "a hardware-accelerated aarch64 guest passes the host cpu through and gets a network" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = try buildArgv(allocator, .{
        .policy = .{
            .emulator_command = "/opt/qemu/bin/qemu-system-aarch64",
            .acceleration = .hardware,
            .network = .declared_repositories,
        },
        .architecture = .aarch64,
        .layout = test_layout,
        .disk = .virtio_blk,
    });

    try std.testing.expectEqualStrings("virt,accel=kvm", valueOfArgument(argv, "-machine").?);
    try std.testing.expectEqualStrings("host", valueOfArgument(argv, "-cpu").?);
    try std.testing.expectEqualStrings("user,id=zvmi0", valueOfArgument(argv, "-netdev").?);
    try std.testing.expectEqualStrings(
        "virtio-net-pci,netdev=zvmi0",
        valueOfArgument(argv, "-device").?,
    );
    try std.testing.expect(indexOfArgument(argv, "-nic") == null);
    try std.testing.expectEqualStrings(
        "console=ttyAMA0,115200n8 rdinit=/zvmi-guest-agent panic=-1 loglevel=4",
        valueOfArgument(argv, "-append").?,
    );
}

test "an explicit machine and cpu override the architecture defaults" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = try buildArgv(allocator, .{
        .policy = .{
            .emulator_command = "/opt/qemu/bin/qemu-system-aarch64",
            .acceleration = .software,
            .machine = "virt,gic-version=3",
            .cpu = "cortex-a57",
        },
        .architecture = .aarch64,
        .layout = test_layout,
        .disk = .virtio_blk,
    });

    try std.testing.expectEqualStrings(
        "virt,gic-version=3,accel=tcg",
        valueOfArgument(argv, "-machine").?,
    );
    try std.testing.expectEqualStrings("cortex-a57", valueOfArgument(argv, "-cpu").?);
}

test "the root partition selector becomes the guest's partition device" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    try std.testing.expectEqualStrings(
        "/dev/vda2",
        try rootDevicePath(allocator, "/dev/vda", .{ .gpt_index = 2 }),
    );
    try std.testing.expectEqualStrings(
        "/dev/vda1",
        try rootDevicePath(allocator, "/dev/vda", .{ .mbr_index = 1 }),
    );
    // The transport decides the name; the selector only decides the index.
    try std.testing.expectEqualStrings(
        "/dev/sda3",
        try rootDevicePath(allocator, "/dev/sda", .{ .gpt_index = 3 }),
    );
    try std.testing.expectError(
        error.UnsupportedRootPartition,
        rootDevicePath(allocator, "/dev/vda", .{ .gpt_index = 0 }),
    );
}

test "trust material reaches the guest as base64 whether it was inline or a host path" {
    const io = std.testing.io;
    const cwd = Io.Dir.cwd();
    const key_path = "test-vm-backend-trust.gpg";
    defer cwd.deleteFile(io, key_path) catch {};
    try writeFileBytes(io, key_path, "\x99\x01\x0dkeyring");

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const control = try controlFromPolicy(allocator, io, .{
        .packages = .{
            .actions = &.{.{ .install = &.{"strace"} }},
            .repositories = &.{.{
                .id = "base",
                .urls = &.{"https://example.invalid/base"},
                .trust = &.{
                    .{ .inline_bytes = "inline-key" },
                    .{ .host_path = key_path },
                },
            }},
        },
        .initramfs = .{ .regenerate = .{ .kernels = &.{"6.12.0-1.azl"} } },
        .network = .declared_repositories,
        .devices = .{ .root_device = "/dev/vda2", .result_device = "/dev/vdb" },
    });
    try control.validate();

    try std.testing.expectEqualStrings("/dev/vdb", control.result_device);
    try std.testing.expectEqualStrings(
        "10.0.2.15",
        control.network.declared_repositories.address,
    );
    try std.testing.expectEqual(@as(usize, 2), control.repositories[0].trust_base64.len);
    for (control.repositories[0].trust_base64, 0..) |encoded, index| {
        const size = try std.base64.standard.Decoder.calcSizeForSlice(encoded);
        const decoded = try allocator.alloc(u8, size);
        try std.base64.standard.Decoder.decode(decoded, encoded);
        const expected: []const u8 = if (index == 0) "inline-key" else "\x99\x01\x0dkeyring";
        try std.testing.expectEqualStrings(expected, decoded);
    }
    try std.testing.expectEqualStrings("6.12.0-1.azl", control.initramfs_kernels[0]);
}

test "an offline guest is never handed package actions" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const control = try controlFromPolicy(allocator, std.testing.io, .{
        .packages = .{ .actions = &.{.{ .install = &.{"strace"} }} },
        .initramfs = .unchanged,
        .network = .offline,
        .devices = .{ .root_device = "/dev/vda2", .result_device = "/dev/vdb" },
    });
    try std.testing.expectError(
        error.OfflineNetworkWithPackageActions,
        control.validate(),
    );
}

test "package actions the guest cannot perform are refused before it boots" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    try std.testing.expectError(error.UnsupportedPackageAction, controlFromPolicy(
        arena.allocator(),
        std.testing.io,
        .{
            .packages = .{ .actions = &.{.update_all} },
            .initramfs = .unchanged,
            .network = .declared_repositories,
            .devices = .{ .root_device = "/dev/vda2", .result_device = "/dev/vdb" },
        },
    ));
}

test "an untouched result device is silence rather than an answer" {
    const io = std.testing.io;
    const cwd = Io.Dir.cwd();
    const path = "test-vm-backend-result.raw";
    defer cwd.deleteFile(io, path) catch {};
    try createResultDevice(io, path);

    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const empty = try readResultDevice(allocator, io, path);
    try std.testing.expect(isZeroed(empty));

    const sealed = try vm_control.seal(allocator, .{
        .tools = &.{.{ .name = "tdnf", .version = "3.5.8", .command = &.{"tdnf"} }},
        .installed_packages = &.{"strace-6.6-1.azl3.x86_64"},
    });
    const file = try cwd.createFile(io, path, .{ .truncate = false });
    try file.writePositionalAll(io, sealed, 0);
    file.close(io);

    const framed = try readResultDevice(allocator, io, path);
    try std.testing.expect(!isZeroed(framed));
    const parsed = try vm_control.parseResult(allocator, framed);
    defer parsed.deinit();
    try std.testing.expect(parsed.value.failure == null);
    try std.testing.expectEqualStrings("tdnf", parsed.value.tools[0].name);
}

test "a kernel release is only requested when the plan names one" {
    try std.testing.expect(requestedKernelRelease(.unchanged) == null);
    try std.testing.expect(requestedKernelRelease(.{ .regenerate = .{} }) == null);
    try std.testing.expectEqualStrings(
        "6.12.0-1.azl",
        requestedKernelRelease(.{ .regenerate = .{ .kernels = &.{"6.12.0-1.azl"} } }).?,
    );
}
