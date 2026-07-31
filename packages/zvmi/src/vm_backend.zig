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
const os_customization = @import("os_customization.zig");
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
    UnsupportedRootPartition,
    VmBootTimedOut,
    VmEmulatorFailed,
    /// The result device still held zeroes: the guest never reached the point
    /// of sealing an answer, which is a different outcome from any answer.
    VmGuestSilent,
    VmGuestFailed,
    /// The plan asked for a firmware boot and the named EDK2 files are not
    /// readable here. Never downgraded to a direct-kernel boot: that would
    /// bypass the boot chain the plan asked to exercise.
    VmFirmwareUnavailable,
    /// The image's boot chain never printed the marker within its own budget.
    /// The recorded console is where the boot actually stopped.
    VmFirmwareBootTimedOut,
    /// The emulator exited before the marker appeared. Either the firmware
    /// found nothing to boot, or the boot chain died on the way up.
    VmFirmwareBootFailed,
    /// The console produced more than the attestation is willing to hold.
    /// A guest that says this much is not booting, it is looping.
    VmFirmwareConsoleOverflowed,
    /// The attested stage differs from the customized stage. Attestation is
    /// contracted to be read-only, so this means the emulator wrote through
    /// the overlay and the published bytes would depend on the boot mode.
    VmFirmwareStageMutated,
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
        // A firmware boot needs the EDK2 pair the plan names. Absence is
        // `.missing` — the operator can install it — and never a silent
        // downgrade to the direct-kernel boot, which would bypass the boot
        // chain the plan exists to exercise.
        .firmware => |firmware| switch (customize.vmFirmwareAvailable(io, firmware)) {
            .available => {},
            .missing => return .missing,
            .unsupported => return .unsupported,
        },
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

    // The boot chain is attested after customization and before publication,
    // because what gets published is the customized stage and that is what has
    // to be proven bootable. A run that reaches here has already produced its
    // result; a failed attestation withholds it rather than rewriting it.
    var boot_record: customize.VmBootRecord = .direct_kernel;
    switch (policy.boot) {
        .direct_kernel => {},
        .firmware => |firmware| {
            const record = try attestFirmwareBoot(work, io, .{
                .policy = policy,
                .firmware = firmware,
                .architecture = data.architectures.runner,
                .transaction_path = options.transaction_path,
                .stage_path = options.target.raw_path,
                .console = options.console,
            });
            // Published whole: a half-filled record behind a set tag would
            // read as a firmware boot nobody performed.
            boot_record = .{ .firmware = record };
        },
    }

    return ownReport(allocator, .{
        .result = parsed.value,
        .policy = policy,
        .architecture = data.architectures.runner,
        .root_device = root_device,
        .control_json = control_json,
        .payload = &payload,
        .emulator_version = version,
        .modules = drivers.modules,
        .boot = boot_record,
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
        // The guest reaches the root through /dev/vdaN, which exists only
        // for a partition. A logical volume would need the volume manager
        // activated inside the guest, which this initramfs does not carry,
        // so the request is refused rather than pointed at the partition
        // that merely contains the volume group.
        .logical_volume => return error.UnsupportedRootPartitionInVm,
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
        .kernel_modules = data.os.kernel_modules,
    });
}

const ControlInput = struct {
    packages: customize.PackagePolicy,
    initramfs: customize.InitramfsPolicy,
    network: customize.VmNetworkPolicy,
    devices: Devices,
    modules: []const []const u8 = &.{},
    kernel_modules: []const customize.KernelModule = &.{},
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
            .update_all => .update_all,
            .update_selected => |names| .{ .update_selected = names },
        };
    }

    // Rendered on the host so the bytes a request produces do not depend on
    // which backend carries it out; the guest only places them.
    const rendered = try os_customization.renderKernelModules(
        allocator,
        input.kernel_modules,
    );
    const kernel_module_files = try allocator.alloc(vm_control.TargetFile, rendered.len);
    for (rendered, kernel_module_files) |source, *target| {
        target.* = .{ .path = source.path, .contents = source.contents };
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
        .initramfs = switch (input.initramfs) {
            .unchanged => .unchanged,
            .regenerate => |regenerate| .{ .regenerate = .{ .kernels = regenerate.kernels } },
        },
        .kernel_module_files = kernel_module_files,
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

// ---- Firmware boot attestation ----------------------------------------

/// Ceiling on an EDK2 file. AAVMF's code and variable images are 64 MiB, which
/// is the largest firmware either supported architecture ships.
pub const max_firmware_bytes: usize = 128 * 1024 * 1024;

/// How much of the attestation console is held while waiting for the marker.
/// A boot chain that says more than this is not booting, and holding its
/// output would cost the host more than the diagnosis is worth.
pub const max_firmware_console_bytes: usize = 32 * 1024 * 1024;

/// Read granularity for digesting the stage. Large enough that a multi-gigabyte
/// image is not read a page at a time, small enough to stay off the stack.
const stage_digest_chunk_bytes: usize = 256 * 1024;

/// What `attestFirmwareBoot` needs. Public because the opt-in real-firmware
/// test drives the attestation directly: a full customization run cannot be
/// synthesized around an image a maintainer supplies.
pub const AttestationInput = struct {
    policy: customize.VmPolicy,
    firmware: customize.VmFirmware,
    architecture: customize.Architecture,
    transaction_path: []const u8,
    stage_path: []const u8,
    console: ?ConsoleSink,
};

/// Boots the customized stage through its own firmware and bootloader and
/// waits for the image to say, on its own console, that it took control.
///
/// Nothing is delivered into this guest. The agent that performed the
/// customization is not present, no device is added for it to find, and the
/// image is not modified to make room for one — a boot chain altered to admit
/// an agent is not the boot chain the published image will run. The guest is
/// therefore observed rather than driven, through the one channel every boot
/// chain already has: the serial console.
///
/// The stage is attached with `snapshot=on`, so every write the guest makes
/// lands in a host-side overlay that is discarded with the process. The
/// digests taken either side of the boot turn that from an assumption into a
/// checked fact.
pub fn attestFirmwareBoot(
    gpa: Allocator,
    io: Io,
    input: AttestationInput,
) !customize.VmFirmwareRecord {
    var arena = std.heap.ArenaAllocator.init(gpa);
    defer arena.deinit();
    const work = arena.allocator();
    const cwd = Io.Dir.cwd();

    const code_bytes = cwd.readFileAlloc(
        io,
        input.firmware.code_path,
        work,
        .limited(max_firmware_bytes),
    ) catch return error.VmFirmwareUnavailable;
    const vars_bytes = cwd.readFileAlloc(
        io,
        input.firmware.vars_path,
        work,
        .limited(max_firmware_bytes),
    ) catch return error.VmFirmwareUnavailable;

    // The variable store is ephemeral: the guest writes to a copy that lives
    // and dies with the transaction, so the template the plan names is never
    // touched and a second run of the same plan starts from the same state.
    const vars_copy_path = try std.fs.path.join(
        work,
        &.{ input.transaction_path, "vm-firmware-vars.fd" },
    );
    try writeFileBytes(io, vars_copy_path, vars_bytes);
    defer cwd.deleteFile(io, vars_copy_path) catch {};

    const stage_before = try streamDigest(io, input.stage_path);

    const argv = try buildFirmwareArgv(work, .{
        .policy = input.policy,
        .firmware = input.firmware,
        .architecture = input.architecture,
        .code_path = input.firmware.code_path,
        .vars_path = vars_copy_path,
        .stage_path = input.stage_path,
    });

    const outcome = try watchForConsoleMarker(work, io, .{
        .argv = argv,
        .marker = input.firmware.console_marker,
        .timeout_seconds = input.firmware.boot_timeout_seconds,
    });
    if (!outcome.found) {
        if (input.console) |sink| {
            sink.write(switch (outcome.stop) {
                .timed_out => "firmware boot did not reach the console marker within its budget\n",
                .exited => "firmware boot ended before the console marker appeared\n",
                .overflowed => "firmware boot produced more console output than the attestation holds\n",
            });
            sink.write(outcome.console);
        }
        return switch (outcome.stop) {
            .timed_out => error.VmFirmwareBootTimedOut,
            .exited => error.VmFirmwareBootFailed,
            .overflowed => error.VmFirmwareConsoleOverflowed,
        };
    }

    const stage_after = try streamDigest(io, input.stage_path);
    if (!std.mem.eql(u8, &stage_before, &stage_after)) return error.VmFirmwareStageMutated;

    return .{
        .code_path = input.firmware.code_path,
        .code_sha256 = .{ .bytes = digestOf(code_bytes) },
        .vars_template_path = input.firmware.vars_path,
        .vars_template_sha256 = .{ .bytes = digestOf(vars_bytes) },
        .variable_store = .ephemeral,
        .secure_boot = input.firmware.secure_boot,
        .machine = firmwareMachineName(input.policy, input.firmware, input.architecture),
        .console_marker = input.firmware.console_marker,
        .boot_timeout_seconds = input.firmware.boot_timeout_seconds,
        .attested_stage_sha256 = .{ .bytes = stage_after },
    };
}

const FirmwareArgvInput = struct {
    policy: customize.VmPolicy,
    firmware: customize.VmFirmware,
    architecture: customize.Architecture,
    code_path: []const u8,
    vars_path: []const u8,
    stage_path: []const u8,
};

/// The attestation guest, which shares only the emulator with the appliance
/// guest that customized the image.
///
/// There is no `-kernel`, no `-initrd` and no `-append`: handing the firmware
/// anything to boot other than the disk would defeat the whole exercise. The
/// stage is attached as virtio-blk regardless of what the image's own kernel
/// needed for the appliance boot, because here it is the firmware that must
/// read the disk first, and both OVMF and AAVMF carry a virtio-blk driver.
fn buildFirmwareArgv(allocator: Allocator, input: FirmwareArgvInput) ![]const []const u8 {
    const policy = input.policy;
    var argv: std.array_list.Managed([]const u8) = .init(allocator);
    errdefer argv.deinit();

    try argv.appendSlice(&.{
        policy.emulator_command,
        "-no-user-config",
        "-nodefaults",
        // A firmware that finds nothing bootable resets. Letting it exit turns
        // an unbootable image into a prompt failure rather than a full budget
        // spent watching the same banner scroll past.
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

    var machine: std.array_list.Managed(u8) = .init(allocator);
    errdefer machine.deinit();
    try machine.appendSlice(firmwareMachineName(policy, input.firmware, input.architecture));
    try machine.appendSlice(",accel=");
    try machine.appendSlice(accelerationName(policy.acceleration));
    try argv.appendSlice(&.{ "-machine", try machine.toOwnedSlice() });
    try argv.appendSlice(&.{ "-cpu", cpuName(policy, input.architecture) });
    try argv.appendSlice(&.{ "-smp", try std.fmt.allocPrint(allocator, "{d}", .{policy.vcpus}) });
    try argv.appendSlice(&.{ "-m", try std.fmt.allocPrint(allocator, "{d}", .{policy.memory_mib}) });

    // Unit 0 is the code, unit 1 the variable store, in that order: EDK2 reads
    // its own layout positionally and a swapped pair simply does not boot.
    try argv.appendSlice(&.{ "-drive", try std.fmt.allocPrint(
        allocator,
        "if=pflash,format=raw,unit=0,readonly=on,file={s}",
        .{input.code_path},
    ) });
    try argv.appendSlice(&.{ "-drive", try std.fmt.allocPrint(
        allocator,
        "if=pflash,format=raw,unit=1,file={s}",
        .{input.vars_path},
    ) });
    if (input.firmware.secure_boot and input.architecture == .x86_64) {
        // Without this the variable store is writable from outside SMM and the
        // firmware's own authentication of it means nothing.
        try argv.appendSlice(&.{
            "-global", "driver=cfi.pflash01,property=secure,value=on",
            "-global", "ICH9-LPC.disable_s3=1",
        });
    }

    // `snapshot=on` is what makes the attestation read-only. The guest boots
    // and writes as it pleases; none of it reaches the file that is published.
    try argv.appendSlice(&.{ "-drive", try std.fmt.allocPrint(
        allocator,
        "file={s},format=raw,if=virtio,snapshot=on",
        .{input.stage_path},
    ) });

    // Always offline, whatever the customization's network policy was. The
    // question is whether the image boots, and an answer that depends on what
    // a network offered the guest is not an answer about the image.
    try argv.appendSlice(&.{ "-nic", "none" });
    return argv.toOwnedSlice();
}

/// Secure Boot needs SMM, which the appliance boot has no use for, so the
/// machine string differs between the two guests of the same run.
fn firmwareMachineName(
    policy: customize.VmPolicy,
    firmware: customize.VmFirmware,
    architecture: customize.Architecture,
) []const u8 {
    const base = machineName(policy, architecture);
    if (!firmware.secure_boot or architecture != .x86_64) return base;
    // An explicit machine is the caller's to get right; only the default is
    // adjusted, and silently rewriting a named one would hide the difference.
    return if (std.mem.eql(u8, base, "q35")) "q35,smm=on" else base;
}

const MarkerStop = enum { exited, timed_out, overflowed };

const MarkerOutcome = struct {
    found: bool,
    stop: MarkerStop,
    console: []const u8,
};

const MarkerInput = struct {
    argv: []const []const u8,
    marker: []const u8,
    timeout_seconds: u32,
};

/// Runs the emulator and returns as soon as the marker appears on its console,
/// or when the boot chain runs out of budget or dies.
///
/// The marker is scanned for incrementally rather than after the fact, because
/// a successful attestation must not wait for a guest that has already proven
/// itself: an image that boots to a login prompt would otherwise sit there for
/// the whole budget.
fn watchForConsoleMarker(
    allocator: Allocator,
    io: Io,
    input: MarkerInput,
) !MarkerOutcome {
    var child = try std.process.spawn(io, .{
        .argv = input.argv,
        .stdin = .ignore,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    // `kill` both terminates and reaps, and is a no-op once the child is gone,
    // so it is the only teardown every path needs. `wait` is deliberately not
    // raced against the console: a cancelled wait detaches the child handle and
    // would leave an emulator running with nothing left to kill it.
    defer child.kill(io);

    var buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var multi_reader: Io.File.MultiReader = undefined;
    multi_reader.init(
        allocator,
        io,
        buffer.toStreams(),
        &.{ child.stdout.?, child.stderr.? },
    );
    defer multi_reader.deinit();
    const console = multi_reader.reader(0);
    const errors = multi_reader.reader(1);

    // One deadline for the whole boot rather than one per read: the budget is
    // the boot chain's, not any single moment of silence within it.
    const deadline = (Io.Timeout{ .duration = .{
        .raw = .fromSeconds(input.timeout_seconds),
        .clock = .awake,
    } }).toDeadline(io);

    var scanned: usize = 0;
    var stop: MarkerStop = .exited;
    while (multi_reader.fill(4096, deadline)) |_| {
        const buffered = console.buffered();
        if (buffered.len > max_firmware_console_bytes or
            errors.buffered().len > max_firmware_console_bytes)
        {
            stop = .overflowed;
            break;
        }
        // Rescanning only the tail keeps a long boot from costing quadratic
        // time, while the overlap keeps a marker split across two reads
        // visible.
        if (std.mem.indexOf(u8, buffered[scanned..], input.marker)) |_| {
            return .{
                .found = true,
                .stop = .exited,
                .console = try ownedConsole(allocator, console, errors),
            };
        }
        scanned = buffered.len -| (input.marker.len -| 1);
    } else |err| switch (err) {
        error.EndOfStream => stop = .exited,
        error.Timeout => stop = .timed_out,
        else => |remaining| return remaining,
    }

    // The final buffer is checked once more: the marker may have arrived in
    // the same read that ended the stream.
    const found = stop != .overflowed and
        std.mem.indexOf(u8, console.buffered(), input.marker) != null;
    return .{
        .found = found,
        .stop = stop,
        .console = try ownedConsole(allocator, console, errors),
    };
}

/// The console as it will be reported, copied out of the reader's buffer
/// because that buffer dies with the reader. The emulator's own stderr is
/// appended: an image that never boots usually failed for a reason QEMU
/// stated there rather than for one the guest printed.
fn ownedConsole(
    allocator: Allocator,
    console: *Io.Reader,
    errors: *Io.Reader,
) ![]const u8 {
    const out = console.buffered();
    const err = errors.buffered();
    const combined = try allocator.alloc(u8, out.len + err.len);
    @memcpy(combined[0..out.len], out);
    @memcpy(combined[out.len..], err);
    return combined;
}

/// Digests a file without holding it in memory. The stage is the whole disk
/// image, which is routinely larger than the host's RAM.
fn streamDigest(io: Io, path: []const u8) ![32]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk: [stage_digest_chunk_bytes]u8 = undefined;
    var offset: u64 = 0;
    while (true) {
        const filled = try file.readPositionalAll(io, &chunk, offset);
        if (filled == 0) break;
        hasher.update(chunk[0..filled]);
        offset += filled;
        if (filled < chunk.len) break;
    }
    var digest: [32]u8 = undefined;
    hasher.final(&digest);
    return digest;
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
    boot: customize.VmBootRecord = .direct_kernel,
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

    // Built whole and only then published into the union, so a set tag can
    // never be read alongside a payload that is still being filled in.
    const boot_record: customize.VmBootRecord = switch (input.boot) {
        .direct_kernel => .direct_kernel,
        .firmware => |firmware| blk: {
            const record: customize.VmFirmwareRecord = .{
                .code_path = try owned.dupe(u8, firmware.code_path),
                .code_sha256 = firmware.code_sha256,
                .vars_template_path = try owned.dupe(u8, firmware.vars_template_path),
                .vars_template_sha256 = firmware.vars_template_sha256,
                .variable_store = firmware.variable_store,
                .secure_boot = firmware.secure_boot,
                .machine = try owned.dupe(u8, firmware.machine),
                .console_marker = try owned.dupe(u8, firmware.console_marker),
                .boot_timeout_seconds = firmware.boot_timeout_seconds,
                .attested_stage_sha256 = firmware.attested_stage_sha256,
            };
            break :blk .{ .firmware = record };
        },
    };

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
            .boot = boot_record,
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
    try std.testing.expectEqualStrings(
        "6.12.0-1.azl",
        control.initramfs.regenerate.kernels[0],
    );
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

test "update actions reach the guest, and an unnamed selective update does not" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();

    const control = try controlFromPolicy(
        arena.allocator(),
        std.testing.io,
        .{
            .packages = .{
                .actions = &.{ .update_all, .{ .update_selected = &.{"kernel"} } },
                .repositories = &.{.{
                    .id = "base",
                    .urls = &.{"https://packages.example.invalid"},
                    .trust = &.{.{ .inline_bytes = "test key" }},
                }},
            },
            .initramfs = .unchanged,
            .network = .declared_repositories,
            .devices = .{ .root_device = "/dev/vda2", .result_device = "/dev/vdb" },
        },
    );
    try control.validate();
    try std.testing.expectEqual(@as(usize, 2), control.actions.len);
    try std.testing.expectEqual(
        vm_control.Action.update_all,
        std.meta.activeTag(control.actions[0]),
    );
    try std.testing.expectEqualStrings("kernel", control.actions[1].update_selected[0]);

    // `update_all` is the only action whose subject is implied. A selective
    // update naming nothing would silently become a no-op in the guest.
    var empty = control;
    empty.actions = &.{.{ .update_selected = &.{} }};
    try std.testing.expectError(error.EmptyAction, empty.validate());
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

// ---- Firmware boot tests ----------------------------------------------

const test_firmware = customize.VmFirmware{
    .code_path = "/opt/qemu/share/edk2-x86_64-code.fd",
    .vars_path = "/opt/qemu/share/edk2-i386-vars.fd",
    .console_marker = "Welcome to Azure Linux",
};

fn testFirmwarePolicy(command: []const u8) customize.VmPolicy {
    return .{
        .emulator_command = command,
        .boot = .{ .firmware = test_firmware },
        .acceleration = .software,
        .acknowledge_software_emulation = true,
        .memory_mib = 3072,
        .vcpus = 4,
        .network = .declared_repositories,
    };
}

fn drivesMatching(argv: []const []const u8, needle: []const u8) usize {
    var count: usize = 0;
    for (argv, 0..) |argument, index| {
        if (index == 0 or !std.mem.eql(u8, argv[index - 1], "-drive")) continue;
        if (std.mem.indexOf(u8, argument, needle) != null) count += 1;
    }
    return count;
}

test "a firmware guest boots the disk through pflash and never a kernel" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const argv = try buildFirmwareArgv(allocator, .{
        .policy = testFirmwarePolicy("/opt/qemu/bin/qemu-system-x86_64"),
        .firmware = test_firmware,
        .architecture = .x86_64,
        .code_path = test_firmware.code_path,
        .vars_path = "work/vm-firmware-vars.fd",
        .stage_path = "work/stage.raw",
    });

    // Handing the firmware a kernel would boot the thing the attestation
    // exists to avoid booting.
    try std.testing.expect(indexOfArgument(argv, "-kernel") == null);
    try std.testing.expect(indexOfArgument(argv, "-initrd") == null);
    try std.testing.expect(indexOfArgument(argv, "-append") == null);

    try std.testing.expectEqualStrings("q35,accel=tcg", valueOfArgument(argv, "-machine").?);
    try std.testing.expectEqual(@as(usize, 1), drivesMatching(
        argv,
        "if=pflash,format=raw,unit=0,readonly=on,file=/opt/qemu/share/edk2-x86_64-code.fd",
    ));
    try std.testing.expectEqual(@as(usize, 1), drivesMatching(
        argv,
        "if=pflash,format=raw,unit=1,file=work/vm-firmware-vars.fd",
    ));
    // The overlay is what keeps the attestation read-only.
    try std.testing.expectEqual(@as(usize, 1), drivesMatching(
        argv,
        "file=work/stage.raw,format=raw,if=virtio,snapshot=on",
    ));
    // The customization asked for a network; proving the image boots must not.
    try std.testing.expectEqualStrings("none", valueOfArgument(argv, "-nic").?);
    try std.testing.expect(indexOfArgument(argv, "-netdev") == null);
}

test "an aarch64 firmware guest uses the same pflash pair on the virt machine" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var firmware = test_firmware;
    firmware.code_path = "/opt/qemu/share/edk2-aarch64-code.fd";
    firmware.vars_path = "/opt/qemu/share/edk2-arm-vars.fd";
    var policy = testFirmwarePolicy("/opt/qemu/bin/qemu-system-aarch64");
    policy.boot = .{ .firmware = firmware };

    const argv = try buildFirmwareArgv(allocator, .{
        .policy = policy,
        .firmware = firmware,
        .architecture = .aarch64,
        .code_path = firmware.code_path,
        .vars_path = "work/vm-firmware-vars.fd",
        .stage_path = "work/stage.raw",
    });

    try std.testing.expectEqualStrings("virt,accel=tcg", valueOfArgument(argv, "-machine").?);
    try std.testing.expectEqualStrings("max", valueOfArgument(argv, "-cpu").?);
    try std.testing.expectEqual(@as(usize, 1), drivesMatching(
        argv,
        "if=pflash,format=raw,unit=0,readonly=on,file=/opt/qemu/share/edk2-aarch64-code.fd",
    ));
    try std.testing.expect(indexOfArgument(argv, "-kernel") == null);
}

test "Secure Boot wires SMM on x86_64 and changes nothing on aarch64" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var firmware = test_firmware;
    firmware.secure_boot = true;
    var policy = testFirmwarePolicy("/opt/qemu/bin/qemu-system-x86_64");
    policy.boot = .{ .firmware = firmware };

    const x86 = try buildFirmwareArgv(allocator, .{
        .policy = policy,
        .firmware = firmware,
        .architecture = .x86_64,
        .code_path = firmware.code_path,
        .vars_path = "work/vars.fd",
        .stage_path = "work/stage.raw",
    });
    try std.testing.expectEqualStrings("q35,smm=on,accel=tcg", valueOfArgument(x86, "-machine").?);
    try std.testing.expectEqualStrings(
        "driver=cfi.pflash01,property=secure,value=on",
        valueOfArgument(x86, "-global").?,
    );

    const arm = try buildFirmwareArgv(allocator, .{
        .policy = policy,
        .firmware = firmware,
        .architecture = .aarch64,
        .code_path = firmware.code_path,
        .vars_path = "work/vars.fd",
        .stage_path = "work/stage.raw",
    });
    // SMM is an x86 concept; AAVMF authenticates its store without it.
    try std.testing.expectEqualStrings("virt,accel=tcg", valueOfArgument(arm, "-machine").?);
    try std.testing.expect(indexOfArgument(arm, "-global") == null);
}

test "an explicitly named machine is not rewritten for Secure Boot" {
    var firmware = test_firmware;
    firmware.secure_boot = true;
    var policy = testFirmwarePolicy("/opt/qemu/bin/qemu-system-x86_64");
    policy.boot = .{ .firmware = firmware };
    policy.machine = "pc-q35-8.2";

    try std.testing.expectEqualStrings(
        "pc-q35-8.2",
        firmwareMachineName(policy, firmware, .x86_64),
    );
}

test "the firmware guest is refused when the named EDK2 files are absent" {
    const io = std.testing.io;
    const absent = customize.VmFirmware{
        .code_path = "/nonexistent/edk2-x86_64-code.fd",
        .vars_path = "/nonexistent/edk2-i386-vars.fd",
        .console_marker = "boot",
    };
    try std.testing.expectEqual(
        customize.CapabilityState.missing,
        customize.vmFirmwareAvailable(io, absent),
    );
}

test "the console marker is found across a read boundary and ends the boot" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    // `sh` stands in for an emulator: it prints in pieces, then keeps the
    // process alive the way a booted guest sitting at a login prompt would.
    // A marker that is only recognised after the child exits would hang here.
    const outcome = try watchForConsoleMarker(allocator, std.testing.io, .{
        .argv = &.{
            "/bin/sh",
            "-c",
            "printf 'Welcome to '; sleep 1; printf 'Azure Linux 3.0\\n'; sleep 300",
        },
        .marker = "Welcome to Azure Linux",
        .timeout_seconds = 60,
    });
    try std.testing.expect(outcome.found);
    try std.testing.expect(std.mem.indexOf(u8, outcome.console, "Azure Linux 3.0") != null);
}

test "a boot chain that dies before the marker is reported as a failure" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const outcome = try watchForConsoleMarker(allocator, std.testing.io, .{
        .argv = &.{
            "/bin/sh",
            "-c",
            "printf 'BdsDxe: failed to load Boot0001\\n' >&2; exit 1",
        },
        .marker = "Welcome to Azure Linux",
        .timeout_seconds = 60,
    });
    try std.testing.expect(!outcome.found);
    try std.testing.expectEqual(MarkerStop.exited, outcome.stop);
    // The reason a firmware gives is on stderr, and attribution depends on it
    // surviving into the recorded console.
    try std.testing.expect(std.mem.indexOf(u8, outcome.console, "failed to load Boot0001") != null);
}

test "a boot that never says anything exhausts its own budget" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const outcome = try watchForConsoleMarker(allocator, std.testing.io, .{
        .argv = &.{ "/bin/sh", "-c", "printf 'UEFI firmware\\n'; sleep 300" },
        .marker = "Welcome to Azure Linux",
        .timeout_seconds = 1,
    });
    try std.testing.expect(!outcome.found);
    try std.testing.expectEqual(MarkerStop.timed_out, outcome.stop);
    try std.testing.expect(std.mem.indexOf(u8, outcome.console, "UEFI firmware") != null);
}

test "digesting a stage is independent of how many reads it takes" {
    const io = std.testing.io;
    const cwd = Io.Dir.cwd();
    const path = "test-vm-backend-stage-digest.raw";
    defer cwd.deleteFile(io, path) catch {};

    const bytes = try std.testing.allocator.alloc(u8, stage_digest_chunk_bytes + 4096);
    defer std.testing.allocator.free(bytes);
    for (bytes, 0..) |*byte, index| byte.* = @truncate(index);
    try writeFileBytes(io, path, bytes);

    try std.testing.expectEqual(digestOf(bytes), try streamDigest(io, path));
}

// `vm_control` deliberately imports nothing but `std`, so it cannot name the
// `os_customization` constants it must agree with. This module is the one
// place that imports both, which makes it the only place the two can be held
// together. Without this, a renamed destination would leave the vm backend
// writing somewhere the rebuild backend does not, and both would look right.
test "the guest's accepted destinations are exactly what the host renders" {
    const rendered = [_][]const u8{
        os_customization.modules_load_path,
        os_customization.modprobe_blacklist_path,
        os_customization.modprobe_options_path,
    };
    try std.testing.expectEqual(
        vm_control.kernel_module_config_paths.len,
        rendered.len,
    );
    for (rendered, vm_control.kernel_module_config_paths) |host, guest| {
        try std.testing.expectEqualStrings(host, guest);
    }
}

test "rendered kernel-module configuration reaches the control document" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const modules = [_]customize.KernelModule{
        .{ .name = "overlay", .load = true },
        .{ .name = "floppy", .disabled = true },
    };
    const control = try controlFromPolicy(allocator, std.testing.io, .{
        .packages = .{},
        .initramfs = .unchanged,
        .network = .offline,
        .devices = .{
            .root_device = "/dev/vda2",
            .result_device = "/dev/vdb",
        },
        .kernel_modules = &modules,
    });
    // The guest is the one that validates, so the host's rendering has to
    // survive that check rather than merely look plausible.
    try control.validate();

    try std.testing.expectEqual(@as(usize, 2), control.kernel_module_files.len);
    try std.testing.expectEqualStrings(
        os_customization.modules_load_path,
        control.kernel_module_files[0].path,
    );
    try std.testing.expectEqualStrings("overlay\n", control.kernel_module_files[0].contents);
    try std.testing.expectEqualStrings(
        os_customization.modprobe_blacklist_path,
        control.kernel_module_files[1].path,
    );
    try std.testing.expectEqualStrings(
        "blacklist floppy\n",
        control.kernel_module_files[1].contents,
    );

    // Asking for nothing plants nothing: an image that had no `modprobe.d`
    // configuration should not come back carrying empty files.
    const empty = try controlFromPolicy(allocator, std.testing.io, .{
        .packages = .{},
        .initramfs = .unchanged,
        .network = .offline,
        .devices = .{
            .root_device = "/dev/vda2",
            .result_device = "/dev/vdb",
        },
    });
    try std.testing.expectEqual(@as(usize, 0), empty.kernel_module_files.len);
}
