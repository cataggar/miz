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
/// Stand-ins for the EDK2 pair. Their only job is to be distinct, non-empty
/// files whose digests provenance can be checked against.
const firmware_code_bytes = "integration-edk2-code\n";
const firmware_vars_bytes = "integration-edk2-vars-template\n";

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
    /// Customizes as `success` does, then, in the attestation invocation the
    /// backend makes afterwards, prints the console marker the way an image
    /// whose own boot chain came up would.
    firmware_success,
    /// Customizes as `success` does, then fails the attestation the way an
    /// image with a broken bootloader configuration does: the firmware says
    /// so on stderr and gives up.
    firmware_unbootable,
    /// Runs every hook the control document carries but reports one fewer
    /// than it was given, as a guest that quietly skipped one would. The host
    /// is required to refuse it rather than publish an image whose provenance
    /// would claim work that may not have happened.
    dropped_hook,
};

/// The scripts the hook cases declare. Distinct bytes, so the digests
/// provenance publishes can be checked against something other than each
/// other.
const hook_scripts = [_][]const u8{
    "#!/bin/sh\necho integration hook after packages\n",
    "#!/bin/sh\necho integration hook at finalize\n",
};

/// What the stand-in image prints once its own boot chain has control. Real
/// plans name whatever their image says; the value only has to be something
/// nothing else on the console would produce by accident.
const console_marker = "zvmi-integration-guest is up";

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

    // Both transports, because which one a run gets is decided by the image
    // and getting it wrong is a root device that never appears. Both driver
    // shapes, because an image that ships its drivers rather than building
    // them in is the one this backend used to refuse outright.
    try runSuccess(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    try runSuccess(allocator, io, self_exe, architecture, .virtio_scsi, .built_in);
    try runSuccess(allocator, io, self_exe, architecture, .virtio_blk, .modular);
    try runSuccess(allocator, io, self_exe, architecture, .virtio_scsi, .modular);
    try runGuestFailure(allocator, io, self_exe, architecture);
    try runSilentGuest(allocator, io, self_exe, architecture);
    try runEmulatorFailure(allocator, io, self_exe, architecture);
    try runHardwareRejected(allocator, io, self_exe, architecture);
    try runFirmwareBootMatchesDirectKernel(allocator, io, self_exe, architecture);
    try runFirmwareUnbootable(allocator, io, self_exe, architecture);
    try runFirmwareMissing(allocator, io, self_exe, architecture);
    try runHooksReachTheGuest(allocator, io, self_exe, architecture);
    try runDroppedHookRefused(allocator, io, self_exe, architecture);
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
    transport: zvmi.vm_payload.DiskTransport,
    drivers: Drivers,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, transport, drivers);
    defer workspace.deinit(io);

    var outcome = try workspace.execute(allocator, io, .success, .software);
    defer outcome.deinit(allocator);

    const result = outcome.result orelse return error.ExecutionProducedNoResult;
    if (outcome.diagnostics.hasErrors()) return error.ExecutionReportedErrors;
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .cleanup_failed) return error.CleanupFailed;
    }

    try ensure(result.provenance.schema_version == zvmi.customize.provenance_schema_version);
    const vm = result.provenance.execution.vm orelse
        return error.MissingVmProvenance;
    try ensure(std.mem.eql(u8, vm.emulator_command, workspace.emulator_path));
    try ensure(std.mem.eql(u8, vm.emulator_version, "stub-emulator 1.0"));
    try ensure(vm.acceleration == .software);
    try ensure(vm.network == .declared_repositories);
    try ensure(std.mem.eql(u8, vm.root_device, switch (transport) {
        .virtio_blk => "/dev/vda1",
        .virtio_scsi => "/dev/sda1",
    }));
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

    // A run that had to load drivers is a materially different run, and an
    // empty list says the image's kernel needed no help.
    switch (drivers) {
        .built_in => try ensure(vm.modules.len == 0),
        .modular => {
            const expected = expectedModules(transport);
            try ensure(vm.modules.len == expected.len);
            for (expected, vm.modules) |name, module| {
                try ensure(std.mem.eql(u8, module.name, name));
                // The file inside the image, not merely the driver it
                // provides: the record can be checked against the source.
                try ensure(std.mem.startsWith(
                    u8,
                    module.image_path,
                    "lib/modules/" ++ kernel_release ++ "/kernel/",
                ));
                const basename = std.fs.path.basename(module.image_path);
                try ensure(std.mem.eql(u8, std.fs.path.stem(basename), name));
                const object = try moduleObject(allocator, name);
                defer allocator.free(object);
                try ensure(std.mem.eql(u8, &module.sha256.bytes, &sha256(object)));
            }
        },
    }

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
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    defer workspace.deinit(io);

    var outcome = try workspace.execute(allocator, io, .guest_failure, .software);
    defer outcome.deinit(allocator);

    try expectFailedRun(io, &workspace, &outcome);
    workspace.completed = true;
}

fn runHooksReachTheGuest(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    defer workspace.deinit(io);

    const hooks = [_]zvmi.customize.Hook{
        .{
            .name = "after-packages",
            .phase = .after_packages,
            .source = .{ .inline_script = hook_scripts[0] },
            .arguments = &.{"--check"},
        },
        .{
            .name = "at-finalize",
            .phase = .finalize,
            .source = .{ .inline_script = hook_scripts[1] },
        },
    };
    workspace.hooks = &hooks;

    var outcome = try workspace.execute(allocator, io, .success, .software);
    defer outcome.deinit(allocator);

    const result = outcome.result orelse return error.ExecutionProducedNoResult;
    if (outcome.diagnostics.hasErrors()) return error.ExecutionReportedErrors;

    // The stand-in already checked the scripts arrived intact. What this side
    // checks is that provenance says the same thing the chroot backend's
    // does: the hook by name, phase, digest and exit code.
    const preserved = result.provenance.execution.preserved orelse
        return error.MissingPreservedProvenance;
    try ensure(preserved.hooks.len == hooks.len);
    for (preserved.hooks, hooks, hook_scripts) |record, hook, script| {
        try ensure(std.mem.eql(u8, record.name, hook.name));
        try ensure(record.phase == hook.phase);
        try ensure(record.exit_code == 0);
        var digest: [32]u8 = undefined;
        std.crypto.hash.sha2.Sha256.hash(script, &digest, .{});
        try ensure(std.mem.eql(u8, &record.source_sha256.bytes, &digest));
    }

    workspace.completed = true;
}

fn runDroppedHookRefused(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    defer workspace.deinit(io);

    const hooks = [_]zvmi.customize.Hook{
        .{
            .name = "after-packages",
            .phase = .after_packages,
            .source = .{ .inline_script = hook_scripts[0] },
        },
        .{
            .name = "at-finalize",
            .phase = .finalize,
            .source = .{ .inline_script = hook_scripts[1] },
        },
    };
    workspace.hooks = &hooks;

    // A guest that reports fewer hooks than it was given is the failure #302
    // shipped, seen from the other side. The run fails and publishes nothing,
    // rather than producing an image whose provenance describes two hooks.
    var outcome = try workspace.execute(allocator, io, .dropped_hook, .software);
    defer outcome.deinit(allocator);
    // The refusal names the hook that went unaccounted for, so the failure
    // cannot be mistaken for an unrelated guest fault.
    var named = false;
    for (outcome.diagnostics.items) |diagnostic| {
        const cause = diagnostic.cause orelse continue;
        if (std.mem.eql(u8, cause.error_name, "UnexecutedHook")) named = true;
    }
    try ensure(named);

    try expectFailedRun(io, &workspace, &outcome);
    workspace.completed = true;
}

fn runSilentGuest(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
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
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
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
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
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

/// The point of the acceptance criterion: the same plan through a firmware
/// boot must publish the same bytes it publishes through a direct-kernel
/// boot. It holds by construction — the firmware boot is the same appliance
/// customization followed by a read-only attestation — and this is where that
/// construction is checked rather than asserted.
fn runFirmwareBootMatchesDirectKernel(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    defer workspace.deinit(io);
    try workspace.installFirmware(allocator, io);

    var direct = try workspace.execute(allocator, io, .success, .software);
    defer direct.deinit(allocator);
    if (direct.result == null) return error.DirectKernelRunProducedNoResult;
    const direct_digest = try digestOfFile(io, workspace.output_path);
    try ensure(direct.result.?.provenance.execution.vm.?.boot == .direct_kernel);
    try Io.Dir.cwd().deleteFile(io, workspace.output_path);

    workspace.firmware_boot = true;
    var attested = try workspace.execute(allocator, io, .firmware_success, .software);
    defer attested.deinit(allocator);
    if (attested.result == null) return error.FirmwareRunProducedNoResult;
    if (attested.diagnostics.hasErrors()) return error.FirmwareRunReportedErrors;

    // Byte-identical, not merely equivalent: the boot mode is an attestation,
    // never a semantic difference in the published image.
    try ensure(std.mem.eql(u8, &direct_digest, &try digestOfFile(io, workspace.output_path)));

    const result = attested.result.?;
    try ensure(result.provenance.schema_version == zvmi.customize.provenance_schema_version);
    const vm = result.provenance.execution.vm orelse return error.MissingVmProvenance;
    // The two modes are distinguishable in provenance, which is the whole
    // reason the record is a union rather than a flag.
    const firmware = switch (vm.boot) {
        .direct_kernel => return error.FirmwareRunRecordedAsDirectKernel,
        .firmware => |record| record,
    };
    try ensure(std.mem.eql(u8, firmware.code_path, workspace.firmware_code_path));
    try ensure(std.mem.eql(u8, &firmware.code_sha256.bytes, &sha256(firmware_code_bytes)));
    try ensure(std.mem.eql(u8, firmware.vars_template_path, workspace.firmware_vars_path));
    try ensure(std.mem.eql(u8, &firmware.vars_template_sha256.bytes, &sha256(firmware_vars_bytes)));
    try ensure(firmware.variable_store == .ephemeral);
    try ensure(!firmware.secure_boot);
    try ensure(std.mem.eql(u8, firmware.console_marker, console_marker));
    try ensure(firmware.boot_timeout_seconds == 120);
    // What was attested is what was published.
    try ensure(std.mem.eql(u8, &firmware.attested_stage_sha256.bytes, &direct_digest));

    // The variable store is ephemeral: the stand-in firmware writes to the
    // store it is given, and the template the plan names is still the
    // template afterwards.
    try ensure(std.mem.eql(
        u8,
        &try digestOfFile(io, workspace.firmware_vars_path),
        &sha256(firmware_vars_bytes),
    ));

    try expectPathAbsent(io, workspace.transaction_path);
    try expectFileExists(io, workspace.output_path);
    try expectSourceUnchanged(io, &workspace);
    workspace.completed = true;
}

/// An image whose boot chain never comes up fails the run outright, and the
/// firmware's own account of why is on the console the caller was given.
fn runFirmwareUnbootable(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    defer workspace.deinit(io);
    try workspace.installFirmware(allocator, io);
    workspace.firmware_boot = true;

    var console: std.array_list.Managed(u8) = .init(allocator);
    defer console.deinit();
    captured_console = &console;
    defer captured_console = null;

    var outcome = try workspace.execute(allocator, io, .firmware_unbootable, .software);
    defer outcome.deinit(allocator);

    try expectFailedRun(io, &workspace, &outcome);
    // Attributable: the recorded console names the boot entry that failed, so
    // the failure is diagnosable without re-running the boot.
    try ensure(std.mem.indexOf(u8, console.items, "failed to load Boot0001") != null);
    workspace.completed = true;
}

/// Firmware that is not on this host is a refusal in preflight, before
/// anything is copied, and never a quiet direct-kernel boot in its place.
fn runFirmwareMissing(
    allocator: Allocator,
    io: Io,
    self_exe: []const u8,
    architecture: zvmi.customize.Architecture,
) !void {
    var workspace = try Workspace.create(allocator, io, self_exe, architecture, .virtio_blk, .built_in);
    defer workspace.deinit(io);
    try workspace.installFirmware(allocator, io);
    workspace.firmware_boot = true;
    try Io.Dir.cwd().deleteFile(io, workspace.firmware_code_path);

    var resolved = try workspace.resolve(allocator, .software);
    defer resolved.deinit(allocator);
    const plan = &(resolved.plan orelse return error.ResolutionProducedNoPlan);
    try workspace.rememberTransaction(plan);

    var platform = zvmi.customize.Platform.system();
    platform.vmCheckFn = checkVm;
    platform.vmRunFn = runVm;
    var report = try zvmi.customize.preflight(allocator, io, plan, platform);
    defer report.deinit(allocator);
    if (report.ready()) return error.MissingFirmwareWasNotRefused;

    // The refusal names the firmware requirement rather than the backend, so
    // an operator is told what to install.
    var named = false;
    for (report.capabilities) |check| {
        if (check.requirement.kind == .vm_firmware and check.state != .available) {
            named = true;
            try ensure(std.mem.eql(u8, check.requirement.path, workspace.firmware_code_path));
        }
    }
    try ensure(named);

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
    transport: zvmi.vm_payload.DiskTransport,
    drivers: Drivers,
    source_digest: [32]u8,
    /// The EDK2 stand-ins, written into the workspace so the plan can name
    /// absolute paths that exist without depending on what this host has
    /// installed. Empty until `installFirmware` runs.
    firmware_code_path: []const u8 = "",
    firmware_vars_path: []const u8 = "",
    /// Selects the boot mode the next `resolve` asks for.
    firmware_boot: bool = false,
    /// Hooks the next `resolve` declares. Empty for every case that is not
    /// about them, so the script channel is exercised where it is the subject
    /// rather than added to the baseline every other assertion is made
    /// against.
    hooks: []const zvmi.customize.Hook = &.{},
    /// Set by a case that reached its last assertion. A workspace is only
    /// removed once that happens, so a failure leaves its source, its output,
    /// and its transaction exactly as they were for inspection.
    completed: bool = false,

    fn create(
        allocator: Allocator,
        io: Io,
        self_exe: []const u8,
        architecture: zvmi.customize.Architecture,
        transport: zvmi.vm_payload.DiskTransport,
        drivers: Drivers,
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

        try createSourceDisk(allocator, io, source_path, spool_path, transport, drivers);
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
            .transport = transport,
            .drivers = drivers,
            .source_digest = try digestOfFile(io, source_path),
        };
    }

    fn installFirmware(self: *Workspace, allocator: Allocator, io: Io) !void {
        self.firmware_code_path = try std.fs.path.join(
            allocator,
            &.{ self.path, "edk2-code.fd" },
        );
        self.firmware_vars_path = try std.fs.path.join(
            allocator,
            &.{ self.path, "edk2-vars.fd" },
        );
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = self.firmware_code_path,
            .data = firmware_code_bytes,
        });
        try Io.Dir.cwd().writeFile(io, .{
            .sub_path = self.firmware_vars_path,
            .data = firmware_vars_bytes,
        });
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
            .hooks = self.hooks,
            .execution = .{
                .workspace_path = self.path,
                .backend = .vm,
                .acknowledge_unsafe = self.hooks.len != 0,
                .vm = .{
                    .emulator_command = self.emulator_path,
                    .boot = if (self.firmware_boot) .{ .firmware = .{
                        .code_path = self.firmware_code_path,
                        .vars_path = self.firmware_vars_path,
                        .console_marker = console_marker,
                        .boot_timeout_seconds = 120,
                    } } else .direct_kernel,
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
        .console = if (captured_console == null) null else .{ .writeFn = captureConsole },
    });
}

/// Where a failing run's console goes while a case is watching for it. The
/// backend hands the console to a sink rather than a writer, so the case that
/// wants it installs one for the duration.
var captured_console: ?*std.array_list.Managed(u8) = null;

fn captureConsole(_: ?*anyopaque, bytes: []const u8) void {
    const sink = captured_console orelse return;
    sink.appendSlice(bytes) catch {};
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

    // The attestation invocation is the one with nothing to boot but the
    // disk. Distinguishing on `-kernel` rather than on a flag is deliberate:
    // it is the property the whole design turns on.
    if (valueAfter(args, "-kernel") == null) {
        return runStubFirmware(io, mode, args);
    }

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
    var members: std.StringHashMapUnmanaged([]const u8) = .empty;
    var reader = zvmi.cpio.Reader.init(initrd);
    while (try reader.next()) |entry| {
        try members.put(allocator, entry.path, entry.content);
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
    const scsi = indexOfArgument(args, "virtio-scsi-pci,id=zvmiscsi") != null;
    try expectStub(std.mem.eql(
        u8,
        control.root_device,
        if (scsi) "/dev/sda1" else "/dev/vda1",
    ));
    try expectStub(std.mem.eql(
        u8,
        control.result_device,
        if (scsi) "/dev/sdb" else "/dev/vdb",
    ));
    try expectStub(control.repositories.len == 1);
    try expectStub(std.mem.eql(u8, control.repositories[0].id, "integration"));
    try expectStub(control.repositories[0].trust_base64.len == 1);
    try expectStub(control.actions.len == 1);
    try expectStub(control.initramfs == .regenerate);
    try expectStub(control.initramfs.regenerate.kernels.len == 1);
    try expectStub(std.mem.eql(u8, control.initramfs.regenerate.kernels[0], kernel_release));
    try expectStub(control.network == .declared_repositories);

    // A module the document names but the initramfs does not carry is a guest
    // that fails at `load-modules`, so the stand-in opens each of them the way
    // the agent would -- and checks the bytes are an object, since the host
    // promises to have decompressed them.
    for (control.modules, 0..) |member, index| {
        const bytes = members.get(member) orelse return error.MissingModuleMember;
        try expectStub(std.mem.startsWith(u8, bytes, "\x7fELF"));
        // The member name carries its own position, so an identical run
        // produces an identical initramfs and the insertion order the host
        // resolved is legible in the payload rather than only in the document.
        var prefix: [32]u8 = undefined;
        try expectStub(std.mem.startsWith(
            u8,
            member,
            try std.fmt.bufPrint(&prefix, "zvmi-module-{d:0>2}-", .{index}),
        ));
    }

    // A hook is the one field a caller fills with code. The stand-in honours
    // exactly what a real guest does with it: decode the script, check it
    // names its own interpreter, and account for every one of them.
    const hook_outcomes = try allocator.alloc(
        zvmi.vm_control.HookOutcome,
        control.hooks.len,
    );
    for (control.hooks, hook_outcomes, 0..) |hook, *outcome, index| {
        const size = try zvmi.vm_control.hookScriptSize(hook);
        const script = try allocator.alloc(u8, size);
        try zvmi.vm_control.decodeHookScript(hook, script);
        try expectStub(std.mem.startsWith(u8, script, "#!"));
        try expectStub(std.mem.eql(u8, script, hook_scripts[index]));
        outcome.* = .{ .index = @intCast(index), .exit_code = 0 };
    }

    // Which drive is which is positional, so the result must be written
    // through the same ordering the guest would see.
    const result_path = driveAt(args, 1) orelse return error.MissingResultDrive;
    const stage_path = driveAt(args, 0) orelse return error.MissingStageDrive;
    try expectStub(!std.mem.eql(u8, stage_path, result_path));
    if (mode == .silent) return;

    const reported = if (mode == .dropped_hook)
        hook_outcomes[0 .. hook_outcomes.len - 1]
    else
        hook_outcomes;

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
            .hooks = reported,
        },
    };
    const sealed = try zvmi.vm_control.seal(allocator, result);
    defer allocator.free(sealed);

    const file = try Io.Dir.cwd().openFile(io, result_path, .{ .mode = .write_only });
    defer file.close(io);
    try file.writePositionalAll(io, sealed, 0);
}

/// The stand-in firmware. It checks that it was handed exactly the shape of
/// guest a firmware boot means — its own code and a writable variable store on
/// pflash, the stage behind a snapshot overlay, and nothing to boot from but
/// the disk — and then speaks, or fails to, on the console.
fn runStubFirmware(io: Io, mode: StubMode, args: []const []const u8) !void {
    try expectStub(valueAfter(args, "-initrd") == null);
    try expectStub(valueAfter(args, "-append") == null);
    try expectStub(std.mem.eql(u8, valueAfter(args, "-nic") orelse "", "none"));

    var code: ?[]const u8 = null;
    var vars: ?[]const u8 = null;
    var stage: ?[]const u8 = null;
    for (args, 0..) |arg, index| {
        if (!std.mem.eql(u8, arg, "-drive") or index + 1 >= args.len) continue;
        const value = args[index + 1];
        if (std.mem.indexOf(u8, value, "if=pflash") != null) {
            if (std.mem.indexOf(u8, value, "unit=0") != null) {
                try expectStub(std.mem.indexOf(u8, value, "readonly=on") != null);
                code = drivePath(value);
            } else if (std.mem.indexOf(u8, value, "unit=1") != null) {
                try expectStub(std.mem.indexOf(u8, value, "readonly=on") == null);
                vars = drivePath(value);
            }
        } else if (std.mem.indexOf(u8, value, "if=virtio") != null) {
            // The overlay is what makes the attestation read-only, so a stage
            // without it is a contract violation rather than a slow path.
            try expectStub(std.mem.indexOf(u8, value, "snapshot=on") != null);
            stage = drivePath(value);
        }
    }
    const code_path = code orelse return error.MissingFirmwareCodeDrive;
    const vars_path = vars orelse return error.MissingFirmwareVarsDrive;
    _ = stage orelse return error.MissingStageDrive;

    const code_bytes = try Io.Dir.cwd().readFileAlloc(
        io,
        code_path,
        std.heap.page_allocator,
        .limited(1024),
    );
    defer std.heap.page_allocator.free(code_bytes);
    try expectStub(std.mem.eql(u8, code_bytes, firmware_code_bytes));

    // A firmware writes to its variable store. Doing so here proves the store
    // is the per-run copy rather than the template the plan named: the case
    // checks the template afterwards.
    const store = try Io.Dir.cwd().openFile(io, vars_path, .{ .mode = .write_only });
    defer store.close(io);
    try store.writePositionalAll(io, "Boot0001", 0);

    if (mode == .firmware_unbootable) {
        var stderr_buffer: [256]u8 = undefined;
        var stderr = Io.File.stderr().writer(io, &stderr_buffer);
        try stderr.interface.writeAll(
            "BdsDxe: failed to load Boot0001 \"UEFI Misc Device\": Not Found\n",
        );
        try stderr.interface.flush();
        return error.StubFirmwareFoundNothingBootable;
    }

    var stdout_buffer: [256]u8 = undefined;
    var stdout = Io.File.stdout().writer(io, &stdout_buffer);
    try stdout.interface.writeAll("UEFI firmware, stand-in build\n");
    try stdout.interface.writeAll(console_marker ++ "\n");
    try stdout.interface.flush();
}

fn drivePath(value: []const u8) ?[]const u8 {
    const marker = "file=";
    const start = std.mem.indexOf(u8, value, marker) orelse return null;
    const rest = value[start + marker.len ..];
    const end = std.mem.indexOfScalar(u8, rest, ',') orelse rest.len;
    return rest[0..end];
}

fn indexOfArgument(args: []const []const u8, wanted: []const u8) ?usize {
    for (args, 0..) |arg, index| {
        if (std.mem.eql(u8, arg, wanted)) return index;
    }
    return null;
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
    transport: zvmi.vm_payload.DiskTransport,
    drivers: Drivers,
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
    inline for (.{
        "boot", "dev",         "etc",                            "lib",
        "proc", "run",         "sys",                            "usr",
        "var",  "lib/modules", "lib/modules/" ++ kernel_release,
    }) |path| {
        try tree.putDirectory(path, .{ .mode = 0o755 });
    }
    // The transport the backend picks is a fact about the image's kernel, so
    // the fixture states it the same way a real image does -- including the
    // PCI bus the devices hang off, and the SCSI disk driver without which a
    // virtio-scsi controller presents no `/dev/sda`.
    try tree.putFileBytes(
        "lib/modules/" ++ kernel_release ++ "/modules.builtin",
        switch (drivers) {
            // A cloud kernel that builds nothing this run needs in: its
            // drivers are all in the tree, and the run has to load them.
            .modular => "kernel/fs/xfs/xfs.ko\n",
            .built_in => switch (transport) {
                .virtio_blk =>
                \\kernel/fs/ext4/ext4.ko
                \\kernel/drivers/virtio/virtio_pci.ko
                \\kernel/drivers/block/virtio_blk.ko
                \\kernel/drivers/net/virtio_net.ko
                \\
                ,
                .virtio_scsi =>
                \\kernel/fs/ext4/ext4.ko
                \\kernel/drivers/virtio/virtio_pci.ko
                \\kernel/drivers/scsi/scsi_mod.ko
                \\kernel/drivers/scsi/sd_mod.ko
                \\kernel/drivers/scsi/virtio_scsi.ko
                \\kernel/drivers/net/virtio_net.ko
                \\
                ,
            },
        },
        .{ .mode = 0o644 },
    );
    if (drivers == .modular) try writeModuleTree(allocator, &tree, transport);
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

/// Whether the fixture image's kernel builds its drivers in or ships them in
/// its own module tree. Both are real cloud images; only the first used to be
/// something this backend could boot.
const Drivers = enum { built_in, modular };

const modular_dep_virtio_blk =
    \\kernel/drivers/virtio/virtio_pci.ko:
    \\kernel/drivers/block/virtio_blk.ko:
    \\kernel/fs/jbd2/jbd2.ko:
    \\kernel/fs/ext4/ext4.ko: kernel/fs/jbd2/jbd2.ko
    \\kernel/drivers/net/virtio_net.ko:
    \\
;

/// The same kernel with no virtio-blk at all, so the disks arrive over SCSI.
const modular_dep_virtio_scsi =
    \\kernel/drivers/virtio/virtio_pci.ko:
    \\kernel/drivers/scsi/scsi_mod.ko:
    \\kernel/drivers/scsi/sd_mod.ko: kernel/drivers/scsi/scsi_mod.ko
    \\kernel/drivers/scsi/virtio_scsi.ko: kernel/drivers/scsi/scsi_mod.ko
    \\kernel/fs/jbd2/jbd2.ko:
    \\kernel/fs/ext4/ext4.ko: kernel/fs/jbd2/jbd2.ko
    \\kernel/drivers/net/virtio_net.ko:
    \\
;

/// The names the backend must insert, in the order it must insert them: the
/// bus before the disk, the disk before the filesystem it carries, and every
/// dependency before what needs it.
fn expectedModules(transport: zvmi.vm_payload.DiskTransport) []const []const u8 {
    return switch (transport) {
        .virtio_blk => &.{ "virtio_pci", "virtio_blk", "jbd2", "ext4", "virtio_net" },
        .virtio_scsi => &.{
            "virtio_pci",
            "scsi_mod",
            "virtio_scsi",
            "sd_mod",
            "jbd2",
            "ext4",
            "virtio_net",
        },
    };
}

/// Enough of an ELF header that the host accepts the file as an object, and
/// distinct per module so the initramfs member, the digest in provenance and
/// the file in the image can be shown to be the same bytes.
fn moduleObject(allocator: Allocator, name: []const u8) ![]u8 {
    return std.fmt.allocPrint(allocator, "\x7fELF\x02\x01\x01\x00integration:{s}", .{name});
}

fn writeModuleTree(
    allocator: Allocator,
    tree: *zvmi.root_tree.RootTree,
    transport: zvmi.vm_payload.DiskTransport,
) !void {
    const prefix = "lib/modules/" ++ kernel_release;
    const dep = switch (transport) {
        .virtio_blk => modular_dep_virtio_blk,
        .virtio_scsi => modular_dep_virtio_scsi,
    };
    try tree.putFileBytes(prefix ++ "/modules.dep", dep, .{ .mode = 0o644 });
    inline for (.{
        "/kernel",               "/kernel/drivers",      "/kernel/drivers/virtio",
        "/kernel/drivers/block", "/kernel/drivers/scsi", "/kernel/drivers/net",
        "/kernel/fs",            "/kernel/fs/ext4",      "/kernel/fs/jbd2",
    }) |directory| {
        try tree.putDirectory(prefix ++ directory, .{ .mode = 0o755 });
    }

    // Every path the dependency file names, and nothing else: a tree that
    // describes a module it does not hold is a refusal, not a boot.
    var lines = std.mem.tokenizeScalar(u8, dep, '\n');
    while (lines.next()) |line| {
        const module_path = line[0 .. std.mem.indexOfScalar(u8, line, ':') orelse continue];
        const name = std.fs.path.stem(std.fs.path.basename(module_path));
        const object = try moduleObject(allocator, name);
        defer allocator.free(object);
        const full = try std.fs.path.join(allocator, &.{ prefix, module_path });
        defer allocator.free(full);
        try tree.putFileBytes(full, object, .{ .mode = 0o644 });
    }
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
