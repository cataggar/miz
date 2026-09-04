//! Opt-in same-architecture QEMU acceptance for finalized Ubuntu 26.04 images.
//!
//! The selected build options and `MIZ_UBUNTU2604_IMAGE` must agree on one
//! full or core candidate. x86_64 is pinned to KVM; AArch64 is pinned to
//! multi-threaded TCG on a native Arm64 host. Neither path probes or falls back
//! to another accelerator.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const qemu_host = @import("qemu_host");
const qmp = @import("qmp");
const miz = @import("miz");
const release = @import("ubuntu2604_release");

// The acceptance harness and the release tooling must agree on the execution
// profile, the size-inventory schema, and the runtime contract, so they are
// taken from the one module that defines them rather than re-imported as
// separate copies of the same files.
const execution = release.execution;
const runtime_contract = release.runtime_contract;
const runtime_contract_document = release.runtime_contract_document;
const size_inventory = release.size_inventory;

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const admin_username = "miztest";
const serial_limit: usize = 2 * 1024 * 1024;
const mib: u64 = 1024 * 1024;
const gib: u64 = 1024 * mib;

const ExpectedPartitionGeometry = struct {
    table_index: u32,
    first_lba: u64,
    last_lba: u64,
};

const PartitionPolicy = struct {
    root_first_lba: u64,
    xbootldr: ?ExpectedPartitionGeometry,
    bios_boot: ?ExpectedPartitionGeometry,
    esp: ExpectedPartitionGeometry,

    fn partitionCount(self: PartitionPolicy) usize {
        var count: usize = 2;
        if (self.xbootldr != null) count += 1;
        if (self.bios_boot != null) count += 1;
        return count;
    }
};

const Architecture = enum {
    x86_64,
    aarch64,

    fn guestArchitecture(self: Architecture) qemu_host.GuestArchitecture {
        return switch (self) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        };
    }

    fn rootGuid(self: Architecture) miz.guid.Guid {
        return switch (self) {
            .x86_64 => miz.guid.linux_root_x86_64,
            .aarch64 => miz.guid.linux_root_aarch64,
        };
    }

    fn partitionPolicy(self: Architecture) PartitionPolicy {
        return switch (self) {
            .x86_64 => .{
                .root_first_lba = 2_324_480,
                .xbootldr = .{
                    .table_index = 12,
                    .first_lba = 2_048,
                    .last_lba = 2_097_152,
                },
                .bios_boot = .{
                    .table_index = 13,
                    .first_lba = 2_099_200,
                    .last_lba = 2_107_391,
                },
                .esp = .{
                    .table_index = 14,
                    .first_lba = 2_107_392,
                    .last_lba = 2_324_479,
                },
            },
            .aarch64 => .{
                .root_first_lba = 2_099_200,
                .xbootldr = null,
                .bios_boot = null,
                .esp = .{
                    .table_index = 14,
                    .first_lba = 2_048,
                    .last_lba = 1_050_623,
                },
            },
        };
    }

    fn ukiMachine(self: Architecture) u16 {
        return switch (self) {
            .x86_64 => 0x8664,
            .aarch64 => 0xaa64,
        };
    }

    fn fallbackUkiPath(self: Architecture) []const u8 {
        return switch (self) {
            .x86_64 => "EFI/BOOT/BOOTX64.EFI",
            .aarch64 => "EFI/BOOT/BOOTAA64.EFI",
        };
    }

    fn serialConsole(self: Architecture) []const u8 {
        return switch (self) {
            .x86_64 => "console=ttyS0,115200n8",
            .aarch64 => "console=ttyAMA0,115200n8",
        };
    }

    fn machineArg(self: Architecture, secure_boot: bool) []const u8 {
        return switch (self) {
            .x86_64 => if (secure_boot)
                "q35,accel=kvm,smm=on"
            else
                "q35,accel=kvm,smm=off",
            .aarch64 => "virt",
        };
    }

    fn runnerCpu(self: Architecture) std.Target.Cpu.Arch {
        return switch (self) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        };
    }

    fn tpmDevice(self: Architecture) []const u8 {
        return switch (self) {
            .x86_64 => "tpm-crb,tpmdev=tpm0",
            .aarch64 => "tpm-tis-device,tpmdev=tpm0",
        };
    }
};

const full_contracts = [_][]const u8{
    "same-architecture-qemu",
    "standalone-zstd-qcow2",
    "gpt-layout",
    "secure-boot",
    "uefi-db-signer",
    "signed-uki",
    "vtpm",
    "kernel-lockdown",
    "module-signatures",
    "tampered-uki-rejected",
    "key-only-ssh",
    "cloud-init-provisioning",
    "walinuxagent",
    "netplan-networkd",
    "generalized-identity",
    "root-growth",
    "reboot-reconnect",
    "clean-service-health",
};

const core_contracts = [_][]const u8{
    "same-architecture-qemu",
    "standalone-zstd-qcow2",
    "gpt-layout",
    "secure-boot",
    "uefi-db-signer",
    "signed-uki",
    "vtpm",
    "kernel-lockdown",
    "module-signatures",
    "tampered-uki-rejected",
    "key-only-ssh",
    "local-ovf-azagent-skip-ready",
    "azagent-provisioning",
    "mizinit-pid1",
    "mizinit-sshd-supervision",
    "sshd-restart",
    "persistent-provisioned-state",
    "no-cloud-init",
    "no-walinuxagent",
    "generalized-identity",
    "root-growth",
    "reboot-reconnect",
    "clean-service-health",
    "signed-binder-module",
    "binder-boot-required",
    "binderfs-dynamic-devices",
    "binder-device-usability",
    "dma-heap-device",
    "runtime-contract",
};

const FlavorPolicy = struct {
    x86_64_file_name: []const u8,
    aarch64_file_name: []const u8,
    virtual_size: u64,
    result_schema: u32,
    contracts: []const []const u8,
};

const Flavor = enum {
    core,
    full,

    fn policy(self: Flavor) *const FlavorPolicy {
        return switch (self) {
            .core => &core_policy,
            .full => &full_policy,
        };
    }
};

const core_policy: FlavorPolicy = .{
    .x86_64_file_name = "Ubuntu-26.04-x86_64.core.qcow2",
    .aarch64_file_name = "Ubuntu-26.04-aarch64.core.qcow2",
    .virtual_size = 3584 * mib,
    .result_schema = 9,
    .contracts = &core_contracts,
};

const full_policy: FlavorPolicy = .{
    .x86_64_file_name = "Ubuntu-26.04-x86_64.qcow2",
    .aarch64_file_name = "Ubuntu-26.04-aarch64.qcow2",
    .virtual_size = 5 * gib,
    .result_schema = 4,
    .contracts = &full_contracts,
};

const Candidate = struct {
    architecture: Architecture,
    flavor: Flavor,

    fn key(self: Candidate) []const u8 {
        return switch (self.architecture) {
            .x86_64 => switch (self.flavor) {
                .full => "x86_64-full",
                .core => "x86_64-core",
            },
            .aarch64 => switch (self.flavor) {
                .full => "aarch64-full",
                .core => "aarch64-core",
            },
        };
    }

    fn expectedFileName(self: Candidate) []const u8 {
        const policy = self.flavor.policy();
        return switch (self.architecture) {
            .x86_64 => policy.x86_64_file_name,
            .aarch64 => policy.aarch64_file_name,
        };
    }

    fn expectedVirtualSize(self: Candidate) u64 {
        return self.flavor.policy().virtual_size;
    }

    fn contracts(self: Candidate) []const []const u8 {
        return self.flavor.policy().contracts;
    }

    fn executionProfile(self: Candidate) *const execution.Profile {
        return execution.forName(@tagName(self.architecture)).?;
    }
};

fn expectedOriginalRootSize(candidate: Candidate) !u64 {
    const virtual_size = candidate.expectedVirtualSize();
    if (virtual_size == 0 or virtual_size % miz.gpt.sector_size != 0)
        return error.InvalidExpectedVirtualSize;

    const total_sectors = virtual_size / miz.gpt.sector_size;
    const reserved_sectors = 2 + miz.gpt.partition_array_sectors;
    if (total_sectors <= reserved_sectors)
        return error.InvalidExpectedVirtualSize;

    const last_usable_lba = total_sectors - reserved_sectors;
    const root_first_lba = candidate.architecture.partitionPolicy().root_first_lba;
    if (root_first_lba > last_usable_lba)
        return error.InvalidExpectedRootGeometry;

    const root_sectors = last_usable_lba - root_first_lba + 1;
    return std.math.mul(u64, root_sectors, miz.gpt.sector_size);
}

fn hasContract(contracts: []const []const u8, expected: []const u8) bool {
    for (contracts) |contract| {
        if (std.mem.eql(u8, contract, expected)) return true;
    }
    return false;
}

const Firmware = qemu_host.FirmwarePair;

const GuestIdentity = struct {
    machine_id: []u8,
    ssh_fingerprint: []u8,
    boot_id: []u8,

    fn deinit(self: *GuestIdentity, allocator: Allocator) void {
        allocator.free(self.machine_id);
        allocator.free(self.ssh_fingerprint);
        allocator.free(self.boot_id);
        self.* = undefined;
    }
};

const CoreProvisionedState = struct {
    account: []u8,
    authorized_key_fingerprint: []u8,
    sentinel: []u8,

    fn deinit(self: *CoreProvisionedState, allocator: Allocator) void {
        allocator.free(self.account);
        allocator.free(self.authorized_key_fingerprint);
        allocator.free(self.sentinel);
        self.* = undefined;
    }
};

const Instance = struct {
    label: []const u8,
    port: u16,
    execution_profile: *const execution.Profile,
    work_path: []u8,
    overlay_path: []u8,
    vars_path: []u8,
    seed_path: []u8,
    private_key_path: []u8,
    public_key_path: []u8,
    serial_path: []u8,
    qmp_socket_path: []u8,
    swtpm_state_path: []u8,
    swtpm_socket_path: []u8,
    swtpm_log_path: []u8,
    swtpm_child: ?std.process.Child = null,
    spawned: ?qmp.Spawned = null,
    child_waited: bool = false,

    fn init(
        self: *Instance,
        allocator: Allocator,
        io: Io,
        parent_path: []const u8,
        label: []const u8,
        port: u16,
        execution_profile: *const execution.Profile,
    ) !void {
        const work_path = try std.fs.path.join(allocator, &.{ parent_path, label });
        errdefer allocator.free(work_path);
        try Dir.cwd().createDir(io, work_path, .default_dir);
        errdefer Dir.cwd().deleteTree(io, work_path) catch {};

        const overlay_path = try std.fs.path.join(allocator, &.{ work_path, "overlay.qcow2" });
        errdefer allocator.free(overlay_path);
        const vars_path = try std.fs.path.join(allocator, &.{ work_path, "vars.fd" });
        errdefer allocator.free(vars_path);
        const seed_path = try std.fs.path.join(allocator, &.{ work_path, "seed.iso" });
        errdefer allocator.free(seed_path);
        const private_key_path = try std.fs.path.join(allocator, &.{ work_path, "id_ed25519" });
        errdefer allocator.free(private_key_path);
        const public_key_path = try std.fmt.allocPrint(allocator, "{s}.pub", .{private_key_path});
        errdefer allocator.free(public_key_path);
        const serial_path = try std.fs.path.join(allocator, &.{ work_path, "serial.log" });
        errdefer allocator.free(serial_path);
        const qmp_socket_path = try std.fs.path.join(allocator, &.{ work_path, "qmp.sock" });
        errdefer allocator.free(qmp_socket_path);
        const swtpm_state_path = try std.fs.path.join(allocator, &.{ work_path, "swtpm-state" });
        errdefer allocator.free(swtpm_state_path);
        const swtpm_socket_path = try std.fs.path.join(allocator, &.{ work_path, "swtpm.sock" });
        errdefer allocator.free(swtpm_socket_path);
        const swtpm_log_path = try std.fs.path.join(allocator, &.{ work_path, "swtpm.log" });
        errdefer allocator.free(swtpm_log_path);

        self.* = .{
            .label = label,
            .port = port,
            .execution_profile = execution_profile,
            .work_path = work_path,
            .overlay_path = overlay_path,
            .vars_path = vars_path,
            .seed_path = seed_path,
            .private_key_path = private_key_path,
            .public_key_path = public_key_path,
            .serial_path = serial_path,
            .qmp_socket_path = qmp_socket_path,
            .swtpm_state_path = swtpm_state_path,
            .swtpm_socket_path = swtpm_socket_path,
            .swtpm_log_path = swtpm_log_path,
        };
    }

    fn deinit(self: *Instance, allocator: Allocator) void {
        if (self.spawned) |*spawned| {
            if (!self.child_waited) spawned.kill();
            spawned.deinit();
        }
        if (self.swtpm_child) |*child| child.kill(std.testing.io);
        allocator.free(self.work_path);
        allocator.free(self.overlay_path);
        allocator.free(self.vars_path);
        allocator.free(self.seed_path);
        allocator.free(self.private_key_path);
        allocator.free(self.public_key_path);
        allocator.free(self.serial_path);
        allocator.free(self.qmp_socket_path);
        allocator.free(self.swtpm_state_path);
        allocator.free(self.swtpm_socket_path);
        allocator.free(self.swtpm_log_path);
        self.* = undefined;
    }

    fn dumpSerial(self: *const Instance, allocator: Allocator, io: Io) void {
        const serial = Dir.cwd().readFileAlloc(
            io,
            self.serial_path,
            allocator,
            .limited(serial_limit),
        ) catch return;
        defer allocator.free(serial);
        std.debug.print(
            "\n--- Ubuntu acceptance serial log ({s}) ---\n{s}\n--- end serial log ---\n",
            .{ self.label, serial },
        );
    }
};

fn optionalEnvAlloc(allocator: Allocator, comptime name: []const u8) !?[]u8 {
    return std.testing.environ.getAlloc(allocator, name) catch |err| switch (err) {
        error.EnvironmentVariableMissing => null,
        else => return err,
    };
}

const AcceptanceResultIdentity = struct {
    source_commit: []u8,
    candidate_run_id: []u8,
    candidate_run_attempt: []u8,
    run_id: []u8,
    run_attempt: []u8,

    fn deinit(self: *AcceptanceResultIdentity, allocator: Allocator) void {
        allocator.free(self.source_commit);
        allocator.free(self.candidate_run_id);
        allocator.free(self.candidate_run_attempt);
        allocator.free(self.run_id);
        allocator.free(self.run_attempt);
        self.* = undefined;
    }
};

fn isLowerHexCommit(value: []const u8) bool {
    if (value.len != 40) return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte) and !(byte >= 'a' and byte <= 'f')) return false;
    }
    return true;
}

fn isPositiveDecimal(value: []const u8) bool {
    if (value.len == 0 or value[0] == '0') return false;
    for (value) |byte| {
        if (!std.ascii.isDigit(byte)) return false;
    }
    return true;
}

fn requireAcceptanceResultIdentityAlloc(
    allocator: Allocator,
) !AcceptanceResultIdentity {
    const source_commit = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_SOURCE_COMMIT",
    );
    errdefer allocator.free(source_commit);
    const candidate_run_id = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_CANDIDATE_RUN_ID",
    );
    errdefer allocator.free(candidate_run_id);
    const candidate_run_attempt = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_CANDIDATE_RUN_ATTEMPT",
    );
    errdefer allocator.free(candidate_run_attempt);
    const run_id = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ACCEPTANCE_RUN_ID",
    );
    errdefer allocator.free(run_id);
    const run_attempt = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ACCEPTANCE_RUN_ATTEMPT",
    );
    errdefer allocator.free(run_attempt);
    if (!isLowerHexCommit(source_commit)) return error.InvalidSourceCommit;
    if (!isPositiveDecimal(candidate_run_id)) {
        return error.InvalidCandidateRunId;
    }
    if (!isPositiveDecimal(candidate_run_attempt)) {
        return error.InvalidCandidateRunAttempt;
    }
    if (!isPositiveDecimal(run_id)) return error.InvalidAcceptanceRunId;
    if (!isPositiveDecimal(run_attempt)) return error.InvalidAcceptanceRunAttempt;
    return .{
        .source_commit = source_commit,
        .candidate_run_id = candidate_run_id,
        .candidate_run_attempt = candidate_run_attempt,
        .run_id = run_id,
        .run_attempt = run_attempt,
    };
}

fn selectedCandidate() !Candidate {
    const architecture = std.meta.stringToEnum(
        Architecture,
        build_options.ubuntu2604_architecture,
    ) orelse return error.InvalidBuildArchitecture;
    const flavor = std.meta.stringToEnum(
        Flavor,
        build_options.ubuntu2604_flavor,
    ) orelse return error.InvalidBuildFlavor;
    return .{ .architecture = architecture, .flavor = flavor };
}

fn requireImageAlloc(
    allocator: Allocator,
    io: Io,
    candidate: Candidate,
) ![]u8 {
    const image_path = try optionalEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_IMAGE",
    ) orelse {
        std.debug.print(
            "skipping Ubuntu 26.04 acceptance: set MIZ_UBUNTU2604_IMAGE to {s}\n",
            .{candidate.expectedFileName()},
        );
        return error.SkipZigTest;
    };
    errdefer allocator.free(image_path);

    if (!std.mem.eql(u8, std.fs.path.basename(image_path), candidate.expectedFileName())) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires the exact finalized candidate {s}, got {s}\n",
            .{ candidate.expectedFileName(), image_path },
        );
        return error.UnexpectedCandidateName;
    }
    if (!try qemu_host.pathAccessible(io, image_path, .{ .read = true })) {
        std.debug.print(
            "MIZ_UBUNTU2604_IMAGE is not readable: {s}\n",
            .{image_path},
        );
        return error.AcceptanceImageNotReadable;
    }
    return image_path;
}

fn validateQemuPrerequisites(
    host_is_linux: bool,
    host_architecture: std.Target.Cpu.Arch,
    kvm_available: ?bool,
    candidate: Candidate,
) !void {
    const profile = candidate.executionProfile();
    if (!host_is_linux) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires a Linux host for same-architecture QEMU\n",
            .{},
        );
        return error.QemuRequiresLinux;
    }
    if (host_architecture != candidate.architecture.runnerCpu()) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires a same-architecture {s} runner\n",
            .{@tagName(candidate.architecture.runnerCpu())},
        );
        return error.QemuRequiresMatchingHostArchitecture;
    }
    switch (profile.accelerator) {
        .kvm => if (!(kvm_available orelse false)) {
            std.debug.print(
                "Ubuntu 26.04 x86_64 acceptance requires readable and writable /dev/kvm\n",
                .{},
            );
            return error.KvmUnavailable;
        },
        .tcg => if (kvm_available != null)
            return error.UnexpectedKvmCheckForTcg,
    }
}

const ConfiguredExecution = struct {
    profile: *const execution.Profile,
    qemu_path: []u8,

    fn deinit(self: *ConfiguredExecution, allocator: Allocator) void {
        allocator.free(self.qemu_path);
        self.* = undefined;
    }
};

const InitialGuestLaunchStep = enum {
    start_first,
    first_ready,
    start_second,
    second_ready,
};

fn initialGuestLaunchOrder(
    policy: execution.InitialGuestLaunchPolicy,
) [4]InitialGuestLaunchStep {
    return switch (policy) {
        .concurrent => .{
            .start_first,
            .start_second,
            .first_ready,
            .second_ready,
        },
        .serial_until_ready => .{
            .start_first,
            .first_ready,
            .start_second,
            .second_ready,
        },
    };
}

fn requireExactExecutionEnvironment(
    allocator: Allocator,
    profile: *const execution.Profile,
) ![]u8 {
    const expectations = [_]struct {
        name: []const u8,
        expected: []const u8,
    }{
        .{
            .name = "MIZ_UBUNTU2604_QEMU_ACCELERATOR",
            .expected = @tagName(profile.accelerator),
        },
        .{
            .name = "MIZ_UBUNTU2604_QEMU_ACCELERATOR_ARGUMENT",
            .expected = profile.accelerator_argument,
        },
        .{
            .name = "MIZ_UBUNTU2604_QEMU_CPU",
            .expected = profile.cpu,
        },
        .{
            .name = "MIZ_UBUNTU2604_QEMU_MACHINE",
            .expected = profile.machine,
        },
        .{
            .name = "MIZ_UBUNTU2604_RUNNER_ARCHITECTURE",
            .expected = profile.runner_architecture,
        },
    };
    for (expectations) |expectation| {
        const actual = std.testing.environ.getAlloc(
            allocator,
            expectation.name,
        ) catch |err| switch (err) {
            error.EnvironmentVariableMissing => {
                std.debug.print(
                    "Ubuntu 26.04 acceptance requires {s}={s}\n",
                    .{ expectation.name, expectation.expected },
                );
                return err;
            },
            else => return err,
        };
        defer allocator.free(actual);
        if (!std.mem.eql(u8, actual, expectation.expected)) {
            std.debug.print(
                "Ubuntu 26.04 acceptance requires {s}={s}, got {s}\n",
                .{ expectation.name, expectation.expected, actual },
            );
            return error.QemuExecutionEnvironmentMismatch;
        }
    }

    const job_timeout_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_QEMU_JOB_TIMEOUT_MINUTES",
    );
    defer allocator.free(job_timeout_text);
    const job_timeout = std.fmt.parseInt(u16, job_timeout_text, 10) catch
        return error.QemuExecutionEnvironmentMismatch;
    if (job_timeout != profile.timeouts.job_minutes) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires a {d}-minute QEMU job timeout, got {s}\n",
            .{ profile.timeouts.job_minutes, job_timeout_text },
        );
        return error.QemuExecutionEnvironmentMismatch;
    }

    const qemu_path = try requireEnvAlloc(allocator, "MIZ_UBUNTU2604_QEMU");
    errdefer allocator.free(qemu_path);
    if (!std.mem.eql(u8, qemu_path, profile.emulator)) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires MIZ_UBUNTU2604_QEMU={s}, got {s}\n",
            .{ profile.emulator, qemu_path },
        );
        return error.QemuExecutionEnvironmentMismatch;
    }
    return qemu_path;
}

fn requireQemuExecutionAlloc(
    allocator: Allocator,
    io: Io,
    candidate: Candidate,
) !ConfiguredExecution {
    const profile = candidate.executionProfile();
    const host_is_linux = builtin.os.tag == .linux;
    const host_is_native = builtin.cpu.arch == candidate.architecture.runnerCpu();
    const kvm_available: ?bool = switch (profile.accelerator) {
        .kvm => if (host_is_linux and host_is_native)
            try qemu_host.pathAccessible(io, "/dev/kvm", .{
                .read = true,
                .write = true,
            })
        else
            false,
        .tcg => null,
    };
    try validateQemuPrerequisites(
        host_is_linux,
        builtin.cpu.arch,
        kvm_available,
        candidate,
    );
    const qemu_path = try requireExactExecutionEnvironment(allocator, profile);
    errdefer allocator.free(qemu_path);
    if (!try qemu_host.pathAccessible(io, qemu_path, .{ .execute = true })) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires executable native QEMU at {s}\n",
            .{qemu_path},
        );
        return error.RequiredQemuNotExecutable;
    }
    return .{ .profile = profile, .qemu_path = qemu_path };
}

fn requireFoundTool(path: ?[]u8, name: []const u8) ![]u8 {
    return path orelse {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires {s} in PATH\n",
            .{name},
        );
        return error.RequiredToolNotFound;
    };
}

fn requireToolAlloc(
    allocator: Allocator,
    io: Io,
    name: []const u8,
) ![]u8 {
    return requireFoundTool(
        try qemu_host.findExecutableInPathAlloc(
            allocator,
            io,
            std.testing.environ,
            name,
        ),
        name,
    );
}

fn requireToolOverrideAlloc(
    allocator: Allocator,
    io: Io,
    comptime environment_name: []const u8,
    default_name: []const u8,
) ![]u8 {
    if (try optionalEnvAlloc(allocator, environment_name)) |path| {
        errdefer allocator.free(path);
        if (!try qemu_host.pathAccessible(io, path, .{ .execute = true }))
            return error.ToolOverrideNotExecutable;
        return path;
    }
    return requireToolAlloc(allocator, io, default_name);
}

fn requireFoundFirmware(firmware: ?Firmware) !Firmware {
    return firmware orelse {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires matching UEFI firmware; set MIZ_UBUNTU2604_UEFI_CODE and MIZ_UBUNTU2604_UEFI_VARS\n",
            .{},
        );
        return error.RequiredFirmwareNotFound;
    };
}

fn requireFirmwareAlloc(
    allocator: Allocator,
    io: Io,
    qemu_path: []const u8,
    architecture: Architecture,
    secure_boot: bool,
) !Firmware {
    const explicit_code = if (secure_boot) try optionalEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_UEFI_CODE",
    ) else null;
    defer if (explicit_code) |path| allocator.free(path);
    const explicit_vars = if (secure_boot) try optionalEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_UEFI_VARS",
    ) else null;
    defer if (explicit_vars) |path| allocator.free(path);

    return requireFoundFirmware(try qemu_host.findFirmwarePairAlloc(allocator, io, .{
        .secure_boot = secure_boot,
        .explicit_code_path = explicit_code,
        .explicit_vars_path = explicit_vars,
        .qemu_path = qemu_path,
        .architecture = architecture.guestArchitecture(),
    }));
}

fn runCommand(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
) !void {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(90),
            .clock = .awake,
        } },
    });
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    if (result.stderr.len != 0) {
        std.debug.print("command failed: {s}\n", .{result.stderr});
    }
    return error.CommandFailed;
}

fn commandOutputAlloc(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
) ![]u8 {
    const result = try std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(1024 * 1024),
        .stderr_limit = .limited(1024 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(90),
            .clock = .awake,
        } },
    });
    allocator.free(result.stderr);
    switch (result.term) {
        .exited => |code| if (code == 0) return result.stdout,
        else => {},
    }
    allocator.free(result.stdout);
    return error.CommandFailed;
}

fn requireEnvAlloc(
    allocator: Allocator,
    comptime name: []const u8,
) ![]u8 {
    return (try optionalEnvAlloc(allocator, name)) orelse {
        std.debug.print("Ubuntu 26.04 Secure Boot acceptance requires {s}\n", .{name});
        return error.RequiredEnvironmentMissing;
    };
}

fn canonicalCertificateSha256(
    allocator: Allocator,
    io: Io,
    openssl_path: []const u8,
    certificate_path: []const u8,
    output_path: []const u8,
) !miz.artifact_pipeline.Digest {
    try runCommand(allocator, io, &.{
        openssl_path,
        "x509",
        "-in",
        certificate_path,
        "-outform",
        "DER",
        "-out",
        output_path,
    });
    const certificate = try Dir.cwd().readFileAlloc(
        io,
        output_path,
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(certificate);
    if (certificate.len == 0) return error.EmptySigningCertificate;
    return miz.artifact_pipeline.sha256Bytes(certificate);
}

/// Appends the candidate leaf to the Microsoft-enrolled firmware `db` and
/// enables Secure Boot, natively: the same `miz.efi_varstore` code path
/// `miz qemu --secure-boot` uses, so acceptance exercises the shipped
/// enrollment rather than a host tool that only resembles it.
fn prepareEnrolledVars(
    allocator: Allocator,
    io: Io,
    source_vars_path: []const u8,
    certificate_der: []const u8,
    certificate_sha256: miz.artifact_pipeline.Digest,
    output_path: []const u8,
) !void {
    Dir.cwd().deleteFile(io, output_path) catch {};
    const trust_state = try miz.efi_varstore.enrollSecureBootFile(
        allocator,
        io,
        source_vars_path,
        output_path,
        certificate_der,
    );
    const revalidated = try miz.efi_varstore.validateSecureBootFile(
        allocator,
        io,
        output_path,
        certificate_sha256,
    );
    if (!revalidated.eql(trust_state)) return error.InvalidEnrolledVars;
    const stat = try Dir.cwd().statFile(io, output_path, .{});
    if (stat.kind != .file or stat.size == 0) return error.InvalidEnrolledVars;
}

const PreservedPartitions = struct {
    root: miz.gpt.PartitionEntry,
    xbootldr: ?miz.gpt.PartitionEntry,
    bios_boot: ?miz.gpt.PartitionEntry,
    esp: miz.gpt.PartitionEntry,
};

fn partitionNameEquals(
    partition: miz.gpt.PartitionEntry,
    expected: []const u8,
) bool {
    if (expected.len > partition.name_utf16le.len) return false;
    for (expected, 0..) |byte, index| {
        if (partition.name_utf16le[index] != byte) return false;
    }
    for (partition.name_utf16le[expected.len..]) |code_unit| {
        if (code_unit != 0) return false;
    }
    return true;
}

fn findPartitionByType(
    partitions: []const miz.gpt.PartitionEntry,
    expected: miz.guid.Guid,
) !?miz.gpt.PartitionEntry {
    var found: ?miz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &expected)) continue;
        if (found != null) return error.AmbiguousPartitionType;
        found = partition;
    }
    return found;
}

fn findEspPartition(
    partitions: []const miz.gpt.PartitionEntry,
) !miz.gpt.PartitionEntry {
    return (try findPartitionByType(partitions, miz.guid.esp)) orelse
        error.MissingEspPartition;
}

fn findRootPartition(
    partitions: []const miz.gpt.PartitionEntry,
    architecture: Architecture,
) !miz.gpt.PartitionEntry {
    var found: ?miz.gpt.PartitionEntry = null;
    for (partitions) |partition| {
        if (!partitionNameEquals(partition, "cloudimg-rootfs")) continue;
        if (found != null) return error.AmbiguousRootPartition;
        found = partition;
    }
    const root = found orelse return error.MissingRootPartition;
    if (!std.mem.eql(
        u8,
        &root.partition_type_guid,
        &architecture.rootGuid(),
    )) {
        return error.UnexpectedRootArchitecture;
    }
    return root;
}

fn partitionGeometryMatches(
    partition: miz.gpt.PartitionEntry,
    expected: ExpectedPartitionGeometry,
) bool {
    return partition.table_index == expected.table_index and
        partition.first_lba == expected.first_lba and
        partition.last_lba == expected.last_lba;
}

fn validatePreservedPartitions(
    partitions: []const miz.gpt.PartitionEntry,
    architecture: Architecture,
    last_usable_lba: u64,
) !PreservedPartitions {
    const policy = architecture.partitionPolicy();
    const bios_boot = try findPartitionByType(partitions, miz.guid.bios_boot);
    if (policy.bios_boot == null and bios_boot != null)
        return error.UnexpectedBiosBootPartition;
    if (partitions.len != policy.partitionCount())
        return error.UnexpectedPartitionCount;
    if (policy.bios_boot != null and bios_boot == null)
        return error.MissingBiosBootPartition;

    const root = try findRootPartition(partitions, architecture);
    const xbootldr = try findPartitionByType(
        partitions,
        miz.guid.linux_xbootldr,
    );
    if (policy.xbootldr == null and xbootldr != null)
        return error.UnexpectedXbootldrPartition;
    if (policy.xbootldr != null and xbootldr == null)
        return error.MissingXbootldrPartition;
    const esp = try findEspPartition(partitions);

    for (partitions, 0..) |partition, index| {
        if (std.mem.eql(
            u8,
            &partition.unique_partition_guid,
            &miz.guid.nil,
        )) {
            return error.InvalidPartitionGuid;
        }
        for (partitions[index + 1 ..]) |other| {
            if (std.mem.eql(
                u8,
                &partition.unique_partition_guid,
                &other.unique_partition_guid,
            )) {
                return error.DuplicatePartitionGuid;
            }
        }
    }

    if (root.table_index != 0 or
        root.first_lba != policy.root_first_lba or
        root.last_lba != last_usable_lba)
    {
        return error.UnexpectedRootGeometry;
    }
    if (policy.xbootldr) |expected| {
        if (!partitionGeometryMatches(xbootldr.?, expected))
            return error.UnexpectedXbootldrGeometry;
    }
    if (policy.bios_boot) |expected| {
        if (!partitionGeometryMatches(bios_boot.?, expected))
            return error.UnexpectedBiosBootGeometry;
    }
    if (!partitionGeometryMatches(esp, policy.esp))
        return error.UnexpectedEspGeometry;

    if ((xbootldr != null and !partitionNameEquals(xbootldr.?, "")) or
        (bios_boot != null and !partitionNameEquals(bios_boot.?, "")) or
        !partitionNameEquals(esp, ""))
    {
        return error.UnexpectedAuxiliaryPartitionName;
    }

    return .{
        .root = root,
        .xbootldr = xbootldr,
        .bios_boot = bios_boot,
        .esp = esp,
    };
}

fn validateClearedArm64XbootldrEntry(parsed: miz.gpt.VerifiedGpt) !void {
    const table_index: usize = 12;
    const entry_size: usize = @intCast(parsed.primary_header.partition_entry_size);
    const start = std.math.mul(usize, table_index, entry_size) catch
        return error.InvalidPartitionArrayBounds;
    const end = std.math.add(usize, start, entry_size) catch
        return error.InvalidPartitionArrayBounds;
    if (end > parsed.partition_array.len or
        !std.mem.allEqual(u8, parsed.partition_array[start..end], 0))
    {
        return error.Arm64XbootldrEntryNotCleared;
    }
}

fn expectOnlyEspEntry(
    allocator: Allocator,
    io: Io,
    esp: *miz.fat32.FileSystem,
    directory: []const u8,
    name: []const u8,
    kind: miz.fat32.DirEntryKind,
    size: u32,
) !void {
    const entries = try esp.listDirAlloc(io, allocator, directory);
    defer miz.fat32.freeDirEntries(allocator, entries);
    if (entries.len != 1 or
        !std.mem.eql(u8, entries[0].name, name) or
        entries[0].kind != kind or
        entries[0].size != size)
    {
        return error.UnexpectedArm64EspContents;
    }
}

fn validateArm64EspContents(
    allocator: Allocator,
    io: Io,
    esp: *miz.fat32.FileSystem,
    uki_size: usize,
) !void {
    const size = std.math.cast(u32, uki_size) orelse return error.UkiTooLarge;
    try expectOnlyEspEntry(allocator, io, esp, "", "EFI", .directory, 0);
    try expectOnlyEspEntry(allocator, io, esp, "EFI", "BOOT", .directory, 0);
    try expectOnlyEspEntry(
        allocator,
        io,
        esp,
        "EFI/BOOT",
        "BOOTAA64.EFI",
        .file,
        size,
    );
}

fn verifyUkiSignatures(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    candidate: Candidate,
    certificate_path: []const u8,
    sbverify_path: []const u8,
    scratch_path: []const u8,
) !void {
    var file = try Dir.cwd().openFile(io, image_path, .{ .mode = .read_only });
    var image = try miz.Image.openStandaloneQcow2File(io, file);
    defer image.close(io);
    file = undefined;
    const parsed = try miz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    const partition = try findEspPartition(parsed.partitions);
    var esp = try miz.fat32.open(&image, io, .{
        .offset = partition.first_lba * miz.gpt.sector_size,
        .length = (partition.last_lba - partition.first_lba + 1) *
            miz.gpt.sector_size,
    });
    // The image carries one signed UKI, at the fallback path firmware loads. Verifying that one is
    // the whole job; the EFI/Linux duplicate this used to walk no longer exists.
    const fallback = try esp.readFileAlloc(
        io,
        allocator,
        candidate.architecture.fallbackUkiPath(),
    );
    defer allocator.free(fallback);
    const fallback_path = try std.fmt.allocPrint(
        allocator,
        "{s}/uki-fallback.efi",
        .{scratch_path},
    );
    defer allocator.free(fallback_path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = fallback_path,
        .data = fallback,
        .flags = .{ .truncate = true, .permissions = .fromMode(0o600) },
    });
    defer Dir.cwd().deleteFile(io, fallback_path) catch {};
    try runCommand(allocator, io, &.{
        sbverify_path,
        "--cert",
        certificate_path,
        fallback_path,
    });
}

fn verifyNativeUkiCertificate(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    expected_certificate_der: []const u8,
    expected_certificate_sha256: miz.artifact_pipeline.Digest,
) !void {
    var image = try miz.Image.openPathReadOnlyStandalone(io, image_path);
    defer image.close(io);
    var extracted = try miz.uki_certificate.extractAlloc(
        allocator,
        io,
        &image,
        .{ .expected_sha256 = expected_certificate_sha256 },
    );
    defer extracted.deinit(allocator);
    if (!std.mem.eql(
        u8,
        expected_certificate_der,
        extracted.certificate_der,
    )) {
        return error.ExtractedSigningCertificateMismatch;
    }
}

fn tamperUkiCmdlineAlloc(
    allocator: Allocator,
    signed: []const u8,
) ![]u8 {
    var inspection = try miz.uki.inspect(allocator, signed);
    defer inspection.deinit(allocator);
    const cmdline = inspection.findSection(".cmdline") orelse
        return error.MissingUkiCmdline;
    const whitespace_offset = std.mem.indexOfScalar(u8, cmdline.contents, ' ') orelse
        return error.MissingUkiCmdlineWhitespace;
    const file_offset = std.math.add(
        usize,
        @as(usize, cmdline.raw_offset),
        whitespace_offset,
    ) catch return error.InvalidUkiCmdlineOffset;
    if (file_offset >= signed.len) return error.InvalidUkiCmdlineOffset;
    const tampered = try allocator.dupe(u8, signed);
    tampered[file_offset] = '\t';
    return tampered;
}

fn requireRejectedUkiSignature(
    allocator: Allocator,
    io: Io,
    sbverify_path: []const u8,
    certificate_path: []const u8,
    scratch_path: []const u8,
    index: usize,
    bytes: []const u8,
) !void {
    const path = try std.fmt.allocPrint(
        allocator,
        "{s}/tampered-{d}.efi",
        .{ scratch_path, index },
    );
    defer allocator.free(path);
    try Dir.cwd().writeFile(io, .{
        .sub_path = path,
        .data = bytes,
        .flags = .{ .truncate = true, .permissions = .fromMode(0o600) },
    });
    defer Dir.cwd().deleteFile(io, path) catch {};
    if (try commandSucceeded(allocator, io, &.{
        sbverify_path,
        "--cert",
        certificate_path,
        path,
    })) {
        return error.TamperedUkiSignatureAccepted;
    }
}

fn createTamperedOverlay(
    allocator: Allocator,
    io: Io,
    qemu_img_path: []const u8,
    source_image: []const u8,
    overlay_path: []const u8,
    candidate: Candidate,
    certificate_path: []const u8,
    sbverify_path: []const u8,
    scratch_path: []const u8,
) !void {
    try runCommand(allocator, io, &.{
        qemu_img_path,
        "create",
        "-q",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        source_image,
        overlay_path,
    });
    var image = try miz.Image.openPath(io, overlay_path);
    defer image.close(io);
    const parsed = try miz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    const partition = try findEspPartition(parsed.partitions);
    var esp = try miz.fat32.open(&image, io, .{
        .offset = partition.first_lba * miz.gpt.sector_size,
        .length = (partition.last_lba - partition.first_lba + 1) *
            miz.gpt.sector_size,
    });
    // Tamper with the one signed UKI the image carries, at the path firmware loads.
    const fallback_path = candidate.architecture.fallbackUkiPath();
    const signed_fallback = try esp.readFileAlloc(io, allocator, fallback_path);
    defer allocator.free(signed_fallback);
    const tampered_fallback = try tamperUkiCmdlineAlloc(allocator, signed_fallback);
    defer allocator.free(tampered_fallback);
    try requireRejectedUkiSignature(
        allocator,
        io,
        sbverify_path,
        certificate_path,
        scratch_path,
        0,
        tampered_fallback,
    );
    try esp.deletePath(io, fallback_path);
    try esp.writeFile(io, fallback_path, tampered_fallback);
}

fn validateQemuImgInfo(
    allocator: Allocator,
    io: Io,
    qemu_img_path: []const u8,
    image_path: []const u8,
) !void {
    try runCommand(allocator, io, &.{ qemu_img_path, "check", image_path });
    const output = try commandOutputAlloc(
        allocator,
        io,
        &.{ qemu_img_path, "info", "--output=json", image_path },
    );
    defer allocator.free(output);

    var parsed = try std.json.parseFromSlice(std.json.Value, allocator, output, .{});
    defer parsed.deinit();
    const info = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidQemuImgInfo,
    };
    const format = info.get("format") orelse return error.InvalidQemuImgInfo;
    if (format != .string or !std.mem.eql(u8, format.string, "qcow2"))
        return error.NotQcow2;
    if (info.get("backing-filename") != null or info.get("full-backing-filename") != null)
        return error.ImageHasBackingFile;

    const format_specific = info.get("format-specific") orelse return error.InvalidQemuImgInfo;
    const format_specific_object = switch (format_specific) {
        .object => |object| object,
        else => return error.InvalidQemuImgInfo,
    };
    const format_specific_data = format_specific_object.get("data") orelse
        return error.InvalidQemuImgInfo;
    const data = switch (format_specific_data) {
        .object => |object| object,
        else => return error.InvalidQemuImgInfo,
    };
    const compression_type = data.get("compression-type") orelse
        return error.MissingZstdCompression;
    if (compression_type != .string or !std.mem.eql(u8, compression_type.string, "zstd"))
        return error.MissingZstdCompression;
}

fn requireNonemptyUkiSection(
    inspection: *const miz.uki.Inspection,
    name: []const u8,
) ![]const u8 {
    const section = inspection.findSection(name) orelse return error.MissingUkiSection;
    if (section.contents.len == 0) return error.EmptyUkiSection;
    return section.contents;
}

fn validateFinalizedImage(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    candidate: Candidate,
) !miz.artifact_pipeline.Digest {
    var file = try Dir.cwd().openFile(io, image_path, .{ .mode = .read_only });
    var image = try miz.Image.openStandaloneQcow2File(io, file);
    defer image.close(io);
    file = undefined;

    if (image.format != .qcow2) return error.NotQcow2;
    const qcow2 = image.qcow2 orelse return error.NotQcow2;
    if (qcow2.backing_file_len != 0) return error.ImageHasBackingFile;
    if (qcow2.data_file_len != 0) return error.ImageHasExternalDataFile;
    if (qcow2.compression_type != 1) return error.MissingZstdCompression;
    if (image.virtual_size != candidate.expectedVirtualSize())
        return error.UnexpectedVirtualSize;

    var parsed = try miz.gpt.readVerifiedGpt(
        image,
        io,
        allocator,
        miz.gpt.default_max_partition_array_bytes,
    );
    defer parsed.deinit(allocator);
    const preserved = try validatePreservedPartitions(
        parsed.partitions,
        candidate.architecture,
        parsed.primary_header.last_usable_lba,
    );
    if (candidate.architecture == .aarch64) {
        try validateClearedArm64XbootldrEntry(parsed);
    }
    const esp_partition = preserved.esp;
    const root_partition = preserved.root;

    var esp = try miz.fat32.open(&image, io, .{
        .offset = esp_partition.first_lba * miz.gpt.sector_size,
        .length = (esp_partition.last_lba - esp_partition.first_lba + 1) *
            miz.gpt.sector_size,
    });
    const uki = try esp.readFileAlloc(
        io,
        allocator,
        candidate.architecture.fallbackUkiPath(),
    );
    defer allocator.free(uki);
    if (candidate.architecture == .aarch64) {
        try validateArm64EspContents(allocator, io, &esp, uki.len);
    }

    var inspection = try miz.uki.inspect(allocator, uki);
    defer inspection.deinit(allocator);
    if (inspection.machine != candidate.architecture.ukiMachine())
        return error.UnexpectedUkiArchitecture;
    if (inspection.subsystem != 10) return error.UnexpectedUkiSubsystem;
    if (inspection.security_directory == null) return error.UnsignedUki;
    _ = try requireNonemptyUkiSection(&inspection, ".linux");
    _ = try requireNonemptyUkiSection(&inspection, ".initrd");
    _ = try requireNonemptyUkiSection(&inspection, ".osrel");
    _ = try requireNonemptyUkiSection(&inspection, ".uname");
    const cmdline = try requireNonemptyUkiSection(&inspection, ".cmdline");

    var root_guid_text: [36]u8 = undefined;
    const root_guid = miz.guid.formatLower(
        &root_guid_text,
        root_partition.unique_partition_guid,
    );
    const expected_prefix = try std.fmt.allocPrint(
        allocator,
        "root=PARTUUID={s} ",
        .{root_guid},
    );
    defer allocator.free(expected_prefix);
    if (!std.mem.startsWith(u8, cmdline, expected_prefix))
        return error.UnexpectedUkiCmdline;

    switch (candidate.flavor) {
        .core => {
            const expected = try std.fmt.allocPrint(
                allocator,
                "{s}init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=auto mizinit.binder=required console=tty0 {s}",
                .{ expected_prefix, candidate.architecture.serialConsole() },
            );
            defer allocator.free(expected);
            if (!std.mem.eql(u8, cmdline, expected))
                return error.UnexpectedCoreUkiCmdline;
        },
        .full => {
            const expected = try std.fmt.allocPrint(
                allocator,
                "{s}{s}",
                .{ expected_prefix, candidate.architecture.serialConsole() },
            );
            defer allocator.free(expected);
            if (!std.mem.eql(u8, cmdline, expected))
                return error.UnexpectedFullUkiCmdline;
            if (std.mem.indexOf(u8, cmdline, "init=/sbin/mizinit") != null)
                return error.FullImageContainsMizinitBootContract;
        },
    }

    // The signed UKI exists once, at the path firmware loads. Assert the duplicate that used to sit
    // under EFI/Linux is absent rather than merely unread: two 62 MiB copies do not fit on this ESP,
    // so a reappearance is a build regression that would fail late, at the second write.
    const entries = esp.listDirAlloc(io, allocator, "EFI/Linux") catch |err| switch (err) {
        error.PathNotFound => return miz.artifact_pipeline.sha256Bytes(uki),
        else => return err,
    };
    defer miz.fat32.freeDirEntries(allocator, entries);
    for (entries) |entry| {
        if (entry.kind != .file or entry.name.len <= 4 or
            !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".efi"))
        {
            continue;
        }
        return error.StaleNamedUkiPresent;
    }
    return miz.artifact_pipeline.sha256Bytes(uki);
}

const qemu_user_data_template =
    \\#cloud-config
    \\bootcmd:
    \\  - [systemctl, mask, --runtime, --now, fwupd.service, fwupd-refresh.service]
    \\users:
    \\  - default
    \\  - name: miztest
    \\    groups: sudo
    \\    shell: /bin/bash
    \\    sudo: "ALL=(ALL) NOPASSWD:ALL"
    \\    ssh_authorized_keys:
    \\      - {s}
    \\ssh_pwauth: false
    \\disable_root: true
    \\
;

fn createSeed(
    allocator: Allocator,
    io: Io,
    ssh_keygen_path: []const u8,
    instance: *const Instance,
) !void {
    try runCommand(allocator, io, &.{
        ssh_keygen_path,
        "-q",
        "-t",
        "ed25519",
        "-N",
        "",
        "-f",
        instance.private_key_path,
    });
    const public_key_file = try Dir.cwd().readFileAlloc(
        io,
        instance.public_key_path,
        allocator,
        .limited(16 * 1024),
    );
    defer allocator.free(public_key_file);
    const public_key = std.mem.trim(u8, public_key_file, " \t\r\n");

    const metadata = try std.fmt.allocPrint(
        allocator,
        "instance-id: miz-ubuntu2604-acceptance-{s}\n" ++
            "local-hostname: miz-ubuntu2604-{s}\n",
        .{ instance.label, instance.label },
    );
    defer allocator.free(metadata);
    const user_data = try std.fmt.allocPrint(
        allocator,
        qemu_user_data_template,
        .{public_key},
    );
    defer allocator.free(user_data);
    const ovf_env = try std.fmt.allocPrint(
        allocator,
        \\<?xml version="1.0" encoding="utf-8"?>
        \\<Environment xmlns="http://schemas.dmtf.org/ovf/environment/1" xmlns:wa="http://schemas.microsoft.com/windowsazure">
        \\  <wa:ProvisioningSection>
        \\    <LinuxProvisioningConfigurationSet xmlns="http://schemas.microsoft.com/windowsazure">
        \\      <ConfigurationSetType>LinuxProvisioningConfiguration</ConfigurationSetType>
        \\      <HostName>miz-ubuntu2604-{s}</HostName>
        \\      <UserName>{s}</UserName>
        \\      <DisableSshPasswordAuthentication>true</DisableSshPasswordAuthentication>
        \\      <SSH><PublicKeys><PublicKey><Path>/home/{s}/.ssh/authorized_keys</Path><Value>{s}</Value></PublicKey></PublicKeys></SSH>
        \\    </LinuxProvisioningConfigurationSet>
        \\  </wa:ProvisioningSection>
        \\</Environment>
        \\
    ,
        .{ instance.label, admin_username, admin_username, public_key },
    );
    defer allocator.free(ovf_env);

    const additional_files = [_]miz.iso9660.NoCloudSeedAdditionalFile{
        .{ .name = "ovf-env.xml", .contents = ovf_env },
        .{ .name = "miz-local-provisioning", .contents = "" },
    };
    _ = try miz.iso9660.writeNoCloudSeedPath(allocator, io, instance.seed_path, .{
        .meta_data = metadata,
        .user_data = user_data,
        .additional_files = &additional_files,
    });
}

test "QEMU seed runtime-masks hardware firmware update services" {
    try std.testing.expect(
        std.mem.indexOf(
            u8,
            qemu_user_data_template,
            "[systemctl, mask, --runtime, --now, fwupd.service, fwupd-refresh.service]",
        ) != null,
    );
}

fn startInstance(
    allocator: Allocator,
    io: Io,
    qemu_img_path: []const u8,
    qemu_path: []const u8,
    swtpm_path: []const u8,
    ssh_keygen_path: []const u8,
    firmware: *const Firmware,
    vars_template_path: []const u8,
    source_image: []const u8,
    candidate: Candidate,
    secure_boot: bool,
    instance: *Instance,
) !void {
    try runCommand(allocator, io, &.{
        qemu_img_path,
        "create",
        "-q",
        "-f",
        "qcow2",
        "-F",
        "qcow2",
        "-b",
        source_image,
        instance.overlay_path,
    });
    try runCommand(allocator, io, &.{
        qemu_img_path,
        "resize",
        instance.overlay_path,
        "+2G",
    });
    try Dir.copyFileAbsolute(vars_template_path, instance.vars_path, io, .{
        .replace = false,
    });
    try createSeed(allocator, io, ssh_keygen_path, instance);
    try Dir.cwd().createDir(io, instance.swtpm_state_path, .default_dir);

    const swtpm_state_arg = try std.fmt.allocPrint(
        allocator,
        "dir={s}",
        .{instance.swtpm_state_path},
    );
    defer allocator.free(swtpm_state_arg);
    const swtpm_ctrl_arg = try std.fmt.allocPrint(
        allocator,
        "type=unixio,path={s}",
        .{instance.swtpm_socket_path},
    );
    defer allocator.free(swtpm_ctrl_arg);
    const swtpm_log_arg = try std.fmt.allocPrint(
        allocator,
        "file={s}",
        .{instance.swtpm_log_path},
    );
    defer allocator.free(swtpm_log_arg);
    instance.swtpm_child = try std.process.spawn(io, .{
        .argv = &.{
            swtpm_path,
            "socket",
            "--tpm2",
            "--tpmstate",
            swtpm_state_arg,
            "--ctrl",
            swtpm_ctrl_arg,
            "--log",
            swtpm_log_arg,
            "--flags",
            "not-need-init,startup-clear",
            "--terminate",
        },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .inherit,
    });
    const swtpm_deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(10));
    while (!try qemu_host.pathAccessible(io, instance.swtpm_socket_path, .{})) {
        if (Io.Clock.awake.now(io).nanoseconds >= swtpm_deadline.nanoseconds)
            return error.SwtpmSocketTimedOut;
        try Io.sleep(io, .fromMilliseconds(50), .awake);
    }

    const hostfwd = try std.fmt.allocPrint(
        allocator,
        "user,id=net0,hostfwd=tcp:127.0.0.1:{d}-:22",
        .{instance.port},
    );
    defer allocator.free(hostfwd);
    const serial_arg = try std.fmt.allocPrint(allocator, "file:{s}", .{instance.serial_path});
    defer allocator.free(serial_arg);
    const code_drive = try std.fmt.allocPrint(
        allocator,
        "if=pflash,unit=0,format=raw,readonly=on,file={s}",
        .{firmware.code_path},
    );
    defer allocator.free(code_drive);
    const vars_drive = try std.fmt.allocPrint(
        allocator,
        "if=pflash,unit=1,format=raw,file={s}",
        .{instance.vars_path},
    );
    defer allocator.free(vars_drive);
    const image_drive = try std.fmt.allocPrint(
        allocator,
        "file={s},format=qcow2,if=virtio",
        .{instance.overlay_path},
    );
    defer allocator.free(image_drive);
    const seed_drive = try std.fmt.allocPrint(
        allocator,
        "file={s},if=none,id=seed,media=cdrom,readonly=on,format=raw",
        .{instance.seed_path},
    );
    defer allocator.free(seed_drive);
    const tpm_chardev = try std.fmt.allocPrint(
        allocator,
        "socket,id=chrtpm,path={s}",
        .{instance.swtpm_socket_path},
    );
    defer allocator.free(tpm_chardev);

    var qemu_args: std.ArrayListUnmanaged([]const u8) = .empty;
    defer qemu_args.deinit(allocator);
    try qemu_args.appendSlice(allocator, &.{
        "-machine",
        candidate.architecture.machineArg(secure_boot),
    });
    if (instance.execution_profile.accelerator == .tcg) {
        try qemu_args.appendSlice(allocator, &.{
            "-accel",
            instance.execution_profile.accelerator_argument,
        });
    }
    try qemu_args.appendSlice(allocator, &.{
        "-cpu",
        instance.execution_profile.cpu,
        "-smp",
        "2",
        "-m",
        "2048",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        serial_arg,
        "-no-shutdown",
        "-drive",
        code_drive,
        "-drive",
        vars_drive,
        "-drive",
        image_drive,
        "-device",
        "virtio-scsi-pci,id=scsi0",
        "-drive",
        seed_drive,
        "-device",
        "scsi-cd,drive=seed,bus=scsi0.0",
        "-chardev",
        tpm_chardev,
        "-tpmdev",
        "emulator,id=tpm0,chardev=chrtpm",
        "-device",
        candidate.architecture.tpmDevice(),
        "-netdev",
        hostfwd,
        "-device",
        "virtio-net-pci,netdev=net0,romfile=",
        "-device",
        "virtio-rng-pci",
    });
    if (secure_boot and candidate.architecture == .x86_64) {
        try qemu_args.appendSlice(allocator, &.{
            "-global",
            "driver=cfi.pflash01,property=secure,value=on",
        });
    }

    instance.spawned = try qmp.spawnAndConnect(allocator, io, .{
        .binary = qemu_path,
        .qmp_socket_path = instance.qmp_socket_path,
        .connect_timeout = .fromSeconds(
            instance.execution_profile.timeouts.qmp_connect_seconds,
        ),
        .extra_args = qemu_args.items,
        .stdout = .ignore,
        .stderr = .inherit,
    });
}

fn commandSucceeded(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
) !bool {
    return commandSucceededWithin(allocator, io, argv, 20);
}

fn commandSucceededWithin(
    allocator: Allocator,
    io: Io,
    argv: []const []const u8,
    timeout_seconds: i64,
) !bool {
    const result = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(512 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(timeout_seconds),
            .clock = .awake,
        } },
    }) catch return false;
    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);
    return switch (result.term) {
        .exited => |code| code == 0,
        else => false,
    };
}

fn sshSucceeded(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    command: []const u8,
) !bool {
    return sshSucceededWithin(
        allocator,
        io,
        ssh_path,
        instance,
        command,
        instance.execution_profile.timeouts.ssh_command_seconds,
    );
}

fn sshSucceededWithin(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    command: []const u8,
    timeout_seconds: i64,
) !bool {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
    const connect_timeout = try std.fmt.allocPrint(
        allocator,
        "ConnectTimeout={d}",
        .{instance.execution_profile.timeouts.ssh_connect_seconds},
    );
    defer allocator.free(connect_timeout);
    return commandSucceededWithin(allocator, io, &.{
        ssh_path,
        "-i",
        instance.private_key_path,
        "-p",
        port_text,
        "-o",
        "BatchMode=yes",
        "-o",
        connect_timeout,
        "-o",
        "ConnectionAttempts=1",
        "-o",
        "IdentitiesOnly=yes",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "NumberOfPasswordPrompts=0",
        "-o",
        "PreferredAuthentications=publickey",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        admin_username ++ "@127.0.0.1",
        command,
    }, timeout_seconds);
}

fn normalizeSshRunError(err: anyerror) anyerror {
    return if (err == error.Timeout) error.SshCommandFailed else err;
}

fn sshOutputAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    command: []const u8,
) ![]u8 {
    return sshOutputAllocWithin(
        allocator,
        io,
        ssh_path,
        instance,
        command,
        instance.execution_profile.timeouts.ssh_command_seconds,
    );
}

fn sshOutputAllocWithin(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    command: []const u8,
    timeout_seconds: i64,
) ![]u8 {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
    const connect_timeout = try std.fmt.allocPrint(
        allocator,
        "ConnectTimeout={d}",
        .{instance.execution_profile.timeouts.ssh_connect_seconds},
    );
    defer allocator.free(connect_timeout);
    const result = std.process.run(allocator, io, .{
        .argv = &.{
            ssh_path,
            "-i",
            instance.private_key_path,
            "-p",
            port_text,
            "-o",
            "BatchMode=yes",
            "-o",
            connect_timeout,
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            admin_username ++ "@127.0.0.1",
            command,
        },
        .stdout_limit = .limited(512 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(timeout_seconds),
            .clock = .awake,
        } },
    }) catch |err| return normalizeSshRunError(err);
    switch (result.term) {
        .exited => |code| if (code == 0) {
            allocator.free(result.stderr);
            return result.stdout;
        },
        else => {},
    }
    if (result.stdout.len != 0) {
        std.debug.print("SSH command stdout for {s}:\n{s}\n", .{
            instance.label,
            result.stdout,
        });
    }
    if (result.stderr.len != 0) {
        std.debug.print("SSH command stderr for {s}:\n{s}\n", .{
            instance.label,
            result.stderr,
        });
    }
    allocator.free(result.stderr);
    allocator.free(result.stdout);
    return error.SshCommandFailed;
}

test "SSH process timeouts are command failures" {
    try std.testing.expect(
        normalizeSshRunError(error.Timeout) == error.SshCommandFailed,
    );
    try std.testing.expect(
        normalizeSshRunError(error.AccessDenied) == error.AccessDenied,
    );
}

fn efiDbContainsCertificate(
    variable: []const u8,
    certificate_sha256: miz.artifact_pipeline.Digest,
) bool {
    const efi_cert_x509_guid = [_]u8{
        0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
        0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
    };
    if (variable.len < 4) return false;
    var list_offset: usize = 4;
    while (list_offset < variable.len) {
        if (variable.len - list_offset < 28) return false;
        const is_x509 = std.mem.eql(
            u8,
            variable[list_offset..][0..efi_cert_x509_guid.len],
            &efi_cert_x509_guid,
        );
        const list_size = std.mem.readInt(
            u32,
            variable[list_offset + 16 ..][0..4],
            .little,
        );
        const header_size = std.mem.readInt(
            u32,
            variable[list_offset + 20 ..][0..4],
            .little,
        );
        const signature_size = std.mem.readInt(
            u32,
            variable[list_offset + 24 ..][0..4],
            .little,
        );
        if (list_size < 28 or signature_size <= 16) return false;
        const list_end = std.math.add(usize, list_offset, list_size) catch return false;
        const signatures_start = std.math.add(
            usize,
            list_offset + 28,
            header_size,
        ) catch return false;
        if (list_end > variable.len or signatures_start > list_end) return false;
        const signatures_bytes = list_end - signatures_start;
        if (signatures_bytes == 0 or signatures_bytes % signature_size != 0)
            return false;
        var signature_offset = signatures_start;
        while (signature_offset < list_end) : (signature_offset += signature_size) {
            const certificate = variable[signature_offset + 16 .. signature_offset + signature_size];
            const digest = miz.artifact_pipeline.sha256Bytes(certificate);
            if (is_x509 and std.mem.eql(u8, &digest, &certificate_sha256)) return true;
        }
        list_offset = list_end;
    }
    return false;
}

const uefi_db_command =
    \\set -eu
    \\if ! mountpoint -q /sys/firmware/efi/efivars; then
    \\  sudo -n /usr/bin/mount -t efivarfs efivarfs /sys/firmware/efi/efivars
    \\fi
    \\sudo -n /bin/cat /sys/firmware/efi/efivars/db-*
;

fn verifyGuestSecureBoot(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    certificate_sha256: miz.artifact_pipeline.Digest,
) !void {
    const db = try sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        uefi_db_command,
    );
    defer allocator.free(db);
    if (!efiDbContainsCertificate(db, certificate_sha256)) {
        return error.SigningCertificateMissingFromDb;
    }

    const command = try std.fmt.allocPrint(
        allocator,
        \\set -eu
        \\secure_boot=$(od -An -t u1 -j 4 -N 1 /sys/firmware/efi/efivars/SecureBoot-* | tr -d ' ')
        \\test "$secure_boot" = 1
        \\if ! test -r /sys/kernel/security/lockdown; then
        \\  sudo -n /usr/bin/mount -t securityfs securityfs /sys/kernel/security
        \\fi
        \\grep -Eq '\[(integrity|confidentiality)\]' /sys/kernel/security/lockdown
        \\test -c /dev/tpm0
        \\test -c /dev/tpmrm0
        \\for module in crc_itu_t udf isofs; do
        \\  test -d "/sys/module/$module" || sudo -n /usr/sbin/modprobe "$module"
        \\  test -d "/sys/module/$module"
        \\done
        \\dmesg_output=$(sudo -n /usr/bin/dmesg) || exit 1
        \\if printf '%s\n' "$dmesg_output" | grep -Eiq 'module verification failed|Loading of unsigned module|Lockdown:.*unsigned'; then
        \\  exit 1
        \\fi
        \\
    ,
        .{},
    );
    defer allocator.free(command);
    const output = sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        command,
    ) catch {
        return error.GuestSecureBootContractFailed;
    };
    allocator.free(output);
}

// --- Binder workload native acceptance (core flavor only) ---
//
// These checks assume the finished core image loads `binder_linux` at boot,
// mounts binderfs at `binderfs_mount_point`, and creates the dynamic devices
// named in `binder_dynamic_device_names` inside it. `binder_linux` itself is
// already present in the pinned Ubuntu kernel module tree the core flavor
// installs (in-tree since Linux 4.9, shipped by the same `linux-azure`
// metapackage the core flavor already requires). The builder and mizinit
// enforce module autoload, the BinderFS mount, and dynamic-device creation
// before acceptance runs.
const binder_module_name = "binder_linux";
const binderfs_mount_point = "/dev/binderfs";
const binder_dynamic_device_names = [_][]const u8{ "binder", "hwbinder", "vndbinder" };
const binder_probe_remote_path = "/tmp/ubuntu2604-binder-probe";

// Satisfies both `signed-binder-module` and `binder-boot-required`: the
// module must already be loaded at boot, so unlike the optional modules
// checked in `verifyGuestSecureBoot`, there is no modprobe fallback here.
const signed_binder_module_checks =
    \\set -eu
    \\test -d /sys/module/binder_linux
    \\module_path=$(modinfo -n binder_linux)
    \\case "$module_path" in
    \\  /lib/modules/*/kernel/*|/usr/lib/modules/*/kernel/*) : ;;
    \\  *) exit 1 ;;
    \\esac
    \\case "$module_path" in
    \\  */updates/*) exit 1 ;;
    \\esac
    \\signer=$(modinfo -F signer binder_linux 2>/dev/null || true)
    \\sig_key=$(modinfo -F sig_key binder_linux 2>/dev/null || true)
    \\sig_hashalgo=$(modinfo -F sig_hashalgo binder_linux 2>/dev/null || true)
    \\test -n "$signer$sig_key$sig_hashalgo"
    \\taint=$(cat /sys/module/binder_linux/taint 2>/dev/null || true)
    \\test -z "$taint"
    \\dmesg_output=$(sudo -n /usr/bin/dmesg) || exit 1
    \\if printf '%s\n' "$dmesg_output" | grep -Eiq 'module verification failed|Loading of unsigned module|Lockdown:.*unsigned|anbox'; then
    \\  exit 1
    \\fi
;

fn verifyGuestSignedBinderModule(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const output = sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        signed_binder_module_checks,
    ) catch return error.GuestSignedBinderModuleContractFailed;
    allocator.free(output);
}

/// The contract requirements `binderfs-dynamic-devices` stands on: the mount
/// must be the real Binder filesystem and each dynamic device must be a live
/// character device. Naming them here keeps the contract's meaning visible at
/// the place the contract is asserted.
const binderfs_contract_requirements = [_][]const u8{
    "binderfs-mount",
    "binder-control-device",
    "binder-device",
    "binder-hwbinder-device",
    "binder-vndbinder-device",
};

/// `binderfs-dynamic-devices`, answered from the contract report. The shell
/// version needed `findmnt` in the guest purely so a test could read a
/// filesystem type; the probe reads `/proc/mounts` itself.
fn verifyGuestBinderfsDevices(report: *const RuntimeContractReport) !void {
    for (binderfs_contract_requirements) |id| {
        report.expectSatisfied(id) catch return error.GuestBinderfsDeviceContractFailed;
    }
}

fn sshWithStdinAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    command: []const u8,
    stdin_data: []const u8,
) ![]u8 {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
    const connect_timeout = try std.fmt.allocPrint(
        allocator,
        "ConnectTimeout={d}",
        .{instance.execution_profile.timeouts.ssh_connect_seconds},
    );
    defer allocator.free(connect_timeout);
    var child = try std.process.spawn(io, .{
        .argv = &.{
            ssh_path,
            "-i",
            instance.private_key_path,
            "-p",
            port_text,
            "-o",
            "BatchMode=yes",
            "-o",
            connect_timeout,
            "-o",
            "ConnectionAttempts=1",
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "KbdInteractiveAuthentication=no",
            "-o",
            "PasswordAuthentication=no",
            "-o",
            "NumberOfPasswordPrompts=0",
            "-o",
            "PreferredAuthentications=publickey",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            "UserKnownHostsFile=/dev/null",
            admin_username ++ "@127.0.0.1",
            command,
        },
        .stdin = .pipe,
        .stdout = .pipe,
        .stderr = .pipe,
    });
    defer child.kill(io);

    var stdin = child.stdin.?;
    child.stdin = null;
    try stdin.writeStreamingAll(io, stdin_data);
    stdin.close(io);

    var streams_buffer: Io.File.MultiReader.Buffer(2) = undefined;
    var streams: Io.File.MultiReader = undefined;
    streams.init(allocator, io, streams_buffer.toStreams(), &.{ child.stdout.?, child.stderr.? });
    defer streams.deinit();
    const stdout_reader = streams.reader(0);
    const stderr_reader = streams.reader(1);
    while (streams.fill(256, .none)) |_| {
        if (stdout_reader.buffered().len > 512 * 1024 or stderr_reader.buffered().len > 16 * 1024) {
            return error.SshStreamTooLarge;
        }
    } else |err| switch (err) {
        error.EndOfStream => {},
        else => return err,
    }
    try streams.checkAnyError();
    const term = try child.wait(io);
    const stdout = try streams.toOwnedSlice(0);
    errdefer allocator.free(stdout);
    const stderr = try streams.toOwnedSlice(1);
    defer allocator.free(stderr);
    switch (term) {
        .exited => |code| if (code == 0) return stdout,
        else => {},
    }
    if (stderr.len != 0) {
        std.debug.print("SSH command with stdin failed for {s}:\n{s}\n", .{
            instance.label,
            stderr,
        });
    }
    allocator.free(stdout);
    return error.SshCommandFailed;
}

/// Uploads a host-built static probe binary into the guest.
///
/// Shared by both probes so a second uploaded probe cannot acquire a second,
/// subtly different transfer path.
fn pushProbeBinary(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    host_path: []const u8,
    remote_path: []const u8,
) !void {
    const probe_bytes = try Dir.cwd().readFileAlloc(
        io,
        host_path,
        allocator,
        .limited(8 * 1024 * 1024),
    );
    defer allocator.free(probe_bytes);

    const encoded_len = std.base64.standard.Encoder.calcSize(probe_bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, probe_bytes);

    const push_command = try std.fmt.allocPrint(
        allocator,
        "base64 -d > {s} && chmod 0755 {s}",
        .{ remote_path, remote_path },
    );
    defer allocator.free(push_command);
    const output = try sshWithStdinAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        push_command,
        encoded,
    );
    allocator.free(output);
}

fn pushBinderProbeBinary(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    try pushProbeBinary(
        allocator,
        io,
        ssh_path,
        instance,
        binderProbeHostPath(),
        binder_probe_remote_path,
    );
}

fn binderProbeHostPath() []const u8 {
    return build_options.ubuntu2604_binder_probe_path;
}

const BinderProbeStatus = enum { ok, open_failed, ioctl_failed };

const BinderProbeLine = struct {
    device: []const u8,
    status: BinderProbeStatus,
};

/// Parses one `device=<path> status=(ok|open-failed|ioctl-failed)[ ...]`
/// line emitted by `tests/ubuntu2604_binder_probe.zig`. Pure and
/// allocation-free so it is directly unit-testable without KVM.
fn parseBinderProbeLine(line: []const u8) !BinderProbeLine {
    const device_prefix = "device=";
    if (!std.mem.startsWith(u8, line, device_prefix)) return error.UnparseableBinderProbeLine;
    const after_device = line[device_prefix.len..];
    const status_marker = " status=";
    const status_index = std.mem.indexOf(u8, after_device, status_marker) orelse
        return error.UnparseableBinderProbeLine;
    const device = after_device[0..status_index];
    if (device.len == 0) return error.UnparseableBinderProbeLine;
    const rest = after_device[status_index + status_marker.len ..];
    const status_end = std.mem.indexOfScalar(u8, rest, ' ') orelse rest.len;
    const status_text = rest[0..status_end];
    const status: BinderProbeStatus = if (std.mem.eql(u8, status_text, "ok"))
        .ok
    else if (std.mem.eql(u8, status_text, "open-failed"))
        .open_failed
    else if (std.mem.eql(u8, status_text, "ioctl-failed"))
        .ioctl_failed
    else
        return error.UnparseableBinderProbeLine;
    return .{ .device = device, .status = status };
}

/// Confirms every path in `expected_devices` appears exactly once in the
/// probe's stdout with `status=ok`. Pure aside from the small allocator-backed
/// lookup table, so failure cases (missing device, duplicate line, unusable
/// device, garbage output) are all directly unit-testable without KVM.
fn verifyBinderProbeOutput(
    allocator: Allocator,
    output: []const u8,
    expected_devices: []const []const u8,
) !void {
    var found = std.StringHashMap(BinderProbeStatus).init(allocator);
    defer found.deinit();

    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |raw_line| {
        const line = std.mem.trim(u8, raw_line, " \t\r");
        if (line.len == 0) continue;
        const parsed = try parseBinderProbeLine(line);
        if (found.contains(parsed.device)) return error.DuplicateBinderProbeDevice;
        try found.put(parsed.device, parsed.status);
    }

    for (expected_devices) |device| {
        const status = found.get(device) orelse return error.MissingBinderProbeDevice;
        if (status != .ok) return error.BinderDeviceNotUsable;
    }
}

fn verifyGuestBinderDeviceUsability(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    try pushBinderProbeBinary(allocator, io, ssh_path, instance);

    var device_paths: [binder_dynamic_device_names.len][]u8 = undefined;
    var built: usize = 0;
    defer for (device_paths[0..built]) |path| allocator.free(path);
    for (binder_dynamic_device_names, 0..) |name, i| {
        device_paths[i] = try std.fmt.allocPrint(
            allocator,
            "{s}/{s}",
            .{ binderfs_mount_point, name },
        );
        built = i + 1;
    }

    var command_buffer = std.array_list.Managed(u8).init(allocator);
    defer command_buffer.deinit();
    try command_buffer.appendSlice("sudo -n " ++ binder_probe_remote_path);
    for (device_paths) |path| {
        try command_buffer.append(' ');
        try command_buffer.appendSlice(path);
    }

    const output = try sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        command_buffer.items,
    );
    defer allocator.free(output);

    var expected: [binder_dynamic_device_names.len][]const u8 = undefined;
    for (device_paths, 0..) |path, i| expected[i] = path;
    verifyBinderProbeOutput(allocator, output, &expected) catch
        return error.GuestBinderDeviceUsabilityContractFailed;
}

// --- Runtime contract (core flavor only) ---
//
// Issue #677 step 2. The contract is evaluated inside the guest by a static
// probe rather than by shell utilities, so package minimization is never asked
// to keep `findmnt`, `od`, `grep`, or `mountpoint` alive for a test. One probe
// run answers the whole contract; the named contracts that used to run their
// own shell checks now read their verdict out of that one report.
const runtime_contract_probe_remote_path = "/tmp/ubuntu2604-runtime-contract-probe";

fn runtimeContractProbeHostPath() []const u8 {
    return build_options.ubuntu2604_runtime_contract_probe_path;
}

/// One guest's runtime-contract report, owned by the caller.
const RuntimeContractReport = struct {
    text: []u8,

    fn deinit(self: *RuntimeContractReport, allocator: Allocator) void {
        allocator.free(self.text);
        self.* = undefined;
    }

    /// Requires the named requirement to have been reported satisfied.
    ///
    /// A requirement the probe never mentioned is a failure, not a pass: a
    /// report that stopped early must never read as agreement.
    fn expectSatisfied(self: *const RuntimeContractReport, id: []const u8) !void {
        const status = runtime_contract.statusOf(self.text, id) orelse {
            std.debug.print("runtime contract probe never reported {s}\n", .{id});
            return error.GuestRuntimeContractFailed;
        };
        if (status != .ok) {
            std.debug.print(
                "runtime contract requirement {s} is {s}\n",
                .{ id, status.key() },
            );
            return error.GuestRuntimeContractFailed;
        }
    }
};

/// Uploads the probe, runs the whole contract, and refuses a report that does
/// not satisfy every guest requirement.
fn readGuestRuntimeContractAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !RuntimeContractReport {
    try pushProbeBinary(
        allocator,
        io,
        ssh_path,
        instance,
        runtimeContractProbeHostPath(),
        runtime_contract_probe_remote_path,
    );
    const output = try sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        "sudo -n " ++ runtime_contract_probe_remote_path ++ " contract",
    );
    errdefer allocator.free(output);
    var diagnostic: runtime_contract_document.Diagnostic = .{};
    runtime_contract_document.verifyProbeReport(output, &diagnostic) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.GuestRuntimeContractFailed;
    };
    return .{ .text = output };
}

/// The guest's own ext4 accounting for `path`, measured with `statfs` by the
/// same static probe, which is what lets the size inventory record a real
/// first-boot phase without a `df` in the final image.
fn readGuestFilesystemUsage(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    path: []const u8,
) !size_inventory.FilesystemUsage {
    const command = try std.fmt.allocPrint(
        allocator,
        "sudo -n {s} filesystem {s}",
        .{ runtime_contract_probe_remote_path, path },
    );
    defer allocator.free(command);
    const output = try sshOutputAlloc(allocator, io, ssh_path, instance, command);
    defer allocator.free(output);
    var diagnostic: runtime_contract_document.Diagnostic = .{};
    const line = runtime_contract_document.filesystemUsage(
        output,
        path,
        &diagnostic,
    ) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.GuestFilesystemAccountingFailed;
    };
    return .{
        .block_size = line.block_size,
        .total_blocks = line.total_blocks,
        .free_blocks = line.free_blocks,
        .total_inodes = line.total_inodes,
        .free_inodes = line.free_inodes,
    };
}

/// `dma-heap-device`, answered from the contract report rather than by
/// `sudo -n test -c/-r/-w` in a shell the final image should not have to keep.
fn verifyGuestDmaHeap(report: *const RuntimeContractReport) !void {
    report.expectSatisfied("dma-heap-system") catch
        return error.GuestDmaHeapContractFailed;
}

fn qemuRunning(instance: *const Instance, deadline: Io.Timestamp) !bool {
    const spawned = &(instance.spawned orelse return error.QemuNotStarted);
    return spawned.client.queryRunningUntil(deadline);
}

fn serialContains(
    allocator: Allocator,
    io: Io,
    instance: *const Instance,
    marker: []const u8,
) !bool {
    const serial = Dir.cwd().readFileAlloc(
        io,
        instance.serial_path,
        allocator,
        .limited(serial_limit),
    ) catch |err| switch (err) {
        error.FileNotFound => return false,
        else => return err,
    };
    defer allocator.free(serial);
    return std.ascii.indexOfIgnoreCase(serial, marker) != null;
}

fn waitForSerialMarker(
    allocator: Allocator,
    io: Io,
    instance: *const Instance,
    marker: []const u8,
    timeout_seconds: i64,
) !void {
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(timeout_seconds));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (try serialContains(allocator, io, instance, marker)) return;
        if (!try qemuRunning(instance, deadline)) return error.QemuExitedEarly;
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.SerialMarkerTimedOut;
}

fn waitForFirmwareRefusal(
    allocator: Allocator,
    io: Io,
    instance: *const Instance,
    timeout_seconds: i64,
) !void {
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(timeout_seconds));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (try serialContains(allocator, io, instance, "Security Violation") or
            try serialContains(allocator, io, instance, ": Access Denied"))
        {
            return;
        }
        if (!try qemuRunning(instance, deadline)) return error.QemuExitedEarly;
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.FirmwareRefusalTimedOut;
}

fn terminateInstance(instance: *Instance) !void {
    const spawned = &(instance.spawned orelse return error.QemuNotStarted);
    spawned.kill();
    instance.child_waited = true;
}

fn waitForSsh(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(
        instance.execution_profile.timeouts.guest_ready_seconds,
    ));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (try sshSucceededWithin(
            allocator,
            io,
            ssh_path,
            instance,
            "true",
            instance.execution_profile.timeouts.ssh_poll_seconds,
        )) return;
        if (!try qemuRunning(instance, deadline)) return error.QemuExitedEarly;
        try Io.sleep(io, .fromSeconds(2), .awake);
    }
    return error.SshTimedOut;
}

const identity_command =
    \\set -eu
    \\test -s /etc/machine-id
    \\test -s /etc/ssh/ssh_host_ed25519_key.pub
    \\cat /etc/machine-id
    \\set -- $(/usr/bin/ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub -E sha256)
    \\printf '%s\n' "$2"
    \\cat /proc/sys/kernel/random/boot_id
;

fn readGuestIdentityAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !GuestIdentity {
    const output = try sshOutputAlloc(allocator, io, ssh_path, instance, identity_command);
    defer allocator.free(output);
    var lines = std.mem.splitScalar(u8, output, '\n');
    const machine_id = std.mem.trim(u8, lines.next() orelse return error.InvalidGuestIdentity, " \t\r");
    const ssh_fingerprint = std.mem.trim(u8, lines.next() orelse return error.InvalidGuestIdentity, " \t\r");
    const boot_id = std.mem.trim(u8, lines.next() orelse return error.InvalidGuestIdentity, " \t\r");
    if (machine_id.len == 0 or ssh_fingerprint.len == 0 or boot_id.len == 0)
        return error.InvalidGuestIdentity;
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len != 0)
            return error.InvalidGuestIdentity;
    }

    const owned_machine_id = try allocator.dupe(u8, machine_id);
    errdefer allocator.free(owned_machine_id);
    const owned_ssh_fingerprint = try allocator.dupe(u8, ssh_fingerprint);
    errdefer allocator.free(owned_ssh_fingerprint);
    return .{
        .machine_id = owned_machine_id,
        .ssh_fingerprint = owned_ssh_fingerprint,
        .boot_id = try allocator.dupe(u8, boot_id),
    };
}

fn verifyAdminLogin(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const output = try sshOutputAlloc(allocator, io, ssh_path, instance, "id -un");
    defer allocator.free(output);
    if (!std.mem.eql(u8, std.mem.trim(u8, output, " \t\r\n"), admin_username))
        return error.UnexpectedAdminUsername;
}

fn verifyKeyOnlySsh(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
    const connect_timeout = try std.fmt.allocPrint(
        allocator,
        "ConnectTimeout={d}",
        .{instance.execution_profile.timeouts.ssh_connect_seconds},
    );
    defer allocator.free(connect_timeout);
    if (try commandSucceededWithin(allocator, io, &.{
        ssh_path,
        "-p",
        port_text,
        "-o",
        "BatchMode=yes",
        "-o",
        connect_timeout,
        "-o",
        "PreferredAuthentications=none",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "PasswordAuthentication=no",
        "-o",
        "KbdInteractiveAuthentication=no",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        admin_username ++ "@127.0.0.1",
        "true",
    }, instance.execution_profile.timeouts.ssh_command_seconds))
        return error.SshAcceptedWithoutKey;
    if (!try sshSucceeded(
        allocator,
        io,
        ssh_path,
        instance,
        "sudo -n sshd -T | grep -Fxq 'passwordauthentication no' && sudo -n sshd -T | grep -Fxq 'kbdinteractiveauthentication no'",
    )) return error.SshPasswordAuthenticationEnabled;
}

const core_checks =
    \\set -eu
    \\sudo -n /usr/bin/test /proc/1/exe -ef /sbin/mizinit
    \\test -x /usr/sbin/azagent
    \\test -f /var/lib/azagent/provisioned
    \\test "$( . /etc/os-release; printf '%s' "$ID")" = ubuntu
    \\test "$( . /etc/os-release; printf '%s' "$VERSION_ID")" = 26.04
    \\for path in \
    \\  /usr/bin/cloud-init /usr/sbin/cloud-init \
    \\  /usr/bin/waagent /usr/sbin/waagent /usr/sbin/WALinuxAgent.py \
    \\  /etc/cloud /var/lib/cloud /var/lib/waagent \
    \\  /usr/lib/python3/dist-packages/cloudinit \
    \\  /usr/lib/python3/dist-packages/azurelinuxagent
    \\do
    \\  test ! -e "$path"
    \\done
    \\self=$$
    \\for proc in /proc/[0-9]*; do
    \\  test "${proc##*/}" = "$self" && continue
    \\  test -r "$proc/cmdline" || continue
    \\  cmdline=$(tr '\000' ' ' < "$proc/cmdline")
    \\  exe=$(readlink "$proc/exe" 2>/dev/null || true)
    \\  test "$exe" != /usr/sbin/azagent
    \\  cloud=cloud init=init wa=wa agent=agent upper=WALinux agent_name=Agent
    \\  case "$cmdline" in
    \\    *"$cloud-$init"*|*"$wa$agent"*|*"$upper$agent_name"*) exit 1 ;;
    \\  esac
    \\done
    \\for status in /proc/[0-9]*/status; do
    \\  test -r "$status" || continue
    \\  ppid= state=
    \\  while read -r key value _; do
    \\    case "$key" in
    \\      PPid:) ppid=$value ;;
    \\      State:) state=$value ;;
    \\    esac
    \\  done < "$status"
    \\  test "$ppid" != 1 || test "$state" != Z
    \\done
    \\find_sshd_master() {
    \\  for proc in /proc/[0-9]*; do
    \\    test -r "$proc/status" || continue
    \\    name= ppid=
    \\    while read -r key value _; do
    \\      case "$key" in
    \\        Name:) name=$value ;;
    \\        PPid:) ppid=$value ;;
    \\      esac
    \\    done < "$proc/status"
    \\    test "$name" = sshd && test "$ppid" = 1 || continue
    \\    cmdline=$(tr '\000' ' ' < "$proc/cmdline")
    \\    case "$cmdline" in
    \\      *"/usr/sbin/sshd -D -e"*) printf '%s\n' "${proc##*/}"; return 0 ;;
    \\    esac
    \\  done
    \\  return 1
    \\}
    \\find_sshd_master
;

fn readCoreSshdPid(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !i32 {
    const output = try sshOutputAlloc(allocator, io, ssh_path, instance, core_checks);
    defer allocator.free(output);
    const pid_text = std.mem.trim(u8, output, " \t\r\n");
    return std.fmt.parseInt(i32, pid_text, 10) catch error.InvalidSshdPid;
}

/// The full-flavor service contract, run as one guest shell script.
///
/// It waits for cloud-init here but deliberately does not decide whether the
/// run finished: the status document is fetched separately by
/// `verifyGuestCloudInitStatus` and judged by this test process, so the guest
/// needs no interpreter and no JSON tooling of its own.
const full_checks =
    \\set -eu
    \\check() {
    \\  label=$1
    \\  shift
    \\  if "$@"; then
    \\    printf 'PASS %s\n' "$label"
    \\  else
    \\    status=$?
    \\    printf 'FAIL %s (exit %s)\n' "$label" "$status" >&2
    \\    return "$status"
    \\  fi
    \\}
    \\diagnose_unit() {
    \\  unit=$1
    \\  {
    \\    printf '%s\n' "--- bounded diagnostics for $unit ---"
    \\    systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,TimeoutStartUSec "$unit"
    \\    sudo -n journalctl --no-pager --boot=0 --unit "$unit" --priority=info..emerg --lines=120 --output=short-monotonic
    \\  } 2>&1 | head -c 49152 >&2 || true
    \\  printf '\n' >&2
    \\}
    \\diagnose_failed_units() {
    \\  printf '%s\n' "$failed_units" |
    \\    awk 'NF { print $1 }' |
    \\    head -n 8 |
    \\    while IFS= read -r unit; do diagnose_unit "$unit"; done
    \\}
    \\check_service() {
    \\  unit=$1
    \\  check "service-active:$unit" systemctl is-active --quiet "$unit" || {
    \\    diagnose_unit "$unit"
    \\    return 1
    \\  }
    \\  check "service-enabled:$unit" systemctl is-enabled --quiet "$unit" || {
    \\    diagnose_unit "$unit"
    \\    return 1
    \\  }
    \\}
    \\package_installed() {
    \\  package=$1
    \\  test "$(dpkg-query -W -f='${db:Status-Status}' "$package" 2>/dev/null)" = installed
    \\}
    \\check pid1-systemd sudo -n /usr/bin/test /proc/1/exe -ef /usr/lib/systemd/systemd
    \\check mizinit-sbin-absent test ! -e /sbin/mizinit
    \\check mizinit-usr-bin-absent test ! -e /usr/bin/mizinit
    \\check os-release-readable test -r /etc/os-release
    \\. /etc/os-release
    \\check os-id-ubuntu test "$ID" = ubuntu
    \\check os-version-26.04 test "$VERSION_ID" = 26.04
    \\check cloud-init-wait cloud-init status --wait
    \\for unit in cloud-init-local.service cloud-init-network.service cloud-config.service cloud-final.service walinuxagent.service ssh.service systemd-networkd.service networkd-dispatcher.service; do
    \\  check_service "$unit"
    \\done
    \\check udisks2-installed package_installed udisks2
    \\check udisks2-dbus-service test -r /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
    \\check udisks2-dbus-name grep -Fxq 'Name=org.freedesktop.UDisks2' /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
    \\check udisks2-systemd-activation grep -Fxq 'SystemdService=udisks2.service' /usr/share/dbus-1/system-services/org.freedesktop.UDisks2.service
    \\check udisks2-unit-loaded test "$(systemctl show --property=LoadState --value udisks2.service)" = loaded
    \\check udisks2-graphical-eager-start-absent test ! -e /etc/systemd/system/graphical.target.wants/udisks2.service
    \\netplan_network=$(find /run/systemd/network -maxdepth 1 -name '10-netplan-*.network' -print -quit)
    \\check netplan-network-generated test -n "$netplan_network"
    \\check network-online systemctl is-active --quiet network-online.target
    \\check waagent-provisioning-agent grep -Eq '^[[:space:]]*Provisioning.Agent[[:space:]]*=[[:space:]]*auto[[:space:]]*$' /etc/waagent.conf
    \\check waagent-resource-disk-format grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
    \\check cloud-init-instance-state test -s /var/lib/cloud/instance/obj.pkl
    \\failed_units=$(systemctl --failed --no-legend --plain)
    \\check no-failed-units test -z "$failed_units" || {
    \\  printf '%s\n' "$failed_units" >&2
    \\  diagnose_failed_units
    \\  exit 1
    \\}
;

/// Retrieves the cloud-init status document verbatim.
///
/// The guest only prints bytes: `--wait` has already been satisfied by
/// `full_checks`, so this reads the recorded result. `cloud-init status` exits
/// nonzero when the run is not clean, and that exit status is deliberately
/// discarded here so the document -- which is what the verdict is made from --
/// still reaches the test process; anything cloud-init writes to stderr stays
/// on stderr, where `sshOutputAlloc` prints it if the query fails. Output that
/// is empty (cloud-init missing, killed, or silent) fails the remote command
/// outright rather than reaching the parser as a plausible-looking success.
const cloud_init_status_command =
    \\set -eu
    \\status_document=$(cloud-init status --format json || true)
    \\test -n "$status_document"
    \\printf '%s\n' "$status_document"
;

/// Largest cloud-init status document accepted. The real document is a few
/// hundred bytes; the bound keeps a runaway or hostile guest from feeding an
/// unbounded document to the JSON parser.
const cloud_init_status_max_bytes: usize = 64 * 1024;

/// How much of a rejected status document is worth printing.
const cloud_init_status_excerpt_bytes: usize = 512;

/// The part of a rejected status document to show in a diagnostic: trimmed,
/// and bounded so a runaway guest cannot flood the test log. Pure and
/// unit-tested.
fn cloudInitStatusExcerpt(document: []const u8) []const u8 {
    const trimmed = std.mem.trim(u8, document, " \t\r\n");
    return trimmed[0..@min(trimmed.len, cloud_init_status_excerpt_bytes)];
}

/// Decides, in this process, whether the guest's cloud-init run completed.
///
/// `document` is the raw `cloud-init status --format json` output. The check
/// is strict and fails closed, with a distinct error for every way the answer
/// can fail to be a confirmed completion: an empty document, one larger than
/// `cloud_init_status_max_bytes`, malformed JSON (duplicate keys included),
/// a top level that is not an object, an absent `status`, a `status` that is
/// not a string, and any status other than exactly `done`. Only the parser's
/// allocator is used, so every failure mode is directly unit-testable without
/// KVM.
fn verifyCloudInitStatusDone(allocator: Allocator, document: []const u8) !void {
    const trimmed = std.mem.trim(u8, document, " \t\r\n");
    if (trimmed.len == 0) return error.CloudInitStatusEmpty;
    if (trimmed.len > cloud_init_status_max_bytes) return error.CloudInitStatusTooLarge;

    var parsed = std.json.parseFromSlice(std.json.Value, allocator, trimmed, .{
        .duplicate_field_behavior = .@"error",
        .max_value_len = cloud_init_status_max_bytes,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.CloudInitStatusMalformed,
    };
    defer parsed.deinit();

    const object = switch (parsed.value) {
        .object => |object| object,
        else => return error.CloudInitStatusNotAnObject,
    };
    const value = object.get("status") orelse return error.CloudInitStatusMissing;
    const status = switch (value) {
        .string => |text| text,
        else => return error.CloudInitStatusNotAString,
    };
    if (!std.mem.eql(u8, status, "done")) return error.CloudInitStatusNotDone;
}

/// Fetches the guest's cloud-init status document and judges it here. A failed
/// query is a failure, never an unknown status, and a rejected document is
/// printed (bounded) so the acceptance log names what the guest actually said.
fn verifyGuestCloudInitStatus(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const document = sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        cloud_init_status_command,
    ) catch |err| switch (err) {
        error.SshCommandFailed => return error.CloudInitStatusQueryFailed,
        else => return err,
    };
    defer allocator.free(document);

    verifyCloudInitStatusDone(allocator, document) catch |err| {
        std.debug.print(
            "cloud-init status for {s} rejected ({s}); document was:\n{s}\n",
            .{ instance.label, @errorName(err), cloudInitStatusExcerpt(document) },
        );
        return err;
    };
}

fn verifyFlavorRuntime(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    candidate: Candidate,
    instance: *const Instance,
) !void {
    switch (candidate.flavor) {
        .core => _ = try readCoreSshdPid(allocator, io, ssh_path, instance),
        .full => {
            const output = sshOutputAllocWithin(
                allocator,
                io,
                ssh_path,
                instance,
                full_checks,
                instance.execution_profile.timeouts.ssh_long_command_seconds,
            ) catch |err| switch (err) {
                error.SshCommandFailed => return error.FullServiceContractFailed,
                else => return err,
            };
            allocator.free(output);
            try verifyGuestCloudInitStatus(allocator, io, ssh_path, instance);
        },
    }
}

fn verifyInitialGuestReady(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    candidate: Candidate,
    instance: *const Instance,
) !void {
    try waitForSsh(allocator, io, ssh_path, instance);
    try verifyAdminLogin(allocator, io, ssh_path, instance);
    try verifyKeyOnlySsh(allocator, io, ssh_path, instance);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, instance);
}

fn verifyCoreSshdRestart(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const initial_pid = try readCoreSshdPid(allocator, io, ssh_path, instance);
    const kill_command = try std.fmt.allocPrint(
        allocator,
        "sudo -n /usr/bin/kill -KILL {d}",
        .{initial_pid},
    );
    defer allocator.free(kill_command);
    _ = sshSucceeded(allocator, io, ssh_path, instance, kill_command) catch false;

    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(
        instance.execution_profile.timeouts.guest_ready_seconds,
    ));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (readCoreSshdPid(allocator, io, ssh_path, instance)) |new_pid| {
            if (new_pid != initial_pid) {
                try verifyAdminLogin(allocator, io, ssh_path, instance);
                try verifyKeyOnlySsh(allocator, io, ssh_path, instance);
                return;
            }
        } else |err| switch (err) {
            error.SshCommandFailed => {},
            else => return err,
        }
        if (!try qemuRunning(instance, deadline)) return error.QemuExitedEarly;
        try Io.sleep(io, .fromSeconds(2), .awake);
    }
    return error.SshdDidNotRestart;
}

const core_provisioned_state_command =
    \\set -eu
    \\account=
    \\while IFS=: read -r name _ uid gid _ home shell; do
    \\  if test "$name" = miztest; then
    \\    account="$name:$uid:$gid:$home:$shell"
    \\    break
    \\  fi
    \\done < /etc/passwd
    \\test -n "$account"
    \\printf '%s\n' "$account"
    \\set -- $(/usr/bin/ssh-keygen -lf /home/miztest/.ssh/authorized_keys -E sha256)
    \\printf '%s\n' "$2"
    \\sentinel=$(sudo -n /bin/cat /var/lib/azagent/provisioned)
    \\test -n "$sentinel"
    \\printf '%s\n' "$sentinel"
;

fn readCoreProvisionedStateAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !CoreProvisionedState {
    const output = try sshOutputAlloc(
        allocator,
        io,
        ssh_path,
        instance,
        core_provisioned_state_command,
    );
    defer allocator.free(output);
    var lines = std.mem.splitScalar(u8, output, '\n');
    const account = std.mem.trim(
        u8,
        lines.next() orelse return error.InvalidCoreProvisionedState,
        " \t\r",
    );
    const authorized_key_fingerprint = std.mem.trim(
        u8,
        lines.next() orelse return error.InvalidCoreProvisionedState,
        " \t\r",
    );
    const sentinel = std.mem.trim(
        u8,
        lines.next() orelse return error.InvalidCoreProvisionedState,
        " \t\r",
    );
    if (account.len == 0 or authorized_key_fingerprint.len == 0 or sentinel.len == 0)
        return error.InvalidCoreProvisionedState;
    while (lines.next()) |line| {
        if (std.mem.trim(u8, line, " \t\r").len != 0)
            return error.InvalidCoreProvisionedState;
    }

    const owned_account = try allocator.dupe(u8, account);
    errdefer allocator.free(owned_account);
    const owned_authorized_key_fingerprint = try allocator.dupe(
        u8,
        authorized_key_fingerprint,
    );
    errdefer allocator.free(owned_authorized_key_fingerprint);
    return .{
        .account = owned_account,
        .authorized_key_fingerprint = owned_authorized_key_fingerprint,
        .sentinel = try allocator.dupe(u8, sentinel),
    };
}

fn publicKeyFingerprintAlloc(
    allocator: Allocator,
    io: Io,
    ssh_keygen_path: []const u8,
    public_key_path: []const u8,
) ![]u8 {
    const output = try commandOutputAlloc(
        allocator,
        io,
        &.{ ssh_keygen_path, "-lf", public_key_path, "-E", "sha256" },
    );
    defer allocator.free(output);
    var tokens = std.mem.tokenizeAny(u8, output, " \t\r\n");
    _ = tokens.next() orelse return error.InvalidPublicKeyFingerprint;
    return allocator.dupe(
        u8,
        tokens.next() orelse return error.InvalidPublicKeyFingerprint,
    );
}

fn expectCoreProvisionedStateEqual(
    expected: *const CoreProvisionedState,
    actual: *const CoreProvisionedState,
) !void {
    try std.testing.expectEqualStrings(expected.account, actual.account);
    try std.testing.expectEqualStrings(
        expected.authorized_key_fingerprint,
        actual.authorized_key_fingerprint,
    );
    try std.testing.expectEqualStrings(expected.sentinel, actual.sentinel);
}

fn verifyRootGrowth(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    candidate: Candidate,
) !void {
    const original_size = candidate.expectedVirtualSize();
    const original_root_size = try expectedOriginalRootSize(candidate);
    const minimum_grown_root_size = try std.math.add(
        u64,
        original_root_size,
        gib,
    );
    const command = try std.fmt.allocPrint(
        allocator,
        \\set -eu
        \\root_source=$(readlink -f "$(findmnt -n -o SOURCE /)")
        \\root_disk=$(lsblk -n -o PKNAME "$root_source")
        \\test -n "$root_disk"
        \\test "$(sudo -n blockdev --getsize64 "/dev/$root_disk")" -gt {d}
        \\test "$(sudo -n blockdev --getsize64 "$root_source")" -gt {d}
        \\
    ,
        .{ original_size, minimum_grown_root_size },
    );
    defer allocator.free(command);
    if (!try sshSucceeded(allocator, io, ssh_path, instance, command))
        return error.RootGrowthContractFailed;
}

fn rebootAndReadIdentity(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    before: *const GuestIdentity,
) !GuestIdentity {
    _ = sshSucceeded(
        allocator,
        io,
        ssh_path,
        instance,
        "sudo -n /sbin/reboot",
    ) catch false;

    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(
        instance.execution_profile.timeouts.guest_ready_seconds,
    ));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (readGuestIdentityAlloc(allocator, io, ssh_path, instance)) |identity| {
            if (!std.mem.eql(u8, identity.boot_id, before.boot_id))
                return identity;
            var unchanged = identity;
            unchanged.deinit(allocator);
        } else |err| switch (err) {
            error.SshCommandFailed => {},
            else => return err,
        }
        if (!try qemuRunning(instance, deadline)) return error.QemuExitedEarly;
        try Io.sleep(io, .fromSeconds(2), .awake);
    }
    return error.RebootTimedOut;
}

fn waitForQemuExit(io: Io, instance: *Instance) !std.process.Child.Term {
    const spawned = &(instance.spawned orelse return error.QemuNotStarted);
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(
        instance.execution_profile.timeouts.guest_ready_seconds,
    ));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (!try spawned.client.queryRunningUntil(deadline)) {
            var reply = try spawned.client.executeUntil("quit", null, deadline);
            defer reply.deinit();
            if (reply.err != null) return error.QemuQuitFailed;
            const term = try spawned.waitUntil(deadline);
            instance.child_waited = true;
            return term;
        }
        try Io.sleep(io, .fromMilliseconds(500), .awake);
    }
    return error.QemuShutdownTimedOut;
}

fn poweroff(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *Instance,
) !void {
    _ = sshSucceeded(
        allocator,
        io,
        ssh_path,
        instance,
        "sudo -n /sbin/poweroff",
    ) catch false;
    const term = try waitForQemuExit(io, instance);
    switch (term) {
        .exited => |code| if (code == 0) return,
        else => {},
    }
    return error.QemuDidNotExitCleanly;
}

fn writeAcceptanceResultValue(
    allocator: Allocator,
    io: Io,
    result_path: []const u8,
    value: anytype,
) !void {
    const result = try std.json.Stringify.valueAlloc(
        allocator,
        value,
        .{ .whitespace = .indent_2 },
    );
    defer allocator.free(result);
    try Dir.cwd().writeFile(io, .{
        .sub_path = result_path,
        .data = result,
        .flags = .{ .truncate = true },
    });
}

/// Appends the measured `first_boot` phase to the candidate's size inventory.
///
/// Issue #678 measured everything a build and a publication can see, and left
/// `first_boot` for "a later stage that boots the image". This is that stage.
/// Two rules keep the result honest:
///
///   * The numbers come from the guest's own `statfs`, taken after the root has
///     grown, so they describe the filesystem that actually booted rather than
///     the geometry the builder wrote.
///   * The bound inventory in the candidate bundle is never edited. Its digest
///     is part of build provenance, and a document rewritten after the fact
///     would break that binding. The phase is appended to a copy, written to
///     the path the acceptance job asked for.
///
/// Both environment variables are optional: a developer running acceptance by
/// hand has no inventory to extend, and inventing one would be worse than
/// recording nothing.
fn recordFirstBootInventory(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    candidate: Candidate,
) !void {
    const source_path = try optionalEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_SIZE_INVENTORY",
    ) orelse return;
    defer allocator.free(source_path);
    const output_path = try optionalEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_FIRST_BOOT_INVENTORY",
    ) orelse return;
    defer allocator.free(output_path);

    const usage = try readGuestFilesystemUsage(allocator, io, ssh_path, instance, "/");

    var diagnostic: size_inventory.Diagnostic = .{};
    var parsed = size_inventory.readValidated(allocator, io, source_path, .{
        .architecture = @tagName(candidate.architecture),
        .flavor = @tagName(candidate.flavor),
        .required_phases = &.{ .root_build, .image_build, .publication },
    }, &diagnostic) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.SizeInventoryUnusable;
    };
    defer parsed.deinit();

    var arena: std.heap.ArenaAllocator = .init(allocator);
    defer arena.deinit();
    const section = size_inventory.firstBootValue(
        arena.allocator(),
        usage,
        &diagnostic,
    ) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.SizeInventoryUnusable;
    };
    const updated = size_inventory.appendPhaseAlloc(
        arena.allocator(),
        parsed.value,
        .first_boot,
        section,
        &diagnostic,
    ) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.SizeInventoryUnusable;
    };

    const text = try std.json.Stringify.valueAlloc(
        allocator,
        updated,
        .{ .whitespace = .indent_2 },
    );
    defer allocator.free(text);
    var document: std.ArrayList(u8) = .empty;
    defer document.deinit(allocator);
    try document.appendSlice(allocator, text);
    try document.append(allocator, '\n');
    try Dir.cwd().writeFile(io, .{ .sub_path = output_path, .data = document.items });

    // Re-read what was written, requiring the phase that was just added. A
    // document nobody re-validated is a document nobody has measured.
    var written = size_inventory.readValidated(allocator, io, output_path, .{
        .architecture = @tagName(candidate.architecture),
        .flavor = @tagName(candidate.flavor),
        .required_phases = &.{ .root_build, .image_build, .publication, .first_boot },
    }, &diagnostic) catch {
        std.debug.print("{s}\n", .{diagnostic.message()});
        return error.SizeInventoryUnusable;
    };
    written.deinit();
}

fn writeAcceptanceResult(
    allocator: Allocator,
    io: Io,
    result_path: []const u8,
    candidate: Candidate,
    source_sha256: miz.artifact_pipeline.Digest,
    certificate_sha256: miz.artifact_pipeline.Digest,
    uki_sha256: miz.artifact_pipeline.Digest,
    identity: *const AcceptanceResultIdentity,
    execution_profile: *const execution.Profile,
    qemu_path: []const u8,
) !void {
    if (!std.mem.eql(
        u8,
        @tagName(execution_profile.architecture),
        @tagName(candidate.architecture),
    ) or
        !std.mem.eql(u8, qemu_path, execution_profile.emulator))
    {
        return error.QemuExecutionIdentityMismatch;
    }
    const source_sha256_hex = miz.artifact_pipeline.formatSha256(source_sha256);
    const certificate_sha256_hex = miz.artifact_pipeline.formatSha256(
        certificate_sha256,
    );
    const uki_sha256_hex = miz.artifact_pipeline.formatSha256(uki_sha256);
    try writeAcceptanceResultValue(
        allocator,
        io,
        result_path,
        .{
            .schema = candidate.flavor.policy().result_schema,
            .type = "ubuntu2604-local-secure-boot-acceptance",
            .key = candidate.key(),
            .architecture = @tagName(candidate.architecture),
            .flavor = @tagName(candidate.flavor),
            .asset_name = candidate.expectedFileName(),
            .source_commit = identity.source_commit,
            .virtual_size = candidate.expectedVirtualSize(),
            .candidate_sha256 = &source_sha256_hex,
            .candidate_workflow = .{
                .run_id = identity.candidate_run_id,
                .run_attempt = identity.candidate_run_attempt,
            },
            .certificate_sha256 = &certificate_sha256_hex,
            .fallback_uki_sha256 = &uki_sha256_hex,
            .status = "success",
            .execution = .{
                .accelerator = @tagName(execution_profile.accelerator),
                .cpu = execution_profile.cpu,
                .emulator = qemu_path,
                .guest_architecture = @tagName(candidate.architecture),
                .machine = execution_profile.machine,
                .runner_architecture = execution_profile.runner_architecture,
            },
            .contracts = candidate.contracts(),
            .workflow = .{
                .run_id = identity.run_id,
                .run_attempt = identity.run_attempt,
            },
        },
    );
}

fn partitionFixture(
    table_index: u32,
    partition_type_guid: miz.guid.Guid,
    unique_partition_guid: miz.guid.Guid,
    first_lba: u64,
    last_lba: u64,
    name: []const u8,
) miz.gpt.PartitionEntry {
    var partition: miz.gpt.PartitionEntry = .{
        .table_index = table_index,
        .partition_type_guid = partition_type_guid,
        .unique_partition_guid = unique_partition_guid,
        .first_lba = first_lba,
        .last_lba = last_lba,
    };
    for (name, 0..) |byte, index| {
        partition.name_utf16le[index] = byte;
    }
    return partition;
}

test "Ubuntu 26.04 acceptance validates architecture-specific final GPT layouts" {
    const last_usable_lba: u64 = 10_485_726;
    const x86_64_partitions = [_]miz.gpt.PartitionEntry{
        partitionFixture(
            0,
            miz.guid.linux_root_x86_64,
            miz.guid.parse("11111111-1111-1111-1111-111111111111"),
            2_324_480,
            last_usable_lba,
            "cloudimg-rootfs",
        ),
        partitionFixture(
            12,
            miz.guid.linux_xbootldr,
            miz.guid.parse("22222222-2222-2222-2222-222222222222"),
            2_048,
            2_097_152,
            "",
        ),
        partitionFixture(
            13,
            miz.guid.bios_boot,
            miz.guid.parse("33333333-3333-3333-3333-333333333333"),
            2_099_200,
            2_107_391,
            "",
        ),
        partitionFixture(
            14,
            miz.guid.esp,
            miz.guid.parse("44444444-4444-4444-4444-444444444444"),
            2_107_392,
            2_324_479,
            "",
        ),
    };
    const x86_64 = try validatePreservedPartitions(
        &x86_64_partitions,
        .x86_64,
        last_usable_lba,
    );
    try std.testing.expectEqual(@as(u32, 0), x86_64.root.table_index);
    try std.testing.expectEqual(@as(u32, 12), x86_64.xbootldr.?.table_index);
    try std.testing.expectEqual(@as(u32, 13), x86_64.bios_boot.?.table_index);
    try std.testing.expectEqual(@as(u32, 14), x86_64.esp.table_index);

    const aarch64_partitions = [_]miz.gpt.PartitionEntry{
        partitionFixture(
            0,
            miz.guid.linux_root_aarch64,
            miz.guid.parse("55555555-5555-5555-5555-555555555555"),
            2_099_200,
            last_usable_lba,
            "cloudimg-rootfs",
        ),
        partitionFixture(
            14,
            miz.guid.esp,
            miz.guid.parse("77777777-7777-7777-7777-777777777777"),
            2_048,
            1_050_623,
            "",
        ),
    };
    const aarch64 = try validatePreservedPartitions(
        &aarch64_partitions,
        .aarch64,
        last_usable_lba,
    );
    try std.testing.expectEqual(@as(u32, 0), aarch64.root.table_index);
    try std.testing.expect(aarch64.xbootldr == null);
    try std.testing.expect(aarch64.bios_boot == null);
    try std.testing.expectEqual(@as(u32, 14), aarch64.esp.table_index);
}

test "Ubuntu 26.04 acceptance rejects synthetic or changed GPT substrates" {
    const last_usable_lba: u64 = 10_485_726;
    var partitions = [_]miz.gpt.PartitionEntry{
        partitionFixture(
            0,
            miz.guid.linux_root_x86_64,
            miz.guid.parse("11111111-1111-1111-1111-111111111111"),
            2_324_480,
            last_usable_lba,
            "cloudimg-rootfs",
        ),
        partitionFixture(
            12,
            miz.guid.linux_xbootldr,
            miz.guid.parse("22222222-2222-2222-2222-222222222222"),
            2_048,
            2_097_152,
            "",
        ),
        partitionFixture(
            13,
            miz.guid.bios_boot,
            miz.guid.parse("33333333-3333-3333-3333-333333333333"),
            2_099_200,
            2_107_391,
            "",
        ),
        partitionFixture(
            14,
            miz.guid.esp,
            miz.guid.parse("44444444-4444-4444-4444-444444444444"),
            2_107_392,
            2_324_479,
            "",
        ),
    };
    try std.testing.expectError(
        error.UnexpectedPartitionCount,
        validatePreservedPartitions(
            &.{ partitions[0], partitions[3] },
            .x86_64,
            last_usable_lba,
        ),
    );

    partitions[0].partition_type_guid = miz.guid.linux_root_aarch64;
    try std.testing.expectError(
        error.UnexpectedRootArchitecture,
        validatePreservedPartitions(
            &partitions,
            .x86_64,
            last_usable_lba,
        ),
    );
    partitions[0].partition_type_guid = miz.guid.linux_root_x86_64;

    partitions[1].name_utf16le[0] = 'x';
    try std.testing.expectError(
        error.UnexpectedAuxiliaryPartitionName,
        validatePreservedPartitions(
            &partitions,
            .x86_64,
            last_usable_lba,
        ),
    );
    partitions[1].name_utf16le[0] = 0;

    partitions[3].unique_partition_guid = partitions[2].unique_partition_guid;
    try std.testing.expectError(
        error.DuplicatePartitionGuid,
        validatePreservedPartitions(
            &partitions,
            .x86_64,
            last_usable_lba,
        ),
    );
    partitions[3].unique_partition_guid =
        miz.guid.parse("44444444-4444-4444-4444-444444444444");

    partitions[3].last_lba -= 1;
    try std.testing.expectError(
        error.UnexpectedEspGeometry,
        validatePreservedPartitions(
            &partitions,
            .x86_64,
            last_usable_lba,
        ),
    );

    const aarch64_with_bios = [_]miz.gpt.PartitionEntry{
        partitionFixture(
            0,
            miz.guid.linux_root_aarch64,
            miz.guid.parse("55555555-5555-5555-5555-555555555555"),
            2_099_200,
            last_usable_lba,
            "cloudimg-rootfs",
        ),
        partitionFixture(
            13,
            miz.guid.bios_boot,
            miz.guid.parse("77777777-7777-7777-7777-777777777777"),
            204_801,
            206_847,
            "",
        ),
        partitionFixture(
            14,
            miz.guid.esp,
            miz.guid.parse("88888888-8888-8888-8888-888888888888"),
            2_048,
            1_050_623,
            "",
        ),
    };
    try std.testing.expectError(
        error.UnexpectedBiosBootPartition,
        validatePreservedPartitions(
            &aarch64_with_bios,
            .aarch64,
            last_usable_lba,
        ),
    );
}

test "Ubuntu 26.04 acceptance candidate names are exact" {
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.qcow2",
        (Candidate{ .architecture = .x86_64, .flavor = .full }).expectedFileName(),
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-aarch64.qcow2",
        (Candidate{ .architecture = .aarch64, .flavor = .full }).expectedFileName(),
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-x86_64.core.qcow2",
        (Candidate{ .architecture = .x86_64, .flavor = .core }).expectedFileName(),
    );
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-aarch64.core.qcow2",
        (Candidate{ .architecture = .aarch64, .flavor = .core }).expectedFileName(),
    );
}

test "Ubuntu 26.04 acceptance derives original root size from preserved GPT geometry" {
    try std.testing.expectEqual(
        @as(u64, 4_178_558_464),
        try expectedOriginalRootSize(.{
            .architecture = .x86_64,
            .flavor = .full,
        }),
    );
    try std.testing.expectEqual(
        @as(u64, 4_293_901_824),
        try expectedOriginalRootSize(.{
            .architecture = .aarch64,
            .flavor = .full,
        }),
    );
    try std.testing.expectEqual(
        @as(u64, 2_567_945_728),
        try expectedOriginalRootSize(.{
            .architecture = .x86_64,
            .flavor = .core,
        }),
    );
    try std.testing.expectEqual(
        @as(u64, 2_683_289_088),
        try expectedOriginalRootSize(.{
            .architecture = .aarch64,
            .flavor = .core,
        }),
    );
}

test "Ubuntu 26.04 acceptance flavor policy preserves full and isolates core" {
    const full = Candidate{ .architecture = .x86_64, .flavor = .full };
    const core = Candidate{ .architecture = .x86_64, .flavor = .core };
    try std.testing.expectEqual(@as(u64, 5 * gib), full.expectedVirtualSize());
    try std.testing.expectEqual(@as(u64, 3584 * mib), core.expectedVirtualSize());
    try std.testing.expect(core.expectedVirtualSize() < full.expectedVirtualSize());
    try std.testing.expectEqual(@as(u32, 4), full.flavor.policy().result_schema);
    try std.testing.expectEqual(@as(u32, 9), core.flavor.policy().result_schema);
    try std.testing.expectEqual(@as(usize, 18), full.contracts().len);
    try std.testing.expectEqual(@as(usize, 29), core.contracts().len);
    try std.testing.expect(hasContract(core.contracts(), "mizinit-sshd-supervision"));
    try std.testing.expect(hasContract(core.contracts(), "no-cloud-init"));
    try std.testing.expect(hasContract(core.contracts(), "signed-binder-module"));
    try std.testing.expect(hasContract(core.contracts(), "binder-boot-required"));
    try std.testing.expect(hasContract(core.contracts(), "binderfs-dynamic-devices"));
    try std.testing.expect(hasContract(core.contracts(), "binder-device-usability"));
    try std.testing.expect(hasContract(core.contracts(), "dma-heap-device"));
    try std.testing.expect(hasContract(core.contracts(), "runtime-contract"));
    try std.testing.expect(!hasContract(full.contracts(), "signed-binder-module"));
    try std.testing.expect(!hasContract(full.contracts(), "binder-boot-required"));
    try std.testing.expect(!hasContract(full.contracts(), "binderfs-dynamic-devices"));
    try std.testing.expect(!hasContract(full.contracts(), "binder-device-usability"));
    try std.testing.expect(!hasContract(full.contracts(), "dma-heap-device"));
    try std.testing.expect(!hasContract(full.contracts(), "runtime-contract"));
    for (core.contracts()) |contract| {
        try std.testing.expect(std.ascii.indexOfIgnoreCase(contract, "android") == null);
    }
}

test "core DMA-heap and BinderFS contracts are answered by the runtime contract" {
    // The shell versions of these checks needed `findmnt` and `test -c/-r/-w`
    // in the guest. They are now requirements in the contract the static probe
    // evaluates, which is what lets a later step remove those utilities.
    const dma_heap = runtime_contract.lookup("dma-heap-system").?;
    try std.testing.expectEqualStrings("/dev/dma_heap/system", dma_heap.target);
    try std.testing.expectEqual(runtime_contract.Kind.device, dma_heap.kind);
    try std.testing.expect(dma_heap.required());

    const mount = runtime_contract.lookup("binderfs-mount").?;
    try std.testing.expectEqualStrings(binderfs_mount_point, mount.target);
    try std.testing.expectEqualStrings("binder", mount.expect);
    for (binder_dynamic_device_names) |name| {
        var found = false;
        for (binderfs_contract_requirements) |id| {
            const entry = runtime_contract.lookup(id).?;
            if (std.mem.endsWith(u8, entry.target, name)) found = true;
        }
        try std.testing.expect(found);
    }
    for (binderfs_contract_requirements) |id| {
        const entry = runtime_contract.lookup(id).?;
        try std.testing.expect(entry.required());
        try std.testing.expectEqual(runtime_contract.Presence.runtime, entry.presence);
    }
}

test "a runtime contract report is read per requirement and refuses silence" {
    const allocator = std.testing.allocator;
    var text: std.ArrayList(u8) = .empty;
    defer text.deinit(allocator);
    for (runtime_contract.requirements()) |requirement| {
        if (!requirement.kind.probeable()) continue;
        const status = if (std.mem.eql(u8, requirement.id, "dma-heap-system"))
            "not-writable"
        else
            "ok";
        try text.print(
            allocator,
            "runtime-contract id={s} status={s}\n",
            .{ requirement.id, status },
        );
    }
    const report: RuntimeContractReport = .{ .text = text.items };
    try verifyGuestBinderfsDevices(&report);
    try std.testing.expectError(
        error.GuestDmaHeapContractFailed,
        verifyGuestDmaHeap(&report),
    );

    const empty: RuntimeContractReport = .{ .text = "" };
    try std.testing.expectError(
        error.GuestBinderfsDeviceContractFailed,
        verifyGuestBinderfsDevices(&empty),
    );
    try std.testing.expectError(
        error.GuestDmaHeapContractFailed,
        verifyGuestDmaHeap(&empty),
    );
}

test "Ubuntu 26.04 full acceptance result binds candidate and workflow identity" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    const candidate = Candidate{ .architecture = .aarch64, .flavor = .full };
    var identity: AcceptanceResultIdentity = .{
        .source_commit = try allocator.dupe(u8, "a" ** 40),
        .candidate_run_id = try allocator.dupe(u8, "90"),
        .candidate_run_attempt = try allocator.dupe(u8, "1"),
        .run_id = try allocator.dupe(u8, "100"),
        .run_attempt = try allocator.dupe(u8, "2"),
    };
    defer identity.deinit(allocator);
    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var root_buffer: [Dir.max_path_bytes]u8 = undefined;
    const root_length = try temporary.dir.realPath(io, &root_buffer);
    const result_path = try std.fs.path.join(
        allocator,
        &.{ root_buffer[0..root_length], "native-result.json" },
    );
    defer allocator.free(result_path);
    const source_digest: miz.artifact_pipeline.Digest = @splat(0x11);
    const certificate_digest: miz.artifact_pipeline.Digest = @splat(0x22);
    const uki_digest: miz.artifact_pipeline.Digest = @splat(0x33);
    try std.testing.expectError(
        error.QemuExecutionIdentityMismatch,
        writeAcceptanceResult(
            allocator,
            io,
            result_path,
            candidate,
            source_digest,
            certificate_digest,
            uki_digest,
            &identity,
            &execution.x86_64_kvm,
            execution.x86_64_kvm.emulator,
        ),
    );
    try writeAcceptanceResult(
        allocator,
        io,
        result_path,
        candidate,
        source_digest,
        certificate_digest,
        uki_digest,
        &identity,
        candidate.executionProfile(),
        candidate.executionProfile().emulator,
    );
    const text = try Dir.cwd().readFileAlloc(
        io,
        result_path,
        allocator,
        .limited(64 * 1024),
    );
    defer allocator.free(text);
    var parsed = try std.json.parseFromSlice(
        std.json.Value,
        allocator,
        text,
        .{},
    );
    defer parsed.deinit();
    const result = parsed.value.object;
    try std.testing.expectEqual(@as(i64, 4), result.get("schema").?.integer);
    try std.testing.expectEqualStrings("aarch64-full", result.get("key").?.string);
    try std.testing.expectEqualStrings("aarch64", result.get("architecture").?.string);
    try std.testing.expectEqualStrings(
        "Ubuntu-26.04-aarch64.qcow2",
        result.get("asset_name").?.string,
    );
    try std.testing.expectEqualStrings("a" ** 40, result.get("source_commit").?.string);
    try std.testing.expectEqualStrings("success", result.get("status").?.string);
    const candidate_workflow = result.get("candidate_workflow").?.object;
    try std.testing.expectEqualStrings(
        "90",
        candidate_workflow.get("run_id").?.string,
    );
    try std.testing.expectEqualStrings(
        "1",
        candidate_workflow.get("run_attempt").?.string,
    );
    const qemu = result.get("execution").?.object;
    try std.testing.expectEqualStrings("tcg", qemu.get("accelerator").?.string);
    try std.testing.expectEqualStrings("max", qemu.get("cpu").?.string);
    try std.testing.expectEqualStrings(
        "/usr/bin/qemu-system-aarch64",
        qemu.get("emulator").?.string,
    );
    try std.testing.expectEqualStrings(
        "aarch64",
        qemu.get("guest_architecture").?.string,
    );
    try std.testing.expectEqualStrings("virt", qemu.get("machine").?.string);
    try std.testing.expectEqualStrings(
        "aarch64",
        qemu.get("runner_architecture").?.string,
    );
    const workflow = result.get("workflow").?.object;
    try std.testing.expectEqualStrings("100", workflow.get("run_id").?.string);
    try std.testing.expectEqualStrings("2", workflow.get("run_attempt").?.string);
}

test "Ubuntu 26.04 configured QEMU prerequisites fail closed" {
    const x86 = Candidate{ .architecture = .x86_64, .flavor = .core };
    const arm = Candidate{ .architecture = .aarch64, .flavor = .core };

    try std.testing.expectError(
        error.QemuRequiresLinux,
        validateQemuPrerequisites(false, .x86_64, false, x86),
    );
    try std.testing.expectError(
        error.QemuRequiresMatchingHostArchitecture,
        validateQemuPrerequisites(true, .aarch64, false, x86),
    );
    try std.testing.expectError(
        error.KvmUnavailable,
        validateQemuPrerequisites(true, .x86_64, false, x86),
    );
    try validateQemuPrerequisites(true, .aarch64, null, arm);
    try std.testing.expectError(
        error.UnexpectedKvmCheckForTcg,
        validateQemuPrerequisites(true, .aarch64, true, arm),
    );
    try std.testing.expectEqual(execution.Accelerator.kvm, x86.executionProfile().accelerator);
    try std.testing.expectEqual(execution.Accelerator.tcg, arm.executionProfile().accelerator);
    try std.testing.expectEqualStrings(
        "tcg,thread=multi",
        arm.executionProfile().accelerator_argument,
    );
    try std.testing.expectEqualStrings("max", arm.executionProfile().cpu);
    try std.testing.expectError(
        error.RequiredToolNotFound,
        requireFoundTool(null, "not-a-real-ubuntu2604-acceptance-tool"),
    );
    try std.testing.expectError(
        error.RequiredFirmwareNotFound,
        requireFoundFirmware(null),
    );
}

test "initial guest launch policy serializes Arm TCG but keeps KVM concurrent" {
    const kvm_order = initialGuestLaunchOrder(
        execution.x86_64_kvm.initial_guest_launch,
    );
    const tcg_order = initialGuestLaunchOrder(
        execution.aarch64_tcg.initial_guest_launch,
    );
    try std.testing.expectEqualSlices(
        InitialGuestLaunchStep,
        &.{
            .start_first,
            .start_second,
            .first_ready,
            .second_ready,
        },
        &kvm_order,
    );
    try std.testing.expectEqualSlices(
        InitialGuestLaunchStep,
        &.{
            .start_first,
            .first_ready,
            .start_second,
            .second_ready,
        },
        &tcg_order,
    );
}

test "full service checks keep dispatcher strict and udisks D-Bus-only" {
    for ([_][]const u8{
        "networkd-dispatcher.service",
        "check udisks2-installed package_installed udisks2",
        "Name=org.freedesktop.UDisks2",
        "SystemdService=udisks2.service",
        "udisks2-graphical-eager-start-absent",
        "failed_units=$(systemctl --failed --no-legend --plain)",
        "check no-failed-units test -z",
        "systemctl show --no-pager --property=Id,LoadState,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus,TimeoutStartUSec",
        "sudo -n journalctl --no-pager --boot=0 --unit \"$unit\" --priority=info..emerg --lines=120",
        "head -c 49152",
        "head -n 8",
        "diagnose_failed_units\n  exit 1",
    }) |needle| {
        try std.testing.expect(std.mem.indexOf(u8, full_checks, needle) != null);
    }
    const cloud_init_wait = std.mem.indexOf(
        u8,
        full_checks,
        "check cloud-init-wait cloud-init status --wait",
    ).?;
    const service_checks = std.mem.indexOf(
        u8,
        full_checks,
        "for unit in cloud-init-local.service",
    ).?;
    try std.testing.expect(cloud_init_wait < service_checks);
    try std.testing.expect(std.mem.indexOf(u8, full_checks, "--property=Environment") == null);
}

test "EFI db parser finds the exact enrolled DER certificate" {
    const efi_cert_x509_guid = [_]u8{
        0xa1, 0x59, 0xc0, 0xa5, 0xe4, 0x94, 0xa7, 0x4a,
        0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72,
    };
    const certificate = "DER certificate";
    var variable = [_]u8{0} ** (4 + 28 + 16 + certificate.len);
    const list_offset = 4;
    @memcpy(variable[list_offset..][0..efi_cert_x509_guid.len], &efi_cert_x509_guid);
    std.mem.writeInt(
        u32,
        variable[list_offset + 16 ..][0..4],
        28 + 16 + certificate.len,
        .little,
    );
    std.mem.writeInt(u32, variable[list_offset + 20 ..][0..4], 0, .little);
    std.mem.writeInt(
        u32,
        variable[list_offset + 24 ..][0..4],
        16 + certificate.len,
        .little,
    );
    @memcpy(variable[list_offset + 28 + 16 ..], certificate);
    const digest = miz.artifact_pipeline.sha256Bytes(certificate);
    try std.testing.expect(efiDbContainsCertificate(&variable, digest));
    try std.testing.expect(!efiDbContainsCertificate(
        &variable,
        [_]u8{0xff} ** 32,
    ));
    try std.testing.expect(!efiDbContainsCertificate(variable[0 .. variable.len - 1], digest));
    variable[list_offset] = 0;
    try std.testing.expect(!efiDbContainsCertificate(&variable, digest));
}

test "Secure Boot evidence mounts efivarfs before reading db" {
    const mount_index = std.mem.indexOf(
        u8,
        uefi_db_command,
        "mount -t efivarfs efivarfs /sys/firmware/efi/efivars",
    ).?;
    const db_index = std.mem.indexOf(
        u8,
        uefi_db_command,
        "cat /sys/firmware/efi/efivars/db-*",
    ).?;
    try std.testing.expect(mount_index < db_index);
}

test "signed Binder module script pins the module tree and requires evidence" {
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, binder_module_name) != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "/sys/module/binder_linux") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "*/updates/*") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "modinfo -F signer") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "taint") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "anbox") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "modprobe") == null);
}

test "the core flavor carries a runtime-contract acceptance contract" {
    const core = Flavor.core;
    try std.testing.expect(hasContract(core.policy().contracts, "runtime-contract"));
    try std.testing.expect(!hasContract(Flavor.full.policy().contracts, "runtime-contract"));
    // Every acceptance-only convenience must be declared as such, so a package
    // is never retained because a test happened to use it.
    try std.testing.expect(runtime_contract.countFor(.acceptance_only) != 0);
    for (runtime_contract.requirements()) |requirement| {
        if (requirement.audience != .acceptance_only) continue;
        try std.testing.expect(!requirement.required());
    }
}

test "Binder probe line parser accepts every reported status" {
    const ok = try parseBinderProbeLine("device=/dev/binderfs/binder status=ok protocol_version=8");
    try std.testing.expectEqualStrings("/dev/binderfs/binder", ok.device);
    try std.testing.expectEqual(BinderProbeStatus.ok, ok.status);

    const open_failed = try parseBinderProbeLine("device=/dev/binderfs/hwbinder status=open-failed errno=13");
    try std.testing.expectEqualStrings("/dev/binderfs/hwbinder", open_failed.device);
    try std.testing.expectEqual(BinderProbeStatus.open_failed, open_failed.status);

    const ioctl_failed = try parseBinderProbeLine("device=/dev/binderfs/vndbinder status=ioctl-failed errno=25");
    try std.testing.expectEqualStrings("/dev/binderfs/vndbinder", ioctl_failed.device);
    try std.testing.expectEqual(BinderProbeStatus.ioctl_failed, ioctl_failed.status);

    // A trailing device with no fields after `status=` is still valid.
    const bare = try parseBinderProbeLine("device=/dev/binderfs/binder status=ok");
    try std.testing.expectEqual(BinderProbeStatus.ok, bare.status);
}

test "Binder probe line parser rejects malformed or unknown lines" {
    try std.testing.expectError(error.UnparseableBinderProbeLine, parseBinderProbeLine(""));
    try std.testing.expectError(error.UnparseableBinderProbeLine, parseBinderProbeLine("not a probe line"));
    try std.testing.expectError(
        error.UnparseableBinderProbeLine,
        parseBinderProbeLine("device= status=ok"),
    );
    try std.testing.expectError(
        error.UnparseableBinderProbeLine,
        parseBinderProbeLine("device=/dev/binderfs/binder statuz=ok"),
    );
    try std.testing.expectError(
        error.UnparseableBinderProbeLine,
        parseBinderProbeLine("device=/dev/binderfs/binder status=unusable"),
    );
}

test "Binder probe output verification accepts exactly the expected usable devices" {
    const allocator = std.testing.allocator;
    const output =
        "device=/dev/binderfs/binder status=ok protocol_version=8\n" ++
        "device=/dev/binderfs/hwbinder status=ok protocol_version=8\n" ++
        "device=/dev/binderfs/vndbinder status=ok protocol_version=8\n";
    try verifyBinderProbeOutput(allocator, output, &.{
        "/dev/binderfs/binder",
        "/dev/binderfs/hwbinder",
        "/dev/binderfs/vndbinder",
    });
}

test "Binder probe output verification fails closed on a missing device" {
    const allocator = std.testing.allocator;
    const output = "device=/dev/binderfs/binder status=ok protocol_version=8\n";
    try std.testing.expectError(error.MissingBinderProbeDevice, verifyBinderProbeOutput(
        allocator,
        output,
        &.{ "/dev/binderfs/binder", "/dev/binderfs/hwbinder" },
    ));
}

test "Binder probe output verification fails closed on an unusable device" {
    const allocator = std.testing.allocator;
    const output = "device=/dev/binderfs/binder status=open-failed errno=13\n";
    try std.testing.expectError(error.BinderDeviceNotUsable, verifyBinderProbeOutput(
        allocator,
        output,
        &.{"/dev/binderfs/binder"},
    ));
}

test "Binder probe output verification fails closed on a duplicated device line" {
    const allocator = std.testing.allocator;
    const output =
        "device=/dev/binderfs/binder status=ok protocol_version=8\n" ++
        "device=/dev/binderfs/binder status=ok protocol_version=8\n";
    try std.testing.expectError(error.DuplicateBinderProbeDevice, verifyBinderProbeOutput(
        allocator,
        output,
        &.{"/dev/binderfs/binder"},
    ));
}

test "Binder probe output verification fails closed on unparseable garbage output" {
    const allocator = std.testing.allocator;
    const output = "the probe did not run\n";
    try std.testing.expectError(error.UnparseableBinderProbeLine, verifyBinderProbeOutput(
        allocator,
        output,
        &.{"/dev/binderfs/binder"},
    ));
}

test "guest cloud-init verification runs no interpreter in the guest" {
    // Spelled in two pieces deliberately: `tests/python_inventory.zig` counts a
    // quoted interpreter word as an invocation site, and this guard exists to
    // prove the guest has none left, not to add one.
    const interpreter = "py" ++ "thon";

    // The remote shell fetches bytes and nothing else, so no interpreter name
    // may appear in either script, and the shell variable that used to carry
    // the guest-side verdict is gone.
    for ([_][]const u8{ full_checks, cloud_init_status_command }) |script| {
        try std.testing.expect(std.ascii.indexOfIgnoreCase(script, interpreter) == null);
        try std.testing.expect(std.mem.indexOf(u8, script, "import ") == null);
    }
    try std.testing.expect(std.mem.indexOf(u8, full_checks, "cloud_init_status") == null);
    try std.testing.expect(std.mem.indexOf(u8, full_checks, "--format json") == null);

    // The wait stays in the guest contract; only the verdict moved out.
    try std.testing.expect(
        std.mem.indexOf(u8, full_checks, "check cloud-init-wait cloud-init status --wait") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, cloud_init_status_command, "cloud-init status --format json") != null,
    );

    // The core contract names Python only as library directories that must be
    // absent from the image; it never runs one.
    const library_prefix = "/usr/lib/";
    const library_suffix = "3/dist-packages/";
    var index: usize = 0;
    var mentions: usize = 0;
    while (std.mem.indexOfPos(u8, core_checks, index, interpreter)) |at| {
        try std.testing.expect(at >= library_prefix.len);
        try std.testing.expectEqualStrings(
            library_prefix,
            core_checks[at - library_prefix.len .. at],
        );
        try std.testing.expect(std.mem.startsWith(
            u8,
            core_checks[at + interpreter.len ..],
            library_suffix,
        ));
        mentions += 1;
        index = at + interpreter.len;
    }
    try std.testing.expectEqual(@as(usize, 2), mentions);
}

test "guest cloud-init status query fetches the document without judging it" {
    // A guest-side verdict would have to compare, test, or grep; this must do
    // none of those, and must fail the remote command outright when cloud-init
    // produces nothing rather than passing an empty document off as a result.
    try std.testing.expect(std.mem.indexOf(u8, cloud_init_status_command, "done") == null);
    try std.testing.expect(std.mem.indexOf(u8, cloud_init_status_command, "grep") == null);
    try std.testing.expect(std.mem.indexOf(u8, cloud_init_status_command, "sed") == null);
    try std.testing.expect(std.mem.indexOf(u8, cloud_init_status_command, "awk") == null);
    try std.testing.expect(std.mem.startsWith(u8, cloud_init_status_command, "set -eu\n"));
    try std.testing.expect(
        std.mem.indexOf(u8, cloud_init_status_command, "test -n \"$status_document\"") != null,
    );
}

test "cloud-init status is accepted only when the guest reports a done status" {
    const allocator = std.testing.allocator;
    const accepted = [_][]const u8{
        "{\"status\": \"done\"}",
        "{\"status\":\"done\"}\n",
        "  \t{\"status\":\"done\"}\r\n\n",
        "{\"boot_status_code\":\"enabled-by-generator\",\"status\":\"done\"," ++
            "\"errors\":[],\"recoverable_errors\":{}}",
    };
    for (accepted) |document| try verifyCloudInitStatusDone(allocator, document);
}

test "cloud-init status verification fails closed on every non-done shape" {
    const allocator = std.testing.allocator;
    const Case = struct { document: []const u8, expected: anyerror };
    const cases = [_]Case{
        .{ .document = "", .expected = error.CloudInitStatusEmpty },
        .{ .document = "   \t\r\n ", .expected = error.CloudInitStatusEmpty },
        .{ .document = "not json", .expected = error.CloudInitStatusMalformed },
        .{ .document = "{\"status\": \"done\"", .expected = error.CloudInitStatusMalformed },
        .{ .document = "{\"status\": done}", .expected = error.CloudInitStatusMalformed },
        .{ .document = "{\"status\":\"done\"} trailing", .expected = error.CloudInitStatusMalformed },
        // A duplicated key makes the answer ambiguous, so it is malformed here.
        .{
            .document = "{\"status\":\"done\",\"status\":\"error\"}",
            .expected = error.CloudInitStatusMalformed,
        },
        .{ .document = "[]", .expected = error.CloudInitStatusNotAnObject },
        .{ .document = "\"done\"", .expected = error.CloudInitStatusNotAnObject },
        .{ .document = "null", .expected = error.CloudInitStatusNotAnObject },
        .{ .document = "[{\"status\":\"done\"}]", .expected = error.CloudInitStatusNotAnObject },
        .{ .document = "{}", .expected = error.CloudInitStatusMissing },
        .{ .document = "{\"Status\":\"done\"}", .expected = error.CloudInitStatusMissing },
        .{ .document = "{\"errors\":[]}", .expected = error.CloudInitStatusMissing },
        .{ .document = "{\"status\":null}", .expected = error.CloudInitStatusNotAString },
        .{ .document = "{\"status\":5}", .expected = error.CloudInitStatusNotAString },
        .{ .document = "{\"status\":true}", .expected = error.CloudInitStatusNotAString },
        .{ .document = "{\"status\":[\"done\"]}", .expected = error.CloudInitStatusNotAString },
        .{ .document = "{\"status\":{\"status\":\"done\"}}", .expected = error.CloudInitStatusNotAString },
        .{ .document = "{\"status\":\"running\"}", .expected = error.CloudInitStatusNotDone },
        .{ .document = "{\"status\":\"error\"}", .expected = error.CloudInitStatusNotDone },
        .{ .document = "{\"status\":\"degraded done\"}", .expected = error.CloudInitStatusNotDone },
        .{ .document = "{\"status\":\"not-run\"}", .expected = error.CloudInitStatusNotDone },
        .{ .document = "{\"status\":\"\"}", .expected = error.CloudInitStatusNotDone },
        .{ .document = "{\"status\":\"Done\"}", .expected = error.CloudInitStatusNotDone },
        .{ .document = "{\"status\":\"done \"}", .expected = error.CloudInitStatusNotDone },
    };
    for (cases) |case| try std.testing.expectError(
        case.expected,
        verifyCloudInitStatusDone(allocator, case.document),
    );
}

test "cloud-init status verification rejects an unbounded document" {
    const allocator = std.testing.allocator;
    const filler = "{\"status\":\"done\",\"note\":\"";
    const oversized = try allocator.alloc(u8, cloud_init_status_max_bytes + 1);
    defer allocator.free(oversized);
    @memcpy(oversized[0..filler.len], filler);
    @memset(oversized[filler.len .. oversized.len - 2], 'a');
    oversized[oversized.len - 2] = '"';
    oversized[oversized.len - 1] = '}';
    try std.testing.expectError(
        error.CloudInitStatusTooLarge,
        verifyCloudInitStatusDone(allocator, oversized),
    );

    // Exactly at the bound the document is still parsed, not silently passed.
    const at_bound = oversized[0..cloud_init_status_max_bytes];
    try std.testing.expectError(
        error.CloudInitStatusMalformed,
        verifyCloudInitStatusDone(allocator, at_bound),
    );
}

test "rejected cloud-init status documents are reported trimmed and bounded" {
    try std.testing.expectEqualStrings(
        "{\"status\":\"error\"}",
        cloudInitStatusExcerpt("\n  {\"status\":\"error\"}\r\n"),
    );
    try std.testing.expectEqualStrings("", cloudInitStatusExcerpt("  \n"));

    const allocator = std.testing.allocator;
    const flood = try allocator.alloc(u8, 8 * cloud_init_status_excerpt_bytes);
    defer allocator.free(flood);
    @memset(flood, 'x');
    const excerpt = cloudInitStatusExcerpt(flood);
    try std.testing.expectEqual(cloud_init_status_excerpt_bytes, excerpt.len);
}

test "Ubuntu 26.04 finalized QCOW2 boots, provisions, restarts, and powers off" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    errdefer |err| {
        std.debug.print(
            "Ubuntu 26.04 same-architecture QEMU acceptance failed: {s}\n",
            .{@errorName(err)},
        );
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpErrorReturnTrace(trace);
        }
    }
    const candidate = try selectedCandidate();

    const image_path = try requireImageAlloc(allocator, io, candidate);
    defer allocator.free(image_path);
    var configured_execution = try requireQemuExecutionAlloc(
        allocator,
        io,
        candidate,
    );
    defer configured_execution.deinit(allocator);
    const absolute_image = try Dir.cwd().realPathFileAlloc(io, image_path, allocator);
    defer allocator.free(absolute_image);
    if (!std.mem.eql(u8, std.fs.path.basename(absolute_image), candidate.expectedFileName()))
        return error.UnexpectedCandidateName;

    const qemu_path = configured_execution.qemu_path;
    const qemu_img_path = try requireToolAlloc(allocator, io, "qemu-img");
    defer allocator.free(qemu_img_path);
    const swtpm_path = try requireToolAlloc(allocator, io, "swtpm");
    defer allocator.free(swtpm_path);
    const ssh_keygen_path = try requireToolAlloc(allocator, io, "ssh-keygen");
    defer allocator.free(ssh_keygen_path);
    const ssh_path = try requireToolAlloc(allocator, io, "ssh");
    defer allocator.free(ssh_path);
    const openssl_path = try requireToolAlloc(allocator, io, "openssl");
    defer allocator.free(openssl_path);
    const sbverify_path = try requireToolOverrideAlloc(
        allocator,
        io,
        "MIZ_UBUNTU2604_SBVERIFY",
        "sbverify",
    );
    defer allocator.free(sbverify_path);
    const certificate_path = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_SIGNING_CERTIFICATE",
    );
    defer allocator.free(certificate_path);
    const expected_certificate_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_SIGNING_CERTIFICATE_SHA256",
    );
    defer allocator.free(expected_certificate_text);
    const expected_certificate_sha256 = miz.artifact_pipeline.parseSha256(
        expected_certificate_text,
    ) catch return error.InvalidSigningCertificateSha256;
    const expected_uki_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_UKI_SHA256",
    );
    defer allocator.free(expected_uki_text);
    const expected_uki_sha256 = miz.artifact_pipeline.parseSha256(
        expected_uki_text,
    ) catch return error.InvalidExpectedUkiSha256;
    const expected_image_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_IMAGE_SHA256",
    );
    defer allocator.free(expected_image_text);
    const expected_image_sha256 = miz.artifact_pipeline.parseSha256(
        expected_image_text,
    ) catch return error.InvalidExpectedImageSha256;
    const result_path = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ACCEPTANCE_RESULT",
    );
    defer allocator.free(result_path);
    var result_identity = try requireAcceptanceResultIdentityAlloc(allocator);
    defer result_identity.deinit(allocator);
    var firmware = try requireFirmwareAlloc(
        allocator,
        io,
        qemu_path,
        candidate.architecture,
        true,
    );
    defer firmware.deinit(allocator);

    try validateQemuImgInfo(allocator, io, qemu_img_path, absolute_image);
    const source_sha256 = (try miz.artifact_pipeline.hashFile(
        io,
        absolute_image,
    )).sha256;
    if (!std.mem.eql(u8, &source_sha256, &expected_image_sha256))
        return error.CandidateDigestMismatch;

    var temporary = std.testing.tmpDir(.{});
    defer temporary.cleanup();
    var temporary_path_buffer: [Dir.max_path_bytes]u8 = undefined;
    const temporary_path_length = try temporary.dir.realPath(io, &temporary_path_buffer);
    const temporary_path = temporary_path_buffer[0..temporary_path_length];
    const certificate_der_path = try std.fs.path.join(
        allocator,
        &.{ temporary_path, "signing-certificate.der" },
    );
    defer allocator.free(certificate_der_path);
    const certificate_sha256 = try canonicalCertificateSha256(
        allocator,
        io,
        openssl_path,
        certificate_path,
        certificate_der_path,
    );
    if (!std.mem.eql(u8, &certificate_sha256, &expected_certificate_sha256)) {
        return error.SigningCertificateFingerprintMismatch;
    }
    const certificate_der = try Dir.cwd().readFileAlloc(
        io,
        certificate_der_path,
        allocator,
        .limited(1024 * 1024),
    );
    defer allocator.free(certificate_der);
    try verifyNativeUkiCertificate(
        allocator,
        io,
        absolute_image,
        certificate_der,
        expected_certificate_sha256,
    );
    const uki_sha256 = try validateFinalizedImage(
        allocator,
        io,
        absolute_image,
        candidate,
    );
    if (!std.mem.eql(u8, &uki_sha256, &expected_uki_sha256)) {
        return error.SignedUkiDigestMismatch;
    }
    try verifyUkiSignatures(
        allocator,
        io,
        absolute_image,
        candidate,
        certificate_path,
        sbverify_path,
        temporary_path,
    );
    const enrolled_vars_path = try std.fs.path.join(
        allocator,
        &.{ temporary_path, "enrolled-vars.fd" },
    );
    defer allocator.free(enrolled_vars_path);
    try prepareEnrolledVars(
        allocator,
        io,
        firmware.vars_path,
        certificate_der,
        expected_certificate_sha256,
        enrolled_vars_path,
    );

    var first: Instance = undefined;
    try first.init(
        allocator,
        io,
        temporary_path,
        "first",
        22220,
        configured_execution.profile,
    );
    defer first.deinit(allocator);
    errdefer first.dumpSerial(allocator, io);

    var second: Instance = undefined;
    try second.init(
        allocator,
        io,
        temporary_path,
        "second",
        22221,
        configured_execution.profile,
    );
    defer second.deinit(allocator);
    errdefer second.dumpSerial(allocator, io);

    // KVM still exercises two concurrent first boots. Arm TCG waits for the
    // first independently provisioned guest to pass the same strict runtime
    // checks before launching the second, avoiding two 2-vCPU startup bursts.
    for (initialGuestLaunchOrder(
        configured_execution.profile.initial_guest_launch,
    )) |step| switch (step) {
        .start_first => try startInstance(
            allocator,
            io,
            qemu_img_path,
            qemu_path,
            swtpm_path,
            ssh_keygen_path,
            &firmware,
            enrolled_vars_path,
            absolute_image,
            candidate,
            true,
            &first,
        ),
        .first_ready => try verifyInitialGuestReady(
            allocator,
            io,
            ssh_path,
            candidate,
            &first,
        ),
        .start_second => try startInstance(
            allocator,
            io,
            qemu_img_path,
            qemu_path,
            swtpm_path,
            ssh_keygen_path,
            &firmware,
            enrolled_vars_path,
            absolute_image,
            candidate,
            true,
            &second,
        ),
        .second_ready => try verifyInitialGuestReady(
            allocator,
            io,
            ssh_path,
            candidate,
            &second,
        ),
    };
    try verifyRootGrowth(allocator, io, ssh_path, &first, candidate);
    try verifyRootGrowth(allocator, io, ssh_path, &second, candidate);
    try verifyGuestSecureBoot(
        allocator,
        io,
        ssh_path,
        &first,
        certificate_sha256,
    );
    try verifyGuestSecureBoot(
        allocator,
        io,
        ssh_path,
        &second,
        certificate_sha256,
    );

    if (candidate.flavor == .core) {
        try verifyGuestSignedBinderModule(allocator, io, ssh_path, &first);
        try verifyGuestSignedBinderModule(allocator, io, ssh_path, &second);

        // One probe run per guest answers the whole runtime contract, and the
        // BinderFS and DMA-heap contracts are then read out of it rather than
        // re-asked with shell utilities the final image should not have to keep.
        var first_contract = try readGuestRuntimeContractAlloc(
            allocator,
            io,
            ssh_path,
            &first,
        );
        defer first_contract.deinit(allocator);
        var second_contract = try readGuestRuntimeContractAlloc(
            allocator,
            io,
            ssh_path,
            &second,
        );
        defer second_contract.deinit(allocator);
        try verifyGuestBinderfsDevices(&first_contract);
        try verifyGuestBinderfsDevices(&second_contract);
        try verifyGuestBinderDeviceUsability(allocator, io, ssh_path, &first);
        try verifyGuestBinderDeviceUsability(allocator, io, ssh_path, &second);
        try verifyGuestDmaHeap(&first_contract);
        try verifyGuestDmaHeap(&second_contract);

        // The measured first-boot phase issue #677 step 1 left open. The root
        // has booted and grown by now, so this is the first moment the numbers
        // exist at all; they are read from the guest's own `statfs` and
        // appended to a copy of the candidate's inventory, never to the bound
        // document, whose digest provenance already depends on.
        try recordFirstBootInventory(allocator, io, ssh_path, &first, candidate);
    }

    var first_before = try readGuestIdentityAlloc(allocator, io, ssh_path, &first);
    defer first_before.deinit(allocator);
    var second_before = try readGuestIdentityAlloc(allocator, io, ssh_path, &second);
    defer second_before.deinit(allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        first_before.machine_id,
        second_before.machine_id,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        first_before.ssh_fingerprint,
        second_before.ssh_fingerprint,
    ));

    var first_core_before: ?CoreProvisionedState = null;
    defer if (first_core_before) |*state| state.deinit(allocator);
    var second_core_before: ?CoreProvisionedState = null;
    defer if (second_core_before) |*state| state.deinit(allocator);
    if (candidate.flavor == .core) {
        try waitForSerialMarker(
            allocator,
            io,
            &first,
            "explicit local provisioning media detected; WireServer Ready will be skipped",
            5,
        );
        try waitForSerialMarker(
            allocator,
            io,
            &second,
            "explicit local provisioning media detected; WireServer Ready will be skipped",
            5,
        );
        const first_public_key_fingerprint = try publicKeyFingerprintAlloc(
            allocator,
            io,
            ssh_keygen_path,
            first.public_key_path,
        );
        defer allocator.free(first_public_key_fingerprint);
        const second_public_key_fingerprint = try publicKeyFingerprintAlloc(
            allocator,
            io,
            ssh_keygen_path,
            second.public_key_path,
        );
        defer allocator.free(second_public_key_fingerprint);

        first_core_before = try readCoreProvisionedStateAlloc(
            allocator,
            io,
            ssh_path,
            &first,
        );
        second_core_before = try readCoreProvisionedStateAlloc(
            allocator,
            io,
            ssh_path,
            &second,
        );
        try std.testing.expectEqualStrings(
            first_public_key_fingerprint,
            first_core_before.?.authorized_key_fingerprint,
        );
        try std.testing.expectEqualStrings(
            second_public_key_fingerprint,
            second_core_before.?.authorized_key_fingerprint,
        );
        try std.testing.expect(!std.mem.eql(
            u8,
            first_core_before.?.authorized_key_fingerprint,
            second_core_before.?.authorized_key_fingerprint,
        ));
        try std.testing.expect(!std.mem.eql(
            u8,
            first_core_before.?.sentinel,
            second_core_before.?.sentinel,
        ));
        try verifyCoreSshdRestart(allocator, io, ssh_path, &first);
        try verifyCoreSshdRestart(allocator, io, ssh_path, &second);
    }

    var first_after = try rebootAndReadIdentity(
        allocator,
        io,
        ssh_path,
        &first,
        &first_before,
    );
    defer first_after.deinit(allocator);
    var second_after = try rebootAndReadIdentity(
        allocator,
        io,
        ssh_path,
        &second,
        &second_before,
    );
    defer second_after.deinit(allocator);

    try std.testing.expectEqualStrings(
        first_before.machine_id,
        first_after.machine_id,
    );
    try std.testing.expectEqualStrings(
        first_before.ssh_fingerprint,
        first_after.ssh_fingerprint,
    );
    try std.testing.expectEqualStrings(
        second_before.machine_id,
        second_after.machine_id,
    );
    try std.testing.expectEqualStrings(
        second_before.ssh_fingerprint,
        second_after.ssh_fingerprint,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        first_after.machine_id,
        second_after.machine_id,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        first_after.ssh_fingerprint,
        second_after.ssh_fingerprint,
    ));
    try verifyAdminLogin(allocator, io, ssh_path, &first);
    try verifyAdminLogin(allocator, io, ssh_path, &second);
    try verifyKeyOnlySsh(allocator, io, ssh_path, &first);
    try verifyKeyOnlySsh(allocator, io, ssh_path, &second);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &first);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &second);
    if (candidate.flavor == .core) {
        var first_core_after = try readCoreProvisionedStateAlloc(
            allocator,
            io,
            ssh_path,
            &first,
        );
        defer first_core_after.deinit(allocator);
        var second_core_after = try readCoreProvisionedStateAlloc(
            allocator,
            io,
            ssh_path,
            &second,
        );
        defer second_core_after.deinit(allocator);
        try expectCoreProvisionedStateEqual(&first_core_before.?, &first_core_after);
        try expectCoreProvisionedStateEqual(&second_core_before.?, &second_core_after);
    }
    try verifyGuestSecureBoot(
        allocator,
        io,
        ssh_path,
        &first,
        certificate_sha256,
    );

    try poweroff(allocator, io, ssh_path, &first);
    try poweroff(allocator, io, ssh_path, &second);

    const tampered_image = try std.fs.path.join(
        allocator,
        &.{ temporary_path, "tampered.qcow2" },
    );
    defer allocator.free(tampered_image);
    try createTamperedOverlay(
        allocator,
        io,
        qemu_img_path,
        absolute_image,
        tampered_image,
        candidate,
        certificate_path,
        sbverify_path,
        temporary_path,
    );
    var ordinary_firmware = try requireFirmwareAlloc(
        allocator,
        io,
        qemu_path,
        candidate.architecture,
        false,
    );
    defer ordinary_firmware.deinit(allocator);

    var control: Instance = undefined;
    try control.init(
        allocator,
        io,
        temporary_path,
        "tamper-control",
        22222,
        configured_execution.profile,
    );
    defer control.deinit(allocator);
    errdefer control.dumpSerial(allocator, io);
    try startInstance(
        allocator,
        io,
        qemu_img_path,
        qemu_path,
        swtpm_path,
        ssh_keygen_path,
        &ordinary_firmware,
        ordinary_firmware.vars_path,
        tampered_image,
        candidate,
        false,
        &control,
    );
    try waitForSerialMarker(
        allocator,
        io,
        &control,
        "Linux version",
        configured_execution.profile.timeouts.tamper_control_seconds,
    );
    try terminateInstance(&control);

    var rejected: Instance = undefined;
    try rejected.init(
        allocator,
        io,
        temporary_path,
        "tamper-rejected",
        22223,
        configured_execution.profile,
    );
    defer rejected.deinit(allocator);
    errdefer rejected.dumpSerial(allocator, io);
    try startInstance(
        allocator,
        io,
        qemu_img_path,
        qemu_path,
        swtpm_path,
        ssh_keygen_path,
        &firmware,
        enrolled_vars_path,
        tampered_image,
        candidate,
        true,
        &rejected,
    );
    try waitForFirmwareRefusal(
        allocator,
        io,
        &rejected,
        configured_execution.profile.timeouts.tamper_refusal_seconds,
    );
    try Io.sleep(io, .fromSeconds(5), .awake);
    if (try serialContains(allocator, io, &rejected, "Linux version") or
        try serialContains(allocator, io, &rejected, "MIZINIT_PID1_READY") or
        try sshSucceeded(allocator, io, ssh_path, &rejected, "true"))
    {
        return error.TamperedUkiBootedWithSecureBoot;
    }
    try terminateInstance(&rejected);

    try std.testing.expectEqual(
        source_sha256,
        (try miz.artifact_pipeline.hashFile(io, absolute_image)).sha256,
    );
    try writeAcceptanceResult(
        allocator,
        io,
        result_path,
        candidate,
        source_sha256,
        certificate_sha256,
        uki_sha256,
        &result_identity,
        configured_execution.profile,
        qemu_path,
    );
}
