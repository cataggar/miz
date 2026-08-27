//! Opt-in native-QEMU acceptance for finalized Ubuntu 26.04 QCOW2 images.
//!
//! The selected build options and `MIZ_UBUNTU2604_IMAGE` must agree on one
//! full or core candidate. This deliberately refuses TCG: acceptance is run
//! only by a native x86_64 or AArch64 matrix entry.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const qemu_host = @import("qemu_host");
const qmp = @import("qmp");
const miz = @import("miz");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const admin_username = "miztest";
const boot_timeout_seconds: i64 = 8 * 60;
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
            .aarch64 => "virt,accel=kvm",
        };
    }

    fn nativeCpu(self: Architecture) std.Target.Cpu.Arch {
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
    "matching-architecture-native-kvm",
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
    "matching-architecture-native-kvm",
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
    "android-smoke-artifact-provenance",
    "android-container-boot-completed",
    "android-container-abi-match",
    "android-smoke-graceful-stop",
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
    // Bumped from 4 so that a result binding a private producer identity
    // instead of the complete provenance-manifest digest can never satisfy
    // the current core contract set.
    .result_schema = 5,
    .contracts = &core_contracts,
};

const full_policy: FlavorPolicy = .{
    .x86_64_file_name = "Ubuntu-26.04-x86_64.qcow2",
    .aarch64_file_name = "Ubuntu-26.04-aarch64.qcow2",
    .virtual_size = 5 * gib,
    .result_schema = 1,
    .contracts = &full_contracts,
};

const Candidate = struct {
    architecture: Architecture,
    flavor: Flavor,

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

fn validateNativeKvmPrerequisites(
    host_is_linux: bool,
    host_architecture: std.Target.Cpu.Arch,
    kvm_available: bool,
    candidate: Candidate,
) !void {
    if (!host_is_linux) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires a Linux host for native KVM QEMU\n",
            .{},
        );
        return error.NativeKvmRequiresLinux;
    }
    if (host_architecture != candidate.architecture.nativeCpu()) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires a native {s} runner; TCG is forbidden\n",
            .{@tagName(candidate.architecture.nativeCpu())},
        );
        return error.NativeKvmRequiresMatchingHostArchitecture;
    }
    if (!kvm_available) {
        std.debug.print(
            "Ubuntu 26.04 acceptance requires readable and writable /dev/kvm; TCG is forbidden\n",
            .{},
        );
        return error.KvmUnavailable;
    }
}

fn requireNativeKvm(io: Io, candidate: Candidate) !void {
    const host_is_linux = builtin.os.tag == .linux;
    const host_is_native = builtin.cpu.arch == candidate.architecture.nativeCpu();
    const kvm_available = if (host_is_linux and host_is_native)
        try qemu_host.pathAccessible(io, "/dev/kvm", .{ .read = true, .write = true })
    else
        false;
    try validateNativeKvmPrerequisites(
        host_is_linux,
        builtin.cpu.arch,
        kvm_available,
        candidate,
    );
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
                "{s}init=/sbin/mizinit mizinit.mode=persistent mizinit.azure=auto console=tty0 {s}",
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
        \\#cloud-config
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
    ,
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
        "-cpu",
        "host",
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
        .connect_timeout = .fromSeconds(30),
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
    const result = std.process.run(allocator, io, .{
        .argv = argv,
        .stdout_limit = .limited(512 * 1024),
        .stderr_limit = .limited(16 * 1024),
        .timeout = .{ .duration = .{
            .raw = .fromSeconds(20),
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
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
    return commandSucceeded(allocator, io, &.{
        ssh_path,
        "-i",
        instance.private_key_path,
        "-p",
        port_text,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
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
    });
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
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
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
            "ConnectTimeout=5",
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
            .raw = .fromSeconds(20),
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
        "sudo -n /bin/sh -c 'cat /sys/firmware/efi/efivars/db-*'",
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
// metapackage the core flavor already requires), but the module-autoload,
// binderfs-mount, and device-creation boot wiring is not added by this
// branch: `scripts/build_generalized_ubuntu2604.zig` is untouched here, and
// that wiring is left to a companion follow-up change. Until that lands,
// these checks describe the contract the finished image must satisfy; they
// do not themselves make an unmodified image satisfy it, and are expected to
// fail against one. The exact assumed mount point is likewise a documented
// assumption pending that companion change, not something enforced elsewhere
// in this repository.
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

const binderfs_dynamic_device_checks =
    \\set -eu
    \\test "$(findmnt -n -o FSTYPE --target /dev/binderfs)" = binder
    \\test -c /dev/binderfs/binder-control
    \\test -c /dev/binderfs/binder
    \\test -c /dev/binderfs/hwbinder
    \\test -c /dev/binderfs/vndbinder
;

fn verifyGuestBinderfsDevices(
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
        binderfs_dynamic_device_checks,
    ) catch return error.GuestBinderfsDeviceContractFailed;
    allocator.free(output);
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
            "ConnectTimeout=5",
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

fn pushBinderProbeBinary(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    const probe_bytes = try Dir.cwd().readFileAlloc(
        io,
        binderProbeHostPath(),
        allocator,
        .limited(4 * 1024 * 1024),
    );
    defer allocator.free(probe_bytes);

    const encoded_len = std.base64.standard.Encoder.calcSize(probe_bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, probe_bytes);

    const push_command = "base64 -d > " ++ binder_probe_remote_path ++
        " && chmod 0755 " ++ binder_probe_remote_path;
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

// --- Android container boot-completion smoke (core flavor only) ---
//
// The core image never embeds an Android OCI runtime or bundle: both are
// supplied externally, at acceptance time, as a digest-bound artifact this
// harness never publishes or persists into the QCOW2. Preparing that
// runtime and bundle is out of scope for this repository; this section only
// transfers the two artifacts the caller already verified, launches them
// with the required BinderFS and DMA-heap access, and binds their
// provenance into the acceptance result so a result recorded before this
// contract existed can never satisfy the current core contract set. Callers
// that cannot supply a real bundle must fail closed via
// `requireAndroidSmokeInputsAlloc` rather than skip this contract.
const android_smoke_runtime_remote_path = "/tmp/ubuntu2604-android-runtime";
const android_smoke_bundle_archive_remote_path = "/tmp/ubuntu2604-android-bundle.tar";
const android_smoke_bundle_remote_dir = "/tmp/ubuntu2604-android-bundle";
const android_smoke_container_id = "miz-android-smoke";
const android_smoke_boot_property = "sys.boot_completed";
const android_smoke_abilist_property = "ro.product.cpu.abilist";
const android_smoke_binderfs_mount_destination = "/dev/binderfs";
const android_smoke_dma_heap_mount_prefix = "/dev/dma_heap";
const android_smoke_poll_interval_seconds: u32 = 5;
const android_smoke_boot_timeout_seconds: u32 = 240;
const android_smoke_stop_timeout_seconds: u32 = 60;
const android_smoke_diagnostics_byte_limit: usize = 8192;

// Fully comptime-known guest commands, named so their exact contents are
// directly unit-testable without SSH: in particular, that stop/delete never
// spell `--force`, that launch always detaches instead of blocking, and that
// the state query never carries a success-shaped fallback that could paper
// over a failed, absent, or malformed query result.
const android_smoke_extract_command = "set -eu; sudo -n rm -rf -- '" ++
    android_smoke_bundle_remote_dir ++ "' && sudo -n mkdir -p -- '" ++
    android_smoke_bundle_remote_dir ++ "' && sudo -n tar -xf '" ++
    android_smoke_bundle_archive_remote_path ++ "' -C '" ++ android_smoke_bundle_remote_dir ++ "'";
const android_smoke_config_command = "sudo -n cat -- '" ++
    android_smoke_bundle_remote_dir ++ "/config.json'";
const android_smoke_launch_command = "sudo -n '" ++ android_smoke_runtime_remote_path ++
    "' run --id " ++ android_smoke_container_id ++ " --bundle '" ++
    android_smoke_bundle_remote_dir ++ "' --detach";
const android_smoke_boot_poll_command = "sudo -n '" ++ android_smoke_runtime_remote_path ++
    "' exec " ++ android_smoke_container_id ++ " -- /system/bin/getprop " ++
    android_smoke_boot_property;
const android_smoke_abi_command = "sudo -n '" ++ android_smoke_runtime_remote_path ++
    "' exec " ++ android_smoke_container_id ++ " -- /system/bin/getprop " ++
    android_smoke_abilist_property;
const android_smoke_kill_command = "sudo -n '" ++ android_smoke_runtime_remote_path ++
    "' kill " ++ android_smoke_container_id ++ " TERM";
// No `|| printf ...` fallback here: a failed, timed-out, or permission-denied
// state query must surface as a command failure to the caller rather than a
// synthetic success-shaped `{"status":"stopped"}` result. The caller (see
// `stopAndroidContainerGracefully`) treats every such failure as "not yet
// stopped" and keeps polling within its bounded timeout instead of ever
// authorizing delete on the strength of a query it could not confirm.
const android_smoke_state_command = "sudo -n '" ++ android_smoke_runtime_remote_path ++
    "' state " ++ android_smoke_container_id ++ " 2>/dev/null";
const android_smoke_delete_command = "sudo -n '" ++ android_smoke_runtime_remote_path ++
    "' delete " ++ android_smoke_container_id;

/// Required, digest-bound provenance for the externally supplied Android OCI
/// runtime and bundle. Every field is read once, up front, alongside the
/// other required acceptance inputs, so this contract fails closed with a
/// clear error rather than silently skipping when the artifacts are absent.
const AndroidSmokeInputs = struct {
    provenance_sha256: miz.artifact_pipeline.Digest,
    runtime_path: []u8,
    runtime_sha256: miz.artifact_pipeline.Digest,
    bundle_path: []u8,
    bundle_sha256: miz.artifact_pipeline.Digest,
    config_sha256: miz.artifact_pipeline.Digest,

    fn deinit(self: *AndroidSmokeInputs, allocator: Allocator) void {
        allocator.free(self.runtime_path);
        allocator.free(self.bundle_path);
        self.* = undefined;
    }
};

fn requireAndroidSmokeInputsAlloc(allocator: Allocator) !AndroidSmokeInputs {
    const provenance_sha256_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ANDROID_PROVENANCE_SHA256",
    );
    defer allocator.free(provenance_sha256_text);
    const provenance_sha256 = miz.artifact_pipeline.parseSha256(provenance_sha256_text) catch
        return error.InvalidAndroidSmokeDigest;

    const runtime_path = try requireEnvAlloc(allocator, "MIZ_UBUNTU2604_ANDROID_RUNTIME");
    errdefer allocator.free(runtime_path);
    const runtime_sha256_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ANDROID_RUNTIME_SHA256",
    );
    defer allocator.free(runtime_sha256_text);
    const runtime_sha256 = miz.artifact_pipeline.parseSha256(runtime_sha256_text) catch
        return error.InvalidAndroidSmokeDigest;

    const bundle_path = try requireEnvAlloc(allocator, "MIZ_UBUNTU2604_ANDROID_BUNDLE");
    errdefer allocator.free(bundle_path);
    const bundle_sha256_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ANDROID_BUNDLE_SHA256",
    );
    defer allocator.free(bundle_sha256_text);
    const bundle_sha256 = miz.artifact_pipeline.parseSha256(bundle_sha256_text) catch
        return error.InvalidAndroidSmokeDigest;

    const config_sha256_text = try requireEnvAlloc(
        allocator,
        "MIZ_UBUNTU2604_ANDROID_CONFIG_SHA256",
    );
    defer allocator.free(config_sha256_text);
    const config_sha256 = miz.artifact_pipeline.parseSha256(config_sha256_text) catch
        return error.InvalidAndroidSmokeDigest;

    return .{
        .provenance_sha256 = provenance_sha256,
        .runtime_path = runtime_path,
        .runtime_sha256 = runtime_sha256,
        .bundle_path = bundle_path,
        .bundle_sha256 = bundle_sha256,
        .config_sha256 = config_sha256,
    };
}

/// Maps the acceptance architecture to the ABI string the Android container
/// must report through `ro.product.cpu.abilist`. Pure and unit-tested
/// without KVM.
fn androidContainerAbi(architecture: Architecture) []const u8 {
    return switch (architecture) {
        .x86_64 => "x86_64",
        .aarch64 => "arm64-v8a",
    };
}

/// Confirms the guest-reported ABI list contains the ABI required for
/// `architecture`. Pure aside from the caller-supplied text, so mismatched,
/// empty, and malformed ABI lists are all directly unit-testable.
fn verifyAndroidAbilist(abilist_output: []const u8, architecture: Architecture) !void {
    const expected = androidContainerAbi(architecture);
    const trimmed = std.mem.trim(u8, abilist_output, " \t\r\n");
    var entries = std.mem.splitScalar(u8, trimmed, ',');
    while (entries.next()) |abi| {
        if (std.mem.eql(u8, abi, expected)) return;
    }
    return error.AndroidContainerAbiMismatch;
}

const AndroidBootPollOutcome = enum { boot_completed, retry, timed_out };

/// Classifies one `getprop sys.boot_completed` observation. Pure and
/// unit-tested directly: this is what guarantees the poll loop below always
/// terminates instead of spinning past its bounded timeout.
fn classifyAndroidBootPoll(
    boot_completed_property: []const u8,
    elapsed_seconds: u32,
    timeout_seconds: u32,
) AndroidBootPollOutcome {
    const trimmed = std.mem.trim(u8, boot_completed_property, " \t\r\n");
    if (std.mem.eql(u8, trimmed, "1")) return .boot_completed;
    if (elapsed_seconds >= timeout_seconds) return .timed_out;
    return .retry;
}

/// Confirms the bundle's `config.json` requests the BinderFS mount and a
/// DMA-heap mount this contract requires, without miz constructing those
/// mounts itself (bundle preparation belongs to the artifact this contract
/// only consumes). Pure JSON parsing, unit-tested directly without KVM.
fn verifyAndroidBundleConfigRequestsRequiredDevices(
    allocator: Allocator,
    config_json: []const u8,
) !void {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, config_json, .{}) catch
        return error.InvalidAndroidBundleConfig;
    defer parsed.deinit();
    const root = switch (parsed.value) {
        .object => |object| object,
        else => return error.InvalidAndroidBundleConfig,
    };
    const mounts_value = root.get("mounts") orelse return error.MissingAndroidBundleMounts;
    const mounts = switch (mounts_value) {
        .array => |array| array,
        else => return error.InvalidAndroidBundleMounts,
    };
    var has_binderfs = false;
    var has_dma_heap = false;
    for (mounts.items) |mount_value| {
        const mount = switch (mount_value) {
            .object => |object| object,
            else => continue,
        };
        const destination_value = mount.get("destination") orelse continue;
        const destination = switch (destination_value) {
            .string => |text| text,
            else => continue,
        };
        if (std.mem.eql(u8, destination, android_smoke_binderfs_mount_destination))
            has_binderfs = true;
        if (std.mem.startsWith(u8, destination, android_smoke_dma_heap_mount_prefix))
            has_dma_heap = true;
    }
    if (!has_binderfs) return error.AndroidBundleMissingBinderfsMount;
    if (!has_dma_heap) return error.AndroidBundleMissingDmaHeapMount;
}

/// Decides whether the guest-reported container state permits issuing
/// `delete` without `--force`. Absent or unparseable state is treated as
/// *not* ready, never as ready: the caller must keep waiting (and
/// eventually fail closed) rather than risk a forced removal of a container
/// that might still be running. Pure and unit-tested directly.
fn androidSmokeReadyForDelete(status: ?[]const u8) bool {
    const value = status orelse return false;
    return std.mem.eql(u8, value, "stopped");
}

/// Extracts the `status` field from a runtime state JSON document. Returns
/// `null` (never an error) for anything unparseable, so the caller always
/// falls through to the conservative "not ready" branch above.
fn extractAndroidContainerStatusAlloc(
    allocator: Allocator,
    state_output: []const u8,
) !?[]u8 {
    var parsed = std.json.parseFromSlice(std.json.Value, allocator, state_output, .{}) catch
        return null;
    defer parsed.deinit();
    const object = switch (parsed.value) {
        .object => |object| object,
        else => return null,
    };
    const status_value = object.get("status") orelse return null;
    return switch (status_value) {
        .string => |text| try allocator.dupe(u8, text),
        else => null,
    };
}

fn pushFileBase64Alloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    local_path: []const u8,
    remote_path: []const u8,
    remote_mode: []const u8,
) !void {
    const bytes = try Dir.cwd().readFileAlloc(
        io,
        local_path,
        allocator,
        .limited(256 * 1024 * 1024),
    );
    defer allocator.free(bytes);
    const encoded_len = std.base64.standard.Encoder.calcSize(bytes.len);
    const encoded = try allocator.alloc(u8, encoded_len);
    defer allocator.free(encoded);
    _ = std.base64.standard.Encoder.encode(encoded, bytes);

    const push_command = try std.fmt.allocPrint(
        allocator,
        "rm -f -- '{s}' && (umask 077; base64 -d >'{s}') && chmod {s} '{s}'",
        .{ remote_path, remote_path, remote_mode, remote_path },
    );
    defer allocator.free(push_command);
    const output = try sshWithStdinAlloc(allocator, io, ssh_path, instance, push_command, encoded);
    allocator.free(output);
}

fn verifyRemoteFileDigest(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    remote_path: []const u8,
    expected: miz.artifact_pipeline.Digest,
) !void {
    const command = try std.fmt.allocPrint(
        allocator,
        "sha256sum -- '{s}' | awk '{{print $1}}'",
        .{remote_path},
    );
    defer allocator.free(command);
    const output = try sshOutputAlloc(allocator, io, ssh_path, instance, command);
    defer allocator.free(output);
    const trimmed = std.mem.trim(u8, output, " \t\r\n");
    const actual = miz.artifact_pipeline.parseSha256(trimmed) catch
        return error.AndroidSmokeRemoteDigestUnparseable;
    if (!std.mem.eql(u8, &actual, &expected)) return error.AndroidSmokeRemoteDigestMismatch;
}

fn captureAndroidSmokeDiagnosticsAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) ![]u8 {
    const command = std.fmt.comptimePrint(
        "{{ sudo -n '{s}' state {s} 2>&1 || true; " ++
            "sudo -n /usr/bin/dmesg 2>&1 | tail -c {d} || true; }} | tail -c {d}",
        .{
            android_smoke_runtime_remote_path,
            android_smoke_container_id,
            android_smoke_diagnostics_byte_limit,
            android_smoke_diagnostics_byte_limit,
        },
    );
    return sshOutputAlloc(allocator, io, ssh_path, instance, command) catch
        allocator.dupe(u8, "android container smoke diagnostics were unavailable\n");
}

fn pollAndroidBootCompleted(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    architecture: Architecture,
) !void {
    var elapsed_seconds: u32 = 0;
    while (true) {
        const output = sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_boot_poll_command) catch
            try allocator.dupe(u8, "");
        defer allocator.free(output);
        switch (classifyAndroidBootPoll(output, elapsed_seconds, android_smoke_boot_timeout_seconds)) {
            .boot_completed => break,
            .timed_out => return error.AndroidContainerBootTimedOut,
            .retry => {
                try Io.sleep(io, .fromSeconds(android_smoke_poll_interval_seconds), .awake);
                elapsed_seconds += android_smoke_poll_interval_seconds;
            },
        }
    }

    const abi_output = try sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_abi_command);
    defer allocator.free(abi_output);
    try verifyAndroidAbilist(abi_output, architecture);
}

fn stopAndroidContainerGracefully(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
) !void {
    if (sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_kill_command)) |output| {
        allocator.free(output);
    } else |err| switch (err) {
        // The container may already have exited on its own; the state poll
        // below is the source of truth for whether it is safe to delete.
        error.SshCommandFailed => {},
        else => return err,
    }

    const max_attempts = android_smoke_stop_timeout_seconds / android_smoke_poll_interval_seconds;
    var attempt: u32 = 0;
    var stopped = false;
    while (attempt < max_attempts) : (attempt += 1) {
        // A failed state query (permission error, transient SSH failure, the
        // runtime itself erroring out, ...) is captured here and folded into
        // empty output, exactly like a transient boot-poll failure above.
        // `extractAndroidContainerStatusAlloc` treats empty output as
        // unparseable and returns `null`, so a query failure can never be
        // read as confirmation the container stopped, and this loop keeps
        // polling within its bounded timeout instead of aborting early or
        // fabricating a "stopped" result.
        const state_output = sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_state_command) catch
            try allocator.dupe(u8, "");
        defer allocator.free(state_output);
        const status = extractAndroidContainerStatusAlloc(allocator, state_output) catch null;
        defer if (status) |value| allocator.free(value);
        if (androidSmokeReadyForDelete(status)) {
            stopped = true;
            break;
        }
        try Io.sleep(io, .fromSeconds(android_smoke_poll_interval_seconds), .awake);
    }
    // Never force-remove a running Android container: if it never reaches
    // "stopped" within the bounded timeout, this contract fails closed
    // instead of issuing a forced delete.
    if (!stopped) return error.AndroidContainerDidNotStopGracefully;

    const delete_output = try sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_delete_command);
    allocator.free(delete_output);
}

fn verifyGuestAndroidContainerSmoke(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    architecture: Architecture,
    smoke: *const AndroidSmokeInputs,
) !void {
    if (!std.mem.eql(
        u8,
        &(try miz.artifact_pipeline.hashFile(io, smoke.runtime_path)).sha256,
        &smoke.runtime_sha256,
    )) return error.AndroidSmokeRuntimeDigestMismatch;
    if (!std.mem.eql(
        u8,
        &(try miz.artifact_pipeline.hashFile(io, smoke.bundle_path)).sha256,
        &smoke.bundle_sha256,
    )) return error.AndroidSmokeBundleDigestMismatch;

    try pushFileBase64Alloc(
        allocator,
        io,
        ssh_path,
        instance,
        smoke.runtime_path,
        android_smoke_runtime_remote_path,
        "0755",
    );
    try verifyRemoteFileDigest(
        allocator,
        io,
        ssh_path,
        instance,
        android_smoke_runtime_remote_path,
        smoke.runtime_sha256,
    );

    try pushFileBase64Alloc(
        allocator,
        io,
        ssh_path,
        instance,
        smoke.bundle_path,
        android_smoke_bundle_archive_remote_path,
        "0600",
    );
    try verifyRemoteFileDigest(
        allocator,
        io,
        ssh_path,
        instance,
        android_smoke_bundle_archive_remote_path,
        smoke.bundle_sha256,
    );

    const extract_output = try sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_extract_command);
    allocator.free(extract_output);

    const config_json = try sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_config_command);
    defer allocator.free(config_json);
    const config_digest = miz.artifact_pipeline.sha256Bytes(config_json);
    if (!std.mem.eql(u8, &config_digest, &smoke.config_sha256))
        return error.AndroidSmokeConfigDigestMismatch;
    try verifyAndroidBundleConfigRequestsRequiredDevices(allocator, config_json);

    const launch_output = try sshOutputAlloc(allocator, io, ssh_path, instance, android_smoke_launch_command);
    allocator.free(launch_output);

    pollAndroidBootCompleted(allocator, io, ssh_path, instance, architecture) catch |err| {
        const diagnostics = try captureAndroidSmokeDiagnosticsAlloc(allocator, io, ssh_path, instance);
        defer allocator.free(diagnostics);
        std.debug.print(
            "\n--- Android container smoke diagnostics ({s}) ---\n{s}\n--- end diagnostics ---\n",
            .{ instance.label, diagnostics },
        );
        stopAndroidContainerGracefully(allocator, io, ssh_path, instance) catch {};
        return err;
    };

    try stopAndroidContainerGracefully(allocator, io, ssh_path, instance);
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
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(boot_timeout_seconds));
    while (Io.Clock.awake.now(io).nanoseconds < deadline.nanoseconds) {
        if (try sshSucceeded(allocator, io, ssh_path, instance, "true")) return;
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
    if (try commandSucceeded(allocator, io, &.{
        ssh_path,
        "-p",
        port_text,
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=5",
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
    })) return error.SshAcceptedWithoutKey;
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
    \\check_service() {
    \\  unit=$1
    \\  check "service-active:$unit" systemctl is-active --quiet "$unit" || {
    \\    systemctl status --no-pager -l "$unit" >&2 || true
    \\    return 1
    \\  }
    \\  check "service-enabled:$unit" systemctl is-enabled --quiet "$unit" || {
    \\    systemctl is-enabled "$unit" >&2 || true
    \\    return 1
    \\  }
    \\}
    \\check pid1-systemd sudo -n /usr/bin/test /proc/1/exe -ef /usr/lib/systemd/systemd
    \\check mizinit-sbin-absent test ! -e /sbin/mizinit
    \\check mizinit-usr-bin-absent test ! -e /usr/bin/mizinit
    \\check os-release-readable test -r /etc/os-release
    \\. /etc/os-release
    \\check os-id-ubuntu test "$ID" = ubuntu
    \\check os-version-26.04 test "$VERSION_ID" = 26.04
    \\for unit in cloud-init-local.service cloud-init-network.service cloud-config.service cloud-final.service walinuxagent.service ssh.service systemd-networkd.service; do
    \\  check_service "$unit"
    \\done
    \\check cloud-init-wait cloud-init status --wait
    \\cloud_init_status=$(cloud-init status --format json | python3 -c 'import json,sys; print(json.load(sys.stdin)["status"])')
    \\check cloud-init-status-done test "$cloud_init_status" = done
    \\netplan_network=$(find /run/systemd/network -maxdepth 1 -name '10-netplan-*.network' -print -quit)
    \\check netplan-network-generated test -n "$netplan_network"
    \\check network-online systemctl is-active --quiet network-online.target
    \\check waagent-provisioning-agent grep -Eq '^[[:space:]]*Provisioning.Agent[[:space:]]*=[[:space:]]*auto[[:space:]]*$' /etc/waagent.conf
    \\check waagent-resource-disk-format grep -Eq '^[[:space:]]*ResourceDisk.Format[[:space:]]*=[[:space:]]*n[[:space:]]*$' /etc/waagent.conf
    \\check cloud-init-instance-state test -s /var/lib/cloud/instance/obj.pkl
    \\failed_units=$(systemctl --failed --no-legend --plain)
    \\check no-failed-units test -z "$failed_units" || {
    \\  printf '%s\n' "$failed_units" >&2
    \\  exit 1
    \\}
;

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
            const output = sshOutputAlloc(
                allocator,
                io,
                ssh_path,
                instance,
                full_checks,
            ) catch |err| switch (err) {
                error.SshCommandFailed => return error.FullServiceContractFailed,
                else => return err,
            };
            allocator.free(output);
        },
    }
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

    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(boot_timeout_seconds));
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

    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(boot_timeout_seconds));
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
    const deadline = Io.Clock.awake.now(io).addDuration(.fromSeconds(boot_timeout_seconds));
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

fn writeAcceptanceResult(
    allocator: Allocator,
    io: Io,
    result_path: []const u8,
    candidate: Candidate,
    source_sha256: miz.artifact_pipeline.Digest,
    certificate_sha256: miz.artifact_pipeline.Digest,
    uki_sha256: miz.artifact_pipeline.Digest,
    android_smoke: ?*const AndroidSmokeInputs,
) !void {
    const source_sha256_hex = miz.artifact_pipeline.formatSha256(source_sha256);
    const certificate_sha256_hex = miz.artifact_pipeline.formatSha256(
        certificate_sha256,
    );
    const uki_sha256_hex = miz.artifact_pipeline.formatSha256(uki_sha256);
    switch (candidate.flavor) {
        .full => {
            if (android_smoke != null) return error.UnexpectedAndroidSmokeProvenance;
            try writeAcceptanceResultValue(
                allocator,
                io,
                result_path,
                .{
                    .schema = candidate.flavor.policy().result_schema,
                    .type = "ubuntu2604-local-secure-boot-acceptance",
                    .candidate_sha256 = &source_sha256_hex,
                    .certificate_sha256 = &certificate_sha256_hex,
                    .fallback_uki_sha256 = &uki_sha256_hex,
                    .contracts = candidate.contracts(),
                },
            );
        },
        .core => {
            const smoke = android_smoke orelse return error.MissingAndroidSmokeProvenance;
            const provenance_sha256_hex = miz.artifact_pipeline.formatSha256(smoke.provenance_sha256);
            const runtime_sha256_hex = miz.artifact_pipeline.formatSha256(smoke.runtime_sha256);
            const bundle_sha256_hex = miz.artifact_pipeline.formatSha256(smoke.bundle_sha256);
            const config_sha256_hex = miz.artifact_pipeline.formatSha256(smoke.config_sha256);
            const candidate_key = try std.fmt.allocPrint(allocator, "{s}-{s}", .{
                @tagName(candidate.architecture),
                @tagName(candidate.flavor),
            });
            defer allocator.free(candidate_key);
            try writeAcceptanceResultValue(
                allocator,
                io,
                result_path,
                .{
                    .schema = candidate.flavor.policy().result_schema,
                    .type = "ubuntu2604-local-secure-boot-acceptance",
                    .architecture = @tagName(candidate.architecture),
                    .flavor = @tagName(candidate.flavor),
                    .virtual_size = candidate.expectedVirtualSize(),
                    .candidate_sha256 = &source_sha256_hex,
                    .certificate_sha256 = &certificate_sha256_hex,
                    .fallback_uki_sha256 = &uki_sha256_hex,
                    .android_smoke = .{
                        .provenance_sha256 = &provenance_sha256_hex,
                        .runtime_sha256 = &runtime_sha256_hex,
                        .bundle_sha256 = &bundle_sha256_hex,
                        .config_sha256 = &config_sha256_hex,
                        .architecture = @tagName(candidate.architecture),
                        .candidate_key = candidate_key,
                    },
                    .contracts = candidate.contracts(),
                },
            );
        },
    }
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
    try std.testing.expectEqual(@as(u32, 1), full.flavor.policy().result_schema);
    try std.testing.expectEqual(@as(u32, 5), core.flavor.policy().result_schema);
    try std.testing.expectEqual(@as(usize, 18), full.contracts().len);
    try std.testing.expectEqual(@as(usize, 31), core.contracts().len);
    try std.testing.expect(hasContract(core.contracts(), "mizinit-sshd-supervision"));
    try std.testing.expect(hasContract(core.contracts(), "no-cloud-init"));
    try std.testing.expect(hasContract(core.contracts(), "signed-binder-module"));
    try std.testing.expect(hasContract(core.contracts(), "binder-boot-required"));
    try std.testing.expect(hasContract(core.contracts(), "binderfs-dynamic-devices"));
    try std.testing.expect(hasContract(core.contracts(), "binder-device-usability"));
    try std.testing.expect(hasContract(core.contracts(), "android-smoke-artifact-provenance"));
    try std.testing.expect(hasContract(core.contracts(), "android-container-boot-completed"));
    try std.testing.expect(hasContract(core.contracts(), "android-container-abi-match"));
    try std.testing.expect(hasContract(core.contracts(), "android-smoke-graceful-stop"));
    try std.testing.expect(!hasContract(full.contracts(), "signed-binder-module"));
    try std.testing.expect(!hasContract(full.contracts(), "binder-boot-required"));
    try std.testing.expect(!hasContract(full.contracts(), "binderfs-dynamic-devices"));
    try std.testing.expect(!hasContract(full.contracts(), "binder-device-usability"));
    try std.testing.expect(!hasContract(full.contracts(), "android-smoke-artifact-provenance"));
    try std.testing.expect(!hasContract(full.contracts(), "android-container-boot-completed"));
    try std.testing.expect(!hasContract(full.contracts(), "android-container-abi-match"));
    try std.testing.expect(!hasContract(full.contracts(), "android-smoke-graceful-stop"));
}

test "Ubuntu 26.04 configured acceptance prerequisites fail closed" {
    const candidate = Candidate{ .architecture = .x86_64, .flavor = .core };

    try std.testing.expectError(
        error.NativeKvmRequiresLinux,
        validateNativeKvmPrerequisites(false, .x86_64, false, candidate),
    );
    try std.testing.expectError(
        error.NativeKvmRequiresMatchingHostArchitecture,
        validateNativeKvmPrerequisites(true, .aarch64, false, candidate),
    );
    try std.testing.expectError(
        error.KvmUnavailable,
        validateNativeKvmPrerequisites(true, .x86_64, false, candidate),
    );
    try std.testing.expectError(
        error.RequiredToolNotFound,
        requireFoundTool(null, "not-a-real-ubuntu2604-acceptance-tool"),
    );
    try std.testing.expectError(
        error.RequiredFirmwareNotFound,
        requireFoundFirmware(null),
    );
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

test "signed Binder module script pins the module tree and requires evidence" {
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, binder_module_name) != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "/sys/module/binder_linux") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "*/updates/*") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "modinfo -F signer") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "taint") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "anbox") != null);
    try std.testing.expect(std.mem.indexOf(u8, signed_binder_module_checks, "modprobe") == null);
}

test "binderfs device script checks the assumed mount point and every dynamic device" {
    try std.testing.expect(std.mem.indexOf(u8, binderfs_dynamic_device_checks, binderfs_mount_point) != null);
    try std.testing.expect(std.mem.indexOf(u8, binderfs_dynamic_device_checks, "binder-control") != null);
    for (binder_dynamic_device_names) |name| {
        try std.testing.expect(std.mem.indexOf(u8, binderfs_dynamic_device_checks, name) != null);
    }
    try std.testing.expect(std.mem.indexOf(u8, binderfs_dynamic_device_checks, "FSTYPE") != null);
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

test "Android container smoke contracts are present only for core" {
    const full = Candidate{ .architecture = .x86_64, .flavor = .full };
    const core = Candidate{ .architecture = .x86_64, .flavor = .core };
    for ([_][]const u8{
        "android-smoke-artifact-provenance",
        "android-container-boot-completed",
        "android-container-abi-match",
        "android-smoke-graceful-stop",
    }) |contract| {
        try std.testing.expect(hasContract(core.contracts(), contract));
        try std.testing.expect(!hasContract(full.contracts(), contract));
    }
}

test "Android container ABI mapping matches the acceptance architectures" {
    try std.testing.expectEqualStrings("x86_64", androidContainerAbi(.x86_64));
    try std.testing.expectEqualStrings("arm64-v8a", androidContainerAbi(.aarch64));
}

test "Android ABI list verification accepts the expected ABI among several" {
    try verifyAndroidAbilist("x86_64,x86\n", .x86_64);
    try verifyAndroidAbilist("arm64-v8a,armeabi-v7a,armeabi\n", .aarch64);
}

test "Android ABI list verification rejects a mismatched or empty ABI list" {
    try std.testing.expectError(
        error.AndroidContainerAbiMismatch,
        verifyAndroidAbilist("armeabi-v7a,armeabi\n", .aarch64),
    );
    try std.testing.expectError(
        error.AndroidContainerAbiMismatch,
        verifyAndroidAbilist("\n", .x86_64),
    );
}

test "Android boot poll classification reports completion, retry, and a bounded timeout" {
    try std.testing.expectEqual(
        AndroidBootPollOutcome.boot_completed,
        classifyAndroidBootPoll("1\n", 0, 240),
    );
    try std.testing.expectEqual(
        AndroidBootPollOutcome.retry,
        classifyAndroidBootPoll("0\n", 5, 240),
    );
    try std.testing.expectEqual(
        AndroidBootPollOutcome.retry,
        classifyAndroidBootPoll("", 5, 240),
    );
    try std.testing.expectEqual(
        AndroidBootPollOutcome.timed_out,
        classifyAndroidBootPoll("0\n", 240, 240),
    );
    try std.testing.expectEqual(
        AndroidBootPollOutcome.timed_out,
        classifyAndroidBootPoll("", 245, 240),
    );
}

test "Android bundle config verification accepts BinderFS and DMA-heap mounts" {
    const allocator = std.testing.allocator;
    const config =
        \\{"mounts":[
        \\  {"destination":"/dev/binderfs","type":"bind"},
        \\  {"destination":"/dev/dma_heap/system","type":"bind"}
        \\]}
    ;
    try verifyAndroidBundleConfigRequestsRequiredDevices(allocator, config);
}

test "Android bundle config verification rejects a missing BinderFS mount" {
    const allocator = std.testing.allocator;
    const config =
        \\{"mounts":[{"destination":"/dev/dma_heap/system","type":"bind"}]}
    ;
    try std.testing.expectError(
        error.AndroidBundleMissingBinderfsMount,
        verifyAndroidBundleConfigRequestsRequiredDevices(allocator, config),
    );
}

test "Android bundle config verification rejects a missing DMA-heap mount" {
    const allocator = std.testing.allocator;
    const config =
        \\{"mounts":[{"destination":"/dev/binderfs","type":"bind"}]}
    ;
    try std.testing.expectError(
        error.AndroidBundleMissingDmaHeapMount,
        verifyAndroidBundleConfigRequestsRequiredDevices(allocator, config),
    );
}

test "Android bundle config verification rejects malformed or missing mounts" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.InvalidAndroidBundleConfig,
        verifyAndroidBundleConfigRequestsRequiredDevices(allocator, "not json"),
    );
    try std.testing.expectError(
        error.MissingAndroidBundleMounts,
        verifyAndroidBundleConfigRequestsRequiredDevices(allocator, "{}"),
    );
    try std.testing.expectError(
        error.InvalidAndroidBundleMounts,
        verifyAndroidBundleConfigRequestsRequiredDevices(allocator, "{\"mounts\":5}"),
    );
}

test "Android bundle config verification skips malformed mount entries but still finds the rest" {
    const allocator = std.testing.allocator;
    const config =
        \\{"mounts":[
        \\  "not-an-object",
        \\  {"type":"bind"},
        \\  {"destination":5},
        \\  {"destination":"/dev/binderfs"},
        \\  {"destination":"/dev/dma_heap/system"}
        \\]}
    ;
    try verifyAndroidBundleConfigRequestsRequiredDevices(allocator, config);
}

test "Android container status extraction parses status and fails closed to null otherwise" {
    const allocator = std.testing.allocator;
    const stopped = try extractAndroidContainerStatusAlloc(allocator, "{\"status\":\"stopped\"}");
    defer if (stopped) |value| allocator.free(value);
    try std.testing.expectEqualStrings("stopped", stopped.?);

    try std.testing.expectEqual(
        @as(?[]u8, null),
        try extractAndroidContainerStatusAlloc(allocator, "not json"),
    );
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try extractAndroidContainerStatusAlloc(allocator, "{}"),
    );
    try std.testing.expectEqual(
        @as(?[]u8, null),
        try extractAndroidContainerStatusAlloc(allocator, "{\"status\":5}"),
    );
}

test "Android smoke graceful-stop safety only allows delete once stopped is confirmed" {
    try std.testing.expect(androidSmokeReadyForDelete("stopped"));
    try std.testing.expect(!androidSmokeReadyForDelete("running"));
    try std.testing.expect(!androidSmokeReadyForDelete("created"));
    try std.testing.expect(!androidSmokeReadyForDelete(null));
}

// Regression coverage for a code-review finding: the state-query command
// used to fall back to a synthetic `{"status":"stopped"}` on any query
// failure (`... || printf '{"status":"stopped"}'`), which could turn a
// permission error, a transient SSH failure, or any other query failure
// into a false confirmation and authorize `delete` on a container that
// might still be running. These tests exercise the actual, generated
// `android_smoke_state_command` string plus the exact extraction/readiness
// helpers `stopAndroidContainerGracefully` calls, so a regression that
// reintroduces any success-shaped fallback fails these tests.
test "Android smoke state-query command never carries a synthetic stopped fallback" {
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_state_command, "||") == null);
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_state_command, "printf") == null);
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_state_command, "stopped") == null);
    try std.testing.expectEqualStrings(
        "sudo -n '" ++ android_smoke_runtime_remote_path ++ "' state " ++
            android_smoke_container_id ++ " 2>/dev/null",
        android_smoke_state_command,
    );
}

test "Android smoke graceful-stop safety refuses delete for every failed or malformed state shape" {
    const allocator = std.testing.allocator;
    // A state query that fails outright (permission error, transient SSH
    // failure, runtime error, ...) is folded into empty output by
    // `stopAndroidContainerGracefully`; confirm that shape, alongside every
    // other unparseable or non-terminal shape, never reads as "stopped".
    const non_terminal_outputs = [_][]const u8{
        "", // the state query failed and produced no output at all
        "\n", // whitespace-only output
        "not json", // malformed output
        "{}", // valid JSON missing the status field entirely
        "{\"status\":5}", // status present but not a string
        "{\"status\":\"running\"}",
        "{\"status\":\"created\"}",
        "{\"status\":\"paused\"}",
        "{\"status\":\"error\"}",
        "{\"status\":\"Stopped\"}", // case must match exactly
        "{\"status\":\"stopped \"}", // trailing whitespace must not match
    };
    for (non_terminal_outputs) |output| {
        const status = try extractAndroidContainerStatusAlloc(allocator, output);
        defer if (status) |value| allocator.free(value);
        try std.testing.expect(!androidSmokeReadyForDelete(status));
    }

    // Only an exact, runtime-confirmed "stopped" status authorizes delete.
    const confirmed = try extractAndroidContainerStatusAlloc(allocator, "{\"status\":\"stopped\"}");
    defer if (confirmed) |value| allocator.free(value);
    try std.testing.expect(androidSmokeReadyForDelete(confirmed));
}

test "Android smoke guest commands never force-remove and always detach on launch" {
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_delete_command, "--force") == null);
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_kill_command, "--force") == null);
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_kill_command, "TERM") != null);
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_kill_command, "KILL") == null);
    try std.testing.expect(std.mem.indexOf(u8, android_smoke_launch_command, "--detach") != null);
    try std.testing.expect(
        std.mem.indexOf(u8, android_smoke_launch_command, android_smoke_container_id) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, android_smoke_boot_poll_command, "/system/bin/getprop") != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, android_smoke_boot_poll_command, android_smoke_boot_property) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, android_smoke_abi_command, android_smoke_abilist_property) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, android_smoke_extract_command, android_smoke_bundle_archive_remote_path) != null,
    );
    try std.testing.expect(
        std.mem.indexOf(u8, android_smoke_config_command, "config.json") != null,
    );
}

test "Android smoke required inputs fail closed rather than skip when absent" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        error.RequiredEnvironmentMissing,
        requireAndroidSmokeInputsAlloc(allocator),
    );
}

test "Ubuntu 26.04 finalized QCOW2 boots, provisions, restarts, and powers off" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
    errdefer |err| {
        std.debug.print(
            "Ubuntu 26.04 native acceptance failed: {s}\n",
            .{@errorName(err)},
        );
        if (@errorReturnTrace()) |trace| {
            std.debug.dumpErrorReturnTrace(trace);
        }
    }
    const candidate = try selectedCandidate();

    const image_path = try requireImageAlloc(allocator, io, candidate);
    defer allocator.free(image_path);
    try requireNativeKvm(io, candidate);
    const absolute_image = try Dir.cwd().realPathFileAlloc(io, image_path, allocator);
    defer allocator.free(absolute_image);
    if (!std.mem.eql(u8, std.fs.path.basename(absolute_image), candidate.expectedFileName()))
        return error.UnexpectedCandidateName;

    const qemu_path = try requireToolOverrideAlloc(
        allocator,
        io,
        "MIZ_UBUNTU2604_QEMU",
        qemu_host.qemuSystemName(candidate.architecture.guestArchitecture()),
    );
    defer allocator.free(qemu_path);
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
    // Required only for the core flavor, and required (never skipped) when
    // it is: the Android container boot-completion smoke has no
    // success-shaped fallback for a missing artifact.
    var android_smoke: ?AndroidSmokeInputs = if (candidate.flavor == .core)
        try requireAndroidSmokeInputsAlloc(allocator)
    else
        null;
    defer if (android_smoke) |*value| value.deinit(allocator);
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
    try first.init(allocator, io, temporary_path, "first", 22220);
    defer first.deinit(allocator);
    errdefer first.dumpSerial(allocator, io);

    var second: Instance = undefined;
    try second.init(allocator, io, temporary_path, "second", 22221);
    defer second.deinit(allocator);
    errdefer second.dumpSerial(allocator, io);

    // Launch both before waiting for either guest: identity generation is
    // thereby exercised by two concurrent first boots from one source image.
    try startInstance(
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
    );
    try startInstance(
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
    );

    try waitForSsh(allocator, io, ssh_path, &first);
    try waitForSsh(allocator, io, ssh_path, &second);
    try verifyAdminLogin(allocator, io, ssh_path, &first);
    try verifyAdminLogin(allocator, io, ssh_path, &second);
    try verifyKeyOnlySsh(allocator, io, ssh_path, &first);
    try verifyKeyOnlySsh(allocator, io, ssh_path, &second);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &first);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &second);
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
        try verifyGuestBinderfsDevices(allocator, io, ssh_path, &first);
        try verifyGuestBinderfsDevices(allocator, io, ssh_path, &second);
        try verifyGuestBinderDeviceUsability(allocator, io, ssh_path, &first);
        try verifyGuestBinderDeviceUsability(allocator, io, ssh_path, &second);

        const smoke = &android_smoke.?;
        try verifyGuestAndroidContainerSmoke(
            allocator,
            io,
            ssh_path,
            &first,
            candidate.architecture,
            smoke,
        );
        try verifyGuestAndroidContainerSmoke(
            allocator,
            io,
            ssh_path,
            &second,
            candidate.architecture,
            smoke,
        );
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
    try control.init(allocator, io, temporary_path, "tamper-control", 22222);
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
        90,
    );
    try terminateInstance(&control);

    var rejected: Instance = undefined;
    try rejected.init(allocator, io, temporary_path, "tamper-rejected", 22223);
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
        60,
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
        if (android_smoke != null) &android_smoke.? else null,
    );
}
