//! Opt-in native-QEMU acceptance for finalized Azure Linux 4 QCOW2 images.
//!
//! The selected build options and `VMIZ_AZURELINUX4_IMAGE` must agree on one
//! of the four release candidates.  This deliberately refuses TCG: release
//! acceptance is run only by a native x86_64 or AArch64 matrix entry.

const std = @import("std");
const builtin = @import("builtin");
const build_options = @import("build_options");
const qemu_host = @import("qemu_host");
const qmp = @import("qmp");
const vmiz = @import("vmiz");

const Allocator = std.mem.Allocator;
const Dir = std.Io.Dir;
const Io = std.Io;

const admin_username = "vmiztest";
const boot_timeout_seconds: i64 = 8 * 60;
const serial_limit: usize = 2 * 1024 * 1024;

const Architecture = enum {
    x86_64,
    aarch64,

    fn guestArchitecture(self: Architecture) qemu_host.GuestArchitecture {
        return switch (self) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        };
    }

    fn rootGuid(self: Architecture) vmiz.guid.Guid {
        return switch (self) {
            .x86_64 => vmiz.guid.linux_root_x86_64,
            .aarch64 => vmiz.guid.linux_root_aarch64,
        };
    }

    fn rootRole(self: Architecture) vmiz.layout.PartitionRole {
        return switch (self) {
            .x86_64 => .root_x86_64,
            .aarch64 => .root_aarch64,
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
};

const Flavor = enum {
    core,
    full,
};

const Candidate = struct {
    architecture: Architecture,
    flavor: Flavor,

    fn expectedFileName(self: Candidate) []const u8 {
        return switch (self.flavor) {
            .core => switch (self.architecture) {
                .x86_64 => "AzureLinux-4.0-x86_64.core.qcow2",
                .aarch64 => "AzureLinux-4.0-aarch64.core.qcow2",
            },
            .full => switch (self.architecture) {
                .x86_64 => "AzureLinux-4.0-x86_64.qcow2",
                .aarch64 => "AzureLinux-4.0-aarch64.qcow2",
            },
        };
    }

    fn expectedVirtualSize(self: Candidate) u64 {
        return switch (self.flavor) {
            .core => 1184 * 1024 * 1024,
            .full => 5 * 1024 * 1024 * 1024,
        };
    }
};

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

const Instance = struct {
    label: []const u8,
    port: u16,
    work_path: []u8,
    overlay_path: []u8,
    vars_path: []u8,
    seed_dir: []u8,
    seed_path: []u8,
    private_key_path: []u8,
    public_key_path: []u8,
    serial_path: []u8,
    qmp_socket_path: []u8,
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
        const seed_dir = try std.fs.path.join(allocator, &.{ work_path, "seed" });
        errdefer allocator.free(seed_dir);
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

        self.* = .{
            .label = label,
            .port = port,
            .work_path = work_path,
            .overlay_path = overlay_path,
            .vars_path = vars_path,
            .seed_dir = seed_dir,
            .seed_path = seed_path,
            .private_key_path = private_key_path,
            .public_key_path = public_key_path,
            .serial_path = serial_path,
            .qmp_socket_path = qmp_socket_path,
        };
    }

    fn deinit(self: *Instance, allocator: Allocator) void {
        if (self.spawned) |*spawned| {
            if (!self.child_waited) spawned.kill();
            spawned.deinit();
        }
        allocator.free(self.work_path);
        allocator.free(self.overlay_path);
        allocator.free(self.vars_path);
        allocator.free(self.seed_dir);
        allocator.free(self.seed_path);
        allocator.free(self.private_key_path);
        allocator.free(self.public_key_path);
        allocator.free(self.serial_path);
        allocator.free(self.qmp_socket_path);
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
            "\n--- Azure Linux acceptance serial log ({s}) ---\n{s}\n--- end serial log ---\n",
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
        build_options.azurelinux_architecture,
    ) orelse return error.InvalidBuildArchitecture;
    const flavor = std.meta.stringToEnum(
        Flavor,
        build_options.azurelinux_flavor,
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
        "VMIZ_AZURELINUX4_IMAGE",
    ) orelse {
        std.debug.print(
            "skipping Azure Linux 4 acceptance: set VMIZ_AZURELINUX4_IMAGE to {s}\n",
            .{candidate.expectedFileName()},
        );
        return error.SkipZigTest;
    };
    errdefer allocator.free(image_path);

    if (!std.mem.eql(u8, std.fs.path.basename(image_path), candidate.expectedFileName())) {
        std.debug.print(
            "Azure Linux 4 acceptance requires the exact finalized candidate {s}, got {s}\n",
            .{ candidate.expectedFileName(), image_path },
        );
        return error.UnexpectedCandidateName;
    }
    if (!try qemu_host.pathAccessible(io, image_path, .{ .read = true })) {
        std.debug.print(
            "VMIZ_AZURELINUX4_IMAGE is not readable: {s}\n",
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
            "Azure Linux 4 acceptance requires a Linux host for native KVM QEMU\n",
            .{},
        );
        return error.NativeKvmRequiresLinux;
    }
    if (host_architecture != candidate.architecture.nativeCpu()) {
        std.debug.print(
            "Azure Linux 4 acceptance requires a native {s} runner; TCG is forbidden\n",
            .{@tagName(candidate.architecture.nativeCpu())},
        );
        return error.NativeKvmRequiresMatchingHostArchitecture;
    }
    if (!kvm_available) {
        std.debug.print(
            "Azure Linux 4 acceptance requires readable and writable /dev/kvm; TCG is forbidden\n",
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
            "Azure Linux 4 acceptance requires {s} in PATH\n",
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
            "Azure Linux 4 acceptance requires matching UEFI firmware; set VMIZ_AZURELINUX4_UEFI_CODE and VMIZ_AZURELINUX4_UEFI_VARS\n",
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
        "VMIZ_AZURELINUX4_UEFI_CODE",
    ) else null;
    defer if (explicit_code) |path| allocator.free(path);
    const explicit_vars = if (secure_boot) try optionalEnvAlloc(
        allocator,
        "VMIZ_AZURELINUX4_UEFI_VARS",
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
        std.debug.print("Azure Linux 4 Secure Boot acceptance requires {s}\n", .{name});
        return error.RequiredEnvironmentMissing;
    };
}

fn canonicalCertificateSha256(
    allocator: Allocator,
    io: Io,
    openssl_path: []const u8,
    certificate_path: []const u8,
    output_path: []const u8,
) !vmiz.artifact_pipeline.Digest {
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
    return vmiz.artifact_pipeline.sha256Bytes(certificate);
}

fn prepareEnrolledVars(
    allocator: Allocator,
    io: Io,
    virt_fw_vars_path: []const u8,
    source_vars_path: []const u8,
    certificate_path: []const u8,
    output_path: []const u8,
) !void {
    Dir.cwd().deleteFile(io, output_path) catch {};
    try runCommand(allocator, io, &.{
        virt_fw_vars_path,
        "--input",
        source_vars_path,
        "--output",
        output_path,
        "--add-db",
        "7f32d4a1-7c10-4e6d-8a89-15ba3f4db734",
        certificate_path,
        "--secure-boot",
    });
    const stat = try Dir.cwd().statFile(io, output_path, .{});
    if (stat.kind != .file or stat.size == 0) return error.InvalidEnrolledVars;
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
    var image = try vmiz.Image.openStandaloneQcow2File(io, file);
    defer image.close(io);
    file = undefined;
    const parsed = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    if (parsed.partitions.len < 1 or
        !std.mem.eql(u8, &parsed.partitions[0].partition_type_guid, &vmiz.guid.esp))
    {
        return error.MissingEspPartition;
    }
    const partition = parsed.partitions[0];
    var esp = try vmiz.fat32.open(&image, io, .{
        .offset = partition.first_lba * vmiz.gpt.sector_size,
        .length = (partition.last_lba - partition.first_lba + 1) *
            vmiz.gpt.sector_size,
    });
    const entries = try esp.listDirAlloc(io, allocator, "EFI/Linux");
    defer vmiz.fat32.freeDirEntries(allocator, entries);
    var index: usize = 0;
    for (entries) |entry| {
        if (entry.kind != .file or entry.name.len <= 4 or
            !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".efi"))
        {
            continue;
        }
        const path = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{entry.name});
        defer allocator.free(path);
        const bytes = try esp.readFileAlloc(io, allocator, path);
        defer allocator.free(bytes);
        const extracted = try std.fmt.allocPrint(
            allocator,
            "{s}/uki-{d}.efi",
            .{ scratch_path, index },
        );
        defer allocator.free(extracted);
        try Dir.cwd().writeFile(io, .{
            .sub_path = extracted,
            .data = bytes,
            .flags = .{ .truncate = true, .permissions = .fromMode(0o600) },
        });
        defer Dir.cwd().deleteFile(io, extracted) catch {};
        try runCommand(allocator, io, &.{
            sbverify_path,
            "--cert",
            certificate_path,
            extracted,
        });
        index += 1;
    }
    if (index == 0) return error.MissingNamedUki;

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
    expected_certificate_sha256: vmiz.artifact_pipeline.Digest,
) !void {
    var image = try vmiz.Image.openPathReadOnlyStandalone(io, image_path);
    defer image.close(io);
    var extracted = try vmiz.uki_certificate.extractAlloc(
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
    var inspection = try vmiz.uki.inspect(allocator, signed);
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
    var image = try vmiz.Image.openPath(io, overlay_path);
    defer image.close(io);
    const parsed = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    if (parsed.partitions.len < 1 or
        !std.mem.eql(u8, &parsed.partitions[0].partition_type_guid, &vmiz.guid.esp))
    {
        return error.MissingEspPartition;
    }
    const partition = parsed.partitions[0];
    var esp = try vmiz.fat32.open(&image, io, .{
        .offset = partition.first_lba * vmiz.gpt.sector_size,
        .length = (partition.last_lba - partition.first_lba + 1) *
            vmiz.gpt.sector_size,
    });
    const entries = try esp.listDirAlloc(io, allocator, "EFI/Linux");
    defer vmiz.fat32.freeDirEntries(allocator, entries);
    var index: usize = 0;
    for (entries) |entry| {
        if (entry.kind != .file or entry.name.len <= 4 or
            !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".efi"))
        {
            continue;
        }
        const path = try std.fmt.allocPrint(allocator, "EFI/Linux/{s}", .{entry.name});
        defer allocator.free(path);
        const signed = try esp.readFileAlloc(io, allocator, path);
        defer allocator.free(signed);
        const tampered = try tamperUkiCmdlineAlloc(allocator, signed);
        defer allocator.free(tampered);
        try requireRejectedUkiSignature(
            allocator,
            io,
            sbverify_path,
            certificate_path,
            scratch_path,
            index,
            tampered,
        );
        try esp.deletePath(io, path);
        try esp.writeFile(io, path, tampered);
        index += 1;
    }
    if (index == 0) return error.MissingNamedUki;

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
        index,
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
    inspection: *const vmiz.uki.Inspection,
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
) !vmiz.artifact_pipeline.Digest {
    var file = try Dir.cwd().openFile(io, image_path, .{ .mode = .read_only });
    var image = try vmiz.Image.openStandaloneQcow2File(io, file);
    defer image.close(io);
    file = undefined;

    if (image.format != .qcow2) return error.NotQcow2;
    const qcow2 = image.qcow2 orelse return error.NotQcow2;
    if (qcow2.backing_file_len != 0) return error.ImageHasBackingFile;
    if (qcow2.data_file_len != 0) return error.ImageHasExternalDataFile;
    if (qcow2.compression_type != 1) return error.MissingZstdCompression;
    if (image.virtual_size != candidate.expectedVirtualSize())
        return error.UnexpectedVirtualSize;

    const parsed = try vmiz.gpt.readGpt(image, io, allocator);
    defer allocator.free(parsed.partitions);
    if (parsed.partitions.len != 2) return error.UnexpectedPartitionCount;
    const esp_partition = parsed.partitions[0];
    const root_partition = parsed.partitions[1];
    if (!std.mem.eql(u8, &esp_partition.partition_type_guid, &vmiz.guid.esp))
        return error.UnexpectedEspPartition;
    if (!std.mem.eql(u8, &root_partition.partition_type_guid, &candidate.architecture.rootGuid()))
        return error.UnexpectedRootArchitecture;
    const esp_size = (esp_partition.last_lba - esp_partition.first_lba + 1) *
        vmiz.gpt.sector_size;
    if (esp_size != 512 * 1024 * 1024)
        return error.UnexpectedEspSize;
    if (esp_partition.first_lba % (1024 * 1024 / vmiz.gpt.sector_size) != 0)
        return error.UnexpectedEspAlignment;
    if (root_partition.first_lba != esp_partition.last_lba + 1 or
        root_partition.last_lba < root_partition.first_lba)
        return error.InvalidRootPartition;
    const requests = [_]vmiz.layout.PartitionRequest{
        .{ .name = "ESP", .role = .esp, .filesystem = .fat32, .size = .{ .fixed = 512 * 1024 * 1024 } },
        .{
            .name = "root",
            .role = candidate.architecture.rootRole(),
            .filesystem = .ext4,
            .size = .{ .percent = 100.0 },
        },
    };
    const expected_layout = try vmiz.layout.planLayout(
        allocator,
        image.virtual_size,
        &requests,
        null,
    );
    defer allocator.free(expected_layout);
    if (esp_partition.first_lba != expected_layout[0].firstLba() or
        esp_partition.last_lba != expected_layout[0].lastLba() or
        root_partition.first_lba != expected_layout[1].firstLba() or
        root_partition.last_lba != expected_layout[1].lastLba())
    {
        return error.InvalidRootPartition;
    }
    if (std.mem.eql(u8, &root_partition.unique_partition_guid, &vmiz.guid.nil))
        return error.InvalidRootPartitionGuid;

    var esp = try vmiz.fat32.open(&image, io, .{
        .offset = esp_partition.first_lba * vmiz.gpt.sector_size,
        .length = (esp_partition.last_lba - esp_partition.first_lba + 1) *
            vmiz.gpt.sector_size,
    });
    const uki = try esp.readFileAlloc(
        io,
        allocator,
        candidate.architecture.fallbackUkiPath(),
    );
    defer allocator.free(uki);

    var inspection = try vmiz.uki.inspect(allocator, uki);
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
    const root_guid = vmiz.guid.formatLower(
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
                "{s}init=/sbin/vmizinit vmizinit.mode=persistent vmizinit.azure=auto console=tty0 {s}",
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
            if (std.mem.indexOf(u8, cmdline, "init=/sbin/vmizinit") != null)
                return error.FullImageContainsVmizinitBootContract;
        },
    }

    const entries = try esp.listDirAlloc(io, allocator, "EFI/Linux");
    defer vmiz.fat32.freeDirEntries(allocator, entries);
    var named_count: usize = 0;
    var fallback_matches_named = false;
    for (entries) |entry| {
        if (entry.kind != .file or entry.name.len <= 4 or
            !std.ascii.eqlIgnoreCase(entry.name[entry.name.len - 4 ..], ".efi"))
        {
            continue;
        }
        named_count += 1;
        const named_path = try std.fmt.allocPrint(
            allocator,
            "EFI/Linux/{s}",
            .{entry.name},
        );
        defer allocator.free(named_path);
        const named = try esp.readFileAlloc(io, allocator, named_path);
        defer allocator.free(named);
        var named_inspection = try vmiz.uki.inspect(allocator, named);
        defer named_inspection.deinit(allocator);
        if (named_inspection.security_directory == null) return error.UnsignedUki;
        if (std.mem.eql(u8, named, uki)) fallback_matches_named = true;
    }
    if (named_count == 0) return error.MissingNamedUki;
    if (!fallback_matches_named) return error.FallbackUkiMismatch;
    return vmiz.artifact_pipeline.sha256Bytes(uki);
}

fn createSeed(
    allocator: Allocator,
    io: Io,
    xorriso_path: []const u8,
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

    try Dir.cwd().createDir(io, instance.seed_dir, .default_dir);
    const metadata = try std.fmt.allocPrint(
        allocator,
        "instance-id: vmiz-azurelinux4-acceptance-{s}\n" ++
            "local-hostname: vmiz-azurelinux4-{s}\n",
        .{ instance.label, instance.label },
    );
    defer allocator.free(metadata);
    const user_data = try std.fmt.allocPrint(
        allocator,
        \\#cloud-config
        \\users:
        \\  - default
        \\  - name: vmiztest
        \\    groups: wheel
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
        \\      <HostName>vmiz-azurelinux4-{s}</HostName>
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

    const metadata_path = try std.fs.path.join(allocator, &.{ instance.seed_dir, "meta-data" });
    defer allocator.free(metadata_path);
    const user_data_path = try std.fs.path.join(allocator, &.{ instance.seed_dir, "user-data" });
    defer allocator.free(user_data_path);
    const ovf_path = try std.fs.path.join(allocator, &.{ instance.seed_dir, "ovf-env.xml" });
    defer allocator.free(ovf_path);
    const marker_path = try std.fs.path.join(
        allocator,
        &.{ instance.seed_dir, "vmiz-local-provisioning" },
    );
    defer allocator.free(marker_path);

    try Dir.cwd().writeFile(io, .{ .sub_path = metadata_path, .data = metadata });
    try Dir.cwd().writeFile(io, .{ .sub_path = user_data_path, .data = user_data });
    try Dir.cwd().writeFile(io, .{ .sub_path = ovf_path, .data = ovf_env });
    try Dir.cwd().writeFile(io, .{ .sub_path = marker_path, .data = "" });

    try runCommand(allocator, io, &.{
        xorriso_path,
        "-as",
        "mkisofs",
        "-quiet",
        "-iso-level",
        "3",
        "-R",
        "-J",
        "-V",
        "cidata",
        "-o",
        instance.seed_path,
        instance.seed_dir,
    });
}

fn startInstance(
    allocator: Allocator,
    io: Io,
    qemu_img_path: []const u8,
    qemu_path: []const u8,
    xorriso_path: []const u8,
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
    try Dir.copyFileAbsolute(vars_template_path, instance.vars_path, io, .{
        .replace = false,
    });
    try createSeed(allocator, io, xorriso_path, ssh_keygen_path, instance);

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

fn sshOutputAlloc(
    allocator: Allocator,
    io: Io,
    ssh_path: []const u8,
    instance: *const Instance,
    command: []const u8,
) ![]u8 {
    const port_text = try std.fmt.allocPrint(allocator, "{d}", .{instance.port});
    defer allocator.free(port_text);
    const result = try std.process.run(allocator, io, .{
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
    });
    switch (result.term) {
        .exited => |code| if (code == 0) {
            allocator.free(result.stderr);
            return result.stdout;
        },
        else => {},
    }
    if (result.stderr.len != 0) {
        std.debug.print("SSH command failed for {s}:\n{s}\n", .{
            instance.label,
            result.stderr,
        });
    }
    allocator.free(result.stderr);
    allocator.free(result.stdout);
    return error.SshCommandFailed;
}

fn efiDbContainsCertificate(
    variable: []const u8,
    certificate_sha256: vmiz.artifact_pipeline.Digest,
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
            const digest = vmiz.artifact_pipeline.sha256Bytes(certificate);
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
    candidate: Candidate,
    instance: *const Instance,
    certificate_sha256: vmiz.artifact_pipeline.Digest,
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

    const module_checks = switch (candidate.flavor) {
        .core =>
        \\for module in crc_itu_t udf isofs; do
        \\  test -d "/sys/module/$module"
        \\done
        ,
        .full =>
        \\for module in crc_itu_t udf isofs; do
        \\  test -d "/sys/module/$module" || sudo -n /usr/sbin/modprobe "$module"
        \\  test -d "/sys/module/$module"
        \\done
        ,
    };
    const command = try std.fmt.allocPrint(
        allocator,
        \\set -eu
        \\secure_boot=$(od -An -t u1 -j 4 -N 1 /sys/firmware/efi/efivars/SecureBoot-* | tr -d ' ')
        \\test "$secure_boot" = 1
        \\if ! test -r /sys/kernel/security/lockdown; then
        \\  sudo -n /usr/bin/mount -t securityfs securityfs /sys/kernel/security
        \\fi
        \\grep -Eq '\[(integrity|confidentiality)\]' /sys/kernel/security/lockdown
        \\{s}
        \\dmesg_output=$(sudo -n /usr/bin/dmesg) || exit 1
        \\if printf '%s\n' "$dmesg_output" | grep -Eiq 'module verification failed|Loading of unsigned module|Lockdown:.*unsigned'; then
        \\  exit 1
        \\fi
        \\
    ,
        .{module_checks},
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

const core_checks =
    \\set -eu
    \\sudo -n /usr/bin/test /proc/1/exe -ef /sbin/vmizinit
    \\test -f /var/lib/azagent/provisioned
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
    \\sudo -n /usr/bin/test /proc/1/exe -ef /usr/lib/systemd/systemd
    \\test ! -e /sbin/vmizinit
    \\test ! -e /usr/bin/vmizinit
    \\for unit in cloud-init-local.service cloud-init-main.service cloud-init-network.service cloud-config.service cloud-final.service waagent.service sshd.service systemd-networkd.service; do
    \\  systemctl is-active --quiet "$unit"
    \\  systemctl is-enabled --quiet "$unit"
    \\done
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
            if (!try sshSucceeded(allocator, io, ssh_path, instance, full_checks))
                return error.FullServiceContractFailed;
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
            if (new_pid != initial_pid) return;
        } else |err| switch (err) {
            error.SshCommandFailed => {},
            else => return err,
        }
        if (!try qemuRunning(instance, deadline)) return error.QemuExitedEarly;
        try Io.sleep(io, .fromSeconds(2), .awake);
    }
    return error.SshdDidNotRestart;
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

test "Azure Linux 4 acceptance candidate names are exact" {
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-x86_64.qcow2",
        (Candidate{ .architecture = .x86_64, .flavor = .full }).expectedFileName(),
    );
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-aarch64.qcow2",
        (Candidate{ .architecture = .aarch64, .flavor = .full }).expectedFileName(),
    );
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-x86_64.core.qcow2",
        (Candidate{ .architecture = .x86_64, .flavor = .core }).expectedFileName(),
    );
    try std.testing.expectEqualStrings(
        "AzureLinux-4.0-aarch64.core.qcow2",
        (Candidate{ .architecture = .aarch64, .flavor = .core }).expectedFileName(),
    );
}

test "Azure Linux 4 configured acceptance prerequisites fail closed" {
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
        requireFoundTool(null, "not-a-real-azurelinux4-acceptance-tool"),
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
    const digest = vmiz.artifact_pipeline.sha256Bytes(certificate);
    try std.testing.expect(efiDbContainsCertificate(&variable, digest));
    try std.testing.expect(!efiDbContainsCertificate(
        &variable,
        [_]u8{0xff} ** 32,
    ));
    try std.testing.expect(!efiDbContainsCertificate(variable[0 .. variable.len - 1], digest));
    variable[list_offset] = 0;
    try std.testing.expect(!efiDbContainsCertificate(&variable, digest));
}

test "Azure Linux 4 finalized QCOW2 boots, provisions, restarts, and powers off" {
    const allocator = std.testing.allocator;
    const io = std.testing.io;
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
        "VMIZ_AZURELINUX4_QEMU",
        qemu_host.qemuSystemName(candidate.architecture.guestArchitecture()),
    );
    defer allocator.free(qemu_path);
    const qemu_img_path = try requireToolAlloc(allocator, io, "qemu-img");
    defer allocator.free(qemu_img_path);
    const xorriso_path = try requireToolAlloc(allocator, io, "xorriso");
    defer allocator.free(xorriso_path);
    const ssh_keygen_path = try requireToolAlloc(allocator, io, "ssh-keygen");
    defer allocator.free(ssh_keygen_path);
    const ssh_path = try requireToolAlloc(allocator, io, "ssh");
    defer allocator.free(ssh_path);
    const openssl_path = try requireToolAlloc(allocator, io, "openssl");
    defer allocator.free(openssl_path);
    const sbverify_path = try requireToolOverrideAlloc(
        allocator,
        io,
        "VMIZ_AZURELINUX4_SBVERIFY",
        "sbverify",
    );
    defer allocator.free(sbverify_path);
    const virt_fw_vars_path = try requireToolOverrideAlloc(
        allocator,
        io,
        "VMIZ_AZURELINUX4_VIRT_FW_VARS",
        "virt-fw-vars",
    );
    defer allocator.free(virt_fw_vars_path);
    const certificate_path = try requireEnvAlloc(
        allocator,
        "VMIZ_AZURELINUX4_SIGNING_CERTIFICATE",
    );
    defer allocator.free(certificate_path);
    const expected_certificate_text = try requireEnvAlloc(
        allocator,
        "VMIZ_AZURELINUX4_SIGNING_CERTIFICATE_SHA256",
    );
    defer allocator.free(expected_certificate_text);
    const expected_certificate_sha256 = vmiz.artifact_pipeline.parseSha256(
        expected_certificate_text,
    ) catch return error.InvalidSigningCertificateSha256;
    const expected_uki_text = try requireEnvAlloc(
        allocator,
        "VMIZ_AZURELINUX4_UKI_SHA256",
    );
    defer allocator.free(expected_uki_text);
    const expected_uki_sha256 = vmiz.artifact_pipeline.parseSha256(
        expected_uki_text,
    ) catch return error.InvalidExpectedUkiSha256;
    const result_path = try requireEnvAlloc(
        allocator,
        "VMIZ_AZURELINUX4_ACCEPTANCE_RESULT",
    );
    defer allocator.free(result_path);
    var firmware = try requireFirmwareAlloc(
        allocator,
        io,
        qemu_path,
        candidate.architecture,
        true,
    );
    defer firmware.deinit(allocator);

    try validateQemuImgInfo(allocator, io, qemu_img_path, absolute_image);
    const source_sha256 = (try vmiz.artifact_pipeline.hashFile(
        io,
        absolute_image,
    )).sha256;

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
        virt_fw_vars_path,
        firmware.vars_path,
        certificate_path,
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
        xorriso_path,
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
        xorriso_path,
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
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &first);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &second);
    try verifyGuestSecureBoot(
        allocator,
        io,
        ssh_path,
        candidate,
        &first,
        certificate_sha256,
    );
    try verifyGuestSecureBoot(
        allocator,
        io,
        ssh_path,
        candidate,
        &second,
        certificate_sha256,
    );

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

    if (candidate.flavor == .core) {
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
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &first);
    try verifyFlavorRuntime(allocator, io, ssh_path, candidate, &second);
    try verifyGuestSecureBoot(
        allocator,
        io,
        ssh_path,
        candidate,
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
        xorriso_path,
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
        xorriso_path,
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
        try serialContains(allocator, io, &rejected, "VMIZINIT_PID1_READY") or
        try sshSucceeded(allocator, io, ssh_path, &rejected, "true"))
    {
        return error.TamperedUkiBootedWithSecureBoot;
    }
    try terminateInstance(&rejected);

    try std.testing.expectEqual(
        source_sha256,
        (try vmiz.artifact_pipeline.hashFile(io, absolute_image)).sha256,
    );
    const source_sha256_hex = vmiz.artifact_pipeline.formatSha256(source_sha256);
    const certificate_sha256_hex = vmiz.artifact_pipeline.formatSha256(
        certificate_sha256,
    );
    const uki_sha256_hex = vmiz.artifact_pipeline.formatSha256(uki_sha256);
    const result = try std.json.Stringify.valueAlloc(
        allocator,
        .{
            .schema = 1,
            .type = "azurelinux4-local-secure-boot-acceptance",
            .candidate_sha256 = &source_sha256_hex,
            .certificate_sha256 = &certificate_sha256_hex,
            .fallback_uki_sha256 = &uki_sha256_hex,
            .contracts = &.{
                "secure-boot",
                "uefi-db-signer",
                "signed-uki",
                "kernel-lockdown",
                "module-signatures",
                "tampered-uki-rejected",
            },
        },
        .{ .whitespace = .indent_2 },
    );
    defer allocator.free(result);
    try Dir.cwd().writeFile(io, .{
        .sub_path = result_path,
        .data = result,
        .flags = .{ .truncate = true },
    });
}
