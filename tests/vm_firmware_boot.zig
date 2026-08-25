//! Attests a real image through real EDK2 firmware in a real emulator.
//!
//! `tests/vm_backend_integration.zig` checks everything the host does around a
//! firmware boot against a stand-in emulator: the argv shape, the ephemeral
//! variable store, the marker scan, the provenance record, and that the
//! published bytes match a direct-kernel run's exactly. What it cannot check
//! is the one claim that needs a real firmware: that an image's own boot chain
//! comes up under EDK2 and says so, and that `snapshot=on` really does keep
//! the attested bytes intact.
//!
//! That needs a bootable image, which no unit test can synthesize, so this is
//! opt-in and told where to find one:
//!
//!   MIZ_RUN_VM_FIRMWARE_TEST=1
//!   MIZ_VM_FIRMWARE_IMAGE=/path/to/bootable.raw
//!   MIZ_VM_FIRMWARE_MARKER='Welcome to Azure Linux'
//!   MIZ_VM_QEMU=/path/to/qemu-system-<arch>
//!   MIZ_VM_FIRMWARE_CODE=/path/to/edk2-code.fd     (optional)
//!   MIZ_VM_FIRMWARE_VARS=/path/to/edk2-vars.fd     (optional)
//!   MIZ_VM_FIRMWARE_ARCH=x86_64|aarch64            (default: the host's)
//!   MIZ_VM_FIRMWARE_SECURE_BOOT=1                  (default: off)
//!   MIZ_VM_FIRMWARE_TIMEOUT=<seconds>              (default: 1800)
//!   MIZ_VM_FIRMWARE_WORKDIR=/path                  (default: /tmp)
//!
//! With the firmware paths unset, resolution goes through the same
//! `qemu_host` search `miz qemu` and the preserved-image builder use, so a
//! `ghr install cataggar/qemu` is enough and this also exercises the
//! resolution path a real build takes.
//!
//! The image is attested in place and left byte-for-byte as it was found.
//! That is not politeness: it is the acceptance criterion, checked here
//! against a real emulator rather than a stand-in that could only agree with
//! the host by construction.

const std = @import("std");
const builtin = @import("builtin");
const qemu_host = @import("qemu_host");
const miz = @import("miz");

const Io = std.Io;
const Allocator = std.mem.Allocator;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    if (builtin.os.tag != .linux) {
        std.debug.print("skipping vm firmware boot: Linux is required\n", .{});
        return;
    }
    const settings = Settings.fromEnvironment(init.environ_map) orelse return;
    try runAttestation(allocator, init.io, settings);
}

const Settings = struct {
    image_path: []const u8,
    marker: []const u8,
    emulator_path: []const u8,
    code_path: ?[]const u8,
    vars_path: ?[]const u8,
    architecture: miz.customize.Architecture,
    host_architecture: miz.customize.Architecture,
    secure_boot: bool,
    timeout_seconds: u32,
    work_root: []const u8,

    fn fromEnvironment(environment: *std.process.Environ.Map) ?Settings {
        const requested = environment.get("MIZ_RUN_VM_FIRMWARE_TEST") orelse "";
        if (!std.mem.eql(u8, requested, "1")) {
            std.debug.print(
                "skipping vm firmware boot: set MIZ_RUN_VM_FIRMWARE_TEST=1 to opt in\n",
                .{},
            );
            return null;
        }
        const host_architecture: miz.customize.Architecture = switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => {
                std.debug.print(
                    "skipping vm firmware boot: unsupported host architecture\n",
                    .{},
                );
                return null;
            },
        };
        const named = environment.get("MIZ_VM_FIRMWARE_ARCH") orelse
            @tagName(host_architecture);
        const architecture = std.meta.stringToEnum(
            miz.customize.Architecture,
            named,
        ) orelse {
            std.debug.print(
                "skipping vm firmware boot: unknown MIZ_VM_FIRMWARE_ARCH {s}\n",
                .{named},
            );
            return null;
        };
        const timeout_text = environment.get("MIZ_VM_FIRMWARE_TIMEOUT") orelse "";
        const timeout_seconds = if (timeout_text.len == 0)
            miz.customize.default_vm_firmware_boot_timeout_seconds
        else
            std.fmt.parseInt(u32, timeout_text, 10) catch {
                std.debug.print(
                    "skipping vm firmware boot: MIZ_VM_FIRMWARE_TIMEOUT is not a number\n",
                    .{},
                );
                return null;
            };
        return .{
            .image_path = environment.get("MIZ_VM_FIRMWARE_IMAGE") orelse {
                std.debug.print(
                    "skipping vm firmware boot: MIZ_VM_FIRMWARE_IMAGE is unset\n",
                    .{},
                );
                return null;
            },
            // Required for the same reason a plan requires it: nothing here
            // knows what the supplied image says on its way up, and a marker
            // this test invented would pass without a boot.
            .marker = environment.get("MIZ_VM_FIRMWARE_MARKER") orelse {
                std.debug.print(
                    "skipping vm firmware boot: MIZ_VM_FIRMWARE_MARKER is unset\n",
                    .{},
                );
                return null;
            },
            .emulator_path = environment.get("MIZ_VM_QEMU") orelse {
                std.debug.print("skipping vm firmware boot: MIZ_VM_QEMU is unset\n", .{});
                return null;
            },
            .code_path = environment.get("MIZ_VM_FIRMWARE_CODE"),
            .vars_path = environment.get("MIZ_VM_FIRMWARE_VARS"),
            .architecture = architecture,
            .host_architecture = host_architecture,
            .secure_boot = std.mem.eql(
                u8,
                environment.get("MIZ_VM_FIRMWARE_SECURE_BOOT") orelse "0",
                "1",
            ),
            .timeout_seconds = timeout_seconds,
            .work_root = environment.get("MIZ_VM_FIRMWARE_WORKDIR") orelse "/tmp",
        };
    }
};

fn runAttestation(allocator: Allocator, io: Io, settings: Settings) !void {
    const cwd = Io.Dir.cwd();

    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    const transaction_path = try std.fmt.allocPrint(
        allocator,
        "{s}/miz-vm-firmware-{s}",
        .{ settings.work_root, &random_hex },
    );
    try cwd.createDirPath(io, transaction_path);
    defer cwd.deleteTree(io, transaction_path) catch {};

    const firmware_paths = try resolveFirmware(allocator, io, settings, transaction_path);
    std.debug.print(
        "vm firmware boot: code {s}\nvm firmware boot: vars {s}\n",
        .{ firmware_paths.code_path, firmware_paths.vars_path },
    );

    const before = try digestOfFile(io, settings.image_path);
    const vars_before = try digestOfFile(io, firmware_paths.vars_path);

    const firmware = miz.customize.VmFirmware{
        .code_path = firmware_paths.code_path,
        .vars_path = firmware_paths.vars_path,
        .console_marker = settings.marker,
        .secure_boot = settings.secure_boot,
        .boot_timeout_seconds = settings.timeout_seconds,
    };
    const policy = miz.customize.VmPolicy{
        .emulator_command = settings.emulator_path,
        .boot = .{ .firmware = firmware },
        // A cross-architecture attestation has no accelerator to use, and a
        // same-architecture one must not need one for this test to run.
        .acceleration = .software,
        .acknowledge_software_emulation = true,
        .memory_mib = 2048,
        .vcpus = 2,
    };

    const attestation = miz.vm_backend.attestFirmwareBoot(allocator, io, .{
        .policy = policy,
        .firmware = firmware,
        .architecture = settings.architecture,
        .transaction_path = transaction_path,
        .stage_path = settings.image_path,
        .console = .{ .writeFn = printConsole },
    }) catch |err| {
        std.debug.print("vm firmware boot failed: {t}\n", .{err});
        return err;
    };

    // The attestation boot is a second emulator invocation, and provenance
    // records it as a command of its own rather than folding it into the
    // appliance boot that ran a different machine with a different disk.
    try ensure(attestation.command.len > 1);
    const record = attestation.record;
    try ensure(record.variable_store == .ephemeral);
    try ensure(record.secure_boot == settings.secure_boot);
    try ensure(std.mem.eql(u8, record.console_marker, settings.marker));
    try ensure(std.mem.eql(u8, record.code_path, firmware_paths.code_path));

    // The attestation is contracted to be read-only. Against a real emulator
    // that is a claim about `snapshot=on`, not about the host's own code.
    const after = try digestOfFile(io, settings.image_path);
    try ensure(std.mem.eql(u8, &before, &after));
    try ensure(std.mem.eql(u8, &record.attested_stage_sha256.bytes, &after));

    // And the variable store the plan named is a template, not a store.
    try ensure(std.mem.eql(
        u8,
        &vars_before,
        &try digestOfFile(io, firmware_paths.vars_path),
    ));

    std.debug.print("vm firmware boot passed\n", .{});
}

const FirmwarePaths = struct {
    code_path: []const u8,
    vars_path: []const u8,
};

fn resolveFirmware(
    allocator: Allocator,
    io: Io,
    settings: Settings,
    transaction_path: []const u8,
) !FirmwarePaths {
    var sources = (try qemu_host.findFirmwareSourcePairAlloc(allocator, io, .{
        .architecture = switch (settings.architecture) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
        },
        .secure_boot = settings.secure_boot,
        .explicit_code_path = settings.code_path,
        .explicit_vars_path = settings.vars_path,
        .qemu_path = settings.emulator_path,
    })) orelse return error.FirmwareNotFound;
    defer sources.deinit(allocator);

    if (sources.code.encoding == .raw and sources.vars.encoding == .raw) {
        return .{
            .code_path = try allocator.dupe(u8, sources.code.path),
            .vars_path = try allocator.dupe(u8, sources.vars.path),
        };
    }

    const directory = try std.fs.path.join(allocator, &.{ transaction_path, "firmware" });
    try Io.Dir.cwd().createDirPath(io, directory);
    var pair = try qemu_host.materializeFirmwarePairAlloc(
        allocator,
        io,
        sources,
        try std.fs.path.join(allocator, &.{ directory, "code.fd" }),
        try std.fs.path.join(allocator, &.{ directory, "vars.fd" }),
        .{},
    );
    defer pair.deinit(allocator);
    return .{
        .code_path = try allocator.dupe(u8, pair.code_path),
        .vars_path = try allocator.dupe(u8, pair.vars_path),
    };
}

fn printConsole(_: ?*anyopaque, bytes: []const u8) void {
    if (bytes.len == 0) return;
    const stderr = std.debug.lockStderr(&.{});
    defer std.debug.unlockStderr();
    stderr.file_writer.interface.writeAll(bytes) catch {};
}

fn digestOfFile(io: Io, path: []const u8) ![32]u8 {
    const file = try Io.Dir.cwd().openFile(io, path, .{ .mode = .read_only });
    defer file.close(io);
    var hasher = std.crypto.hash.sha2.Sha256.init(.{});
    var chunk: [256 * 1024]u8 = undefined;
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

fn ensure(condition: bool) !void {
    if (!condition) return error.FirmwareAttestationAssertionFailed;
}
