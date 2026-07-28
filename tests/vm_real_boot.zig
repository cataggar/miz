//! Boots a real guest, in a real emulator, on a real distribution kernel.
//!
//! The stand-in emulator integration checks everything the host does. This
//! checks the one thing it cannot: that the appliance actually comes up. It is
//! the test that would have caught `virtio_blk` being a module rather than a
//! built-in driver, and it is the only place the guest agent's mount, chroot
//! and teardown paths execute at all, since they need to be PID 1 to run.
//!
//! It needs a kernel, so it is opt-in and told where to find one:
//!
//!   ZVMI_RUN_VM_BOOT_TEST=1
//!   ZVMI_VM_BOOT_KERNEL=/path/to/vmlinuz-<release>
//!   ZVMI_VM_BOOT_MODULES_BUILTIN=/path/to/modules.builtin
//!   ZVMI_VM_BOOT_MODULE_TREE=/path/to/lib/modules/<release>   (optional)
//!   ZVMI_VM_QEMU=/path/to/qemu-system-<arch>
//!   ZVMI_VM_ACCEL=software|hardware        (default: software)
//!   ZVMI_VM_BOOT_ARCH=x86_64|aarch64       (default: the host's)
//!   ZVMI_VM_BOOT_WORKDIR=/path             (default: /tmp)
//!
//! `modules.builtin` comes from the same kernel package and is what decides
//! how the guest's disks are attached, so it is required rather than inferred.
//!
//! `ZVMI_VM_BOOT_MODULE_TREE` points at a real `lib/modules/<release>`, which
//! is staged into the image verbatim: this test computes no dependency closure
//! of its own, so what a kernel that modularizes `ext4` or its virtio drivers
//! boots on is the production resolver rather than a fixture agreeing with it.
//!
//! Naming an architecture the host does not have makes this the
//! cross-architecture acceptance test: the kernel, the agent and the binary the
//! guest executes are all the guest's, and only the emulator is the host's.

const std = @import("std");
const builtin = @import("builtin");
const zvmi = @import("zvmi");

const Io = std.Io;
const Allocator = std.mem.Allocator;

const guest_stub = @import("vm_guest_stub.zig");

const guest_agents = std.StaticStringMap([]const u8).initComptime(.{
    .{ "x86_64", @embedFile("zvmi_guest_agent_x86_64") },
    .{ "aarch64", @embedFile("zvmi_guest_agent_aarch64") },
});
const guest_stubs = std.StaticStringMap([]const u8).initComptime(.{
    .{ "x86_64", @embedFile("vm_guest_stub_x86_64") },
    .{ "aarch64", @embedFile("vm_guest_stub_aarch64") },
});

const disk_size: u64 = 512 * 1024 * 1024;
const partition_first_lba: u32 = 2048;
const partition_sectors: u32 = 900 * 1024;
const partition_offset = @as(u64, partition_first_lba) * zvmi.mbr.sector_size;
const partition_length = @as(u64, partition_sectors) * zvmi.mbr.sector_size;

/// Written by the `rpm` stub from inside the guest's chroot. Its presence in
/// the published image is the proof that matters: the guest booted, found the
/// root filesystem, mounted it writable, and executed a binary out of it.
const marker_path = guest_stub.marker_path;
const marker_bytes = guest_stub.marker_bytes;
const installed_nevra = guest_stub.installed_nevra;

pub fn main(init: std.process.Init) !void {
    const allocator = init.arena.allocator();
    if (builtin.os.tag != .linux) {
        std.debug.print("skipping vm real boot: Linux is required\n", .{});
        return;
    }

    const settings = Settings.fromEnvironment(init.environ_map) orelse return;
    try runBoot(allocator, init.io, settings);
}

const Settings = struct {
    kernel_path: []const u8,
    modules_builtin_path: []const u8,
    /// A real `lib/modules/<release>`, staged verbatim when given. Absent is
    /// the case this test has always run: a kernel that needs nothing loaded.
    module_tree_path: ?[]const u8,
    emulator_path: []const u8,
    acceleration: zvmi.customize.VmAcceleration,
    /// The guest's architecture: what the image is, what the kernel is, and
    /// what the emulator has to emulate.
    architecture: zvmi.customize.Architecture,
    host_architecture: zvmi.customize.Architecture,
    work_root: []const u8,

    fn fromEnvironment(environment: *std.process.Environ.Map) ?Settings {
        const requested = environment.get("ZVMI_RUN_VM_BOOT_TEST") orelse "";
        if (!std.mem.eql(u8, requested, "1")) {
            std.debug.print(
                "skipping vm real boot: set ZVMI_RUN_VM_BOOT_TEST=1 to opt in\n",
                .{},
            );
            return null;
        }
        const host_architecture: zvmi.customize.Architecture = switch (builtin.cpu.arch) {
            .x86_64 => .x86_64,
            .aarch64 => .aarch64,
            else => {
                std.debug.print("skipping vm real boot: unsupported host architecture\n", .{});
                return null;
            },
        };
        const named = environment.get("ZVMI_VM_BOOT_ARCH") orelse @tagName(host_architecture);
        const architecture = std.meta.stringToEnum(
            zvmi.customize.Architecture,
            named,
        ) orelse {
            std.debug.print("skipping vm real boot: unknown ZVMI_VM_BOOT_ARCH {s}\n", .{named});
            return null;
        };
        return .{
            .kernel_path = environment.get("ZVMI_VM_BOOT_KERNEL") orelse {
                std.debug.print("skipping vm real boot: ZVMI_VM_BOOT_KERNEL is unset\n", .{});
                return null;
            },
            .modules_builtin_path = environment.get("ZVMI_VM_BOOT_MODULES_BUILTIN") orelse {
                std.debug.print(
                    "skipping vm real boot: ZVMI_VM_BOOT_MODULES_BUILTIN is unset\n",
                    .{},
                );
                return null;
            },
            .emulator_path = environment.get("ZVMI_VM_QEMU") orelse {
                std.debug.print("skipping vm real boot: ZVMI_VM_QEMU is unset\n", .{});
                return null;
            },
            .module_tree_path = environment.get("ZVMI_VM_BOOT_MODULE_TREE"),
            // Software emulation is the default because the runners this is
            // expected to run on have no accelerator, and a test that demands
            // one is a test that is usually skipped.
            .acceleration = if (std.mem.eql(
                u8,
                environment.get("ZVMI_VM_ACCEL") orelse "software",
                "hardware",
            )) .hardware else .software,
            .architecture = architecture,
            .host_architecture = host_architecture,
            // A boot needs room for two copies of the image, and the default
            // temporary directory is frequently a small tmpfs, so where the
            // workspace lands has to be the caller's decision.
            .work_root = environment.get("ZVMI_VM_BOOT_WORKDIR") orelse "/tmp",
        };
    }
};

fn runBoot(
    allocator: Allocator,
    io: Io,
    settings: Settings,
) !void {
    var random: [8]u8 = undefined;
    Io.random(io, &random);
    const random_hex = std.fmt.bytesToHex(random, .lower);
    const work_path = try std.fmt.allocPrint(
        allocator,
        "{s}/zvmi-vm-boot-{s}",
        .{ settings.work_root, &random_hex },
    );
    const source_path = try std.fs.path.join(allocator, &.{ work_path, "source.raw" });
    const output_path = try std.fs.path.join(allocator, &.{ work_path, "output.raw" });
    const spool_path = try std.fs.path.join(allocator, &.{ work_path, "root.spool" });
    try Io.Dir.cwd().createDir(io, work_path, .default_dir);

    var completed = false;
    defer if (!completed) std.debug.print(
        "vm real boot retained failed workspace: {s}\n",
        .{work_path},
    );

    const release = try createSourceDisk(
        allocator,
        io,
        settings,
        source_path,
        spool_path,
    );
    const source_digest = try digestOfFile(io, source_path);

    const request = zvmi.customize.Request{
        .target_architecture = settings.architecture,
        .input = .{ .disk = .{ .path = source_path } },
        .output = .{
            .path = output_path,
            .format = .raw,
            .size_policy = .preserve_source,
        },
        .storage = .{ .preserve = .{
            .root_partition = .{ .mbr_index = 1 },
        } },
        .execution = .{
            .workspace_path = work_path,
            .backend = .vm,
            .vm = .{
                .emulator_command = settings.emulator_path,
                .acceleration = settings.acceleration,
                .acknowledge_software_emulation = settings.acceleration == .software,
                .memory_mib = 1024,
                .network = .offline,
                .boot_timeout_seconds = 600,
            },
        },
        // A guest that is not the host's architecture has to be declared as
        // such: the runner is named explicitly so nothing about which emulator
        // ran can be inferred after the fact.
        .cross_architecture = if (settings.architecture == settings.host_architecture)
            .reject
        else
            .{ .runner = .{
                .kind = .vm,
                .guest_architecture = settings.architecture,
                .command = settings.emulator_path,
            } },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x57} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
    var resolved = try zvmi.customize.resolve(allocator, &request, .{
        .host_architecture = settings.host_architecture,
    });
    defer resolved.deinit(allocator);
    const plan = &(resolved.plan orelse return error.ResolutionProducedNoPlan);
    if (resolved.diagnostics.hasErrors()) return error.ResolutionReportedErrors;
    const transaction_path = try allocator.dupe(u8, plan.data.transaction_path);

    var platform = zvmi.customize.Platform.system();
    platform.vmCheckFn = checkVm;
    platform.vmRunFn = runVm;

    var report = try zvmi.customize.preflight(allocator, io, plan, platform);
    defer report.deinit(allocator);
    if (!report.ready()) {
        for (report.capabilities) |capability| {
            if (capability.state == .available) continue;
            std.debug.print("preflight refusal: {t} is {t}\n", .{
                capability.requirement.kind,
                capability.state,
            });
        }
        return error.PreflightRefusedTheRun;
    }

    const started = Io.Clock.awake.now(io);
    var outcome = try zvmi.customize.execute(allocator, io, plan, platform, null);
    defer outcome.deinit(allocator);
    const elapsed_ms: u64 = @intCast(@divTrunc(
        Io.Clock.awake.now(io).nanoseconds - started.nanoseconds,
        std.time.ns_per_ms,
    ));

    const result = outcome.result orelse return error.ExecutionProducedNoResult;
    if (outcome.diagnostics.hasErrors()) return error.ExecutionReportedErrors;

    const vm = result.provenance.execution.vm orelse return error.MissingVmProvenance;
    try ensure(vm.acceleration == settings.acceleration);
    try ensure(std.mem.eql(u8, vm.kernel_release, release));
    try ensure(std.mem.eql(u8, vm.emulator_command, settings.emulator_path));
    try ensure(vm.emulator_version.len != 0);

    // A kernel given a module tree is expected to have needed something out of
    // it: a run that quietly loaded nothing would prove only that the built-in
    // path still works, which the Azure Linux boot already proves.
    if (settings.module_tree_path != null) {
        try ensure(vm.modules.len != 0);
        std.debug.print("vm real boot: guest inserted", .{});
        for (vm.modules) |module| std.debug.print(" {s}", .{module.name});
        std.debug.print("\n", .{});
    } else {
        try ensure(vm.modules.len == 0);
    }

    const preserved = result.provenance.execution.preserved orelse
        return error.MissingPreservedProvenance;
    try ensure(preserved.installed_packages.len == 1);
    try ensure(std.mem.eql(u8, preserved.installed_packages[0], installed_nevra));

    // The marker is in the published image and not in the source, which is the
    // whole contract: the guest changed a copy and the original is untouched.
    try expectGuestFile(allocator, io, output_path, marker_path, marker_bytes);
    try expectMissingGuestFile(allocator, io, source_path, marker_path);
    const after = try digestOfFile(io, source_path);
    try ensure(std.mem.eql(u8, &after, &source_digest));

    try expectPathAbsent(io, transaction_path);
    try Io.Dir.cwd().deleteTree(io, work_path);
    completed = true;
    std.debug.print(
        "vm real boot passed on {s} with {s} acceleration in {d}.{d:0>3}s\n",
        .{
            @tagName(settings.architecture),
            @tagName(settings.acceleration),
            elapsed_ms / 1000,
            elapsed_ms % 1000,
        },
    );
}

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
        .agent = guest_agents.get(
            @tagName(plan.data.architectures.runner),
        ) orelse return error.VmGuestAgentUnavailable,
        .console = .{ .writeFn = writeConsole },
    });
}

fn writeConsole(_: ?*anyopaque, bytes: []const u8) void {
    std.debug.print("{s}", .{bytes});
}

/// Builds a root filesystem the agent will accept, carrying the caller's
/// kernel and that kernel's own built-in driver list.
fn createSourceDisk(
    allocator: Allocator,
    io: Io,
    settings: Settings,
    source_path: []const u8,
    spool_path: []const u8,
) ![]const u8 {
    const cwd = Io.Dir.cwd();
    const kernel = try cwd.readFileAlloc(
        io,
        settings.kernel_path,
        allocator,
        .limited(zvmi.vm_payload.max_kernel_bytes),
    );
    const modules_builtin = try cwd.readFileAlloc(
        io,
        settings.modules_builtin_path,
        allocator,
        .limited(4 * 1024 * 1024),
    );
    const release = releaseFromKernelPath(settings.kernel_path) orelse
        return error.KernelPathDoesNotNameARelease;

    var image = try zvmi.Image.createExclusive(io, source_path, .raw, disk_size, .{});
    defer image.close(io);
    const boot_record = zvmi.mbr.singleLinuxPartitionMbr(
        partition_first_lba,
        partition_sectors,
    ).encode();
    try image.pwrite(io, &boot_record, 0);

    var tree = try zvmi.root_tree.RootTree.init(allocator, io, spool_path, .{});
    defer tree.deinit();
    inline for (.{
        "boot",    "dev",         "etc", "lib",     "proc",
        "run",     "sys",         "usr", "usr/bin", "var",
        "var/lib", "lib/modules",
    }) |path| {
        try tree.putDirectory(path, .{ .mode = 0o755 });
    }
    const module_directory = try std.fmt.allocPrint(
        allocator,
        "lib/modules/{s}",
        .{release},
    );
    try tree.putDirectory(module_directory, .{ .mode = 0o755 });
    try tree.putFileBytes(
        try std.fmt.allocPrint(allocator, "{s}/modules.builtin", .{module_directory}),
        modules_builtin,
        .{ .mode = 0o644 },
    );
    if (settings.module_tree_path) |source| {
        try stageModuleTree(allocator, io, &tree, module_directory, source);
    }
    try tree.putFileBytes(
        try std.fmt.allocPrint(allocator, "boot/vmlinuz-{s}", .{release}),
        kernel,
        .{ .mode = 0o644 },
    );
    // The agent is appended to whatever the image ships, so an archive holding
    // nothing but its own end marker is enough to prove the concatenation.
    try tree.putFileBytes(
        try std.fmt.allocPrint(allocator, "boot/initramfs-{s}.img", .{release}),
        cpio_trailer,
        .{ .mode = 0o600 },
    );
    try tree.putFileBytes(
        "usr/bin/rpm",
        guest_stubs.get(@tagName(settings.architecture)).?,
        .{ .mode = 0o755 },
    );
    _ = try zvmi.ext4.populate(io, image.file, allocator, try tree.ext4View(), .{
        .offset = partition_offset,
        .length = partition_length,
        .label = "vm-boot",
        .uuid = [_]u8{0x57} ** 16,
        .timestamp = 1_735_689_600,
    });
    return release;
}

/// Copies a real module tree into the image under `lib/modules/<release>`,
/// exactly as the kernel package laid it out.
///
/// Nothing here selects, renames or decompresses anything: the whole point is
/// that the backend is given a real tree and has to find its own way through
/// it, so a resolver that agrees with a fixture but not with a distribution
/// fails here rather than in production. A file the tree already holds --
/// `modules.builtin` in particular -- wins over what was staged before it.
fn stageModuleTree(
    allocator: Allocator,
    io: Io,
    tree: *zvmi.root_tree.RootTree,
    module_directory: []const u8,
    source_path: []const u8,
) !void {
    var dir = try Io.Dir.cwd().openDir(io, source_path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();

    var count: usize = 0;
    while (try walker.next(io)) |entry| {
        const destination = try std.fs.path.join(
            allocator,
            &.{ module_directory, entry.path },
        );
        defer allocator.free(destination);
        switch (entry.kind) {
            .directory => try tree.putDirectory(destination, .{ .mode = 0o755 }),
            .file => {
                const host_path = try std.fs.path.join(
                    allocator,
                    &.{ source_path, entry.path },
                );
                defer allocator.free(host_path);
                try tree.putFileFromPath(destination, host_path, .{ .mode = 0o644 });
                count += 1;
            },
            // A module tree with a symlink or a device node in it is not a
            // tree this test was handed on purpose.
            else => return error.UnsupportedModuleTreeEntry,
        }
    }
    std.debug.print("vm real boot: staged {d} module tree files\n", .{count});
}

fn releaseFromKernelPath(path: []const u8) ?[]const u8 {
    const name = std.fs.path.basename(path);
    const prefix = "vmlinuz-";
    if (!std.mem.startsWith(u8, name, prefix)) return null;
    const release = name[prefix.len..];
    return if (release.len == 0) null else release;
}

/// A newc header for `TRAILER!!!`, padded to a four-byte boundary.
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

fn expectGuestFile(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    guest_path: []const u8,
    expected: []const u8,
) !void {
    var image = try zvmi.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try zvmi.ext4.open(io, image.file, allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    const bytes = try reader.readFileAlloc(io, allocator, guest_path);
    defer allocator.free(bytes);
    if (!std.mem.eql(u8, bytes, expected)) return error.UnexpectedGuestFile;
}

fn expectMissingGuestFile(
    allocator: Allocator,
    io: Io,
    image_path: []const u8,
    guest_path: []const u8,
) !void {
    var image = try zvmi.Image.openPathReadOnly(io, image_path);
    defer image.close(io);
    var reader = try zvmi.ext4.open(io, image.file, allocator, .{
        .offset = partition_offset,
    });
    defer reader.deinit();
    _ = reader.statPath(io, guest_path) catch |err| switch (err) {
        error.NotFound => return,
        else => return err,
    };
    return error.UnexpectedGuestFile;
}

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

fn expectPathAbsent(io: Io, path: []const u8) !void {
    _ = Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    return error.UnexpectedPath;
}

fn ensure(condition: bool) !void {
    if (!condition) return error.BootAssertionFailed;
}
