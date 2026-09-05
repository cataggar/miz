//! Host-native entry point for the preserved-image `std.Build` helper.

const std = @import("std");
const builtin = @import("builtin");
const customization_loader = @import("customization_loader.zig");
const vm_firmware = @import("vm_firmware.zig");
const miz = @import("miz");
const wire = miz.preserved_image_wire;

/// The in-VM guest agents, embedded by the build graph. Both architectures
/// travel with the builder because cross-architecture customization is the
/// point of the `vm` backend: the runner architecture, not the host's, decides
/// which one boots.
const guest_agents = std.StaticStringMap([]const u8).initComptime(.{
    .{ "x86_64", @embedFile("miz_guest_agent_x86_64") },
    .{ "aarch64", @embedFile("miz_guest_agent_aarch64") },
});

const ParsedArgs = struct {
    api_version: u32 = miz.customize.current_api_version,
    architecture: miz.customize.Architecture,
    disk_path: []const u8,
    dependency_paths: []const []const u8,
    configuration_path: []const u8,
    operation_source_paths: []const []const u8,
    bundle_output_path: []const u8,
    image_basename: []const u8,
    format: miz.customize.OutputFormat,
    seed: miz.customize.Seed,
    source_date_epoch: u64,
    limits: miz.limits.ImportLimits = .{},
    preflight_only: bool = false,
    reuse_success: bool = false,
    verbose: bool = false,
};

const LoadedConfiguration = struct {
    backend: miz.customize.ExecutionBackend,
    root_partition: miz.customize.PartitionSelector,
    source_profile: miz.customize.SourceProfilePolicy,
    source_mounts: []const miz.customize.SourceMount,
    identity_rewrite: miz.customize.IdentityRewritePolicy,
    journal: miz.ext4.JournalOptions,
    inodes: miz.ext4.InodeOptions,
    operations: []const miz.customize.ExistingPathOperation,
    os: miz.customize.OsCustomization,
    generalization: miz.customize.GeneralizationPolicy,
    acknowledge_unsafe: bool,
    packages: miz.customize.PackagePolicy,
    hooks: []const miz.customize.Hook,
    initramfs: miz.customize.InitramfsPolicy,
    selinux: miz.customize.SelinuxPolicy,
    guest_execution: wire.GuestExecutionPolicy,
    runner: ?wire.Runner,
    vm: ?miz.customize.VmPolicy,
    deadline_seconds: ?u32 = null,
    /// Set when the configuration asked for a firmware boot without naming the
    /// EDK2 files. Resolution needs the runner architecture and the filesystem,
    /// so it happens in `main` where a failure can be reported as the
    /// resolution failure it is rather than as an invalid configuration.
    vm_firmware_unresolved: bool = false,
};

pub fn main(init: std.process.Init) !void {
    const arena = init.arena.allocator();
    const argv = try init.minimal.args.toSlice(arena);
    if (argv.len == 3 and std.mem.eql(u8, argv[1], "--unsafe-chroot-worker")) {
        return miz.unsafe_chroot.workerMain(init, argv[2]);
    }
    const args = parseArgs(arena, argv[1..]) catch |err| {
        std.debug.print("miz-preserved-image-builder: invalid arguments: {t}\n", .{err});
        std.process.exit(2);
    };
    if (!isBasename(args.image_basename) or isReservedBasename(args.image_basename)) {
        std.debug.print("miz-preserved-image-builder: image output must be a non-reserved basename\n", .{});
        std.process.exit(2);
    }

    const lock_path = try std.fmt.allocPrint(arena, "{s}.lock", .{args.bundle_output_path});
    validateIsolation(arena, init.io, &args, lock_path) catch |err| {
        std.debug.print("miz-preserved-image-builder: result paths overlap an input: {t}\n", .{err});
        std.process.exit(2);
    };
    const dependency_closure_exact = validateDependencyClosure(
        arena,
        init.io,
        &args,
        lock_path,
    ) catch |err| {
        std.debug.print("miz-preserved-image-builder: invalid disk dependency closure: {t}\n", .{err});
        std.process.exit(2);
    };

    const lock_file = acquireBundleLock(init.io, lock_path) catch |err| {
        std.debug.print("miz-preserved-image-builder: cannot lock result bundle: {t}\n", .{err});
        std.process.exit(1);
    };
    defer lock_file.close(init.io);

    if (dependency_closure_exact and
        args.reuse_success and
        try hasReusableSuccess(init.io, arena, argv, &args))
    {
        return;
    }

    try resetBundle(arena, init.io, args.bundle_output_path);
    std.Io.Dir.cwd().createDirPath(init.io, args.bundle_output_path) catch |err| {
        std.debug.print("miz-preserved-image-builder: cannot create result bundle: {t}\n", .{err});
        std.process.exit(1);
    };

    const output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, args.image_basename });
    const plan_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "plan.json" });
    const diagnostics_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "diagnostics.json" });
    const provenance_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "provenance.json" });
    const reuse_key_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "reuse-key" });
    const status_output_path = try std.fs.path.join(arena, &.{ args.bundle_output_path, "status" });
    try writeBytes(init.io, plan_output_path, "null\n");
    try writeBytes(init.io, diagnostics_output_path, "[]\n");
    try writeBytes(init.io, provenance_output_path, "null\n");
    try writeBytes(init.io, status_output_path, "failure\n");
    if (!dependency_closure_exact) {
        try writeRunnerDiagnostic(
            arena,
            init.io,
            diagnostics_output_path,
            .preflight,
            .missing_capability,
            "/input/disk/dependencies",
            "the declared disk dependencies do not match the source image closure",
            "declare every qcow2 backing and external-data file exactly once",
            null,
        );
        return;
    }
    const reuse_key_before = try computeReuseKey(arena, init.io, argv, &args);

    var keep_image = false;
    defer if (!keep_image) std.Io.Dir.cwd().deleteFile(init.io, output_path) catch {};

    const configuration = loadConfiguration(
        arena,
        init.io,
        args.configuration_path,
        args.operation_source_paths,
    ) catch |err| {
        try writeRunnerDiagnostic(
            arena,
            init.io,
            diagnostics_output_path,
            .validation,
            .invalid_customization,
            "/existing_path_operations",
            "the preserved-image operation configuration is invalid",
            "use the versioned configuration emitted by addPreservedImage",
            err,
        );
        return;
    };

    var vm_policy = configuration.vm;
    if (configuration.vm_firmware_unresolved) {
        const policy = &vm_policy.?;
        const firmware = &policy.boot.firmware;
        const options: vm_firmware.Options = .{
            .architecture = switch (configuration.guest_execution) {
                .same_architecture => args.architecture,
                .cross_architecture => switch (configuration.runner.?.guest_architecture) {
                    .x86_64 => .x86_64,
                    .aarch64 => .aarch64,
                },
            },
            .emulator_command = policy.emulator_command,
            .secure_boot = firmware.secure_boot,
            // Deterministic, because the resolved paths are hashed into the
            // plan: a per-run directory would move the plan hash for
            // unchanged inputs.
            .materialize_directory = try std.fs.path.join(
                arena,
                &.{ args.bundle_output_path, "firmware" },
            ),
        };
        const resolved_firmware = vm_firmware.resolveAlloc(arena, init.io, options) catch |err| {
            try writeRunnerDiagnostic(
                arena,
                init.io,
                diagnostics_output_path,
                .resolution,
                .missing_capability,
                "/execution/vm/boot/firmware/code_path",
                try vm_firmware.describeAlloc(arena, options, err),
                "install cataggar/qemu with ghr, or name --firmware-code and --firmware-vars in the customization",
                err,
            );
            return;
        };
        firmware.code_path = resolved_firmware.code_path;
        firmware.vars_path = resolved_firmware.vars_path;
    }

    const request = miz.customize.Request{
        .api_version = args.api_version,
        .target_architecture = args.architecture,
        .input = .{ .disk = .{
            .path = args.disk_path,
            .dependencies = args.dependency_paths,
        } },
        .output = .{
            .path = output_path,
            .format = args.format,
            .size = 0,
            .size_policy = .preserve_source,
        },
        .storage = .{ .preserve = .{
            .root_partition = configuration.root_partition,
            .source_profile = configuration.source_profile,
            .source_mounts = configuration.source_mounts,
            .identity_rewrite = configuration.identity_rewrite,
            .journal = configuration.journal,
            .inodes = configuration.inodes,
        } },
        .os = configuration.os,
        .existing_path_operations = configuration.operations,
        .packages = configuration.packages,
        .hooks = configuration.hooks,
        .initramfs = configuration.initramfs,
        .selinux = configuration.selinux,
        .cross_architecture = switch (configuration.guest_execution) {
            .same_architecture => .reject,
            .cross_architecture => .{ .runner = .{
                .kind = switch (configuration.runner.?.kind) {
                    .qemu_user => .qemu_user,
                    .binfmt_misc => .binfmt_misc,
                    .vm => .vm,
                },
                .guest_architecture = switch (configuration.runner.?.guest_architecture) {
                    .x86_64 => .x86_64,
                    .aarch64 => .aarch64,
                },
                .command = configuration.runner.?.command,
            } },
        },
        .execution = .{
            .workspace_path = args.bundle_output_path,
            .backend = configuration.backend,
            .acknowledge_unsafe = configuration.acknowledge_unsafe,
            .vm = vm_policy,
            .deadline_seconds = configuration.deadline_seconds,
        },
        .generalization = configuration.generalization,
        .reproducibility = .{
            .seed = args.seed,
            .source_date_epoch = args.source_date_epoch,
        },
        .limits = args.limits,
    };

    const host_architecture: miz.customize.Architecture = switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .aarch64,
        else => {
            try writeRunnerDiagnostic(
                arena,
                init.io,
                diagnostics_output_path,
                .resolution,
                .incompatible_architecture,
                "/architectures/host",
                "the host architecture is unsupported",
                "run the host-native builder on x86_64 or aarch64",
                null,
            );
            return;
        },
    };

    var resolved = try miz.customize.resolve(init.gpa, &request, .{
        .host_architecture = host_architecture,
    });
    defer resolved.deinit(init.gpa);
    const self_exe = try std.process.executablePathAlloc(init.io, arena);
    var unsafe_context = UnsafeRuntimeContext{
        .self_exe = self_exe,
        .environ = init.minimal.environ,
    };
    const platform = unsafePlatform(&unsafe_context);
    if (resolved.plan) |*plan| try writePlan(init.gpa, init.io, plan_output_path, plan);
    if (resolved.diagnostics.hasErrors()) {
        try writeDiagnostics(init.gpa, init.io, diagnostics_output_path, resolved.diagnostics);
        return;
    }

    if (args.preflight_only) {
        var report = try miz.customize.preflight(
            init.gpa,
            init.io,
            &resolved.plan.?,
            platform,
        );
        defer report.deinit(init.gpa);
        try writeDiagnostics(init.gpa, init.io, diagnostics_output_path, report.diagnostics);
        if (!report.ready()) return;
        if (!try inputsUnchanged(arena, init.io, argv, &args, reuse_key_before)) {
            try writeRunnerDiagnostic(
                arena,
                init.io,
                diagnostics_output_path,
                .preflight,
                .source_changed,
                "/input",
                "an input changed during preflight",
                "retry with immutable build inputs",
                null,
            );
            return;
        }
        try writeBytes(init.io, status_output_path, "success\n");
        return;
    }

    var console = ConsoleEvents{ .verbose = args.verbose };
    var outcome = try miz.customize.execute(
        init.gpa,
        init.io,
        &resolved.plan.?,
        platform,
        .{ .context = &console, .emitFn = ConsoleEvents.emit },
    );
    defer outcome.deinit(init.gpa);
    try writeDiagnostics(init.gpa, init.io, diagnostics_output_path, outcome.diagnostics);
    const result = if (outcome.result) |*success| success else return;

    if (!try inputsUnchanged(arena, init.io, argv, &args, reuse_key_before)) {
        try writeRunnerDiagnostic(
            arena,
            init.io,
            diagnostics_output_path,
            .execution,
            .source_changed,
            "/input",
            "an input changed during preserved-image execution",
            "retry with immutable build inputs",
            null,
        );
        return;
    }
    if (!std.mem.eql(u8, result.output_path, output_path)) {
        try writeRunnerDiagnostic(
            arena,
            init.io,
            diagnostics_output_path,
            .execution,
            .commit_failed,
            "/output/path",
            "the runtime published an unexpected output path",
            "use the unmodified plan returned by resolve",
            null,
        );
        return;
    }
    const output_stat = std.Io.Dir.cwd().statFile(init.io, output_path, .{}) catch |err| {
        try writeRunnerDiagnostic(
            arena,
            init.io,
            diagnostics_output_path,
            .execution,
            .commit_failed,
            "/output/path",
            "the runtime did not publish a readable image",
            "inspect the execution diagnostics and retry",
            err,
        );
        return;
    };
    if (output_stat.kind != .file) {
        try writeRunnerDiagnostic(
            arena,
            init.io,
            diagnostics_output_path,
            .execution,
            .commit_failed,
            "/output/path",
            "the runtime output is not a regular file",
            "choose a regular-file image output",
            null,
        );
        return;
    }

    try writeProvenance(init.gpa, init.io, provenance_output_path, result.provenance);
    try writeReuseKey(init.io, reuse_key_output_path, reuse_key_before);
    try writeBytes(init.io, status_output_path, "success\n");
    keep_image = true;
}

fn parseArgs(allocator: std.mem.Allocator, args: []const []const u8) !ParsedArgs {
    var api_version: u32 = miz.customize.current_api_version;
    var architecture: ?miz.customize.Architecture = null;
    var disk_path: ?[]const u8 = null;
    var dependencies = std.array_list.Managed([]const u8).init(allocator);
    errdefer dependencies.deinit();
    var configuration_path: ?[]const u8 = null;
    var operation_sources = std.array_list.Managed([]const u8).init(allocator);
    errdefer operation_sources.deinit();
    var bundle_output_path: ?[]const u8 = null;
    var image_basename: ?[]const u8 = null;
    var format: ?miz.customize.OutputFormat = null;
    var seed: ?miz.customize.Seed = null;
    var source_date_epoch: ?u64 = null;
    var limits: miz.limits.ImportLimits = .{};
    var preflight_only = false;
    var reuse_success = false;
    var verbose = false;

    var i: usize = 0;
    while (i < args.len) : (i += 1) {
        const arg = args[i];
        if (std.mem.eql(u8, arg, "--preflight-only")) {
            preflight_only = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--reuse-success")) {
            reuse_success = true;
            continue;
        }
        if (std.mem.eql(u8, arg, "--verbose")) {
            verbose = true;
            continue;
        }

        i += 1;
        if (i >= args.len) return error.MissingArgumentValue;
        const value = args[i];
        if (std.mem.eql(u8, arg, "--api-version")) {
            api_version = try std.fmt.parseInt(u32, value, 10);
        } else if (std.mem.eql(u8, arg, "--architecture")) {
            architecture = parseArchitecture(value) orelse return error.InvalidArchitecture;
        } else if (std.mem.eql(u8, arg, "--disk")) {
            disk_path = value;
        } else if (std.mem.eql(u8, arg, "--disk-dependency")) {
            try dependencies.append(value);
        } else if (std.mem.eql(u8, arg, "--configuration")) {
            configuration_path = value;
        } else if (std.mem.eql(u8, arg, "--operation-source")) {
            try operation_sources.append(value);
        } else if (std.mem.eql(u8, arg, "--bundle-output")) {
            bundle_output_path = value;
        } else if (std.mem.eql(u8, arg, "--image-basename")) {
            image_basename = value;
        } else if (std.mem.eql(u8, arg, "-O")) {
            format = parseFormat(value) orelse return error.InvalidFormat;
        } else if (std.mem.eql(u8, arg, "--seed")) {
            if (value.len != 64) return error.InvalidSeed;
            var bytes: [32]u8 = undefined;
            const decoded = try std.fmt.hexToBytes(&bytes, value);
            if (decoded.len != bytes.len) return error.InvalidSeed;
            seed = .{ .bytes = bytes };
        } else if (std.mem.eql(u8, arg, "--source-date-epoch")) {
            source_date_epoch = try std.fmt.parseInt(u64, value, 10);
        } else if (try limits.parseFlag(arg, value)) {
            // Handled: `arg` named an import limit and `value` raised it.
        } else {
            return error.UnexpectedArgument;
        }
    }
    if (preflight_only and reuse_success) return error.IncompatibleFlags;

    return .{
        .api_version = api_version,
        .architecture = architecture orelse return error.MissingArchitecture,
        .disk_path = disk_path orelse return error.MissingDisk,
        .dependency_paths = try dependencies.toOwnedSlice(),
        .configuration_path = configuration_path orelse return error.MissingConfiguration,
        .operation_source_paths = try operation_sources.toOwnedSlice(),
        .bundle_output_path = bundle_output_path orelse return error.MissingBundleOutput,
        .image_basename = image_basename orelse return error.MissingImageBasename,
        .format = format orelse return error.MissingFormat,
        .seed = seed orelse return error.MissingSeed,
        .source_date_epoch = source_date_epoch orelse return error.MissingSourceDateEpoch,
        .limits = limits,
        .preflight_only = preflight_only,
        .reuse_success = reuse_success,
        .verbose = verbose,
    };
}

fn loadConfiguration(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    source_paths: []const []const u8,
) !LoadedConfiguration {
    const bytes = try std.Io.Dir.cwd().readFileAlloc(
        io,
        path,
        allocator,
        .limited(16 * 1024 * 1024),
    );
    // Safe only because the loaders parse with `.alloc_always`; by default
    // `std.json` returns slices into this buffer.
    defer allocator.free(bytes);
    return parseConfiguration(allocator, bytes, source_paths);
}

fn parseConfiguration(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    source_paths: []const []const u8,
) !LoadedConfiguration {
    const header = try std.json.parseFromSlice(
        struct { api_version: u32 = wire.previous_api_version },
        allocator,
        bytes,
        .{ .ignore_unknown_fields = true },
    );
    defer header.deinit();
    return switch (header.value.api_version) {
        wire.previous_api_version => loadV2Configuration(
            allocator,
            bytes,
            source_paths,
        ),
        wire.api_version => loadV3Configuration(
            allocator,
            bytes,
            source_paths,
        ),
        else => error.UnsupportedApiVersion,
    };
}

fn loadV2Configuration(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    source_paths: []const []const u8,
) !LoadedConfiguration {
    const parsed = try std.json.parseFromSlice(
        wire.ConfigurationV2,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    try wire.validateV2(parsed.value, source_paths.len);
    const customization = try customization_loader.map(
        allocator,
        parsed.value.customization,
        source_paths,
    );
    return .{
        .backend = switch (parsed.value.backend) {
            .native_edit => .native_edit,
            .rebuild => .rebuild,
        },
        .root_partition = switch (parsed.value.root_partition) {
            .gpt_index => |index| .{ .gpt_index = index },
            .mbr_index => |index| .{ .mbr_index = index },
            // Refused by `validateV2` above; spelled out so this switch
            // stays exhaustive rather than silently mapping a v3 shape.
            .logical_volume => return error.UnsupportedPartitionSelectorForApiVersion,
        },
        .source_profile = .strict,
        .source_mounts = &.{},
        .identity_rewrite = .rewrite_and_verify,
        // The v2 wire format has neither a journal nor an inode field, so a
        // v2 configuration keeps producing exactly what it always has.
        .journal = .{},
        .inodes = .{},
        .operations = try mapOperations(allocator, parsed.value.operations, source_paths),
        .os = customization.os,
        .generalization = customization.generalization,
        .acknowledge_unsafe = false,
        .packages = .{},
        .hooks = &.{},
        .initramfs = .unchanged,
        .selinux = .unchanged,
        .guest_execution = .same_architecture,
        .runner = null,
        .vm = null,
    };
}

fn loadV3Configuration(
    allocator: std.mem.Allocator,
    bytes: []const u8,
    source_paths: []const []const u8,
) !LoadedConfiguration {
    const parsed = try std.json.parseFromSlice(
        wire.Configuration,
        allocator,
        bytes,
        .{ .ignore_unknown_fields = false, .allocate = .alloc_always },
    );
    try wire.validate(parsed.value, source_paths.len);
    const customization = try customization_loader.map(
        allocator,
        parsed.value.customization,
        source_paths,
    );
    return .{
        .backend = switch (parsed.value.backend) {
            .native_edit => .native_edit,
            .rebuild => .rebuild,
            .unsafe_chroot => .unsafe_chroot,
            .vm => .vm,
        },
        .root_partition = switch (parsed.value.root_partition) {
            .gpt_index => |index| .{ .gpt_index = index },
            .mbr_index => |index| .{ .mbr_index = index },
            .logical_volume => |volume| .{ .logical_volume = .{
                .volume_group = volume.volume_group,
                .logical_volume = volume.logical_volume,
            } },
        },
        .source_profile = switch (parsed.value.source_profile) {
            .strict => .strict,
            .general => .general,
        },
        .source_mounts = try mapSourceMounts(allocator, parsed.value.source_mounts),
        .identity_rewrite = switch (parsed.value.identity_rewrite) {
            .rewrite_and_verify => .rewrite_and_verify,
            .rewrite_only => .rewrite_only,
            .off => .off,
        },
        .journal = .{
            .enabled = parsed.value.journal.enabled,
            .size_bytes = parsed.value.journal.size_bytes,
        },
        .inodes = .{ .bytes_per_inode = parsed.value.inodes.bytes_per_inode },
        .operations = try mapOperations(allocator, parsed.value.operations, source_paths),
        .os = customization.os,
        .generalization = customization.generalization,
        .acknowledge_unsafe = parsed.value.acknowledge_unsafe,
        .packages = try mapPackagePolicy(
            allocator,
            parsed.value.packages,
            source_paths,
        ),
        .hooks = try mapHooks(allocator, parsed.value.hooks, source_paths),
        .initramfs = try mapInitramfsPolicy(allocator, parsed.value.initramfs),
        .selinux = switch (parsed.value.selinux) {
            .unchanged => .unchanged,
            .relabel => .relabel,
        },
        .guest_execution = parsed.value.guest_execution,
        .runner = parsed.value.runner,
        .vm = mapVmPolicy(parsed.value.vm),
        .vm_firmware_unresolved = vmFirmwareUnresolved(parsed.value.vm),
        .deadline_seconds = parsed.value.deadline_seconds,
    };
}

fn vmFirmwareUnresolved(configuration: ?wire.VmConfiguration) bool {
    const present = configuration orelse return false;
    return switch (present.boot) {
        .direct_kernel => false,
        .firmware => |firmware| firmware.code_path == null,
    };
}

fn mapSourceMounts(
    allocator: std.mem.Allocator,
    mounts: []const wire.SourceMount,
) ![]const miz.customize.SourceMount {
    const mapped = try allocator.alloc(miz.customize.SourceMount, mounts.len);
    for (mounts, mapped) |mount, *slot| {
        slot.* = .{
            .source_path = mount.source_path,
            .partition = switch (mount.partition) {
                .gpt_index => |index| .{ .gpt_index = index },
                .mbr_index => |index| .{ .mbr_index = index },
                .logical_volume => |volume| .{ .logical_volume = .{
                    .volume_group = volume.volume_group,
                    .logical_volume = volume.logical_volume,
                } },
            },
            .target = mount.target,
            .filesystem = switch (mount.filesystem) {
                .detect => .detect,
                .ext4 => .ext4,
                .fat32 => .fat32,
                .xfs => .xfs,
            },
            .fat_metadata = .{
                .directory_mode = mount.fat_metadata.directory_mode,
                .file_mode = mount.fat_metadata.file_mode,
                .uid = mount.fat_metadata.uid,
                .gid = mount.fat_metadata.gid,
            },
        };
    }
    return mapped;
}

fn mapVmPolicy(configuration: ?wire.VmConfiguration) ?miz.customize.VmPolicy {
    const present = configuration orelse return null;
    return .{
        .emulator_command = present.emulator_command,
        .boot = switch (present.boot) {
            .direct_kernel => .direct_kernel,
            .firmware => |firmware| .{
                .firmware = .{
                    // Empty paths never reach the plan: `main` resolves them
                    // before the request is built, and refuses the run if it
                    // cannot. Validation would reject them anyway.
                    .code_path = firmware.code_path orelse "",
                    .vars_path = firmware.vars_path orelse "",
                    .console_marker = firmware.console_marker,
                    .secure_boot = firmware.secure_boot,
                    .boot_timeout_seconds = firmware.boot_timeout_seconds,
                },
            },
        },
        .acceleration = switch (present.acceleration) {
            .hardware => .hardware,
            .software => .software,
        },
        .acknowledge_software_emulation = present.acknowledge_software_emulation,
        .memory_mib = present.memory_mib,
        .vcpus = present.vcpus,
        .network = switch (present.network) {
            .offline => .offline,
            .declared_repositories => .declared_repositories,
        },
        .boot_timeout_seconds = present.boot_timeout_seconds,
        .machine = present.machine,
        .cpu = present.cpu,
    };
}

fn mapOperations(
    allocator: std.mem.Allocator,
    operations: []const wire.Operation,
    source_paths: []const []const u8,
) ![]const miz.customize.ExistingPathOperation {
    const mapped = try allocator.alloc(miz.customize.ExistingPathOperation, operations.len);
    errdefer allocator.free(mapped);
    for (operations, 0..) |operation, index| {
        mapped[index] = switch (operation) {
            .overwrite_file => |overwrite| .{ .overwrite_file = .{
                .path = overwrite.path,
                .source = .{ .host_path = if (overwrite.source_index < source_paths.len)
                    source_paths[overwrite.source_index]
                else
                    return error.SourceIndexOutOfBounds },
            } },
            .remove_file => |path| .{ .remove_file = path },
            .remove_tree => |path| .{ .remove_tree = path },
        };
    }
    return mapped;
}

/// Hook sources arrive as indices into the staged source list, the same way
/// repository trust does. Both forms the build API offers -- an inline script
/// and a path -- reach here as a file the build system staged, so the CLI has
/// one shape to map rather than two.
fn mapHooks(
    allocator: std.mem.Allocator,
    hooks: []const wire.Hook,
    source_paths: []const []const u8,
) ![]const miz.customize.Hook {
    const mapped = try allocator.alloc(miz.customize.Hook, hooks.len);
    errdefer allocator.free(mapped);
    for (hooks, mapped) |hook, *slot| {
        if (hook.source.source_index >= source_paths.len) {
            return error.SourceIndexOutOfBounds;
        }
        slot.* = .{
            .name = hook.name,
            .phase = switch (hook.phase) {
                .after_packages => .after_packages,
                .before_initramfs => .before_initramfs,
                .before_seal => .before_seal,
                .finalize => .finalize,
            },
            .source = .{ .host_path = source_paths[hook.source.source_index] },
            .arguments = hook.arguments,
        };
    }
    return mapped;
}

fn mapPackagePolicy(
    allocator: std.mem.Allocator,
    policy: wire.PackagePolicy,
    source_paths: []const []const u8,
) !miz.customize.PackagePolicy {
    const actions = try allocator.alloc(
        miz.customize.PackageAction,
        policy.actions.len,
    );
    errdefer allocator.free(actions);
    for (policy.actions, 0..) |action, index| {
        actions[index] = switch (action) {
            .install => |packages| .{ .install = packages },
            .remove => |packages| .{ .remove = packages },
            .update_all => .update_all,
            .update_selected => |packages| .{ .update_selected = packages },
        };
    }
    const repositories = try allocator.alloc(
        miz.customize.PackageRepository,
        policy.repositories.len,
    );
    errdefer allocator.free(repositories);
    // Each repository owns a trust slice, so a refusal partway through has to
    // free the ones already built. Recording the repository before filling its
    // trust in is what lets a single count describe everything allocated.
    var owned_repositories: usize = 0;
    errdefer for (repositories[0..owned_repositories]) |built| {
        allocator.free(built.trust);
    };
    for (policy.repositories, 0..) |repository, index| {
        const trust = try allocator.alloc(
            miz.customize.TrustSource,
            repository.trust.len,
        );
        repositories[index] = .{
            .id = repository.id,
            .urls = repository.urls,
            .trust = trust,
            .use = switch (repository.use) {
                .package_manager => .package_manager,
                .network_only => .network_only,
            },
            .credential = if (repository.credential) |credential| switch (credential) {
                .basic => |basic| .{ .basic = .{
                    .username = basic.username,
                    .password = switch (basic.password) {
                        .host_path => |path| .{ .host_path = path },
                        .host_environment => |name| .{ .host_environment = name },
                    },
                } },
            } else null,
        };
        owned_repositories = index + 1;
        for (repository.trust, 0..) |source, source_index| {
            if (source.source_index >= source_paths.len) {
                return error.SourceIndexOutOfBounds;
            }
            trust[source_index] = .{
                .host_path = source_paths[source.source_index],
            };
        }
    }
    return .{
        .actions = actions,
        .repositories = repositories,
        .cache = switch (policy.cache) {
            .online => .online,
            .online_populating => |path| .{ .online_populating = path },
            .cache_only => |path| .{ .cache_only = path },
        },
        .lock = switch (policy.lock) {
            .unlocked => .unlocked,
            .snapshot => |snapshot| .{ .snapshot = snapshot },
            .exact => |locks| exact: {
                const mapped = try allocator.alloc(
                    miz.customize.PackageVersionLock,
                    locks.len,
                );
                for (locks, 0..) |lock, index| mapped[index] = .{
                    .name = lock.name,
                    .evr = lock.evr,
                    .architecture = lock.architecture,
                };
                break :exact .{ .exact = mapped };
            },
        },
        .resolver = switch (policy.resolver) {
            .host_resolver => .host_resolver,
            .nameservers => |nameservers| .{ .nameservers = nameservers },
        },
    };
}

fn mapInitramfsPolicy(
    allocator: std.mem.Allocator,
    policy: wire.InitramfsPolicy,
) !miz.customize.InitramfsPolicy {
    return switch (policy) {
        .unchanged => .unchanged,
        .regenerate => |regenerate| .{ .regenerate = .{
            .generator = if (regenerate.generator) |generator|
                try allocator.dupe(u8, generator)
            else
                null,
            .kernels = regenerate.kernels,
            .no_installed_kernels = switch (regenerate.no_installed_kernels) {
                .fail => .fail,
                .nothing_to_regenerate => .nothing_to_regenerate,
            },
        } },
        .when_needed => |when_needed| .{ .when_needed = .{
            .generator = if (when_needed.generator) |generator|
                try allocator.dupe(u8, generator)
            else
                null,
        } },
    };
}

fn parseArchitecture(value: []const u8) ?miz.customize.Architecture {
    if (std.mem.eql(u8, value, "x86_64")) return .x86_64;
    if (std.mem.eql(u8, value, "aarch64")) return .aarch64;
    return null;
}

fn parseFormat(value: []const u8) ?miz.customize.OutputFormat {
    return miz.customize.OutputFormat.parseName(value);
}

fn isBasename(path: []const u8) bool {
    return path.len != 0 and
        !std.fs.path.isAbsolute(path) and
        std.mem.eql(u8, path, std.fs.path.basename(path)) and
        !std.mem.eql(u8, path, ".") and
        !std.mem.eql(u8, path, "..");
}

fn isReservedBasename(path: []const u8) bool {
    return std.ascii.eqlIgnoreCase(path, "status") or
        std.ascii.eqlIgnoreCase(path, "plan.json") or
        std.ascii.eqlIgnoreCase(path, "diagnostics.json") or
        std.ascii.eqlIgnoreCase(path, "provenance.json") or
        std.ascii.eqlIgnoreCase(path, "reuse-key");
}

fn validateIsolation(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: *const ParsedArgs,
    lock_path: []const u8,
) !void {
    try validateInputIsolation(allocator, io, args.bundle_output_path, args.disk_path);
    try validateInputIsolation(allocator, io, lock_path, args.disk_path);
    for (args.dependency_paths) |path| {
        try validateInputIsolation(allocator, io, args.bundle_output_path, path);
        try validateInputIsolation(allocator, io, lock_path, path);
    }
    try validateInputIsolation(allocator, io, args.bundle_output_path, args.configuration_path);
    try validateInputIsolation(allocator, io, lock_path, args.configuration_path);
    for (args.operation_source_paths) |path| {
        try validateInputIsolation(allocator, io, args.bundle_output_path, path);
        try validateInputIsolation(allocator, io, lock_path, path);
    }
}

fn validateDependencyClosure(
    allocator: std.mem.Allocator,
    io: std.Io,
    args: *const ParsedArgs,
    lock_path: []const u8,
) !bool {
    var image = try miz.Image.openPathReadOnly(io, args.disk_path);
    defer image.close(io);
    const discovered = try image.sourceDependencyPaths(allocator);
    defer {
        for (discovered) |path| allocator.free(path);
        allocator.free(discovered);
    }

    for (discovered) |path| {
        try validateInputIsolation(allocator, io, args.bundle_output_path, path);
        try validateInputIsolation(allocator, io, lock_path, path);
    }
    return samePathSet(args.dependency_paths, discovered);
}

fn samePathSet(expected: []const []const u8, actual: []const []u8) bool {
    if (expected.len != actual.len) return false;
    for (expected) |expected_path| {
        for (actual) |actual_path| {
            if (std.mem.eql(u8, expected_path, actual_path)) break;
        } else return false;
    }
    return true;
}

fn validateInputIsolation(
    allocator: std.mem.Allocator,
    io: std.Io,
    result_path: []const u8,
    input_path: []const u8,
) !void {
    if (try pathsOverlapCanonically(allocator, io, result_path, input_path)) {
        return error.ResultPathOverlap;
    }
}

fn pathsOverlapCanonically(
    allocator: std.mem.Allocator,
    io: std.Io,
    first: []const u8,
    second: []const u8,
) !bool {
    const canonical_first = try canonicalProspectivePath(allocator, io, first);
    const canonical_second = try canonicalProspectivePath(allocator, io, second);
    return pathOverlaps(canonical_first, canonical_second);
}

fn canonicalProspectivePath(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) ![]const u8 {
    const resolved = try std.fs.path.resolve(allocator, &.{path});
    const absolute = if (std.fs.path.isAbsolute(resolved))
        resolved
    else blk: {
        var cwd_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
        const cwd_len = try std.Io.Dir.cwd().realPathFile(io, ".", &cwd_buffer);
        break :blk try std.fs.path.join(allocator, &.{ cwd_buffer[0..cwd_len], resolved });
    };
    var candidate: []const u8 = absolute;
    var buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    while (true) {
        if (std.Io.Dir.cwd().realPathFile(io, candidate, &buffer)) |len| {
            return try std.mem.concat(allocator, u8, &.{ buffer[0..len], absolute[candidate.len..] });
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return err,
        }

        const parent = std.fs.path.dirname(candidate) orelse return absolute;
        if (std.mem.eql(u8, parent, candidate)) return absolute;
        candidate = parent;
    }
}

fn pathOverlaps(first: []const u8, second: []const u8) bool {
    if (std.mem.eql(u8, first, second)) return true;
    return pathContains(first, second) or pathContains(second, first);
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    if (!std.mem.startsWith(u8, child, parent) or child.len <= parent.len) return false;
    return std.fs.path.isSep(parent[parent.len - 1]) or std.fs.path.isSep(child[parent.len]);
}

fn hasReusableSuccess(
    io: std.Io,
    allocator: std.mem.Allocator,
    argv: []const []const u8,
    args: *const ParsedArgs,
) !bool {
    const status_path = try std.fs.path.join(allocator, &.{ args.bundle_output_path, "status" });
    const status = std.Io.Dir.cwd().readFileAlloc(io, status_path, allocator, .limited(64)) catch return false;
    if (!std.mem.eql(u8, std.mem.trim(u8, status, " \r\n\t"), "success")) return false;

    const required_files = [_][]const u8{
        args.image_basename,
        "plan.json",
        "diagnostics.json",
        "provenance.json",
        "reuse-key",
    };
    for (required_files) |basename| {
        const path = try std.fs.path.join(allocator, &.{ args.bundle_output_path, basename });
        const stat = std.Io.Dir.cwd().statFile(io, path, .{}) catch return false;
        if (stat.kind != .file) return false;
    }

    const reuse_key_path = try std.fs.path.join(allocator, &.{ args.bundle_output_path, "reuse-key" });
    const stored_key = std.Io.Dir.cwd().readFileAlloc(io, reuse_key_path, allocator, .limited(128)) catch return false;
    const current_key = computeReuseKey(allocator, io, argv, args) catch return false;
    const current_hex = std.fmt.bytesToHex(current_key, .lower);
    return std.mem.eql(u8, std.mem.trim(u8, stored_key, " \r\n\t"), &current_hex);
}

fn inputsUnchanged(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    args: *const ParsedArgs,
    expected: [32]u8,
) !bool {
    const current = try computeReuseKey(allocator, io, argv, args);
    return std.mem.eql(u8, &expected, &current);
}

fn computeReuseKey(
    allocator: std.mem.Allocator,
    io: std.Io,
    argv: []const []const u8,
    args: *const ParsedArgs,
) ![32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("miz-preserved-image-builder-reuse-v1\x00");
    for (argv[1..]) |arg| {
        var length: [8]u8 = undefined;
        std.mem.writeInt(u64, &length, arg.len, .big);
        hash.update(&length);
        hash.update(arg);
    }

    try hashSource(&hash, allocator, io, argv[0]);
    try hashSource(&hash, allocator, io, args.disk_path);
    for (args.dependency_paths) |path| try hashSource(&hash, allocator, io, path);
    try hashSource(&hash, allocator, io, args.configuration_path);
    for (args.operation_source_paths) |path| try hashSource(&hash, allocator, io, path);

    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn hashSource(
    hash: *std.crypto.hash.sha2.Sha256,
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !void {
    const digest = try miz.customize.hashSourcePath(allocator, io, path);
    hash.update(&digest.bytes);
}

const UnsafeRuntimeContext = struct {
    self_exe: []const u8,
    environ: std.process.Environ = .empty,
    availability: ?miz.customize.CapabilityState = null,
};

fn unsafePlatform(context: *UnsafeRuntimeContext) miz.customize.Platform {
    var platform = miz.customize.Platform.system();
    platform.context = context;
    platform.unsafeChrootCheckFn = checkUnsafeChroot;
    platform.unsafeChrootRunFn = runUnsafeChroot;
    platform.vmCheckFn = checkVm;
    platform.vmRunFn = runVm;
    return platform;
}

fn checkUnsafeChroot(
    context_ptr: ?*anyopaque,
    io: std.Io,
    _: *const miz.customize.ResolvedPlan,
) miz.customize.CapabilityState {
    const context: *UnsafeRuntimeContext = @ptrCast(@alignCast(context_ptr.?));
    if (context.availability == null) {
        context.availability = miz.unsafe_chroot.available(io);
    }
    return context.availability.?;
}

fn runUnsafeChroot(
    context_ptr: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    plan: *const miz.customize.ResolvedPlan,
    target: miz.preserved_image.RawMutationTarget,
    deadline: miz.customize.Deadline,
) !miz.customize.UnsafeChrootRuntimeReport {
    const context: *UnsafeRuntimeContext = @ptrCast(@alignCast(context_ptr.?));
    return miz.unsafe_chroot.runParent(allocator, io, .{
        .self_exe = context.self_exe,
        .transaction_path = plan.data.transaction_path,
        .plan = plan,
        .target = target,
        .environ = context.environ,
        .deadline = deadline,
    });
}

fn checkVm(
    _: ?*anyopaque,
    io: std.Io,
    plan: *const miz.customize.ResolvedPlan,
) miz.customize.CapabilityState {
    return miz.vm_backend.available(io, plan);
}

fn runVm(
    context_ptr: ?*anyopaque,
    allocator: std.mem.Allocator,
    io: std.Io,
    plan: *const miz.customize.ResolvedPlan,
    target: miz.preserved_image.RawMutationTarget,
    deadline: miz.customize.Deadline,
) !miz.customize.VmRuntimeReport {
    const context: *UnsafeRuntimeContext = @ptrCast(@alignCast(context_ptr.?));
    const agent = guest_agents.get(
        @tagName(plan.data.architectures.runner),
    ) orelse return error.VmGuestAgentUnavailable;
    return miz.vm_backend.run(allocator, io, .{
        .plan = plan,
        .transaction_path = plan.data.transaction_path,
        .target = target,
        .agent = .{ .embedded_bytes = agent },
        .console = .{ .writeFn = writeGuestConsole },
        // The same environment the chroot backend reads, for the same reason:
        // a credential declared as `host_environment` is resolved from the
        // caller's environment, and reading the process's own would make the
        // library's answer depend on something the caller never handed it.
        .environ = context.environ,
        .deadline = deadline,
    });
}

/// A failed guest's console is the only account of what went wrong, so it is
/// forwarded verbatim rather than summarized.
fn writeGuestConsole(_: ?*anyopaque, bytes: []const u8) void {
    if (bytes.len == 0) return;
    const stderr = std.debug.lockStderr(&.{});
    defer std.debug.unlockStderr();
    stderr.file_writer.interface.writeAll(bytes) catch {};
}

fn resetBundle(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
) !void {
    const cwd = std.Io.Dir.cwd();
    const stat = cwd.statFile(io, path, .{ .follow_symlinks = false }) catch |err| switch (err) {
        error.FileNotFound => return,
        else => return err,
    };
    if (stat.kind == .directory) {
        var dir = try cwd.openDir(io, path, .{ .iterate = true });
        defer dir.close(io);
        var walker = try dir.walk(allocator);
        defer walker.deinit();
        while (try walker.next(io)) |entry| {
            if (std.mem.eql(
                u8,
                entry.basename,
                miz.unsafe_chroot.active_lease_basename,
            )) {
                return error.MutationResourcesActive;
            }
        }
        try cwd.deleteTree(io, path);
    } else {
        try cwd.deleteFile(io, path);
    }
}

test "bundle reset preserves transactions with active backend resources" {
    const io = std.testing.io;
    const bundle_path = "test-active-bundle";
    const transaction_path = bundle_path ++ "/transaction";
    defer std.Io.Dir.cwd().deleteTree(io, bundle_path) catch {};
    try std.Io.Dir.cwd().createDirPath(io, transaction_path);
    var marker_buffer: [std.Io.Dir.max_path_bytes]u8 = undefined;
    const marker_path = try miz.unsafe_chroot.activeLeasePath(
        transaction_path,
        &marker_buffer,
    );
    try writeBytes(io, marker_path, "");

    try std.testing.expectError(
        error.MutationResourcesActive,
        resetBundle(std.testing.allocator, io, bundle_path),
    );
    _ = try std.Io.Dir.cwd().statFile(io, transaction_path, .{});

    try std.Io.Dir.cwd().deleteFile(io, marker_path);
    try resetBundle(std.testing.allocator, io, bundle_path);
    try std.testing.expectError(
        error.FileNotFound,
        std.Io.Dir.cwd().statFile(io, bundle_path, .{}),
    );
}

fn acquireBundleLock(io: std.Io, path: []const u8) !std.Io.File {
    const cwd = std.Io.Dir.cwd();
    if (std.fs.path.dirname(path)) |parent| try cwd.createDirPath(io, parent);
    return cwd.createFile(io, path, .{
        .read = true,
        .truncate = false,
        .lock = .exclusive,
    });
}

fn writeReuseKey(io: std.Io, path: []const u8, key: [32]u8) !void {
    const key_hex = std.fmt.bytesToHex(key, .lower);
    var bytes: [key_hex.len + 1]u8 = undefined;
    @memcpy(bytes[0..key_hex.len], &key_hex);
    bytes[key_hex.len] = '\n';
    try writeBytes(io, path, &bytes);
}

fn writePlan(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    plan: *const miz.customize.ResolvedPlan,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try miz.customize.writePlanJson(plan, &output.writer);
    try writeBytes(io, path, output.written());
}

fn writeDiagnostics(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    diagnostics: miz.customize.DiagnosticSet,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try miz.customize.writeDiagnosticsJson(diagnostics, &output.writer);
    try writeBytes(io, path, output.written());
}

fn writeRunnerDiagnostic(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    phase: miz.customize.DiagnosticPhase,
    code: miz.customize.DiagnosticCode,
    configuration_path: []const u8,
    message: []const u8,
    remediation: []const u8,
    cause: ?anyerror,
) !void {
    var items = [_]miz.customize.Diagnostic{.{
        .severity = .@"error",
        .phase = phase,
        .code = code,
        .configuration_path = configuration_path,
        .message = message,
        .cause = if (cause) |err| .{ .error_name = @errorName(err) } else null,
        .remediation = remediation,
    }};
    try writeDiagnostics(allocator, io, path, .{ .items = &items });
}

fn writeProvenance(
    allocator: std.mem.Allocator,
    io: std.Io,
    path: []const u8,
    provenance: miz.customize.Provenance,
) !void {
    var output: std.Io.Writer.Allocating = .init(allocator);
    defer output.deinit();
    try miz.customize.writeProvenanceJson(provenance, &output.writer);
    try writeBytes(io, path, output.written());
}

fn writeBytes(io: std.Io, path: []const u8, bytes: []const u8) !void {
    const file = try std.Io.Dir.cwd().createFile(io, path, .{ .truncate = true });
    defer file.close(io);
    try file.writePositionalAll(io, bytes, 0);
}

const ConsoleEvents = struct {
    verbose: bool,

    fn emit(context: ?*anyopaque, event: miz.customize.ExecutionEvent) void {
        const self: *ConsoleEvents = @ptrCast(@alignCast(context.?));
        switch (event) {
            .progress => |progress| if (self.verbose) {
                std.debug.print("miz-preserved-image-builder: {s}\n", .{progress.message});
            },
            .diagnostic => {},
        }
    }
};

test "operation mapping preserves order and indexed sources" {
    const operations = [_]wire.Operation{
        .{ .overwrite_file = .{ .path = "/etc/first", .source_index = 1 } },
        .{ .remove_file = "/etc/remove" },
        .{ .overwrite_file = .{ .path = "/etc/second", .source_index = 0 } },
        .{ .remove_tree = "/var/cache/old" },
    };
    const mapped = try mapOperations(
        std.testing.allocator,
        &operations,
        &.{ "source-zero", "source-one" },
    );
    defer std.testing.allocator.free(mapped);

    try std.testing.expectEqual(@as(usize, 4), mapped.len);
    try std.testing.expect(mapped[0] == .overwrite_file);
    try std.testing.expectEqualStrings("/etc/first", mapped[0].overwrite_file.path);
    try std.testing.expectEqualStrings(
        "source-one",
        mapped[0].overwrite_file.source.host_path,
    );
    try std.testing.expect(mapped[1] == .remove_file);
    try std.testing.expectEqualStrings("/etc/remove", mapped[1].remove_file);
    try std.testing.expect(mapped[2] == .overwrite_file);
    try std.testing.expectEqualStrings(
        "source-zero",
        mapped[2].overwrite_file.source.host_path,
    );
    try std.testing.expect(mapped[3] == .remove_tree);
    try std.testing.expectEqualStrings("/var/cache/old", mapped[3].remove_tree);
}

test "operation mapping permits customization sources in the shared index space" {
    const operations = [_]wire.Operation{
        .{ .overwrite_file = .{ .path = "/etc/existing", .source_index = 0 } },
    };
    const mapped = try mapOperations(
        std.testing.allocator,
        &operations,
        &.{ "existing-source", "customization-source" },
    );
    defer std.testing.allocator.free(mapped);
    try std.testing.expectEqualStrings(
        "existing-source",
        mapped[0].overwrite_file.source.host_path,
    );
}

test "configuration loader accepts v2 and v3 transport" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const v2_json =
        \\{"backend":"rebuild","root_partition":{"gpt_index":1},"operations":[{"overwrite_file":{"path":"/etc/value","source_index":0}}]}
    ;
    const v2 = try parseConfiguration(
        allocator,
        v2_json,
        &.{"replacement"},
    );
    try std.testing.expectEqual(
        miz.customize.ExecutionBackend.rebuild,
        v2.backend,
    );
    try std.testing.expectEqual(@as(usize, 0), v2.packages.actions.len);

    const v3_json =
        \\{"api_version":3,"backend":"unsafe_chroot","root_partition":{"mbr_index":1},"acknowledge_unsafe":true,"packages":{"actions":[{"install":["dracut"]}],"repositories":[{"id":"base","urls":["https://packages.example.invalid"],"trust":[{"source_index":0}]}]},"initramfs":{"regenerate":{"generator":"dracut","kernels":["6.12.0-test"]}}}
    ;
    const v3 = try parseConfiguration(
        allocator,
        v3_json,
        &.{"trust-source"},
    );
    try std.testing.expectEqual(
        miz.customize.ExecutionBackend.unsafe_chroot,
        v3.backend,
    );
    try std.testing.expect(v3.acknowledge_unsafe);
    try std.testing.expectEqualStrings(
        "trust-source",
        v3.packages.repositories[0].trust[0].host_path,
    );
    try std.testing.expectEqualStrings(
        "dracut",
        v3.initramfs.regenerate.generator.?,
    );

    // `loadConfiguration` frees the document once parsing returns, so the
    // loaded configuration must own its strings rather than alias it.
    const path = "test-preserved-image-configuration.json";
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{});
        defer file.close(std.testing.io);
        try file.writePositionalAll(std.testing.io, v3_json, 0);
    }
    const from_file = try loadConfiguration(
        allocator,
        std.testing.io,
        path,
        &.{"trust-source"},
    );
    try std.testing.expectEqualStrings(
        "dracut",
        from_file.initramfs.regenerate.generator.?,
    );
    try std.testing.expectEqualStrings(
        "base",
        from_file.packages.repositories[0].id,
    );
}

test "the vm backend and a cross-architecture runner survive the loader" {
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    const json =
        \\{"api_version":3,"backend":"vm","root_partition":{"gpt_index":2},"guest_execution":"cross_architecture","runner":{"kind":"vm","guest_architecture":"aarch64","command":"/usr/bin/qemu-system-aarch64"},"vm":{"emulator_command":"/usr/bin/qemu-system-aarch64","boot":{"direct_kernel":{}},"acceleration":"software"}}
    ;
    const loaded = try parseConfiguration(allocator, json, &.{});
    try std.testing.expectEqual(miz.customize.ExecutionBackend.vm, loaded.backend);
    try std.testing.expectEqual(
        wire.GuestExecutionPolicy.cross_architecture,
        loaded.guest_execution,
    );
    try std.testing.expectEqualStrings(
        "/usr/bin/qemu-system-aarch64",
        loaded.runner.?.command.?,
    );
    try std.testing.expectEqualStrings(
        "/usr/bin/qemu-system-aarch64",
        loaded.vm.?.emulator_command,
    );
    try std.testing.expect(loaded.vm.?.boot == .direct_kernel);
    try std.testing.expectEqual(
        miz.customize.VmAcceleration.software,
        loaded.vm.?.acceleration,
    );

    // `loadConfiguration` frees the document after parsing, so the loaded
    // configuration must not alias it.
    const path = "test-preserved-vm-configuration.json";
    defer std.Io.Dir.cwd().deleteFile(std.testing.io, path) catch {};
    {
        const file = try std.Io.Dir.cwd().createFile(std.testing.io, path, .{});
        defer file.close(std.testing.io);
        try file.writePositionalAll(std.testing.io, json, 0);
    }
    const from_file = try loadConfiguration(allocator, std.testing.io, path, &.{});
    try std.testing.expectEqualStrings(
        "/usr/bin/qemu-system-aarch64",
        from_file.vm.?.emulator_command,
    );
}

test "package mapping resolves trust sources and execution policies" {
    const policy = wire.PackagePolicy{
        .actions = &.{
            .{ .install = &.{ "dracut", "systemd" } },
            .{ .remove = &.{"obsolete"} },
        },
        .repositories = &.{.{
            .id = "base",
            .urls = &.{"https://packages.example.invalid"},
            .trust = &.{.{ .source_index = 1 }},
        }},
        .lock = .{ .exact = &.{.{
            .name = "dracut",
            .evr = "0:1.0-1.azl3",
            .architecture = "x86_64",
        }} },
    };
    const mapped = try mapPackagePolicy(
        std.testing.allocator,
        policy,
        &.{ "operation-source", "trust-source" },
    );
    defer {
        std.testing.allocator.free(mapped.actions);
        std.testing.allocator.free(mapped.repositories[0].trust);
        std.testing.allocator.free(mapped.repositories);
        std.testing.allocator.free(mapped.lock.exact);
    }
    try std.testing.expectEqualStrings(
        "trust-source",
        mapped.repositories[0].trust[0].host_path,
    );
    try std.testing.expectEqualStrings("obsolete", mapped.actions[1].remove[0]);
    try std.testing.expectEqualStrings("0:1.0-1.azl3", mapped.lock.exact[0].evr);
}

test "a credential crosses the wire as a locator the build system never stages" {
    // Trust material is a `source_index`, so the build system stages a copy of
    // the file and hashes it into the build graph. A credential must not be:
    // a copy of a secret in the build cache is a file nobody deletes. So it
    // crosses as the locator alone, and this test is what keeps the two apart.
    const policy = wire.PackagePolicy{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &.{.{
            .id = "base",
            .urls = &.{"https://packages.example.invalid"},
            .trust = &.{.{ .source_index = 0 }},
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_environment = "MIZ_REPOSITORY_TOKEN" },
            } },
        }},
    };
    const mapped = try mapPackagePolicy(
        std.testing.allocator,
        policy,
        &.{"trust-source"},
    );
    defer {
        std.testing.allocator.free(mapped.actions);
        std.testing.allocator.free(mapped.repositories[0].trust);
        std.testing.allocator.free(mapped.repositories);
    }
    const credential = mapped.repositories[0].credential orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqualStrings("builder", credential.basic.username);
    try std.testing.expectEqualStrings(
        "MIZ_REPOSITORY_TOKEN",
        credential.basic.password.host_environment,
    );

    // And the staged closure is unchanged by declaring one: the single source
    // this repository has is its trust material, exactly as before.
    try std.testing.expectEqual(@as(usize, 1), mapped.repositories[0].trust.len);
    try std.testing.expectEqualStrings(
        "trust-source",
        mapped.repositories[0].trust[0].host_path,
    );
}

test "a hook crosses the wire as a staged source and lands on a host path" {
    // The opposite of the credential above: a hook script is code the build is
    // accountable for and provenance names by digest, so the build system does
    // stage a copy and hash it into the graph. Both forms the build API offers
    // -- an inline script and a path -- are staged before they get here, so
    // everything downstream sees one shape.
    const hooks = [_]wire.Hook{
        .{
            .name = "early",
            .phase = .after_packages,
            .source = .{ .source_index = 1 },
            .arguments = &.{ "--quiet", "/etc" },
        },
        .{ .name = "late", .phase = .finalize, .source = .{ .source_index = 0 } },
    };
    const mapped = try mapHooks(
        std.testing.allocator,
        &hooks,
        &.{ "staged/late.sh", "staged/early.sh" },
    );
    defer std.testing.allocator.free(mapped);

    try std.testing.expectEqual(@as(usize, 2), mapped.len);
    try std.testing.expectEqualStrings("early", mapped[0].name);
    try std.testing.expectEqual(miz.customize.HookPhase.after_packages, mapped[0].phase);
    try std.testing.expectEqualStrings("staged/early.sh", mapped[0].source.host_path);
    try std.testing.expectEqual(@as(usize, 2), mapped[0].arguments.len);
    try std.testing.expectEqualStrings("--quiet", mapped[0].arguments[0]);
    try std.testing.expectEqualStrings("late", mapped[1].name);
    try std.testing.expectEqual(miz.customize.HookPhase.finalize, mapped[1].phase);
    try std.testing.expectEqualStrings("staged/late.sh", mapped[1].source.host_path);

    // An index the caller never staged is refused rather than silently reading
    // whatever file happens to sit at that position.
    try std.testing.expectError(error.SourceIndexOutOfBounds, mapHooks(
        std.testing.allocator,
        &hooks,
        &.{"staged/late.sh"},
    ));
}

test "a mapper that refuses an out-of-range source keeps nothing it allocated" {
    // Every mapper allocates before it has finished checking, so a refusal is
    // the one path where the caller is handed an error and cannot free what it
    // never received. The testing allocator is what makes this assertable.
    try std.testing.expectError(error.SourceIndexOutOfBounds, mapOperations(
        std.testing.allocator,
        &.{
            .{ .remove_file = "/etc/old" },
            .{ .overwrite_file = .{ .path = "/etc/one", .source_index = 7 } },
        },
        &.{"staged"},
    ));
    try std.testing.expectError(error.SourceIndexOutOfBounds, mapHooks(
        std.testing.allocator,
        &.{.{ .name = "late", .phase = .finalize, .source = .{ .source_index = 7 } }},
        &.{"staged"},
    ));
    // Two repositories, so the refusal lands after a trust slice was already
    // built for an earlier one.
    try std.testing.expectError(error.SourceIndexOutOfBounds, mapPackagePolicy(
        std.testing.allocator,
        .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &.{
                .{
                    .id = "base",
                    .urls = &.{"https://packages.example.invalid"},
                    .trust = &.{.{ .source_index = 0 }},
                },
                .{
                    .id = "extra",
                    .urls = &.{"https://extra.example.invalid"},
                    .trust = &.{.{ .source_index = 7 }},
                },
            },
        },
        &.{"staged"},
    ));
}

test "unsafe image basenames are rejected" {
    try std.testing.expect(isBasename("disk.qcow2"));
    try std.testing.expect(!isBasename("../disk.qcow2"));
    try std.testing.expect(!isBasename("nested/disk.qcow2"));
    try std.testing.expect(isReservedBasename("STATUS"));
    try std.testing.expect(isReservedBasename("provenance.json"));
}

test "dependency closure is checked before a bundle can be reset" {
    const io = std.testing.io;
    const bundle_path = "test-preserved-builder-bundle";
    const base_path = bundle_path ++ "/base.raw";
    const disk_path = "test-preserved-builder-overlay.qcow2";
    const lock_path = bundle_path ++ ".lock";
    defer std.Io.Dir.cwd().deleteTree(io, bundle_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, disk_path) catch {};
    defer std.Io.Dir.cwd().deleteFile(io, lock_path) catch {};

    try std.Io.Dir.cwd().createDirPath(io, bundle_path);
    {
        var base = try miz.Image.createExclusive(io, base_path, .qcow2, 4096, .{});
        base.close(io);
    }
    {
        var overlay = try miz.Image.createExclusive(io, disk_path, .qcow2, 4096, .{});
        var backing_offset: [8]u8 = undefined;
        std.mem.writeInt(u64, &backing_offset, 104, .big);
        var backing_length: [4]u8 = undefined;
        std.mem.writeInt(u32, &backing_length, base_path.len, .big);
        try overlay.file.writePositionalAll(io, &backing_offset, 8);
        try overlay.file.writePositionalAll(io, &backing_length, 16);
        try overlay.file.writePositionalAll(io, base_path, 104);
        overlay.close(io);
    }

    const args = ParsedArgs{
        .architecture = .x86_64,
        .disk_path = disk_path,
        .dependency_paths = &.{},
        .configuration_path = "unused.json",
        .operation_source_paths = &.{},
        .bundle_output_path = bundle_path,
        .image_basename = "disk.raw",
        .format = .raw,
        .seed = .{ .bytes = [_]u8{0} ** 32 },
        .source_date_epoch = 0,
    };
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    try std.testing.expectError(
        error.ResultPathOverlap,
        validateDependencyClosure(arena.allocator(), io, &args, lock_path),
    );
    _ = try std.Io.Dir.cwd().statFile(io, base_path, .{});
}

test "import limit flags raise the limits the request carries" {
    const args = [_][]const u8{
        "--architecture",          "x86_64",
        "--disk",                  "source.raw",
        "--configuration",         "preserved-image.json",
        "--bundle-output",         "out",
        "--image-basename",        "image.raw",
        "-O",                      "raw",
        "--seed",                  "00" ** 32,
        "--source-date-epoch",     "0",
        "--max-nodes",             "8M",
        "--max-source-file-bytes", "4G",
    };
    const parsed = try parseArgs(std.testing.allocator, &args);
    defer std.testing.allocator.free(parsed.dependency_paths);
    defer std.testing.allocator.free(parsed.operation_source_paths);

    try std.testing.expectEqual(@as(usize, 8 * 1024 * 1024), parsed.limits.max_nodes);
    try std.testing.expectEqual(@as(u64, 4 * 1024 * 1024 * 1024), parsed.limits.max_source_file_bytes);
    // Every other limit keeps its conservative default.
    try std.testing.expectEqual(miz.limits.ImportLimits{
        .max_nodes = parsed.limits.max_nodes,
        .max_source_file_bytes = parsed.limits.max_source_file_bytes,
    }, parsed.limits);
}

test "a zero limit is rejected instead of silently rejecting every source" {
    const args = [_][]const u8{
        "--architecture",      "x86_64",
        "--disk",              "source.raw",
        "--configuration",     "preserved-image.json",
        "--bundle-output",     "out",
        "--image-basename",    "image.raw",
        "-O",                  "raw",
        "--seed",              "00" ** 32,
        "--source-date-epoch", "0",
        "--max-nodes",         "0",
    };
    try std.testing.expectError(error.ZeroLimit, parseArgs(std.testing.allocator, &args));
}

test "merged source mounts survive the loader with their synthesized metadata" {
    const allocator = std.testing.allocator;
    const configuration =
        \\{
        \\  "api_version": 3,
        \\  "backend": "rebuild",
        \\  "root_partition": { "mbr_index": 3 },
        \\  "source_profile": "general",
        \\  "source_mounts": [
        \\    { "partition": { "mbr_index": 2 }, "target": "/boot" },
        \\    {
        \\      "source_path": "/dev/sdb",
        \\      "partition": { "mbr_index": 1 },
        \\      "target": "/boot/efi",
        \\      "filesystem": "fat32",
        \\      "fat_metadata": { "directory_mode": 448, "file_mode": 384, "uid": 42, "gid": 43 }
        \\    }
        \\  ]
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const loaded = try loadV3Configuration(arena.allocator(), configuration, &.{});
    try std.testing.expectEqual(@as(usize, 2), loaded.source_mounts.len);

    // An unstated source path means the disk being rebuilt, which is the
    // common case of several partitions of one disk.
    try std.testing.expectEqualStrings("", loaded.source_mounts[0].source_path);
    try std.testing.expectEqualStrings("/boot", loaded.source_mounts[0].target);
    try std.testing.expectEqual(
        @as(u8, 2),
        loaded.source_mounts[0].partition.mbr_index,
    );
    try std.testing.expectEqual(
        miz.customize.SourceFilesystem.detect,
        loaded.source_mounts[0].filesystem,
    );
    // Unstated FAT metadata is the documented default, not an accident.
    try std.testing.expectEqual(
        @as(u16, 0o755),
        loaded.source_mounts[0].fat_metadata.directory_mode,
    );
    try std.testing.expectEqual(
        @as(u16, 0o644),
        loaded.source_mounts[0].fat_metadata.file_mode,
    );
    try std.testing.expectEqual(@as(u32, 0), loaded.source_mounts[0].fat_metadata.uid);
    try std.testing.expectEqual(@as(u32, 0), loaded.source_mounts[0].fat_metadata.gid);

    try std.testing.expectEqualStrings("/dev/sdb", loaded.source_mounts[1].source_path);
    try std.testing.expectEqualStrings("/boot/efi", loaded.source_mounts[1].target);
    try std.testing.expectEqual(
        miz.customize.SourceFilesystem.fat32,
        loaded.source_mounts[1].filesystem,
    );
    try std.testing.expectEqual(
        @as(u16, 0o700),
        loaded.source_mounts[1].fat_metadata.directory_mode,
    );
    try std.testing.expectEqual(
        @as(u16, 0o600),
        loaded.source_mounts[1].fat_metadata.file_mode,
    );
    try std.testing.expectEqual(@as(u32, 42), loaded.source_mounts[1].fat_metadata.uid);
    try std.testing.expectEqual(@as(u32, 43), loaded.source_mounts[1].fat_metadata.gid);

    // Absent from the configuration above, so it has to arrive as the safe
    // default rather than as whatever the loader's zero value happens to be.
    try std.testing.expectEqual(
        miz.customize.IdentityRewritePolicy.rewrite_and_verify,
        loaded.identity_rewrite,
    );
}

test "an explicit XFS source mount survives the loader" {
    const configuration =
        \\{
        \\  "api_version": 3,
        \\  "backend": "rebuild",
        \\  "root_partition": { "gpt_index": 2 },
        \\  "source_profile": "general",
        \\  "source_mounts": [
        \\    {
        \\      "partition": { "gpt_index": 3 },
        \\      "target": "/var",
        \\      "filesystem": "xfs"
        \\    }
        \\  ]
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena.deinit();
    const loaded = try loadV3Configuration(arena.allocator(), configuration, &.{});
    try std.testing.expectEqual(@as(usize, 1), loaded.source_mounts.len);
    try std.testing.expectEqual(
        miz.customize.SourceFilesystem.xfs,
        loaded.source_mounts[0].filesystem,
    );
}

test "an operator can opt out of failing on an identifier the rewriter cannot reach" {
    const allocator = std.testing.allocator;
    const configuration =
        \\{
        \\  "api_version": 3,
        \\  "backend": "rebuild",
        \\  "root_partition": { "mbr_index": 3 },
        \\  "identity_rewrite": "rewrite_only"
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const loaded = try loadV3Configuration(arena.allocator(), configuration, &.{});
    try std.testing.expectEqual(
        miz.customize.IdentityRewritePolicy.rewrite_only,
        loaded.identity_rewrite,
    );
}

test "a version 2 configuration keeps the safe identity rewrite default" {
    const allocator = std.testing.allocator;
    const configuration =
        \\{
        \\  "api_version": 2,
        \\  "backend": "rebuild",
        \\  "root_partition": { "mbr_index": 3 }
        \\}
    ;
    var arena = std.heap.ArenaAllocator.init(allocator);
    defer arena.deinit();
    const loaded = try loadV2Configuration(arena.allocator(), configuration, &.{});
    try std.testing.expectEqual(
        miz.customize.IdentityRewritePolicy.rewrite_and_verify,
        loaded.identity_rewrite,
    );
}

test "the wire's synthesized FAT metadata defaults are the library's" {
    // Two spellings of the same policy would eventually disagree, and the
    // disagreement would show up as an image whose ownership silently changed.
    const wire_defaults = wire.SynthesizedFatMetadata{};
    const library_defaults = miz.customize.SynthesizedFatMetadata{};
    try std.testing.expectEqual(library_defaults.directory_mode, wire_defaults.directory_mode);
    try std.testing.expectEqual(library_defaults.file_mode, wire_defaults.file_mode);
    try std.testing.expectEqual(library_defaults.uid, wire_defaults.uid);
    try std.testing.expectEqual(library_defaults.gid, wire_defaults.gid);
}
