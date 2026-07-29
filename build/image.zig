const std = @import("std");
const customization_wire = @import("../packages/zvmi/src/customization_wire.zig");
const customize = @import("../packages/zvmi/src/customize.zig");
const preserved_image_wire = @import("../packages/zvmi/src/preserved_image_wire.zig");
const limits_mod = @import("../packages/zvmi/src/limits.zig");

pub const Format = enum {
    raw,
    vhd,
    vhdx,
    qcow2,

    fn cliName(format: Format) []const u8 {
        return @tagName(format);
    }
};

pub const Generation = enum {
    gen1,
    gen2,

    fn cliName(generation: Generation) []const u8 {
        return switch (generation) {
            .gen1 => "1",
            .gen2 => "2",
        };
    }
};

pub const BootMode = enum {
    bls,
    uki,
    both,

    fn cliName(mode: BootMode) []const u8 {
        return @tagName(mode);
    }
};

pub const Architecture = enum {
    x86_64,
    aarch64,

    fn cliName(architecture: Architecture) []const u8 {
        return @tagName(architecture);
    }
};

pub const Reproducibility = struct {
    seed: [32]u8,
    source_date_epoch: u64,
};

pub const UkiOptions = struct {
    stub_source_path: ?[]const u8 = null,
    os_release_source_path: ?[]const u8 = null,
    splash_source_path: ?[]const u8 = null,
    output_directory: []const u8 = "EFI/Linux",
};

pub const Xattr = customization_wire.Xattr;

/// Import guardrails, mirrored from the library so a build graph can raise
/// them for a large installed root filesystem without reaching into the CLI.
pub const ImportLimits = limits_mod.ImportLimits;

/// Emits a flag per raised limit. A limit left at its default emits nothing,
/// so an unchanged build graph produces the exact command line it did before
/// and its cached results stay valid.
fn addLimitArgs(b: *std.Build, run: *std.Build.Step.Run, limits: ImportLimits) void {
    const defaults = ImportLimits{};
    inline for (comptime std.enums.values(limits_mod.Limit)) |limit| {
        const raised = limits.value(limit);
        if (raised != defaults.value(limit)) {
            run.addArgs(&.{ comptime limit.flag(), b.fmt("{d}", .{raised}) });
        }
    }
}
pub const Metadata = customization_wire.Metadata;

pub const FileSource = union(enum) {
    inline_bytes: []const u8,
    path: std.Build.LazyPath,
};

pub const PutFile = struct {
    path: []const u8,
    source: FileSource,
    metadata: Metadata = .{ .mode = 0o644 },
};

pub const FilesystemOperation = union(enum) {
    put_file: PutFile,
    put_directory: customization_wire.PutDirectory,
    put_symlink: customization_wire.PutSymlink,
    remove: []const u8,
    set_metadata: customization_wire.MetadataChange,
};

pub const Group = customization_wire.Group;
pub const User = customization_wire.User;
pub const Password = customization_wire.Password;
pub const Service = customization_wire.Service;
pub const ServiceState = customization_wire.ServiceState;
pub const KernelModule = customization_wire.KernelModule;
pub const AzureGeneralization = customization_wire.AzureGeneralization;
pub const GeneralizationPolicy = customization_wire.GeneralizationPolicy;

pub const OsCustomization = struct {
    filesystem: []const FilesystemOperation = &.{},
    hostname: ?[]const u8 = null,
    groups: []const Group = &.{},
    users: []const User = &.{},
    services: []const Service = &.{},
    kernel_modules: []const KernelModule = &.{},
};

pub const Container = union(enum) {
    /// An OCI image-layout directory. The helper snapshots the complete
    /// directory into the build cache so additions and removals invalidate
    /// the image step, not just changes to the directory path.
    oci_layout: std.Build.LazyPath,
    /// A docker/podman save archive.
    archive: std.Build.LazyPath,
};

pub const Input = struct {
    iso: std.Build.LazyPath,
    container: Container,
};

pub const Output = struct {
    format: Format,
    basename: []const u8,
};

pub const Options = struct {
    name: []const u8,
    input: Input,
    output: Output,
    size: u64,
    target_architecture: Architecture,
    reproducibility: Reproducibility,
    generation: Generation = .gen2,
    rootfs_path_in_iso: []const u8,
    skip_iso_rootfs: bool = false,
    esp_size: ?u64 = null,
    ext4_label: []const u8 = "rootfs",
    verity: bool = false,
    extra_kernel_options: []const u8 = "",
    boot_mode: BootMode = .bls,
    uki: UkiOptions = .{},
    os: OsCustomization = .{},
    generalization: GeneralizationPolicy = .none,
    limits: ImportLimits = .{},
    verbose: bool = false,
};

pub const PreservedInput = struct {
    disk: std.Build.LazyPath,
    /// Every transitive qcow2 backing and external-data file.
    dependencies: []const std.Build.LazyPath = &.{},
};

pub const PreservedRootPartition = union(enum) {
    /// One-based slot in the GPT partition entry array.
    gpt_index: u32,
    /// One-based slot in the four-entry MBR partition table.
    mbr_index: u8,
};

pub const PreservedFileSource = union(enum) {
    inline_bytes: []const u8,
    path: std.Build.LazyPath,
};

pub const OverwriteExistingFile = struct {
    path: []const u8,
    source: PreservedFileSource,
};

pub const PreservedOperation = union(enum) {
    overwrite_file: OverwriteExistingFile,
    remove_file: []const u8,
    remove_tree: []const u8,
};

pub const PreservedBackend = enum {
    native_edit,
    rebuild,
    unsafe_chroot,
    vm,
};

pub const PreservedPackageAction = preserved_image_wire.PackageAction;

pub const PreservedTrustSource = union(enum) {
    inline_bytes: []const u8,
    path: std.Build.LazyPath,
};

pub const PreservedPackageRepository = struct {
    id: []const u8,
    urls: []const []const u8,
    trust: []const PreservedTrustSource = &.{},
};

pub const PreservedPackageCachePolicy = preserved_image_wire.PackageCachePolicy;
pub const PreservedPackageVersionLock = preserved_image_wire.PackageVersionLock;
pub const PreservedPackageLockPolicy = preserved_image_wire.PackageLockPolicy;

pub const PreservedPackagePolicy = struct {
    actions: []const PreservedPackageAction = &.{},
    repositories: []const PreservedPackageRepository = &.{},
    cache: PreservedPackageCachePolicy = .online,
    lock: PreservedPackageLockPolicy = .unlocked,
};

pub const PreservedInitramfsPolicy = preserved_image_wire.InitramfsPolicy;
pub const PreservedGuestExecutionPolicy = preserved_image_wire.GuestExecutionPolicy;
pub const PreservedRunnerKind = preserved_image_wire.RunnerKind;
pub const PreservedRunner = preserved_image_wire.Runner;
pub const PreservedVmAcceleration = preserved_image_wire.VmAcceleration;
pub const PreservedVmNetworkPolicy = preserved_image_wire.VmNetworkPolicy;
pub const PreservedVmFirmware = preserved_image_wire.VmFirmware;
pub const PreservedVmBoot = preserved_image_wire.VmBoot;
pub const PreservedVmPolicy = preserved_image_wire.VmConfiguration;
pub const PreservedSourceProfile = preserved_image_wire.SourceProfile;

pub const PreservedOptions = struct {
    name: []const u8,
    input: PreservedInput,
    root_partition: PreservedRootPartition,
    output: Output,
    target_architecture: Architecture,
    reproducibility: Reproducibility,
    backend: PreservedBackend = .native_edit,
    operations: []const PreservedOperation = &.{},
    os: OsCustomization = .{},
    generalization: GeneralizationPolicy = .none,
    acknowledge_unsafe: bool = false,
    packages: PreservedPackagePolicy = .{},
    initramfs: PreservedInitramfsPolicy = .unchanged,
    guest_execution: PreservedGuestExecutionPolicy = .same_architecture,
    /// The runner that makes a foreign guest architecture executable.
    /// Required by, and only meaningful to, `cross_architecture` execution.
    runner: ?PreservedRunner = null,
    /// Required by, and only meaningful to, the `vm` backend.
    vm: ?PreservedVmPolicy = null,
    limits: ImportLimits = .{},
    /// Which ext4 sources the `rebuild` backend accepts. `general` gives up
    /// the byte-for-byte reproducibility claim in exchange for being able to
    /// import a filesystem a distro installer produced.
    source_profile: PreservedSourceProfile = .strict,
    verbose: bool = false,
};

pub const Result = struct {
    path: std.Build.LazyPath,
    plan_path: std.Build.LazyPath,
    diagnostics_path: std.Build.LazyPath,
    provenance_path: std.Build.LazyPath,
    preflight_plan_path: std.Build.LazyPath,
    preflight_diagnostics_path: std.Build.LazyPath,
    preflight_provenance_path: std.Build.LazyPath,
    step: *std.Build.Step.Run,
};

const TrackedContainer = union(enum) {
    oci_layout: std.Build.LazyPath,
    archive: std.Build.LazyPath,
};

pub fn add(
    b: *std.Build,
    dependency: *std.Build.Dependency,
    options: Options,
) Result {
    validateBuildName(options.name);
    validateOutputBasename(options.output.basename);
    const container: TrackedContainer = switch (options.input.container) {
        .oci_layout => |layout| blk: {
            const validate = b.addRunArtifact(dependency.artifact("zvmi-input-validator"));
            validate.setName(b.fmt("validate OCI layout for {s}", .{options.name}));
            validate.addDirectoryArg(layout);

            const snapshot = b.addWriteFiles();
            snapshot.step.name = b.fmt("snapshot OCI layout for {s}", .{options.name});
            snapshot.step.dependOn(&validate.step);
            const tracked_layout = snapshot.addCopyDirectory(layout, "oci-layout", .{});
            break :blk .{ .oci_layout = tracked_layout };
        },
        .archive => |archive| .{ .archive = archive },
    };

    const preflight = b.addRunArtifact(dependency.artifact("zvmi-image-builder"));
    preflight.setName(b.fmt("preflight image {s}", .{options.name}));
    preflight.has_side_effects = true;
    configureRequest(b, preflight, options, container);
    preflight.addArg("--preflight-only");
    preflight.addArgs(&.{ "--image-basename", options.output.basename });
    preflight.addArg("--bundle-output");
    const preflight_bundle = preflight.addOutputDirectoryArg(b.fmt("{s}-preflight-result", .{options.name}));

    const preflight_check = b.addRunArtifact(dependency.artifact("zvmi-image-status-check"));
    preflight_check.setName(b.fmt("check image preflight {s}", .{options.name}));
    preflight_check.addDirectoryArg(preflight_bundle);
    preflight_check.addFileInput(preflight_bundle.path(b, "status"));

    const run = b.addRunArtifact(dependency.artifact("zvmi-image-builder"));
    run.setName(b.fmt("build image {s}", .{options.name}));
    run.has_side_effects = true;
    run.step.dependOn(&preflight_check.step);
    configureRequest(b, run, options, container);

    run.addArg("--reuse-success");
    run.addArgs(&.{ "--image-basename", options.output.basename });
    run.addArg("--bundle-output");
    const bundle = run.addOutputDirectoryArg(b.fmt("{s}-result", .{options.name}));

    const status_check = b.addRunArtifact(dependency.artifact("zvmi-image-status-check"));
    status_check.setName(b.fmt("check image result {s}", .{options.name}));
    status_check.addDirectoryArg(bundle);
    status_check.addFileInput(bundle.path(b, "status"));
    status_check.addFileInput(bundle.path(b, "provenance.json"));
    status_check.addArg(options.output.basename);
    const output = status_check.addOutputFileArg(options.output.basename);

    return .{
        .path = output,
        .plan_path = bundle.path(b, "plan.json"),
        .diagnostics_path = bundle.path(b, "diagnostics.json"),
        .provenance_path = bundle.path(b, "provenance.json"),
        .preflight_plan_path = preflight_bundle.path(b, "plan.json"),
        .preflight_diagnostics_path = preflight_bundle.path(b, "diagnostics.json"),
        .preflight_provenance_path = preflight_bundle.path(b, "provenance.json"),
        .step = status_check,
    };
}

pub fn addPreserved(
    b: *std.Build,
    dependency: *std.Build.Dependency,
    options: PreservedOptions,
) Result {
    validateBuildName(options.name);
    validateOutputBasename(options.output.basename);
    const configuration = materializePreservedConfiguration(b, options) catch
        @panic("failed to materialize preserved-image configuration");

    const preflight = b.addRunArtifact(dependency.artifact("zvmi-preserved-image-builder"));
    preflight.setName(b.fmt("preflight preserved image {s}", .{options.name}));
    preflight.has_side_effects = true;
    configurePreservedRequest(b, preflight, options, configuration);
    preflight.addArg("--preflight-only");
    preflight.addArgs(&.{ "--image-basename", options.output.basename });
    preflight.addArg("--bundle-output");
    const preflight_bundle = preflight.addOutputDirectoryArg(
        b.fmt("{s}-preserved-preflight-result", .{options.name}),
    );

    const preflight_check = b.addRunArtifact(dependency.artifact("zvmi-image-status-check"));
    preflight_check.setName(b.fmt("check preserved image preflight {s}", .{options.name}));
    preflight_check.addDirectoryArg(preflight_bundle);
    preflight_check.addFileInput(preflight_bundle.path(b, "status"));

    const run = b.addRunArtifact(dependency.artifact("zvmi-preserved-image-builder"));
    run.setName(b.fmt("build preserved image {s}", .{options.name}));
    run.has_side_effects = true;
    run.step.dependOn(&preflight_check.step);
    configurePreservedRequest(b, run, options, configuration);
    run.addArg("--reuse-success");
    run.addArgs(&.{ "--image-basename", options.output.basename });
    run.addArg("--bundle-output");
    const bundle = run.addOutputDirectoryArg(
        b.fmt("{s}-preserved-result", .{options.name}),
    );

    const status_check = b.addRunArtifact(dependency.artifact("zvmi-image-status-check"));
    status_check.setName(b.fmt("check preserved image result {s}", .{options.name}));
    status_check.addDirectoryArg(bundle);
    status_check.addFileInput(bundle.path(b, "status"));
    status_check.addFileInput(bundle.path(b, "provenance.json"));
    status_check.addArg(options.output.basename);
    const output = status_check.addOutputFileArg(options.output.basename);

    return .{
        .path = output,
        .plan_path = bundle.path(b, "plan.json"),
        .diagnostics_path = bundle.path(b, "diagnostics.json"),
        .provenance_path = bundle.path(b, "provenance.json"),
        .preflight_plan_path = preflight_bundle.path(b, "plan.json"),
        .preflight_diagnostics_path = preflight_bundle.path(b, "diagnostics.json"),
        .preflight_provenance_path = preflight_bundle.path(b, "provenance.json"),
        .step = status_check,
    };
}

fn validateBuildName(name: []const u8) void {
    if (name.len == 0 or
        std.mem.indexOfScalar(u8, name, 0) != null or
        std.fs.path.isAbsolute(name) or
        !std.mem.eql(u8, name, std.fs.path.basename(name)) or
        std.mem.eql(u8, name, ".") or
        std.mem.eql(u8, name, ".."))
    {
        @panic("image build name must be a non-empty path component");
    }
}

fn validateOutputBasename(name: []const u8) void {
    validateBuildName(name);
    if (std.ascii.eqlIgnoreCase(name, "status") or
        std.ascii.eqlIgnoreCase(name, "plan.json") or
        std.ascii.eqlIgnoreCase(name, "diagnostics.json") or
        std.ascii.eqlIgnoreCase(name, "provenance.json") or
        std.ascii.eqlIgnoreCase(name, "reuse-key"))
    {
        @panic("image output basename conflicts with a result-bundle artifact");
    }
}

const MaterializedPreservedConfiguration = struct {
    path: std.Build.LazyPath,
    sources: []const std.Build.LazyPath,
};

fn materializePreservedConfiguration(
    b: *std.Build,
    options: PreservedOptions,
) !MaterializedPreservedConfiguration {
    const operations = try b.allocator.alloc(
        preserved_image_wire.Operation,
        options.operations.len,
    );
    var sources = std.array_list.Managed(std.Build.LazyPath).init(b.allocator);
    errdefer sources.deinit();
    const inline_files = b.addWriteFiles();
    inline_files.step.name = b.fmt(
        "materialize inline preserved-image replacements for {s}",
        .{options.name},
    );

    for (options.operations, 0..) |operation, index| {
        operations[index] = switch (operation) {
            .overwrite_file => |overwrite| blk: {
                const source: std.Build.LazyPath = switch (overwrite.source) {
                    .path => |path| path,
                    .inline_bytes => |bytes| inline_files.add(
                        b.fmt("inline-{d}", .{index}),
                        bytes,
                    ),
                };
                const source_index = sources.items.len;
                try sources.append(source);
                break :blk .{ .overwrite_file = .{
                    .path = overwrite.path,
                    .source_index = source_index,
                } };
            },
            .remove_file => |path| .{ .remove_file = path },
            .remove_tree => |path| .{ .remove_tree = path },
        };
    }

    const filesystem = try b.allocator.alloc(
        customization_wire.FilesystemOperation,
        options.os.filesystem.len,
    );
    for (options.os.filesystem, 0..) |operation, index| {
        filesystem[index] = switch (operation) {
            .put_file => |file| blk: {
                const source: std.Build.LazyPath = switch (file.source) {
                    .path => |path| path,
                    .inline_bytes => |bytes| inline_files.add(
                        b.fmt("customization-inline-{d}", .{index}),
                        bytes,
                    ),
                };
                const source_index = sources.items.len;
                try sources.append(source);
                break :blk .{ .put_file = .{
                    .path = file.path,
                    .source_index = source_index,
                    .metadata = file.metadata,
                } };
            },
            .put_directory => |directory| .{ .put_directory = directory },
            .put_symlink => |link| .{ .put_symlink = link },
            .remove => |path| .{ .remove = path },
            .set_metadata => |change| .{ .set_metadata = change },
        };
    }

    const repositories = try b.allocator.alloc(
        preserved_image_wire.PackageRepository,
        options.packages.repositories.len,
    );
    for (options.packages.repositories, 0..) |repository, repository_index| {
        const trust = try b.allocator.alloc(
            preserved_image_wire.TrustSource,
            repository.trust.len,
        );
        for (repository.trust, 0..) |trust_source, trust_index| {
            const source: std.Build.LazyPath = switch (trust_source) {
                .path => |path| path,
                .inline_bytes => |bytes| inline_files.add(
                    b.fmt("repository-{d}-trust-{d}", .{
                        repository_index,
                        trust_index,
                    }),
                    bytes,
                ),
            };
            trust[trust_index] = .{ .source_index = sources.items.len };
            try sources.append(source);
        }
        repositories[repository_index] = .{
            .id = repository.id,
            .urls = repository.urls,
            .trust = trust,
        };
    }

    const configuration = preserved_image_wire.Configuration{
        .backend = switch (options.backend) {
            .native_edit => .native_edit,
            .rebuild => .rebuild,
            .unsafe_chroot => .unsafe_chroot,
            .vm => .vm,
        },
        .root_partition = switch (options.root_partition) {
            .gpt_index => |index| .{ .gpt_index = index },
            .mbr_index => |index| .{ .mbr_index = index },
        },
        .source_profile = options.source_profile,
        .operations = operations,
        .customization = .{
            .os = .{
                .filesystem = filesystem,
                .hostname = options.os.hostname,
                .groups = options.os.groups,
                .users = options.os.users,
                .services = options.os.services,
                .kernel_modules = options.os.kernel_modules,
            },
            .generalization = options.generalization,
        },
        .acknowledge_unsafe = options.acknowledge_unsafe,
        .packages = .{
            .actions = options.packages.actions,
            .repositories = repositories,
            .cache = options.packages.cache,
            .lock = options.packages.lock,
        },
        .initramfs = options.initramfs,
        .guest_execution = options.guest_execution,
        .runner = options.runner,
        .vm = options.vm,
    };
    try preserved_image_wire.validate(configuration, sources.items.len);
    const json = try std.json.Stringify.valueAlloc(b.allocator, configuration, .{});
    const config_files = b.addWriteFiles();
    config_files.step.name = b.fmt(
        "write preserved-image configuration for {s}",
        .{options.name},
    );
    return .{
        .path = config_files.add("preserved-image.json", json),
        .sources = try sources.toOwnedSlice(),
    };
}

fn configurePreservedRequest(
    b: *std.Build,
    run: *std.Build.Step.Run,
    options: PreservedOptions,
    configuration: MaterializedPreservedConfiguration,
) void {
    run.addArg("--disk");
    run.addFileArg(options.input.disk);
    for (options.input.dependencies) |dependency| {
        run.addArg("--disk-dependency");
        run.addFileArg(dependency);
    }
    run.addArg("--configuration");
    run.addFileArg(configuration.path);
    for (configuration.sources) |source| {
        run.addArg("--operation-source");
        run.addFileArg(source);
    }
    run.addArgs(&.{ "-O", options.output.format.cliName() });
    run.addArgs(&.{ "--architecture", options.target_architecture.cliName() });
    const seed_hex = std.fmt.bytesToHex(options.reproducibility.seed, .lower);
    run.addArgs(&.{ "--seed", b.fmt("{s}", .{seed_hex}) });
    run.addArgs(&.{
        "--source-date-epoch",
        b.fmt("{d}", .{options.reproducibility.source_date_epoch}),
    });
    run.addArgs(&.{
        "--api-version",
        b.fmt("{d}", .{customize.current_api_version}),
    });
    addLimitArgs(b, run, options.limits);
    if (options.verbose) run.addArg("--verbose");
}

fn configureRequest(
    b: *std.Build,
    run: *std.Build.Step.Run,
    options: Options,
    container: TrackedContainer,
) void {
    run.addArg("--iso");
    run.addFileArg(options.input.iso);
    run.addArg("--container");
    switch (container) {
        .oci_layout => |layout| run.addDirectoryArg(layout),
        .archive => |archive| run.addFileArg(archive),
    }
    run.addArgs(&.{ "--generation", options.generation.cliName() });
    run.addArgs(&.{ "--size", b.fmt("{d}", .{options.size}) });
    run.addArgs(&.{ "-O", options.output.format.cliName() });
    run.addArgs(&.{ "--architecture", options.target_architecture.cliName() });
    const seed_hex = std.fmt.bytesToHex(options.reproducibility.seed, .lower);
    run.addArgs(&.{ "--seed", b.fmt("{s}", .{seed_hex}) });
    run.addArgs(&.{ "--source-date-epoch", b.fmt("{d}", .{options.reproducibility.source_date_epoch}) });
    run.addArgs(&.{ "--api-version", b.fmt("{d}", .{customize.current_api_version}) });
    run.addArgs(&.{ "--rootfs-path", options.rootfs_path_in_iso });
    if (options.skip_iso_rootfs) run.addArg("--skip-iso-rootfs");
    if (options.esp_size) |size| run.addArgs(&.{ "--esp-size", b.fmt("{d}", .{size}) });
    if (!std.mem.eql(u8, options.ext4_label, "rootfs")) run.addArgs(&.{ "--ext4-label", options.ext4_label });
    if (options.verity) run.addArg("--verity");
    if (options.extra_kernel_options.len != 0) run.addArgs(&.{ "--extra-kernel-options", options.extra_kernel_options });
    if (options.boot_mode != .bls) run.addArgs(&.{ "--boot-mode", options.boot_mode.cliName() });
    if (options.uki.stub_source_path) |path| run.addArgs(&.{ "--stub-source-path", path });
    if (options.uki.os_release_source_path) |path| run.addArgs(&.{ "--os-release-source-path", path });
    if (options.uki.splash_source_path) |path| run.addArgs(&.{ "--splash-source-path", path });
    if (!std.mem.eql(u8, options.uki.output_directory, "EFI/Linux")) {
        run.addArgs(&.{ "--uki-output-directory", options.uki.output_directory });
    }
    addLimitArgs(b, run, options.limits);
    addCustomizationArgs(b, run, options) catch @panic("failed to materialize image customization");
    if (options.verbose) run.addArg("--verbose");
}

fn addCustomizationArgs(
    b: *std.Build,
    run: *std.Build.Step.Run,
    options: Options,
) !void {
    if (!hasCustomization(options.os, options.generalization)) return;

    const operations = try b.allocator.alloc(customization_wire.FilesystemOperation, options.os.filesystem.len);
    var sources = std.array_list.Managed(std.Build.LazyPath).init(b.allocator);
    defer sources.deinit();
    const inline_files = b.addWriteFiles();
    inline_files.step.name = b.fmt("materialize inline customization for {s}", .{options.name});

    for (options.os.filesystem, 0..) |operation, index| {
        operations[index] = switch (operation) {
            .put_file => |file| blk: {
                const source: std.Build.LazyPath = switch (file.source) {
                    .path => |path| path,
                    .inline_bytes => |bytes| inline_files.add(
                        b.fmt("inline-{d}", .{index}),
                        bytes,
                    ),
                };
                const source_index = sources.items.len;
                try sources.append(source);
                break :blk .{ .put_file = .{
                    .path = file.path,
                    .source_index = source_index,
                    .metadata = file.metadata,
                } };
            },
            .put_directory => |directory| .{ .put_directory = directory },
            .put_symlink => |link| .{ .put_symlink = link },
            .remove => |path| .{ .remove = path },
            .set_metadata => |change| .{ .set_metadata = change },
        };
    }

    const configuration = customization_wire.Configuration{
        .os = .{
            .filesystem = operations,
            .hostname = options.os.hostname,
            .groups = options.os.groups,
            .users = options.os.users,
            .services = options.os.services,
            .kernel_modules = options.os.kernel_modules,
        },
        .generalization = options.generalization,
    };
    const json = try std.json.Stringify.valueAlloc(b.allocator, configuration, .{});
    const config_files = b.addWriteFiles();
    config_files.step.name = b.fmt("write customization plan for {s}", .{options.name});
    const config_path = config_files.add("customization.json", json);
    run.addArg("--customization");
    run.addFileArg(config_path);
    for (sources.items) |source| {
        run.addArg("--customization-source");
        run.addFileArg(source);
    }
}

fn hasCustomization(os: OsCustomization, generalization: GeneralizationPolicy) bool {
    if (os.filesystem.len != 0 or os.hostname != null or os.groups.len != 0 or
        os.users.len != 0 or os.services.len != 0 or os.kernel_modules.len != 0)
    {
        return true;
    }
    return switch (generalization) {
        .none => false,
        .azure => true,
    };
}
