//! Exported `std.Build` helper for generating a customized LiveOS ISO during a
//! consumer's build. Runs the host `zvmi-iso-builder` over a source ISO and an
//! OCI container image and yields the generated ISO plus a machine-readable
//! report.
//!
//! An ISO is an optical artifact, not a disk block format, so this is a
//! separate helper from `build/image.zig` rather than another output format of
//! it. Its result exposes the ISO and a report; it deliberately does not carry
//! the disk-image builder's preflight/provenance bundle, whose plan is a
//! partition/format plan an ISO does not have.

const std = @import("std");
const customization_wire = @import("../packages/zvmi/src/customization_wire.zig");
const limits_mod = @import("../packages/zvmi/src/limits.zig");

pub const Architecture = enum {
    x86_64,
    aarch64,

    fn cliName(self: Architecture) []const u8 {
        return switch (self) {
            .x86_64 => "x86_64",
            .aarch64 => "aarch64",
        };
    }
};

pub const Compression = enum {
    zstd,
    none,

    fn cliName(self: Compression) []const u8 {
        return switch (self) {
            .zstd => "zstd",
            .none => "none",
        };
    }
};

pub const BootPlatform = enum { bios, uefi };

pub const BootImage = struct {
    platform: BootPlatform,
    /// Root-relative path (no leading slash) of the boot image within the
    /// output ISO tree.
    image_path: []const u8,
};

pub const Container = union(enum) {
    /// An OCI image-layout directory, snapshotted into the build cache so
    /// additions and removals invalidate the step.
    oci_layout: std.Build.LazyPath,
    /// A docker/podman `save` archive.
    archive: std.Build.LazyPath,
};

pub const ImportLimits = limits_mod.ImportLimits;

pub const Xattr = customization_wire.Xattr;
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
pub const Service = customization_wire.Service;
pub const KernelModule = customization_wire.KernelModule;
pub const GeneralizationPolicy = customization_wire.GeneralizationPolicy;

pub const OsCustomization = struct {
    filesystem: []const FilesystemOperation = &.{},
    hostname: ?[]const u8 = null,
    groups: []const Group = &.{},
    users: []const User = &.{},
    services: []const Service = &.{},
    kernel_modules: []const KernelModule = &.{},
};

pub const Options = struct {
    name: []const u8,
    iso: std.Build.LazyPath,
    container: Container,
    /// ext4 rootfs.img size before SquashFS wrapping. Rounded up to the ext4
    /// block size; must be large enough to hold the customized tree.
    rootfs_size: u64,
    /// Basename of the generated ISO inside the result bundle.
    output_basename: []const u8,
    /// LiveOS payload path in the source ISO to replace. Null discovers it.
    rootfs_path_in_iso: ?[]const u8 = null,
    /// Path of the ext4 image inside the regenerated SquashFS.
    nested_rootfs_path: ?[]const u8 = null,
    /// Output ISO volume identifier. Null reuses the source ISO's.
    volume_id: ?[]const u8 = null,
    /// El Torito boot images. Empty probes common source layouts; at least one
    /// entry (UEFI-only is fine) must resolve.
    boot_images: []const BootImage = &.{},
    squashfs_compression: Compression = .zstd,
    skip_iso_rootfs: bool = false,
    architecture: ?Architecture = null,
    ext4_label: []const u8 = "rootfs",
    journal: bool = false,
    journal_size: ?u64 = null,
    root_selinux_label: ?[]const u8 = null,
    /// Stamp this POSIX timestamp into the ext4/SquashFS/ISO and derive a fixed
    /// root filesystem UUID from it for a byte-for-byte reproducible ISO.
    source_date_epoch: ?u32 = null,
    os: OsCustomization = .{},
    generalization: GeneralizationPolicy = .none,
    limits: ImportLimits = .{},
    verbose: bool = false,
};

pub const Result = struct {
    /// The generated ISO.
    path: std.Build.LazyPath,
    /// A machine-readable JSON report (volume id, rootfs path, digests, boot
    /// entries, output size and hash).
    report_path: std.Build.LazyPath,
    step: *std.Build.Step.Run,
};

pub fn add(
    b: *std.Build,
    dependency: *std.Build.Dependency,
    options: Options,
) Result {
    const container: Container = switch (options.container) {
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

    const run = b.addRunArtifact(dependency.artifact("zvmi-iso-builder"));
    run.setName(b.fmt("build iso {s}", .{options.name}));
    run.has_side_effects = true;
    configureRequest(b, run, options, container);

    run.addArgs(&.{ "--iso-basename", options.output_basename });
    run.addArg("--bundle-output");
    const bundle = run.addOutputDirectoryArg(b.fmt("{s}-result", .{options.name}));

    return .{
        .path = bundle.path(b, options.output_basename),
        .report_path = bundle.path(b, "report.json"),
        .step = run,
    };
}

fn configureRequest(
    b: *std.Build,
    run: *std.Build.Step.Run,
    options: Options,
    container: Container,
) void {
    run.addArg("--iso");
    run.addFileArg(options.iso);
    run.addArg("--container");
    switch (container) {
        .oci_layout => |layout| run.addDirectoryArg(layout),
        .archive => |archive| run.addFileArg(archive),
    }
    run.addArgs(&.{ "--rootfs-size", b.fmt("{d}", .{options.rootfs_size}) });
    if (options.rootfs_path_in_iso) |path| run.addArgs(&.{ "--rootfs-path", path });
    if (options.nested_rootfs_path) |path| run.addArgs(&.{ "--nested-rootfs-path", path });
    if (options.volume_id) |id| run.addArgs(&.{ "--volume-id", id });
    for (options.boot_images) |image| switch (image.platform) {
        .uefi => run.addArgs(&.{ "--uefi-boot-image", image.image_path }),
        .bios => run.addArgs(&.{ "--bios-boot-image", image.image_path }),
    };
    if (options.squashfs_compression != .zstd) {
        run.addArgs(&.{ "--squashfs-compression", options.squashfs_compression.cliName() });
    }
    if (options.skip_iso_rootfs) run.addArg("--skip-iso-rootfs");
    if (options.architecture) |arch| run.addArgs(&.{ "--architecture", arch.cliName() });
    if (!std.mem.eql(u8, options.ext4_label, "rootfs")) run.addArgs(&.{ "--ext4-label", options.ext4_label });
    if (options.journal) run.addArg("--journal");
    if (options.journal_size) |size| run.addArgs(&.{ "--journal-size", b.fmt("{d}", .{size}) });
    if (options.root_selinux_label) |label| run.addArgs(&.{ "--root-selinux-label", label });
    if (options.source_date_epoch) |epoch| run.addArgs(&.{ "--source-date-epoch", b.fmt("{d}", .{epoch}) });
    addLimitArgs(b, run, options.limits);
    addCustomizationArgs(b, run, options) catch @panic("failed to materialize iso customization");
    if (options.verbose) run.addArg("--verbose");
}

fn addLimitArgs(b: *std.Build, run: *std.Build.Step.Run, limits: ImportLimits) void {
    const defaults = ImportLimits{};
    inline for (comptime std.enums.values(limits_mod.Limit)) |limit| {
        const raised = limits.value(limit);
        if (raised != defaults.value(limit)) {
            run.addArgs(&.{ comptime limit.flag(), b.fmt("{d}", .{raised}) });
        }
    }
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
                    .inline_bytes => |bytes| inline_files.add(b.fmt("inline-{d}", .{index}), bytes),
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
    config_files.step.name = b.fmt("write iso customization config for {s}", .{options.name});
    const config_path = config_files.add("customization.json", json);

    run.addArg("--customization-config");
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
    return generalization != .none;
}

test {
    std.testing.refAllDecls(@This());
}
