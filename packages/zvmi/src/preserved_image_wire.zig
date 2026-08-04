const std = @import("std");
const customization_wire = @import("customization_wire.zig");
const lvm = @import("lvm.zig");

pub const previous_api_version: u32 = 2;
pub const api_version: u32 = 3;

pub const Backend = enum {
    native_edit,
    rebuild,
    unsafe_chroot,
    vm,
};

/// Names a logical volume inside an LVM2 volume group on the disk.
/// `volume_group` may be left empty when the disk carries exactly one.
pub const LogicalVolumeSelector = struct {
    volume_group: []const u8 = "",
    logical_volume: []const u8,
};

pub const PartitionSelector = union(enum) {
    gpt_index: u32,
    mbr_index: u8,
    /// Only meaningful from api_version 3 onwards; `validateV2` refuses it so
    /// a v2 configuration accepts exactly what it always did.
    logical_volume: LogicalVolumeSelector,
};

/// Which ext4 sources the `rebuild` backend will import. Defaulted to
/// `strict`, so a configuration written before this existed keeps the only
/// profile that underwrites a byte-for-byte reproducible rebuild.
pub const SourceProfile = enum {
    strict,
    general,
};

/// Whether the rebuilt root filesystem carries a JBD2 journal, and how large.
/// `rebuild`-only, like every other field that describes the filesystem the
/// rebuild writes. Off by default so a configuration written before this
/// existed keeps producing the same bytes.
pub const JournalPolicy = struct {
    enabled: bool = false,
    /// Journal size in bytes, a whole number of filesystem blocks. Null takes
    /// the `mke2fs`-derived default scaled to the filesystem size.
    size_bytes: ?u64 = null,
};

/// What the rebuild is allowed to do about the identifiers it retires.
/// `rewrite_and_verify` is the default because the failure the verification
/// pass prevents -- an image whose `/etc/fstab` or bootloader configuration
/// still names a filesystem that no longer exists -- is invisible until the
/// image is booted.
pub const IdentityRewrite = enum {
    rewrite_and_verify,
    rewrite_only,
    off,
};

/// Which reader a merged source is handed to. `detect` probes the on-disk
/// magic and refuses anything it cannot name, so it never guesses.
pub const SourceFilesystem = enum {
    detect,
    ext4,
    fat32,
};

/// POSIX metadata invented for entries read from a FAT source, which stores
/// none of its own. The defaults are the documented ones and are spelled out
/// here so a configuration that says nothing still says what it got.
pub const SynthesizedFatMetadata = struct {
    directory_mode: u16 = 0o755,
    file_mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
};

/// One extra filesystem merged into the rebuilt root. `source_path` is empty
/// for the disk being rebuilt, which is the common case of several partitions
/// of one disk.
pub const SourceMount = struct {
    source_path: []const u8 = "",
    partition: PartitionSelector,
    target: []const u8,
    filesystem: SourceFilesystem = .detect,
    fat_metadata: SynthesizedFatMetadata = .{},
};

pub const OverwriteFile = struct {
    path: []const u8,
    source_index: usize,
};

pub const Operation = union(enum) {
    overwrite_file: OverwriteFile,
    remove_file: []const u8,
    remove_tree: []const u8,
};

pub const PackageAction = union(enum) {
    install: []const []const u8,
    remove: []const []const u8,
    update_all,
    update_selected: []const []const u8,
};

pub const TrustSource = struct {
    source_index: usize,
};

/// Deliberately not a `source_index`. Trust material is public, so it is staged
/// into the build graph and travels as a file the build system owns a copy of.
/// Credential material must never be staged: a copy in the build cache is a
/// secret written somewhere nobody deletes. Only the locator crosses this wire.
pub const CredentialSource = union(enum) {
    host_path: []const u8,
    host_environment: []const u8,
};

pub const BasicCredential = struct {
    username: []const u8,
    password: CredentialSource,
};

pub const RepositoryCredential = union(enum) {
    basic: BasicCredential,
};

pub const PackageRepository = struct {
    id: []const u8,
    urls: []const []const u8,
    trust: []const TrustSource = &.{},
    credential: ?RepositoryCredential = null,
};

pub const HookPhase = enum {
    after_packages,
    before_initramfs,
    before_seal,
    finalize,
};

/// A staged file, like repository trust and unlike a credential. A hook script
/// is code the build produced and the provenance names by digest, so the build
/// system owning a copy of it is the point rather than a leak.
pub const HookSource = struct {
    source_index: usize,
};

pub const Hook = struct {
    name: []const u8,
    phase: HookPhase,
    source: HookSource,
    arguments: []const []const u8 = &.{},
};

pub const PackageCachePolicy = enum {
    online,
    cache_only,
};

pub const PackageVersionLock = struct {
    name: []const u8,
    /// rpm's `EPOCH:VERSION-RELEASE`. See `customize.PackageVersionLock` for
    /// why identity is spelled this way and why no repository id travels with
    /// it: nothing on either side of this wire can determine one.
    evr: []const u8,
    architecture: []const u8,
};

pub const PackageLockPolicy = union(enum) {
    unlocked,
    snapshot: []const u8,
    exact: []const PackageVersionLock,
};

pub const ResolverPolicy = union(enum) {
    /// The build host's resolver, however the chosen backend reaches it.
    host_resolver,
    /// Exactly these nameservers, and nothing the host knows.
    nameservers: []const []const u8,
};

pub const PackagePolicy = struct {
    actions: []const PackageAction = &.{},
    repositories: []const PackageRepository = &.{},
    cache: PackageCachePolicy = .online,
    lock: PackageLockPolicy = .unlocked,
    resolver: ResolverPolicy = .host_resolver,
};

/// Whether an empty `kernels` list that discovers no installed kernel is an
/// error or simply nothing to do.
pub const NoInstalledKernelsPolicy = enum {
    fail,
    nothing_to_regenerate,
};

pub const InitramfsPolicy = union(enum) {
    unchanged,
    regenerate: struct {
        generator: ?[]const u8 = null,
        kernels: []const []const u8 = &.{},
        no_installed_kernels: NoInstalledKernelsPolicy = .fail,
    },
    /// Let the build decide from the rest of the configuration. See
    /// `customize.initramfsNeedsRegeneration` for what implies a rebuild.
    when_needed: struct {
        generator: ?[]const u8 = null,
    },
};

/// Whether the guest runs at the host architecture or a foreign one. This
/// stays an enum so configurations written before cross-architecture support
/// keep deserializing unchanged; the runner that makes a foreign architecture
/// executable is a separate optional field.
pub const GuestExecutionPolicy = enum {
    same_architecture,
    cross_architecture,
};

pub const RunnerKind = enum {
    qemu_user,
    binfmt_misc,
    vm,
};

pub const Architecture = enum {
    x86_64,
    aarch64,
};

pub const Runner = struct {
    kind: RunnerKind,
    guest_architecture: Architecture,
    command: ?[]const u8 = null,
};

pub const VmAcceleration = enum {
    hardware,
    software,
};

pub const VmNetworkPolicy = enum {
    offline,
    declared_repositories,
};

pub const VmFirmware = struct {
    /// Absent asks the builder to resolve architecture-matched EDK2 firmware
    /// the way `zvmi qemu` does, from the emulator's own `share/` directory
    /// and then the system locations. Present names the files exactly, which
    /// is what a build that must pin its firmware does. Both or neither: half
    /// a pair would leave the other half resolved against a different
    /// firmware build.
    code_path: ?[]const u8 = null,
    vars_path: ?[]const u8 = null,
    /// What the image's own boot chain prints on the serial console once it
    /// has taken control. Required: nothing on the host can know it, and a
    /// guessed marker would attest a boot that never happened.
    console_marker: []const u8,
    secure_boot: bool = false,
    boot_timeout_seconds: u32 = 1800,
};

pub const VmBoot = union(enum) {
    direct_kernel,
    firmware: VmFirmware,
};

pub const VmConfiguration = struct {
    emulator_command: []const u8,
    boot: VmBoot = .direct_kernel,
    acceleration: VmAcceleration = .hardware,
    acknowledge_software_emulation: bool = false,
    memory_mib: u32 = 2048,
    vcpus: u8 = 2,
    network: VmNetworkPolicy = .offline,
    boot_timeout_seconds: u32 = 900,
    machine: ?[]const u8 = null,
    cpu: ?[]const u8 = null,
};

pub const ConfigurationV2 = struct {
    api_version: u32 = previous_api_version,
    backend: enum { native_edit, rebuild } = .native_edit,
    root_partition: PartitionSelector,
    operations: []const Operation = &.{},
    customization: customization_wire.Configuration = .{},
};

pub const Configuration = struct {
    api_version: u32 = api_version,
    backend: Backend = .native_edit,
    root_partition: PartitionSelector,
    operations: []const Operation = &.{},
    customization: customization_wire.Configuration = .{},
    acknowledge_unsafe: bool = false,
    packages: PackagePolicy = .{},
    hooks: []const Hook = &.{},
    initramfs: InitramfsPolicy = .unchanged,
    guest_execution: GuestExecutionPolicy = .same_architecture,
    runner: ?Runner = null,
    vm: ?VmConfiguration = null,
    /// Only the `rebuild` backend imports a filesystem, so this is only
    /// meaningful there; `validate` rejects it elsewhere rather than letting
    /// it read as an accepted setting that silently does nothing.
    source_profile: SourceProfile = .strict,
    /// Extra filesystems merged into the rebuilt root, in order, each at its
    /// own mount point. Also `rebuild`-only. The full mount-target rules --
    /// absolute, normalized, non-overlapping, reached without traversing a
    /// symlink -- are enforced by the rebuild itself against the assembled
    /// tree, because only that tree knows what the targets have to exist in;
    /// restating them here would let the two drift apart.
    source_mounts: []const SourceMount = &.{},
    /// Whether the rebuilt tree's `/etc/fstab` and bootloader configuration
    /// are reconciled with the identifiers the rebuild retired, and whether a
    /// surviving stale one fails the build. `rebuild`-only for the same
    /// reason as the two fields above: every other backend keeps the source's
    /// filesystems exactly as they are, so nothing is ever retired.
    identity_rewrite: IdentityRewrite = .rewrite_and_verify,
    /// Whether the rebuilt root filesystem gets a journal. `rebuild`-only:
    /// every other backend preserves the source's filesystem rather than
    /// writing a new one, so there is nothing here for it to decide.
    journal: JournalPolicy = .{},
};

pub const ValidationError = error{
    UnsupportedApiVersion,
    InvalidPartitionSelector,
    MissingSourceArgument,
    ExtraSourceArgument,
    SourceIndexOutOfBounds,
    DuplicateSourceIndex,
    MissingVmConfiguration,
    UnexpectedVmConfiguration,
    IncompleteFirmwareOverride,
    MissingFirmwareConsoleMarker,
    MissingCrossArchitectureRunner,
    UnexpectedCrossArchitectureRunner,
    UnexpectedSourceProfile,
    UnexpectedSourceMounts,
    UnexpectedIdentityRewrite,
    UnexpectedJournalPolicy,
    MissingMountTarget,
    UnsupportedPartitionSelectorForApiVersion,
};

pub fn validateV2(configuration: ConfigurationV2, source_count: usize) ValidationError!void {
    if (configuration.api_version != previous_api_version) {
        return error.UnsupportedApiVersion;
    }
    // Logical volume selectors arrived with v3. A v2 configuration is
    // accepted on exactly the terms it was written against.
    if (configuration.root_partition == .logical_volume) {
        return error.UnsupportedPartitionSelectorForApiVersion;
    }
    try validatePartition(configuration.root_partition);
    try validateExistingSourceClosure(
        configuration.operations,
        configuration.customization,
        source_count,
    );
}

pub fn validate(configuration: Configuration, source_count: usize) ValidationError!void {
    if (configuration.api_version != api_version) return error.UnsupportedApiVersion;
    try validatePartition(configuration.root_partition);

    // The VM configuration and the backend that reads it travel together, so a
    // configuration can never describe a guest that will not be built or a
    // backend that would have to invent one.
    if (configuration.backend == .vm) {
        if (configuration.vm == null) return error.MissingVmConfiguration;
        switch (configuration.vm.?.boot) {
            .direct_kernel => {},
            .firmware => |firmware| {
                if ((firmware.code_path == null) != (firmware.vars_path == null)) {
                    return error.IncompleteFirmwareOverride;
                }
                if (firmware.console_marker.len == 0) {
                    return error.MissingFirmwareConsoleMarker;
                }
            },
        }
    } else if (configuration.vm != null) {
        return error.UnexpectedVmConfiguration;
    }
    if (configuration.backend != .rebuild and configuration.source_profile != .strict) {
        return error.UnexpectedSourceProfile;
    }
    if (configuration.backend != .rebuild and configuration.source_mounts.len != 0) {
        return error.UnexpectedSourceMounts;
    }
    if (configuration.backend != .rebuild and
        configuration.identity_rewrite != .rewrite_and_verify)
    {
        return error.UnexpectedIdentityRewrite;
    }
    if (configuration.backend != .rebuild and
        (configuration.journal.enabled or configuration.journal.size_bytes != null))
    {
        return error.UnexpectedJournalPolicy;
    }
    for (configuration.source_mounts) |mount| {
        try validatePartition(mount.partition);
        if (mount.target.len == 0) return error.MissingMountTarget;
    }
    switch (configuration.guest_execution) {
        .same_architecture => if (configuration.runner != null) {
            return error.UnexpectedCrossArchitectureRunner;
        },
        .cross_architecture => if (configuration.runner == null) {
            return error.MissingCrossArchitectureRunner;
        },
    }

    var expected_sources: usize = 0;
    for (configuration.operations) |operation| {
        if (operation == .overwrite_file) expected_sources += 1;
    }
    for (configuration.customization.os.filesystem) |operation| {
        if (operation == .put_file) expected_sources += 1;
    }
    for (configuration.packages.repositories) |repository| {
        expected_sources += repository.trust.len;
    }
    expected_sources += configuration.hooks.len;
    if (source_count < expected_sources) return error.MissingSourceArgument;
    if (source_count > expected_sources) return error.ExtraSourceArgument;

    var iterator = SourceIndexIterator.init(configuration);
    var ordinal: usize = 0;
    while (iterator.next()) |source_index| : (ordinal += 1) {
        if (source_index >= source_count) return error.SourceIndexOutOfBounds;
        var previous = SourceIndexIterator.init(configuration);
        var previous_ordinal: usize = 0;
        while (previous_ordinal < ordinal) : (previous_ordinal += 1) {
            if (source_index == previous.next().?) return error.DuplicateSourceIndex;
        }
    }
}

fn validatePartition(partition: PartitionSelector) ValidationError!void {
    switch (partition) {
        .gpt_index => |index| if (index == 0) return error.InvalidPartitionSelector,
        .mbr_index => |index| if (index == 0 or index > 4) {
            return error.InvalidPartitionSelector;
        },
        .logical_volume => |volume| {
            // The volume group may be left unnamed on a disk that carries
            // one, but a selector that names no logical volume names
            // nothing at all.
            if (volume.logical_volume.len == 0) return error.InvalidPartitionSelector;
            if (volume.logical_volume.len > lvm.max_name_len or
                volume.volume_group.len > lvm.max_name_len)
            {
                return error.InvalidPartitionSelector;
            }
        },
    }
}

fn validateExistingSourceClosure(
    operations: []const Operation,
    customization: customization_wire.Configuration,
    source_count: usize,
) ValidationError!void {
    const configuration = Configuration{
        .root_partition = .{ .gpt_index = 1 },
        .operations = operations,
        .customization = customization,
    };
    try validate(configuration, source_count);
}

const SourceIndexIterator = struct {
    configuration: Configuration,
    operation_index: usize = 0,
    filesystem_index: usize = 0,
    repository_index: usize = 0,
    trust_index: usize = 0,
    hook_index: usize = 0,

    fn init(configuration: Configuration) SourceIndexIterator {
        return .{ .configuration = configuration };
    }

    fn next(self: *SourceIndexIterator) ?usize {
        while (self.operation_index < self.configuration.operations.len) {
            const operation = self.configuration.operations[self.operation_index];
            self.operation_index += 1;
            switch (operation) {
                .overwrite_file => |overwrite| return overwrite.source_index,
                .remove_file, .remove_tree => {},
            }
        }
        while (self.filesystem_index < self.configuration.customization.os.filesystem.len) {
            const operation = self.configuration.customization.os.filesystem[self.filesystem_index];
            self.filesystem_index += 1;
            switch (operation) {
                .put_file => |file| return file.source_index,
                .put_directory, .put_symlink, .remove, .set_metadata => {},
            }
        }
        while (self.repository_index < self.configuration.packages.repositories.len) {
            const repository = self.configuration.packages.repositories[self.repository_index];
            if (self.trust_index < repository.trust.len) {
                const source_index = repository.trust[self.trust_index].source_index;
                self.trust_index += 1;
                return source_index;
            }
            self.repository_index += 1;
            self.trust_index = 0;
        }
        while (self.hook_index < self.configuration.hooks.len) {
            const hook = self.configuration.hooks[self.hook_index];
            self.hook_index += 1;
            return hook.source.source_index;
        }
        return null;
    }
};

test "source arguments form an exact indexed closure" {
    const operations = [_]Operation{
        .{ .overwrite_file = .{ .path = "/etc/first", .source_index = 1 } },
        .{ .remove_file = "/etc/old" },
        .{ .overwrite_file = .{ .path = "/etc/second", .source_index = 0 } },
    };
    var customization_operations = [_]customization_wire.FilesystemOperation{
        .{ .put_file = .{ .path = "/etc/third", .source_index = 2 } },
    };
    const configuration = Configuration{
        .backend = .unsafe_chroot,
        .root_partition = .{ .gpt_index = 2 },
        .operations = &operations,
        .customization = .{ .os = .{ .filesystem = &customization_operations } },
        .acknowledge_unsafe = true,
        .packages = .{ .repositories = &.{.{
            .id = "base",
            .urls = &.{"https://packages.example.invalid"},
            .trust = &.{.{ .source_index = 3 }},
        }} },
    };

    try validate(configuration, 4);
    try std.testing.expectError(error.MissingSourceArgument, validate(configuration, 3));
    try std.testing.expectError(error.ExtraSourceArgument, validate(configuration, 5));

    var out_of_bounds = operations;
    out_of_bounds[0].overwrite_file.source_index = 4;
    try std.testing.expectError(error.SourceIndexOutOfBounds, validate(.{
        .root_partition = .{ .gpt_index = 2 },
        .operations = &out_of_bounds,
        .customization = configuration.customization,
        .packages = configuration.packages,
    }, 4));

    var duplicate = operations;
    duplicate[0].overwrite_file.source_index = 0;
    try std.testing.expectError(error.DuplicateSourceIndex, validate(.{
        .root_partition = .{ .mbr_index = 1 },
        .operations = &duplicate,
        .customization = configuration.customization,
        .packages = configuration.packages,
    }, 4));

    customization_operations[0].put_file.source_index = 0;
    try std.testing.expectError(
        error.DuplicateSourceIndex,
        validate(configuration, 4),
    );
}

test "repository trust participates in the shared source closure" {
    var trust = [_]TrustSource{.{ .source_index = 2 }};
    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &trust,
    }};
    const configuration = Configuration{
        .root_partition = .{ .gpt_index = 1 },
        .operations = &.{.{ .overwrite_file = .{
            .path = "/etc/one",
            .source_index = 0,
        } }},
        .customization = .{
            .os = .{
                .filesystem = &.{.{ .put_file = .{
                    .path = "/etc/two",
                    .source_index = 1,
                } }},
            },
        },
        .packages = .{
            .repositories = &repositories,
        },
    };
    try validate(configuration, 3);
    try std.testing.expectError(
        error.MissingSourceArgument,
        validate(configuration, 2),
    );
    try std.testing.expectError(
        error.ExtraSourceArgument,
        validate(configuration, 4),
    );

    trust[0].source_index = 1;
    try std.testing.expectError(
        error.DuplicateSourceIndex,
        validate(configuration, 3),
    );
    trust[0].source_index = 3;
    try std.testing.expectError(
        error.SourceIndexOutOfBounds,
        validate(configuration, 3),
    );
}

test "a hook script participates in the shared source closure" {
    var hooks = [_]Hook{
        .{ .name = "early", .phase = .after_packages, .source = .{ .source_index = 1 } },
        .{ .name = "late", .phase = .finalize, .source = .{ .source_index = 2 } },
    };
    const configuration = Configuration{
        .root_partition = .{ .gpt_index = 1 },
        .operations = &.{.{ .overwrite_file = .{
            .path = "/etc/one",
            .source_index = 0,
        } }},
        .hooks = &hooks,
    };
    // A hook script is code the build is accountable for, so it is staged and
    // indexed like every other byte stream rather than named by host path.
    try validate(configuration, 3);
    try std.testing.expectError(
        error.MissingSourceArgument,
        validate(configuration, 2),
    );
    try std.testing.expectError(
        error.ExtraSourceArgument,
        validate(configuration, 4),
    );

    hooks[1].source.source_index = 0;
    try std.testing.expectError(
        error.DuplicateSourceIndex,
        validate(configuration, 3),
    );
    hooks[1].source.source_index = 3;
    try std.testing.expectError(
        error.SourceIndexOutOfBounds,
        validate(configuration, 3),
    );
}

test "configuration version and one-based partition are validated" {
    try std.testing.expectError(error.UnsupportedApiVersion, validate(.{
        .api_version = api_version + 1,
        .root_partition = .{ .gpt_index = 1 },
    }, 0));
    try std.testing.expectError(error.InvalidPartitionSelector, validate(.{
        .root_partition = .{ .mbr_index = 0 },
    }, 0));
    try std.testing.expectError(error.InvalidPartitionSelector, validate(.{
        .root_partition = .{ .mbr_index = 5 },
    }, 0));
}

test "a logical volume selector needs a volume name and only exists from v3" {
    try validate(.{
        .root_partition = .{ .logical_volume = .{ .logical_volume = "root" } },
    }, 0);
    try validate(.{
        .root_partition = .{ .logical_volume = .{
            .volume_group = "ubuntu-vg",
            .logical_volume = "ubuntu-lv",
        } },
    }, 0);
    // The volume group may be omitted on a disk that carries one, but a
    // selector naming no logical volume names nothing.
    try std.testing.expectError(error.InvalidPartitionSelector, validate(.{
        .root_partition = .{ .logical_volume = .{ .logical_volume = "" } },
    }, 0));
    try std.testing.expectError(error.InvalidPartitionSelector, validate(.{
        .root_partition = .{ .logical_volume = .{
            .logical_volume = "x" ** (lvm.max_name_len + 1),
        } },
    }, 0));
    // v2 predates logical volumes, so a v2 configuration is held to exactly
    // what it was written against.
    try std.testing.expectError(
        error.UnsupportedPartitionSelectorForApiVersion,
        validateV2(.{ .root_partition = .{ .logical_volume = .{ .logical_volume = "root" } } }, 0),
    );
}

test "a merged source can be a logical volume too" {
    const boot = SourceMount{
        .partition = .{ .logical_volume = .{ .logical_volume = "boot" } },
        .target = "/boot",
    };
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .logical_volume = .{ .logical_volume = "root" } },
        .source_mounts = &.{boot},
    }, 0);
}

test "a source profile only travels with the backend that imports a filesystem" {
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .gpt_index = 1 },
        .source_profile = .general,
    }, 0);
    // Every other backend copies the source's bytes rather than reading its
    // tree, so a profile there would read as an accepted setting that does
    // nothing at all.
    try std.testing.expectError(error.UnexpectedSourceProfile, validate(.{
        .backend = .native_edit,
        .root_partition = .{ .gpt_index = 1 },
        .source_profile = .general,
    }, 0));
    try validate(.{
        .backend = .native_edit,
        .root_partition = .{ .gpt_index = 1 },
    }, 0);
}

test "merged sources only travel with the backend that imports a filesystem" {
    const boot = SourceMount{ .partition = .{ .mbr_index = 2 }, .target = "/boot" };
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .source_mounts = &.{boot},
    }, 0);
    try std.testing.expectError(error.UnexpectedSourceMounts, validate(.{
        .backend = .native_edit,
        .root_partition = .{ .mbr_index = 3 },
        .source_mounts = &.{boot},
    }, 0));
    // A mount's partition selector is as one-based as the root's, and a mount
    // with nowhere to land is not a mount.
    try std.testing.expectError(error.InvalidPartitionSelector, validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .source_mounts = &.{.{ .partition = .{ .mbr_index = 0 }, .target = "/boot" }},
    }, 0));
    try std.testing.expectError(error.MissingMountTarget, validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .source_mounts = &.{.{ .partition = .{ .mbr_index = 2 }, .target = "" }},
    }, 0));
}

test "the identity rewrite policy only travels with the backend that can retire an identifier" {
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .identity_rewrite = .rewrite_only,
    }, 0);
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .identity_rewrite = .off,
    }, 0);
    // Nothing but a rebuild reads the source's tree, so nothing but a rebuild
    // can retire an identifier; accepting the setting elsewhere would let an
    // operator believe they had turned a safety net off that was never on.
    try std.testing.expectError(error.UnexpectedIdentityRewrite, validate(.{
        .backend = .native_edit,
        .root_partition = .{ .mbr_index = 3 },
        .identity_rewrite = .off,
    }, 0));
    try validate(.{
        .backend = .native_edit,
        .root_partition = .{ .mbr_index = 3 },
    }, 0);
}

test "the journal policy only travels with the backend that writes a filesystem" {
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .journal = .{ .enabled = true },
    }, 0);
    try validate(.{
        .backend = .rebuild,
        .root_partition = .{ .mbr_index = 3 },
        .journal = .{ .enabled = true, .size_bytes = 32 * 1024 * 1024 },
    }, 0);
    // Every other backend preserves the source's filesystem rather than
    // writing a new one, so a journal setting there would read as an accepted
    // durability choice that nothing acts on.
    try std.testing.expectError(error.UnexpectedJournalPolicy, validate(.{
        .backend = .native_edit,
        .root_partition = .{ .mbr_index = 3 },
        .journal = .{ .enabled = true },
    }, 0));
    // A size without `enabled` is refused for the same reason: it is still a
    // journal setting, and silence about it would be the misleading part.
    try std.testing.expectError(error.UnexpectedJournalPolicy, validate(.{
        .backend = .vm,
        .root_partition = .{ .mbr_index = 3 },
        .vm = .{ .emulator_command = "qemu-system-x86_64" },
        .journal = .{ .size_bytes = 32 * 1024 * 1024 },
    }, 0));
    try validate(.{
        .backend = .native_edit,
        .root_partition = .{ .mbr_index = 3 },
    }, 0);
}

test "the vm backend and its configuration travel together" {
    const vm = VmConfiguration{ .emulator_command = "/usr/bin/qemu-system-x86_64" };

    try std.testing.expectError(error.MissingVmConfiguration, validate(.{
        .backend = .vm,
        .root_partition = .{ .gpt_index = 1 },
    }, 0));
    try std.testing.expectError(error.UnexpectedVmConfiguration, validate(.{
        .backend = .unsafe_chroot,
        .root_partition = .{ .gpt_index = 1 },
        .vm = vm,
    }, 0));
    try validate(.{
        .backend = .vm,
        .root_partition = .{ .gpt_index = 1 },
        .vm = vm,
    }, 0);
}

test "a cross-architecture guest requires exactly one declared runner" {
    const runner = Runner{
        .kind = .vm,
        .guest_architecture = .aarch64,
        .command = "/usr/bin/qemu-system-aarch64",
    };

    try std.testing.expectError(error.MissingCrossArchitectureRunner, validate(.{
        .root_partition = .{ .gpt_index = 1 },
        .guest_execution = .cross_architecture,
    }, 0));
    try std.testing.expectError(error.UnexpectedCrossArchitectureRunner, validate(.{
        .root_partition = .{ .gpt_index = 1 },
        .guest_execution = .same_architecture,
        .runner = runner,
    }, 0));
    try validate(.{
        .root_partition = .{ .gpt_index = 1 },
        .guest_execution = .cross_architecture,
        .runner = runner,
    }, 0);
}

test "configurations written before vm support still deserialize" {
    // `runner` and `vm` are additive, so a v3 document that predates them
    // parses without an api_version bump. Deriving the legacy document from
    // the serializer keeps this honest as other fields change.
    const legacy_shape = Configuration{
        .backend = .unsafe_chroot,
        .root_partition = .{ .mbr_index = 1 },
        .acknowledge_unsafe = true,
    };
    const full = try std.json.Stringify.valueAlloc(
        std.testing.allocator,
        legacy_shape,
        .{},
    );
    defer std.testing.allocator.free(full);
    try std.testing.expect(std.mem.indexOf(u8, full, "\"runner\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, full, "\"vm\":null") != null);

    const legacy = try std.mem.replaceOwned(
        u8,
        std.testing.allocator,
        full,
        ",\"runner\":null,\"vm\":null",
        "",
    );
    defer std.testing.allocator.free(legacy);

    const parsed = try std.json.parseFromSlice(
        Configuration,
        std.testing.allocator,
        legacy,
        .{ .ignore_unknown_fields = false },
    );
    defer parsed.deinit();
    try std.testing.expectEqual(Backend.unsafe_chroot, parsed.value.backend);
    try std.testing.expect(parsed.value.runner == null);
    try std.testing.expect(parsed.value.vm == null);
    try validate(parsed.value, 0);
}

test "v2 configurations remain valid with their original source closure" {
    const configuration = ConfigurationV2{
        .backend = .rebuild,
        .root_partition = .{ .gpt_index = 1 },
        .operations = &.{.{ .overwrite_file = .{
            .path = "/etc/value",
            .source_index = 0,
        } }},
    };
    try validateV2(configuration, 1);
    try std.testing.expectError(
        error.UnsupportedApiVersion,
        validateV2(.{
            .api_version = api_version,
            .root_partition = .{ .gpt_index = 1 },
        }, 0),
    );
}
