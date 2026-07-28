//! Versioned image-customization request, planning, preflight, execution, and
//! provenance API. Native fresh construction and constrained native preserved
//! disk editing are implemented. Broader mutation and guest-code backends are
//! modeled explicitly and fail capability preflight until implemented.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const azure = @import("azure.zig");
const bootconfig = @import("bootconfig.zig");
const build_image = @import("build_image.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const Format = @import("formats.zig").Format;
const gpt = @import("gpt.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const layout = @import("layout.zig");
const mbr = @import("mbr.zig");
const os_customization = @import("os_customization.zig");
const customization_wire = @import("customization_wire.zig");
const preserved_image = @import("preserved_image.zig");
const root_tree = @import("root_tree.zig");
const transaction_guard = @import("transaction_guard.zig");
const verity = @import("verity.zig");

pub const legacy_api_version: u32 = 2;
pub const current_api_version: u32 = 3;
pub const plan_schema_version: u32 = 4;
pub const provenance_schema_version: u32 = 7;
const mib: u64 = 1024 * 1024;

comptime {
    std.debug.assert(customization_wire.api_version == legacy_api_version);
}

pub const Architecture = bootconfig.Architecture;

pub const Seed = struct {
    bytes: [32]u8,

    pub fn jsonStringify(self: Seed, stringify: anytype) !void {
        const hex = std.fmt.bytesToHex(self.bytes, .lower);
        try stringify.write(&hex);
    }
};

pub const Digest = struct {
    bytes: [32]u8,

    pub fn jsonStringify(self: Digest, stringify: anytype) !void {
        const hex = std.fmt.bytesToHex(self.bytes, .lower);
        try stringify.write(&hex);
    }
};

pub const Guid = struct {
    bytes: guid.Guid,

    pub fn jsonStringify(self: Guid, stringify: anytype) !void {
        var buf: [36]u8 = undefined;
        try stringify.write(guid.formatLower(&buf, self.bytes));
    }
};

pub const Uuid = struct {
    bytes: [16]u8,

    pub fn jsonStringify(self: Uuid, stringify: anytype) !void {
        const hex = std.fmt.bytesToHex(self.bytes, .lower);
        try stringify.write(&hex);
    }
};

pub const IsoOciInput = struct {
    iso_path: []const u8,
    container_path: []const u8,
    rootfs_path_in_iso: ?[]const u8,
};

pub const DiskInput = struct {
    path: []const u8,
    /// Every qcow2 backing or external-data file, transitively. The native
    /// editor verifies this declaration before creating its workspace.
    dependencies: []const []const u8 = &.{},
};

pub const Input = union(enum) {
    iso_oci: IsoOciInput,
    disk: DiskInput,
};

pub const OutputFormat = enum {
    raw,
    vhd,
    vhdx,
    qcow2,
    cosi,

    fn imageFormat(self: OutputFormat) ?Format {
        return switch (self) {
            .raw => .raw,
            .vhd => .vhd,
            .vhdx => .vhdx,
            .qcow2 => .qcow2,
            .cosi => null,
        };
    }
};

pub const Output = struct {
    path: []const u8,
    format: OutputFormat,
    /// Fresh images use `.explicit`; preserved images must use
    /// `.preserve_source` with `size == 0`.
    size: u64 = 0,
    size_policy: OutputSizePolicy = .explicit,
};

pub const OutputSizePolicy = enum {
    explicit,
    preserve_source,
};

pub const FreshStorage = struct {
    generation: azure.Generation = .gen2,
    esp_size: u64 = build_image.default_esp_size,
    ext4_label: []const u8 = "rootfs",
    skip_iso_rootfs: bool = false,
};

pub const PartitionSelector = preserved_image.PartitionSelector;

pub const PreservedStorage = struct {
    root_partition: PartitionSelector,
};
pub const PreserveStorage = PreservedStorage;
pub const RootPartitionSelector = PartitionSelector;

pub const StoragePolicy = union(enum) {
    fresh: FreshStorage,
    preserve: PreservedStorage,
};

pub const ExistingPathOperation = preserved_image.Operation;
pub const ExistingPathFileSource = preserved_image.FileSource;
pub const PreservedOperation = ExistingPathOperation;
pub const PreservedFileSource = ExistingPathFileSource;

pub const OsCustomization = os_customization.OsCustomization;
pub const FilesystemOperation = os_customization.FilesystemOperation;
pub const PutFile = os_customization.PutFile;
pub const PutDirectory = os_customization.PutDirectory;
pub const PutSymlink = os_customization.PutSymlink;
pub const FileSource = os_customization.FileSource;
pub const Metadata = os_customization.Metadata;
pub const MetadataChange = os_customization.MetadataChange;
pub const Group = os_customization.Group;
pub const User = os_customization.User;
pub const Password = os_customization.Password;
pub const Service = os_customization.Service;
pub const ServiceState = os_customization.ServiceState;
pub const KernelModule = os_customization.KernelModule;

pub const UkiOptions = struct {
    stub_source_path: ?[]const u8 = null,
    os_release_source_path: ?[]const u8 = null,
    splash_source_path: ?[]const u8 = null,
    output_directory: []const u8 = "EFI/Linux",
};

pub const BootSecurityPolicy = struct {
    boot_mode: bootconfig.BootMode = .bls_only,
    verity: bool = false,
    extra_kernel_options: []const u8 = "",
    uki: UkiOptions = .{},
};

pub const AzureGeneralization = os_customization.AzureGeneralization;
pub const GeneralizationPolicy = os_customization.GeneralizationPolicy;

pub const ExecutionBackend = enum {
    native_fresh,
    native_edit,
    rebuild,
    unsafe_chroot,
    vm,
};

pub const ExecutionPolicy = struct {
    workspace_path: []const u8,
    backend: ExecutionBackend = .native_fresh,
    overwrite: bool = false,
    /// Required for scripts and for `unsafe_chroot`, which executes target
    /// code on the host and is not a sandbox.
    acknowledge_unsafe: bool = false,
    /// Required by, and only meaningful to, the `vm` backend.
    vm: ?VmPolicy = null,
};

/// How the `vm` backend executes guest instructions. There is deliberately no
/// `auto`: a run that claims hardware acceleration and silently receives
/// software emulation would record a false accelerator in its provenance.
pub const VmAcceleration = enum {
    /// Hardware virtualization. Requires the runner architecture to equal the
    /// host architecture and an accessible accelerator device.
    hardware,
    /// Full software emulation. The only option across architectures.
    software,
};

/// Whether the guest is given a network device. Package repositories are the
/// only reason to attach one.
pub const VmNetworkPolicy = enum {
    offline,
    declared_repositories,
};

/// UEFI firmware for a guest that boots the way real hardware would.
pub const VmFirmware = struct {
    /// Read-only firmware code for the runner architecture.
    code_path: []const u8,
    /// Template variable store. The backend works on a copy, so the file named
    /// here is never modified.
    vars_path: []const u8,
};

/// How the guest is brought up.
pub const VmBoot = union(enum) {
    /// Boot the image's own kernel and initramfs directly, with the guest
    /// agent appended to the initramfs. No firmware, bootloader, or init
    /// system stands between the emulator and the agent, which is what keeps
    /// software emulation affordable and boot failures attributable.
    direct_kernel,
    /// Boot through UEFI firmware, exercising the image's own boot chain.
    firmware: VmFirmware,
};

pub const VmPolicy = struct {
    /// The `qemu-system-<arch>` binary for the runner architecture. Never
    /// inferred from the host architecture.
    emulator_command: []const u8,
    boot: VmBoot = .direct_kernel,
    acceleration: VmAcceleration = .hardware,
    /// Acknowledges software emulation for a same-architecture run, where
    /// hardware acceleration would otherwise be expected.
    acknowledge_software_emulation: bool = false,
    memory_mib: u32 = 2048,
    vcpus: u8 = 2,
    network: VmNetworkPolicy = .offline,
    boot_timeout_seconds: u32 = 900,
    machine: ?[]const u8 = null,
    cpu: ?[]const u8 = null,
};

pub const min_vm_memory_mib: u32 = 512;
pub const max_vm_memory_mib: u32 = 1024 * 1024;
pub const max_vm_boot_timeout_seconds: u32 = 24 * 60 * 60;

pub const PackageAction = union(enum) {
    install: []const []const u8,
    remove: []const []const u8,
    update_all,
    update_selected: []const []const u8,
};

pub const TrustSource = union(enum) {
    inline_bytes: []const u8,
    host_path: []const u8,
};

pub const PackageRepository = struct {
    id: []const u8,
    urls: []const []const u8,
    trust: []const TrustSource,
};

pub const PackageCachePolicy = enum {
    online,
    cache_only,
};

pub const PackageVersionLock = struct {
    name: []const u8,
    version: []const u8,
    repository_id: []const u8,
};

pub const PackageLockPolicy = union(enum) {
    unlocked,
    snapshot: []const u8,
    exact: []const PackageVersionLock,
};

pub const PackagePolicy = struct {
    actions: []const PackageAction = &.{},
    repositories: []const PackageRepository = &.{},
    cache: PackageCachePolicy = .online,
    lock: PackageLockPolicy = .unlocked,
};

pub const HookPhase = enum {
    after_packages,
    before_initramfs,
    before_seal,
    finalize,
};

pub const HookSource = union(enum) {
    inline_script: []const u8,
    host_path: []const u8,
};

pub const Hook = struct {
    name: []const u8,
    phase: HookPhase,
    source: HookSource,
    arguments: []const []const u8 = &.{},
};

pub const InitramfsPolicy = union(enum) {
    unchanged,
    regenerate: struct {
        generator: ?[]const u8 = null,
        kernels: []const []const u8 = &.{},
    },
};

pub const SelinuxMode = enum {
    enforcing,
    permissive,
    disabled,
};

pub const SelinuxPolicy = union(enum) {
    unchanged,
    configure: struct {
        mode: SelinuxMode,
        policy: ?[]const u8 = null,
        relabel: bool = false,
    },
};

pub const RunnerKind = enum {
    qemu_user,
    binfmt_misc,
    vm,
};

pub const CompatibleRunner = struct {
    kind: RunnerKind,
    guest_architecture: Architecture,
    command: ?[]const u8 = null,
};

pub const CrossArchitecturePolicy = union(enum) {
    reject,
    runner: CompatibleRunner,
};

pub const Reproducibility = struct {
    seed: Seed,
    source_date_epoch: u64,
};

pub const Request = struct {
    api_version: u32 = current_api_version,
    target_architecture: ?Architecture = null,
    input: Input,
    output: Output,
    storage: StoragePolicy,
    os: OsCustomization = .{},
    existing_path_operations: []const ExistingPathOperation = &.{},
    packages: PackagePolicy = .{},
    hooks: []const Hook = &.{},
    initramfs: InitramfsPolicy = .unchanged,
    selinux: SelinuxPolicy = .unchanged,
    cross_architecture: CrossArchitecturePolicy = .reject,
    boot_security: BootSecurityPolicy = .{},
    generalization: GeneralizationPolicy = .none,
    execution: ExecutionPolicy,
    reproducibility: Reproducibility,
};

pub const V2ExecutionBackend = enum {
    native,
    chroot,
    vm,
};

pub const V2ExecutionPolicy = struct {
    workspace_path: []const u8,
    backend: V2ExecutionBackend = .native,
    overwrite: bool = false,
};

pub const V2StoragePolicy = union(enum) {
    fresh: FreshStorage,
    preserve: void,
};

pub const V2Output = struct {
    path: []const u8,
    format: OutputFormat,
    size: u64,
};

/// The frozen v2 request shape. It can only enter v3 through
/// `adaptV2NativeFresh`; v3 validation never reinterprets `api_version = 2`.
pub const RequestV2 = struct {
    api_version: u32 = legacy_api_version,
    target_architecture: ?Architecture = null,
    input: Input,
    output: V2Output,
    storage: V2StoragePolicy,
    os: OsCustomization = .{},
    boot_security: BootSecurityPolicy = .{},
    generalization: GeneralizationPolicy = .none,
    execution: V2ExecutionPolicy,
    reproducibility: Reproducibility,
};

pub const V2Request = RequestV2;

pub const AdaptV2Error = error{
    UnsupportedApiVersion,
    UnsupportedV2Input,
    UnsupportedV2Storage,
    UnsupportedV2Backend,
};

pub fn adaptV2NativeFresh(request: *const RequestV2) AdaptV2Error!Request {
    if (request.api_version != legacy_api_version) return error.UnsupportedApiVersion;
    if (request.input != .iso_oci) return error.UnsupportedV2Input;
    if (request.storage != .fresh) return error.UnsupportedV2Storage;
    if (request.execution.backend != .native) return error.UnsupportedV2Backend;
    return .{
        .api_version = current_api_version,
        .target_architecture = request.target_architecture,
        .input = request.input,
        .output = .{
            .path = request.output.path,
            .format = request.output.format,
            .size = request.output.size,
            .size_policy = .explicit,
        },
        .storage = .{ .fresh = request.storage.fresh },
        .os = request.os,
        .boot_security = request.boot_security,
        .generalization = request.generalization,
        .execution = .{
            .workspace_path = request.execution.workspace_path,
            .backend = .native_fresh,
            .overwrite = request.execution.overwrite,
        },
        .reproducibility = request.reproducibility,
    };
}

pub const adaptV2 = adaptV2NativeFresh;

pub fn resolveV2NativeFresh(
    allocator: Allocator,
    request: *const RequestV2,
    context: ResolveContext,
) (Allocator.Error || AdaptV2Error)!ResolveOutcome {
    const adapted = try adaptV2NativeFresh(request);
    return resolve(allocator, &adapted, context);
}

pub const Severity = enum {
    info,
    warning,
    @"error",
};

pub const DiagnosticPhase = enum {
    validation,
    resolution,
    preflight,
    execution,
    cleanup,
};

pub const DiagnosticCode = enum {
    unsupported_api_version,
    missing_target_architecture,
    missing_input_path,
    missing_rootfs_path,
    unsupported_input,
    invalid_output,
    invalid_storage,
    unsupported_storage,
    unsupported_output_format,
    invalid_partition_selector,
    incompatible_boot_policy,
    unsupported_generalization,
    invalid_customization,
    invalid_policy,
    unsafe_acknowledgement_required,
    unsupported_execution_backend,
    incompatible_architecture,
    invalid_workspace,
    path_conflict,
    invalid_reproducibility,
    invalid_plan,
    missing_capability,
    source_hash_failed,
    source_changed,
    execution_failed,
    commit_failed,
    cleanup_completed,
    cleanup_failed,
    runtime_warning,
};

pub const Cause = struct {
    error_name: []const u8,
};

pub const CommandDiagnostic = struct {
    argv: []const []const u8,
    exit_status: ?u8 = null,
};

pub const Diagnostic = struct {
    severity: Severity,
    phase: DiagnosticPhase,
    code: DiagnosticCode,
    configuration_path: []const u8,
    message: []const u8,
    cause: ?Cause = null,
    command: ?CommandDiagnostic = null,
    remediation: ?[]const u8 = null,
};

pub const DiagnosticSet = struct {
    items: []Diagnostic,
    arena: ?std.heap.ArenaAllocator = null,

    pub fn deinit(self: *DiagnosticSet, allocator: Allocator) void {
        if (self.arena) |*arena| {
            arena.deinit();
        } else {
            allocator.free(self.items);
        }
        self.* = undefined;
    }

    pub fn hasErrors(self: DiagnosticSet) bool {
        for (self.items) |diagnostic| {
            if (diagnostic.severity == .@"error") return true;
        }
        return false;
    }
};

pub fn validate(allocator: Allocator, request: *const Request) Allocator.Error!DiagnosticSet {
    var diagnostics = std.array_list.Managed(Diagnostic).init(allocator);
    errdefer diagnostics.deinit();

    if (request.api_version != current_api_version) {
        try diagnostics.append(validationError(
            .unsupported_api_version,
            "/api_version",
            "the request API version is not supported",
            "use the v3 request contract; v2 native-fresh requests must pass through adaptV2NativeFresh",
        ));
    }
    if (request.target_architecture == null) {
        try diagnostics.append(validationError(
            .missing_target_architecture,
            "/target_architecture",
            "target architecture must be specified explicitly",
            "set target_architecture to x86_64 or aarch64",
        ));
    }

    switch (request.input) {
        .iso_oci => |input| {
            if (input.iso_path.len == 0) {
                try diagnostics.append(validationError(.missing_input_path, "/input/iso_oci/iso_path", "ISO path must not be empty", null));
            }
            if (input.container_path.len == 0) {
                try diagnostics.append(validationError(.missing_input_path, "/input/iso_oci/container_path", "container path must not be empty", null));
            }
            if (input.rootfs_path_in_iso == null or input.rootfs_path_in_iso.?.len == 0) {
                try diagnostics.append(validationError(
                    .missing_rootfs_path,
                    "/input/iso_oci/rootfs_path_in_iso",
                    "rootfs_path_in_iso is required so the resolved plan contains no input-dependent path inference",
                    "set the exact SquashFS rootfs path from the ISO",
                ));
            }
        },
        .disk => |input| if (input.path.len == 0) {
            try diagnostics.append(validationError(
                .missing_input_path,
                "/input/disk/path",
                "disk input path must not be empty",
                null,
            ));
        } else for (input.dependencies, 0..) |dependency, index| {
            if (dependency.len == 0) {
                try diagnostics.append(validationError(
                    .missing_input_path,
                    "/input/disk/dependencies",
                    "disk dependency paths must not be empty",
                    null,
                ));
            }
            for (input.dependencies[0..index]) |previous| {
                if (std.mem.eql(u8, previous, dependency)) {
                    try diagnostics.append(validationError(
                        .invalid_policy,
                        "/input/disk/dependencies",
                        "disk dependency paths must be unique",
                        null,
                    ));
                }
            }
        },
    }

    if (request.output.path.len == 0) {
        try diagnostics.append(validationError(.invalid_output, "/output/path", "output path must not be empty", null));
    }
    if (request.output.format == .cosi) {
        try diagnostics.append(validationError(
            .unsupported_output_format,
            "/output/format",
            "COSI is not supported by the v3 native fresh or preserved-image executors",
            "select raw, vhd, vhdx, or qcow2",
        ));
    }

    const preserved_backend = switch (request.execution.backend) {
        .native_fresh => false,
        .native_edit, .rebuild, .unsafe_chroot, .vm => true,
    };
    if (!preserved_backend) {
        if (request.input != .iso_oci) {
            try diagnostics.append(validationError(
                .unsupported_input,
                "/input",
                "native_fresh requires an ISO+OCI input",
                "select input.iso_oci or a preserved-image backend",
            ));
        }
        if (request.storage != .fresh) {
            try diagnostics.append(validationError(
                .unsupported_storage,
                "/storage",
                "native_fresh requires fresh storage",
                "select storage.fresh or a preserved-image backend",
            ));
        }
        if (request.output.size_policy != .explicit) {
            try diagnostics.append(validationError(
                .invalid_output,
                "/output/size_policy",
                "native_fresh requires an explicit output size",
                "set size_policy to explicit",
            ));
        }
        if (request.existing_path_operations.len != 0) {
            try diagnostics.append(validationError(
                .invalid_customization,
                "/existing_path_operations",
                "existing-path operations require preserved storage",
                "select native_edit with a disk input and preserved storage",
            ));
        }
    } else {
        if (request.input != .disk) {
            try diagnostics.append(validationError(
                .unsupported_input,
                "/input",
                "the selected preserved-image backend requires a disk input",
                "select input.disk",
            ));
        }
        if (request.storage != .preserve) {
            try diagnostics.append(validationError(
                .unsupported_storage,
                "/storage",
                "the selected preserved-image backend requires preserved storage",
                "select storage.preserve with an explicit root partition",
            ));
        }
        if (request.output.size_policy != .preserve_source or request.output.size != 0) {
            try diagnostics.append(validationError(
                .invalid_output,
                "/output/size",
                "preserved-image output must retain the source virtual size",
                "set size to 0 and size_policy to preserve_source",
            ));
        }
    }

    switch (request.storage) {
        .fresh => |storage| if (request.output.size_policy == .explicit) {
            if (request.output.size % 512 != 0) {
                try diagnostics.append(validationError(.invalid_output, "/output/size", "output size must be a multiple of 512 bytes", null));
            }
            if (request.output.size > std.math.maxInt(u64) - mib) {
                try diagnostics.append(validationError(.invalid_output, "/output/size", "output size is too large to align safely", null));
            }
            const minimum_size = switch (storage.generation) {
                .gen1 => 2 * mib,
                .gen2 => if (storage.esp_size > std.math.maxInt(u64) - 2 * mib)
                    std.math.maxInt(u64)
                else
                    storage.esp_size + 2 * mib,
            };
            if (storage.generation == .gen2 and storage.esp_size > std.math.maxInt(u64) - 2 * mib) {
                try diagnostics.append(validationError(.invalid_storage, "/storage/fresh/esp_size", "ESP size is too large to plan safely", null));
            }
            if (request.output.size <= minimum_size) {
                try diagnostics.append(validationError(.invalid_storage, "/output/size", "output is too small for the selected partition layout", null));
            }
            if (storage.ext4_label.len > 16) {
                try diagnostics.append(validationError(.invalid_storage, "/storage/fresh/ext4_label", "ext4 label must be at most 16 bytes", null));
            }
            if (storage.generation == .gen1 and request.boot_security.boot_mode != .bls_only) {
                try diagnostics.append(validationError(
                    .incompatible_boot_policy,
                    "/boot_security/boot_mode",
                    "UKI modes require a Gen2 EFI System Partition",
                    "use bls_only for Gen1 or select Gen2 storage",
                ));
            }
            if (storage.generation == .gen1 and request.boot_security.verity) {
                try diagnostics.append(validationError(
                    .incompatible_boot_policy,
                    "/boot_security/verity",
                    "Gen1 verity cannot generate a final-hash-aware BIOS GRUB configuration",
                    "disable verity or select Gen2 storage",
                ));
            }
            if (storage.generation == .gen1 and request.target_architecture != null and request.target_architecture.? != .x86_64) {
                try diagnostics.append(validationError(
                    .incompatible_boot_policy,
                    "/target_architecture",
                    "the native Gen1 BIOS backend only supports x86_64 images",
                    "select x86_64 or use Gen2 storage for aarch64",
                ));
            }
            if (request.output.size % 512 == 0 and
                request.output.size <= std.math.maxInt(u64) - mib and
                (storage.generation == .gen1 or storage.esp_size <= std.math.maxInt(u64) - 2 * mib))
            {
                if (validateStorageGeometry(
                    if (request.output.format == .vhd) azure.alignSizeToMib(request.output.size) else request.output.size,
                    storage,
                    request.boot_security.verity,
                )) |diagnostic| {
                    try diagnostics.append(diagnostic);
                }
            }
        },
        .preserve => |storage| switch (storage.root_partition) {
            .gpt_index => |index| if (index == 0) {
                try diagnostics.append(validationError(
                    .invalid_partition_selector,
                    "/storage/preserve/root_partition/gpt_index",
                    "GPT partition selectors are one-based",
                    "select a GPT partition index of at least 1",
                ));
            },
            .mbr_index => |index| if (index == 0 or index > 4) {
                try diagnostics.append(validationError(
                    .invalid_partition_selector,
                    "/storage/preserve/root_partition/mbr_index",
                    "MBR partition selectors are one-based and limited to the four primary entries",
                    "select an MBR partition index from 1 through 4",
                ));
            },
        },
    }

    try validateOsCustomization(&diagnostics, request.os);
    try validateExistingPathOperations(&diagnostics, request.existing_path_operations);
    try validatePackagePolicy(&diagnostics, request.packages);
    try validateHooks(&diagnostics, request.hooks);
    try validateInitramfsPolicy(&diagnostics, request.initramfs);
    try validateSelinuxPolicy(&diagnostics, request.selinux);
    try validateCrossArchitecturePolicy(&diagnostics, request.cross_architecture);
    try validateVmPolicy(&diagnostics, request);
    if (request.packages.actions.len > std.math.maxInt(u16) - 32 or
        request.hooks.len > std.math.maxInt(u16) - 32 or
        request.packages.actions.len + request.hooks.len > std.math.maxInt(u16) - 32)
    {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/",
            "the request contains too many ordered package and hook operations",
            "use fewer than 65504 package actions and hooks",
        ));
    }
    try validateGeneralization(&diagnostics, request.generalization);
    if (request.execution.backend == .unsafe_chroot and !request.execution.acknowledge_unsafe) {
        try diagnostics.append(validationError(
            .unsafe_acknowledgement_required,
            "/execution/backend",
            "unsafe_chroot executes target code on the host and is not a sandbox",
            "set execution.acknowledge_unsafe only after accepting unsafe host-code execution",
        ));
    }
    if (request.hooks.len != 0) {
        if (request.execution.backend != .unsafe_chroot and request.execution.backend != .vm) {
            try diagnostics.append(validationError(
                .unsupported_execution_backend,
                "/execution/backend",
                "scripts require an unsafe-capable backend",
                "select unsafe_chroot or vm; unsafe_chroot is not a sandbox",
            ));
        }
        if (!request.execution.acknowledge_unsafe) {
            try diagnostics.append(validationError(
                .unsafe_acknowledgement_required,
                "/execution/acknowledge_unsafe",
                "scripts require explicit acknowledgement of unsafe code execution",
                "set acknowledge_unsafe only after reviewing every script",
            ));
        }
    }
    if (request.execution.workspace_path.len == 0) {
        try diagnostics.append(validationError(.invalid_workspace, "/execution/workspace_path", "workspace path must not be empty", null));
    }
    if (request.output.path.len != 0 and
        request.execution.workspace_path.len != 0 and
        std.fs.path.isAbsolute(request.output.path) == std.fs.path.isAbsolute(request.execution.workspace_path))
    {
        const output_path = try std.fs.path.resolve(allocator, &.{request.output.path});
        defer allocator.free(output_path);
        const workspace_path = try std.fs.path.resolve(allocator, &.{request.execution.workspace_path});
        defer allocator.free(workspace_path);
        const output_parent = std.fs.path.dirname(output_path) orelse ".";
        if (!std.mem.eql(u8, workspace_path, output_parent)) {
            try diagnostics.append(validationError(
                .path_conflict,
                "/execution/workspace_path",
                "the workspace must be the output directory so publication is atomic",
                "set workspace_path to the parent directory of output.path",
            ));
        }
    }
    if (request.output.path.len != 0) {
        const output_path = try std.fs.path.resolve(allocator, &.{request.output.path});
        defer allocator.free(output_path);
        switch (request.input) {
            .iso_oci => |input| {
                const iso_path = if (input.iso_path.len != 0) try std.fs.path.resolve(allocator, &.{input.iso_path}) else null;
                defer if (iso_path) |path| allocator.free(path);
                const container_path = if (input.container_path.len != 0) try std.fs.path.resolve(allocator, &.{input.container_path}) else null;
                defer if (container_path) |path| allocator.free(path);
                if ((iso_path != null and std.mem.eql(u8, output_path, iso_path.?)) or
                    (container_path != null and
                        (std.mem.eql(u8, output_path, container_path.?) or pathContains(container_path.?, output_path))))
                {
                    try diagnostics.append(validationError(
                        .path_conflict,
                        "/output/path",
                        "output path must not alias or be contained by a source path",
                        "choose an output directory outside the ISO and container inputs",
                    ));
                }
            },
            .disk => |input| {
                if (input.path.len != 0) {
                    const disk_path = try std.fs.path.resolve(allocator, &.{input.path});
                    defer allocator.free(disk_path);
                    if (std.mem.eql(u8, output_path, disk_path)) {
                        try diagnostics.append(validationError(
                            .path_conflict,
                            "/output/path",
                            "output path must not alias the preserved source disk",
                            "choose a distinct transactional output path",
                        ));
                    }
                }
                for (input.dependencies) |dependency| {
                    if (dependency.len == 0) continue;
                    const dependency_path = try std.fs.path.resolve(
                        allocator,
                        &.{dependency},
                    );
                    defer allocator.free(dependency_path);
                    if (std.mem.eql(u8, output_path, dependency_path)) {
                        try diagnostics.append(validationError(
                            .path_conflict,
                            "/output/path",
                            "output path must not alias a preserved disk dependency",
                            "choose a distinct transactional output path",
                        ));
                    }
                }
            },
        }
    }
    if (request.storage == .fresh and request.reproducibility.source_date_epoch > std.math.maxInt(u32)) {
        try diagnostics.append(validationError(
            .invalid_reproducibility,
            "/reproducibility/source_date_epoch",
            "source_date_epoch exceeds the ext4 timestamp range",
            "use a value no greater than 4294967295",
        ));
    } else if (request.reproducibility.source_date_epoch > std.math.maxInt(i64)) {
        try diagnostics.append(validationError(
            .invalid_reproducibility,
            "/reproducibility/source_date_epoch",
            "source_date_epoch exceeds the output metadata timestamp range",
            "use a value no greater than 9223372036854775807",
        ));
    }

    return .{ .items = try diagnostics.toOwnedSlice() };
}

fn validateExistingPathOperations(
    diagnostics: *std.array_list.Managed(Diagnostic),
    operations: []const ExistingPathOperation,
) Allocator.Error!void {
    for (operations) |operation| {
        const path = switch (operation) {
            .overwrite_file => |overwrite| overwrite.path,
            .remove_file => |path| path,
            .remove_tree => |path| path,
        };
        if (!validImagePath(path)) {
            try diagnostics.append(validationError(
                .invalid_customization,
                "/existing_path_operations/path",
                "existing-path operations require normalized absolute image paths",
                null,
            ));
        }
        if (operation == .overwrite_file) switch (operation.overwrite_file.source) {
            .bytes => {},
            .host_path => |source_path| if (source_path.len == 0) {
                try diagnostics.append(validationError(
                    .invalid_customization,
                    "/existing_path_operations/overwrite_file/source/host_path",
                    "edit source paths must not be empty",
                    null,
                ));
            },
        };
    }
}

fn validatePackagePolicy(
    diagnostics: *std.array_list.Managed(Diagnostic),
    policy: PackagePolicy,
) Allocator.Error!void {
    var needs_repository = false;
    for (policy.actions) |action| {
        const names: []const []const u8 = switch (action) {
            .install => |values| blk: {
                needs_repository = true;
                break :blk values;
            },
            .remove => |values| values,
            .update_all => blk: {
                needs_repository = true;
                break :blk &.{};
            },
            .update_selected => |values| blk: {
                needs_repository = true;
                break :blk values;
            },
        };
        for (names) |name| {
            if (name.len == 0 or std.mem.indexOfAny(u8, name, "\r\n\x00") != null) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/actions",
                    "package names must be non-empty single-line values",
                    null,
                ));
            }
        }
    }
    if (needs_repository and policy.repositories.len == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/packages/repositories",
            "install and update actions require explicit repositories",
            "declare repository URLs and trust sources; host repositories are never inherited",
        ));
    }
    for (policy.repositories, 0..) |repository, index| {
        if (!validConfigName(repository.id) or repository.urls.len == 0 or repository.trust.len == 0) {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/packages/repositories",
                "repositories require a safe id, at least one URL, and explicit trust material",
                null,
            ));
        }
        for (policy.repositories[0..index]) |previous| {
            if (std.mem.eql(u8, previous.id, repository.id)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/repositories/id",
                    "repository ids must be unique",
                    null,
                ));
            }
        }
        for (repository.urls) |url| {
            if (url.len == 0 or std.mem.indexOfAny(u8, url, "\r\n\x00") != null) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/repositories/urls",
                    "repository URLs must be non-empty single-line values",
                    null,
                ));
            }
        }
        for (repository.trust) |trust| switch (trust) {
            .inline_bytes => |bytes| if (bytes.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/packages/repositories/trust", "inline trust material must not be empty", null));
            },
            .host_path => |path| if (path.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/packages/repositories/trust", "trust source paths must not be empty", null));
            },
        };
    }
    switch (policy.lock) {
        .unlocked => {},
        .snapshot => |snapshot| if (snapshot.len == 0) {
            try diagnostics.append(validationError(.invalid_policy, "/packages/lock/snapshot", "snapshot identifiers must not be empty", null));
        },
        .exact => |locks| for (locks) |lock| {
            if (lock.name.len == 0 or lock.version.len == 0 or lock.repository_id.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/packages/lock/exact", "exact locks require package, version, and repository id", null));
            }
        },
    }
}

fn validateHooks(
    diagnostics: *std.array_list.Managed(Diagnostic),
    hooks: []const Hook,
) Allocator.Error!void {
    var previous_phase: ?HookPhase = null;
    for (hooks, 0..) |hook, index| {
        if (!validConfigName(hook.name)) {
            try diagnostics.append(validationError(.invalid_policy, "/hooks/name", "hook names must be safe non-empty values", null));
        }
        if (previous_phase) |phase| {
            if (@intFromEnum(hook.phase) < @intFromEnum(phase)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/hooks/phase",
                    "hooks must be declared in nondecreasing phase order",
                    "order hooks as after_packages, before_initramfs, before_seal, then finalize",
                ));
            }
        }
        previous_phase = hook.phase;
        for (hooks[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, hook.name)) {
                try diagnostics.append(validationError(.invalid_policy, "/hooks/name", "hook names must be unique", null));
            }
        }
        switch (hook.source) {
            .inline_script => |script| if (script.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/hooks/source", "inline scripts must not be empty", null));
            },
            .host_path => |path| if (path.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/hooks/source", "hook source paths must not be empty", null));
            },
        }
        for (hook.arguments) |argument| {
            if (std.mem.indexOfScalar(u8, argument, 0) != null) {
                try diagnostics.append(validationError(.invalid_policy, "/hooks/arguments", "hook arguments must not contain NUL", null));
            }
        }
    }
}

fn validateInitramfsPolicy(
    diagnostics: *std.array_list.Managed(Diagnostic),
    policy: InitramfsPolicy,
) Allocator.Error!void {
    switch (policy) {
        .unchanged => {},
        .regenerate => |regenerate| {
            if (regenerate.generator) |generator| {
                if (generator.len == 0 or std.mem.indexOfAny(u8, generator, "\r\n\x00") != null) {
                    try diagnostics.append(validationError(.invalid_policy, "/initramfs/regenerate/generator", "initramfs generators must be non-empty single-line values", null));
                }
            }
            for (regenerate.kernels) |kernel| {
                if (kernel.len == 0 or std.mem.indexOfAny(u8, kernel, "\r\n\x00") != null) {
                    try diagnostics.append(validationError(.invalid_policy, "/initramfs/regenerate/kernels", "kernel selectors must be non-empty single-line values", null));
                }
            }
        },
    }
}

fn validateSelinuxPolicy(
    diagnostics: *std.array_list.Managed(Diagnostic),
    policy: SelinuxPolicy,
) Allocator.Error!void {
    switch (policy) {
        .unchanged => {},
        .configure => |configure| if (configure.policy) |name| {
            if (!validConfigName(name)) {
                try diagnostics.append(validationError(.invalid_policy, "/selinux/configure/policy", "SELinux policy names must be safe non-empty values", null));
            }
        },
    }
}

fn validateCrossArchitecturePolicy(
    diagnostics: *std.array_list.Managed(Diagnostic),
    policy: CrossArchitecturePolicy,
) Allocator.Error!void {
    switch (policy) {
        .reject => {},
        .runner => |runner| if ((runner.kind == .qemu_user or runner.kind == .vm) and
            (runner.command == null or runner.command.?.len == 0))
        {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/cross_architecture/runner/command",
                "qemu_user and vm runners require an explicit command",
                null,
            ));
        },
    }
}

fn validateVmPolicy(
    diagnostics: *std.array_list.Managed(Diagnostic),
    request: *const Request,
) Allocator.Error!void {
    const policy = request.execution.vm orelse {
        if (request.execution.backend == .vm) {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/execution/vm",
                "the vm backend requires an explicit VM policy",
                "set execution.vm with at least an emulator_command",
            ));
        }
        return;
    };
    if (request.execution.backend != .vm) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm",
            "a VM policy is only meaningful to the vm backend",
            "select execution.backend = vm or remove execution.vm",
        ));
        return;
    }
    if (policy.emulator_command.len == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/emulator_command",
            "the vm backend requires an explicit emulator command",
            "set emulator_command to the qemu-system binary for the runner architecture",
        ));
    } else if (!std.fs.path.isAbsolute(policy.emulator_command)) {
        // Resolving a bare name against PATH here would let the recorded
        // emulator differ from the one that ran, so the caller must resolve it.
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/emulator_command",
            "the emulator command must be an absolute path",
            "resolve the qemu-system binary against PATH before building the request",
        ));
    }
    switch (policy.boot) {
        .direct_kernel => {},
        .firmware => |firmware| {
            // Firmware paths follow the same rule as the emulator: named
            // exactly, so provenance records the files that were actually used.
            if (firmware.code_path.len == 0 or
                !std.fs.path.isAbsolute(firmware.code_path))
            {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/execution/vm/boot/firmware/code_path",
                    "firmware boot requires an absolute firmware code path",
                    "name the firmware code file for the runner architecture",
                ));
            }
            if (firmware.vars_path.len == 0 or
                !std.fs.path.isAbsolute(firmware.vars_path))
            {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/execution/vm/boot/firmware/vars_path",
                    "firmware boot requires an absolute firmware variable store path",
                    "name the firmware variable template for the runner architecture",
                ));
            }
        },
    }
    if (policy.memory_mib < min_vm_memory_mib or policy.memory_mib > max_vm_memory_mib) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/memory_mib",
            "guest memory is outside the supported range",
            "select at least 512 MiB and at most 1 TiB",
        ));
    }
    if (policy.vcpus == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/vcpus",
            "the guest requires at least one virtual CPU",
            "select a vcpu count of at least 1",
        ));
    }
    if (policy.boot_timeout_seconds == 0 or
        policy.boot_timeout_seconds > max_vm_boot_timeout_seconds)
    {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/boot_timeout_seconds",
            "the guest boot timeout is outside the supported range",
            "select a timeout of at least 1 second and at most 86400 seconds",
        ));
    }
    if (policy.machine) |machine| if (machine.len == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/machine",
            "the machine override must not be empty",
            "remove the override or name a machine type",
        ));
    };
    if (policy.cpu) |cpu| if (cpu.len == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/vm/cpu",
            "the cpu override must not be empty",
            "remove the override or name a cpu model",
        ));
    };
    switch (policy.network) {
        .offline => if (request.packages.actions.len != 0 and
            request.packages.cache != .cache_only)
        {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/execution/vm/network",
                "online package actions cannot run in an offline guest",
                "attach declared_repositories networking or select a cache_only package policy",
            ));
        },
        .declared_repositories => if (request.packages.repositories.len == 0) {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/execution/vm/network",
                "guest networking was requested without any declared repository",
                "declare the repositories the guest may reach or select offline networking",
            ));
        },
    }
}

fn validateOsCustomization(
    diagnostics: *std.array_list.Managed(Diagnostic),
    customization: OsCustomization,
) Allocator.Error!void {
    for (customization.filesystem) |operation| {
        const path = switch (operation) {
            .put_file => |value| value.path,
            .put_directory => |value| value.path,
            .put_symlink => |value| value.path,
            .remove => |value| value,
            .set_metadata => |value| value.path,
        };
        if (!validImagePath(path)) {
            try diagnostics.append(validationError(
                .invalid_customization,
                "/os/filesystem/path",
                "filesystem customization paths must be normalized absolute image paths",
                "use a path such as /etc/example without empty, dot, or dot-dot components",
            ));
        }
        switch (operation) {
            .put_file => |file| {
                if (file.source == .host_path and file.source.host_path.len == 0) {
                    try diagnostics.append(validationError(
                        .invalid_customization,
                        "/os/filesystem/put_file/source/host_path",
                        "host file source paths must not be empty",
                        null,
                    ));
                }
                try validateMetadata(diagnostics, file.metadata, "/os/filesystem/put_file/metadata");
            },
            .put_directory => |directory| try validateMetadata(
                diagnostics,
                directory.metadata,
                "/os/filesystem/put_directory/metadata",
            ),
            .put_symlink => |link| {
                if (link.target.len == 0 or std.mem.indexOfScalar(u8, link.target, 0) != null) {
                    try diagnostics.append(validationError(
                        .invalid_customization,
                        "/os/filesystem/put_symlink/target",
                        "symlink targets must not be empty or contain NUL",
                        null,
                    ));
                }
                try validateMetadata(diagnostics, link.metadata, "/os/filesystem/put_symlink/metadata");
            },
            .set_metadata => |change| {
                if (change.mode) |mode| {
                    if (mode & ~@as(u16, 0o7777) != 0) {
                        try diagnostics.append(validationError(
                            .invalid_customization,
                            "/os/filesystem/set_metadata/mode",
                            "file modes may contain only permission and special bits",
                            null,
                        ));
                    }
                }
                if (change.xattrs) |xattrs| {
                    try validateXattrs(diagnostics, xattrs, "/os/filesystem/set_metadata/xattrs");
                }
            },
            .remove => {},
        }
    }

    if (customization.hostname) |hostname| {
        if (!validHostname(hostname)) {
            try diagnostics.append(validationError(
                .invalid_customization,
                "/os/hostname",
                "hostname must be a valid non-empty DNS-style name of at most 64 bytes",
                null,
            ));
        }
    }
    for (customization.groups) |group| {
        if (!validAccountName(group.name)) {
            try diagnostics.append(validationError(.invalid_customization, "/os/groups/name", "group names must use portable account-name characters", null));
        }
        for (group.members) |member| {
            if (!validAccountName(member)) {
                try diagnostics.append(validationError(.invalid_customization, "/os/groups/members", "group members must use portable account-name characters", null));
            }
        }
    }
    for (customization.users) |user| {
        if (!validAccountName(user.name)) {
            try diagnostics.append(validationError(.invalid_customization, "/os/users/name", "user names must use portable account-name characters", null));
        }
        if (user.primary_group) |name| {
            if (!validAccountName(name)) {
                try diagnostics.append(validationError(.invalid_customization, "/os/users/primary_group", "primary group names must use portable account-name characters", null));
            }
        }
        if (!validImagePath(user.home orelse "/home/default") or
            user.shell.len == 0 or user.shell[0] != '/' or containsRecordDelimiter(user.shell))
        {
            try diagnostics.append(validationError(.invalid_customization, "/os/users", "user home and shell values must be safe absolute image paths", null));
        }
        switch (user.password) {
            .locked => {},
            .prehashed => |hash| {
                if (!validPasswordHash(hash)) {
                    try diagnostics.append(validationError(
                        .invalid_customization,
                        "/os/users/password/prehashed",
                        "pre-hashed passwords must use a crypt-style $... value and contain no record delimiters",
                        "provide a pre-hashed value or use the locked policy; plaintext passwords are not accepted",
                    ));
                }
            },
        }
        for (user.secondary_groups) |name| {
            if (!validAccountName(name)) {
                try diagnostics.append(validationError(.invalid_customization, "/os/users/secondary_groups", "secondary group names must use portable account-name characters", null));
            }
        }
        for (user.ssh_authorized_keys) |key| {
            if (key.len == 0 or std.mem.indexOfAny(u8, key, "\r\n\x00") != null) {
                try diagnostics.append(validationError(.invalid_customization, "/os/users/ssh_authorized_keys", "SSH authorized keys must each occupy one non-empty line", null));
            }
        }
    }
    for (customization.services) |service| {
        if (!validConfigName(service.name)) {
            try diagnostics.append(validationError(.invalid_customization, "/os/services/name", "service names must be safe systemd unit basenames", null));
        }
    }
    for (customization.kernel_modules) |module| {
        if (!validConfigName(module.name) or (module.load and module.disabled)) {
            try diagnostics.append(validationError(.invalid_customization, "/os/kernel_modules", "kernel module names must be safe and cannot be loaded and disabled simultaneously", null));
        }
        if (module.options) |options| {
            if (std.mem.indexOfAny(u8, options, "\r\n\x00") != null) {
                try diagnostics.append(validationError(.invalid_customization, "/os/kernel_modules/options", "kernel module options must occupy one line", null));
            }
        }
    }
}

fn validateGeneralization(
    diagnostics: *std.array_list.Managed(Diagnostic),
    policy: GeneralizationPolicy,
) Allocator.Error!void {
    switch (policy) {
        .none => {},
        .azure => |options| for (options.remove_users) |username| {
            if (!validAccountName(username)) {
                try diagnostics.append(validationError(
                    .invalid_customization,
                    "/generalization/azure/remove_users",
                    "generalization user names must use portable account-name characters",
                    null,
                ));
            }
        },
    }
}

fn validateMetadata(
    diagnostics: *std.array_list.Managed(Diagnostic),
    metadata: Metadata,
    path: []const u8,
) Allocator.Error!void {
    if (metadata.mode & ~@as(u16, 0o7777) != 0) {
        try diagnostics.append(validationError(.invalid_customization, path, "file modes may contain only permission and special bits", null));
    }
    try validateXattrs(diagnostics, metadata.xattrs, path);
}

fn validateXattrs(
    diagnostics: *std.array_list.Managed(Diagnostic),
    xattrs: []const ext4.Xattr,
    path: []const u8,
) Allocator.Error!void {
    for (xattrs, 0..) |xattr, index| {
        if (xattr.name.len == 0 or std.mem.indexOfScalar(u8, xattr.name, 0) != null) {
            try diagnostics.append(validationError(.invalid_customization, path, "xattr names must not be empty or contain NUL", null));
        }
        for (xattrs[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, xattr.name)) {
                try diagnostics.append(validationError(.invalid_customization, path, "xattr names must be unique per operation", null));
            }
        }
    }
}

fn validImagePath(path: []const u8) bool {
    if (path.len < 2 or path[0] != '/' or path[1] == '/' or path[path.len - 1] == '/') return false;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or component.len > 255 or
            std.mem.eql(u8, component, ".") or std.mem.eql(u8, component, "..") or
            std.mem.indexOfScalar(u8, component, 0) != null)
        {
            return false;
        }
    }
    return true;
}

fn validHostname(hostname: []const u8) bool {
    if (hostname.len == 0 or hostname.len > 64 or hostname[0] == '.' or hostname[hostname.len - 1] == '.') return false;
    var labels = std.mem.splitScalar(u8, hostname, '.');
    while (labels.next()) |label| {
        if (label.len == 0 or label.len > 63 or label[0] == '-' or label[label.len - 1] == '-') return false;
        for (label) |byte| if (!std.ascii.isAlphanumeric(byte) and byte != '-') return false;
    }
    return true;
}

fn validAccountName(name: []const u8) bool {
    if (name.len == 0 or name.len > 32) return false;
    for (name, 0..) |byte, index| {
        if (std.ascii.isLower(byte) or byte == '_' or (index != 0 and (std.ascii.isDigit(byte) or byte == '-'))) continue;
        return false;
    }
    return true;
}

fn validConfigName(name: []const u8) bool {
    if (name.len == 0 or name.len > 255 or name[0] == '.' or std.mem.indexOfAny(u8, name, "/\r\n\x00") != null) return false;
    return true;
}

fn containsRecordDelimiter(value: []const u8) bool {
    return std.mem.indexOfAny(u8, value, ":\r\n\x00") != null;
}

fn validPasswordHash(hash: []const u8) bool {
    const value = if (std.mem.startsWith(u8, hash, "!")) hash[1..] else hash;
    return value.len >= 3 and value[0] == '$' and std.mem.indexOfScalarPos(u8, value, 1, '$') != null and
        !containsRecordDelimiter(value);
}

fn pathContains(parent: []const u8, child: []const u8) bool {
    return child.len > parent.len and
        std.mem.startsWith(u8, child, parent) and
        (std.fs.path.isSep(parent[parent.len - 1]) or std.fs.path.isSep(child[parent.len]));
}

fn validateStorageGeometry(
    disk_size: u64,
    storage: FreshStorage,
    verity_enabled: bool,
) ?Diagnostic {
    var root_length: u64 = undefined;
    switch (storage.generation) {
        .gen2 => {
            const first_usable_lba: u64 = 2 + gpt.partition_array_sectors;
            const backup_reserved_sectors: u64 = 1 + gpt.partition_array_sectors;
            const total_sectors = disk_size / gpt.sector_size;
            if (total_sectors <= first_usable_lba + backup_reserved_sectors) return storageGeometryError(
                "/output/size",
                "the requested Gen2 disk is too small for GPT metadata",
                error.DiskTooSmall,
                "increase output.size",
            );
            const first_partition_offset = azure.alignSizeToMib(first_usable_lba * gpt.sector_size);
            const usable_end_offset = disk_size - backup_reserved_sectors * gpt.sector_size;
            if (first_partition_offset >= usable_end_offset) return storageGeometryError(
                "/output/size",
                "the requested Gen2 disk has no aligned partition space",
                error.DiskTooSmall,
                "increase output.size",
            );
            const usable_aligned_bytes = (usable_end_offset - first_partition_offset) / mib * mib;
            const esp_length = azure.alignSizeToMib(storage.esp_size);
            if (esp_length >= usable_aligned_bytes) return storageGeometryError(
                "/storage/fresh/esp_size",
                "the requested ESP leaves no aligned root partition",
                error.OverAllocated,
                "increase the disk or reduce the ESP size",
            );

            fat32.validateFormatOptions(.{
                .partition_offset = first_partition_offset,
                .partition_len = esp_length,
            }) catch |err| return storageGeometryError(
                "/storage/fresh/esp_size",
                "the requested ESP cannot be formatted as FAT32",
                err,
                "use an ESP size supported by the native FAT32 backend",
            );
            root_length = usable_aligned_bytes - esp_length;
        },
        .gen1 => {
            const root_offset = mib;
            if (disk_size <= root_offset + mib) return storageGeometryError(
                "/output/size",
                "the requested Gen1 disk is too small for its BIOS boot gap and root partition",
                error.DiskTooSmall,
                "increase output.size",
            );
            root_length = (disk_size - root_offset) / mib * mib;
            if (root_length / gpt.sector_size > std.math.maxInt(u32)) return storageGeometryError(
                "/output/size",
                "the requested Gen1 root partition exceeds the MBR sector-count limit",
                error.PartitionTooLargeForMbr,
                "use a disk no larger than the MBR backend supports or select Gen2",
            );
        },
    }

    const max_ext4_length = @as(u64, std.math.maxInt(u32)) * ext4.default_block_size;
    if (verity_enabled) {
        const max_hash_tree_length = verity.hashTreeSizeBytes(
            max_ext4_length,
            ext4.default_block_size,
            ext4.default_block_size,
        ) catch unreachable;
        if (root_length > max_ext4_length + max_hash_tree_length) return storageGeometryError(
            "/output/size",
            "the requested verity data partition exceeds the native ext4 geometry limits",
            error.FilesystemTooLarge,
            "reduce output.size or select a backend that supports larger filesystems",
        );
        const verity_layout = verity.splitPartition(root_length, ext4.default_block_size, ext4.default_block_size) catch |err|
            return storageGeometryError(
                "/boot_security/verity",
                "the root partition is too small or misaligned for dm-verity",
                err,
                "increase output.size or disable verity",
            );
        root_length = verity_layout.data_size;
    }
    if (root_length == 0 or
        root_length % ext4.default_block_size != 0 or
        root_length > max_ext4_length)
    {
        return storageGeometryError(
            "/output/size",
            "the requested root partition exceeds the native ext4 geometry limits",
            error.FilesystemTooLarge,
            "reduce output.size or select a backend that supports larger filesystems",
        );
    }
    return null;
}

fn storageGeometryError(
    path: []const u8,
    message: []const u8,
    cause: anyerror,
    remediation: []const u8,
) Diagnostic {
    return .{
        .severity = .@"error",
        .phase = .validation,
        .code = .invalid_storage,
        .configuration_path = path,
        .message = message,
        .cause = .{ .error_name = @errorName(cause) },
        .remediation = remediation,
    };
}

fn validationError(
    code: DiagnosticCode,
    path: []const u8,
    message: []const u8,
    remediation: ?[]const u8,
) Diagnostic {
    return .{
        .severity = .@"error",
        .phase = .validation,
        .code = code,
        .configuration_path = path,
        .message = message,
        .remediation = remediation,
    };
}

pub const ResolveContext = struct {
    host_architecture: Architecture,
    base_path: []const u8 = ".",
    firmware_architecture: ?Architecture = null,
    repository_architecture: ?Architecture = null,
    runner_architecture: ?Architecture = null,
};

pub const ArchitectureSet = struct {
    host: Architecture,
    image: Architecture,
    firmware: Architecture,
    repository: Architecture,
    runner: Architecture,
};

pub const Phase = enum {
    prepare,
    filesystem_changes,
    generalization_cleanup,
    packages,
    after_packages,
    before_initramfs,
    initramfs,
    before_seal,
    selinux,
    bootloader_prepare,
    filesystem_finalize,
    verity_seal,
    bootloader_install,
    uki,
    finalize,
    filesystem_close,
    output_conversion,
};

pub const Action = enum {
    load_sources,
    apply_filesystem_changes,
    generalize_and_cleanup,
    prepare_initramfs,
    prepare_boot_configuration,
    populate_filesystem,
    seal_verity,
    install_bootloader,
    generate_uki,
    check_and_close_filesystems,
    convert_output,
    load_preserved_source,
    extract_preserved_root,
    edit_existing_paths,
    populate_preserved_root,
    publish_standalone_output,
    execute_package_action,
    execute_hook,
    regenerate_initramfs,
    apply_selinux_policy,
    execute_unsafe_chroot,
    execute_vm,
};

pub const Operation = struct {
    id: u16,
    phase: Phase,
    depends_on: []const u16,
    action: Action,
};

pub const CapabilityKind = enum {
    read_iso,
    read_container,
    read_customization_file,
    read_disk,
    read_disk_dependency,
    disk_dependencies,
    read_edit_source,
    read_hook_source,
    read_trust_source,
    write_workspace_parent,
    write_output_parent,
    output_absent,
    transaction_absent,
    path_isolation,
    native_fresh,
    native_edit,
    partition_edit,
    standalone_output,
    rebuild,
    unsafe_chroot,
    vm,
    package_management,
    repository_access,
    repository_trust,
    package_cache,
    package_lock,
    script_execution,
    guest_execution,
    initramfs_regeneration,
    selinux_policy,
    selinux_relabel,
    cross_architecture_runner,
    arbitrary_filesystem_mutation,
    boot_policy_mutation,
    generalization,
    atomic_commit,
};

pub const CapabilityRequirement = struct {
    kind: CapabilityKind,
    path: []const u8,
    related_path: []const u8 = "",
    reason: []const u8,
};

pub const GeneratedIdentifiers = struct {
    disk_guid: Guid,
    esp_partition_guid: Guid,
    root_partition_guid: Guid,
    root_filesystem_uuid: Uuid,
    mbr_disk_signature: u32,
    verity_salt: Digest,
    output_unique_id: Uuid,
    vhdx_header_sequence_base: u64,
    vhdx_file_write_guid: Guid,
    vhdx_data_write_guid: Guid,
    vhdx_page83_guid: Guid,
    vhdx_write_guid_seed: Seed,
    transaction_id: Uuid,
};

pub const OutputIdentifiers = struct {
    output_unique_id: Uuid,
    vhdx_header_sequence_base: u64,
    vhdx_file_write_guid: Guid,
    vhdx_data_write_guid: Guid,
    vhdx_page83_guid: Guid,
    vhdx_write_guid_seed: Seed,
};

pub const ResolvedIsoOciInput = struct {
    iso_path: []const u8,
    container_path: []const u8,
    rootfs_path_in_iso: []const u8,
};

pub const ResolvedDiskInput = struct {
    path: []const u8,
    dependencies: []const []const u8,
};

pub const ResolvedInput = union(enum) {
    iso_oci: ResolvedIsoOciInput,
    disk: ResolvedDiskInput,
};

pub const ResolvedOutput = struct {
    path: []const u8,
    format: OutputFormat,
    requested_size: u64,
    disk_size: u64,
    size_policy: OutputSizePolicy,
};

pub const ResolvedFreshStorage = struct {
    generation: azure.Generation,
    esp_size: u64,
    ext4_label: []const u8,
    skip_iso_rootfs: bool,
};

pub const ResolvedPreservedStorage = struct {
    root_partition: PartitionSelector,
};

pub const ResolvedStorage = union(enum) {
    fresh: ResolvedFreshStorage,
    preserve: ResolvedPreservedStorage,
};

pub const ResolvedPlanData = struct {
    schema_version: u32 = plan_schema_version,
    request_api_version: u32,
    architectures: ArchitectureSet,
    input: ResolvedInput,
    output: ResolvedOutput,
    storage: ResolvedStorage,
    os: OsCustomization,
    existing_path_operations: []const ExistingPathOperation,
    packages: PackagePolicy,
    hooks: []const Hook,
    initramfs: InitramfsPolicy,
    selinux: SelinuxPolicy,
    cross_architecture: CrossArchitecturePolicy,
    boot_security: BootSecurityPolicy,
    generalization: GeneralizationPolicy,
    execution: ExecutionPolicy,
    reproducibility: Reproducibility,
    transaction_path: []const u8,
    staging_output_path: []const u8,
    transaction_id: Uuid,
    output_identifiers: OutputIdentifiers,
    generated: ?GeneratedIdentifiers,
    operations: []const Operation,
    required_capabilities: []const CapabilityRequirement,
    plan_hash: Digest,
};

pub const ResolvedPlan = struct {
    arena: std.heap.ArenaAllocator,
    data: *const ResolvedPlanData,

    pub fn deinit(self: *ResolvedPlan) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn view(self: *const ResolvedPlan) *const ResolvedPlanData {
        return self.data;
    }
};

pub const ResolveOutcome = struct {
    diagnostics: DiagnosticSet,
    plan: ?ResolvedPlan,

    pub fn deinit(self: *ResolveOutcome, allocator: Allocator) void {
        self.diagnostics.deinit(allocator);
        if (self.plan) |*plan| plan.deinit();
        self.* = undefined;
    }
};

pub fn resolve(
    allocator: Allocator,
    request: *const Request,
    context: ResolveContext,
) Allocator.Error!ResolveOutcome {
    const diagnostics = try validate(allocator, request);
    if (diagnostics.hasErrors()) return .{ .diagnostics = diagnostics, .plan = null };

    const target_architecture = request.target_architecture.?;
    var resolution_diagnostics = std.array_list.Managed(Diagnostic).init(allocator);
    defer resolution_diagnostics.deinit();
    if (context.firmware_architecture) |architecture| {
        if (request.execution.backend == .native_fresh and architecture != target_architecture) {
            try resolution_diagnostics.append(.{
                .severity = .@"error",
                .phase = .resolution,
                .code = .incompatible_architecture,
                .configuration_path = "/architectures/firmware",
                .message = "the native backend uses image-architecture firmware assets",
                .remediation = "set firmware_architecture to the target image architecture",
            });
        }
    }
    if (context.repository_architecture) |architecture| {
        if ((request.execution.backend == .native_fresh or request.packages.actions.len != 0) and
            architecture != target_architecture)
        {
            try resolution_diagnostics.append(.{
                .severity = .@"error",
                .phase = .resolution,
                .code = .incompatible_architecture,
                .configuration_path = "/architectures/repository",
                .message = "repository content must match the target image architecture",
                .remediation = "set repository_architecture to the target image architecture",
            });
        }
    }

    const needs_guest_execution = requiresGuestExecution(request);
    var resolved_runner_architecture = context.runner_architecture orelse context.host_architecture;
    if (needs_guest_execution and target_architecture != context.host_architecture) {
        switch (request.cross_architecture) {
            .reject => try resolution_diagnostics.append(.{
                .severity = .@"error",
                .phase = .resolution,
                .code = .incompatible_architecture,
                .configuration_path = "/cross_architecture",
                .message = "cross-architecture guest execution requires an explicit compatible runner policy",
                .remediation = "configure cross_architecture.runner for the target architecture",
            }),
            .runner => |runner| {
                if (runner.guest_architecture != target_architecture) {
                    try resolution_diagnostics.append(.{
                        .severity = .@"error",
                        .phase = .resolution,
                        .code = .incompatible_architecture,
                        .configuration_path = "/cross_architecture/runner/guest_architecture",
                        .message = "the configured runner does not target the image architecture",
                        .remediation = "set guest_architecture to the target architecture",
                    });
                }
                if ((request.execution.backend == .vm and runner.kind != .vm) or
                    (request.execution.backend == .unsafe_chroot and runner.kind == .vm))
                {
                    try resolution_diagnostics.append(.{
                        .severity = .@"error",
                        .phase = .resolution,
                        .code = .incompatible_architecture,
                        .configuration_path = "/cross_architecture/runner/kind",
                        .message = "the configured runner kind is incompatible with the selected execution backend",
                        .remediation = if (request.execution.backend == .vm)
                            "select a vm runner for the VM backend"
                        else
                            "select qemu_user or binfmt_misc for unsafe_chroot",
                    });
                }
                resolved_runner_architecture = runner.guest_architecture;
            },
        }
    } else if (context.runner_architecture) |architecture| {
        if (!needs_guest_execution and architecture != context.host_architecture) {
            try resolution_diagnostics.append(.{
                .severity = .@"error",
                .phase = .resolution,
                .code = .incompatible_architecture,
                .configuration_path = "/architectures/runner",
                .message = "a request without guest execution uses the host architecture",
                .remediation = "set runner_architecture to the host architecture",
            });
        }
    }

    if (request.execution.vm) |vm| {
        const native_runner = resolved_runner_architecture == context.host_architecture;
        switch (vm.acceleration) {
            .hardware => if (!native_runner) {
                try resolution_diagnostics.append(.{
                    .severity = .@"error",
                    .phase = .resolution,
                    .code = .incompatible_architecture,
                    .configuration_path = "/execution/vm/acceleration",
                    .message = "hardware acceleration cannot emulate a foreign runner architecture",
                    .remediation = "select software acceleration for a cross-architecture run",
                });
            },
            .software => if (native_runner and !vm.acknowledge_software_emulation) {
                try resolution_diagnostics.append(.{
                    .severity = .@"error",
                    .phase = .resolution,
                    .code = .invalid_policy,
                    .configuration_path = "/execution/vm/acceleration",
                    .message = "software emulation was selected for a native runner architecture",
                    .remediation = "select hardware acceleration or set acknowledge_software_emulation",
                });
            },
        }
    }

    const checked_output_path = try std.fs.path.resolve(allocator, &.{ context.base_path, request.output.path });
    defer allocator.free(checked_output_path);
    const checked_workspace_path = try std.fs.path.resolve(allocator, &.{ context.base_path, request.execution.workspace_path });
    defer allocator.free(checked_workspace_path);

    const checked_output_parent = std.fs.path.dirname(checked_output_path) orelse ".";
    if (!std.mem.eql(u8, checked_workspace_path, checked_output_parent)) {
        try resolution_diagnostics.append(.{
            .severity = .@"error",
            .phase = .resolution,
            .code = .path_conflict,
            .configuration_path = "/execution/workspace_path",
            .message = "the resolved workspace must be the output directory so publication is atomic",
            .remediation = "resolve workspace_path to the parent directory of output.path",
        });
    }

    switch (request.input) {
        .iso_oci => |input| {
            const checked_iso_path = try std.fs.path.resolve(allocator, &.{ context.base_path, input.iso_path });
            defer allocator.free(checked_iso_path);
            const checked_container_path = try std.fs.path.resolve(allocator, &.{ context.base_path, input.container_path });
            defer allocator.free(checked_container_path);
            if (std.mem.eql(u8, checked_output_path, checked_iso_path) or
                std.mem.eql(u8, checked_output_path, checked_container_path) or
                pathContains(checked_container_path, checked_output_path))
            {
                try resolution_diagnostics.append(.{
                    .severity = .@"error",
                    .phase = .resolution,
                    .code = .path_conflict,
                    .configuration_path = "/output/path",
                    .message = "the resolved output path must not alias or be contained by a source path",
                    .remediation = "resolve the output outside the ISO and container inputs",
                });
            }
        },
        .disk => |input| {
            const checked_disk_path = try std.fs.path.resolve(allocator, &.{ context.base_path, input.path });
            defer allocator.free(checked_disk_path);
            if (std.mem.eql(u8, checked_output_path, checked_disk_path)) {
                try resolution_diagnostics.append(.{
                    .severity = .@"error",
                    .phase = .resolution,
                    .code = .path_conflict,
                    .configuration_path = "/output/path",
                    .message = "the resolved output must not alias the preserved source disk",
                    .remediation = "resolve the output to a distinct path",
                });
            }
            for (input.dependencies) |dependency| {
                try checkResolvedSourceIsolation(
                    allocator,
                    &resolution_diagnostics,
                    context.base_path,
                    checked_output_path,
                    dependency,
                    "/input/disk/dependencies",
                );
            }
        },
    }

    for (request.os.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .inline_bytes => {},
            .host_path => |source_path| {
                try checkResolvedSourceIsolation(
                    allocator,
                    &resolution_diagnostics,
                    context.base_path,
                    checked_output_path,
                    source_path,
                    "/os/filesystem/put_file/source/host_path",
                );
            },
        },
        else => {},
    };
    for (request.existing_path_operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| switch (overwrite.source) {
            .bytes => {},
            .host_path => |source_path| try checkResolvedSourceIsolation(
                allocator,
                &resolution_diagnostics,
                context.base_path,
                checked_output_path,
                source_path,
                "/existing_path_operations/overwrite_file/source/host_path",
            ),
        },
        .remove_file, .remove_tree => {},
    };
    for (request.hooks) |hook| switch (hook.source) {
        .inline_script => {},
        .host_path => |source_path| try checkResolvedSourceIsolation(
            allocator,
            &resolution_diagnostics,
            context.base_path,
            checked_output_path,
            source_path,
            "/hooks/source/host_path",
        ),
    };
    for (request.packages.repositories) |repository| for (repository.trust) |trust| switch (trust) {
        .inline_bytes => {},
        .host_path => |source_path| try checkResolvedSourceIsolation(
            allocator,
            &resolution_diagnostics,
            context.base_path,
            checked_output_path,
            source_path,
            "/packages/repositories/trust/host_path",
        ),
    };
    if (resolution_diagnostics.items.len != 0) {
        allocator.free(diagnostics.items);
        return .{
            .diagnostics = .{ .items = try resolution_diagnostics.toOwnedSlice() },
            .plan = null,
        };
    }

    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const plan_allocator = arena.allocator();

    const resolved_output_path = try std.fs.path.resolve(plan_allocator, &.{ context.base_path, request.output.path });
    const resolved_workspace_path = try std.fs.path.resolve(plan_allocator, &.{ context.base_path, request.execution.workspace_path });

    var derived = deriveIdentifiers(request.reproducibility.seed);
    const transaction_id = deriveTransactionId(request.reproducibility.seed, resolved_output_path);
    derived.transaction_id = transaction_id;
    const transaction_hex = std.fmt.bytesToHex(transaction_id.bytes, .lower);
    const transaction_name = try std.fmt.allocPrint(plan_allocator, ".zvmi-{s}", .{transaction_hex});
    const transaction_path = try std.fs.path.join(plan_allocator, &.{ resolved_workspace_path, transaction_name });
    const staging_output_path = try std.fs.path.join(plan_allocator, &.{ transaction_path, "output.img" });

    const resolved_execution = ExecutionPolicy{
        .workspace_path = resolved_workspace_path,
        .backend = request.execution.backend,
        .overwrite = request.execution.overwrite,
        .acknowledge_unsafe = request.execution.acknowledge_unsafe,
        .vm = try dupeVmPolicy(plan_allocator, request.execution.vm),
    };
    const resolved_input: ResolvedInput = switch (request.input) {
        .iso_oci => |input| .{ .iso_oci = .{
            .iso_path = try std.fs.path.resolve(plan_allocator, &.{ context.base_path, input.iso_path }),
            .container_path = try std.fs.path.resolve(plan_allocator, &.{ context.base_path, input.container_path }),
            .rootfs_path_in_iso = try plan_allocator.dupe(u8, input.rootfs_path_in_iso.?),
        } },
        .disk => |input| .{ .disk = .{
            .path = try std.fs.path.resolve(plan_allocator, &.{ context.base_path, input.path }),
            .dependencies = try resolvePaths(
                plan_allocator,
                context.base_path,
                input.dependencies,
            ),
        } },
    };
    const disk_size = switch (request.storage) {
        .fresh => if (request.output.format == .vhd)
            azure.alignSizeToMib(request.output.size)
        else
            request.output.size,
        .preserve => 0,
    };
    const resolved_output = ResolvedOutput{
        .path = resolved_output_path,
        .format = request.output.format,
        .requested_size = request.output.size,
        .disk_size = disk_size,
        .size_policy = request.output.size_policy,
    };
    const resolved_storage: ResolvedStorage = switch (request.storage) {
        .fresh => |storage| .{ .fresh = .{
            .generation = storage.generation,
            .esp_size = storage.esp_size,
            .ext4_label = try plan_allocator.dupe(u8, storage.ext4_label),
            .skip_iso_rootfs = storage.skip_iso_rootfs,
        } },
        .preserve => |storage| .{ .preserve = .{
            .root_partition = storage.root_partition,
        } },
    };
    const resolved_os = try dupeOsCustomization(plan_allocator, request.os, context.base_path);
    const resolved_existing_operations = try dupeExistingPathOperations(
        plan_allocator,
        request.existing_path_operations,
        context.base_path,
    );
    const resolved_packages = try dupePackagePolicy(plan_allocator, request.packages, context.base_path);
    const resolved_hooks = try dupeHooks(plan_allocator, request.hooks, context.base_path);
    const resolved_initramfs = try dupeInitramfsPolicy(plan_allocator, request.initramfs);
    const resolved_selinux = try dupeSelinuxPolicy(plan_allocator, request.selinux);
    const resolved_cross_architecture = try dupeCrossArchitecturePolicy(plan_allocator, request.cross_architecture);
    const resolved_generalization = try dupeGeneralization(plan_allocator, request.generalization);
    const resolved_boot = try dupeBootPolicy(plan_allocator, request.boot_security);
    const operations = try buildOperations(
        plan_allocator,
        resolved_execution.backend,
        resolved_boot,
        resolved_storage,
        resolved_packages,
        resolved_hooks,
        resolved_initramfs,
        resolved_selinux,
    );
    const capabilities = try buildCapabilities(
        plan_allocator,
        resolved_input,
        resolved_output,
        resolved_storage,
        resolved_execution,
        transaction_path,
        resolved_os,
        resolved_existing_operations,
        resolved_packages,
        resolved_hooks,
        resolved_initramfs,
        resolved_selinux,
        resolved_generalization,
        resolved_boot,
        resolved_cross_architecture,
        target_architecture,
        context.host_architecture,
    );

    var data = ResolvedPlanData{
        .request_api_version = request.api_version,
        .architectures = .{
            .host = context.host_architecture,
            .image = target_architecture,
            .firmware = context.firmware_architecture orelse target_architecture,
            .repository = context.repository_architecture orelse target_architecture,
            .runner = resolved_runner_architecture,
        },
        .input = resolved_input,
        .output = resolved_output,
        .storage = resolved_storage,
        .os = resolved_os,
        .existing_path_operations = resolved_existing_operations,
        .packages = resolved_packages,
        .hooks = resolved_hooks,
        .initramfs = resolved_initramfs,
        .selinux = resolved_selinux,
        .cross_architecture = resolved_cross_architecture,
        .boot_security = resolved_boot,
        .generalization = resolved_generalization,
        .execution = resolved_execution,
        .reproducibility = request.reproducibility,
        .transaction_path = transaction_path,
        .staging_output_path = staging_output_path,
        .transaction_id = transaction_id,
        .output_identifiers = outputIdentifiers(derived),
        .generated = if (request.execution.backend == .native_fresh) derived else null,
        .operations = operations,
        .required_capabilities = capabilities,
        .plan_hash = .{ .bytes = [_]u8{0} ** 32 },
    };
    data.plan_hash = hashPlan(data);

    const data_ptr = try plan_allocator.create(ResolvedPlanData);
    data_ptr.* = data;

    return .{
        .diagnostics = diagnostics,
        .plan = .{ .arena = arena, .data = data_ptr },
    };
}

fn checkResolvedSourceIsolation(
    allocator: Allocator,
    diagnostics: *std.array_list.Managed(Diagnostic),
    base_path: []const u8,
    output_path: []const u8,
    source_path: []const u8,
    configuration_path: []const u8,
) Allocator.Error!void {
    const checked_source_path = try std.fs.path.resolve(allocator, &.{ base_path, source_path });
    defer allocator.free(checked_source_path);
    if (std.mem.eql(u8, output_path, checked_source_path) or
        pathContains(checked_source_path, output_path))
    {
        try diagnostics.append(.{
            .severity = .@"error",
            .phase = .resolution,
            .code = .path_conflict,
            .configuration_path = configuration_path,
            .message = "the resolved output path must not alias or be contained by a declared source path",
            .remediation = "place declared sources outside the output location",
        });
    }
}

fn requiresGuestExecution(request: *const Request) bool {
    return request.execution.backend == .unsafe_chroot or
        request.execution.backend == .vm or
        request.packages.actions.len != 0 or
        request.hooks.len != 0 or
        request.initramfs != .unchanged or
        request.selinux != .unchanged;
}

fn dupeOsCustomization(
    allocator: Allocator,
    customization: OsCustomization,
    base_path: ?[]const u8,
) Allocator.Error!OsCustomization {
    const filesystem = try allocator.alloc(FilesystemOperation, customization.filesystem.len);
    for (customization.filesystem, 0..) |operation, index| {
        filesystem[index] = switch (operation) {
            .put_file => |file| .{ .put_file = .{
                .path = try allocator.dupe(u8, file.path),
                .source = switch (file.source) {
                    .inline_bytes => |bytes| .{ .inline_bytes = try allocator.dupe(u8, bytes) },
                    .host_path => |path| .{ .host_path = if (base_path) |base|
                        try std.fs.path.resolve(allocator, &.{ base, path })
                    else
                        try allocator.dupe(u8, path) },
                },
                .metadata = try dupeMetadata(allocator, file.metadata),
            } },
            .put_directory => |directory| .{ .put_directory = .{
                .path = try allocator.dupe(u8, directory.path),
                .metadata = try dupeMetadata(allocator, directory.metadata),
            } },
            .put_symlink => |link| .{ .put_symlink = .{
                .path = try allocator.dupe(u8, link.path),
                .target = try allocator.dupe(u8, link.target),
                .metadata = try dupeMetadata(allocator, link.metadata),
            } },
            .remove => |path| .{ .remove = try allocator.dupe(u8, path) },
            .set_metadata => |change| .{ .set_metadata = .{
                .path = try allocator.dupe(u8, change.path),
                .mode = change.mode,
                .uid = change.uid,
                .gid = change.gid,
                .xattrs = if (change.xattrs) |xattrs| try dupeXattrs(allocator, xattrs) else null,
            } },
        };
    }

    const groups = try allocator.alloc(Group, customization.groups.len);
    for (customization.groups, 0..) |group, index| {
        groups[index] = .{
            .name = try allocator.dupe(u8, group.name),
            .gid = group.gid,
            .members = try dupeStrings(allocator, group.members),
        };
    }
    const users = try allocator.alloc(User, customization.users.len);
    for (customization.users, 0..) |user, index| {
        users[index] = .{
            .name = try allocator.dupe(u8, user.name),
            .uid = user.uid,
            .gid = user.gid,
            .primary_group = if (user.primary_group) |value| try allocator.dupe(u8, value) else null,
            .secondary_groups = try dupeStrings(allocator, user.secondary_groups),
            .home = if (user.home) |value| try allocator.dupe(u8, value) else null,
            .shell = try allocator.dupe(u8, user.shell),
            .password = switch (user.password) {
                .locked => .locked,
                .prehashed => |value| .{ .prehashed = try allocator.dupe(u8, value) },
            },
            .ssh_authorized_keys = try dupeStrings(allocator, user.ssh_authorized_keys),
            .passwordless_sudo = user.passwordless_sudo,
        };
    }
    const services = try allocator.alloc(Service, customization.services.len);
    for (customization.services, 0..) |service, index| {
        services[index] = .{
            .name = try allocator.dupe(u8, service.name),
            .state = service.state,
        };
    }
    const modules = try allocator.alloc(KernelModule, customization.kernel_modules.len);
    for (customization.kernel_modules, 0..) |module, index| {
        modules[index] = .{
            .name = try allocator.dupe(u8, module.name),
            .load = module.load,
            .disabled = module.disabled,
            .options = if (module.options) |value| try allocator.dupe(u8, value) else null,
        };
    }
    return .{
        .filesystem = filesystem,
        .hostname = if (customization.hostname) |value| try allocator.dupe(u8, value) else null,
        .groups = groups,
        .users = users,
        .services = services,
        .kernel_modules = modules,
    };
}

fn dupeExistingPathOperations(
    allocator: Allocator,
    operations: []const ExistingPathOperation,
    base_path: ?[]const u8,
) Allocator.Error![]const ExistingPathOperation {
    const owned = try allocator.alloc(ExistingPathOperation, operations.len);
    for (operations, 0..) |operation, index| {
        owned[index] = switch (operation) {
            .overwrite_file => |overwrite| .{ .overwrite_file = .{
                .path = try allocator.dupe(u8, overwrite.path),
                .source = switch (overwrite.source) {
                    .bytes => |bytes| .{ .bytes = try allocator.dupe(u8, bytes) },
                    .host_path => |path| .{ .host_path = if (base_path) |base|
                        try std.fs.path.resolve(allocator, &.{ base, path })
                    else
                        try allocator.dupe(u8, path) },
                },
            } },
            .remove_file => |path| .{ .remove_file = try allocator.dupe(u8, path) },
            .remove_tree => |path| .{ .remove_tree = try allocator.dupe(u8, path) },
        };
    }
    return owned;
}

fn resolvePaths(
    allocator: Allocator,
    base_path: []const u8,
    values: []const []const u8,
) Allocator.Error![]const []const u8 {
    const owned = try allocator.alloc([]const u8, values.len);
    for (values, 0..) |value, index| {
        owned[index] = try std.fs.path.resolve(allocator, &.{ base_path, value });
    }
    return owned;
}

fn dupePackagePolicy(
    allocator: Allocator,
    policy: PackagePolicy,
    base_path: ?[]const u8,
) Allocator.Error!PackagePolicy {
    const actions = try allocator.alloc(PackageAction, policy.actions.len);
    for (policy.actions, 0..) |action, index| {
        actions[index] = switch (action) {
            .install => |packages| .{ .install = try dupeStrings(allocator, packages) },
            .remove => |packages| .{ .remove = try dupeStrings(allocator, packages) },
            .update_all => .update_all,
            .update_selected => |packages| .{ .update_selected = try dupeStrings(allocator, packages) },
        };
    }
    const repositories = try allocator.alloc(PackageRepository, policy.repositories.len);
    for (policy.repositories, 0..) |repository, index| {
        const trust = try allocator.alloc(TrustSource, repository.trust.len);
        for (repository.trust, 0..) |source, source_index| {
            trust[source_index] = switch (source) {
                .inline_bytes => |bytes| .{ .inline_bytes = try allocator.dupe(u8, bytes) },
                .host_path => |path| .{ .host_path = if (base_path) |base|
                    try std.fs.path.resolve(allocator, &.{ base, path })
                else
                    try allocator.dupe(u8, path) },
            };
        }
        repositories[index] = .{
            .id = try allocator.dupe(u8, repository.id),
            .urls = try dupeStrings(allocator, repository.urls),
            .trust = trust,
        };
    }
    const lock: PackageLockPolicy = switch (policy.lock) {
        .unlocked => .unlocked,
        .snapshot => |snapshot| .{ .snapshot = try allocator.dupe(u8, snapshot) },
        .exact => |locks| blk: {
            const owned = try allocator.alloc(PackageVersionLock, locks.len);
            for (locks, 0..) |lock, index| {
                owned[index] = .{
                    .name = try allocator.dupe(u8, lock.name),
                    .version = try allocator.dupe(u8, lock.version),
                    .repository_id = try allocator.dupe(u8, lock.repository_id),
                };
            }
            break :blk .{ .exact = owned };
        },
    };
    return .{
        .actions = actions,
        .repositories = repositories,
        .cache = policy.cache,
        .lock = lock,
    };
}

fn dupeHooks(
    allocator: Allocator,
    hooks: []const Hook,
    base_path: ?[]const u8,
) Allocator.Error![]const Hook {
    const owned = try allocator.alloc(Hook, hooks.len);
    for (hooks, 0..) |hook, index| {
        owned[index] = .{
            .name = try allocator.dupe(u8, hook.name),
            .phase = hook.phase,
            .source = switch (hook.source) {
                .inline_script => |script| .{ .inline_script = try allocator.dupe(u8, script) },
                .host_path => |path| .{ .host_path = if (base_path) |base|
                    try std.fs.path.resolve(allocator, &.{ base, path })
                else
                    try allocator.dupe(u8, path) },
            },
            .arguments = try dupeStrings(allocator, hook.arguments),
        };
    }
    return owned;
}

fn dupeInitramfsPolicy(
    allocator: Allocator,
    policy: InitramfsPolicy,
) Allocator.Error!InitramfsPolicy {
    return switch (policy) {
        .unchanged => .unchanged,
        .regenerate => |regenerate| .{ .regenerate = .{
            .generator = if (regenerate.generator) |generator| try allocator.dupe(u8, generator) else null,
            .kernels = try dupeStrings(allocator, regenerate.kernels),
        } },
    };
}

fn dupeVmPolicy(
    allocator: Allocator,
    policy: ?VmPolicy,
) Allocator.Error!?VmPolicy {
    const present = policy orelse return null;
    return .{
        .emulator_command = try allocator.dupe(u8, present.emulator_command),
        .boot = switch (present.boot) {
            .direct_kernel => .direct_kernel,
            .firmware => |firmware| .{ .firmware = .{
                .code_path = try allocator.dupe(u8, firmware.code_path),
                .vars_path = try allocator.dupe(u8, firmware.vars_path),
            } },
        },
        .acceleration = present.acceleration,
        .acknowledge_software_emulation = present.acknowledge_software_emulation,
        .memory_mib = present.memory_mib,
        .vcpus = present.vcpus,
        .network = present.network,
        .boot_timeout_seconds = present.boot_timeout_seconds,
        .machine = if (present.machine) |machine| try allocator.dupe(u8, machine) else null,
        .cpu = if (present.cpu) |cpu| try allocator.dupe(u8, cpu) else null,
    };
}

fn dupeSelinuxPolicy(
    allocator: Allocator,
    policy: SelinuxPolicy,
) Allocator.Error!SelinuxPolicy {
    return switch (policy) {
        .unchanged => .unchanged,
        .configure => |configure| .{ .configure = .{
            .mode = configure.mode,
            .policy = if (configure.policy) |name| try allocator.dupe(u8, name) else null,
            .relabel = configure.relabel,
        } },
    };
}

fn dupeCrossArchitecturePolicy(
    allocator: Allocator,
    policy: CrossArchitecturePolicy,
) Allocator.Error!CrossArchitecturePolicy {
    return switch (policy) {
        .reject => .reject,
        .runner => |runner| .{ .runner = .{
            .kind = runner.kind,
            .guest_architecture = runner.guest_architecture,
            .command = if (runner.command) |command| try allocator.dupe(u8, command) else null,
        } },
    };
}

fn dupeMetadata(allocator: Allocator, metadata: Metadata) Allocator.Error!Metadata {
    return .{
        .mode = metadata.mode,
        .uid = metadata.uid,
        .gid = metadata.gid,
        .xattrs = try dupeXattrs(allocator, metadata.xattrs),
    };
}

fn dupeXattrs(allocator: Allocator, xattrs: []const ext4.Xattr) Allocator.Error![]const ext4.Xattr {
    const owned = try allocator.alloc(ext4.Xattr, xattrs.len);
    for (xattrs, 0..) |xattr, index| {
        owned[index] = .{
            .name = try allocator.dupe(u8, xattr.name),
            .value = try allocator.dupe(u8, xattr.value),
        };
    }
    return owned;
}

fn dupeStrings(allocator: Allocator, values: []const []const u8) Allocator.Error![]const []const u8 {
    const owned = try allocator.alloc([]const u8, values.len);
    for (values, 0..) |value, index| owned[index] = try allocator.dupe(u8, value);
    return owned;
}

fn dupeGeneralization(
    allocator: Allocator,
    policy: GeneralizationPolicy,
) Allocator.Error!GeneralizationPolicy {
    return switch (policy) {
        .none => .none,
        .azure => |options| .{ .azure = .{
            .reset_hostname = options.reset_hostname,
            .clear_machine_id = options.clear_machine_id,
            .remove_ssh_host_keys = options.remove_ssh_host_keys,
            .remove_agent_state = options.remove_agent_state,
            .remove_dhcp_leases = options.remove_dhcp_leases,
            .remove_logs = options.remove_logs,
            .remove_caches = options.remove_caches,
            .clear_random_seed = options.clear_random_seed,
            .remove_users = try dupeStrings(allocator, options.remove_users),
        } },
    };
}

fn dupeBootPolicy(allocator: Allocator, policy: BootSecurityPolicy) Allocator.Error!BootSecurityPolicy {
    return .{
        .boot_mode = policy.boot_mode,
        .verity = policy.verity,
        .extra_kernel_options = try allocator.dupe(u8, policy.extra_kernel_options),
        .uki = .{
            .stub_source_path = if (policy.uki.stub_source_path) |path| try allocator.dupe(u8, path) else null,
            .os_release_source_path = if (policy.uki.os_release_source_path) |path| try allocator.dupe(u8, path) else null,
            .splash_source_path = if (policy.uki.splash_source_path) |path| try allocator.dupe(u8, path) else null,
            .output_directory = try allocator.dupe(u8, policy.uki.output_directory),
        },
    };
}

fn buildOperations(
    allocator: Allocator,
    backend: ExecutionBackend,
    policy: BootSecurityPolicy,
    storage: ResolvedStorage,
    packages: PackagePolicy,
    hooks: []const Hook,
    initramfs: InitramfsPolicy,
    selinux: SelinuxPolicy,
) Allocator.Error![]Operation {
    var specs = std.array_list.Managed(OperationSpec).init(allocator);
    defer specs.deinit();
    try appendBackendOperationSpecs(&specs, backend, storage);
    try appendPreInitramfsOperationSpecs(&specs, packages, hooks);
    try appendBackendFinalOperationSpecs(&specs, backend, policy, storage, hooks, initramfs, selinux);

    const operations = try allocator.alloc(Operation, specs.items.len);
    for (specs.items, 0..) |spec, index| {
        const dependencies = if (index == 0) &.{} else blk: {
            const ids = try allocator.alloc(u16, 1);
            ids[0] = @intCast(index - 1);
            break :blk ids;
        };
        operations[index] = .{
            .id = @intCast(index),
            .phase = spec.phase,
            .depends_on = dependencies,
            .action = spec.action,
        };
    }
    return operations;
}

const OperationSpec = struct {
    phase: Phase,
    action: Action,
};

fn appendBackendOperationSpecs(
    specs: *std.array_list.Managed(OperationSpec),
    backend: ExecutionBackend,
    storage: ResolvedStorage,
) Allocator.Error!void {
    switch (backend) {
        .native_fresh => {
            _ = storage.fresh;
            try specs.append(.{ .phase = .prepare, .action = .load_sources });
            try specs.append(.{ .phase = .filesystem_changes, .action = .apply_filesystem_changes });
            try specs.append(.{ .phase = .generalization_cleanup, .action = .generalize_and_cleanup });
        },
        .native_edit => {
            try specs.append(.{ .phase = .prepare, .action = .load_preserved_source });
            try specs.append(.{ .phase = .filesystem_changes, .action = .edit_existing_paths });
        },
        .rebuild => {
            try specs.append(.{ .phase = .prepare, .action = .load_preserved_source });
            try specs.append(.{ .phase = .prepare, .action = .extract_preserved_root });
            try specs.append(.{ .phase = .filesystem_changes, .action = .edit_existing_paths });
            try specs.append(.{ .phase = .filesystem_changes, .action = .apply_filesystem_changes });
            try specs.append(.{ .phase = .generalization_cleanup, .action = .generalize_and_cleanup });
            try specs.append(.{ .phase = .filesystem_finalize, .action = .populate_preserved_root });
        },
        .unsafe_chroot => try specs.append(.{ .phase = .filesystem_changes, .action = .execute_unsafe_chroot }),
        .vm => try specs.append(.{ .phase = .filesystem_changes, .action = .execute_vm }),
    }
}

fn appendPreInitramfsOperationSpecs(
    specs: *std.array_list.Managed(OperationSpec),
    packages: PackagePolicy,
    hooks: []const Hook,
) Allocator.Error!void {
    for (packages.actions) |_| try specs.append(.{ .phase = .packages, .action = .execute_package_action });
    for (hooks) |hook| if (hook.phase == .after_packages) {
        try specs.append(.{ .phase = .after_packages, .action = .execute_hook });
    };
    for (hooks) |hook| if (hook.phase == .before_initramfs) {
        try specs.append(.{ .phase = .before_initramfs, .action = .execute_hook });
    };
}

fn appendBackendFinalOperationSpecs(
    specs: *std.array_list.Managed(OperationSpec),
    backend: ExecutionBackend,
    policy: BootSecurityPolicy,
    storage: ResolvedStorage,
    hooks: []const Hook,
    initramfs: InitramfsPolicy,
    selinux: SelinuxPolicy,
) Allocator.Error!void {
    switch (backend) {
        .native_fresh => {
            const generation = storage.fresh.generation;
            try specs.append(.{ .phase = .initramfs, .action = .prepare_initramfs });
            try appendInitramfsPolicySpec(specs, initramfs);
            if (generation == .gen1) try specs.append(.{ .phase = .bootloader_prepare, .action = .prepare_boot_configuration });
            try specs.append(.{ .phase = .filesystem_finalize, .action = .populate_filesystem });
            try appendBeforeSealSpecs(specs, hooks, selinux);
            if (policy.verity) try specs.append(.{ .phase = .verity_seal, .action = .seal_verity });
            if (generation == .gen2) try specs.append(.{ .phase = .bootloader_prepare, .action = .prepare_boot_configuration });
            try specs.append(.{ .phase = .bootloader_install, .action = .install_bootloader });
            if (policy.boot_mode != .bls_only) try specs.append(.{ .phase = .uki, .action = .generate_uki });
            try appendFinalizeHookSpecs(specs, hooks);
            try specs.append(.{ .phase = .filesystem_close, .action = .check_and_close_filesystems });
            try specs.append(.{ .phase = .output_conversion, .action = .convert_output });
        },
        .native_edit, .rebuild, .unsafe_chroot, .vm => {
            try appendInitramfsPolicySpec(specs, initramfs);
            try appendBeforeSealSpecs(specs, hooks, selinux);
            try appendFinalizeHookSpecs(specs, hooks);
            try specs.append(.{ .phase = .output_conversion, .action = .publish_standalone_output });
        },
    }
}

fn appendInitramfsPolicySpec(
    specs: *std.array_list.Managed(OperationSpec),
    initramfs: InitramfsPolicy,
) Allocator.Error!void {
    if (initramfs != .unchanged) {
        try specs.append(.{ .phase = .initramfs, .action = .regenerate_initramfs });
    }
}

fn appendBeforeSealSpecs(
    specs: *std.array_list.Managed(OperationSpec),
    hooks: []const Hook,
    selinux: SelinuxPolicy,
) Allocator.Error!void {
    for (hooks) |hook| if (hook.phase == .before_seal) {
        try specs.append(.{ .phase = .before_seal, .action = .execute_hook });
    };
    if (selinux != .unchanged) {
        try specs.append(.{ .phase = .selinux, .action = .apply_selinux_policy });
    }
}

fn appendFinalizeHookSpecs(
    specs: *std.array_list.Managed(OperationSpec),
    hooks: []const Hook,
) Allocator.Error!void {
    for (hooks) |hook| if (hook.phase == .finalize) {
        try specs.append(.{ .phase = .finalize, .action = .execute_hook });
    };
}

fn hasExpectedOperations(allocator: Allocator, plan: *const ResolvedPlan) Allocator.Error!bool {
    var specs = std.array_list.Managed(OperationSpec).init(allocator);
    defer specs.deinit();
    try appendBackendOperationSpecs(
        &specs,
        plan.data.execution.backend,
        plan.data.storage,
    );
    try appendPreInitramfsOperationSpecs(&specs, plan.data.packages, plan.data.hooks);
    try appendBackendFinalOperationSpecs(
        &specs,
        plan.data.execution.backend,
        plan.data.boot_security,
        plan.data.storage,
        plan.data.hooks,
        plan.data.initramfs,
        plan.data.selinux,
    );
    if (plan.data.operations.len != specs.items.len) return false;
    for (plan.data.operations, specs.items, 0..) |operation, spec, index| {
        if (operation.id != index or operation.phase != spec.phase or operation.action != spec.action) return false;
        if (index == 0) {
            if (operation.depends_on.len != 0) return false;
        } else if (operation.depends_on.len != 1 or operation.depends_on[0] != index - 1) {
            return false;
        }
    }
    return true;
}

fn buildCapabilities(
    allocator: Allocator,
    input: ResolvedInput,
    output: ResolvedOutput,
    storage: ResolvedStorage,
    execution: ExecutionPolicy,
    transaction_path: []const u8,
    customization: OsCustomization,
    existing_operations: []const ExistingPathOperation,
    packages: PackagePolicy,
    hooks: []const Hook,
    initramfs: InitramfsPolicy,
    selinux: SelinuxPolicy,
    generalization_policy: GeneralizationPolicy,
    boot_policy: BootSecurityPolicy,
    cross_architecture: CrossArchitecturePolicy,
    target_architecture: Architecture,
    host_architecture: Architecture,
) Allocator.Error![]CapabilityRequirement {
    var capabilities = std.array_list.Managed(CapabilityRequirement).init(allocator);
    defer capabilities.deinit();

    switch (input) {
        .iso_oci => |iso_oci| {
            try capabilities.append(.{ .kind = .read_iso, .path = iso_oci.iso_path, .reason = "read the source ISO" });
            try capabilities.append(.{ .kind = .read_container, .path = iso_oci.container_path, .reason = "read the source OCI layout or archive" });
            try appendIsolationCapability(&capabilities, output.path, iso_oci.iso_path, "keep the output distinct from the source ISO");
            try appendIsolationCapability(&capabilities, output.path, iso_oci.container_path, "keep the output outside the source container");
        },
        .disk => |disk| {
            try capabilities.append(.{ .kind = .read_disk, .path = disk.path, .reason = "read the preserved source disk without write access" });
            for (disk.dependencies) |dependency| {
                try capabilities.append(.{
                    .kind = .read_disk_dependency,
                    .path = dependency,
                    .reason = "read a declared qcow2 backing or external-data file",
                });
                try appendIsolationCapability(
                    &capabilities,
                    output.path,
                    dependency,
                    "keep the output distinct from every preserved disk dependency",
                );
            }
            try capabilities.append(.{
                .kind = .disk_dependencies,
                .path = disk.path,
                .related_path = output.path,
                .reason = "read and isolate every qcow2 backing or external-data file",
            });
            try appendIsolationCapability(&capabilities, output.path, disk.path, "keep the output distinct from the preserved source disk");
        },
    }
    for (customization.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .host_path => |path| {
                try capabilities.append(.{
                    .kind = .read_customization_file,
                    .path = path,
                    .reason = "read a declared customization file",
                });
                try appendIsolationCapability(&capabilities, output.path, path, "keep the output distinct from customization source files");
            },
            .inline_bytes => {},
        },
        else => {},
    };
    for (existing_operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| switch (overwrite.source) {
            .bytes => {},
            .host_path => |path| {
                try capabilities.append(.{ .kind = .read_edit_source, .path = path, .reason = "read a declared existing-file replacement source" });
                try appendIsolationCapability(&capabilities, output.path, path, "keep the output distinct from edit source files");
            },
        },
        .remove_file, .remove_tree => {},
    };
    for (packages.repositories) |repository| for (repository.trust) |trust| switch (trust) {
        .inline_bytes => {},
        .host_path => |path| {
            try capabilities.append(.{ .kind = .read_trust_source, .path = path, .reason = "read declared package trust material" });
            try appendIsolationCapability(&capabilities, output.path, path, "keep the output distinct from package trust sources");
        },
    };
    for (hooks) |hook| switch (hook.source) {
        .inline_script => {},
        .host_path => |path| {
            try capabilities.append(.{ .kind = .read_hook_source, .path = path, .reason = "read a declared hook script" });
            try appendIsolationCapability(&capabilities, output.path, path, "keep the output distinct from hook sources");
        },
    };
    try capabilities.append(.{
        .kind = .write_workspace_parent,
        .path = execution.workspace_path,
        .reason = "create the explicit transaction workspace",
    });
    try capabilities.append(.{
        .kind = .write_output_parent,
        .path = std.fs.path.dirname(output.path) orelse ".",
        .reason = "atomically commit the completed image",
    });
    if (!execution.overwrite) {
        try capabilities.append(.{ .kind = .output_absent, .path = output.path, .reason = "preserve an existing output" });
    }
    try capabilities.append(.{ .kind = .transaction_absent, .path = transaction_path, .reason = "avoid colliding with another or stale transaction" });
    switch (execution.backend) {
        .native_fresh => try capabilities.append(.{ .kind = .native_fresh, .path = "", .reason = "execute the selected rootless native-fresh backend" }),
        .native_edit => {
            try capabilities.append(.{ .kind = .native_edit, .path = "", .reason = "execute the rootless preserved-image editor" });
            try capabilities.append(.{ .kind = .partition_edit, .path = "", .reason = "edit the explicitly selected existing partition" });
            try capabilities.append(.{ .kind = .standalone_output, .path = output.path, .reason = "publish a standalone output with any backing chain flattened" });
        },
        .rebuild => {
            try capabilities.append(.{ .kind = .rebuild, .path = "", .reason = "extract and rebuild the strict writer-compatible ext4 profile without guest execution" });
            try capabilities.append(.{ .kind = .standalone_output, .path = output.path, .reason = "publish a standalone rebuilt output" });
        },
        .unsafe_chroot => {
            try capabilities.append(.{ .kind = .unsafe_chroot, .path = "", .reason = "run the Linux-only privileged same-architecture chroot executor; chroot is not a sandbox" });
            try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "execute target code on the host" });
            try capabilities.append(.{ .kind = .standalone_output, .path = output.path, .reason = "publish a standalone output" });
        },
        .vm => {
            try capabilities.append(.{ .kind = .vm, .path = "", .reason = "run the isolated full-system VM executor" });
            try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "execute target code in a VM" });
            try capabilities.append(.{ .kind = .standalone_output, .path = output.path, .reason = "publish a standalone output" });
        },
    }
    if (execution.backend != .native_fresh and hasOsCustomization(customization)) {
        try capabilities.append(.{
            .kind = .arbitrary_filesystem_mutation,
            .path = "",
            .reason = if (execution.backend == .rebuild)
                "apply deterministic filesystem and OS changes to the imported strict ext4 tree"
            else
                "general preserved-filesystem creation and metadata mutation are not implemented",
        });
    }
    if (packages.actions.len != 0) {
        try capabilities.append(.{ .kind = .package_management, .path = "", .reason = "execute declared package actions" });
        try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "run the target package manager" });
    }
    if (packages.repositories.len != 0) {
        try capabilities.append(.{ .kind = .repository_access, .path = "", .reason = "access only explicitly declared package repositories" });
        try capabilities.append(.{ .kind = .repository_trust, .path = "", .reason = "install explicitly declared repository trust material" });
    }
    if (packages.cache == .cache_only) {
        try capabilities.append(.{ .kind = .package_cache, .path = "", .reason = "satisfy package actions from the declared offline cache" });
    }
    if (packages.lock != .unlocked) {
        try capabilities.append(.{ .kind = .package_lock, .path = "", .reason = "enforce the declared package snapshot or exact-version lock" });
    }
    if (hooks.len != 0) {
        try capabilities.append(.{ .kind = .script_execution, .path = "", .reason = "execute explicitly acknowledged scripts using an unsafe-capable backend" });
        try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "execute target hook code" });
    }
    if (initramfs != .unchanged) {
        try capabilities.append(.{ .kind = .initramfs_regeneration, .path = "", .reason = "regenerate initramfs with the declared policy" });
        try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "run the target initramfs generator" });
    }
    switch (selinux) {
        .unchanged => {},
        .configure => |configure| {
            try capabilities.append(.{ .kind = .selinux_policy, .path = "", .reason = "apply the declared SELinux policy and mode" });
            try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "use target SELinux policy tooling" });
            if (configure.relabel) {
                try capabilities.append(.{ .kind = .selinux_relabel, .path = "", .reason = "relabel the preserved filesystem" });
            }
        },
    }
    if (execution.backend != .native_fresh and !isDefaultBootPolicy(boot_policy)) {
        try capabilities.append(.{ .kind = .boot_policy_mutation, .path = "", .reason = "mutate preserved boot configuration" });
    }
    if (execution.backend != .native_fresh and generalization_policy != .none) {
        try capabilities.append(.{
            .kind = .generalization,
            .path = "",
            .reason = if (execution.backend == .rebuild)
                "apply deterministic generalization to the imported strict ext4 tree"
            else
                "apply preserved-image generalization",
        });
    }
    if (target_architecture != host_architecture and
        (execution.backend == .unsafe_chroot or
            execution.backend == .vm or
            packages.actions.len != 0 or
            hooks.len != 0 or
            initramfs != .unchanged or
            selinux != .unchanged))
    {
        const runner_path = switch (cross_architecture) {
            .reject => "",
            .runner => |runner| runner.command orelse "",
        };
        try capabilities.append(.{
            .kind = .cross_architecture_runner,
            .path = runner_path,
            .reason = "execute target binaries only through the explicit compatible runner policy",
        });
    }
    _ = storage;
    try capabilities.append(.{ .kind = .atomic_commit, .path = output.path, .reason = "publish output only after successful completion" });
    return try capabilities.toOwnedSlice();
}

fn appendIsolationCapability(
    capabilities: *std.array_list.Managed(CapabilityRequirement),
    output_path: []const u8,
    source_path: []const u8,
    reason: []const u8,
) Allocator.Error!void {
    try capabilities.append(.{
        .kind = .path_isolation,
        .path = output_path,
        .related_path = source_path,
        .reason = reason,
    });
}

fn hasOsCustomization(customization: OsCustomization) bool {
    return customization.filesystem.len != 0 or
        customization.hostname != null or
        customization.groups.len != 0 or
        customization.users.len != 0 or
        customization.services.len != 0 or
        customization.kernel_modules.len != 0;
}

fn isDefaultBootPolicy(policy: BootSecurityPolicy) bool {
    return policy.boot_mode == .bls_only and
        !policy.verity and
        policy.extra_kernel_options.len == 0 and
        policy.uki.stub_source_path == null and
        policy.uki.os_release_source_path == null and
        policy.uki.splash_source_path == null and
        std.mem.eql(u8, policy.uki.output_directory, "EFI/Linux");
}

fn deriveIdentifiers(seed: Seed) GeneratedIdentifiers {
    return .{
        .disk_guid = .{ .bytes = deriveGuid(seed, "disk-guid") },
        .esp_partition_guid = .{ .bytes = deriveGuid(seed, "esp-partition-guid") },
        .root_partition_guid = .{ .bytes = deriveGuid(seed, "root-partition-guid") },
        .root_filesystem_uuid = .{ .bytes = deriveUuid(seed, "root-filesystem-uuid") },
        .mbr_disk_signature = deriveNonzeroU32(seed, "mbr-disk-signature"),
        .verity_salt = .{ .bytes = derive(seed, "verity-salt", 0) },
        .output_unique_id = .{ .bytes = deriveUuid(seed, "output-unique-id") },
        .vhdx_header_sequence_base = deriveHeaderSequenceBase(seed),
        .vhdx_file_write_guid = .{ .bytes = deriveGuid(seed, "vhdx-file-write-guid") },
        .vhdx_data_write_guid = .{ .bytes = deriveGuid(seed, "vhdx-data-write-guid") },
        .vhdx_page83_guid = .{ .bytes = deriveGuid(seed, "vhdx-page83-guid") },
        .vhdx_write_guid_seed = .{ .bytes = derive(seed, "vhdx-write-guid-seed", 0) },
        .transaction_id = .{ .bytes = deriveUuid(seed, "transaction-id") },
    };
}

fn outputIdentifiers(generated: GeneratedIdentifiers) OutputIdentifiers {
    return .{
        .output_unique_id = generated.output_unique_id,
        .vhdx_header_sequence_base = generated.vhdx_header_sequence_base,
        .vhdx_file_write_guid = generated.vhdx_file_write_guid,
        .vhdx_data_write_guid = generated.vhdx_data_write_guid,
        .vhdx_page83_guid = generated.vhdx_page83_guid,
        .vhdx_write_guid_seed = generated.vhdx_write_guid_seed,
    };
}

fn deriveTransactionId(seed: Seed, output_path: []const u8) Uuid {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("zvmi-transaction-id-v1\x00");
    hashString(&hash, output_path);
    hash.update(&seed.bytes);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    var value: [16]u8 = digest[0..16].*;
    value[6] = (value[6] & 0x0F) | 0x40;
    value[8] = (value[8] & 0x3F) | 0x80;
    return .{ .bytes = value };
}

fn derive(seed: Seed, label: []const u8, index: u64) [32]u8 {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("zvmi-plan-derive-v1\x00");
    var label_len: [4]u8 = undefined;
    std.mem.writeInt(u32, &label_len, @intCast(label.len), .big);
    hash.update(&label_len);
    hash.update(label);
    var index_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &index_bytes, index, .big);
    hash.update(&index_bytes);
    hash.update(&seed.bytes);
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return digest;
}

fn deriveGuid(seed: Seed, label: []const u8) guid.Guid {
    const digest = derive(seed, label, 0);
    var value: guid.Guid = digest[0..16].*;
    value[7] = (value[7] & 0x0F) | 0x40;
    value[8] = (value[8] & 0x3F) | 0x80;
    return value;
}

fn deriveUuid(seed: Seed, label: []const u8) [16]u8 {
    const digest = derive(seed, label, 0);
    var value: [16]u8 = digest[0..16].*;
    value[6] = (value[6] & 0x0F) | 0x40;
    value[8] = (value[8] & 0x3F) | 0x80;
    return value;
}

fn deriveU64(seed: Seed, label: []const u8) u64 {
    const digest = derive(seed, label, 0);
    return std.mem.readInt(u64, digest[0..8], .big);
}

fn deriveHeaderSequenceBase(seed: Seed) u64 {
    return @min(deriveU64(seed, "vhdx-header-sequence"), std.math.maxInt(u64) - 3);
}

fn deriveNonzeroU32(seed: Seed, label: []const u8) u32 {
    const digest = derive(seed, label, 0);
    const value = std.mem.readInt(u32, digest[0..4], .big);
    return if (value == 0) 1 else value;
}

fn hashPlan(plan: ResolvedPlanData) Digest {
    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("zvmi-resolved-plan-v3\x00");
    hashInt(&hash, plan.schema_version);
    hashInt(&hash, plan.request_api_version);
    hashInt(&hash, @intFromEnum(plan.architectures.host));
    hashInt(&hash, @intFromEnum(plan.architectures.image));
    hashInt(&hash, @intFromEnum(plan.architectures.firmware));
    hashInt(&hash, @intFromEnum(plan.architectures.repository));
    hashInt(&hash, @intFromEnum(plan.architectures.runner));
    hashInt(&hash, @intFromEnum(std.meta.activeTag(plan.input)));
    switch (plan.input) {
        .iso_oci => |input| {
            hashString(&hash, input.iso_path);
            hashString(&hash, input.container_path);
            hashString(&hash, input.rootfs_path_in_iso);
        },
        .disk => |input| {
            hashString(&hash, input.path);
            hashStrings(&hash, input.dependencies);
        },
    }
    hashString(&hash, plan.output.path);
    hashInt(&hash, @intFromEnum(plan.output.format));
    hashInt(&hash, plan.output.requested_size);
    hashInt(&hash, plan.output.disk_size);
    hashInt(&hash, @intFromEnum(plan.output.size_policy));
    hashInt(&hash, @intFromEnum(std.meta.activeTag(plan.storage)));
    switch (plan.storage) {
        .fresh => |storage| {
            hashInt(&hash, @intFromEnum(storage.generation));
            hashInt(&hash, storage.esp_size);
            hashString(&hash, storage.ext4_label);
            hashBool(&hash, storage.skip_iso_rootfs);
        },
        .preserve => |storage| hashPartitionSelector(&hash, storage.root_partition),
    }
    hashOsCustomization(&hash, plan.os);
    hashExistingPathOperations(&hash, plan.existing_path_operations);
    hashPackagePolicy(&hash, plan.packages);
    hashHooks(&hash, plan.hooks);
    hashInitramfsPolicy(&hash, plan.initramfs);
    hashSelinuxPolicy(&hash, plan.selinux);
    hashCrossArchitecturePolicy(&hash, plan.cross_architecture);
    hashInt(&hash, @intFromEnum(plan.boot_security.boot_mode));
    hashBool(&hash, plan.boot_security.verity);
    hashString(&hash, plan.boot_security.extra_kernel_options);
    hashOptionalString(&hash, plan.boot_security.uki.stub_source_path);
    hashOptionalString(&hash, plan.boot_security.uki.os_release_source_path);
    hashOptionalString(&hash, plan.boot_security.uki.splash_source_path);
    hashString(&hash, plan.boot_security.uki.output_directory);
    hashGeneralization(&hash, plan.generalization);
    hashString(&hash, plan.execution.workspace_path);
    hashInt(&hash, @intFromEnum(plan.execution.backend));
    hashBool(&hash, plan.execution.overwrite);
    hashBool(&hash, plan.execution.acknowledge_unsafe);
    if (plan.execution.vm) |vm| {
        hash.update(&.{1});
        hashString(&hash, vm.emulator_command);
        hashInt(&hash, @intFromEnum(std.meta.activeTag(vm.boot)));
        switch (vm.boot) {
            .direct_kernel => {},
            .firmware => |firmware| {
                hashString(&hash, firmware.code_path);
                hashString(&hash, firmware.vars_path);
            },
        }
        hashInt(&hash, @intFromEnum(vm.acceleration));
        hashBool(&hash, vm.acknowledge_software_emulation);
        hashInt(&hash, vm.memory_mib);
        hashInt(&hash, vm.vcpus);
        hashInt(&hash, @intFromEnum(vm.network));
        hashInt(&hash, vm.boot_timeout_seconds);
        hashOptionalString(&hash, vm.machine);
        hashOptionalString(&hash, vm.cpu);
    } else {
        hash.update(&.{0});
    }
    hash.update(&plan.reproducibility.seed.bytes);
    hashInt(&hash, plan.reproducibility.source_date_epoch);
    hashString(&hash, plan.transaction_path);
    hashString(&hash, plan.staging_output_path);
    hash.update(&plan.transaction_id.bytes);
    hashOutputIdentifiers(&hash, plan.output_identifiers);
    if (plan.generated) |generated| {
        hash.update(&.{1});
        hash.update(&generated.disk_guid.bytes);
        hash.update(&generated.esp_partition_guid.bytes);
        hash.update(&generated.root_partition_guid.bytes);
        hash.update(&generated.root_filesystem_uuid.bytes);
        hashInt(&hash, generated.mbr_disk_signature);
        hash.update(&generated.verity_salt.bytes);
        hashOutputIdentifiers(&hash, outputIdentifiers(generated));
        hash.update(&generated.transaction_id.bytes);
    } else {
        hash.update(&.{0});
    }
    hashInt(&hash, plan.operations.len);
    for (plan.operations) |operation| {
        hashInt(&hash, operation.id);
        hashInt(&hash, @intFromEnum(operation.phase));
        hashInt(&hash, @intFromEnum(operation.action));
        hashInt(&hash, operation.depends_on.len);
        for (operation.depends_on) |dependency| hashInt(&hash, dependency);
    }
    hashInt(&hash, plan.required_capabilities.len);
    for (plan.required_capabilities) |capability| {
        hashInt(&hash, @intFromEnum(capability.kind));
        hashString(&hash, capability.path);
        hashString(&hash, capability.related_path);
        hashString(&hash, capability.reason);
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .bytes = digest };
}

fn hashOsCustomization(hash: *std.crypto.hash.sha2.Sha256, customization: OsCustomization) void {
    hashInt(hash, customization.filesystem.len);
    for (customization.filesystem) |operation| {
        hashInt(hash, @intFromEnum(std.meta.activeTag(operation)));
        switch (operation) {
            .put_file => |file| {
                hashString(hash, file.path);
                hashInt(hash, @intFromEnum(std.meta.activeTag(file.source)));
                switch (file.source) {
                    .inline_bytes => |bytes| hashString(hash, bytes),
                    .host_path => |path| hashString(hash, path),
                }
                hashMetadata(hash, file.metadata);
            },
            .put_directory => |directory| {
                hashString(hash, directory.path);
                hashMetadata(hash, directory.metadata);
            },
            .put_symlink => |link| {
                hashString(hash, link.path);
                hashString(hash, link.target);
                hashMetadata(hash, link.metadata);
            },
            .remove => |path| hashString(hash, path),
            .set_metadata => |change| {
                hashString(hash, change.path);
                hashOptionalInt(hash, change.mode);
                hashOptionalInt(hash, change.uid);
                hashOptionalInt(hash, change.gid);
                if (change.xattrs) |xattrs| {
                    hash.update(&.{1});
                    hashXattrs(hash, xattrs);
                } else {
                    hash.update(&.{0});
                }
            },
        }
    }
    hashOptionalString(hash, customization.hostname);
    hashInt(hash, customization.groups.len);
    for (customization.groups) |group| {
        hashString(hash, group.name);
        hashOptionalInt(hash, group.gid);
        hashStrings(hash, group.members);
    }
    hashInt(hash, customization.users.len);
    for (customization.users) |user| {
        hashString(hash, user.name);
        hashOptionalInt(hash, user.uid);
        hashOptionalInt(hash, user.gid);
        hashOptionalString(hash, user.primary_group);
        hashStrings(hash, user.secondary_groups);
        hashOptionalString(hash, user.home);
        hashString(hash, user.shell);
        hashInt(hash, @intFromEnum(std.meta.activeTag(user.password)));
        switch (user.password) {
            .locked => {},
            .prehashed => |value| hashString(hash, value),
        }
        hashStrings(hash, user.ssh_authorized_keys);
        hashBool(hash, user.passwordless_sudo);
    }
    hashInt(hash, customization.services.len);
    for (customization.services) |service| {
        hashString(hash, service.name);
        hashInt(hash, @intFromEnum(service.state));
    }
    hashInt(hash, customization.kernel_modules.len);
    for (customization.kernel_modules) |module| {
        hashString(hash, module.name);
        hashBool(hash, module.load);
        hashBool(hash, module.disabled);
        hashOptionalString(hash, module.options);
    }
}

fn hashExistingPathOperations(
    hash: *std.crypto.hash.sha2.Sha256,
    operations: []const ExistingPathOperation,
) void {
    hashInt(hash, operations.len);
    for (operations) |operation| {
        hashInt(hash, @intFromEnum(std.meta.activeTag(operation)));
        switch (operation) {
            .overwrite_file => |overwrite| {
                hashString(hash, overwrite.path);
                hashInt(hash, @intFromEnum(std.meta.activeTag(overwrite.source)));
                switch (overwrite.source) {
                    .bytes => |bytes| hashString(hash, bytes),
                    .host_path => |path| hashString(hash, path),
                }
            },
            .remove_file => |path| hashString(hash, path),
            .remove_tree => |path| hashString(hash, path),
        }
    }
}

fn hashPackagePolicy(hash: *std.crypto.hash.sha2.Sha256, policy: PackagePolicy) void {
    hashInt(hash, policy.actions.len);
    for (policy.actions) |action| {
        hashInt(hash, @intFromEnum(std.meta.activeTag(action)));
        switch (action) {
            .install => |packages| hashStrings(hash, packages),
            .remove => |packages| hashStrings(hash, packages),
            .update_all => {},
            .update_selected => |packages| hashStrings(hash, packages),
        }
    }
    hashInt(hash, policy.repositories.len);
    for (policy.repositories) |repository| {
        hashString(hash, repository.id);
        hashStrings(hash, repository.urls);
        hashInt(hash, repository.trust.len);
        for (repository.trust) |trust| {
            hashInt(hash, @intFromEnum(std.meta.activeTag(trust)));
            switch (trust) {
                .inline_bytes => |bytes| hashString(hash, bytes),
                .host_path => |path| hashString(hash, path),
            }
        }
    }
    hashInt(hash, @intFromEnum(policy.cache));
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy.lock)));
    switch (policy.lock) {
        .unlocked => {},
        .snapshot => |snapshot| hashString(hash, snapshot),
        .exact => |locks| {
            hashInt(hash, locks.len);
            for (locks) |lock| {
                hashString(hash, lock.name);
                hashString(hash, lock.version);
                hashString(hash, lock.repository_id);
            }
        },
    }
}

fn hashHooks(hash: *std.crypto.hash.sha2.Sha256, hooks: []const Hook) void {
    hashInt(hash, hooks.len);
    for (hooks) |hook| {
        hashString(hash, hook.name);
        hashInt(hash, @intFromEnum(hook.phase));
        hashInt(hash, @intFromEnum(std.meta.activeTag(hook.source)));
        switch (hook.source) {
            .inline_script => |script| hashString(hash, script),
            .host_path => |path| hashString(hash, path),
        }
        hashStrings(hash, hook.arguments);
    }
}

fn hashInitramfsPolicy(hash: *std.crypto.hash.sha2.Sha256, policy: InitramfsPolicy) void {
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy)));
    switch (policy) {
        .unchanged => {},
        .regenerate => |regenerate| {
            hashOptionalString(hash, regenerate.generator);
            hashStrings(hash, regenerate.kernels);
        },
    }
}

fn hashSelinuxPolicy(hash: *std.crypto.hash.sha2.Sha256, policy: SelinuxPolicy) void {
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy)));
    switch (policy) {
        .unchanged => {},
        .configure => |configure| {
            hashInt(hash, @intFromEnum(configure.mode));
            hashOptionalString(hash, configure.policy);
            hashBool(hash, configure.relabel);
        },
    }
}

fn hashCrossArchitecturePolicy(
    hash: *std.crypto.hash.sha2.Sha256,
    policy: CrossArchitecturePolicy,
) void {
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy)));
    switch (policy) {
        .reject => {},
        .runner => |runner| {
            hashInt(hash, @intFromEnum(runner.kind));
            hashInt(hash, @intFromEnum(runner.guest_architecture));
            hashOptionalString(hash, runner.command);
        },
    }
}

fn hashPartitionSelector(
    hash: *std.crypto.hash.sha2.Sha256,
    selector: PartitionSelector,
) void {
    hashInt(hash, @intFromEnum(std.meta.activeTag(selector)));
    switch (selector) {
        .gpt_index => |index| hashInt(hash, index),
        .mbr_index => |index| hashInt(hash, index),
    }
}

fn hashOutputIdentifiers(
    hash: *std.crypto.hash.sha2.Sha256,
    identifiers: OutputIdentifiers,
) void {
    hash.update(&identifiers.output_unique_id.bytes);
    hashInt(hash, identifiers.vhdx_header_sequence_base);
    hash.update(&identifiers.vhdx_file_write_guid.bytes);
    hash.update(&identifiers.vhdx_data_write_guid.bytes);
    hash.update(&identifiers.vhdx_page83_guid.bytes);
    hash.update(&identifiers.vhdx_write_guid_seed.bytes);
}

fn hashMetadata(hash: *std.crypto.hash.sha2.Sha256, metadata: Metadata) void {
    hashInt(hash, metadata.mode);
    hashInt(hash, metadata.uid);
    hashInt(hash, metadata.gid);
    hashXattrs(hash, metadata.xattrs);
}

fn hashXattrs(hash: *std.crypto.hash.sha2.Sha256, xattrs: []const ext4.Xattr) void {
    hashInt(hash, xattrs.len);
    for (xattrs) |xattr| {
        hashString(hash, xattr.name);
        hashString(hash, xattr.value);
    }
}

fn hashStrings(hash: *std.crypto.hash.sha2.Sha256, values: []const []const u8) void {
    hashInt(hash, values.len);
    for (values) |value| hashString(hash, value);
}

fn hashGeneralization(hash: *std.crypto.hash.sha2.Sha256, policy: GeneralizationPolicy) void {
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy)));
    switch (policy) {
        .none => {},
        .azure => |options| {
            hashBool(hash, options.reset_hostname);
            hashBool(hash, options.clear_machine_id);
            hashBool(hash, options.remove_ssh_host_keys);
            hashBool(hash, options.remove_agent_state);
            hashBool(hash, options.remove_dhcp_leases);
            hashBool(hash, options.remove_logs);
            hashBool(hash, options.remove_caches);
            hashBool(hash, options.clear_random_seed);
            hashStrings(hash, options.remove_users);
        },
    }
}

fn hashInt(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    var bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &bytes, @intCast(value), .big);
    hash.update(&bytes);
}

fn hashOptionalInt(hash: *std.crypto.hash.sha2.Sha256, value: anytype) void {
    if (value) |present| {
        hash.update(&.{1});
        hashInt(hash, present);
    } else {
        hash.update(&.{0});
    }
}

fn hashBool(hash: *std.crypto.hash.sha2.Sha256, value: bool) void {
    hash.update(if (value) &.{1} else &.{0});
}

fn hashString(hash: *std.crypto.hash.sha2.Sha256, value: []const u8) void {
    hashInt(hash, @as(u64, value.len));
    hash.update(value);
}

fn hashOptionalString(hash: *std.crypto.hash.sha2.Sha256, value: ?[]const u8) void {
    if (value) |present| {
        hash.update(&.{1});
        hashString(hash, present);
    } else {
        hash.update(&.{0});
    }
}

pub const CapabilityState = enum {
    available,
    missing,
    unsupported,
};

pub const CapabilityCheck = struct {
    requirement: CapabilityRequirement,
    state: CapabilityState,
};

pub const Platform = struct {
    context: ?*anyopaque = null,
    checkFn: *const fn (context: ?*anyopaque, io: Io, requirement: CapabilityRequirement) CapabilityState,
    runFn: ?*const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        plan: *const ResolvedPlan,
        event_sink: ?EventSink,
        stage_sink: build_image.StageSink,
    ) anyerror!void = null,
    unsafeChrootCheckFn: ?*const fn (
        context: ?*anyopaque,
        io: Io,
        plan: *const ResolvedPlan,
    ) CapabilityState = null,
    unsafeChrootRunFn: ?*const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        plan: *const ResolvedPlan,
        target: preserved_image.RawMutationTarget,
    ) anyerror!UnsafeChrootRuntimeReport = null,
    vmCheckFn: ?*const fn (
        context: ?*anyopaque,
        io: Io,
        plan: *const ResolvedPlan,
    ) CapabilityState = null,
    vmRunFn: ?*const fn (
        context: ?*anyopaque,
        allocator: Allocator,
        io: Io,
        plan: *const ResolvedPlan,
        target: preserved_image.RawMutationTarget,
    ) anyerror!VmRuntimeReport = null,

    pub fn system() Platform {
        return .{ .checkFn = systemCapabilityCheck };
    }

    fn check(self: Platform, io: Io, requirement: CapabilityRequirement) CapabilityState {
        return self.checkFn(self.context, io, requirement);
    }

    fn checkVm(
        self: Platform,
        io: Io,
        plan: *const ResolvedPlan,
    ) CapabilityState {
        const check_fn = self.vmCheckFn orelse return .unsupported;
        return check_fn(self.context, io, plan);
    }

    fn checkUnsafeChroot(
        self: Platform,
        io: Io,
        plan: *const ResolvedPlan,
    ) CapabilityState {
        const check_fn = self.unsafeChrootCheckFn orelse return .unsupported;
        return check_fn(self.context, io, plan);
    }
};

pub const PreflightReport = struct {
    arena: std.heap.ArenaAllocator,
    capabilities: []CapabilityCheck,
    diagnostics: DiagnosticSet,

    pub fn deinit(self: *PreflightReport, _: Allocator) void {
        self.arena.deinit();
        self.* = undefined;
    }

    pub fn ready(self: PreflightReport) bool {
        return !self.diagnostics.hasErrors();
    }
};

pub fn preflight(
    allocator: Allocator,
    io: Io,
    plan: *const ResolvedPlan,
    platform: Platform,
) Allocator.Error!PreflightReport {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const report_allocator = arena.allocator();
    const requirements = plan.data.required_capabilities;
    const checks = try report_allocator.alloc(CapabilityCheck, requirements.len);
    const diagnostic_buffer = try report_allocator.alloc(Diagnostic, requirements.len + 1);
    var diagnostic_count: usize = 0;

    if (!try hasValidPlanIntegrity(report_allocator, plan)) {
        diagnostic_buffer[diagnostic_count] = .{
            .severity = .@"error",
            .phase = .preflight,
            .code = .invalid_plan,
            .configuration_path = "/",
            .message = "the resolved plan failed its integrity or backend invariant checks",
            .remediation = "preflight the immutable plan returned by resolve without modification",
        };
        diagnostic_count += 1;
    }

    for (requirements, 0..) |requirement, index| {
        const state: CapabilityState = switch (requirement.kind) {
            .disk_dependencies => switch (plan.data.input) {
                .disk => |disk| diskDependenciesAvailable(
                    io,
                    disk,
                    plan.data.output.path,
                ),
                .iso_oci => .unsupported,
            },
            .rebuild => if (plan.data.execution.backend == .rebuild)
                rebuildAvailable(io, plan)
            else
                .unsupported,
            .arbitrary_filesystem_mutation,
            .generalization,
            => if (plan.data.execution.backend == .rebuild) .available else .unsupported,
            .vm => vmCapabilityState(platform, io, plan),
            .package_cache,
            .package_lock,
            .selinux_policy,
            .selinux_relabel,
            .boot_policy_mutation,
            => .unsupported,
            .script_execution,
            .cross_architecture_runner,
            => if (plan.data.execution.backend == .vm)
                vmCapabilityState(platform, io, plan)
            else
                .unsupported,
            .unsafe_chroot,
            .package_management,
            .repository_access,
            .repository_trust,
            .guest_execution,
            .initramfs_regeneration,
            => if (plan.data.execution.backend == .vm)
                vmCapabilityState(platform, io, plan)
            else
                unsafeChrootCapabilityState(platform, io, plan),
            else => platform.check(io, requirement),
        };
        const owned_requirement = CapabilityRequirement{
            .kind = requirement.kind,
            .path = try report_allocator.dupe(u8, requirement.path),
            .related_path = try report_allocator.dupe(u8, requirement.related_path),
            .reason = try report_allocator.dupe(u8, requirement.reason),
        };
        checks[index] = .{ .requirement = owned_requirement, .state = state };
        if (state != .available) {
            diagnostic_buffer[diagnostic_count] = .{
                .severity = .@"error",
                .phase = .preflight,
                .code = .missing_capability,
                .configuration_path = owned_requirement.path,
                .message = if (state == .missing) "a required host capability is unavailable" else "a required host capability is unsupported",
                .remediation = owned_requirement.reason,
            };
            diagnostic_count += 1;
        }
    }

    return .{
        .arena = arena,
        .capabilities = checks,
        .diagnostics = .{ .items = diagnostic_buffer[0..diagnostic_count] },
    };
}

fn unsafeChrootCapabilityState(
    platform: Platform,
    io: Io,
    plan: *const ResolvedPlan,
) CapabilityState {
    const data = plan.data;
    if (data.execution.backend != .unsafe_chroot or
        data.architectures.host != data.architectures.image or
        !data.execution.acknowledge_unsafe or
        data.input != .disk or
        data.storage != .preserve or
        data.existing_path_operations.len != 0 or
        hasOsCustomization(data.os) or
        data.generalization != .none or
        data.hooks.len != 0 or
        data.selinux != .unchanged or
        !isDefaultBootPolicy(data.boot_security) or
        data.packages.cache != .online or
        data.packages.lock != .unlocked)
    {
        return .unsupported;
    }
    for (data.packages.actions) |action| {
        const names = switch (action) {
            .install => |values| values,
            .remove => |values| values,
            .update_all, .update_selected => return .unsupported,
        };
        if (names.len == 0) return .unsupported;
        for (names) |name| {
            if (!validUnsafePackageName(name)) return .unsupported;
        }
    }
    for (data.packages.repositories) |repository| {
        if (!validUnsafeRepositoryId(repository.id)) return .unsupported;
    }
    switch (data.initramfs) {
        .unchanged => {},
        .regenerate => |regenerate| {
            if (regenerate.kernels.len == 0) return .unsupported;
            for (regenerate.kernels) |kernel| {
                if (!validUnsafeKernelRelease(kernel)) return .unsupported;
            }
            if (regenerate.generator) |generator| {
                if (!std.mem.eql(u8, generator, "dracut")) return .unsupported;
            }
        },
    }
    return platform.checkUnsafeChroot(io, plan);
}

/// Gates the `vm` backend on the plan shape it can actually execute, then
/// defers the host resource probe (emulator, accelerator, free space) to the
/// platform. Every rejection here happens before any output is touched.
fn vmCapabilityState(
    platform: Platform,
    io: Io,
    plan: *const ResolvedPlan,
) CapabilityState {
    const data = plan.data;
    const vm = data.execution.vm orelse return .unsupported;
    if (data.execution.backend != .vm or
        data.input != .disk or
        data.storage != .preserve or
        data.existing_path_operations.len != 0 or
        hasOsCustomization(data.os) or
        data.generalization != .none or
        data.selinux != .unchanged or
        !isDefaultBootPolicy(data.boot_security) or
        data.packages.cache != .online or
        data.packages.lock != .unlocked)
    {
        return .unsupported;
    }
    // Nothing in the guest executes caller-supplied scripts, so a plan that
    // carries hooks would silently drop them rather than run them.
    if (data.hooks.len != 0) return .unsupported;
    if (vm.acceleration == .hardware and
        data.architectures.runner != data.architectures.host)
    {
        return .unsupported;
    }
    if (data.architectures.runner != data.architectures.image) return .unsupported;
    for (data.packages.actions) |action| {
        const names = switch (action) {
            .install => |values| values,
            .remove => |values| values,
            .update_all, .update_selected => return .unsupported,
        };
        if (names.len == 0) return .unsupported;
        for (names) |name| {
            if (!validUnsafePackageName(name)) return .unsupported;
        }
    }
    for (data.packages.repositories) |repository| {
        if (!validUnsafeRepositoryId(repository.id)) return .unsupported;
    }
    switch (data.initramfs) {
        .unchanged => {},
        .regenerate => |regenerate| {
            if (regenerate.kernels.len == 0) return .unsupported;
            for (regenerate.kernels) |kernel| {
                if (!validUnsafeKernelRelease(kernel)) return .unsupported;
            }
            if (regenerate.generator) |generator| {
                if (!std.mem.eql(u8, generator, "dracut")) return .unsupported;
            }
        },
    }
    return platform.checkVm(io, plan);
}

fn validUnsafeRepositoryId(id: []const u8) bool {
    if (id.len == 0 or !std.ascii.isAlphanumeric(id[0])) return false;
    for (id[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '-')
        {
            return false;
        }
    }
    return true;
}

fn validUnsafePackageName(name: []const u8) bool {
    if (name.len == 0 or !std.ascii.isAlphanumeric(name[0])) return false;
    if (name.len >= 4 and
        std.ascii.eqlIgnoreCase(name[name.len - 4 ..], ".rpm"))
    {
        return false;
    }
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~' and
            byte != '^')
        {
            return false;
        }
    }
    return true;
}

fn validUnsafeKernelRelease(kernel: []const u8) bool {
    if (kernel.len == 0 or !std.ascii.isAlphanumeric(kernel[0])) return false;
    for (kernel[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~')
        {
            return false;
        }
    }
    return true;
}

fn systemCapabilityCheck(_: ?*anyopaque, io: Io, requirement: CapabilityRequirement) CapabilityState {
    const cwd = Io.Dir.cwd();
    return switch (requirement.kind) {
        .read_iso => if (isReadableKind(cwd, io, requirement.path, .file)) .available else .missing,
        .read_container => if (isReadablePath(cwd, io, requirement.path)) .available else .missing,
        .read_customization_file,
        .read_disk,
        .read_disk_dependency,
        .read_edit_source,
        .read_hook_source,
        .read_trust_source,
        => if (isReadableKind(cwd, io, requirement.path, .file)) .available else .missing,
        .disk_dependencies => .unsupported,
        .write_workspace_parent => if (canCreatePath(cwd, io, requirement.path)) .available else .missing,
        .write_output_parent => if (canCreatePath(cwd, io, requirement.path)) .available else .missing,
        .output_absent, .transaction_absent => if (pathAbsent(cwd, io, requirement.path)) .available else .missing,
        .path_isolation => blk: {
            const overlaps = canonicalPathsOverlap(cwd, io, requirement.path, requirement.related_path) orelse
                break :blk .unsupported;
            break :blk if (overlaps) .missing else .available;
        },
        .native_fresh,
        .native_edit,
        .partition_edit,
        .standalone_output,
        .atomic_commit,
        => .available,
        .rebuild,
        .unsafe_chroot,
        .vm,
        .package_management,
        .repository_access,
        .repository_trust,
        .package_cache,
        .package_lock,
        .script_execution,
        .guest_execution,
        .initramfs_regeneration,
        .selinux_policy,
        .selinux_relabel,
        .cross_architecture_runner,
        .arbitrary_filesystem_mutation,
        .boot_policy_mutation,
        .generalization,
        => .unsupported,
    };
}

fn diskDependenciesAvailable(
    io: Io,
    disk: ResolvedDiskInput,
    output_path: []const u8,
) CapabilityState {
    var image = image_mod.Image.openPathReadOnly(io, disk.path) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .unsupported,
    };
    defer image.close(io);
    const dependencies = image.sourceDependencyPaths(std.heap.page_allocator) catch return .unsupported;
    defer {
        for (dependencies) |path| std.heap.page_allocator.free(path);
        std.heap.page_allocator.free(dependencies);
    }
    if (!samePathSet(disk.dependencies, dependencies)) return .missing;
    for (disk.dependencies) |path| {
        if (!isReadableKind(Io.Dir.cwd(), io, path, .file)) return .missing;
        const overlaps = canonicalPathsOverlap(
            Io.Dir.cwd(),
            io,
            output_path,
            path,
        ) orelse return .unsupported;
        if (overlaps) return .missing;
    }
    return .available;
}

fn rebuildAvailable(io: Io, plan: *const ResolvedPlan) CapabilityState {
    const disk = switch (plan.data.input) {
        .disk => |value| value,
        .iso_oci => return .unsupported,
    };
    const storage = switch (plan.data.storage) {
        .preserve => |value| value,
        .fresh => return .unsupported,
    };
    const output_format = plan.data.output.format.imageFormat() orelse return .unsupported;
    _ = preserved_image.inspectRebuild(std.heap.page_allocator, io, .{
        .source_path = disk.path,
        .output_path = plan.data.staging_output_path,
        .output_format = output_format,
        .root_partition = storage.root_partition,
        .existing_operations = plan.data.existing_path_operations,
        .customization = plan.data.os,
        .generalization = plan.data.generalization,
        .source_date_epoch = plan.data.reproducibility.source_date_epoch,
        .expected_virtual_size = null,
        .output_create_options = outputCreateOptions(plan),
    }) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .unsupported,
    };
    return .available;
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

fn canonicalPathsOverlap(dir: Io.Dir, io: Io, first: []const u8, second: []const u8) ?bool {
    var first_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    var second_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const first_len = canonicalPath(dir, io, first, &first_buffer) orelse return null;
    const second_len = canonicalPath(dir, io, second, &second_buffer) orelse return null;
    const canonical_first = first_buffer[0..first_len];
    const canonical_second = second_buffer[0..second_len];
    return std.mem.eql(u8, canonical_first, canonical_second) or
        pathContains(canonical_second, canonical_first);
}

fn canonicalPath(dir: Io.Dir, io: Io, path: []const u8, buffer: *[Io.Dir.max_path_bytes]u8) ?usize {
    var absolute_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const absolute_path = if (std.fs.path.isAbsolute(path))
        path
    else blk: {
        const cwd_len = dir.realPathFile(io, ".", &absolute_buffer) catch return null;
        const separator_len: usize = @intFromBool(cwd_len != 0 and !std.fs.path.isSep(absolute_buffer[cwd_len - 1]));
        if (cwd_len + separator_len + path.len > absolute_buffer.len) return null;
        if (separator_len != 0) absolute_buffer[cwd_len] = std.fs.path.sep;
        @memcpy(absolute_buffer[cwd_len + separator_len ..][0..path.len], path);
        break :blk absolute_buffer[0 .. cwd_len + separator_len + path.len];
    };
    var candidate: []const u8 = absolute_path;
    while (true) {
        if (dir.realPathFile(io, candidate, buffer)) |len| {
            const suffix = absolute_path[candidate.len..];
            if (len + suffix.len > buffer.len) return null;
            @memcpy(buffer[len..][0..suffix.len], suffix);
            return len + suffix.len;
        } else |err| switch (err) {
            error.FileNotFound => {},
            else => return null,
        }

        const parent = std.fs.path.dirname(candidate) orelse return null;
        if (std.mem.eql(u8, parent, candidate)) return null;
        candidate = parent;
    }
}

fn isReadableKind(dir: Io.Dir, io: Io, path: []const u8, kind: Io.File.Kind) bool {
    dir.access(io, path, .{ .read = true }) catch return false;
    const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == kind;
}

fn isReadablePath(dir: Io.Dir, io: Io, path: []const u8) bool {
    dir.access(io, path, .{ .read = true }) catch return false;
    const stat = dir.statFile(io, path, .{ .follow_symlinks = false }) catch return false;
    return stat.kind == .file or stat.kind == .directory;
}

fn canWrite(dir: Io.Dir, io: Io, path: []const u8) bool {
    dir.access(io, path, .{ .write = true }) catch return false;
    const stat = dir.statFile(io, path, .{}) catch return false;
    return stat.kind == .directory;
}

fn canCreatePath(dir: Io.Dir, io: Io, path: []const u8) bool {
    var candidate = path;
    while (true) {
        if (dir.statFile(io, candidate, .{})) |stat| {
            if (stat.kind != .directory) return false;
            return canWrite(dir, io, candidate);
        } else |err| switch (err) {
            error.FileNotFound => {
                candidate = std.fs.path.dirname(candidate) orelse ".";
            },
            else => return false,
        }
    }
}

fn pathAbsent(dir: Io.Dir, io: Io, path: []const u8) bool {
    _ = dir.statFile(io, path, .{ .follow_symlinks = false }) catch |err| return err == error.FileNotFound;
    return false;
}

pub const SourceKind = enum {
    iso,
    container,
    customization_file,
    disk,
    disk_dependency,
    edit_source,
    hook_source,
    trust_source,
};

pub const SourceRecord = struct {
    kind: SourceKind,
    path: []const u8,
    sha256: Digest,
};

pub const ToolRecord = struct {
    name: []const u8,
    version: []const u8,
    command: []const []const u8,
};

pub const UnsafeChrootRuntimeReport = struct {
    arena: std.heap.ArenaAllocator,
    tools: []const ToolRecord,
    installed_packages: []const []const u8,

    pub fn deinit(self: *UnsafeChrootRuntimeReport) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

/// Where the guest's kernel and initramfs were copied from. Recorded so a
/// reader can tell which boot layout the run actually exercised without
/// re-inspecting the published image.
pub const VmBootOrigin = union(enum) {
    boot_directory: struct {
        kernel_path: []const u8,
        initrd_path: []const u8,
    },
    unified_kernel: struct {
        esp_path: []const u8,
    },
};

/// A driver the image's own kernel did not build in, read out of the image's
/// module tree and inserted by the guest agent before it touched a disk.
///
/// Recorded because a run that had to load drivers is a materially different
/// run from one that did not: it names the file inside the image that was
/// loaded, not merely the driver it provides, and the digest is of the object
/// as the guest received it.
pub const VmModuleRecord = struct {
    name: []const u8,
    image_path: []const u8,
    sha256: Digest,
};

/// What the emulator was, how it was configured, and exactly which bytes the
/// guest booted. `acceleration` is the accelerator that ran, not the one that
/// was requested — the backend never degrades silently, so the two always
/// agree, and recording the effective value keeps that checkable.
pub const VmExecutionRecord = struct {
    emulator_command: []const u8,
    emulator_version: []const u8,
    machine: []const u8,
    cpu: []const u8,
    acceleration: VmAcceleration,
    network: VmNetworkPolicy,
    memory_mib: u32,
    vcpus: u8,
    runner_architecture: Architecture,
    root_device: []const u8,
    kernel_release: []const u8,
    kernel_sha256: Digest,
    initrd_sha256: Digest,
    control_sha256: Digest,
    boot_origin: VmBootOrigin,
    /// Modules the guest inserted, in insertion order. Empty says the image's
    /// kernel needed no help, which is the case this backend started with.
    modules: []const VmModuleRecord = &.{},
};

pub const VmRuntimeReport = struct {
    arena: std.heap.ArenaAllocator,
    tools: []const ToolRecord,
    installed_packages: []const []const u8,
    execution: VmExecutionRecord,

    pub fn deinit(self: *VmRuntimeReport) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const ArtifactRecord = struct {
    path: []const u8,
    format: OutputFormat,
    size: u64,
    sha256: Digest,
};

pub const ResolvedConfiguration = struct {
    architectures: ArchitectureSet,
    input: ResolvedInput,
    output: ResolvedOutput,
    storage: ResolvedStorage,
    os: OsCustomization,
    existing_path_operations: []const ExistingPathOperation,
    packages: PackagePolicy,
    hooks: []const Hook,
    initramfs: InitramfsPolicy,
    selinux: SelinuxPolicy,
    cross_architecture: CrossArchitecturePolicy,
    boot_security: BootSecurityPolicy,
    generalization: GeneralizationPolicy,
    execution: ExecutionPolicy,
    operations: []const Operation,
};

pub const PartitionRecord = struct {
    name: []const u8,
    role: layout.PartitionRole,
    offset_bytes: u64,
    length_bytes: u64,
    unique_guid: ?Guid,
    mbr_disk_signature: ?u32,
};

pub const VhdxMetadataRecord = struct {
    header_sequence_number: u64,
    file_write_guid: Guid,
    data_write_guid: Guid,
    page83_guid: Guid,
};

pub const VerityRecord = struct {
    format: u32,
    hash_algorithm: []const u8,
    data_block_size: u32,
    hash_block_size: u32,
    data_blocks: u64,
    hash_offset: u64,
    hash_tree_size: u64,
    salt: Digest,
    root_hash: Digest,
};

pub const PartitionStyleRecord = struct {
    ok: bool,
    message: []const u8,
};

pub const PreservedExecutionRecord = struct {
    source_format: Format,
    output_format: Format,
    virtual_size: u64,
    selected_partition: PartitionSelector,
    partition_offset: u64,
    partition_length: u64,
    flattened_backing_chain: bool,
    operation_count: usize,
    installed_packages: []const []const u8,
    rebuild: ?PreservedRebuildRecord,
};

pub const PreservedRebuildRecord = struct {
    profile: ext4.StrictProfile,
    ext4_uuid: Uuid,
    ext4_label: [16]u8,
    ext4_block_size: u32,
    filesystem_length: u64,
    ext4_global_timestamp: u32,
    source_root_tree_digest: Digest,
    final_root_tree_digest: Digest,
    imported_node_count: usize,
    final_node_count: usize,
    existing_operation_count: usize,
    os_customization_count: usize,
    generalization_count: usize,
};

pub const ExecutionRecord = struct {
    rootfs_path_in_iso: []const u8,
    root_tree_digest: ?Digest,
    partitions: []const PartitionRecord,
    verity: ?VerityRecord,
    vhd_alignment: ?azure.FixupResult,
    partition_style: ?PartitionStyleRecord,
    vhdx_metadata: ?VhdxMetadataRecord,
    preserved: ?PreservedExecutionRecord,
    vm: ?VmExecutionRecord,
};

pub const Provenance = struct {
    schema_version: u32 = provenance_schema_version,
    plan_hash: Digest,
    sources: []const SourceRecord,
    resolved: ResolvedConfiguration,
    output_identifiers: OutputIdentifiers,
    generated: ?GeneratedIdentifiers,
    reproducibility: Reproducibility,
    tools: []const ToolRecord,
    execution: ExecutionRecord,
    final_output: ArtifactRecord,
};

pub const Result = struct {
    arena: std.heap.ArenaAllocator,
    output_path: []const u8,
    provenance: Provenance,

    fn deinit(self: *Result, _: Allocator) void {
        self.arena.deinit();
        self.* = undefined;
    }
};

pub const ExecutionEvent = union(enum) {
    progress: Progress,
    diagnostic: Diagnostic,
};

pub const Progress = struct {
    phase: DiagnosticPhase,
    message: []const u8,
};

pub const EventSink = struct {
    context: ?*anyopaque = null,
    emitFn: *const fn (context: ?*anyopaque, event: ExecutionEvent) void,

    fn emit(self: EventSink, event: ExecutionEvent) void {
        self.emitFn(self.context, event);
    }
};

pub const ExecutionOutcome = struct {
    diagnostics: DiagnosticSet,
    result: ?Result,

    pub fn deinit(self: *ExecutionOutcome, allocator: Allocator) void {
        self.diagnostics.deinit(allocator);
        if (self.result) |*result| result.deinit(allocator);
        self.* = undefined;
    }
};

fn ownDiagnosticSet(allocator: Allocator, diagnostics: []const Diagnostic) Allocator.Error!DiagnosticSet {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = try dupeDiagnostics(arena.allocator(), diagnostics, 0);
    return .{ .items = owned, .arena = arena };
}

fn ownDiagnosticSetWithCleanupSlot(
    allocator: Allocator,
    diagnostics: []const Diagnostic,
    transaction_path: []const u8,
) Allocator.Error!DiagnosticSet {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const owned = try dupeDiagnostics(arena.allocator(), diagnostics, 1);
    owned[owned.len - 1] = .{
        .severity = .info,
        .phase = .cleanup,
        .code = .cleanup_completed,
        .configuration_path = try arena.allocator().dupe(u8, transaction_path),
        .message = "transaction artifacts were removed",
    };
    return .{ .items = owned, .arena = arena };
}

fn dupeDiagnostics(
    allocator: Allocator,
    diagnostics: []const Diagnostic,
    extra_items: usize,
) Allocator.Error![]Diagnostic {
    const owned = try allocator.alloc(Diagnostic, diagnostics.len + extra_items);
    for (diagnostics, 0..) |diagnostic, index| {
        const command = if (diagnostic.command) |command_value| blk: {
            const argv = try allocator.alloc([]const u8, command_value.argv.len);
            for (command_value.argv, 0..) |arg, arg_index| argv[arg_index] = try allocator.dupe(u8, arg);
            break :blk CommandDiagnostic{
                .argv = argv,
                .exit_status = command_value.exit_status,
            };
        } else null;
        owned[index] = .{
            .severity = diagnostic.severity,
            .phase = diagnostic.phase,
            .code = diagnostic.code,
            .configuration_path = try allocator.dupe(u8, diagnostic.configuration_path),
            .message = try allocator.dupe(u8, diagnostic.message),
            .cause = if (diagnostic.cause) |cause| .{
                .error_name = try allocator.dupe(u8, cause.error_name),
            } else null,
            .command = command,
            .remediation = if (diagnostic.remediation) |remediation| try allocator.dupe(u8, remediation) else null,
        };
    }
    return owned;
}

fn failureOutcome(allocator: Allocator, diagnostics: []const Diagnostic) Allocator.Error!ExecutionOutcome {
    return .{
        .diagnostics = try ownDiagnosticSet(allocator, diagnostics),
        .result = null,
    };
}

/// Only one guest backend can have run, so the reports are alternatives rather
/// than a merge: taking the first present one keeps provenance describing a
/// single execution.
fn guestPackages(
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
    vm_report: ?*const VmRuntimeReport,
) []const []const u8 {
    if (unsafe_report) |report| return report.installed_packages;
    if (vm_report) |report| return report.installed_packages;
    return &.{};
}

fn guestTools(
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
    vm_report: ?*const VmRuntimeReport,
) []const ToolRecord {
    if (unsafe_report) |report| return report.tools;
    if (vm_report) |report| return report.tools;
    return &.{};
}

fn buildResult(
    allocator: Allocator,
    plan: *const ResolvedPlan,
    fresh_report: ?*const build_image.BuildImageReport,
    preserved_report: ?*const preserved_image.Report,
    rebuild_report: ?*const preserved_image.RebuildReport,
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
    vm_report: ?*const VmRuntimeReport,
    source_digests: []const SourceRecord,
    output_digest: Digest,
    output_file_size: u64,
) Allocator.Error!Result {
    var arena = std.heap.ArenaAllocator.init(allocator);
    errdefer arena.deinit();
    const result_allocator = arena.allocator();

    const output_path = try result_allocator.dupe(u8, plan.data.output.path);
    const input: ResolvedInput = switch (plan.data.input) {
        .iso_oci => |value| .{ .iso_oci = .{
            .iso_path = try result_allocator.dupe(u8, value.iso_path),
            .container_path = try result_allocator.dupe(u8, value.container_path),
            .rootfs_path_in_iso = try result_allocator.dupe(u8, value.rootfs_path_in_iso),
        } },
        .disk => |value| .{ .disk = .{
            .path = try result_allocator.dupe(u8, value.path),
            .dependencies = try dupeStrings(result_allocator, value.dependencies),
        } },
    };
    const sources = try result_allocator.alloc(SourceRecord, source_digests.len);
    for (source_digests, 0..) |source, index| {
        sources[index] = .{
            .kind = source.kind,
            .path = try result_allocator.dupe(u8, source.path),
            .sha256 = source.sha256,
        };
    }
    const resolved_output = ResolvedOutput{
        .path = output_path,
        .format = plan.data.output.format,
        .requested_size = plan.data.output.requested_size,
        .disk_size = plan.data.output.disk_size,
        .size_policy = plan.data.output.size_policy,
    };
    const resolved_storage: ResolvedStorage = switch (plan.data.storage) {
        .fresh => |storage| .{ .fresh = .{
            .generation = storage.generation,
            .esp_size = storage.esp_size,
            .ext4_label = try result_allocator.dupe(u8, storage.ext4_label),
            .skip_iso_rootfs = storage.skip_iso_rootfs,
        } },
        .preserve => |storage| .{ .preserve = storage },
    };
    const resolved_execution = ExecutionPolicy{
        .workspace_path = try result_allocator.dupe(u8, plan.data.execution.workspace_path),
        .backend = plan.data.execution.backend,
        .overwrite = plan.data.execution.overwrite,
        .acknowledge_unsafe = plan.data.execution.acknowledge_unsafe,
        .vm = try dupeVmPolicy(result_allocator, plan.data.execution.vm),
    };
    const resolved_boot = try dupeBootPolicy(result_allocator, plan.data.boot_security);
    const resolved_os = try dupeOsCustomization(result_allocator, plan.data.os, null);
    const resolved_existing_operations = try dupeExistingPathOperations(
        result_allocator,
        plan.data.existing_path_operations,
        null,
    );
    const resolved_packages = try dupePackagePolicy(result_allocator, plan.data.packages, null);
    const resolved_hooks = try dupeHooks(result_allocator, plan.data.hooks, null);
    const resolved_initramfs = try dupeInitramfsPolicy(result_allocator, plan.data.initramfs);
    const resolved_selinux = try dupeSelinuxPolicy(result_allocator, plan.data.selinux);
    const resolved_cross_architecture = try dupeCrossArchitecturePolicy(
        result_allocator,
        plan.data.cross_architecture,
    );
    const resolved_generalization = try dupeGeneralization(result_allocator, plan.data.generalization);
    const operations = try dupeOperations(result_allocator, plan.data.operations);
    const partitions = if (fresh_report) |build_report| blk: {
        const records = try result_allocator.alloc(PartitionRecord, build_report.planned_partitions.len);
        for (build_report.planned_partitions, 0..) |partition, index| {
            records[index] = .{
                .name = try result_allocator.dupe(u8, partition.planned.name),
                .role = partition.planned.role,
                .offset_bytes = partition.planned.offset_bytes,
                .length_bytes = partition.planned.length_bytes,
                .unique_guid = if (partition.mbr_disk_signature == null) .{ .bytes = partition.unique_guid } else null,
                .mbr_disk_signature = partition.mbr_disk_signature,
            };
        }
        break :blk records;
    } else &.{};
    const verity_record = if (fresh_report) |build_report|
        if (build_report.verity) |verity_info| VerityRecord{
            .format = verity_info.format,
            .hash_algorithm = try result_allocator.dupe(u8, verity_info.hashAlgorithm),
            .data_block_size = verity_info.dataBlockSize,
            .hash_block_size = verity_info.hashBlockSize,
            .data_blocks = verity_info.dataBlocks,
            .hash_offset = verity_info.hashOffset,
            .hash_tree_size = verity_info.hashTreeSize,
            .salt = .{ .bytes = verity_info.salt },
            .root_hash = .{ .bytes = verity_info.rootHash },
        } else null
    else
        null;
    const partition_style = if (fresh_report) |build_report|
        if (build_report.partition_style) |style| PartitionStyleRecord{
            .ok = style.ok,
            .message = try result_allocator.dupe(u8, style.message),
        } else null
    else
        null;
    const actual_rootfs_path = if (fresh_report) |build_report|
        try result_allocator.dupe(u8, build_report.rootfs_path_in_iso)
    else switch (input) {
        .iso_oci => |iso_oci| iso_oci.rootfs_path_in_iso,
        .disk => "",
    };
    const preserved_record = if (preserved_report != null or rebuild_report != null) blk: {
        const source_format = if (preserved_report) |report| report.source_format else rebuild_report.?.source_format;
        const output_format = if (preserved_report) |report| report.output_format else rebuild_report.?.output_format;
        const virtual_size = if (preserved_report) |report| report.virtual_size else rebuild_report.?.virtual_size;
        const partition_offset = if (preserved_report) |report| report.partition_offset else rebuild_report.?.partition_offset;
        const partition_length = if (preserved_report) |report| report.partition_length else rebuild_report.?.partition_length;
        const flattened = if (preserved_report) |report| report.flattened_backing_chain else rebuild_report.?.flattened_backing_chain;
        const operation_count = if (preserved_report) |report| report.operation_count else rebuild_report.?.existing_operation_count;
        break :blk PreservedExecutionRecord{
            .source_format = source_format,
            .output_format = output_format,
            .virtual_size = virtual_size,
            .selected_partition = plan.data.storage.preserve.root_partition,
            .partition_offset = partition_offset,
            .partition_length = partition_length,
            .flattened_backing_chain = flattened,
            .operation_count = operation_count,
            .installed_packages = try dupeStrings(result_allocator, guestPackages(unsafe_report, vm_report)),
            .rebuild = if (rebuild_report) |report| .{
                .profile = report.strict_profile,
                .ext4_uuid = .{ .bytes = report.ext4_uuid },
                .ext4_label = report.ext4_label,
                .ext4_block_size = report.ext4_block_size,
                .filesystem_length = report.filesystem_length,
                .ext4_global_timestamp = report.ext4_global_timestamp,
                .source_root_tree_digest = .{ .bytes = report.source_manifest_sha256 },
                .final_root_tree_digest = .{ .bytes = report.final_manifest_sha256 },
                .imported_node_count = report.imported_node_count,
                .final_node_count = report.final_node_count,
                .existing_operation_count = report.existing_operation_count,
                .os_customization_count = report.os_customization_count,
                .generalization_count = report.generalization_count,
            } else null,
        };
    } else null;
    const tools = blk: {
        const source = guestTools(unsafe_report, vm_report);
        const owned = try result_allocator.alloc(ToolRecord, source.len);
        for (source, 0..) |tool, index| {
            owned[index] = .{
                .name = try result_allocator.dupe(u8, tool.name),
                .version = try result_allocator.dupe(u8, tool.version),
                .command = try dupeStrings(result_allocator, tool.command),
            };
        }
        break :blk owned;
    };
    const vm_record = if (vm_report) |report| blk: {
        const record = report.execution;
        const modules = try result_allocator.alloc(VmModuleRecord, record.modules.len);
        for (record.modules, modules) |source, *target| {
            target.* = .{
                .name = try result_allocator.dupe(u8, source.name),
                .image_path = try result_allocator.dupe(u8, source.image_path),
                .sha256 = source.sha256,
            };
        }
        break :blk VmExecutionRecord{
            .emulator_command = try result_allocator.dupe(u8, record.emulator_command),
            .emulator_version = try result_allocator.dupe(u8, record.emulator_version),
            .machine = try result_allocator.dupe(u8, record.machine),
            .cpu = try result_allocator.dupe(u8, record.cpu),
            .acceleration = record.acceleration,
            .network = record.network,
            .memory_mib = record.memory_mib,
            .vcpus = record.vcpus,
            .runner_architecture = record.runner_architecture,
            .root_device = try result_allocator.dupe(u8, record.root_device),
            .kernel_release = try result_allocator.dupe(u8, record.kernel_release),
            .kernel_sha256 = record.kernel_sha256,
            .initrd_sha256 = record.initrd_sha256,
            .control_sha256 = record.control_sha256,
            .boot_origin = switch (record.boot_origin) {
                .boot_directory => |boot| .{ .boot_directory = .{
                    .kernel_path = try result_allocator.dupe(u8, boot.kernel_path),
                    .initrd_path = try result_allocator.dupe(u8, boot.initrd_path),
                } },
                .unified_kernel => |unified| .{ .unified_kernel = .{
                    .esp_path = try result_allocator.dupe(u8, unified.esp_path),
                } },
            },
            .modules = modules,
        };
    } else null;

    return .{
        .arena = arena,
        .output_path = output_path,
        .provenance = .{
            .plan_hash = plan.data.plan_hash,
            .sources = sources,
            .resolved = .{
                .architectures = plan.data.architectures,
                .input = input,
                .output = resolved_output,
                .storage = resolved_storage,
                .os = resolved_os,
                .existing_path_operations = resolved_existing_operations,
                .packages = resolved_packages,
                .hooks = resolved_hooks,
                .initramfs = resolved_initramfs,
                .selinux = resolved_selinux,
                .cross_architecture = resolved_cross_architecture,
                .boot_security = resolved_boot,
                .generalization = resolved_generalization,
                .execution = resolved_execution,
                .operations = operations,
            },
            .output_identifiers = plan.data.output_identifiers,
            .generated = plan.data.generated,
            .reproducibility = plan.data.reproducibility,
            .tools = tools,
            .execution = .{
                .rootfs_path_in_iso = actual_rootfs_path,
                .root_tree_digest = if (fresh_report) |build_report|
                    if (build_report.root_tree_digest) |digest| .{ .bytes = digest } else null
                else
                    null,
                .partitions = partitions,
                .verity = verity_record,
                .vhd_alignment = if (fresh_report) |build_report| build_report.vhd_alignment else null,
                .partition_style = partition_style,
                .vhdx_metadata = if (fresh_report) |build_report|
                    if (build_report.vhdx_metadata) |metadata| .{
                        .header_sequence_number = metadata.header_sequence_number,
                        .file_write_guid = .{ .bytes = metadata.file_write_guid },
                        .data_write_guid = .{ .bytes = metadata.data_write_guid },
                        .page83_guid = .{ .bytes = metadata.page83_guid },
                    } else null
                else
                    null,
                .preserved = preserved_record,
                .vm = vm_record,
            },
            .final_output = .{
                .path = output_path,
                .format = plan.data.output.format,
                .size = output_file_size,
                .sha256 = output_digest,
            },
        },
    };
}

fn dupeOperations(allocator: Allocator, operations: []const Operation) Allocator.Error![]Operation {
    const owned = try allocator.alloc(Operation, operations.len);
    for (operations, 0..) |operation, index| {
        owned[index] = .{
            .id = operation.id,
            .phase = operation.phase,
            .depends_on = try allocator.dupe(u16, operation.depends_on),
            .action = operation.action,
        };
    }
    return owned;
}

pub fn execute(
    allocator: Allocator,
    io: Io,
    plan: *const ResolvedPlan,
    platform: Platform,
    event_sink: ?EventSink,
) Allocator.Error!ExecutionOutcome {
    var diagnostics = std.array_list.Managed(Diagnostic).init(allocator);
    defer diagnostics.deinit();
    try diagnostics.ensureTotalCapacity(8);

    if (!try hasValidPlanIntegrity(allocator, plan)) {
        try diagnostics.append(.{
            .severity = .@"error",
            .phase = .execution,
            .code = .invalid_plan,
            .configuration_path = "/",
            .message = "the resolved plan failed its integrity or backend invariant checks",
            .remediation = "execute the immutable plan returned by resolve without modification",
        });
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    }

    var preflight_report = try preflight(allocator, io, plan, platform);
    defer preflight_report.deinit(allocator);
    try diagnostics.appendSlice(preflight_report.diagnostics.items);
    if (!preflight_report.ready()) {
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    }

    const source_digests_before = hashPlanSources(allocator, io, plan) catch |err| {
        try appendFailure(&diagnostics, .source_hash_failed, .execution, "/input", "failed to hash a declared source", err);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    defer freeSourceRecords(allocator, source_digests_before);

    const cwd = Io.Dir.cwd();
    cwd.createDirPath(io, plan.data.execution.workspace_path) catch |err| {
        try appendFailure(&diagnostics, .execution_failed, .execution, "/execution/workspace_path", "failed to create the workspace", err);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    cwd.createDir(io, plan.data.transaction_path, .default_dir) catch |err| {
        try appendFailure(&diagnostics, .execution_failed, .execution, "/execution/workspace_path", "failed to create the transaction directory", err);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    var transaction_active = true;
    errdefer if (transaction_active) {
        _ = cleanupTransaction(io, plan.data.transaction_path);
    };

    var bridge = BuildEventBridge{
        .event_sink = event_sink,
        .diagnostics = &diagnostics,
    };
    var fresh_report: ?build_image.BuildImageReport = null;
    defer if (fresh_report) |*report| report.deinit(allocator);
    var preserved_report: ?preserved_image.Report = null;
    var rebuild_report: ?preserved_image.RebuildReport = null;
    var unsafe_report: ?UnsafeChrootRuntimeReport = null;
    defer if (unsafe_report) |*report| report.deinit();
    var vm_report: ?VmRuntimeReport = null;
    defer if (vm_report) |*report| report.deinit();
    switch (plan.data.execution.backend) {
        .native_fresh => {
            fresh_report = runPlan(allocator, io, plan, platform, event_sink, &bridge) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "", "native-fresh execution failed", err);
                if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
                emitDiagnostics(event_sink, diagnostics.items);
                return try failureOutcome(allocator, diagnostics.items);
            };
        },
        .native_edit => {
            if (event_sink) |sink| sink.emit(.{ .progress = .{
                .phase = .execution,
                .message = "copy and edit preserved disk",
            } });
            preserved_report = preserved_image.edit(allocator, io, .{
                .source_path = plan.data.input.disk.path,
                .output_path = plan.data.staging_output_path,
                .output_format = plan.data.output.format.imageFormat().?,
                .root_partition = plan.data.storage.preserve.root_partition,
                .operations = plan.data.existing_path_operations,
                .expected_virtual_size = null,
                .output_create_options = outputCreateOptions(plan),
            }) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "/existing_path_operations", "native preserved-image execution failed", err);
                if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
                emitDiagnostics(event_sink, diagnostics.items);
                return try failureOutcome(allocator, diagnostics.items);
            };
        },
        .rebuild => {
            if (event_sink) |sink| sink.emit(.{ .progress = .{
                .phase = .execution,
                .message = "extract, customize, and rebuild preserved ext4 root",
            } });
            rebuild_report = preserved_image.rebuild(allocator, io, .{
                .source_path = plan.data.input.disk.path,
                .output_path = plan.data.staging_output_path,
                .output_format = plan.data.output.format.imageFormat().?,
                .root_partition = plan.data.storage.preserve.root_partition,
                .existing_operations = plan.data.existing_path_operations,
                .customization = plan.data.os,
                .generalization = plan.data.generalization,
                .source_date_epoch = plan.data.reproducibility.source_date_epoch,
                .expected_virtual_size = null,
                .output_create_options = outputCreateOptions(plan),
            }) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "/execution/backend", "strict preserved-image rebuild failed", err);
                if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
                emitDiagnostics(event_sink, diagnostics.items);
                return try failureOutcome(allocator, diagnostics.items);
            };
        },
        .unsafe_chroot => {
            if (event_sink) |sink| sink.emit(.{ .progress = .{
                .phase = .execution,
                .message = "run package and initramfs policy in an isolated unsafe chroot worker",
            } });
            var hook_context = UnsafeChrootHookContext{
                .platform = platform,
                .plan = plan,
            };
            defer if (hook_context.report) |*report| report.deinit();
            const raw_report = preserved_image.transactRaw(allocator, io, .{
                .source_path = plan.data.input.disk.path,
                .output_path = plan.data.staging_output_path,
                .output_format = plan.data.output.format.imageFormat().?,
                .root_partition = plan.data.storage.preserve.root_partition,
                .require_linux_partition = true,
                .output_create_options = outputCreateOptions(plan),
            }, .{
                .context = &hook_context,
                .runFn = runUnsafeChrootHook,
            }) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "/execution/backend", "unsafe chroot preserved-image execution failed", err);
                if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
                emitDiagnostics(event_sink, diagnostics.items);
                return try failureOutcome(allocator, diagnostics.items);
            };
            unsafe_report = hook_context.report;
            hook_context.report = null;
            preserved_report = .{
                .source_format = raw_report.source_format,
                .output_format = raw_report.output_format,
                .virtual_size = raw_report.virtual_size,
                .partition_offset = raw_report.partition_offset,
                .partition_length = raw_report.partition_length,
                .flattened_backing_chain = raw_report.flattened_backing_chain,
                .operation_count = plan.data.packages.actions.len +
                    @intFromBool(plan.data.initramfs != .unchanged),
            };
        },
        .vm => {
            if (event_sink) |sink| sink.emit(.{ .progress = .{
                .phase = .execution,
                .message = "run package and initramfs policy inside an isolated virtual machine",
            } });
            var hook_context = VmHookContext{
                .platform = platform,
                .plan = plan,
            };
            defer if (hook_context.report) |*report| report.deinit();
            const raw_report = preserved_image.transactRaw(allocator, io, .{
                .source_path = plan.data.input.disk.path,
                .output_path = plan.data.staging_output_path,
                .output_format = plan.data.output.format.imageFormat().?,
                .root_partition = plan.data.storage.preserve.root_partition,
                .require_linux_partition = true,
                .output_create_options = outputCreateOptions(plan),
            }, .{
                .context = &hook_context,
                .runFn = runVmHook,
            }) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "/execution/backend", "virtual machine preserved-image execution failed", err);
                if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
                emitDiagnostics(event_sink, diagnostics.items);
                return try failureOutcome(allocator, diagnostics.items);
            };
            vm_report = hook_context.report;
            hook_context.report = null;
            preserved_report = .{
                .source_format = raw_report.source_format,
                .output_format = raw_report.output_format,
                .virtual_size = raw_report.virtual_size,
                .partition_offset = raw_report.partition_offset,
                .partition_length = raw_report.partition_length,
                .flattened_backing_chain = raw_report.flattened_backing_chain,
                .operation_count = plan.data.packages.actions.len +
                    @intFromBool(plan.data.initramfs != .unchanged),
            };
        },
    }

    var commit_barrier = transaction_guard.seal(
        io,
        plan.data.transaction_path,
    ) catch |err| {
        try appendFailure(
            &diagnostics,
            .cleanup_failed,
            .cleanup,
            plan.data.transaction_path,
            "could not seal the backend transaction before final verification",
            err,
        );
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    defer commit_barrier.release(io);

    const source_digests_after = hashPlanSources(allocator, io, plan) catch |err| {
        try appendFailure(&diagnostics, .source_hash_failed, .execution, "/input", "failed to verify a declared source hash", err);
        commit_barrier.release(io);
        if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    defer freeSourceRecords(allocator, source_digests_after);
    if (!sourceRecordsEqual(source_digests_before, source_digests_after)) {
        try diagnostics.append(.{
            .severity = .@"error",
            .phase = .execution,
            .code = .source_changed,
            .configuration_path = "/input",
            .message = "a source changed while the image was being built",
            .remediation = "retry with immutable or cache-snapshotted inputs",
        });
        commit_barrier.release(io);
        if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    }

    const output_digest = hashPath(allocator, io, plan.data.staging_output_path) catch |err| {
        try appendFailure(&diagnostics, .source_hash_failed, .execution, "/output/path", "failed to hash the completed output", err);
        commit_barrier.release(io);
        if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    const output_file_size = (cwd.statFile(io, plan.data.staging_output_path, .{}) catch |err| {
        try appendFailure(&diagnostics, .execution_failed, .execution, "/output/path", "failed to inspect the completed output", err);
        commit_barrier.release(io);
        if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    }).size;

    var result = try buildResult(
        allocator,
        plan,
        if (fresh_report) |*report| report else null,
        if (preserved_report) |*report| report else null,
        if (rebuild_report) |*report| report else null,
        if (unsafe_report) |*report| report else null,
        if (vm_report) |*report| report else null,
        source_digests_before,
        output_digest,
        output_file_size,
    );
    var result_owned_by_function = true;
    errdefer if (result_owned_by_function) result.deinit(allocator);
    var final_diagnostics = try ownDiagnosticSetWithCleanupSlot(
        allocator,
        diagnostics.items,
        plan.data.transaction_path,
    );
    var final_diagnostics_owned_by_function = true;
    errdefer if (final_diagnostics_owned_by_function) final_diagnostics.deinit(allocator);

    const commit_result = if (plan.data.execution.overwrite)
        cwd.rename(plan.data.staging_output_path, cwd, plan.data.output.path, io)
    else
        cwd.renamePreserve(plan.data.staging_output_path, cwd, plan.data.output.path, io);
    commit_result catch |err| {
        commit_barrier.release(io);
        result.deinit(allocator);
        final_diagnostics.deinit(allocator);
        final_diagnostics_owned_by_function = false;
        result_owned_by_function = false;
        const cleanup_diagnostic = cleanupTransaction(io, plan.data.transaction_path);
        transaction_active = false;
        try appendFailure(&diagnostics, .commit_failed, .execution, "/output/path", "failed to atomically commit the completed output", err);
        if (cleanup_diagnostic) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };

    commit_barrier.release(io);
    const cleanup_failure = cleanupTransaction(io, plan.data.transaction_path);
    transaction_active = false;
    const cleanup_slot = &final_diagnostics.items[final_diagnostics.items.len - 1];
    if (cleanup_failure != null) {
        cleanup_slot.severity = .warning;
        cleanup_slot.code = .cleanup_failed;
        cleanup_slot.message = "failed to remove the transaction directory";
    }
    if (event_sink) |sink| sink.emit(.{ .diagnostic = cleanup_slot.* });
    final_diagnostics_owned_by_function = false;
    result_owned_by_function = false;
    return .{
        .diagnostics = final_diagnostics,
        .result = result,
    };
}

const UnsafeChrootHookContext = struct {
    platform: Platform,
    plan: *const ResolvedPlan,
    report: ?UnsafeChrootRuntimeReport = null,
};

fn runUnsafeChrootHook(
    context_ptr: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    target: preserved_image.RawMutationTarget,
) !void {
    const context: *UnsafeChrootHookContext = @ptrCast(@alignCast(context_ptr.?));
    const run_fn = context.platform.unsafeChrootRunFn orelse
        return error.UnsafeChrootRunnerUnavailable;
    context.report = try run_fn(
        context.platform.context,
        allocator,
        io,
        context.plan,
        target,
    );
}

const VmHookContext = struct {
    platform: Platform,
    plan: *const ResolvedPlan,
    report: ?VmRuntimeReport = null,
};

fn runVmHook(
    context_ptr: ?*anyopaque,
    allocator: Allocator,
    io: Io,
    target: preserved_image.RawMutationTarget,
) !void {
    const context: *VmHookContext = @ptrCast(@alignCast(context_ptr.?));
    const run_fn = context.platform.vmRunFn orelse return error.VmRunnerUnavailable;
    context.report = try run_fn(
        context.platform.context,
        allocator,
        io,
        context.plan,
        target,
    );
}

fn hasValidPlanIntegrity(allocator: Allocator, plan: *const ResolvedPlan) Allocator.Error!bool {
    const data = plan.data;
    const computed_hash = hashPlan(data.*);
    if (data.schema_version != plan_schema_version or
        data.request_api_version != current_api_version or
        data.output.format.imageFormat() == null or
        !std.mem.eql(u8, &computed_hash.bytes, &data.plan_hash.bytes))
    {
        return false;
    }
    var expected_generated = deriveIdentifiers(data.reproducibility.seed);
    const expected_transaction_id = deriveTransactionId(data.reproducibility.seed, data.output.path);
    expected_generated.transaction_id = expected_transaction_id;
    if (!std.meta.eql(data.transaction_id, expected_transaction_id) or
        !std.meta.eql(data.output_identifiers, outputIdentifiers(expected_generated)))
    {
        return false;
    }
    switch (data.execution.backend) {
        .native_fresh => {
            if (data.input != .iso_oci or data.storage != .fresh or data.generated == null or
                data.output.size_policy != .explicit)
            {
                return false;
            }
            if (!std.meta.eql(data.generated.?, expected_generated)) return false;
            if (data.storage.fresh.generation == .gen1 and data.architectures.image != .x86_64) return false;
        },
        .native_edit, .rebuild, .unsafe_chroot, .vm => {
            if (data.input != .disk or data.storage != .preserve or data.generated != null or
                data.output.size_policy != .preserve_source or data.output.requested_size != 0 or
                data.output.disk_size != 0)
            {
                return false;
            }
        },
    }
    if ((data.execution.backend == .vm) != (data.execution.vm != null)) return false;
    if (!try hasExpectedOperations(allocator, plan)) return false;
    const needs_guest_execution = data.execution.backend == .unsafe_chroot or
        data.execution.backend == .vm or
        data.packages.actions.len != 0 or
        data.hooks.len != 0 or
        data.initramfs != .unchanged or
        data.selinux != .unchanged;
    if (needs_guest_execution and data.architectures.image != data.architectures.host) {
        switch (data.cross_architecture) {
            .reject => return false,
            .runner => |runner| {
                if (runner.guest_architecture != data.architectures.image or
                    data.architectures.runner != data.architectures.image or
                    (data.execution.backend == .vm and runner.kind != .vm) or
                    (data.execution.backend == .unsafe_chroot and runner.kind == .vm))
                {
                    return false;
                }
            },
        }
    }
    if (data.execution.backend == .unsafe_chroot and !data.execution.acknowledge_unsafe) return false;
    if (data.hooks.len != 0 and
        (!data.execution.acknowledge_unsafe or
            (data.execution.backend != .unsafe_chroot and data.execution.backend != .vm)))
    {
        return false;
    }
    const output_parent = std.fs.path.dirname(data.output.path) orelse ".";
    if (!std.mem.eql(u8, output_parent, data.execution.workspace_path)) return false;

    const transaction_hex = std.fmt.bytesToHex(data.transaction_id.bytes, .lower);
    const transaction_name = try std.fmt.allocPrint(allocator, ".zvmi-{s}", .{transaction_hex});
    defer allocator.free(transaction_name);
    const expected_transaction = try std.fs.path.join(allocator, &.{ data.execution.workspace_path, transaction_name });
    defer allocator.free(expected_transaction);
    const expected_staging = try std.fs.path.join(allocator, &.{ expected_transaction, "output.img" });
    defer allocator.free(expected_staging);
    return std.mem.eql(u8, expected_transaction, data.transaction_path) and
        std.mem.eql(u8, expected_staging, data.staging_output_path);
}

fn runPlan(
    allocator: Allocator,
    io: Io,
    plan: *const ResolvedPlan,
    platform: Platform,
    event_sink: ?EventSink,
    bridge: *BuildEventBridge,
) !?build_image.BuildImageReport {
    if (plan.data.execution.backend != .native_fresh) return error.InvalidBackend;
    var stage_bridge = NativeStageBridge{ .operations = plan.data.operations };
    const stage_sink = build_image.StageSink{ .context = &stage_bridge, .advanceFn = NativeStageBridge.advance };
    if (platform.runFn) |run| {
        try run(platform.context, allocator, io, plan, event_sink, stage_sink);
        if (stage_bridge.next != plan.data.operations.len) return error.InvalidOperationOrder;
        return null;
    }
    var options = buildOptionsFromPlan(plan, bridge);
    options.stage_sink = stage_sink;
    var report = try build_image.build(allocator, io, options);
    errdefer report.deinit(allocator);
    if (stage_bridge.next != plan.data.operations.len) return error.InvalidOperationOrder;
    return report;
}

fn buildOptionsFromPlan(plan: *const ResolvedPlan, bridge: *BuildEventBridge) build_image.BuildImageOptions {
    const generated = plan.data.generated.?;
    const input = plan.data.input.iso_oci;
    const storage = plan.data.storage.fresh;
    return .{
        .iso_path = input.iso_path,
        .container_path = input.container_path,
        .output_path = plan.data.staging_output_path,
        .size = plan.data.output.disk_size,
        .generation = storage.generation,
        .output_format = plan.data.output.format.imageFormat().?,
        .rootfs_path_in_iso = input.rootfs_path_in_iso,
        .skip_iso_rootfs = storage.skip_iso_rootfs,
        .os = plan.data.os,
        .generalization = plan.data.generalization,
        .esp_size = storage.esp_size,
        .ext4_label = storage.ext4_label,
        .verity = plan.data.boot_security.verity,
        .extra_kernel_options = plan.data.boot_security.extra_kernel_options,
        .boot_mode = plan.data.boot_security.boot_mode,
        .uki = .{
            .stub_source_path = plan.data.boot_security.uki.stub_source_path,
            .os_release_source_path = plan.data.boot_security.uki.os_release_source_path,
            .splash_source_path = plan.data.boot_security.uki.splash_source_path,
            .output_directory = plan.data.boot_security.uki.output_directory,
        },
        .architecture = plan.data.architectures.image,
        .deterministic = .{
            .disk_guid = generated.disk_guid.bytes,
            .esp_partition_guid = generated.esp_partition_guid.bytes,
            .root_partition_guid = generated.root_partition_guid.bytes,
            .mbr_disk_signature = generated.mbr_disk_signature,
            .root_filesystem_uuid = generated.root_filesystem_uuid.bytes,
            .verity_salt = generated.verity_salt.bytes,
            .filesystem_timestamp = @intCast(plan.data.reproducibility.source_date_epoch),
            .output_create_options = .{
                .unique_id = generated.output_unique_id.bytes,
                .timestamp_unix = @intCast(plan.data.reproducibility.source_date_epoch),
                .vhdx = .{
                    .header_sequence_base = generated.vhdx_header_sequence_base,
                    .file_write_guid = generated.vhdx_file_write_guid.bytes,
                    .data_write_guid = generated.vhdx_data_write_guid.bytes,
                    .page83_guid = generated.vhdx_page83_guid.bytes,
                    .write_guid_seed = generated.vhdx_write_guid_seed.bytes,
                },
            },
        },
        .event_sink = .{ .context = bridge, .emitFn = BuildEventBridge.emit },
    };
}

const NativeStageBridge = struct {
    operations: []const Operation,
    next: usize = 0,

    fn advance(context: ?*anyopaque, stage: build_image.Stage) bool {
        const self: *NativeStageBridge = @ptrCast(@alignCast(context.?));
        if (self.next >= self.operations.len) return false;
        const operation = self.operations[self.next];
        if (operation.action != actionForFreshStage(stage)) return false;
        for (operation.depends_on) |dependency| {
            if (dependency >= self.next) return false;
        }
        self.next += 1;
        return true;
    }
};

fn actionForFreshStage(stage: build_image.Stage) Action {
    return switch (stage) {
        .load_sources => .load_sources,
        .apply_filesystem_changes => .apply_filesystem_changes,
        .generalize_and_cleanup => .generalize_and_cleanup,
        .prepare_initramfs => .prepare_initramfs,
        .prepare_boot_configuration => .prepare_boot_configuration,
        .populate_filesystem => .populate_filesystem,
        .seal_verity => .seal_verity,
        .install_bootloader => .install_bootloader,
        .generate_uki => .generate_uki,
        .check_and_close_filesystems => .check_and_close_filesystems,
        .convert_output => .convert_output,
    };
}

fn freshStageForAction(action: Action) ?build_image.Stage {
    return switch (action) {
        .load_sources => .load_sources,
        .apply_filesystem_changes => .apply_filesystem_changes,
        .generalize_and_cleanup => .generalize_and_cleanup,
        .prepare_initramfs => .prepare_initramfs,
        .prepare_boot_configuration => .prepare_boot_configuration,
        .populate_filesystem => .populate_filesystem,
        .seal_verity => .seal_verity,
        .install_bootloader => .install_bootloader,
        .generate_uki => .generate_uki,
        .check_and_close_filesystems => .check_and_close_filesystems,
        .convert_output => .convert_output,
        else => null,
    };
}

fn outputCreateOptions(plan: *const ResolvedPlan) image_mod.CreateOptions {
    const identifiers = plan.data.output_identifiers;
    return .{
        .vhd_subformat = .fixed,
        .unique_id = identifiers.output_unique_id.bytes,
        .timestamp_unix = @intCast(plan.data.reproducibility.source_date_epoch),
        .vhdx = .{
            .header_sequence_base = identifiers.vhdx_header_sequence_base,
            .file_write_guid = identifiers.vhdx_file_write_guid.bytes,
            .data_write_guid = identifiers.vhdx_data_write_guid.bytes,
            .page83_guid = identifiers.vhdx_page83_guid.bytes,
            .write_guid_seed = identifiers.vhdx_write_guid_seed.bytes,
        },
    };
}

const BuildEventBridge = struct {
    event_sink: ?EventSink,
    diagnostics: *std.array_list.Managed(Diagnostic),

    fn emit(context: ?*anyopaque, event: build_image.Event) void {
        const self: *BuildEventBridge = @ptrCast(@alignCast(context.?));
        switch (event) {
            .progress => |message| {
                if (self.event_sink) |sink| {
                    sink.emit(.{ .progress = .{ .phase = .execution, .message = message } });
                }
            },
            .warning => |warning| {
                const diagnostic = Diagnostic{
                    .severity = .warning,
                    .phase = .execution,
                    .code = .runtime_warning,
                    .configuration_path = "",
                    .message = warning.message,
                };
                self.diagnostics.appendAssumeCapacity(diagnostic);
                if (self.event_sink) |sink| sink.emit(.{ .diagnostic = diagnostic });
            },
        }
    }
};

fn appendFailure(
    diagnostics: *std.array_list.Managed(Diagnostic),
    code: DiagnosticCode,
    phase: DiagnosticPhase,
    path: []const u8,
    message: []const u8,
    err: anyerror,
) Allocator.Error!void {
    try diagnostics.append(.{
        .severity = .@"error",
        .phase = phase,
        .code = code,
        .configuration_path = path,
        .message = message,
        .cause = .{ .error_name = @errorName(err) },
    });
}

fn cleanupTransaction(io: Io, transaction_path: []const u8) ?Diagnostic {
    var barrier = transaction_guard.seal(io, transaction_path) catch |err| {
        return .{
            .severity = .warning,
            .phase = .cleanup,
            .code = .cleanup_failed,
            .configuration_path = transaction_path,
            .message = "refused to remove a transaction that could not be sealed against backend leases",
            .cause = .{ .error_name = @errorName(err) },
        };
    };
    barrier.release(io);
    Io.Dir.cwd().deleteTree(io, transaction_path) catch |err| {
        return .{
            .severity = .warning,
            .phase = .cleanup,
            .code = .cleanup_failed,
            .configuration_path = transaction_path,
            .message = "failed to remove the transaction directory",
            .cause = .{ .error_name = @errorName(err) },
        };
    };
    transaction_guard.finishCleanup(io, transaction_path) catch |err| {
        return .{
            .severity = .warning,
            .phase = .cleanup,
            .code = .cleanup_failed,
            .configuration_path = transaction_path,
            .message = "removed the transaction but failed to remove its external cleanup seal",
            .cause = .{ .error_name = @errorName(err) },
        };
    };
    return null;
}

fn emitDiagnostics(event_sink: ?EventSink, diagnostics: []const Diagnostic) void {
    const sink = event_sink orelse return;
    for (diagnostics) |diagnostic| sink.emit(.{ .diagnostic = diagnostic });
}

const HashEntry = struct {
    path: []u8,
    kind: Io.File.Kind,
};

fn hashPlanSources(
    allocator: Allocator,
    io: Io,
    plan: *const ResolvedPlan,
) ![]SourceRecord {
    var records = std.array_list.Managed(SourceRecord).init(allocator);
    errdefer {
        for (records.items) |record| allocator.free(record.path);
        records.deinit();
    }

    switch (plan.data.input) {
        .iso_oci => |input| {
            try appendHashedSource(&records, allocator, io, .iso, input.iso_path);
            try appendHashedSource(&records, allocator, io, .container, input.container_path);
        },
        .disk => |input| {
            if (diskDependenciesAvailable(io, input, plan.data.output.path) != .available) {
                return error.DiskDependencyMismatch;
            }
            try appendHashedSource(&records, allocator, io, .disk, input.path);
            for (input.dependencies) |path| {
                try appendHashedSource(&records, allocator, io, .disk_dependency, path);
            }
        },
    }
    for (plan.data.os.filesystem) |operation| switch (operation) {
        .put_file => |file| switch (file.source) {
            .inline_bytes => {},
            .host_path => |path| try appendHashedSource(&records, allocator, io, .customization_file, path),
        },
        else => {},
    };
    for (plan.data.existing_path_operations) |operation| switch (operation) {
        .overwrite_file => |overwrite| switch (overwrite.source) {
            .bytes => {},
            .host_path => |path| try appendHashedSource(&records, allocator, io, .edit_source, path),
        },
        .remove_file, .remove_tree => {},
    };
    for (plan.data.hooks) |hook| switch (hook.source) {
        .inline_script => {},
        .host_path => |path| try appendHashedSource(&records, allocator, io, .hook_source, path),
    };
    for (plan.data.packages.repositories) |repository| for (repository.trust) |trust| switch (trust) {
        .inline_bytes => {},
        .host_path => |path| try appendHashedSource(&records, allocator, io, .trust_source, path),
    };
    return records.toOwnedSlice();
}

fn appendHashedSource(
    records: *std.array_list.Managed(SourceRecord),
    allocator: Allocator,
    io: Io,
    kind: SourceKind,
    path: []const u8,
) !void {
    for (records.items) |record| {
        if (record.kind == kind and std.mem.eql(u8, record.path, path)) return;
    }
    const owned_path = try allocator.dupe(u8, path);
    errdefer allocator.free(owned_path);
    try records.append(.{
        .kind = kind,
        .path = owned_path,
        .sha256 = try hashPath(allocator, io, path),
    });
}

fn freeSourceRecords(allocator: Allocator, records: []SourceRecord) void {
    for (records) |record| allocator.free(record.path);
    allocator.free(records);
}

fn sourceRecordsEqual(left: []const SourceRecord, right: []const SourceRecord) bool {
    if (left.len != right.len) return false;
    for (left, right) |left_record, right_record| {
        if (left_record.kind != right_record.kind or
            !std.mem.eql(u8, left_record.path, right_record.path) or
            !std.mem.eql(u8, &left_record.sha256.bytes, &right_record.sha256.bytes))
        {
            return false;
        }
    }
    return true;
}

fn hashPath(allocator: Allocator, io: Io, path: []const u8) !Digest {
    const stat = try Io.Dir.cwd().statFile(io, path, .{ .follow_symlinks = false });
    return switch (stat.kind) {
        .file => hashFile(io, Io.Dir.cwd(), path),
        .directory => hashDirectory(allocator, io, path),
        else => error.UnsupportedSourceEntry,
    };
}

pub fn hashSourcePath(allocator: Allocator, io: Io, path: []const u8) !Digest {
    return hashPath(allocator, io, path);
}

fn hashFile(io: Io, dir: Io.Dir, path: []const u8) !Digest {
    const file = try dir.openFile(io, path, .{});
    defer file.close(io);
    const size = (try file.stat(io)).size;

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    var buffer: [64 * 1024]u8 = undefined;
    var offset: u64 = 0;
    while (offset < size) {
        const length: usize = @intCast(@min(size - offset, buffer.len));
        const read = try file.readPositionalAll(io, buffer[0..length], offset);
        if (read != length) return error.ShortRead;
        hash.update(buffer[0..length]);
        offset += length;
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .bytes = digest };
}

fn hashDirectory(allocator: Allocator, io: Io, path: []const u8) !Digest {
    var dir = try Io.Dir.cwd().openDir(io, path, .{ .iterate = true });
    defer dir.close(io);
    var walker = try dir.walk(allocator);
    defer walker.deinit();
    var entries = std.array_list.Managed(HashEntry).init(allocator);
    defer {
        for (entries.items) |entry| allocator.free(entry.path);
        entries.deinit();
    }

    while (try walker.next(io)) |entry| {
        if (entry.kind != .file and entry.kind != .directory) return error.UnsupportedSourceEntry;
        try entries.append(.{
            .path = try allocator.dupe(u8, entry.path),
            .kind = entry.kind,
        });
    }
    std.mem.sortUnstable(HashEntry, entries.items, {}, struct {
        fn lessThan(_: void, lhs: HashEntry, rhs: HashEntry) bool {
            return std.mem.lessThan(u8, lhs.path, rhs.path);
        }
    }.lessThan);

    var hash = std.crypto.hash.sha2.Sha256.init(.{});
    hash.update("zvmi-directory-hash-v1\x00");
    for (entries.items) |entry| {
        hashString(&hash, entry.path);
        hashInt(&hash, @intFromEnum(entry.kind));
        if (entry.kind == .file) {
            const digest = try hashFile(io, dir, entry.path);
            hash.update(&digest.bytes);
        }
    }
    var digest: [32]u8 = undefined;
    hash.final(&digest);
    return .{ .bytes = digest };
}

pub fn writeRequestJson(request: Request, writer: *Io.Writer) !void {
    try std.json.Stringify.value(request, .{ .whitespace = .indent_2 }, writer);
}

pub fn writePlanJson(plan: *const ResolvedPlan, writer: *Io.Writer) !void {
    try std.json.Stringify.value(plan.data, .{ .whitespace = .indent_2 }, writer);
}

pub fn writeDiagnosticsJson(diagnostics: DiagnosticSet, writer: *Io.Writer) !void {
    try std.json.Stringify.value(diagnostics.items, .{ .whitespace = .indent_2 }, writer);
}

pub fn writeProvenanceJson(provenance: Provenance, writer: *Io.Writer) !void {
    try std.json.Stringify.value(provenance, .{ .whitespace = .indent_2 }, writer);
}

fn validRequest() Request {
    return .{
        .target_architecture = .x86_64,
        .input = .{ .iso_oci = .{
            .iso_path = "source.iso",
            .container_path = "oci-layout",
            .rootfs_path_in_iso = "images/rootfs.squashfs",
        } },
        .output = .{
            .path = "output.qcow2",
            .format = .qcow2,
            .size = 128 * mib,
        },
        .storage = .{ .fresh = .{} },
        .execution = .{ .workspace_path = "." },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x5A} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
}

const customize_test_disk_size: u64 = 32 * mib;
const customize_test_partition_first_lba: u32 = 2048;
const customize_test_partition_sectors: u32 = 48 * 1024;

fn createCustomizeTestDisk(io: Io, path: []const u8, spool_path: []const u8) !void {
    var image = try image_mod.Image.createExclusive(io, path, .raw, customize_test_disk_size, .{});
    defer image.close(io);
    const boot_record = mbr.singleLinuxPartitionMbr(
        customize_test_partition_first_lba,
        customize_test_partition_sectors,
    ).encode();
    try image.pwrite(io, &boot_record, 0);

    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try root_tree.RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/config", "before\n", .{ .mode = 0o640, .uid = 12, .gid = 34 });
    try tree.putFileBytes("etc/remove", "remove\n", .{ .mode = 0o644 });
    try tree.putDirectory("var", .{ .mode = 0o755 });
    try tree.putDirectory("var/drop", .{ .mode = 0o700 });
    try tree.putFileBytes("var/drop/item", "drop\n", .{ .mode = 0o600 });
    _ = try ext4.populate(io, image.file, std.testing.allocator, try tree.ext4View(), .{
        .offset = @as(u64, customize_test_partition_first_lba) * mbr.sector_size,
        .length = @as(u64, customize_test_partition_sectors) * mbr.sector_size,
        .label = "customize-root",
        .uuid = [_]u8{0x63} ** 16,
        .timestamp = 1_735_689_600,
    });
}

fn validNativeEditRequest(
    source_path: []const u8,
    output_path: []const u8,
    workspace_path: []const u8,
    operations: []const ExistingPathOperation,
) Request {
    return .{
        .target_architecture = .x86_64,
        .input = .{ .disk = .{ .path = source_path } },
        .output = .{
            .path = output_path,
            .format = .raw,
            .size_policy = .preserve_source,
        },
        .storage = .{ .preserve = .{
            .root_partition = .{ .mbr_index = 1 },
        } },
        .existing_path_operations = operations,
        .execution = .{
            .workspace_path = workspace_path,
            .backend = .native_edit,
        },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0xA7} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
}

/// A VM policy that passes validation, so tests can isolate the property they
/// are actually exercising.
fn validVmPolicy() VmPolicy {
    return .{
        .emulator_command = "/usr/bin/qemu-system-x86_64",
        .acceleration = .software,
        .acknowledge_software_emulation = true,
    };
}

fn hasDiagnosticCode(diagnostics: DiagnosticSet, code: DiagnosticCode) bool {
    for (diagnostics.items) |diagnostic| {
        if (diagnostic.code == code) return true;
    }
    return false;
}

test "unsafe chroot platform executes the supported preserved subset" {
    const io = std.testing.io;
    const source_path = "test-customize-unsafe-source.raw";
    const spool_path = "test-customize-unsafe-spool";
    const workspace_path = "test-customize-unsafe-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, source_path, spool_path);
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    const actions = [_]PackageAction{.{ .remove = &.{"obsolete"} }};
    var request = validNativeEditRequest(
        source_path,
        output_path,
        workspace_path,
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.packages.actions = &actions;

    const FakeUnsafe = struct {
        fn check(
            _: ?*anyopaque,
            _: Io,
            _: *const ResolvedPlan,
        ) CapabilityState {
            return .available;
        }

        fn run(
            context_ptr: ?*anyopaque,
            allocator: Allocator,
            _: Io,
            plan: *const ResolvedPlan,
            target: preserved_image.RawMutationTarget,
        ) !UnsafeChrootRuntimeReport {
            const called: *bool = @ptrCast(@alignCast(context_ptr.?));
            called.* = true;
            try std.testing.expect(target.partition.length != 0);
            try std.testing.expectEqual(
                @as(usize, 1),
                plan.data.packages.actions.len,
            );
            return .{
                .arena = std.heap.ArenaAllocator.init(allocator),
                .tools = &.{.{
                    .name = "tdnf",
                    .version = "tdnf 3.5.0",
                    .command = &.{ "/usr/bin/tdnf", "remove", "obsolete" },
                }},
                .installed_packages = &.{"base-files-0:1.0-1.x86_64"},
            };
        }
    };

    var called = false;
    var platform = Platform.system();
    platform.context = &called;
    platform.unsafeChrootCheckFn = FakeUnsafe.check;
    platform.unsafeChrootRunFn = FakeUnsafe.run;
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    var report = try preflight(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        platform,
    );
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(report.ready());

    var outcome = try execute(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(called);
    try std.testing.expect(outcome.result != null);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    try std.testing.expectEqual(
        @as(usize, 1),
        outcome.result.?.provenance.tools.len,
    );
    try std.testing.expectEqualStrings(
        "tdnf 3.5.0",
        outcome.result.?.provenance.tools[0].version,
    );
    try std.testing.expectEqualStrings(
        "base-files-0:1.0-1.x86_64",
        outcome.result.?.provenance.execution.preserved.?.installed_packages[0],
    );
    _ = try Io.Dir.cwd().statFile(io, output_path, .{});
}

test "unsafe chroot preflight accepts only the implemented policy subset" {
    const Check = struct {
        fn available(
            _: ?*anyopaque,
            _: Io,
            _: *const ResolvedPlan,
        ) CapabilityState {
            return .available;
        }

        fn state(
            request: *const Request,
            host_architecture: Architecture,
        ) !CapabilityState {
            var resolved = try resolve(
                std.testing.allocator,
                request,
                .{ .host_architecture = host_architecture },
            );
            defer resolved.deinit(std.testing.allocator);
            try std.testing.expect(resolved.plan != null);
            var platform = Platform.system();
            platform.unsafeChrootCheckFn = available;
            return unsafeChrootCapabilityState(
                platform,
                std.testing.io,
                &resolved.plan.?,
            );
        }
    };

    const install = [_]PackageAction{.{ .install = &.{"dracut"} }};
    const update = [_]PackageAction{.update_all};
    const invalid_package = [_]PackageAction{.{ .install = &.{"payload.rpm"} }};
    const valid_repository = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    const invalid_repository = [_]PackageRepository{.{
        .id = "*",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    var baseline = validNativeEditRequest(
        "source.raw",
        "unsafe-policy-work/output.raw",
        "unsafe-policy-work",
        &.{},
    );
    baseline.execution.backend = .unsafe_chroot;
    baseline.execution.acknowledge_unsafe = true;
    baseline.packages = .{
        .actions = &install,
        .repositories = &valid_repository,
    };
    baseline.initramfs = .{ .regenerate = .{
        .generator = "dracut",
        .kernels = &.{"6.12.0-test"},
    } };
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&baseline, .x86_64),
    );

    var request = baseline;
    request.packages.actions = &invalid_package;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.repositories = &invalid_repository;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.initramfs = .{ .regenerate = .{
        .generator = "dracut",
        .kernels = &.{"../../etc/passwd"},
    } };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.cache = .cache_only;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.lock = .{ .snapshot = "snapshot-1" };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.actions = &update;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.target_architecture = .aarch64;
    request.cross_architecture = .{ .runner = .{
        .kind = .qemu_user,
        .guest_architecture = .aarch64,
        .command = "qemu-aarch64",
    } };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    const existing_operations = [_]ExistingPathOperation{.{
        .overwrite_file = .{
            .path = "/etc/hostname",
            .source = .{ .bytes = "guest\n" },
        },
    }};
    request = baseline;
    request.existing_path_operations = &existing_operations;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.os.hostname = "guest";
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.generalization = .{ .azure = .{} };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    const hooks = [_]Hook{.{
        .name = "unsupported",
        .phase = .finalize,
        .source = .{ .inline_script = "true" },
    }};
    request = baseline;
    request.hooks = &hooks;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );
}

test "v2 native-fresh requests require the explicit adapter" {
    var request_v2 = RequestV2{
        .target_architecture = .x86_64,
        .input = .{ .iso_oci = .{
            .iso_path = "source.iso",
            .container_path = "oci-layout",
            .rootfs_path_in_iso = "images/rootfs.squashfs",
        } },
        .output = .{
            .path = "output.raw",
            .format = .raw,
            .size = 128 * mib,
        },
        .storage = .{ .fresh = .{} },
        .execution = .{ .workspace_path = "." },
        .reproducibility = .{
            .seed = .{ .bytes = [_]u8{0x19} ** 32 },
            .source_date_epoch = 1_735_689_600,
        },
    };
    const adapted = try adaptV2NativeFresh(&request_v2);
    try std.testing.expectEqual(current_api_version, adapted.api_version);
    try std.testing.expectEqual(ExecutionBackend.native_fresh, adapted.execution.backend);
    try std.testing.expect(adapted.input == .iso_oci);
    try std.testing.expect(adapted.storage == .fresh);
    try std.testing.expectEqual(OutputSizePolicy.explicit, adapted.output.size_policy);

    var disguised_v2 = adapted;
    disguised_v2.api_version = legacy_api_version;
    var diagnostics = try validate(std.testing.allocator, &disguised_v2);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(diagnostics, .unsupported_api_version));

    request_v2.execution.backend = .chroot;
    try std.testing.expectError(error.UnsupportedV2Backend, adaptV2NativeFresh(&request_v2));
    request_v2.execution.backend = .native;
    request_v2.storage = .preserve;
    try std.testing.expectError(error.UnsupportedV2Storage, adaptV2NativeFresh(&request_v2));
}

test "v3 validation models the backend and unsafe execution matrix" {
    const no_operations: []const ExistingPathOperation = &.{};
    var native_edit = validNativeEditRequest(
        "source.raw",
        "native-edit-work/output.raw",
        "native-edit-work",
        no_operations,
    );
    inline for (.{ ExecutionBackend.native_edit, .rebuild, .unsafe_chroot, .vm }) |backend| {
        native_edit.execution.backend = backend;
        native_edit.execution.acknowledge_unsafe = backend == .unsafe_chroot;
        native_edit.execution.vm = if (backend == .vm) validVmPolicy() else null;
        var diagnostics = try validate(std.testing.allocator, &native_edit);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(!diagnostics.hasErrors());
    }
    native_edit.execution.vm = null;

    native_edit.execution.backend = .native_fresh;
    var wrong_shape = try validate(std.testing.allocator, &native_edit);
    defer wrong_shape.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(wrong_shape, .unsupported_input));
    try std.testing.expect(hasDiagnosticCode(wrong_shape, .unsupported_storage));

    native_edit.execution.backend = .native_edit;
    native_edit.storage.preserve.root_partition = .{ .gpt_index = 0 };
    var bad_partition = try validate(std.testing.allocator, &native_edit);
    defer bad_partition.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(bad_partition, .invalid_partition_selector));

    const hooks = [_]Hook{.{
        .name = "unsafe-script",
        .phase = .finalize,
        .source = .{ .inline_script = "#!/bin/sh\ntrue\n" },
    }};
    native_edit.storage.preserve.root_partition = .{ .mbr_index = 1 };
    native_edit.hooks = &hooks;
    var unsafe_missing = try validate(std.testing.allocator, &native_edit);
    defer unsafe_missing.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(unsafe_missing, .unsupported_execution_backend));
    try std.testing.expect(hasDiagnosticCode(unsafe_missing, .unsafe_acknowledgement_required));

    native_edit.execution.backend = .unsafe_chroot;
    native_edit.execution.acknowledge_unsafe = true;
    var unsafe_explicit = try validate(std.testing.allocator, &native_edit);
    defer unsafe_explicit.deinit(std.testing.allocator);
    try std.testing.expect(!unsafe_explicit.hasErrors());
}

test "cross-architecture guest execution requires an explicit compatible runner" {
    const hooks = [_]Hook{.{
        .name = "guest-script",
        .phase = .finalize,
        .source = .{ .inline_script = "#!/bin/sh\ntrue\n" },
    }};
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.target_architecture = .aarch64;
    request.execution.backend = .vm;
    request.execution.acknowledge_unsafe = true;
    request.execution.vm = .{
        .emulator_command = "/usr/bin/qemu-system-aarch64",
        .acceleration = .software,
    };
    request.hooks = &hooks;

    var rejected = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer rejected.deinit(std.testing.allocator);
    try std.testing.expect(rejected.plan == null);
    try std.testing.expect(hasDiagnosticCode(rejected.diagnostics, .incompatible_architecture));

    request.cross_architecture = .{ .runner = .{
        .kind = .vm,
        .guest_architecture = .aarch64,
        .command = "qemu-system-aarch64",
    } };
    var accepted = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expect(accepted.plan != null);
    var saw_runner_capability = false;
    for (accepted.plan.?.data.required_capabilities) |capability| {
        saw_runner_capability = saw_runner_capability or capability.kind == .cross_architecture_runner;
    }
    try std.testing.expect(saw_runner_capability);
}

test "hook phases remain ordered in validation and resolved operations" {
    const unordered_hooks = [_]Hook{
        .{ .name = "final", .phase = .finalize, .source = .{ .inline_script = "true" } },
        .{ .name = "early", .phase = .after_packages, .source = .{ .inline_script = "true" } },
    };
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.hooks = &unordered_hooks;
    var unordered = try validate(std.testing.allocator, &request);
    defer unordered.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(unordered, .invalid_policy));

    const ordered_hooks = [_]Hook{
        .{ .name = "packages", .phase = .after_packages, .source = .{ .inline_script = "true" } },
        .{ .name = "initramfs", .phase = .before_initramfs, .source = .{ .inline_script = "true" } },
        .{ .name = "seal", .phase = .before_seal, .source = .{ .inline_script = "true" } },
        .{ .name = "final", .phase = .finalize, .source = .{ .inline_script = "true" } },
    };
    request.hooks = &ordered_hooks;
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    var phases: [4]Phase = undefined;
    var count: usize = 0;
    for (resolved.plan.?.data.operations) |operation| {
        if (operation.action == .execute_hook) {
            phases[count] = operation.phase;
            count += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, phases.len), count);
    try std.testing.expectEqualSlices(
        Phase,
        &.{ .after_packages, .before_initramfs, .before_seal, .finalize },
        &phases,
    );
    try std.testing.expectEqual(
        Action.publish_standalone_output,
        resolved.plan.?.data.operations[resolved.plan.?.data.operations.len - 1].action,
    );
}

test "unimplemented typed policies become semantic preflight requirements" {
    const io = std.testing.io;
    const source_path = "test-customize-policy-source.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    {
        const source = try Io.Dir.cwd().createFile(io, source_path, .{});
        source.close(io);
    }
    const remove_packages = [_][]const u8{"old-package"};
    const package_actions = [_]PackageAction{.{ .remove = &remove_packages }};
    var request = validNativeEditRequest(source_path, "policy-output.raw", ".", &.{});
    request.packages = .{
        .actions = &package_actions,
        .cache = .cache_only,
        .lock = .{ .snapshot = "snapshot-2026-07-15" },
    };
    request.initramfs = .{ .regenerate = .{ .generator = "dracut" } };
    request.selinux = .{ .configure = .{
        .mode = .enforcing,
        .policy = "targeted",
        .relabel = true,
    } };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    var saw_package = false;
    var saw_initramfs = false;
    var saw_selinux = false;
    var saw_relabel = false;
    for (resolved.plan.?.data.required_capabilities) |capability| switch (capability.kind) {
        .package_management => saw_package = true,
        .initramfs_regeneration => saw_initramfs = true,
        .selinux_policy => saw_selinux = true,
        .selinux_relabel => saw_relabel = true,
        else => {},
    };
    try std.testing.expect(saw_package and saw_initramfs and saw_selinux and saw_relabel);

    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(!report.ready());
    for (report.capabilities) |capability| switch (capability.requirement.kind) {
        .package_management, .initramfs_regeneration, .selinux_policy, .selinux_relabel => {
            try std.testing.expectEqual(CapabilityState.unsupported, capability.state);
        },
        else => {},
    };
}

test "unsupported guest-code backends fail preflight before workspace mutation" {
    const io = std.testing.io;
    const source_path = "test-customize-unsupported-source.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    {
        const source = try Io.Dir.cwd().createFile(io, source_path, .{});
        defer source.close(io);
        try source.writePositionalAll(io, "readable-source", 0);
    }

    const cases = [_]struct {
        backend: ExecutionBackend,
        workspace: []const u8,
        output: []const u8,
    }{
        .{ .backend = .unsafe_chroot, .workspace = "test-customize-chroot-work", .output = "test-customize-chroot-work/output.raw" },
        .{ .backend = .vm, .workspace = "test-customize-vm-work", .output = "test-customize-vm-work/output.raw" },
    };
    for (cases) |case| {
        defer Io.Dir.cwd().deleteTree(io, case.workspace) catch {};
        var request = validNativeEditRequest(source_path, case.output, case.workspace, &.{});
        request.execution.backend = case.backend;
        request.execution.acknowledge_unsafe = case.backend == .unsafe_chroot;
        request.execution.vm = if (case.backend == .vm) validVmPolicy() else null;
        var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan != null);

        var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
        defer report.deinit(std.testing.allocator);
        try std.testing.expect(!report.ready());
        var saw_unsupported = false;
        for (report.capabilities) |capability| {
            if ((capability.requirement.kind == .rebuild or
                capability.requirement.kind == .unsafe_chroot or
                capability.requirement.kind == .vm) and capability.state == .unsupported)
            {
                saw_unsupported = true;
            }
        }
        try std.testing.expect(saw_unsupported);

        var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, Platform.system(), null);
        defer outcome.deinit(std.testing.allocator);
        try std.testing.expect(outcome.result == null);
        try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, case.workspace, .{}));
        try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, case.output, .{}));
    }
}

test "the vm backend requires an explicit and self-consistent VM policy" {
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .vm;

    // A VM backend without a policy is rejected rather than given host defaults.
    {
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));
    }

    // A policy is equally meaningless to every other backend.
    {
        var stray = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
        stray.execution.vm = validVmPolicy();
        var diagnostics = try validate(std.testing.allocator, &stray);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));
    }

    const install = [_]PackageAction{.{ .install = &.{"vim"} }};
    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.com/base"},
        .trust = &.{.{ .inline_bytes = "key" }},
    }};

    const cases = [_]struct {
        name: []const u8,
        policy: VmPolicy,
        packages: PackagePolicy = .{},
    }{
        .{ .name = "empty emulator", .policy = .{ .emulator_command = "" } },
        .{ .name = "relative emulator", .policy = .{
            .emulator_command = "qemu-system-x86_64",
            .acceleration = .software,
            .acknowledge_software_emulation = true,
        } },
        .{ .name = "memory below floor", .policy = blk: {
            var policy = validVmPolicy();
            policy.memory_mib = min_vm_memory_mib - 1;
            break :blk policy;
        } },
        .{ .name = "memory above ceiling", .policy = blk: {
            var policy = validVmPolicy();
            policy.memory_mib = max_vm_memory_mib + 1;
            break :blk policy;
        } },
        .{ .name = "no vcpus", .policy = blk: {
            var policy = validVmPolicy();
            policy.vcpus = 0;
            break :blk policy;
        } },
        .{ .name = "no boot timeout", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot_timeout_seconds = 0;
            break :blk policy;
        } },
        .{ .name = "boot timeout above ceiling", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot_timeout_seconds = max_vm_boot_timeout_seconds + 1;
            break :blk policy;
        } },
        .{ .name = "firmware without a code path", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot = .{ .firmware = .{
                .code_path = "",
                .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
            } };
            break :blk policy;
        } },
        .{ .name = "relative firmware vars path", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot = .{ .firmware = .{
                .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
                .vars_path = "OVMF_VARS.fd",
            } };
            break :blk policy;
        } },
        .{ .name = "empty machine override", .policy = blk: {
            var policy = validVmPolicy();
            policy.machine = "";
            break :blk policy;
        } },
        .{ .name = "empty cpu override", .policy = blk: {
            var policy = validVmPolicy();
            policy.cpu = "";
            break :blk policy;
        } },
        .{
            .name = "online packages in an offline guest",
            .policy = validVmPolicy(),
            .packages = .{ .actions = &install, .repositories = &repositories },
        },
        .{
            .name = "networking without declared repositories",
            .policy = blk: {
                var policy = validVmPolicy();
                policy.network = .declared_repositories;
                break :blk policy;
            },
        },
    };

    for (cases) |case| {
        request.execution.vm = case.policy;
        request.packages = case.packages;
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy)) catch |err| {
            std.debug.print("expected rejection for case '{s}'\n", .{case.name});
            return err;
        };
    }

    // The same request with a coherent policy validates, so the cases above
    // each isolate one property rather than a shared mistake.
    request.execution.vm = validVmPolicy();
    request.packages = .{};
    var accepted = try validate(std.testing.allocator, &request);
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expect(!accepted.hasErrors());
}

test "firmware boot is a valid policy that no backend implements yet" {
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .vm;
    var policy = validVmPolicy();
    policy.boot = .{ .firmware = .{
        .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
        .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
    } };
    request.execution.vm = policy;

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!diagnostics.hasErrors());

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    try std.testing.expect(resolved.plan.?.data.execution.vm.?.boot == .firmware);
}

test "vm acceleration is resolved against the runner architecture" {
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .vm;

    // Hardware acceleration cannot cross architectures, so it is rejected
    // rather than quietly degraded to software emulation.
    request.target_architecture = .aarch64;
    request.cross_architecture = .{ .runner = .{
        .kind = .vm,
        .guest_architecture = .aarch64,
        .command = "qemu-system-aarch64",
    } };
    request.execution.vm = .{
        .emulator_command = "/usr/bin/qemu-system-aarch64",
        .acceleration = .hardware,
    };
    var foreign = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer foreign.deinit(std.testing.allocator);
    try std.testing.expect(foreign.plan == null);
    try std.testing.expect(hasDiagnosticCode(foreign.diagnostics, .incompatible_architecture));

    // Software emulation on a native runner is a large silent cost, so it must
    // be acknowledged.
    request.target_architecture = .x86_64;
    request.cross_architecture = .reject;
    request.execution.vm = .{
        .emulator_command = "/usr/bin/qemu-system-x86_64",
        .acceleration = .software,
    };
    var unacknowledged = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer unacknowledged.deinit(std.testing.allocator);
    try std.testing.expect(unacknowledged.plan == null);
    try std.testing.expect(hasDiagnosticCode(unacknowledged.diagnostics, .invalid_policy));

    request.execution.vm.?.acknowledge_software_emulation = true;
    var acknowledged = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer acknowledged.deinit(std.testing.allocator);
    try std.testing.expect(acknowledged.plan != null);
}

test "a vm plan whose policy was stripped fails integrity before mutation" {
    const io = std.testing.io;
    const source_path = "test-customize-vm-integrity.raw";
    const workspace_path = "test-customize-vm-integrity-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    {
        const source = try Io.Dir.cwd().createFile(io, source_path, .{});
        defer source.close(io);
        try source.writePositionalAll(io, "readable-source", 0);
    }

    var request = validNativeEditRequest(source_path, output_path, workspace_path, &.{});
    request.execution.backend = .vm;
    request.execution.vm = validVmPolicy();
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);

    @constCast(resolved.plan.?.data).execution.vm = null;
    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(!report.ready());
    try std.testing.expectEqual(DiagnosticCode.invalid_plan, report.diagnostics.items[0].code);

    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, Platform.system(), null);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.result == null);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, workspace_path, .{}));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));
}

test "rebuild rejects unsupported source profiles before workspace mutation" {
    const io = std.testing.io;
    const source_path = "test-customize-rebuild-unsupported.raw";
    const workspace_path = "test-customize-rebuild-unsupported-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    {
        const source = try Io.Dir.cwd().createFile(io, source_path, .{});
        defer source.close(io);
        try source.setLength(io, 4096);
    }

    var request = validNativeEditRequest(source_path, output_path, workspace_path, &.{});
    request.execution.backend = .rebuild;
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);

    var report = try preflight(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        Platform.system(),
    );
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(!report.ready());
    var saw_rebuild_rejection = false;
    for (report.capabilities) |capability| {
        if (capability.requirement.kind == .rebuild and
            capability.state == .unsupported)
        {
            saw_rebuild_rejection = true;
        }
    }
    try std.testing.expect(saw_rebuild_rejection);
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, workspace_path, .{}),
    );
}

test "validation reports multiple problems without mutating the request" {
    var request = validRequest();
    request.api_version = 99;
    request.target_architecture = null;
    request.output.path = "";
    request.output.size = 123;
    request.execution.workspace_path = "";
    const before = request;

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);

    try std.testing.expect(diagnostics.items.len >= 5);
    try std.testing.expect(diagnostics.hasErrors());
    try std.testing.expect(std.meta.eql(before, request));
}

test "validation rejects normalized source aliases and unsupported aarch64 BIOS" {
    var request = validRequest();
    request.input.iso_oci.iso_path = "./output.qcow2";
    request.target_architecture = .aarch64;
    request.storage.fresh.generation = .gen1;
    request.boot_security.verity = true;
    request.execution.overwrite = true;

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);

    var saw_path_conflict = false;
    var saw_boot_conflict = false;
    var saw_verity_conflict = false;
    for (diagnostics.items) |diagnostic| {
        saw_path_conflict = saw_path_conflict or diagnostic.code == .path_conflict;
        saw_boot_conflict = saw_boot_conflict or diagnostic.code == .incompatible_boot_policy;
        saw_verity_conflict = saw_verity_conflict or
            (diagnostic.code == .incompatible_boot_policy and
                std.mem.eql(u8, diagnostic.configuration_path, "/boot_security/verity"));
    }
    try std.testing.expect(saw_path_conflict);
    try std.testing.expect(saw_boot_conflict);
    try std.testing.expect(saw_verity_conflict);
}

test "validation rejects guaranteed-invalid filesystem and partition geometries" {
    var tiny_esp = validRequest();
    tiny_esp.storage.fresh.esp_size = 1;
    var tiny_diagnostics = try validate(std.testing.allocator, &tiny_esp);
    defer tiny_diagnostics.deinit(std.testing.allocator);
    var saw_fat32_limit = false;
    for (tiny_diagnostics.items) |diagnostic| {
        saw_fat32_limit = saw_fat32_limit or
            (diagnostic.code == .invalid_storage and
                std.mem.eql(u8, diagnostic.configuration_path, "/storage/fresh/esp_size"));
    }
    try std.testing.expect(saw_fat32_limit);

    var oversized_mbr = validRequest();
    oversized_mbr.storage.fresh.generation = .gen1;
    oversized_mbr.output.size = 3 * 1024 * 1024 * 1024 * 1024;
    var mbr_diagnostics = try validate(std.testing.allocator, &oversized_mbr);
    defer mbr_diagnostics.deinit(std.testing.allocator);
    var saw_mbr_limit = false;
    for (mbr_diagnostics.items) |diagnostic| {
        saw_mbr_limit = saw_mbr_limit or
            (diagnostic.cause != null and std.mem.eql(u8, diagnostic.cause.?.error_name, "PartitionTooLargeForMbr"));
    }
    try std.testing.expect(saw_mbr_limit);

    var oversized_ext4 = validRequest();
    oversized_ext4.output.size = 20 * 1024 * 1024 * 1024 * 1024;
    var ext4_diagnostics = try validate(std.testing.allocator, &oversized_ext4);
    defer ext4_diagnostics.deinit(std.testing.allocator);
    var saw_ext4_limit = false;
    for (ext4_diagnostics.items) |diagnostic| {
        saw_ext4_limit = saw_ext4_limit or
            (diagnostic.cause != null and std.mem.eql(u8, diagnostic.cause.?.error_name, "FilesystemTooLarge"));
    }
    try std.testing.expect(saw_ext4_limit);

    var oversized_esp = validRequest();
    oversized_esp.storage.fresh.esp_size = std.math.maxInt(u64);
    var esp_diagnostics = try validate(std.testing.allocator, &oversized_esp);
    defer esp_diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(esp_diagnostics.hasErrors());

    var huge_verity = validRequest();
    huge_verity.boot_security.verity = true;
    huge_verity.output.size = std.math.maxInt(u64) / mib * mib - 2 * mib;
    var verity_diagnostics = try validate(std.testing.allocator, &huge_verity);
    defer verity_diagnostics.deinit(std.testing.allocator);
    var saw_huge_verity_limit = false;
    for (verity_diagnostics.items) |diagnostic| {
        saw_huge_verity_limit = saw_huge_verity_limit or
            (diagnostic.cause != null and std.mem.eql(u8, diagnostic.cause.?.error_name, "FilesystemTooLarge"));
    }
    try std.testing.expect(saw_huge_verity_limit);
}

test "validation rejects unsafe customization values and plaintext-shaped password hashes" {
    var request = validRequest();
    const operations = [_]FilesystemOperation{
        .{ .put_file = .{
            .path = "etc/not-absolute",
            .source = .{ .inline_bytes = "value" },
        } },
        .{ .set_metadata = .{
            .path = "/etc/example",
            .mode = 0o10000,
        } },
    };
    const users = [_]User{.{
        .name = "Invalid User",
        .password = .{ .prehashed = "plaintext" },
        .ssh_authorized_keys = &.{"line1\nline2"},
    }};
    request.os = .{
        .filesystem = &operations,
        .hostname = "-invalid",
        .users = &users,
    };

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    var customization_errors: usize = 0;
    for (diagnostics.items) |diagnostic| {
        customization_errors += @intFromBool(diagnostic.code == .invalid_customization);
    }
    try std.testing.expect(customization_errors >= 6);
}

test "resolved customization deeply owns nested content and contributes to plan integrity" {
    var inline_bytes = "original".*;
    var hostname = "owned-vm".*;
    var key = "ssh-ed25519 AAAA original".*;
    const operations = [_]FilesystemOperation{.{ .put_file = .{
        .path = "/etc/owned",
        .source = .{ .inline_bytes = &inline_bytes },
    } }};
    const users = [_]User{.{
        .name = "alice",
        .ssh_authorized_keys = &.{&key},
    }};
    var request = validRequest();
    request.os = .{
        .filesystem = &operations,
        .hostname = &hostname,
        .users = &users,
    };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    const original_hash = resolved.plan.?.data.plan_hash;
    inline_bytes[0] = 'X';
    hostname[0] = 'X';
    key[0] = 'X';

    try std.testing.expectEqualStrings(
        "original",
        resolved.plan.?.data.os.filesystem[0].put_file.source.inline_bytes,
    );
    try std.testing.expectEqualStrings("owned-vm", resolved.plan.?.data.os.hostname.?);
    try std.testing.expectEqualStrings(
        "ssh-ed25519 AAAA original",
        resolved.plan.?.data.os.users[0].ssh_authorized_keys[0],
    );
    try std.testing.expect(try hasValidPlanIntegrity(std.testing.allocator, &resolved.plan.?));
    try std.testing.expectEqualSlices(u8, &original_hash.bytes, &resolved.plan.?.data.plan_hash.bytes);

    var changed_request = validRequest();
    const changed_operations = [_]FilesystemOperation{.{ .put_file = .{
        .path = "/etc/owned",
        .source = .{ .inline_bytes = "different" },
    } }};
    changed_request.os.filesystem = &changed_operations;
    var changed = try resolve(std.testing.allocator, &changed_request, .{ .host_architecture = .x86_64 });
    defer changed.deinit(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &original_hash.bytes,
        &changed.plan.?.data.plan_hash.bytes,
    ));
}

test "resolution applies base_path before checking mixed path forms" {
    var cwd_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const cwd_len = try Io.Dir.cwd().realPathFile(std.testing.io, ".", &cwd_buffer);
    const base_path = try std.fs.path.join(std.testing.allocator, &.{ cwd_buffer[0..cwd_len], "test-customize-base" });
    defer std.testing.allocator.free(base_path);
    const output_path = try std.fs.path.join(std.testing.allocator, &.{ base_path, "output.qcow2" });
    defer std.testing.allocator.free(output_path);

    var request = validRequest();
    request.output.path = output_path;
    request.execution.workspace_path = ".";
    var resolved = try resolve(std.testing.allocator, &request, .{
        .host_architecture = .x86_64,
        .base_path = base_path,
    });
    defer resolved.deinit(std.testing.allocator);

    try std.testing.expect(resolved.plan != null);
    try std.testing.expectEqualStrings(base_path, resolved.plan.?.data.execution.workspace_path);
}

test "resolution is deterministic and encodes operation ordering" {
    const request = validRequest();
    var first = try resolve(std.testing.allocator, &request, .{ .host_architecture = .aarch64 });
    defer first.deinit(std.testing.allocator);
    var second = try resolve(std.testing.allocator, &request, .{ .host_architecture = .aarch64 });
    defer second.deinit(std.testing.allocator);

    try std.testing.expect(first.plan != null);
    try std.testing.expect(second.plan != null);
    try std.testing.expectEqualSlices(u8, &first.plan.?.data.plan_hash.bytes, &second.plan.?.data.plan_hash.bytes);
    try std.testing.expect(std.meta.eql(first.plan.?.data.generated, second.plan.?.data.generated));

    const operations = first.plan.?.data.operations;
    try std.testing.expectEqual(Phase.prepare, operations[0].phase);
    try std.testing.expectEqual(Phase.output_conversion, operations[operations.len - 1].phase);
    try std.testing.expectEqual(operations[operations.len - 2].id, operations[operations.len - 1].depends_on[0]);
    try std.testing.expectEqual(Action.populate_filesystem, operations[4].action);
    try std.testing.expectEqual(Action.prepare_boot_configuration, operations[5].action);
    var stage_bridge = NativeStageBridge{ .operations = operations };
    for (operations) |operation| {
        try std.testing.expect(NativeStageBridge.advance(&stage_bridge, freshStageForAction(operation.action).?));
    }
    try std.testing.expectEqual(operations.len, stage_bridge.next);
    try std.testing.expect(!NativeStageBridge.advance(&stage_bridge, .convert_output));

    var other_request = request;
    other_request.output.path = "other-output.qcow2";
    var other = try resolve(std.testing.allocator, &other_request, .{ .host_architecture = .aarch64 });
    defer other.deinit(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &first.plan.?.data.transaction_id.bytes,
        &other.plan.?.data.transaction_id.bytes,
    ));
    try std.testing.expectEqualSlices(
        u8,
        &first.plan.?.data.generated.?.disk_guid.bytes,
        &other.plan.?.data.generated.?.disk_guid.bytes,
    );

    var gen1_request = request;
    gen1_request.storage.fresh.generation = .gen1;
    var gen1 = try resolve(std.testing.allocator, &gen1_request, .{ .host_architecture = .x86_64 });
    defer gen1.deinit(std.testing.allocator);
    try std.testing.expectEqual(Action.prepare_boot_configuration, gen1.plan.?.data.operations[4].action);
    try std.testing.expectEqual(Action.populate_filesystem, gen1.plan.?.data.operations[5].action);
}

test "resolution rejects architecture roles the native backend cannot honor" {
    const request = validRequest();
    var resolved = try resolve(std.testing.allocator, &request, .{
        .host_architecture = .x86_64,
        .firmware_architecture = .aarch64,
    });
    defer resolved.deinit(std.testing.allocator);

    try std.testing.expect(resolved.plan == null);
    try std.testing.expectEqual(@as(usize, 1), resolved.diagnostics.items.len);
    try std.testing.expectEqual(DiagnosticCode.incompatible_architecture, resolved.diagnostics.items[0].code);
}

test "preflight and execution reject a modified resolved plan" {
    const request = validRequest();
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    @constCast(resolved.plan.?.data).output.format = .cosi;

    var report = try preflight(std.testing.allocator, std.testing.io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(!report.ready());
    try std.testing.expectEqual(DiagnosticCode.invalid_plan, report.diagnostics.items[0].code);

    var outcome = try execute(std.testing.allocator, std.testing.io, &resolved.plan.?, Platform.system(), null);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.result == null);
    try std.testing.expectEqual(DiagnosticCode.invalid_plan, outcome.diagnostics.items[0].code);
}

test "planned metadata makes VHD and VHDX creation deterministic" {
    const io = std.testing.io;
    const request = validRequest();
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    const generated = resolved.plan.?.data.generated.?;
    const create_options = image_mod.CreateOptions{
        .vhd_subformat = .fixed,
        .unique_id = generated.output_unique_id.bytes,
        .timestamp_unix = @intCast(request.reproducibility.source_date_epoch),
        .vhdx = .{
            .header_sequence_base = generated.vhdx_header_sequence_base,
            .file_write_guid = generated.vhdx_file_write_guid.bytes,
            .data_write_guid = generated.vhdx_data_write_guid.bytes,
            .page83_guid = generated.vhdx_page83_guid.bytes,
            .write_guid_seed = generated.vhdx_write_guid_seed.bytes,
        },
    };

    inline for (.{ Format.vhd, Format.vhdx }) |format| {
        const first_path = "test-customize-deterministic-a." ++ @tagName(format);
        const second_path = "test-customize-deterministic-b." ++ @tagName(format);
        defer Io.Dir.cwd().deleteFile(io, first_path) catch {};
        defer Io.Dir.cwd().deleteFile(io, second_path) catch {};

        var first = try image_mod.Image.create(io, first_path, format, 8 * mib, create_options);
        defer first.close(io);
        var second = try image_mod.Image.create(io, second_path, format, 8 * mib, create_options);
        defer second.close(io);
        try first.pwrite(io, "deterministic", 4096);
        try second.pwrite(io, "deterministic", 4096);

        const first_digest = try hashPath(std.testing.allocator, io, first_path);
        const second_digest = try hashPath(std.testing.allocator, io, second_path);
        try std.testing.expectEqualSlices(u8, &first_digest.bytes, &second_digest.bytes);
    }
}

test "preflight reports multiple missing capabilities" {
    const request = validRequest();
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });

    const Fake = struct {
        fn check(_: ?*anyopaque, _: Io, requirement: CapabilityRequirement) CapabilityState {
            return switch (requirement.kind) {
                .native_fresh, .atomic_commit => .available,
                else => .missing,
            };
        }
    };
    var report = try preflight(std.testing.allocator, std.testing.io, &resolved.plan.?, .{ .checkFn = Fake.check });
    defer report.deinit(std.testing.allocator);
    resolved.deinit(std.testing.allocator);

    try std.testing.expect(!report.ready());
    try std.testing.expect(report.diagnostics.items.len >= 4);
    try std.testing.expect(report.capabilities[0].requirement.path.len != 0);
}

test "preflight accepts a missing but creatable output directory" {
    const io = std.testing.io;
    const iso_path = "test-customize-creatable.iso";
    const container_path = "test-customize-creatable.container";
    const workspace_path = "test-customize-creatable-work";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, container_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};

    {
        const file = try Io.Dir.cwd().createFile(io, iso_path, .{});
        file.close(io);
    }
    {
        const file = try Io.Dir.cwd().createFile(io, container_path, .{});
        file.close(io);
    }

    var request = validRequest();
    request.input.iso_oci.iso_path = iso_path;
    request.input.iso_oci.container_path = container_path;
    request.output.path = workspace_path ++ "/output.raw";
    request.output.format = .raw;
    request.execution.workspace_path = workspace_path;

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);

    try std.testing.expect(report.ready());
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, workspace_path, .{}));
}

test "preflight resolves a symlink before missing output ancestors" {
    const io = std.testing.io;
    const source_path = "test-customize-isolation-source";
    const alias_path = "test-customize-isolation-alias";
    defer Io.Dir.cwd().deleteFile(io, alias_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, source_path) catch {};
    try Io.Dir.cwd().createDirPath(io, source_path);
    try Io.Dir.cwd().symLink(io, source_path, alias_path, .{ .is_directory = true });

    const source_absolute = try std.fs.path.resolve(std.testing.allocator, &.{source_path});
    defer std.testing.allocator.free(source_absolute);
    const output_absolute = try std.fs.path.resolve(std.testing.allocator, &.{ alias_path, "missing", "deeper", "output.raw" });
    defer std.testing.allocator.free(output_absolute);

    const state = systemCapabilityCheck(null, io, .{
        .kind = .path_isolation,
        .path = output_absolute,
        .related_path = source_absolute,
        .reason = "test prospective canonical isolation",
    });
    try std.testing.expectEqual(CapabilityState.missing, state);
}

test "transaction cleanup refuses an active backend lease" {
    const io = std.testing.io;
    const transaction_path = "test-customize-active-backend";
    defer Io.Dir.cwd().deleteTree(io, transaction_path) catch {};
    try Io.Dir.cwd().createDirPath(io, transaction_path);
    var lease = try transaction_guard.acquire(io, transaction_path);

    const blocked = cleanupTransaction(io, transaction_path).?;
    try std.testing.expectEqual(DiagnosticCode.cleanup_failed, blocked.code);
    try std.testing.expect(try transaction_guard.hasActiveLease(io, transaction_path));
    _ = try Io.Dir.cwd().statFile(io, transaction_path, .{});

    try lease.release(io);
    try std.testing.expect(cleanupTransaction(io, transaction_path) == null);
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, transaction_path, .{}),
    );
}

test "failed execution leaves no final output and removes its transaction" {
    const io = std.testing.io;
    const iso_path = "test-customize-invalid.iso";
    const container_path = "test-customize-container.tar";
    const workspace_path = "test-customize-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, container_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    {
        var file = try Io.Dir.cwd().createFile(io, iso_path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "not-an-iso", 0);
    }
    {
        var file = try Io.Dir.cwd().createFile(io, container_path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "not-a-container", 0);
    }

    var request = validRequest();
    request.input = .{ .iso_oci = .{
        .iso_path = iso_path,
        .container_path = container_path,
        .rootfs_path_in_iso = "rootfs.squashfs",
    } };
    request.output = .{ .path = output_path, .format = .raw, .size = 128 * mib };
    request.execution.workspace_path = workspace_path;

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    const transaction_path = try std.testing.allocator.dupe(u8, resolved.plan.?.data.transaction_path);
    defer std.testing.allocator.free(transaction_path);
    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, Platform.system(), null);
    defer outcome.deinit(std.testing.allocator);
    resolved.deinit(std.testing.allocator);

    try std.testing.expect(outcome.result == null);
    try std.testing.expect(outcome.diagnostics.hasErrors());
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, transaction_path, .{}));
}

test "custom execution platforms must advance every planned operation" {
    const IncompleteRunner = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            _: Io,
            _: *const ResolvedPlan,
            _: ?EventSink,
            _: build_image.StageSink,
        ) !void {}
    };

    const request = validRequest();
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);

    var diagnostics = std.array_list.Managed(Diagnostic).init(std.testing.allocator);
    defer diagnostics.deinit();
    var bridge = BuildEventBridge{
        .event_sink = null,
        .diagnostics = &diagnostics,
    };
    var platform = Platform.system();
    platform.runFn = IncompleteRunner.run;
    try std.testing.expectError(
        error.InvalidOperationOrder,
        runPlan(std.testing.allocator, std.testing.io, &resolved.plan.?, platform, null, &bridge),
    );
}

test "successful execution commits output and emits provenance" {
    const io = std.testing.io;
    const iso_path = "test-customize-success.iso";
    const container_path = "test-customize-success.container";
    const customization_path = "test-customize-success.conf";
    const workspace_path = "test-customize-success-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, container_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, customization_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    {
        var file = try Io.Dir.cwd().createFile(io, iso_path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "source-iso", 0);
    }
    {
        var file = try Io.Dir.cwd().createFile(io, container_path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "source-container", 0);
    }
    {
        var file = try Io.Dir.cwd().createFile(io, customization_path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, "source-customization", 0);
    }

    var request = validRequest();
    const filesystem = [_]FilesystemOperation{
        .{ .put_file = .{
            .path = "/etc/example.conf",
            .source = .{ .host_path = customization_path },
        } },
    };
    request.input = .{ .iso_oci = .{
        .iso_path = iso_path,
        .container_path = container_path,
        .rootfs_path_in_iso = "rootfs.squashfs",
    } };
    request.output = .{ .path = output_path, .format = .raw, .size = 128 * mib };
    request.os.filesystem = &filesystem;
    request.execution.workspace_path = workspace_path;

    const FakeRunner = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            run_io: Io,
            plan: *const ResolvedPlan,
            _: ?EventSink,
            stage_sink: build_image.StageSink,
        ) !void {
            for (plan.data.operations) |operation| {
                if (!stage_sink.advance(freshStageForAction(operation.action) orelse return error.InvalidOperationOrder)) {
                    return error.InvalidOperationOrder;
                }
            }
            const file = try Io.Dir.cwd().createFile(run_io, plan.data.staging_output_path, .{});
            defer file.close(run_io);
            try file.writePositionalAll(run_io, "completed-image", 0);
        }
    };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    const transaction_path = try std.testing.allocator.dupe(u8, resolved.plan.?.data.transaction_path);
    defer std.testing.allocator.free(transaction_path);
    var platform = Platform.system();
    platform.runFn = FakeRunner.run;
    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, platform, null);
    defer outcome.deinit(std.testing.allocator);
    resolved.deinit(std.testing.allocator);

    try std.testing.expect(outcome.result != null);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    try std.testing.expectEqual(@as(u64, "completed-image".len), outcome.result.?.provenance.final_output.size);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, transaction_path, .{}));
    const output_digest = try hashPath(std.testing.allocator, io, output_path);
    try std.testing.expectEqualSlices(
        u8,
        &output_digest.bytes,
        &outcome.result.?.provenance.final_output.sha256.bytes,
    );
    try std.testing.expectEqual(@as(usize, 3), outcome.result.?.provenance.sources.len);
    try std.testing.expectEqual(SourceKind.customization_file, outcome.result.?.provenance.sources[2].kind);
    try std.testing.expect(std.mem.endsWith(
        u8,
        outcome.result.?.provenance.sources[2].path,
        customization_path,
    ));
}

test "execution never publishes while a backend lease remains active" {
    const io = std.testing.io;
    const iso_path = "test-customize-lease.iso";
    const container_path = "test-customize-lease.container";
    const workspace_path = "test-customize-lease-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, container_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);
    for ([_]struct { path: []const u8, content: []const u8 }{
        .{ .path = iso_path, .content = "source-iso" },
        .{ .path = container_path, .content = "source-container" },
    }) |source| {
        var file = try Io.Dir.cwd().createFile(io, source.path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, source.content, 0);
    }

    var request = validRequest();
    request.input = .{ .iso_oci = .{
        .iso_path = iso_path,
        .container_path = container_path,
        .rootfs_path_in_iso = "rootfs.squashfs",
    } };
    request.output = .{ .path = output_path, .format = .raw, .size = 128 * mib };
    request.execution.workspace_path = workspace_path;

    const LeaseRunner = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            run_io: Io,
            plan: *const ResolvedPlan,
            _: ?EventSink,
            stage_sink: build_image.StageSink,
        ) !void {
            for (plan.data.operations) |operation| {
                if (!stage_sink.advance(freshStageForAction(operation.action) orelse
                    return error.InvalidOperationOrder))
                {
                    return error.InvalidOperationOrder;
                }
            }
            const file = try Io.Dir.cwd().createFile(
                run_io,
                plan.data.staging_output_path,
                .{},
            );
            defer file.close(run_io);
            try file.writePositionalAll(run_io, "unreleased-image", 0);
            var lease_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
            const lease_path = try transaction_guard.activeLeasePath(
                plan.data.transaction_path,
                &lease_buffer,
            );
            const lease = try Io.Dir.cwd().createFile(
                run_io,
                lease_path,
                .{ .exclusive = true },
            );
            lease.close(run_io);
        }
    };

    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    const transaction_path = resolved.plan.?.data.transaction_path;
    var platform = Platform.system();
    platform.runFn = LeaseRunner.run;
    var outcome = try execute(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expect(outcome.result == null);
    try std.testing.expect(outcome.diagnostics.hasErrors());
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, output_path, .{}),
    );
    try std.testing.expect(try transaction_guard.hasActiveLease(
        io,
        transaction_path,
    ));
    var lease_buffer: [Io.Dir.max_path_bytes]u8 = undefined;
    const lease_path = try transaction_guard.activeLeasePath(
        transaction_path,
        &lease_buffer,
    );
    try Io.Dir.cwd().deleteFile(io, lease_path);
}

test "execution rejects a customization source changed during the build" {
    const io = std.testing.io;
    const iso_path = "test-customize-source-change.iso";
    const container_path = "test-customize-source-change.container";
    const customization_path = "test-customize-source-change.conf";
    const workspace_path = "test-customize-source-change-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, container_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, customization_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, output_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    for ([_]struct { path: []const u8, content: []const u8 }{
        .{ .path = iso_path, .content = "source-iso" },
        .{ .path = container_path, .content = "source-container" },
        .{ .path = customization_path, .content = "before" },
    }) |source| {
        var file = try Io.Dir.cwd().createFile(io, source.path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, source.content, 0);
    }

    const filesystem = [_]FilesystemOperation{
        .{ .put_file = .{
            .path = "/etc/example.conf",
            .source = .{ .host_path = customization_path },
        } },
    };
    var request = validRequest();
    request.input = .{ .iso_oci = .{
        .iso_path = iso_path,
        .container_path = container_path,
        .rootfs_path_in_iso = "rootfs.squashfs",
    } };
    request.output = .{ .path = output_path, .format = .raw, .size = 128 * mib };
    request.os.filesystem = &filesystem;
    request.execution.workspace_path = workspace_path;

    const MutationRunner = struct {
        const Context = struct {
            source_path: []const u8,
        };

        fn run(
            context_ptr: ?*anyopaque,
            _: Allocator,
            run_io: Io,
            plan: *const ResolvedPlan,
            _: ?EventSink,
            stage_sink: build_image.StageSink,
        ) !void {
            for (plan.data.operations) |operation| {
                if (!stage_sink.advance(freshStageForAction(operation.action) orelse return error.InvalidOperationOrder)) {
                    return error.InvalidOperationOrder;
                }
            }
            const output = try Io.Dir.cwd().createFile(run_io, plan.data.staging_output_path, .{});
            defer output.close(run_io);
            try output.writePositionalAll(run_io, "completed-image", 0);

            const context: *Context = @ptrCast(@alignCast(context_ptr.?));
            const source = try Io.Dir.cwd().createFile(run_io, context.source_path, .{ .truncate = true });
            defer source.close(run_io);
            try source.writePositionalAll(run_io, "after", 0);
        }
    };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    var context = MutationRunner.Context{ .source_path = customization_path };
    var platform = Platform.system();
    platform.context = &context;
    platform.runFn = MutationRunner.run;
    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, platform, null);
    defer outcome.deinit(std.testing.allocator);

    try std.testing.expect(outcome.result == null);
    var found_source_changed = false;
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .source_changed) found_source_changed = true;
    }
    try std.testing.expect(found_source_changed);
    try std.testing.expectError(error.FileNotFound, Io.Dir.cwd().statFile(io, output_path, .{}));
}

test "plan JSON renders identifiers as stable strings" {
    const request = validRequest();
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);

    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writePlanJson(&resolved.plan.?, &output.writer);
    const json = output.written();
    try std.testing.expect(std.mem.indexOf(u8, json, "\"schema_version\": 4") != null);
    try std.testing.expect(std.mem.indexOf(u8, json, "\"plan_hash\": \"") != null);
}

test "native-edit resolution is deterministic, deeply owned, and integrity checked" {
    var disk_path = "native-edit-source.raw".*;
    var edit_path = "native-edit-content.txt".*;
    var guest_path = "/etc/config".*;
    var inline_bytes = "inline".*;
    const operations = [_]ExistingPathOperation{
        .{ .overwrite_file = .{
            .path = &guest_path,
            .source = .{ .host_path = &edit_path },
        } },
        .{ .overwrite_file = .{
            .path = "/etc/second",
            .source = .{ .bytes = &inline_bytes },
        } },
    };
    const request = validNativeEditRequest(&disk_path, "native-edit-output.raw", ".", &operations);
    var first = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer first.deinit(std.testing.allocator);
    var second = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer second.deinit(std.testing.allocator);
    try std.testing.expect(first.plan != null);
    try std.testing.expectEqualSlices(
        u8,
        &first.plan.?.data.plan_hash.bytes,
        &second.plan.?.data.plan_hash.bytes,
    );
    try std.testing.expect(first.plan.?.data.input == .disk);
    try std.testing.expect(first.plan.?.data.storage == .preserve);
    try std.testing.expect(first.plan.?.data.generated == null);
    try std.testing.expectEqual(@as(u64, 0), first.plan.?.data.output.disk_size);
    try std.testing.expectEqual(@as(usize, 3), first.plan.?.data.operations.len);
    try std.testing.expectEqual(Action.load_preserved_source, first.plan.?.data.operations[0].action);
    try std.testing.expectEqual(Action.edit_existing_paths, first.plan.?.data.operations[1].action);
    try std.testing.expectEqual(Action.publish_standalone_output, first.plan.?.data.operations[2].action);

    disk_path[0] = 'X';
    edit_path[0] = 'X';
    guest_path[1] = 'X';
    inline_bytes[0] = 'X';
    try std.testing.expect(std.mem.endsWith(
        u8,
        first.plan.?.data.input.disk.path,
        "native-edit-source.raw",
    ));
    try std.testing.expect(std.mem.endsWith(
        u8,
        first.plan.?.data.existing_path_operations[0].overwrite_file.source.host_path,
        "native-edit-content.txt",
    ));
    try std.testing.expectEqualStrings(
        "/etc/config",
        first.plan.?.data.existing_path_operations[0].overwrite_file.path,
    );
    try std.testing.expectEqualStrings(
        "inline",
        first.plan.?.data.existing_path_operations[1].overwrite_file.source.bytes,
    );
    try std.testing.expect(try hasValidPlanIntegrity(std.testing.allocator, &first.plan.?));

    const mutable_operations = @constCast(first.plan.?.data.operations);
    const original_action = mutable_operations[1].action;
    mutable_operations[1].action = .publish_standalone_output;
    var tampered = try preflight(std.testing.allocator, std.testing.io, &first.plan.?, Platform.system());
    defer tampered.deinit(std.testing.allocator);
    try std.testing.expectEqual(DiagnosticCode.invalid_plan, tampered.diagnostics.items[0].code);
    mutable_operations[1].action = original_action;
}

test "native-edit resolution rejects disk and edit source aliases" {
    var disk_alias = validNativeEditRequest("alias.raw", "alias.raw", ".", &.{});
    var disk_diagnostics = try validate(std.testing.allocator, &disk_alias);
    defer disk_diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(disk_diagnostics, .path_conflict));

    const operations = [_]ExistingPathOperation{.{ .overwrite_file = .{
        .path = "/etc/config",
        .source = .{ .host_path = "alias.raw" },
    } }};
    disk_alias = validNativeEditRequest("source.raw", "alias.raw", ".", &operations);
    var edit_alias = try resolve(std.testing.allocator, &disk_alias, .{ .host_architecture = .x86_64 });
    defer edit_alias.deinit(std.testing.allocator);
    try std.testing.expect(edit_alias.plan == null);
    try std.testing.expect(hasDiagnosticCode(edit_alias.diagnostics, .path_conflict));
}

test "native-edit source hashing covers the disk and host edit sources" {
    const io = std.testing.io;
    const disk_path = "test-customize-hash-disk.raw";
    const edit_path = "test-customize-hash-edit.txt";
    defer Io.Dir.cwd().deleteFile(io, disk_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, edit_path) catch {};
    for ([_]struct { path: []const u8, contents: []const u8 }{
        .{ .path = disk_path, .contents = "disk" },
        .{ .path = edit_path, .contents = "before" },
    }) |source| {
        const file = try Io.Dir.cwd().createFile(io, source.path, .{});
        defer file.close(io);
        try file.writePositionalAll(io, source.contents, 0);
    }
    const operations = [_]ExistingPathOperation{.{ .overwrite_file = .{
        .path = "/etc/config",
        .source = .{ .host_path = edit_path },
    } }};
    const request = validNativeEditRequest(disk_path, "hash-output.raw", ".", &operations);
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    const before = try hashPlanSources(std.testing.allocator, io, &resolved.plan.?);
    defer freeSourceRecords(std.testing.allocator, before);
    try std.testing.expectEqual(@as(usize, 2), before.len);
    try std.testing.expectEqual(SourceKind.disk, before[0].kind);
    try std.testing.expectEqual(SourceKind.edit_source, before[1].kind);

    {
        const file = try Io.Dir.cwd().createFile(io, edit_path, .{ .truncate = true });
        defer file.close(io);
        try file.writePositionalAll(io, "after", 0);
    }
    const after = try hashPlanSources(std.testing.allocator, io, &resolved.plan.?);
    defer freeSourceRecords(std.testing.allocator, after);
    try std.testing.expect(!sourceRecordsEqual(before, after));
    try std.testing.expectEqualSlices(u8, &before[0].sha256.bytes, &after[0].sha256.bytes);
}

test "native-edit tracks qcow2 backing files and rejects output aliases" {
    const io = std.testing.io;
    const raw_path = "test-customize-backing-base.raw";
    const base_path = "test-customize-backing-base.qcow2";
    const overlay_path = "test-customize-backing-overlay.qcow2";
    const spool_path = "test-customize-backing-root.spool";
    const workspace_path = "test-customize-backing-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, raw_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, base_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, overlay_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, raw_path, spool_path);
    {
        var raw = try image_mod.Image.openPathReadOnly(io, raw_path);
        defer raw.close(io);
        var base = try image_mod.Image.createExclusive(
            io,
            base_path,
            .qcow2,
            customize_test_disk_size,
            .{},
        );
        defer base.close(io);
        try image_mod.copyAll(io, raw, &base, std.testing.allocator);
    }
    {
        var overlay = try image_mod.Image.createExclusive(
            io,
            overlay_path,
            .qcow2,
            customize_test_disk_size,
            .{},
        );
        overlay.close(io);
        const file = try Io.Dir.cwd().openFile(io, overlay_path, .{ .mode = .read_write });
        defer file.close(io);
        var header: [104]u8 = undefined;
        if (try file.readPositionalAll(io, &header, 0) != header.len) {
            return error.UnexpectedEndOfFile;
        }
        const backing_offset = std.mem.readInt(u32, header[100..104], .big);
        std.mem.writeInt(u64, header[8..16], backing_offset, .big);
        std.mem.writeInt(u32, header[16..20], base_path.len, .big);
        try file.writePositionalAll(io, &header, 0);
        try file.writePositionalAll(io, base_path, backing_offset);
    }

    const operations = [_]ExistingPathOperation{.{ .overwrite_file = .{
        .path = "/etc/config",
        .source = .{ .bytes = "backing\n" },
    } }};
    var request = validNativeEditRequest(
        overlay_path,
        output_path,
        workspace_path,
        &operations,
    );
    request.input.disk.dependencies = &.{base_path};
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    var ready = try preflight(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        Platform.system(),
    );
    defer ready.deinit(std.testing.allocator);
    try std.testing.expect(ready.ready());

    var outcome = try execute(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        Platform.system(),
        null,
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.result != null);
    try std.testing.expectEqual(@as(usize, 2), outcome.result.?.provenance.sources.len);
    try std.testing.expectEqual(SourceKind.disk, outcome.result.?.provenance.sources[0].kind);
    try std.testing.expectEqual(
        SourceKind.disk_dependency,
        outcome.result.?.provenance.sources[1].kind,
    );
    try std.testing.expect(
        outcome.result.?.provenance.execution.preserved.?.flattened_backing_chain,
    );

    var alias_request = validNativeEditRequest(
        overlay_path,
        base_path,
        ".",
        &operations,
    );
    alias_request.input.disk.dependencies = &.{base_path};
    alias_request.execution.overwrite = true;
    var alias_resolved = try resolve(
        std.testing.allocator,
        &alias_request,
        .{ .host_architecture = .x86_64 },
    );
    defer alias_resolved.deinit(std.testing.allocator);
    try std.testing.expect(alias_resolved.plan == null);
    try std.testing.expect(hasDiagnosticCode(alias_resolved.diagnostics, .path_conflict));

    const undeclared_request = validNativeEditRequest(
        overlay_path,
        "test-customize-backing-undeclared.raw",
        ".",
        &operations,
    );
    var undeclared_resolved = try resolve(
        std.testing.allocator,
        &undeclared_request,
        .{ .host_architecture = .x86_64 },
    );
    defer undeclared_resolved.deinit(std.testing.allocator);
    var undeclared_preflight = try preflight(
        std.testing.allocator,
        io,
        &undeclared_resolved.plan.?,
        Platform.system(),
    );
    defer undeclared_preflight.deinit(std.testing.allocator);
    try std.testing.expect(!undeclared_preflight.ready());
    var saw_dependency_conflict = false;
    for (undeclared_preflight.capabilities) |capability| {
        if (capability.requirement.kind == .disk_dependencies and
            capability.state == .missing)
        {
            saw_dependency_conflict = true;
        }
    }
    try std.testing.expect(saw_dependency_conflict);
}

test "native-edit execution preserves source size and emits preserved provenance" {
    const io = std.testing.io;
    const source_path = "test-customize-native-edit-source.raw";
    const edit_path = "test-customize-native-edit-content.txt";
    const spool_path = "test-customize-native-edit-root.spool";
    const workspace_path = "test-customize-native-edit-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, edit_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, source_path, spool_path);
    {
        const edit_source = try Io.Dir.cwd().createFile(io, edit_path, .{});
        defer edit_source.close(io);
        try edit_source.writePositionalAll(io, "after\n", 0);
    }
    const source_before = try hashPath(std.testing.allocator, io, source_path);
    const operations = [_]ExistingPathOperation{
        .{ .overwrite_file = .{
            .path = "/etc/config",
            .source = .{ .host_path = edit_path },
        } },
        .{ .remove_file = "/etc/remove" },
        .{ .remove_tree = "/var/drop" },
    };
    const request = validNativeEditRequest(source_path, output_path, workspace_path, &operations);
    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    var preflight_report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer preflight_report.deinit(std.testing.allocator);
    try std.testing.expect(preflight_report.ready());

    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, Platform.system(), null);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.result != null);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    const result = &outcome.result.?;
    try std.testing.expectEqual(provenance_schema_version, result.provenance.schema_version);
    try std.testing.expect(result.provenance.generated == null);
    try std.testing.expectEqual(@as(usize, 2), result.provenance.sources.len);
    try std.testing.expectEqual(SourceKind.disk, result.provenance.sources[0].kind);
    try std.testing.expectEqual(SourceKind.edit_source, result.provenance.sources[1].kind);
    const preserved = result.provenance.execution.preserved.?;
    try std.testing.expectEqual(Format.raw, preserved.source_format);
    try std.testing.expectEqual(Format.raw, preserved.output_format);
    try std.testing.expectEqual(customize_test_disk_size, preserved.virtual_size);
    try std.testing.expectEqual(
        @as(u64, customize_test_partition_first_lba) * mbr.sector_size,
        preserved.partition_offset,
    );
    try std.testing.expectEqual(
        @as(u64, customize_test_partition_sectors) * mbr.sector_size,
        preserved.partition_length,
    );
    try std.testing.expect(!preserved.flattened_backing_chain);
    try std.testing.expectEqual(@as(usize, operations.len), preserved.operation_count);
    try std.testing.expect(std.meta.eql(
        PartitionSelector{ .mbr_index = 1 },
        preserved.selected_partition,
    ));
    try std.testing.expectEqual(customize_test_disk_size, result.provenance.final_output.size);
    try std.testing.expectEqualSlices(
        u8,
        &source_before.bytes,
        &(try hashPath(std.testing.allocator, io, source_path)).bytes,
    );

    var output = try image_mod.Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    try std.testing.expectEqual(customize_test_disk_size, output.virtual_size);
    var output_reader = try ext4.open(io, output.file, std.testing.allocator, .{
        .offset = @as(u64, customize_test_partition_first_lba) * mbr.sector_size,
    });
    defer output_reader.deinit();
    const output_config = try output_reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(output_config);
    try std.testing.expectEqualStrings("after\n", output_config);
    try std.testing.expectError(error.NotFound, output_reader.statPath(io, "/etc/remove"));
    try std.testing.expectError(error.NotFound, output_reader.statPath(io, "/var/drop"));

    var source = try image_mod.Image.openPathReadOnly(io, source_path);
    defer source.close(io);
    var source_reader = try ext4.open(io, source.file, std.testing.allocator, .{
        .offset = @as(u64, customize_test_partition_first_lba) * mbr.sector_size,
    });
    defer source_reader.deinit();
    const source_config = try source_reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(source_config);
    try std.testing.expectEqualStrings("before\n", source_config);
}

test "rebuild execution creates paths and emits strict tree provenance" {
    const io = std.testing.io;
    const source_path = "test-customize-rebuild-source.raw";
    const spool_path = "test-customize-rebuild-root.spool";
    const workspace_path = "test-customize-rebuild-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, source_path, spool_path);
    const source_before = try hashPath(std.testing.allocator, io, source_path);

    const existing = [_]ExistingPathOperation{.{ .overwrite_file = .{
        .path = "/etc/config",
        .source = .{ .bytes = "rebuilt\n" },
    } }};
    var request = validNativeEditRequest(
        source_path,
        output_path,
        workspace_path,
        &existing,
    );
    request.execution.backend = .rebuild;
    request.os.filesystem = &.{
        .{ .put_file = .{
            .path = "/etc/new.conf",
            .source = .{ .inline_bytes = "created\n" },
            .metadata = .{ .mode = 0o600, .uid = 45, .gid = 67 },
        } },
    };

    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    const operations = resolved.plan.?.data.operations;
    try std.testing.expectEqual(@as(usize, 7), operations.len);
    try std.testing.expectEqual(Action.load_preserved_source, operations[0].action);
    try std.testing.expectEqual(Action.extract_preserved_root, operations[1].action);
    try std.testing.expectEqual(Action.edit_existing_paths, operations[2].action);
    try std.testing.expectEqual(Action.apply_filesystem_changes, operations[3].action);
    try std.testing.expectEqual(Action.generalize_and_cleanup, operations[4].action);
    try std.testing.expectEqual(Action.populate_preserved_root, operations[5].action);
    try std.testing.expectEqual(Action.publish_standalone_output, operations[6].action);

    var preflight_report = try preflight(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        Platform.system(),
    );
    defer preflight_report.deinit(std.testing.allocator);
    try std.testing.expect(preflight_report.ready());

    var outcome = try execute(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        Platform.system(),
        null,
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.result != null);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    const rebuild_record = outcome.result.?.provenance.execution.preserved.?.rebuild.?;
    try std.testing.expectEqual(ext4.StrictProfile.zvmi_ext4_v1, rebuild_record.profile);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x63} ** 16), &rebuild_record.ext4_uuid.bytes);
    try std.testing.expectEqual(@as(usize, 1), rebuild_record.existing_operation_count);
    try std.testing.expectEqual(@as(usize, 1), rebuild_record.os_customization_count);
    try std.testing.expect(rebuild_record.final_node_count > rebuild_record.imported_node_count);
    try std.testing.expect(!std.mem.eql(
        u8,
        &rebuild_record.source_root_tree_digest.bytes,
        &rebuild_record.final_root_tree_digest.bytes,
    ));
    try std.testing.expectEqualSlices(
        u8,
        &source_before.bytes,
        &(try hashPath(std.testing.allocator, io, source_path)).bytes,
    );

    var output = try image_mod.Image.openPathReadOnly(io, output_path);
    defer output.close(io);
    var reader = try ext4.open(io, output.file, std.testing.allocator, .{
        .offset = @as(u64, customize_test_partition_first_lba) * mbr.sector_size,
    });
    defer reader.deinit();
    const rebuilt = try reader.readFileAlloc(io, std.testing.allocator, "/etc/config");
    defer std.testing.allocator.free(rebuilt);
    try std.testing.expectEqualStrings("rebuilt\n", rebuilt);
    const created = try reader.readFileAlloc(io, std.testing.allocator, "/etc/new.conf");
    defer std.testing.allocator.free(created);
    try std.testing.expectEqualStrings("created\n", created);
    const created_stat = try reader.statPath(io, "/etc/new.conf");
    try std.testing.expectEqual(@as(u16, 0o600), created_stat.mode);
    try std.testing.expectEqual(@as(u32, 45), created_stat.uid);
    try std.testing.expectEqual(@as(u32, 67), created_stat.gid);
}
