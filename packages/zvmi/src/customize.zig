//! Versioned image-customization request, planning, preflight, execution, and
//! provenance API. Native fresh construction and constrained native preserved
//! disk editing are implemented. Broader mutation and guest-code backends are
//! modeled explicitly and fail capability preflight until implemented.

const std = @import("std");
const Io = std.Io;
const Allocator = std.mem.Allocator;
const azure = @import("azure.zig");
const bootconfig = @import("bootconfig.zig");
const boot_options = @import("boot_options.zig");
const build_image = @import("build_image.zig");
const cosi = @import("cosi.zig");
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const Format = @import("formats.zig").Format;
const gpt = @import("gpt.zig");
const grub_defaults = @import("grub_defaults.zig");
const guid = @import("guid.zig");
const image_mod = @import("image.zig");
const layout = @import("layout.zig");
const identity_rewrite = @import("identity_rewrite.zig");
const limits_mod = @import("limits.zig");
const mbr = @import("mbr.zig");
const os_customization = @import("os_customization.zig");
const output_mod = @import("output.zig");
const customization_wire = @import("customization_wire.zig");
const preserved_image = @import("preserved_image.zig");
const selinux_mod = @import("selinux.zig");
const root_tree = @import("root_tree.zig");
const transaction_guard = @import("transaction_guard.zig");
const verity = @import("verity.zig");
const vm_control = @import("vm_control.zig");

pub const legacy_api_version: u32 = 2;
pub const current_api_version: u32 = 3;
pub const plan_schema_version: u32 = 22;
pub const provenance_schema_version: u32 = 25;
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

    /// The inverse of `jsonStringify`, so a document carrying a digest can be
    /// read back by the same program that wrote it. The unsafe backend's
    /// worker report crosses a process boundary as JSON; without this, the
    /// digests in it would need a second on-the-wire representation, and two
    /// spellings of the same value drift.
    pub fn jsonParse(
        allocator: Allocator,
        source: anytype,
        options: std.json.ParseOptions,
    ) std.json.ParseError(@TypeOf(source.*))!Digest {
        const hex = try std.json.innerParse([]const u8, allocator, source, options);
        if (hex.len != 64) return error.InvalidCharacter;
        var digest: Digest = undefined;
        _ = std.fmt.hexToBytes(&digest.bytes, hex) catch return error.InvalidCharacter;
        return digest;
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
    /// A raw image compressed as it is written. Only raw has a compressed
    /// spelling: every other format amends metadata after the data it
    /// already wrote, which cannot be done through a compressor.
    raw_gz,
    raw_zst,
    vhd,
    vhdx,
    qcow2,
    cosi,

    /// The disk format a caller receives, or `null` for a format that is not
    /// a disk image at all. `cosi` is a bundle of compressed partition
    /// payloads and metadata, so it has no answer here.
    fn imageFormat(self: OutputFormat) ?Format {
        return switch (self) {
            .raw, .raw_gz, .raw_zst => .raw,
            .vhd => .vhd,
            .vhdx => .vhdx,
            .qcow2 => .qcow2,
            .cosi => null,
        };
    }

    /// The disk format a backend builds before the output is published.
    /// Every backend writes a disk image; `cosi` is produced by reading the
    /// finished raw image back and describing it, so it stages as raw.
    pub fn stagingImageFormat(self: OutputFormat) Format {
        return switch (self) {
            .cosi => .raw,
            else => self.imageFormat().?,
        };
    }

    /// Whether publishing this format requires a second artifact built from
    /// the staged disk image rather than the staged image itself.
    pub fn bundlesStagedImage(self: OutputFormat) bool {
        return self == .cosi;
    }

    pub fn compression(self: OutputFormat) output_mod.Compression {
        return switch (self) {
            .raw_gz => .gzip,
            .raw_zst => .zstd,
            .raw, .vhd, .vhdx, .qcow2, .cosi => .none,
        };
    }

    /// Parses an `-O` argument, including the compressed spellings
    /// `raw.gz`/`raw.zst`. `cosi` is accepted here but not by
    /// `output.Spec.parseName`, which names disk formats a caller can open,
    /// convert, and create -- a COSI bundle is none of those.
    pub fn parseName(name: []const u8) ?OutputFormat {
        if (std.ascii.eqlIgnoreCase(name, "cosi")) return .cosi;
        const spec = output_mod.Spec.parseName(name) orelse return null;
        return switch (spec.compression) {
            .none => switch (spec.format) {
                .raw => .raw,
                .vhd => .vhd,
                .vhdx => .vhdx,
                .qcow2 => .qcow2,
            },
            .gzip => if (spec.format == .raw) .raw_gz else null,
            .zstd => if (spec.format == .raw) .raw_zst else null,
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

pub const SourceProfilePolicy = preserved_image.SourceProfilePolicy;
pub const IdentityRewritePolicy = identity_rewrite.Policy;
pub const SourceMount = preserved_image.SourceMount;
pub const SourceFilesystem = preserved_image.SourceFilesystem;
pub const SynthesizedFatMetadata = fat32.SynthesizedMetadata;

pub const PreservedStorage = struct {
    root_partition: PartitionSelector,
    /// Only the `rebuild` backend imports a filesystem, so this only reaches
    /// that path; the others preserve the source's bytes rather than reading
    /// its tree at all.
    source_profile: SourceProfilePolicy = .strict,
    /// Extra filesystems merged into the rebuilt root, each at its own mount
    /// point, in order. Also `rebuild`-only, for the same reason.
    source_mounts: []const SourceMount = &.{},
    /// Whether the rebuilt tree's `/etc/fstab` and bootloader configuration
    /// are reconciled with the identifiers the rebuild retired, and whether a
    /// surviving stale one fails the build. `rebuild`-only, for the same
    /// reason again: nothing else here reads a source's tree.
    identity_rewrite: IdentityRewritePolicy = .rewrite_and_verify,
    /// Whether the rebuilt root filesystem carries a JBD2 journal, and how
    /// large. `rebuild`-only, for the same reason: every other backend keeps
    /// the source's filesystem rather than writing a new one. Off by default,
    /// so an existing plan keeps producing the bytes it always has.
    journal: ext4.JournalOptions = .{},
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
    /// Wall-clock budget for the whole execution, from the moment the
    /// workspace is created to the moment the output is published.
    ///
    /// It belongs to the run rather than to any command in it. Package
    /// scriptlets, dracut modules and hooks are all target-supplied code
    /// running as root with no deadline of their own, and a per-command bound
    /// is defeated by a policy that declares more commands, so the only bound
    /// that means anything is the one over the whole thing.
    ///
    /// Absent means unbounded, which is where every caller that does not set
    /// it stands today. There is deliberately no default: one short enough to
    /// be useful would fail slow mirrors and emulated cross-architecture
    /// guests, and inventing a number for them is not this policy's business.
    ///
    /// A run that exceeds it fails with a diagnostic of its own rather than a
    /// command failure, and the transaction is torn down rather than left
    /// holding a mount or a loop device.
    deadline_seconds: ?u32 = null,
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

/// What happens to the UEFI variable store a firmware boot writes to.
///
/// Only `ephemeral` exists, and the choice is deliberate rather than pending:
/// the run has to answer "does the image as published boot", and a preserved
/// store would answer "does it boot on a machine a previous run already
/// primed". A firmware that wrote a `Boot####` entry on its first pass would
/// make the second pass of an identical plan a different experiment, which is
/// exactly the property this backend refuses to give up. It is recorded in
/// provenance as a value rather than assumed, so a future preserved store is a
/// readable difference rather than a silent one.
pub const VmVariableStorePolicy = enum {
    /// The template is copied into the transaction, used once, and removed
    /// with the transaction. The file the policy names is never written.
    ephemeral,
};

/// UEFI firmware for a guest that boots the way real hardware would.
pub const VmFirmware = struct {
    /// Read-only firmware code for the runner architecture.
    code_path: []const u8,
    /// Template variable store. The backend works on a copy, so the file named
    /// here is never modified.
    vars_path: []const u8,
    /// What the guest's own boot chain prints on the serial console once it
    /// has taken control.
    ///
    /// Named by the plan rather than guessed at, because nothing on the host
    /// knows what a given image says on its way up, and a marker the backend
    /// invented would make a boot that never happened indistinguishable from
    /// one that did. This is the whole contract an image has to satisfy to be
    /// attested: emit these bytes on the console the firmware guest is given.
    console_marker: []const u8,
    /// Whether the named firmware pair is a Secure Boot capable one, and the
    /// guest is therefore built with the SMM and secure-pflash wiring that
    /// makes the variable store authenticated.
    ///
    /// Policy input only. Observing what the guest concluded about its own
    /// Secure Boot state would require code running inside a guest this
    /// backend deliberately does not enter, so a claim about it is never
    /// recorded as an observation.
    secure_boot: bool = false,
    /// The attestation's own budget. A firmware boot is bounded by a full
    /// boot chain rather than by kernel-to-agent, and under emulation that
    /// difference is measured in tens of minutes, so it is not shared with
    /// `VmPolicy.boot_timeout_seconds`.
    boot_timeout_seconds: u32 = default_vm_firmware_boot_timeout_seconds,
};

/// How the guest is brought up.
pub const VmBoot = union(enum) {
    /// Boot the image's own kernel and initramfs directly, with the guest
    /// agent appended to the initramfs. No firmware, bootloader, or init
    /// system stands between the emulator and the agent, which is what keeps
    /// software emulation affordable and boot failures attributable.
    direct_kernel,
    /// Customize exactly as `direct_kernel` does, then attest the customized
    /// stage by booting it through UEFI firmware and its own boot chain
    /// before anything is published.
    ///
    /// The agent is not carried into that boot. Getting it there would take
    /// either modifying the image — which would mean attesting a boot chain
    /// nobody will ever run — or a cooperating image, which is not something
    /// a backend that customizes arbitrary images may require. So the two
    /// jobs are split: the appliance boot mutates, the firmware boot only
    /// watches, and the bytes it watches are proven unchanged afterwards.
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
/// Ceiling on the whole-run deadline. The same day as the boot timeouts it has
/// to contain: a budget larger than the longest thing it bounds would be a
/// number rather than a bound.
pub const max_execution_deadline_seconds: u32 = 24 * 60 * 60;

/// The run's declared budget, resolved to one absolute point in time.
///
/// Resolved once, when execution starts, and passed down rather than
/// recomputed. A budget that restarted at each phase, or at each command,
/// would be defeated by a policy that declares more of them, which is the
/// whole reason the deadline belongs to the run.
pub const Deadline = struct {
    /// `.none` for a run that declared no deadline, which is every run that
    /// predates the policy.
    timeout: Io.Timeout = .none,

    pub const unbounded: Deadline = .{};

    pub const Error = error{ExecutionDeadlineExceeded};

    /// Starts the budget now, on the `.awake` clock the guest boot timeouts
    /// already use, so the deadline and the budgets it contains are measured
    /// against the same thing.
    pub fn start(io: Io, seconds: ?u32) Deadline {
        const budget = seconds orelse return .unbounded;
        return .{ .timeout = (Io.Timeout{ .duration = .{
            .raw = .fromSeconds(budget),
            .clock = .awake,
        } }).toDeadline(io) };
    }

    /// Fails once the budget is spent. Called at phase boundaries, where the
    /// alternative is starting work the run has no time left to finish.
    pub fn check(self: Deadline, io: Io) Error!void {
        if (self.expired(io)) return error.ExecutionDeadlineExceeded;
    }

    pub fn expired(self: Deadline, io: Io) bool {
        const remaining = self.timeout.toDurationFromNow(io) orelse return false;
        return remaining.raw.toNanoseconds() <= 0;
    }

    /// Whole seconds left, for handing the remaining budget to a process that
    /// takes seconds rather than a timestamp. Rounded up, so a budget with any
    /// time left is never handed over as zero.
    pub fn remainingSeconds(self: Deadline, io: Io) ?u32 {
        const remaining = self.timeout.toDurationFromNow(io) orelse return null;
        const nanoseconds = remaining.raw.toNanoseconds();
        if (nanoseconds <= 0) return 0;
        const seconds = @divFloor(nanoseconds + std.time.ns_per_s - 1, std.time.ns_per_s);
        return std.math.cast(u32, seconds) orelse std.math.maxInt(u32);
    }

    /// This deadline extended by a fixed grace, for a supervisor that has to
    /// outlive the process it is bounding: the bounded process must be the one
    /// that reports its own expiry, or the report would say the supervisor
    /// gave up rather than what the run did.
    pub fn withGrace(self: Deadline, seconds: u32) Deadline {
        return switch (self.timeout) {
            .none => .unbounded,
            .duration => |duration| .{ .timeout = .{ .duration = .{
                .raw = .fromNanoseconds(
                    duration.raw.toNanoseconds() + @as(i96, seconds) * std.time.ns_per_s,
                ),
                .clock = duration.clock,
            } } },
            .deadline => |timestamp| .{ .timeout = .{ .deadline = timestamp.addDuration(.{
                .raw = .fromSeconds(seconds),
                .clock = timestamp.clock,
            }) } },
        };
    }

    /// The earlier of this deadline and a budget starting now, and which of
    /// the two that was. Used where a backend already has a bound of its own:
    /// the inner budget keeps its meaning, and the run deadline still cannot
    /// be outlived.
    pub fn clamped(self: Deadline, io: Io, budget_seconds: u32) Clamp {
        const budget: Io.Clock.Duration = .{
            .raw = .fromSeconds(budget_seconds),
            .clock = .awake,
        };
        const remaining = self.timeout.toDurationFromNow(io) orelse return .{
            .timeout = (Io.Timeout{ .duration = budget }).toDeadline(io),
            .deadline_first = false,
        };
        const deadline_first = remaining.raw.toNanoseconds() < budget.raw.toNanoseconds();
        const chosen = if (deadline_first) remaining else budget;
        return .{
            .timeout = (Io.Timeout{ .duration = chosen }).toDeadline(io),
            .deadline_first = deadline_first,
        };
    }

    /// A backend's own budget after the run deadline has been applied to it.
    ///
    /// Which budget the timeout came from is recorded when it is chosen rather
    /// than worked out after it fires: by the time a boot has been torn down
    /// and its console written out, a run deadline that had time left when the
    /// boot gave up may have passed, and the failure would be renamed after
    /// the fact into one the caller could not have caused.
    pub const Clamp = struct {
        timeout: Io.Timeout,
        deadline_first: bool,

        /// The failure to report when this timeout fires: the run's, if the
        /// run's is what it was, and otherwise whatever the backend calls its
        /// own.
        pub fn expiry(self: Clamp, backend_error: anyerror) anyerror {
            return if (self.deadline_first)
                error.ExecutionDeadlineExceeded
            else
                backend_error;
        }
    };
};

/// Twice the appliance boot's budget. A firmware guest interprets the
/// firmware, the bootloader, the kernel and an init system where the
/// appliance interprets a kernel and one static binary, and on a software
/// emulator each of those is paid for one instruction at a time.
pub const default_vm_firmware_boot_timeout_seconds: u32 = 1800;
/// Ceiling on the console marker. Long enough for a full banner line, short
/// enough that the marker is a marker rather than a transcript.
pub const max_vm_console_marker_bytes: usize = 256;

/// Bounds on the parts of a credential that are declared rather than read. A
/// user name or variable name longer than this is a mistake, and refusing it
/// where it is written beats writing it into a repository file and finding out
/// from the package manager.
pub const max_credential_field_bytes: usize = 256;

/// The largest material a credential source may hold. Generous for a password,
/// tight enough that a misnamed source cannot spool a whole file into memory.
pub const max_credential_material_bytes: usize = 4096;

/// What a hook is allowed to be, stated here rather than discovered when a
/// read runs out of memory or an `execve` runs out of argument space. A hook
/// is the one place a caller supplies code rather than configuration, so the
/// bounds on it are part of the declaration and not a property of the host it
/// happens to run on.
pub const max_hook_script_bytes: usize = 256 * 1024;
pub const max_hook_arguments: usize = 64;
pub const max_hook_argument_bytes: usize = 4096;

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

/// Where a credential's material is read from, never the material itself.
///
/// Two reasons it is a reference. `writeRequestJson` stringifies the whole
/// request by reflection, and `writePlanJson` and `writeProvenanceJson` do the
/// same for what they publish, so secret bytes anywhere in these types would be
/// emitted by a public API by default rather than by mistake. And a plan hash
/// covering a password would verify a guess offline, turning a published plan
/// identifier into an oracle for a low-entropy secret.
///
/// So the plan states where the material comes from, the hash covers that, and
/// provenance records it. What was at the path or in the variable when the run
/// happened is deliberately not recoverable from any output -- the same stance
/// the repository policy already takes towards package versions, where the
/// identifier covers the instruction and not the outcome.
pub const CredentialSource = union(enum) {
    /// A file on the build machine, named by absolute path. Read when the run
    /// needs it and not before.
    host_path: []const u8,
    /// An environment variable of the build process, named rather than read at
    /// request time so the value never enters a serializable type.
    host_environment: []const u8,
};

/// HTTP basic authentication. The user name is not a secret and is stated
/// outright, so a reader can tell which identity a build ran as; only the
/// password is a reference.
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
    trust: []const TrustSource,
    /// Authentication for every URL of this repository, or none. Declared per
    /// repository rather than globally because a credential that applied to
    /// whichever repository happened to ask would be sent to any of them.
    credential: ?RepositoryCredential = null,
};

/// Where the package transaction's downloads and repository metadata live.
///
/// A cache is the difference between a build that reaches the network and one
/// that does not, so leaving it ambient -- whatever the target image's
/// `/var/cache/tdnf` happens to hold, or whatever a previous run left on the
/// build machine -- makes "offline" a property of the machine rather than of
/// the plan. Naming a directory makes the cache a declared input, and the
/// mode says whether this run reads it or fills it.
///
/// The directory is a **locator**, not staged content: it is potentially
/// enormous, the run writes to it, and its whole purpose is to be reused
/// across builds, so a copy in the build cache would defeat it. The same
/// reasoning that keeps credential material out of the build graph keeps a
/// cache directory out of it, for the opposite reason.
pub const PackageCachePolicy = union(enum) {
    /// Resolve and download over the network, into whatever cache the target
    /// image carries. Nothing is declared and nothing is kept.
    online,
    /// Resolve and download over the network, into the named host directory,
    /// so that a later `cache_only` run has something to read. The directory
    /// is this run's output and is created when it does not exist.
    online_populating: []const u8,
    /// Resolve and install from the named host directory and reach no
    /// network at all. The directory is this run's input and must exist.
    cache_only: []const u8,
};

/// The declared cache directory, or null when the cache is ambient.
pub fn packageCacheDirectory(cache: PackageCachePolicy) ?[]const u8 {
    return switch (cache) {
        .online => null,
        .online_populating, .cache_only => |path| path,
    };
}

/// Whether the transaction must not reach the network.
pub fn offlinePackageCache(cache: PackageCachePolicy) bool {
    return cache == .cache_only;
}

pub const PackageCacheError = error{
    PackageCacheDirectoryNotAbsolute,
    PackageCacheDirectoryIsRoot,
    PackageCacheDirectoryNotNormalized,
};

/// Whether a declared cache directory is a path this build can bind-mount.
///
/// Pure and shared, because the privileged worker re-checks it on the far
/// side of the privilege boundary: a control document names a directory that
/// a process running as root mounts into the target, so the shape of that
/// path is not something to trust once and hope about afterwards. `..` is
/// refused rather than resolved for the same reason it is in a mount target
/// -- what the path denotes must be readable from the path.
pub fn validatePackageCacheDirectory(path: []const u8) PackageCacheError!void {
    if (path.len == 0 or path[0] != '/') return error.PackageCacheDirectoryNotAbsolute;
    if (path.len == 1) return error.PackageCacheDirectoryIsRoot;
    if (path[path.len - 1] == '/') return error.PackageCacheDirectoryNotNormalized;
    var components = std.mem.splitScalar(u8, path[1..], '/');
    while (components.next()) |component| {
        if (component.len == 0 or
            std.mem.eql(u8, component, ".") or
            std.mem.eql(u8, component, ".."))
        {
            return error.PackageCacheDirectoryNotNormalized;
        }
    }
}

/// One package pinned to one exact identity.
///
/// The three fields are rpm's own notion of identity, split the way rpm
/// splits it, so a lock and the `rpm -qa` line it is checked against are the
/// same value written two ways rather than two descriptions that have to be
/// kept in agreement.
///
/// **There is deliberately no repository id.** An earlier shape of this type
/// carried one, and nothing could have filled it honestly: rpm's database
/// does not record which repository a package came from, and the
/// `repoquery --installed` route to it is documented as unreliable under the
/// DNF5 backend Azure Linux ships as tdnf -- `reponame` is answered for
/// available packages and not for installed ones. So an emitted lock could
/// only have copied the sole declared repository's id, or invented one, and a
/// verifier reading it back would be checking a claim the run never made. The
/// repositories a transaction was allowed to use are already declared in the
/// request, hashed into the plan, and recorded in provenance; the lock's job
/// is the part that is not, which is the exact version.
pub const PackageVersionLock = struct {
    name: []const u8,
    /// rpm's `EPOCH:VERSION-RELEASE`, with the epoch always written even when
    /// it is zero. Required in full rather than accepted as a bare version,
    /// because `1.2.3` and `0:1.2.3-4.azl3` are different amounts of pinning
    /// and only one of them is a lock -- a caller who wrote the short form and
    /// got a silent partial match would have a build that reports itself
    /// reproducible and is not.
    evr: []const u8,
    /// rpm's `%{ARCH}`. Part of identity rather than decoration: `noarch` and
    /// `x86_64` builds of one name at one EVR are different packages, and a
    /// multilib root can hold two of them at once.
    architecture: []const u8,
};

/// Splits an `rpm -qa` record of the form `NAME-EPOCH:VERSION-RELEASE.ARCH`
/// back into the lock that would state it, or nothing if it is not one.
///
/// The rule itself lives in `vm_control` because the guest agent needs it too
/// and cannot import this module. See there for why the split is decidable.
pub fn parseInstalledPackageRecord(record: []const u8) ?PackageVersionLock {
    const pin = vm_control.parseInstalledPackageRecord(record) orelse return null;
    return .{
        .name = pin.name,
        .evr = pin.evr,
        .architecture = pin.architecture,
    };
}

pub const PackageLockPolicy = union(enum) {
    unlocked,
    snapshot: []const u8,
    /// Every package the transaction may leave installed, pinned by exact
    /// identity, and checked against the target's own rpm database once the
    /// transaction has run.
    ///
    /// This is the closure and not only the packages the actions name --
    /// `install openssh` that pulls in a dependency the lock does not mention
    /// has not been pinned, it has been pinned in one place and left free in
    /// another. `validatePackageLock` therefore refuses an action naming a
    /// package the lock omits, and a completed run emits the whole delta so
    /// the next run can state it.
    exact: []const PackageVersionLock,
};

pub const PackagePolicy = struct {
    actions: []const PackageAction = &.{},
    repositories: []const PackageRepository = &.{},
    cache: PackageCachePolicy = .online,
    lock: PackageLockPolicy = .unlocked,
    resolver: ResolverPolicy = .host_resolver,
};

/// Where the package transaction's `/etc/resolv.conf` comes from.
///
/// The target root has no reason to name a resolver reachable from wherever
/// this build runs, so something has to supply one, and until this policy
/// existed each backend quietly supplied its own. Naming the choice puts it in
/// the plan, under the plan hash, and into provenance, so a run that resolved
/// names through the build machine says so.
///
/// Whatever is installed is removed again when the transaction ends. This is
/// build-time configuration, not a property of the image.
pub const ResolverPolicy = union(enum) {
    /// The build host's resolver, however this backend reaches it.
    ///
    /// `unsafe_chroot` binds the host's own `/etc/resolv.conf` into the target
    /// root read-only. The VM backend reaches the same resolver indirectly:
    /// QEMU's user-mode networking answers on `10.0.2.3` by forwarding to
    /// whatever the host is configured to use.
    ///
    /// The default, because it is what a build machine already means by "the
    /// network", and because the alternative cannot be guessed. It is a
    /// declared inheritance rather than a silent one: the run states that its
    /// name resolution came from outside the plan, so two machines producing
    /// different output is a readable difference rather than a mystery.
    host_resolver,
    /// Exactly these nameservers, in this order, and nothing the host knows.
    ///
    /// Both backends render the same bytes from the same list, so the resolver
    /// stops being a property of where the build ran.
    nameservers: []const []const u8,
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

/// What an empty `kernels` list means when the target root turns out to carry
/// no kernel at all -- a question only the run can answer, since the plan
/// cannot see inside the image.
pub const NoInstalledKernelsPolicy = enum {
    /// Fail the run with `NoInstalledKernels`. Right for an instruction: the
    /// caller asked for every installed kernel's initramfs to be regenerated,
    /// and a run that regenerated none has not done what it said.
    fail,
    /// Succeed having regenerated nothing. Right for a decision derived from
    /// `when_needed`: nothing asked for a regeneration, so a root carrying no
    /// kernel has no stale initramfs and there is nothing to do. Without this
    /// the derived form would fail builds that the same request completes with
    /// `unchanged`.
    nothing_to_regenerate,
};

pub const InitramfsPolicy = union(enum) {
    unchanged,
    /// Leaving `kernels` empty regenerates the initramfs for every kernel
    /// release installed in the target root, which the backend discovers
    /// after the package actions have run. That ordering is the point: a
    /// kernel pulled in by `update_all` has a release string the caller
    /// could not have known when writing this policy. Naming releases
    /// explicitly overrides discovery.
    regenerate: struct {
        generator: ?[]const u8 = null,
        kernels: []const []const u8 = &.{},
        no_installed_kernels: NoInstalledKernelsPolicy = .fail,
    },
    /// Regenerate only if the rest of the request implies it, deciding from
    /// the declared plan rather than from what the run turns out to do.
    ///
    /// This resolves to `unchanged` or to `regenerate` with no named kernels
    /// before the plan is built, so the plan states the outcome, the plan
    /// hash covers it, and the executors never see this tag. A request that
    /// asks for it produces exactly the plan the equivalent explicit request
    /// would -- it is a way of not having to know the rule, not a different
    /// instruction.
    ///
    /// Declared last so the tags before it keep the values
    /// `hashInitramfsPolicy` already gave them. The schema version moves for
    /// this change regardless, so this buys nothing on its own; it costs
    /// nothing either, and it keeps the two concrete outcomes reading first.
    ///
    /// See `initramfsNeedsRegeneration` for the rule and for what is
    /// deliberately not part of it.
    when_needed: struct {
        generator: ?[]const u8 = null,
    },
};

pub const SelinuxMode = enum {
    enforcing,
    permissive,
    disabled,
};

pub const SelinuxPolicy = union(enum) {
    unchanged,
    /// Relabel the root filesystem with the policy the target already carries,
    /// changing nothing else about its SELinux configuration.
    ///
    /// Its own variant rather than a flag on `configure` because it is the one
    /// SELinux operation a preserved-image run can carry out, and because it
    /// is the operation a mutating run needs: a package action, a hook, a
    /// kernel-module write or an initramfs regeneration creates files with no
    /// `security.selinux` xattr at all -- neither executor has selinuxfs, so
    /// rpm cannot label as it installs -- and an enforcing root with
    /// unlabelled files is a root that may not boot. Existing labels survive a
    /// preserved-image round trip; only new ones are missing, and this is what
    /// assigns them.
    ///
    /// Which policy is not named here. The target's own
    /// `/etc/selinux/config` decides, read while the run executes rather than
    /// while the plan is resolved, because a package action in the same run
    /// can install or replace the policy the relabel must then use.
    relabel,
    /// Change the SELinux mode, the active policy, or both. Modelled and
    /// validated, but no backend implements it: preflight refuses it before a
    /// workspace exists. Nothing has asked for it, and a type that accepted it
    /// silently would be a promise the backends do not keep.
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
    /// Import limits, each raisable by its own flag. The defaults are
    /// guardrails sized for a purpose-built image, not a statement about how
    /// large a real installed root filesystem is.
    limits: limits_mod.ImportLimits = .{},
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
    invalid_limits,
    limit_exceeded,
    stale_filesystem_identifier,
    invalid_plan,
    missing_capability,
    source_hash_failed,
    source_changed,
    execution_failed,
    /// The run exceeded its declared wall-clock budget. Distinct from
    /// `execution_failed`, which is a command that ran and did not succeed.
    deadline_exceeded,
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
    if (request.output.format == .cosi and
        request.execution.backend == .native_fresh and
        request.storage == .fresh and
        request.storage.fresh.generation == .gen1)
    {
        try diagnostics.append(validationError(
            .unsupported_output_format,
            "/output/format",
            "a gen1 image is MBR-partitioned and COSI describes a GPT disk",
            "select gen2 storage, or select raw, vhd, vhdx, or qcow2",
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
            .logical_volume => |volume| if (volume.logical_volume.len == 0) {
                try diagnostics.append(validationError(
                    .invalid_partition_selector,
                    "/storage/preserve/root_partition/logical_volume/logical_volume",
                    "a logical volume selector needs the name of a logical volume",
                    "name the logical volume, as in vg/root or just root when the disk has one volume group",
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
    try validateExecutionDeadline(&diagnostics, request);
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
    try validateKernelOptionChange(&diagnostics, request);
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

    inline for (comptime std.enums.values(limits_mod.Limit)) |limit| {
        if (request.limits.value(limit) == 0) {
            try diagnostics.append(validationError(
                .invalid_limits,
                "/limits",
                "a limit of zero would reject every source, including an empty one",
                comptime "raise it with " ++ limit.flag() ++ " <value>",
            ));
        }
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
        // The same predicate the guest applies, rather than a looser one here:
        // a URL this accepts and the boundary refuses is a plan that resolves,
        // hashes and then fails once the run is already under way.
        for (repository.urls) |url| {
            if (vm_control.hasUserinfo(url)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/repositories/urls",
                    "a repository URL must not carry a userinfo component",
                    "declare the credential under the repository instead; a URL is hashed into the plan and recorded in provenance verbatim",
                ));
            } else if (!vm_control.validRepositoryUrl(url)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/repositories/urls",
                    "repository URLs must be single-line http, https or file URLs",
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
        if (repository.credential) |credential| {
            try validateRepositoryCredential(diagnostics, credential, repository.urls);
        }
    }
    try validatePackageLock(diagnostics, policy);
    if (packageCacheDirectory(policy.cache)) |directory| {
        if (validatePackageCacheDirectory(directory)) |_| {} else |err| {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/packages/cache",
                switch (err) {
                    error.PackageCacheDirectoryNotAbsolute => "a declared package cache directory must be an absolute host path",
                    error.PackageCacheDirectoryIsRoot => "a declared package cache directory must not be the host root",
                    error.PackageCacheDirectoryNotNormalized => "a declared package cache directory must be normalized, with no empty, `.` or `..` component",
                },
                "name the directory the way the build machine names it, without a trailing slash or a relative component",
            ));
        }
    }
    // An offline transaction resolves no names, so a resolver declared
    // alongside one would be installed, unused and recorded -- a plan
    // asserting a dependence the run cannot have. The default `host_resolver`
    // is not refused, because it is what a caller who said nothing gets.
    if (offlinePackageCache(policy.cache) and policy.resolver == .nameservers) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/packages/resolver",
            "an offline package transaction has no name to resolve",
            "drop the resolver policy, or select an online cache mode if the transaction really does reach a network",
        ));
    }
    switch (policy.resolver) {
        .host_resolver => {},
        // Two refusals with two messages. `127.0.0.53` is one well-formed
        // dotted quad, so telling its author to check the count and the format
        // names the only two things they got right.
        .nameservers => |nameservers| vm_control.validateNameservers(nameservers) catch |err| switch (err) {
            error.UnusableNameserver => try diagnostics.append(validationError(
                .invalid_policy,
                "/packages/resolver/nameservers",
                "a declared resolver cannot be a loopback, unspecified, multicast or reserved address",
                "name the resolver by the address other machines reach it on, or select host_resolver to state that this machine's own is meant",
            )),
            else => try diagnostics.append(validationError(
                .invalid_policy,
                "/packages/resolver/nameservers",
                "a declared resolver needs one to three dotted-quad IPv4 addresses",
                "state at most MAXNS nameservers, each as a dotted quad",
            )),
        },
    }
}

/// Whether a package lock says something a run can act on and check.
///
/// The rules are all pure -- actions and locks are both in the request -- so
/// every one of them is a refusal written where the request is written rather
/// than a failure discovered with the target root already mounted.
fn validatePackageLock(
    diagnostics: *std.array_list.Managed(Diagnostic),
    policy: PackagePolicy,
) !void {
    const locks = switch (policy.lock) {
        .unlocked => return,
        .snapshot => |snapshot| {
            if (snapshot.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/packages/lock/snapshot", "snapshot identifiers must not be empty", null));
            }
            return;
        },
        .exact => |locks| locks,
    };

    // A lock that pins nothing is not a weaker lock, it is a policy that says
    // "these are all the packages" while naming none -- and under the coverage
    // rule below it would refuse every action it was paired with, which is a
    // confusing way to say the request meant `unlocked`.
    if (locks.len == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/packages/lock/exact",
            "an exact lock must pin at least one package",
            "select unlocked to state that versions are not pinned",
        ));
    }

    // A lock is a statement about a transaction, so a request with no package
    // actions has nothing for it to be about. Refused here rather than left to
    // run, because the run would compare the whole installed set against an
    // empty transaction and fail on the first package the input image already
    // carried -- an error naming something the request never touched, raised
    // after the image had been staged.
    if (policy.actions.len == 0) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/packages/lock/exact",
            "an exact lock requires at least one package action to lock",
            "select unlocked when the request declares no package actions",
        ));
    }

    for (locks, 0..) |lock, index| {
        if (!validLockField(lock.name) or
            !validLockField(lock.evr) or
            !validLockField(lock.architecture))
        {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/packages/lock/exact",
                "exact locks require a package name, an EVR, and an architecture, each a non-empty single-line value",
                null,
            ));
            continue;
        }
        // `1.2.3` and `0:1.2.3-4.azl3` are different amounts of pinning, and
        // only the second is one. Refusing the short form here is what keeps a
        // half-written lock from reporting itself as reproducible after
        // matching whatever release the repository happened to hold.
        if (std.mem.indexOfScalar(u8, lock.evr, ':') == null or
            std.mem.indexOfScalar(u8, lock.evr, '-') == null)
        {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/packages/lock/exact",
                "an exact lock's EVR must be rpm's full epoch:version-release form",
                "write the epoch even when it is zero, as `rpm -qa --qf '%{EPOCHNUM}:%{VERSION}-%{RELEASE}'` reports it",
            ));
        }
        // Two locks for one name cannot both hold, and the verifier would
        // report whichever it compared second.
        for (locks[0..index]) |previous| {
            if (std.mem.eql(u8, previous.name, lock.name) and
                std.mem.eql(u8, previous.architecture, lock.architecture))
            {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/lock/exact",
                    "an exact lock must not pin one package and architecture twice",
                    null,
                ));
            }
        }
    }

    for (policy.actions) |action| {
        const names: []const []const u8 = switch (action) {
            // Removal is the one action a lock has nothing to say about: it
            // names what must not be installed, and a lock names versions for
            // what is.
            .remove => continue,
            // The one action that names nothing. Its subject is whatever the
            // declared repositories hold at the moment it runs, which is the
            // question an exact lock exists to close, so the two cannot be
            // stated together -- and saying so here beats resolving a plan
            // that could never have been reproducible.
            .update_all => {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/lock/exact",
                    "an exact lock cannot be combined with update_all, which names its subject as whatever the repositories hold",
                    "name the packages to update with update_selected, and pin each of them",
                ));
                continue;
            },
            .install, .update_selected => |values| values,
        };
        for (names) |name| {
            if (!containsLockFor(locks, name)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/lock/exact",
                    "every package an action names must be pinned by the exact lock",
                    "add the package, and the dependencies it pulls in, from the lock a completed online run emits",
                ));
            }
        }
    }
}

fn validLockField(value: []const u8) bool {
    return value.len != 0 and std.mem.indexOfAny(u8, value, "\r\n\x00 \t") == null;
}

fn containsLockFor(locks: []const PackageVersionLock, name: []const u8) bool {
    for (locks) |lock| {
        if (std.mem.eql(u8, lock.name, name)) return true;
    }
    return false;
}

/// A credential is sent to every URL of its repository, so every URL has to be
/// one that can carry it and one it is safe to send to.
fn validateRepositoryCredential(
    diagnostics: *std.array_list.Managed(Diagnostic),
    credential: RepositoryCredential,
    urls: []const []const u8,
) !void {
    switch (credential) {
        .basic => |basic| {
            // The user name is written as its own line in a tdnf repository
            // file, so anything that could end the line or start a second
            // directive would be a way to configure the package manager.
            if (basic.username.len == 0 or
                basic.username.len > max_credential_field_bytes or
                !isSingleLinePrintable(basic.username))
            {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/repositories/credential/basic/username",
                    "a user name must be a non-empty single-line printable value",
                    null,
                ));
            }
            try validateCredentialSource(
                diagnostics,
                basic.password,
                "/packages/repositories/credential/basic/password",
            );
        },
    }

    for (urls) |url| {
        if (std.mem.startsWith(u8, url, "https://")) continue;
        // Basic authentication puts the password on the wire under nothing but
        // base64, so a plaintext URL sends it to anyone on the path; a
        // `file://` URL cannot carry it at all, and a credential declared
        // against one would be a policy stated and never applied. Both are
        // refused where they are written rather than discovered afterwards.
        try diagnostics.append(validationError(
            .invalid_policy,
            "/packages/repositories/urls",
            "a repository with a declared credential must use https for every URL",
            "use https, or remove the credential if the repository needs none",
        ));
        break;
    }
}

fn validateCredentialSource(
    diagnostics: *std.array_list.Managed(Diagnostic),
    source: CredentialSource,
    path: []const u8,
) !void {
    switch (source) {
        // Absolute, because the material is read by the run rather than by the
        // caller, and a relative path would name a different file depending on
        // where the build happened to be started from.
        .host_path => |file| if (file.len == 0 or
            file.len > Io.Dir.max_path_bytes or
            !std.fs.path.isAbsolute(file) or
            !isSingleLinePrintable(file))
        {
            try diagnostics.append(validationError(
                .invalid_policy,
                path,
                "a credential file must be named by an absolute single-line path",
                null,
            ));
        },
        .host_environment => |name| if (!isValidEnvironmentName(name)) {
            try diagnostics.append(validationError(
                .invalid_policy,
                path,
                "a credential environment variable must be named [A-Za-z_][A-Za-z0-9_]*",
                null,
            ));
        },
    }
}

fn isSingleLinePrintable(text: []const u8) bool {
    for (text) |byte| {
        if (byte < 0x20 or byte == 0x7F) return false;
    }
    return true;
}

fn isValidEnvironmentName(name: []const u8) bool {
    if (name.len == 0 or name.len > max_credential_field_bytes) return false;
    if (!std.ascii.isAlphabetic(name[0]) and name[0] != '_') return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and byte != '_') return false;
    }
    return true;
}

/// Whether a hook script says what should run it.
///
/// The kernel decides how to execute a file from its first bytes, so a script
/// without a shebang is refused where it is written instead of failing with an
/// unattributed `ENOEXEC` from a `chroot` several phases into a privileged
/// run. Requiring it also makes what interprets the hook a property of the
/// declaration rather than of whichever shell the target image happens to
/// ship: the same request runs the same interpreter everywhere, or does not
/// run at all.
fn namesAnInterpreter(script: []const u8) bool {
    return std.mem.startsWith(u8, script, "#!");
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
            .inline_script => |script| {
                if (script.len == 0) {
                    try diagnostics.append(validationError(.invalid_policy, "/hooks/source", "inline scripts must not be empty", null));
                } else if (!namesAnInterpreter(script)) {
                    try diagnostics.append(validationError(
                        .invalid_policy,
                        "/hooks/source/inline_script",
                        "a hook script must name its own interpreter on its first line",
                        "start the script with a shebang, for example #!/bin/sh",
                    ));
                }
                if (script.len > max_hook_script_bytes) {
                    try diagnostics.append(validationError(
                        .invalid_policy,
                        "/hooks/source/inline_script",
                        "the hook script is larger than a hook script may be",
                        "keep a hook under 256 KiB, or install what it needs as a package",
                    ));
                }
            },
            .host_path => |path| if (path.len == 0) {
                try diagnostics.append(validationError(.invalid_policy, "/hooks/source", "hook source paths must not be empty", null));
            },
        }
        if (hook.arguments.len > max_hook_arguments) {
            try diagnostics.append(validationError(
                .invalid_policy,
                "/hooks/arguments",
                "the hook declares more arguments than a hook may take",
                "pass at most 64 arguments, or move the list into the script",
            ));
        }
        for (hook.arguments) |argument| {
            if (std.mem.indexOfScalar(u8, argument, 0) != null) {
                try diagnostics.append(validationError(.invalid_policy, "/hooks/arguments", "hook arguments must not contain NUL", null));
            }
            if (argument.len > max_hook_argument_bytes) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/hooks/arguments",
                    "a hook argument is longer than a hook argument may be",
                    "keep each argument under 4096 bytes",
                ));
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
        .when_needed => |when_needed| {
            if (when_needed.generator) |generator| {
                if (generator.len == 0 or std.mem.indexOfAny(u8, generator, "\r\n\x00") != null) {
                    try diagnostics.append(validationError(.invalid_policy, "/initramfs/when_needed/generator", "initramfs generators must be non-empty single-line values", null));
                }
            }
        },
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
        .unchanged, .relabel => {},
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

/// A kernel-argument change reaches a preserved image one of two ways, and
/// which one is a property of the backend rather than of the request: an
/// unprivileged backend rewrites the boot entries the image already carries,
/// and `unsafe_chroot` edits the input the target's own generator reads and
/// re-runs that generator. The backend that can do neither is refused here
/// rather than in preflight, because the answer depends only on the request.
fn validateKernelOptionChange(
    diagnostics: *std.array_list.Managed(Diagnostic),
    request: *const Request,
) Allocator.Error!void {
    const options = request.boot_security.extra_kernel_options;
    if (options.len == 0) return;
    switch (request.execution.backend) {
        // A fresh build renders the options into the configuration it
        // generates, so nothing has to be rewritten and nothing here applies.
        .native_fresh => return,
        .native_edit, .rebuild => {},
        .unsafe_chroot => {
            // `/etc/default/grub` is sourced by the shell that runs the
            // generator as root inside the target, so this path holds the
            // option text to a stricter rule than the entry files do.
            grub_defaults.validateOptions(options) catch {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/boot_security/extra_kernel_options",
                    "this backend splices the options into a shell assignment in /etc/default/grub, so they cannot carry a quote, a backslash, a dollar sign or a backtick",
                    "write the options as plain kernel command-line words, as in console=ttyS0 quiet",
                ));
                return;
            };
        },
        .vm => {
            try diagnostics.append(validationError(
                .unsupported_execution_backend,
                "/boot_security/extra_kernel_options",
                "this backend never mounts the image it customizes, so it can reach neither the boot entries on the ESP nor the target's own bootloader tooling",
                "select native_edit, rebuild, or unsafe_chroot to change kernel arguments",
            ));
            return;
        },
    }
    boot_options.validateOptions(options) catch {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/boot_security/extra_kernel_options",
            "kernel options must be non-empty printable text with no surrounding whitespace",
            "write the options as they should appear on the kernel command line, as in console=ttyS0 quiet",
        ));
    };
}

/// The whole-run budget, and how it composes with the budgets inside it.
///
/// The guest boot timeouts are not duplicated by this deadline: they bound
/// different things, and a run deadline that could preempt them would make
/// them unreachable. So the deadline must be strictly larger than every boot
/// budget the run can spend in sequence. Refused here rather than resolved by
/// clamping, because a boot timeout that can never fire is a policy the caller
/// wrote and did not get.
fn validateExecutionDeadline(
    diagnostics: *std.array_list.Managed(Diagnostic),
    request: *const Request,
) Allocator.Error!void {
    const deadline_seconds = request.execution.deadline_seconds orelse return;
    if (deadline_seconds == 0 or deadline_seconds > max_execution_deadline_seconds) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/deadline_seconds",
            "the execution deadline is outside the supported range",
            "select a deadline of at least 1 second and at most 86400 seconds",
        ));
        return;
    }
    if (request.execution.backend != .vm) return;
    const policy = request.execution.vm orelse return;
    const guest_budget: u64 = @as(u64, policy.boot_timeout_seconds) + switch (policy.boot) {
        .direct_kernel => 0,
        .firmware => |firmware| @as(u64, firmware.boot_timeout_seconds),
    };
    if (deadline_seconds <= guest_budget) {
        try diagnostics.append(validationError(
            .invalid_policy,
            "/execution/deadline_seconds",
            "the execution deadline does not exceed the guest boot budget it contains",
            "raise deadline_seconds above the sum of the vm boot timeouts, or lower those timeouts",
        ));
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
            if (!isValidConsoleMarker(firmware.console_marker)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/execution/vm/boot/firmware/console_marker",
                    "firmware boot requires a printable single-line console marker",
                    "name the bytes the image's own boot chain prints once it has taken control",
                ));
            }
            if (firmware.boot_timeout_seconds == 0 or
                firmware.boot_timeout_seconds > max_vm_boot_timeout_seconds)
            {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/execution/vm/boot/firmware/boot_timeout_seconds",
                    "the firmware boot timeout is outside the supported range",
                    "select a timeout of at least 1 second and at most 86400 seconds",
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
            !offlinePackageCache(request.packages.cache))
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
    // A hook now reaches the guest through the control document's script
    // channel, so what is left to refuse is only what the channel itself
    // cannot carry: the document is bounded, and a request with more hooks
    // than it holds must be told so rather than failing when it is written.
    if (request.hooks.len > vm_control.max_hooks) {
        try diagnostics.append(validationError(
            .unsupported_execution_backend,
            "/hooks",
            "the vm backend carries fewer hooks than this request declares",
            "reduce the number of hooks, or use the unsafe_chroot backend",
        ));
    }
    // A cache directory is a host directory the run reads and writes through,
    // and the control document carries rendered JSON rather than host files.
    // Named for the same reason a hook is: a guest that quietly resolved
    // against the network would publish an image whose plan says it was built
    // from a declared cache.
    if (packageCacheDirectory(request.packages.cache) != null) {
        try diagnostics.append(validationError(
            .unsupported_execution_backend,
            "/packages/cache",
            "the vm backend has no channel that carries a cache directory to the guest",
            "use the unsafe_chroot backend for a declared package cache",
        ));
    }
    // A resolver the chroot backend reaches happily can mean something else
    // entirely from a guest behind user-mode networking, which would make one
    // hashed plan resolve names two different ways -- the divergence a declared
    // resolver exists to remove. Addresses outside the subnet are fine: slirp
    // NATs their traffic out through the host to the same place a chroot would
    // reach. Addresses inside it are aliases for the build machine.
    switch (request.packages.resolver) {
        .host_resolver => {},
        .nameservers => |nameservers| for (nameservers) |nameserver| {
            if (vm_control.isUserNetAddress(nameserver)) {
                try diagnostics.append(validationError(
                    .invalid_policy,
                    "/packages/resolver/nameservers",
                    "the guest's user-mode network aliases its own subnet to this machine",
                    "name a resolver outside 10.0.2.0/24, or select host_resolver to state that the build machine's own is meant",
                ));
            }
        },
    }
}

/// A marker is matched against a byte stream a guest emits, so it must be
/// something a guest can actually emit on one line. Control bytes are refused
/// because a marker spanning a line break would match only if the guest's
/// console happened to use the same line ending the plan was written with.
fn isValidConsoleMarker(marker: []const u8) bool {
    if (marker.len == 0 or marker.len > max_vm_console_marker_bytes) return false;
    for (marker) |byte| {
        if (byte < 0x20 or byte > 0x7e) return false;
    }
    return true;
}

/// Whether the host can read the firmware a plan's firmware boot names.
///
/// Separate from the rest of the `vm` probe because it is the one part whose
/// refusal an operator fixes by installing something, and because the
/// requirement that carries it names the exact file that was missing.
pub fn vmFirmwareAvailable(io: Io, firmware: VmFirmware) CapabilityState {
    if (!readableRegularFile(io, firmware.code_path)) return .missing;
    if (!readableRegularFile(io, firmware.vars_path)) return .missing;
    return .available;
}

fn readableRegularFile(io: Io, path: []const u8) bool {
    const stat = Io.Dir.cwd().statFile(io, path, .{}) catch return false;
    if (stat.kind != .file or stat.size == 0) return false;
    Io.Dir.cwd().access(io, path, .{ .read = true }) catch return false;
    return true;
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
        if (!validKernelModuleName(module.name) or (module.load and module.disabled)) {
            try diagnostics.append(validationError(.invalid_customization, "/os/kernel_modules", "kernel module names must be safe and cannot be loaded and disabled simultaneously", null));
        }
        if (module.options) |options| {
            // `\\` is refused with the line terminators because `modprobe.d`
            // continues a line ending in one, which would absorb whatever
            // directive is rendered next into this module's parameters.
            if (std.mem.indexOfAny(u8, options, "\r\n\x00\\") != null) {
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

/// Stricter than `validConfigName`, because a module name is not only a
/// filename component: it is the whole of a `modules-load.d` line and the
/// subject of a `modprobe.d` `blacklist` or `options` directive. Every way
/// out of that position is silent, so this is an allowlist rather than a list
/// of things to refuse -- whitespace retargets the directive at a different
/// module (`overlay -f` blacklists `overlay`), a trailing `\` continues the
/// line and swallows the directive rendered after it, and a leading `#` or
/// `;` turns a `modules-load.d` line into a comment that loads nothing. Real
/// module names are alphanumerics, `_`, `-` and `.`, none of which are.
///
/// Mirrored by `unsafe_chroot.validKernelModuleName`.
fn validKernelModuleName(name: []const u8) bool {
    if (name.len == 0 or name.len > 128 or !std.ascii.isAlphanumeric(name[0])) return false;
    for (name[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '_' and byte != '-' and byte != '.')
        {
            return false;
        }
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
    bootloader_prepare,
    filesystem_finalize,
    verity_seal,
    bootloader_install,
    uki,
    finalize,
    /// Relabelling comes after every other change the run makes, including the
    /// bootloader configuration and the `finalize` hooks. A relabel is only
    /// true of the tree as it stood when the tool walked it, so anything
    /// written afterwards would be exactly the unlabelled file the relabel
    /// exists to prevent.
    selinux,
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
    /// Appends the declared options to the kernel command line of every boot
    /// entry the preserved image carries.
    change_kernel_options,
    /// Adds the declared options to the input the target's own bootloader
    /// generator reads, then re-runs that generator inside the target. The
    /// durable form of the same change, and the only one that survives the
    /// target's next kernel update.
    regenerate_boot_configuration,
    /// Reads the disk image a backend staged and writes the COSI bundle that
    /// the transaction commits in its place.
    write_cosi_bundle,
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
    /// The preserved source disk must carry a GPT, because a COSI bundle
    /// describes a GPT disk and a preserved output keeps the partitioning it
    /// was given.
    gpt_source,
    /// The preserved source disk must carry boot entries whose kernel command
    /// line can be appended to. Probed against the source, because whether it
    /// does is a property of the image and not of the request.
    kernel_option_change,
    rebuild,
    unsafe_chroot,
    vm,
    package_management,
    repository_access,
    repository_trust,
    package_cache,
    package_lock,
    /// Declares that the run's name resolution comes from the build host
    /// rather than from the request.
    ///
    /// Both executing backends inherit it, by different routes.
    /// `unsafe_chroot` binds the host's own `/etc/resolv.conf` into the target
    /// root. The VM backend looks like it escapes this and does not: libslirp
    /// rewrites packets addressed to `10.0.2.3` to whatever `get_dns_addr`
    /// returns, and on Linux that reads `/etc/resolv.conf` in the emulator
    /// process. So the guest's answers depend on the build machine exactly as
    /// much; only the process that opens the file differs.
    ///
    /// It is a declaration rather than a probe -- `systemCapabilityCheck`
    /// always reports it available -- because the executors tolerate a host
    /// with no resolver, and rightly: a transaction whose repository URLs are
    /// literal addresses, or that only removes packages, resolves no names at
    /// all. Refusing those runs for a file they never read would be a false
    /// refusal. Its job is to name the one input the plan does not carry, so a
    /// consumer that requires every input to come from the request can refuse
    /// exactly this.
    read_host_resolver,
    /// A credential's material is read from the build machine -- a file it
    /// names or a variable of the build process -- rather than carried in the
    /// request. The plan states which, and this names it so a consumer that
    /// requires every input to come from the request can refuse it.
    ///
    /// The material itself is deliberately nowhere: not in the request, not
    /// under the plan hash, not in provenance. The `path` here is the locator,
    /// which is the part that can be published.
    ///
    /// Like `read_host_resolver` this is a declaration rather than a probe. A
    /// preflight that opened the file would make the capability a blocking
    /// check on a secret's presence, which is a different question from
    /// whether the plan is allowed to read one -- and would have to open it
    /// long before the run needs it.
    read_host_credential,
    script_execution,
    guest_execution,
    initramfs_regeneration,
    selinux_policy,
    selinux_relabel,
    cross_architecture_runner,
    /// Placing the declared `modules-load.d`/`modprobe.d` configuration in
    /// the target root. Separate from `arbitrary_filesystem_mutation` because
    /// its destinations are a closed, named set rather than anywhere in the
    /// filesystem, which is what lets the executor backends satisfy it
    /// without being able to create files in general.
    kernel_module_configuration,
    arbitrary_filesystem_mutation,
    boot_policy_mutation,
    generalization,
    atomic_commit,
    /// The EDK2 code and variable-store template a firmware boot names. Its
    /// own requirement rather than part of `vm`, so a refusal says which file
    /// was missing instead of only that the backend was unavailable.
    vm_firmware,
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
    source_profile: SourceProfilePolicy = .strict,
    source_mounts: []const SourceMount = &.{},
    identity_rewrite: IdentityRewritePolicy = .rewrite_and_verify,
    journal: ext4.JournalOptions = .{},
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
    limits: limits_mod.ImportLimits,
    transaction_path: []const u8,
    staging_output_path: []const u8,
    /// The artifact the transaction commits to `output.path`. It is
    /// `staging_output_path` for every disk format, and the COSI bundle built
    /// from that image when the request asks for one.
    staging_commit_path: []const u8,
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
    const staging_commit_path = if (request.output.format.bundlesStagedImage())
        try std.fs.path.join(plan_allocator, &.{ transaction_path, "output.cosi" })
    else
        staging_output_path;

    const resolved_execution = ExecutionPolicy{
        .workspace_path = resolved_workspace_path,
        .backend = request.execution.backend,
        .overwrite = request.execution.overwrite,
        .acknowledge_unsafe = request.execution.acknowledge_unsafe,
        .vm = try dupeVmPolicy(plan_allocator, request.execution.vm),
        .deadline_seconds = request.execution.deadline_seconds,
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
            .root_partition = try dupePartitionSelector(plan_allocator, storage.root_partition),
            .source_profile = storage.source_profile,
            .source_mounts = try dupeSourceMounts(plan_allocator, storage.source_mounts),
            .identity_rewrite = storage.identity_rewrite,
            .journal = storage.journal,
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
    const resolved_initramfs = try resolveInitramfsPolicy(
        plan_allocator,
        request.initramfs,
        resolved_packages,
    );
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
        request.output.format,
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
        resolved_runner_architecture,
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
        .limits = request.limits,
        .transaction_path = transaction_path,
        .staging_output_path = staging_output_path,
        .staging_commit_path = staging_commit_path,
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
    // `when_needed` is asked rather than taken at face value. It is a
    // question, and the plan carries its answer, so a request that resolves
    // to `unchanged` has to reach the same architecture decisions as one that
    // stated `unchanged` outright -- otherwise `when_needed` would refuse
    // cross-architecture builds that its own resolved plan permits.
    const initramfs_changes = switch (request.initramfs) {
        .unchanged => false,
        .regenerate => true,
        .when_needed => initramfsNeedsRegeneration(request.packages),
    };
    return request.execution.backend == .unsafe_chroot or
        request.execution.backend == .vm or
        request.packages.actions.len != 0 or
        request.hooks.len != 0 or
        initramfs_changes or
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

/// Mount specifications hold borrowed paths, so a resolved plan -- which
/// outlives the request that produced it -- has to own copies of them.
fn dupeSourceMounts(
    allocator: Allocator,
    mounts: []const SourceMount,
) Allocator.Error![]const SourceMount {
    const copies = try allocator.alloc(SourceMount, mounts.len);
    for (mounts, copies) |mount, *copy| {
        copy.* = mount;
        copy.source_path = try allocator.dupe(u8, mount.source_path);
        copy.target = try allocator.dupe(u8, mount.target);
        copy.partition = try dupePartitionSelector(allocator, mount.partition);
    }
    return copies;
}

/// A logical volume selector borrows the caller's names, so a plan that
/// outlives the request has to own them like every other string it keeps.
fn dupePartitionSelector(
    allocator: Allocator,
    selector: PartitionSelector,
) Allocator.Error!PartitionSelector {
    return switch (selector) {
        .gpt_index, .mbr_index => selector,
        .logical_volume => |volume| .{ .logical_volume = .{
            .volume_group = try allocator.dupe(u8, volume.volume_group),
            .logical_volume = try allocator.dupe(u8, volume.logical_volume),
        } },
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
            .credential = if (repository.credential) |credential| switch (credential) {
                .basic => |basic| .{
                    .basic = .{
                        .username = try allocator.dupe(u8, basic.username),
                        // Not resolved against `base_path`, unlike a trust
                        // path. Validation demands an absolute path precisely so
                        // that it is not build-relative: trust material sits
                        // beside the build file and is meant to, a credential
                        // never should, and a relative one silently reading a
                        // file out of the source tree is the mistake worth
                        // making impossible.
                        .password = switch (basic.password) {
                            .host_path => |path| .{
                                .host_path = try allocator.dupe(u8, path),
                            },
                            .host_environment => |name| .{
                                .host_environment = try allocator.dupe(u8, name),
                            },
                        },
                    },
                },
            } else null,
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
                    .evr = try allocator.dupe(u8, lock.evr),
                    .architecture = try allocator.dupe(u8, lock.architecture),
                };
            }
            break :blk .{ .exact = owned };
        },
    };
    return .{
        .actions = actions,
        .repositories = repositories,
        .cache = switch (policy.cache) {
            .online => .online,
            .online_populating => |path| .{
                .online_populating = try allocator.dupe(u8, path),
            },
            .cache_only => |path| .{ .cache_only = try allocator.dupe(u8, path) },
        },
        .lock = lock,
        .resolver = switch (policy.resolver) {
            .host_resolver => .host_resolver,
            .nameservers => |nameservers| .{
                .nameservers = try dupeStrings(allocator, nameservers),
            },
        },
    };
}

fn dupeHookRecords(
    allocator: Allocator,
    records: []const HookRecord,
) Allocator.Error![]const HookRecord {
    const owned = try allocator.alloc(HookRecord, records.len);
    for (records, 0..) |record, index| {
        owned[index] = .{
            .name = try allocator.dupe(u8, record.name),
            .phase = record.phase,
            .source_sha256 = record.source_sha256,
            .exit_code = record.exit_code,
        };
    }
    return owned;
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

/// Whether the declared changes make the existing initramfs wrong.
///
/// **Package actions are the whole rule today**, and the reason is dracut's
/// own: an initramfs is a snapshot of a subset of the root filesystem, so a
/// package that ships a kernel module, a udev rule, or one of the binaries
/// dracut copies in leaves the existing image describing a root that no
/// longer exists. `update_all` additionally may install a kernel that has no
/// initramfs at all yet.
///
/// **Kernel-module configuration is deliberately not a trigger.** The
/// intuition says it should be -- it is configuration about modules -- but
/// zvmi runs dracut `--no-hostonly` on both executors, and every path by
/// which dracut consults the target's own `/etc/modules-load.d` or
/// `/etc/modprobe.d` is gated on `$hostonly`: `90kernel-modules` installs
/// `/etc/modprobe.d/*.conf` only under `[[ $hostonly ]]`, and
/// `01systemd-modules-load` both reads `modulesloadconfdir` and installs
/// `/etc/modules-load.d/*.conf` only under `[[ $hostonly ]]`. So that
/// configuration does not reach the initramfs and does not change a byte of
/// it; it takes effect when the real root boots. Triggering on it would do
/// minutes of work to produce an identical image and would assert a causal
/// link that does not exist.
///
/// Nothing else in the request can reach here: both executor backends refuse
/// every other part of the model -- general OS customization, existing-path
/// operations, generalization, hooks, SELinux, and any non-default boot
/// policy, which is where `verity` lives -- so there is no third case to get
/// wrong. When one of those is implemented, it belongs in this function.
fn initramfsNeedsRegeneration(packages: PackagePolicy) bool {
    return packages.actions.len != 0;
}

/// Turns a request's policy into the one the plan carries.
///
/// `when_needed` is resolved away here rather than carried into the plan, so
/// that the plan states what will happen, the plan hash covers it, provenance
/// records it, and no executor has to learn a third tag. A resolved plan
/// therefore never holds `when_needed`, which is why copying one uses
/// `dupeInitramfsPolicy` instead.
fn resolveInitramfsPolicy(
    allocator: Allocator,
    policy: InitramfsPolicy,
    packages: PackagePolicy,
) Allocator.Error!InitramfsPolicy {
    const decided: InitramfsPolicy = switch (policy) {
        .when_needed => |when_needed| if (initramfsNeedsRegeneration(packages)) .{
            .regenerate = .{
                .generator = when_needed.generator,
                // Named by nobody, because a run that did not decide *whether* to
                // regenerate is in no position to decide *what* -- the releases
                // are discovered in the target root after the packages have run.
                .kernels = &.{},
                // A derived decision must not be stricter than the question
                // that produced it. Nothing asked for a regeneration here, so
                // a root with no kernel has nothing stale in it; failing would
                // turn a build that succeeds under `unchanged` into an error
                // purely for having asked to be told.
                .no_installed_kernels = .nothing_to_regenerate,
            },
        } else .unchanged,
        else => policy,
    };
    return dupeInitramfsPolicy(allocator, decided);
}

fn dupeInitramfsPolicy(
    allocator: Allocator,
    policy: InitramfsPolicy,
) Allocator.Error!InitramfsPolicy {
    return switch (policy) {
        .unchanged => .unchanged,
        .when_needed => |when_needed| .{ .when_needed = .{
            .generator = if (when_needed.generator) |generator| try allocator.dupe(u8, generator) else null,
        } },
        .regenerate => |regenerate| .{ .regenerate = .{
            .generator = if (regenerate.generator) |generator| try allocator.dupe(u8, generator) else null,
            .kernels = try dupeStrings(allocator, regenerate.kernels),
            .no_installed_kernels = regenerate.no_installed_kernels,
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
            .firmware => |firmware| blk: {
                // Built whole before it becomes the union's payload: a
                // half-filled firmware behind a `.firmware` tag would read as
                // a complete policy to everything downstream.
                const owned = VmFirmware{
                    .code_path = try allocator.dupe(u8, firmware.code_path),
                    .vars_path = try allocator.dupe(u8, firmware.vars_path),
                    .console_marker = try allocator.dupe(u8, firmware.console_marker),
                    .secure_boot = firmware.secure_boot,
                    .boot_timeout_seconds = firmware.boot_timeout_seconds,
                };
                break :blk .{ .firmware = owned };
            },
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
        .relabel => .relabel,
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

fn dupePackageLock(
    allocator: Allocator,
    pins: []const PackageVersionLock,
) Allocator.Error![]const PackageVersionLock {
    const owned = try allocator.alloc(PackageVersionLock, pins.len);
    for (pins, owned) |pin, *target| {
        target.* = .{
            .name = try allocator.dupe(u8, pin.name),
            .evr = try allocator.dupe(u8, pin.evr),
            .architecture = try allocator.dupe(u8, pin.architecture),
        };
    }
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
    output_format: OutputFormat,
) Allocator.Error![]Operation {
    var specs = std.array_list.Managed(OperationSpec).init(allocator);
    defer specs.deinit();
    try appendBackendOperationSpecs(&specs, backend, storage);
    try appendPreInitramfsOperationSpecs(&specs, packages, hooks);
    try appendBackendFinalOperationSpecs(&specs, backend, policy, storage, hooks, initramfs, selinux, output_format);

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
    output_format: OutputFormat,
) Allocator.Error!void {
    switch (backend) {
        .native_fresh => {
            const generation = storage.fresh.generation;
            try specs.append(.{ .phase = .initramfs, .action = .prepare_initramfs });
            try appendInitramfsPolicySpec(specs, initramfs);
            if (generation == .gen1) try specs.append(.{ .phase = .bootloader_prepare, .action = .prepare_boot_configuration });
            try specs.append(.{ .phase = .filesystem_finalize, .action = .populate_filesystem });
            try appendBeforeSealSpecs(specs, hooks);
            if (policy.verity) try specs.append(.{ .phase = .verity_seal, .action = .seal_verity });
            if (generation == .gen2) try specs.append(.{ .phase = .bootloader_prepare, .action = .prepare_boot_configuration });
            try specs.append(.{ .phase = .bootloader_install, .action = .install_bootloader });
            if (policy.boot_mode != .bls_only) try specs.append(.{ .phase = .uki, .action = .generate_uki });
            try appendFinalizeHookSpecs(specs, hooks);
            try appendSelinuxSpecs(specs, selinux);
            try specs.append(.{ .phase = .filesystem_close, .action = .check_and_close_filesystems });
            try specs.append(.{ .phase = .output_conversion, .action = .convert_output });
        },
        .native_edit, .rebuild, .unsafe_chroot, .vm => {
            try appendInitramfsPolicySpec(specs, initramfs);
            try appendBeforeSealSpecs(specs, hooks);
            // In the phase that prepares boot configuration, after every
            // filesystem change and before the stage is published: the
            // declared options have to be what the published image carries,
            // whatever else the run rewrote on the way there.
            if (policy.extra_kernel_options.len != 0 and appendsKernelOptions(backend)) {
                try specs.append(.{ .phase = .bootloader_prepare, .action = .change_kernel_options });
            }
            if (policy.extra_kernel_options.len != 0 and regeneratesBootConfiguration(backend)) {
                try specs.append(.{ .phase = .bootloader_prepare, .action = .regenerate_boot_configuration });
            }
            try appendFinalizeHookSpecs(specs, hooks);
            try appendSelinuxSpecs(specs, selinux);
            try specs.append(.{ .phase = .output_conversion, .action = .publish_standalone_output });
        },
    }
    if (output_format.bundlesStagedImage()) {
        try specs.append(.{ .phase = .output_conversion, .action = .write_cosi_bundle });
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
) Allocator.Error!void {
    for (hooks) |hook| if (hook.phase == .before_seal) {
        try specs.append(.{ .phase = .before_seal, .action = .execute_hook });
    };
}

fn appendSelinuxSpecs(
    specs: *std.array_list.Managed(OperationSpec),
    selinux: SelinuxPolicy,
) Allocator.Error!void {
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
        plan.data.output.format,
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
    runner_architecture: Architecture,
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
            if (output.format.bundlesStagedImage()) {
                try capabilities.append(.{
                    .kind = .gpt_source,
                    .path = disk.path,
                    .reason = "select a GPT-partitioned source, or an output format other than cosi",
                });
            }
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
            try capabilities.append(.{ .kind = .rebuild, .path = "", .reason = "extract and rebuild the selected ext4 source profile without guest execution" });
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
            if (execution.vm) |vm| switch (vm.boot) {
                .direct_kernel => {},
                .firmware => |firmware| try capabilities.append(.{
                    .kind = .vm_firmware,
                    .path = firmware.code_path,
                    .related_path = firmware.vars_path,
                    .reason = switch (runner_architecture) {
                        .x86_64 => "read the x86_64 EDK2 firmware code and variable template the firmware boot names",
                        .aarch64 => "read the aarch64 EDK2 firmware code and variable template the firmware boot names",
                    },
                }),
            };
        },
    }
    if (execution.backend != .native_fresh and hasGeneralOsCustomization(customization)) {
        try capabilities.append(.{
            .kind = .arbitrary_filesystem_mutation,
            .path = "",
            .reason = if (execution.backend == .rebuild)
                "apply deterministic filesystem and OS changes to the imported strict ext4 tree"
            else
                "general preserved-filesystem creation and metadata mutation are not implemented",
        });
    }
    // Excluded for `native_fresh` on the same grounds as the blanket above:
    // a fresh build creates the whole tree, so nothing it writes into that
    // tree is a question about what can be done to a preserved filesystem.
    if (execution.backend != .native_fresh and customization.kernel_modules.len != 0) {
        try capabilities.append(.{
            .kind = .kernel_module_configuration,
            .path = "",
            .reason = "write the declared kernel-module configuration to its named destinations",
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
    if (packageCacheDirectory(packages.cache)) |directory| {
        try capabilities.append(.{
            .kind = .package_cache,
            .path = directory,
            .reason = if (offlinePackageCache(packages.cache))
                "satisfy package actions from the declared offline cache"
            else
                "write the transaction's downloads into the declared cache directory",
        });
    }
    if (packages.lock != .unlocked) {
        try capabilities.append(.{ .kind = .package_lock, .path = "", .reason = "enforce the declared package snapshot or exact-version lock" });
    }
    // The chroot backend unshares only mount and pid, so its transaction
    // resolves through the build host -- unless the cache policy is offline,
    // in which case the run installs no resolver into the target at all and
    // there is nothing to read. A guest resolves through the host only when
    // it is given the network that reaches it: an offline guest is started
    // with `-nic none`, so there is no route to a host resolver for it to
    // take and a plan must not declare a dependence the run cannot have.
    // Three terms rather than one, because the capability set has to be a
    // function of what the run does rather than of which refusal happens to
    // be in force.
    const resolves_through_host = !offlinePackageCache(packages.cache) and
        switch (execution.backend) {
            .unsafe_chroot => true,
            .vm => if (execution.vm) |vm| vm.network == .declared_repositories else false,
            else => false,
        };
    if (resolves_through_host and
        packages.actions.len != 0 and
        packages.resolver == .host_resolver)
    {
        try capabilities.append(.{
            .kind = .read_host_resolver,
            .path = "/etc/resolv.conf",
            .reason = "resolve package repository names through the build host's resolver",
        });
    }
    // One per declared source rather than one for the set, because the point
    // is to name each thing the run will read: a consumer refusing host inputs
    // needs to see which file or variable, not merely that there was one.
    for (packages.repositories) |repository| {
        const credential = repository.credential orelse continue;
        const source = switch (credential) {
            .basic => |basic| basic.password,
        };
        try capabilities.append(.{
            .kind = .read_host_credential,
            .path = switch (source) {
                .host_path => |file| file,
                .host_environment => |name| try std.fmt.allocPrint(
                    allocator,
                    "env:{s}",
                    .{name},
                ),
            },
            .reason = try std.fmt.allocPrint(
                allocator,
                "authenticate to the declared repository '{s}'",
                .{repository.id},
            ),
        });
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
        .relabel => {
            try capabilities.append(.{
                .kind = .selinux_relabel,
                .path = switch (input) {
                    .disk => |disk| disk.path,
                    .iso_oci => "",
                },
                .reason = "relabel the preserved filesystem with the policy the target carries",
            });
            try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "run the target SELinux labelling tool" });
        },
        .configure => |configure| {
            try capabilities.append(.{ .kind = .selinux_policy, .path = "", .reason = "apply the declared SELinux policy and mode" });
            try capabilities.append(.{ .kind = .guest_execution, .path = "", .reason = "use target SELinux policy tooling" });
            if (configure.relabel) {
                try capabilities.append(.{ .kind = .selinux_relabel, .path = "", .reason = "relabel the preserved filesystem" });
            }
        },
    }
    if (execution.backend != .native_fresh) {
        if (hasUnsupportedBootPolicyChange(boot_policy)) {
            try capabilities.append(.{ .kind = .boot_policy_mutation, .path = "", .reason = "mutate preserved boot configuration" });
        }
        if (boot_policy.extra_kernel_options.len != 0 and appendsKernelOptions(execution.backend)) {
            try capabilities.append(.{
                .kind = .kernel_option_change,
                .path = switch (input) {
                    .disk => |disk| disk.path,
                    .iso_oci => "",
                },
                .reason = "append the declared options to the kernel command line the image already carries",
            });
        }
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

/// OS customization that needs the ability to create and mutate files
/// anywhere in the target root, which is everything except kernel-module
/// configuration -- that one has a closed set of destinations and so is
/// requested as its own, narrower capability.
fn hasGeneralOsCustomization(customization: OsCustomization) bool {
    return customization.filesystem.len != 0 or
        customization.hostname != null or
        customization.groups.len != 0 or
        customization.users.len != 0 or
        customization.services.len != 0;
}

/// The backends that apply a kernel-argument change by rewriting the boot
/// entries on the image's ESP. The rest either generate the command line
/// themselves (`native_fresh`) or cannot reach the ESP at all.
/// Whether the backend adds the options by editing the boot entries the
/// image already carries. `unsafe_chroot` adds them too, but by regenerating
/// from the target's own configuration, which is a different operation with a
/// different capability and a different provenance record.
fn appendsKernelOptions(backend: ExecutionBackend) bool {
    return backend == .native_edit or backend == .rebuild;
}

/// Whether the backend adds the options by re-running the target's own
/// bootloader generator.
fn regeneratesBootConfiguration(backend: ExecutionBackend) bool {
    return backend == .unsafe_chroot;
}

/// Whether the policy asks for something no preserved backend can carry out.
/// Kernel options are excluded because they are now applied where they can
/// be, and requested as their own, narrower capability where they cannot be
/// assumed to apply.
fn hasUnsupportedBootPolicyChange(policy: BootSecurityPolicy) bool {
    var without_options = policy;
    without_options.extra_kernel_options = "";
    return !isDefaultBootPolicy(without_options);
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
        .preserve => |storage| {
            hashPartitionSelector(&hash, storage.root_partition);
            hash.update(@tagName(storage.source_profile));
            // Order matters: a later mount shadows an earlier one, so two
            // plans that list the same mounts in a different order describe
            // different trees and must not share a hash.
            hashInt(&hash, storage.source_mounts.len);
            for (storage.source_mounts) |mount| {
                hashString(&hash, mount.source_path);
                hashPartitionSelector(&hash, mount.partition);
                hashString(&hash, mount.target);
                hash.update(@tagName(mount.filesystem));
                hashInt(&hash, mount.fat_metadata.directory_mode);
                hashInt(&hash, mount.fat_metadata.file_mode);
                hashInt(&hash, mount.fat_metadata.uid);
                hashInt(&hash, mount.fat_metadata.gid);
            }
            hash.update(@tagName(storage.identity_rewrite));
            hashBool(&hash, storage.journal.enabled);
            // The absent size is hashed as its own value rather than as zero,
            // so "default for this filesystem size" and an explicit size that
            // happens to match it stay distinguishable.
            hashBool(&hash, storage.journal.size_bytes != null);
            hashInt(&hash, storage.journal.size_bytes orelse 0);
        },
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
    // The absent deadline is hashed as its own value rather than as zero, so
    // "unbounded" and a declared budget stay distinguishable.
    hashBool(&hash, plan.execution.deadline_seconds != null);
    hashInt(&hash, plan.execution.deadline_seconds orelse 0);
    if (plan.execution.vm) |vm| {
        hash.update(&.{1});
        hashString(&hash, vm.emulator_command);
        hashInt(&hash, @intFromEnum(std.meta.activeTag(vm.boot)));
        switch (vm.boot) {
            .direct_kernel => {},
            .firmware => |firmware| {
                hashString(&hash, firmware.code_path);
                hashString(&hash, firmware.vars_path);
                hashString(&hash, firmware.console_marker);
                hashBool(&hash, firmware.secure_boot);
                hashInt(&hash, firmware.boot_timeout_seconds);
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
    inline for (comptime std.enums.values(limits_mod.Limit)) |limit| {
        hashInt(&hash, plan.limits.value(limit));
    }
    hashString(&hash, plan.transaction_path);
    hashString(&hash, plan.staging_output_path);
    hashString(&hash, plan.staging_commit_path);
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
        // Where the credential comes from, never what it is -- there is no
        // material in these types to hash, by construction. A plan hash that
        // covered a password would verify a guess of it offline.
        hashInt(hash, @intFromBool(repository.credential != null));
        if (repository.credential) |credential| {
            hashInt(hash, @intFromEnum(std.meta.activeTag(credential)));
            switch (credential) {
                .basic => |basic| {
                    hashString(hash, basic.username);
                    hashInt(hash, @intFromEnum(std.meta.activeTag(basic.password)));
                    switch (basic.password) {
                        .host_path => |path| hashString(hash, path),
                        .host_environment => |name| hashString(hash, name),
                    }
                },
            }
        }
    }
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy.cache)));
    // The directory, not only the mode. Two runs reading different caches
    // could install different bytes, so they are not one plan -- and hashing
    // it here rather than relying on the `package_cache` capability's path
    // keeps that true whatever the capability set later becomes.
    switch (policy.cache) {
        .online => {},
        .online_populating, .cache_only => |path| hashString(hash, path),
    }
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy.lock)));
    switch (policy.lock) {
        .unlocked => {},
        .snapshot => |snapshot| hashString(hash, snapshot),
        .exact => |locks| {
            hashInt(hash, locks.len);
            for (locks) |lock| {
                hashString(hash, lock.name);
                hashString(hash, lock.evr);
                hashString(hash, lock.architecture);
            }
        },
    }
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy.resolver)));
    switch (policy.resolver) {
        .host_resolver => {},
        .nameservers => |nameservers| hashStrings(hash, nameservers),
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
            hashInt(hash, @intFromEnum(regenerate.no_installed_kernels));
        },
        // Resolved away before a plan exists, so this never contributes to a
        // plan hash. Hashed distinctly anyway rather than asserted absent:
        // a wrong digest is a better failure than undefined behaviour.
        .when_needed => |when_needed| hashOptionalString(hash, when_needed.generator),
    }
}

fn hashSelinuxPolicy(hash: *std.crypto.hash.sha2.Sha256, policy: SelinuxPolicy) void {
    hashInt(hash, @intFromEnum(std.meta.activeTag(policy)));
    switch (policy) {
        .unchanged, .relabel => {},
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
        .logical_volume => |volume| {
            hashString(hash, volume.volume_group);
            hashString(hash, volume.logical_volume);
        },
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
        deadline: Deadline,
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
        deadline: Deadline,
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
            // The rebuild backend writes it into the tree it imports; the two
            // executor backends write it into a filesystem they have mounted.
            .kernel_module_configuration => switch (plan.data.execution.backend) {
                .rebuild => .available,
                .unsafe_chroot => unsafeChrootCapabilityState(platform, io, plan),
                .vm => vmCapabilityState(platform, io, plan),
                else => .unsupported,
            },
            .vm => vmCapabilityState(platform, io, plan),
            .gpt_source => gptSourceAvailable(io, requirement.path),
            .kernel_option_change => kernelOptionChangeAvailable(io, requirement.path),
            .vm_firmware => if (plan.data.execution.vm) |vm| switch (vm.boot) {
                .direct_kernel => .unsupported,
                .firmware => |firmware| vmFirmwareAvailable(io, firmware),
            } else .unsupported,
            .package_cache => packageCacheAvailable(io, plan),
            .selinux_relabel => switch (plan.data.execution.backend) {
                .unsafe_chroot => selinuxRelabelAvailable(
                    io,
                    plan,
                    unsafeChrootCapabilityState(platform, io, plan),
                ),
                .vm => selinuxRelabelAvailable(
                    io,
                    plan,
                    vmCapabilityState(platform, io, plan),
                ),
                else => .unsupported,
            },
            .selinux_policy,
            .boot_policy_mutation,
            => .unsupported,
            // Both executor backends enforce the lock now, and neither the
            // rebuild backend nor any other runs a package transaction at all,
            // so there is nothing for them to enforce it against.
            .package_lock => if (plan.data.execution.backend == .vm)
                vmCapabilityState(platform, io, plan)
            else if (plan.data.execution.backend == .unsafe_chroot)
                unsafeChrootCapabilityState(platform, io, plan)
            else
                .unsupported,
            .cross_architecture_runner,
            => if (plan.data.execution.backend == .vm)
                vmCapabilityState(platform, io, plan)
            else
                .unsupported,
            .script_execution,
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
        // Kernel-module configuration is the one piece of the OS model these
        // backends carry out; the rest still needs general file creation in
        // the target root, which neither of them implements.
        hasGeneralOsCustomization(data.os) or
        data.generalization != .none or
        // Relabelling is the one SELinux operation these backends carry out.
        // Changing the mode or the active policy is still refused here, so a
        // request for it fails preflight rather than being half-honoured.
        data.selinux == .configure or
        // Kernel options are the one boot-policy field this backend carries
        // out: it edits the input the target's own generator reads and
        // re-runs that generator. Every other field asks for a bootloader
        // this backend does not install.
        hasUnsupportedBootPolicyChange(data.boot_security) or
        !validUnsafePackageLock(data.packages.lock))
    {
        return .unsupported;
    }
    // Nothing about `data.hooks` is checked here on purpose. `resolve` runs
    // `validate` first, so every hook shape this backend could not execute --
    // an empty or oversized script, one naming no interpreter, an argument
    // vector past the declared bounds -- has already been refused by name and
    // can never reach a plan. A second copy of those rules here would be
    // unreachable, and an unreachable rule is one that quietly stops matching
    // the reachable one. What the worker does not trust, it re-checks on its
    // own side of the privilege boundary instead, in `validateManifestPolicy`.
    for (data.packages.actions) |action| {
        const names: []const []const u8 = switch (action) {
            .install, .remove, .update_selected => |values| values,
            // The one action that names nothing: its subject is whatever the
            // declared repositories hold, so an empty name list is the shape
            // rather than an omission.
            .update_all => continue,
        };
        if (names.len == 0) return .unsupported;
        for (names) |name| {
            if (!validUnsafePackageName(name)) return .unsupported;
        }
    }
    for (data.packages.repositories) |repository| {
        if (!validUnsafeRepositoryId(repository.id)) return .unsupported;
    }
    for (data.os.kernel_modules) |module| {
        if (!validKernelModuleName(module.name)) return .unsupported;
    }
    switch (data.initramfs) {
        .unchanged => {},
        .regenerate => |regenerate| {
            // Naming no kernel release means every release installed in the
            // target root, which only the backend can enumerate and only
            // after the package actions have run. Both backends support that,
            // so there is nothing to refuse here.
            for (regenerate.kernels) |kernel| {
                if (!validUnsafeKernelRelease(kernel)) return .unsupported;
            }
            if (regenerate.generator) |generator| {
                if (!std.mem.eql(u8, generator, "dracut")) return .unsupported;
            }
        },
        // `resolve` turns this into one of the arms above, so a resolved plan
        // cannot hold it. Declining rather than asserting keeps the failure on
        // the safe side of the boundary if that ever stops being true.
        .when_needed => return .unsupported,
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
        // Kernel-module configuration is the one piece of the OS model these
        // backends carry out; the rest still needs general file creation in
        // the target root, which neither of them implements.
        hasGeneralOsCustomization(data.os) or
        data.generalization != .none or
        // Relabelling is the one SELinux operation these backends carry out;
        // see `unsafeChrootCapabilityState`.
        data.selinux == .configure or
        !isDefaultBootPolicy(data.boot_security) or
        // A declared cache directory is a host directory the run reads and
        // writes, and the guest control document carries rendered JSON rather
        // than host files. Refused by name here for the same reason hooks
        // are, rather than accepted and quietly not honoured.
        data.packages.cache != .online or
        !validUnsafePackageLock(data.packages.lock))
    {
        return .unsupported;
    }
    // The guest runs a hook only where the whole document reaches it, so this
    // bounds what the channel carries rather than whether it exists.
    if (data.hooks.len > vm_control.max_hooks) return .unsupported;
    if (vm.acceleration == .hardware and
        data.architectures.runner != data.architectures.host)
    {
        return .unsupported;
    }
    if (data.architectures.runner != data.architectures.image) return .unsupported;
    for (data.packages.actions) |action| {
        const names: []const []const u8 = switch (action) {
            .install, .remove, .update_selected => |values| values,
            // The one action that names nothing: its subject is whatever the
            // declared repositories hold, so an empty name list is the shape
            // rather than an omission.
            .update_all => continue,
        };
        if (names.len == 0) return .unsupported;
        for (names) |name| {
            if (!validUnsafePackageName(name)) return .unsupported;
        }
    }
    for (data.packages.repositories) |repository| {
        if (!validUnsafeRepositoryId(repository.id)) return .unsupported;
    }
    for (data.os.kernel_modules) |module| {
        if (!validKernelModuleName(module.name)) return .unsupported;
    }
    switch (data.initramfs) {
        .unchanged => {},
        .regenerate => |regenerate| {
            // Naming no kernel release means every release installed in the
            // target root, which only the backend can enumerate and only
            // after the package actions have run. Both backends support that,
            // so there is nothing to refuse here.
            for (regenerate.kernels) |kernel| {
                if (!validUnsafeKernelRelease(kernel)) return .unsupported;
            }
            if (regenerate.generator) |generator| {
                if (!std.mem.eql(u8, generator, "dracut")) return .unsupported;
            }
        },
        // `resolve` turns this into one of the arms above, so a resolved plan
        // cannot hold it. Declining rather than asserting keeps the failure on
        // the safe side of the boundary if that ever stops being true.
        .when_needed => return .unsupported,
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

/// Gates the lock on what the executors can put on a package-manager command
/// line and compare against the rpm database afterwards. `validate` has
/// already refused every lock that is not a complete identity; this is the
/// narrower question of whether these particular bytes are safe to hand to
/// tdnf as a `name-epoch:version-release.arch` spec.
fn validUnsafePackageLock(lock: PackageLockPolicy) bool {
    const pins = switch (lock) {
        .unlocked => return true,
        // A snapshot names a state of the repositories, not of the target
        // root, so there is nothing in the image for an executor to check it
        // against. Whatever ends up honouring it belongs on the repository
        // side of the run, and until something does, a plan that declares one
        // must not resolve as though it were enforced.
        .snapshot => return false,
        .exact => |pins| pins,
    };
    for (pins) |pin| {
        if (!validUnsafePackageName(pin.name)) return false;
        if (!validUnsafeEvr(pin.evr)) return false;
        if (!validUnsafeKernelRelease(pin.architecture)) return false;
    }
    return true;
}

/// An EVR carries one `:` that a package name may not, so it gets its own
/// check rather than reusing the name rule.
fn validUnsafeEvr(evr: []const u8) bool {
    if (evr.len == 0 or !std.ascii.isAlphanumeric(evr[0])) return false;
    for (evr[1..]) |byte| {
        if (!std.ascii.isAlphanumeric(byte) and
            byte != '.' and
            byte != '_' and
            byte != '+' and
            byte != '-' and
            byte != '~' and
            byte != '^' and
            byte != ':')
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
        .disk_dependencies, .gpt_source, .kernel_option_change => .unsupported,
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
        // A declaration, not a probe: the executors tolerate a host with no
        // resolver because a transaction can resolve no names at all, so a
        // `missing` here would refuse runs that never read the file. Naming
        // it in the plan is the whole job.
        .read_host_resolver,
        // Same reasoning, and one more: probing would mean opening a secret to
        // decide whether the plan may open it.
        .read_host_credential,
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
        .kernel_module_configuration,
        .arbitrary_filesystem_mutation,
        .boot_policy_mutation,
        .generalization,
        // Firmware is only ever probed against the plan's own policy, which
        // a bare requirement does not carry; preflight routes it there.
        .vm_firmware,
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

/// Whether the declared package cache directory can be used as the plan
/// says.
///
/// The mode decides what "can" means, because it decides whether the
/// directory is an input or an output: `cache_only` reads it, so a directory
/// that is not there yet is `missing` -- a run that would reach the network
/// instead of failing is the one outcome this policy exists to prevent.
/// `online_populating` writes it, and this run creates it, so only its parent
/// has to exist.
fn packageCacheAvailable(io: Io, plan: *const ResolvedPlan) CapabilityState {
    const cache = plan.data.packages.cache;
    const directory = packageCacheDirectory(cache) orelse return .unsupported;
    validatePackageCacheDirectory(directory) catch return .unsupported;
    // The backend has to be one that can carry a host directory into the
    // target at all; the VM backend refuses this policy outright.
    if (plan.data.execution.backend != .unsafe_chroot) return .unsupported;
    const probed = if (offlinePackageCache(cache))
        directory
    else
        std.fs.path.dirname(directory) orelse return .unsupported;
    const stat = Io.Dir.cwd().statFile(io, probed, .{}) catch return .missing;
    if (stat.kind != .directory) return .missing;
    return .available;
}

/// Whether a disk carries a GPT that the COSI writer can describe.
fn gptSourceAvailable(io: Io, path: []const u8) CapabilityState {
    var image = image_mod.Image.openPathReadOnly(io, path) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .unsupported,
    };
    defer image.close(io);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    _ = gpt.readGpt(image, io, arena.allocator()) catch return .missing;
    return .available;
}

/// Whether the source image carries boot entries the declared options can be
/// appended to. Answered by reading the source, so a request that could only
/// fail is refused before a workspace exists, which is the difference between
/// a named refusal and a half-built image.
fn kernelOptionChangeAvailable(io: Io, path: []const u8) CapabilityState {
    var image = image_mod.Image.openPathReadOnly(io, path) catch |err| switch (err) {
        error.FileNotFound => return .missing,
        else => return .unsupported,
    };
    defer image.close(io);
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    _ = boot_options.inspect(arena.allocator(), io, &image, null) catch return .missing;
    return .available;
}

/// Whether the source root carries what a relabel needs: a labelling tool and
/// the file-contexts file of the policy it names.
///
/// Answered by reading the source image, in the shape `gptSourceAvailable` and
/// `kernelOptionChangeAvailable` already use, because the alternative is to
/// discover it inside the executor after the source has been copied -- which
/// spends the whole copy to learn something the source could have been asked.
///
/// `backend_state` is the backend's own answer, threaded in rather than
/// recomputed so a plan the backend cannot execute at all is reported as that
/// rather than as a missing policy.
///
/// The policy is read from the target's own configuration here only to decide
/// whether one exists. Which policy the relabel actually uses is resolved
/// again while the run executes, because a package action in the same run can
/// install or replace it.
fn selinuxRelabelAvailable(
    io: Io,
    plan: *const ResolvedPlan,
    backend_state: CapabilityState,
) CapabilityState {
    if (plan.data.selinux != .relabel) return .unsupported;
    if (backend_state != .available) return backend_state;
    const disk = switch (plan.data.input) {
        .disk => |value| value,
        .iso_oci => return .unsupported,
    };
    const storage = switch (plan.data.storage) {
        .preserve => |value| value,
        .fresh => return .unsupported,
    };
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();
    const allocator = arena.allocator();

    var root: preserved_image.SourceRoot = .{};
    root.open(allocator, io, disk.path, storage.root_partition) catch return .missing;
    defer root.close(io);

    const has_tool = for (selinux_mod.setfiles_candidates) |candidate| {
        if (root.exists(io, candidate)) break true;
    } else false;
    if (!has_tool) return .missing;

    const config = root.readFileAlloc(io, allocator, selinux_mod.config_path) catch return .missing;
    const policy = selinux_mod.parseConfiguredPolicy(config) orelse return .missing;
    var buffer: [selinux_mod.max_policy_name_bytes + 64]u8 = undefined;
    const contexts = selinux_mod.fileContextsPath(&buffer, policy) catch return .missing;
    if (!root.exists(io, contexts)) return .missing;
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
    const output_format = plan.data.output.format.stagingImageFormat();
    _ = preserved_image.inspectRebuild(std.heap.page_allocator, io, .{
        .source_path = disk.path,
        .output_path = plan.data.staging_output_path,
        .output_format = output_format,
        .root_partition = storage.root_partition,
        .source_profile = storage.source_profile,
        .source_mounts = storage.source_mounts,
        .identity_rewrite = storage.identity_rewrite,
        .journal = storage.journal,
        .existing_operations = plan.data.existing_path_operations,
        .customization = plan.data.os,
        .generalization = plan.data.generalization,
        .source_date_epoch = plan.data.reproducibility.source_date_epoch,
        .limits = plan.data.limits,
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

/// What a hook was and what running it did.
///
/// A hook is the one input whose effect the plan cannot describe -- everything
/// else in a request says what will be true afterwards, a hook says only that
/// some code ran. So the record names the code by digest rather than by where
/// it came from: an inline script and a host path that held the same bytes
/// produced the same run, and a host path whose contents changed between two
/// runs did not.
pub const HookRecord = struct {
    name: []const u8,
    phase: HookPhase,
    /// The bytes as they were placed in the target root and executed, not the
    /// bytes of whatever file was named. For a `host_path` source the two are
    /// the same read; digesting the placed copy is what makes that checkable.
    source_sha256: Digest,
    /// Zero in every published provenance, because a hook that exited nonzero
    /// fails the run and nothing is published. Recorded anyway, so the record
    /// states what was observed rather than leaving it to be assumed.
    exit_code: u8,
};

/// What the target's own bootloader tooling was asked to do, and what came
/// out. A regenerated configuration is a file the run did not write itself,
/// so the only durable account of the change is which input was edited, which
/// program regenerated from it, and how many entries came out carrying the
/// options.
pub const BootConfigurationRecord = struct {
    /// The source of truth that was edited, as an absolute guest path.
    defaults_path: []const u8,
    /// The generator, as an absolute guest path. `tools` carries its reported
    /// version and the exact argv it was run with.
    generator_path: []const u8,
    /// The configuration the generator wrote, as an absolute guest path.
    generated_path: []const u8,
    /// Entries in the regenerated configuration whose command line carries the
    /// options. Zero never reaches a record: the run fails first.
    entries: usize,
    /// Whether the source of truth already ended with these options, so the
    /// run regenerated from an input it did not have to change. Distinguishes
    /// an image that gained the options from one that already had them.
    defaults_already_current: bool,
    /// The text that was added, recorded because the published command line is
    /// the target's own plus this and neither half is derivable from the other.
    options: []const u8,
};

pub const UnsafeChrootRuntimeReport = struct {
    arena: std.heap.ArenaAllocator,
    tools: []const ToolRecord,
    installed_packages: []const []const u8,
    package_lock: []const PackageVersionLock = &.{},
    hooks: []const HookRecord = &.{},
    /// Present exactly when the request asked for a kernel-argument change.
    boot_configuration: ?BootConfigurationRecord = null,
    /// Present exactly when the request declared a cache directory.
    package_cache: ?PackageCacheRecord = null,

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

/// The firmware a firmware-booted run was attested through, named by digest
/// as well as by path so the record can be checked against the host later.
pub const VmFirmwareRecord = struct {
    code_path: []const u8,
    code_sha256: Digest,
    /// The template the per-run store was copied from. The copy itself is
    /// gone by the time this is written, which is what `variable_store` says.
    vars_template_path: []const u8,
    vars_template_sha256: Digest,
    variable_store: VmVariableStorePolicy,
    /// What the policy asked for, not what the guest concluded: this backend
    /// never enters the firmware-booted guest, so it has nothing to observe
    /// Secure Boot state with and does not pretend otherwise.
    secure_boot: bool,
    /// The machine the attestation guest ran on, which differs from the
    /// appliance's when Secure Boot wiring is required.
    machine: []const u8,
    console_marker: []const u8,
    boot_timeout_seconds: u32,
    /// The stage as it was published, digested after the attestation guest
    /// exited. Equal to the digest taken before it started, or the run failed:
    /// this is the recorded proof that the boot mode did not change the bytes.
    attested_stage_sha256: Digest,
};

/// How the guest that performed the customization was brought up, and — for a
/// firmware run — what the published bytes were additionally attested with.
pub const VmBootRecord = union(enum) {
    direct_kernel,
    firmware: VmFirmwareRecord,
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
    /// `direct_kernel` for a run that was only an appliance boot, `firmware`
    /// for one whose published bytes also came up through their own boot
    /// chain. The two are never the same run recorded differently.
    boot: VmBootRecord = .direct_kernel,
    /// Modules the guest inserted, in insertion order. Empty says the image's
    /// kernel needed no help, which is the case this backend started with.
    modules: []const VmModuleRecord = &.{},
};

pub const VmRuntimeReport = struct {
    arena: std.heap.ArenaAllocator,
    tools: []const ToolRecord,
    installed_packages: []const []const u8,
    package_lock: []const PackageVersionLock = &.{},
    hooks: []const HookRecord = &.{},
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
    /// The lock this run would have to declare to install exactly what it
    /// installed: every package the transaction added or changed, at the
    /// identity it settled on, and nothing the input image already carried.
    ///
    /// Emitted whether or not a lock was declared. A run that verified one
    /// restates it here, which is a tautology worth keeping because the
    /// alternative is a provenance record whose meaning depends on the policy
    /// beside it. A run that declared none is the interesting case: this is
    /// where the lock for the next run comes from.
    ///
    /// Empty for a run with no package actions, where there is nothing to
    /// state rather than nothing found.
    emitted_package_lock: []const PackageVersionLock = &.{},
    /// Hooks that ran, in the order they ran. Empty for a run that declared
    /// none, which is not the same as a backend that could not have run them:
    /// that request never reaches a provenance record at all.
    hooks: []const HookRecord = &.{},
    rebuild: ?PreservedRebuildRecord,
    /// Present exactly when the request asked for a kernel-argument change on
    /// a backend that applies it by rewriting the entries the image carries.
    kernel_options: ?KernelOptionsRecord,
    /// Present exactly when the request asked for a kernel-argument change on
    /// a backend that applies it by re-running the target's own bootloader
    /// generator. Never set at the same time as `kernel_options`: the two are
    /// different operations and the plan names which one it published.
    boot_configuration: ?BootConfigurationRecord = null,
    /// Present exactly when the request declared a cache directory. Absent
    /// means the transaction used whatever cache the target image carried,
    /// which is the ambient state this record exists to distinguish itself
    /// from.
    package_cache: ?PackageCacheRecord = null,
};

/// What a run did with a declared package cache directory.
///
/// Both paths are recorded because they answer different questions: the host
/// path says which directory on the build machine this run read or filled,
/// and the guest path says where the transaction saw it, which is what the
/// tdnf configuration in the run names.
pub const PackageCacheRecord = struct {
    /// Whether the run filled the directory or was confined to it.
    offline: bool,
    host_path: []const u8,
    guest_path: []const u8,
};

pub const KernelOptionsRecord = struct {
    /// The text appended, recorded because the published command line is the
    /// image's own plus this and neither half is derivable from the other.
    appended: []const u8,
    grub_entries: usize,
    bls_entries: usize,
    /// Entries that already ended with exactly this text and were left alone.
    /// Non-zero means the source already carried the options, which is a
    /// different image from one where they were added.
    entries_already_current: usize,
    files_rewritten: usize,
    /// Entry files the verification pass read back after the rewrite.
    verified_files: usize,
};

pub const PreservedRebuildRecord = struct {
    /// Which importer accepted the source. Recorded rather than assumed,
    /// because `reproducible` follows from it and a provenance record that
    /// implied reproducibility it does not have would be worse than silent.
    profile: ext4.SourceProfile,
    reproducible: bool,
    ext4_uuid: Uuid,
    ext4_label: [16]u8,
    ext4_block_size: u32,
    filesystem_length: u64,
    ext4_global_timestamp: u32,
    /// Whether the source filesystem carried a journal, and how many blocks
    /// the rebuilt one's journal occupies. Both recorded because a rebuild
    /// that drops a journal, or adds one, changes what the image does after
    /// an unclean shutdown -- and neither is visible from the tree digests.
    source_has_journal: bool,
    journal_block_count: u32,
    source_root_tree_digest: Digest,
    final_root_tree_digest: Digest,
    imported_node_count: usize,
    /// Filesystems merged into the root at a mount point, and how many nodes
    /// those mount points hid. Recorded because the output tree cannot be
    /// explained from the root source alone once either is non-zero.
    merged_source_count: usize,
    shadowed_node_count: usize,
    final_node_count: usize,
    existing_operation_count: usize,
    os_customization_count: usize,
    generalization_count: usize,
    /// What reconciling the imported configuration with the rebuilt image's
    /// identifiers changed. Recorded because an fstab entry that was dropped
    /// and a bootloader reference that was rewritten are edits nobody asked
    /// for by name, and provenance is where edits like that are accounted
    /// for. `identity_stale_references` is non-zero only when the operator
    /// chose to be told rather than refused.
    identity_retired_identifiers: usize,
    identity_fstab_entries_rewritten: usize,
    identity_fstab_entries_dropped: usize,
    identity_fstab_entries_unresolved: usize,
    identity_config_files_rewritten: usize,
    identity_config_references_rewritten: usize,
    identity_verified_files: usize,
    identity_stale_references: usize,
};

pub const CosiRecord = struct {
    /// The COSI metadata schema the bundle declares, recorded because a
    /// consumer reads the bundle by that number and it is not derivable from
    /// the request.
    metadata_version: []const u8,
    partition_count: usize,
    /// Whether the bundle carries dm-verity metadata for the root
    /// filesystem. Only a backend that sealed the verity tree itself can
    /// supply it, so this records which kind of COSI was published rather
    /// than leaving its absence to be discovered by a consumer.
    verity_included: bool,
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
    /// Present exactly when the output format is a bundle built from the
    /// staged image.
    cosi: ?CosiRecord,
    /// The largest value each limit reached during this run. A caller sizes a
    /// larger run from these instead of guessing, and a dry run reports them
    /// without committing to a build.
    limit_peaks: limits_mod.Peaks,
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

/// Same alternation, and for the same reason: one run, one emitted lock.
fn guestPackageLock(
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
    vm_report: ?*const VmRuntimeReport,
) []const PackageVersionLock {
    if (unsafe_report) |report| return report.package_lock;
    if (vm_report) |report| return report.package_lock;
    return &.{};
}

/// One run, one set of hooks, so whichever backend carried it out is the one
/// that has them. Written as a lookup for the same reason `guestPackages` is:
/// a second spelling of the alternation is a second place to forget an arm.
fn guestHooks(
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
    vm_report: ?*const VmRuntimeReport,
) []const HookRecord {
    if (unsafe_report) |report| return report.hooks;
    if (vm_report) |report| return report.hooks;
    return &.{};
}

fn guestPackageCache(
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
) ?PackageCacheRecord {
    if (unsafe_report) |report| return report.package_cache;
    return null;
}

fn dupePackageCacheRecord(
    allocator: Allocator,
    record: ?PackageCacheRecord,
) Allocator.Error!?PackageCacheRecord {
    const resolved = record orelse return null;
    return .{
        .offline = resolved.offline,
        .host_path = try allocator.dupe(u8, resolved.host_path),
        .guest_path = try allocator.dupe(u8, resolved.guest_path),
    };
}

fn guestBootConfiguration(
    unsafe_report: ?*const UnsafeChrootRuntimeReport,
) ?BootConfigurationRecord {
    if (unsafe_report) |report| return report.boot_configuration;
    return null;
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
    cosi_report: ?cosi.Report,
    source_digests: []const SourceRecord,
    output_digest: Digest,
    output_file_size: u64,
    limit_peaks: limits_mod.Peaks,
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
        .deadline_seconds = plan.data.execution.deadline_seconds,
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
        const kernel_options = if (preserved_report) |report| report.kernel_options else rebuild_report.?.kernel_options;
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
            .emitted_package_lock = try dupePackageLock(
                result_allocator,
                guestPackageLock(unsafe_report, vm_report),
            ),
            .hooks = try dupeHookRecords(result_allocator, guestHooks(unsafe_report, vm_report)),
            .package_cache = try dupePackageCacheRecord(
                result_allocator,
                guestPackageCache(unsafe_report),
            ),
            .rebuild = if (rebuild_report) |report| .{
                .profile = report.source_profile,
                .reproducible = report.source_reproducible,
                .ext4_uuid = .{ .bytes = report.ext4_uuid },
                .ext4_label = report.ext4_label,
                .ext4_block_size = report.ext4_block_size,
                .filesystem_length = report.filesystem_length,
                .ext4_global_timestamp = report.ext4_global_timestamp,
                .source_has_journal = report.source_has_journal,
                .journal_block_count = report.journal_block_count,
                .source_root_tree_digest = .{ .bytes = report.source_manifest_sha256 },
                .final_root_tree_digest = .{ .bytes = report.final_manifest_sha256 },
                .imported_node_count = report.imported_node_count,
                .merged_source_count = report.merged_source_count,
                .shadowed_node_count = report.shadowed_node_count,
                .final_node_count = report.final_node_count,
                .existing_operation_count = report.existing_operation_count,
                .os_customization_count = report.os_customization_count,
                .generalization_count = report.generalization_count,
                .identity_retired_identifiers = report.identity_rewrite.retired_identifiers,
                .identity_fstab_entries_rewritten = report.identity_rewrite.fstab_entries_rewritten,
                .identity_fstab_entries_dropped = report.identity_rewrite.fstab_entries_dropped,
                .identity_fstab_entries_unresolved = report.identity_rewrite.fstab_entries_unresolved,
                .identity_config_files_rewritten = report.identity_rewrite.config_files_rewritten,
                .identity_config_references_rewritten = report.identity_rewrite.config_references_rewritten,
                .identity_verified_files = report.identity_rewrite.verified_files,
                .identity_stale_references = report.identity_rewrite.stale_references,
            } else null,
            .boot_configuration = if (guestBootConfiguration(unsafe_report)) |record| .{
                .defaults_path = try result_allocator.dupe(u8, record.defaults_path),
                .generator_path = try result_allocator.dupe(u8, record.generator_path),
                .generated_path = try result_allocator.dupe(u8, record.generated_path),
                .entries = record.entries,
                .defaults_already_current = record.defaults_already_current,
                .options = try result_allocator.dupe(u8, record.options),
            } else null,
            .kernel_options = if (kernel_options) |report| .{
                .appended = try result_allocator.dupe(u8, plan.data.boot_security.extra_kernel_options),
                .grub_entries = report.grub_entries,
                .bls_entries = report.bls_entries,
                .entries_already_current = report.entries_already_current,
                .files_rewritten = report.files_rewritten,
                .verified_files = report.verified_files,
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
        // Assembled whole before the tag is published, so a reader can never
        // see `.firmware` beside a record that is still being filled in.
        const boot_record: VmBootRecord = switch (record.boot) {
            .direct_kernel => .direct_kernel,
            .firmware => |firmware| blk_boot: {
                const owned_firmware = VmFirmwareRecord{
                    .code_path = try result_allocator.dupe(u8, firmware.code_path),
                    .code_sha256 = firmware.code_sha256,
                    .vars_template_path = try result_allocator.dupe(
                        u8,
                        firmware.vars_template_path,
                    ),
                    .vars_template_sha256 = firmware.vars_template_sha256,
                    .variable_store = firmware.variable_store,
                    .secure_boot = firmware.secure_boot,
                    .machine = try result_allocator.dupe(u8, firmware.machine),
                    .console_marker = try result_allocator.dupe(u8, firmware.console_marker),
                    .boot_timeout_seconds = firmware.boot_timeout_seconds,
                    .attested_stage_sha256 = firmware.attested_stage_sha256,
                };
                break :blk_boot .{ .firmware = owned_firmware };
            },
        };
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
            .boot = boot_record,
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
                .cosi = if (cosi_report) |report| .{
                    .metadata_version = try result_allocator.dupe(u8, report.metadata_version),
                    .partition_count = report.partition_count,
                    .verity_included = report.verity_included,
                } else null,
                .limit_peaks = limit_peaks,
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
    // Started before the first thing the run creates, so the budget covers
    // the whole execution rather than the part of it a backend happens to
    // own. Everything from here to the commit is inside it.
    const deadline = Deadline.start(io, plan.data.execution.deadline_seconds);
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
    // One sink for whichever backend runs: it collects the peak measurement
    // of every limit for provenance, and the first breach for the diagnostic
    // that names the flag which raises it. The message buffers live here
    // because a diagnostic borrows its strings until the outcome owns them.
    var limit_sink = limits_mod.Diagnostic{};
    var limit_message: [limits_mod.Exceeded.max_message_bytes]u8 = undefined;
    var limit_remediation: [limits_mod.Exceeded.max_remediation_bytes]u8 = undefined;
    // The same arrangement for the first surviving stale identifier, which
    // only the rebuild backend can produce.
    var identity_sink = identity_rewrite.Diagnostic{};
    var identity_message: [identity_rewrite.Stale.max_message_bytes]u8 = undefined;
    var identity_remediation: [identity_rewrite.Stale.max_remediation_bytes]u8 = undefined;
    // And for the boot configuration file a kernel-option change could not
    // apply to, which names the one file a caller has to look at.
    var kernel_options_sink = boot_options.Diagnostic{};
    var kernel_options_message: [kernel_option_message_bytes]u8 = undefined;
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
            fresh_report = runPlan(
                allocator,
                io,
                plan,
                platform,
                event_sink,
                &bridge,
                &limit_sink,
            ) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "", "native-fresh execution failed", err);
                try appendLimitFailure(
                    &diagnostics,
                    limit_sink,
                    "/limits",
                    &limit_message,
                    &limit_remediation,
                );
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
                .output_format = plan.data.output.format.stagingImageFormat(),
                .output_compression = plan.data.output.format.compression(),
                .root_partition = plan.data.storage.preserve.root_partition,
                .operations = plan.data.existing_path_operations,
                .expected_virtual_size = null,
                .max_source_file_bytes = plan.data.limits.max_source_file_bytes,
                .limit_diagnostic = &limit_sink,
                .kernel_options = plan.data.boot_security.extra_kernel_options,
                .kernel_options_diagnostic = &kernel_options_sink,
                .output_create_options = outputCreateOptions(plan),
            }) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "/existing_path_operations", "native preserved-image execution failed", err);
                try appendKernelOptionFailure(&diagnostics, kernel_options_sink, &kernel_options_message, err);
                try appendLimitFailure(
                    &diagnostics,
                    limit_sink,
                    "/limits",
                    &limit_message,
                    &limit_remediation,
                );
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
                .output_format = plan.data.output.format.stagingImageFormat(),
                .output_compression = plan.data.output.format.compression(),
                .root_partition = plan.data.storage.preserve.root_partition,
                .source_profile = plan.data.storage.preserve.source_profile,
                .source_mounts = plan.data.storage.preserve.source_mounts,
                .identity_rewrite = plan.data.storage.preserve.identity_rewrite,
                .journal = plan.data.storage.preserve.journal,
                .identity_diagnostic = &identity_sink,
                .existing_operations = plan.data.existing_path_operations,
                .customization = plan.data.os,
                .generalization = plan.data.generalization,
                .source_date_epoch = plan.data.reproducibility.source_date_epoch,
                .limits = plan.data.limits,
                .limit_diagnostic = &limit_sink,
                .kernel_options = plan.data.boot_security.extra_kernel_options,
                .kernel_options_diagnostic = &kernel_options_sink,
                .expected_virtual_size = null,
                .output_create_options = outputCreateOptions(plan),
            }) catch |err| {
                try appendFailure(&diagnostics, .execution_failed, .execution, "/execution/backend", "preserved-image rebuild failed", err);
                try appendKernelOptionFailure(&diagnostics, kernel_options_sink, &kernel_options_message, err);
                try appendLimitFailure(
                    &diagnostics,
                    limit_sink,
                    "/limits",
                    &limit_message,
                    &limit_remediation,
                );
                try appendStaleIdentityFailure(
                    &diagnostics,
                    identity_sink,
                    &identity_message,
                    &identity_remediation,
                );
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
                .deadline = deadline,
            };
            defer if (hook_context.report) |*report| report.deinit();
            const raw_report = preserved_image.transactRaw(allocator, io, .{
                .source_path = plan.data.input.disk.path,
                .output_path = plan.data.staging_output_path,
                .output_format = plan.data.output.format.stagingImageFormat(),
                .output_compression = plan.data.output.format.compression(),
                .root_partition = plan.data.storage.preserve.root_partition,
                .require_linux_partition = true,
                .output_create_options = outputCreateOptions(plan),
            }, .{
                .context = &hook_context,
                .runFn = runUnsafeChrootHook,
            }) catch |err| {
                try appendExecutionFailure(&diagnostics, "/execution/backend", "unsafe chroot preserved-image execution failed", err);
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
                .kernel_options = raw_report.kernel_options,
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
                .deadline = deadline,
            };
            defer if (hook_context.report) |*report| report.deinit();
            const raw_report = preserved_image.transactRaw(allocator, io, .{
                .source_path = plan.data.input.disk.path,
                .output_path = plan.data.staging_output_path,
                .output_format = plan.data.output.format.stagingImageFormat(),
                .output_compression = plan.data.output.format.compression(),
                .root_partition = plan.data.storage.preserve.root_partition,
                .require_linux_partition = true,
                .output_create_options = outputCreateOptions(plan),
            }, .{
                .context = &hook_context,
                .runFn = runVmHook,
            }) catch |err| {
                try appendExecutionFailure(&diagnostics, "/execution/backend", "virtual machine preserved-image execution failed", err);
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
                .kernel_options = raw_report.kernel_options,
            };
        },
    }

    // Nothing is published after the budget is spent. For the backends that
    // enforce the deadline over their own children this is the second answer
    // to the same question; for the ones that run no target-supplied code --
    // where the work is bounded local disk I/O and interrupting it would only
    // corrupt a staging file -- it is the whole of it: the run finishes what
    // it started and then refuses to commit it.
    deadline.check(io) catch |err| {
        try appendExecutionFailure(&diagnostics, "/execution/backend", "the run exceeded its deadline", err);
        if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };

    // The bundle is written from the image the backend staged, so every
    // backend reaches it by the same route: whatever produced the disk, the
    // bundle describes the bytes that disk ended up holding. Only verity has
    // to be carried in, because a hash tree cannot be recovered from the
    // partition it protects.
    var cosi_report: ?cosi.Report = null;
    if (plan.data.output.format.bundlesStagedImage()) {
        if (event_sink) |sink| sink.emit(.{ .progress = .{
            .phase = .execution,
            .message = "write COSI bundle from the staged image",
        } });
        cosi_report = writeCosiBundle(allocator, io, plan, fresh_report) catch |err| {
            try appendFailure(&diagnostics, .execution_failed, .execution, "/output/format", "failed to write the COSI bundle from the staged image", err);
            if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
            emitDiagnostics(event_sink, diagnostics.items);
            return try failureOutcome(allocator, diagnostics.items);
        };
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

    const output_digest = hashPath(allocator, io, plan.data.staging_commit_path) catch |err| {
        try appendFailure(&diagnostics, .source_hash_failed, .execution, "/output/path", "failed to hash the completed output", err);
        commit_barrier.release(io);
        if (cleanupTransaction(io, plan.data.transaction_path)) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };
    const output_file_size = (cwd.statFile(io, plan.data.staging_commit_path, .{}) catch |err| {
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
        cosi_report,
        source_digests_before,
        output_digest,
        output_file_size,
        limit_sink.peaks,
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

    // The last word before the rename. Everything between the backend and
    // here -- the COSI bundle, the source re-hash, the output digest -- is
    // work the run was still spending time on, and a budget that had run out
    // during it must not end in a published image.
    deadline.check(io) catch |err| {
        result.deinit(allocator);
        final_diagnostics.deinit(allocator);
        final_diagnostics_owned_by_function = false;
        result_owned_by_function = false;
        commit_barrier.release(io);
        const cleanup_diagnostic = cleanupTransaction(io, plan.data.transaction_path);
        transaction_active = false;
        try appendExecutionFailure(&diagnostics, "/output/path", "the run exceeded its deadline", err);
        if (cleanup_diagnostic) |diagnostic| try diagnostics.append(diagnostic);
        emitDiagnostics(event_sink, diagnostics.items);
        return try failureOutcome(allocator, diagnostics.items);
    };

    const commit_result = if (plan.data.execution.overwrite)
        cwd.rename(plan.data.staging_commit_path, cwd, plan.data.output.path, io)
    else
        cwd.renamePreserve(plan.data.staging_commit_path, cwd, plan.data.output.path, io);
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
    deadline: Deadline,
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
    // Before the worker is spawned rather than after it returns: a run with no
    // budget left must not start privileged target code it has no time to
    // finish, and the copy that got the raw stage here is where the budget
    // went.
    try context.deadline.check(io);
    context.report = try run_fn(
        context.platform.context,
        allocator,
        io,
        context.plan,
        target,
        context.deadline,
    );
}

const VmHookContext = struct {
    platform: Platform,
    plan: *const ResolvedPlan,
    deadline: Deadline,
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
    try context.deadline.check(io);
    context.report = try run_fn(
        context.platform.context,
        allocator,
        io,
        context.plan,
        target,
        context.deadline,
    );
}

fn hasValidPlanIntegrity(allocator: Allocator, plan: *const ResolvedPlan) Allocator.Error!bool {
    const data = plan.data;
    const computed_hash = hashPlan(data.*);
    if (data.schema_version != plan_schema_version or
        data.request_api_version != current_api_version or
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
            if (data.storage.fresh.generation == .gen1 and data.output.format == .cosi) return false;
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
    // Kernel arguments reach the image at bootloader install time
    // (native_fresh), through a rewrite of the staged ESP (native_edit,
    // rebuild), or by re-running the target's own generator inside it
    // (unsafe_chroot). The VM backend never mounts the image at all, so a
    // plan that pairs it with kernel options describes an output nobody can
    // produce.
    if (data.boot_security.extra_kernel_options.len != 0 and data.execution.backend == .vm) {
        return false;
    }
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
    const expected_commit = if (data.output.format.bundlesStagedImage())
        try std.fs.path.join(allocator, &.{ expected_transaction, "output.cosi" })
    else
        try allocator.dupe(u8, expected_staging);
    defer allocator.free(expected_commit);
    return std.mem.eql(u8, expected_transaction, data.transaction_path) and
        std.mem.eql(u8, expected_staging, data.staging_output_path) and
        std.mem.eql(u8, expected_commit, data.staging_commit_path);
}

fn runPlan(
    allocator: Allocator,
    io: Io,
    plan: *const ResolvedPlan,
    platform: Platform,
    event_sink: ?EventSink,
    bridge: *BuildEventBridge,
    limit_sink: *limits_mod.Diagnostic,
) !?build_image.BuildImageReport {
    if (plan.data.execution.backend != .native_fresh) return error.InvalidBackend;
    // A bundled output ends with an operation the builder does not run: the
    // bundle is written from the finished image after `build` returns, so the
    // builder is only accountable for the operations before it.
    const trailing = @intFromBool(plan.data.output.format.bundlesStagedImage());
    const build_operations = plan.data.operations[0 .. plan.data.operations.len - trailing];
    var stage_bridge = NativeStageBridge{ .operations = build_operations };
    const stage_sink = build_image.StageSink{ .context = &stage_bridge, .advanceFn = NativeStageBridge.advance };
    if (platform.runFn) |run| {
        try run(platform.context, allocator, io, plan, event_sink, stage_sink);
        if (stage_bridge.next != build_operations.len) return error.InvalidOperationOrder;
        return null;
    }
    var options = buildOptionsFromPlan(plan, bridge, limit_sink);
    options.stage_sink = stage_sink;
    var report = try build_image.build(allocator, io, options);
    errdefer report.deinit(allocator);
    if (stage_bridge.next != build_operations.len) return error.InvalidOperationOrder;
    return report;
}

fn buildOptionsFromPlan(
    plan: *const ResolvedPlan,
    bridge: *BuildEventBridge,
    limit_sink: *limits_mod.Diagnostic,
) build_image.BuildImageOptions {
    const generated = plan.data.generated.?;
    const input = plan.data.input.iso_oci;
    const storage = plan.data.storage.fresh;
    return .{
        .iso_path = input.iso_path,
        .container_path = input.container_path,
        .output_path = plan.data.staging_output_path,
        .size = plan.data.output.disk_size,
        .generation = storage.generation,
        .output_format = plan.data.output.format.stagingImageFormat(),
        .output_compression = plan.data.output.format.compression(),
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
        .limits = plan.data.limits.tree(),
        .limit_diagnostic = limit_sink,
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

/// Writes the COSI bundle the transaction will commit, reading back the disk
/// image the backend staged.
fn writeCosiBundle(
    allocator: Allocator,
    io: Io,
    plan: *const ResolvedPlan,
    fresh_report: ?build_image.BuildImageReport,
) !cosi.Report {
    var img = try image_mod.Image.openPathReadOnly(io, plan.data.staging_output_path);
    defer img.close(io);
    return try cosi.writeWithOptions(img, io, allocator, plan.data.staging_commit_path, .{
        .os_arch = cosiOsArch(plan.data.architectures.image),
        // Only the backend that built the hash tree knows its salt and root
        // hash; a preserved image carries the verity partition without any
        // record of how it was produced, so its bundle omits the block
        // rather than describing it wrongly.
        .root_verity = if (fresh_report) |report| report.verity else null,
    });
}

fn cosiOsArch(architecture: Architecture) []const u8 {
    return switch (architecture) {
        .x86_64 => "x86_64",
        .aarch64 => "arm64",
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

/// Names an execution failure, and says which kind it was.
///
/// A run that spent its budget and a command that failed are different
/// answers to "why did this not publish", and a caller that retries the first
/// with a larger budget would be retrying the second forever. So the deadline
/// gets its own code and its own message rather than arriving as one more
/// error name under `execution_failed`.
fn appendExecutionFailure(
    diagnostics: *std.array_list.Managed(Diagnostic),
    path: []const u8,
    message: []const u8,
    err: anyerror,
) Allocator.Error!void {
    if (err != error.ExecutionDeadlineExceeded) {
        return appendFailure(diagnostics, .execution_failed, .execution, path, message, err);
    }
    try diagnostics.append(.{
        .severity = .@"error",
        .phase = .execution,
        .code = .deadline_exceeded,
        .configuration_path = "/execution/deadline_seconds",
        .message = "the run exceeded its declared execution deadline",
        .cause = .{ .error_name = @errorName(err) },
        .remediation = "raise execution.deadline_seconds, or reduce the work the run declares",
    });
}

/// Adds the diagnostic that names the limit, the observed value, and the flag
/// that raises it. A failure that was not a limit adds nothing, so the generic
/// failure diagnostic stays alone. The message borrows the caller's buffers,
/// which the outcome copies before returning.
fn appendLimitFailure(
    diagnostics: *std.array_list.Managed(Diagnostic),
    limit_sink: limits_mod.Diagnostic,
    path: []const u8,
    message_buffer: []u8,
    remediation_buffer: []u8,
) Allocator.Error!void {
    const breach = limit_sink.exceeded orelse return;
    const message = breach.describe(message_buffer) catch return;
    const remediation = breach.remediation(remediation_buffer) catch return;
    try diagnostics.append(.{
        .severity = .@"error",
        .phase = .execution,
        .code = .limit_exceeded,
        .configuration_path = path,
        .message = message,
        .cause = .{ .error_name = @errorName(breach.limit.err()) },
        .remediation = remediation,
    });
}

/// Adds the diagnostic that names the file still carrying an identifier the
/// rebuild retired. A failure that was not a stale identifier adds nothing,
/// so the generic failure diagnostic stays alone. The message borrows the
/// caller's buffers, which the outcome copies before returning.
/// Enough for the longest path a `boot_options.Diagnostic` carries plus the
/// sentence around it.
const kernel_option_message_bytes: usize = boot_options.max_path_bytes + 128;

/// Names the boot configuration file a kernel-option change stopped on. The
/// backend error alone says only that the run failed; the file is what tells
/// a caller whether the image or the request is the thing to change.
fn appendKernelOptionFailure(
    diagnostics: *std.array_list.Managed(Diagnostic),
    sink: boot_options.Diagnostic,
    message_buffer: []u8,
    cause: anyerror,
) Allocator.Error!void {
    const file = sink.file orelse return;
    const message = std.fmt.bufPrint(
        message_buffer,
        "the kernel options could not be applied to the boot configuration file {s}{s}",
        .{ file.path(), if (file.path_truncated) "..." else "" },
    ) catch return;
    try diagnostics.append(.{
        .severity = .@"error",
        .phase = .execution,
        .code = .execution_failed,
        .configuration_path = "/boot_security/extra_kernel_options",
        .message = message,
        .cause = .{ .error_name = @errorName(cause) },
        .remediation = "change kernel arguments on an image whose boot entries carry an inline kernel command line",
    });
}

fn appendStaleIdentityFailure(
    diagnostics: *std.array_list.Managed(Diagnostic),
    identity_sink: identity_rewrite.Diagnostic,
    message_buffer: []u8,
    remediation_buffer: []u8,
) Allocator.Error!void {
    const stale = identity_sink.stale orelse return;
    const message = stale.describe(message_buffer) catch return;
    const remediation = stale.remediation(remediation_buffer) catch return;
    try diagnostics.append(.{
        .severity = .@"error",
        .phase = .execution,
        .code = .stale_filesystem_identifier,
        .configuration_path = "/storage/preserve/identity_rewrite",
        .message = message,
        .cause = .{ .error_name = @errorName(error.StaleFilesystemIdentifier) },
        .remediation = remediation,
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

/// An MBR disk whose root carries what a relabel needs: the labelling tool,
/// a configuration naming a policy, and that policy's file-contexts file.
/// `complete = false` drops the file-contexts file only, which is the shape a
/// target has when it names a policy it does not actually ship.
fn createCustomizeSelinuxTestDisk(
    io: Io,
    path: []const u8,
    spool_path: []const u8,
    complete: bool,
) !void {
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
    try tree.putDirectory("usr", .{ .mode = 0o755 });
    try tree.putDirectory("usr/sbin", .{ .mode = 0o755 });
    try tree.putFileBytes("usr/sbin/setfiles", "ELF\n", .{ .mode = 0o755 });
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putDirectory("etc/selinux", .{ .mode = 0o755 });
    try tree.putFileBytes(
        "etc/selinux/config",
        "SELINUX=enforcing\nSELINUXTYPE=targeted\n",
        .{ .mode = 0o644 },
    );
    if (complete) {
        try tree.putDirectory("etc/selinux/targeted", .{ .mode = 0o755 });
        try tree.putDirectory("etc/selinux/targeted/contexts", .{ .mode = 0o755 });
        try tree.putDirectory("etc/selinux/targeted/contexts/files", .{ .mode = 0o755 });
        try tree.putFileBytes(
            "etc/selinux/targeted/contexts/files/file_contexts",
            "/.*  system_u:object_r:default_t:s0\n",
            .{ .mode = 0o644 },
        );
    }
    _ = try ext4.populate(io, image.file, std.testing.allocator, try tree.ext4View(), .{
        .offset = @as(u64, customize_test_partition_first_lba) * mbr.sector_size,
        .length = @as(u64, customize_test_partition_sectors) * mbr.sector_size,
        .label = "customize-root",
        .uuid = [_]u8{0x65} ** 16,
        .timestamp = 1_735_689_600,
    });
}

const customize_gpt_disk_size: u64 = 24 * mib;
const customize_gpt_esp_sectors: u32 = 2048;
const customize_gpt_root_sectors: u32 = 16384;
const linux_root_x86_64_partition_type = guid.parse("4F68BCE3-E8CD-4DB1-96E7-FBCAF984B709");

/// A GPT disk with an ESP and an ext4 root, which is the shape the COSI
/// writer describes. `createCustomizeTestDisk` deliberately writes an MBR
/// instead, so the two together cover both answers to the GPT question.
fn createCustomizeGptTestDisk(io: Io, path: []const u8, spool_path: []const u8) !void {
    var image = try image_mod.Image.createExclusive(io, path, .raw, customize_gpt_disk_size, .{});
    defer image.close(io);

    const specs = [_]gpt.PartitionSpec{
        .{
            .type_guid = guid.esp,
            .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = customize_gpt_esp_sectors,
            .name_utf16le = gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = linux_root_x86_64_partition_type,
            .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .size_sectors = customize_gpt_root_sectors,
            .name_utf16le = gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &image,
        io,
        guid.parse("33333333-3333-3333-3333-333333333333"),
        &specs,
        &placements,
    );

    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try root_tree.RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/config", "before\n", .{ .mode = 0o640 });
    try tree.putFileBytes(
        "etc/os-release",
        "NAME=zvmi\nID=zvmi\nVERSION_ID=1\n",
        .{ .mode = 0o644 },
    );
    _ = try ext4.populate(io, image.file, std.testing.allocator, try tree.ext4View(), .{
        .offset = placements[1].first_lba * gpt.sector_size,
        .length = (placements[1].last_lba - placements[1].first_lba + 1) * gpt.sector_size,
        .label = "customize-root",
        .uuid = [_]u8{0x64} ** 16,
        .timestamp = 1_735_689_600,
    });
}

const customize_boot_esp_sectors: u32 = 64 * 2048;
const customize_boot_root_sectors: u32 = 16384;
const customize_boot_disk_size: u64 =
    (2048 + @as(u64, customize_boot_esp_sectors) + customize_boot_root_sectors + 2048) * gpt.sector_size;

const customize_boot_grub_cfg =
    "set default=0\nset timeout=5\n\n" ++
    "menuentry 'zvmi' --id 'zvmi-1' {\n" ++
    "    linux ($kernel_root)/boot/vmlinuz root=PARTUUID=22222222-2222-2222-2222-222222222222\n" ++
    "    initrd ($kernel_root)/boot/initrd.img\n" ++
    "}\n";

const customize_boot_bls_entry =
    "title zvmi\nlinux /boot/vmlinuz\ninitrd /boot/initrd.img\n" ++
    "options root=PARTUUID=22222222-2222-2222-2222-222222222222\n";

/// A GPT disk whose ESP is a real FAT32 volume carrying the GRUB and BLS
/// entries `bootconfig` generates. `createCustomizeGptTestDisk` leaves its ESP
/// unformatted, which is the other half of the question a kernel-argument
/// change asks of a source image.
fn createCustomizeBootTestDisk(io: Io, path: []const u8, spool_path: []const u8) !void {
    var image = try image_mod.Image.createExclusive(io, path, .raw, customize_boot_disk_size, .{});
    defer image.close(io);

    const specs = [_]gpt.PartitionSpec{
        .{
            .type_guid = guid.esp,
            .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111"),
            .size_sectors = customize_boot_esp_sectors,
            .name_utf16le = gpt.asciiName("EFI System"),
        },
        .{
            .type_guid = linux_root_x86_64_partition_type,
            .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222"),
            .size_sectors = customize_boot_root_sectors,
            .name_utf16le = gpt.asciiName("root"),
        },
    };
    var placements: [specs.len]gpt.Placement = undefined;
    try gpt.writeGpt(
        &image,
        io,
        guid.parse("33333333-3333-3333-3333-333333333333"),
        &specs,
        &placements,
    );

    const esp_offset = placements[0].first_lba * gpt.sector_size;
    const esp_length = (placements[0].last_lba - placements[0].first_lba + 1) * gpt.sector_size;
    try fat32.format(&image, io, .{ .partition_offset = esp_offset, .partition_len = esp_length });
    {
        var esp = try fat32.open(&image, io, .{ .offset = esp_offset, .length = esp_length });
        try esp.createDir(io, "EFI");
        try esp.createDir(io, "EFI/BOOT");
        try esp.writeFile(io, "EFI/BOOT/grub.cfg", customize_boot_grub_cfg);
        try esp.createDir(io, "loader");
        try esp.createDir(io, "loader/entries");
        try esp.writeFile(io, "loader/entries/zvmi-1.conf", customize_boot_bls_entry);
    }

    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    var tree = try root_tree.RootTree.init(std.testing.allocator, io, spool_path, .{});
    defer tree.deinit();
    try tree.putDirectory("etc", .{ .mode = 0o755 });
    try tree.putFileBytes("etc/config", "before\n", .{ .mode = 0o640 });
    _ = try ext4.populate(io, image.file, std.testing.allocator, try tree.ext4View(), .{
        .offset = placements[1].first_lba * gpt.sector_size,
        .length = (placements[1].last_lba - placements[1].first_lba + 1) * gpt.sector_size,
        .label = "customize-root",
        .uuid = [_]u8{0x65} ** 16,
        .timestamp = 1_735_689_600,
    });
}

/// Reads one file out of the ESP of a published raw image, which is the only
/// way to state what a caller booting the output would actually see.
fn readPublishedEspFile(io: Io, path: []const u8, esp_path: []const u8) ![]u8 {
    var image = try image_mod.Image.openPathReadOnly(io, path);
    defer image.close(io);
    const parsed = try gpt.readGpt(image, io, std.testing.allocator);
    defer std.testing.allocator.free(parsed.partitions);
    for (parsed.partitions) |partition| {
        if (!std.mem.eql(u8, &partition.partition_type_guid, &guid.esp)) continue;
        var esp = try fat32.open(&image, io, .{
            .offset = partition.first_lba * gpt.sector_size,
            .length = (partition.last_lba - partition.first_lba + 1) * gpt.sector_size,
        });
        return esp.readFileAlloc(io, std.testing.allocator, esp_path);
    }
    return error.NoEsp;
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

test "output format names cover the compressed raw spellings" {
    try std.testing.expectEqual(OutputFormat.raw, OutputFormat.parseName("raw").?);
    try std.testing.expectEqual(OutputFormat.raw_gz, OutputFormat.parseName("raw.gz").?);
    try std.testing.expectEqual(OutputFormat.raw_zst, OutputFormat.parseName("raw.zst").?);
    try std.testing.expectEqual(OutputFormat.qcow2, OutputFormat.parseName("qcow2").?);
    try std.testing.expectEqual(OutputFormat.cosi, OutputFormat.parseName("cosi").?);
    // Only raw can be compressed, and a COSI bundle has no compressed
    // spelling: its members are already compressed individually.
    try std.testing.expectEqual(@as(?OutputFormat, null), OutputFormat.parseName("vhd.gz"));
    try std.testing.expectEqual(@as(?OutputFormat, null), OutputFormat.parseName("cosi.gz"));

    try std.testing.expectEqual(Format.raw, OutputFormat.raw_gz.imageFormat().?);
    try std.testing.expectEqual(@as(?Format, null), OutputFormat.cosi.imageFormat());
    try std.testing.expectEqual(Format.raw, OutputFormat.cosi.stagingImageFormat());
    try std.testing.expectEqual(Format.qcow2, OutputFormat.qcow2.stagingImageFormat());
    try std.testing.expect(OutputFormat.cosi.bundlesStagedImage());
    try std.testing.expect(!OutputFormat.raw.bundlesStagedImage());
    try std.testing.expectEqual(output_mod.Compression.gzip, OutputFormat.raw_gz.compression());
    try std.testing.expectEqual(output_mod.Compression.zstd, OutputFormat.raw_zst.compression());
    try std.testing.expectEqual(output_mod.Compression.none, OutputFormat.raw.compression());
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
            _: Deadline,
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
    const update_named = [_]PackageAction{.{ .update_selected = &.{"kernel"} }};
    const update_nothing = [_]PackageAction{.{ .update_selected = &.{} }};
    const update_invalid = [_]PackageAction{.{ .update_selected = &.{"payload.rpm"} }};
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

    // A declared cache directory is now executable here: this backend mounts
    // the host filesystem, so it can bind one in.
    request = baseline;
    request.packages.cache = .{ .cache_only = "/var/cache/zvmi" };
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.cache = .{ .online_populating = "/var/cache/zvmi" };
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.lock = .{ .snapshot = "snapshot-1" };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    // An exact lock the backend can put on a command line and check against
    // the rpm database afterwards is one it can execute.
    request = baseline;
    request.packages.lock = .{ .exact = &.{
        .{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64" },
    } };
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    // Not a validation duplicate. `validate` asks whether a lock states a
    // whole identity; this asks the narrower question of whether these bytes
    // are ones the backend can put on a package-manager command line. An
    // architecture of `x86_64!` is a complete identity and still not one.
    request = baseline;
    request.packages.lock = .{ .exact = &.{
        .{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64!" },
    } };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.actions = &update;
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.actions = &update_named;
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    // `update_all` earns its empty name list; nothing else does.
    request = baseline;
    request.packages.actions = &update_nothing;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.packages.actions = &update_invalid;
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

    // Kernel-module configuration is the one part of the OS model this
    // backend carries out. It has a closed set of destinations, so it needs
    // none of the general file creation the rest of the model does -- and
    // accepting it must not have widened the gate to anything else, which the
    // hostname case above is what holds down.
    const kernel_modules = [_]KernelModule{
        .{ .name = "overlay", .load = true },
        .{ .name = "floppy", .disabled = true },
    };
    request = baseline;
    request.os.kernel_modules = &kernel_modules;
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    request = baseline;
    request.generalization = .{ .azure = .{} };
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Check.state(&request, .x86_64),
    );

    // Hooks are the one input that is caller-supplied code rather than
    // configuration, and this backend runs them. What it still refuses is a
    // hook it could not execute: a script that names no interpreter would
    // reach `execve` and come back as an exit status with nothing attached to
    // it, so it is refused where the bytes are first visible instead.
    const hooks = [_]Hook{.{
        .name = "supported",
        .phase = .finalize,
        .source = .{ .inline_script = "#!/bin/sh\ntrue\n" },
    }};
    request = baseline;
    request.hooks = &hooks;
    try std.testing.expectEqual(
        CapabilityState.available,
        try Check.state(&request, .x86_64),
    );

    const unrunnable_hooks = [_]Hook{.{
        .name = "unrunnable",
        .phase = .finalize,
        .source = .{ .inline_script = "true" },
    }};
    request = baseline;
    request.hooks = &unrunnable_hooks;
    var unrunnable = try validate(std.testing.allocator, &request);
    defer unrunnable.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(unrunnable, .invalid_policy));
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
    // The vm backend is itself guest execution, so nothing else has to be
    // declared to make the architectures matter -- a request with no hook at
    // all still has to name a runner.
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.target_architecture = .aarch64;
    request.execution.backend = .vm;
    request.execution.acknowledge_unsafe = true;
    request.execution.vm = .{
        .emulator_command = "/usr/bin/qemu-system-aarch64",
        .acceleration = .software,
    };

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
        .{ .name = "final", .phase = .finalize, .source = .{ .inline_script = "#!/bin/sh\ntrue\n" } },
        .{ .name = "early", .phase = .after_packages, .source = .{ .inline_script = "#!/bin/sh\ntrue\n" } },
    };
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.hooks = &unordered_hooks;
    var unordered = try validate(std.testing.allocator, &request);
    defer unordered.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(unordered, .invalid_policy));

    const ordered_hooks = [_]Hook{
        .{ .name = "packages", .phase = .after_packages, .source = .{ .inline_script = "#!/bin/sh\ntrue\n" } },
        .{ .name = "initramfs", .phase = .before_initramfs, .source = .{ .inline_script = "#!/bin/sh\ntrue\n" } },
        .{ .name = "seal", .phase = .before_seal, .source = .{ .inline_script = "#!/bin/sh\ntrue\n" } },
        .{ .name = "final", .phase = .finalize, .source = .{ .inline_script = "#!/bin/sh\ntrue\n" } },
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
        .cache = .{ .cache_only = "/var/cache/zvmi" },
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

test "a relabel is probed against the source the run would label" {
    const io = std.testing.io;
    const Case = struct {
        complete: bool,
        expected: CapabilityState,
        source: []const u8,
        spool: []const u8,
    };
    const cases = [_]Case{
        .{
            .complete = true,
            .expected = .available,
            .source = "test-customize-selinux-ready-source.raw",
            .spool = "test-customize-selinux-ready-root.spool",
        },
        // A policy the configuration names but the target does not carry.
        // Reported before the run rather than discovered inside a chroot,
        // which is the whole point of probing the source.
        .{
            .complete = false,
            .expected = .missing,
            .source = "test-customize-selinux-partial-source.raw",
            .spool = "test-customize-selinux-partial-root.spool",
        },
    };

    for (cases) |case| {
        defer Io.Dir.cwd().deleteFile(io, case.source) catch {};
        defer Io.Dir.cwd().deleteFile(io, case.spool) catch {};
        try createCustomizeSelinuxTestDisk(io, case.source, case.spool, case.complete);

        var request = validNativeEditRequest(
            case.source,
            "selinux-probe-work/output.raw",
            "selinux-probe-work",
            &.{},
        );
        request.execution.backend = .unsafe_chroot;
        request.execution.acknowledge_unsafe = true;
        request.selinux = .relabel;

        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan != null);
        // The backend state is supplied rather than measured, because whether
        // this host can run a chroot is not what this test is about.
        try std.testing.expectEqual(
            case.expected,
            selinuxRelabelAvailable(io, &resolved.plan.?, .available),
        );
    }

    // A plan that asks for no relabel has no source to probe, whatever the
    // disk under it looks like.
    const source_path = "test-customize-selinux-unchanged-source.raw";
    const spool_path = "test-customize-selinux-unchanged-root.spool";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    try createCustomizeSelinuxTestDisk(io, source_path, spool_path, true);
    var request = validNativeEditRequest(
        source_path,
        "selinux-probe-work/output.raw",
        "selinux-probe-work",
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        selinuxRelabelAvailable(io, &resolved.plan.?, .available),
    );
}

test "a relabel is published after everything that writes to the root" {
    const hooks = [_]Hook{
        .{
            .name = "seal",
            .phase = .before_seal,
            .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
        },
        .{
            .name = "final",
            .phase = .finalize,
            .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
        },
    };
    var request = validNativeEditRequest(
        "source.raw",
        "selinux-order-work/output.raw",
        "selinux-order-work",
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.hooks = &hooks;
    request.selinux = .relabel;

    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);

    const operations = resolved.plan.?.data.operations;
    // Labels describe the bytes that existed when the tool walked them, so
    // nothing may write into the root after the relabel. Only phases that
    // close or convert the image are allowed to follow it.
    var relabel_index: ?usize = null;
    var saw_finalize_hook = false;
    for (operations, 0..) |operation, index| {
        if (operation.phase == .selinux) {
            try std.testing.expectEqual(Action.apply_selinux_policy, operation.action);
            try std.testing.expect(relabel_index == null);
            relabel_index = index;
        }
        if (operation.phase == .finalize and operation.action == .execute_hook) {
            saw_finalize_hook = true;
            try std.testing.expect(relabel_index == null);
        }
    }
    try std.testing.expect(saw_finalize_hook);
    for (operations[relabel_index.? + 1 ..]) |operation| {
        try std.testing.expect(switch (operation.phase) {
            .filesystem_close, .output_conversion => true,
            else => false,
        });
    }
}

test "a relabel is a different plan from leaving the labels alone" {
    var request = validNativeEditRequest(
        "source.raw",
        "selinux-hash-work/output.raw",
        "selinux-hash-work",
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;

    var unchanged = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer unchanged.deinit(std.testing.allocator);

    request.selinux = .relabel;
    var relabel = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer relabel.deinit(std.testing.allocator);

    // Two runs that label differently must not share a plan hash, or a cached
    // result from one would be accepted as the other.
    try std.testing.expect(!std.mem.eql(
        u8,
        &unchanged.plan.?.data.plan_hash.bytes,
        &relabel.plan.?.data.plan_hash.bytes,
    ));
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
                .console_marker = "Linux version ",
            } };
            break :blk policy;
        } },
        .{ .name = "relative firmware vars path", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot = .{ .firmware = .{
                .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
                .vars_path = "OVMF_VARS.fd",
                .console_marker = "Linux version ",
            } };
            break :blk policy;
        } },
        .{ .name = "firmware without a console marker", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot = .{ .firmware = .{
                .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
                .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
                .console_marker = "",
            } };
            break :blk policy;
        } },
        .{ .name = "multi-line console marker", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot = .{ .firmware = .{
                .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
                .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
                .console_marker = "reached\ntarget",
            } };
            break :blk policy;
        } },
        .{ .name = "no firmware boot timeout", .policy = blk: {
            var policy = validVmPolicy();
            policy.boot = .{ .firmware = .{
                .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
                .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
                .console_marker = "Linux version ",
                .boot_timeout_seconds = 0,
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

test "the execution deadline is bounded and must contain the guest boot budgets" {
    // Absent is the only shape with no bound to check: a run that declared no
    // deadline is unbounded on purpose and has nothing to be inconsistent
    // with.
    {
        var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(!diagnostics.hasErrors());
        try std.testing.expect(request.execution.deadline_seconds == null);
    }

    // Zero is not "no deadline": it is a budget nothing can be done within,
    // and a run that declared it meant to say something else.
    for ([_]u32{ 0, max_execution_deadline_seconds + 1 }) |seconds| {
        var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
        request.execution.deadline_seconds = seconds;
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));
    }

    {
        var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
        request.execution.deadline_seconds = max_execution_deadline_seconds;
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(!diagnostics.hasErrors());
    }

    // A deadline no larger than the boots it contains would preempt a budget
    // the caller declared, so the two are refused together rather than one
    // silently winning.
    var vm_request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    vm_request.execution.backend = .vm;
    var policy = validVmPolicy();
    policy.boot_timeout_seconds = 900;
    vm_request.execution.vm = policy;
    vm_request.execution.deadline_seconds = 900;
    {
        var diagnostics = try validate(std.testing.allocator, &vm_request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));
    }
    vm_request.execution.deadline_seconds = 901;
    {
        var diagnostics = try validate(std.testing.allocator, &vm_request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(!diagnostics.hasErrors());
    }

    // A firmware boot is a second boot in sequence, so it is added to what the
    // deadline has to exceed rather than compared against separately.
    policy.boot = .{ .firmware = .{
        .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
        .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
        .console_marker = "Linux version ",
        .boot_timeout_seconds = 600,
    } };
    vm_request.execution.vm = policy;
    {
        var diagnostics = try validate(std.testing.allocator, &vm_request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));
    }
    vm_request.execution.deadline_seconds = 1501;
    {
        var diagnostics = try validate(std.testing.allocator, &vm_request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(!diagnostics.hasErrors());
    }
}

test "the plan hash covers the run's declared deadline" {
    // A run given twice the time may install what a shorter one could not
    // finish, and an absent deadline is not the same declaration as a large
    // one: all three have to be different plans.
    const budgets = [_]?u32{ null, 600, 1200 };
    var hashes: [budgets.len]Digest = undefined;
    for (budgets, 0..) |budget, index| {
        var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
        request.execution.deadline_seconds = budget;
        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan != null);
        try std.testing.expectEqual(
            budget,
            resolved.plan.?.data.execution.deadline_seconds,
        );
        hashes[index] = resolved.plan.?.data.plan_hash;
    }
    for (hashes, 0..) |left, i| {
        for (hashes[i + 1 ..]) |right| {
            try std.testing.expect(!std.mem.eql(u8, &left.bytes, &right.bytes));
        }
    }
}

test "a run that exceeds its deadline is reported as a deadline rather than a failure" {
    const io = std.testing.io;
    const source_path = "test-customize-deadline-source.raw";
    const spool_path = "test-customize-deadline-spool";
    const workspace_path = "test-customize-deadline-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, source_path, spool_path);
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    var request = validNativeEditRequest(
        source_path,
        output_path,
        workspace_path,
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.execution.deadline_seconds = 600;

    const FakeUnsafe = struct {
        fn check(
            _: ?*anyopaque,
            _: Io,
            _: *const ResolvedPlan,
        ) CapabilityState {
            return .available;
        }

        fn run(
            _: ?*anyopaque,
            _: Allocator,
            io_arg: Io,
            _: *const ResolvedPlan,
            _: preserved_image.RawMutationTarget,
            deadline: Deadline,
        ) !UnsafeChrootRuntimeReport {
            // The backend is handed a live budget, not the number that was
            // declared: what it has to bound is whatever is left by the time
            // it starts.
            try std.testing.expect(deadline.remainingSeconds(io_arg) != null);
            try std.testing.expect(deadline.remainingSeconds(io_arg).? <= 600);
            return error.ExecutionDeadlineExceeded;
        }
    };

    var platform = Platform.system();
    platform.unsafeChrootCheckFn = FakeUnsafe.check;
    platform.unsafeChrootRunFn = FakeUnsafe.run;
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);

    var outcome = try execute(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(outcome.result == null);
    // The dedicated code is the whole point: a caller that reads
    // `execution_failed` cannot tell a run that ran out of time from one whose
    // policy was wrong, and only one of the two is answered by more time.
    try std.testing.expect(hasDiagnosticCode(outcome.diagnostics, .deadline_exceeded));
    for (outcome.diagnostics.items) |diagnostic| {
        if (diagnostic.code != .deadline_exceeded) continue;
        try std.testing.expectEqualStrings(
            "/execution/deadline_seconds",
            diagnostic.configuration_path,
        );
    }
    // Nothing is published by a run that ran out of time.
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, output_path, .{}),
    );
}

test "a firmware boot names its own firmware, marker, and budget in the plan" {
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .vm;
    var policy = validVmPolicy();
    policy.boot = .{ .firmware = .{
        .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
        .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
        .console_marker = "Linux version ",
        .secure_boot = true,
    } };
    request.execution.vm = policy;

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!diagnostics.hasErrors());

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    const firmware = resolved.plan.?.data.execution.vm.?.boot.firmware;
    try std.testing.expectEqualStrings("Linux version ", firmware.console_marker);
    try std.testing.expect(firmware.secure_boot);
    try std.testing.expectEqual(
        default_vm_firmware_boot_timeout_seconds,
        firmware.boot_timeout_seconds,
    );

    // The firmware is its own preflight requirement, so a refusal names the
    // file that was missing rather than only the backend that wanted it.
    var saw_firmware_requirement = false;
    for (resolved.plan.?.data.required_capabilities) |requirement| {
        if (requirement.kind != .vm_firmware) continue;
        saw_firmware_requirement = true;
        try std.testing.expectEqualStrings("/usr/share/OVMF/OVMF_CODE.fd", requirement.path);
        try std.testing.expectEqualStrings(
            "/usr/share/OVMF/OVMF_VARS.fd",
            requirement.related_path,
        );
        try std.testing.expect(std.mem.indexOf(u8, requirement.reason, "x86_64") != null);
    }
    try std.testing.expect(saw_firmware_requirement);
}

test "a direct-kernel plan carries no firmware requirement" {
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .vm;
    request.execution.vm = validVmPolicy();

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    for (resolved.plan.?.data.required_capabilities) |requirement| {
        try std.testing.expect(requirement.kind != .vm_firmware);
    }
}

test "the firmware a plan names changes its hash" {
    var request = validNativeEditRequest("source.raw", "output.raw", ".", &.{});
    request.execution.backend = .vm;
    var policy = validVmPolicy();
    policy.boot = .{ .firmware = .{
        .code_path = "/usr/share/OVMF/OVMF_CODE.fd",
        .vars_path = "/usr/share/OVMF/OVMF_VARS.fd",
        .console_marker = "Linux version ",
    } };
    request.execution.vm = policy;

    var base = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer base.deinit(std.testing.allocator);

    // Everything about the run is identical but the bytes the attestation
    // waits for, which is a different experiment and so a different plan.
    policy.boot.firmware.console_marker = "systemd 255 running";
    request.execution.vm = policy;
    var moved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer moved.deinit(std.testing.allocator);

    try std.testing.expect(!std.mem.eql(
        u8,
        &base.plan.?.data.plan_hash.bytes,
        &moved.plan.?.data.plan_hash.bytes,
    ));
}

test "firmware readability is probed as its own capability" {
    const io = std.testing.io;
    const cwd = Io.Dir.cwd();
    const code_path = "test-customize-firmware-code.fd";
    const vars_path = "test-customize-firmware-vars.fd";
    defer cwd.deleteFile(io, code_path) catch {};
    defer cwd.deleteFile(io, vars_path) catch {};

    const absent = VmFirmware{
        .code_path = code_path,
        .vars_path = vars_path,
        .console_marker = "Linux version ",
    };
    try std.testing.expectEqual(CapabilityState.missing, vmFirmwareAvailable(io, absent));

    try cwd.writeFile(io, .{ .sub_path = code_path, .data = "code" });
    try std.testing.expectEqual(CapabilityState.missing, vmFirmwareAvailable(io, absent));
    try cwd.writeFile(io, .{ .sub_path = vars_path, .data = "vars" });
    try std.testing.expectEqual(CapabilityState.available, vmFirmwareAvailable(io, absent));

    // An empty file is a firmware that was never materialized, not firmware.
    try cwd.writeFile(io, .{ .sub_path = vars_path, .data = "" });
    try std.testing.expectEqual(CapabilityState.missing, vmFirmwareAvailable(io, absent));
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

test "a kernel module name that would render as two tokens is rejected" {
    // `validConfigName` permits spaces, which is harmless for a filename but
    // not for a name that becomes the subject of a `modprobe.d` directive:
    // `options overlay -f redirect_dir=on` retargets the directive at
    // `overlay` and turns the rest into its options. The refusal belongs here
    // rather than only in the executors, so it arrives at preflight instead
    // of part-way through a run.
    const cases = [_][]const u8{
        "overlay -f",
        "overlay\tredirect_dir=on",
        "over lay",
        "",
        ".hidden",
        "sub/dir",
        // `modprobe.d` continues a line ending in a backslash, so this one
        // swallows whatever directive is rendered after it -- the module
        // named next is then silently not blacklisted at all.
        "overlay\\",
        // systemd ignores a `modules-load.d` line whose first non-blank
        // character is `#` or `;`, so these load nothing and say nothing.
        "#overlay",
        ";overlay",
    };
    for (cases) |name| {
        var request = validRequest();
        const modules = [_]KernelModule{.{ .name = name, .load = true }};
        request.os = .{ .kernel_modules = &modules };

        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        var rejected = false;
        for (diagnostics.items) |diagnostic| {
            if (diagnostic.code == .invalid_customization and
                std.mem.eql(u8, diagnostic.configuration_path, "/os/kernel_modules"))
            {
                rejected = true;
            }
        }
        if (!rejected) {
            std.debug.print("accepted kernel module name: '{s}'\n", .{name});
            return error.TestUnexpectedResult;
        }
    }

    // A backslash in the options is the same failure arriving by the other
    // route: `options i915 enable_guc=2\` absorbs the next module's directive
    // into i915's parameter string.
    var continued = validRequest();
    const continued_modules = [_]KernelModule{
        .{ .name = "i915", .options = "enable_guc=2\\" },
    };
    continued.os = .{ .kernel_modules = &continued_modules };
    var continued_diagnostics = try validate(std.testing.allocator, &continued);
    defer continued_diagnostics.deinit(std.testing.allocator);
    var refused_options = false;
    for (continued_diagnostics.items) |diagnostic| {
        if (std.mem.eql(u8, diagnostic.configuration_path, "/os/kernel_modules/options")) {
            refused_options = true;
        }
    }
    try std.testing.expect(refused_options);

    var accepted = validRequest();
    const modules = [_]KernelModule{
        .{ .name = "overlay", .load = true },
        .{ .name = "snd-hda-intel", .options = "power_save=1" },
        .{ .name = "8021q", .load = true },
        .{ .name = "nf_conntrack", .options = "nf_conntrack_max=65536" },
    };
    accepted.os = .{ .kernel_modules = &modules };
    var diagnostics = try validate(std.testing.allocator, &accepted);
    defer diagnostics.deinit(std.testing.allocator);
    for (diagnostics.items) |diagnostic| {
        try std.testing.expect(diagnostic.code != .invalid_customization);
    }
}

test "a fresh build writes kernel-module configuration without asking for a capability" {
    // `native_fresh` creates the whole tree, so nothing it writes into that
    // tree is a question about what can be done to a preserved filesystem.
    // Requesting the capability for it anyway would refuse in preflight a
    // build that has always worked -- `build_image` applies the OS
    // customization model in full.
    var request = validRequest();
    const modules = [_]KernelModule{.{ .name = "overlay", .load = true }};
    request.os = .{ .kernel_modules = &modules };

    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    try std.testing.expectEqual(ExecutionBackend.native_fresh, resolved.plan.?.data.execution.backend);
    for (resolved.plan.?.data.required_capabilities) |capability| {
        try std.testing.expect(capability.kind != .kernel_module_configuration);
    }
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
    var limit_sink = limits_mod.Diagnostic{};
    try std.testing.expectError(
        error.InvalidOperationOrder,
        runPlan(std.testing.allocator, std.testing.io, &resolved.plan.?, platform, null, &bridge, &limit_sink),
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

test "a fresh COSI request publishes a bundle built from the staged image" {
    const io = std.testing.io;
    const iso_path = "test-customize-cosi.iso";
    const container_path = "test-customize-cosi.container";
    const workspace_path = "test-customize-cosi-work";
    const output_path = workspace_path ++ "/output.cosi";
    defer Io.Dir.cwd().deleteFile(io, iso_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, container_path) catch {};
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

    var request = validRequest();
    request.input = .{ .iso_oci = .{
        .iso_path = iso_path,
        .container_path = container_path,
        .rootfs_path_in_iso = "rootfs.squashfs",
    } };
    request.output = .{ .path = output_path, .format = .cosi, .size = 128 * mib };
    request.execution.workspace_path = workspace_path;

    const StagedGptRunner = struct {
        fn run(
            _: ?*anyopaque,
            _: Allocator,
            run_io: Io,
            plan: *const ResolvedPlan,
            _: ?EventSink,
            stage_sink: build_image.StageSink,
        ) !void {
            for (plan.data.operations) |operation| {
                const stage = freshStageForAction(operation.action) orelse continue;
                if (!stage_sink.advance(stage)) return error.InvalidOperationOrder;
            }
            try createCustomizeGptTestDisk(
                run_io,
                plan.data.staging_output_path,
                "test-customize-cosi-root.spool",
            );
        }
    };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    const plan = resolved.plan.?;
    const operations = plan.data.operations;
    const last = operations[operations.len - 1];
    try std.testing.expectEqual(Action.write_cosi_bundle, last.action);
    try std.testing.expectEqual(Phase.output_conversion, last.phase);
    try std.testing.expectEqual(Action.convert_output, operations[operations.len - 2].action);
    try std.testing.expect(std.mem.endsWith(u8, plan.data.staging_output_path, "output.img"));
    try std.testing.expect(std.mem.endsWith(u8, plan.data.staging_commit_path, "output.cosi"));

    var platform = Platform.system();
    platform.runFn = StagedGptRunner.run;
    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, platform, null);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    try std.testing.expect(outcome.result != null);

    const record = outcome.result.?.provenance.execution.cosi.?;
    try std.testing.expectEqualStrings(cosi.metadata_version, record.metadata_version);
    try std.testing.expectEqual(@as(usize, 2), record.partition_count);
    // A stand-in backend seals no verity tree, so the bundle describes none.
    try std.testing.expect(!record.verity_included);
    try std.testing.expectEqual(OutputFormat.cosi, outcome.result.?.provenance.final_output.format);

    const bundle = try Io.Dir.cwd().openFile(io, output_path, .{});
    defer bundle.close(io);
    const bundle_size = (try bundle.stat(io)).size;
    const bundle_bytes = try std.testing.allocator.alloc(u8, bundle_size);
    defer std.testing.allocator.free(bundle_bytes);
    _ = try bundle.readPositionalAll(io, bundle_bytes, 0);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "cosi-marker") != null);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "metadata.json") != null);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "images/image_gpt.raw.zst") != null);
    // A stand-in backend seals nothing, so every filesystem entry carries an
    // explicitly empty verity block rather than an invented one.
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "\"verity\":null") != null);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "\"roothash\"") == null);
    try std.testing.expectEqual(bundle_size, outcome.result.?.provenance.final_output.size);

    // The staged disk image was an intermediate, not the artifact: only the
    // bundle survives the transaction.
    try std.testing.expectError(
        error.FileNotFound,
        Io.Dir.cwd().statFile(io, plan.data.transaction_path, .{}),
    );
}

test "a preserved COSI request is refused on a source without a GPT" {
    const io = std.testing.io;
    const source_path = "test-customize-cosi-mbr-source.raw";
    const spool_path = "test-customize-cosi-mbr-root.spool";
    const workspace_path = "test-customize-cosi-mbr-work";
    const output_path = workspace_path ++ "/output.cosi";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);
    try createCustomizeTestDisk(io, source_path, spool_path);

    var request = validNativeEditRequest(source_path, output_path, workspace_path, &.{});
    request.output.format = .cosi;

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);

    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(!report.ready());
    try std.testing.expect(hasDiagnosticCode(report.diagnostics, .missing_capability));
    var saw_gpt_requirement = false;
    for (report.capabilities) |check| {
        if (check.requirement.kind != .gpt_source) continue;
        saw_gpt_requirement = true;
        try std.testing.expectEqual(CapabilityState.missing, check.state);
    }
    try std.testing.expect(saw_gpt_requirement);
}

test "native-edit publishes a COSI bundle from a GPT source" {
    const io = std.testing.io;
    const source_path = "test-customize-cosi-edit-source.raw";
    const spool_path = "test-customize-cosi-edit-root.spool";
    const edit_path = "test-customize-cosi-edit-content.txt";
    const workspace_path = "test-customize-cosi-edit-work";
    const output_path = workspace_path ++ "/output.cosi";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, edit_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);
    try createCustomizeGptTestDisk(io, source_path, spool_path);
    {
        const edit_source = try Io.Dir.cwd().createFile(io, edit_path, .{});
        defer edit_source.close(io);
        try edit_source.writePositionalAll(io, "after\n", 0);
    }

    const operations = [_]ExistingPathOperation{
        .{ .overwrite_file = .{
            .path = "/etc/config",
            .source = .{ .host_path = edit_path },
        } },
    };
    var request = validNativeEditRequest(source_path, output_path, workspace_path, &operations);
    request.output.format = .cosi;
    request.storage.preserve.root_partition = .{ .gpt_index = 2 };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    const operations_planned = resolved.plan.?.data.operations;
    try std.testing.expectEqual(
        Action.write_cosi_bundle,
        operations_planned[operations_planned.len - 1].action,
    );
    try std.testing.expectEqual(
        Action.publish_standalone_output,
        operations_planned[operations_planned.len - 2].action,
    );

    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(report.ready());

    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, Platform.system(), null);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    try std.testing.expect(outcome.result != null);

    const record = outcome.result.?.provenance.execution.cosi.?;
    try std.testing.expectEqual(@as(usize, 2), record.partition_count);
    // Only the backend that sealed a hash tree can describe one, and the
    // preserved editor seals none.
    try std.testing.expect(!record.verity_included);
    // The staged image is raw whatever the bundle is, and provenance says so.
    try std.testing.expectEqual(Format.raw, outcome.result.?.provenance.execution.preserved.?.output_format);

    const bundle = try Io.Dir.cwd().openFile(io, output_path, .{});
    defer bundle.close(io);
    const bundle_size = (try bundle.stat(io)).size;
    const bundle_bytes = try std.testing.allocator.alloc(u8, bundle_size);
    defer std.testing.allocator.free(bundle_bytes);
    _ = try bundle.readPositionalAll(io, bundle_bytes, 0);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "cosi-marker") != null);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "\"osArch\":\"x86_64\"") != null);
    try std.testing.expect(std.mem.indexOf(u8, bundle_bytes, "ID=zvmi") != null);
}

test "native-edit appends kernel options to every boot entry on the ESP" {
    const io = std.testing.io;
    const source_path = "test-customize-kopts-source.raw";
    const spool_path = "test-customize-kopts-root.spool";
    const workspace_path = "test-customize-kopts-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);
    try createCustomizeBootTestDisk(io, source_path, spool_path);

    var request = validNativeEditRequest(source_path, output_path, workspace_path, &.{});
    request.storage.preserve.root_partition = .{ .gpt_index = 2 };
    request.boot_security = .{ .extra_kernel_options = "console=ttyS0 quiet" };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(!resolved.diagnostics.hasErrors());
    const planned = resolved.plan.?.data.operations;
    var planned_change = false;
    for (planned) |operation| {
        if (operation.action == .change_kernel_options) planned_change = true;
    }
    try std.testing.expect(planned_change);

    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(report.ready());

    var outcome = try execute(std.testing.allocator, io, &resolved.plan.?, Platform.system(), null);
    defer outcome.deinit(std.testing.allocator);
    try std.testing.expect(!outcome.diagnostics.hasErrors());
    try std.testing.expect(outcome.result != null);

    const record = outcome.result.?.provenance.execution.preserved.?.kernel_options.?;
    try std.testing.expectEqualStrings("console=ttyS0 quiet", record.appended);
    try std.testing.expectEqual(@as(usize, 1), record.grub_entries);
    try std.testing.expectEqual(@as(usize, 1), record.bls_entries);
    try std.testing.expectEqual(@as(usize, 0), record.entries_already_current);
    try std.testing.expectEqual(@as(usize, 2), record.files_rewritten);
    try std.testing.expectEqual(@as(usize, 2), record.verified_files);

    const grub = try readPublishedEspFile(io, output_path, "EFI/BOOT/grub.cfg");
    defer std.testing.allocator.free(grub);
    try std.testing.expect(std.mem.indexOf(
        u8,
        grub,
        "root=PARTUUID=22222222-2222-2222-2222-222222222222 console=ttyS0 quiet\n",
    ) != null);
    // The menu around the command line is the distro's, not ours.
    try std.testing.expect(std.mem.indexOf(u8, grub, "set timeout=5\n") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub, "initrd ($kernel_root)/boot/initrd.img\n") != null);

    const bls = try readPublishedEspFile(io, output_path, "loader/entries/zvmi-1.conf");
    defer std.testing.allocator.free(bls);
    try std.testing.expect(std.mem.indexOf(
        u8,
        bls,
        "options root=PARTUUID=22222222-2222-2222-2222-222222222222 console=ttyS0 quiet\n",
    ) != null);
}

test "the vm backend refuses a kernel argument change by name" {
    var request = validNativeEditRequest("source.raw", "work/output.raw", "work", &.{});
    request.boot_security = .{ .extra_kernel_options = "console=ttyS0" };
    request.execution.backend = .vm;
    request.execution.acknowledge_unsafe = true;
    request.execution.vm = validVmPolicy();

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(diagnostics, .unsupported_execution_backend));

    // The same request on the backend that can reach the ESP validates.
    request.execution.backend = .native_edit;
    request.execution.acknowledge_unsafe = false;
    request.execution.vm = null;
    var accepted = try validate(std.testing.allocator, &request);
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expect(!accepted.hasErrors());
}

test "the chroot backend accepts a kernel argument change and plans the regeneration" {
    var request = validNativeEditRequest("source.raw", "work/output.raw", "work", &.{});
    request.boot_security = .{ .extra_kernel_options = "console=ttyS0 quiet" };
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;

    var accepted = try validate(std.testing.allocator, &request);
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expect(!accepted.hasErrors());

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);

    // The regeneration is published as its own operation, and it happens
    // during the bootloader phase rather than alongside the ESP edit the
    // preserved-image backends perform.
    var regenerations: usize = 0;
    var appends: usize = 0;
    for (resolved.plan.?.data.operations) |operation| {
        switch (operation.action) {
            .regenerate_boot_configuration => {
                regenerations += 1;
                try std.testing.expectEqual(Phase.bootloader_prepare, operation.phase);
            },
            .change_kernel_options => appends += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 1), regenerations);
    // The chroot does not touch the ESP: the distro's generator owns the
    // generated file, so there is nothing for zvmi to append to by hand.
    try std.testing.expectEqual(@as(usize, 0), appends);
}

test "kernel option text the target's shell would interpret is refused on the chroot backend" {
    // `/etc/default/grub` is sourced by the shell that runs the generator as
    // root inside the target, so the characters that are merely awkward in a
    // GRUB entry are a command-injection vector here.
    for ([_][]const u8{
        "console=ttyS0 $(id)",
        "console=ttyS0 `id`",
        "console=\"ttyS0\"",
        "console='ttyS0'",
        "console=ttyS0\\",
    }) |options| {
        var request = validNativeEditRequest("source.raw", "work/output.raw", "work", &.{});
        request.boot_security = .{ .extra_kernel_options = options };
        request.execution.backend = .unsafe_chroot;
        request.execution.acknowledge_unsafe = true;

        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));

        // The preserved-image backends never hand the text to a shell, so
        // they still accept it.
        request.execution.backend = .native_edit;
        request.execution.acknowledge_unsafe = false;
        var accepted = try validate(std.testing.allocator, &request);
        defer accepted.deinit(std.testing.allocator);
        try std.testing.expect(!accepted.hasErrors());
    }
}

test "kernel option text that could change more than the command line is refused" {
    var request = validNativeEditRequest("source.raw", "work/output.raw", "work", &.{});
    request.boot_security = .{ .extra_kernel_options = "console=ttyS0\nmenuentry 'x' {" };

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy));
}

test "a source with no boot entry to change reports the capability missing" {
    const io = std.testing.io;
    const source_path = "test-customize-kopts-bare-source.raw";
    const spool_path = "test-customize-kopts-bare-root.spool";
    const workspace_path = "test-customize-kopts-bare-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try Io.Dir.cwd().createDirPath(io, workspace_path);
    // This disk's ESP partition exists but was never formatted, so there is
    // no command line on it to append to.
    try createCustomizeGptTestDisk(io, source_path, spool_path);

    var request = validNativeEditRequest(source_path, output_path, workspace_path, &.{});
    request.storage.preserve.root_partition = .{ .gpt_index = 2 };
    request.boot_security = .{ .extra_kernel_options = "console=ttyS0" };

    var resolved = try resolve(std.testing.allocator, &request, .{ .host_architecture = .x86_64 });
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(!resolved.diagnostics.hasErrors());

    var report = try preflight(std.testing.allocator, io, &resolved.plan.?, Platform.system());
    defer report.deinit(std.testing.allocator);
    try std.testing.expect(!report.ready());
    var found = false;
    for (report.capabilities) |capability| {
        if (capability.requirement.kind != .kernel_option_change) continue;
        found = true;
        try std.testing.expectEqual(CapabilityState.missing, capability.state);
    }
    try std.testing.expect(found);
}

test "a gen1 fresh request cannot ask for a COSI output" {
    var request = validRequest();
    request.output = .{ .path = "output.cosi", .format = .cosi, .size = 128 * mib };
    request.storage.fresh.generation = .gen1;

    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(hasDiagnosticCode(diagnostics, .unsupported_output_format));

    request.storage.fresh.generation = .gen2;
    var gen2 = try validate(std.testing.allocator, &request);
    defer gen2.deinit(std.testing.allocator);
    try std.testing.expect(!hasDiagnosticCode(gen2, .unsupported_output_format));
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
    // Formatted from the constant rather than written out, so a bump that
    // forgets this test cannot be reported as the JSON losing its version.
    const expected_version = try std.fmt.allocPrint(
        std.testing.allocator,
        "\"schema_version\": {d}",
        .{plan_schema_version},
    );
    defer std.testing.allocator.free(expected_version);
    try std.testing.expect(std.mem.indexOf(u8, json, expected_version) != null);
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
    try std.testing.expectEqual(ext4.SourceProfile.zvmi_ext4_v1, rebuild_record.profile);
    try std.testing.expect(rebuild_record.reproducible);
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

// A helper for the `when_needed` tests: an `unsafe_chroot` request that is
// valid apart from whatever the caller sets on it.
fn whenNeededRequest() Request {
    var request = validNativeEditRequest(
        "source.raw",
        "when-needed-work/output.raw",
        "when-needed-work",
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    return request;
}

// Returns the tag only. The policy itself points into the plan's arena, which
// this function frees before returning, so nothing but the tag may leave here.
fn resolvedInitramfsTag(request: *const Request) !std.meta.Tag(InitramfsPolicy) {
    var resolved = try resolve(
        std.testing.allocator,
        request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    for (resolved.diagnostics.items) |diagnostic| {
        try std.testing.expect(diagnostic.code != .invalid_policy);
    }
    try std.testing.expect(resolved.plan != null);
    return std.meta.activeTag(resolved.plan.?.data.initramfs);
}

test "when_needed regenerates for package actions and names no kernel" {
    const actions = [_]PackageAction{.{ .install = &.{"dracut"} }};
    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    var request = whenNeededRequest();
    request.packages = .{ .actions = &actions, .repositories = &repositories };
    request.initramfs = .{ .when_needed = .{ .generator = "dracut" } };

    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    const policy = resolved.plan.?.data.initramfs;
    try std.testing.expectEqual(
        std.meta.Tag(InitramfsPolicy).regenerate,
        std.meta.activeTag(policy),
    );
    // A run that did not decide *whether* to regenerate cannot decide *what*:
    // an empty list is the instruction to discover the releases in the target
    // root once the packages have run.
    try std.testing.expectEqual(@as(usize, 0), policy.regenerate.kernels.len);
    try std.testing.expectEqualStrings("dracut", policy.regenerate.generator.?);
    // The derived form must not inherit the explicit form's strictness. An
    // explicit "regenerate every installed kernel" that finds none has not
    // done what it said and fails; a derived one has simply learned that
    // there was nothing stale.
    try std.testing.expectEqual(
        NoInstalledKernelsPolicy.nothing_to_regenerate,
        policy.regenerate.no_installed_kernels,
    );
}

test "a derived regeneration is a different instruction from a strict one" {
    // The counterpart to the plan-identity test: `when_needed` matches the
    // explicit request that states the *same* thing, and must not collide
    // with the one that states something stricter. The two differ only in
    // what an empty module tree means, so if that field were dropped on the
    // way into the plan these hashes would be equal.
    const actions = [_]PackageAction{.update_all};
    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};

    var derived = whenNeededRequest();
    derived.packages = .{ .actions = &actions, .repositories = &repositories };
    derived.initramfs = .{ .when_needed = .{} };

    var strict = whenNeededRequest();
    strict.packages = .{ .actions = &actions, .repositories = &repositories };
    strict.initramfs = .{ .regenerate = .{ .kernels = &.{} } };

    var derived_resolved = try resolve(
        std.testing.allocator,
        &derived,
        .{ .host_architecture = .x86_64 },
    );
    defer derived_resolved.deinit(std.testing.allocator);
    var strict_resolved = try resolve(
        std.testing.allocator,
        &strict,
        .{ .host_architecture = .x86_64 },
    );
    defer strict_resolved.deinit(std.testing.allocator);
    try std.testing.expect(derived_resolved.plan != null);
    try std.testing.expect(strict_resolved.plan != null);
    try std.testing.expectEqual(
        NoInstalledKernelsPolicy.fail,
        strict_resolved.plan.?.data.initramfs.regenerate.no_installed_kernels,
    );
    try std.testing.expect(!std.mem.eql(
        u8,
        &strict_resolved.plan.?.data.plan_hash.bytes,
        &derived_resolved.plan.?.data.plan_hash.bytes,
    ));
}

test "when_needed does not refuse a cross-architecture build it resolves away" {
    // `requiresGuestExecution` reads the request, not the plan, so a
    // `when_needed` taken at face value would look like guest execution and
    // refuse a cross-architecture `native_edit` build that the identical
    // request with `unchanged` completes -- even though it resolves to
    // exactly that.
    var request = validNativeEditRequest(
        "source.raw",
        "when-needed-cross/output.raw",
        "when-needed-cross",
        &.{},
    );
    request.target_architecture = .aarch64;
    request.initramfs = .{ .when_needed = .{} };

    try std.testing.expectEqual(
        std.meta.Tag(InitramfsPolicy).unchanged,
        try resolvedInitramfsTag(&request),
    );
}

test "when_needed leaves the initramfs alone when no package action is declared" {
    var request = whenNeededRequest();
    request.initramfs = .{ .when_needed = .{} };

    try std.testing.expectEqual(
        std.meta.Tag(InitramfsPolicy).unchanged,
        try resolvedInitramfsTag(&request),
    );
}

test "when_needed is not triggered by kernel-module configuration alone" {
    // The load-bearing case for the rule. The intuition is that configuring
    // kernel modules should rebuild the initramfs, and it is wrong here: zvmi
    // runs dracut `--no-hostonly`, under which `90kernel-modules` and
    // `01systemd-modules-load` both gate reading and installing the target's
    // `/etc/modprobe.d` and `/etc/modules-load.d` on `$hostonly`. The
    // configuration this request writes cannot reach the initramfs, so
    // regenerating would spend minutes producing an identical image.
    const modules = [_]KernelModule{
        .{ .name = "overlay", .load = true },
        .{ .name = "i915", .options = "enable_guc=2" },
    };
    var request = whenNeededRequest();
    request.os = .{ .kernel_modules = &modules };
    request.initramfs = .{ .when_needed = .{} };

    try std.testing.expectEqual(
        std.meta.Tag(InitramfsPolicy).unchanged,
        try resolvedInitramfsTag(&request),
    );
}

test "a when_needed plan is byte-identical to the explicit plan it resolves to" {
    // The whole design in one assertion: `when_needed` is a way of not having
    // to know the rule, not a different instruction. Because it resolves away
    // before the plan is built, the plan hash -- which covers the resolved
    // initramfs policy -- cannot tell the two requests apart.
    const actions = [_]PackageAction{.update_all};
    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};

    var derived = whenNeededRequest();
    derived.packages = .{ .actions = &actions, .repositories = &repositories };
    derived.initramfs = .{ .when_needed = .{ .generator = "dracut" } };

    var explicit = whenNeededRequest();
    explicit.packages = .{ .actions = &actions, .repositories = &repositories };
    explicit.initramfs = .{ .regenerate = .{
        .generator = "dracut",
        .kernels = &.{},
        .no_installed_kernels = .nothing_to_regenerate,
    } };

    var derived_resolved = try resolve(
        std.testing.allocator,
        &derived,
        .{ .host_architecture = .x86_64 },
    );
    defer derived_resolved.deinit(std.testing.allocator);
    var explicit_resolved = try resolve(
        std.testing.allocator,
        &explicit,
        .{ .host_architecture = .x86_64 },
    );
    defer explicit_resolved.deinit(std.testing.allocator);
    try std.testing.expect(derived_resolved.plan != null);
    try std.testing.expect(explicit_resolved.plan != null);
    try std.testing.expectEqualSlices(
        u8,
        &explicit_resolved.plan.?.data.plan_hash.bytes,
        &derived_resolved.plan.?.data.plan_hash.bytes,
    );
}

fn resolverRequest(resolver: ResolverPolicy) Request {
    const actions = struct {
        const value = [_]PackageAction{.{ .install = &.{"dracut"} }};
    };
    const repositories = struct {
        const value = [_]PackageRepository{.{
            .id = "base",
            .urls = &.{"https://packages.example.invalid"},
            .trust = &.{.{ .inline_bytes = "test key" }},
        }};
    };
    var request = whenNeededRequest();
    request.packages = .{
        .actions = &actions.value,
        .repositories = &repositories.value,
        .resolver = resolver,
    };
    return request;
}

test "a declared resolver must be one to three dotted quads" {
    // `MAXNS` is the bound because it is the bound a resolver library applies.
    // Accepting a fourth would record a nameserver in the plan that the run
    // demonstrably never asks, which is worse than refusing it.
    const rejected = [_][]const []const u8{
        &.{},
        &.{ "192.0.2.1", "192.0.2.2", "192.0.2.3", "192.0.2.4" },
        &.{"resolver.example.invalid"},
        &.{"192.0.2.256"},
        &.{"192.0.2"},
        &.{""},
        // Loopback is the trap worth naming. `127.0.0.53` reaches the build
        // host's own stub resolver from a chroot, which shares the host's
        // network namespace, and reaches nothing from inside a guest -- so it
        // is both the likeliest thing to copy off a working machine and a
        // silent way back to the dependence the declaration removes.
        &.{"127.0.0.53"},
        &.{"127.0.0.1"},
        &.{"0.0.0.0"},
        &.{"224.0.0.1"},
        &.{"255.255.255.255"},
        &.{ "192.0.2.1", "127.0.0.53" },
    };
    for (rejected) |nameservers| {
        var request = resolverRequest(.{ .nameservers = nameservers });
        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan == null);
        try std.testing.expect(hasDiagnosticCode(
            resolved.diagnostics,
            .invalid_policy,
        ));
    }

    // Refusing is not enough: `127.0.0.53` is one well-formed dotted quad, so
    // a message about the count and the format would name the only two things
    // its author got right and send them back to re-check both.
    var loopback = resolverRequest(.{ .nameservers = &.{"127.0.0.53"} });
    var loopback_resolved = try resolve(
        std.testing.allocator,
        &loopback,
        .{ .host_architecture = .x86_64 },
    );
    defer loopback_resolved.deinit(std.testing.allocator);
    var named_loopback = false;
    for (loopback_resolved.diagnostics.items) |diagnostic| {
        if (std.mem.indexOf(u8, diagnostic.message, "loopback") != null) {
            named_loopback = true;
        }
    }
    try std.testing.expect(named_loopback);

    var accepted = resolverRequest(.{ .nameservers = &.{ "192.0.2.1", "198.51.100.7" } });
    var resolved = try resolve(
        std.testing.allocator,
        &accepted,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    try std.testing.expectEqualStrings(
        "198.51.100.7",
        resolved.plan.?.data.packages.resolver.nameservers[1],
    );
}

fn cacheRequest(cache: PackageCachePolicy) Request {
    var request = resolverRequest(.host_resolver);
    request.packages.cache = cache;
    return request;
}

test "a declared package cache directory must be an absolute normalized path" {
    // The path is bound into a target root by a process running as root, so
    // it is checked for shape rather than resolved: what a path denotes has
    // to be readable from the path, which `..` destroys.
    const rejected = [_][]const u8{
        "",
        "relative/cache",
        "/",
        "/var/cache/zvmi/",
        "/var//cache",
        "/var/./cache",
        "/var/cache/../../etc",
    };
    for (rejected) |path| {
        var request = cacheRequest(.{ .cache_only = path });
        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan == null);
        try std.testing.expect(hasDiagnosticCode(resolved.diagnostics, .invalid_policy));

        // The same shape is refused whichever mode declares it: the directory
        // is mounted either way, and only the direction of the traffic differs.
        var populating = cacheRequest(.{ .online_populating = path });
        var populating_resolved = try resolve(
            std.testing.allocator,
            &populating,
            .{ .host_architecture = .x86_64 },
        );
        defer populating_resolved.deinit(std.testing.allocator);
        try std.testing.expect(populating_resolved.plan == null);
    }

    // Three shapes, three messages: an author who wrote a relative path and
    // an author who wrote `/` have made different mistakes.
    const named = [_]struct { path: []const u8, needle: []const u8 }{
        .{ .path = "relative/cache", .needle = "absolute" },
        .{ .path = "/", .needle = "host root" },
        .{ .path = "/var/cache/../etc", .needle = "normalized" },
    };
    for (named) |case| {
        var request = cacheRequest(.{ .cache_only = case.path });
        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        var saw = false;
        for (resolved.diagnostics.items) |diagnostic| {
            if (std.mem.indexOf(u8, diagnostic.message, case.needle) != null) saw = true;
        }
        try std.testing.expect(saw);
    }

    var accepted = cacheRequest(.{ .cache_only = "/var/cache/zvmi" });
    var resolved = try resolve(
        std.testing.allocator,
        &accepted,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);
    try std.testing.expectEqualStrings(
        "/var/cache/zvmi",
        resolved.plan.?.data.packages.cache.cache_only,
    );
}

test "an offline package transaction refuses a declared resolver and the VM backend" {
    // Refused rather than ignored. A plan that recorded nameservers a
    // cache-only run never consults would assert a dependence the run cannot
    // have, and the record is the whole point of declaring one.
    var declared = cacheRequest(.{ .cache_only = "/var/cache/zvmi" });
    declared.packages.resolver = .{ .nameservers = &.{"192.0.2.1"} };
    var declared_resolved = try resolve(
        std.testing.allocator,
        &declared,
        .{ .host_architecture = .x86_64 },
    );
    defer declared_resolved.deinit(std.testing.allocator);
    try std.testing.expect(declared_resolved.plan == null);
    var named_resolution = false;
    for (declared_resolved.diagnostics.items) |diagnostic| {
        if (std.mem.indexOf(u8, diagnostic.message, "no name to resolve") != null) {
            named_resolution = true;
        }
    }
    try std.testing.expect(named_resolution);

    // The inherited default is not refused, because it is what an author who
    // said nothing about resolution gets; the run simply installs none.
    var inherited = cacheRequest(.{ .cache_only = "/var/cache/zvmi" });
    var inherited_resolved = try resolve(
        std.testing.allocator,
        &inherited,
        .{ .host_architecture = .x86_64 },
    );
    defer inherited_resolved.deinit(std.testing.allocator);
    try std.testing.expect(inherited_resolved.plan != null);

    // The guest control document carries rendered JSON, not host directories,
    // so the VM backend refuses the policy where it is written rather than
    // running online and calling the result a cached build.
    var guest = cacheRequest(.{ .online_populating = "/var/cache/zvmi" });
    guest.execution.backend = .vm;
    guest.execution.vm = .{ .emulator_command = "/usr/bin/qemu-system-x86_64" };
    var guest_diagnostics = try validate(std.testing.allocator, &guest);
    defer guest_diagnostics.deinit(std.testing.allocator);
    var named_backend = false;
    for (guest_diagnostics.items) |diagnostic| {
        if (diagnostic.code == .unsupported_execution_backend and
            std.mem.eql(u8, diagnostic.configuration_path, "/packages/cache"))
        {
            named_backend = true;
        }
    }
    try std.testing.expect(named_backend);

    // The same policy on the backend that can carry it is accepted, so the
    // refusal is about the channel rather than about the cache.
    var chroot = guest;
    chroot.execution.backend = .unsafe_chroot;
    chroot.execution.vm = null;
    var chroot_diagnostics = try validate(std.testing.allocator, &chroot);
    defer chroot_diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!chroot_diagnostics.hasErrors());
}

test "the plan hash covers which cache the packages came from" {
    // Two runs reading different directories could install different bytes,
    // so they are not one plan -- and the mode alone is not enough, because
    // two offline runs reading different caches are the interesting case.
    const shapes = [_]PackageCachePolicy{
        .online,
        .{ .online_populating = "/var/cache/zvmi" },
        .{ .cache_only = "/var/cache/zvmi" },
        .{ .cache_only = "/var/cache/other" },
    };
    var hashes: [shapes.len]Digest = undefined;
    for (shapes, 0..) |shape, index| {
        var request = cacheRequest(shape);
        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan != null);
        hashes[index] = resolved.plan.?.data.plan_hash;
    }
    for (hashes, 0..) |left, i| {
        for (hashes[i + 1 ..]) |right| {
            try std.testing.expect(!std.mem.eql(u8, &left.bytes, &right.bytes));
        }
    }
}

test "the declared cache directory is the capability the preflight probes" {
    const io = std.testing.io;
    // Absolute because the policy requires it, and a probe of a relative path
    // would be a probe of wherever the test happened to be run from.
    const cache_path = "/tmp/test-customize-package-cache";
    const nested_path = cache_path ++ "/rpms";
    Io.Dir.cwd().deleteTree(io, cache_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, cache_path) catch {};

    // The mode decides whether the directory is an input or an output, and so
    // decides what the probe has to find. A cache-only run that cannot see
    // its directory must fail rather than reach the network instead.
    var relative = cacheRequest(.{ .cache_only = "test-customize-package-cache" });
    var relative_resolved = try resolve(
        std.testing.allocator,
        &relative,
        .{ .host_architecture = .x86_64 },
    );
    defer relative_resolved.deinit(std.testing.allocator);
    try std.testing.expect(relative_resolved.plan == null);

    const Probe = struct {
        fn state(request: *const Request, probe_io: Io) !CapabilityState {
            var resolved = try resolve(
                std.testing.allocator,
                request,
                .{ .host_architecture = .x86_64 },
            );
            defer resolved.deinit(std.testing.allocator);
            try std.testing.expect(resolved.plan != null);
            var saw: ?[]const u8 = null;
            for (resolved.plan.?.data.required_capabilities) |capability| {
                if (capability.kind == .package_cache) saw = capability.path;
            }
            // The capability names the directory, so a preflight report says
            // which one was missing rather than that some cache was.
            try std.testing.expect(saw != null);
            try std.testing.expectEqualStrings(
                packageCacheDirectory(resolved.plan.?.data.packages.cache).?,
                saw.?,
            );
            return packageCacheAvailable(probe_io, &resolved.plan.?);
        }
    };

    var missing = cacheRequest(.{ .cache_only = nested_path });
    try std.testing.expectEqual(
        CapabilityState.missing,
        try Probe.state(&missing, io),
    );

    // A populating run creates its own directory, so only the parent has to
    // be there -- and when the parent is not, it is still missing.
    var populating = cacheRequest(.{ .online_populating = nested_path });
    try std.testing.expectEqual(
        CapabilityState.missing,
        try Probe.state(&populating, io),
    );

    try Io.Dir.cwd().createDirPath(io, cache_path);
    try std.testing.expectEqual(
        CapabilityState.available,
        try Probe.state(&populating, io),
    );
    try std.testing.expectEqual(
        CapabilityState.missing,
        try Probe.state(&missing, io),
    );

    try Io.Dir.cwd().createDirPath(io, nested_path);
    try std.testing.expectEqual(
        CapabilityState.available,
        try Probe.state(&missing, io),
    );

    // No other backend can carry a host directory into the target, so the
    // probe reports the request as unsupported rather than as a directory
    // that happens to be there.
    var native = cacheRequest(.{ .cache_only = nested_path });
    native.execution.backend = .native_edit;
    native.execution.acknowledge_unsafe = false;
    try std.testing.expectEqual(
        CapabilityState.unsupported,
        try Probe.state(&native, io),
    );
}

test "the plan hash covers where name resolution came from" {
    // The point of declaring the resolver at all. If the hash did not cover
    // it, two runs that resolved repository names through different servers --
    // and so could have installed different bytes -- would claim to be the
    // same plan.
    var inherited = resolverRequest(.host_resolver);
    var declared = resolverRequest(.{ .nameservers = &.{"192.0.2.1"} });
    var other = resolverRequest(.{ .nameservers = &.{"198.51.100.7"} });

    var inherited_resolved = try resolve(
        std.testing.allocator,
        &inherited,
        .{ .host_architecture = .x86_64 },
    );
    defer inherited_resolved.deinit(std.testing.allocator);
    var declared_resolved = try resolve(
        std.testing.allocator,
        &declared,
        .{ .host_architecture = .x86_64 },
    );
    defer declared_resolved.deinit(std.testing.allocator);
    var other_resolved = try resolve(
        std.testing.allocator,
        &other,
        .{ .host_architecture = .x86_64 },
    );
    defer other_resolved.deinit(std.testing.allocator);

    try std.testing.expect(!std.mem.eql(
        u8,
        &inherited_resolved.plan.?.data.plan_hash.bytes,
        &declared_resolved.plan.?.data.plan_hash.bytes,
    ));
    try std.testing.expect(!std.mem.eql(
        u8,
        &declared_resolved.plan.?.data.plan_hash.bytes,
        &other_resolved.plan.?.data.plan_hash.bytes,
    ));
}

test "both executing backends declare inheriting the host resolver" {
    // The capability is the visible half of the declaration: a consumer that
    // requires every input to come from the request can refuse exactly this
    // one. The VM backend looks like it escapes the dependence and does not --
    // libslirp answers `10.0.2.3` by forwarding to whatever `/etc/resolv.conf`
    // names in the emulator process -- so declaring it for the chroot alone
    // would let the same request shed the capability by changing backend while
    // keeping every bit of the dependence.
    for ([_]ExecutionBackend{ .unsafe_chroot, .vm }) |backend| {
        var inherited = resolverRequest(.host_resolver);
        var declared = resolverRequest(.{ .nameservers = &.{"192.0.2.1"} });
        if (backend == .vm) {
            inherited.execution.backend = .vm;
            inherited.execution.vm = validVmPolicy();
            inherited.execution.vm.?.network = .declared_repositories;
            declared.execution.backend = .vm;
            declared.execution.vm = validVmPolicy();
            declared.execution.vm.?.network = .declared_repositories;
        }

        var inherited_resolved = try resolve(
            std.testing.allocator,
            &inherited,
            .{ .host_architecture = .x86_64 },
        );
        defer inherited_resolved.deinit(std.testing.allocator);
        var declared_resolved = try resolve(
            std.testing.allocator,
            &declared,
            .{ .host_architecture = .x86_64 },
        );
        defer declared_resolved.deinit(std.testing.allocator);

        try std.testing.expect(hasCapabilityKind(
            inherited_resolved.plan.?.data.required_capabilities,
            .read_host_resolver,
        ));
        try std.testing.expect(!hasCapabilityKind(
            declared_resolved.plan.?.data.required_capabilities,
            .read_host_resolver,
        ));
    }

    // An offline package transaction reads no resolver, on either backend and
    // whatever the resolver policy says, because the run installs none: the
    // chroot backend is where this is reachable, since the VM backend refuses
    // a declared cache outright. The capability has to follow what the run
    // does rather than which backend it runs on.
    var offline = resolverRequest(.host_resolver);
    offline.packages.cache = .{ .cache_only = "/var/cache/zvmi" };
    var offline_resolved = try resolve(
        std.testing.allocator,
        &offline,
        .{ .host_architecture = .x86_64 },
    );
    defer offline_resolved.deinit(std.testing.allocator);
    try std.testing.expect(!hasCapabilityKind(
        offline_resolved.plan.?.data.required_capabilities,
        .read_host_resolver,
    ));

    // And the same request with a populating cache keeps it: the directory is
    // an output, the transaction still resolves repository names, so this is
    // about the network the run reaches and not about declaring a directory.
    var populating = resolverRequest(.host_resolver);
    populating.packages.cache = .{ .online_populating = "/var/cache/zvmi" };
    var populating_resolved = try resolve(
        std.testing.allocator,
        &populating,
        .{ .host_architecture = .x86_64 },
    );
    defer populating_resolved.deinit(std.testing.allocator);
    try std.testing.expect(hasCapabilityKind(
        populating_resolved.plan.?.data.required_capabilities,
        .read_host_resolver,
    ));

    // And it never gates a run, because the executors tolerate a host with no
    // resolver: a transaction that only removes packages, or whose repository
    // URLs are literal addresses, resolves no names at all.
    try std.testing.expectEqual(
        CapabilityState.available,
        systemCapabilityCheck(null, std.testing.io, .{
            .kind = .read_host_resolver,
            .path = "/no/such/resolv.conf",
            .reason = "",
        }),
    );
}

test "a guest cannot be pointed at its own network's alias for this machine" {
    // Outside 10.0.2.0/24 slirp NATs the traffic out through real host sockets,
    // so a declared resolver reaches exactly what a chroot would reach. Inside
    // it nothing does: 10.0.2.3 is answered by rewriting the packet to whatever
    // the emulator process's own `/etc/resolv.conf` names, and every other
    // in-subnet address is rewritten to the build host's loopback.
    //
    // 10.0.2.3 has to be refused rather than waved through as "what
    // host_resolver uses anyway". `controlFromPolicy` would render a control
    // document byte-identical to `host_resolver`'s, so accepting it would let a
    // request shed the `read_host_resolver` capability while keeping the whole
    // dependence on the build machine -- defeating the one consumer a declared
    // resolver exists to serve. It is also the inverse of the loopback rule:
    // 127.0.0.53 is refused for working on the chroot backend and failing in a
    // guest, and this would be permitted for the reverse.
    const rejected = [_][]const u8{ "10.0.2.2", "10.0.2.15", "10.0.2.1", "10.0.2.3" };
    for (rejected) |nameserver| {
        var request = resolverRequest(.{ .nameservers = &.{nameserver} });
        request.execution.backend = .vm;
        request.execution.vm = validVmPolicy();
        request.execution.vm.?.network = .declared_repositories;
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(diagnostics.hasErrors());
    }

    // The same addresses are unremarkable on the backend that has no such
    // network, so the refusal has to be the VM policy's rather than the
    // resolver's.
    for (rejected) |nameserver| {
        var request = resolverRequest(.{ .nameservers = &.{nameserver} });
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(!diagnostics.hasErrors());
    }

    // The rule is the subnet and not "declared resolvers are suspect": an
    // address slirp forwards is accepted on the same backend.
    var accepted = resolverRequest(.{ .nameservers = &.{"10.1.2.3"} });
    accepted.execution.backend = .vm;
    accepted.execution.vm = validVmPolicy();
    accepted.execution.vm.?.network = .declared_repositories;
    var diagnostics = try validate(std.testing.allocator, &accepted);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!diagnostics.hasErrors());
}

test "a repository credential is declared by reference and never by value" {
    // The structural guarantee the rest of this test rests on. Every writer in
    // this module stringifies whole types by reflection, so an arm holding
    // bytes would be published by a public API by default. Adding one has to
    // fail here rather than in a customer's provenance document.
    inline for (@typeInfo(CredentialSource).@"union".fields) |field| {
        comptime std.debug.assert(
            std.mem.eql(u8, field.name, "host_path") or
                std.mem.eql(u8, field.name, "host_environment"),
        );
    }

    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_environment = "ZVMI_REPOSITORY_TOKEN" },
        } },
    }};
    var request = whenNeededRequest();
    request.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &repositories,
    };
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    const plan = resolved.plan orelse return error.TestUnexpectedResult;

    // Where the material comes from is recorded everywhere, because a reader
    // has to be able to tell which identity a build ran as and what it read.
    inline for (.{ "request", "plan" }) |which| {
        var output: Io.Writer.Allocating = .init(std.testing.allocator);
        defer output.deinit();
        if (comptime std.mem.eql(u8, which, "request")) {
            try writeRequestJson(request, &output.writer);
        } else {
            try writePlanJson(&plan, &output.writer);
        }
        const json = output.written();
        try std.testing.expect(
            std.mem.indexOf(u8, json, "ZVMI_REPOSITORY_TOKEN") != null,
        );
        try std.testing.expect(std.mem.indexOf(u8, json, "builder") != null);
    }

    // Reading it is a declared capability, named one source at a time so a
    // consumer refusing host inputs can see which variable, not merely that
    // there was one. `env:` distinguishes a variable from a path, since a
    // relative path is refused and so cannot collide with the prefix.
    var found: usize = 0;
    for (plan.data.required_capabilities) |capability| {
        if (capability.kind != .read_host_credential) continue;
        found += 1;
        try std.testing.expectEqualStrings("env:ZVMI_REPOSITORY_TOKEN", capability.path);
    }
    try std.testing.expectEqual(@as(usize, 1), found);

    // The hash covers the source, so pointing a build at a different variable
    // is a different plan -- but there is no material in these types to hash,
    // which is what keeps a published plan identifier from verifying a guess
    // of a low-entropy password offline.
    var elsewhere = [_]PackageRepository{repositories[0]};
    elsewhere[0].credential = .{ .basic = .{
        .username = "builder",
        .password = .{ .host_environment = "ZVMI_OTHER_TOKEN" },
    } };
    var moved = request;
    moved.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &elsewhere,
    };
    var moved_resolved = try resolve(
        std.testing.allocator,
        &moved,
        .{ .host_architecture = .x86_64 },
    );
    defer moved_resolved.deinit(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &plan.data.plan_hash.bytes,
        &moved_resolved.plan.?.data.plan_hash.bytes,
    ));

    // And declaring none is a different plan again, so a credential cannot be
    // added to a build without changing its identifier.
    var bare = [_]PackageRepository{repositories[0]};
    bare[0].credential = null;
    var bare_request = request;
    bare_request.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &bare,
    };
    var bare_resolved = try resolve(
        std.testing.allocator,
        &bare_request,
        .{ .host_architecture = .x86_64 },
    );
    defer bare_resolved.deinit(std.testing.allocator);
    try std.testing.expect(!std.mem.eql(
        u8,
        &plan.data.plan_hash.bytes,
        &bare_resolved.plan.?.data.plan_hash.bytes,
    ));
    for (bare_resolved.plan.?.data.required_capabilities) |capability| {
        try std.testing.expect(capability.kind != .read_host_credential);
    }
}

test "a credential is refused where it could not be kept secret" {
    const Case = struct {
        credential: RepositoryCredential,
        url: []const u8,
        expected: []const u8,
    };
    const cases = [_]Case{
        // Basic authentication puts the password on the wire, so a plaintext
        // URL for a credentialed repository leaks it to anyone on the path.
        .{
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_environment = "ZVMI_REPOSITORY_TOKEN" },
            } },
            .url = "http://packages.example.invalid",
            .expected = "https",
        },
        // A `file://` repository cannot carry a credential at all, so one
        // declared against it is a mistake about what the build will do.
        .{
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_path = "/run/secrets/token" },
            } },
            .url = "file:///srv/packages",
            .expected = "https",
        },
        // Read by the run rather than by the caller, so a relative path would
        // name a different file depending on where the build was started.
        .{
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_path = "secrets/token" },
            } },
            .url = "https://packages.example.invalid",
            .expected = "absolute",
        },
        .{
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_environment = "2TOKEN" },
            } },
            .url = "https://packages.example.invalid",
            .expected = "environment variable",
        },
        .{
            .credential = .{ .basic = .{
                .username = "builder",
                .password = .{ .host_environment = "TOKEN=x" },
            } },
            .url = "https://packages.example.invalid",
            .expected = "environment variable",
        },
        // A newline in the user name would end the `username=` line and let
        // whatever followed be read back as repository configuration.
        .{
            .credential = .{ .basic = .{
                .username = "builder\nenabled=0",
                .password = .{ .host_path = "/run/secrets/token" },
            } },
            .url = "https://packages.example.invalid",
            .expected = "user name",
        },
        .{
            .credential = .{ .basic = .{
                .username = "",
                .password = .{ .host_path = "/run/secrets/token" },
            } },
            .url = "https://packages.example.invalid",
            .expected = "user name",
        },
    };
    for (cases) |case| {
        const repositories = [_]PackageRepository{.{
            .id = "base",
            .urls = &.{case.url},
            .trust = &.{.{ .inline_bytes = "test key" }},
            .credential = case.credential,
        }};
        var request = whenNeededRequest();
        request.packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
        };
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(diagnostics.hasErrors());
        var named = false;
        for (diagnostics.items) |diagnostic| {
            if (std.mem.indexOf(u8, diagnostic.message, case.expected) != null) {
                named = true;
            }
        }
        try std.testing.expect(named);
    }
}

test "a hook is refused where it could not be run" {
    const runnable = "#!/bin/sh\nexit 0\n";
    const oversized = "#!" ++ ("x" ** max_hook_script_bytes);
    const long_argument = "x" ** (max_hook_argument_bytes + 1);
    var many_arguments: [max_hook_arguments + 1][]const u8 = undefined;
    for (&many_arguments) |*slot| slot.* = "x";

    const cases = [_]struct {
        why: []const u8,
        hooks: []const Hook,
    }{
        .{
            .why = "a script that names no interpreter",
            .hooks = &.{.{ .name = "bare", .phase = .finalize, .source = .{ .inline_script = "exit 0\n" } }},
        },
        .{
            .why = "a script with nothing in it",
            .hooks = &.{.{ .name = "empty", .phase = .finalize, .source = .{ .inline_script = "" } }},
        },
        .{
            .why = "a script past the declared bound",
            .hooks = &.{.{ .name = "huge", .phase = .finalize, .source = .{ .inline_script = oversized } }},
        },
        .{
            .why = "a source naming no path",
            .hooks = &.{.{ .name = "nowhere", .phase = .finalize, .source = .{ .host_path = "" } }},
        },
        .{
            .why = "more arguments than a hook may take",
            .hooks = &.{.{
                .name = "wordy",
                .phase = .finalize,
                .source = .{ .inline_script = runnable },
                .arguments = &many_arguments,
            }},
        },
        .{
            .why = "an argument past the declared bound",
            .hooks = &.{.{
                .name = "long",
                .phase = .finalize,
                .source = .{ .inline_script = runnable },
                .arguments = &.{long_argument},
            }},
        },
        .{
            .why = "an argument that would be truncated at a NUL",
            .hooks = &.{.{
                .name = "truncating",
                .phase = .finalize,
                .source = .{ .inline_script = runnable },
                .arguments = &.{"one\x00two"},
            }},
        },
        .{
            .why = "two hooks answering to the same name",
            .hooks = &.{
                .{ .name = "same", .phase = .finalize, .source = .{ .inline_script = runnable } },
                .{ .name = "same", .phase = .finalize, .source = .{ .inline_script = runnable } },
            },
        },
        .{
            .why = "phases declared out of the order they run in",
            .hooks = &.{
                .{ .name = "late", .phase = .finalize, .source = .{ .inline_script = runnable } },
                .{ .name = "early", .phase = .after_packages, .source = .{ .inline_script = runnable } },
            },
        },
    };
    for (cases) |case| {
        var request = whenNeededRequest();
        request.hooks = case.hooks;
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        std.testing.expect(hasDiagnosticCode(diagnostics, .invalid_policy)) catch |err| {
            std.debug.print("accepted {s}\n", .{case.why});
            return err;
        };
    }

    // The shape that is refused everywhere else is accepted here, so the table
    // above is about what each case says and not about hooks in general.
    var accepted = whenNeededRequest();
    accepted.hooks = &.{
        .{
            .name = "first",
            .phase = .after_packages,
            .source = .{ .inline_script = runnable },
            .arguments = &.{"--quiet"},
        },
        .{ .name = "second", .phase = .finalize, .source = .{ .host_path = "hooks/second.sh" } },
    };
    var diagnostics = try validate(std.testing.allocator, &accepted);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!diagnostics.hasErrors());
}

test "the vm backend carries a hook, and refuses more than the channel holds" {
    const hooks = [_]Hook{.{
        .name = "guest-script",
        .phase = .finalize,
        .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
    }};
    var request = whenNeededRequest();
    request.execution.backend = .vm;
    request.execution.vm = .{ .emulator_command = "/usr/bin/qemu-system-x86_64" };
    request.hooks = &hooks;

    // The guest has a script channel now, so the hook that was refused for
    // having nowhere to go is accepted for the same reason.
    var accepted = try validate(std.testing.allocator, &request);
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expect(!accepted.hasErrors());

    // What is left to refuse is what the control document cannot hold. Named
    // rather than left to a generic unsupported capability, because a request
    // whose hooks were dropped would publish an image the plan says had them.
    var too_many = request;
    const overflowing = try std.testing.allocator.alloc(Hook, vm_control.max_hooks + 1);
    defer std.testing.allocator.free(overflowing);
    const names = try std.testing.allocator.alloc([16]u8, overflowing.len);
    defer std.testing.allocator.free(names);
    for (overflowing, names, 0..) |*hook, *name, index| {
        hook.* = .{
            .name = std.fmt.bufPrint(name, "hook-{d}", .{index}) catch unreachable,
            .phase = .finalize,
            .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
        };
    }
    too_many.hooks = overflowing;

    var diagnostics = try validate(std.testing.allocator, &too_many);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(diagnostics.hasErrors());
    var named = false;
    for (diagnostics.items) |diagnostic| {
        if (diagnostic.code == .unsupported_execution_backend and
            std.mem.eql(u8, diagnostic.configuration_path, "/hooks"))
        {
            named = true;
        }
    }
    try std.testing.expect(named);

    // The same request on the backend whose channel is the filesystem is
    // accepted, so the refusal is about the document rather than about hooks.
    var chroot = too_many;
    chroot.execution.backend = .unsafe_chroot;
    chroot.execution.vm = null;
    var chroot_diagnostics = try validate(std.testing.allocator, &chroot);
    defer chroot_diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!chroot_diagnostics.hasErrors());
}

test "a hook clears preflight on the backend that runs it" {
    // A hook derives a `script_execution` capability, and preflight is a
    // separate mapping from the capability state each backend publishes. The
    // backend saying yes is therefore not the same statement as the request
    // clearing preflight, which is why this asserts the second one.
    const io = std.testing.io;
    const source_path = "test-customize-hook-preflight.raw";
    const spool_path = "test-customize-hook-preflight-spool";
    const workspace_path = "test-customize-hook-preflight-work";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, source_path, spool_path);

    const hooks = [_]Hook{.{
        .name = "marker",
        .phase = .finalize,
        .source = .{ .inline_script = "#!/bin/sh\nexit 0\n" },
    }};
    var request = validNativeEditRequest(
        source_path,
        workspace_path ++ "/output.raw",
        workspace_path,
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.hooks = &hooks;

    const Available = struct {
        fn check(_: ?*anyopaque, _: Io, _: *const ResolvedPlan) CapabilityState {
            return .available;
        }
    };
    var platform = Platform.system();
    platform.unsafeChrootCheckFn = Available.check;
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(!resolved.diagnostics.hasErrors());
    var report = try preflight(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        platform,
    );
    defer report.deinit(std.testing.allocator);
    var saw_script_execution = false;
    for (report.capabilities) |check| {
        if (check.requirement.kind != .script_execution) continue;
        saw_script_execution = true;
        try std.testing.expectEqual(CapabilityState.available, check.state);
    }
    try std.testing.expect(saw_script_execution);
    try std.testing.expect(report.ready());

    // The routing arm above sends every non-vm backend to the same function,
    // so what keeps it from accepting a hook on a backend that cannot run one
    // is that function's own backend guard. Asserting that means reaching
    // preflight with such a plan, which `resolve` will not produce -- so the
    // accepted plan is retargeted rather than a new request validated.
    var retargeted_data = resolved.plan.?.data.*;
    retargeted_data.execution.backend = .native_edit;
    var scratch = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer scratch.deinit();
    const retargeted = ResolvedPlan{
        .arena = scratch,
        .data = &retargeted_data,
    };
    var refused = try preflight(
        std.testing.allocator,
        io,
        &retargeted,
        platform,
    );
    defer refused.deinit(std.testing.allocator);
    var refused_script_execution = false;
    for (refused.capabilities) |check| {
        if (check.requirement.kind != .script_execution) continue;
        refused_script_execution = true;
        try std.testing.expectEqual(CapabilityState.unsupported, check.state);
    }
    try std.testing.expect(refused_script_execution);
    try std.testing.expect(!refused.ready());

    // And the request form is refused earlier still, by name, so a caller
    // never gets as far as the plan that had to be forged above.
    var native = request;
    native.execution.backend = .native_edit;
    var native_resolved = try resolve(
        std.testing.allocator,
        &native,
        .{ .host_architecture = .x86_64 },
    );
    defer native_resolved.deinit(std.testing.allocator);
    var named = false;
    for (native_resolved.diagnostics.items) |diagnostic| {
        if (diagnostic.code == .unsupported_execution_backend and
            std.mem.eql(u8, diagnostic.configuration_path, "/execution/backend"))
        {
            named = true;
        }
    }
    try std.testing.expect(named);
}

test "a hook that ran is recorded by digest in provenance" {
    const io = std.testing.io;
    const source_path = "test-customize-hook-source.raw";
    const spool_path = "test-customize-hook-spool";
    const workspace_path = "test-customize-hook-work";
    const output_path = workspace_path ++ "/output.raw";
    defer Io.Dir.cwd().deleteFile(io, source_path) catch {};
    defer Io.Dir.cwd().deleteFile(io, spool_path) catch {};
    defer Io.Dir.cwd().deleteTree(io, workspace_path) catch {};
    try createCustomizeTestDisk(io, source_path, spool_path);
    try Io.Dir.cwd().createDirPath(io, workspace_path);

    const script = "#!/bin/sh\ntouch /etc/ran\n";
    var script_digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(script, &script_digest, .{});
    const hooks = [_]Hook{.{
        .name = "marker",
        .phase = .finalize,
        .source = .{ .inline_script = script },
    }};
    var request = validNativeEditRequest(
        source_path,
        output_path,
        workspace_path,
        &.{},
    );
    request.execution.backend = .unsafe_chroot;
    request.execution.acknowledge_unsafe = true;
    request.hooks = &hooks;

    const FakeUnsafe = struct {
        // The report crosses back to `buildResult`, which copies it there, so
        // the records have to outlive this call rather than be a temporary the
        // return statement points at.
        var records: [1]HookRecord = undefined;

        fn check(_: ?*anyopaque, _: Io, _: *const ResolvedPlan) CapabilityState {
            return .available;
        }

        fn run(
            _: ?*anyopaque,
            allocator: Allocator,
            _: Io,
            plan: *const ResolvedPlan,
            _: preserved_image.RawMutationTarget,
            _: Deadline,
        ) !UnsafeChrootRuntimeReport {
            try std.testing.expectEqual(@as(usize, 1), plan.data.hooks.len);
            return .{
                .arena = std.heap.ArenaAllocator.init(allocator),
                .tools = &.{},
                .installed_packages = &.{},
                .hooks = &records,
            };
        }
    };
    FakeUnsafe.records = .{.{
        .name = "marker",
        .phase = .finalize,
        .source_sha256 = .{ .bytes = script_digest },
        .exit_code = 0,
    }};

    var platform = Platform.system();
    platform.unsafeChrootCheckFn = FakeUnsafe.check;
    platform.unsafeChrootRunFn = FakeUnsafe.run;
    var resolved = try resolve(
        std.testing.allocator,
        &request,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    var outcome = try execute(
        std.testing.allocator,
        io,
        &resolved.plan.?,
        platform,
        null,
    );
    defer outcome.deinit(std.testing.allocator);
    const result = outcome.result orelse return error.TestUnexpectedResult;
    const preserved = result.provenance.execution.preserved orelse
        return error.TestUnexpectedResult;
    try std.testing.expectEqual(@as(usize, 1), preserved.hooks.len);
    try std.testing.expectEqualStrings("marker", preserved.hooks[0].name);
    try std.testing.expectEqual(HookPhase.finalize, preserved.hooks[0].phase);
    try std.testing.expectEqualSlices(
        u8,
        &script_digest,
        &preserved.hooks[0].source_sha256.bytes,
    );
    try std.testing.expectEqual(@as(u8, 0), preserved.hooks[0].exit_code);

    // Provenance is published as JSON, so a record that cannot be read back is
    // a record only this program can use.
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    try writeProvenanceJson(result.provenance, &output.writer);
    const document = output.written();
    const hex = std.fmt.bytesToHex(script_digest, .lower);
    try std.testing.expect(std.mem.indexOf(u8, document, &hex) != null);
}

test "a digest survives the round trip a worker report makes" {
    // The unsafe backend's report crosses a process boundary as JSON, so a
    // digest that stringifies one way and parses another would arrive as a
    // different value or not at all.
    const original = Digest{ .bytes = [_]u8{0xa5} ** 32 };
    var output: Io.Writer.Allocating = .init(std.testing.allocator);
    defer output.deinit();
    var stringify: std.json.Stringify = .{ .writer = &output.writer };
    try stringify.write(original);
    const parsed = try std.json.parseFromSlice(
        Digest,
        std.testing.allocator,
        output.written(),
        .{},
    );
    defer parsed.deinit();
    try std.testing.expectEqualSlices(u8, &original.bytes, &parsed.value.bytes);

    try std.testing.expectError(
        error.InvalidCharacter,
        std.json.parseFromSlice(Digest, std.testing.allocator, "\"beef\"", .{}),
    );
}

test "the vm backend accepts a credential and carries it off the control document" {
    const repositories = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
        .credential = .{ .basic = .{
            .username = "builder",
            .password = .{ .host_environment = "ZVMI_REPOSITORY_TOKEN" },
        } },
    }};
    var request = whenNeededRequest();
    request.execution.backend = .vm;
    request.execution.vm = .{
        .emulator_command = "/usr/bin/qemu-system-x86_64",
        .network = .declared_repositories,
    };
    request.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &repositories,
    };
    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    try std.testing.expect(!diagnostics.hasErrors());

    // The same policy is accepted on the backend that has always carried it,
    // so both backends now answer a declared credential the same way.
    var chroot = request;
    chroot.execution.backend = whenNeededRequest().execution.backend;
    chroot.execution.vm = null;
    var accepted = try validate(std.testing.allocator, &chroot);
    defer accepted.deinit(std.testing.allocator);
    try std.testing.expect(!accepted.hasErrors());

    // The control document a plan produces names the device rather than the
    // material, and the material is not representable in it: `Repository`
    // carries a user name and an index, and there is no field a password could
    // occupy. Asserted structurally, because a test that only checked the
    // rendered bytes would pass again the moment someone added one.
    const fields = @typeInfo(vm_control.ControlCredential).@"union".fields;
    try std.testing.expectEqual(@as(usize, 1), fields.len);
    const basic = @typeInfo(fields[0].type).@"struct".fields;
    try std.testing.expectEqual(@as(usize, 2), basic.len);
    try std.testing.expect(std.mem.eql(u8, basic[0].name, "username"));
    try std.testing.expect(std.mem.eql(u8, basic[1].name, "password_index"));
}

test "a repository URL cannot smuggle a credential past the declaration" {
    // Everything about a repository is kept: the URL is hashed into the plan
    // identifier, written out verbatim by `writeRequestJson` and
    // `writePlanJson`, and recorded in provenance. A password in the authority
    // would be published by all three, and would be the one way a secret could
    // reach a run without being declared at all.
    const smuggled = [_][]const u8{
        "https://builder:hunter2@packages.example.invalid",
        "https://token@packages.example.invalid",
        "http://builder:hunter2@packages.example.invalid/base",
    };
    for (smuggled) |url| {
        const repositories = [_]PackageRepository{.{
            .id = "base",
            .urls = &.{url},
            .trust = &.{.{ .inline_bytes = "test key" }},
        }};
        var request = whenNeededRequest();
        request.packages = .{
            .actions = &.{.{ .install = &.{"dracut"} }},
            .repositories = &repositories,
        };
        var resolved = try resolve(
            std.testing.allocator,
            &request,
            .{ .host_architecture = .x86_64 },
        );
        defer resolved.deinit(std.testing.allocator);
        try std.testing.expect(resolved.plan == null);
        var named_userinfo = false;
        for (resolved.diagnostics.items) |diagnostic| {
            if (std.mem.indexOf(u8, diagnostic.message, "userinfo") != null) {
                named_userinfo = true;
            }
        }
        try std.testing.expect(named_userinfo);
    }

    // An `@` in the path is not a credential, and refusing it would refuse
    // repositories that are laid out per-account.
    const path_at = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid/user@example/rpms"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    var accepted = whenNeededRequest();
    accepted.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &path_at,
    };
    var resolved = try resolve(
        std.testing.allocator,
        &accepted,
        .{ .host_architecture = .x86_64 },
    );
    defer resolved.deinit(std.testing.allocator);
    try std.testing.expect(resolved.plan != null);

    // The request validator and the two privilege boundaries share one
    // predicate, so a URL cannot be accepted here and refused once the run is
    // already under way.
    const scheme = [_]PackageRepository{.{
        .id = "base",
        .urls = &.{"ftp://packages.example.invalid/base"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
    var wrong_scheme = whenNeededRequest();
    wrong_scheme.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = &scheme,
    };
    var scheme_resolved = try resolve(
        std.testing.allocator,
        &wrong_scheme,
        .{ .host_architecture = .x86_64 },
    );
    defer scheme_resolved.deinit(std.testing.allocator);
    try std.testing.expect(scheme_resolved.plan == null);
}

fn hasCapabilityKind(
    capabilities: []const CapabilityRequirement,
    kind: CapabilityKind,
) bool {
    for (capabilities) |capability| {
        if (capability.kind == kind) return true;
    }
    return false;
}

// The repositories every lock test needs, so the cases below carry only what
// they are about.
fn lockTestRepositories() []const PackageRepository {
    return &.{.{
        .id = "base",
        .urls = &.{"https://packages.example.invalid"},
        .trust = &.{.{ .inline_bytes = "test key" }},
    }};
}

test "an exact lock states a whole identity or is refused where it is written" {
    const Case = struct {
        actions: []const PackageAction,
        lock: []const PackageVersionLock,
        expected: []const u8,
    };
    const install_dracut: []const PackageAction = &.{.{ .install = &.{"dracut"} }};
    const cases = [_]Case{
        // A lock that pins nothing would refuse every action it was paired
        // with under the coverage rule, which is a confusing way to say the
        // request meant `unlocked`.
        .{
            .actions = install_dracut,
            .lock = &.{},
            .expected = "at least one package",
        },
        // The whole point of the type. A bare version matches whatever
        // release the repository happens to hold, so a request that wrote one
        // would report itself reproducible without being it.
        .{
            .actions = install_dracut,
            .lock = &.{.{ .name = "dracut", .evr = "059", .architecture = "x86_64" }},
            .expected = "epoch:version-release",
        },
        // An epoch and no release is the same failure, half-corrected.
        .{
            .actions = install_dracut,
            .lock = &.{.{ .name = "dracut", .evr = "0:059", .architecture = "x86_64" }},
            .expected = "epoch:version-release",
        },
        .{
            .actions = install_dracut,
            .lock = &.{.{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "" }},
            .expected = "architecture",
        },
        // Two pins for one package and architecture cannot both hold, and the
        // verifier would report whichever it happened to compare second.
        .{
            .actions = install_dracut,
            .lock = &.{
                .{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64" },
                .{ .name = "dracut", .evr = "0:060-1.azl3", .architecture = "x86_64" },
            },
            .expected = "twice",
        },
        // `update_all`'s subject is whatever the repositories hold when it
        // runs, which is the question an exact lock exists to close.
        .{
            .actions = &.{.update_all},
            .lock = &.{.{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64" }},
            .expected = "update_all",
        },
        // Pinning one package and leaving another free is pinned in one place
        // and open in the other, which is not a locked transaction.
        .{
            .actions = &.{.{ .install = &.{ "dracut", "openssh" } }},
            .lock = &.{.{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64" }},
            .expected = "must be pinned",
        },
        // A lock with no transaction to lock. Refused here because the run
        // would otherwise compare the whole installed set against an empty
        // baseline and fail on the first package the input image carried.
        .{
            .actions = &.{},
            .lock = &.{.{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64" }},
            .expected = "at least one package action",
        },
    };
    for (cases) |case| {
        var request = whenNeededRequest();
        request.packages = .{
            .actions = case.actions,
            .repositories = lockTestRepositories(),
            .lock = .{ .exact = case.lock },
        };
        var diagnostics = try validate(std.testing.allocator, &request);
        defer diagnostics.deinit(std.testing.allocator);
        try std.testing.expect(diagnostics.hasErrors());
        var named = false;
        for (diagnostics.items) |diagnostic| {
            if (std.mem.indexOf(u8, diagnostic.message, case.expected) != null) {
                named = true;
            }
        }
        try std.testing.expect(named);
    }
}

test "a lock covering the whole declared closure resolves" {
    // The positive case, and the shape a completed online run is meant to
    // emit: every name an action mentions is pinned, including the dependency
    // the action did not name.
    var request = whenNeededRequest();
    request.packages = .{
        .actions = &.{.{ .install = &.{"dracut"} }},
        .repositories = lockTestRepositories(),
        .lock = .{ .exact = &.{
            .{ .name = "dracut", .evr = "0:059-1.azl3", .architecture = "x86_64" },
            .{ .name = "kpartx", .evr = "0:0.9.5-2.azl3", .architecture = "x86_64" },
        } },
    };
    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    for (diagnostics.items) |diagnostic| {
        try std.testing.expect(diagnostic.code != .invalid_policy);
    }

    // A removal is the one action a lock has nothing to say about: it names
    // what must not be installed, and a lock names versions for what is.
    request.packages.actions = &.{.{ .remove = &.{"obsolete"} }};
    var removal_diagnostics = try validate(std.testing.allocator, &request);
    defer removal_diagnostics.deinit(std.testing.allocator);
    for (removal_diagnostics.items) |diagnostic| {
        try std.testing.expect(diagnostic.code != .invalid_policy);
    }
}

test "an installed-package record splits back into the lock that would state it" {
    const parsed = parseInstalledPackageRecord("dracut-0:059-1.azl3.x86_64").?;
    try std.testing.expectEqualStrings("dracut", parsed.name);
    try std.testing.expectEqualStrings("0:059-1.azl3", parsed.evr);
    try std.testing.expectEqualStrings("x86_64", parsed.architecture);

    // The case that defeats splitting on the first `-`.
    const hyphenated = parseInstalledPackageRecord("python3-libs-0:3.12.9-1.azl3.aarch64").?;
    try std.testing.expectEqualStrings("python3-libs", hyphenated.name);
    try std.testing.expectEqualStrings("0:3.12.9-1.azl3", hyphenated.evr);
    try std.testing.expectEqualStrings("aarch64", hyphenated.architecture);

    // A name ending in a digit, where the character before the epoch's `-` is
    // indistinguishable from part of a version.
    const digits = parseInstalledPackageRecord("libstdc++6-0:13.2.0-3.noarch").?;
    try std.testing.expectEqualStrings("libstdc++6", digits.name);
    try std.testing.expectEqualStrings("0:13.2.0-3", digits.evr);
    try std.testing.expectEqualStrings("noarch", digits.architecture);

    // What a lock is built from has to round-trip, or the emitted lock names
    // something other than what was installed.
    for ([_][]const u8{
        "dracut-0:059-1.azl3.x86_64",
        "python3-libs-0:3.12.9-1.azl3.aarch64",
        "libstdc++6-0:13.2.0-3.noarch",
    }) |record| {
        const pin = parseInstalledPackageRecord(record).?;
        const rebuilt = try std.fmt.allocPrint(
            std.testing.allocator,
            "{s}-{s}.{s}",
            .{ pin.name, pin.evr, pin.architecture },
        );
        defer std.testing.allocator.free(rebuilt);
        try std.testing.expectEqualStrings(record, rebuilt);
    }

    // Not records rpm writes, and each one is a different way of not being.
    try std.testing.expect(parseInstalledPackageRecord("dracut") == null);
    try std.testing.expect(parseInstalledPackageRecord("dracut-059-1.x86_64") == null);
    try std.testing.expect(parseInstalledPackageRecord("-0:1-1.x86_64") == null);
    try std.testing.expect(parseInstalledPackageRecord("dracut-0:059-1.azl3.") == null);
}

test "a multilib lock pins one name at two architectures" {
    // The case that makes a name-only pin lookup wrong: `glibc` at both
    // architectures is two packages a root holds at once, so both are legal
    // in one lock and an executor must ask for both rather than for whichever
    // it found first.
    var request = whenNeededRequest();
    request.packages = .{
        .actions = &.{.{ .install = &.{"glibc"} }},
        .repositories = lockTestRepositories(),
        .lock = .{ .exact = &.{
            .{ .name = "glibc", .evr = "0:2.38-6.azl3", .architecture = "i686" },
            .{ .name = "glibc", .evr = "0:2.38-6.azl3", .architecture = "x86_64" },
        } },
    };
    var diagnostics = try validate(std.testing.allocator, &request);
    defer diagnostics.deinit(std.testing.allocator);
    for (diagnostics.items) |diagnostic| {
        try std.testing.expect(diagnostic.code != .invalid_policy);
    }
}
