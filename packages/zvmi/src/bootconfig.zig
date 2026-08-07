//! Bootloader population helpers: discover prebuilt EFI and BIOS GRUB assets
//! in a merged source tree, copy/install them into their target on-disk
//! locations, and generate minimal GRUB + Boot Loader Specification text
//! configuration without invoking any external bootloader tooling.
//!
//! To keep future image-build orchestration consistent with `zvmi.ext4`, this
//! module reuses the exact same vtable-style source-tree interface:
//! `bootconfig.SourceTreeView == ext4.FileTreeView`.

const std = @import("std");
const Io = std.Io;
const ext4 = @import("ext4.zig");
const fat32 = @import("fat32.zig");
const guid = @import("guid.zig");
const layout = @import("layout.zig");
const Image = @import("image.zig").Image;
const mbr = @import("mbr.zig");
const gpt = @import("gpt.zig");
const uki = @import("uki.zig");
const uki_signing = @import("uki_signing.zig");
const verity = @import("verity.zig");

pub const SourceTreeView = ext4.FileTreeView;
pub const SourceKind = ext4.Kind;

pub const Architecture = enum {
    x86_64,
    aarch64,

    fn defaultBootPath(self: Architecture) []const u8 {
        return switch (self) {
            .x86_64 => "EFI/BOOT/BOOTX64.EFI",
            .aarch64 => "EFI/BOOT/BOOTAA64.EFI",
        };
    }
};

pub const PlannedPartitionIdentity = struct {
    planned: layout.PlannedPartition,
    unique_guid: guid.Guid,
    /// Optional DOS/MBR disk signature used to synthesize Linux PARTUUID text
    /// (`<8-hex-signature>-<2-hex-partition-number>`) for BIOS/MBR builds.
    mbr_disk_signature: ?u32 = null,
};

pub const BootMode = enum {
    bls_only,
    uki_only,
    bls_and_uki,

    fn includesBls(self: BootMode) bool {
        return self != .uki_only;
    }

    fn includesUki(self: BootMode) bool {
        return self != .bls_only;
    }
};

pub const UkiOptions = struct {
    /// Optional source-tree override for the PE/EFI stub. When omitted,
    /// `populateEsp()` discovers common `systemd-stub` filenames.
    stub_source_path: ?[]const u8 = null,
    /// Optional source-tree override for the os-release payload. When omitted,
    /// `populateEsp()` prefers `usr/lib/os-release` then `etc/os-release`,
    /// falling back to a synthesized minimal payload if neither exists.
    os_release_source_path: ?[]const u8 = null,
    /// Optional source-tree path for a splash image embedded into `.splash`.
    splash_source_path: ?[]const u8 = null,
    /// Directory inside the ESP that receives generated named UKIs.
    output_directory: []const u8 = "EFI/Linux",
};

pub const PopulateStage = enum {
    prepare,
    bootloader,
    uki,
    /// Reached once, before the first generated UKI is handed to the signer.
    /// A run without `uki_signer` never reaches it.
    sign_uki,
};

pub const PopulateStageSink = struct {
    context: ?*anyopaque = null,
    advanceFn: *const fn (context: ?*anyopaque, stage: PopulateStage) bool,

    fn advance(self: PopulateStageSink, stage: PopulateStage) bool {
        return self.advanceFn(self.context, stage);
    }
};

pub const PopulateOptions = struct {
    /// The planned partitions plus the on-disk identifiers used to reference
    /// them from generated kernel command lines.
    planned_partitions: []const PlannedPartitionIdentity,
    /// Optional explicit CPU architecture. If omitted, the module infers it
    /// from EFI binary names and/or the planned root-partition role.
    architecture: ?Architecture = null,
    /// Optional override when the root partition is not the DPS root role for
    /// the detected architecture.
    root_role: ?layout.PartitionRole = null,
    /// Optional override for the partition that will contain the kernel and
    /// initrd paths referenced from the generated GRUB config. Defaults to the
    /// resolved root partition.
    kernel_device_partuuid: ?guid.Guid = null,
    /// The root ext4 filesystem's own UUID (its superblock `s_uuid`, plain
    /// big-endian/RFC4122 byte order -- NOT the mixed-endian `guid.Guid`
    /// convention used elsewhere in this repo for GPT GUIDs). When supplied,
    /// the generated `grub.cfg`'s `search` command uses
    /// `--fs-uuid <this UUID>` to locate `$kernel_root`, which is the only
    /// search-type GRUB's `search` command actually supports for this
    /// purpose (confirmed via real QEMU + OVMF boot testing against the real
    /// Azure Linux 4.0 ISO, see issue #72 -- GRUB's `search` command does
    /// NOT have a `--partuuid` flag; that flag silently fails with
    /// "unspecified search type", leaving `$kernel_root` unset and every
    /// menu entry failing with "you need to load the kernel first"). Callers
    /// that actually want a bootable image MUST supply this, matching
    /// whatever UUID was written into the root partition's ext4 superblock
    /// (see `ext4.PopulateOptions.uuid`). If omitted, `grub.cfg` falls back
    /// to the old (non-functional on real hardware/QEMU) `--partuuid`
    /// search for backward compatibility with structural-only tests.
    root_filesystem_uuid: ?[16]u8 = null,
    /// Optional leading path prefix to strip when emitting `linux`/`initrd`
    /// paths. For example, stripping `boot/` turns `boot/vmlinuz-*` into
    /// `/vmlinuz-*` for callers that materialize `/boot` into a separate
    /// XBOOTLDR partition.
    path_strip_prefix: []const u8 = "",
    /// Optional human-friendly prefix for generated menu/BLS titles.
    title_prefix: []const u8 = "",
    /// Extra kernel command-line arguments appended after
    /// `root=PARTUUID=<...>`.
    extra_kernel_options: []const u8 = "",
    /// Optional dm-verity metadata used to switch the generated kernel
    /// command line to `root=/dev/mapper/root` plus the matching
    /// `roothash=`/`systemd.verity_root_*` arguments.
    verity: ?verity.Info = null,
    /// Select whether `populateEsp()` emits the existing shim/GRUB/BLS chain,
    /// generated UKIs, or both.
    boot_mode: BootMode = .bls_only,
    /// UKI-specific discovery/output controls used when `boot_mode` includes
    /// `.uki_only` or `.bls_and_uki`.
    uki: UkiOptions = .{},
    grub_timeout_seconds: u32 = 1,
    stage_sink: ?PopulateStageSink = null,
    /// Optional Authenticode signing step applied to every generated UKI
    /// before it reaches the ESP.
    ///
    /// Injected as a function rather than a concrete signer so this module
    /// keeps building PE images without gaining the ability to run host
    /// commands, and so the wiring is provable without a signing service.
    /// Signing here rather than over a finished image is what lets the ESP
    /// capacity check, the reported sizes, and the published digests all
    /// describe the bytes that actually boot.
    uki_signer: ?uki_signing.Signer = null,
};

pub const PopulateReport = struct {
    architecture: Architecture,
    copied_efi_file_count: usize,
    copied_secure_boot_file_count: usize,
    bls_entry_count: usize,
    uki_count: usize,
    default_bootloader_path: []const u8,
    esp_partuuid: guid.Guid,
    root_partuuid: guid.Guid,
    kernel_device_partuuid: guid.Guid,
    /// The kernel command line this call wrote into every entry it generated,
    /// verbatim.
    ///
    /// Reported rather than left to be reconstructed, because it is composed
    /// here from three things the caller holds separately -- the root
    /// PARTUUID text, the verity superblock, and the caller's own appended
    /// options -- by a rule that lives in this file. A caller that rebuilt it
    /// from those parts would be a second implementation of that rule, free
    /// to drift from the one that produced the bytes on the disk. This is the
    /// string that was written.
    ///
    /// Owned by the report; release it with `deinit`.
    kernel_command_line: []u8,

    pub fn deinit(self: *PopulateReport, allocator: std.mem.Allocator) void {
        allocator.free(self.kernel_command_line);
        self.* = undefined;
    }
};

pub const PopulateError = std.mem.Allocator.Error || fat32.MutationError ||
    SourceTreeView.IteratorError || SourceTreeView.ContentError || uki.GenerateError ||
    uki_signing.Error || error{
    AmbiguousArchitecture,
    AmbiguousRootPartition,
    FileTooLarge,
    MissingBootloader,
    MissingContentReader,
    MissingEspPartition,
    MissingKernel,
    MissingRootPartition,
    MissingUkiStub,
    UnexpectedSourceLength,
    InvalidOperationOrder,
};

pub const InstallBiosOptions = struct {
    planned_partitions: []const PlannedPartitionIdentity,
    architecture: ?Architecture = null,
    root_role: ?layout.PartitionRole = null,
    /// Optional dm-verity metadata preserved alongside BIOS installation
    /// options so BIOS/MBR callers can share the same root-cmdline inputs as
    /// GPT/UEFI callers.
    verity: ?verity.Info = null,
};

pub const InstallBiosError = PopulateError || Image.PreadError || Image.PwriteError || error{
    BiosEmbedAreaTooSmall,
    InvalidBiosBootImgSize,
    InvalidBiosCoreImgSize,
    MissingBiosBootImg,
    MissingBiosCoreImg,
    UnsupportedBiosArchitecture,
};

const grub_bios_boot_img_kernel_sector_offset: usize = 0x5C;
const grub_bios_boot_img_preserve_offset: usize = 0x1B8;
const grub_bios_core_blocklist_offset: usize = mbr.sector_size - 12;
const grub_bios_kernel_segment: u16 = 0x800;
const grub_bios_second_sector_segment: u16 = grub_bios_kernel_segment + 0x20;
const max_partuuid_text_len: usize = 36;

const EfiBinaryKind = enum {
    default_boot,
    shim,
    grub,
    mok_manager,
};

const EfiBinary = struct {
    destination_path: []u8,
    architecture: Architecture,
    kind: EfiBinaryKind,
    size: u64,
    content: SourceTreeView.ContentReader,
};

const CopyableFile = struct {
    destination_path: []u8,
    size: u64,
    content: SourceTreeView.ContentReader,
};

const BootArtifactCandidate = struct {
    source_path: []u8,
    config_path: []u8,
    size: u64,
    content: SourceTreeView.ContentReader,
};

const SourceAsset = struct {
    source_path: []u8,
    size: u64,
    content: SourceTreeView.ContentReader,
};

const UkiAssets = struct {
    stub: SourceAsset,
    os_release: ?SourceAsset,
    splash: ?SourceAsset,

    fn deinit(self: *UkiAssets, allocator: std.mem.Allocator) void {
        allocator.free(self.stub.source_path);
        if (self.os_release) |*asset| allocator.free(asset.source_path);
        if (self.splash) |*asset| allocator.free(asset.source_path);
        self.* = undefined;
    }
};

const ScanResult = struct {
    efi_binaries: []EfiBinary,
    secure_boot_files: []CopyableFile,
    kernels: []BootArtifactCandidate,
    initrds: []BootArtifactCandidate,

    fn deinit(self: *ScanResult, allocator: std.mem.Allocator) void {
        for (self.efi_binaries) |binary| allocator.free(binary.destination_path);
        allocator.free(self.efi_binaries);
        for (self.secure_boot_files) |file| allocator.free(file.destination_path);
        allocator.free(self.secure_boot_files);
        freeCandidates(allocator, self.kernels);
        freeCandidates(allocator, self.initrds);
        self.* = undefined;
    }
};

const CopyPlanEntry = struct {
    destination_path: []u8,
    size: u64,
    content: SourceTreeView.ContentReader,
};

const BootEntry = struct {
    id: []u8,
    title: []u8,
    kernel: BootArtifactCandidate,
    initrd: ?BootArtifactCandidate,
};

const GrubPartitionModule = enum {
    gpt,
    msdos,

    fn name(self: GrubPartitionModule) []const u8 {
        return switch (self) {
            .gpt => "part_gpt",
            .msdos => "part_msdos",
        };
    }
};

const BootPlanOptions = struct {
    planned_partitions: []const PlannedPartitionIdentity,
    architecture: ?Architecture = null,
    root_role: ?layout.PartitionRole = null,
    kernel_device_partuuid: ?guid.Guid = null,
    root_filesystem_uuid: ?[16]u8 = null,
    path_strip_prefix: []const u8 = "",
    title_prefix: []const u8 = "",
};

const BootPlan = struct {
    scan: ScanResult,
    architecture: Architecture,
    root_partition: PlannedPartitionIdentity,
    kernel_device_partuuid: guid.Guid,
    root_partuuid_buf: [max_partuuid_text_len]u8 = undefined,
    root_partuuid_len: usize = 0,
    kernel_device_partuuid_buf: [max_partuuid_text_len]u8 = undefined,
    kernel_device_partuuid_len: usize = 0,
    root_filesystem_uuid_buf: [36]u8 = undefined,
    root_filesystem_uuid_len: ?usize = null,
    boot_entries: []BootEntry,

    fn deinit(self: *BootPlan, allocator: std.mem.Allocator) void {
        freeBootEntries(allocator, self.boot_entries);
        self.scan.deinit(allocator);
        self.* = undefined;
    }

    fn rootPartuuidText(self: *const BootPlan) []const u8 {
        return self.root_partuuid_buf[0..self.root_partuuid_len];
    }

    fn kernelDevicePartuuidText(self: *const BootPlan) []const u8 {
        return self.kernel_device_partuuid_buf[0..self.kernel_device_partuuid_len];
    }

    fn rootFilesystemUuidText(self: *const BootPlan) ?[]const u8 {
        const len = self.root_filesystem_uuid_len orelse return null;
        return self.root_filesystem_uuid_buf[0..len];
    }
};

pub const GeneratedConfigFile = struct {
    path: []u8,
    bytes: []u8,
    /// The kernel command line embedded in `bytes`, verbatim. Reported for
    /// the same reason as `PopulateReport.kernel_command_line`: the rule that
    /// composes it lives here, so this file states the result rather than
    /// inviting a caller to derive it a second time.
    kernel_command_line: []u8,

    pub fn deinit(self: *GeneratedConfigFile, allocator: std.mem.Allocator) void {
        allocator.free(self.path);
        allocator.free(self.bytes);
        allocator.free(self.kernel_command_line);
        self.* = undefined;
    }
};

pub const GenerateBiosGrubCfgOptions = struct {
    planned_partitions: []const PlannedPartitionIdentity,
    architecture: ?Architecture = null,
    root_role: ?layout.PartitionRole = null,
    kernel_device_partuuid: ?guid.Guid = null,
    root_filesystem_uuid: ?[16]u8 = null,
    path_strip_prefix: []const u8 = "",
    title_prefix: []const u8 = "",
    extra_kernel_options: []const u8 = "",
    verity: ?verity.Info = null,
    grub_timeout_seconds: u32 = 1,
};

fn freeCandidates(allocator: std.mem.Allocator, entries: []BootArtifactCandidate) void {
    for (entries) |entry| {
        allocator.free(entry.source_path);
        allocator.free(entry.config_path);
    }
    allocator.free(entries);
}

fn freeBootEntries(allocator: std.mem.Allocator, entries: []BootEntry) void {
    for (entries) |entry| {
        allocator.free(entry.id);
        allocator.free(entry.title);
    }
    allocator.free(entries);
}

fn freeCopyPlan(allocator: std.mem.Allocator, entries: []CopyPlanEntry) void {
    for (entries) |entry| allocator.free(entry.destination_path);
    allocator.free(entries);
}

/// Discovers EFI binaries + kernel/initrd paths in `source`, copies the EFI
/// binaries into `esp`, and generates `EFI/.../grub.cfg`,
/// `loader/loader.conf`, `loader/entries/*.conf`, and/or `EFI/Linux/*.efi`
/// UKIs depending on `options.boot_mode`.
pub fn populateEsp(
    allocator: std.mem.Allocator,
    io: Io,
    esp: *fat32.FileSystem,
    source: *SourceTreeView,
    options: PopulateOptions,
) PopulateError!PopulateReport {
    if (options.stage_sink) |sink| {
        if (!sink.advance(.prepare)) return error.InvalidOperationOrder;
    }
    var plan = try buildBootPlan(allocator, source, .{
        .planned_partitions = options.planned_partitions,
        .architecture = options.architecture,
        .root_role = options.root_role,
        .kernel_device_partuuid = options.kernel_device_partuuid,
        .root_filesystem_uuid = options.root_filesystem_uuid,
        .path_strip_prefix = options.path_strip_prefix,
        .title_prefix = options.title_prefix,
    });
    defer plan.deinit(allocator);

    if (options.boot_mode.includesBls() and plan.scan.efi_binaries.len == 0) return error.MissingBootloader;

    const esp_partuuid = findPartitionGuidByRole(options.planned_partitions, .esp) orelse return error.MissingEspPartition;
    const root_partuuid = plan.root_partition.unique_guid;

    const copy_plan = try buildCopyPlan(allocator, plan.scan.efi_binaries, plan.architecture, options.boot_mode);
    defer freeCopyPlan(allocator, copy_plan);
    const secure_boot_plan = try buildSecureBootCopyPlan(allocator, plan.scan.secure_boot_files, copy_plan, plan.architecture, options.boot_mode);
    defer freeCopyPlan(allocator, secure_boot_plan);

    // Composed once, here, and then handed to every renderer below. GRUB
    // entries, BLS entries and UKIs all boot the same root filesystem, so a
    // run that gave them different command lines would be publishing an image
    // whose behaviour depended on which entry the firmware picked.
    const kernel_command_line = try renderKernelOptions(
        allocator,
        plan.rootPartuuidText(),
        options.extra_kernel_options,
        options.verity,
    );
    errdefer allocator.free(kernel_command_line);

    if (options.stage_sink) |sink| {
        if (!sink.advance(.bootloader)) return error.InvalidOperationOrder;
    }
    for (copy_plan) |entry| try copyIntoFat32(allocator, io, esp, entry);
    for (secure_boot_plan) |entry| try copyIntoFat32(allocator, io, esp, entry);

    if (options.boot_mode.includesBls()) {
        const loader_conf = try renderLoaderConf(allocator, plan.boot_entries, options.grub_timeout_seconds);
        defer allocator.free(loader_conf);
        try writeGeneratedFile(io, esp, "loader/loader.conf", loader_conf);

        const grub_cfg = try renderGrubCfg(
            allocator,
            plan.boot_entries,
            plan.kernelDevicePartuuidText(),
            plan.rootFilesystemUuidText(),
            kernel_command_line,
            .gpt,
            options.grub_timeout_seconds,
        );
        defer allocator.free(grub_cfg);

        try writeGeneratedFile(io, esp, "EFI/BOOT/grub.cfg", grub_cfg);

        var vendor_cfg_paths = try collectVendorGrubCfgPaths(allocator, copy_plan);
        defer {
            for (vendor_cfg_paths.items) |path| allocator.free(path);
            vendor_cfg_paths.deinit();
        }
        for (vendor_cfg_paths.items) |path| try writeGeneratedFile(io, esp, path, grub_cfg);

        for (plan.boot_entries) |entry| {
            const bls_text = try renderBlsEntry(allocator, entry, kernel_command_line);
            defer allocator.free(bls_text);
            const bls_path = try std.fmt.allocPrint(allocator, "loader/entries/{s}.conf", .{entry.id});
            defer allocator.free(bls_path);
            try writeGeneratedFile(io, esp, bls_path, bls_text);
        }
    }

    const uki_count = if (options.boot_mode.includesUki()) blk: {
        if (options.stage_sink) |sink| {
            if (!sink.advance(.uki)) return error.InvalidOperationOrder;
        }
        break :blk try generateUkis(allocator, io, esp, source, plan.architecture, plan.boot_entries, kernel_command_line, options);
    } else 0;

    return .{
        .architecture = plan.architecture,
        .copied_efi_file_count = copy_plan.len,
        .copied_secure_boot_file_count = secure_boot_plan.len,
        .bls_entry_count = if (options.boot_mode.includesBls()) plan.boot_entries.len else 0,
        .uki_count = uki_count,
        .default_bootloader_path = plan.architecture.defaultBootPath(),
        .esp_partuuid = esp_partuuid,
        .root_partuuid = root_partuuid,
        .kernel_device_partuuid = plan.kernel_device_partuuid,
        .kernel_command_line = kernel_command_line,
    };
}

/// Installs a BIOS/MBR GRUB chain by embedding `core.img` into the classic
/// post-MBR gap (sector 1 up to the first partition) and overlaying GRUB's
/// stage-1 `boot.img` onto the existing MBR while preserving the disk
/// signature, partition table, and boot signature already written there.
pub fn installBiosBoot(
    allocator: std.mem.Allocator,
    io: Io,
    img: *Image,
    source: *SourceTreeView,
    options: InstallBiosOptions,
) InstallBiosError!void {
    const architecture = options.architecture orelse try resolveArchitectureFromPlannedPartitions(options.planned_partitions, options.root_role);
    if (architecture != .x86_64) return error.UnsupportedBiosArchitecture;

    const root_partition = try resolveRootPartition(options.planned_partitions, architecture, options.root_role);
    const embed_start_lba: u64 = 1;
    const available_embed_sectors = root_partition.planned.firstLba() -| embed_start_lba;
    if (available_embed_sectors == 0) return error.BiosEmbedAreaTooSmall;

    var assets = try discoverBiosGrubAssets(allocator, source);
    defer assets.deinit(allocator);

    const boot_img_bytes = try readSourceFileAlloc(allocator, assets.boot_img.content, assets.boot_img.size);
    defer allocator.free(boot_img_bytes);
    if (boot_img_bytes.len != mbr.sector_size) return error.InvalidBiosBootImgSize;

    const core_img_bytes = try readSourceFileAlloc(allocator, assets.core_img.content, assets.core_img.size);
    defer allocator.free(core_img_bytes);
    if (core_img_bytes.len < mbr.sector_size) return error.InvalidBiosCoreImgSize;

    const core_sector_count = std.math.divCeil(u64, core_img_bytes.len, mbr.sector_size) catch unreachable;
    if (core_sector_count > available_embed_sectors) return error.BiosEmbedAreaTooSmall;
    const remaining_sector_count = core_sector_count - 1;
    if (remaining_sector_count > std.math.maxInt(u16)) return error.BiosEmbedAreaTooSmall;

    var mbr_sector: [mbr.sector_size]u8 = undefined;
    _ = try img.pread(io, &mbr_sector, 0);
    std.mem.copyForwards(u8, mbr_sector[0..grub_bios_boot_img_preserve_offset], boot_img_bytes[0..grub_bios_boot_img_preserve_offset]);
    std.mem.writeInt(u64, mbr_sector[grub_bios_boot_img_kernel_sector_offset..][0..8], embed_start_lba, .little);
    try img.pwrite(io, &mbr_sector, 0);

    const padded_core_len = std.math.cast(usize, core_sector_count * mbr.sector_size) orelse return error.FileTooLarge;
    const padded_core_img = try allocator.alloc(u8, padded_core_len);
    defer allocator.free(padded_core_img);
    @memset(padded_core_img, 0);
    std.mem.copyForwards(u8, padded_core_img[0..core_img_bytes.len], core_img_bytes);

    if (remaining_sector_count == 0) {
        @memset(padded_core_img[grub_bios_core_blocklist_offset..][0..12], 0);
    } else {
        std.mem.writeInt(u64, padded_core_img[grub_bios_core_blocklist_offset..][0..8], embed_start_lba + 1, .little);
        std.mem.writeInt(u16, padded_core_img[grub_bios_core_blocklist_offset + 8 ..][0..2], @intCast(remaining_sector_count), .little);
        std.mem.writeInt(u16, padded_core_img[grub_bios_core_blocklist_offset + 10 ..][0..2], grub_bios_second_sector_segment, .little);
    }

    try img.pwrite(io, padded_core_img, embed_start_lba * mbr.sector_size);
}

pub fn generateBiosGrubCfg(
    allocator: std.mem.Allocator,
    source: *SourceTreeView,
    options: GenerateBiosGrubCfgOptions,
) InstallBiosError!GeneratedConfigFile {
    const architecture = options.architecture orelse try resolveArchitectureFromPlannedPartitions(options.planned_partitions, options.root_role);
    if (architecture != .x86_64) return error.UnsupportedBiosArchitecture;

    var assets = try discoverBiosGrubAssets(allocator, source);
    defer assets.deinit(allocator);
    const config_path = (try existingBiosGrubConfigPath(source)) orelse
        biosGrubConfigPathForAssetPath(assets.core_img.source_path);

    var plan = try buildBootPlan(allocator, source, .{
        .planned_partitions = options.planned_partitions,
        .architecture = architecture,
        .root_role = options.root_role,
        .kernel_device_partuuid = options.kernel_device_partuuid,
        .root_filesystem_uuid = options.root_filesystem_uuid,
        .path_strip_prefix = options.path_strip_prefix,
        .title_prefix = options.title_prefix,
    });
    defer plan.deinit(allocator);

    const kernel_command_line = try renderKernelOptions(
        allocator,
        plan.rootPartuuidText(),
        options.extra_kernel_options,
        options.verity,
    );
    errdefer allocator.free(kernel_command_line);

    const path = try allocator.dupe(u8, config_path);
    errdefer allocator.free(path);

    return .{
        .path = path,
        .bytes = try renderGrubCfg(
            allocator,
            plan.boot_entries,
            plan.kernelDevicePartuuidText(),
            plan.rootFilesystemUuidText(),
            kernel_command_line,
            .msdos,
            options.grub_timeout_seconds,
        ),
        .kernel_command_line = kernel_command_line,
    };
}

fn scanSourceTree(
    allocator: std.mem.Allocator,
    source: *SourceTreeView,
    strip_prefix: []const u8,
) PopulateError!ScanResult {
    var efi_binaries = std.array_list.Managed(EfiBinary).init(allocator);
    errdefer {
        for (efi_binaries.items) |entry| allocator.free(entry.destination_path);
        efi_binaries.deinit();
    }

    var secure_boot_files = std.array_list.Managed(CopyableFile).init(allocator);
    errdefer {
        for (secure_boot_files.items) |entry| allocator.free(entry.destination_path);
        secure_boot_files.deinit();
    }

    var kernels = std.array_list.Managed(BootArtifactCandidate).init(allocator);
    errdefer {
        freeCandidates(allocator, kernels.items);
        kernels.deinit();
    }

    var initrds = std.array_list.Managed(BootArtifactCandidate).init(allocator);
    errdefer {
        freeCandidates(allocator, initrds.items);
        initrds.deinit();
    }

    source.reset();
    while (try source.next()) |entry| {
        if (entry.kind == .file) {
            if (entry.content) |content| {
                if (try classifyEfiBinary(allocator, entry.path)) |efi_binary| {
                    try efi_binaries.append(.{
                        .destination_path = efi_binary.destination_path,
                        .architecture = efi_binary.architecture,
                        .kind = efi_binary.kind,
                        .size = entry.size,
                        .content = content,
                    });
                } else if (try classifySecureBootFile(allocator, entry.path)) |destination_path| {
                    try secure_boot_files.append(.{
                        .destination_path = destination_path,
                        .size = entry.size,
                        .content = content,
                    });
                }
            }
        }

        if (entry.kind == .directory) continue;
        if (isKernelPath(entry.path)) {
            try kernels.append(.{
                .source_path = try allocator.dupe(u8, entry.path),
                .config_path = try makeConfigPath(allocator, entry.path, strip_prefix),
                .size = entry.size,
                .content = entry.content orelse return error.MissingContentReader,
            });
        } else if (isInitrdPath(entry.path)) {
            try initrds.append(.{
                .source_path = try allocator.dupe(u8, entry.path),
                .config_path = try makeConfigPath(allocator, entry.path, strip_prefix),
                .size = entry.size,
                .content = entry.content orelse return error.MissingContentReader,
            });
        }
    }

    return .{
        .efi_binaries = try efi_binaries.toOwnedSlice(),
        .secure_boot_files = try secure_boot_files.toOwnedSlice(),
        .kernels = try kernels.toOwnedSlice(),
        .initrds = try initrds.toOwnedSlice(),
    };
}

fn buildBootPlan(
    allocator: std.mem.Allocator,
    source: *SourceTreeView,
    options: BootPlanOptions,
) PopulateError!BootPlan {
    var scan = try scanSourceTree(allocator, source, options.path_strip_prefix);
    errdefer scan.deinit(allocator);

    if (scan.kernels.len == 0) return error.MissingKernel;

    sortKernelCandidates(scan.kernels);
    sortKernelCandidates(scan.initrds);

    const architecture = try resolveArchitecture(scan.efi_binaries, options);
    const root_partition = try resolveRootPartition(options.planned_partitions, architecture, options.root_role);
    const kernel_device_partuuid = options.kernel_device_partuuid orelse root_partition.unique_guid;
    const boot_entries = try buildBootEntries(allocator, scan.kernels, scan.initrds, options.title_prefix);
    errdefer freeBootEntries(allocator, boot_entries);

    var plan = BootPlan{
        .scan = scan,
        .architecture = architecture,
        .root_partition = root_partition,
        .kernel_device_partuuid = kernel_device_partuuid,
        .boot_entries = boot_entries,
    };

    const root_partuuid_text = formatPlannedPartitionPartuuid(&plan.root_partuuid_buf, options.planned_partitions, root_partition);
    plan.root_partuuid_len = root_partuuid_text.len;

    if (options.kernel_device_partuuid) |partuuid| {
        const kernel_device_partuuid_text = guid.formatLower(&plan.kernel_device_partuuid_buf, partuuid);
        plan.kernel_device_partuuid_len = kernel_device_partuuid_text.len;
    } else {
        @memcpy(plan.kernel_device_partuuid_buf[0..root_partuuid_text.len], root_partuuid_text);
        plan.kernel_device_partuuid_len = root_partuuid_text.len;
    }

    if (options.root_filesystem_uuid) |fs_uuid| {
        const root_filesystem_uuid_text = formatPlainUuidBytes(&plan.root_filesystem_uuid_buf, &fs_uuid);
        plan.root_filesystem_uuid_len = root_filesystem_uuid_text.len;
    }

    return plan;
}

fn classifyEfiBinary(
    allocator: std.mem.Allocator,
    path: []const u8,
) std.mem.Allocator.Error!?struct {
    destination_path: []u8,
    architecture: Architecture,
    kind: EfiBinaryKind,
} {
    const basename = baseName(path);
    const classification: ?struct { architecture: Architecture, kind: EfiBinaryKind } = if (std.ascii.eqlIgnoreCase(basename, "BOOTX64.EFI"))
        .{ .architecture = Architecture.x86_64, .kind = EfiBinaryKind.default_boot }
    else if (std.ascii.eqlIgnoreCase(basename, "shimx64.efi"))
        .{ .architecture = Architecture.x86_64, .kind = EfiBinaryKind.shim }
    else if (std.ascii.eqlIgnoreCase(basename, "grubx64.efi"))
        .{ .architecture = Architecture.x86_64, .kind = EfiBinaryKind.grub }
    else if (std.ascii.eqlIgnoreCase(basename, "mmx64.efi"))
        .{ .architecture = Architecture.x86_64, .kind = EfiBinaryKind.mok_manager }
    else if (std.ascii.eqlIgnoreCase(basename, "BOOTAA64.EFI"))
        .{ .architecture = Architecture.aarch64, .kind = EfiBinaryKind.default_boot }
    else if (std.ascii.eqlIgnoreCase(basename, "shimaa64.efi"))
        .{ .architecture = Architecture.aarch64, .kind = EfiBinaryKind.shim }
    else if (std.ascii.eqlIgnoreCase(basename, "grubaa64.efi"))
        .{ .architecture = Architecture.aarch64, .kind = EfiBinaryKind.grub }
    else if (std.ascii.eqlIgnoreCase(basename, "mmaa64.efi"))
        .{ .architecture = Architecture.aarch64, .kind = EfiBinaryKind.mok_manager }
    else
        null;
    if (classification == null) return null;

    const dest_path = try efiDestinationPath(allocator, path) orelse return null;
    return .{
        .destination_path = dest_path,
        .architecture = classification.?.architecture,
        .kind = classification.?.kind,
    };
}

fn classifySecureBootFile(allocator: std.mem.Allocator, path: []const u8) std.mem.Allocator.Error!?[]u8 {
    const destination_path = try efiDestinationPath(allocator, path) orelse return null;
    errdefer allocator.free(destination_path);

    const basename = baseName(path);
    if (isSecureBootAuxiliaryEfi(basename) or isSecureBootConfigFile(basename)) {
        return destination_path;
    }

    allocator.free(destination_path);
    return null;
}

fn isSecureBootAuxiliaryEfi(basename: []const u8) bool {
    return std.ascii.eqlIgnoreCase(basename, "MokManager.efi") or
        std.ascii.eqlIgnoreCase(basename, "MokManagerX64.efi") or
        std.ascii.eqlIgnoreCase(basename, "MokManagerAA64.efi") or
        std.ascii.eqlIgnoreCase(basename, "fbx64.efi") or
        std.ascii.eqlIgnoreCase(basename, "fbaa64.efi") or
        std.ascii.eqlIgnoreCase(basename, "fallback.efi");
}

fn isSecureBootConfigFile(basename: []const u8) bool {
    return endsWithIgnoreCase(basename, ".csv") or
        endsWithIgnoreCase(basename, ".cer") or
        endsWithIgnoreCase(basename, ".crt") or
        endsWithIgnoreCase(basename, ".der") or
        endsWithIgnoreCase(basename, ".esl") or
        endsWithIgnoreCase(basename, ".auth") or
        endsWithIgnoreCase(basename, ".conf");
}

fn efiDestinationPath(allocator: std.mem.Allocator, path: []const u8) std.mem.Allocator.Error!?[]u8 {
    var start: usize = 0;
    while (start < path.len) {
        const end = std.mem.indexOfScalarPos(u8, path, start, '/') orelse path.len;
        if (std.ascii.eqlIgnoreCase(path[start..end], "EFI")) {
            if (end == path.len) return null;
            const out = try std.fmt.allocPrint(allocator, "EFI/{s}", .{path[end + 1 ..]});
            return out;
        }
        if (end == path.len) break;
        start = end + 1;
    }
    return null;
}

fn isKernelPath(path: []const u8) bool {
    if (!isBootScopedPath(path)) return false;
    if (isNonKernelBootPath(path)) return false;
    const basename = baseName(path);
    return std.ascii.startsWithIgnoreCase(basename, "vmlinuz") or
        std.ascii.eqlIgnoreCase(basename, "Image") or
        std.ascii.startsWithIgnoreCase(basename, "Image-") or
        std.ascii.eqlIgnoreCase(basename, "bzImage") or
        std.ascii.eqlIgnoreCase(basename, "zImage");
}

/// Directories that legitimately contain files whose names would otherwise
/// look like kernel/initrd candidates but are not the installed OS's own
/// boot payload:
///   - `boot/grub2/**` (and per-arch variants like `boot/grub2/i386-pc/`)
///     holds GRUB's OWN loadable modules, e.g. `linux.mod`, which implements
///     the `linux`/`initrd` commands for legacy BIOS GRUB -- it is not a
///     Linux kernel image and cannot be loaded by the `linux` command.
///   - `boot/<arch>/loader/**` (e.g. `boot/x86_64/loader/linux` +
///     `boot/x86_64/loader/initrd`) holds the distro installer's own
///     live/install-environment boot loader binary and initrd (Anaconda-style
///     "loader"), not the installed system's kernel.
/// Confirmed via real QEMU + OVMF boot testing against the real Azure Linux
/// 4.0 ISO (see issue #72): without this exclusion, `linux.mod` and
/// `boot/x86_64/loader/linux` were previously misidentified as kernel
/// candidates (matched by an overly broad `linux`-prefix heuristic) and one
/// of them was picked as the default boot entry instead of the real
/// `vmlinuz-*` kernel, causing GRUB to fail with
/// "you need to load the kernel first."
fn isNonKernelBootPath(path: []const u8) bool {
    return containsPathSegmentIgnoreCase(path, "grub2") or containsPathSegmentIgnoreCase(path, "loader");
}

fn containsPathSegmentIgnoreCase(path: []const u8, segment: []const u8) bool {
    var start: usize = 0;
    while (start <= path.len) {
        const end = std.mem.indexOfScalarPos(u8, path, start, '/') orelse path.len;
        if (std.ascii.eqlIgnoreCase(path[start..end], segment)) return true;
        if (end == path.len) break;
        start = end + 1;
    }
    return false;
}

fn isInitrdPath(path: []const u8) bool {
    if (!isBootScopedPath(path)) return false;
    if (isNonKernelBootPath(path)) return false;
    const basename = baseName(path);
    return std.ascii.startsWithIgnoreCase(basename, "initrd") or
        std.ascii.startsWithIgnoreCase(basename, "initramfs");
}

fn isBootScopedPath(path: []const u8) bool {
    if (std.mem.indexOfScalar(u8, path, '/')) |slash| {
        return std.ascii.eqlIgnoreCase(path[0..slash], "boot");
    }
    const basename = baseName(path);
    return std.ascii.startsWithIgnoreCase(basename, "vmlinuz") or
        std.ascii.eqlIgnoreCase(basename, "Image") or
        std.ascii.startsWithIgnoreCase(basename, "Image-") or
        std.ascii.eqlIgnoreCase(basename, "bzImage") or
        std.ascii.eqlIgnoreCase(basename, "zImage");
}

fn makeConfigPath(allocator: std.mem.Allocator, source_path: []const u8, strip_prefix: []const u8) std.mem.Allocator.Error![]u8 {
    const trimmed_prefix = trimSlashes(strip_prefix);
    var remainder = source_path;
    if (trimmed_prefix.len > 0) {
        if (std.ascii.eqlIgnoreCase(remainder, trimmed_prefix)) {
            remainder = "";
        } else if (remainder.len > trimmed_prefix.len and
            std.ascii.eqlIgnoreCase(remainder[0..trimmed_prefix.len], trimmed_prefix) and
            remainder[trimmed_prefix.len] == '/')
        {
            remainder = remainder[trimmed_prefix.len + 1 ..];
        }
    }
    return std.fmt.allocPrint(allocator, "/{s}", .{remainder});
}

fn trimSlashes(value: []const u8) []const u8 {
    var start: usize = 0;
    var end = value.len;
    while (start < end and value[start] == '/') : (start += 1) {}
    while (end > start and value[end - 1] == '/') : (end -= 1) {}
    return value[start..end];
}

fn sortKernelCandidates(entries: []BootArtifactCandidate) void {
    var i: usize = 1;
    while (i < entries.len) : (i += 1) {
        var j = i;
        while (j > 0 and std.mem.lessThan(u8, entries[j].source_path, entries[j - 1].source_path)) : (j -= 1) {
            std.mem.swap(BootArtifactCandidate, &entries[j], &entries[j - 1]);
        }
    }
}

fn resolveArchitecture(efi_binaries: []const EfiBinary, options: BootPlanOptions) PopulateError!Architecture {
    if (options.architecture) |architecture| return architecture;
    if (options.root_role) |role| {
        if (architectureForRole(role)) |architecture| return architecture;
    }

    var saw_x86 = false;
    var saw_arm = false;
    for (efi_binaries) |binary| switch (binary.architecture) {
        .x86_64 => saw_x86 = true,
        .aarch64 => saw_arm = true,
    };

    if (saw_x86 and !saw_arm) return .x86_64;
    if (saw_arm and !saw_x86) return .aarch64;

    var inferred_from_partitions: ?Architecture = null;
    for (options.planned_partitions) |partition| {
        const architecture = architectureForRole(partition.planned.role) orelse continue;
        if (inferred_from_partitions == null) {
            inferred_from_partitions = architecture;
        } else if (inferred_from_partitions.? != architecture) {
            inferred_from_partitions = null;
            break;
        }
    }
    if (inferred_from_partitions) |architecture| return architecture;

    return error.AmbiguousArchitecture;
}

fn resolveArchitectureFromPlannedPartitions(
    planned_partitions: []const PlannedPartitionIdentity,
    override_role: ?layout.PartitionRole,
) error{AmbiguousArchitecture}!Architecture {
    if (override_role) |role| {
        if (architectureForRole(role)) |architecture| return architecture;
    }

    var inferred: ?Architecture = null;
    for (planned_partitions) |partition| {
        const architecture = architectureForRole(partition.planned.role) orelse continue;
        if (inferred == null) {
            inferred = architecture;
        } else if (inferred.? != architecture) {
            return error.AmbiguousArchitecture;
        }
    }

    return inferred orelse error.AmbiguousArchitecture;
}

fn architectureForRole(role: layout.PartitionRole) ?Architecture {
    return switch (role) {
        .root_x86_64, .usr_x86_64 => .x86_64,
        .root_aarch64, .usr_aarch64 => .aarch64,
        else => null,
    };
}

fn defaultRootRoleForArchitecture(architecture: Architecture) layout.PartitionRole {
    return switch (architecture) {
        .x86_64 => .root_x86_64,
        .aarch64 => .root_aarch64,
    };
}

fn findPartitionGuidByRole(
    planned_partitions: []const PlannedPartitionIdentity,
    role: layout.PartitionRole,
) ?guid.Guid {
    for (planned_partitions) |partition| {
        if (partition.planned.role == role) return partition.unique_guid;
    }
    return null;
}

fn resolveRootPartition(
    planned_partitions: []const PlannedPartitionIdentity,
    architecture: Architecture,
    override_role: ?layout.PartitionRole,
) error{ AmbiguousRootPartition, MissingRootPartition }!PlannedPartitionIdentity {
    if (override_role) |role| {
        for (planned_partitions) |partition| {
            if (partition.planned.role == role) return partition;
        }
        return error.MissingRootPartition;
    }

    const default_role = defaultRootRoleForArchitecture(architecture);
    for (planned_partitions) |partition| {
        if (partition.planned.role == default_role) return partition;
    }

    var fallback: ?PlannedPartitionIdentity = null;
    for (planned_partitions) |partition| {
        switch (partition.planned.role) {
            .root_x86_64, .root_aarch64, .linux_filesystem_data => {
                if (fallback == null) {
                    fallback = partition;
                } else if (!std.mem.eql(u8, &fallback.?.unique_guid, &partition.unique_guid)) {
                    return error.AmbiguousRootPartition;
                }
            },
            else => {},
        }
    }

    return fallback orelse error.MissingRootPartition;
}

fn resolveRootPartitionGuid(
    planned_partitions: []const PlannedPartitionIdentity,
    architecture: Architecture,
    override_role: ?layout.PartitionRole,
) PopulateError!guid.Guid {
    return (try resolveRootPartition(planned_partitions, architecture, override_role)).unique_guid;
}

const BiosGrubAssets = struct {
    boot_img: SourceAsset,
    core_img: SourceAsset,

    fn deinit(self: *BiosGrubAssets, allocator: std.mem.Allocator) void {
        allocator.free(self.boot_img.source_path);
        allocator.free(self.core_img.source_path);
        self.* = undefined;
    }
};

const bios_grub2_config_path = "boot/grub2/grub.cfg";
const bios_grub_config_path = "boot/grub/grub.cfg";

fn biosGrubConfigPathForAssetPath(core_img_source_path: []const u8) []const u8 {
    return if (containsPathSegmentIgnoreCase(core_img_source_path, "grub2"))
        bios_grub2_config_path
    else
        bios_grub_config_path;
}

// Some distros (including the real Azure Linux 4.0 ISO from issue #76) ship
// BIOS GRUB's `core.img` under `usr/lib/grub/i386-pc/` even though the
// embedded handoff still loads `/boot/grub2/grub.cfg` at boot. Prefer
// replacing an existing on-disk BIOS grub.cfg over inferring the config path
// from the asset install location.
fn existingBiosGrubConfigPath(source: *SourceTreeView) SourceTreeView.IteratorError!?[]const u8 {
    var found_legacy = false;

    source.reset();
    while (try source.next()) |entry| {
        if (entry.kind != .file) continue;
        if (std.mem.eql(u8, entry.path, bios_grub2_config_path)) return bios_grub2_config_path;
        if (std.mem.eql(u8, entry.path, bios_grub_config_path)) found_legacy = true;
    }

    return if (found_legacy) bios_grub_config_path else null;
}

fn discoverBiosGrubAssets(allocator: std.mem.Allocator, source: *SourceTreeView) InstallBiosError!BiosGrubAssets {
    var best_boot_img: ?SourceAsset = null;
    var best_boot_score: usize = std.math.maxInt(usize);
    var best_core_img: ?SourceAsset = null;
    var best_core_score: usize = std.math.maxInt(usize);

    errdefer {
        if (best_boot_img) |asset| allocator.free(asset.source_path);
        if (best_core_img) |asset| allocator.free(asset.source_path);
    }

    source.reset();
    while (try source.next()) |entry| {
        if (entry.kind != .file or entry.content == null) continue;
        const content = entry.content.?;

        if (biosBootImgScore(entry.path)) |score| {
            if (score < best_boot_score) {
                if (best_boot_img) |asset| allocator.free(asset.source_path);
                best_boot_img = try dupeSourceAsset(allocator, entry.path, entry.size, content);
                best_boot_score = score;
            }
        }

        if (biosCoreImgScore(entry.path)) |score| {
            if (score < best_core_score) {
                if (best_core_img) |asset| allocator.free(asset.source_path);
                best_core_img = try dupeSourceAsset(allocator, entry.path, entry.size, content);
                best_core_score = score;
            }
        }
    }

    return .{
        .boot_img = best_boot_img orelse return error.MissingBiosBootImg,
        .core_img = best_core_img orelse return error.MissingBiosCoreImg,
    };
}

fn biosBootImgScore(path: []const u8) ?usize {
    if (std.ascii.eqlIgnoreCase(path, "boot/grub2/i386-pc/boot.img")) return 0;
    if (std.ascii.eqlIgnoreCase(path, "boot/grub/i386-pc/boot.img")) return 1;
    if (std.ascii.eqlIgnoreCase(path, "usr/lib/grub/i386-pc/boot.img")) return 2;
    if (std.ascii.eqlIgnoreCase(path, "usr/share/grub/i386-pc/boot.img")) return 3;
    if (endsWithIgnoreCase(path, "/i386-pc/boot.img")) return 10;
    return null;
}

fn biosCoreImgScore(path: []const u8) ?usize {
    if (std.ascii.eqlIgnoreCase(path, "boot/grub2/i386-pc/core.img")) return 0;
    if (std.ascii.eqlIgnoreCase(path, "boot/grub/i386-pc/core.img")) return 1;
    if (std.ascii.eqlIgnoreCase(path, "usr/lib/grub/i386-pc/core.img")) return 2;
    if (std.ascii.eqlIgnoreCase(path, "usr/share/grub/i386-pc/core.img")) return 3;
    if (endsWithIgnoreCase(path, "/i386-pc/core.img")) return 10;
    return null;
}

fn buildCopyPlan(
    allocator: std.mem.Allocator,
    efi_binaries: []const EfiBinary,
    architecture: Architecture,
    boot_mode: BootMode,
) std.mem.Allocator.Error![]CopyPlanEntry {
    var plan = std.array_list.Managed(CopyPlanEntry).init(allocator);
    errdefer {
        for (plan.items) |entry| allocator.free(entry.destination_path);
        plan.deinit();
    }

    for (efi_binaries) |binary| {
        if (boot_mode == .uki_only and std.ascii.eqlIgnoreCase(binary.destination_path, architecture.defaultBootPath())) continue;
        if (containsPathIgnoreCase(plan.items, binary.destination_path)) continue;
        try plan.append(.{
            .destination_path = try allocator.dupe(u8, binary.destination_path),
            .size = binary.size,
            .content = binary.content,
        });
    }

    const fallback_path = architecture.defaultBootPath();
    if (boot_mode.includesBls() and !containsPathIgnoreCase(plan.items, fallback_path)) {
        if (bestFallbackBinary(efi_binaries, architecture)) |binary| {
            try plan.append(.{
                .destination_path = try allocator.dupe(u8, fallback_path),
                .size = binary.size,
                .content = binary.content,
            });
        }
    }

    return plan.toOwnedSlice();
}

fn buildSecureBootCopyPlan(
    allocator: std.mem.Allocator,
    files: []const CopyableFile,
    existing_plan: []const CopyPlanEntry,
    architecture: Architecture,
    boot_mode: BootMode,
) std.mem.Allocator.Error![]CopyPlanEntry {
    var plan = std.array_list.Managed(CopyPlanEntry).init(allocator);
    errdefer {
        for (plan.items) |entry| allocator.free(entry.destination_path);
        plan.deinit();
    }

    const default_boot_path = architecture.defaultBootPath();
    for (files) |file| {
        if (boot_mode == .uki_only and std.ascii.eqlIgnoreCase(file.destination_path, default_boot_path)) continue;
        if (containsPathIgnoreCase(existing_plan, file.destination_path) or containsPathIgnoreCase(plan.items, file.destination_path)) continue;
        try plan.append(.{
            .destination_path = try allocator.dupe(u8, file.destination_path),
            .size = file.size,
            .content = file.content,
        });
    }

    return plan.toOwnedSlice();
}

fn containsPathIgnoreCase(entries: []const CopyPlanEntry, candidate: []const u8) bool {
    for (entries) |entry| {
        if (std.ascii.eqlIgnoreCase(entry.destination_path, candidate)) return true;
    }
    return false;
}

fn bestFallbackBinary(efi_binaries: []const EfiBinary, architecture: Architecture) ?EfiBinary {
    var best: ?EfiBinary = null;
    var best_priority: usize = std.math.maxInt(usize);
    for (efi_binaries) |binary| {
        if (binary.architecture != architecture) continue;
        const priority: usize = switch (binary.kind) {
            .default_boot => 0,
            .shim => 1,
            .grub => 2,
            .mok_manager => 3,
        };
        if (best == null or priority < best_priority) {
            best = binary;
            best_priority = priority;
        }
    }
    return best;
}

fn copyIntoFat32(
    allocator: std.mem.Allocator,
    io: Io,
    esp: *fat32.FileSystem,
    entry: CopyPlanEntry,
) PopulateError!void {
    const contents = try readSourceFileAlloc(allocator, entry.content, entry.size);
    defer allocator.free(contents);
    try writeGeneratedFile(io, esp, entry.destination_path, contents);
}

fn readSourceFileAlloc(
    allocator: std.mem.Allocator,
    reader: SourceTreeView.ContentReader,
    size: u64,
) PopulateError![]u8 {
    const len = std.math.cast(usize, size) orelse return error.FileTooLarge;
    const out = try allocator.alloc(u8, len);
    errdefer allocator.free(out);

    var done: usize = 0;
    while (done < out.len) {
        const got = try reader.readAt(out[done..], done);
        if (got == 0) return error.UnexpectedSourceLength;
        done += got;
    }
    return out;
}

fn buildBootEntries(
    allocator: std.mem.Allocator,
    kernels: []const BootArtifactCandidate,
    initrds: []const BootArtifactCandidate,
    title_prefix: []const u8,
) std.mem.Allocator.Error![]BootEntry {
    var used_ids = std.array_list.Managed([]u8).init(allocator);
    defer {
        for (used_ids.items) |id| allocator.free(id);
        used_ids.deinit();
    }

    var entries = std.array_list.Managed(BootEntry).init(allocator);
    errdefer {
        for (entries.items) |entry| {
            allocator.free(entry.id);
            allocator.free(entry.title);
        }
        entries.deinit();
    }

    for (kernels) |kernel| {
        const basename = baseName(kernel.source_path);
        const base_id = try sanitizeId(allocator, basename);
        defer allocator.free(base_id);
        const id = try makeUniqueId(allocator, base_id, used_ids.items);
        errdefer allocator.free(id);
        try used_ids.append(try allocator.dupe(u8, id));

        const title = if (title_prefix.len == 0)
            try allocator.dupe(u8, basename)
        else
            try std.fmt.allocPrint(allocator, "{s} {s}", .{ title_prefix, basename });
        errdefer allocator.free(title);

        const initrd = bestMatchingInitrd(kernel, initrds);
        try entries.append(.{
            .id = id,
            .title = title,
            .kernel = kernel,
            .initrd = initrd,
        });
    }

    return entries.toOwnedSlice();
}

fn sanitizeId(allocator: std.mem.Allocator, value: []const u8) std.mem.Allocator.Error![]u8 {
    var out = std.array_list.Managed(u8).init(allocator);
    errdefer out.deinit();

    for (value) |ch| {
        const mapped = if ((ch >= 'a' and ch <= 'z') or (ch >= '0' and ch <= '9') or ch == '-' or ch == '_' or ch == '.')
            ch
        else if (ch >= 'A' and ch <= 'Z')
            std.ascii.toLower(ch)
        else
            '-';
        try out.append(mapped);
    }
    if (out.items.len == 0) try out.appendSlice("entry");
    return out.toOwnedSlice();
}

fn makeUniqueId(
    allocator: std.mem.Allocator,
    base_id: []const u8,
    existing_ids: []const []u8,
) std.mem.Allocator.Error![]u8 {
    if (!containsString(existing_ids, base_id)) return allocator.dupe(u8, base_id);

    var suffix: usize = 2;
    while (true) : (suffix += 1) {
        const candidate = try std.fmt.allocPrint(allocator, "{s}-{d}", .{ base_id, suffix });
        errdefer allocator.free(candidate);
        if (!containsString(existing_ids, candidate)) return candidate;
        allocator.free(candidate);
    }
}

fn containsString(existing: []const []u8, candidate: []const u8) bool {
    for (existing) |value| {
        if (std.mem.eql(u8, value, candidate)) return true;
    }
    return false;
}

fn bestMatchingInitrd(kernel: BootArtifactCandidate, initrds: []const BootArtifactCandidate) ?BootArtifactCandidate {
    var best_index: ?usize = null;
    var best_score: i32 = -1;
    for (initrds, 0..) |candidate, index| {
        const score = scoreKernelInitrdPair(kernel, candidate);
        if (score > best_score) {
            best_score = score;
            best_index = index;
        }
    }
    if (best_index == null or best_score < 0) return null;
    return initrds[best_index.?];
}

fn scoreKernelInitrdPair(kernel: BootArtifactCandidate, initrd: BootArtifactCandidate) i32 {
    var score: i32 = 1;
    if (std.ascii.eqlIgnoreCase(dirName(kernel.source_path), dirName(initrd.source_path))) score += 10;

    const kernel_key = versionKey(baseName(kernel.source_path), true);
    const initrd_key = versionKey(baseName(initrd.source_path), false);
    if (kernel_key.len != 0 and initrd_key.len != 0 and std.ascii.eqlIgnoreCase(kernel_key, initrd_key)) {
        score += 100;
    } else if (kernel_key.len != 0 and endsWithIgnoreCase(baseName(initrd.source_path), kernel_key)) {
        score += 50;
    }

    return score;
}

fn versionKey(name: []const u8, comptime kernel: bool) []const u8 {
    if (kernel) {
        if (std.ascii.startsWithIgnoreCase(name, "vmlinuz-")) return name[8..];
        if (std.ascii.startsWithIgnoreCase(name, "linux-")) return name[6..];
        if (std.ascii.startsWithIgnoreCase(name, "Image-")) return name[6..];
        return "";
    }

    if (std.ascii.startsWithIgnoreCase(name, "initramfs-")) {
        return trimImgSuffix(name[10..]);
    }
    if (std.ascii.startsWithIgnoreCase(name, "initrd.img-")) {
        return trimImgSuffix(name[11..]);
    }
    if (std.ascii.startsWithIgnoreCase(name, "initrd-")) {
        return trimImgSuffix(name[7..]);
    }
    if (std.ascii.eqlIgnoreCase(name, "initrd.img") or std.ascii.eqlIgnoreCase(name, "initrd")) {
        return "";
    }
    return "";
}

fn trimImgSuffix(value: []const u8) []const u8 {
    if (value.len > 4 and std.ascii.eqlIgnoreCase(value[value.len - 4 ..], ".img")) {
        return value[0 .. value.len - 4];
    }
    return value;
}

fn endsWithIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;
    return std.ascii.eqlIgnoreCase(haystack[haystack.len - needle.len ..], needle);
}

fn generateUkis(
    allocator: std.mem.Allocator,
    io: Io,
    esp: *fat32.FileSystem,
    source: *SourceTreeView,
    architecture: Architecture,
    entries: []const BootEntry,
    cmdline: []const u8,
    options: PopulateOptions,
) PopulateError!usize {
    std.debug.assert(entries.len != 0);

    var assets = try discoverUkiAssets(allocator, source, architecture, options.uki);
    defer assets.deinit(allocator);

    const stub_bytes = try readSourceFileAlloc(allocator, assets.stub.content, assets.stub.size);
    defer allocator.free(stub_bytes);

    const os_release_bytes = if (assets.os_release) |asset|
        try readSourceFileAlloc(allocator, asset.content, asset.size)
    else
        try synthesizeOsRelease(allocator, options.title_prefix);
    defer allocator.free(os_release_bytes);

    const splash_bytes = if (assets.splash) |asset|
        try readSourceFileAlloc(allocator, asset.content, asset.size)
    else
        null;
    defer if (splash_bytes) |bytes| allocator.free(bytes);

    const output_directory = effectiveUkiOutputDirectory(options.uki.output_directory);
    if (options.uki_signer != null) {
        if (options.stage_sink) |sink| {
            if (!sink.advance(.sign_uki)) return error.InvalidOperationOrder;
        }
    }
    for (entries, 0..) |entry, index| {
        const kernel_bytes = try readSourceFileAlloc(allocator, entry.kernel.content, entry.kernel.size);
        defer allocator.free(kernel_bytes);

        const initrd_bytes = if (entry.initrd) |initrd|
            try readSourceFileAlloc(allocator, initrd.content, initrd.size)
        else
            null;
        defer if (initrd_bytes) |bytes| allocator.free(bytes);

        const uname = kernelReleaseName(entry.kernel.source_path);
        const uki_bytes = try uki.generate(allocator, .{
            .stub = stub_bytes,
            .linux = kernel_bytes,
            .initrd = initrd_bytes,
            .cmdline = cmdline,
            .os_release = os_release_bytes,
            .uname = uname,
            .splash = splash_bytes,
        });
        defer allocator.free(uki_bytes);

        const destination_path = try std.fmt.allocPrint(allocator, "{s}/{s}.efi", .{ output_directory, entry.id });
        defer allocator.free(destination_path);

        // The `uki_only` fallback is the same bytes at a second path, not a
        // second artifact. Naming both destinations up front means one
        // signing operation covers both, so the two copies cannot diverge
        // and a signer cannot be asked to sign the same image twice.
        var destinations: [2][]const u8 = undefined;
        destinations[0] = destination_path;
        var destination_count: usize = 1;
        if (options.boot_mode == .uki_only and index == 0) {
            destinations[1] = architecture.defaultBootPath();
            destination_count = 2;
        }
        const esp_paths = destinations[0..destination_count];

        const signed_bytes: ?[]u8 = if (options.uki_signer) |signer|
            try signer.sign(allocator, .{
                .esp_paths = esp_paths,
                .unsigned = uki_bytes,
            })
        else
            null;
        defer if (signed_bytes) |bytes| allocator.free(bytes);

        const final_bytes = signed_bytes orelse uki_bytes;
        for (esp_paths) |path| {
            try writeGeneratedFile(io, esp, path, final_bytes);
        }
    }

    return entries.len;
}

fn discoverUkiAssets(
    allocator: std.mem.Allocator,
    source: *SourceTreeView,
    architecture: Architecture,
    options: UkiOptions,
) PopulateError!UkiAssets {
    var best_stub: ?SourceAsset = null;
    var best_stub_score: usize = std.math.maxInt(usize);
    var explicit_os_release: ?SourceAsset = null;
    var usr_lib_os_release: ?SourceAsset = null;
    var etc_os_release: ?SourceAsset = null;
    var splash: ?SourceAsset = null;

    errdefer {
        if (best_stub) |asset| allocator.free(asset.source_path);
        if (explicit_os_release) |asset| allocator.free(asset.source_path);
        if (usr_lib_os_release) |asset| allocator.free(asset.source_path);
        if (etc_os_release) |asset| allocator.free(asset.source_path);
        if (splash) |asset| allocator.free(asset.source_path);
    }

    source.reset();
    while (try source.next()) |entry| {
        if (entry.kind != .file or entry.content == null) continue;
        const content = entry.content.?;

        if (options.stub_source_path) |stub_source_path| {
            if (std.ascii.eqlIgnoreCase(entry.path, stub_source_path)) {
                if (best_stub) |asset| allocator.free(asset.source_path);
                best_stub = try dupeSourceAsset(allocator, entry.path, entry.size, content);
                best_stub_score = 0;
            }
        } else if (ukiStubScore(entry.path, architecture)) |score| {
            if (score < best_stub_score) {
                if (best_stub) |asset| allocator.free(asset.source_path);
                best_stub = try dupeSourceAsset(allocator, entry.path, entry.size, content);
                best_stub_score = score;
            }
        }

        if (options.os_release_source_path) |os_release_source_path| {
            if (std.ascii.eqlIgnoreCase(entry.path, os_release_source_path)) {
                if (explicit_os_release) |asset| allocator.free(asset.source_path);
                explicit_os_release = try dupeSourceAsset(allocator, entry.path, entry.size, content);
            }
        } else if (std.ascii.eqlIgnoreCase(entry.path, "usr/lib/os-release")) {
            if (usr_lib_os_release) |asset| allocator.free(asset.source_path);
            usr_lib_os_release = try dupeSourceAsset(allocator, entry.path, entry.size, content);
        } else if (std.ascii.eqlIgnoreCase(entry.path, "etc/os-release")) {
            if (etc_os_release) |asset| allocator.free(asset.source_path);
            etc_os_release = try dupeSourceAsset(allocator, entry.path, entry.size, content);
        }

        if (options.splash_source_path) |splash_source_path| {
            if (std.ascii.eqlIgnoreCase(entry.path, splash_source_path)) {
                if (splash) |asset| allocator.free(asset.source_path);
                splash = try dupeSourceAsset(allocator, entry.path, entry.size, content);
            }
        }
    }

    const stub = best_stub orelse return error.MissingUkiStub;
    var os_release: ?SourceAsset = null;
    if (explicit_os_release) |asset| {
        os_release = asset;
        if (usr_lib_os_release) |other| allocator.free(other.source_path);
        if (etc_os_release) |other| allocator.free(other.source_path);
    } else if (usr_lib_os_release) |asset| {
        os_release = asset;
        if (etc_os_release) |other| allocator.free(other.source_path);
    } else if (etc_os_release) |asset| {
        os_release = asset;
    }

    return .{
        .stub = stub,
        .os_release = os_release,
        .splash = splash,
    };
}

fn dupeSourceAsset(
    allocator: std.mem.Allocator,
    path: []const u8,
    size: u64,
    content: SourceTreeView.ContentReader,
) std.mem.Allocator.Error!SourceAsset {
    return .{
        .source_path = try allocator.dupe(u8, path),
        .size = size,
        .content = content,
    };
}

pub fn isUkiStubPath(path: []const u8, architecture: Architecture) bool {
    return ukiStubScore(path, architecture) != null;
}

fn ukiStubScore(path: []const u8, architecture: Architecture) ?usize {
    const basename = baseName(path);
    const preferred_dir_bonus: usize = if (containsIgnoreCase(path, "systemd/boot/efi")) 0 else 10;
    return switch (architecture) {
        .x86_64 => if (std.ascii.eqlIgnoreCase(basename, "linuxx64.efi.stub"))
            preferred_dir_bonus
        else if (std.ascii.eqlIgnoreCase(basename, "systemd-stubx64.efi"))
            preferred_dir_bonus + 1
        else if (std.ascii.eqlIgnoreCase(basename, "stubx64.efi"))
            preferred_dir_bonus + 2
        else
            null,
        .aarch64 => if (std.ascii.eqlIgnoreCase(basename, "linuxaa64.efi.stub"))
            preferred_dir_bonus
        else if (std.ascii.eqlIgnoreCase(basename, "systemd-stubaa64.efi"))
            preferred_dir_bonus + 1
        else if (std.ascii.eqlIgnoreCase(basename, "stubaa64.efi"))
            preferred_dir_bonus + 2
        else
            null,
    };
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0) return true;
    if (needle.len > haystack.len) return false;
    var start: usize = 0;
    while (start + needle.len <= haystack.len) : (start += 1) {
        if (std.ascii.eqlIgnoreCase(haystack[start .. start + needle.len], needle)) return true;
    }
    return false;
}

fn synthesizeOsRelease(allocator: std.mem.Allocator, title_prefix: []const u8) std.mem.Allocator.Error![]u8 {
    const pretty_name = if (title_prefix.len != 0) title_prefix else "zvmi";
    return std.fmt.allocPrint(
        allocator,
        "ID=zvmi\nNAME=\"zvmi\"\nPRETTY_NAME=\"{s}\"\n",
        .{pretty_name},
    );
}

/// Renders the shared kernel command line used by generated GRUB, BLS, and
/// UKI boot entries. `root_partuuid_text` may be a GPT partition GUID or the
/// synthesized Linux MBR PARTUUID form (`<disk-signature>-<partition-number>`).
pub fn renderKernelOptions(
    allocator: std.mem.Allocator,
    root_partuuid_text: []const u8,
    extra_kernel_options: []const u8,
    verity_info: ?verity.Info,
) std.mem.Allocator.Error![]u8 {
    const base = if (verity_info) |info| blk: {
        var root_hash_buf: [verity.digest_size * 2]u8 = undefined;
        var salt_buf: [verity.salt_size * 2]u8 = undefined;
        break :blk try std.fmt.allocPrint(
            allocator,
            "root=/dev/mapper/root ro roothash={s} systemd.verity_root_data=PARTUUID={s} systemd.verity_root_hash=PARTUUID={s} systemd.verity_root_options=superblock=0,format={d},data-block-size={d},hash-block-size={d},data-blocks={d},hash-offset={d},salt={s},hash={s}",
            .{
                info.formatRootHash(&root_hash_buf),
                root_partuuid_text,
                root_partuuid_text,
                info.format,
                info.dataBlockSize,
                info.hashBlockSize,
                info.dataBlocks,
                info.hashOffset,
                info.formatSalt(&salt_buf),
                info.hashAlgorithm,
            },
        );
    } else try std.fmt.allocPrint(allocator, "root=PARTUUID={s}", .{root_partuuid_text});
    defer allocator.free(base);

    return if (extra_kernel_options.len == 0)
        allocator.dupe(u8, base)
    else
        std.fmt.allocPrint(allocator, "{s} {s}", .{ base, extra_kernel_options });
}

fn effectiveUkiOutputDirectory(output_directory: []const u8) []const u8 {
    const trimmed = trimSlashes(output_directory);
    return if (trimmed.len == 0) "EFI/Linux" else trimmed;
}

fn kernelReleaseName(kernel_source_path: []const u8) []const u8 {
    const basename = baseName(kernel_source_path);
    const version = versionKey(basename, true);
    return if (version.len != 0) version else basename;
}

fn renderLoaderConf(
    allocator: std.mem.Allocator,
    entries: []const BootEntry,
    timeout_seconds: u32,
) std.mem.Allocator.Error![]u8 {
    std.debug.assert(entries.len != 0);
    return std.fmt.allocPrint(allocator, "default {s}\ntimeout {d}\n", .{ entries[0].id, timeout_seconds });
}

fn renderGrubCfg(
    allocator: std.mem.Allocator,
    entries: []const BootEntry,
    kernel_device_partuuid_text: []const u8,
    root_filesystem_uuid_text: ?[]const u8,
    kernel_options: []const u8,
    partition_module: GrubPartitionModule,
    timeout_seconds: u32,
) std.mem.Allocator.Error![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    out.writer.print("set default=0\nset timeout={d}\n\ninsmod {s}\ninsmod ext2\n", .{ timeout_seconds, partition_module.name() }) catch return error.OutOfMemory;
    if (root_filesystem_uuid_text) |fs_uuid_text| {
        // GRUB's `search` command has no `--partuuid` search type -- only
        // `--file`, `--label`, and `--fs-uuid` are recognized. Searching by
        // the root filesystem's own UUID is the correct, portable way to
        // locate `$kernel_root` at GRUB's boot stage (distinct from the
        // `root=PARTUUID=...` argument passed to the *kernel*, which the
        // Linux kernel/udev resolve independently at OS boot time).
        out.writer.print("search --no-floppy --fs-uuid --set=kernel_root {s}\n\n", .{fs_uuid_text}) catch return error.OutOfMemory;
    } else {
        // Fallback retained for callers/tests that don't supply the root
        // filesystem's UUID. NOTE: `--partuuid` is not a real GRUB `search`
        // type and will fail with "unspecified search type" on real GRUB,
        // leaving `$kernel_root` unset (see issue #72) -- this branch exists
        // only for structural-test backward compatibility, not real boots.
        out.writer.print("search --no-floppy --partuuid --set=kernel_root {s}\n\n", .{kernel_device_partuuid_text}) catch return error.OutOfMemory;
    }

    for (entries) |entry| {
        out.writer.print("menuentry '{s}' --id '{s}' {{\n", .{ entry.title, entry.id }) catch return error.OutOfMemory;
        out.writer.print("    linux ($kernel_root){s} {s}\n", .{ entry.kernel.config_path, kernel_options }) catch return error.OutOfMemory;
        if (entry.initrd) |initrd| {
            out.writer.print("    initrd ($kernel_root){s}\n", .{initrd.config_path}) catch return error.OutOfMemory;
        }
        out.writer.writeAll("}\n\n") catch return error.OutOfMemory;
    }

    return out.toOwnedSlice();
}

fn renderBlsEntry(
    allocator: std.mem.Allocator,
    entry: BootEntry,
    kernel_options: []const u8,
) std.mem.Allocator.Error![]u8 {
    var out = std.Io.Writer.Allocating.init(allocator);
    errdefer out.deinit();

    out.writer.print(
        "title {s}\nversion {s}\nlinux {s}\n",
        .{ entry.title, baseName(entry.kernel.config_path), entry.kernel.config_path },
    ) catch return error.OutOfMemory;
    if (entry.initrd) |initrd| {
        out.writer.print("initrd {s}\n", .{initrd.config_path}) catch return error.OutOfMemory;
    }
    out.writer.print("options {s}\n", .{kernel_options}) catch return error.OutOfMemory;

    return out.toOwnedSlice();
}

fn formatPlannedPartitionPartuuid(
    buf: *[max_partuuid_text_len]u8,
    planned_partitions: []const PlannedPartitionIdentity,
    partition: PlannedPartitionIdentity,
) []const u8 {
    if (partition.mbr_disk_signature) |disk_signature| {
        var mbr_buf: [mbr.partuuid_len]u8 = undefined;
        const text = mbr.formatPartuuid(&mbr_buf, disk_signature, partitionIndex1Based(planned_partitions, partition));
        @memcpy(buf[0..text.len], text);
        return buf[0..text.len];
    }
    return guid.formatLower(buf, partition.unique_guid);
}

/// Formats a 16-byte UUID in plain big-endian/RFC4122 byte order (the
/// convention used by ext4's superblock `s_uuid`, Linux's libuuid, and most
/// POSIX tooling) as a lowercase canonical string. This is deliberately NOT
/// `guid.formatLower`, which assumes the mixed-endian Microsoft `GUID`
/// convention used by GPT -- using it here would silently byte-swap the
/// ext4 filesystem UUID and produce a string GRUB's `--fs-uuid` search would
/// never match. Mirrors `cosi.zig`'s private `formatUuidBytes` helper.
fn formatPlainUuidBytes(buf: *[36]u8, bytes: *const [16]u8) []const u8 {
    _ = std.fmt.bufPrint(
        buf,
        "{x:0>2}{x:0>2}{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}-{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}{x:0>2}",
        .{
            bytes[0],  bytes[1],  bytes[2],  bytes[3],
            bytes[4],  bytes[5],  bytes[6],  bytes[7],
            bytes[8],  bytes[9],  bytes[10], bytes[11],
            bytes[12], bytes[13], bytes[14], bytes[15],
        },
    ) catch unreachable;
    return buf;
}

fn partitionIndex1Based(
    planned_partitions: []const PlannedPartitionIdentity,
    partition: PlannedPartitionIdentity,
) u8 {
    for (planned_partitions, 0..) |candidate, index| {
        if (std.mem.eql(u8, &candidate.unique_guid, &partition.unique_guid)) {
            return std.math.cast(u8, index + 1) orelse unreachable;
        }
    }
    unreachable;
}

fn collectVendorGrubCfgPaths(
    allocator: std.mem.Allocator,
    copy_plan: []const CopyPlanEntry,
) std.mem.Allocator.Error!std.array_list.Managed([]u8) {
    var paths = std.array_list.Managed([]u8).init(allocator);
    errdefer {
        for (paths.items) |path| allocator.free(path);
        paths.deinit();
    }

    for (copy_plan) |entry| {
        const vendor = efiVendor(entry.destination_path) orelse continue;
        if (std.ascii.eqlIgnoreCase(vendor, "BOOT")) continue;
        const cfg_path = try std.fmt.allocPrint(allocator, "EFI/{s}/grub.cfg", .{vendor});
        errdefer allocator.free(cfg_path);
        if (containsSliceIgnoreCase(paths.items, cfg_path)) {
            allocator.free(cfg_path);
            continue;
        }
        try paths.append(cfg_path);
    }

    return paths;
}

fn containsSliceIgnoreCase(values: []const []u8, candidate: []const u8) bool {
    for (values) |value| {
        if (std.ascii.eqlIgnoreCase(value, candidate)) return true;
    }
    return false;
}

fn efiVendor(path: []const u8) ?[]const u8 {
    if (!std.ascii.startsWithIgnoreCase(path, "EFI/")) return null;
    const rest = path[4..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return null;
    return rest[0..slash];
}

fn writeGeneratedFile(io: Io, esp: *fat32.FileSystem, path: []const u8, contents: []const u8) PopulateError!void {
    const parent = dirName(path);
    if (parent.len != 0) try esp.createDir(io, parent);
    try esp.writeFile(io, path, contents);
}

fn baseName(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return path;
    return path[slash + 1 ..];
}

fn dirName(path: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, path, '/') orelse return "";
    return path[0..slash];
}

test "populateEsp copies EFI binaries and generates grub.cfg plus BLS entries" {
    const io = std.testing.io;
    const path = "test-bootconfig-populate.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size = 256 * 1024 * 1024;
    const requests = [_]layout.PartitionRequest{
        .{ .name = "ESP", .role = .esp, .size = .{ .fixed = 96 * 1024 * 1024 } },
        .{ .name = "root", .role = .root_x86_64, .size = .{ .percent = 100.0 } },
    };
    const planned = try layout.planLayout(std.testing.allocator, disk_size, &requests, null);
    defer std.testing.allocator.free(planned);

    const identities = [_]PlannedPartitionIdentity{
        .{ .planned = planned[0], .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111") },
        .{ .planned = planned[1], .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222") },
    };

    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]gpt.PlacedPartitionSpec{
        .{
            .type_guid = identities[0].planned.type_guid,
            .unique_guid = identities[0].unique_guid,
            .placement = .{ .first_lba = identities[0].planned.firstLba(), .last_lba = identities[0].planned.lastLba() },
            .name_utf16le = gpt.asciiName(identities[0].planned.name),
        },
        .{
            .type_guid = identities[1].planned.type_guid,
            .unique_guid = identities[1].unique_guid,
            .placement = .{ .first_lba = identities[1].planned.firstLba(), .last_lba = identities[1].planned.lastLba() },
            .name_utf16le = gpt.asciiName(identities[1].planned.name),
        },
    };
    try gpt.writeGptPlaced(&img, io, guid.parse("33333333-3333-3333-3333-333333333333"), &specs);

    try fat32.format(&img, io, .{
        .partition_offset = identities[0].planned.offset_bytes,
        .partition_len = identities[0].planned.length_bytes,
    });
    var esp = try fat32.open(&img, io, .{ .offset = identities[0].planned.offset_bytes, .length = identities[0].planned.length_bytes });

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .kind = .file, .bytes = "bootx64-bytes" },
        .{ .path = "EFI/Acme/shimx64.efi", .kind = .file, .bytes = "shimx64-bytes" },
        .{ .path = "EFI/Acme/grubx64.efi", .kind = .file, .bytes = "grubx64-bytes" },
        .{ .path = "EFI/Acme/mmx64.efi", .kind = .file, .bytes = "mmx64-bytes" },
        .{ .path = "boot/vmlinuz-6.8.12-test", .kind = .file, .bytes = "kernel-bits" },
        .{ .path = "boot/initramfs-6.8.12-test.img", .kind = .file, .bytes = "initrd-bits" },
    });
    tree.bind();

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &identities,
        .extra_kernel_options = "console=ttyS0 quiet",
        .title_prefix = "zvmi",
    });
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(Architecture.x86_64, report.architecture);
    try std.testing.expectEqual(@as(usize, 4), report.copied_efi_file_count);
    try std.testing.expectEqual(@as(usize, 0), report.copied_secure_boot_file_count);
    try std.testing.expectEqual(@as(usize, 1), report.bls_entry_count);
    try std.testing.expectEqual(@as(usize, 0), report.uki_count);

    const parsed = try gpt.readGpt(img, io, std.testing.allocator);
    defer std.testing.allocator.free(parsed.partitions);
    try std.testing.expectEqual(@as(usize, 2), parsed.partitions.len);
    try std.testing.expectEqualSlices(u8, &identities[0].unique_guid, &parsed.partitions[0].unique_partition_guid);
    try std.testing.expectEqualSlices(u8, &identities[1].unique_guid, &parsed.partitions[1].unique_partition_guid);

    const bootx64 = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/BOOTX64.EFI");
    defer std.testing.allocator.free(bootx64);
    try std.testing.expectEqualStrings("bootx64-bytes", bootx64);

    const shim = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/shimx64.efi");
    defer std.testing.allocator.free(shim);
    try std.testing.expectEqualStrings("shimx64-bytes", shim);

    const grub = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/grubx64.efi");
    defer std.testing.allocator.free(grub);
    try std.testing.expectEqualStrings("grubx64-bytes", grub);

    const mok = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/mmx64.efi");
    defer std.testing.allocator.free(mok);
    try std.testing.expectEqualStrings("mmx64-bytes", mok);

    const loader_conf = try esp.readFileAlloc(io, std.testing.allocator, "loader/loader.conf");
    defer std.testing.allocator.free(loader_conf);
    try std.testing.expectEqualStrings("default vmlinuz-6.8.12-test\ntimeout 1\n", loader_conf);

    const grub_cfg = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/grub.cfg");
    defer std.testing.allocator.free(grub_cfg);
    var root_guid_buf: [36]u8 = undefined;
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "search --no-floppy --partuuid --set=kernel_root 22222222-2222-2222-2222-222222222222") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "menuentry 'zvmi vmlinuz-6.8.12-test' --id 'vmlinuz-6.8.12-test'") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "linux ($kernel_root)/boot/vmlinuz-6.8.12-test root=PARTUUID=22222222-2222-2222-2222-222222222222 console=ttyS0 quiet") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "initrd ($kernel_root)/boot/initramfs-6.8.12-test.img") != null);
    _ = guid.formatLower(&root_guid_buf, parsed.partitions[1].unique_partition_guid);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, root_guid_buf[0..]) != null);

    const vendor_grub_cfg = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/grub.cfg");
    defer std.testing.allocator.free(vendor_grub_cfg);
    try std.testing.expectEqualSlices(u8, grub_cfg, vendor_grub_cfg);

    const bls_entry = try esp.readFileAlloc(io, std.testing.allocator, "loader/entries/vmlinuz-6.8.12-test.conf");
    defer std.testing.allocator.free(bls_entry);
    const parsed_bls = try parseBlsEntry(bls_entry);
    try std.testing.expectEqualStrings("zvmi vmlinuz-6.8.12-test", parsed_bls.title.?);
    try std.testing.expectEqualStrings("/boot/vmlinuz-6.8.12-test", parsed_bls.linux.?);
    try std.testing.expectEqualStrings("/boot/initramfs-6.8.12-test.img", parsed_bls.initrd.?);
    try std.testing.expectEqualStrings("root=PARTUUID=22222222-2222-2222-2222-222222222222 console=ttyS0 quiet", parsed_bls.options.?);
}

test "populateEsp ignores GRUB's own linux.mod and installer loader binaries as kernel candidates" {
    // Regression test for a bug found via real QEMU + OVMF boot testing
    // against the real Azure Linux 4.0 ISO (see issue #72): `isKernelPath`
    // used to match ANY basename starting with "linux", which incorrectly
    // picked up GRUB's own `boot/grub2/i386-pc/linux.mod` loadable module and
    // the installer's own `boot/x86_64/loader/linux` boot binary as kernel
    // candidates alongside the real `boot/vmlinuz-*` kernel, and one of the
    // false positives ended up selected as the default boot entry -- GRUB
    // then failed to boot with "you need to load the kernel first" since
    // `linux.mod` is not a valid Linux kernel image.
    const io = std.testing.io;
    const path = "test-bootconfig-real-kernel-only.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const disk_size = 256 * 1024 * 1024;
    const requests = [_]layout.PartitionRequest{
        .{ .name = "ESP", .role = .esp, .size = .{ .fixed = 96 * 1024 * 1024 } },
        .{ .name = "root", .role = .root_x86_64, .size = .{ .percent = 100.0 } },
    };
    const planned = try layout.planLayout(std.testing.allocator, disk_size, &requests, null);
    defer std.testing.allocator.free(planned);

    const identities = [_]PlannedPartitionIdentity{
        .{ .planned = planned[0], .unique_guid = guid.parse("11111111-1111-1111-1111-111111111111") },
        .{ .planned = planned[1], .unique_guid = guid.parse("22222222-2222-2222-2222-222222222222") },
    };

    var img = try Image.create(io, path, .raw, disk_size, .{});
    defer img.close(io);

    const specs = [_]gpt.PlacedPartitionSpec{
        .{
            .type_guid = identities[0].planned.type_guid,
            .unique_guid = identities[0].unique_guid,
            .placement = .{ .first_lba = identities[0].planned.firstLba(), .last_lba = identities[0].planned.lastLba() },
            .name_utf16le = gpt.asciiName(identities[0].planned.name),
        },
        .{
            .type_guid = identities[1].planned.type_guid,
            .unique_guid = identities[1].unique_guid,
            .placement = .{ .first_lba = identities[1].planned.firstLba(), .last_lba = identities[1].planned.lastLba() },
            .name_utf16le = gpt.asciiName(identities[1].planned.name),
        },
    };
    try gpt.writeGptPlaced(&img, io, guid.parse("33333333-3333-3333-3333-333333333333"), &specs);

    try fat32.format(&img, io, .{
        .partition_offset = identities[0].planned.offset_bytes,
        .partition_len = identities[0].planned.length_bytes,
    });
    var esp = try fat32.open(&img, io, .{ .offset = identities[0].planned.offset_bytes, .length = identities[0].planned.length_bytes });

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .kind = .file, .bytes = "bootx64-bytes" },
        // GRUB's own module, matching the real ISO's boot/grub2/i386-pc/linux.mod:
        .{ .path = "boot/grub2/i386-pc/linux.mod", .kind = .file, .bytes = "not-a-kernel" },
        // Installer's own loader binary + initrd, matching the real ISO's boot/x86_64/loader/{linux,initrd}:
        .{ .path = "boot/x86_64/loader/linux", .kind = .file, .bytes = "not-a-kernel-either" },
        .{ .path = "boot/x86_64/loader/initrd", .kind = .file, .bytes = "not-an-initrd-either" },
        // The real kernel/initrd:
        .{ .path = "boot/vmlinuz-6.18.31-1.3.azl4.x86_64", .kind = .file, .bytes = "real-kernel-bits" },
        .{ .path = "boot/initramfs-6.18.31-1.3.azl4.x86_64.img", .kind = .file, .bytes = "real-initrd-bits" },
    });
    tree.bind();

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &identities,
        .title_prefix = "zvmi",
        .root_filesystem_uuid = [_]u8{
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        },
    });
    defer report.deinit(std.testing.allocator);
    // Only the real kernel should have produced a BLS entry -- not 3.
    try std.testing.expectEqual(@as(usize, 1), report.bls_entry_count);

    const loader_conf = try esp.readFileAlloc(io, std.testing.allocator, "loader/loader.conf");
    defer std.testing.allocator.free(loader_conf);
    try std.testing.expectEqualStrings("default vmlinuz-6.18.31-1.3.azl4.x86_64\ntimeout 1\n", loader_conf);

    const grub_cfg = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/grub.cfg");
    defer std.testing.allocator.free(grub_cfg);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "linux.mod") == null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "loader/linux") == null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "loader/initrd") == null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "menuentry 'zvmi vmlinuz-6.18.31-1.3.azl4.x86_64'") != null);
    // GRUB's `search` command has no `--partuuid` search type (see issue
    // #72) -- when a root filesystem UUID is supplied, the generated
    // grub.cfg must use `--fs-uuid` instead, in plain big-endian byte order
    // (NOT the mixed-endian `guid.formatLower` GPT convention).
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "search --no-floppy --fs-uuid --set=kernel_root abcdef01-2345-6789-abcd-ef0123456789") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, "--partuuid") == null);

    const bls_entry = try esp.readFileAlloc(io, std.testing.allocator, "loader/entries/vmlinuz-6.18.31-1.3.azl4.x86_64.conf");
    defer std.testing.allocator.free(bls_entry);
    const parsed_bls = try parseBlsEntry(bls_entry);
    try std.testing.expectEqualStrings("/boot/vmlinuz-6.18.31-1.3.azl4.x86_64", parsed_bls.linux.?);
    try std.testing.expectEqualStrings("/boot/initramfs-6.18.31-1.3.azl4.x86_64.img", parsed_bls.initrd.?);
}

test "populateEsp synthesizes fallback BOOTX64.EFI from shim when needed" {
    const io = std.testing.io;
    const path = "test-bootconfig-fallback.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const esp_len = 96 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, esp_len, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{ .partition_offset = 0, .partition_len = esp_len });
    var esp = try fat32.open(&img, io, .{ .offset = 0, .length = esp_len });

    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "ESP",
            .role = .esp,
            .type_guid = guid.esp,
            .offset_bytes = 0,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("44444444-4444-4444-4444-444444444444") },
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = esp_len,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("55555555-5555-5555-5555-555555555555") },
    };

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "EFI/Test/shimx64.efi", .kind = .file, .bytes = "shim-payload" },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel" },
        .{ .path = "boot/initrd-test.img", .kind = .file, .bytes = "initrd" },
    });
    tree.bind();

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &planned,
    });
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqualStrings("EFI/BOOT/BOOTX64.EFI", report.default_bootloader_path);

    const fallback = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/BOOTX64.EFI");
    defer std.testing.allocator.free(fallback);
    try std.testing.expectEqualStrings("shim-payload", fallback);

    const shim = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Test/shimx64.efi");
    defer std.testing.allocator.free(shim);
    try std.testing.expectEqualStrings("shim-payload", shim);
}

test "populateEsp appends dm-verity kernel arguments to grub.cfg and BLS entries" {
    const io = std.testing.io;
    const path = "test-bootconfig-verity.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const esp_len = 96 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, esp_len * 2, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{ .partition_offset = 0, .partition_len = esp_len });
    var esp = try fat32.open(&img, io, .{ .offset = 0, .length = esp_len });

    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "ESP",
            .role = .esp,
            .type_guid = guid.esp,
            .offset_bytes = 0,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa") },
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = esp_len,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb") },
    };

    var salt: [verity.salt_size]u8 = undefined;
    var root_hash: [verity.digest_size]u8 = undefined;
    for (&salt, 0..) |*byte, index| byte.* = @intCast(index);
    for (&root_hash, 0..) |*byte, index| byte.* = @intCast(0xF0 - index);

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "EFI/BOOT/BOOTX64.EFI", .kind = .file, .bytes = "bootx64-bytes" },
        .{ .path = "EFI/Acme/grubx64.efi", .kind = .file, .bytes = "grubx64-bytes" },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel-bits" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .bytes = "initrd-bits" },
    });
    tree.bind();

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &planned,
        .extra_kernel_options = "console=ttyS0 quiet",
        .verity = .{
            .dataBlockSize = 4096,
            .hashBlockSize = 4096,
            .dataBlocks = 1234,
            .hashOffset = 5054464,
            .hashTreeSize = 4096,
            .salt = salt,
            .rootHash = root_hash,
        },
    });
    defer report.deinit(std.testing.allocator);

    var salt_buf: [verity.salt_size * 2]u8 = undefined;
    var root_hash_buf: [verity.digest_size * 2]u8 = undefined;
    const expected_verity: verity.Info = .{
        .dataBlockSize = 4096,
        .hashBlockSize = 4096,
        .dataBlocks = 1234,
        .hashOffset = 5054464,
        .hashTreeSize = 4096,
        .salt = salt,
        .rootHash = root_hash,
    };
    const expected_options = try std.fmt.allocPrint(
        std.testing.allocator,
        "root=/dev/mapper/root ro roothash={s} systemd.verity_root_data=PARTUUID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb systemd.verity_root_hash=PARTUUID=bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb systemd.verity_root_options=superblock=0,format=1,data-block-size=4096,hash-block-size=4096,data-blocks=1234,hash-offset=5054464,salt={s},hash=sha256 console=ttyS0 quiet",
        .{
            expected_verity.formatRootHash(&root_hash_buf),
            expected_verity.formatSalt(&salt_buf),
        },
    );
    defer std.testing.allocator.free(expected_options);

    const grub_cfg = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/grub.cfg");
    defer std.testing.allocator.free(grub_cfg);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, expected_options) != null);

    const bls_entry = try esp.readFileAlloc(io, std.testing.allocator, "loader/entries/vmlinuz-test.conf");
    defer std.testing.allocator.free(bls_entry);
    const parsed_bls = try parseBlsEntry(bls_entry);
    try std.testing.expectEqualStrings(expected_options, parsed_bls.options.?);

    // The report is only worth having if it is the same bytes. Compared
    // against what was read back off the ESP rather than against
    // `expected_options` alone, so that a renderer which stopped using the
    // reported line would fail here instead of quietly reporting a string no
    // entry contains.
    try std.testing.expectEqualStrings(parsed_bls.options.?, report.kernel_command_line);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg, report.kernel_command_line) != null);
}

test "renderKernelOptions accepts synthesized MBR PARTUUID text for dm-verity" {
    var partuuid_buf: [mbr.partuuid_len]u8 = undefined;
    const root_partuuid_text = mbr.formatPartuuid(&partuuid_buf, 0xA1B2C3D4, 1);

    var salt: [verity.salt_size]u8 = undefined;
    var root_hash: [verity.digest_size]u8 = undefined;
    for (&salt, 0..) |*byte, index| byte.* = @intCast(index);
    for (&root_hash, 0..) |*byte, index| byte.* = @intCast(0xF0 - index);

    const rendered = try renderKernelOptions(std.testing.allocator, root_partuuid_text, "console=ttyS0 quiet", .{
        .dataBlockSize = 4096,
        .hashBlockSize = 4096,
        .dataBlocks = 1234,
        .hashOffset = 5054464,
        .hashTreeSize = 4096,
        .salt = salt,
        .rootHash = root_hash,
    });
    defer std.testing.allocator.free(rendered);

    try std.testing.expect(std.mem.indexOf(u8, rendered, "systemd.verity_root_data=PARTUUID=a1b2c3d4-01") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "systemd.verity_root_hash=PARTUUID=a1b2c3d4-01") != null);
    try std.testing.expect(std.mem.indexOf(u8, rendered, "console=ttyS0 quiet") != null);
}

test "generateBiosGrubCfg renders an MBR grub.cfg for the discovered kernel" {
    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = 1024 * 1024,
            .length_bytes = 128 * 1024 * 1024,
        }, .unique_guid = guid.parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa"), .mbr_disk_signature = 0xA1B2C3D4 },
    };

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "boot/grub2/i386-pc/boot.img", .kind = .file, .bytes = "boot-img" },
        .{ .path = "boot/grub2/i386-pc/core.img", .kind = .file, .bytes = "core-img" },
        .{ .path = "boot/grub2/grub.cfg", .kind = .file, .bytes = "linux /boot/x86_64/loader/linux root=live:CDLABEL=CDROM\n" },
        .{ .path = "boot/x86_64/loader/linux", .kind = .file, .bytes = "installer-kernel" },
        .{ .path = "boot/x86_64/loader/initrd", .kind = .file, .bytes = "installer-initrd" },
        .{ .path = "boot/vmlinuz-6.8.12-test", .kind = .file, .bytes = "kernel-bits" },
        .{ .path = "boot/initramfs-6.8.12-test.img", .kind = .file, .bytes = "initrd-bits" },
    });
    tree.bind();

    var grub_cfg = try generateBiosGrubCfg(std.testing.allocator, &tree.view, .{
        .planned_partitions = &planned,
        .root_filesystem_uuid = [_]u8{
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
            0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89,
        },
        .extra_kernel_options = "console=ttyS0 quiet",
        .title_prefix = "zvmi",
    });
    defer grub_cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("boot/grub2/grub.cfg", grub_cfg.path);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "insmod part_msdos") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "insmod part_gpt") == null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "search --no-floppy --fs-uuid --set=kernel_root abcdef01-2345-6789-abcd-ef0123456789") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "menuentry 'zvmi vmlinuz-6.8.12-test' --id 'vmlinuz-6.8.12-test'") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "linux ($kernel_root)/boot/vmlinuz-6.8.12-test root=PARTUUID=a1b2c3d4-01 console=ttyS0 quiet") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "initrd ($kernel_root)/boot/initramfs-6.8.12-test.img") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "boot/x86_64/loader/linux") == null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "root=live:CDLABEL=CDROM") == null);
}

test "generateBiosGrubCfg selects boot/grub/grub.cfg for legacy BIOS assets" {
    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = 1024 * 1024,
            .length_bytes = 128 * 1024 * 1024,
        }, .unique_guid = guid.parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb"), .mbr_disk_signature = 0x55667788 },
    };

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "boot/grub/i386-pc/boot.img", .kind = .file, .bytes = "boot-img" },
        .{ .path = "boot/grub/i386-pc/core.img", .kind = .file, .bytes = "core-img" },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel-bits" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .bytes = "initrd-bits" },
    });
    tree.bind();

    var grub_cfg = try generateBiosGrubCfg(std.testing.allocator, &tree.view, .{
        .planned_partitions = &planned,
    });
    defer grub_cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings("boot/grub/grub.cfg", grub_cfg.path);
}

test "generateBiosGrubCfg prefers an existing boot/grub2/grub.cfg over usr/lib BIOS assets" {
    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = 1024 * 1024,
            .length_bytes = 128 * 1024 * 1024,
        }, .unique_guid = guid.parse("cccccccc-cccc-cccc-cccc-cccccccccccc"), .mbr_disk_signature = 0x1234ABCD },
    };

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "usr/lib/grub/i386-pc/boot.img", .kind = .file, .bytes = "boot-img" },
        .{ .path = "usr/lib/grub/i386-pc/core.img", .kind = .file, .bytes = "core-img" },
        .{ .path = "boot/grub2/grub.cfg", .kind = .file, .bytes = "linux /boot/x86_64/loader/linux root=live:CDLABEL=CDROM\n" },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel-bits" },
        .{ .path = "boot/initramfs-test.img", .kind = .file, .bytes = "initrd-bits" },
    });
    tree.bind();

    var grub_cfg = try generateBiosGrubCfg(std.testing.allocator, &tree.view, .{
        .planned_partitions = &planned,
    });
    defer grub_cfg.deinit(std.testing.allocator);

    try std.testing.expectEqualStrings(bios_grub2_config_path, grub_cfg.path);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "root=PARTUUID=1234abcd-01") != null);
    try std.testing.expect(std.mem.indexOf(u8, grub_cfg.bytes, "root=live:CDLABEL=CDROM") == null);
}

test "populateEsp copies MOK assets and emits UKIs when requested" {
    const io = std.testing.io;
    const path = "test-bootconfig-secureboot-uki.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const esp_len = 96 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, esp_len * 2, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{ .partition_offset = 0, .partition_len = esp_len });
    var esp = try fat32.open(&img, io, .{ .offset = 0, .length = esp_len });

    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "ESP",
            .role = .esp,
            .type_guid = guid.esp,
            .offset_bytes = 0,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("66666666-6666-6666-6666-666666666666") },
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = esp_len,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("77777777-7777-7777-7777-777777777777") },
    };

    const stub = try makeTestStubPe(std.testing.allocator, 0x8664);
    defer std.testing.allocator.free(stub);

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "EFI/Acme/shimx64.efi", .kind = .file, .bytes = "shimx64" },
        .{ .path = "EFI/Acme/grubx64.efi", .kind = .file, .bytes = "grubx64" },
        .{ .path = "EFI/Acme/mmx64.efi", .kind = .file, .bytes = "mmx64" },
        .{ .path = "EFI/Acme/MokManager.efi", .kind = .file, .bytes = "mokmanager" },
        .{ .path = "EFI/Acme/BOOTX64.CSV", .kind = .file, .bytes = "\"zvmi\",\"grubx64.efi\",\"shim managed entry\"" },
        .{ .path = "EFI/Acme/MOK.der", .kind = .file, .bytes = "mok-der" },
        .{ .path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub", .kind = .file, .bytes = stub },
        .{ .path = "usr/lib/os-release", .kind = .file, .bytes = "ID=zvmi\nPRETTY_NAME=\"zvmi test\"\n" },
        .{ .path = "boot/vmlinuz-6.8.12-test", .kind = .file, .bytes = "kernel-payload" },
        .{ .path = "boot/initramfs-6.8.12-test.img", .kind = .file, .bytes = "initrd-payload" },
    });
    tree.bind();

    const StageRecorder = struct {
        stages: [3]PopulateStage = undefined,
        len: usize = 0,

        fn advance(context: ?*anyopaque, stage: PopulateStage) bool {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.len == self.stages.len) return false;
            self.stages[self.len] = stage;
            self.len += 1;
            return true;
        }
    };
    var stage_recorder = StageRecorder{};
    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &planned,
        .boot_mode = .bls_and_uki,
        .extra_kernel_options = "quiet splash",
        .stage_sink = .{ .context = &stage_recorder, .advanceFn = StageRecorder.advance },
    });
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqualSlices(PopulateStage, &.{ .prepare, .bootloader, .uki }, stage_recorder.stages[0..stage_recorder.len]);
    try std.testing.expectEqual(@as(usize, 4), report.copied_efi_file_count);
    try std.testing.expectEqual(@as(usize, 3), report.copied_secure_boot_file_count);
    try std.testing.expectEqual(@as(usize, 1), report.bls_entry_count);
    try std.testing.expectEqual(@as(usize, 1), report.uki_count);

    const mok_manager = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/MokManager.efi");
    defer std.testing.allocator.free(mok_manager);
    try std.testing.expectEqualStrings("mokmanager", mok_manager);

    const boot_csv = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/BOOTX64.CSV");
    defer std.testing.allocator.free(boot_csv);
    try std.testing.expectEqualStrings("\"zvmi\",\"grubx64.efi\",\"shim managed entry\"", boot_csv);

    const mok_cert = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Acme/MOK.der");
    defer std.testing.allocator.free(mok_cert);
    try std.testing.expectEqualStrings("mok-der", mok_cert);

    const named_uki = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Linux/vmlinuz-6.8.12-test.efi");
    defer std.testing.allocator.free(named_uki);
    try std.testing.expectEqualStrings("MZ", named_uki[0..2]);
}

test "populateEsp can generate UKI-only ESP boot path" {
    const io = std.testing.io;
    const path = "test-bootconfig-uki-only.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const esp_len = 96 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, esp_len * 2, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{ .partition_offset = 0, .partition_len = esp_len });
    var esp = try fat32.open(&img, io, .{ .offset = 0, .length = esp_len });

    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "ESP",
            .role = .esp,
            .type_guid = guid.esp,
            .offset_bytes = 0,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("88888888-8888-8888-8888-888888888888") },
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = esp_len,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("99999999-9999-9999-9999-999999999999") },
    };

    const stub = try makeTestStubPe(std.testing.allocator, 0x8664);
    defer std.testing.allocator.free(stub);

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub", .kind = .file, .bytes = stub },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel" },
        .{ .path = "boot/initrd-test.img", .kind = .file, .bytes = "initrd" },
    });
    tree.bind();

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &planned,
        .boot_mode = .uki_only,
    });
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 0), report.copied_efi_file_count);
    try std.testing.expectEqual(@as(usize, 0), report.bls_entry_count);
    try std.testing.expectEqual(@as(usize, 1), report.uki_count);

    const fallback = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/BOOTX64.EFI");
    defer std.testing.allocator.free(fallback);
    try std.testing.expectEqualStrings("MZ", fallback[0..2]);

    const named = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Linux/vmlinuz-test.efi");
    defer std.testing.allocator.free(named);
    try std.testing.expectEqualStrings("MZ", named[0..2]);

    try std.testing.expectError(error.PathNotFound, esp.readFileAlloc(io, std.testing.allocator, "loader/loader.conf"));
}

test "a UKI-only ESP signs once and writes the signed bytes to both destinations" {
    const io = std.testing.io;
    const path = "test-bootconfig-uki-signed.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const esp_len = 96 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, esp_len * 2, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{ .partition_offset = 0, .partition_len = esp_len });
    var esp = try fat32.open(&img, io, .{ .offset = 0, .length = esp_len });

    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "ESP",
            .role = .esp,
            .type_guid = guid.esp,
            .offset_bytes = 0,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("88888888-8888-8888-8888-888888888888") },
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = esp_len,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("99999999-9999-9999-9999-999999999999") },
    };

    const stub = try makeTestStubPe(std.testing.allocator, 0x8664);
    defer std.testing.allocator.free(stub);

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub", .kind = .file, .bytes = stub },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel" },
        .{ .path = "boot/initrd-test.img", .kind = .file, .bytes = "initrd" },
    });
    tree.bind();

    // Stands in for a signing provider without being one: it appends a marker
    // so the written bytes are distinguishable from the generated ones, and
    // counts its calls so a second signing operation for the fallback copy
    // would be visible.
    const RecordingSigner = struct {
        calls: usize = 0,
        // Copied rather than borrowed: `esp_paths` names paths the generator
        // owns for the length of one iteration, so a recorded slice would
        // dangle by the time the test reads it.
        destination_storage: [4][64]u8 = undefined,
        destination_lengths: [4]usize = undefined,
        destination_count: usize = 0,

        const marker = "-signed";

        fn destination(self: *const @This(), index: usize) []const u8 {
            return self.destination_storage[index][0..self.destination_lengths[index]];
        }

        fn sign(
            context: ?*anyopaque,
            allocator: std.mem.Allocator,
            request: uki_signing.SignRequest,
        ) uki_signing.Error![]u8 {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            self.calls += 1;
            for (request.esp_paths) |esp_path| {
                const slot = &self.destination_storage[self.destination_count];
                @memcpy(slot[0..esp_path.len], esp_path);
                self.destination_lengths[self.destination_count] = esp_path.len;
                self.destination_count += 1;
            }
            const signed = try allocator.alloc(u8, request.unsigned.len + marker.len);
            @memcpy(signed[0..request.unsigned.len], request.unsigned);
            @memcpy(signed[request.unsigned.len..], marker);
            return signed;
        }
    };
    var recording = RecordingSigner{};

    const StageRecorder = struct {
        stages: [4]PopulateStage = undefined,
        len: usize = 0,

        fn advance(context: ?*anyopaque, stage: PopulateStage) bool {
            const self: *@This() = @ptrCast(@alignCast(context.?));
            if (self.len == self.stages.len) return false;
            self.stages[self.len] = stage;
            self.len += 1;
            return true;
        }
    };
    var stage_recorder = StageRecorder{};

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &planned,
        .boot_mode = .uki_only,
        .uki_signer = .{ .context = &recording, .signFn = RecordingSigner.sign },
        .stage_sink = .{ .context = &stage_recorder, .advanceFn = StageRecorder.advance },
    });
    defer report.deinit(std.testing.allocator);
    try std.testing.expectEqual(@as(usize, 1), report.uki_count);

    // One signing operation, naming both destinations, rather than one per
    // written file.
    try std.testing.expectEqual(@as(usize, 1), recording.calls);
    try std.testing.expectEqual(@as(usize, 2), recording.destination_count);
    try std.testing.expectEqualStrings("EFI/Linux/vmlinuz-test.efi", recording.destination(0));
    try std.testing.expectEqualStrings("EFI/BOOT/BOOTX64.EFI", recording.destination(1));

    try std.testing.expectEqualSlices(
        PopulateStage,
        &.{ .prepare, .bootloader, .uki, .sign_uki },
        stage_recorder.stages[0..stage_recorder.len],
    );

    const fallback = try esp.readFileAlloc(io, std.testing.allocator, "EFI/BOOT/BOOTX64.EFI");
    defer std.testing.allocator.free(fallback);
    const named = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Linux/vmlinuz-test.efi");
    defer std.testing.allocator.free(named);
    try std.testing.expectEqualSlices(u8, named, fallback);
    try std.testing.expectEqualStrings(
        RecordingSigner.marker,
        named[named.len - RecordingSigner.marker.len ..],
    );
}

test "an unsigned UKI reaches the ESP exactly as generated" {
    const io = std.testing.io;
    const path = "test-bootconfig-uki-unsigned-identity.img";
    defer Io.Dir.cwd().deleteFile(io, path) catch {};

    const esp_len = 96 * 1024 * 1024;
    var img = try Image.create(io, path, .raw, esp_len * 2, .{});
    defer img.close(io);
    try fat32.format(&img, io, .{ .partition_offset = 0, .partition_len = esp_len });
    var esp = try fat32.open(&img, io, .{ .offset = 0, .length = esp_len });

    const planned = [_]PlannedPartitionIdentity{
        .{ .planned = .{
            .name = "ESP",
            .role = .esp,
            .type_guid = guid.esp,
            .offset_bytes = 0,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("88888888-8888-8888-8888-888888888888") },
        .{ .planned = .{
            .name = "root",
            .role = .root_x86_64,
            .type_guid = guid.linux_root_x86_64,
            .offset_bytes = esp_len,
            .length_bytes = esp_len,
        }, .unique_guid = guid.parse("99999999-9999-9999-9999-999999999999") },
    };

    const stub = try makeTestStubPe(std.testing.allocator, 0x8664);
    defer std.testing.allocator.free(stub);

    var tree = InMemoryTree.init(&[_]InMemoryEntry{
        .{ .path = "usr/lib/systemd/boot/efi/linuxx64.efi.stub", .kind = .file, .bytes = stub },
        .{ .path = "boot/vmlinuz-test", .kind = .file, .bytes = "kernel" },
        .{ .path = "boot/initrd-test.img", .kind = .file, .bytes = "initrd" },
    });
    tree.bind();

    var report = try populateEsp(std.testing.allocator, io, &esp, &tree.view, .{
        .planned_partitions = &planned,
        .boot_mode = .uki_only,
    });
    defer report.deinit(std.testing.allocator);

    // `uki.generate` zeroes the certificate table on purpose, and without a
    // signer nothing fills it. This is the precondition the signing path
    // depends on, asserted from the ESP side.
    const named = try esp.readFileAlloc(io, std.testing.allocator, "EFI/Linux/vmlinuz-test.efi");
    defer std.testing.allocator.free(named);
    var inspection = try uki.inspect(std.testing.allocator, named);
    defer inspection.deinit(std.testing.allocator);
    try std.testing.expect(inspection.security_directory == null);
}

const ParsedBlsEntry = struct {
    title: ?[]const u8 = null,
    version: ?[]const u8 = null,
    linux: ?[]const u8 = null,
    initrd: ?[]const u8 = null,
    options: ?[]const u8 = null,
};

fn parseBlsEntry(contents: []const u8) !ParsedBlsEntry {
    var parsed = ParsedBlsEntry{};
    var it = std.mem.tokenizeScalar(u8, contents, '\n');
    while (it.next()) |line| {
        if (line.len == 0 or line[0] == '#') continue;
        const split = std.mem.indexOfScalar(u8, line, ' ') orelse continue;
        const key = line[0..split];
        var value = line[split + 1 ..];
        while (value.len != 0 and value[0] == " "[0]) value = value[1..];
        if (std.mem.eql(u8, key, "title")) parsed.title = value else if (std.mem.eql(u8, key, "version")) parsed.version = value else if (std.mem.eql(u8, key, "linux")) parsed.linux = value else if (std.mem.eql(u8, key, "initrd")) parsed.initrd = value else if (std.mem.eql(u8, key, "options")) parsed.options = value;
    }
    try std.testing.expect(parsed.title != null);
    try std.testing.expect(parsed.linux != null);
    try std.testing.expect(parsed.options != null);
    return parsed;
}

fn makeTestStubPe(allocator: std.mem.Allocator, machine: u16) ![]u8 {
    const file_alignment: u32 = 0x200;
    const section_alignment: u32 = 0x1000;
    const pe_offset: usize = 0x80;
    const optional_header_size: usize = 240;
    const section_count: usize = 1;
    const file_header_size = 20;
    const section_header_size = 40;
    const size_of_headers = std.mem.alignForward(u32, pe_offset + 4 + file_header_size + optional_header_size + section_count * section_header_size, file_alignment);
    const file_len = size_of_headers + file_alignment;

    var buffer = try allocator.alloc(u8, file_len);
    @memset(buffer, 0);

    std.mem.copyForwards(u8, buffer[0..2], "MZ");
    std.mem.writeInt(u32, buffer[0x3C..0x40], pe_offset, .little);
    std.mem.copyForwards(u8, buffer[pe_offset .. pe_offset + 4], "PE\x00\x00");

    const file_header_offset = pe_offset + 4;
    std.mem.writeInt(u16, buffer[file_header_offset..][0..2], machine, .little);
    std.mem.writeInt(u16, buffer[file_header_offset + 2 ..][0..2], section_count, .little);
    std.mem.writeInt(u16, buffer[file_header_offset + 16 ..][0..2], optional_header_size, .little);
    std.mem.writeInt(u16, buffer[file_header_offset + 18 ..][0..2], 0x202, .little);

    const optional_header_offset = file_header_offset + file_header_size;
    std.mem.writeInt(u16, buffer[optional_header_offset..][0..2], 0x20B, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 4 ..][0..4], file_alignment, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 16 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 20 ..][0..4], 0x1000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 24 ..][0..8], 0x400000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 32 ..][0..4], section_alignment, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 36 ..][0..4], file_alignment, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 40 ..][0..2], 6, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 48 ..][0..2], 6, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 56 ..][0..4], 0x2000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 60 ..][0..4], size_of_headers, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 68 ..][0..2], 10, .little);
    std.mem.writeInt(u16, buffer[optional_header_offset + 70 ..][0..2], 0x160, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 72 ..][0..8], 0x100000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 80 ..][0..8], 0x1000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 88 ..][0..8], 0x100000, .little);
    std.mem.writeInt(u64, buffer[optional_header_offset + 96 ..][0..8], 0x1000, .little);
    std.mem.writeInt(u32, buffer[optional_header_offset + 108 ..][0..4], 16, .little);

    const section_header_offset = optional_header_offset + optional_header_size;
    const header = buffer[section_header_offset .. section_header_offset + section_header_size];
    std.mem.copyForwards(u8, header[0..5], ".text");
    std.mem.writeInt(u32, header[8..12], 1, .little);
    std.mem.writeInt(u32, header[12..16], 0x1000, .little);
    std.mem.writeInt(u32, header[16..20], file_alignment, .little);
    std.mem.writeInt(u32, header[20..24], size_of_headers, .little);
    std.mem.writeInt(u32, header[36..40], 0x60000020, .little);

    buffer[size_of_headers] = 0xC3;
    return buffer;
}

const InMemoryEntry = struct {
    path: []const u8,
    kind: SourceKind,
    bytes: []const u8 = "",
    mode: u16 = 0o644,
    uid: u32 = 0,
    gid: u32 = 0,
};

const InMemoryTree = struct {
    entries: []const InMemoryEntry,
    index: usize = 0,
    view: SourceTreeView,

    fn init(entries: []const InMemoryEntry) InMemoryTree {
        return .{
            .entries = entries,
            .view = .{
                .ctx = undefined,
                .next_fn = next,
                .reset_fn = reset,
            },
        };
    }

    fn bind(self: *InMemoryTree) void {
        self.view = .{
            .ctx = self,
            .next_fn = next,
            .reset_fn = reset,
        };
    }

    fn reset(ctx: *anyopaque) void {
        const self: *InMemoryTree = @ptrCast(@alignCast(ctx));
        self.index = 0;
    }

    fn next(ctx: *anyopaque) SourceTreeView.IteratorError!?SourceTreeView.Entry {
        const self: *InMemoryTree = @ptrCast(@alignCast(ctx));
        if (self.index >= self.entries.len) return null;
        const entry = self.entries[self.index];
        self.index += 1;
        return .{
            .path = entry.path,
            .kind = entry.kind,
            .mode = entry.mode,
            .uid = entry.uid,
            .gid = entry.gid,
            .size = entry.bytes.len,
            .content = if (entry.kind == .directory)
                null
            else
                .{ .ctx = &self.entries[self.index - 1], .read_at_fn = readContent },
        };
    }

    fn readContent(ctx: *const anyopaque, buffer: []u8, offset: u64) SourceTreeView.ContentError!usize {
        const entry: *const InMemoryEntry = @ptrCast(@alignCast(ctx));
        const start = std.math.cast(usize, offset) orelse return error.UnexpectedEndOfStream;
        if (start > entry.bytes.len) return error.UnexpectedEndOfStream;
        const count = @min(buffer.len, entry.bytes.len - start);
        std.mem.copyForwards(u8, buffer[0..count], entry.bytes[start .. start + count]);
        return count;
    }
};
